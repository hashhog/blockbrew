package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// pruneblockchain against Core's rpc/blockchain.cpp:908-963. Before this
// commit the handler deleted nothing and answered the pruner's watermark
// (0 on a node that never auto-pruned), so a manual (-prune=1) node could
// never prune, and the "too short" / "shorter than" / timestamp paths did not
// exist. Results and errors here are Core's, read from that source.

// pruneRigBlock mines a coinbase-only regtest block on prev paying the
// regtest subsidy (halving every 150 blocks).
func pruneRigBlock(t *testing.T, params *consensus.ChainParams, prev *consensus.BlockNode) *wire.MsgBlock {
	t.Helper()
	height := prev.Height + 1
	sig := encodeBIP34HeightForTest(height)
	if len(sig) < 2 {
		sig = append(sig, 0x00)
	}
	cb := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0xFFFFFFFF},
			SignatureScript:  sig,
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    consensus.CalcBlockSubsidyForInterval(height, params.SubsidyHalvingInterval),
			PkScript: []byte{0x51},
		}},
	}
	b := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    4,
			PrevBlock:  prev.Hash,
			MerkleRoot: consensus.CalcMerkleRoot([]wire.Hash256{cb.TxHash()}),
			Timestamp:  prev.Header.Timestamp + 600,
			Bits:       params.PowLimitBits,
		},
		Transactions: []*wire.MsgTx{cb},
	}
	target := consensus.CompactToBig(b.Header.Bits)
	for n := uint32(0); ; n++ {
		b.Header.Nonce = n
		if consensus.HashToBig(b.Header.BlockHash()).Cmp(target) <= 0 {
			return b
		}
	}
}

type pruneRig struct {
	server *Server
	cm     *consensus.ChainManager
	bs     *storage.BlockStore
	cdb    *storage.ChainDB
	pruner *storage.Pruner
	tip    int32
	capped bool // block files capped small (false only before this fix)
}

// newPruneRig connects a regtest chain of `tip` blocks into flat files capped
// at 8 KiB (dozens of files), with a pruner in the given mode. pruneMode
// false attaches no pruner: an archive node.
func newPruneRig(t *testing.T, tip int32, pruneMode bool) *pruneRig {
	t.Helper()
	params := consensus.RegtestParams()
	db := storage.NewMemDB()
	t.Cleanup(func() { db.Close() })
	bs, err := storage.NewBlockStore(t.TempDir(), 0xDAB5BFFA, db)
	if err != nil {
		t.Fatalf("NewBlockStore: %v", err)
	}
	t.Cleanup(func() { bs.Close() })
	// Small files so a short chain spans many (Core's -fastprune). Asserted
	// through an interface so this file also compiles on the parent commit,
	// which has no SetMaxFileSize; there the chain sits in one file.
	capped := false
	if c, ok := interface{}(bs).(interface{ SetMaxFileSize(uint32) }); ok {
		c.SetMaxFileSize(8 << 10)
		capped = true
	}
	cdb := storage.NewChainDB(db)
	cdb.SetBlockStore(bs)
	idx := consensus.NewHeaderIndex(params)
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: cdb, UTXOSet: consensus.NewUTXOSet(cdb),
	})
	if err := cdb.StoreBlockAt(params.GenesisHash, params.GenesisBlock, 0); err != nil {
		t.Fatalf("StoreBlockAt(genesis): %v", err)
	}
	if err := cdb.SetBlockHeight(0, params.GenesisHash); err != nil {
		t.Fatalf("SetBlockHeight(genesis): %v", err)
	}
	prev := idx.Genesis()
	for h := int32(1); h <= tip; h++ {
		b := pruneRigBlock(t, params, prev)
		node, err := idx.AddHeader(b.Header, true)
		if err != nil {
			t.Fatalf("AddHeader(%d): %v", h, err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock(%d): %v", h, err)
		}
		prev = node
	}
	if _, h := cm.BestBlock(); h != tip {
		t.Fatalf("precondition: tip %d, want %d", h, tip)
	}
	r := &pruneRig{cm: cm, bs: bs, cdb: cdb, tip: tip, capped: capped}
	opts := []ServerOption{
		WithChainParams(params), WithHeaderIndex(idx), WithChainManager(cm), WithChainDB(cdb),
	}
	if pruneMode {
		r.pruner = storage.NewPruner(storage.PruneConfig{Manual: true}, bs, cdb)
		opts = append(opts, WithPruner(r.pruner))
	}
	r.server = NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, opts...)
	return r
}

func (r *pruneRig) hashAt(t *testing.T, h int32) wire.Hash256 {
	t.Helper()
	n := r.cm.BestBlockNode().GetAncestor(h)
	if n == nil {
		t.Fatalf("no block at height %d", h)
	}
	return n.Hash
}

// fileOf maps every height to its blk file number (read before pruning).
func (r *pruneRig) fileOf(t *testing.T) map[int32]int32 {
	t.Helper()
	m := map[int32]int32{}
	for h := int32(0); h <= r.tip; h++ {
		pos, err := r.bs.GetBlockPos(r.hashAt(t, h))
		if err != nil {
			t.Fatalf("GetBlockPos(%d): %v", h, err)
		}
		m[h] = pos.FileNum
	}
	return m
}

// expectedPruned is what Core would answer after pruning to `to`: files are
// pruned whole, so the last pruned block is the one before the first block
// of the file that holds `to` (or `to` itself when it ends its file).
func expectedPruned(fileOf map[int32]int32, to int32) int64 {
	if fileOf[to+1] != fileOf[to] {
		return int64(to)
	}
	h := to
	for h > 0 && fileOf[h-1] == fileOf[to] {
		h--
	}
	return int64(h) - 1
}

func (r *pruneRig) call(t *testing.T, params []interface{}) *RPCResponse {
	t.Helper()
	return testRPCRequest(t, r.server.handleRPC, "pruneblockchain", params, "", "")
}

func wantRPCError(t *testing.T, resp *RPCResponse, code int, msg string) {
	t.Helper()
	if resp.Error == nil {
		t.Fatalf("got result %v, want error %d %q", resp.Result, code, msg)
	}
	if resp.Error.Code != code || resp.Error.Message != msg {
		t.Fatalf("got error %d %q, want %d %q", resp.Error.Code, resp.Error.Message, code, msg)
	}
}

func wantResult(t *testing.T, resp *RPCResponse, want int64) {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("got error %d %q, want result %d", resp.Error.Code, resp.Error.Message, want)
	}
	got, ok := resp.Result.(float64)
	if !ok || int64(got) != want {
		t.Fatalf("got result %v, want %d", resp.Result, want)
	}
}

// TestPruneBlockchainNotPruneMode: an archive node refuses, and the refusal
// comes before the integer conversion and the negative check (Core order).
func TestPruneBlockchainNotPruneMode(t *testing.T) {
	r := newPruneRig(t, 10, false)
	const msg = "Cannot prune blocks because node is not in prune mode."
	for _, arg := range []interface{}{5, -1, 1.5, 1e12} {
		wantRPCError(t, r.call(t, []interface{}{arg}), RPCErrMisc, msg)
	}
	// Type check still runs first (RPCHelpMan).
	if resp := r.call(t, []interface{}{"zz"}); resp.Error == nil || resp.Error.Code != RPCErrTypeError {
		t.Fatalf("pruneblockchain(\"zz\") = %+v, want RPC_TYPE_ERROR", resp.Error)
	}
}

// TestPruneBlockchainErrors: every refusal Core makes in prune mode.
func TestPruneBlockchainErrors(t *testing.T) {
	short := newPruneRig(t, 50, true)
	wantRPCError(t, short.call(t, []interface{}{-1}), RPCErrInvalidParameter, "Negative block height.")
	wantRPCError(t, short.call(t, []interface{}{10}), RPCErrMisc, "Blockchain is too short for pruning.")

	r := newPruneRig(t, 1300, true)
	wantRPCError(t, r.call(t, []interface{}{1301}), RPCErrInvalidParameter,
		"Blockchain is shorter than the attempted prune height.")
	tipTime := int64(r.cm.BestBlockNode().Header.Timestamp)
	wantRPCError(t, r.call(t, []interface{}{tipTime + 2*60*60 + 1}), RPCErrInvalidParameter,
		"Could not find block with at least the specified timestamp.")
	if r.pruner.HavePruned() {
		t.Fatal("a refused pruneblockchain deleted data")
	}
}

// TestPruneBlockchainPrunesToHeight: the RPC really deletes the files at or
// below the height and answers Core's GetPruneHeight: the last pruned block.
func TestPruneBlockchainPrunesToHeight(t *testing.T) {
	r := newPruneRig(t, 1300, true)
	fileOf := r.fileOf(t)

	// Nothing to prune yet: Core answers -1.
	wantResult(t, r.call(t, []interface{}{0}), -1)

	const to = 500
	want := expectedPruned(fileOf, to)
	if r.capped && want < 100 {
		t.Fatalf("precondition: expected prune height %d is too low to mean anything", want)
	}
	t.Logf("tip %d in %d blk files; pruning to %d should answer %d", r.tip, r.bs.MaxBlockfileNum(), to, want)
	wantResult(t, r.call(t, []interface{}{to}), want)
	for h := int32(1); h <= r.tip; h++ {
		has := r.cdb.HasBlockBody(r.hashAt(t, h))
		if int64(h) <= want && has {
			t.Fatalf("block %d is at or below the pruned height %d but still has its body", h, want)
		}
		if int64(h) > want && !has {
			t.Fatalf("block %d is above the pruned height %d but its body is gone", h, want)
		}
	}
	// getblockchaininfo agrees: pruneheight is the first unpruned block.
	info := testRPCRequest(t, r.server.handleRPC, "getblockchaininfo", []interface{}{}, "", "")
	m, _ := info.Result.(map[string]interface{})
	if ph, _ := m["pruneheight"].(float64); int64(ph) != want+1 {
		t.Errorf("getblockchaininfo pruneheight = %v, want %d", m["pruneheight"], want+1)
	}

	// A lower height prunes nothing more and answers the same height.
	wantResult(t, r.call(t, []interface{}{100}), want)
}

// TestPruneBlockchainKeepsLast288: a height near the tip is clamped to
// tip - 288; no block above that loses its body.
func TestPruneBlockchainKeepsLast288(t *testing.T) {
	r := newPruneRig(t, 1300, true)
	fileOf := r.fileOf(t)
	clamp := r.tip - storage.MinBlocksToKeep
	want := expectedPruned(fileOf, clamp)
	t.Logf("pruneblockchain(%d) at tip %d clamps to %d and should answer %d", r.tip, r.tip, clamp, want)
	wantResult(t, r.call(t, []interface{}{r.tip}), want)
	for h := clamp + 1; h <= r.tip; h++ {
		if !r.cdb.HasBlockBody(r.hashAt(t, h)) {
			t.Fatalf("block %d is within %d of the tip but was pruned", h, storage.MinBlocksToKeep)
		}
	}
}

// TestPruneBlockchainByTimestamp: a value above 1e9 is a block time; Core
// prunes to the first block with time >= value - 2 h.
func TestPruneBlockchainByTimestamp(t *testing.T) {
	r := newPruneRig(t, 1300, true)
	fileOf := r.fileOf(t)
	const to = 700
	ts := int64(r.cm.BestBlockNode().GetAncestor(to).Header.Timestamp) + 2*60*60
	wantResult(t, r.call(t, []interface{}{ts}), expectedPruned(fileOf, to))
}
