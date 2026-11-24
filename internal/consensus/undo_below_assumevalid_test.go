package consensus

import (
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ─── The defect these tests pin ─────────────────────────────────────────────
//
// ConnectBlock skipped undo data for a block whose scripts assume-valid let it
// skip, while the node was in IBD:
//
//	generateUndo := !skipScripts || !cm.isIBD
//
// Such a block connected fine but could never be disconnected again:
// DisconnectBlock reads the undo record and returned "failed to read undo
// data". invalidateblock of a block below the assume-valid point, a reorg that
// reaches below the IBD tip, and the boot consistency probe's peel all go
// through that path. Core writes undo for every connected block; assume-valid
// only skips script checks (validation.cpp ConnectBlock: blockundo is filled
// for every non-coinbase tx and WriteBlockUndo runs whenever the block is not
// genesis).
//
// The fixture below makes shouldSkipScripts really return true on regtest:
// the assume-valid hash is a header 2,100 blocks above the connected blocks,
// so every connected block is its ancestor, lies on the best-header chain,
// and is more than two weeks of equivalent work below it. The chain manager
// stays in IBD throughout (block timestamps are 2011-era and the assume-valid
// height is never reached).

const avExtraHeaders = 2100 // > 2016, so the equivalent-time gate passes

// avHeader mines a version-4 regtest header on prev.
func avHeader(params *ChainParams, prev *BlockNode) wire.BlockHeader {
	h := wire.BlockHeader{
		Version:   4,
		PrevBlock: prev.Hash,
		Timestamp: prev.Header.Timestamp + 600,
		Bits:      params.PowLimitBits,
	}
	target := CompactToBig(h.Bits)
	for n := uint32(0); ; n++ {
		h.Nonce = n
		if HashToBig(h.BlockHash()).Cmp(target) <= 0 {
			return h
		}
	}
}

type avFixture struct {
	params  *ChainParams
	idx     *HeaderIndex
	chainDB *storage.ChainDB
	utxoSet *UTXOSet
	cm      *ChainManager
	blocks  []*wire.MsgBlock // blocks[h] is the block at height h (blocks[0] unused)
	nodes   []*BlockNode
	victim  wire.OutPoint // block 1's coinbase, spent by block 102
	spend   *wire.MsgTx   // the spending tx in block 102
	// The coins at height 101, the set a disconnect of 102 must restore.
	hash101  wire.Hash256
	coins101 uint64
}

// newAVFixture builds genesis..103 (block 102 spends block 1's coinbase) plus
// avExtraHeaders headers above it, sets assumevalid to the top header, and
// connects 1..103 in IBD.
func newAVFixture(t *testing.T) *avFixture {
	t.Helper()
	f := &avFixture{params: RegtestParams()}
	f.idx = NewHeaderIndex(f.params)
	db, err := storage.NewPebbleDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewPebbleDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	f.chainDB = storage.NewChainDB(db)
	f.utxoSet = NewUTXOSet(f.chainDB)

	// Full blocks 1..103, headers only for now.
	f.blocks = make([]*wire.MsgBlock, 104)
	f.nodes = make([]*BlockNode, 104)
	f.nodes[0] = f.idx.Genesis()
	for h := 1; h <= 103; h++ {
		var txs []*wire.MsgTx
		if h == 102 {
			f.spend = h4SpendTx(f.victim, 1000)
			txs = []*wire.MsgTx{f.spend}
		}
		b := createTestBlock(t, f.params, f.nodes[h-1], txs)
		node, err := f.idx.AddHeader(b.Header, true)
		if err != nil {
			t.Fatalf("AddHeader(%d): %v", h, err)
		}
		f.blocks[h], f.nodes[h] = b, node
		if h == 1 {
			f.victim = wire.OutPoint{Hash: b.Transactions[0].TxHash(), Index: 0}
		}
	}
	// Headers above, so the assume-valid block is far ahead of everything
	// we connect.
	prev := f.nodes[103]
	for i := 0; i < avExtraHeaders; i++ {
		node, err := f.idx.AddHeader(avHeader(f.params, prev), true)
		if err != nil {
			t.Fatalf("AddHeader(av +%d): %v", i, err)
		}
		prev = node
	}

	f.cm = NewChainManager(ChainManagerConfig{
		Params: f.params, HeaderIndex: f.idx, ChainDB: f.chainDB, UTXOSet: f.utxoSet,
		AssumeValidHash: prev.Hash,
	})
	if !f.cm.IsIBD() {
		t.Fatalf("precondition: a new chain manager must start in IBD")
	}

	for h := 1; h <= 103; h++ {
		if !f.cm.shouldSkipScripts(f.nodes[h]) {
			t.Fatalf("precondition: block %d must be connected under assume-valid (shouldSkipScripts=false)", h)
		}
		if err := f.cm.ConnectBlock(f.blocks[h]); err != nil {
			t.Fatalf("ConnectBlock(%d): %v", h, err)
		}
		if h == 101 {
			f.hash101, f.coins101 = f.flushedSet(t)
		}
	}
	if !f.cm.IsIBD() {
		t.Fatalf("precondition: blocks 1..103 must connect in IBD (left IBD early)")
	}
	if _, h := f.cm.BestBlock(); h != 103 {
		t.Fatalf("precondition: tip height %d, want 103", h)
	}
	return f
}

func (f *avFixture) flushedSet(t *testing.T) (wire.Hash256, uint64) {
	t.Helper()
	if err := f.utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	hash, coins, err := ComputeHashSerialized(f.utxoSet)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	return hash, coins
}

// TestUndoWrittenForBlocksConnectedUnderAssumeValid: every block connected
// under assume-valid in IBD has an undo record on disk and HAVE_UNDO set, and
// block 102's record holds the coin it spent.
func TestUndoWrittenForBlocksConnectedUnderAssumeValid(t *testing.T) {
	f := newAVFixture(t)
	for h := 1; h <= 103; h++ {
		hash := f.nodes[h].Hash
		undo, err := f.chainDB.ReadBlockUndo(hash)
		if err != nil {
			t.Fatalf("block %d connected under assume-valid has no undo record: %v", h, err)
		}
		if want := len(f.blocks[h].Transactions) - 1; len(undo.TxUndos) != want {
			t.Errorf("block %d undo has %d tx records, want %d", h, len(undo.TxUndos), want)
		}
		if f.nodes[h].Status&StatusHaveUndo == 0 {
			t.Errorf("block %d connected under assume-valid lacks StatusHaveUndo", h)
		}
	}
	undo, err := f.chainDB.ReadBlockUndo(f.nodes[102].Hash)
	if err != nil {
		t.Fatalf("ReadBlockUndo(102): %v", err)
	}
	if len(undo.TxUndos) != 1 || len(undo.TxUndos[0].SpentCoins) != 1 {
		t.Fatalf("block 102 undo = %+v, want one tx spending one coin", undo.TxUndos)
	}
	got := undo.TxUndos[0].SpentCoins[0]
	cb := f.blocks[1].Transactions[0].TxOut[0]
	if got.TxOut.Value != cb.Value || got.Height != 1 || !got.Coinbase {
		t.Errorf("block 102 undo coin = {value %d height %d coinbase %v}, want {value %d height 1 coinbase true}",
			got.TxOut.Value, got.Height, got.Coinbase, cb.Value)
	}
}

// TestDisconnectBlockConnectedUnderAssumeValid is the repro: invalidateblock
// of block 102 (connected under assume-valid in IBD) must disconnect 103 and
// 102 and restore the set at 101 exactly, as Core does.
func TestDisconnectBlockConnectedUnderAssumeValid(t *testing.T) {
	f := newAVFixture(t)

	if err := f.cm.InvalidateBlock(f.nodes[102].Hash); err != nil {
		t.Fatalf("InvalidateBlock(102), a block connected under assume-valid: %v", err)
	}
	if got, h := f.cm.BestBlock(); got != f.nodes[101].Hash || h != 101 {
		t.Fatalf("after invalidateblock 102: tip %s@%d, want block 101", got.String()[:16], h)
	}
	if f.utxoSet.GetUTXO(f.victim) == nil {
		t.Errorf("coin %v spent by the disconnected block 102 was not restored", f.victim)
	}
	for _, h := range []int{102, 103} {
		for i, tx := range f.blocks[h].Transactions {
			op := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
			if f.utxoSet.GetUTXO(op) != nil {
				t.Errorf("output %v of disconnected block %d (tx %d) is still in the set", op, h, i)
			}
		}
	}
	if hash, coins := f.flushedSet(t); hash != f.hash101 || coins != f.coins101 {
		t.Errorf("set after disconnect = %d coins %s, want block 101's %d coins %s",
			coins, hash.String()[:16], f.coins101, f.hash101.String()[:16])
	}
}

// TestDisconnectUnderAssumeValidKeepsValidityVerdicts covers the consensus
// risk of the fix: after the disconnect, (a) a block that spends an output of
// the disconnected block 102 must be rejected (it no longer exists), and
// (b) the valid block 102 must reconnect when reconsidered.
func TestDisconnectUnderAssumeValidKeepsValidityVerdicts(t *testing.T) {
	f := newAVFixture(t)
	if err := f.cm.InvalidateBlock(f.nodes[102].Hash); err != nil {
		t.Fatalf("InvalidateBlock(102): %v", err)
	}

	// (a) Invalid stays invalid. This block is a fork of 101, not an
	// ancestor of the assume-valid block, so its scripts are checked; the
	// input itself is missing, which assume-valid never skips.
	phantom := wire.OutPoint{Hash: f.spend.TxHash(), Index: 0}
	bad := taggedBlock(t, f.params, f.nodes[101], 0xE1, []*wire.MsgTx{h4SpendTx(phantom, 500)})
	if _, err := f.idx.AddHeader(bad.Header, true); err != nil {
		t.Fatalf("AddHeader(bad): %v", err)
	}
	err := f.cm.ConnectBlock(bad)
	if err == nil {
		t.Fatalf("a block spending output %v of the disconnected block 102 was ACCEPTED", phantom)
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("block spending the disconnected output rejected for the wrong reason: %v", err)
	}
	if _, h := f.cm.BestBlock(); h != 101 {
		t.Fatalf("after the rejected block: tip height %d, want 101", h)
	}

	// (b) Valid stays valid: reconsider 102 reconnects 102 and 103.
	if err := f.cm.ReconsiderBlock(f.nodes[102].Hash); err != nil {
		t.Fatalf("ReconsiderBlock(102): %v", err)
	}
	if got, h := f.cm.BestBlock(); got != f.nodes[103].Hash {
		t.Fatalf("after reconsiderblock: tip height %d, want 103", h)
	}
	if f.utxoSet.GetUTXO(f.victim) != nil {
		t.Errorf("after reconsiderblock: %v is unspent, want spent by 102", f.victim)
	}
	if f.utxoSet.GetUTXO(phantom) == nil {
		t.Errorf("after reconsiderblock: block 102's output %v is missing", phantom)
	}
	// And it can be taken off again: the reconnect wrote undo too.
	if err := f.cm.DisconnectBlock(f.nodes[103].Hash); err != nil {
		t.Fatalf("DisconnectBlock(103) after reconsider: %v", err)
	}
}
