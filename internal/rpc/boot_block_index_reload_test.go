package rpc

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Core's block index keeps every header it ever accepted, and a restart
// reloads all of it (node/blockstorage.cpp LoadBlockIndexGuts reads every
// DB_BLOCK_INDEX record; validation.cpp LoadBlockIndex re-adds each one to
// setBlockIndexCandidates / m_best_header). getchaintips and
// getblockchaininfo.headers therefore answer the same before and after a
// restart.
//
// blockbrew's boot rebuilt only the active chain (walked back from the saved
// tip) and the blocks that carry a persisted failure flag, and only when their
// header or body was on disk. A restart dropped:
//   - a side block stored by submitblock that never connected (Core:
//     "valid-headers"),
//   - a side branch that connected once and was then displaced (Core:
//     "valid-fork"),
//   - a block that failed ConnectBlock at the tip (Core: "invalid"): its
//     failure flag was persisted but neither its header nor its body was,
//   - headers accepted by submitheader (Core: "headers-only", counted in
//     getblockchaininfo.headers): never written to disk at all.
//
// Core v31.1 regtest rows: warden_invalidated_submit/{restart,p2p-header}/
// tips:{$keys,15b45ee2…,6646aead…,7c898bd0…}, warden_invalidated_submit/
// {restart,p2p-header}/info:headers, failed_reorg/{e-restart,
// e-restart-invalidated}/tips:{$keys,795f067e…}.

type bootRig struct {
	params *consensus.ChainParams
	db     *storage.ChainDB
	idx    *consensus.HeaderIndex
	utxo   *consensus.UTXOSet
	cm     *consensus.ChainManager
	server *Server
}

func newBootRig(params *consensus.ChainParams, db *storage.ChainDB, idx *consensus.HeaderIndex) *bootRig {
	utxo := consensus.NewUTXOSet(db)
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db, UTXOSet: utxo,
	})
	cm.SetIBD(false)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainManager(cm),
		WithHeaderIndex(idx),
		WithChainDB(db),
	)
	return &bootRig{params: params, db: db, idx: idx, utxo: utxo, cm: cm, server: server}
}

// reboot stops the rig cleanly (coins flushed, chain-state pointer written)
// and boots a fresh header index + chain manager on the same DB the way
// cmd/blockbrew does: HydrateFromDB from the saved tip, then
// RecoverFromPersistedBlocks.
func (r *bootRig) reboot(t *testing.T) *bootRig {
	t.Helper()
	if err := r.utxo.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	best, height := r.cm.BestBlock()
	if err := r.db.SetChainState(&storage.ChainState{BestHash: best, BestHeight: height}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}
	idx := consensus.NewHeaderIndex(r.params)
	if _, err := idx.HydrateFromDB(r.db, best, height); err != nil {
		t.Fatalf("HydrateFromDB: %v", err)
	}
	r2 := newBootRig(r.params, r.db, idx)
	if _, err := r2.cm.RecoverFromPersistedBlocks(); err != nil {
		t.Fatalf("RecoverFromPersistedBlocks: %v", err)
	}
	return r2
}

func (r *bootRig) submit(t *testing.T, blk *wire.MsgBlock) interface{} {
	t.Helper()
	var w byteWriter
	if err := blk.Serialize(&w); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	raw, _ := json.Marshal([]interface{}{hex.EncodeToString(w.bytes)})
	res, rpcErr := r.server.handleSubmitBlock(raw)
	if rpcErr != nil {
		t.Fatalf("submitblock: RPC error %v", rpcErr)
	}
	return res
}

func (r *bootRig) submitHeader(t *testing.T, hdr wire.BlockHeader) {
	t.Helper()
	var w byteWriter
	if err := hdr.Serialize(&w); err != nil {
		t.Fatalf("serialize header: %v", err)
	}
	raw, _ := json.Marshal([]interface{}{hex.EncodeToString(w.bytes)})
	if res, rpcErr := r.server.handleSubmitHeader(raw); rpcErr != nil || res != nil {
		t.Fatalf("submitheader = %v / %v, want null", res, rpcErr)
	}
}

func (r *bootRig) tips(t *testing.T) []ChainTip {
	t.Helper()
	res, rpcErr := r.server.handleGetChainTips()
	if rpcErr != nil {
		t.Fatalf("getchaintips: %v", rpcErr)
	}
	tips := append([]ChainTip(nil), res.([]ChainTip)...)
	sort.Slice(tips, func(i, j int) bool { return tips[i].Hash < tips[j].Hash })
	return tips
}

func (r *bootRig) headers(t *testing.T) int32 {
	t.Helper()
	res, rpcErr := r.server.handleGetBlockchainInfo()
	if rpcErr != nil {
		t.Fatalf("getblockchaininfo: %v", rpcErr)
	}
	return res.(*BlockchainInfo).Headers
}

// variantBlock is buildRegtestBlock with the coinbase paying `less` satoshis
// under the subsidy, so a sibling at the same height gets its own hash and
// still connects.
func variantBlock(t *testing.T, params *consensus.ChainParams, prev *consensus.BlockNode, less int64) *wire.MsgBlock {
	t.Helper()
	blk := buildRegtestBlock(t, params, prev)
	blk.Transactions[0].TxOut[0].Value -= less
	blk.Header.MerkleRoot = consensus.CalcMerkleRoot([]wire.Hash256{blk.Transactions[0].TxHash()})
	target := consensus.CompactToBig(blk.Header.Bits)
	for i := uint32(0); i < 10_000_000; i++ {
		blk.Header.Nonce = i
		if consensus.HashToBig(blk.Header.BlockHash()).Cmp(target) <= 0 {
			return blk
		}
	}
	t.Fatal("could not mine the variant block")
	return nil
}

func TestBootBlockIndexReloadKeepsEveryTip(t *testing.T) {
	params := consensus.RegtestParams()
	pdb, err := storage.NewPebbleDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewPebbleDB: %v", err)
	}
	t.Cleanup(func() { pdb.Close() })
	r := newBootRig(params, storage.NewChainDB(pdb), consensus.NewHeaderIndex(params))
	node := func(b *wire.MsgBlock) *consensus.BlockNode {
		n := r.idx.GetNode(b.Header.BlockHash())
		if n == nil {
			t.Fatalf("block %s not in the index", b.Header.BlockHash())
		}
		return n
	}

	// Active chain 1-2-3.
	m := []*wire.MsgBlock{}
	prev := r.idx.Genesis()
	for i := 0; i < 3; i++ {
		b := buildRegtestBlock(t, params, prev)
		if res := r.submit(t, b); res != nil {
			t.Fatalf("submitblock main %d = %v", i+1, res)
		}
		m = append(m, b)
		prev = node(b)
	}

	// A side branch s3-s4 off 2 takes the tip (connects), then 4-5 on the
	// main chain takes it back: s3-s4 is a displaced, once-connected branch
	// (Core: "valid-fork", failed_reorg 795f067e…).
	s3 := variantBlock(t, params, node(m[1]), 1)
	if res := r.submit(t, s3); res != "inconclusive" {
		t.Fatalf("submitblock s3 = %v, want inconclusive", res)
	}
	s4 := variantBlock(t, params, node(s3), 1)
	if res := r.submit(t, s4); res != nil {
		t.Fatalf("submitblock s4 = %v, want null (reorg)", res)
	}
	m4 := buildRegtestBlock(t, params, node(m[2]))
	if res := r.submit(t, m4); res != "inconclusive" {
		t.Fatalf("submitblock m4 = %v, want inconclusive", res)
	}
	m5 := buildRegtestBlock(t, params, node(m4))
	if res := r.submit(t, m5); res != nil {
		t.Fatalf("submitblock m5 = %v, want null (reorg back)", res)
	}

	// A height-1 block off genesis: stored, never connected (Core:
	// "valid-headers", warden 7c898bd0…).
	side1 := variantBlock(t, params, r.idx.Genesis(), 2)
	if res := r.submit(t, side1); res != "inconclusive" {
		t.Fatalf("submitblock side1 = %v, want inconclusive", res)
	}

	// A block on the tip that fails ConnectBlock (Core: "invalid", warden
	// 6646aead…).
	bad := failedConnectBlock(t, params, node(m5))
	if res := r.submit(t, bad); res != "bad-cb-amount" {
		t.Fatalf("submitblock bad = %v, want bad-cb-amount", res)
	}

	// Two headers past the tip by submitheader (Core: "headers-only" at 7,
	// headers=7, warden 15b45ee2… and info:headers).
	h6 := variantBlock(t, params, node(m5), 3)
	r.submitHeader(t, h6.Header)
	h7 := variantBlock(t, params, r.idx.GetNode(h6.Header.BlockHash()), 3)
	r.submitHeader(t, h7.Header)

	tip := node(m5)
	want := []ChainTip{
		{Height: 7, Hash: h7.Header.BlockHash().String(), BranchLen: 2, Status: "headers-only"},
		{Height: 6, Hash: bad.Header.BlockHash().String(), BranchLen: 1, Status: "invalid"},
		{Height: 5, Hash: tip.Hash.String(), BranchLen: 0, Status: "active"},
		{Height: 4, Hash: s4.Header.BlockHash().String(), BranchLen: 2, Status: "valid-fork"},
		{Height: 1, Hash: side1.Header.BlockHash().String(), BranchLen: 1, Status: "valid-headers"},
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Hash < want[j].Hash })

	before := r.tips(t)
	if !equalTips(before, want) {
		t.Fatalf("before restart: getchaintips = %+v\nwant %+v", before, want)
	}
	if h := r.headers(t); h != 7 {
		t.Fatalf("before restart: headers = %d, want 7", h)
	}

	r2 := r.reboot(t)
	if best, h := r2.cm.BestBlock(); best != tip.Hash || h != 5 {
		t.Fatalf("after restart: tip %s@%d, want m5@5", best, h)
	}
	after := r2.tips(t)
	if !equalTips(after, want) {
		t.Errorf("after restart: getchaintips = %+v\nwant (Core, unchanged by a restart) %+v", after, want)
	}
	if h := r2.headers(t); h != 7 {
		t.Errorf("after restart: getblockchaininfo headers = %d, want 7 (Core keeps submitheader headers)", h)
	}

	// The invalid block stays invalid across the restart: resubmitting it is
	// still duplicate-invalid, and a valid block on the tip still connects.
	if res := r2.submit(t, bad); res != "duplicate-invalid" {
		t.Errorf("after restart: resubmit bad = %v, want duplicate-invalid", res)
	}
	next := variantBlock(t, params, tip, 4)
	if res := r2.submit(t, next); res != nil {
		t.Errorf("after restart: a valid child of the tip = %v, want null", res)
	}
	// A second restart keeps the same set (nothing is reloaded twice or lost).
	r3 := r2.reboot(t)
	if best, h := r3.cm.BestBlock(); best != next.Header.BlockHash() || h != 6 {
		t.Fatalf("after second restart: tip %s@%d, want next@6", best, h)
	}
	if got := len(r3.tips(t)); got != len(r2.tips(t)) {
		t.Errorf("after second restart: %d tips, want %d", got, len(r2.tips(t)))
	}
}

func equalTips(a, b []ChainTip) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
