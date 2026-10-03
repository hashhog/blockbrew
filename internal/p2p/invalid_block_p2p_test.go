package p2p

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// mkBlock builds a coinbase-only regtest block on prev. salt makes a sibling
// at the same height hash differently; overpay adds satoshis above the subsidy
// (overpay > 0 => bad-cb-amount, a consensus failure only ConnectBlock sees).
// spend, when non-nil, adds a second tx spending that outpoint (used to make a
// block whose input is absent from the UTXO set).
func mkBlock(t *testing.T, params *consensus.ChainParams, prev *consensus.BlockNode, salt byte, overpay int64, spend *wire.OutPoint) *wire.MsgBlock {
	t.Helper()
	h := prev.Height + 1
	if h < 1 || h > 16 {
		t.Fatalf("mkBlock: height %d outside the OP_N BIP34 range this helper encodes", h)
	}
	cb := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0xFFFFFFFF},
			SignatureScript:  []byte{byte(0x50 + h), salt, salt},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: consensus.CalcBlockSubsidyForInterval(h, params.SubsidyHalvingInterval) + overpay, PkScript: []byte{0x51}}},
	}
	txs := []*wire.MsgTx{cb}
	if spend != nil {
		txs = append(txs, &wire.MsgTx{
			Version:  1,
			TxIn:     []*wire.TxIn{{PreviousOutPoint: *spend, SignatureScript: []byte{0x51}, Sequence: 0xFFFFFFFF}},
			TxOut:    []*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}},
			LockTime: 0,
		})
	}
	hashes := make([]wire.Hash256, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.TxHash()
	}
	hdr := wire.BlockHeader{
		Version:    4,
		PrevBlock:  prev.Hash,
		MerkleRoot: consensus.CalcMerkleRoot(hashes),
		Timestamp:  prev.Header.Timestamp + 600,
		Bits:       params.PowLimitBits,
	}
	target := consensus.CompactToBig(hdr.Bits)
	for i := uint32(0); i < 10_000_000; i++ {
		hdr.Nonce = i
		if consensus.HashToBig(hdr.BlockHash()).Cmp(target) <= 0 {
			break
		}
	}
	return &wire.MsgBlock{Header: hdr, Transactions: txs}
}

type invalidBlockRig struct {
	t      *testing.T
	params *consensus.ChainParams
	idx    *consensus.HeaderIndex
	db     *storage.ChainDB
	cm     *consensus.ChainManager
	sm     *SyncManager
}

// newInvalidBlockRig: real ChainManager (production code path, not a mock),
// post-IBD, active chain genesis..A3 connected.
func newInvalidBlockRig(t *testing.T) (*invalidBlockRig, *consensus.BlockNode) {
	t.Helper()
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db, UTXOSet: consensus.NewUTXOSet(db),
	})
	cm.SetIBD(false)
	r := &invalidBlockRig{t: t, params: params, idx: idx, db: db, cm: cm}
	idx.MarkDataStored(idx.Genesis().Hash)
	tip := idx.Genesis()
	for i := 0; i < 3; i++ {
		b := mkBlock(t, params, tip, 0xA0, 0, nil)
		r.stage(b)
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("connect A%d: %v", i+1, err)
		}
		tip = idx.GetNode(b.Header.BlockHash())
	}
	r.sm = NewSyncManager(SyncManagerConfig{ChainParams: params, HeaderIndex: idx, ChainManager: cm, ChainDB: db})
	t.Cleanup(func() { close(r.sm.quit) })
	return r, tip
}

func (r *invalidBlockRig) header(b *wire.MsgBlock) *consensus.BlockNode {
	r.t.Helper()
	n, err := r.idx.AddHeader(b.Header, true)
	if err != nil {
		r.t.Fatalf("AddHeader: %v", err)
	}
	return n
}

// stage = header + body on disk (what HandleBlock does before validation).
func (r *invalidBlockRig) stage(b *wire.MsgBlock) *consensus.BlockNode {
	r.t.Helper()
	n := r.idx.GetNode(b.Header.BlockHash())
	if n == nil {
		n = r.header(b)
	}
	if err := r.db.StoreBlock(n.Hash, b); err != nil {
		r.t.Fatalf("StoreBlock: %v", err)
	}
	r.idx.MarkDataStored(n.Hash)
	return n
}

func (r *invalidBlockRig) queued() map[wire.Hash256]bool {
	r.sm.mu.RLock()
	defer r.sm.mu.RUnlock()
	out := map[wire.Hash256]bool{}
	for _, req := range r.sm.blockQueue {
		out[req.Hash] = true
	}
	return out
}

func (r *invalidBlockRig) deliver(pending map[int32]*blockWithRequest, b *wire.MsgBlock, from *Peer) {
	n := r.stage(b)
	pending[n.Height] = &blockWithRequest{
		block: b,
		req:   &blockRequest{Hash: n.Hash, Height: n.Height, State: BlockDownloadValidated},
		from:  from,
	}
}

// TestInvalidBlockP2P_BeforeScenario_MarksPunishesAndFetchesCompetitor is the
// regression for the [CHAINSTATE-CORRUPTION] halt on a peer-delivered
// consensus-invalid block (instrument p2p-invalid-block-feed.py, scenario
// "before", invalid=badcb).
//
//	genesis - A1 - A2 - A3 (tip) - B1  (bad-cb-amount, from attacker X)
//	                            \- B1' - B2' (valid, honest H; heavier)
//
// Pre-fix: ProcessSubmittedBlock(B1) failed, the connect loop latched
// chainstateCorrupted, did NOT mark B1, and every later block was refused
// until a restart. Core (InvalidBlockFound + MaybePunishNodeForBlock): mark B1
// failed, punish X, fetch B1'/B2' and follow the valid chain.
func TestInvalidBlockP2P_BeforeScenario_MarksPunishesAndFetchesCompetitor(t *testing.T) {
	r, a3 := newInvalidBlockRig(t)
	x := &Peer{addr: "127.0.0.2:40000"}

	b1 := mkBlock(t, r.params, a3, 0xB1, 1, nil) // coinbase overpays by 1 sat
	b1n := r.header(b1)
	r.sm.StartBlockDownload()
	if q := r.queued(); !q[b1n.Hash] || len(q) != 1 {
		t.Fatalf("setup: queue should be exactly [B1], got %d entries", len(q))
	}

	// Honest competitor headers arrive (B1' equal work, B2' heavier).
	b1v := mkBlock(t, r.params, a3, 0xC1, 0, nil)
	b1vn := r.header(b1v)
	b2v := mkBlock(t, r.params, b1vn, 0xC2, 0, nil)
	b2vn := r.header(b2v)

	pending := map[int32]*blockWithRequest{}
	r.deliver(pending, b1, x)
	r.sm.connectPendingBlocks(pending)

	if r.sm.chainstateCorrupted.Load() {
		t.Fatal("chainstateCorrupted latched on a consensus-invalid peer block — the node halts (pre-fix behaviour)")
	}
	if b1n.Status&consensus.StatusInvalid == 0 {
		t.Fatal("B1 was not marked StatusInvalid")
	}
	if !x.ShouldBan() {
		t.Fatal("the peer that delivered B1 was not punished")
	}
	if got := r.idx.BestTip(); got != b2vn {
		t.Fatalf("best header = %v (h=%d), want B2' (the most-work valid header)", got.Hash, got.Height)
	}
	q := r.queued()
	if q[b1n.Hash] {
		t.Fatal("B1 is still queued for download after being marked invalid (would be re-requested)")
	}
	if !q[b1vn.Hash] || !q[b2vn.Hash] {
		t.Fatalf("competitor not queued: B1'=%v B2'=%v", q[b1vn.Hash], q[b2vn.Hash])
	}
	if fails, err := r.db.ReadBlockFailures(); err != nil || len(fails) == 0 {
		t.Fatalf("B1's failure flag was not persisted (fails=%v err=%v)", fails, err)
	}

	// A later announcement / re-delivery of B1 must not be fetched or
	// processed: it can never be queued again (not on the best header chain)…
	r.sm.StartBlockDownload()
	if r.queued()[b1n.Hash] {
		t.Fatal("B1 re-queued by a later StartBlockDownload")
	}
	// …and a header extending it is refused (Core bad-prevblk).
	if _, err := r.idx.AddHeader(mkBlock(t, r.params, b1n, 0xB2, 0, nil).Header, true); err != consensus.ErrInvalidParentHeader {
		t.Fatalf("header on top of invalid B1: err=%v, want ErrInvalidParentHeader", err)
	}

	// The valid chain connects.
	r.deliver(pending, b1v, nil)
	r.deliver(pending, b2v, nil)
	r.sm.connectPendingBlocks(pending)
	if h, ht := r.cm.BestBlock(); h != b2vn.Hash || ht != 5 {
		t.Fatalf("tip = h%d, want B2' at h5", ht)
	}
}

// TestInvalidBlockP2P_AfterScenario_FailedReorgDoesNotHalt: B1' is the tip,
// the attacker delivers B1 (equal work, stored side-branch) then B2x on top of
// it (heavier). The reorg fails on B1; ReorgTo rolls back to B1' and marks B1
// (+B2x as invalid-child). The connect loop must NOT latch, and a later
// heavier VALID block must still connect (recovers_with_heavier_chain).
func TestInvalidBlockP2P_AfterScenario_FailedReorgDoesNotHalt(t *testing.T) {
	runAfterScenario(t, false)
}

// Same, with the node still in IBD (instrument after/bip68 uses a corpus
// prefix whose tip is old). Pre-fix the IBD connect path fed the sibling B1 to
// raw ConnectBlock ("does not connect to tip during IBD"), and the cascade
// handler evicted + re-fetched it every 100 ms forever, wedging the cursor so
// the valid B2' never connected either.
func TestInvalidBlockP2P_AfterScenario_DuringIBD(t *testing.T) {
	runAfterScenario(t, true)
}

func runAfterScenario(t *testing.T, ibd bool) {
	r, a3 := newInvalidBlockRig(t)
	r.cm.SetIBD(ibd)
	x := &Peer{addr: "127.0.0.2:40001"}

	b1v := mkBlock(t, r.params, a3, 0xC1, 0, nil)
	pending := map[int32]*blockWithRequest{}
	r.sm.mu.Lock()
	r.sm.nextHeight = 4
	r.sm.mu.Unlock()
	r.deliver(pending, b1v, nil)
	r.sm.connectPendingBlocks(pending)
	b1vn := r.idx.GetNode(b1v.Header.BlockHash())
	if h, _ := r.cm.BestBlock(); h != b1vn.Hash {
		t.Fatal("setup: B1' did not become the tip")
	}

	b1 := mkBlock(t, r.params, a3, 0xB1, 1, nil)
	b1n := r.stage(b1)
	b2x := mkBlock(t, r.params, b1n, 0xB2, 0, nil)
	r.sm.mu.Lock()
	r.sm.nextHeight = 4
	r.sm.mu.Unlock()
	r.deliver(pending, b1, x)
	r.deliver(pending, b2x, x)
	r.sm.connectPendingBlocks(pending)

	b2xn := r.idx.GetNode(b2x.Header.BlockHash())
	if r.sm.chainstateCorrupted.Load() {
		t.Fatal("chainstateCorrupted latched after a failed reorg onto an invalid branch")
	}
	if b1n.Status&consensus.StatusInvalid == 0 || !b2xn.Status.IsInvalid() {
		t.Fatalf("B1/B2x not marked: B1=%v B2x=%v", b1n.Status, b2xn.Status)
	}
	if !x.ShouldBan() {
		t.Fatal("attacker not punished")
	}
	if h, _ := r.cm.BestBlock(); h != b1vn.Hash {
		t.Fatal("tip did not stay on B1' after the failed reorg")
	}

	b2v := mkBlock(t, r.params, b1vn, 0xC2, 0, nil)
	b2vn := r.header(b2v)
	if got := r.idx.BestTip(); got != b2vn {
		t.Fatalf("best header after B2' = h%d, want B2'", got.Height)
	}
	r.deliver(pending, b2v, nil)
	r.sm.mu.Lock()
	r.sm.nextHeight = 5
	r.sm.mu.Unlock()
	r.sm.connectPendingBlocks(pending)
	if h, _ := r.cm.BestBlock(); h != b2vn.Hash {
		t.Fatal("a heavier valid block did not connect after the invalid branch was rejected")
	}
}

// TestInvalidBlockP2P_MissingUTXOStillHaltsUnmarked: a block whose input is
// absent from the local UTXO set is NOT a verdict on the active-tip connect
// path (blockbrew's documented local-UTXO-damage divergence): no invalid mark,
// no peer punishment, and the loud halt is kept.
func TestInvalidBlockP2P_MissingUTXOStillHaltsUnmarked(t *testing.T) {
	r, a3 := newInvalidBlockRig(t)
	x := &Peer{addr: "127.0.0.2:40002"}
	ghost := &wire.OutPoint{Hash: wire.Hash256{0xde, 0xad}, Index: 0}
	b1 := mkBlock(t, r.params, a3, 0xB1, 0, ghost)
	pending := map[int32]*blockWithRequest{}
	r.sm.mu.Lock()
	r.sm.nextHeight = 4
	r.sm.mu.Unlock()
	r.deliver(pending, b1, x)
	r.sm.connectPendingBlocks(pending)

	b1n := r.idx.GetNode(b1.Header.BlockHash())
	if b1n.Status.IsInvalid() {
		t.Fatal("missing-UTXO failure marked the block invalid — a local-state gap must never blacklist a block")
	}
	if x.ShouldBan() {
		t.Fatal("peer punished for a missing-UTXO (local-state) failure")
	}
	if !r.sm.chainstateCorrupted.Load() {
		t.Fatal("missing-UTXO failure no longer halts loudly (the deliberate divergence was lost)")
	}
}

// TestInvalidBlockP2P_MissingAncestorIsDeferredNotMarked: a connect that cannot
// be decided yet (ErrMissingAncestorHeader) is kept pending: no mark, no
// punishment, no halt.
func TestInvalidBlockP2P_MissingAncestorIsDeferredNotMarked(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	main := addChain(t, idx, idx.Genesis(), 3, 1)
	b := main[2]
	mock := &mockChainConnector{tipHash: main[1].Hash, tipHeight: 2, postIBD: true}
	mock.processFn = func(*wire.MsgBlock) error {
		return &wrapErr{consensus.ErrMissingAncestorHeader}
	}
	sm := NewSyncManager(SyncManagerConfig{ChainParams: params, HeaderIndex: idx, ChainManager: mock})
	defer close(sm.quit)
	x := &Peer{addr: "127.0.0.2:40003"}
	sm.mu.Lock()
	sm.nextHeight = 3
	sm.mu.Unlock()
	pending := map[int32]*blockWithRequest{3: {
		block: &wire.MsgBlock{Header: b.Header},
		req:   &blockRequest{Hash: b.Hash, Height: 3, State: BlockDownloadValidated},
		from:  x,
	}}
	sm.connectPendingBlocks(pending)
	if b.Status.IsInvalid() || x.ShouldBan() || sm.chainstateCorrupted.Load() {
		t.Fatalf("missing-ancestor deferral produced a verdict: invalid=%v punished=%v halted=%v",
			b.Status.IsInvalid(), x.ShouldBan(), sm.chainstateCorrupted.Load())
	}
	if _, still := pending[3]; !still {
		t.Fatal("deferred block was dropped from pending instead of retried")
	}
}

type wrapErr struct{ inner error }

func (e *wrapErr) Error() string { return "block deferred: " + e.inner.Error() }
func (e *wrapErr) Unwrap() error { return e.inner }
