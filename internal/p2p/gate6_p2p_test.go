package p2p

// Gate 6 at the P2P layer (receipts/gate6-resource-limit-audit-2026-10-04.md,
// blockbrew): a system fault while connecting a peer's block must never mark
// the block failed or punish the peer, and a panic mid-connect must halt block
// connection instead of resuming on a torn view.

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// newGate6P2PRig is newInvalidBlockRig on a FaultDB with an empty coin cache
// (every coin read is a real database read), plus one planted, durable,
// spendable (OP_TRUE) coin.
func newGate6P2PRig(t *testing.T) (*invalidBlockRig, *storage.FaultDB, *consensus.BlockNode, wire.OutPoint) {
	t.Helper()
	consensus.ResetAbortForTesting()
	t.Cleanup(consensus.ResetAbortForTesting)
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	fdb := storage.NewFaultDB(storage.NewMemDB())
	db := storage.NewChainDB(fdb)
	utxo := consensus.NewUTXOSetWithMaxCache(db, 0)
	cm := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: db, UTXOSet: utxo,
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
	coin := wire.OutPoint{Hash: wire.Hash256{0x6a, 0x7e, 0x60}, Index: 0}
	utxo.AddUTXO(coin, &consensus.UTXOEntry{Amount: 50_000, PkScript: []byte{0x51}, Height: 1})
	if err := utxo.Flush(); err != nil {
		t.Fatalf("plant: %v", err)
	}
	r.sm = NewSyncManager(SyncManagerConfig{ChainParams: params, HeaderIndex: idx, ChainManager: cm, ChainDB: db})
	t.Cleanup(func() { close(r.sm.quit) })
	return r, fdb, tip, coin
}

// Reorg onto a heavier branch whose first block spends a cold coin the
// database fails to read. Pre-fix: GetUTXO -> nil -> missing-inputs ->
// reorg verdict: branch marked (persisted) and the delivering peer banned.
func TestGate6P2P_ReorgCoinReadErrorNeitherMarksNorPunishes(t *testing.T) {
	r, fdb, a3, coin := newGate6P2PRig(t)
	x := &Peer{addr: "127.0.0.2:41000"}
	a2 := a3.Parent

	// Competing branch from A2: B3 (spends coin) - B4 (heavier than A3).
	b3 := mkBlock(t, r.params, a2, 0xB3, 0, &coin)
	b3n := r.stage(b3)
	b4 := mkBlock(t, r.params, b3n, 0xB4, 0, nil)

	fdb.FailGet(storage.MakeUTXOKey(coin), nil)
	pending := map[int32]*blockWithRequest{}
	r.sm.mu.Lock()
	r.sm.nextHeight = 3
	r.sm.mu.Unlock()
	r.deliver(pending, b3, x)
	r.deliver(pending, b4, x)
	r.sm.connectPendingBlocks(pending)

	b4n := r.idx.GetNode(b4.Header.BlockHash())
	if fdb.ReadsFailed() == 0 {
		t.Fatal("instrument: the read fault never fired (the reorg never read the coin)")
	}
	if b3n.Status.IsInvalid() || b4n.Status.IsInvalid() {
		t.Fatalf("branch marked invalid because the coins DB could not be read (B3=%v B4=%v)", b3n.Status, b4n.Status)
	}
	if fails, _ := r.db.ReadBlockFailures(); len(fails) != 0 {
		t.Fatalf("failure flag persisted for a read error: %v", fails)
	}
	if x.ShouldBan() {
		t.Fatal("peer punished for OUR coins-DB read error")
	}
	if !consensus.IsAborted() {
		t.Error("coins-DB read error did not latch AbortNode")
	}
	if h, _ := r.cm.BestBlock(); h != a3.Hash {
		t.Error("tip did not stay on A3")
	}
}

// Control: the same branch spending a coin that genuinely does not exist is a
// verdict — marked and the peer punished.
func TestGate6P2P_Control_ReorgMissingCoinMarksAndPunishes(t *testing.T) {
	r, _, a3, _ := newGate6P2PRig(t)
	x := &Peer{addr: "127.0.0.2:41001"}
	ghost := wire.OutPoint{Hash: wire.Hash256{0xde, 0xad, 0x01}, Index: 0}
	b3 := mkBlock(t, r.params, a3.Parent, 0xB3, 0, &ghost)
	b3n := r.stage(b3)
	b4 := mkBlock(t, r.params, b3n, 0xB4, 0, nil)
	pending := map[int32]*blockWithRequest{}
	r.sm.mu.Lock()
	r.sm.nextHeight = 3
	r.sm.mu.Unlock()
	r.deliver(pending, b3, x)
	r.deliver(pending, b4, x)
	r.sm.connectPendingBlocks(pending)
	if !b3n.Status.IsInvalid() {
		t.Fatal("branch spending a non-existent coin was not marked")
	}
	if !x.ShouldBan() {
		t.Fatal("peer delivering a branch spending a non-existent coin was not punished")
	}
	if consensus.IsAborted() {
		t.Error("a genuine consensus failure latched AbortNode")
	}
}

// A panic while connecting a peer's block (here: on reading its prevout).
// Pre-fix the connect loop's recover turned it into an ordinary error and the
// node ran on with a torn view (later flushed at shutdown). Now: AbortNode,
// no mark, no punishment, and no further block is connected.
func TestGate6P2P_PanicMidConnectHaltsWithoutVerdict(t *testing.T) {
	r, fdb, a3, coin := newGate6P2PRig(t)
	x := &Peer{addr: "127.0.0.2:41002"}
	b4 := mkBlock(t, r.params, a3, 0xB4, 0, &coin)
	fdb.PanicOnGet(storage.MakeUTXOKey(coin), "gate6 test: injected panic mid-connect")
	pending := map[int32]*blockWithRequest{}
	r.sm.mu.Lock()
	r.sm.nextHeight = 4
	r.sm.mu.Unlock()
	r.deliver(pending, b4, x)
	r.sm.connectPendingBlocks(pending)
	fdb.ClearFaults()

	b4n := r.idx.GetNode(b4.Header.BlockHash())
	if !consensus.IsAborted() {
		t.Fatal("a panic mid-connect did not latch AbortNode — the node resumes on a torn view")
	}
	if b4n.Status.IsInvalid() {
		t.Error("block marked invalid because WE panicked")
	}
	if x.ShouldBan() {
		t.Error("peer punished because WE panicked")
	}

	// Nothing more is connected: a valid block on A3 delivered now stays put.
	b4v := mkBlock(t, r.params, a3, 0xC4, 0, nil)
	r.sm.mu.Lock()
	r.sm.nextHeight = 4
	r.sm.mu.Unlock()
	delete(pending, 4)
	r.deliver(pending, b4v, nil)
	r.sm.connectPendingBlocks(pending)
	if h, _ := r.cm.BestBlock(); h != a3.Hash {
		t.Fatal("a block was connected after a panic mid-connect (no halt)")
	}
}

// Audit B2: a body whose timestamp is too far in the future (wall clock) is
// Core's BLOCK_TIME_FUTURE: never marked, never punished. The validation
// worker used to mark it failed and Misbehaving(100) its sender.
func TestGate6P2P_TimeTooNewBodyIsNotPunished(t *testing.T) {
	r, _, a3, _ := newGate6P2PRig(t)
	x := &Peer{addr: "127.0.0.2:41003"}
	b := mkBlock(t, r.params, a3, 0xD4, 0, nil)
	b.Header.Timestamp = uint32(time.Now().Unix() + 3*3600)
	target := consensus.CompactToBig(b.Header.Bits)
	for i := uint32(0); ; i++ {
		b.Header.Nonce = i
		if consensus.HashToBig(b.Header.BlockHash()).Cmp(target) <= 0 {
			break
		}
	}
	req := &blockRequest{Hash: b.Header.BlockHash(), Height: 4, State: BlockDownloadInFlight}
	r.sm.wg.Add(1)
	go r.sm.validationWorker()
	r.sm.validationChan <- &blockWithRequest{block: b, req: req, from: x}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r.sm.mu.RLock()
		st := req.State
		r.sm.mu.RUnlock()
		if x.ShouldBan() || st != BlockDownloadInFlight {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if x.ShouldBan() {
		t.Fatal("peer punished for a block that is merely early (time-too-new)")
	}
	r.sm.mu.RLock()
	st := req.State
	r.sm.mu.RUnlock()
	if st != BlockDownloadPending {
		t.Fatalf("time-too-new block state = %v, want re-queued (pending)", st)
	}
}
