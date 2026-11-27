package p2p

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Core serves a block by hash only if BlockRequestAllowed says so
// (net_processing.cpp ProcessGetBlockData): the block is on the active chain,
// or it is BLOCK_VALID_SCRIPTS and within STALE_RELAY_AGE_LIMIT (30 days) of
// the best header. Anything else is ignored: no block, no notfound.
// blockbrew's serveGetDataBlock served any block it had on disk, so a failed
// or never-validated side-branch block was relayed to whoever asked, and the
// answer told a peer which forks we had seen.

// coreStaleRelayAgeLimit is Core's STALE_RELAY_AGE_LIMIT, spelled out here
// so this file builds on a base without the fix.
const coreStaleRelayAgeLimit = 30 * 24 * 60 * 60

// servedBlocks collects the hashes of every block (full or compact) the peer
// has been sent until want arrives or the deadline passes. want is a control
// item queued AFTER the items under test: getdata items are served in order,
// so once it arrives every earlier item has had its turn.
func servedBlocks(t *testing.T, peer *Peer, want wire.Hash256) map[wire.Hash256]bool {
	t.Helper()
	served := map[wire.Hash256]bool{}
	deadline := time.Now().Add(5 * time.Second)
	for !served[want] && time.Now().Before(deadline) {
		for _, m := range drainSent(peer) {
			switch msg := m.(type) {
			case *MsgBlock:
				served[msg.Block.Header.BlockHash()] = true
			case *MsgCmpctBlock:
				served[msg.Header.BlockHash()] = true
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !served[want] {
		t.Fatalf("control block %s on the active chain was never served", want.String()[:16])
	}
	return served
}

// newFailedSideBlockRig builds, on a real ChainManager:
//
//	genesis - A1 - A2 - A3 - B1' (active tip)
//	                      \- B1 (bad-cb-amount, marked failed) - B2x
//
// the same failed-reorg path as runAfterScenario, and returns the rig, the
// failed B1 and the active tip B1'.
func newFailedSideBlockRig(t *testing.T) (*invalidBlockRig, *consensus.BlockNode, *consensus.BlockNode) {
	t.Helper()
	r, a3 := newInvalidBlockRig(t)
	pending := map[int32]*blockWithRequest{}

	b1v := mkBlock(t, r.params, a3, 0xC1, 0, nil)
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
	r.deliver(pending, b1, &Peer{addr: "127.0.0.2:40001"})
	r.deliver(pending, b2x, &Peer{addr: "127.0.0.2:40001"})
	r.sm.connectPendingBlocks(pending)
	if b1n.Status&consensus.StatusInvalid == 0 {
		t.Fatalf("setup: B1 not marked failed (status %v)", b1n.Status)
	}
	if b1n.Status&consensus.StatusDataStored == 0 {
		t.Fatal("setup: B1's body is not stored, so the test could not tell refusal from a miss")
	}
	if _, err := r.db.GetBlock(b1n.Hash); err != nil {
		t.Fatalf("setup: B1 not readable from the block store: %v", err)
	}
	if h, _ := r.cm.BestBlock(); h != b1vn.Hash {
		t.Fatal("setup: tip left B1'")
	}
	return r, b1n, b1vn
}

// TestGetDataRefusesFailedSideBlock: a getdata for a stored side-branch block
// that failed validation must not be answered with the block, in any of the
// three block inv types. The active tip, asked for after it, is served.
func TestGetDataRefusesFailedSideBlock(t *testing.T) {
	r, b1, b1v := newFailedSideBlockRig(t)
	peer := createMockPeer("6.6.6.6:8333", 100)
	defer close(peer.quit)

	r.sm.HandleGetData(peer, &MsgGetData{InvList: []*InvVect{
		{Type: InvTypeWitnessBlock, Hash: b1.Hash},
		{Type: InvTypeBlock, Hash: b1.Hash},
		{Type: InvTypeCmpctBlock, Hash: b1.Hash},
		{Type: InvTypeWitnessBlock, Hash: b1v.Hash},
	}})
	served := servedBlocks(t, peer, b1v.Hash)
	if served[b1.Hash] {
		t.Fatal("getdata served a side-branch block that failed validation; Core's BlockRequestAllowed refuses it")
	}
}

// TestGetDataRefusesUnvalidatedSideBlock: a side-branch block whose header and
// body are stored but which was never connected is not BLOCK_VALID_SCRIPTS,
// so it is not served either.
func TestGetDataRefusesUnvalidatedSideBlock(t *testing.T) {
	r, a3 := newInvalidBlockRig(t)
	a1 := a3.GetAncestor(1)
	side := r.stage(mkBlock(t, r.params, a1, 0xD2, 0, nil))
	if side.Status&consensus.StatusFullyValid != 0 || side.Status.IsInvalid() {
		t.Fatalf("setup: side block status %v, want stored but never validated", side.Status)
	}
	peer := createMockPeer("6.6.6.6:8333", 100)
	defer close(peer.quit)

	r.sm.HandleGetData(peer, &MsgGetData{InvList: []*InvVect{
		{Type: InvTypeWitnessBlock, Hash: side.Hash},
		{Type: InvTypeWitnessBlock, Hash: a3.Hash},
	}})
	if served := servedBlocks(t, peer, a3.Hash); served[side.Hash] {
		t.Fatal("getdata served a side-branch block that was never validated")
	}
}

// newStaleValidRig connects genesis-A1-A2-A3, then reorgs onto a heavier
// branch C3-C4 forking at A2, so A3 was fully validated once and is now a
// stale block off the active chain. It returns the rig, A3 and the tip C4.
func newStaleValidRig(t *testing.T) (*invalidBlockRig, *consensus.BlockNode, *consensus.BlockNode) {
	t.Helper()
	r, a3 := newInvalidBlockRig(t)
	a2 := a3.GetAncestor(2)
	c3 := mkBlock(t, r.params, a2, 0xE3, 0, nil)
	r.stage(c3)
	if err := r.cm.ProcessSubmittedBlock(c3); err != nil && err != consensus.ErrSideBranchAccepted {
		t.Fatalf("setup: C3: %v", err)
	}
	c3n := r.idx.GetNode(c3.Header.BlockHash())
	c4 := mkBlock(t, r.params, c3n, 0xE4, 0, nil)
	c4n := r.stage(c4)
	if err := r.cm.ProcessSubmittedBlock(c4); err != nil {
		t.Fatalf("setup: C4: %v", err)
	}
	if h, _ := r.cm.BestBlock(); h != c4n.Hash {
		t.Fatal("setup: did not reorg onto C4")
	}
	if a3.Status&consensus.StatusFullyValid == 0 || a3.Status.IsInvalid() {
		t.Fatalf("setup: stale A3 status %v, want fully valid", a3.Status)
	}
	return r, a3, c4n
}

// TestGetDataServesRecentValidStaleBlock: Core still serves a stale block that
// passed full validation if it is recent (a peer may be reorging through it).
// The check must not refuse that.
func TestGetDataServesRecentValidStaleBlock(t *testing.T) {
	r, a3, c4 := newStaleValidRig(t)
	peer := createMockPeer("6.6.6.6:8333", 100)
	defer close(peer.quit)

	r.sm.HandleGetData(peer, &MsgGetData{InvList: []*InvVect{
		{Type: InvTypeWitnessBlock, Hash: a3.Hash},
		{Type: InvTypeWitnessBlock, Hash: c4.Hash},
	}})
	if served := servedBlocks(t, peer, c4.Hash); !served[a3.Hash] {
		t.Fatal("getdata refused a recent, fully-validated stale block that Core serves")
	}
}

// TestGetDataRefusesOldStaleBlock: once the best header is 30 days past a
// stale block, Core stops serving it. An active-chain block just as old is
// still served.
func TestGetDataRefusesOldStaleBlock(t *testing.T) {
	r, a3, c4 := newStaleValidRig(t)
	hdr := wire.BlockHeader{
		Version:   4,
		PrevBlock: c4.Hash,
		Timestamp: a3.Header.Timestamp + coreStaleRelayAgeLimit + 3600,
		Bits:      r.params.PowLimitBits,
	}
	mineRegtestHeader(&hdr)
	if _, err := r.idx.AddHeader(hdr, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if best := r.idx.BestTip(); best.Hash != hdr.BlockHash() {
		t.Fatal("setup: the 30-days-later header is not the best header")
	}
	a2 := a3.GetAncestor(2)
	peer := createMockPeer("6.6.6.6:8333", 100)
	defer close(peer.quit)

	r.sm.HandleGetData(peer, &MsgGetData{InvList: []*InvVect{
		{Type: InvTypeWitnessBlock, Hash: a3.Hash},
		{Type: InvTypeWitnessBlock, Hash: a2.Hash},
	}})
	if served := servedBlocks(t, peer, a2.Hash); served[a3.Hash] {
		t.Fatal("getdata served a stale block more than STALE_RELAY_AGE_LIMIT behind the best header")
	}
}

// TestDeepGetBlockTxnRefusesFailedSideBlock: a getblocktxn for a block more
// than MAX_BLOCKTXN_DEPTH deep is answered through the getdata path with the
// full block, so the same check must hold there: a failed side-branch block
// 11 deep is not sent. An active-chain block deeper still is.
func TestDeepGetBlockTxnRefusesFailedSideBlock(t *testing.T) {
	r, b1, tip := newFailedSideBlockRig(t)
	for i := 0; i < MaxBlocktxnDepth+1; i++ {
		b := mkBlock(t, r.params, tip, byte(0x10+i), 0, nil)
		r.stage(b)
		if err := r.cm.ConnectBlock(b); err != nil {
			t.Fatalf("setup: extend tip: %v", err)
		}
		tip = r.idx.GetNode(b.Header.BlockHash())
	}
	if depth, _ := r.sm.blockDepth(b1.Hash); depth <= MaxBlocktxnDepth {
		t.Fatalf("setup: B1 is %d deep, want > %d", depth, MaxBlocktxnDepth)
	}
	a1 := tip.GetAncestor(1)
	peer := createMockPeer("6.6.6.6:8333", 100)
	defer close(peer.quit)

	r.sm.HandleGetBlockTxn(peer, &MsgGetBlockTxn{BlockHash: b1.Hash, Indexes: []uint32{0}})
	r.sm.HandleGetBlockTxn(peer, &MsgGetBlockTxn{BlockHash: a1.Hash, Indexes: []uint32{0}})
	if served := servedBlocks(t, peer, a1.Hash); served[b1.Hash] {
		t.Fatal("deep getblocktxn served a side-branch block that failed validation")
	}
}

// TestGetDataRefusesStaleBlockByProofTime: the second age clause. The best
// header is only minutes past the stale block by header time, but carries more
// than 30 days of block production in extra work (regtest: 600 s per block),
// so Core's GetBlockProofEquivalentTime clause refuses the stale block.
func TestGetDataRefusesStaleBlockByProofTime(t *testing.T) {
	r, a3, c4 := newStaleValidRig(t)
	prev := c4.Hash
	ts := c4.Header.Timestamp
	// best - A3 = 1 (C4 over A2-A3's height) + n blocks; refused once
	// (1+n)*600 >= 30 days, i.e. n >= 4319.
	const n = coreStaleRelayAgeLimit/600 + 1
	for i := 0; i < n; i++ {
		ts++
		hdr := wire.BlockHeader{Version: 4, PrevBlock: prev, Timestamp: ts, Bits: r.params.PowLimitBits}
		mineRegtestHeader(&hdr)
		if _, err := r.idx.AddHeader(hdr, true); err != nil {
			t.Fatalf("AddHeader %d: %v", i, err)
		}
		prev = hdr.BlockHash()
	}
	best := r.idx.BestTip()
	if best.Hash != prev {
		t.Fatal("setup: the long header run is not the best header")
	}
	if dt := int64(best.Header.Timestamp) - int64(a3.Header.Timestamp); dt >= coreStaleRelayAgeLimit/100 {
		t.Fatalf("setup: header time gap %d s, want far under 30 days so only the work clause applies", dt)
	}
	a2 := a3.GetAncestor(2)
	peer := createMockPeer("6.6.6.6:8333", 100)
	defer close(peer.quit)

	r.sm.HandleGetData(peer, &MsgGetData{InvList: []*InvVect{
		{Type: InvTypeWitnessBlock, Hash: a3.Hash},
		{Type: InvTypeWitnessBlock, Hash: a2.Hash},
	}})
	if served := servedBlocks(t, peer, a2.Hash); served[a3.Hash] {
		t.Fatal("getdata served a stale block more than 30 days of proof-equivalent time behind the best header")
	}
}

// TestGetDataRefusesUnindexedBlock: a block body in the store whose header is
// not in the index (Core: LookupBlockIndex misses) is not served.
func TestGetDataRefusesUnindexedBlock(t *testing.T) {
	r, a3 := newInvalidBlockRig(t)
	orphan := getDataTestBlock(7)
	hash := orphan.Header.BlockHash()
	if err := r.db.StoreBlock(hash, orphan); err != nil {
		t.Fatalf("StoreBlock: %v", err)
	}
	if r.idx.GetNode(hash) != nil {
		t.Fatal("setup: orphan block is indexed")
	}
	peer := createMockPeer("6.6.6.6:8333", 100)
	defer close(peer.quit)

	r.sm.HandleGetData(peer, &MsgGetData{InvList: []*InvVect{
		{Type: InvTypeWitnessBlock, Hash: hash},
		{Type: InvTypeWitnessBlock, Hash: a3.Hash},
	}})
	if served := servedBlocks(t, peer, a3.Hash); served[hash] {
		t.Fatal("getdata served a block that is not in the header index")
	}
}

// TestGetDataRefusesInvalidatedStaleBlock: a stale block that passed full
// validation and was then marked failed (invalidateblock) keeps its
// fully-validated flag, but Core's IsValid(BLOCK_VALID_SCRIPTS) is false for a
// failed block, so it is not served.
func TestGetDataRefusesInvalidatedStaleBlock(t *testing.T) {
	r, a3, c4 := newStaleValidRig(t)
	if err := r.cm.InvalidateBlock(a3.Hash); err != nil {
		t.Fatalf("InvalidateBlock(A3): %v", err)
	}
	if a3.Status&consensus.StatusFullyValid == 0 || !a3.Status.IsInvalid() {
		t.Fatalf("setup: A3 status %v, want fully-validated and marked failed", a3.Status)
	}
	if h, _ := r.cm.BestBlock(); h != c4.Hash {
		t.Fatal("setup: invalidating the stale A3 moved the tip")
	}
	peer := createMockPeer("6.6.6.6:8333", 100)
	defer close(peer.quit)

	r.sm.HandleGetData(peer, &MsgGetData{InvList: []*InvVect{
		{Type: InvTypeWitnessBlock, Hash: a3.Hash},
		{Type: InvTypeWitnessBlock, Hash: c4.Hash},
	}})
	if served := servedBlocks(t, peer, c4.Hash); served[a3.Hash] {
		t.Fatal("getdata served a stale block marked failed by invalidateblock")
	}
}
