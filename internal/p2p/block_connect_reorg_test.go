package p2p

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestConnectPendingBlocks_BelowTipHeavierForkReorgs is the part-2 regression
// (reorg-drop fix). Part 1 made StartBlockDownload fetch competing-fork bodies
// below the active tip; runtime evidence then showed the P2P connect loop STILL
// did not reorg — it fed each fork body to the RAW ConnectBlock, which rejects
// (without storing) any block that does not extend the active tip and has less
// work. The fork blocks arrive bottom-up, each lighter than the active chain, so
// b1 was rejected forever and the side branch never accumulated.
//
// Part 2 routes the post-IBD connect through the side-branch-aware
// ProcessSubmittedBlock: each below-tip fork body is STORED
// (ErrSideBranchAccepted, a SUCCESS — cursor advances, tip stays put), and the
// fork tip — whose TotalWork now exceeds the active tip with its full ancestor
// chain stored — drives ReorgTo.
//
// Topology (regtest, equal-difficulty so height == work proxy):
//
//	genesis - 1 .. 10 (F, fork point; active chain 1..10 connected, tip=10)
//	                \- 11'.. 25' (heavier fork, NO bodies connected yet)
//
// We connect the fork bodies 11'..25' bottom-up. Heights 11'..24' are below/at
// the active tip work (10..24 height) — wait, the fork is taller, so each fork
// body's cumulative work only overtakes the active tip once the fork height
// exceeds 10. To exercise the genuine "stored as side branch, lighter than tip"
// path we make the active chain HEAVIER per-block via a deeper fork: fork point
// at height 10, active tip at height 20, fork tip at height 35. Fork bodies
// 11'..20' are at or below the active tip's work and MUST be stored
// (ErrSideBranchAccepted) without error; 21'..35' progressively overtake, and
// the first fork body whose cumulative work strictly exceeds the active tip
// triggers the reorg.
func TestConnectPendingBlocks_BelowTipHeavierForkReorgs(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// Active chain: genesis -> 1..20, all connected (bodies stored).
	main := addChain(t, idx, idx.Genesis(), 20, 1)
	const forkPointHeight = 10
	const activeTipHeight = 20
	forkPoint := main[forkPointHeight-1] // height 10
	activeTip := main[activeTipHeight-1] // height 20

	idx.MarkDataStored(idx.Genesis().Hash)
	for _, n := range main {
		idx.MarkDataStored(n.Hash)
	}

	// Heavier competing fork off the fork point: heights 11..35 (25 blocks).
	// 35 > 20 work => this becomes the header best tip.
	fork := addChain(t, idx, forkPoint, 25, 5_000_000)
	forkTip := fork[len(fork)-1]
	if forkTip.Height != 35 {
		t.Fatalf("fork tip height = %d, want 35", forkTip.Height)
	}

	// Model the real *consensus.ChainManager.ProcessSubmittedBlock semantics:
	//   - parent == active tip   -> extend (connect), advance tip.
	//   - side branch, work > tip -> ReorgTo (return nil), tip jumps to it.
	//   - side branch, work <= tip -> store, return ErrSideBranchAccepted.
	// Work is proxied by height on equal-difficulty regtest, matching the
	// header index TotalWork ordering used by the production code.
	mock := &mockChainConnector{
		tipHash:   activeTip.Hash,
		tipHeight: activeTipHeight,
		postIBD:   true, // at-tip / post-IBD: route through ProcessSubmittedBlock
	}

	var stored []int32 // heights stored as side branches (in arrival order)
	var reorgedTo int32 = -1
	mock.processFn = func(b *wire.MsgBlock) error {
		hash := b.Header.BlockHash()
		node := idx.GetNode(hash)
		if node == nil {
			t.Fatalf("connect of unknown block hash %x", hash[:8])
		}
		// Extension fast path: parent is the active tip.
		if node.Header.PrevBlock == mock.tipHash {
			mock.tipHash = node.Hash
			mock.tipHeight = node.Height
			return nil
		}
		// Side branch. Heavier than tip -> reorg; else store.
		tipNode := idx.GetNode(mock.tipHash)
		if node.TotalWork.Cmp(tipNode.TotalWork) > 0 {
			mock.tipHash = node.Hash
			mock.tipHeight = node.Height
			reorgedTo = node.Height
			return nil
		}
		stored = append(stored, node.Height)
		return consensus.ErrSideBranchAccepted
	}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  idx,
		ChainManager: mock,
	})
	defer close(sm.quit)

	// Seed the connect cursor at the first fork body above the fork point and
	// hand every fork body to the connect loop in ascending (bottom-up) order —
	// exactly how the download pipeline delivers them.
	sm.mu.Lock()
	sm.nextHeight = int32(forkPointHeight + 1)
	sm.mu.Unlock()

	pending := make(map[int32]*blockWithRequest)
	for _, n := range fork {
		pending[n.Height] = &blockWithRequest{
			block: &wire.MsgBlock{Header: n.Header},
			req:   &blockRequest{Hash: n.Hash, Height: n.Height, State: BlockDownloadReceived},
		}
	}

	sm.connectPendingBlocks(pending)

	// 1. The chainstate-corruption wedge must NOT have latched — a side-branch
	//    store is a success, never a validation failure (invariant 2).
	if sm.chainstateCorrupted.Load() {
		t.Fatalf("chainstateCorrupted latched on a side-branch store — wedge path wrongly triggered")
	}

	// 2. Every below/at-tip-work fork body (heights 11..20) must have been
	//    STORED as a side branch (ErrSideBranchAccepted), NOT rejected.
	wantStored := map[int32]bool{}
	for h := int32(forkPointHeight + 1); h <= activeTipHeight; h++ {
		wantStored[h] = true
	}
	gotStored := map[int32]bool{}
	for _, h := range stored {
		gotStored[h] = true
	}
	for h := range wantStored {
		if !gotStored[h] {
			t.Fatalf("fork body at height %d was NOT stored as a side branch — part 2 still open", h)
		}
	}

	// 3. The fork tip (or the first fork body that overtakes the active tip's
	//    work) must have triggered a reorg. The first overtaking height is
	//    activeTipHeight+1 == 21.
	if reorgedTo < 0 {
		t.Fatalf("no reorg was triggered — the heavier fork never overtook the active tip")
	}
	if reorgedTo != activeTipHeight+1 {
		t.Fatalf("reorg fired at height %d, want %d (first fork body exceeding the active tip work)",
			reorgedTo, activeTipHeight+1)
	}

	// 4. After the reorg + connecting the remaining fork bodies, the active tip
	//    must be the fork tip (height 35) — blockbrew switched to chain B.
	if mock.tipHeight != forkTip.Height || mock.tipHash != forkTip.Hash {
		t.Fatalf("final active tip = height %d (hash %x), want fork tip height %d (hash %x)",
			mock.tipHeight, mock.tipHash[:8], forkTip.Height, forkTip.Hash[:8])
	}

	// 5. The connect cursor advanced to one past the fork tip.
	sm.mu.RLock()
	nh := sm.nextHeight
	sm.mu.RUnlock()
	if nh != forkTip.Height+1 {
		t.Fatalf("nextHeight = %d, want %d (one past the fork tip)", nh, forkTip.Height+1)
	}
}

// TestConnectPendingBlocks_IBDExtensionUnchanged is the invariant-1 guard: during
// IBD (IsIBD()==true) the connect loop must keep using raw ConnectBlock with
// identical behaviour — ProcessSubmittedBlock must NOT be consulted. A simple
// in-order extension connects every block and advances the tip exactly as before.
func TestConnectPendingBlocks_IBDExtensionUnchanged(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	chain := addChain(t, idx, idx.Genesis(), 5, 1)
	idx.MarkDataStored(idx.Genesis().Hash)

	mock := &mockChainConnector{
		tipHash:   idx.Genesis().Hash,
		tipHeight: 0,
		// postIBD defaults false -> IsIBD()==true -> raw ConnectBlock path.
	}
	processCalled := false
	mock.processFn = func(*wire.MsgBlock) error {
		processCalled = true
		return nil
	}
	mock.connectFn = func(b *wire.MsgBlock) error {
		node := idx.GetNode(b.Header.BlockHash())
		mock.tipHash = node.Hash
		mock.tipHeight = node.Height
		return nil
	}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  idx,
		ChainManager: mock,
	})
	defer close(sm.quit)

	sm.mu.Lock()
	sm.nextHeight = 1
	sm.mu.Unlock()

	pending := make(map[int32]*blockWithRequest)
	for _, n := range chain {
		pending[n.Height] = &blockWithRequest{
			block: &wire.MsgBlock{Header: n.Header},
			req:   &blockRequest{Hash: n.Hash, Height: n.Height, State: BlockDownloadReceived},
		}
	}

	sm.connectPendingBlocks(pending)

	if processCalled {
		t.Fatalf("ProcessSubmittedBlock was consulted during IBD — invariant 1 violated "+
			"(the IBD path must use raw ConnectBlock)")
	}
	if mock.tipHeight != 5 {
		t.Fatalf("IBD extension stopped at tip height %d, want 5", mock.tipHeight)
	}
	sm.mu.RLock()
	nh := sm.nextHeight
	sm.mu.RUnlock()
	if nh != 6 {
		t.Fatalf("nextHeight = %d, want 6 after connecting 1..5", nh)
	}
}
