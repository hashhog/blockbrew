package p2p

import (
	"sort"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// addChain appends `n` headers on top of `prev`, returning every created node
// (ascending). `nonceBase` keeps fork branches from colliding with the main
// chain's hashes. Timestamps advance 600s per block so each header clears its
// parent's median-time-past.
func addChain(t *testing.T, idx *consensus.HeaderIndex, prev *consensus.BlockNode, n int, nonceBase uint32) []*consensus.BlockNode {
	t.Helper()
	out := make([]*consensus.BlockNode, 0, n)
	cur := prev
	for i := 0; i < n; i++ {
		h := createTestBlockHeader(cur.Hash, cur.Header.Timestamp+600, nonceBase+uint32(i)*1000)
		node, err := idx.AddHeader(h, true)
		if err != nil {
			t.Fatalf("add header on top of height %d (branch nonce %d): %v", cur.Height, nonceBase, err)
		}
		out = append(out, node)
		cur = node
	}
	return out
}

// queueHeights returns the ascending list of heights currently enqueued for
// download. The test lives in package p2p, so it reads sm.blockQueue directly.
func queueHeights(sm *SyncManager) []int32 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	heights := make([]int32, 0, len(sm.blockQueue))
	for _, req := range sm.blockQueue {
		heights = append(heights, req.Height)
	}
	sort.Slice(heights, func(i, j int) bool { return heights[i] < heights[j] })
	return heights
}

// TestStartBlockDownload_BelowTipHeavierFork is the GAP2 regression: a competing
// branch that forks BELOW the active validated tip and is heavier (more total
// work) must have its bridging bodies — the fork-point..below-tip span — enqueued
// for download, not just the blocks strictly above the active tip. Pre-fix the
// walk floored at the active tip height and stopped at the sibling whose height
// equalled the tip, starving the reorg path. Post-fix the walk descends by
// ancestry to the fork point, enqueuing every block we still need.
//
// Topology:
//
//	genesis - 1 .. 10 (F, fork point)        <- bodies stored for 1..H
//	                \- 11 .. 20 (H, active validated tip; bodies 1..20 stored)
//	                 \ 11'.. 30' (T, heavier fork tip; NO bodies stored)
//
// Active tip H=20, fork point F=10, fork tip T=30. The fork is heavier (30 > 20
// blocks of equal-difficulty work) so the header index makes T the best tip.
// The download set MUST be the full fork span 11'..30' (the fork point's
// children up to T), which includes the bridging heights 11..20 on the fork
// branch — exactly the bodies the old floor skipped.
func TestStartBlockDownload_BelowTipHeavierFork(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// Main chain genesis -> 1..20. The active validated tip is height 20.
	main := addChain(t, idx, idx.Genesis(), 20, 1)
	const forkPointHeight = 10
	const activeTipHeight = 20
	forkPoint := main[forkPointHeight-1] // height 10
	activeTip := main[activeTipHeight-1] // height 20

	// The node has VALIDATED + stored bodies for the active chain 1..20.
	idx.MarkDataStored(idx.Genesis().Hash)
	for _, n := range main {
		idx.MarkDataStored(n.Hash)
	}

	// Heavier competing fork off the fork point: 20 blocks (heights 11..30),
	// no bodies stored. 30 > 20 work => this becomes the best tip.
	fork := addChain(t, idx, forkPoint, 20, 1_000_000)
	forkTip := fork[len(fork)-1]

	if bt := idx.BestTip(); bt != forkTip {
		t.Fatalf("expected the heavier fork tip (height %d) to be the best tip, got height %d",
			forkTip.Height, bt.Height)
	}
	if forkTip.Height != 30 {
		t.Fatalf("fork tip height = %d, want 30", forkTip.Height)
	}

	// Active validated tip is the MAIN chain tip at height 20 (NOT the header
	// best tip). The mock returns that tip's hash so StartBlockDownload can
	// resolve the active-chain node and walk past the tip height to the fork.
	mock := &mockChainConnector{tipHash: activeTip.Hash, tipHeight: activeTipHeight}
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  idx,
		ChainManager: mock,
	})
	defer close(sm.quit)

	sm.StartBlockDownload()

	got := queueHeights(sm)

	// Expect the full fork span: the fork-point's children up to the fork tip,
	// i.e. heights 11..30 ON THE FORK BRANCH. That is 20 blocks, and crucially
	// INCLUDES the bridging heights 11..20 that the old active-tip floor dropped.
	want := make([]int32, 0, 20)
	for h := int32(forkPointHeight + 1); h <= forkTip.Height; h++ {
		want = append(want, h)
	}
	if len(got) != len(want) {
		t.Fatalf("download set size = %d, want %d (got heights %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("download set heights = %v, want %v", got, want)
		}
	}

	// The bridging fork bodies F+1..H (11..20) MUST be present — this is the
	// exact set GAP2 starved. Verify the enqueued hashes are the FORK branch's
	// nodes, not the (already-stored) active-chain nodes at those heights.
	enqueued := map[wire.Hash256]bool{}
	sm.mu.RLock()
	for _, req := range sm.blockQueue {
		enqueued[req.Hash] = true
	}
	sm.mu.RUnlock()
	for _, n := range fork {
		if n.Height <= activeTipHeight { // 11..20 on the fork branch
			if !enqueued[n.Hash] {
				t.Fatalf("bridging fork body at height %d (hash %x) was NOT enqueued — GAP2 still open",
					n.Height, n.Hash[:8])
			}
		}
	}
	// And the already-stored active-chain siblings at those heights must NOT be
	// re-requested.
	for _, n := range main {
		if n.Height > forkPointHeight && enqueued[n.Hash] {
			t.Fatalf("already-stored active-chain block at height %d was wrongly enqueued", n.Height)
		}
	}

	// nextHeight must target the first block above the fork point, which is
	// BELOW the active tip — the connect loop has to start there for the reorg.
	sm.mu.RLock()
	nh := sm.nextHeight
	sm.mu.RUnlock()
	if nh != int32(forkPointHeight+1) {
		t.Fatalf("nextHeight = %d, want %d (first block above the fork point)", nh, forkPointHeight+1)
	}
}

// TestStartBlockDownload_NoForkUnchanged is the invariant guard: when the header
// best tip is a simple extension of the active validated tip (normal IBD /
// steady state), the enqueued set must be IDENTICAL to the pre-fix behaviour —
// startHeight+1 .. bestTip.Height on the active chain. Only a genuine below-tip
// fork may change behaviour.
func TestStartBlockDownload_NoForkUnchanged(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// genesis -> 1..50, single chain. Bodies stored for 1..20 (the connected
	// tip); 21..50 are header-only (the normal "headers ahead of blocks" state).
	chain := addChain(t, idx, idx.Genesis(), 50, 1)
	const connectedH = 20
	idx.MarkDataStored(idx.Genesis().Hash)
	for _, n := range chain {
		if n.Height <= connectedH {
			idx.MarkDataStored(n.Hash)
		}
	}
	activeTip := chain[connectedH-1]

	mock := &mockChainConnector{tipHash: activeTip.Hash, tipHeight: connectedH}
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  idx,
		ChainManager: mock,
	})
	defer close(sm.quit)

	sm.StartBlockDownload()

	got := queueHeights(sm)
	want := make([]int32, 0, 30)
	for h := int32(connectedH + 1); h <= 50; h++ {
		want = append(want, h)
	}
	if len(got) != len(want) {
		t.Fatalf("no-fork download set size = %d, want %d (heights %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("no-fork download set heights = %v, want %v (extension behaviour must be unchanged)", got, want)
		}
	}

	sm.mu.RLock()
	nh := sm.nextHeight
	sm.mu.RUnlock()
	if nh != int32(connectedH+1) {
		t.Fatalf("no-fork nextHeight = %d, want %d", nh, connectedH+1)
	}
}
