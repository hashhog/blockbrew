package p2p

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestBlockDownloadLoopRebuildsQueueOnDrain is a regression test for the
// block-download queue-refill stall observed on the 2026-06-06 blockbrew
// mainnet snapshot restore (stuck at blocks=946000 with headers=952612,
// queue=0, inflight=0).
//
// The block queue is a SNAPSHOT of the header tip taken when StartBlockDownload
// built it. Header sync runs concurrently and keeps advancing the header tip
// AFTER the queue is built; late header batches that arrive while the loop is
// still draining hit StartBlockDownload's "already populated" short-circuit and
// are dropped, and once sm.headersSynced is set the HandleHeaders kickoff
// (gated on !headersSynced) stops firing on the periodic empty batches. With
// the old code, when the queue drained mid-IBD the loop simply returned —
// leaving the node with a full header chain but blocks stuck short of the tip
// and nothing to resume the download. The fix rebuilds the queue from the
// CURRENT header tip on drain instead of exiting.
//
// The test runs blockDownloadLoop with an EMPTY queue (the post-drain state)
// while the header index extends well past the connected tip, and asserts the
// loop REBUILDS the queue. Pre-fix the queue stays at 0 (the loop exits);
// post-fix it becomes connectedTip+1..headerTip.
func TestBlockDownloadLoopRebuildsQueueOnDrain(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// Build a real header chain to height 50.
	prevNode := idx.Genesis()
	for i := 1; i <= 50; i++ {
		h := createTestBlockHeader(prevNode.Hash, prevNode.Header.Timestamp+600, uint32(i))
		node, err := idx.AddHeader(h, true)
		if err != nil {
			t.Fatalf("add header %d: %v", i, err)
		}
		prevNode = node
	}

	const connectedH = 20
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  idx,
		ChainManager: &mockChainConnector{tipHeight: connectedH},
	})

	// Start the loop with an EMPTY queue while headers extend to 50. With no
	// peerMgr, requestBlocks is a safe no-op, so the loop's very first
	// drain-check fires: queue+inflight empty AND header tip (50) > connected
	// tip (20) => the fix must rebuild the queue.
	go sm.blockDownloadLoop()
	defer close(sm.quit)

	want := int(50 - connectedH)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if sm.BlockQueueLength() == want {
			return // rebuilt — the fix works
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("block queue not rebuilt on drain: length=%d, want %d "+
		"(blockDownloadLoop must rebuild from the current header tip instead of exiting)",
		sm.BlockQueueLength(), want)
}

// TestHealGappedBlockQueue is a regression test for the GEN-BREW-665671
// block-download livelock: the scheduler spins forever logging
// "stall ... NOT IN QUEUE" because the block queue's lowest height sits ABOVE
// nextHeight, leaving a gap [nextHeight, floor-1] that requestBlocks can never
// fill (it only requests queued blocks) with nothing in flight to close it.
// Observed for 3.5 days at height 665671 and again at 444235 (queue floor
// 444247, connected tip 444234, so [444235,444246] absent).
//
// healGappedBlockQueue must detect that gap and DROP the queue (so the loop's
// drain check rebuilds from the validated tip), while leaving the queue intact
// for the two states that are NOT this bug: a below-tip heavier fork (floor
// <= nextHeight) and any state with blocks still in flight.
func TestHealGappedBlockQueue(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	newSM := func() *SyncManager {
		return NewSyncManager(SyncManagerConfig{ChainParams: params, HeaderIndex: idx})
	}

	// --- Case 1: the wedge. floor (447) > nextHeight (435), inflight empty. ---
	// Must heal: return true and clear the gapped queue.
	{
		sm := newSM()
		sm.mu.Lock()
		sm.blockQueue = nil
		for h := int32(447); h <= 488; h++ { // 42 queued blocks, floor 447
			sm.blockQueue = append(sm.blockQueue, &blockRequest{
				Hash: wire.Hash256{byte(h), byte(h >> 8)}, Height: h, State: BlockDownloadPending,
			})
		}
		healed := sm.healGappedBlockQueue(435, 0) // nextHeight 435, inflight 0
		queueLen := len(sm.blockQueue)
		sm.mu.Unlock()
		if !healed {
			t.Fatalf("Case 1 (gap floor 447 > nextHeight 435, inflight 0): healGappedBlockQueue=false, want true")
		}
		if queueLen != 0 {
			t.Fatalf("Case 1: gapped queue not dropped: len=%d, want 0", queueLen)
		}
	}

	// --- Case 2: below-tip heavier fork. floor (435) <= nextHeight (435). ---
	// Must NOT heal: floor is not above nextHeight, so the queue is legitimate
	// (reorg-drop invariant) and must be left intact.
	{
		sm := newSM()
		sm.mu.Lock()
		sm.blockQueue = nil
		for h := int32(435); h <= 460; h++ {
			sm.blockQueue = append(sm.blockQueue, &blockRequest{
				Hash: wire.Hash256{byte(h), byte(h >> 8)}, Height: h, State: BlockDownloadPending,
			})
		}
		healed := sm.healGappedBlockQueue(435, 0)
		queueLen := len(sm.blockQueue)
		sm.mu.Unlock()
		if healed {
			t.Fatalf("Case 2 (floor 435 == nextHeight 435): healGappedBlockQueue=true, want false — must not drop a non-gapped queue")
		}
		if queueLen == 0 {
			t.Fatalf("Case 2: non-gapped queue was wrongly dropped")
		}
	}

	// --- Case 3: gap present BUT blocks in flight. Must NOT heal (something is ---
	// coming that may advance the tip / close the gap; don't tear down mid-flight).
	{
		sm := newSM()
		sm.mu.Lock()
		sm.blockQueue = nil
		for h := int32(447); h <= 460; h++ {
			sm.blockQueue = append(sm.blockQueue, &blockRequest{
				Hash: wire.Hash256{byte(h), byte(h >> 8)}, Height: h, State: BlockDownloadPending,
			})
		}
		healed := sm.healGappedBlockQueue(435, 3) // inflightLen 3
		queueLen := len(sm.blockQueue)
		sm.mu.Unlock()
		if healed {
			t.Fatalf("Case 3 (gap but inflight=3): healGappedBlockQueue=true, want false")
		}
		if queueLen == 0 {
			t.Fatalf("Case 3: queue dropped while blocks in flight")
		}
	}

	// --- Case 4: empty queue. Must NOT heal (nothing to drop). ---
	{
		sm := newSM()
		sm.mu.Lock()
		healed := sm.healGappedBlockQueue(435, 0)
		sm.mu.Unlock()
		if healed {
			t.Fatalf("Case 4 (empty queue): healGappedBlockQueue=true, want false")
		}
	}
}

// TestBlockDownloadLoopStaysAliveAfterDrainRebuild is a regression test for
// GEN-BREW-444534: the drain-rebuild path left the rebuilt queue with no loop
// to service it, so the tip froze (observed live at 444533->444534: 288 queued,
// 0 inflight, ~1h, no progress).
//
// The drain branch calls StartBlockDownload from INSIDE the running loop. That
// call's launch CAS sees blockDownloadLoopRunning still true (the loop's
// deferred Store(false) hasn't fired) and deliberately does NOT spawn a second
// loop. The old code then `return`ed, so the loop exited and the just-rebuilt
// queue had nobody to download it — a permanent stall.
//
// This test reproduces the production condition the existing drain test misses:
// it sets blockDownloadLoopRunning=true BEFORE launching (as the real
// StartBlockDownload does), so the drain's re-entrant CAS fails exactly as in
// production. Pre-fix: the loop exits (running flips to false) and the rebuilt
// queue is abandoned. Post-fix: the loop `continue`s and keeps servicing it
// (running stays true).
func TestBlockDownloadLoopStaysAliveAfterDrainRebuild(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	prevNode := idx.Genesis()
	for i := 1; i <= 50; i++ {
		h := createTestBlockHeader(prevNode.Hash, prevNode.Header.Timestamp+600, uint32(i))
		node, err := idx.AddHeader(h, true)
		if err != nil {
			t.Fatalf("add header %d: %v", i, err)
		}
		prevNode = node
	}

	const connectedH = 20
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  idx,
		ChainManager: &mockChainConnector{tipHeight: connectedH},
	})

	// Simulate the real launch path: StartBlockDownload sets the running flag
	// true before the loop goroutine starts. This is what makes the drain
	// branch's re-entrant StartBlockDownload CAS fail (as in production).
	sm.blockDownloadLoopRunning.Store(true)
	go sm.blockDownloadLoop()
	defer close(sm.quit)

	// Wait for the drain-rebuild to occur.
	want := int(50 - connectedH)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && sm.BlockQueueLength() != want {
		time.Sleep(20 * time.Millisecond)
	}
	if sm.BlockQueueLength() != want {
		t.Fatalf("queue not rebuilt on drain: length=%d, want %d", sm.BlockQueueLength(), want)
	}

	// The loop must STILL be alive to service the rebuilt queue. Pre-fix it
	// exited right after the rebuild (running -> false); post-fix it continues.
	// Give the old code's return+defer time to flip the flag if it were going to.
	time.Sleep(300 * time.Millisecond)
	if !sm.blockDownloadLoopRunning.Load() {
		t.Fatalf("block-download loop exited after drain-rebuild — the rebuilt queue "+
			"(len %d) has no loop to service it (GEN-BREW-444534 stall). The drain "+
			"branch must continue the loop, not return.", sm.BlockQueueLength())
	}
	if sm.BlockQueueLength() != want {
		t.Fatalf("queue changed unexpectedly after rebuild: %d, want %d", sm.BlockQueueLength(), want)
	}
}
