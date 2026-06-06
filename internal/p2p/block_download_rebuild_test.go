package p2p

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
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
