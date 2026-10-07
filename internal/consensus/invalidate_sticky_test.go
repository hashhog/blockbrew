package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ---------------------------------------------------------------------------
// invalidateblock must STICK (audit 2026-10-07, BB-3 / BB-4, fleet fix #6).
//
// Bitcoin Core: InvalidateBlock marks the block BLOCK_FAILED_VALID and its
// descendants BLOCK_FAILED_CHILD; AcceptBlockHeader answers "duplicate-invalid"
// for a failed block and "bad-prevblk" for a child of one; FindMostWorkChain /
// ActivateBestChainStep never connect a failed block. Nothing but
// reconsiderblock brings the branch back.
// ---------------------------------------------------------------------------

func newStickyChain(t *testing.T, n int) (*ChainManager, *HeaderIndex, []*BlockNode, []*wire.MsgBlock) {
	t.Helper()
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{Params: params, HeaderIndex: idx, ChainDB: db})
	cm.SetIBD(false)
	nodes := []*BlockNode{idx.Genesis()}
	blocks := []*wire.MsgBlock{nil}
	for i := 0; i < n; i++ {
		blk := createTestBlock(t, params, nodes[len(nodes)-1], nil)
		node, err := idx.AddHeader(blk.Header, true)
		if err != nil {
			t.Fatalf("AddHeader %d: %v", i, err)
		}
		if err := db.StoreBlock(blk.Header.BlockHash(), blk); err != nil {
			t.Fatalf("StoreBlock %d: %v", i, err)
		}
		if err := cm.ConnectBlock(blk); err != nil {
			t.Fatalf("ConnectBlock %d: %v", i, err)
		}
		nodes = append(nodes, node)
		blocks = append(blocks, blk)
	}
	return cm, idx, nodes, blocks
}

// BB-3: submitblock of a stored block that invalidateblock disconnected
// (ProcessSubmittedBlock -> parent == tip -> ConnectBlock) reconnected it and
// stamped it FullyValid while it was still flagged Invalid.
func TestInvalidateStickySubmitInvalidatedBlock(t *testing.T) {
	cm, _, nodes, blocks := newStickyChain(t, 6)
	if err := cm.InvalidateBlock(nodes[4].Hash); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}
	if got := cm.TipNode(); got != nodes[3] {
		t.Fatalf("after invalidate tip=%d want 3", got.Height)
	}
	// The invalidated block itself (extends the tip).
	if err := cm.ProcessSubmittedBlock(blocks[4]); err == nil {
		t.Errorf("ProcessSubmittedBlock(invalidated block 4) succeeded; want a refusal")
	}
	if got := cm.TipNode(); got != nodes[3] {
		t.Fatalf("BB-3: submit of the invalidated block moved the tip to %d (Core: duplicate-invalid, tip stays 3)", got.Height)
	}
	// A descendant with more work than the tip (reorg route).
	if err := cm.ProcessSubmittedBlock(blocks[6]); err == nil {
		t.Errorf("ProcessSubmittedBlock(descendant 6) succeeded; want a refusal")
	}
	if got := cm.TipNode(); got != nodes[3] {
		t.Fatalf("BB-3: submit of a descendant reorged onto the invalidated branch, tip=%d", got.Height)
	}
	// Plain ConnectBlock of the failed block must refuse too.
	if err := cm.ConnectBlock(blocks[4]); err == nil || cm.TipNode() != nodes[3] {
		t.Fatalf("ConnectBlock(invalidated) err=%v tip=%d; want refusal at 3", err, cm.TipNode().Height)
	}
	if nodes[4].Status&StatusFullyValid != 0 && nodes[4].Status.IsInvalid() && cm.TipNode() == nodes[4] {
		t.Fatalf("block 4 is the tip AND flagged invalid")
	}
	// Negative control: reconsider brings the branch back to 6.
	if err := cm.ReconsiderBlock(nodes[4].Hash); err != nil {
		t.Fatalf("ReconsiderBlock: %v", err)
	}
	if got := cm.TipNode(); got != nodes[6] {
		t.Fatalf("control: after reconsider tip=%d want 6", got.Height)
	}
}

// BB-4: a sync connect of a block on the branch being invalidated, arriving
// while InvalidateBlock holds reorgMu, queued in ReorgTo and — once the
// invalidation returned — reconnected the just-invalidated chain.
// Deterministic: the disconnect hook (inside InvalidateBlock, reorgMu held)
// starts the racing ConnectBlock and waits until it is about to block on
// reorgMu.
func TestInvalidateStickyQueuedSyncReorg(t *testing.T) {
	cm, idx, nodes, blocks := newStickyChain(t, 6)
	// Block 7 on the current chain: header + body known, not connected.
	params := RegtestParams()
	b7 := createTestBlock(t, params, nodes[6], nil)
	n7, err := idx.AddHeader(b7.Header, true)
	if err != nil {
		t.Fatalf("AddHeader 7: %v", err)
	}
	if err := cm.chainDB.StoreBlock(b7.Header.BlockHash(), b7); err != nil {
		t.Fatalf("StoreBlock 7: %v", err)
	}
	_ = blocks

	queued := make(chan struct{})
	done := make(chan error, 1)
	started := false
	testHookBeforeReorgLock = func(newTip *BlockNode) {
		if newTip == n7 {
			close(queued)
		}
	}
	defer func() { testHookBeforeReorgLock = nil }()
	cm.SetOnBlockDisconnected(func(_ *wire.MsgBlock, _ int32) {
		if started {
			return
		}
		started = true
		go func() { done <- cm.ConnectBlock(b7) }()
		// Either the sync connect reaches ReorgTo and is about to wait on
		// reorgMu (the BB-4 window), or it is refused outright because its
		// branch is already flagged; both must end with the tip at 3.
		select {
		case <-queued:
		case err := <-done:
			done <- err
		}
	})

	if err := cm.InvalidateBlock(nodes[4].Hash); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}
	if !started {
		t.Fatal("disconnect hook never fired; the seam proved nothing")
	}
	serr := <-done
	tip := cm.TipNode()
	if tip != nodes[3] {
		t.Fatalf("BB-4: the queued sync connect undid invalidateblock: tip=%d (want 3), sync err=%v, tip invalid=%v",
			tip.Height, serr, tip.Status.IsInvalid())
	}
	if serr == nil {
		t.Errorf("queued sync ConnectBlock(7) returned nil; want a refusal")
	}
}

// The reorg engine itself refuses a target whose branch holds a failed block,
// before disconnecting anything (the guard a queued ReorgTo meets once
// invalidateblock releases reorgMu, whatever path queued it).
func TestInvalidateStickyReorgToRefusesFailedBranch(t *testing.T) {
	cm, idx, nodes, _ := newStickyChain(t, 6)
	params := RegtestParams()
	b7 := createTestBlock(t, params, nodes[6], nil)
	n7, err := idx.AddHeader(b7.Header, true)
	if err != nil {
		t.Fatalf("AddHeader 7: %v", err)
	}
	if err := cm.chainDB.StoreBlock(b7.Header.BlockHash(), b7); err != nil {
		t.Fatalf("StoreBlock 7: %v", err)
	}
	if err := cm.InvalidateBlock(nodes[4].Hash); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}
	if err := cm.ReorgTo(n7); err == nil {
		t.Errorf("ReorgTo(7) onto the invalidated branch returned nil")
	}
	if got := cm.TipNode(); got != nodes[3] {
		t.Fatalf("ReorgTo reconnected the invalidated branch: tip=%d want 3", got.Height)
	}
	// Best header is off the failed branch (Core RecalculateBestHeader).
	if bt := idx.BestTip(); bt == nil || bt.Status.IsInvalid() {
		t.Fatalf("best header still on the failed branch: %v", bt)
	}
}
