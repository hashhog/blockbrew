package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Resubmitting a side-branch block that submitblock already stored must
// answer BIP-22 "duplicate", as Core does.
//
// Core: submitblock runs ProcessNewBlock unconditionally and answers
// "duplicate" when `!new_block && accepted` (rpc/mining.cpp). new_block comes
// from AcceptBlock, which returns early with fNewBlock=false when the index
// entry already has BLOCK_HAVE_DATA (validation.cpp, `fAlreadyHave`). The
// first submission of a lighter side-branch block writes the body and
// ReceivedBlockTransactions sets BLOCK_HAVE_DATA, so the second submission is
// "duplicate" (core-regtest row
// warden_invalidated_submit/submit/inconclusive-resubmit).
//
// blockbrew stored the side-branch body but never set StatusDataStored on its
// index node, so the already-have check in handleSubmitBlock missed and the
// resubmit answered "inconclusive" a second time.

func mineSideBlock(t *testing.T, rig *submitBlockTestRig, parent *consensus.BlockNode, bump uint32) *wire.MsgBlock {
	t.Helper()
	blk := buildRegtestBlock(t, rig.params, parent)
	blk.Header.Timestamp += bump
	target := consensus.CompactToBig(blk.Header.Bits)
	for i := uint32(0); i < 10_000_000; i++ {
		blk.Header.Nonce = i
		if consensus.HashToBig(blk.Header.BlockHash()).Cmp(target) <= 0 {
			return blk
		}
	}
	t.Fatalf("could not mine side block")
	return nil
}

func TestSubmitBlockResubmitSideBranchAnswersDuplicate(t *testing.T) {
	rig := newSubmitBlockRig(t, 3)
	tipBefore, heightBefore := rig.cm.BestBlock()

	side := mineSideBlock(t, rig, rig.idx.Genesis(), 1)
	sideHash := side.Header.BlockHash()

	res, rpcErr := rig.submitBlock(t, side)
	if rpcErr != nil {
		t.Fatalf("first submit: RPC error %+v", rpcErr)
	}
	if got, _ := res.(string); got != "inconclusive" {
		t.Fatalf("first submit: got %v, want \"inconclusive\"", res)
	}
	node := rig.idx.GetNode(sideHash)
	if node == nil || node.Status&consensus.StatusDataStored == 0 {
		t.Fatalf("stored side-branch block has no StatusDataStored (Core BLOCK_HAVE_DATA)")
	}

	res, rpcErr = rig.submitBlock(t, side)
	if rpcErr != nil {
		t.Fatalf("resubmit: RPC error %+v", rpcErr)
	}
	if got, _ := res.(string); got != "duplicate" {
		t.Fatalf("resubmit: got %v, want \"duplicate\"", res)
	}

	// A duplicate answer must not move the tip: the side block is lighter.
	if tip, h := rig.cm.BestBlock(); tip != tipBefore || h != heightBefore {
		t.Fatalf("resubmit moved the tip: %s@%d -> %s@%d",
			tipBefore.String()[:16], heightBefore, tip.String()[:16], h)
	}
}

// Marking the side block as having data makes it a chain-selection
// candidate. It must still only become active through a full connect once its
// branch outweighs the tip, exactly as before.
func TestSubmitBlockStoredSideBranchStillReorgsWhenHeavier(t *testing.T) {
	rig := newSubmitBlockRig(t, 2) // tip at height 2

	s1 := mineSideBlock(t, rig, rig.idx.Genesis(), 1)
	if res, rpcErr := rig.submitBlock(t, s1); rpcErr != nil || res != "inconclusive" {
		t.Fatalf("s1: got %v %+v, want \"inconclusive\"", res, rpcErr)
	}
	n1 := rig.idx.GetNode(s1.Header.BlockHash())
	s2 := mineSideBlock(t, rig, n1, 1)
	if res, rpcErr := rig.submitBlock(t, s2); rpcErr != nil || res != "inconclusive" {
		t.Fatalf("s2 (equal work): got %v %+v, want \"inconclusive\"", res, rpcErr)
	}
	n2 := rig.idx.GetNode(s2.Header.BlockHash())
	s3 := mineSideBlock(t, rig, n2, 1)
	if res, rpcErr := rig.submitBlock(t, s3); rpcErr != nil || res != nil {
		t.Fatalf("s3 (heavier): got %v %+v, want null (reorg)", res, rpcErr)
	}
	if tip, h := rig.cm.BestBlock(); tip != s3.Header.BlockHash() || h != 3 {
		t.Fatalf("heavier side branch not activated: tip %s@%d", tip.String()[:16], h)
	}
	// Each block on the new active chain must be fully validated.
	for _, b := range []*wire.MsgBlock{s1, s2, s3} {
		n := rig.idx.GetNode(b.Header.BlockHash())
		if n.Status&consensus.StatusFullyValid == 0 {
			t.Fatalf("active block %s at height %d not FullyValid", n.Hash.String()[:16], n.Height)
		}
	}
	// And resubmitting an active block is still "duplicate".
	if res, _ := rig.submitBlock(t, s2); res != "duplicate" {
		t.Fatalf("resubmit active s2: got %v, want \"duplicate\"", res)
	}
}
