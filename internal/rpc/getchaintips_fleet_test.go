package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Fleet item done-fleet-regtest-getchaintips: getchaintips must enumerate
// every tip of the block index with Core's status and branchlen
// (bitcoin-core/src/rpc/blockchain.cpp getchaintips), not just the active tip
// plus the best header. Each test below FAILS on 1b143a6, which reported only
// the active tip and, at most, one same-lineage "headers-only" header tip.

// gctSideBlock builds a regtest block on prev whose hash differs from the
// main-chain block buildRegtestBlock would build there (time shifted by salt).
func gctSideBlock(t *testing.T, params *consensus.ChainParams, prev *consensus.BlockNode, salt uint32) *wire.MsgBlock {
	t.Helper()
	blk := buildRegtestBlock(t, params, prev)
	blk.Header.Timestamp += salt
	target := consensus.CompactToBig(blk.Header.Bits)
	for i := uint32(0); i < 10_000_000; i++ {
		blk.Header.Nonce = i
		if consensus.HashToBig(blk.Header.BlockHash()).Cmp(target) <= 0 {
			return blk
		}
	}
	t.Fatal("could not mine side block")
	return nil
}

func gctTips(t *testing.T, rig *dumpTxOutSetTestRig) map[string]ChainTip {
	t.Helper()
	res, rpcErr := rig.server.handleGetChainTips()
	if rpcErr != nil {
		t.Fatalf("handleGetChainTips: %v", rpcErr)
	}
	out := map[string]ChainTip{}
	for _, tip := range res.([]ChainTip) {
		if _, dup := out[tip.Hash]; dup {
			t.Fatalf("tip %s reported twice", tip.Hash)
		}
		out[tip.Hash] = tip
	}
	return out
}

func gctExpect(t *testing.T, tips map[string]ChainTip, want []ChainTip) {
	t.Helper()
	if len(tips) != len(want) {
		t.Errorf("got %d tips %v, want %d %v", len(tips), tips, len(want), want)
	}
	for _, w := range want {
		got, ok := tips[w.Hash]
		if !ok {
			t.Errorf("tip %s (height %d, %s) missing; got %v", w.Hash, w.Height, w.Status, tips)
			continue
		}
		if got != w {
			t.Errorf("tip %s = %+v, want %+v", w.Hash, got, w)
		}
	}
}

// A block stored with its body but never connected (a lighter side branch,
// submitblock "inconclusive") is a "valid-headers" tip; Core lists it with
// branchlen = height - fork height.
func TestGetChainTipsFleetValidHeadersSideBranch(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 3)
	side := gctSideBlock(t, rig.params, rig.idx.Genesis(), 1)
	node, err := rig.idx.AddHeader(side.Header, true)
	if err != nil {
		t.Fatalf("AddHeader side: %v", err)
	}
	if err := rig.db.StoreBlock(node.Hash, side); err != nil {
		t.Fatalf("StoreBlock side: %v", err)
	}
	rig.idx.MarkDataStored(node.Hash)

	gctExpect(t, gctTips(t, rig), []ChainTip{
		{Height: 3, Hash: rig.tips[2].Hash.String(), BranchLen: 0, Status: "active"},
		{Height: 1, Hash: node.Hash.String(), BranchLen: 1, Status: "valid-headers"},
	})
}

// A side-branch header whose body never arrived is "headers-only", even when
// it is not the best header (the old code only ever reported the best header,
// and only when it extended the active tip).
func TestGetChainTipsFleetHeadersOnlySideBranch(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 3)
	side := gctSideBlock(t, rig.params, rig.tips[0], 7)
	node, err := rig.idx.AddHeader(side.Header, true)
	if err != nil {
		t.Fatalf("AddHeader side: %v", err)
	}

	gctExpect(t, gctTips(t, rig), []ChainTip{
		{Height: 3, Hash: rig.tips[2].Hash.String(), BranchLen: 0, Status: "active"},
		{Height: 2, Hash: node.Hash.String(), BranchLen: 1, Status: "headers-only"},
	})
}

// invalidateblock on the tip: the invalidated block stays in the index as an
// "invalid" tip with branchlen 1, and the new active tip is its parent.
func TestGetChainTipsFleetInvalidatedTip(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 3)
	if err := rig.cm.InvalidateBlock(rig.tips[2].Hash); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}
	gctExpect(t, gctTips(t, rig), []ChainTip{
		{Height: 2, Hash: rig.tips[1].Hash.String(), BranchLen: 0, Status: "active"},
		{Height: 3, Hash: rig.tips[2].Hash.String(), BranchLen: 1, Status: "invalid"},
	})
}

// A descendant of an invalidated block is reported "invalid" at the leaf: the
// failed block itself has a child, so it is not a tip, and the leaf carries
// the failure (Core: BLOCK_FAILED_VALID on descendants).
func TestGetChainTipsFleetInvalidAncestor(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 3)
	if err := rig.cm.InvalidateBlock(rig.tips[1].Hash); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}
	gctExpect(t, gctTips(t, rig), []ChainTip{
		{Height: 1, Hash: rig.tips[0].Hash.String(), BranchLen: 0, Status: "active"},
		{Height: 3, Hash: rig.tips[2].Hash.String(), BranchLen: 2, Status: "invalid"},
	})
}

// After a reorg, the branch that was connected and then disconnected is a
// "valid-fork" tip (Core: IsValid(BLOCK_VALID_SCRIPTS) off the active chain).
func TestGetChainTipsFleetValidForkAfterReorg(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 3)
	prev := rig.tips[0]
	var sideTip *consensus.BlockNode
	for i := 0; i < 3; i++ {
		blk := gctSideBlock(t, rig.params, prev, 3)
		node, err := rig.idx.AddHeader(blk.Header, true)
		if err != nil {
			t.Fatalf("AddHeader side %d: %v", i, err)
		}
		if err := rig.db.StoreBlock(node.Hash, blk); err != nil {
			t.Fatalf("StoreBlock side %d: %v", i, err)
		}
		rig.idx.MarkDataStored(node.Hash)
		prev, sideTip = node, node
	}
	if err := rig.cm.ReorgTo(sideTip); err != nil {
		t.Fatalf("ReorgTo side tip: %v", err)
	}
	gctExpect(t, gctTips(t, rig), []ChainTip{
		{Height: 4, Hash: sideTip.Hash.String(), BranchLen: 0, Status: "active"},
		{Height: 3, Hash: rig.tips[2].Hash.String(), BranchLen: 2, Status: "valid-fork"},
	})
}

// The best header is a failed block one above the active tip (a submitblock
// whose connect was refused and marked): Core reports it "invalid"; the old
// code labelled the best header "headers-only" regardless of its flags.
func TestGetChainTipsFleetFailedBestHeaderIsInvalid(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 3)
	blk := buildRegtestBlock(t, rig.params, rig.tips[2])
	node, err := rig.idx.AddHeader(blk.Header, true)
	if err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if !rig.cm.MarkBlockFailed(node.Hash) {
		t.Fatal("MarkBlockFailed returned false")
	}
	gctExpect(t, gctTips(t, rig), []ChainTip{
		{Height: 3, Hash: rig.tips[2].Hash.String(), BranchLen: 0, Status: "active"},
		{Height: 4, Hash: node.Hash.String(), BranchLen: 1, Status: "invalid"},
	})
}
