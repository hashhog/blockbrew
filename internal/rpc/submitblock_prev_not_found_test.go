package rpc

import "testing"

import "github.com/hashhog/blockbrew/internal/consensus"

// Core ProcessNewBlock -> AcceptBlockHeader answers a header whose parent is
// not in the block index with BLOCK_MISSING_PREV, reject reason
// "prev-blk-not-found" (validation.cpp:4217), which BIP22ValidationResult
// returns verbatim. blockbrew answered the generic "rejected".
func TestSubmitBlockUnknownParentIsPrevBlkNotFound(t *testing.T) {
	rig := newSubmitBlockRig(t, 2)
	tip := rig.tips[len(rig.tips)-1]
	// A parent node that is not in the header index.
	var ghost consensus.BlockNode
	ghost.Header = tip.Header
	ghost.Height = tip.Height
	ghost.Hash = tip.Hash
	ghost.Hash[0] ^= 0xff
	blk := buildRegtestBlock(t, rig.params, &ghost)

	res, rpcErr := rig.submitBlock(t, blk)
	if rpcErr != nil {
		t.Fatalf("submitblock returned an RPC error: %v", rpcErr)
	}
	if s, _ := res.(string); s != "prev-blk-not-found" {
		t.Fatalf("submitblock = %v, want %q (Core validation.cpp:4217)", res, "prev-blk-not-found")
	}
}
