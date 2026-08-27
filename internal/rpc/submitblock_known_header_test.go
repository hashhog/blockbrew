package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
)

// TestSubmitBlockAfterKnownHeaderStoresBody is the regression test for the
// BIP-22 "duplicate" divergence.
//
// Bug: submitblock called headerIndex.AddHeader first and returned "duplicate"
// on ErrDuplicateHeader — BEFORE storing the body and before
// ProcessSubmittedBlock. So a block whose HEADER was already known (submitted
// via submitheader, or seen over P2P ahead of its body) could never be
// submitted at all: the caller was told "duplicate" while zero bodies landed.
//
// Core answers "duplicate" only when the block DATA was already known AND
// accepted — `if (!new_block && accepted)` AFTER an unconditional
// ProcessNewBlock (rpc/mining.cpp:1094-1098). Core looks up only the PARENT
// hash beforehand, and solely to run UpdateUncommittedBlockStructures. The
// header-lookup early-return at mining.cpp:742-749 belongs to getblocktemplate
// "proposal" mode, not to submitblock.
//
// It also silently defeated boot-smoke's own body feed, which counts BIP-22
// "duplicate" as accepted: the gate reported "bodies via submitblock: 299"
// while nothing was stored, re-creating the very bg-validator "failed to get
// block at height 1" failure that adding blockbrew to BODY_FEED_IMPLS on
// 2026-07-15 was supposed to fix.
//
// The invariant under test is the one a caller actually cares about: after the
// header is known, submitblock must leave the node HOLDING the block — not
// merely acknowledging it.
func TestSubmitBlockAfterKnownHeaderStoresBody(t *testing.T) {
	rig := newSubmitBlockRig(t, 2)

	tip := rig.tips[len(rig.tips)-1]
	blk := buildRegtestBlock(t, rig.params, tip)
	hash := blk.Header.BlockHash()

	// Pre-seed the HEADER only — exactly what submitheader does, or a P2P
	// headers message arriving ahead of the body.
	if _, err := rig.idx.AddHeader(blk.Header, false); err != nil {
		t.Fatalf("pre-seeding header: %v", err)
	}
	seeded := rig.idx.GetNode(hash)
	if seeded == nil {
		t.Fatalf("precondition: header should be in the index")
	}
	if seeded.Status&consensus.StatusDataStored != 0 {
		t.Fatalf("precondition: block data must NOT be present yet")
	}

	res, rpcErr := rig.submitBlock(t, blk)
	if rpcErr != nil {
		t.Fatalf("submitblock returned an RPC error: %v", rpcErr)
	}
	if s, _ := res.(string); s == "duplicate" {
		t.Fatalf(`submitblock answered "duplicate" for a block whose only prior ` +
			`trace was its HEADER, so the body was never stored — this is the ` +
			`shipped divergence (Core answers duplicate only when the block ` +
			`DATA was already known)`)
	}

	after := rig.idx.GetNode(hash)
	if after == nil {
		t.Fatalf("header node vanished after submitblock")
	}
	if after.Status&consensus.StatusDataStored == 0 {
		t.Errorf("block data still absent after submitblock (result=%v)", res)
	}
}

// TestSubmitBlockGenuineDuplicateStillDuplicate pins the other direction: once
// the block DATA is known, submitblock must still answer "duplicate", matching
// Core's `!new_block && accepted`. The fix must not turn a real duplicate into
// a silent re-process.
func TestSubmitBlockGenuineDuplicateStillDuplicate(t *testing.T) {
	rig := newSubmitBlockRig(t, 2)

	tip := rig.tips[len(rig.tips)-1]
	blk := buildRegtestBlock(t, rig.params, tip)

	res1, rpcErr := rig.submitBlock(t, blk)
	if rpcErr != nil {
		t.Fatalf("first submitblock errored: %v", rpcErr)
	}
	if s, _ := res1.(string); s == "duplicate" {
		t.Fatalf("first submitblock should not report duplicate, got %v", res1)
	}

	res2, rpcErr := rig.submitBlock(t, blk)
	if rpcErr != nil {
		t.Fatalf("second submitblock errored: %v", rpcErr)
	}
	if s, _ := res2.(string); s != "duplicate" {
		t.Errorf(`re-submitting a block whose DATA is already known must answer `+
			`"duplicate" (Core: !new_block && accepted), got %v`, res2)
	}
}

// TestSubmitBlockDuplicateStillActivates pins #73 layer B — the 964241 wedge's
// blocked repair path, reconstructed exactly as observed live on mainnet
// 2026-08-27: header known, body on disk, StatusDataStored set, but the block
// NEVER CONNECTED. Core's submitblock answers "duplicate" for such a block but
// still runs ProcessNewBlock unconditionally (rpc/mining.cpp:1094-1098), whose
// ActivateBestChain connects a stored-but-unconnected best-chain block. Our
// StatusDataStored early-return skipped that, so submitblock(964241) answered
// "duplicate" while the tip stayed put — the manual repair path was
// permanently gated. The BIP-22 answer stays "duplicate"; the ACTIVATION must
// happen anyway.
func TestSubmitBlockDuplicateStillActivates(t *testing.T) {
	rig := newSubmitBlockRig(t, 2)

	tip := rig.tips[len(rig.tips)-1]
	blk := buildRegtestBlock(t, rig.params, tip)
	hash := blk.Header.BlockHash()

	// Strand the block: header + body + StatusDataStored, no connect.
	if _, err := rig.idx.AddHeader(blk.Header, false); err != nil {
		t.Fatalf("pre-seeding header: %v", err)
	}
	if err := rig.db.StoreBlock(hash, blk); err != nil {
		t.Fatalf("pre-storing body: %v", err)
	}
	rig.idx.MarkDataStored(hash)

	_, beforeH := rig.cm.BestBlock()

	res, rpcErr := rig.submitBlock(t, blk)
	if rpcErr != nil {
		t.Fatalf("submitblock errored: %v", rpcErr)
	}
	if s, _ := res.(string); s != "duplicate" {
		t.Errorf(`stored-block resubmission must still answer "duplicate" `+
			`(Core: !new_block && accepted), got %v`, res)
	}

	_, afterH := rig.cm.BestBlock()
	if afterH != beforeH+1 {
		t.Fatalf("stored-but-unconnected block was NOT activated by submitblock: "+
			"tip height %d -> %d (want %d). This is the #73 strand: \"duplicate\" "+
			"without Core's unconditional ProcessNewBlock leaves the node wedged "+
			"behind a block it already holds.", beforeH, afterH, beforeH+1)
	}
}
