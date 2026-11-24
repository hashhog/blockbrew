package rpc

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// R3 differential fuzzer, night 1 (seed 739943, group G1): a block spending a
// coin whose scriptPubKey is exactly MAX_SCRIPT_SIZE (10,000) bytes connected
// fine, but blockbrew could not disconnect it again. Its undo record holds the
// script behind a 1-byte compression tag (10,001 bytes) and the undo decoder
// refused any compressed script over 10,000 bytes. Every reorg past that block
// failed and rolled back to the old tip, and submitblock's catch-all turned the
// error text ("compressed script length too large") into the script verdict
// "block-script-verify-flag-failed". Core v31.1 reorgs (compressor.h
// ScriptCompression::Unser bounds the RAW script length).

// bigScript builds a bare script of exactly n bytes that leaves OP_1 on the
// stack: OP_1 + 75-byte pushes each followed by OP_DROP + a shorter push and
// OP_DROP + OP_NOP padding (for n = 10,000 this is the night-1 trigger:
// OP_1 + 129x(PUSH75 OP_DROP) + PUSH63 OP_DROP + OP_NOP).
func bigScript(n int) []byte {
	s := []byte{0x51} // OP_1
	for n-len(s) >= 77+1 {
		s = append(s, 75)
		s = append(s, bytes.Repeat([]byte{0x01}, 75)...)
		s = append(s, 0x75) // OP_DROP
	}
	if rest := n - len(s) - 2; rest > 0 {
		push := rest
		if push > 75 {
			push = 75
		}
		s = append(s, byte(push))
		s = append(s, bytes.Repeat([]byte{0x01}, push)...)
		s = append(s, 0x75)
	}
	for len(s) < n {
		s = append(s, 0x61) // OP_NOP
	}
	return s
}

// reorgPastBigScriptSpend builds genesis..101, then block 102 funding a bare
// output whose scriptPubKey is scriptLen bytes (spending block 1's coinbase)
// and block 103 spending it, both through submitblock. It then submits a
// coinbase-only sibling branch 102'..104' forking at 101 and returns
// submitblock's answer for 104' (the block that makes the branch heavier and
// forces the reorg), plus the rig and the branch tip.
func reorgPastBigScriptSpend(t *testing.T, scriptLen int) (interface{}, *RPCError, *submitBlockTestRig, *wire.MsgBlock) {
	t.Helper()
	consensus.ResetAbortForTesting()
	t.Cleanup(consensus.ResetAbortForTesting)

	rig := newSubmitBlockRig(t, 101)
	if len(rig.tips) != 101 {
		t.Fatalf("precondition: rig has %d blocks, want 101", len(rig.tips))
	}
	n1 := rig.tips[0]
	n101 := rig.tips[100]

	cb1, err := rig.db.GetBlock(n1.Hash)
	if err != nil {
		t.Fatalf("GetBlock(1): %v", err)
	}
	cbValue := cb1.Transactions[0].TxOut[0].Value
	script := bigScript(scriptLen)
	if len(script) != scriptLen {
		t.Fatalf("precondition: script is %d bytes, want %d", len(script), scriptLen)
	}

	fund := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: cb1.Transactions[0].TxHash(), Index: 0},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: cbValue - 1_000, PkScript: script}},
	}
	spend := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: fund.TxHash(), Index: 0},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: cbValue - 2_000, PkScript: []byte{0x51}}},
	}

	b102 := buildRegtestBlockWithTxs(t, rig.params, n101, []*wire.MsgTx{fund})
	if res, rpcErr := rig.submitBlock(t, b102); rpcErr != nil || res != nil {
		t.Fatalf("precondition: block 102 (funds the %d-byte output): got %v %+v, want null", scriptLen, res, rpcErr)
	}
	n102 := rig.idx.GetNode(b102.Header.BlockHash())
	b103 := buildRegtestBlockWithTxs(t, rig.params, n102, []*wire.MsgTx{spend})
	if res, rpcErr := rig.submitBlock(t, b103); rpcErr != nil || res != nil {
		t.Fatalf("precondition: block 103 (spends the %d-byte output): got %v %+v, want null", scriptLen, res, rpcErr)
	}
	if tip, h := rig.cm.BestBlock(); tip != b103.Header.BlockHash() || h != 103 {
		t.Fatalf("precondition: tip %s@%d, want block 103", tip.String()[:16], h)
	}

	parent := n101
	var res interface{}
	var rpcErr *RPCError
	var side *wire.MsgBlock
	for h := 102; h <= 104; h++ {
		side = mineSideBlock(t, rig, parent, 7)
		res, rpcErr = rig.submitBlock(t, side)
		if h < 104 {
			if rpcErr != nil || res != "inconclusive" {
				t.Fatalf("precondition: side block %d': got %v %+v, want \"inconclusive\"", h, res, rpcErr)
			}
		}
		parent = rig.idx.GetNode(side.Header.BlockHash())
	}
	return res, rpcErr, rig, side
}

// TestSubmitBlockReorgsPastMaxScriptSizeSpend is the repro: Core reorgs to the
// heavier sibling branch; blockbrew master answered
// "block-script-verify-flag-failed" and stayed on 103.
func TestSubmitBlockReorgsPastMaxScriptSizeSpend(t *testing.T) {
	res, rpcErr, rig, side := reorgPastBigScriptSpend(t, 10_000)
	if rpcErr != nil || res != nil {
		t.Fatalf("heavier sibling of a block that spent a 10,000-byte (MAX_SCRIPT_SIZE) scriptPubKey: "+
			"submitblock got %v %+v, want null (Core reorgs)", res, rpcErr)
	}
	if tip, h := rig.cm.BestBlock(); tip != side.Header.BlockHash() || h != 104 {
		t.Fatalf("reorg past a 10,000-byte scriptPubKey spend did not happen: tip %s@%d, want 104'", tip.String()[:16], h)
	}
	if consensus.IsAborted() {
		t.Fatalf("node aborted during the reorg: %v", consensus.AbortReason())
	}
}

// Control: the same with a 9,999-byte scriptPubKey reorgs on master too.
func TestSubmitBlockReorgsPastMaxScriptSizeMinusOneSpend(t *testing.T) {
	res, rpcErr, rig, side := reorgPastBigScriptSpend(t, 9_999)
	if rpcErr != nil || res != nil {
		t.Fatalf("heavier sibling of a block that spent a 9,999-byte scriptPubKey: got %v %+v, want null", res, rpcErr)
	}
	if tip, h := rig.cm.BestBlock(); tip != side.Header.BlockHash() || h != 104 {
		t.Fatalf("control reorg did not happen: tip %s@%d, want 104'", tip.String()[:16], h)
	}
}

// A reorg that cannot disconnect the old tip (its undo record is gone) is a
// local failure, not a verdict on the submitted block. Core: DisconnectTip
// fails inside ActivateBestChain before the submitted block is ever checked,
// so submitblock's state catcher never fires and the answer is
// "inconclusive" (rpc/mining.cpp submitblock, validation.cpp
// ActivateBestChainStep). blockbrew's catch-all used to read the error text:
// the undo decoder's message contained "script" and became
// "block-script-verify-flag-failed"; any other disconnect failure became
// "rejected". Neither is a verdict Core gives, and the submitted block must
// not be marked invalid.
func TestSubmitBlockDisconnectFailureIsNotAVerdict(t *testing.T) {
	consensus.ResetAbortForTesting()
	t.Cleanup(consensus.ResetAbortForTesting)

	rig := newSubmitBlockRig(t, 3)
	oldTip, _ := rig.cm.BestBlock()
	if err := rig.db.DeleteBlockUndo(oldTip); err != nil {
		t.Fatalf("DeleteBlockUndo: %v", err)
	}

	parent := rig.idx.Genesis()
	var res interface{}
	var rpcErr *RPCError
	var side *wire.MsgBlock
	for h := 1; h <= 4; h++ {
		side = mineSideBlock(t, rig, parent, 7)
		res, rpcErr = rig.submitBlock(t, side)
		if h < 4 && (rpcErr != nil || res != "inconclusive") {
			t.Fatalf("precondition: side block %d': got %v %+v, want \"inconclusive\"", h, res, rpcErr)
		}
		parent = rig.idx.GetNode(side.Header.BlockHash())
	}
	if rpcErr != nil || res != "inconclusive" {
		t.Fatalf("heavier branch whose reorg cannot disconnect the old tip: got %v %+v, want \"inconclusive\" "+
			"(a failed disconnect is not a verdict on the submitted block)", res, rpcErr)
	}
	if tip, _ := rig.cm.BestBlock(); tip != oldTip {
		t.Fatalf("tip moved to %s although the old tip could not be disconnected", tip.String()[:16])
	}
	if n := rig.idx.GetNode(side.Header.BlockHash()); n == nil || n.Status.IsInvalid() {
		t.Fatalf("submitted block was marked invalid for a local disconnect failure")
	}
}
