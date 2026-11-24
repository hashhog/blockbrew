package rpc

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// submitblockbatch (blockbrew-only; Core has no batch RPC, so its per-block
// semantics must equal submitblock's) must run the same AcceptBlock-time
// contextual checks on a side-branch block before storing it. On master the
// batch arm stored a side block with a wrong BIP34 coinbase height and only
// then failed it as a lighter branch.

func neonSBBatch(t *testing.T, rig *submitBlockTestRig, blk *wire.MsgBlock) string {
	t.Helper()
	var w byteWriter
	if err := blk.Serialize(&w); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	raw, err := json.Marshal([]interface{}{[]string{hex.EncodeToString(w.bytes)}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, rpcErr := rig.server.handleSubmitBlockBatch(raw)
	if rpcErr != nil {
		t.Fatalf("submitblockbatch returned an RPC error: %+v", rpcErr)
	}
	results, ok := res.([]interface{})
	if !ok || len(results) != 1 {
		t.Fatalf("submitblockbatch returned %T %v, want a 1-element array", res, res)
	}
	s, _ := results[0].(string)
	return s
}

func TestNeonSubmitBlockBatchSideBranchBadCbHeightNotStored(t *testing.T) {
	rig := newSubmitBlockRig(t, 2) // tip at height 2; side block at height 1 is lighter
	blk := buildRegtestBlock(t, rig.params, rig.idx.Genesis())
	blk.Transactions[0].TxIn[0].SignatureScript = []byte{0x55, 0x00} // claims height 5 at height 1
	neonSBMine(t, blk)
	tipBefore, hBefore := rig.cm.BestBlock()

	got := neonSBBatch(t, rig, blk)
	if !strings.HasPrefix(got, "block context check failed") || !strings.Contains(got, "height") {
		t.Fatalf("submitblockbatch side block with bad BIP34 height: got %q, want a block-context (bad-cb-height) refusal", got)
	}
	if rig.db.HasBlock(blk.Header.BlockHash()) {
		t.Fatalf("submitblockbatch stored a side-branch block that fails ContextualCheckBlock (Core bad-cb-height)")
	}
	if tip, h := rig.cm.BestBlock(); tip != tipBefore || h != hBefore {
		t.Fatalf("tip moved")
	}
}

// Control: a valid lighter side block is still stored by the batch arm, as on
// master (it is then reported as not connecting, being lighter).
func TestNeonSubmitBlockBatchSideBranchValidStillStored(t *testing.T) {
	rig := newSubmitBlockRig(t, 2)
	blk := buildRegtestBlock(t, rig.params, rig.idx.Genesis())
	blk.Header.Timestamp++ // differ from the active height-1 block
	neonSBMine(t, blk)
	if _, h := rig.cm.BestBlock(); rig.idx.GetNode(blk.Header.BlockHash()) != nil || h != 2 {
		t.Fatalf("fixture: side block must be new and lighter than the tip")
	}
	got := neonSBBatch(t, rig, blk)
	if strings.HasPrefix(got, "block context check failed") {
		t.Fatalf("valid side block refused by the context gate: %q", got)
	}
	if !rig.db.HasBlock(blk.Header.BlockHash()) {
		t.Fatalf("valid side-branch block not stored by submitblockbatch (result %q)", got)
	}
}
