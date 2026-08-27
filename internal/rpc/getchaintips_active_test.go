package rpc

import "testing"

// TestGetChainTipsActiveIsValidatedTip pins the #43 blockbrew slice:
// getchaintips must report the VALIDATED chain tip as "active", not the
// header-index best tip.  We connect 3 blocks (validated tip = h3) then push
// headers-only to h5.  Active must be h3; the header tip appears separately as
// "headers-only" with branchLen 2.  FAILS AT PARENT (which labelled the h5
// header tip "active").
func TestGetChainTipsActiveIsValidatedTip(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 3)

	// Push two header-only blocks above the validated tip (no ConnectBlock).
	prev := rig.tips[len(rig.tips)-1] // h3 node
	for i := 0; i < 2; i++ {
		blk := buildRegtestBlock(t, rig.params, prev)
		node, err := rig.idx.AddHeader(blk.Header, true)
		if err != nil {
			t.Fatalf("AddHeader (header-only) at height %d: %v", prev.Height+1, err)
		}
		prev = node
	}
	headerTipHeight := prev.Height // 5

	res, rpcErr := rig.server.handleGetChainTips()
	if rpcErr != nil {
		t.Fatalf("handleGetChainTips: %v", rpcErr)
	}
	tips := res.([]ChainTip)
	if len(tips) == 0 {
		t.Fatal("no tips returned")
	}

	active := tips[0]
	if active.Status != "active" {
		t.Fatalf("tips[0].Status = %q, want active", active.Status)
	}
	if active.Height != 3 {
		t.Errorf("active tip height = %d, want 3 (the VALIDATED tip, not the header tip)", active.Height)
	}
	validated := rig.cm.BestBlockNode()
	if active.Hash != validated.Hash.String() {
		t.Errorf("active tip hash = %s, want validated tip %s", active.Hash, validated.Hash.String())
	}

	// The header-only tip must appear separately.
	var headersOnly *ChainTip
	for i := range tips {
		if tips[i].Status == "headers-only" {
			headersOnly = &tips[i]
		}
	}
	if headersOnly == nil {
		t.Fatal("expected a headers-only tip for the header chain ahead of the validated tip")
	}
	if headersOnly.Height != headerTipHeight {
		t.Errorf("headers-only tip height = %d, want %d", headersOnly.Height, headerTipHeight)
	}
	if headersOnly.BranchLen != headerTipHeight-3 {
		t.Errorf("headers-only branchLen = %d, want %d", headersOnly.BranchLen, headerTipHeight-3)
	}
}
