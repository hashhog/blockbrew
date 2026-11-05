package consensus

import "testing"

// TestReconsideredDisplacedBlockSurvivesSecondRestart pins failed_reorg
// scenario E, row failed_reorg/e-restart/displaced-header: invalidateblock(m4a)
// moves the node to s4; restart; reconsiderblock(m4a) clears the failure flag
// and, on a tie, the node stays on s4; restart again. m4a is now a stored,
// connected block off the active chain with no failure flag, and the boot
// hydration (walk back from the tip + persisted failure flags) never reached
// it, so getblockheader(m4a) answered -5 "Block not found" where Core
// (whose block index holds every block ever stored) answers with
// confirmations -1.
func TestReconsideredDisplacedBlockSurvivesSecondRestart(t *testing.T) {
	params, cm, utxoSet, chainDB, m, s := reconsiderRestartFixture(t)
	if err := cm.InvalidateBlock(m[3].Hash); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}
	cleanStop(t, cm, utxoSet, chainDB)

	cm2, utxo2 := reboot(t, params, chainDB)
	if err := cm2.ReconsiderBlock(m[3].Hash); err != nil {
		t.Fatalf("ReconsiderBlock: %v", err)
	}
	if best, _ := cm2.BestBlock(); best != s[1].Hash {
		t.Fatalf("tip after reconsider = %s, want s4", best.String()[:16])
	}
	cleanStop(t, cm2, utxo2, chainDB)

	cm3, _ := reboot(t, params, chainDB)
	if best, _ := cm3.BestBlock(); best != s[1].Hash {
		t.Fatalf("tip after second restart = %s, want s4", best.String()[:16])
	}
	for i, n := range []*BlockNode{m[2], m[3]} {
		if cm3.headerIndex.GetNode(n.Hash) == nil {
			t.Errorf("after second restart: displaced block m%da is missing from the index (getblockheader would say Block not found)", i+3)
		}
	}
	if cm3.IsInMainChain(m[3].Hash) {
		t.Errorf("m4a must not be on the active chain")
	}
}
