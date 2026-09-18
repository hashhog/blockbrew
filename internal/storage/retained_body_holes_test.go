package storage

import (
	"testing"
)

// Retained-range body-hole audit. The check that takes the contiguous
// suffix as its own floor cannot fail: the hole decides where it starts
// looking (nimrod 87ac1d8: checked=145, hole 966302..967347 never
// visited). Scan from FirstBody.
//
// CONTROL companion to TestBodyFloor_* / TestPrunedHistory_*.

func seedRange(t *testing.T, c *ChainDB, lo, hi int32, withBody func(int32) bool) {
	t.Helper()
	for n := lo; n <= hi; n++ {
		h := historyFloorHash(n)
		if err := c.SetBlockHeight(n, h); err != nil {
			t.Fatalf("SetBlockHeight(%d): %v", n, err)
		}
		if withBody(n) {
			if err := c.StoreBlock(h, historyFloorBlock(n)); err != nil {
				t.Fatalf("StoreBlock(%d): %v", n, err)
			}
		}
	}
}

func deleteBody(t *testing.T, c *ChainDB, n int32) {
	t.Helper()
	h := historyFloorHash(n)
	if err := c.DB().Delete(MakeBlockDataKey(h)); err != nil {
		t.Fatalf("delete body %d: %v", n, err)
	}
	if c.HasBlockBody(h) {
		t.Fatalf("body still present at %d", n)
	}
}

func TestRetainedBody_AuditFindsInteriorHoleAndIgnoresPrefix(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedRange(t, c, 0, 12, func(n int32) bool { return true })
	deleteBody(t, c, 8)

	audit := c.AuditRetainedBodies(12, -1, 16, nil)
	if audit.Floor != 0 {
		t.Fatalf("floor = %d, want 0 (height 1 has a body)", audit.Floor)
	}
	if audit.Tip != 12 {
		t.Fatalf("tip = %d, want 12", audit.Tip)
	}
	if audit.Checked != 13 {
		t.Fatalf("checked = %d, want 13", audit.Checked)
	}
	if audit.HoleCount != 1 {
		t.Fatalf("holeCount = %d, want 1", audit.HoleCount)
	}
	if len(audit.Holes) != 1 || audit.Holes[0] != 8 {
		t.Fatalf("holes = %v, want [8]", audit.Holes)
	}
	if audit.Truncated {
		t.Fatal("truncated")
	}
}

func TestRetainedBody_AuditWithPruneHeightOnlyScansRetainedRange(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedRange(t, c, 0, 10, func(n int32) bool { return true })
	deleteBody(t, c, 2)
	deleteBody(t, c, 7)

	audit := c.AuditRetainedBodies(10, 5, 16, nil)
	if audit.Floor != 5 {
		t.Fatalf("floor = %d, want 5", audit.Floor)
	}
	if audit.Checked != 6 {
		t.Fatalf("checked = %d, want 6", audit.Checked)
	}
	if audit.HoleCount != 1 || len(audit.Holes) != 1 || audit.Holes[0] != 7 {
		t.Fatalf("holes = %v count=%d, want [7]", audit.Holes, audit.HoleCount)
	}
}

func TestRetainedBody_UnretainedPrefixIsAFloorNotHoles(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedRange(t, c, 0, 10, func(n int32) bool { return n == 0 || n >= 6 })

	audit := c.AuditRetainedBodies(10, -1, 16, nil)
	if audit.Floor != 6 {
		t.Fatalf("floor = %d, want 6 (first body)", audit.Floor)
	}
	if audit.Checked != 5 {
		t.Fatalf("checked = %d, want 5", audit.Checked)
	}
	if audit.HoleCount != 0 {
		t.Fatalf("prefix must not be holes, holeCount=%d holes=%v", audit.HoleCount, audit.Holes)
	}
}

func TestRetainedBody_NegativeControlDenseRangeAuditsCleanThenNoticesAPunch(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedRange(t, c, 0, 6, func(n int32) bool { return true })
	audit := c.AuditRetainedBodies(6, -1, 16, nil)
	if audit.Floor != 0 || audit.HoleCount != 0 || audit.Checked != 7 {
		t.Fatalf("clean audit = %+v, want floor=0 holes=0 checked=7", audit)
	}
	deleteBody(t, c, 3)
	broken := c.AuditRetainedBodies(6, -1, 16, nil)
	if broken.HoleCount != 1 || len(broken.Holes) != 1 || broken.Holes[0] != 3 {
		t.Fatalf("punched hole not reported: %+v", broken)
	}
}

func TestRetainedBody_NegativeControlLargeHoleAboveClaimedFloorIsReported(t *testing.T) {
	// Live 87ac1d8: 1,046 missing bodies sat above first-body 952185.
	// An audit that infers its floor from the contiguous suffix starts
	// at 967348 and logs contiguous. Punch a hole above the first body
	// and the default path (pruneHeight=-1) must still report it.
	c := NewChainDB(NewMemDB())
	seedRange(t, c, 0, 20, func(n int32) bool {
		return n == 0 || (n >= 6 && n <= 10) || n >= 14
	})
	claimed, ok := c.FirstBody(20, nil)
	if !ok || claimed != 6 {
		t.Fatalf("FirstBody = %d, %v; want 6, true", claimed, ok)
	}
	suffix, ok := c.BodyFloor(20, nil)
	if !ok || suffix != 14 {
		t.Fatalf("BodyFloor = %d, %v; want 14, true", suffix, ok)
	}
	audit := c.AuditRetainedBodies(20, -1, 16, nil)
	if audit.Floor != claimed {
		t.Fatalf("audit floor = %d, want first body %d (not suffix %d)", audit.Floor, claimed, suffix)
	}
	if audit.Tip != 20 {
		t.Fatalf("tip = %d, want 20", audit.Tip)
	}
	if audit.Checked != 15 {
		t.Fatalf("checked = %d, want 15 (6..20)", audit.Checked)
	}
	if audit.HoleCount != 3 {
		t.Fatalf("holeCount = %d, want 3", audit.HoleCount)
	}
	want := []int32{11, 12, 13}
	if len(audit.Holes) != 3 || audit.Holes[0] != 11 || audit.Holes[1] != 12 || audit.Holes[2] != 13 {
		t.Fatalf("holes = %v, want %v", audit.Holes, want)
	}
	fromClaimed := c.AuditRetainedBodies(20, claimed, 16, nil)
	if fromClaimed.HoleCount != 3 {
		t.Fatalf("from claimed floor: holes=%v count=%d", fromClaimed.Holes, fromClaimed.HoleCount)
	}
}

func TestRetainedBody_NegativeControlLargeHoleInOtherwiseCompleteChain(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedRange(t, c, 0, 20, func(n int32) bool { return true })
	claimed := c.AuditRetainedBodies(20, -1, 16, nil).Floor
	if claimed != 0 {
		t.Fatalf("complete floor = %d, want 0", claimed)
	}
	for n := int32(8); n <= 12; n++ {
		deleteBody(t, c, n)
	}
	broken := c.AuditRetainedBodies(20, -1, 16, nil)
	if broken.Floor != claimed {
		t.Fatalf("must not raise the floor over the hole: floor=%d", broken.Floor)
	}
	if broken.HoleCount != 5 {
		t.Fatalf("holeCount = %d, want 5", broken.HoleCount)
	}
	want := []int32{8, 9, 10, 11, 12}
	if len(broken.Holes) != 5 {
		t.Fatalf("holes = %v, want %v", broken.Holes, want)
	}
	for i, h := range want {
		if broken.Holes[i] != h {
			t.Fatalf("holes = %v, want %v", broken.Holes, want)
		}
	}
	explicit := c.AuditRetainedBodies(20, claimed, 16, nil)
	if explicit.HoleCount != broken.HoleCount {
		t.Fatalf("explicit claimed floor disagrees: %+v vs %+v", explicit, broken)
	}
}

func TestRetainedBody_IndexedMissingIsAHoleUnknownHeightIsNot(t *testing.T) {
	c := NewChainDB(NewMemDB())
	seedRange(t, c, 0, 5, func(n int32) bool { return n != 3 })
	// Height 3 has an index row and no body — a hole.
	// Height 99 has neither — not in range.
	audit := c.AuditRetainedBodies(5, -1, 16, nil)
	if audit.HoleCount != 1 || len(audit.Holes) != 1 || audit.Holes[0] != 3 {
		t.Fatalf("want hole at 3, got %+v", audit)
	}
}
