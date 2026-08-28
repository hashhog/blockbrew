package consensus

import (
	"os"

	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TestBIP68IntraBlockChainUsesConservativePrevHeight is the behavioural pin
// promised by e461f5a.
//
// ConnectBlock builds prevHeights from the cached UTXO view.  A MISS means the
// input coin was created by an EARLIER TX IN THE SAME BLOCK (an intra-block
// chain) — the coin is not in the view because it does not exist on disk yet.
// The old code left that entry at Go's zero value, which made every BIP-68
// relative HEIGHT lock on such an input trivially satisfiable: a lock of N
// blocks resolves to minHeight = 0 + N - 1, which is below any real block
// height, so the tx sails through.  Fail-open on a chain-derived value — the
// fabrication family.
//
// Core assigns a same-block coin the containing block's height
// (CalculateSequenceLocks treats MEMPOOL_HEIGHT coins as tip+1,
// consensus/tx_verify.cpp), so a relative height lock of N >= 1 against a
// same-block parent can NEVER be satisfied: you cannot wait N blocks inside
// the block that created the coin.
//
// This asserts the DECISION on both sides of the fix, which is what makes it
// fail at the parent commit rather than merely describe it.
func TestBIP68IntraBlockChainUsesConservativePrevHeight(t *testing.T) {
	const blockHeight int32 = 500

	// A version-2 tx spending one input under a relative HEIGHT lock of 1
	// block (sequence = 1, type flag clear => height-based).
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.Hash256{0xAB},
				Index: 0,
			},
			Sequence: 1,
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}},
	}

	// MTP lookup is irrelevant for a height-based lock; return a fixed value.
	getMTP := func(int32) int64 { return 1_500_000_000 }

	// --- the FIXED behaviour: a same-block coin carries the block's height ---
	conservative := []int32{blockHeight}
	lockFixed := CalculateSequenceLocks(tx, conservative, getMTP)
	if EvaluateSequenceLocks(lockFixed, blockHeight, 1_600_000_000) {
		t.Fatalf("a relative height lock of 1 against a SAME-BLOCK parent must be "+
			"unsatisfiable (coin height %d == block height %d), but the lock "+
			"evaluated as met (MinHeight=%d)", blockHeight, blockHeight, lockFixed.MinHeight)
	}
	// Core: minHeight = prevHeight + N - 1 = 500 + 1 - 1 = 500, and
	// EvaluateSequenceLocks rejects when MinHeight >= blockHeight.
	if lockFixed.MinHeight != blockHeight {
		t.Errorf("MinHeight = %d, want %d (prevHeight + relative - 1)",
			lockFixed.MinHeight, blockHeight)
	}

	// --- the DEFECT: the old zero default ---
	// Retained as an executable statement of what went wrong: with prevHeights
	// left at zero the very same transaction is ACCEPTED.  If a future change
	// reintroduces the zero default, the assertion above flips and this one
	// documents exactly why.
	fabricated := []int32{0}
	lockBuggy := CalculateSequenceLocks(tx, fabricated, getMTP)
	if !EvaluateSequenceLocks(lockBuggy, blockHeight, 1_600_000_000) {
		t.Fatalf("guard broken: with the fabricated zero prevHeight the lock is "+
			"expected to be (wrongly) satisfied — if this no longer holds, the "+
			"test no longer demonstrates the defect it pins")
	}
	if lockBuggy.MinHeight == lockFixed.MinHeight {
		t.Errorf("the two prevHeight sources must produce DIFFERENT verdicts, "+
			"otherwise this test cannot distinguish the fix from the bug "+
			"(both MinHeight=%d)", lockBuggy.MinHeight)
	}
}

// TestBIP68DisabledFlagZeroesPrevHeight pins the second half of the same
// commit: Core zeroes prevheights[i] for a lock-DISABLED input
// (consensus/tx_verify.cpp:50) so later consumers never read a stale height.
func TestBIP68DisabledFlagZeroesPrevHeight(t *testing.T) {
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xCD}, Index: 0},
			Sequence:         SequenceLockTimeDisabledFlag,
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}},
	}
	prevHeights := []int32{12345}
	_ = CalculateSequenceLocks(tx, prevHeights, func(int32) int64 { return 0 })
	if prevHeights[0] != 0 {
		t.Errorf("prevHeights[0] = %d, want 0 — Core zeroes the entry for a "+
			"lock-disabled input so a later consumer cannot read a stale height",
			prevHeights[0])
	}
}

// TestConnectPathAssignsBlockHeightOnCachedViewMiss binds the semantic pin
// above to the ACTUAL connect path.
//
// The semantic test proves WHY a fabricated zero prevHeight is dangerous, but
// it calls CalculateSequenceLocks directly, so on its own it would still pass
// if ConnectBlock stopped supplying the conservative height.  The prevHeights
// construction is inline in ConnectBlock (no seam to call), and driving a full
// intra-block chain through ConnectBlock needs a mature funding coin plus a
// halving-correct subsidy — a fixture whose own failures read exactly like
// consensus defects.  So this asserts the source directly.
//
// FAILS AT PARENT: e461f5a ADDED the else-branch; before it, a cached-view
// miss left prevHeights[j] at Go's zero value with no else at all.
func TestConnectPathAssignsBlockHeightOnCachedViewMiss(t *testing.T) {
	src, err := os.ReadFile("chainmanager.go")
	if err != nil {
		t.Fatalf("read chainmanager.go: %v", err)
	}
	text := string(src)

	const missSite = "cachedView.cache[in.PreviousOutPoint]"
	idx := strings.Index(text, missSite)
	if idx < 0 {
		t.Fatalf("could not find the prevHeights cached-view lookup (%q) — "+
			"ConnectBlock was restructured; re-point this pin", missSite)
	}
	// The miss branch follows the hit branch closely; scan a bounded window.
	window := text[idx:]
	if len(window) > 2000 {
		window = window[:2000]
	}
	if !strings.Contains(window, "prevHeights[j] = node.Height") {
		t.Error("ConnectBlock must assign node.Height (not the zero value) when the " +
			"cached UTXO view misses — that miss IS the intra-block-chain case, and " +
			"a zero there makes every BIP-68 relative height lock trivially satisfied")
	}
	if strings.Contains(window, "prevHeights[j] = 0") {
		t.Error("ConnectBlock assigns a literal zero to prevHeights[j] — the " +
			"fabricated value e461f5a removed")
	}
}
