package mempool

// W73 BIP-125 RBF comprehensive audit tests.
//
// Covers the four gates added/fixed in this wave:
//
//   Gate 1+2: ancestor-inherited RBF signaling (Core rbf.cpp:24-50).
//             A conflicting tx whose *ancestor* signals nSequence<=0xfffffffd
//             must be accepted as replaceable even if the conflicting tx itself
//             has all inputs at nSequence=0xffffffff.
//   Gate 3:   Rule #3 equal-fee boundary (rbf.cpp:109-112).
//             replacement_fees == original_fees must PASS Rule 3 (Rule 4 will
//             then reject if the bump is insufficient). Pre-fix blockbrew used
//             `<=` which wrongly rejected equal-fee replacements.
//   Gate 4:   EntriesAndTxidsDisjoint (rbf.cpp:85-98, validation.cpp:1356).
//             Replacement's in-mempool ancestors must not overlap with direct
//             conflicts — i.e., the replacement must not spend an output of the
//             tx it is trying to replace.
//   Gate 5:   Rule #4 uses IncrementalRelayFee, not MinRelayFeeRate.
//             Both default to 1000 sat/kvB, but the wrong field was referenced.

import (
	"errors"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ---- helpers ----------------------------------------------------------------

// addPoolEntry injects a TxEntry directly into mp.pool and wires outpoints.
// Caller must hold mp.mu.
func addPoolEntry(mp *Mempool, entry *TxEntry) {
	mp.pool[entry.TxHash] = entry
	for _, in := range entry.Tx.TxIn {
		mp.outpoints[in.PreviousOutPoint] = entry.TxHash
	}
	mp.totalSize += entry.Size
}

// makeRBFTx builds a tx spending the given outpoints with sequence=0 (signals RBF).
func makeRBFTx(inputs []wire.OutPoint, outputValue int64) *wire.MsgTx {
	tx := &wire.MsgTx{Version: 2}
	for _, op := range inputs {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: op,
			Sequence:         0, // signals RBF
		})
	}
	tx.TxOut = []*wire.TxOut{{
		Value:    outputValue,
		PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	}}
	return tx
}

// makeFinalTx builds a tx spending the given outpoints with sequence=0xffffffff (does NOT signal RBF).
func makeFinalTx(inputs []wire.OutPoint, outputValue int64) *wire.MsgTx {
	tx := &wire.MsgTx{Version: 2}
	for _, op := range inputs {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: op,
			Sequence:         0xFFFFFFFF, // does NOT signal RBF
		})
	}
	tx.TxOut = []*wire.TxOut{{
		Value:    outputValue,
		PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	}}
	return tx
}

// ---- Gate 1+2: ancestor-inherited RBF signaling ----------------------------

// TestRBFAncestorInheritedSignaling verifies that a conflicting tx is
// treated as opt-in replaceable when one of its *mempool ancestors* signals
// RBF, even though the conflicting tx itself has all inputs at
// nSequence=0xffffffff (does not directly signal).
//
// Topology:
//
//	grandparent G (signals RBF, sequence=0)
//	  └─ parent P (does NOT signal RBF, sequence=0xffffffff, spends G's output)
//	       └─ conflict C (does NOT signal RBF, sequence=0xffffffff, spends P's output)
//
// A replacement that conflicts with C should be allowed because G (ancestor of C)
// signals RBF. Mirrors Core IsRBFOptIn (rbf.cpp:39-48).
func TestRBFAncestorInheritedSignaling(t *testing.T) {
	utxoSet := newTestUTXOSet()

	// Seed UTXO for grandparent G.
	var seedHash wire.Hash256
	seedHash[0] = 0xA0
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 300_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)
	mp.mu.Lock()

	// Grandparent G: signals RBF (sequence=0).
	txG := makeRBFTx([]wire.OutPoint{opSeed}, 290_000)
	hashG := txG.TxHash()
	opG0 := wire.OutPoint{Hash: hashG, Index: 0}
	addPoolEntry(mp, &TxEntry{
		Tx: txG, TxHash: hashG, Fee: 10_000, Size: 200,
		Time: time.Now(), AncestorFee: 10_000, AncestorSize: 200,
		DescendantFee: 10_000, DescendantSize: 200,
	})

	// Parent P: does NOT signal RBF, but inherits from G.
	txP := makeFinalTx([]wire.OutPoint{opG0}, 280_000)
	hashP := txP.TxHash()
	opP0 := wire.OutPoint{Hash: hashP, Index: 0}
	pEntry := &TxEntry{
		Tx: txP, TxHash: hashP, Fee: 10_000, Size: 200,
		Time: time.Now(), AncestorFee: 20_000, AncestorSize: 400,
		DescendantFee: 10_000, DescendantSize: 200,
		Depends: []wire.Hash256{hashG},
	}
	addPoolEntry(mp, pEntry)
	mp.pool[hashG].SpentBy = append(mp.pool[hashG].SpentBy, hashP)

	// Conflict C: does NOT signal RBF, spends P's output.
	txC := makeFinalTx([]wire.OutPoint{opP0}, 270_000)
	hashC := txC.TxHash()
	cEntry := &TxEntry{
		Tx: txC, TxHash: hashC, Fee: 10_000, Size: 200,
		Time: time.Now(), AncestorFee: 30_000, AncestorSize: 600,
		DescendantFee: 10_000, DescendantSize: 200,
		Depends: []wire.Hash256{hashP},
	}
	addPoolEntry(mp, cEntry)
	mp.pool[hashP].SpentBy = append(mp.pool[hashP].SpentBy, hashC)

	// Replacement tries to spend P's output (conflicts with C).
	// It also needs enough fee to pass Rule 3 and Rule 4.
	// C's fee is 10_000 sat; replacement needs fee > 10_000 AND enough bump.
	// Replacement spends opP0 (same outpoint as C). Input value from mempool lookup
	// would be 280_000 sat (P's output). Output = 260_000 → fee = 20_000.
	// 20_000 > 10_000 (Rule 3 ok). Additional = 10_000 > minBump (Rule 4 ok).
	replacement := makeFinalTx([]wire.OutPoint{opP0}, 260_000)
	// replacement itself does NOT signal RBF either (sequence=0xffffffff),
	// but C's ancestor G does — so Rule 1 must pass.

	conflicts := map[wire.Hash256]bool{hashC: true}

	// totalInputValue for the replacement: P's output = 280_000.
	err := mp.checkRBFLocked(replacement, conflicts, 280_000)
	mp.mu.Unlock()

	if err != nil {
		t.Fatalf("ancestor-inherited RBF should succeed (G signals for C), got: %v", err)
	}
}

// TestRBFNoAncestorSignaling verifies rejection when neither the conflicting tx
// nor any of its ancestors signal RBF.
//
// Topology: A → B (conflict). Neither A nor B signals RBF.
// Replacement that conflicts with B should be rejected with ErrRBFNotSignaled.
func TestRBFNoAncestorSignaling(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var seedHash wire.Hash256
	seedHash[0] = 0xB0
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 200_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)
	mp.mu.Lock()

	// A: does not signal RBF.
	txA := makeFinalTx([]wire.OutPoint{opSeed}, 190_000)
	hashA := txA.TxHash()
	opA0 := wire.OutPoint{Hash: hashA, Index: 0}
	addPoolEntry(mp, &TxEntry{
		Tx: txA, TxHash: hashA, Fee: 10_000, Size: 200,
		Time: time.Now(), AncestorFee: 10_000, AncestorSize: 200,
		DescendantFee: 10_000, DescendantSize: 200,
	})

	// B (conflict): also does not signal RBF.
	txB := makeFinalTx([]wire.OutPoint{opA0}, 180_000)
	hashB := txB.TxHash()
	bEntry := &TxEntry{
		Tx: txB, TxHash: hashB, Fee: 10_000, Size: 200,
		Time: time.Now(), AncestorFee: 20_000, AncestorSize: 400,
		DescendantFee: 10_000, DescendantSize: 200,
		Depends: []wire.Hash256{hashA},
	}
	addPoolEntry(mp, bEntry)
	mp.pool[hashA].SpentBy = append(mp.pool[hashA].SpentBy, hashB)

	replacement := makeRBFTx([]wire.OutPoint{opA0}, 160_000)
	conflicts := map[wire.Hash256]bool{hashB: true}

	err := mp.checkRBFLocked(replacement, conflicts, 190_000)
	mp.mu.Unlock()

	if !errors.Is(err, ErrRBFNotSignaled) {
		t.Fatalf("expected ErrRBFNotSignaled when no ancestor signals, got: %v", err)
	}
}

// ---- Gate 3: Rule #3 equal-fee boundary ------------------------------------

// TestRBFRule3EqualFeePassesRule3 verifies that replacement_fees == original_fees
// passes Rule #3. Core rbf.cpp:109-112 rejects only when `<`, not `<=`.
// Equal fees must still fail Rule #4 (insufficient bandwidth bump), but that
// is a different sentinel — ErrRBFInsufficientFee from the Rule 4 path.
//
// Pre-fix blockbrew used `if newFee <= totalConflictingFee` which caused an
// equal-fee replacement to fail with a Rule-3-style error instead of Rule-4.
func TestRBFRule3EqualFeePassesRule3(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var seedHash wire.Hash256
	seedHash[0] = 0xC0
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 100_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)
	mp.mu.Lock()

	// Conflict: signals RBF, fee = 1_000.
	txConflict := makeRBFTx([]wire.OutPoint{opSeed}, 99_000)
	hashConflict := txConflict.TxHash()
	addPoolEntry(mp, &TxEntry{
		Tx: txConflict, TxHash: hashConflict, Fee: 1_000, Size: 200,
		Time: time.Now(), AncestorFee: 1_000, AncestorSize: 200,
		DescendantFee: 1_000, DescendantSize: 200,
	})

	// Replacement: same fee (1_000) — equal to conflicting fees.
	// Rule 3 says `replacement_fees < original_fees` → reject. Equal passes Rule 3.
	// Rule 4 will reject because additional_fees = 0 < minFeeBump.
	replacement := makeRBFTx([]wire.OutPoint{opSeed}, 99_000)
	conflicts := map[wire.Hash256]bool{hashConflict: true}

	// totalInputValue = 100_000; replacement output = 99_000 → fee = 1_000 = equal.
	err := mp.checkRBFLocked(replacement, conflicts, 100_000)
	mp.mu.Unlock()

	// The error must come from Rule 4 (ErrRBFInsufficientFee),
	// NOT from Rule 3. Both wrap ErrRBFInsufficientFee, so we check the message.
	if err == nil {
		t.Fatal("expected Rule 4 rejection for equal-fee replacement, got nil")
	}
	if !errors.Is(err, ErrRBFInsufficientFee) {
		t.Fatalf("expected ErrRBFInsufficientFee (from Rule 4), got: %v", err)
	}
	// Verify Rule 3 is not the rejection source by checking the message does NOT
	// contain "less fees than conflicting txs".
	if errStr := err.Error(); containsString(errStr, "less fees than conflicting txs") {
		t.Fatalf("equal-fee replacement was rejected by Rule 3 (should pass Rule 3 and fail Rule 4): %v", err)
	}
}

// TestRBFRule3RejectsLowerFee verifies that a replacement with fees strictly
// less than the conflicting tx is rejected by Rule #3.
func TestRBFRule3RejectsLowerFee(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var seedHash wire.Hash256
	seedHash[0] = 0xC1
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 100_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)
	mp.mu.Lock()

	// Conflict: fee = 5_000.
	txConflict := makeRBFTx([]wire.OutPoint{opSeed}, 95_000)
	hashConflict := txConflict.TxHash()
	addPoolEntry(mp, &TxEntry{
		Tx: txConflict, TxHash: hashConflict, Fee: 5_000, Size: 200,
		Time: time.Now(), AncestorFee: 5_000, AncestorSize: 200,
		DescendantFee: 5_000, DescendantSize: 200,
	})

	// Replacement: fee = 4_000 < 5_000 → Rule 3 reject.
	replacement := makeRBFTx([]wire.OutPoint{opSeed}, 96_000)
	conflicts := map[wire.Hash256]bool{hashConflict: true}

	// totalInputValue = 100_000; replacement output = 96_000 → fee = 4_000.
	err := mp.checkRBFLocked(replacement, conflicts, 100_000)
	mp.mu.Unlock()

	if !errors.Is(err, ErrRBFInsufficientFee) {
		t.Fatalf("expected ErrRBFInsufficientFee for lower-fee replacement, got: %v", err)
	}
	if errStr := err.Error(); !containsString(errStr, "less fees than conflicting txs") {
		t.Fatalf("expected Rule 3 rejection message, got: %v", err)
	}
}

// ---- Gate 4: EntriesAndTxidsDisjoint ----------------------------------------

// TestRBFAncestorConflictDisjoint verifies that a replacement transaction that
// spends an output of the tx it is trying to replace is rejected with
// ErrRBFAncestorConflict. Mirrors Core rbf.cpp:85-98.
//
// Topology:
//
//	conflict C (signals RBF, spends UTXO U)
//	  replacement R spends C's output (and also U, so it conflicts with C)
//
// R cannot be both: "spending C's output" AND "replacing C".
func TestRBFAncestorConflictDisjoint(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var seedHash wire.Hash256
	seedHash[0] = 0xD0
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 200_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)
	mp.mu.Lock()

	// Conflict C: signals RBF.
	txC := makeRBFTx([]wire.OutPoint{opSeed}, 190_000)
	hashC := txC.TxHash()
	addPoolEntry(mp, &TxEntry{
		Tx: txC, TxHash: hashC, Fee: 10_000, Size: 200,
		Time: time.Now(), AncestorFee: 10_000, AncestorSize: 200,
		DescendantFee: 10_000, DescendantSize: 200,
	})

	// Replacement R spends C's output (index 0) AND the original UTXO.
	// This makes R conflict with C (both spend opSeed),
	// but R also depends on C as a parent.
	opC0 := wire.OutPoint{Hash: hashC, Index: 0}
	replacement := makeRBFTx([]wire.OutPoint{opSeed, opC0}, 150_000)
	conflicts := map[wire.Hash256]bool{hashC: true}

	// totalInputValue = 200_000 (U) + 190_000 (C's output) = 390_000.
	err := mp.checkRBFLocked(replacement, conflicts, 390_000)
	mp.mu.Unlock()

	if !errors.Is(err, ErrRBFAncestorConflict) {
		t.Fatalf("expected ErrRBFAncestorConflict when replacement spends conflict's output, got: %v", err)
	}
}

// TestRBFAncestorConflictDisjointAllowedAncestor verifies that a replacement
// is NOT rejected by EntriesAndTxidsDisjoint when the only in-mempool parent
// is the conflict itself (which is already in the allowed set for Rule 2).
// The disjoint check fires separately AFTER Rule 2.
//
// Scenario: replacement spends output of C (conflict). Rule 2 passes because C
// is in the conflict set (allowed). Disjoint check should fire with
// ErrRBFAncestorConflict because C is both an ancestor AND a direct conflict.
func TestRBFAncestorConflictDisjointAllowedAncestor(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var seedHash wire.Hash256
	seedHash[0] = 0xD1
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 300_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)
	mp.mu.Lock()

	// Conflict C: signals RBF.
	txC := makeRBFTx([]wire.OutPoint{opSeed}, 290_000)
	hashC := txC.TxHash()
	opC0 := wire.OutPoint{Hash: hashC, Index: 0}
	addPoolEntry(mp, &TxEntry{
		Tx: txC, TxHash: hashC, Fee: 10_000, Size: 200,
		Time: time.Now(), AncestorFee: 10_000, AncestorSize: 200,
		DescendantFee: 10_000, DescendantSize: 200,
	})

	// Replacement R spends opSeed (direct conflict with C) AND C's output (opC0).
	// Rule 2: C is in the conflict set → opC0's parent C is "allowed" → Rule 2 passes.
	// Disjoint check: C is both a direct conflict and a parent of R → ErrRBFAncestorConflict.
	replacement := makeRBFTx([]wire.OutPoint{opSeed, opC0}, 200_000)
	conflicts := map[wire.Hash256]bool{hashC: true}

	// totalInputValue = 300_000 (seed) + 290_000 (C's output) = 590_000.
	err := mp.checkRBFLocked(replacement, conflicts, 590_000)
	mp.mu.Unlock()

	// The disjoint check must fire (same as TestRBFAncestorConflictDisjoint).
	if !errors.Is(err, ErrRBFAncestorConflict) {
		t.Fatalf("expected ErrRBFAncestorConflict (replacement spends conflict's output), got: %v", err)
	}
}

// ---- Gate 5: Rule #4 uses IncrementalRelayFee --------------------------------

// TestRBFRule4UsesIncrementalRelayFee verifies that the bandwidth bump check
// (Rule #4) uses IncrementalRelayFee, not MinRelayFeeRate.
// When IncrementalRelayFee > MinRelayFeeRate, a replacement that satisfies
// the MinRelayFeeRate bump but not the IncrementalRelayFee bump must be rejected.
//
// The test transaction (1-input, no witness) serialises to 82 vB.
//   minBump(IncrementalRelayFee=5000): (82 * 5000 + 999) / 1000 = 410 sat
//   minBump(MinRelayFeeRate=1000):     (82 * 1000 + 999) / 1000 = 82 sat
//
// additional_fees = 200 sat:  > 82 (passes MinRelayFeeRate) but < 410 (fails IncrementalRelayFee).
func TestRBFRule4UsesIncrementalRelayFee(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var seedHash wire.Hash256
	seedHash[0] = 0xE0
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 1_000_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)
	// IncrementalRelayFee higher than MinRelayFeeRate.
	mp.config.MinRelayFeeRate = 1_000    // 1 sat/kvB
	mp.config.IncrementalRelayFee = 5_000 // 5 sat/kvB — higher

	mp.mu.Lock()

	// Conflict: signals RBF, fee = 10_000.
	txConflict := makeRBFTx([]wire.OutPoint{opSeed}, 990_000)
	hashConflict := txConflict.TxHash()
	addPoolEntry(mp, &TxEntry{
		Tx: txConflict, TxHash: hashConflict, Fee: 10_000, Size: 200,
		Time: time.Now(), AncestorFee: 10_000, AncestorSize: 200,
		DescendantFee: 10_000, DescendantSize: 200,
	})

	// additional_fees = 200; replacement fee = 10_200; output = 1_000_000 - 10_200 = 989_800.
	// 200 > 82 (passes MinRelayFeeRate), 200 < 410 (fails IncrementalRelayFee) → reject.
	replacement := makeRBFTx([]wire.OutPoint{opSeed}, 989_800)
	conflicts := map[wire.Hash256]bool{hashConflict: true}

	err := mp.checkRBFLocked(replacement, conflicts, 1_000_000)
	mp.mu.Unlock()

	if !errors.Is(err, ErrRBFInsufficientFee) {
		t.Fatalf("expected ErrRBFInsufficientFee (Rule 4 with IncrementalRelayFee=5000), got: %v", err)
	}
	// Verify it is Rule 4, not Rule 3.
	if errStr := err.Error(); !containsString(errStr, "not enough additional fees") {
		t.Fatalf("expected Rule 4 rejection message ('not enough additional fees'), got: %v", err)
	}
}

// TestRBFRule4PassesWithSufficientBump verifies that a replacement with
// additional_fees >= IncrementalRelayFee * vsize passes Rule #4.
// additional_fees = 500 sat ≥ minBump(5000, 82vB) = 410 sat.
func TestRBFRule4PassesWithSufficientBump(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var seedHash wire.Hash256
	seedHash[0] = 0xE1
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 1_000_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)
	mp.config.MinRelayFeeRate = 1_000
	mp.config.IncrementalRelayFee = 5_000

	mp.mu.Lock()

	// Conflict: fee = 10_000.
	txConflict := makeRBFTx([]wire.OutPoint{opSeed}, 990_000)
	hashConflict := txConflict.TxHash()
	addPoolEntry(mp, &TxEntry{
		Tx: txConflict, TxHash: hashConflict, Fee: 10_000, Size: 200,
		Time: time.Now(), AncestorFee: 10_000, AncestorSize: 200,
		DescendantFee: 10_000, DescendantSize: 200,
	})

	// additional_fees = 500 ≥ minBump(5000, 82vB) = 410. Should pass.
	// fee = 10_500; output = 989_500.
	replacement := makeRBFTx([]wire.OutPoint{opSeed}, 989_500)
	conflicts := map[wire.Hash256]bool{hashConflict: true}

	err := mp.checkRBFLocked(replacement, conflicts, 1_000_000)
	mp.mu.Unlock()

	if err != nil {
		t.Fatalf("additional_fees=500 >= minBump=410 should pass Rule 4, got: %v", err)
	}
}

// ---- Boundary: MAX_REPLACEMENT_CANDIDATES eviction count -------------------

// TestRBFRule5MaxReplacementCandidates verifies that attempting to evict more
// than MaxRBFReplacedTxs (100) transactions is rejected.
func TestRBFRule5MaxReplacementCandidates(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var seedHash wire.Hash256
	seedHash[0] = 0xF0
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 10_000_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)
	mp.mu.Lock()

	// Insert a conflict tx that signals RBF.
	txConflict := makeRBFTx([]wire.OutPoint{opSeed}, 9_990_000)
	hashConflict := txConflict.TxHash()
	addPoolEntry(mp, &TxEntry{
		Tx: txConflict, TxHash: hashConflict, Fee: 10_000, Size: 200,
		Time: time.Now(), AncestorFee: 10_000, AncestorSize: 200,
		DescendantFee: 10_000, DescendantSize: 200,
	})

	// Add 100 descendants of the conflict. This brings the total eviction count
	// to 101 (conflict + 100 descendants) which exceeds MaxRBFReplacedTxs=100.
	prevHash := hashConflict
	for i := 0; i < 100; i++ {
		var h wire.Hash256
		h[0] = byte(0x01 + i/256)
		h[1] = byte(i % 256)
		op := wire.OutPoint{Hash: prevHash, Index: 0}
		descTx := makeFinalTx([]wire.OutPoint{op}, int64(9_000_000-i*10_000))
		descHash := descTx.TxHash()
		descEntry := &TxEntry{
			Tx: descTx, TxHash: descHash, Fee: 10_000, Size: 200,
			Time:    time.Now(),
			Depends: []wire.Hash256{prevHash},
		}
		mp.pool[descHash] = descEntry
		mp.pool[prevHash].SpentBy = append(mp.pool[prevHash].SpentBy, descHash)
		prevHash = descHash
	}

	// Replacement conflicts only with the root (hashConflict), but eviction
	// would include all 100 descendants → 101 total.
	replacement := makeRBFTx([]wire.OutPoint{opSeed}, 5_000_000)
	conflicts := map[wire.Hash256]bool{hashConflict: true}

	err := mp.checkRBFLocked(replacement, conflicts, 10_000_000)
	mp.mu.Unlock()

	if !errors.Is(err, ErrRBFTooManyConflicts) {
		t.Fatalf("expected ErrRBFTooManyConflicts for 101-eviction scenario, got: %v", err)
	}
}

// TestRBFRule5AtExactLimit verifies that exactly MaxRBFReplacedTxs (100)
// evictions is accepted (boundary condition).
func TestRBFRule5AtExactLimit(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var seedHash wire.Hash256
	seedHash[0] = 0xF1
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 10_000_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempool(utxoSet)
	mp.mu.Lock()

	// Insert conflict.
	txConflict := makeRBFTx([]wire.OutPoint{opSeed}, 9_990_000)
	hashConflict := txConflict.TxHash()
	addPoolEntry(mp, &TxEntry{
		Tx: txConflict, TxHash: hashConflict, Fee: 10_000, Size: 200,
		Time: time.Now(), AncestorFee: 10_000, AncestorSize: 200,
		DescendantFee: 10_000, DescendantSize: 200,
	})

	// Add exactly 99 descendants → total eviction = 100 = MaxRBFReplacedTxs.
	prevHash := hashConflict
	for i := 0; i < 99; i++ {
		op := wire.OutPoint{Hash: prevHash, Index: 0}
		descTx := makeFinalTx([]wire.OutPoint{op}, int64(9_000_000-i*10_000))
		descHash := descTx.TxHash()
		descEntry := &TxEntry{
			Tx: descTx, TxHash: descHash, Fee: 10_000, Size: 200,
			Time:    time.Now(),
			Depends: []wire.Hash256{prevHash},
		}
		mp.pool[descHash] = descEntry
		mp.pool[prevHash].SpentBy = append(mp.pool[prevHash].SpentBy, descHash)
		prevHash = descHash
	}

	// Replacement: fee must exceed totalConflictingFee (100 * 10_000 = 1_000_000).
	// Input = 10_000_000; output = 7_000_000 → fee = 3_000_000 > 1_000_000.
	// Additional = 3_000_000 - 1_000_000 = 2_000_000 >> minBump. Should pass.
	replacement := makeRBFTx([]wire.OutPoint{opSeed}, 7_000_000)
	conflicts := map[wire.Hash256]bool{hashConflict: true}

	err := mp.checkRBFLocked(replacement, conflicts, 10_000_000)
	mp.mu.Unlock()

	if errors.Is(err, ErrRBFTooManyConflicts) {
		t.Fatalf("exactly 100 evictions should pass Rule 5, got: %v", err)
	}
}
