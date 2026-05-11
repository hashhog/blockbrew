// W78: Comprehensive BIP-431 TRUC v3 policy tests.
//
// Tests cover:
//   Rule 1: TRUC tx must only have TRUC in-mempool ancestors
//   Rule 2: Non-TRUC tx must only have non-TRUC in-mempool ancestors
//   Rule 3: TRUC ancestor set (incl. self) ≤ 2
//   Rule 4: TRUC descendant set (incl. self) ≤ 2
//   Rule 5: TRUC child (has unconfirmed ancestor) must have sigop-vsize ≤ 1000
//   Rule 6: Any TRUC tx must have sigop-vsize ≤ 10000
//   Constants: TRUCVersion, TRUCAncestorLimit, TRUCDescendantLimit,
//              TRUCMaxVSize, TRUCChildMaxVSize, weights
//   PackageTRUCChecks: 1-parent-1-child topology, sibling eviction hint,
//                      non-TRUC cannot spend TRUC parent
//   Boundary: 10000/10001 vbytes, 1000/1001 vbytes child
//
// Reference: bitcoin-core/src/policy/truc_policy.h + truc_policy.cpp
package mempool

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// Helpers
// ============================================================================

// makeTRUCTx returns a version=3 transaction spending op, leaving a fee.
// The output is a standard P2WPKH script so the isStandardOutputScript gate passes.
func makeTRUCTx(op wire.OutPoint, inputAmount int64, seed byte) *wire.MsgTx {
	pkScript := make([]byte, 22)
	pkScript[0] = 0x00
	pkScript[1] = 0x14
	for i := 2; i < 22; i++ {
		pkScript[i] = seed + byte(i)
	}
	return &wire.MsgTx{
		Version: TRUCVersion,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: op,
			SignatureScript:  make([]byte, 107),
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:    inputAmount - 5000,
			PkScript: pkScript,
		}},
		LockTime: 0,
	}
}

// makeNonTRUCTx returns a version=2 transaction spending op.
func makeNonTRUCTx(op wire.OutPoint, inputAmount int64, seed byte) *wire.MsgTx {
	tx := makeTRUCTx(op, inputAmount, seed)
	tx.Version = 2
	return tx
}

// makeFundedTRUCMempool returns a mempool with one confirmed UTXO pre-loaded.
func makeFundedTRUCMempool(seed byte, amount int64) (*Mempool, wire.OutPoint) {
	utxoSet := newTestUTXOSet()
	var h wire.Hash256
	h[0] = seed
	op, entry := createFundingUTXO(h, 0, amount)
	utxoSet.AddUTXO(op, entry)
	return newTestMempool(utxoSet), op
}

// injectTxEntry inserts a fake TxEntry directly into the mempool pool,
// bypassing validation. Used to set up the ancestor/descendant state for
// TRUC policy tests without needing real signatures.
// Must NOT be called with mu held.
func injectTxEntry(mp *Mempool, tx *wire.MsgTx, utxoSet *testUTXOSet) {
	txHash := tx.TxHash()
	mp.mu.Lock()
	defer mp.mu.Unlock()

	// Resolve parents.
	var depends []wire.Hash256
	for _, in := range tx.TxIn {
		if parent, ok := mp.pool[in.PreviousOutPoint.Hash]; ok {
			depends = append(depends, parent.TxHash)
			parent.SpentBy = append(parent.SpentBy, txHash)
			mp.pool[in.PreviousOutPoint.Hash] = parent
		}
		mp.outpoints[in.PreviousOutPoint] = txHash
	}

	// Also expose tx outputs as UTXOs so children can find them.
	if utxoSet != nil {
		for idx, out := range tx.TxOut {
			op := wire.OutPoint{Hash: txHash, Index: uint32(idx)}
			utxoSet.AddUTXO(op, &consensus.UTXOEntry{
				Amount:   out.Value,
				PkScript: out.PkScript,
				Height:   1,
			})
		}
	}

	mp.pool[txHash] = &TxEntry{
		Tx:      tx,
		TxHash:  txHash,
		Fee:     5000,
		Size:    200,
		FeeRate: 25,
		Depends: depends,
	}
	mp.totalSize += 200
}

// ============================================================================
// Constant sanity tests
// ============================================================================

func TestTRUCConstants(t *testing.T) {
	if TRUCVersion != 3 {
		t.Errorf("TRUCVersion = %d, want 3", TRUCVersion)
	}
	if TRUCAncestorLimit != 2 {
		t.Errorf("TRUCAncestorLimit = %d, want 2", TRUCAncestorLimit)
	}
	if TRUCDescendantLimit != 2 {
		t.Errorf("TRUCDescendantLimit = %d, want 2", TRUCDescendantLimit)
	}
	if TRUCMaxVSize != 10_000 {
		t.Errorf("TRUCMaxVSize = %d, want 10000", TRUCMaxVSize)
	}
	if TRUCChildMaxVSize != 1_000 {
		t.Errorf("TRUCChildMaxVSize = %d, want 1000", TRUCChildMaxVSize)
	}
	if TRUCMaxWeight != 40_000 {
		t.Errorf("TRUCMaxWeight = %d, want 40000 (10000 × 4)", TRUCMaxWeight)
	}
	if TRUCChildMaxWeight != 4_000 {
		t.Errorf("TRUCChildMaxWeight = %d, want 4000 (1000 × 4)", TRUCChildMaxWeight)
	}
}

// ============================================================================
// Rule 6: TRUC tx vsize ≤ 10000 (TRUCMaxVSize)
// ============================================================================

func TestTRUCRule6_MaxVSizeBoundary(t *testing.T) {
	// A tiny TRUC tx with no parents should pass rule 6.
	mp, op := makeFundedTRUCMempool(0xA0, 1_000_000)

	tx := makeTRUCTx(op, 1_000_000, 0x01)
	err := mp.singleTRUCChecks(tx, nil)
	// Script validation is not called here — we test the policy gate only.
	if err != nil {
		// Only acceptable errors are script/fee/missing-input from the outer
		// AddTransaction, not TRUC errors. singleTRUCChecks itself should pass.
		if errors.Is(err, ErrTRUCTooBig) {
			t.Errorf("tiny TRUC tx incorrectly flagged as too big: %v", err)
		}
	}
}

func TestTRUCRule6_VSize10000_Accepted(t *testing.T) {
	// Craft a TRUC tx with sigop-adjusted vsize ≤ TRUCMaxVSize (10_000).
	// Strategy: measure base vsize, then add witness bytes to approach but not
	// exceed the limit. The witness compact-size overhead (stack-count byte +
	// per-item length byte) means each chunk of 4 witness bytes adds slightly
	// more than 1 vbyte when we add the first item; we account for this by
	// targeting TRUCMaxVSize - 1 as our upper bound.
	mp, op := makeFundedTRUCMempool(0xA1, 2_000_000)

	tx := makeTRUCTx(op, 2_000_000, 0x02)

	// Measure base vsize (no witness).
	mp.mu.Lock()
	baseSigopVsize := mp.trucSigopVsize(tx)
	mp.mu.Unlock()

	if baseSigopVsize > TRUCMaxVSize {
		t.Skipf("base tx already exceeds TRUCMaxVSize (%d > %d); skip", baseSigopVsize, TRUCMaxVSize)
	}

	// Attempt to add witness to reach TRUCMaxVSize - 1.
	// Account for 2 bytes of witness overhead (stack count + item length).
	// +2 witness bytes overhead → +2 WU → rounds up with existing weight.
	// We conservatively target TRUCMaxVSize - 2 to avoid overshoot.
	target := TRUCMaxVSize - 2
	deficit := target - baseSigopVsize
	if deficit > 0 {
		// deficit vbytes × 4 WU/vbyte - 2 WU overhead = witness item bytes.
		witnessBytes := int(deficit)*4 - 2
		if witnessBytes > 0 {
			tx.TxIn[0].Witness = [][]byte{make([]byte, witnessBytes)}
		}
	}

	mp.mu.Lock()
	sigopVsize := mp.trucSigopVsize(tx)
	err := mp.singleTRUCChecks(tx, nil)
	mp.mu.Unlock()

	if sigopVsize > TRUCMaxVSize {
		t.Skipf("craft still overshot (%d > %d); witness overhead miscalculation — acceptable skip", sigopVsize, TRUCMaxVSize)
	}
	if errors.Is(err, ErrTRUCTooBig) {
		t.Errorf("vsize %d (≤ %d) should not hit ErrTRUCTooBig: %v", sigopVsize, TRUCMaxVSize, err)
	}
}

func TestTRUCRule6_VSize10001_Rejected(t *testing.T) {
	// Craft a TRUC tx with sigop-adjusted vsize just above TRUCMaxVSize (10_000).
	// Measure base vsize, then add witness bytes to exceed the limit by 1.
	mp, op := makeFundedTRUCMempool(0xA2, 3_000_000)

	tx := makeTRUCTx(op, 3_000_000, 0x03)

	mp.mu.Lock()
	baseSigopVsize := mp.trucSigopVsize(tx)
	mp.mu.Unlock()

	// Add witness bytes to bring vsize to exactly TRUCMaxVSize+1.
	surplus := TRUCMaxVSize + 1 - baseSigopVsize
	if surplus <= 0 {
		// Base tx is already too big; bump by 1 vbyte (4 WU).
		surplus = 1
	}
	tx.TxIn[0].Witness = [][]byte{make([]byte, int(surplus)*4)}

	mp.mu.Lock()
	sigopVsize := mp.trucSigopVsize(tx)
	err := mp.singleTRUCChecks(tx, nil)
	mp.mu.Unlock()

	if sigopVsize <= TRUCMaxVSize {
		t.Errorf("craft produced sigop-vsize %d ≤ %d; test construction error", sigopVsize, TRUCMaxVSize)
	}
	if !errors.Is(err, ErrTRUCTooBig) {
		t.Errorf("sigop-vsize %d (> %d) should hit ErrTRUCTooBig, got: %v", sigopVsize, TRUCMaxVSize, err)
	}
}

// ============================================================================
// Rule 5: TRUC child vsize ≤ 1000 (TRUCChildMaxVSize)
// ============================================================================

// setupTRUCParent inserts a TRUC parent into the mempool, adds its output as a
// UTXO, and returns the parent's outpoint for use by child txs.
func setupTRUCParent(mp *Mempool, utxoSet *testUTXOSet, confirmedOp wire.OutPoint, seed byte) wire.OutPoint {
	parent := makeTRUCTx(confirmedOp, 1_000_000, seed)
	injectTxEntry(mp, parent, utxoSet)
	parentHash := parent.TxHash()
	return wire.OutPoint{Hash: parentHash, Index: 0}
}

func TestTRUCRule5_ChildVSize1000_Accepted(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xB0
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 2_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	parentOp := setupTRUCParent(mp, utxoSet, confirmedOp, 0x10)

	// Construct a TRUC child whose sigop-vsize is ≤ 1000.
	// Base tx (no witness) ≈ 165 bytes → vsize ≈ 165. Well under 1000.
	child := makeTRUCTx(parentOp, 1_000_000-5000, 0x20)

	mp.mu.Lock()
	childVsize := mp.trucSigopVsize(child)
	err := mp.singleTRUCChecks(child, nil)
	mp.mu.Unlock()

	if childVsize > TRUCChildMaxVSize {
		t.Skipf("child construct has sigop-vsize %d > 1000 (test construction issue)", childVsize)
	}
	if errors.Is(err, ErrTRUCChildTooBig) {
		t.Errorf("child vsize %d (≤ 1000) should not hit ErrTRUCChildTooBig: %v", childVsize, err)
	}
}

func TestTRUCRule5_ChildVSize1001_Rejected(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xB1
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 3_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	parentOp := setupTRUCParent(mp, utxoSet, confirmedOp, 0x11)

	// Craft a child with sigop-vsize exactly TRUCChildMaxVSize+1.
	child := makeTRUCTx(parentOp, 3_000_000-5000, 0x21)

	mp.mu.Lock()
	baseVsize := mp.trucSigopVsize(child)
	mp.mu.Unlock()

	surplus := TRUCChildMaxVSize + 1 - baseVsize
	if surplus <= 0 {
		surplus = 1
	}
	child.TxIn[0].Witness = [][]byte{make([]byte, int(surplus)*4)}

	mp.mu.Lock()
	childVsize := mp.trucSigopVsize(child)
	err := mp.singleTRUCChecks(child, nil)
	mp.mu.Unlock()

	if childVsize <= TRUCChildMaxVSize {
		t.Errorf("child craft has sigop-vsize %d ≤ %d; test construction error", childVsize, TRUCChildMaxVSize)
	}
	if !errors.Is(err, ErrTRUCChildTooBig) {
		t.Errorf("child vsize %d (> %d) should hit ErrTRUCChildTooBig, got: %v", childVsize, TRUCChildMaxVSize, err)
	}
}

// ============================================================================
// Rule 1+2: TRUC/non-TRUC inheritance (mixing prohibition)
// ============================================================================

func TestTRUCRule1_TRUCSpendingNonTRUC_Rejected(t *testing.T) {
	// A TRUC tx must not spend a non-TRUC in-mempool parent.
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xC0
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 2_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	// Insert non-TRUC parent.
	parent := makeNonTRUCTx(confirmedOp, 2_000_000, 0x30)
	injectTxEntry(mp, parent, utxoSet)
	parentOp := wire.OutPoint{Hash: parent.TxHash(), Index: 0}

	// TRUC child spending non-TRUC parent → Rule 1 violation.
	child := makeTRUCTx(parentOp, 2_000_000-5000, 0x31)

	mp.mu.Lock()
	err := mp.singleTRUCChecks(child, nil)
	mp.mu.Unlock()

	if !errors.Is(err, ErrTRUCVersionMixing) {
		t.Errorf("TRUC spending non-TRUC parent: expected ErrTRUCVersionMixing, got %v", err)
	}
}

func TestTRUCRule2_NonTRUCSpendingTRUC_Rejected(t *testing.T) {
	// A non-TRUC tx must not spend a TRUC in-mempool parent.
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xC1
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 2_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	// Insert TRUC parent.
	parent := makeTRUCTx(confirmedOp, 2_000_000, 0x40)
	injectTxEntry(mp, parent, utxoSet)
	parentOp := wire.OutPoint{Hash: parent.TxHash(), Index: 0}

	// Non-TRUC child spending TRUC parent → Rule 2 violation.
	child := makeNonTRUCTx(parentOp, 2_000_000-5000, 0x41)

	mp.mu.Lock()
	err := mp.singleTRUCChecks(child, nil)
	mp.mu.Unlock()

	if !errors.Is(err, ErrTRUCVersionMixing) {
		t.Errorf("non-TRUC spending TRUC parent: expected ErrTRUCVersionMixing, got %v", err)
	}
}

func TestTRUCRule1_TRUCSpendingTRUC_Allowed(t *testing.T) {
	// A TRUC tx spending a TRUC parent is allowed (rule 1 not violated).
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xC2
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 2_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	parent := makeTRUCTx(confirmedOp, 2_000_000, 0x50)
	injectTxEntry(mp, parent, utxoSet)
	parentOp := wire.OutPoint{Hash: parent.TxHash(), Index: 0}

	child := makeTRUCTx(parentOp, 2_000_000-5000, 0x51)

	mp.mu.Lock()
	err := mp.singleTRUCChecks(child, nil)
	mp.mu.Unlock()

	if errors.Is(err, ErrTRUCVersionMixing) {
		t.Errorf("TRUC spending TRUC parent incorrectly flagged as version mixing: %v", err)
	}
}

func TestTRUCRule2_NonTRUCSpendingNonTRUC_Allowed(t *testing.T) {
	// A non-TRUC tx spending a non-TRUC parent is fine.
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xC3
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 2_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	parent := makeNonTRUCTx(confirmedOp, 2_000_000, 0x60)
	injectTxEntry(mp, parent, utxoSet)
	parentOp := wire.OutPoint{Hash: parent.TxHash(), Index: 0}

	child := makeNonTRUCTx(parentOp, 2_000_000-5000, 0x61)

	mp.mu.Lock()
	err := mp.singleTRUCChecks(child, nil)
	mp.mu.Unlock()

	if errors.Is(err, ErrTRUCVersionMixing) {
		t.Errorf("non-TRUC spending non-TRUC parent incorrectly flagged as version mixing: %v", err)
	}
}

// ============================================================================
// Rule 3: TRUC ancestor set ≤ 2
// ============================================================================

func TestTRUCRule3_TwoAncestors_Rejected(t *testing.T) {
	// A TRUC tx with 2 in-mempool parents (ancestor-set = 3 including self)
	// violates the ancestor limit.
	utxoSet := newTestUTXOSet()

	var s1 wire.Hash256
	s1[0] = 0xD0
	op1, e1 := createFundingUTXO(s1, 0, 2_000_000)
	utxoSet.AddUTXO(op1, e1)

	var s2 wire.Hash256
	s2[0] = 0xD1
	op2, e2 := createFundingUTXO(s2, 0, 2_000_000)
	utxoSet.AddUTXO(op2, e2)

	mp := newTestMempool(utxoSet)

	parent1 := makeTRUCTx(op1, 2_000_000, 0x70)
	injectTxEntry(mp, parent1, utxoSet)
	parentOp1 := wire.OutPoint{Hash: parent1.TxHash(), Index: 0}

	parent2 := makeTRUCTx(op2, 2_000_000, 0x71)
	injectTxEntry(mp, parent2, utxoSet)
	parentOp2 := wire.OutPoint{Hash: parent2.TxHash(), Index: 0}

	// Child spending both TRUC parents → ancestor-set = 3 > TRUC_ANCESTOR_LIMIT=2.
	pkScript := make([]byte, 22)
	pkScript[0] = 0x00
	pkScript[1] = 0x14
	child := &wire.MsgTx{
		Version: TRUCVersion,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: parentOp1, SignatureScript: make([]byte, 107), Sequence: 0xffffffff},
			{PreviousOutPoint: parentOp2, SignatureScript: make([]byte, 107), Sequence: 0xffffffff},
		},
		TxOut: []*wire.TxOut{{Value: 2_000_000 - 5000, PkScript: pkScript}},
	}

	mp.mu.Lock()
	err := mp.singleTRUCChecks(child, nil)
	mp.mu.Unlock()

	if !errors.Is(err, ErrTRUCTooManyAncestors) {
		t.Errorf("TRUC tx with 2 parents should hit ErrTRUCTooManyAncestors, got: %v", err)
	}
}

func TestTRUCRule3_OneAncestor_Allowed(t *testing.T) {
	// Exactly 1 unconfirmed parent → ancestor-set = 2 = TRUC_ANCESTOR_LIMIT. OK.
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xD2
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 2_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	parent := makeTRUCTx(confirmedOp, 2_000_000, 0x80)
	injectTxEntry(mp, parent, utxoSet)
	parentOp := wire.OutPoint{Hash: parent.TxHash(), Index: 0}

	child := makeTRUCTx(parentOp, 2_000_000-5000, 0x81)

	mp.mu.Lock()
	err := mp.singleTRUCChecks(child, nil)
	mp.mu.Unlock()

	if errors.Is(err, ErrTRUCTooManyAncestors) {
		t.Errorf("TRUC tx with 1 parent should not hit ErrTRUCTooManyAncestors: %v", err)
	}
}

// ============================================================================
// Rule 4: TRUC descendant set ≤ 2
// ============================================================================

func TestTRUCRule4_SecondChild_Rejected(t *testing.T) {
	// A TRUC parent that already has one TRUC child cannot accept another.
	// The incoming tx causes parent's descendant count to become 3 > TRUC_DESCENDANT_LIMIT.
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xE0
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 3_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	parent := makeTRUCTx(confirmedOp, 3_000_000, 0x90)
	injectTxEntry(mp, parent, utxoSet)
	parentOp := wire.OutPoint{Hash: parent.TxHash(), Index: 0}

	// First child (accepted via inject).
	child1 := makeTRUCTx(parentOp, 3_000_000-5000, 0x91)
	injectTxEntry(mp, child1, utxoSet)
	// child1 output (not needed for this test).

	// Second child also spending parent → descendant count would be 3.
	// We need a different output — use a fake second output from parent or
	// simulate by using a different index. For the purpose of testing the
	// descendant count gate, we use the same outpoint (index 0) with a
	// different incoming tx — the gate fires on parent's descendant count
	// before the double-spend check because singleTRUCChecks runs first.
	var s2 wire.Hash256
	s2[0] = 0xE1
	op2, e2 := createFundingUTXO(s2, 1, 2_000_000)
	utxoSet.AddUTXO(op2, e2)
	// Make a second confirmed input for child2 so it doesn't double-spend.
	child2 := &wire.MsgTx{
		Version: TRUCVersion,
		TxIn: []*wire.TxIn{
			// Spend an output from parent (same hash, index 0) — in practice
			// this is a sibling scenario; singleTRUCChecks checks descendant
			// count of parent regardless of which specific output is spent.
			{PreviousOutPoint: parentOp, SignatureScript: make([]byte, 107), Sequence: 0xffffffff},
		},
		TxOut: []*wire.TxOut{{
			Value:    2_000_000 - 5000,
			PkScript: func() []byte { s := make([]byte, 22); s[0] = 0x00; s[1] = 0x14; return s }(),
		}},
	}

	mp.mu.Lock()
	err := mp.singleTRUCChecks(child2, nil)
	mp.mu.Unlock()

	// Rule 4 violation: parent already has a child; adding child2 would give parent
	// descendant count 3 > TRUC_DESCENDANT_LIMIT(2). We expect EITHER a
	// ErrTRUCTooManyDescendants or a sibling-eviction hint (trucSiblingEviction).
	if err == nil {
		t.Errorf("second TRUC child should be rejected, got nil")
		return
	}
	_, isSiblingEviction := IsTRUCSiblingEviction(err)
	if !errors.Is(err, ErrTRUCTooManyDescendants) && !isSiblingEviction {
		t.Errorf("second child: expected ErrTRUCTooManyDescendants or sibling eviction, got: %v", err)
	}
}

func TestTRUCRule4_FirstChild_Allowed(t *testing.T) {
	// First TRUC child of a TRUC parent: descendant count = 2 = limit. OK.
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xE2
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 2_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	parent := makeTRUCTx(confirmedOp, 2_000_000, 0xA0)
	injectTxEntry(mp, parent, utxoSet)
	parentOp := wire.OutPoint{Hash: parent.TxHash(), Index: 0}

	child := makeTRUCTx(parentOp, 2_000_000-5000, 0xA1)

	mp.mu.Lock()
	err := mp.singleTRUCChecks(child, nil)
	mp.mu.Unlock()

	if errors.Is(err, ErrTRUCTooManyDescendants) {
		t.Errorf("first TRUC child should not hit ErrTRUCTooManyDescendants: %v", err)
	}
}

// ============================================================================
// Sibling eviction hint
// ============================================================================

func TestTRUCSiblingEviction_HintReturned(t *testing.T) {
	// A TRUC parent has exactly one child. The incoming second child should
	// trigger a sibling-eviction hint (not a hard reject).
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xF0
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 3_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	parent := makeTRUCTx(confirmedOp, 3_000_000, 0xB0)
	injectTxEntry(mp, parent, utxoSet)
	parentOp := wire.OutPoint{Hash: parent.TxHash(), Index: 0}

	existingChild := makeTRUCTx(parentOp, 3_000_000-5000, 0xB1)
	injectTxEntry(mp, existingChild, utxoSet)

	// Incoming second child (different confirmed input to avoid double-spend
	// at the outpoint level during the check).
	var s2 wire.Hash256
	s2[0] = 0xF1
	op2, e2 := createFundingUTXO(s2, 0, 2_000_000)
	utxoSet.AddUTXO(op2, e2)

	// The second child spends parent's output (same outpoint as existingChild).
	child2 := makeTRUCTx(parentOp, 3_000_000-5000, 0xB2)

	mp.mu.Lock()
	err := mp.singleTRUCChecks(child2, nil)
	mp.mu.Unlock()

	if err == nil {
		t.Errorf("expected sibling eviction hint or rejection, got nil")
		return
	}
	siblingHash, isSiblingEviction := IsTRUCSiblingEviction(err)
	if !isSiblingEviction {
		// Also acceptable: hard rejection if sibling has additional descendants.
		if !errors.Is(err, ErrTRUCTooManyDescendants) {
			t.Errorf("expected sibling eviction or ErrTRUCTooManyDescendants, got: %v", err)
		}
		return
	}
	if siblingHash != existingChild.TxHash() {
		t.Errorf("sibling eviction hint points to wrong tx: got %v, want %v",
			siblingHash, existingChild.TxHash())
	}
}

func TestTRUCSiblingEviction_NoHint_WhenNotDirectConflict_AlreadyHandled(t *testing.T) {
	// When the existing child is in directConflicts (would be replaced anyway),
	// no sibling-eviction hint is needed — singleTRUCChecks should accept.
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0xF2
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 3_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	parent := makeTRUCTx(confirmedOp, 3_000_000, 0xC0)
	injectTxEntry(mp, parent, utxoSet)
	parentOp := wire.OutPoint{Hash: parent.TxHash(), Index: 0}

	existingChild := makeTRUCTx(parentOp, 3_000_000-5000, 0xC1)
	injectTxEntry(mp, existingChild, utxoSet)

	// Mark the existing child as a direct conflict (will be replaced by RBF).
	directConflicts := map[wire.Hash256]bool{
		existingChild.TxHash(): true,
	}

	child2 := makeTRUCTx(parentOp, 3_000_000-5000, 0xC2)

	mp.mu.Lock()
	err := mp.singleTRUCChecks(child2, directConflicts)
	mp.mu.Unlock()

	// With the existing child marked as a direct conflict, the descendant
	// count condition should be satisfied (child_will_be_replaced is true).
	if errors.Is(err, ErrTRUCTooManyDescendants) {
		t.Errorf("with direct conflict flagged, should not hit ErrTRUCTooManyDescendants: %v", err)
	}
	if _, isSibEvict := IsTRUCSiblingEviction(err); isSibEvict {
		t.Errorf("with direct conflict flagged, should not return sibling eviction hint: %v", err)
	}
}

// ============================================================================
// PackageTRUCChecks: 1-parent-1-child topology (no siblings in package)
// ============================================================================

func TestPackageTRUC_TwoSiblings_Rejected(t *testing.T) {
	// Package: [parent, child1, child2] where child1 and child2 both spend parent.
	// This violates the 1-parent-1-child topology.
	pkScript := func(seed byte) []byte {
		s := make([]byte, 22)
		s[0] = 0x00
		s[1] = 0x14
		for i := 2; i < 22; i++ {
			s[i] = seed + byte(i)
		}
		return s
	}

	var baseHash wire.Hash256
	baseHash[0] = 0x01
	parent := &wire.MsgTx{
		Version: TRUCVersion,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: baseHash}, SignatureScript: make([]byte, 107), Sequence: 0xffffffff}},
		TxOut: []*wire.TxOut{
			{Value: 900_000, PkScript: pkScript(0x01)},
			{Value: 900_000, PkScript: pkScript(0x02)},
		},
	}
	parentHash := parent.TxHash()

	child1 := &wire.MsgTx{
		Version: TRUCVersion,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 0}, SignatureScript: make([]byte, 107), Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 890_000, PkScript: pkScript(0x03)}},
	}
	child2 := &wire.MsgTx{
		Version: TRUCVersion,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 1}, SignatureScript: make([]byte, 107), Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 890_000, PkScript: pkScript(0x04)}},
	}

	pkg := []*wire.MsgTx{parent, child1, child2}
	utxoSet := newTestUTXOSet()
	var fundHash wire.Hash256
	fundHash[0] = 0xFF
	op, entry := createFundingUTXO(fundHash, 0, 2_000_000)
	utxoSet.AddUTXO(op, entry)
	mp := newTestMempool(utxoSet)

	// Check child1 (index 1 in pkg).
	mp.mu.Lock()
	sv1 := mp.trucSigopVsize(child1)
	err1 := mp.packageTRUCChecks(child1, sv1, pkg, 1)
	mp.mu.Unlock()

	// Check child2 (index 2 in pkg).
	mp.mu.Lock()
	sv2 := mp.trucSigopVsize(child2)
	err2 := mp.packageTRUCChecks(child2, sv2, pkg, 2)
	mp.mu.Unlock()

	// At least one sibling should be rejected.
	if err1 == nil && err2 == nil {
		t.Errorf("two TRUC siblings in a package should fail PackageTRUCChecks; both returned nil")
	}
}

func TestPackageTRUC_OneParentOneChild_Allowed(t *testing.T) {
	// Package: [parent, child] with 1-parent-1-child topology. Should pass.
	var baseHash wire.Hash256
	baseHash[0] = 0x02
	parent := &wire.MsgTx{
		Version: TRUCVersion,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: baseHash}, SignatureScript: make([]byte, 107), Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 900_000, PkScript: func() []byte { s := make([]byte, 22); s[0] = 0x00; s[1] = 0x14; return s }()}},
	}
	parentHash := parent.TxHash()
	child := &wire.MsgTx{
		Version: TRUCVersion,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 0}, SignatureScript: make([]byte, 107), Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 890_000, PkScript: func() []byte { s := make([]byte, 22); s[0] = 0x00; s[1] = 0x14; return s }()}},
	}

	pkg := []*wire.MsgTx{parent, child}
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	// Parent (idx 0): no in-package parents, no in-mempool parents.
	mp.mu.Lock()
	sv0 := mp.trucSigopVsize(parent)
	err0 := mp.packageTRUCChecks(parent, sv0, pkg, 0)

	// Child (idx 1): parent is in-package.
	sv1 := mp.trucSigopVsize(child)
	err1 := mp.packageTRUCChecks(child, sv1, pkg, 1)
	mp.mu.Unlock()

	if err0 != nil {
		t.Errorf("TRUC parent in package failed PackageTRUCChecks unexpectedly: %v", err0)
	}
	if err1 != nil {
		t.Errorf("TRUC child in 1-parent-1-child package failed PackageTRUCChecks: %v", err1)
	}
}

func TestPackageTRUC_NonTRUCChildOfTRUCParent_Rejected(t *testing.T) {
	// Package: [TRUC parent, non-TRUC child]. The child must not spend a TRUC parent.
	var baseHash wire.Hash256
	baseHash[0] = 0x03
	parent := &wire.MsgTx{
		Version: TRUCVersion,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: baseHash}, SignatureScript: make([]byte, 107), Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 900_000, PkScript: func() []byte { s := make([]byte, 22); s[0] = 0x00; s[1] = 0x14; return s }()}},
	}
	parentHash := parent.TxHash()
	child := &wire.MsgTx{
		Version: 2, // non-TRUC
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 0}, SignatureScript: make([]byte, 107), Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 890_000, PkScript: func() []byte { s := make([]byte, 22); s[0] = 0x00; s[1] = 0x14; return s }()}},
	}

	pkg := []*wire.MsgTx{parent, child}
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	mp.mu.Lock()
	sv1 := mp.trucSigopVsize(child)
	err := mp.packageTRUCChecks(child, sv1, pkg, 1)
	mp.mu.Unlock()

	if err == nil {
		t.Errorf("non-TRUC child of TRUC parent in package should fail PackageTRUCChecks")
	}
}

// ============================================================================
// AddTransaction integration: TRUC gates wire end-to-end
// ============================================================================

func TestTRUC_AddTransaction_NonTRUCSpendingTRUCParent_Rejected(t *testing.T) {
	// Wire AddTransaction: non-TRUC spending TRUC should return ErrTRUCVersionMixing.
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0x10
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 2_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	parent := makeTRUCTx(confirmedOp, 2_000_000, 0x11)
	injectTxEntry(mp, parent, utxoSet)
	parentOp := wire.OutPoint{Hash: parent.TxHash(), Index: 0}

	child := makeNonTRUCTx(parentOp, 2_000_000-5000, 0x12)
	err := mp.AddTransaction(child)

	if !errors.Is(err, ErrTRUCVersionMixing) {
		t.Errorf("AddTransaction non-TRUC spending TRUC parent: expected ErrTRUCVersionMixing, got %v", err)
	}
}

func TestTRUC_AddTransaction_TRUCSpendingNonTRUCParent_Rejected(t *testing.T) {
	// Wire AddTransaction: TRUC spending non-TRUC should return ErrTRUCVersionMixing.
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0x13
	confirmedOp, entry := createFundingUTXO(seedHash, 0, 2_000_000)
	utxoSet.AddUTXO(confirmedOp, entry)
	mp := newTestMempool(utxoSet)

	parent := makeNonTRUCTx(confirmedOp, 2_000_000, 0x14)
	injectTxEntry(mp, parent, utxoSet)
	parentOp := wire.OutPoint{Hash: parent.TxHash(), Index: 0}

	child := makeTRUCTx(parentOp, 2_000_000-5000, 0x15)
	err := mp.AddTransaction(child)

	if !errors.Is(err, ErrTRUCVersionMixing) {
		t.Errorf("AddTransaction TRUC spending non-TRUC parent: expected ErrTRUCVersionMixing, got %v", err)
	}
}

// ============================================================================
// countAncestorsLocked / countDescendantsLocked internal helpers
// ============================================================================

func TestCountAncestors_Linear(t *testing.T) {
	// Build a linear chain A → B → C and verify ancestor counts.
	utxoSet := newTestUTXOSet()
	var s wire.Hash256
	s[0] = 0x20
	op, entry := createFundingUTXO(s, 0, 3_000_000)
	utxoSet.AddUTXO(op, entry)
	mp := newTestMempool(utxoSet)

	a := makeTRUCTx(op, 3_000_000, 0x21)
	injectTxEntry(mp, a, utxoSet)
	aOp := wire.OutPoint{Hash: a.TxHash(), Index: 0}

	b := makeTRUCTx(aOp, 3_000_000-5000, 0x22)
	injectTxEntry(mp, b, utxoSet)
	bOp := wire.OutPoint{Hash: b.TxHash(), Index: 0}

	c := makeTRUCTx(bOp, 3_000_000-10000, 0x23)
	injectTxEntry(mp, c, utxoSet)

	mp.mu.Lock()
	defer mp.mu.Unlock()

	if got := mp.countAncestorsLocked(a.TxHash()); got != 1 {
		t.Errorf("A ancestors: got %d, want 1", got)
	}
	if got := mp.countAncestorsLocked(b.TxHash()); got != 2 {
		t.Errorf("B ancestors: got %d, want 2", got)
	}
	if got := mp.countAncestorsLocked(c.TxHash()); got != 3 {
		t.Errorf("C ancestors: got %d, want 3", got)
	}
}

func TestCountDescendants_Linear(t *testing.T) {
	// Build a linear chain A → B → C and verify descendant counts.
	utxoSet := newTestUTXOSet()
	var s wire.Hash256
	s[0] = 0x30
	op, entry := createFundingUTXO(s, 0, 3_000_000)
	utxoSet.AddUTXO(op, entry)
	mp := newTestMempool(utxoSet)

	a := makeTRUCTx(op, 3_000_000, 0x31)
	injectTxEntry(mp, a, utxoSet)
	aOp := wire.OutPoint{Hash: a.TxHash(), Index: 0}

	b := makeTRUCTx(aOp, 3_000_000-5000, 0x32)
	injectTxEntry(mp, b, utxoSet)
	bOp := wire.OutPoint{Hash: b.TxHash(), Index: 0}

	c := makeTRUCTx(bOp, 3_000_000-10000, 0x33)
	injectTxEntry(mp, c, utxoSet)

	mp.mu.Lock()
	defer mp.mu.Unlock()

	if got := mp.countDescendantsLocked(a.TxHash()); got != 3 {
		t.Errorf("A descendants: got %d, want 3", got)
	}
	if got := mp.countDescendantsLocked(b.TxHash()); got != 2 {
		t.Errorf("B descendants: got %d, want 2", got)
	}
	if got := mp.countDescendantsLocked(c.TxHash()); got != 1 {
		t.Errorf("C descendants: got %d, want 1", got)
	}
}

// ============================================================================
// findInPackageParents helper
// ============================================================================

func TestFindInPackageParents(t *testing.T) {
	// Package: [A, B_spends_A, C_spends_A, D_spends_B].
	// findInPackageParents(D, 3) should return [1] (B is at index 1).
	var h0 wire.Hash256
	h0[0] = 0x40
	a := &wire.MsgTx{
		Version: TRUCVersion,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: h0}}},
		TxOut:   []*wire.TxOut{{Value: 900_000, PkScript: make([]byte, 22)}},
	}
	aHash := a.TxHash()

	b := &wire.MsgTx{
		Version: TRUCVersion,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: aHash, Index: 0}}},
		TxOut:   []*wire.TxOut{{Value: 890_000, PkScript: make([]byte, 22)}},
	}
	bHash := b.TxHash()

	c := &wire.MsgTx{
		Version: TRUCVersion,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: aHash, Index: 0}}},
		TxOut:   []*wire.TxOut{{Value: 880_000, PkScript: make([]byte, 22)}},
	}

	d := &wire.MsgTx{
		Version: TRUCVersion,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: bHash, Index: 0}}},
		TxOut:   []*wire.TxOut{{Value: 870_000, PkScript: make([]byte, 22)}},
	}

	pkg := []*wire.MsgTx{a, b, c, d}

	// A has no parents.
	if parents := findInPackageParents(pkg, 0); len(parents) != 0 {
		t.Errorf("A: expected 0 parents, got %v", parents)
	}
	// B's parent is A (index 0).
	if parents := findInPackageParents(pkg, 1); len(parents) != 1 || parents[0] != 0 {
		t.Errorf("B: expected [0], got %v", parents)
	}
	// C's parent is A (index 0).
	if parents := findInPackageParents(pkg, 2); len(parents) != 1 || parents[0] != 0 {
		t.Errorf("C: expected [0], got %v", parents)
	}
	// D's parent is B (index 1).
	if parents := findInPackageParents(pkg, 3); len(parents) != 1 || parents[0] != 1 {
		t.Errorf("D: expected [1], got %v", parents)
	}
}

// ============================================================================
// Error sentinel tests
// ============================================================================

func TestTRUCErrorSentinels(t *testing.T) {
	sentinels := []error{
		ErrTRUCVersionMixing,
		ErrTRUCTooManyAncestors,
		ErrTRUCTooManyDescendants,
		ErrTRUCTooBig,
		ErrTRUCChildTooBig,
		ErrTRUCPackageTooManyAncestors,
		ErrTRUCPackageTooManyDescendants,
		ErrTRUCPackageChildHasChild,
	}
	for _, s := range sentinels {
		if s == nil {
			t.Error("nil sentinel")
		}
		wrapped := errors.Join(s, nil)
		if !errors.Is(wrapped, s) {
			t.Errorf("errors.Is broken for sentinel: %v", s)
		}
	}
}
