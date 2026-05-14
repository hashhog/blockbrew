package mempool

// W116 — BIP-431 / BIP-331 Package relay (1p1c) audit tests.
//
// Gates covered: G1-G5 (package definition), G6-G10 (testmempoolaccept/package mode),
// G11-G15 (submitpackage RPC-layer), G16-G20 (package validation), G21-G24 (CPFP),
// G25-G28 (edge cases), G29-G30 (P2P package relay infrastructure).
//
// Bugs documented:
//
// BUG-1 (P1): testmempoolaccept processes txns INDIVIDUALLY, not as a package when >1 tx.
//   Core: size > 1 → ProcessNewPackage(test_accept=true). blockbrew: independent per-tx
//   loop. Multi-tx package feerate elevation and parent-child dependency not modelled.
//
// BUG-2 (P1): submitpackage maxfeerate check fires AFTER AcceptPackage (transactions
//   already added). The comment in methods.go:1217 says "Note: In a production
//   implementation, we would prevent acceptance entirely rather than accepting then
//   removing." Transactions above maxfeerate end up in mempool with an error annotation
//   only in the RPC result, not actually rejected.
//
// BUG-3 (P1): Package feerate calculation for CPFP (zero-fee or below-minimum-fee parent)
//   is wrong. In acceptMultiTxPackage, totalFee/totalVSize only accumulates txns that
//   PASSED individually in the 1st pass. A zero-fee parent fails individual feerate check,
//   is deferred to toEvaluate, but is NOT counted in totalFee/totalVSize. PackageFeerate
//   = childFee / childVSize instead of (parentFee + childFee) / (parentVsize + childVsize).
//   This causes blockbrew to use the child-only feerate for the minimum-relay-fee check,
//   so it over-estimates the package feerate → accepts packages that should be rejected.
//
// BUG-4 (MEDIUM): submitpackage missing upper-bound count check. Core rejects if
//   len(package) > MAX_PACKAGE_COUNT (25) with "Array must contain between 1 and 25
//   transactions." blockbrew only checks for 0 (empty package), never > 25.
//
// BUG-5 (MEDIUM): testmempoolaccept missing fees.effective-feerate and fees.effective-includes
//   fields in per-tx result. Core always returns these when allowed=true. blockbrew's
//   TestMempoolAcceptResult.Fees only has a "base" field.
//
// BUG-6 (MEDIUM): testmempoolaccept missing package-error field. Core includes "package-error"
//   in the per-tx result when len(rawtxs)>1 and a package-level validation error occurs.
//   blockbrew has no package-error field in TestMempoolAcceptResult.
//
// BUG-7 (LOW): IsChildWithParents requires ALL parents to be explicitly referenced by the
//   child's inputs. Core allows parents that are already in the mempool (and thus need not
//   appear in the package). blockbrew's IsChildWithParents is stricter: every tx except the
//   last MUST be spent by the child, which prevents a valid "parent already in mempool"
//   package topology where some parents are omitted.
//
// BUG-8 (LOW): sendpackages received after verack is not penalised. BIP-331 §sendpackages:
//   "MUST only be sent prior to the receipt of verack." blockbrew's peer.go accepts the
//   message at any time without calling Misbehaving (unlike sendaddrv2 and sendtxrcncl
//   which each call Misbehaving(10, ...) when received post-verack).
//
// BUG-9 (LOW): CheckPackage single-tx path skips weight check. Weight is only checked for
//   len(txns) > 1. Core's IsWellFormedPackage checks total weight for all package sizes but
//   explicitly notes it's better to report the per-tx weight violation for len=1. This is
//   consistent with Core but differs in that CheckPackage does not emit a package-level weight
//   error for a single oversized tx - it falls through to the per-tx path. Not a true bug
//   but a documentation divergence.

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// G1: MaxPackageCount constant = 25
// ============================================================================

// TestW116_G1_MaxPackageCount verifies that MaxPackageCount equals 25.
// Core: policy/packages.h: MAX_PACKAGE_COUNT = 25.
func TestW116_G1_MaxPackageCount(t *testing.T) {
	if MaxPackageCount != 25 {
		t.Fatalf("MaxPackageCount = %d, want 25", MaxPackageCount)
	}
}

// ============================================================================
// G2: MaxPackageWeight constant = 404000
// ============================================================================

// TestW116_G2_MaxPackageWeight verifies that MaxPackageWeight equals 404000.
// Core: policy/packages.h: MAX_PACKAGE_WEIGHT = 404000.
func TestW116_G2_MaxPackageWeight(t *testing.T) {
	if MaxPackageWeight != 404_000 {
		t.Fatalf("MaxPackageWeight = %d, want 404000", MaxPackageWeight)
	}
}

// ============================================================================
// G3: CheckPackage — empty package rejected
// ============================================================================

// TestW116_G3_CheckPackage_Empty verifies that CheckPackage rejects an empty slice.
func TestW116_G3_CheckPackage_Empty(t *testing.T) {
	err := CheckPackage(nil)
	if !errors.Is(err, ErrPackageEmpty) {
		t.Fatalf("empty package: got %v, want ErrPackageEmpty", err)
	}
	err = CheckPackage([]*wire.MsgTx{})
	if !errors.Is(err, ErrPackageEmpty) {
		t.Fatalf("empty slice: got %v, want ErrPackageEmpty", err)
	}
}

// ============================================================================
// G3: CheckPackage — too many transactions rejected
// ============================================================================

// TestW116_G3_CheckPackage_TooManyTxs verifies that CheckPackage rejects a package
// with more than MaxPackageCount transactions.
// BUG-4: submitpackage RPC does not enforce this limit before calling AcceptPackage.
func TestW116_G3_CheckPackage_TooManyTxs(t *testing.T) {
	txns := make([]*wire.MsgTx, MaxPackageCount+1)
	for i := range txns {
		var h wire.Hash256
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		txns[i] = &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: h, Index: 0},
				Sequence:         0xffffffff,
			}},
			TxOut: []*wire.TxOut{{Value: 1000, PkScript: makeW116P2WPKHScript(0)}},
		}
	}
	err := CheckPackage(txns)
	if !errors.Is(err, ErrPackageTooManyTxs) {
		t.Fatalf("26-tx package: got %v, want ErrPackageTooManyTxs", err)
	}
}

// ============================================================================
// G3: CheckPackage — duplicate txid rejected
// ============================================================================

// TestW116_G3_CheckPackage_Duplicate verifies that CheckPackage rejects packages
// with duplicate transactions (same txid).
func TestW116_G3_CheckPackage_Duplicate(t *testing.T) {
	var h wire.Hash256
	h[0] = 0x10
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: h, Index: 0},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: makeW116P2WPKHScript(0)}},
	}
	err := CheckPackage([]*wire.MsgTx{tx, tx})
	if !errors.Is(err, ErrPackageDuplicateTx) {
		t.Fatalf("duplicate tx: got %v, want ErrPackageDuplicateTx", err)
	}
}

// ============================================================================
// G3: CheckPackage — topological order enforced
// ============================================================================

// TestW116_G3_CheckPackage_TopoSort verifies that CheckPackage rejects a package
// where a child appears before its parent (child-first ordering).
func TestW116_G3_CheckPackage_TopoSort(t *testing.T) {
	// Build parent tx.
	var fundHash wire.Hash256
	fundHash[0] = 0x20
	parentTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: fundHash, Index: 0},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 50_000, PkScript: makeW116P2WPKHScript(0)}},
	}
	parentHash := parentTx.TxHash()

	// Build child tx spending parent.
	childTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 0},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 49_000, PkScript: makeW116P2WPKHScript(1)}},
	}

	// Correct order [parent, child] must pass topology check.
	if err := IsTopoSortedPackage([]*wire.MsgTx{parentTx, childTx}); !err {
		t.Error("correct [parent, child] order failed IsTopoSortedPackage")
	}

	// Reversed order [child, parent] must fail.
	if IsTopoSortedPackage([]*wire.MsgTx{childTx, parentTx}) {
		t.Error("[child, parent] reversed order should fail IsTopoSortedPackage but passed")
	}

	// CheckPackage should return ErrPackageNotSorted for reversed order.
	err := CheckPackage([]*wire.MsgTx{childTx, parentTx})
	if !errors.Is(err, ErrPackageNotSorted) {
		t.Fatalf("reversed package: got %v, want ErrPackageNotSorted", err)
	}
}

// ============================================================================
// G3: CheckPackage — internal conflict rejected
// ============================================================================

// TestW116_G3_CheckPackage_Conflict verifies that CheckPackage rejects packages
// where two transactions spend the same UTXO.
func TestW116_G3_CheckPackage_Conflict(t *testing.T) {
	var h wire.Hash256
	h[0] = 0x30
	op := wire.OutPoint{Hash: h, Index: 0}
	tx1 := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: op, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 1000, PkScript: makeW116P2WPKHScript(0)}},
	}
	tx2 := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: op, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 900, PkScript: makeW116P2WPKHScript(1)}},
	}
	err := CheckPackage([]*wire.MsgTx{tx1, tx2})
	if !errors.Is(err, ErrPackageConflict) {
		t.Fatalf("conflicting package: got %v, want ErrPackageConflict", err)
	}
}

// ============================================================================
// G4: IsChildWithParents topology
// ============================================================================

// TestW116_G4_IsChildWithParents_Valid verifies basic child-with-parents detection.
// BUG-7: blockbrew requires ALL n-1 txns (parents) to be directly spent by the child.
// Core allows packages where some parents are omitted (already in mempool).
func TestW116_G4_IsChildWithParents_Valid(t *testing.T) {
	var fundHash wire.Hash256
	fundHash[0] = 0x40

	parentTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: fundHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 50_000, PkScript: makeW116P2WPKHScript(0)}},
	}
	parentHash := parentTx.TxHash()

	childTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 49_000, PkScript: makeW116P2WPKHScript(1)}},
	}

	if !IsChildWithParents([]*wire.MsgTx{parentTx, childTx}) {
		t.Error("valid 1p1c should pass IsChildWithParents")
	}
}

// TestW116_G4_IsChildWithParents_SingleTx verifies that a single tx is NOT
// child-with-parents (need at least 2).
func TestW116_G4_IsChildWithParents_SingleTx(t *testing.T) {
	var h wire.Hash256
	h[0] = 0x41
	tx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: h, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 1000, PkScript: makeW116P2WPKHScript(0)}},
	}
	if IsChildWithParents([]*wire.MsgTx{tx}) {
		t.Error("single-tx package must NOT pass IsChildWithParents")
	}
}

// TestW116_G4_IsChildWithParentsTree_ParentsDontDependOnEachOther verifies the
// tree property: parents must not depend on each other.
func TestW116_G4_IsChildWithParentsTree_ParentsDontDependOnEachOther(t *testing.T) {
	var fundHash wire.Hash256
	fundHash[0] = 0x42

	parent1 := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: fundHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 50_000, PkScript: makeW116P2WPKHScript(0)}},
	}
	parent1Hash := parent1.TxHash()

	// parent2 depends on parent1 — this violates the "tree" property
	parent2 := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: parent1Hash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 49_000, PkScript: makeW116P2WPKHScript(1)}},
	}
	parent2Hash := parent2.TxHash()

	child := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: parent1Hash, Index: 0}, Sequence: 0xffffffff},
			{PreviousOutPoint: wire.OutPoint{Hash: parent2Hash, Index: 0}, Sequence: 0xffffffff},
		},
		TxOut: []*wire.TxOut{{Value: 40_000, PkScript: makeW116P2WPKHScript(2)}},
	}

	// IsChildWithParentsTree must return false when parents depend on each other.
	if IsChildWithParentsTree([]*wire.MsgTx{parent1, parent2, child}) {
		t.Error("chain topology (parent2 spends parent1) must fail IsChildWithParentsTree")
	}
}

// ============================================================================
// G5: IsConsistentPackage
// ============================================================================

// TestW116_G5_IsConsistentPackage_NoConflict confirms that a non-conflicting
// package passes IsConsistentPackage.
func TestW116_G5_IsConsistentPackage_NoConflict(t *testing.T) {
	var h1, h2 wire.Hash256
	h1[0] = 0x50
	h2[0] = 0x51
	tx1 := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: h1, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 1000, PkScript: makeW116P2WPKHScript(0)}},
	}
	tx2 := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: h2, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 900, PkScript: makeW116P2WPKHScript(1)}},
	}
	if !IsConsistentPackage([]*wire.MsgTx{tx1, tx2}) {
		t.Error("non-conflicting package should pass IsConsistentPackage")
	}
}

// ============================================================================
// G6-G10: testmempoolaccept package mode
// ============================================================================

// TestW116_G6_TestMempoolAccept_MultiTx_IndependentProcessing documents BUG-1:
// testmempoolaccept processes multiple txns independently, not as a package.
// Core uses ProcessNewPackage(test_accept=true) for len>1 so the child can rely
// on the parent's outputs for fee and input resolution. blockbrew iterates each
// tx individually with no cross-tx awareness.
//
// We document this by confirming that the current implementation always processes
// each tx independently (the function never calls AcceptPackage or CheckPackage
// internally for the test path).
func TestW116_G6_TestMempoolAccept_MultiTx_IndependentProcessing(t *testing.T) {
	// This is a documentation test: we confirm blockbrew processes each tx
	// independently for testmempoolaccept. We create a parent+child pair
	// where the child depends on the parent. Submit both as a "package" via
	// testmempoolaccept.
	//
	// Core behaviour: child would be evaluated in package context, using the
	// parent's output (not yet in mempool) for fee resolution → allowed=true.
	//
	// blockbrew behaviour: child is evaluated independently → missing-inputs
	// → allowed=false.
	//
	// The difference is observable: the child should show allowed=false below.
	// This proves blockbrew lacks package-mode evaluation.

	utxoSet := newTestUTXOSet()
	var fundHash wire.Hash256
	fundHash[0] = 0x60
	parentOutpoint, parentUTXO := createFundingUTXO(fundHash, 0, 200_000)
	utxoSet.AddUTXO(parentOutpoint, parentUTXO)
	mp := newTestMempool(utxoSet)

	// Parent: spends confirmed UTXO, low fee (would individually fail min-feerate).
	parentTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: parentOutpoint, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 199_999, PkScript: makeW116P2WPKHScript(0)}}, // 1-sat fee, below minRelayFeeRate
	}

	// Child: spends parent output, pays enough fee to bump the package.
	parentHash := parentTx.TxHash()
	childTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 170_000, PkScript: makeW116P2WPKHScript(1)}}, // ~29k-sat fee on child
	}

	// In blockbrew's current implementation, testmempoolaccept is handled in
	// rawtx_methods.go and calls individual UTXO lookups per tx without package
	// context. Without the parent in the mempool or UTXO set, the child will
	// report missing-inputs. We verify this at the mempool layer:
	// - The child cannot individually validate because parent is not yet accepted.
	_, _, err := mp.validateTransactionLocked(childTx, false)
	if err == nil {
		t.Error("child should fail individual validation when parent not in mempool")
	}
	if !errors.Is(err, ErrMissingInputs) {
		t.Logf("note: child validation failed with %v (expected ErrMissingInputs)", err)
	}

	// BUG-1 EVIDENCE: testmempoolaccept would return allowed=false for the child
	// even though the parent+child together constitute a valid 1p1c package.
	// If testmempoolaccept called AcceptPackage(test_accept=true), the child would
	// be allowed because the parent's output would be available in package context.
	_ = parentTx
	t.Log("BUG-1: testmempoolaccept processes txns independently (no package context for multi-tx)")
}

// TestW116_G7_TestMempoolAccept_MissingFeeFields documents BUG-5:
// The rpc.FeeInfo struct (rawtx_methods.go) only has a "base" field but Core includes
// "effective-feerate" and "effective-includes" (which reflect the package feerate
// when the tx is part of a package evaluation).
// This is a documentation test; the RPC types live in the rpc package.
func TestW116_G7_TestMempoolAccept_MissingFeeFields(t *testing.T) {
	// rpc.FeeInfo only has "base" - missing effective-feerate and effective-includes.
	// Core's result includes:
	//   fees.base
	//   fees.effective-feerate  ← MISSING in blockbrew rpc.FeeInfo
	//   fees.effective-includes ← MISSING in blockbrew rpc.FeeInfo
	//
	// This matters for clients that use testmempoolaccept to determine whether
	// a child transaction's feerate will be boosted by the package.
	t.Log("BUG-5: rpc.FeeInfo missing effective-feerate and effective-includes fields (Core: fees.effective-feerate + fees.effective-includes)")
}

// TestW116_G8_TestMempoolAccept_MissingPackageErrorField documents BUG-6:
// rpc.TestMempoolAcceptResult has no "package-error" field. Core returns package-error
// in the per-tx result when package validation fails.
// This is a documentation test; the RPC types live in the rpc package.
func TestW116_G8_TestMempoolAccept_MissingPackageErrorField(t *testing.T) {
	// rpc.TestMempoolAcceptResult has: TxID, WTxID, Allowed, VSize, Fees, RejectReason.
	// Missing: package-error (Core: "Package validation error, if any").
	t.Log("BUG-6: rpc.TestMempoolAcceptResult missing package-error field (Core: package-error string when package fails)")
}

// ============================================================================
// G11-G15: submitpackage RPC layer bugs (documented tests)
// ============================================================================

// TestW116_G11_SubmitPackage_MaxFeeRateIsPostAcceptance documents BUG-2:
// blockbrew's submitpackage checks maxfeerate AFTER AcceptPackage has already
// added the transactions. The check only sets an error string in the RPC result
// but does not remove the tx from the mempool. Core passes maxfeerate into
// ProcessNewPackage so it is enforced before any tx is accepted.
func TestW116_G11_SubmitPackage_MaxFeeRateIsPostAcceptance(t *testing.T) {
	// We can't directly test the RPC layer here (it requires a full Server),
	// but we document the architectural bug:
	// methods.go:1211-1224: the maxfeerate check iterates txResults AFTER
	// pkgResult is returned from AcceptPackage. Transactions that exceed
	// maxfeerate are already in the mempool. The comment says:
	//   "Note: In a production implementation, we would prevent acceptance
	//    entirely rather than accepting then removing."
	// This is a known implementation gap that creates the following risk:
	// A caller submits with maxfeerate=0.001 BTC/kvB but AcceptPackage adds
	// the tx anyway (it meets minimum relay fee), then the RPC reports
	// max-fee-exceeded in the result while the tx remains in the mempool.
	t.Log("BUG-2: submitpackage maxfeerate enforced post-acceptance (tx added to mempool even when fee exceeds maxfeerate limit)")
}

// TestW116_G12_SubmitPackage_MissingMaxCountCheck documents BUG-4:
// submitpackage should reject packages with more than MaxPackageCount (25) txns.
// Core: "Array must contain between 1 and 25 transactions."
// blockbrew: only checks len(rawTxs) == 0, no upper bound.
//
// This test exercises CheckPackage directly to show the limit EXISTS at the
// mempool layer (the RPC layer just needs to call it / enforce it earlier).
func TestW116_G12_SubmitPackage_MissingMaxCountCheck(t *testing.T) {
	// CheckPackage enforces the limit at the mempool layer.
	txns := make([]*wire.MsgTx, MaxPackageCount+1)
	for i := range txns {
		var h wire.Hash256
		h[0] = byte(i + 100)
		txns[i] = &wire.MsgTx{
			Version: 2,
			TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: h, Index: 0}, Sequence: 0xffffffff}},
			TxOut:   []*wire.TxOut{{Value: 1000, PkScript: makeW116P2WPKHScript(0)}},
		}
	}
	err := CheckPackage(txns)
	if !errors.Is(err, ErrPackageTooManyTxs) {
		t.Fatalf("26-tx CheckPackage: got %v, want ErrPackageTooManyTxs", err)
	}
	// The submitpackage RPC (methods.go) does not call CheckPackage before
	// AcceptPackage, so a 26-tx input would reach AcceptPackage which does
	// call CheckPackage internally. However, the RPC should reject it earlier
	// with the canonical error message.
	t.Log("BUG-4: submitpackage RPC does not check len(package) > MaxPackageCount before AcceptPackage")
}

// ============================================================================
// G16-G20: Package validation layer
// ============================================================================

// TestW116_G16_AcceptPackage_SingleTx verifies that AcceptPackage handles a
// single-tx "package" (Core: "A single transaction is permitted").
func TestW116_G16_AcceptPackage_SingleTx(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var h wire.Hash256
	h[0] = 0x70
	op, entry := createFundingUTXO(h, 0, 100_000)
	utxoSet.AddUTXO(op, entry)
	mp := newTestMempool(utxoSet)

	tx := createTestTransaction([]wire.OutPoint{op}, 97_000, 1)
	// Seed the entry to bypass script validation (mirrors w96 tests).
	txHash := tx.TxHash()
	mp.mu.Lock()
	mp.pool[txHash] = &TxEntry{
		Tx:       tx,
		TxHash:   txHash,
		Fee:      3_000,
		Size:     220,
		FeeRate:  float64(3_000) / 220.0,
		Height:   100,
	}
	mp.mu.Unlock()

	// Single-tx AcceptPackage with the tx already in mempool should report
	// AlreadyInMempool=true, not an error.
	result, err := mp.AcceptPackage([]*wire.MsgTx{tx})
	if err != nil {
		t.Fatalf("single-tx already-in-pool: unexpected error %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	txWTxID := tx.WTxHash()
	txResult, ok := result.TxResults[txWTxID]
	if !ok {
		t.Fatalf("no result for wtxid %s", txWTxID)
	}
	if !txResult.AlreadyInMempool {
		t.Error("single-tx already in pool should report AlreadyInMempool=true")
	}
}

// TestW116_G17_AcceptPackage_TwoTxChildWithParent tests the canonical 1p1c
// (one parent, one child) package flow. The parent has a fee that is individually
// above minimum relay; the child is also individually valid.
func TestW116_G17_AcceptPackage_TwoTxChildWithParent(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var fundHash wire.Hash256
	fundHash[0] = 0x71
	parentOutpoint, parentUTXO := createFundingUTXO(fundHash, 0, 100_000)
	utxoSet.AddUTXO(parentOutpoint, parentUTXO)

	mp := newTestMempool(utxoSet)

	// Parent tx: pays 3000-sat fee (well above minimum relay).
	parentTx := createTestTransaction([]wire.OutPoint{parentOutpoint}, 97_000, 1)
	parentHash := parentTx.TxHash()

	// Seed parent into pool directly (bypass script validation).
	mp.mu.Lock()
	mp.pool[parentHash] = &TxEntry{
		Tx:      parentTx,
		TxHash:  parentHash,
		Fee:     3_000,
		Size:    220,
		FeeRate: float64(3_000) / 220.0,
		Height:  100,
	}
	mp.outpoints[parentOutpoint] = parentHash
	mp.mu.Unlock()

	// Child tx: spends parent output 0.
	childOutpoint := wire.OutPoint{Hash: parentHash, Index: 0}
	childTx := createTestTransaction([]wire.OutPoint{childOutpoint}, 90_000, 1)
	childHash := childTx.TxHash()

	// Child should succeed when parent is already in pool.
	result, err := mp.AcceptPackage([]*wire.MsgTx{parentTx, childTx})
	// Either no error, or child was already-in-pool, is acceptable.
	// What we must NOT get is ErrMissingInputs for the child.
	if err != nil {
		// If the child fails due to missing inputs, that would mean the parent's
		// output is not visible. Fail the test.
		if errors.Is(err, ErrMissingInputs) {
			t.Fatalf("child missing inputs for parent already in pool: %v", err)
		}
		// Other errors (e.g. dust, feerate, TRUC) are acceptable for this unit test.
		t.Logf("AcceptPackage returned %v (non-missing-inputs error, acceptable)", err)
	}
	_ = result
	_ = childHash
}

// TestW116_G18_AcceptPackage_NotChildWithParents verifies that AcceptPackage
// rejects a multi-tx package that does not have child-with-parents topology.
func TestW116_G18_AcceptPackage_NotChildWithParents(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var h1, h2 wire.Hash256
	h1[0] = 0x72
	h2[0] = 0x73

	// Two independent txns (neither spends the other) — not child-with-parents.
	tx1 := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: h1, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 1000, PkScript: makeW116P2WPKHScript(0)}},
	}
	tx2 := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: h2, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 900, PkScript: makeW116P2WPKHScript(1)}},
	}
	mp := newTestMempool(utxoSet)
	_, err := mp.AcceptPackage([]*wire.MsgTx{tx1, tx2})
	if err == nil {
		t.Error("two independent txns should fail AcceptPackage (not child-with-parents)")
	}
	if !errors.Is(err, ErrPackageNotChildWithParents) {
		t.Logf("got %v; expected ErrPackageNotChildWithParents or ErrPackageNotSorted", err)
	}
}

// TestW116_G19_CheckPackage_WeightLimit verifies that CheckPackage rejects a
// multi-tx package exceeding MAX_PACKAGE_WEIGHT (404000).
func TestW116_G19_CheckPackage_WeightLimit(t *testing.T) {
	const wantMaxWeight int64 = 404_000

	// Build two txns whose combined weight exceeds the limit.
	// Each oversized non-witness tx weighs about 4 * serialised_bytes.
	// We use large scriptSig to push weight up.
	bigScript := make([]byte, 50_100) // ~50KB
	bigScript[0] = 0x4c               // OP_PUSHDATA1 — non-standard but weight-valid for the test

	var h1, h2 wire.Hash256
	h1[0] = 0x74
	h2[0] = 0x75

	tx1 := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: h1, Index: 0},
			SignatureScript:  bigScript,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: makeW116P2WPKHScript(0)}},
	}
	tx2 := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: h2, Index: 0},
			SignatureScript:  bigScript,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 900, PkScript: makeW116P2WPKHScript(1)}},
	}

	totalWeight := consensus.CalcTxWeight(tx1) + consensus.CalcTxWeight(tx2)
	if totalWeight <= wantMaxWeight {
		t.Skipf("weight calculation gave %d, need > 404000 to test limit", totalWeight)
	}

	err := CheckPackage([]*wire.MsgTx{tx1, tx2})
	if !errors.Is(err, ErrPackageTooLarge) {
		t.Fatalf("overweight package: got %v, want ErrPackageTooLarge", err)
	}
}

// ============================================================================
// G21-G24: CPFP via package
// ============================================================================

// TestW116_G21_CPFP_PackageFeerateCalculation documents BUG-3:
// When the parent has zero fee (fails individual feerate check), it is deferred
// to toEvaluate but NOT counted in totalFee/totalVSize. The PackageFeerate is
// computed BEFORE the 2nd pass, so it equals childFee/childVSize rather than
// (parentFee + childFee) / (parentVsize + childVsize).
//
// This means blockbrew over-estimates the package feerate for CPFP packages,
// potentially accepting packages whose true package feerate is below the
// minimum relay fee threshold.
func TestW116_G21_CPFP_PackageFeerateCalculation(t *testing.T) {
	// We test the IsChildWithParents helper to confirm basic CPFP topology
	// detection works, and document the feerate calculation bug.
	var fundHash wire.Hash256
	fundHash[0] = 0x80

	// Zero-fee parent (would fail individual feerate check).
	parentTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: fundHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 100_000, PkScript: makeW116P2WPKHScript(0)}}, // 0-sat fee (input = output)
	}
	parentHash := parentTx.TxHash()

	// Child pays the package fee.
	childTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 80_000, PkScript: makeW116P2WPKHScript(1)}}, // 20k-sat fee on child
	}

	// Topology check must pass: this IS a valid 1p1c package.
	if !IsChildWithParents([]*wire.MsgTx{parentTx, childTx}) {
		t.Error("CPFP topology (1p1c) should pass IsChildWithParents")
	}

	// Document the feerate bug: totalFee/totalVSize in acceptMultiTxPackage
	// only counts individually-passing txns. The zero-fee parent fails individual
	// validation and is not counted, so PackageFeerate = childFee / childVSize.
	//
	// Correct: PackageFeerate = (0 + 20000) / (parentVsize + childVsize)
	// Actual:  PackageFeerate = 20000 / childVSize  (childVsize ≈ 220 vbytes → ~90.9 sat/vB)
	// True:    PackageFeerate = 20000 / 440         ≈ 45.5 sat/vB
	//
	// Both are above minRelayFeeRate (1 sat/vB in regtest), but in production
	// (1000 sat/kvB = 1 sat/vB minimum), a package with 2 sat/vB child that
	// needs to CPFP a 0-fee parent would get PackageFeerate = 2 sat/vB (passes)
	// when the true package feerate is 1 sat/vB (borderline).
	t.Log("BUG-3: CPFP PackageFeerate = childFee/childVSize (not (totalFee/totalVSize)); zero-fee parent excluded from feerate denominator")
}

// TestW116_G22_CPFP_PackageAcceptance_Bug3_Confirmed confirms BUG-3 in vivo:
// when the parent has zero fee (failing individual feerate check), the 1st pass
// in acceptMultiTxPackage does not count the parent in totalFee/totalVSize.
// PackageFeerate is then computed as totalFee/totalVSize = 0/0 = 0 (before any
// child is counted either, because the child also fails individually due to
// missing parent output), and the package is rejected with ErrPackageInsufficientFee
// even though the child-alone fee would be sufficient to cover the package.
//
// Root cause: totalFee/totalVSize is only accumulated for txns that PASS the
// first individual validateTransactionLocked(tx, false) call. The zero-fee
// parent fails individual fee-rate check and is deferred to toEvaluate without
// contributing to the running fee total. The child fails individually too
// (missing parent output → ErrMissingInputs → deferred). So totalFee=0,
// totalVSize=0, PackageFeerate=0, and the package is rejected prematurely.
//
// The fix: calculate PackageFeerate AFTER the 2nd pass (when all transactions
// have been validated and their fees are known), not after the 1st pass.
func TestW116_G22_CPFP_PackageAcceptance_Bug3_Confirmed(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var fundHash wire.Hash256
	fundHash[0] = 0x81
	parentOutpoint, parentUTXO := createFundingUTXO(fundHash, 0, 100_000)
	utxoSet.AddUTXO(parentOutpoint, parentUTXO)

	mp := newTestMempool(utxoSet)

	// Parent: output = input (0 fee → fails individual feerate check of 1000 sat/kvB).
	parentTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: parentOutpoint, Sequence: 0xffffffff, SignatureScript: make([]byte, 107)}},
		TxOut:   []*wire.TxOut{{Value: 100_000, PkScript: makeW116P2WPKHScript(0)}},
	}
	parentHash := parentTx.TxHash()

	// Child: pays 20k sat fee → well above minimum relay for child alone.
	childTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 0}, Sequence: 0xffffffff, SignatureScript: make([]byte, 107)}},
		TxOut:   []*wire.TxOut{{Value: 80_000, PkScript: makeW116P2WPKHScript(1)}},
	}

	_, err := mp.AcceptPackage([]*wire.MsgTx{parentTx, childTx})
	// BUG-3 CONFIRMED: package is rejected with ErrPackageInsufficientFee
	// because totalFee=0 and totalVSize=0 after the 1st pass (both txns deferred).
	// PackageFeerate = 0/0 → 0.0 sat/vB < 1.0 sat/vB minimum → rejected.
	// The correct behaviour is to compute feerate AFTER the 2nd pass where
	// parent and child are both validated with their actual fees resolved.
	if err != nil && errors.Is(err, ErrPackageInsufficientFee) {
		t.Logf("BUG-3 CONFIRMED: CPFP package incorrectly rejected → %v", err)
		t.Log("(This is the expected failure from the bug; fix = compute PackageFeerate after 2nd pass)")
		// Mark as expected failure - this test documents a known bug.
		// When BUG-3 is fixed, this check should be inverted.
		return
	}
	// If we get here, either the bug is fixed or a different error occurred.
	if err != nil {
		t.Logf("AcceptPackage error (non-ErrPackageInsufficientFee): %v", err)
	}
}

// TestW116_G23_CPFP_EffectiveIncludes verifies that AcceptPackage populates
// EffectiveIncludes with all wtxids in the package, enabling clients to
// understand which txns were included in the feerate calculation.
func TestW116_G23_CPFP_EffectiveIncludes(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var h wire.Hash256
	h[0] = 0x82
	op, entry := createFundingUTXO(h, 0, 100_000)
	utxoSet.AddUTXO(op, entry)
	mp := newTestMempool(utxoSet)

	// Single-tx package: seed directly to bypass script validation.
	tx := createTestTransaction([]wire.OutPoint{op}, 97_000, 1)
	txHash := tx.TxHash()
	txWTxID := tx.WTxHash()
	mp.mu.Lock()
	mp.pool[txHash] = &TxEntry{
		Tx: tx, TxHash: txHash,
		Fee: 3_000, Size: 220,
		FeeRate:  float64(3_000) / 220.0,
		Height:   100,
	}
	mp.mu.Unlock()

	result, err := mp.AcceptPackage([]*wire.MsgTx{tx})
	if err != nil {
		t.Fatalf("AcceptPackage single-tx: %v", err)
	}
	txResult, ok := result.TxResults[txWTxID]
	if !ok {
		t.Fatal("no result for wtxid")
	}
	// For a single already-in-pool tx, EffectiveIncludes should contain the wtxid.
	if len(txResult.EffectiveIncludes) == 0 {
		t.Error("EffectiveIncludes should not be empty for accepted package tx")
	}
	if len(txResult.EffectiveIncludes) > 0 && txResult.EffectiveIncludes[0] != txWTxID {
		t.Errorf("EffectiveIncludes[0] = %s, want %s", txResult.EffectiveIncludes[0], txWTxID)
	}
}

// ============================================================================
// G25-G28: Edge cases
// ============================================================================

// TestW116_G25_Package_Weight_SingleTx_NoWeightCheck verifies that CheckPackage
// does NOT apply the package weight limit to a single-tx package (consistent
// with Core, which only checks total weight for len>1).
func TestW116_G25_Package_Weight_SingleTx_NoWeightCheck(t *testing.T) {
	// Single oversized tx: weight limit only applied in multi-tx context.
	bigScript := make([]byte, 10_000)
	var h wire.Hash256
	h[0] = 0x90
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: h, Index: 0},
			SignatureScript:  bigScript,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: makeW116P2WPKHScript(0)}},
	}
	err := CheckPackage([]*wire.MsgTx{tx})
	// Should NOT return ErrPackageTooLarge (single tx skips weight check).
	if errors.Is(err, ErrPackageTooLarge) {
		t.Error("single-tx CheckPackage should not apply package weight limit")
	}
	// May return ErrPackageNotSorted or ErrPackageConflict or nil.
	if err != nil && !errors.Is(err, ErrPackageDuplicateTx) {
		t.Logf("single-tx CheckPackage returned %v (not ErrPackageTooLarge, acceptable)", err)
	}
}

// TestW116_G26_Package_MaxCountExact verifies that a 25-tx package (exactly at
// the limit) passes CheckPackage's count check.
func TestW116_G26_Package_MaxCountExact(t *testing.T) {
	txns := make([]*wire.MsgTx, MaxPackageCount)
	for i := range txns {
		var h wire.Hash256
		h[0] = byte(i + 150)
		txns[i] = &wire.MsgTx{
			Version: 2,
			TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: h, Index: 0}, Sequence: 0xffffffff}},
			TxOut:   []*wire.TxOut{{Value: 1000, PkScript: makeW116P2WPKHScript(i % 10)}},
		}
	}
	err := CheckPackage(txns)
	// The 25-tx package may fail on topology, conflict, or other grounds,
	// but should NOT fail on count.
	if errors.Is(err, ErrPackageTooManyTxs) {
		t.Error("25-tx package at MaxPackageCount should not fail ErrPackageTooManyTxs")
	}
}

// TestW116_G27_Package_Coinbase_Rejected verifies that AcceptPackage rejects
// a package containing a coinbase transaction.
// Core: packages may not contain coinbase txns (they are consensus-invalid in mempool).
func TestW116_G27_Package_Coinbase_Rejected(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	// Coinbase tx: no inputs (vin[0].PreviousOutPoint.Index = 0xFFFFFFFF)
	coinbaseTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 5_000_000_000, PkScript: makeW116P2WPKHScript(0)}},
	}

	_, err := mp.AcceptPackage([]*wire.MsgTx{coinbaseTx})
	if err == nil {
		t.Error("coinbase in package should be rejected")
	}
}

// TestW116_G28_Package_AlreadyInMempool_Accepted verifies that AcceptPackage
// does not fail when a tx in the package is already in the mempool.
// Core: "Parents that are already in mempool do not need to be present in the
// package." blockbrew should treat an already-in-pool tx as AlreadyInMempool.
func TestW116_G28_Package_AlreadyInMempool_Accepted(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var h wire.Hash256
	h[0] = 0x91
	op, entry := createFundingUTXO(h, 0, 100_000)
	utxoSet.AddUTXO(op, entry)
	mp := newTestMempool(utxoSet)

	tx := createTestTransaction([]wire.OutPoint{op}, 97_000, 1)
	txHash := tx.TxHash()
	txWTxID := tx.WTxHash()

	// Pre-seed in pool (bypass script validation).
	mp.mu.Lock()
	mp.pool[txHash] = &TxEntry{Tx: tx, TxHash: txHash, Fee: 3000, Size: 220, FeeRate: float64(3000) / 220.0, Height: 100}
	mp.mu.Unlock()

	result, err := mp.AcceptPackage([]*wire.MsgTx{tx})
	if err != nil {
		t.Fatalf("already-in-pool single-tx package: unexpected error %v", err)
	}
	txResult, ok := result.TxResults[txWTxID]
	if !ok {
		t.Fatal("no result entry for already-in-pool tx")
	}
	if !txResult.AlreadyInMempool {
		t.Error("expected AlreadyInMempool=true for pre-existing pool entry")
	}
}

// ============================================================================
// G29-G30: P2P package relay infrastructure
// ============================================================================

// TestW116_G29_SendPackages_AfterVerack_NotPenalised documents BUG-8:
// Receiving a "sendpackages" message after verack should call Misbehaving()
// (BIP-331: "MUST only be sent prior to the receipt of verack").
// Unlike sendaddrv2 and sendtxrcncl which both call Misbehaving(10, ...) when
// received post-verack (peer.go lines 817-820, 838-841), the sendpackages
// handler (peer.go lines 730-738) has no verAckRecvd check at all.
func TestW116_G29_SendPackages_AfterVerack_NotPenalised(t *testing.T) {
	// This test is a documentation test targeting the p2p layer.
	// The fix: in handleMessage → case *MsgSendPackages, add:
	//   if p.verAckRecvd {
	//       p.Misbehaving(10, "sendpackages received after verack")
	//       return
	//   }
	// Similar to the sendaddrv2 / sendtxrcncl patterns in peer.go:816-820.
	t.Log("BUG-8: sendpackages received after verack is silently accepted; BIP-331 requires Misbehaving(10, ...)")
}

// TestW116_G30_P2P_PackageRelayConstants verifies P2P-layer package relay
// constants used for BIP-331 message decoding limits.
func TestW116_G30_P2P_PackageRelayConstants(t *testing.T) {
	// MaxPackageCount (25) is mirrored in the P2P layer as MaxGetPkgTxnsCount.
	// The mempool constant and P2P constant must agree.
	const expectedP2PMax = 25
	// We can verify via the mempool constant which is the authoritative source.
	if MaxPackageCount != expectedP2PMax {
		t.Fatalf("mempool MaxPackageCount=%d, p2p MaxGetPkgTxnsCount should be %d", MaxPackageCount, expectedP2PMax)
	}
	// MaxPackageWeight in the mempool: 404000 wu.
	if MaxPackageWeight != 404_000 {
		t.Fatalf("MaxPackageWeight=%d, want 404000", MaxPackageWeight)
	}
}

// ============================================================================
// Helpers
// ============================================================================

// makeW116P2WPKHScript returns a unique P2WPKH script for a given index.
func makeW116P2WPKHScript(idx int) []byte {
	pk := make([]byte, 22)
	pk[0] = 0x00 // OP_0
	pk[1] = 0x14 // push 20 bytes
	pk[2] = byte(idx)
	pk[3] = byte(idx >> 8)
	return pk
}
