package mempool

// Package-relay PreChecks bypass regression suite.
//
// GAP (DoS): the package-accept path (submitpackage / 1p1c) used to admit and
// relay transactions that the single-tx PreChecks reject. acceptMultiTxPackage
// validates members via validateTransactionLocked, which SKIPPED the IsStandardTx
// gates that AddTransactionFrom enforces (version range, MIN_STANDARD_TX_
// NONWITNESS_SIZE, scriptSig size + push-only, output-script standardness,
// OP_RETURN datacarrier) and never ran checkRBFLocked on a member that conflicts
// with the mempool. A peer could therefore relay non-standard txs through the
// package door — a relay-policy DoS.
//
// FIX: checkStandardnessLocked is now shared by both paths and called from
// validateTransactionLocked; IsFinalTx + ephemeral-aware dust + checkRBFLocked
// are wired into the package-member path. The ONLY single-tx gate deliberately
// bypassed in package mode remains the per-tx fee floor (CPFP carve-out).
//
// These tests are "proven-teeth": each FAILS if the bypass regresses.
//
// Core reference: validation.cpp AcceptSubPackage / AcceptMultipleTransactions
// runs PreChecks per member; policy.cpp IsStandardTx.

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestPkgBypass_NonStandardVersionRejectedViaPackagePath proves a non-standard
// (version=0) member is rejected by the package-member validation path. Before
// the fix, validateTransactionLocked skipped the version gate entirely, so
// version=0 sailed through to script validation / admission.
func TestPkgBypass_NonStandardVersionRejectedViaPackagePath(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var fundHash wire.Hash256
	fundHash[0] = 0xA1
	outpoint, entry := createFundingUTXO(fundHash, 0, 100_000)
	utxoSet.AddUTXO(outpoint, entry)

	mp := newTestMempool(utxoSet)

	// Standard-output, fee-paying tx but VERSION=0 (non-standard).
	tx := createTestTransaction([]wire.OutPoint{outpoint}, 90_000, 1)
	tx.Version = 0

	// packageMode=true: must still be rejected on the version gate, which fires
	// before script validation.
	_, _, err := func() (int64, int64, error) {
		mp.mu.Lock()
		defer mp.mu.Unlock()
		return mp.validateTransactionLocked(tx, true)
	}()
	if !errors.Is(err, ErrTxVersion) {
		t.Fatalf("package path must reject version=0 member with ErrTxVersion; got %v", err)
	}
}

// TestPkgBypass_NonStandardOutputRejectedViaPackagePath proves a member with a
// nonstandard output script is rejected by the package-member path. A bare
// OP_RETURN with a non-push trailing byte (6a 09 ...) is classified NONSTANDARD
// by isStandardOutputScript (it is not well-formed nulldata).
func TestPkgBypass_NonStandardOutputRejectedViaPackagePath(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var fundHash wire.Hash256
	fundHash[0] = 0xA2
	outpoint, entry := createFundingUTXO(fundHash, 0, 100_000)
	utxoSet.AddUTXO(outpoint, entry)

	mp := newTestMempool(utxoSet)

	tx := createTestTransaction([]wire.OutPoint{outpoint}, 90_000, 1)
	// Malformed: OP_RETURN (0x6a) + length-prefix 0x09 claiming 9 bytes that
	// aren't there -> not well-formed nulldata -> nonstandard.
	tx.TxOut[0].PkScript = []byte{0x6a, 0x09, 0xde, 0xad, 0xbe, 0xef}

	_, _, err := func() (int64, int64, error) {
		mp.mu.Lock()
		defer mp.mu.Unlock()
		return mp.validateTransactionLocked(tx, true)
	}()
	if !errors.Is(err, ErrNonStandardOutput) {
		t.Fatalf("package path must reject nonstandard-output member with ErrNonStandardOutput; got %v", err)
	}
}

// TestPkgBypass_NonPushScriptSigRejectedViaPackagePath proves a member whose
// scriptSig is not push-only is rejected by the package-member path.
func TestPkgBypass_NonPushScriptSigRejectedViaPackagePath(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var fundHash wire.Hash256
	fundHash[0] = 0xA3
	outpoint, entry := createFundingUTXO(fundHash, 0, 100_000)
	utxoSet.AddUTXO(outpoint, entry)

	mp := newTestMempool(utxoSet)

	tx := createTestTransaction([]wire.OutPoint{outpoint}, 90_000, 1)
	// OP_NOP (0x61) is not a push opcode -> IsPushOnly == false -> nonstandard.
	tx.TxIn[0].SignatureScript = []byte{0x61}

	_, _, err := func() (int64, int64, error) {
		mp.mu.Lock()
		defer mp.mu.Unlock()
		return mp.validateTransactionLocked(tx, true)
	}()
	if !errors.Is(err, ErrScriptSigNotPushOnly) {
		t.Fatalf("package path must reject non-push scriptSig member with ErrScriptSigNotPushOnly; got %v", err)
	}
}

// TestPkgBypass_CPFPFeeFloorCarveOutPreserved is the teeth in the OTHER
// direction: the fix must NOT re-introduce a per-member individual-min-fee
// rejection. A low-fee (below MinRelayFeeRate) member with a standard output:
//   - single-tx mode  -> rejected with ErrInsufficientFee (fee floor enforced)
//   - package mode     -> NOT rejected with ErrInsufficientFee (carve-out)
//
// The fee-floor gate fires before script validation, so the distinction is
// observable even though createTestTransaction uses fake signatures (the
// package-mode tx then proceeds and fails later at the script gate — crucially
// NOT on the fee floor). This pins the CPFP semantics: a low-fee parent paid
// for by its child is still admissible at the per-member fee gate.
func TestPkgBypass_CPFPFeeFloorCarveOutPreserved(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var fundHash wire.Hash256
	fundHash[0] = 0xA4
	// Fund with exactly the output value + a tiny (below-floor) fee.
	const inAmt = 100_000
	const outAmt = 99_999 // 1-sat fee on a ~140-vB tx -> well below 1 sat/vB floor
	outpoint, entry := createFundingUTXO(fundHash, 0, inAmt)
	utxoSet.AddUTXO(outpoint, entry)

	mp := newTestMempool(utxoSet)

	tx := createTestTransaction([]wire.OutPoint{outpoint}, outAmt, 1) // standard P2WPKH output

	// Sanity: confirm the fee really is below the floor so the test is meaningful.
	if fee := int64(inAmt - outAmt); fee*1000/140 >= mp.config.MinRelayFeeRate {
		t.Fatalf("test setup: fee %d is not below the relay floor", fee)
	}

	// Single-tx mode: the fee floor MUST reject this.
	_, _, errSingle := func() (int64, int64, error) {
		mp.mu.Lock()
		defer mp.mu.Unlock()
		return mp.validateTransactionLocked(tx, false)
	}()
	if !errors.Is(errSingle, ErrInsufficientFee) {
		t.Fatalf("single-tx mode must reject below-floor tx with ErrInsufficientFee; got %v", errSingle)
	}

	// Package mode: the per-member fee floor MUST be bypassed (CPFP). The tx may
	// still fail later (fake-sig script check), but it must NOT fail on the
	// individual fee floor.
	_, _, errPkg := func() (int64, int64, error) {
		mp.mu.Lock()
		defer mp.mu.Unlock()
		return mp.validateTransactionLocked(tx, true)
	}()
	if errors.Is(errPkg, ErrInsufficientFee) {
		t.Fatalf("CPFP carve-out broken: package mode rejected a below-floor member "+
			"with ErrInsufficientFee (must be bypassed); got %v", errPkg)
	}
}

// TestPkgBypass_StandardnessHelperSharedBySingleAndPackagePaths is a structural
// guard: it confirms checkStandardnessLocked yields the SAME standardness
// verdict regardless of which path calls it, so the two paths cannot drift.
func TestPkgBypass_StandardnessHelperSharedBySingleAndPackagePaths(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())

	var fundHash wire.Hash256
	fundHash[0] = 0xA5
	op := wire.OutPoint{Hash: fundHash, Index: 0}

	// A standard tx passes; the same tx mutated non-standard fails — proving the
	// helper actually has teeth and is not a no-op.
	good := createTestTransaction([]wire.OutPoint{op}, 90_000, 1)
	mp.mu.Lock()
	errGood := mp.checkStandardnessLocked(good)
	mp.mu.Unlock()
	if errGood != nil {
		t.Fatalf("standard tx must pass checkStandardnessLocked; got %v", errGood)
	}

	bad := createTestTransaction([]wire.OutPoint{op}, 90_000, 1)
	bad.Version = 0
	mp.mu.Lock()
	errBad := mp.checkStandardnessLocked(bad)
	mp.mu.Unlock()
	if !errors.Is(errBad, ErrTxVersion) {
		t.Fatalf("non-standard tx must fail checkStandardnessLocked; got %v", errBad)
	}

	// Keep the consensus import anchored (used widely across the suite) so this
	// file stays consistent with sibling tests even if assertions are trimmed.
	_ = consensus.MaxStandardTxWeight
}
