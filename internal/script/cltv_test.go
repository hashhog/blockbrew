package script

// BIP-65 CHECKLOCKTIMEVERIFY comprehensive test suite.
// Covers all 7 gates from Bitcoin Core interpreter.cpp:522-558 +
// CheckLockTime:1745-1779.
//
//	Gate 1:  ScriptVerifyCLTV flag off → treated as NOP, stack untouched
//	Gate 2:  Stack empty → SCRIPT_ERR_INVALID_STACK_OPERATION
//	Gate 3:  5-byte ScriptNum accepted (year-2038 avoidance), Core:546
//	Gate 4:  Negative lock time → SCRIPT_ERR_NEGATIVE_LOCKTIME
//	Gate 5:  Apples-to-apples type check (both height OR both timestamp)
//	Gate 6:  nLockTime > tx.nLockTime → SCRIPT_ERR_UNSATISFIED_LOCKTIME
//	Gate 7:  Input nSequence == SEQUENCE_FINAL (0xFFFFFFFF) → fail
//	Gate W80: fRequireMinimal honours engine policy (regression)

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// makeCLTVTx builds a minimal transaction suitable for CLTV tests.
// sequence should NOT be 0xFFFFFFFF unless the test needs the SEQUENCE_FINAL path.
func makeCLTVTx(txLockTime uint32, inputSequence uint32) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			SignatureScript:  []byte{},
			Sequence:         inputSequence,
		}},
		TxOut:    []*wire.TxOut{{Value: 1000, PkScript: []byte{OP_1}}},
		LockTime: txLockTime,
	}
}

// runCLTVScript pushes scriptLockTime as a script operand then executes
// OP_CHECKLOCKTIMEVERIFY against tx. Returns any error from execution.
func runCLTVScript(t *testing.T, scriptLockTime int64, tx *wire.MsgTx, flags ScriptFlags, sigVer SigVersion) error {
	t.Helper()
	var script []byte
	if scriptLockTime == 0 {
		script = []byte{OP_0, OP_CHECKLOCKTIMEVERIFY}
	} else {
		push := pushScriptNum(scriptLockTime)
		script = append(push, OP_CHECKLOCKTIMEVERIFY)
	}
	prevOuts := []*wire.TxOut{{PkScript: script}}
	engine, err := NewEngine(script, tx, 0, flags, 0, prevOuts)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	engine.sigVersion = sigVer
	engine.stack = NewStack()
	return engine.executeScript(script)
}

// ─── Gate 1: CLTV as NOP when ScriptVerifyCLTV is off ────────────────────────

// TestCLTVGate1_NopWhenFlagOff verifies that OP_CHECKLOCKTIMEVERIFY is a
// NOP when ScriptVerifyCLTV is not set — even if the locktime would otherwise
// fail. Core: interpreter.cpp:524-527.
func TestCLTVGate1_NopWhenFlagOff(t *testing.T) {
	// Operand is 10 but tx.LockTime=0 and sequence=FINAL — both failure conditions.
	// Without the flag the opcode is a NOP and the result is success.
	tx := makeCLTVTx(0, 0xFFFFFFFF)
	err := runCLTVScript(t, 10, tx, ScriptVerifyNone, SigVersionBase)
	if err != nil {
		t.Fatalf("CLTV-as-NOP must succeed, got: %v", err)
	}
}

// TestCLTVGate1_NopLeavesStackUntouched checks that treating CLTV as NOP
// does not pop the operand from the stack (the opcode is a pure NOP).
func TestCLTVGate1_NopLeavesStackUntouched(t *testing.T) {
	// Push OP_1 then CLTV-as-NOP; stack should still have 1 element.
	script := []byte{OP_1, OP_CHECKLOCKTIMEVERIFY}
	tx := makeCLTVTx(1, 0xFFFFFFFE)
	engine, _ := NewEngine(script, tx, 0, ScriptVerifyNone, 0, []*wire.TxOut{{PkScript: script}})
	engine.stack = NewStack()
	if err := engine.executeScript(script); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if engine.stack.Size() != 1 {
		t.Fatalf("NOP must not pop operand: stack size = %d, want 1", engine.stack.Size())
	}
}

// ─── Gate 2: Empty stack ──────────────────────────────────────────────────────

// TestCLTVGate2_EmptyStack verifies SCRIPT_ERR_INVALID_STACK_OPERATION when
// the stack is empty. Core: interpreter.cpp:529-530.
func TestCLTVGate2_EmptyStack(t *testing.T) {
	script := []byte{OP_CHECKLOCKTIMEVERIFY}
	tx := makeCLTVTx(1, 0xFFFFFFFE)
	engine, err := NewEngine(script, tx, 0, ScriptVerifyCLTV, 0, []*wire.TxOut{{PkScript: script}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	engine.stack = NewStack()
	if err := engine.executeScript(script); err == nil {
		t.Fatal("expected error for empty stack, got nil")
	}
}

// ─── Gate 3: 5-byte ScriptNum accepted ───────────────────────────────────────

// TestCLTVGate3_FiveByteScriptNumAccepted ensures CLTV accepts a 5-byte
// script number (values > 2^31 − 1). Core comment: "special case we tell
// CScriptNum to accept up to 5-byte bignums" — interpreter.cpp:546.
func TestCLTVGate3_FiveByteScriptNumAccepted(t *testing.T) {
	// Value 0x100000000 (2^32) requires 5 bytes as a script number.
	// tx.LockTime must be >= the operand but it's uint32 so it can't hold 2^32.
	// Use DISABLE approach: pick a value that is valid 5-byte but still <= uint32 max.
	// 500000001 fits in 4 bytes; instead use 0xFFFFFFFF (uint32 max) as operand.
	// As a script number, 0xFFFFFFFF positive = 4294967295 = needs 5 bytes
	// because the 4-byte representation 0xFF 0xFF 0xFF 0xFF has high bit set
	// so a sign extension byte 0x00 must be appended.
	val := int64(0xFFFFFFFF) // 4294967295 — needs 5 bytes as CScriptNum
	b := ScriptNumSerialize(val)
	if len(b) != 5 {
		t.Fatalf("expected 5-byte encoding for 0xFFFFFFFF, got %d bytes: %x", len(b), b)
	}
	// tx.LockTime max is 0xFFFFFFFF — equal to operand, so gate 6 passes (<=).
	// Sequence must not be FINAL.
	tx := makeCLTVTx(0xFFFFFFFF, 0xFFFFFFFE)
	// Both are >= LOCKTIME_THRESHOLD (500_000_000) so apples-to-apples passes.
	err := runCLTVScript(t, val, tx, ScriptVerifyCLTV, SigVersionBase)
	if err != nil {
		t.Fatalf("5-byte CLTV operand (0xFFFFFFFF) should pass, got: %v", err)
	}
}

// ─── Gate 4: Negative lock time ──────────────────────────────────────────────

// TestCLTVGate4_NegativeLockTimeFails verifies that a negative CLTV operand
// causes an immediate failure. Core: interpreter.cpp:551-552.
func TestCLTVGate4_NegativeLockTimeFails(t *testing.T) {
	// Push -1 (0x81 in script encoding).
	script := []byte{0x01, 0x81, OP_CHECKLOCKTIMEVERIFY} // push 1 byte [0x81] = -1
	tx := makeCLTVTx(0, 0xFFFFFFFE)
	engine, err := NewEngine(script, tx, 0, ScriptVerifyCLTV, 0, []*wire.TxOut{{PkScript: script}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	engine.stack = NewStack()
	if err := engine.executeScript(script); err == nil {
		t.Fatal("expected failure for negative CLTV operand, got nil")
	}
}

// TestCLTVGate4_ZeroLockTimePasses verifies that locktime==0 (empty/OP_0)
// is treated as the minimal non-negative value and passes if tx.LockTime==0.
func TestCLTVGate4_ZeroLockTimePasses(t *testing.T) {
	tx := makeCLTVTx(0, 0xFFFFFFFE) // LockTime=0, not FINAL
	err := runCLTVScript(t, 0, tx, ScriptVerifyCLTV, SigVersionBase)
	if err != nil {
		t.Fatalf("CLTV with zero operand + zero tx locktime should pass, got: %v", err)
	}
}

// ─── Gate 5: Apples-to-apples type check ─────────────────────────────────────

// TestCLTVGate5_TypeMismatch_HeightVsTimeFails checks that a block-height
// operand against a timestamp tx locktime is rejected. Core:1754-1758.
func TestCLTVGate5_TypeMismatch_HeightVsTimeFails(t *testing.T) {
	// Operand: 100 (block height, < LOCKTIME_THRESHOLD=500_000_000)
	// tx.LockTime: 500_000_001 (timestamp, >= LOCKTIME_THRESHOLD)
	tx := makeCLTVTx(500_000_001, 0xFFFFFFFE)
	err := runCLTVScript(t, 100, tx, ScriptVerifyCLTV, SigVersionBase)
	if err == nil {
		t.Fatal("expected failure for type mismatch (height vs timestamp), got nil")
	}
}

// TestCLTVGate5_TypeMismatch_TimeVsHeightFails checks the inverse: timestamp
// operand against a block-height tx locktime. Core:1754-1758.
func TestCLTVGate5_TypeMismatch_TimeVsHeightFails(t *testing.T) {
	// Operand: 500_000_001 (timestamp)
	// tx.LockTime: 100 (height)
	tx := makeCLTVTx(100, 0xFFFFFFFE)
	err := runCLTVScript(t, 500_000_001, tx, ScriptVerifyCLTV, SigVersionBase)
	if err == nil {
		t.Fatal("expected failure for type mismatch (timestamp vs height), got nil")
	}
}

// TestCLTVGate5_BothHeight_Passes confirms that two height-based values with
// the correct ordering pass the type check and value check. Core:1754-1763.
func TestCLTVGate5_BothHeight_Passes(t *testing.T) {
	// Operand: 1000 (height), tx.LockTime: 1000 (height). Equal → passes.
	tx := makeCLTVTx(1000, 0xFFFFFFFE)
	err := runCLTVScript(t, 1000, tx, ScriptVerifyCLTV, SigVersionBase)
	if err != nil {
		t.Fatalf("both height-based CLTV should pass, got: %v", err)
	}
}

// TestCLTVGate5_BothTimestamp_Passes confirms that two timestamp-based values
// with the correct ordering pass the type check.
func TestCLTVGate5_BothTimestamp_Passes(t *testing.T) {
	// Operand: 500_000_000 (threshold), tx.LockTime: 500_000_000. Equal → passes.
	tx := makeCLTVTx(500_000_000, 0xFFFFFFFE)
	err := runCLTVScript(t, 500_000_000, tx, ScriptVerifyCLTV, SigVersionBase)
	if err != nil {
		t.Fatalf("both timestamp-based CLTV should pass, got: %v", err)
	}
}

// ─── Gate 6: nLockTime > tx.nLockTime fails ──────────────────────────────────

// TestCLTVGate6_OperandExceedsTxLockTimeFails verifies rejection when the
// script operand exceeds the transaction's nLockTime. Core:1762-1763.
func TestCLTVGate6_OperandExceedsTxLockTimeFails(t *testing.T) {
	// Operand 10, tx.LockTime 5 — operand is greater.
	tx := makeCLTVTx(5, 0xFFFFFFFE)
	err := runCLTVScript(t, 10, tx, ScriptVerifyCLTV, SigVersionBase)
	if err == nil {
		t.Fatal("expected failure when operand (10) > tx.LockTime (5), got nil")
	}
}

// TestCLTVGate6_OperandEqualsTxLockTimePasses verifies the boundary case
// where operand == tx.LockTime — this must pass (Core uses <= check).
func TestCLTVGate6_OperandEqualsTxLockTimePasses(t *testing.T) {
	tx := makeCLTVTx(500, 0xFFFFFFFE)
	err := runCLTVScript(t, 500, tx, ScriptVerifyCLTV, SigVersionBase)
	if err != nil {
		t.Fatalf("operand == tx.LockTime should pass, got: %v", err)
	}
}

// TestCLTVGate6_OperandLessThanTxLockTimePasses verifies the normal case
// where operand < tx.LockTime.
func TestCLTVGate6_OperandLessThanTxLockTimePasses(t *testing.T) {
	tx := makeCLTVTx(1000, 0xFFFFFFFE)
	err := runCLTVScript(t, 500, tx, ScriptVerifyCLTV, SigVersionBase)
	if err != nil {
		t.Fatalf("operand < tx.LockTime should pass, got: %v", err)
	}
}

// ─── Gate 7: SEQUENCE_FINAL bypass ───────────────────────────────────────────

// TestCLTVGate7_SequenceFinalFails verifies that a spending input with
// nSequence == 0xFFFFFFFF (SEQUENCE_FINAL) causes CLTV to fail regardless
// of locktime values. Core:1775-1776.
// Rationale: SEQUENCE_FINAL disables locktime in IsFinalTx, so CLTV must also
// reject it to prevent bypassing the locktime constraint.
func TestCLTVGate7_SequenceFinalFails(t *testing.T) {
	// Valid locktime relationship (0 <= 100), but sequence is FINAL.
	tx := makeCLTVTx(100, 0xFFFFFFFF) // SEQUENCE_FINAL
	err := runCLTVScript(t, 100, tx, ScriptVerifyCLTV, SigVersionBase)
	if err == nil {
		t.Fatal("expected failure when input nSequence == SEQUENCE_FINAL, got nil")
	}
}

// TestCLTVGate7_SequenceFinalFails_Timestamp is the same as Gate7 but with
// timestamp-based locktime to confirm the check applies in both modes.
func TestCLTVGate7_SequenceFinalFails_Timestamp(t *testing.T) {
	tx := makeCLTVTx(500_000_001, 0xFFFFFFFF) // FINAL + timestamp
	err := runCLTVScript(t, 500_000_001, tx, ScriptVerifyCLTV, SigVersionBase)
	if err == nil {
		t.Fatal("expected failure for SEQUENCE_FINAL on timestamp-based CLTV, got nil")
	}
}

// TestCLTVGate7_OneBelowFinalPasses confirms that nSequence = 0xFFFFFFFE
// (one below SEQUENCE_FINAL) is accepted.
func TestCLTVGate7_OneBelowFinalPasses(t *testing.T) {
	tx := makeCLTVTx(100, 0xFFFFFFFE) // one below FINAL
	err := runCLTVScript(t, 100, tx, ScriptVerifyCLTV, SigVersionBase)
	if err != nil {
		t.Fatalf("nSequence=0xFFFFFFFE should pass CLTV, got: %v", err)
	}
}

// ─── Gate W80 regression: fRequireMinimal ─────────────────────────────────────

// TestCLTVGateW80_RequireMinimalWitnessV0 is the regression test for W80 fix:
// ScriptNumDeserialize must be called with e.requireMinimalData(), not hard-
// coded false. In witness v0 context, a non-minimal encoding must be rejected.
// The seqlock_test.go already covers this (TestCLTVGate14d_RequireMinimalEnforced)
// but we include it here as a named W80 regression sentinel.
func TestCLTVGateW80_RequireMinimalWitnessV0Regression(t *testing.T) {
	// Non-minimal encoding of locktime 1: push 2 bytes [0x01, 0x00] instead of [0x01].
	nonMinimal := []byte{0x02, 0x01, 0x00}
	script := append(nonMinimal, OP_CHECKLOCKTIMEVERIFY)
	tx := makeCLTVTx(1, 0xFFFFFFFE)
	engine, err := NewEngine(script, tx, 0, ScriptVerifyCLTV, 0, []*wire.TxOut{{PkScript: script}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	// WitnessV0 forces requireMinimalData() = true.
	engine.sigVersion = SigVersionWitnessV0
	engine.stack = NewStack()
	if err := engine.executeScript(script); err == nil {
		t.Fatal("W80 regression: non-minimal CLTV operand in witness v0 must be rejected")
	}
}

// TestCLTVGateW80_RequireMinimalBase confirms the complement: without
// ScriptVerifyMinimalData in legacy context, non-minimal is accepted.
func TestCLTVGateW80_NonMinimalAcceptedLegacy(t *testing.T) {
	nonMinimal := []byte{0x02, 0x01, 0x00}
	script := append(nonMinimal, OP_CHECKLOCKTIMEVERIFY)
	tx := makeCLTVTx(1, 0xFFFFFFFE)
	engine, err := NewEngine(script, tx, 0, ScriptVerifyCLTV, 0, []*wire.TxOut{{PkScript: script}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	engine.sigVersion = SigVersionBase
	engine.stack = NewStack()
	if err := engine.executeScript(script); err != nil {
		t.Fatalf("non-minimal CLTV in legacy context (no MinimalData flag) should pass, got: %v", err)
	}
}
