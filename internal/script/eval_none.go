package script

import "github.com/hashhog/blockbrew/internal/wire"

// EvalScriptNone runs one script on an empty stack with no verification flags
// in the BASE (legacy) signature version and returns the resulting stack,
// bottom first. It is Core's
//
//	EvalScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE, &serror)
//
// as Core's ValidateInputsStandardness (policy/policy.cpp) uses it to turn a
// P2SH input's scriptSig into a stack. Every limit Core's EvalScript applies
// without flags applies here too: script size, push size (520 bytes), bad
// or disabled opcodes, op count and stack size (1000). The returned error
// carries the Core script error code (ErrorCodeOf).
//
// tx and txIdx only give the engine a spending context. Core uses a
// BaseSignatureChecker, whose signature checks always fail, where this checks
// signatures against tx. The two can differ only for a scriptSig with a
// signature opcode, i.e. one that is not push-only. Core never gets here with
// one: IsStandardTx refuses it first (scriptsig-not-pushonly). The real
// accept path enforces that rule before this runs; the testmempoolaccept
// dry-run does not yet, but there Core's answer for such a tx is the
// scriptsig-not-pushonly refusal anyway, never this function's result.
func EvalScriptNone(scriptBytes []byte, tx *wire.MsgTx, txIdx int) ([][]byte, error) {
	e, err := NewEngine(nil, tx, txIdx, ScriptVerifyNone, 0, nil)
	if err != nil {
		return nil, err
	}
	e.sigVersion = SigVersionBase
	if err := e.executeScript(scriptBytes); err != nil {
		return nil, err
	}
	return e.stack.Items(), nil
}
