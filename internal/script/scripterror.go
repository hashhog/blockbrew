package script

import (
	"errors"
	"fmt"
)

// ErrorCode mirrors Bitcoin Core's ScriptError_t (script/script_error.h),
// same names and order. Every failure the validation engine returns carries
// one, so the block-connect classifier can decide by TYPE whether a failure
// is a verdict on the block: every Core code is (Core: CheckInputScripts ->
// BLOCK_CONSENSUS), ErrCodeInternal is not.
type ErrorCode int

const (
	ErrCodeOK ErrorCode = iota // SCRIPT_ERR_OK, never carried by an error
	ErrCodeUnknownError
	ErrCodeEvalFalse
	ErrCodeOpReturn
	ErrCodeScriptNum

	ErrCodeScriptSize
	ErrCodePushSize
	ErrCodeOpCount
	ErrCodeStackSize
	ErrCodeSigCount
	ErrCodePubKeyCount

	ErrCodeVerify
	ErrCodeEqualVerify
	ErrCodeCheckMultiSigVerify
	ErrCodeCheckSigVerify
	ErrCodeNumEqualVerify

	ErrCodeBadOpcode
	ErrCodeDisabledOpcode
	ErrCodeInvalidStackOperation
	ErrCodeInvalidAltstackOperation
	ErrCodeUnbalancedConditional

	ErrCodeNegativeLocktime
	ErrCodeUnsatisfiedLocktime

	ErrCodeSigHashType
	ErrCodeSigDER
	ErrCodeMinimalData
	ErrCodeSigPushOnly
	ErrCodeSigHighS
	ErrCodeSigNullDummy
	ErrCodePubKeyType
	ErrCodeCleanStack
	ErrCodeMinimalIf
	ErrCodeSigNullFail

	ErrCodeDiscourageUpgradableNops
	ErrCodeDiscourageUpgradableWitnessProgram
	ErrCodeDiscourageUpgradableTaprootVersion
	ErrCodeDiscourageOpSuccess
	ErrCodeDiscourageUpgradablePubKeyType

	ErrCodeWitnessProgramWrongLength
	ErrCodeWitnessProgramWitnessEmpty
	ErrCodeWitnessProgramMismatch
	ErrCodeWitnessMalleated
	ErrCodeWitnessMalleatedP2SH
	ErrCodeWitnessUnexpected
	ErrCodeWitnessPubKeyType

	ErrCodeSchnorrSigSize
	ErrCodeSchnorrSigHashType
	ErrCodeSchnorrSig
	ErrCodeTaprootWrongControlSize
	ErrCodeTapscriptValidationWeight
	ErrCodeTapscriptCheckMultiSig
	ErrCodeTapscriptMinimalIf
	ErrCodeTapscriptEmptyPubKey

	ErrCodeOpCodeSeparator
	ErrCodeSigFindAndDelete

	// ErrCodeInternal is blockbrew's own: the engine was called in a way no
	// transaction can cause (input index out of range, prevouts missing). It
	// says nothing about the block, so it is never a verdict. Core asserts.
	ErrCodeInternal

	numErrorCodes
)

var errorCodeNames = [numErrorCodes]string{
	"SCRIPT_ERR_OK",
	"SCRIPT_ERR_UNKNOWN_ERROR",
	"SCRIPT_ERR_EVAL_FALSE",
	"SCRIPT_ERR_OP_RETURN",
	"SCRIPT_ERR_SCRIPTNUM",
	"SCRIPT_ERR_SCRIPT_SIZE",
	"SCRIPT_ERR_PUSH_SIZE",
	"SCRIPT_ERR_OP_COUNT",
	"SCRIPT_ERR_STACK_SIZE",
	"SCRIPT_ERR_SIG_COUNT",
	"SCRIPT_ERR_PUBKEY_COUNT",
	"SCRIPT_ERR_VERIFY",
	"SCRIPT_ERR_EQUALVERIFY",
	"SCRIPT_ERR_CHECKMULTISIGVERIFY",
	"SCRIPT_ERR_CHECKSIGVERIFY",
	"SCRIPT_ERR_NUMEQUALVERIFY",
	"SCRIPT_ERR_BAD_OPCODE",
	"SCRIPT_ERR_DISABLED_OPCODE",
	"SCRIPT_ERR_INVALID_STACK_OPERATION",
	"SCRIPT_ERR_INVALID_ALTSTACK_OPERATION",
	"SCRIPT_ERR_UNBALANCED_CONDITIONAL",
	"SCRIPT_ERR_NEGATIVE_LOCKTIME",
	"SCRIPT_ERR_UNSATISFIED_LOCKTIME",
	"SCRIPT_ERR_SIG_HASHTYPE",
	"SCRIPT_ERR_SIG_DER",
	"SCRIPT_ERR_MINIMALDATA",
	"SCRIPT_ERR_SIG_PUSHONLY",
	"SCRIPT_ERR_SIG_HIGH_S",
	"SCRIPT_ERR_SIG_NULLDUMMY",
	"SCRIPT_ERR_PUBKEYTYPE",
	"SCRIPT_ERR_CLEANSTACK",
	"SCRIPT_ERR_MINIMALIF",
	"SCRIPT_ERR_SIG_NULLFAIL",
	"SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS",
	"SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
	"SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION",
	"SCRIPT_ERR_DISCOURAGE_OP_SUCCESS",
	"SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE",
	"SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH",
	"SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY",
	"SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH",
	"SCRIPT_ERR_WITNESS_MALLEATED",
	"SCRIPT_ERR_WITNESS_MALLEATED_P2SH",
	"SCRIPT_ERR_WITNESS_UNEXPECTED",
	"SCRIPT_ERR_WITNESS_PUBKEYTYPE",
	"SCRIPT_ERR_SCHNORR_SIG_SIZE",
	"SCRIPT_ERR_SCHNORR_SIG_HASHTYPE",
	"SCRIPT_ERR_SCHNORR_SIG",
	"SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE",
	"SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT",
	"SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG",
	"SCRIPT_ERR_TAPSCRIPT_MINIMALIF",
	"SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY",
	"SCRIPT_ERR_OP_CODESEPARATOR",
	"SCRIPT_ERR_SIG_FINDANDDELETE",
	"BLOCKBREW_INTERNAL_ERROR",
}

// NumErrorCodes is one past the last valid ErrorCode (for exhaustive tests).
const NumErrorCodes = numErrorCodes

// String returns Core's enum name, e.g. "SCRIPT_ERR_BAD_OPCODE".
func (c ErrorCode) String() string {
	if c >= 0 && c < numErrorCodes {
		return errorCodeNames[c]
	}
	return fmt.Sprintf("ErrorCode(%d)", int(c))
}

// IsConsensus reports whether a failure with this code is a property of the
// transaction being checked: every Core ScriptError except SCRIPT_ERR_OK. In
// block validation that is a BLOCK_CONSENSUS verdict. ErrCodeInternal and
// out-of-range values are not.
func (c ErrorCode) IsConsensus() bool {
	return c > ErrCodeOK && c < ErrCodeInternal
}

// Error is a failure of the script engine. Its text is the message the engine
// has always returned, so string consumers (reject reasons, logs) are
// unchanged; Code is what classifiers use.
type Error struct {
	Code ErrorCode
	msg  string
}

func (e *Error) Error() string { return e.msg }

// ScriptError returns the Core ScriptError_t name of the failure.
func (e *Error) ScriptError() string { return e.Code.String() }

func newError(code ErrorCode, msg string) *Error { return &Error{Code: code, msg: msg} }

func errorf(code ErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, msg: fmt.Sprintf(format, args...)}
}

// ErrorCodeOf returns the code of the script Error in err's chain, if any.
func ErrorCodeOf(err error) (ErrorCode, bool) {
	var se *Error
	if errors.As(err, &se) {
		return se.Code, true
	}
	return 0, false
}
