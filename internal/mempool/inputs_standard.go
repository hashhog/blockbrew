package mempool

import (
	"errors"
	"fmt"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ErrNonStandardInputs is the cause of a "bad-txns-nonstandard-inputs"
// rejection other than the two sigop limits (which keep their own sentinels,
// ErrTxLegacySigOpsTooMany and ErrP2SHSigOpsTooMany): a prevout Solver calls
// NONSTANDARD or WITNESS_UNKNOWN, or a P2SH scriptSig that fails to evaluate
// or leaves an empty stack.
var ErrNonStandardInputs = errors.New("bad-txns-nonstandard-inputs")

// nonStandardInputs builds Core's TX_INPUTS_NOT_STANDARD state: reason
// "bad-txns-nonstandard-inputs" and Core's debug string as the detail.
func nonStandardInputs(cause error, detail string) error {
	return &RBFRejectError{Reason: "bad-txns-nonstandard-inputs", Detail: detail, Err: cause}
}

// ValidateInputsStandardness is Bitcoin Core's ValidateInputsStandardness
// (policy/policy.cpp, called from MemPoolAccept::PreChecks at
// validation.cpp:903 after CheckTxInputs and before IsWitnessStandard),
// in Core's order:
//
//  1. CheckSigopsBIP54: non-witness sigops over all inputs > 2500.
//  2. For each input, Solver on the prevout scriptPubKey:
//     - NONSTANDARD       -> "input %u script unknown"
//     - WITNESS_UNKNOWN   -> "input %u witness program is undefined"
//     - SCRIPTHASH: EvalScript(scriptSig, SCRIPT_VERIFY_NONE); an error is
//     "p2sh scriptsig malformed", an empty stack "P2SH redeemscript
//     missing", and a redeemScript (top of stack) with more than 15
//     accurate sigops "p2sh redeemscript sigops exceed limit".
//
// Every failure is reason "bad-txns-nonstandard-inputs". lookup returns the
// coin an input spends; Core only gets here with every coin present, so
// callers run this after the missing-inputs check. A nil coin is skipped.
func ValidateInputsStandardness(tx *wire.MsgTx, lookup func(wire.OutPoint) *consensus.UTXOEntry) error {
	if consensus.IsCoinbaseTx(tx) {
		return nil
	}

	// CheckSigopsBIP54 (policy.cpp CheckSigopsBIP54).
	var legacySigops int
	for _, in := range tx.TxIn {
		legacySigops += consensus.CountSigOpsAccurate(in.SignatureScript)
		if utxo := lookup(in.PreviousOutPoint); utxo != nil {
			legacySigops += consensus.CountScriptPubKeySigOps(utxo.PkScript, in.SignatureScript)
		}
		if legacySigops > consensus.MaxTxLegacySigOps {
			return nonStandardInputs(
				fmt.Errorf("%w: %d > %d", ErrTxLegacySigOpsTooMany, legacySigops, consensus.MaxTxLegacySigOps),
				"non-witness sigops exceed bip54 limit")
		}
	}

	for i, in := range tx.TxIn {
		utxo := lookup(in.PreviousOutPoint)
		if utxo == nil {
			continue
		}
		switch script.Solver(utxo.PkScript) {
		case script.TxoutNonstandard:
			return nonStandardInputs(ErrNonStandardInputs,
				fmt.Sprintf("input %d script unknown", i))
		case script.TxoutWitnessUnknown:
			return nonStandardInputs(ErrNonStandardInputs,
				fmt.Sprintf("input %d witness program is undefined", i))
		case script.TxoutScriptHash:
			stack, err := script.EvalScriptNone(in.SignatureScript, tx, i)
			if err != nil {
				code, ok := script.ErrorCodeOf(err)
				if !ok {
					code = script.ErrCodeUnknownError
				}
				return nonStandardInputs(ErrNonStandardInputs,
					fmt.Sprintf("p2sh scriptsig malformed (input %d: %s)", i, script.CoreErrorString(code)))
			}
			if len(stack) == 0 {
				return nonStandardInputs(ErrNonStandardInputs,
					fmt.Sprintf("input %d P2SH redeemscript missing", i))
			}
			sigops := consensus.CountSigOpsAccurate(stack[len(stack)-1])
			if sigops > consensus.MaxP2SHSigOpsPerInput {
				return nonStandardInputs(
					fmt.Errorf("%w: input %d has %d sigops > %d",
						ErrP2SHSigOpsTooMany, i, sigops, consensus.MaxP2SHSigOpsPerInput),
					fmt.Sprintf("p2sh redeemscript sigops exceed limit (input %d: %d > %d)",
						i, sigops, consensus.MaxP2SHSigOpsPerInput))
			}
		}
	}
	return nil
}
