package mempool

import (
	"fmt"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ScriptCheckError is a failed input script check, carrying what Core's
// TxValidationState holds after CheckInputScripts (validation.cpp): the reject
// reason "mempool-script-verify-flag-failed (<ScriptErrorString>)" (or
// "block-script-verify-flag-failed (...)" when only the consensus flags fail)
// and the debug string "input N of <txid> (wtxid <wtxid>), spending <prev>:<n>".
type ScriptCheckError struct {
	Reason string
	Debug  string
	Err    error
}

// Error is Core's TxValidationState::ToString(): "<reason>, <debug>".
func (e *ScriptCheckError) Error() string { return e.Reason + ", " + e.Debug }

func (e *ScriptCheckError) Unwrap() error { return e.Err }

// CheckInputScripts runs the two script passes of Core's MemPoolAccept against
// the given prevout view: PolicyScriptChecks with the STANDARD flags, then
// ConsensusScriptChecks with the next block's flags. It is the script stage of
// the testmempoolaccept dry-run, which builds its own view of the inputs
// instead of going through acceptLocked. Returns nil or a *ScriptCheckError.
func (mp *Mempool) CheckInputScripts(tx *wire.MsgTx, view consensus.UTXOView) error {
	mp.mu.RLock()
	policyFlags := mp.getStandardScriptFlags()
	consensusFlags := mp.getConsensusScriptFlags()
	mp.mu.RUnlock()

	prevOuts := make([]*wire.TxOut, len(tx.TxIn))
	for i, in := range tx.TxIn {
		utxo := view.GetUTXO(in.PreviousOutPoint)
		if utxo == nil {
			return consensus.ErrMissingInput
		}
		prevOuts[i] = &wire.TxOut{Value: utxo.Amount, PkScript: utxo.PkScript}
	}
	if err := checkInputScripts(tx, prevOuts, policyFlags, "mempool-script-verify-flag-failed"); err != nil {
		return err
	}
	if consensusFlags != policyFlags {
		return checkInputScripts(tx, prevOuts, consensusFlags, "block-script-verify-flag-failed")
	}
	return nil
}

func checkInputScripts(tx *wire.MsgTx, prevOuts []*wire.TxOut, flags script.ScriptFlags, prefix string) error {
	for i, in := range tx.TxIn {
		err := script.VerifyScript(in.SignatureScript, prevOuts[i].PkScript, tx, i, flags, prevOuts[i].Value, prevOuts)
		if err == nil {
			continue
		}
		code, ok := script.ErrorCodeOf(err)
		if !ok {
			code = script.ErrCodeUnknownError
		}
		txid, wtxid := tx.TxHash(), tx.WTxHash()
		return &ScriptCheckError{
			Reason: fmt.Sprintf("%s (%s)", prefix, script.CoreErrorString(code)),
			Debug: fmt.Sprintf("input %d of %s (wtxid %s), spending %s:%d",
				i, txid.String(), wtxid.String(), in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index),
			Err: err,
		}
	}
	return nil
}
