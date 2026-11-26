package mempool

import (
	"fmt"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Read-only policy probes for the single-transaction testmempoolaccept dry
// run (internal/rpc handleTestMempoolAccept). That dry run builds its own
// prevout view and walks Core's PreChecks order itself, and it had drifted
// from acceptLocked: it never ran IsStandardTx's scriptSig loop,
// IsWitnessStandard, the BIP68 sequence locks or SingleTRUCChecks, so it
// reported allowed (or a later failure) for transactions Core's test_accept
// and blockbrew's own sendrawtransaction refuse. Each probe below calls the
// exact function acceptLocked calls, so the two paths cannot drift on these
// rules again.

// checkScriptSigStandard is Core IsStandardTx's input loop
// (policy/policy.cpp:117-133): each scriptSig at most
// MAX_STANDARD_SCRIPTSIG_SIZE bytes ("scriptsig-size") and push-only
// ("scriptsig-not-pushonly"). Shared by acceptLocked (through
// checkStandardnessLocked) and the dry run.
func checkScriptSigStandard(tx *wire.MsgTx) error {
	for i, in := range tx.TxIn {
		if len(in.SignatureScript) > MaxStandardScriptSigSize {
			return fmt.Errorf("%w: input %d scriptSig %d bytes > %d",
				ErrScriptSigTooLarge, i, len(in.SignatureScript), MaxStandardScriptSigSize)
		}
		if len(in.SignatureScript) > 0 && !script.IsPushOnly(in.SignatureScript) {
			return fmt.Errorf("%w: input %d", ErrScriptSigNotPushOnly, i)
		}
	}
	return nil
}

// CheckScriptSigStandard runs IsStandardTx's scriptSig loop. It returns nil,
// or an error wrapping ErrScriptSigTooLarge or ErrScriptSigNotPushOnly.
func CheckScriptSigStandard(tx *wire.MsgTx) error {
	return checkScriptSigStandard(tx)
}

// CheckSequenceLocks is Core's CheckSequenceLocksAtTip (validation.cpp:894)
// against the next block: acceptLocked's BIP68 gate. It returns nil, or an
// error wrapping ErrSequenceLockNotMet (Core "non-BIP68-final"). Skipped,
// as in acceptLocked, when no ChainState is wired.
func (mp *Mempool) CheckSequenceLocks(tx *wire.MsgTx) error {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.checkSequenceLocksLocked(tx)
}

// CheckWitnessStandard is Core's IsWitnessStandard (policy/policy.cpp:251,
// validation.cpp:908), run only for a transaction carrying witness data, as
// acceptLocked runs it. The prevouts come from view. A non-nil error means
// Core's "bad-witness-nonstandard".
func CheckWitnessStandard(tx *wire.MsgTx, view consensus.UTXOView) error {
	if !tx.HasWitness() {
		return nil
	}
	return isWitnessStandard(tx, view.GetUTXO)
}

// CheckSingleTRUC is Core's SingleTRUCChecks (policy/truc_policy.cpp:171,
// validation.cpp:960) against the current mempool, with the mempool
// transactions tx conflicts with as the direct conflicts: acceptLocked's
// TRUC gate. A non-nil error means Core's "TRUC-violation".
func (mp *Mempool) CheckSingleTRUC(tx *wire.MsgTx) error {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	var conflicts map[wire.Hash256]bool
	for _, in := range tx.TxIn {
		if h, ok := mp.outpoints[in.PreviousOutPoint]; ok {
			if conflicts == nil {
				conflicts = make(map[wire.Hash256]bool)
			}
			conflicts[h] = true
		}
	}
	return mp.singleTRUCChecks(tx, conflicts)
}
