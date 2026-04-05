package consensus

import (
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// GetBlockScriptFlags returns the script verification flags for a given block.
// This function returns ONLY consensus-critical flags. Adding policy flags here
// will cause valid blocks to be rejected.
//
// The blockHash parameter is checked against ScriptFlagExceptions in the chain
// params, matching Bitcoin Core's handling of historical blocks that violate
// current rules (BIP16 exception at block 170,060, taproot exception, etc.).
func GetBlockScriptFlags(height int32, params *ChainParams, blockHash wire.Hash256) script.ScriptFlags {
	// Check for per-block script flag exceptions (e.g., BIP16 exception at
	// block 170,060 on mainnet). Bitcoin Core does this in GetBlockScriptFlags
	// in validation.cpp.
	if params.ScriptFlagExceptions != nil {
		if overrideFlags, ok := params.ScriptFlagExceptions[blockHash]; ok {
			return overrideFlags
		}
	}

	var flags script.ScriptFlags

	// P2SH is always active (activated at height 173805 on mainnet, but we
	// treat it as always active for simplicity since all networks we support
	// have it active from genesis or very early)
	flags |= script.ScriptVerifyP2SH

	// BIP66: Strict DER signatures (activated at BIP66Height)
	if height >= params.BIP66Height {
		flags |= script.ScriptVerifyDERSig
		flags |= script.ScriptVerifyStrictEncoding
	}

	// BIP65: CHECKLOCKTIMEVERIFY (activated at BIP65Height)
	if height >= params.BIP65Height {
		flags |= script.ScriptVerifyCLTV
	}

	// BIP68/BIP112/BIP113: Relative lock-time (CSV) (activated at CSVHeight)
	if height >= params.CSVHeight {
		flags |= script.ScriptVerifyCSV
	}

	// BIP141/BIP143/BIP147: Segregated Witness (activated at SegwitHeight)
	// BIP146: NULLFAIL is also activated with segwit
	// BIP141: WITNESS_PUBKEYTYPE requires compressed pubkeys in witness v0
	if height >= params.SegwitHeight {
		flags |= script.ScriptVerifyWitness
		flags |= script.ScriptVerifyNullDummy
		flags |= script.ScriptVerifyNullFail
		flags |= script.ScriptVerifyWitnessPubKeyType
	}

	// BIP341/BIP342: Taproot (activated at TaprootHeight)
	if height >= params.TaprootHeight {
		flags |= script.ScriptVerifyTaproot
	}

	return flags
}

// ValidateTransactionScripts validates all input scripts of a transaction.
// This calls into the script engine for each input.
func ValidateTransactionScripts(tx *wire.MsgTx, utxoView UTXOView, flags script.ScriptFlags) error {
	// Coinbase transactions have no scripts to validate
	if IsCoinbaseTx(tx) {
		return nil
	}

	// Build the prevOuts slice for the transaction
	prevOuts := make([]*wire.TxOut, len(tx.TxIn))
	for i, in := range tx.TxIn {
		utxo := utxoView.GetUTXO(in.PreviousOutPoint)
		if utxo == nil {
			return ErrMissingInput
		}
		prevOuts[i] = &wire.TxOut{
			Value:    utxo.Amount,
			PkScript: utxo.PkScript,
		}
	}

	// Validate each input
	for i, in := range tx.TxIn {
		utxo := utxoView.GetUTXO(in.PreviousOutPoint)
		if utxo == nil {
			return ErrMissingInput
		}

		// Create script engine and execute
		err := script.VerifyScript(
			in.SignatureScript,
			utxo.PkScript,
			tx,
			i,
			flags,
			utxo.Amount,
			prevOuts,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// ValidateTransactionScriptsParallel validates all input scripts in parallel.
// This is more efficient for transactions with many inputs.
func ValidateTransactionScriptsParallel(tx *wire.MsgTx, utxoView UTXOView, flags script.ScriptFlags) error {
	// Coinbase transactions have no scripts to validate
	if IsCoinbaseTx(tx) {
		return nil
	}

	numInputs := len(tx.TxIn)
	if numInputs == 0 {
		return nil
	}

	// Build the prevOuts slice for the transaction
	prevOuts := make([]*wire.TxOut, numInputs)
	for i, in := range tx.TxIn {
		utxo := utxoView.GetUTXO(in.PreviousOutPoint)
		if utxo == nil {
			return ErrMissingInput
		}
		prevOuts[i] = &wire.TxOut{
			Value:    utxo.Amount,
			PkScript: utxo.PkScript,
		}
	}

	// For small transactions, sequential validation is fine
	if numInputs <= 4 {
		return ValidateTransactionScripts(tx, utxoView, flags)
	}

	// Create channels for parallel validation
	type result struct {
		idx int
		err error
	}
	results := make(chan result, numInputs)

	// Launch goroutines for each input
	for i := range tx.TxIn {
		go func(idx int) {
			utxo := utxoView.GetUTXO(tx.TxIn[idx].PreviousOutPoint)
			if utxo == nil {
				results <- result{idx, ErrMissingInput}
				return
			}

			err := script.VerifyScript(
				tx.TxIn[idx].SignatureScript,
				utxo.PkScript,
				tx,
				idx,
				flags,
				utxo.Amount,
				prevOuts,
			)
			results <- result{idx, err}
		}(i)
	}

	// Collect results
	for range numInputs {
		res := <-results
		if res.err != nil {
			return res.err
		}
	}

	return nil
}
