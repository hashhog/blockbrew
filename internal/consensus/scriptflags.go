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
// current rules (BIP16 exception at block 170,060, taproot exception at block
// 692,261, and one testnet3 BIP16 exception).
//
// Structure mirrors Core's GetBlockScriptFlags (validation.cpp:2249-2289)
// EXACTLY, in three ordered steps:
//
//  1. Seed with P2SH | WITNESS | TAPROOT — UNCONDITIONALLY, for every block
//     at every height on every network (validation.cpp:2262). Core has had no
//     BIP16Height and no taprootHeight in the script-flag path since v23.
//     Deviations are NOT expressed as height gates; see step 2.
//  2. On a block-hash hit in script_flag_exceptions, REPLACE the whole flag
//     set with the exception value (`flags = it->second`,
//     validation.cpp:2263-2266). This is an assignment, not an OR and not an
//     AND-NOT: the exception value is the complete trio-level answer for that
//     block, so e.g. SCRIPT_VERIFY_NONE at 170,060 clears P2SH+WITNESS+TAPROOT
//     together.
//  3. THEN OR the four height-gated flags on top — DERSIG (BIP66), CLTV
//     (BIP65), CSV (BIP112), NULLDUMMY (BIP147, activated with segwit)
//     (validation.cpp:2268-2286). Because this happens AFTER the replace,
//     an exception block still gets its era-appropriate DERSIG/CLTV/CSV/
//     NULLDUMMY rules — e.g. 692,261 ends up P2SH|WITNESS|DERSIG|CLTV|CSV|
//     NULLDUMMY, with only TAPROOT withheld.
//
// The old shape here early-returned the exception value, which silently
// dropped step 3 and would have under-enforced DERSIG/CLTV/CSV/NULLDUMMY on
// block 692,261.
//
// NOTE: params.TaprootHeight and params.SegwitHeight remain in ChainParams and
// are still consumed for softfork *reporting* (getblockchaininfo/
// getdeploymentinfo) and for the height-gated witness-commitment check in
// blockvalidation.go — they are deliberately NOT consulted here any more.
func GetBlockScriptFlags(height int32, params *ChainParams, blockHash wire.Hash256) script.ScriptFlags {
	// Step 1 — Core validation.cpp:2262. BIP16 didn't become active until Apr
	// 1 2012 and taproot until block 709,632, but only a handful of historical
	// blocks ever violated those rules, and each is named explicitly in
	// script_flag_exceptions. So, exactly as Core puts it: "For simplicity,
	// always leave P2SH+WITNESS+TAPROOT on except for the violating blocks."
	flags := script.ScriptVerifyP2SH | script.ScriptVerifyWitness | script.ScriptVerifyTaproot

	// Step 2 — Core validation.cpp:2263-2266. REPLACE, do not OR.
	// blockHash is in internal (little-endian) byte order, which is the order
	// ScriptFlagExceptions is keyed in: chaincfg.go builds its keys with
	// wire.NewHash256FromHex, which reverses the Core display hex on load, and
	// every production caller passes a hash produced by
	// wire.BlockHeader.BlockHash() (also internal order).
	if params.ScriptFlagExceptions != nil {
		if overrideFlags, ok := params.ScriptFlagExceptions[blockHash]; ok {
			flags = overrideFlags
		}
	}

	// Step 3 — Core validation.cpp:2268-2286. These four remain height-gated,
	// and are OR-ed on top of whatever step 2 left behind.

	// BIP66: Strict DER signatures (activated at BIP66Height).
	// ScriptVerifyStrictEncoding is policy-only (STANDARD_SCRIPT_VERIFY_FLAGS).
	if height >= params.BIP66Height {
		flags |= script.ScriptVerifyDERSig
	}

	// BIP65: CHECKLOCKTIMEVERIFY (activated at BIP65Height)
	if height >= params.BIP65Height {
		flags |= script.ScriptVerifyCLTV
	}

	// BIP68/BIP112/BIP113: Relative lock-time (CSV) (activated at CSVHeight)
	if height >= params.CSVHeight {
		flags |= script.ScriptVerifyCSV
	}

	// BIP147: NULLDUMMY, activated simultaneously with segwit. Core gates this
	// on DEPLOYMENT_SEGWIT (validation.cpp:2283-2286). Note that
	// SCRIPT_VERIFY_WITNESS itself is NOT gated here — it is part of the
	// unconditional step-1 trio.
	// ScriptVerifyNullFail and ScriptVerifyWitnessPubKeyType are policy-only
	// (STANDARD_SCRIPT_VERIFY_FLAGS per Bitcoin Core policy/policy.h:125,128).
	if height >= params.SegwitHeight {
		flags |= script.ScriptVerifyNullDummy
	}

	return flags
}

// GetStandardScriptFlags returns mempool/relay script verification flags for a
// given height.  This composes the consensus flags from GetBlockScriptFlags and
// adds the policy-only STANDARD_SCRIPT_VERIFY_FLAGS additions that Bitcoin Core
// uses in mempool acceptance (policy/policy.h:119-132).
//
// Do NOT use this for block validation — use GetBlockScriptFlags instead.
func GetStandardScriptFlags(height int32, params *ChainParams, blockHash wire.Hash256) script.ScriptFlags {
	flags := GetBlockScriptFlags(height, params, blockHash)

	// Add policy-only flags for mempool standardness enforcement
	if height >= params.BIP66Height {
		flags |= script.ScriptVerifyStrictEncoding
	}
	if height >= params.SegwitHeight {
		flags |= script.ScriptVerifyNullFail
		flags |= script.ScriptVerifyWitnessPubKeyType
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
