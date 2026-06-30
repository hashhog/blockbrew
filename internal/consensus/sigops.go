package consensus

import (
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// CountSigOps counts the signature operations in a script with accurate
// CHECKMULTISIG counting (fAccurate=true in Bitcoin Core terms).
// Mirrors Bitcoin Core's CScript::GetSigOpCount(fAccurate=true)
// (script.cpp:158-180):
//   - OP_CHECKSIG / OP_CHECKSIGVERIFY → 1 each
//   - OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY → key-count from lastOpcode
//     if lastOpcode is OP_1..OP_16, otherwise MaxPubKeysPerMultisig (20)
//
// Used for: P2SH redeemScript counting (gate 2/4), witness script counting
// (gate 8), and the BIP54 per-input legacy sigop sum (gate 3 in the BIP54
// CheckSigopsBIP54 path, which also uses fAccurate=true).
func CountSigOps(scriptBytes []byte) int {
	return countSigOpsCore(scriptBytes, true)
}

// CountSigOpsInaccurate counts signature operations with CHECKMULTISIG always
// treated as MaxPubKeysPerMultisig (20), regardless of the preceding push
// opcode. This is the fAccurate=false variant used by GetLegacySigOpCount
// (script.cpp:158-180 with fAccurate=false).
//
// Used for: legacy block sigops counting (GetLegacySigOpCount, gate 1/5/9):
// every OP_CHECKMULTISIG/OP_CHECKMULTISIGVERIFY in a scriptSig or scriptPubKey
// contributes 20 to the legacy count, which is then scaled by
// WITNESS_SCALE_FACTOR (4) for the block budget.
func CountSigOpsInaccurate(scriptBytes []byte) int {
	return countSigOpsCore(scriptBytes, false)
}

// CountSigOpsAccurate is an alias for CountSigOps (fAccurate=true).
// Provided so callers can use a name that makes the accurate/inaccurate
// distinction explicit.
func CountSigOpsAccurate(scriptBytes []byte) int {
	return countSigOpsCore(scriptBytes, true)
}

// countSigOpsCore is the shared implementation of accurate and inaccurate
// sigop counting. Mirrors Bitcoin Core's CScript::GetSigOpCount(fAccurate)
// at script.cpp:158-180.
func countSigOpsCore(scriptBytes []byte, fAccurate bool) int {
	sigOps := 0
	pc := 0
	lastOp := byte(script.OP_INVALIDOPCODE)

	for pc < len(scriptBytes) {
		op := scriptBytes[pc]
		pc++

		// Handle push operations - skip the data.
		// Per Core: lastOpcode is updated for EVERY opcode including pushdatas.
		if op >= 0x01 && op <= 0x4b {
			pc += int(op)
			lastOp = op
			continue
		}

		switch op {
		case script.OP_PUSHDATA1:
			if pc >= len(scriptBytes) {
				return sigOps
			}
			dataLen := int(scriptBytes[pc])
			pc += 1 + dataLen
		case script.OP_PUSHDATA2:
			if pc+2 > len(scriptBytes) {
				return sigOps
			}
			dataLen := int(scriptBytes[pc]) | int(scriptBytes[pc+1])<<8
			pc += 2 + dataLen
		case script.OP_PUSHDATA4:
			if pc+4 > len(scriptBytes) {
				return sigOps
			}
			dataLen := int(scriptBytes[pc]) | int(scriptBytes[pc+1])<<8 |
				int(scriptBytes[pc+2])<<16 | int(scriptBytes[pc+3])<<24
			pc += 4 + dataLen
		case script.OP_CHECKSIG, script.OP_CHECKSIGVERIFY:
			sigOps++
		case script.OP_CHECKMULTISIG, script.OP_CHECKMULTISIGVERIFY:
			if fAccurate && lastOp >= script.OP_1 && lastOp <= script.OP_16 {
				// Accurate: use the actual key count pushed by the preceding opcode.
				sigOps += int(lastOp - script.OP_1 + 1)
			} else {
				// Inaccurate or no preceding OP_N: worst-case 20.
				sigOps += MaxPubKeysPerMultisig
			}
		}
		lastOp = op
	}

	return sigOps
}

// CountScriptSigOps counts sigops in a scriptSig for P2SH transactions.
// For P2SH, the sigop count comes from the redeemScript (last push in scriptSig).
// Returns 0 if scriptSig is not push-only (any opcode > OP_16 aborts, matching
// Bitcoin Core's CScript::GetSigOpCount(scriptSig) at script.cpp:197).
func CountScriptSigOps(scriptSig []byte) int {
	// Core: if any opcode > OP_16 in scriptSig, return 0.
	if !script.IsPushOnly(scriptSig) {
		return 0
	}
	// Find the last push data in the script
	lastPush := extractLastPush(scriptSig)
	if lastPush == nil {
		return 0
	}

	// Count sigops in the redeem script with accurate CHECKMULTISIG counting.
	// Core: subscript.GetSigOpCount(true) — fAccurate=true.
	return CountSigOps(lastPush)
}

// extractLastPush extracts the last push data item from a script.
// The caller must ensure the script is push-only before calling this function.
func extractLastPush(scriptBytes []byte) []byte {
	var lastPush []byte
	pc := 0

	for pc < len(scriptBytes) {
		op := scriptBytes[pc]
		pc++

		var pushData []byte

		if op >= 0x01 && op <= 0x4b {
			dataLen := int(op)
			if pc+dataLen > len(scriptBytes) {
				return lastPush
			}
			pushData = scriptBytes[pc : pc+dataLen]
			pc += dataLen
		} else if op == script.OP_PUSHDATA1 {
			if pc >= len(scriptBytes) {
				return lastPush
			}
			dataLen := int(scriptBytes[pc])
			pc++
			if pc+dataLen > len(scriptBytes) {
				return lastPush
			}
			pushData = scriptBytes[pc : pc+dataLen]
			pc += dataLen
		} else if op == script.OP_PUSHDATA2 {
			if pc+2 > len(scriptBytes) {
				return lastPush
			}
			dataLen := int(scriptBytes[pc]) | int(scriptBytes[pc+1])<<8
			pc += 2
			if pc+dataLen > len(scriptBytes) {
				return lastPush
			}
			pushData = scriptBytes[pc : pc+dataLen]
			pc += dataLen
		} else if op == script.OP_PUSHDATA4 {
			if pc+4 > len(scriptBytes) {
				return lastPush
			}
			dataLen := int(scriptBytes[pc]) | int(scriptBytes[pc+1])<<8 |
				int(scriptBytes[pc+2])<<16 | int(scriptBytes[pc+3])<<24
			pc += 4
			if pc+dataLen > len(scriptBytes) {
				return lastPush
			}
			pushData = scriptBytes[pc : pc+dataLen]
			pc += dataLen
		} else {
			// OP_0 (0x00), OP_1NEGATE (0x4f), OP_RESERVED (0x50), OP_1..OP_16 (0x51..0x60).
			// IsPushOnly (called before extractLastPush) guarantees op <= OP_16, so no
			// other opcodes reach here.
			//
			// Bitcoin Core GetScriptOp (script.cpp:312-362) calls pvchRet->clear() at
			// the start of every call:
			//   - OP_0 (0x00 < OP_PUSHDATA1): reads 0 bytes → pvchRet = empty slice.
			//   - OP_1NEGATE..OP_16 (> OP_PUSHDATA4): the data-assignment block is not
			//     entered → pvchRet stays cleared, i.e. empty.
			//
			// In GetSigOpCount(scriptSig) (script.cpp:182-204), vData holds the last
			// GetOp result. A trailing OP_0 or OP_1..OP_16 therefore leaves vData empty,
			// so the P2SH redeemScript subscript is empty → 0 sigops.
			//
			// Mirror this by setting pushData to a non-nil empty slice, so the
			// lastPush update below resets it to empty instead of keeping the prior push.
			pushData = []byte{}
		}

		if pushData != nil {
			lastPush = pushData
		}
	}

	return lastPush
}

// CountScriptPubKeySigOps returns the P2SH-aware sigop count for a single
// output being spent. This mirrors Bitcoin Core's
// CScript::GetSigOpCount(const CScript& scriptSig) at script.cpp:182-204:
//   - If scriptPubKey is NOT P2SH: return GetSigOpCount(true) (accurate).
//   - If scriptPubKey IS P2SH:     walk scriptSig push-only (return 0 if any
//     opcode > OP_16); extract last push as redeemScript; return accurate count.
//
// Used for the BIP54 per-input sigop sum (CheckSigopsBIP54) at policy.cpp:186.
func CountScriptPubKeySigOps(scriptPubKey []byte, scriptSig []byte) int {
	if !script.IsP2SH(scriptPubKey) {
		return CountSigOps(scriptPubKey)
	}
	// P2SH: count sigops inside the redeemScript.
	return CountScriptSigOps(scriptSig)
}

// GetTransactionSigOpCost returns the BIP141 sigops cost for a single transaction.
// This mirrors Bitcoin Core's GetTransactionSigOpCost (consensus/tx_verify.cpp:143-162):
//   - legacy (scriptSig of each vin + scriptPubKey of each vout) × WITNESS_SCALE_FACTOR
//     using INACCURATE counting (CHECKMULTISIG = 20 always), matching
//     GetLegacySigOpCount which calls GetSigOpCount(false).
//   - coinbase: return after legacy, skip P2SH + witness
//   - P2SH redeem-script sigops × WITNESS_SCALE_FACTOR (accurate)
//   - witness sigops (unscaled, ×1) (accurate)
//
// Used for both the per-tx mempool policy gate (MAX_STANDARD_TX_SIGOPS_COST=16000)
// and the per-tx contribution to the block-level gate (MAX_BLOCK_SIGOPS_COST=80000).
func GetTransactionSigOpCost(tx *wire.MsgTx, utxoView UTXOView) int64 {
	// Legacy sigops: count in every vin scriptSig and every vout scriptPubKey,
	// scale by WITNESS_SCALE_FACTOR.
	// Core: GetLegacySigOpCount calls GetSigOpCount(fAccurate=false) →
	// CHECKMULTISIG always counts as 20 (inaccurate).
	var legacy int
	for _, in := range tx.TxIn {
		legacy += CountSigOpsInaccurate(in.SignatureScript)
	}
	for _, out := range tx.TxOut {
		legacy += CountSigOpsInaccurate(out.PkScript)
	}
	cost := int64(legacy) * int64(WitnessScaleFactor)

	// Coinbase short-circuit: P2SH and witness sigops are skipped.
	// Core: if (tx.IsCoinBase()) return nSigOps; (tx_verify.cpp:147-148)
	if IsCoinbaseTx(tx) {
		return cost
	}

	if utxoView != nil {
		// P2SH sigops: already scaled inside CountP2SHSigOps.
		cost += int64(CountP2SHSigOps(tx, utxoView))
		// Witness sigops: unscaled (×1).
		cost += int64(CountWitnessSigOps(tx, utxoView))
	}

	return cost
}

// CountP2SHSigOps counts sigops for P2SH transactions.
// This includes sigops in the redeem script, scaled by WitnessScaleFactor.
func CountP2SHSigOps(tx *wire.MsgTx, utxoView UTXOView) int {
	if IsCoinbaseTx(tx) {
		return 0
	}

	totalSigOps := 0

	for _, in := range tx.TxIn {
		utxo := utxoView.GetUTXO(in.PreviousOutPoint)
		if utxo == nil {
			continue
		}

		// Check if this is a P2SH output
		if script.IsP2SH(utxo.PkScript) {
			// Count sigops in the redeem script (P2SH sigops are scaled)
			sigOps := CountScriptSigOps(in.SignatureScript)
			totalSigOps += sigOps * WitnessScaleFactor
		}
	}

	return totalSigOps
}

// CountWitnessSigOps counts sigops in witness scripts.
// Witness sigops are NOT scaled by WitnessScaleFactor (they count as 1 each).
func CountWitnessSigOps(tx *wire.MsgTx, utxoView UTXOView) int {
	if IsCoinbaseTx(tx) {
		return 0
	}

	totalSigOps := 0

	for i, in := range tx.TxIn {
		utxo := utxoView.GetUTXO(in.PreviousOutPoint)
		if utxo == nil {
			continue
		}

		pkScript := utxo.PkScript

		// Check if spending from P2SH-wrapped witness
		if script.IsP2SH(pkScript) && len(in.SignatureScript) > 0 {
			// Extract the redeem script (last push in scriptSig)
			redeemScript := extractLastPush(in.SignatureScript)
			if redeemScript != nil {
				pkScript = redeemScript
			}
		}

		// Extract witness program
		witnessVersion, witnessProgram := script.ExtractWitnessProgram(pkScript)
		if witnessVersion < 0 || len(in.Witness) == 0 {
			continue
		}

		sigOps := countWitnessSigOpsForInput(witnessVersion, witnessProgram, in.Witness, i)
		totalSigOps += sigOps
	}

	return totalSigOps
}

// countWitnessSigOpsForInput counts sigops for a single witness input,
// for the purpose of the block-level MaxBlockSigOpsCost (80,000) budget.
//
// This MUST mirror Bitcoin Core's WitnessSigOps (interpreter.cpp:2123-2137):
// only segwit v0 contributes to the block sigop budget. Taproot (v1) and
// any future witness version return 0 here. Per BIP-342, Taproot enforces
// its own per-input validation-weight budget
// (VALIDATION_WEIGHT_PER_SIGOP_PASSED), which is checked inside the script
// interpreter — NOT against MaxBlockSigOpsCost. Counting tapscript
// CHECKSIG/CHECKSIGADD ops toward the block budget would reject blocks
// that Core accepts (e.g. ordinals/inscription blocks with high-opcount
// tapscripts).
//
// CountTaprootSigOps is preserved for callers that need a tapscript-only
// estimate (e.g. mempool policy heuristics), but it must NOT be summed
// into CountBlockSigOpsCost.
func countWitnessSigOpsForInput(version int, program []byte, witness [][]byte, inputIdx int) int {
	if version == 0 {
		// Segwit v0
		if len(program) == 20 {
			// P2WPKH: exactly 1 signature operation
			return 1
		}
		if len(program) == 32 {
			// P2WSH: count sigops in the witness script (last witness item)
			if len(witness) == 0 {
				return 0
			}
			witnessScript := witness[len(witness)-1]
			return CountWitnessSigOpsV0(witnessScript)
		}
	}

	// Future flags may be implemented here. Taproot (v1) and beyond
	// contribute 0 to the block sigop budget. (Core: interpreter.cpp:2135-2136.)
	return 0
}

// CountWitnessSigOpsV0 counts sigops in a segwit v0 witness script.
// For segwit v0, OP_CHECKSIG counts as 1, and OP_CHECKMULTISIG counts as n (key count).
func CountWitnessSigOpsV0(witnessScript []byte) int {
	sigOps := 0
	pc := 0
	lastOp := byte(script.OP_INVALIDOPCODE)

	for pc < len(witnessScript) {
		op := witnessScript[pc]
		pc++

		// Handle push operations
		if op >= 0x01 && op <= 0x4b {
			pc += int(op)
			lastOp = op
			continue
		}

		switch op {
		case script.OP_PUSHDATA1:
			if pc >= len(witnessScript) {
				return sigOps
			}
			dataLen := int(witnessScript[pc])
			pc += 1 + dataLen
		case script.OP_PUSHDATA2:
			if pc+2 > len(witnessScript) {
				return sigOps
			}
			dataLen := int(witnessScript[pc]) | int(witnessScript[pc+1])<<8
			pc += 2 + dataLen
		case script.OP_PUSHDATA4:
			if pc+4 > len(witnessScript) {
				return sigOps
			}
			dataLen := int(witnessScript[pc]) | int(witnessScript[pc+1])<<8 |
				int(witnessScript[pc+2])<<16 | int(witnessScript[pc+3])<<24
			pc += 4 + dataLen
		case script.OP_CHECKSIG, script.OP_CHECKSIGVERIFY:
			sigOps++
		case script.OP_CHECKMULTISIG, script.OP_CHECKMULTISIGVERIFY:
			// For segwit, use actual key count if available
			if lastOp >= script.OP_1 && lastOp <= script.OP_16 {
				sigOps += int(lastOp - script.OP_1 + 1)
			} else {
				sigOps += MaxPubKeysPerMultisig
			}
		}
		lastOp = op
	}

	return sigOps
}

// CountTaprootSigOps counts sigops in a tapscript.
// For taproot, only OP_CHECKSIG, OP_CHECKSIGVERIFY, and OP_CHECKSIGADD count,
// each counting as 1 sigop. OP_CHECKMULTISIG is not available in tapscript.
func CountTaprootSigOps(tapscript []byte) int {
	sigOps := 0
	pc := 0

	for pc < len(tapscript) {
		op := tapscript[pc]
		pc++

		// Handle push operations
		if op >= 0x01 && op <= 0x4b {
			pc += int(op)
			continue
		}

		switch op {
		case script.OP_PUSHDATA1:
			if pc >= len(tapscript) {
				return sigOps
			}
			dataLen := int(tapscript[pc])
			pc += 1 + dataLen
		case script.OP_PUSHDATA2:
			if pc+2 > len(tapscript) {
				return sigOps
			}
			dataLen := int(tapscript[pc]) | int(tapscript[pc+1])<<8
			pc += 2 + dataLen
		case script.OP_PUSHDATA4:
			if pc+4 > len(tapscript) {
				return sigOps
			}
			dataLen := int(tapscript[pc]) | int(tapscript[pc+1])<<8 |
				int(tapscript[pc+2])<<16 | int(tapscript[pc+3])<<24
			pc += 4 + dataLen
		case script.OP_CHECKSIG, script.OP_CHECKSIGVERIFY, script.OP_CHECKSIGADD:
			sigOps++
		}
	}

	return sigOps
}

// CountBlockSigOpsCost counts the total signature operation cost for a block.
// This includes:
// - Legacy sigops in scriptSig (vin) + scriptPubKey (vout), scaled by WitnessScaleFactor.
//   Uses INACCURATE counting (CHECKMULTISIG=20 always), matching Core's
//   GetLegacySigOpCount which calls GetSigOpCount(fAccurate=false).
// - P2SH sigops in redeem scripts (accurate, already scaled by CountP2SHSigOps)
// - Witness sigops (accurate, not scaled)
func CountBlockSigOpsCost(block *wire.MsgBlock, utxoView UTXOView) int {
	totalCost := 0

	for _, tx := range block.Transactions {
		// Legacy sigops: INACCURATE counting (CHECKMULTISIG = 20), scaled ×4.
		// Core: GetLegacySigOpCount calls GetSigOpCount(fAccurate=false).
		for _, in := range tx.TxIn {
			totalCost += CountSigOpsInaccurate(in.SignatureScript) * WitnessScaleFactor
		}
		for _, out := range tx.TxOut {
			totalCost += CountSigOpsInaccurate(out.PkScript) * WitnessScaleFactor
		}

		// P2SH sigops (accurate, already scaled in CountP2SHSigOps)
		totalCost += CountP2SHSigOps(tx, utxoView)

		// Witness sigops (accurate, not scaled)
		totalCost += CountWitnessSigOps(tx, utxoView)
	}

	return totalCost
}
