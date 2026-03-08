package consensus

import (
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// CountSigOps counts the signature operations in a script.
// This counts OP_CHECKSIG/OP_CHECKSIGVERIFY as 1 each,
// and OP_CHECKMULTISIG/OP_CHECKMULTISIGVERIFY as 20 (max possible keys).
func CountSigOps(scriptBytes []byte) int {
	sigOps := 0
	pc := 0
	lastOp := byte(script.OP_INVALIDOPCODE)

	for pc < len(scriptBytes) {
		op := scriptBytes[pc]
		pc++

		// Handle push operations - skip the data
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
			// If the last opcode was a small integer (OP_1 to OP_16),
			// use that as the key count. Otherwise, assume worst case (20).
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

// CountScriptSigOps counts sigops in a scriptSig for P2SH transactions.
// For P2SH, we need to count sigops in the redeem script (last push in scriptSig).
func CountScriptSigOps(scriptSig []byte) int {
	// Find the last push data in the script
	lastPush := extractLastPush(scriptSig)
	if lastPush == nil {
		return 0
	}

	// Count sigops in the redeem script
	return CountSigOps(lastPush)
}

// extractLastPush extracts the last push data from a script.
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
		}

		if pushData != nil {
			lastPush = pushData
		}
	}

	return lastPush
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

// countWitnessSigOpsForInput counts sigops for a single witness input.
func countWitnessSigOpsForInput(version int, program []byte, witness [][]byte, inputIdx int) int {
	switch version {
	case 0:
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
	case 1:
		// Taproot (v1)
		if len(program) != 32 {
			return 0
		}
		if len(witness) == 0 {
			return 0
		}

		// Check for annex (starts with 0x50)
		stack := witness
		if len(stack) >= 2 && len(stack[len(stack)-1]) > 0 && stack[len(stack)-1][0] == 0x50 {
			stack = stack[:len(stack)-1]
		}

		if len(stack) == 1 {
			// Key path: 1 sigop
			return 1
		}
		// Script path: count OP_CHECKSIG/OP_CHECKSIGVERIFY in the tapscript
		if len(stack) >= 2 {
			tapscript := stack[len(stack)-2]
			return CountTaprootSigOps(tapscript)
		}
	}

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
// - Base sigops in scriptPubKey (scaled by WitnessScaleFactor)
// - P2SH sigops in redeem scripts (scaled by WitnessScaleFactor)
// - Witness sigops (not scaled)
func CountBlockSigOpsCost(block *wire.MsgBlock, utxoView UTXOView) int {
	totalCost := 0

	for _, tx := range block.Transactions {
		// Base sigops from outputs (scaled)
		for _, out := range tx.TxOut {
			totalCost += CountSigOps(out.PkScript) * WitnessScaleFactor
		}

		// P2SH sigops (already scaled in CountP2SHSigOps)
		totalCost += CountP2SHSigOps(tx, utxoView)

		// Witness sigops (not scaled)
		totalCost += CountWitnessSigOps(tx, utxoView)
	}

	return totalCost
}
