// Package mempool — witness standardness policy.
//
// isWitnessStandard mirrors Bitcoin Core's IsWitnessStandard
// (policy/policy.cpp:265-352). It is called for every mempool-bound
// transaction that carries witness data, after IsStandardTx gates have
// already run (scriptSig push-only, size caps, etc.).
//
// Gates (numbered as in Core):
//
//  1. P2A input with any witness               → "bad-witness-nonstandard"
//  2. P2SH-wrapped: EvalScript scriptSig → top = redeemScript
//     fail/empty                               → "bad-witness-nonstandard"
//  3. Non-witness prevScript + non-empty witness → "bad-witness-nonstandard"
//  4. P2WSH v0 32B:
//       witness[-1] (redeemScript) size > 3600 → reject
//       stack depth (minus script) > 100        → reject
//       each stack item > 80 bytes              → reject
//  5. P2TR v1 32B (not P2SH-wrapped):
//       annex (0x50 tag) present                → reject
//       script-path (≥2 items), leaf ver 0xc0  → each item ≤ 80 bytes
//       empty stack (0 items)                   → reject
//  6. Coinbase inputs are skipped (handled by caller: coinbase txs never
//     reach the mempool).
package mempool

import (
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Witness policy constants (mirrors policy/policy.h and interpreter.h).
const (
	// MaxStandardP2WSHScriptSize is the maximum byte size of the witness
	// script in a P2WSH input. Mirrors Core's MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600.
	MaxStandardP2WSHScriptSize = 3600

	// MaxStandardP2WSHStackItems is the maximum number of stack items
	// (excluding the witness script itself) for a P2WSH input.
	// Mirrors Core's MAX_STANDARD_P2WSH_STACK_ITEMS = 100.
	MaxStandardP2WSHStackItems = 100

	// MaxStandardP2WSHStackItemSize is the maximum byte size of any single
	// stack item (excluding the witness script) in a P2WSH input.
	// Mirrors Core's MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80.
	MaxStandardP2WSHStackItemSize = 80

	// MaxStandardTapscriptStackItemSize is the maximum byte size of any
	// single stack item in a tapscript (BIP-342) execution context.
	// Mirrors Core's MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80.
	MaxStandardTapscriptStackItemSize = 80

	// annexTag is the first byte of a taproot annex (BIP-341 §Spending).
	// Mirrors interpreter.h ANNEX_TAG = 0x50.
	annexTag = 0x50

	// taprootLeafMask masks the leaf version field in the control block.
	// Mirrors interpreter.h TAPROOT_LEAF_MASK = 0xfe.
	taprootLeafMask = 0xfe

	// taprootLeafTapscript is the leaf version for BIP-342 tapscript.
	// Mirrors interpreter.h TAPROOT_LEAF_TAPSCRIPT = 0xc0.
	taprootLeafTapscript = 0xc0
)

// isWitnessStandard checks whether every witness in tx satisfies the
// non-standard-witness policy rules described above. It is safe to call
// for coinbase transactions (they are skipped), but in practice the mempool
// never accepts coinbase txs.
//
// lookupUTXO must return the spending output for the given outpoint; it
// returns nil for missing inputs (which isWitnessStandard treats as skipped,
// because CheckInputs will catch them earlier).
func isWitnessStandard(tx *wire.MsgTx, lookupUTXO func(wire.OutPoint) *consensus.UTXOEntry) error {
	// Gate 6: Coinbase inputs are skipped (policy/policy.cpp:267-268).
	// In practice the mempool rejects coinbase at an earlier gate; this guard
	// makes the function safe to call in any context.
	if consensus.IsCoinbaseTx(tx) {
		return nil
	}

	for _, in := range tx.TxIn {
		// Skip inputs with no witness — they cannot violate witness policy.
		// (Core: "We don't care if witness for this input is empty"; line 274.)
		if len(in.Witness) == 0 {
			continue
		}

		entry := lookupUTXO(in.PreviousOutPoint)
		if entry == nil {
			// Missing input — will be caught by CheckInputs; skip here.
			continue
		}

		prevScript := entry.PkScript

		// Gate 1: P2A (Pay-to-Anchor) with any witness is non-standard.
		// Core: policy.cpp:283-285.
		if script.IsPayToAnchor(prevScript) {
			return ErrWitnessStuffing
		}

		// Gate 2: P2SH-wrapped — evaluate the scriptSig (push-only) to
		// extract the redeemScript from the top of the stack, then use
		// that as prevScript for the remaining checks.
		// Core: policy.cpp:288-298 (EvalScript with SCRIPT_VERIFY_NONE).
		p2sh := false
		if script.IsP2SH(prevScript) {
			// EvalScript(NONE) on a push-only scriptSig: parse pushes and
			// collect items, take the top.
			stack, ok := evalPushScriptToStack(in.SignatureScript)
			if !ok || len(stack) == 0 {
				// Evaluation failed or produced an empty stack: reject.
				return ErrWitnessNonstandardP2SHRedeem
			}
			// redeemScript = top of stack.
			prevScript = stack[len(stack)-1]
			p2sh = true
		}

		// Gate 3: Non-witness prevScript + non-empty witness → reject.
		// Core: policy.cpp:305-306 ("Non-witness program must not be
		// associated with any witness").
		witnessVersion, witnessProgram := script.ExtractWitnessProgram(prevScript)
		if witnessVersion < 0 {
			// prevScript is not a witness program, but this input has a
			// non-empty witness (checked at loop top). Reject.
			return ErrWitnessNonstandardNonWitness
		}

		// Gate 4: P2WSH v0 with 32-byte program.
		// Core: policy.cpp:309-318.
		if witnessVersion == 0 && len(witnessProgram) == 32 {
			witnessScript := in.Witness[len(in.Witness)-1]
			if len(witnessScript) > MaxStandardP2WSHScriptSize {
				return ErrWitnessNonstandardP2WSHScriptSize
			}
			stackDepth := len(in.Witness) - 1 // exclude witness script
			if stackDepth > MaxStandardP2WSHStackItems {
				return ErrWitnessNonstandardP2WSHStackDepth
			}
			for j := 0; j < stackDepth; j++ {
				if len(in.Witness[j]) > MaxStandardP2WSHStackItemSize {
					return ErrWitnessNonstandardP2WSHStackItemSize
				}
			}
		}

		// Gate 5: P2TR v1 with 32-byte program, not P2SH-wrapped.
		// Core: policy.cpp:324-349.
		if witnessVersion == 1 && len(witnessProgram) == 32 && !p2sh {
			stack := in.Witness // local alias for clarity

			// Annex detection: if there are ≥2 items and the last is non-empty
			// and starts with ANNEX_TAG (0x50), reject.
			// Core: policy.cpp:327-329.
			if len(stack) >= 2 && len(stack[len(stack)-1]) > 0 &&
				stack[len(stack)-1][0] == annexTag {
				return ErrWitnessNonstandardTaprootAnnex
			}

			if len(stack) >= 2 {
				// Script-path spend: 2+ items (after optional annex removal).
				// Core: policy.cpp:331-341.
				// Stack layout (without annex): [...args, script, control_block]
				controlBlock := stack[len(stack)-1]
				if len(controlBlock) == 0 {
					return ErrWitnessNonstandardTaprootEmptyControl
				}
				// Check leaf version.
				if (controlBlock[0] & taprootLeafMask) == taprootLeafTapscript {
					// BIP-342 tapscript: enforce MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE
					// on every stack element except the script and control block.
					// Core: policy.cpp:338-340.
					argDepth := len(stack) - 2 // exclude script + control block
					for j := 0; j < argDepth; j++ {
						if len(stack[j]) > MaxStandardTapscriptStackItemSize {
							return ErrWitnessNonstandardTapscriptStackItemSize
						}
					}
				}
			} else if len(stack) == 0 {
				// Empty stack: already invalid by consensus (BIP-341 requires
				// at least one element for a v1 spend). Reject as non-standard
				// so the tx is filtered before script validation.
				// Core: policy.cpp:346-347.
				return ErrWitnessNonstandardTaprootEmptyStack
			}
			// len(stack) == 1: key-path spend — no additional policy rules.
			// Core: policy.cpp:342-344.
		}
	}

	return nil
}

// evalPushScriptToStack executes a push-only script with no verification
// flags, collecting all pushed items onto a slice. This mirrors Bitcoin
// Core's EvalScript(stack, scriptSig, SCRIPT_VERIFY_NONE, ...) used in
// IsWitnessStandard for P2SH redeemScript extraction.
//
// Returns (items, true) on success, (nil, false) on any parse error.
// Items are in bottom-to-top order (items[len-1] = top of stack).
func evalPushScriptToStack(scriptSig []byte) ([][]byte, bool) {
	var stack [][]byte
	pc := 0
	for pc < len(scriptSig) {
		op := scriptSig[pc]
		pc++

		switch {
		case op == 0x00: // OP_0 / OP_FALSE
			stack = append(stack, []byte{})

		case op >= 0x01 && op <= 0x4b: // direct push N bytes
			n := int(op)
			if pc+n > len(scriptSig) {
				return nil, false
			}
			item := make([]byte, n)
			copy(item, scriptSig[pc:pc+n])
			stack = append(stack, item)
			pc += n

		case op == 0x4c: // OP_PUSHDATA1
			if pc >= len(scriptSig) {
				return nil, false
			}
			n := int(scriptSig[pc])
			pc++
			if pc+n > len(scriptSig) {
				return nil, false
			}
			item := make([]byte, n)
			copy(item, scriptSig[pc:pc+n])
			stack = append(stack, item)
			pc += n

		case op == 0x4d: // OP_PUSHDATA2
			if pc+2 > len(scriptSig) {
				return nil, false
			}
			n := int(scriptSig[pc]) | int(scriptSig[pc+1])<<8
			pc += 2
			if pc+n > len(scriptSig) {
				return nil, false
			}
			item := make([]byte, n)
			copy(item, scriptSig[pc:pc+n])
			stack = append(stack, item)
			pc += n

		case op == 0x4e: // OP_PUSHDATA4
			if pc+4 > len(scriptSig) {
				return nil, false
			}
			n := int(scriptSig[pc]) | int(scriptSig[pc+1])<<8 |
				int(scriptSig[pc+2])<<16 | int(scriptSig[pc+3])<<24
			pc += 4
			if pc+n > len(scriptSig) {
				return nil, false
			}
			item := make([]byte, n)
			copy(item, scriptSig[pc:pc+n])
			stack = append(stack, item)
			pc += n

		case op == 0x4f: // OP_1NEGATE
			stack = append(stack, []byte{0x81})

		case op >= 0x51 && op <= 0x60: // OP_1 .. OP_16
			stack = append(stack, []byte{op - 0x50})

		default:
			// Non-push opcode: evaluation fails under SCRIPT_VERIFY_NONE
			// for a scriptSig that is not push-only. Core's EvalScript with
			// SCRIPT_VERIFY_NONE executes non-push opcodes, but for witness
			// standard checking we rely on the scriptSig already having
			// passed the push-only gate (IsStandardTx gate 5a). Any
			// remaining non-push op is treated as a parse failure here.
			return nil, false
		}
	}
	return stack, true
}
