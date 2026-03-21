package script

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Script validation errors
var (
	ErrScriptTooLong        = errors.New("script too long")
	ErrScriptNotClean       = errors.New("stack not clean after execution")
	ErrScriptFailed         = errors.New("script evaluation failed")
	ErrInvalidIndex         = errors.New("invalid input index")
	ErrDisabledOpcode       = errors.New("disabled opcode")
	ErrInvalidOpcode        = errors.New("invalid opcode")
	ErrOpCount              = errors.New("too many operations")
	ErrPushSize             = errors.New("push data too large")
	ErrUnbalancedConditional = errors.New("unbalanced conditional")
	ErrVerifyFailed         = errors.New("verify operation failed")
	ErrOpReturn             = errors.New("OP_RETURN executed")
	ErrEqualVerify          = errors.New("OP_EQUALVERIFY failed")
	ErrCheckSigFailed       = errors.New("signature verification failed")
	ErrCheckMultiSigFailed  = errors.New("multisig verification failed")
	ErrNullDummy            = errors.New("multisig dummy must be empty")
	ErrInvalidPubKeyCount   = errors.New("invalid public key count")
	ErrInvalidSigCount      = errors.New("invalid signature count")
	ErrWitnessProgram       = errors.New("invalid witness program")
	ErrWitnessMismatch      = errors.New("witness data mismatch")
	ErrWitnessMalleated     = errors.New("witness malleated")
	ErrTaprootSigVerify         = errors.New("taproot signature verification failed")
	ErrMinimalData              = errors.New("non-minimal data push")
	ErrCLTVFailed               = errors.New("OP_CHECKLOCKTIMEVERIFY failed")
	ErrCSVFailed                = errors.New("OP_CHECKSEQUENCEVERIFY failed")
	ErrTapscriptCheckMultiSig   = errors.New("OP_CHECKMULTISIG(VERIFY) not allowed in tapscript")
	ErrTaprootControlBlockSize  = errors.New("taproot control block wrong size")
	ErrNullFail                 = errors.New("non-empty signature on failed CHECKSIG when NULLFAIL is active")
	ErrSigPushOnly              = errors.New("scriptSig contains non-push opcode")
	ErrWitnessUnexpected        = errors.New("unexpected witness data for non-witness script")
	ErrSigDER                   = errors.New("signature is not valid DER encoding")
	ErrSigHighS                 = errors.New("signature S value is not low")
	ErrSigHashType              = errors.New("signature has undefined hashtype")
	ErrPubKeyType               = errors.New("public key is not compressed or uncompressed")
	ErrWitnessPubKeyType        = errors.New("witness v0 requires compressed public key")
	ErrEvalFalse                = errors.New("script evaluated to false")
	ErrCleanStack               = errors.New("stack not clean after witness script execution")
)

// ScriptFlags control which script validation rules are enabled.
type ScriptFlags uint32

const (
	ScriptVerifyNone           ScriptFlags = 0
	ScriptVerifyP2SH           ScriptFlags = 1 << 0  // BIP16
	ScriptVerifyWitness        ScriptFlags = 1 << 1  // BIP141
	ScriptVerifyCleanStack     ScriptFlags = 1 << 2  // Require clean stack after execution
	ScriptVerifyDERSig         ScriptFlags = 1 << 3  // BIP66 - strict DER signatures
	ScriptVerifyLowS           ScriptFlags = 1 << 4  // BIP62 rule 5 - low S values
	ScriptVerifyMinimalData    ScriptFlags = 1 << 5  // Minimal push encodings
	ScriptVerifyNullDummy      ScriptFlags = 1 << 6  // BIP147 - null dummy for CHECKMULTISIG
	ScriptVerifyStrictEncoding ScriptFlags = 1 << 7  // Strict signature/pubkey encoding
	ScriptVerifyTaproot        ScriptFlags = 1 << 8  // BIP341/342
	ScriptVerifyCLTV              ScriptFlags = 1 << 9  // BIP65 - CHECKLOCKTIMEVERIFY
	ScriptVerifyCSV               ScriptFlags = 1 << 10 // BIP112 - CHECKSEQUENCEVERIFY
	ScriptVerifyNullFail          ScriptFlags = 1 << 11 // BIP146 - NULLFAIL
	ScriptVerifySigPushOnly       ScriptFlags = 1 << 12 // Require scriptSig is push-only
	ScriptVerifyWitnessPubKeyType ScriptFlags = 1 << 13 // BIP141 - compressed keys in witness v0
	ScriptVerifyDiscourageUpgradableNops ScriptFlags = 1 << 14 // Discourage upgradable NOPs
	ScriptVerifyConstScriptCode          ScriptFlags = 1 << 15 // OP_CODESEPARATOR forbidden in witness v0
	ScriptVerifyDiscourageOpSuccess                ScriptFlags = 1 << 16 // Discourage OP_SUCCESSx in tapscript
	ScriptVerifyDiscourageUpgradableWitnessProgram ScriptFlags = 1 << 17 // Discourage unknown witness versions
	ScriptVerifyMinimalIf                          ScriptFlags = 1 << 18 // Require minimal IF/NOTIF arguments
)

// SigVersion indicates the signature validation rules to use.
type SigVersion int

const (
	SigVersionBase       SigVersion = 0 // Pre-segwit
	SigVersionWitnessV0  SigVersion = 1 // Segwit v0
	SigVersionTaproot    SigVersion = 2 // Taproot key path
	SigVersionTapscript  SigVersion = 3 // Tapscript
)

// Engine executes Bitcoin scripts.
type Engine struct {
	tx          *wire.MsgTx   // Transaction being validated
	txIdx       int           // Input index being validated
	flags       ScriptFlags
	stack       *Stack
	altStack    *Stack
	condStack   []bool        // For nested IF/ELSE/ENDIF
	amount      int64         // Value of the output being spent (for segwit sighash)
	prevOuts    []*wire.TxOut // Previous outputs (for taproot sighash)
	sigVersion  SigVersion
	opCount     int           // Number of operations executed
	codesepPos  uint32        // Position of last OP_CODESEPARATOR (for tapscript)
	sigopBudget int           // Tapscript signature validation weight budget

	// For legacy sighash: track the script and the byte offset after last OP_CODESEPARATOR
	currentScript    []byte // The script currently being executed
	lastCodeSepIdx   int    // Byte index after last OP_CODESEPARATOR (-1 = use entire script)
}

// NewEngine creates a script execution engine.
func NewEngine(scriptPubKey []byte, tx *wire.MsgTx, txIdx int, flags ScriptFlags, amount int64, prevOuts []*wire.TxOut) (*Engine, error) {
	if txIdx < 0 || txIdx >= len(tx.TxIn) {
		return nil, ErrInvalidIndex
	}

	return &Engine{
		tx:             tx,
		txIdx:          txIdx,
		flags:          flags,
		stack:          NewStack(),
		altStack:       NewStack(),
		condStack:      make([]bool, 0),
		amount:         amount,
		prevOuts:       prevOuts,
		sigVersion:     SigVersionBase,
		codesepPos:     0xFFFFFFFF, // Initialize to 0xFFFFFFFF per Bitcoin Core
		lastCodeSepIdx: 0,          // Start at beginning of script
	}, nil
}

// Execute runs the script engine and returns nil if the script is valid.
func (e *Engine) Execute() error {
	txIn := e.tx.TxIn[e.txIdx]
	scriptSig := txIn.SignatureScript

	var scriptPubKey []byte
	if e.prevOuts != nil && e.txIdx < len(e.prevOuts) {
		scriptPubKey = e.prevOuts[e.txIdx].PkScript
	}

	// Check script sizes
	if len(scriptSig) > MaxScriptSize {
		return ErrScriptTooLong
	}
	if len(scriptPubKey) > MaxScriptSize {
		return ErrScriptTooLong
	}

	// Detect witness program
	witnessVersion, witnessProgram := ExtractWitnessProgram(scriptPubKey)
	hasWitness := witnessVersion >= 0
	hadWitness := false // tracks whether any witness program was executed

	// For native segwit, scriptSig must be empty
	if hasWitness && (e.flags&ScriptVerifyWitness != 0) && len(scriptSig) > 0 {
		return ErrWitnessMalleated
	}

	// SIGPUSHONLY: scriptSig must contain only push operations
	if (e.flags&ScriptVerifySigPushOnly != 0) && !IsPushOnly(scriptSig) {
		return ErrSigPushOnly
	}

	// P2SH requires scriptSig to be push-only (BIP16 consensus rule)
	if (e.flags&ScriptVerifyP2SH != 0) && IsP2SH(scriptPubKey) && !IsPushOnly(scriptSig) {
		return ErrSigPushOnly
	}

	// Execute scriptSig (for non-segwit or P2SH-wrapped segwit)
	if len(scriptSig) > 0 {
		e.sigVersion = SigVersionBase
		if err := e.executeScript(scriptSig); err != nil {
			return err
		}
	}

	// Save the stack state for P2SH
	savedStack := e.stack.Copy()

	// Clear altstack between scriptSig and scriptPubKey execution.
	// Bitcoin Core does this implicitly by creating separate execution contexts.
	e.altStack = NewStack()

	// Reset condition stack between scriptSig and scriptPubKey
	e.condStack = e.condStack[:0]

	// Execute scriptPubKey
	e.sigVersion = SigVersionBase
	e.opCount = 0 // Reset op count for scriptPubKey
	if err := e.executeScript(scriptPubKey); err != nil {
		return err
	}

	// Check if script succeeded (top of stack is truthy)
	if e.stack.IsEmpty() {
		return ErrScriptFailed
	}
	result, _ := e.stack.Pop()
	if !CastToBool(result) {
		return ErrScriptFailed
	}

	// Handle P2SH
	if (e.flags&ScriptVerifyP2SH != 0) && IsP2SH(scriptPubKey) {
		// The serialized script is at the top of the saved stack
		if savedStack.IsEmpty() {
			return ErrScriptFailed
		}
		serializedScript, _ := savedStack.Pop()

		// Check if it's a P2SH-wrapped witness program
		witnessVersion, witnessProgram := ExtractWitnessProgram(serializedScript)

		if witnessVersion >= 0 && (e.flags&ScriptVerifyWitness != 0) {
			// P2SH-wrapped segwit
			hadWitness = true
			// Fix #7: P2SH-wrapped witness v1+ is not executed (BIP341).
			if witnessVersion >= 1 {
				return nil
			}
			if err := e.executeWitnessProgram(witnessVersion, witnessProgram, txIn.Witness); err != nil {
				return err
			}
		} else {
			// Regular P2SH
			e.stack = savedStack
			e.opCount = 0
			if err := e.executeScript(serializedScript); err != nil {
				return err
			}

			// Check result
			if e.stack.IsEmpty() {
				return ErrScriptFailed
			}
			result, _ := e.stack.Pop()
			if !CastToBool(result) {
				return ErrScriptFailed
			}
		}
	}

	// Handle native witness program
	if hasWitness && (e.flags&ScriptVerifyWitness != 0) {
		hadWitness = true
		if err := e.executeWitnessProgram(witnessVersion, witnessProgram, txIn.Witness); err != nil {
			return err
		}
	}

	// Clean stack check
	if (e.flags & ScriptVerifyCleanStack) != 0 {
		if e.stack.Size() != 0 {
			return ErrScriptNotClean
		}
	}

	// WITNESS_UNEXPECTED: if no witness program was found but the input has
	// non-empty witness data, the script must fail.
	if (e.flags&ScriptVerifyWitness != 0) && !hadWitness && len(txIn.Witness) > 0 {
		return ErrWitnessUnexpected
	}

	return nil
}

// executeWitnessProgram executes a witness program.
func (e *Engine) executeWitnessProgram(version int, program []byte, witness [][]byte) error {
	switch version {
	case 0:
		// Segwit v0: reverse witness stack for execution (wire order is bottom-to-top)
		reversedWitness := make([][]byte, len(witness))
		for i, w := range witness {
			reversedWitness[len(witness)-1-i] = w
		}
		return e.executeWitnessV0(program, reversedWitness)
	case 1:
		// P2A (Pay-to-Anchor) is witness v1 with a 2-byte program (0x4e73).
		// It's anyone-can-spend and requires an empty witness.
		if IsPayToAnchorWitnessProgram(version, program) {
			// P2A is always anyone-can-spend, no verification needed
			return nil
		}
		// Taproot (v1) with 32-byte program
		if len(program) == 32 && e.flags&ScriptVerifyTaproot != 0 {
			// Taproot uses witness in wire order (not reversed); the control block
			// and script are the last elements, and executeTaproot indexes from the end.
			return e.executeTaproot(program, witness)
		}
		// Non-taproot v1 (or taproot not enabled): future anyone-can-spend
		if e.flags&ScriptVerifyDiscourageUpgradableWitnessProgram != 0 {
			return ErrWitnessProgram
		}
		return nil
	default:
		// Future witness versions are anyone-can-spend (for forward compatibility)
		if e.flags&ScriptVerifyWitness != 0 && version > 16 {
			return ErrWitnessProgram
		}
		if e.flags&ScriptVerifyDiscourageUpgradableWitnessProgram != 0 {
			return ErrWitnessProgram
		}
		return nil
	}
}

// verifyWitnessCleanStack checks the cleanstack condition for witness scripts.
// After witness script execution, the stack must have exactly one element,
// and that element must be true. This is BIP141 consensus, not gated by flags.
func (e *Engine) verifyWitnessCleanStack() error {
	if e.stack.Size() == 0 {
		return ErrEvalFalse
	}
	if e.stack.Size() != 1 {
		return ErrCleanStack
	}
	result, _ := e.stack.Peek()
	if !CastToBool(result) {
		return ErrEvalFalse
	}
	return nil
}

// executeWitnessV0 executes a segwit v0 program.
func (e *Engine) executeWitnessV0(program []byte, witness [][]byte) error {
	e.sigVersion = SigVersionWitnessV0

	if len(program) == 20 {
		// P2WPKH
		if len(witness) != 2 {
			return ErrWitnessMismatch
		}
		// Construct equivalent P2PKH script: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
		script := make([]byte, 25)
		script[0] = OP_DUP
		script[1] = OP_HASH160
		script[2] = 20
		copy(script[3:23], program)
		script[23] = OP_EQUALVERIFY
		script[24] = OP_CHECKSIG

		// Set up stack with witness items (reversed back to normal order)
		e.stack = NewStack()
		for i := len(witness) - 1; i >= 0; i-- {
			e.stack.Push(witness[i])
		}

		e.opCount = 0
		if err := e.executeScript(script); err != nil {
			return err
		}
		// BIP141: witness scripts implicitly require cleanstack
		return e.verifyWitnessCleanStack()
	}

	if len(program) == 32 {
		// P2WSH
		if len(witness) == 0 {
			return ErrWitnessMismatch
		}
		// After reversal in executeWitnessProgram, the witness script is at index 0
		// (it was originally the last/top item in wire format)
		witnessScript := witness[0]

		// Verify SHA256 of witness script matches program
		hash := crypto.SHA256Hash(witnessScript)
		if !bytes.Equal(hash[:], program) {
			return ErrWitnessMismatch
		}

		// Set up stack with remaining witness items (indices 1 through len-1)
		// Push from the end going backwards to maintain correct stack order
		e.stack = NewStack()
		for i := len(witness) - 1; i >= 1; i-- {
			e.stack.Push(witness[i])
		}

		e.opCount = 0
		if err := e.executeScript(witnessScript); err != nil {
			return err
		}
		// BIP141: witness scripts implicitly require cleanstack
		return e.verifyWitnessCleanStack()
	}

	return ErrWitnessProgram
}

// executeTaproot executes a taproot (segwit v1) program.
func (e *Engine) executeTaproot(program []byte, witness [][]byte) error {
	if len(program) != 32 {
		return ErrWitnessProgram
	}

	if len(witness) == 0 {
		return ErrWitnessMismatch
	}

	// Check for annex (starts with 0x50)
	var annex []byte
	if len(witness) >= 2 && len(witness[len(witness)-1]) > 0 && witness[len(witness)-1][0] == 0x50 {
		annex = witness[len(witness)-1]
		witness = witness[:len(witness)-1]
	}

	if len(witness) == 1 {
		// Key path spending
		return e.executeTaprootKeyPath(program, witness[0], annex)
	}

	// Script path spending
	return e.executeTaprootScriptPath(program, witness, annex)
}

// executeTaprootKeyPath verifies a taproot key path spend.
func (e *Engine) executeTaprootKeyPath(pubKey []byte, sig []byte, annex []byte) error {
	e.sigVersion = SigVersionTaproot

	// Parse signature and hash type
	var hashType SigHashType
	var signature []byte

	if len(sig) == 64 {
		hashType = SigHashDefault
		signature = sig
	} else if len(sig) == 65 {
		hashType = SigHashType(sig[64])
		signature = sig[:64]
		// Validate hash type
		if hashType == SigHashDefault {
			return ErrTaprootSigVerify // 0x00 not allowed with 65 bytes
		}
	} else {
		return ErrTaprootSigVerify
	}

	// Compute sighash
	opts := &TaprootSigHashOptions{
		CodeSepPos: e.codesepPos,
	}
	if annex != nil {
		// Bitcoin Core serializes the annex with its compact-size length prefix before hashing
		var annexBuf bytes.Buffer
		wire.WriteVarBytes(&annexBuf, annex)
		annexHash := crypto.SHA256Hash(annexBuf.Bytes())
		opts.AnnexHash = &annexHash
	}

	sighash, err := CalcTaprootSignatureHash(hashType, e.tx, e.txIdx, e.prevOuts, opts)
	if err != nil {
		return err
	}

	// Verify Schnorr signature
	if !crypto.VerifySchnorr(pubKey, sighash, signature) {
		return ErrTaprootSigVerify
	}

	return nil
}

// executeTaprootScriptPath executes a taproot script path spend.
func (e *Engine) executeTaprootScriptPath(outputKey []byte, witness [][]byte, annex []byte) error {
	e.sigVersion = SigVersionTapscript

	// witness = [stack items..., script, control block]
	if len(witness) < 2 {
		return ErrWitnessMismatch
	}

	controlBlock := witness[len(witness)-1]
	script := witness[len(witness)-2]
	stackItems := witness[:len(witness)-2]

	// Control block: [leaf version + parity] [internal pubkey (32)] [merkle path (32*n)]
	if len(controlBlock) < 33 || len(controlBlock) > 4129 || (len(controlBlock)-33)%32 != 0 {
		return ErrTaprootControlBlockSize
	}

	leafVersionAndParity := controlBlock[0]
	leafVersion := leafVersionAndParity & 0xFE
	internalPubKey := controlBlock[1:33]
	merklePath := controlBlock[33:]

	// Compute leaf hash
	leafHash := TapLeaf(leafVersion, script)

	// Compute merkle root
	k := leafHash
	for i := 0; i < len(merklePath); i += 32 {
		node := [32]byte{}
		copy(node[:], merklePath[i:i+32])
		k = TapBranch(k, node)
	}

	// Compute tweaked output key and verify it matches
	tweak := TapTweak(internalPubKey, k[:])

	// Extract output parity from control block
	outputParity := leafVersionAndParity & 0x01

	if !crypto.VerifyTaprootCommitment(outputKey, internalPubKey, tweak, outputParity) {
		return ErrWitnessProgram
	}

	// Fix #6: Only execute as tapscript if leaf version is 0xc0.
	// Unknown leaf versions succeed unconditionally.
	if leafVersion != 0xc0 {
		return nil
	}

	// Set up stack and execute the script.
	// Wire-order stackItems: index 0 = bottom of stack, last = top.
	// Push in wire order so that stackItems[0] ends up at the bottom.
	e.stack = NewStack()
	for i := 0; i < len(stackItems); i++ {
		e.stack.Push(stackItems[i])
	}

	// Set leaf hash for sighash computation
	e.codesepPos = 0xFFFFFFFF

	// Fix #9: Initialize tapscript signature validation weight budget (BIP342).
	// Budget = VALIDATION_WEIGHT_OFFSET (50) + serialized witness size.
	// Serialized witness size uses the ORIGINAL witness (including annex if present).
	// Format: compact_size(num_items) + sum(compact_size(len(item)) + len(item)).
	totalItems := len(witness)
	if annex != nil {
		totalItems++
	}
	witnessSize := compactSizeLen(totalItems)
	for _, w := range witness {
		witnessSize += compactSizeLen(len(w)) + len(w)
	}
	if annex != nil {
		witnessSize += compactSizeLen(len(annex)) + len(annex)
	}
	e.sigopBudget = 50 + witnessSize

	e.opCount = 0
	if err := e.executeScript(script); err != nil {
		return err
	}
	// BIP342: tapscript also implicitly requires cleanstack
	return e.verifyWitnessCleanStack()
}

// IsOpSuccess returns true if the opcode is an OP_SUCCESSx opcode (BIP342).
func IsOpSuccess(op byte) bool {
	return op == 80 || op == 98 || (op >= 126 && op <= 129) ||
		(op >= 131 && op <= 134) || (op >= 137 && op <= 138) ||
		(op >= 141 && op <= 142) || (op >= 149 && op <= 153) ||
		(op >= 187 && op <= 254)
}

// compactSizeLen returns the number of bytes needed to encode n as a Bitcoin compact size.
func compactSizeLen(n int) int {
	if n < 253 {
		return 1
	} else if n <= 0xFFFF {
		return 3
	} else if n <= 0xFFFFFFFF {
		return 5
	}
	return 9
}

// requireMinimalData returns true if minimal push encoding must be enforced.
// This is mandatory for witness v0 and tapscript (consensus), and for legacy
// scripts when ScriptVerifyMinimalData flag is set.
func (e *Engine) requireMinimalData() bool {
	return e.sigVersion == SigVersionWitnessV0 ||
		e.sigVersion == SigVersionTapscript ||
		(e.flags&ScriptVerifyMinimalData != 0)
}

// checkMinimalPush verifies that a push operation uses the minimal encoding.
// op is the opcode used, data is the data being pushed, dataLen is len(data).
// Returns an error if the push is non-minimal.
func checkMinimalPush(op byte, data []byte, dataLen int) error {
	if dataLen == 0 {
		// Empty data should use OP_0.
		if op != OP_0 {
			return ErrMinimalData
		}
	} else if dataLen == 1 {
		b := data[0]
		if b >= 1 && b <= 16 {
			// Single byte 1-16 should use OP_1 through OP_16.
			if op != OP_1+b-1 {
				return ErrMinimalData
			}
		} else if b == 0x81 {
			// 0x81 should use OP_1NEGATE.
			if op != OP_1NEGATE {
				return ErrMinimalData
			}
		}
		// Any other single byte value is fine with a direct 1-byte push (op == 0x01).
	}
	if dataLen >= 1 && dataLen <= 75 {
		// Should use direct push (0x01-0x4b), not OP_PUSHDATA1/2/4.
		if op == OP_PUSHDATA1 || op == OP_PUSHDATA2 || op == OP_PUSHDATA4 {
			return ErrMinimalData
		}
	} else if dataLen <= 255 {
		// Should use OP_PUSHDATA1, not OP_PUSHDATA2/4.
		if op == OP_PUSHDATA2 || op == OP_PUSHDATA4 {
			return ErrMinimalData
		}
	} else if dataLen <= 65535 {
		// Should use OP_PUSHDATA2, not OP_PUSHDATA4.
		if op == OP_PUSHDATA4 {
			return ErrMinimalData
		}
	}
	return nil
}

// executeScript executes a single script.
func (e *Engine) executeScript(script []byte) error {
	// Fix #2: Script size limit only applies to BASE and WITNESS_V0.
	if (e.sigVersion == SigVersionBase || e.sigVersion == SigVersionWitnessV0) && len(script) > MaxScriptSize {
		return ErrScriptTooLong
	}

	// Track the script for legacy sighash computation with OP_CODESEPARATOR
	e.currentScript = script
	e.lastCodeSepIdx = 0 // Reset: scriptCode starts from beginning

	// Fix #3: OP_SUCCESSx handling for tapscript.
	if e.sigVersion == SigVersionTapscript {
		scanPC := 0
		for scanPC < len(script) {
			op := script[scanPC]
			scanPC++
			if op >= 0x01 && op <= 0x4b {
				scanPC += int(op)
			} else if op == OP_PUSHDATA1 {
				if scanPC >= len(script) {
					return errors.New("script too short for OP_PUSHDATA1")
				}
				scanPC += 1 + int(script[scanPC])
			} else if op == OP_PUSHDATA2 {
				if scanPC+2 > len(script) {
					return errors.New("script too short for OP_PUSHDATA2")
				}
				dataLen := int(script[scanPC]) | int(script[scanPC+1])<<8
				scanPC += 2 + dataLen
			} else if op == OP_PUSHDATA4 {
				if scanPC+4 > len(script) {
					return errors.New("script too short for OP_PUSHDATA4")
				}
				dataLen := int(script[scanPC]) | int(script[scanPC+1])<<8 | int(script[scanPC+2])<<16 | int(script[scanPC+3])<<24
				scanPC += 4 + dataLen
			} else if IsOpSuccess(op) {
				if e.flags&ScriptVerifyDiscourageOpSuccess != 0 {
					return errors.New("discouraged OP_SUCCESS opcode in tapscript")
				}
				return nil
			}
		}
	}

	pc := 0 // Program counter
	var opcodePos uint32 // Fix #5: opcode index counter for OP_CODESEPARATOR
	for pc < len(script) {
		op := script[pc]
		pc++

		// Check for disabled opcodes
		if IsDisabledOpcode(op) {
			return ErrDisabledOpcode
		}

		// Determine if we're in an executing branch
		executing := e.isExecuting()

		// Handle data push operations
		if op == OP_0 {
			if executing {
				e.stack.Push([]byte{})
			}
			opcodePos++
			continue
		}

		if op >= 0x01 && op <= 0x4b {
			// Direct push: op is the number of bytes to push
			dataLen := int(op)
			if pc+dataLen > len(script) {
				return fmt.Errorf("script too short for push of %d bytes", dataLen)
			}
			if dataLen > MaxScriptElementSize {
				return ErrPushSize
			}
			if executing {
				if e.requireMinimalData() {
					if err := checkMinimalPush(op, script[pc:pc+dataLen], dataLen); err != nil {
						return err
					}
				}
				e.stack.Push(script[pc : pc+dataLen])
			}
			pc += dataLen
			opcodePos++
			continue
		}

		if op == OP_PUSHDATA1 {
			if pc >= len(script) {
				return errors.New("script too short for OP_PUSHDATA1")
			}
			dataLen := int(script[pc])
			pc++
			if pc+dataLen > len(script) {
				return errors.New("script too short for OP_PUSHDATA1 data")
			}
			if dataLen > MaxScriptElementSize {
				return ErrPushSize
			}
			if executing {
				if e.requireMinimalData() {
					if err := checkMinimalPush(op, script[pc:pc+dataLen], dataLen); err != nil {
						return err
					}
				}
				e.stack.Push(script[pc : pc+dataLen])
			}
			pc += dataLen
			opcodePos++
			continue
		}

		if op == OP_PUSHDATA2 {
			if pc+2 > len(script) {
				return errors.New("script too short for OP_PUSHDATA2")
			}
			dataLen := int(script[pc]) | int(script[pc+1])<<8
			pc += 2
			if pc+dataLen > len(script) {
				return errors.New("script too short for OP_PUSHDATA2 data")
			}
			if dataLen > MaxScriptElementSize {
				return ErrPushSize
			}
			if executing {
				if e.requireMinimalData() {
					if err := checkMinimalPush(op, script[pc:pc+dataLen], dataLen); err != nil {
						return err
					}
				}
				e.stack.Push(script[pc : pc+dataLen])
			}
			pc += dataLen
			opcodePos++
			continue
		}

		if op == OP_PUSHDATA4 {
			if pc+4 > len(script) {
				return errors.New("script too short for OP_PUSHDATA4")
			}
			dataLen := int(script[pc]) | int(script[pc+1])<<8 | int(script[pc+2])<<16 | int(script[pc+3])<<24
			pc += 4
			if pc+dataLen > len(script) {
				return errors.New("script too short for OP_PUSHDATA4 data")
			}
			if dataLen > MaxScriptElementSize {
				return ErrPushSize
			}
			if executing {
				if e.requireMinimalData() {
					if err := checkMinimalPush(op, script[pc:pc+dataLen], dataLen); err != nil {
						return err
					}
				}
				e.stack.Push(script[pc : pc+dataLen])
			}
			pc += dataLen
			opcodePos++
			continue
		}

		if op == OP_1NEGATE {
			if executing {
				e.stack.PushInt(-1)
			}
			opcodePos++
			continue
		}

		if op >= OP_1 && op <= OP_16 {
			if executing {
				e.stack.PushInt(int64(op - OP_1 + 1))
			}
			opcodePos++
			continue
		}

		// Fix #1: Count non-push operations only for BASE and WITNESS_V0.
		if op > OP_16 {
			if e.sigVersion == SigVersionBase || e.sigVersion == SigVersionWitnessV0 {
				e.opCount++
				if e.opCount > MaxOpsPerScript {
					return ErrOpCount
				}
			}
		}

		// Handle control flow (must be processed even when not executing)
		switch op {
		case OP_IF, OP_NOTIF:
			var cond bool
			if executing {
				if e.stack.IsEmpty() {
					return ErrStackUnderflow
				}
				val, _ := e.stack.Pop()

				// BIP342: Tapscript requires minimal IF — condition must be
				// exactly empty (false) or exactly {0x01} (true).
				// MINIMALIF flag enforces the same for witness v0 (not base scripts).
				if e.sigVersion == SigVersionTapscript ||
					(e.sigVersion == SigVersionWitnessV0 && e.flags&ScriptVerifyMinimalIf != 0) {
					if len(val) > 1 || (len(val) == 1 && val[0] != 1) {
						return fmt.Errorf("tapscript requires minimal IF/NOTIF argument")
					}
				}

				cond = CastToBool(val)
				if op == OP_NOTIF {
					cond = !cond
				}
			}
			e.condStack = append(e.condStack, executing && cond)
			opcodePos++
			// Stack size check after control flow opcode
			if e.stack.Size()+e.altStack.Size() > MaxStackSize {
				return ErrStackOverflow
			}
			continue

		case OP_ELSE:
			if len(e.condStack) == 0 {
				return ErrUnbalancedConditional
			}
			// Flip the current condition, but only if parent branch is executing
			if len(e.condStack) == 1 || e.condStack[len(e.condStack)-2] {
				e.condStack[len(e.condStack)-1] = !e.condStack[len(e.condStack)-1]
			}
			opcodePos++
			// Stack size check after control flow opcode
			if e.stack.Size()+e.altStack.Size() > MaxStackSize {
				return ErrStackOverflow
			}
			continue

		case OP_ENDIF:
			if len(e.condStack) == 0 {
				return ErrUnbalancedConditional
			}
			e.condStack = e.condStack[:len(e.condStack)-1]
			opcodePos++
			// Stack size check after control flow opcode
			if e.stack.Size()+e.altStack.Size() > MaxStackSize {
				return ErrStackOverflow
			}
			continue
		}

		// Skip remaining operations if not executing
		if !executing {
			opcodePos++
			continue
		}

		// Execute opcode
		if err := e.executeOpcode(op, script, pc, opcodePos); err != nil {
			return err
		}
		opcodePos++

		// Check stack size limit after every opcode execution
		if e.stack.Size()+e.altStack.Size() > MaxStackSize {
			return ErrStackOverflow
		}
	}

	// Check for unbalanced conditionals
	if len(e.condStack) != 0 {
		return ErrUnbalancedConditional
	}

	return nil
}

// isExecuting returns true if we're in an executing branch.
func (e *Engine) isExecuting() bool {
	for _, cond := range e.condStack {
		if !cond {
			return false
		}
	}
	return true
}

// executeOpcode executes a single opcode.
func (e *Engine) executeOpcode(op byte, script []byte, pc int, opcodePos uint32) error {
	switch op {
	case OP_VER:
		// OP_VER is only an error when actually executed (not in unexecuted branches).
		return ErrDisabledOpcode

	case OP_NOP:
		return nil

	case OP_NOP1, OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10:
		// Reserved for future upgrades, treated as NOP for now
		if e.flags&ScriptVerifyDiscourageUpgradableNops != 0 {
			return errors.New("discouraged upgradable NOP")
		}
		return nil

	case OP_VERIFY:
		return e.opVerify()

	case OP_RETURN:
		return ErrOpReturn

	case OP_TOALTSTACK:
		return e.opToAltStack()

	case OP_FROMALTSTACK:
		return e.opFromAltStack()

	case OP_DROP:
		return e.opDrop()

	case OP_2DROP:
		return e.op2Drop()

	case OP_DUP:
		return e.opDup()

	case OP_2DUP:
		return e.op2Dup()

	case OP_3DUP:
		return e.op3Dup()

	case OP_NIP:
		return e.opNip()

	case OP_OVER:
		return e.opOver()

	case OP_2OVER:
		return e.op2Over()

	case OP_ROT:
		return e.opRot()

	case OP_SWAP:
		return e.opSwap()

	case OP_2SWAP:
		return e.op2Swap()

	case OP_2ROT:
		return e.op2Rot()

	case OP_TUCK:
		return e.opTuck()

	case OP_SIZE:
		return e.opSize()

	case OP_EQUAL:
		return e.opEqual()

	case OP_EQUALVERIFY:
		if err := e.opEqual(); err != nil {
			return err
		}
		return e.opVerify()

	case OP_1ADD:
		return e.op1Add()

	case OP_1SUB:
		return e.op1Sub()

	case OP_NEGATE:
		return e.opNegate()

	case OP_ABS:
		return e.opAbs()

	case OP_NOT:
		return e.opNot()

	case OP_0NOTEQUAL:
		return e.op0NotEqual()

	case OP_ADD:
		return e.opAdd()

	case OP_SUB:
		return e.opSub()

	case OP_BOOLAND:
		return e.opBoolAnd()

	case OP_BOOLOR:
		return e.opBoolOr()

	case OP_NUMEQUAL:
		return e.opNumEqual()

	case OP_NUMEQUALVERIFY:
		if err := e.opNumEqual(); err != nil {
			return err
		}
		return e.opVerify()

	case OP_NUMNOTEQUAL:
		return e.opNumNotEqual()

	case OP_LESSTHAN:
		return e.opLessThan()

	case OP_GREATERTHAN:
		return e.opGreaterThan()

	case OP_LESSTHANOREQUAL:
		return e.opLessThanOrEqual()

	case OP_GREATERTHANOREQUAL:
		return e.opGreaterThanOrEqual()

	case OP_MIN:
		return e.opMin()

	case OP_MAX:
		return e.opMax()

	case OP_WITHIN:
		return e.opWithin()

	case OP_RIPEMD160:
		return e.opRIPEMD160()

	case OP_SHA1:
		return e.opSHA1()

	case OP_SHA256:
		return e.opSHA256()

	case OP_HASH160:
		return e.opHash160()

	case OP_HASH256:
		return e.opHash256()

	case OP_CODESEPARATOR:
		// In witness v0, OP_CODESEPARATOR is forbidden if CONST_SCRIPTCODE is set
		if e.sigVersion == SigVersionWitnessV0 && e.flags&ScriptVerifyConstScriptCode != 0 {
			return errors.New("OP_CODESEPARATOR in witness v0 script")
		}
		// For tapscript, update codesep_pos (opcode index)
		e.codesepPos = opcodePos
		// For legacy scripts, track byte position after this opcode
		// pc is already positioned after the OP_CODESEPARATOR opcode
		e.lastCodeSepIdx = pc
		return nil

	case OP_CHECKSIG:
		return e.opCheckSig(script)

	case OP_CHECKSIGVERIFY:
		if err := e.opCheckSig(script); err != nil {
			return err
		}
		return e.opVerify()

	case OP_CHECKMULTISIG:
		if e.sigVersion == SigVersionTapscript {
			return ErrTapscriptCheckMultiSig
		}
		return e.opCheckMultiSig(script)

	case OP_CHECKMULTISIGVERIFY:
		if e.sigVersion == SigVersionTapscript {
			return ErrTapscriptCheckMultiSig
		}
		if err := e.opCheckMultiSig(script); err != nil {
			return err
		}
		return e.opVerify()

	case OP_CHECKLOCKTIMEVERIFY:
		if e.flags&ScriptVerifyCLTV == 0 {
			return nil // Treat as NOP
		}
		return e.opCheckLockTimeVerify()

	case OP_CHECKSEQUENCEVERIFY:
		if e.flags&ScriptVerifyCSV == 0 {
			return nil // Treat as NOP
		}
		return e.opCheckSequenceVerify()

	case OP_CHECKSIGADD:
		return e.opCheckSigAdd(script)

	case OP_DEPTH:
		return e.opDepth()

	case OP_IFDUP:
		return e.opIfDup()

	case OP_PICK:
		return e.opPick()

	case OP_ROLL:
		return e.opRoll()

	default:
		return fmt.Errorf("unimplemented opcode: 0x%02x (%s)", op, OpcodeName(op))
	}
}

// IsP2SH returns true if the script is a P2SH output script.
func IsP2SH(script []byte) bool {
	return len(script) == 23 &&
		script[0] == OP_HASH160 &&
		script[1] == 20 &&
		script[22] == OP_EQUAL
}

// IsP2PKH returns true if the script is a P2PKH output script.
func IsP2PKH(script []byte) bool {
	return len(script) == 25 &&
		script[0] == OP_DUP &&
		script[1] == OP_HASH160 &&
		script[2] == 20 &&
		script[23] == OP_EQUALVERIFY &&
		script[24] == OP_CHECKSIG
}

// IsP2WPKH returns true if the script is a P2WPKH output script.
func IsP2WPKH(script []byte) bool {
	return len(script) == 22 &&
		script[0] == OP_0 &&
		script[1] == 20
}

// IsP2WSH returns true if the script is a P2WSH output script.
func IsP2WSH(script []byte) bool {
	return len(script) == 34 &&
		script[0] == OP_0 &&
		script[1] == 32
}

// IsP2TR returns true if the script is a P2TR output script.
func IsP2TR(script []byte) bool {
	return len(script) == 34 &&
		script[0] == OP_1 &&
		script[1] == 32
}

// IsPayToAnchor returns true if the script is a Pay-to-Anchor output script.
// P2A is exactly 4 bytes: OP_1 OP_PUSHBYTES_2 0x4e 0x73 (witness v1, 2-byte program).
// This is a standardized anyone-can-spend output used for anchor outputs in
// Lightning and other L2 protocols.
func IsPayToAnchor(script []byte) bool {
	return len(script) == 4 &&
		script[0] == OP_1 && // 0x51
		script[1] == 0x02 && // push 2 bytes
		script[2] == 0x4e &&
		script[3] == 0x73
}

// IsPayToAnchorWitnessProgram checks if a witness version and program represent P2A.
// This is the static variant that checks after ExtractWitnessProgram has been called.
func IsPayToAnchorWitnessProgram(version int, program []byte) bool {
	return version == 1 &&
		len(program) == 2 &&
		program[0] == 0x4e &&
		program[1] == 0x73
}

// ExtractWitnessProgram extracts the witness version and program from a script.
// Returns -1 for version if not a witness program.
func ExtractWitnessProgram(script []byte) (version int, program []byte) {
	if len(script) < 4 || len(script) > 42 {
		return -1, nil
	}

	// First byte must be OP_0 (0x00) or OP_1-OP_16 (0x51-0x60)
	firstByte := script[0]
	if firstByte == OP_0 {
		version = 0
	} else if firstByte >= OP_1 && firstByte <= OP_16 {
		version = int(firstByte - OP_1 + 1)
	} else {
		return -1, nil
	}

	// Second byte is the push opcode for the program
	if len(script) < 2 {
		return -1, nil
	}
	pushLen := int(script[1])
	if pushLen < 2 || pushLen > 40 {
		return -1, nil
	}

	if len(script) != 2+pushLen {
		return -1, nil
	}

	return version, script[2:]
}

// IsPushOnly returns true if the script contains only push operations.
// This is used for the SIGPUSHONLY check on scriptSig.
func IsPushOnly(script []byte) bool {
	pc := 0
	for pc < len(script) {
		op := script[pc]
		pc++

		if op > OP_16 {
			return false
		}

		// Skip push data
		if op >= 0x01 && op <= 0x4b {
			pc += int(op)
		} else if op == OP_PUSHDATA1 {
			if pc >= len(script) {
				return false
			}
			pc += 1 + int(script[pc])
		} else if op == OP_PUSHDATA2 {
			if pc+2 > len(script) {
				return false
			}
			dataLen := int(script[pc]) | int(script[pc+1])<<8
			pc += 2 + dataLen
		} else if op == OP_PUSHDATA4 {
			if pc+4 > len(script) {
				return false
			}
			dataLen := int(script[pc]) | int(script[pc+1])<<8 | int(script[pc+2])<<16 | int(script[pc+3])<<24
			pc += 4 + dataLen
		}
	}
	return true
}

// VerifyScript is a convenience function to verify a transaction input.
func VerifyScript(scriptSig, scriptPubKey []byte, tx *wire.MsgTx, txIdx int, flags ScriptFlags, amount int64, prevOuts []*wire.TxOut) error {
	engine, err := NewEngine(scriptPubKey, tx, txIdx, flags, amount, prevOuts)
	if err != nil {
		return err
	}
	return engine.Execute()
}
