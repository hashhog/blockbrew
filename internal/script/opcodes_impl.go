package script

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"

	"github.com/hashhog/blockbrew/internal/crypto"
	"golang.org/x/crypto/ripemd160"
)

// Stack operations

func (e *Engine) opVerify() error {
	if e.stack.IsEmpty() {
		return ErrStackUnderflow
	}
	val, _ := e.stack.Pop()
	if !CastToBool(val) {
		return ErrVerifyFailed
	}
	return nil
}

func (e *Engine) opToAltStack() error {
	val, err := e.stack.Pop()
	if err != nil {
		return err
	}
	e.altStack.Push(val)
	return nil
}

func (e *Engine) opFromAltStack() error {
	val, err := e.altStack.Pop()
	if err != nil {
		return err
	}
	e.stack.Push(val)
	return nil
}

func (e *Engine) opDrop() error {
	_, err := e.stack.Pop()
	return err
}

func (e *Engine) op2Drop() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	e.stack.Pop()
	e.stack.Pop()
	return nil
}

func (e *Engine) opDup() error {
	val, err := e.stack.Peek()
	if err != nil {
		return err
	}
	e.stack.Push(val)
	return nil
}

func (e *Engine) op2Dup() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	val1, _ := e.stack.PeekAt(1)
	val2, _ := e.stack.PeekAt(0)
	e.stack.Push(val1)
	e.stack.Push(val2)
	return nil
}

func (e *Engine) op3Dup() error {
	if e.stack.Size() < 3 {
		return ErrStackUnderflow
	}
	val1, _ := e.stack.PeekAt(2)
	val2, _ := e.stack.PeekAt(1)
	val3, _ := e.stack.PeekAt(0)
	e.stack.Push(val1)
	e.stack.Push(val2)
	e.stack.Push(val3)
	return nil
}

func (e *Engine) opNip() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	// Remove second-to-top item
	_, err := e.stack.RemoveAt(1)
	return err
}

func (e *Engine) opOver() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	val, _ := e.stack.PeekAt(1)
	e.stack.Push(val)
	return nil
}

func (e *Engine) op2Over() error {
	if e.stack.Size() < 4 {
		return ErrStackUnderflow
	}
	val1, _ := e.stack.PeekAt(3)
	val2, _ := e.stack.PeekAt(2)
	e.stack.Push(val1)
	e.stack.Push(val2)
	return nil
}

func (e *Engine) opRot() error {
	if e.stack.Size() < 3 {
		return ErrStackUnderflow
	}
	// Move third item to top: [a, b, c] -> [b, c, a]
	val, _ := e.stack.RemoveAt(2)
	e.stack.Push(val)
	return nil
}

func (e *Engine) opSwap() error {
	return e.stack.SwapTop()
}

func (e *Engine) op2Rot() error {
	if e.stack.Size() < 6 {
		return ErrStackUnderflow
	}
	// Move the 5th and 6th items to the top
	// [a, b, c, d, e, f] -> [c, d, e, f, a, b]
	val1, _ := e.stack.RemoveAt(5) // 6th from top (deepest)
	val2, _ := e.stack.RemoveAt(4) // 5th from top (shifted after first remove)
	e.stack.Push(val1)
	e.stack.Push(val2)
	return nil
}

func (e *Engine) op2Swap() error {
	if e.stack.Size() < 4 {
		return ErrStackUnderflow
	}
	// [a, b, c, d] -> [c, d, a, b]
	items := e.stack.Items()
	n := len(items)
	items[n-4], items[n-2] = items[n-2], items[n-4]
	items[n-3], items[n-1] = items[n-1], items[n-3]
	return nil
}

func (e *Engine) opTuck() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	// OP_TUCK: Copy top and insert it before the second-to-top item
	// [x1, x2] -> [x2, x1, x2] where x2 is top
	top, _ := e.stack.Peek()
	items := e.stack.Items()
	n := len(items)

	// Create new slice with space for one more item
	newItems := make([][]byte, n+1)

	// Copy everything except the last two items
	copy(newItems, items[:n-2])

	// Insert: copy of top, then second-to-top, then top
	cp := make([]byte, len(top))
	copy(cp, top)
	newItems[n-2] = cp           // copy of top goes before second-to-top
	newItems[n-1] = items[n-2]   // second-to-top item
	newItems[n] = items[n-1]     // top stays on top

	e.stack.SetItems(newItems)
	return nil
}

func (e *Engine) opSize() error {
	val, err := e.stack.Peek()
	if err != nil {
		return err
	}
	e.stack.PushInt(int64(len(val)))
	return nil
}

func (e *Engine) opDepth() error {
	e.stack.PushInt(int64(e.stack.Size()))
	return nil
}

func (e *Engine) opIfDup() error {
	val, err := e.stack.Peek()
	if err != nil {
		return err
	}
	if CastToBool(val) {
		e.stack.Push(val)
	}
	return nil
}

func (e *Engine) opPick() error {
	n, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	if n < 0 || int(n) >= e.stack.Size() {
		return ErrStackUnderflow
	}
	val, _ := e.stack.PeekAt(int(n))
	e.stack.Push(val)
	return nil
}

func (e *Engine) opRoll() error {
	n, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	if n < 0 || int(n) >= e.stack.Size() {
		return ErrStackUnderflow
	}
	val, _ := e.stack.RemoveAt(int(n))
	e.stack.Push(val)
	return nil
}

// Comparison operations

func (e *Engine) opEqual() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	a, _ := e.stack.Pop()
	b, _ := e.stack.Pop()
	e.stack.PushBool(bytes.Equal(a, b))
	return nil
}

// Arithmetic operations

func (e *Engine) op1Add() error {
	n, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	e.stack.PushInt(n + 1)
	return nil
}

func (e *Engine) op1Sub() error {
	n, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	e.stack.PushInt(n - 1)
	return nil
}

func (e *Engine) opNegate() error {
	n, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	e.stack.PushInt(-n)
	return nil
}

func (e *Engine) opAbs() error {
	n, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	if n < 0 {
		n = -n
	}
	e.stack.PushInt(n)
	return nil
}

func (e *Engine) opNot() error {
	n, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	if n == 0 {
		e.stack.PushInt(1)
	} else {
		e.stack.PushInt(0)
	}
	return nil
}

func (e *Engine) op0NotEqual() error {
	n, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	if n != 0 {
		e.stack.PushInt(1)
	} else {
		e.stack.PushInt(0)
	}
	return nil
}

func (e *Engine) opAdd() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	b, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	a, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	e.stack.PushInt(a + b)
	return nil
}

func (e *Engine) opSub() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	b, errB := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if errB != nil {
		return errB
	}
	a, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	e.stack.PushInt(a - b)
	return nil
}

func (e *Engine) opBoolAnd() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	b, errB := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if errB != nil {
		return errB
	}
	a, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	if a != 0 && b != 0 {
		e.stack.PushInt(1)
	} else {
		e.stack.PushInt(0)
	}
	return nil
}

func (e *Engine) opBoolOr() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	b, errB := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if errB != nil {
		return errB
	}
	a, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	if a != 0 || b != 0 {
		e.stack.PushInt(1)
	} else {
		e.stack.PushInt(0)
	}
	return nil
}

func (e *Engine) opNumEqual() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	b, errB := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if errB != nil {
		return errB
	}
	a, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	e.stack.PushBool(a == b)
	return nil
}

func (e *Engine) opNumNotEqual() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	b, errB := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if errB != nil {
		return errB
	}
	a, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	e.stack.PushBool(a != b)
	return nil
}

func (e *Engine) opLessThan() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	b, errB := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if errB != nil {
		return errB
	}
	a, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	e.stack.PushBool(a < b)
	return nil
}

func (e *Engine) opGreaterThan() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	b, errB := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if errB != nil {
		return errB
	}
	a, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	e.stack.PushBool(a > b)
	return nil
}

func (e *Engine) opLessThanOrEqual() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	b, errB := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if errB != nil {
		return errB
	}
	a, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	e.stack.PushBool(a <= b)
	return nil
}

func (e *Engine) opGreaterThanOrEqual() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	b, errB := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if errB != nil {
		return errB
	}
	a, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	e.stack.PushBool(a >= b)
	return nil
}

func (e *Engine) opMin() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	b, errB := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if errB != nil {
		return errB
	}
	a, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	if a < b {
		e.stack.PushInt(a)
	} else {
		e.stack.PushInt(b)
	}
	return nil
}

func (e *Engine) opMax() error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}
	b, errB := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if errB != nil {
		return errB
	}
	a, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	if a > b {
		e.stack.PushInt(a)
	} else {
		e.stack.PushInt(b)
	}
	return nil
}

func (e *Engine) opWithin() error {
	if e.stack.Size() < 3 {
		return ErrStackUnderflow
	}
	max, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	min, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	x, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	e.stack.PushBool(min <= x && x < max)
	return nil
}

// Crypto operations

func (e *Engine) opRIPEMD160() error {
	val, err := e.stack.Pop()
	if err != nil {
		return err
	}
	h := ripemd160.New()
	h.Write(val)
	e.stack.Push(h.Sum(nil))
	return nil
}

func (e *Engine) opSHA1() error {
	val, err := e.stack.Pop()
	if err != nil {
		return err
	}
	h := sha1.Sum(val)
	e.stack.Push(h[:])
	return nil
}

func (e *Engine) opSHA256() error {
	val, err := e.stack.Pop()
	if err != nil {
		return err
	}
	h := sha256.Sum256(val)
	e.stack.Push(h[:])
	return nil
}

func (e *Engine) opHash160() error {
	val, err := e.stack.Pop()
	if err != nil {
		return err
	}
	h := crypto.Hash160(val)
	e.stack.Push(h[:])
	return nil
}

func (e *Engine) opHash256() error {
	val, err := e.stack.Pop()
	if err != nil {
		return err
	}
	h := crypto.DoubleSHA256(val)
	e.stack.Push(h[:])
	return nil
}

// Signature operations

func (e *Engine) opCheckSig(script []byte) error {
	if e.stack.Size() < 2 {
		return ErrStackUnderflow
	}

	// Pop pubkey first (top of stack), then signature
	pubKeyBytes, _ := e.stack.Pop()
	sigBytes, err := e.stack.Pop()
	if err != nil {
		return err
	}

	// Compute sighash based on sig version
	var sighash [32]byte
	var valid bool

	switch e.sigVersion {
	case SigVersionBase, SigVersionWitnessV0:
		// Empty signature is always false (but not an error) for legacy/segwit
		if len(sigBytes) == 0 {
			e.stack.PushBool(false)
			return nil
		}

		// DER signature encoding check (BIP66)
		if (e.flags&ScriptVerifyDERSig != 0) || (e.flags&ScriptVerifyLowS != 0) || (e.flags&ScriptVerifyStrictEncoding != 0) {
			if !IsValidDERSignatureEncoding(sigBytes) {
				return ErrSigDER
			}
		}

		// Low-S check (BIP62 rule 5)
		if e.flags&ScriptVerifyLowS != 0 {
			if !IsLowSSignature(sigBytes) {
				return ErrSigHighS
			}
		}

		// WITNESS_PUBKEYTYPE: witness v0 requires compressed pubkeys
		if e.sigVersion == SigVersionWitnessV0 && (e.flags&ScriptVerifyWitnessPubKeyType != 0) {
			if !IsCompressedPubKey(pubKeyBytes) {
				return ErrWitnessPubKeyType
			}
		}

		// Extract sighash type (last byte of signature)
		hashType := SigHashType(sigBytes[len(sigBytes)-1])
		sig := sigBytes[:len(sigBytes)-1]

		if e.sigVersion == SigVersionBase {
			// For legacy, get scriptCode from after last OP_CODESEPARATOR
			scriptCode := e.currentScript[e.lastCodeSepIdx:]
			// Apply FindAndDelete to remove the push-encoded signature from scriptCode
			scriptCode = FindAndDelete(scriptCode, sigBytes)
			sighash, err = CalcSignatureHash(scriptCode, hashType, e.tx, e.txIdx)
		} else {
			// For witness v0, use BIP143 sighash (no FindAndDelete, no OP_CODESEPARATOR handling needed)
			sighash, err = CalcWitnessSignatureHash(script, hashType, e.tx, e.txIdx, e.amount)
		}
		if err != nil {
			e.stack.PushBool(false)
			return nil
		}
		pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
		if err != nil {
			e.stack.PushBool(false)
			return nil
		}
		valid = crypto.VerifyECDSA(pubKey, sighash, sig)

		// NULLFAIL: non-empty signature that fails verification must cause error
		if !valid && len(sigBytes) > 0 && (e.flags&ScriptVerifyNullFail != 0) {
			return ErrNullFail
		}

	case SigVersionTapscript:
		// Empty pubkey is a hard error in tapscript
		if len(pubKeyBytes) == 0 {
			return fmt.Errorf("tapscript empty pubkey")
		}

		// Empty signature pushes false (soft failure, no budget cost)
		if len(sigBytes) == 0 {
			e.stack.PushBool(false)
			return nil
		}

		// Decrement tapscript signature validation weight budget (BIP342)
		e.sigopBudget -= TapscriptSigopBudgetCost
		if e.sigopBudget < 0 {
			return fmt.Errorf("tapscript validation weight exceeded")
		}

		// For non-32-byte pubkeys (unknown key version), push true for upgradability
		if len(pubKeyBytes) != 32 {
			e.stack.PushBool(true)
			return nil
		}

		// Schnorr signature length handling:
		// 64 bytes: SIGHASH_DEFAULT (0x00), signature is entire blob
		// 65 bytes: last byte is hashType, signature is first 64 bytes
		// Other: hard error
		var hashType SigHashType
		var sig []byte
		if len(sigBytes) == 64 {
			hashType = SigHashDefault
			sig = sigBytes
		} else if len(sigBytes) == 65 {
			hashType = SigHashType(sigBytes[64])
			if hashType == SigHashDefault {
				return fmt.Errorf("schnorr signature hash type 0x00 not allowed with 65-byte signature")
			}
			sig = sigBytes[:64]
		} else {
			return fmt.Errorf("invalid schnorr signature size: %d", len(sigBytes))
		}

		// Get tapscript-specific sighash
		leafHash := TapLeaf(0xC0, script) // 0xC0 is TAPSCRIPT_LEAF_MASK
		opts := &TaprootSigHashOptions{
			TapLeafHash: &leafHash,
			KeyVersion:  0,
			CodeSepPos:  e.codesepPos,
		}
		sighash, err = CalcTaprootSignatureHash(hashType, e.tx, e.txIdx, e.prevOuts, opts)
		if err != nil {
			return err
		}
		valid = crypto.VerifySchnorr(pubKeyBytes, sighash, sig)

		// In tapscript, non-empty signature that fails verification is a HARD error
		if !valid {
			return fmt.Errorf("schnorr signature verification failed")
		}

	default:
		e.stack.PushBool(false)
		return nil
	}

	e.stack.PushBool(valid)
	return nil
}

func (e *Engine) opCheckMultiSig(script []byte) error {
	// Get number of public keys
	nPubKeys, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	if nPubKeys < 0 || nPubKeys > MaxPubKeysPerMultisig {
		return ErrInvalidPubKeyCount
	}

	// Add to op count
	e.opCount += int(nPubKeys)
	if e.opCount > MaxOpsPerScript {
		return ErrOpCount
	}

	// Get public keys
	if e.stack.Size() < int(nPubKeys) {
		return ErrStackUnderflow
	}
	pubKeys := make([][]byte, nPubKeys)
	for i := int64(0); i < nPubKeys; i++ {
		pubKeys[i], _ = e.stack.Pop()
	}

	// Get number of signatures
	nSigs, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	if nSigs < 0 || nSigs > nPubKeys {
		return ErrInvalidSigCount
	}

	// Get signatures
	if e.stack.Size() < int(nSigs) {
		return ErrStackUnderflow
	}
	sigs := make([][]byte, nSigs)
	for i := int64(0); i < nSigs; i++ {
		sigs[i], _ = e.stack.Pop()
	}

	// Pop the dummy element (Bitcoin off-by-one bug)
	if e.stack.IsEmpty() {
		return ErrStackUnderflow
	}
	dummy, _ := e.stack.Pop()

	// If NULLDUMMY flag is set, dummy must be empty
	if e.flags&ScriptVerifyNullDummy != 0 && len(dummy) > 0 {
		return ErrNullDummy
	}

	// For legacy scripts, prepare scriptCode by:
	// 1. Taking script from after last OP_CODESEPARATOR
	// 2. Applying FindAndDelete for ALL signatures before verification
	// This matches Bitcoin Core's behavior in interpreter.cpp lines 1138-1150
	var scriptCode []byte
	if e.sigVersion == SigVersionBase {
		scriptCode = e.currentScript[e.lastCodeSepIdx:]
		// Remove all signatures from scriptCode before verification
		for _, sigBytes := range sigs {
			scriptCode = FindAndDelete(scriptCode, sigBytes)
		}
	}

	// Verify signatures
	success := true
	pubKeyIdx := 0
	for _, sigBytes := range sigs {
		if len(sigBytes) == 0 {
			success = false
			break
		}

		// DER signature encoding check (BIP66)
		if (e.flags&ScriptVerifyDERSig != 0) || (e.flags&ScriptVerifyLowS != 0) || (e.flags&ScriptVerifyStrictEncoding != 0) {
			if !IsValidDERSignatureEncoding(sigBytes) {
				return ErrSigDER
			}
		}

		// Low-S check (BIP62 rule 5)
		if e.flags&ScriptVerifyLowS != 0 {
			if !IsLowSSignature(sigBytes) {
				return ErrSigHighS
			}
		}

		hashType := SigHashType(sigBytes[len(sigBytes)-1])
		sig := sigBytes[:len(sigBytes)-1]

		// Find a matching public key
		matched := false
		for pubKeyIdx < len(pubKeys) {
			pubKeyBytes := pubKeys[pubKeyIdx]
			pubKeyIdx++

			// WITNESS_PUBKEYTYPE: witness v0 requires compressed pubkeys
			if e.sigVersion == SigVersionWitnessV0 && (e.flags&ScriptVerifyWitnessPubKeyType != 0) {
				if !IsCompressedPubKey(pubKeyBytes) {
					return ErrWitnessPubKeyType
				}
			}

			var sighash [32]byte
			switch e.sigVersion {
			case SigVersionBase:
				// Use the pre-computed scriptCode with all sigs removed
				sighash, err = CalcSignatureHash(scriptCode, hashType, e.tx, e.txIdx)
			case SigVersionWitnessV0:
				// For witness v0, use BIP143 sighash (no FindAndDelete needed)
				sighash, err = CalcWitnessSignatureHash(script, hashType, e.tx, e.txIdx, e.amount)
			default:
				continue
			}
			if err != nil {
				continue
			}

			pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
			if err != nil {
				continue
			}

			if crypto.VerifyECDSA(pubKey, sighash, sig) {
				matched = true
				break
			}
		}

		if !matched {
			success = false
			break
		}
	}

	// NULLFAIL: if multisig failed, all signatures must be empty
	if !success && (e.flags&ScriptVerifyNullFail != 0) {
		for _, sigBytes := range sigs {
			if len(sigBytes) > 0 {
				return ErrNullFail
			}
		}
	}

	e.stack.PushBool(success)
	return nil
}

func (e *Engine) opCheckSigAdd(script []byte) error {
	// Tapscript only
	if e.sigVersion != SigVersionTapscript {
		return ErrInvalidOpcode
	}

	if e.stack.Size() < 3 {
		return ErrStackUnderflow
	}

	// Pop pubkey (top), n, sig
	pubKeyBytes, _ := e.stack.Pop()
	n, err := e.stack.PopInt(MaxScriptNumLen, e.requireMinimalData())
	if err != nil {
		return err
	}
	sigBytes, err := e.stack.Pop()
	if err != nil {
		return err
	}

	// Empty pubkey is a hard error in tapscript
	if len(pubKeyBytes) == 0 {
		return fmt.Errorf("tapscript empty pubkey")
	}

	// If signature is empty, just push n (no budget cost for empty sig)
	if len(sigBytes) == 0 {
		e.stack.PushInt(n)
		return nil
	}

	// Decrement tapscript signature validation weight budget (BIP342)
	e.sigopBudget -= TapscriptSigopBudgetCost
	if e.sigopBudget < 0 {
		return fmt.Errorf("tapscript validation weight exceeded")
	}

	// For non-32-byte pubkeys (unknown key version), push n+1 for upgradability
	if len(pubKeyBytes) != 32 {
		e.stack.PushInt(n + 1)
		return nil
	}

	// Schnorr signature length handling:
	// 64 bytes: SIGHASH_DEFAULT (0x00), signature is entire blob
	// 65 bytes: last byte is hashType, signature is first 64 bytes
	// Other: hard error
	var hashType SigHashType
	var sig []byte
	if len(sigBytes) == 64 {
		hashType = SigHashDefault
		sig = sigBytes
	} else if len(sigBytes) == 65 {
		hashType = SigHashType(sigBytes[64])
		if hashType == SigHashDefault {
			return fmt.Errorf("schnorr signature hash type 0x00 not allowed with 65-byte signature")
		}
		sig = sigBytes[:64]
	} else {
		return fmt.Errorf("invalid schnorr signature size: %d", len(sigBytes))
	}

	// Compute sighash
	leafHash := TapLeaf(0xC0, script)
	opts := &TaprootSigHashOptions{
		TapLeafHash: &leafHash,
		KeyVersion:  0,
		CodeSepPos:  e.codesepPos,
	}
	sighash, err := CalcTaprootSignatureHash(hashType, e.tx, e.txIdx, e.prevOuts, opts)
	if err != nil {
		return err
	}

	if crypto.VerifySchnorr(pubKeyBytes, sighash, sig) {
		e.stack.PushInt(n + 1)
	} else {
		// In tapscript, non-empty signature that fails verification is a HARD error
		return fmt.Errorf("schnorr signature verification failed")
	}
	return nil
}

// Locktime operations

func (e *Engine) opCheckLockTimeVerify() error {
	if e.stack.IsEmpty() {
		return ErrStackUnderflow
	}

	// Peek at the value (don't pop - CLTV leaves the value on stack)
	lockTimeBytes, _ := e.stack.Peek()
	lockTime, err := ScriptNumDeserialize(lockTimeBytes, 5, false) // 5 bytes allowed for CLTV
	if err != nil {
		return ErrCLTVFailed
	}

	// Locktime must be non-negative
	if lockTime < 0 {
		return ErrCLTVFailed
	}

	// Compare types must match (both block height or both timestamp)
	// Threshold is 500000000 (Nov 5, 1985)
	const lockTimeThreshold = 500000000
	txLockTime := int64(e.tx.LockTime)

	if (lockTime < lockTimeThreshold) != (txLockTime < lockTimeThreshold) {
		return ErrCLTVFailed
	}

	// Locktime must be <= tx locktime
	if lockTime > txLockTime {
		return ErrCLTVFailed
	}

	// Sequence must not be 0xffffffff (which disables locktime)
	if e.tx.TxIn[e.txIdx].Sequence == 0xffffffff {
		return ErrCLTVFailed
	}

	return nil
}

func (e *Engine) opCheckSequenceVerify() error {
	if e.stack.IsEmpty() {
		return ErrStackUnderflow
	}

	// Peek at the value (don't pop - CSV leaves the value on stack)
	sequenceBytes, _ := e.stack.Peek()
	sequence, err := ScriptNumDeserialize(sequenceBytes, 5, false) // 5 bytes allowed for CSV
	if err != nil {
		return ErrCSVFailed
	}

	// Sequence must be non-negative
	if sequence < 0 {
		return ErrCSVFailed
	}

	// If the disable flag is set, treat as NOP
	const sequenceLocktimeDisableFlag = 1 << 31
	if sequence&sequenceLocktimeDisableFlag != 0 {
		return nil
	}

	// Transaction version must be >= 2 for CSV
	if e.tx.Version < 2 {
		return ErrCSVFailed
	}

	// Check sequence type match (time-based vs block-based)
	const sequenceLocktimeTypeFlag = 1 << 22
	const sequenceLocktimeMask = 0x0000ffff

	txSequence := int64(e.tx.TxIn[e.txIdx].Sequence)

	// If tx sequence has disable flag set, fail
	if txSequence&sequenceLocktimeDisableFlag != 0 {
		return ErrCSVFailed
	}

	// Type flags must match
	if (sequence&sequenceLocktimeTypeFlag != 0) != (txSequence&sequenceLocktimeTypeFlag != 0) {
		return ErrCSVFailed
	}

	// Sequence value must be <= tx sequence value
	if (sequence & sequenceLocktimeMask) > (txSequence & sequenceLocktimeMask) {
		return ErrCSVFailed
	}

	return nil
}

// IsValidDERSignatureEncoding checks if a signature has valid DER encoding.
// The signature includes the sighash type byte as the last byte.
// This is consensus-critical since BIP66.
func IsValidDERSignatureEncoding(sig []byte) bool {
	// Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
	// Minimum and maximum size constraints.
	if len(sig) < 9 {
		return false
	}
	if len(sig) > 73 {
		return false
	}

	// A signature is of type 0x30 (compound).
	if sig[0] != 0x30 {
		return false
	}

	// Make sure the length covers the entire signature.
	if int(sig[1]) != len(sig)-3 {
		return false
	}

	// Extract the length of the R element.
	lenR := int(sig[3])

	// Make sure the length of the S element is still inside the signature.
	if 5+lenR >= len(sig) {
		return false
	}

	// Extract the length of the S element.
	lenS := int(sig[5+lenR])

	// Verify that the length of the signature matches the sum of the length
	// of the elements.
	if lenR+lenS+7 != len(sig) {
		return false
	}

	// Check whether the R element is an integer.
	if sig[2] != 0x02 {
		return false
	}

	// Zero-length integers are not allowed for R.
	if lenR == 0 {
		return false
	}

	// Negative numbers are not allowed for R.
	if sig[4]&0x80 != 0 {
		return false
	}

	// Null bytes at the start of R are not allowed, unless R would
	// otherwise be interpreted as a negative number.
	if lenR > 1 && sig[4] == 0x00 && sig[5]&0x80 == 0 {
		return false
	}

	// Check whether the S element is an integer.
	if sig[lenR+4] != 0x02 {
		return false
	}

	// Zero-length integers are not allowed for S.
	if lenS == 0 {
		return false
	}

	// Negative numbers are not allowed for S.
	if sig[lenR+6]&0x80 != 0 {
		return false
	}

	// Null bytes at the start of S are not allowed, unless S would otherwise be
	// interpreted as a negative number.
	if lenS > 1 && sig[lenR+6] == 0x00 && sig[lenR+7]&0x80 == 0 {
		return false
	}

	return true
}

// IsLowSSignature checks that the S value in a DER-encoded signature is in the
// lower half of the curve order (BIP62 rule 5). The signature must already be
// valid DER encoding. The signature includes the sighash type byte.
func IsLowSSignature(sig []byte) bool {
	if !IsValidDERSignatureEncoding(sig) {
		return false
	}

	// Extract S value from DER signature (without sighash byte)
	lenR := int(sig[3])
	sStart := 6 + lenR
	lenS := int(sig[5+lenR])
	sBytes := sig[sStart : sStart+lenS]

	// The secp256k1 curve order / 2:
	// 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
	halfOrder := [32]byte{
		0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
		0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
	}

	// Pad S to 32 bytes for comparison
	var sPadded [32]byte
	if lenS > 32 {
		return false
	}
	copy(sPadded[32-lenS:], sBytes)

	// Compare: S must be <= halfOrder
	for i := 0; i < 32; i++ {
		if sPadded[i] < halfOrder[i] {
			return true
		}
		if sPadded[i] > halfOrder[i] {
			return false
		}
	}
	return true // equal is ok
}

// IsCompressedPubKey returns true if the public key is a compressed public key
// (33 bytes starting with 0x02 or 0x03).
func IsCompressedPubKey(pubKey []byte) bool {
	return len(pubKey) == 33 && (pubKey[0] == 0x02 || pubKey[0] == 0x03)
}
