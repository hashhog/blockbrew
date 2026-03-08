package script

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"

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
	n, err := e.stack.PopInt(MaxScriptNumLen)
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
	n, err := e.stack.PopInt(MaxScriptNumLen)
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
	n, err := e.stack.PopInt(MaxScriptNumLen)
	if err != nil {
		return err
	}
	e.stack.PushInt(n + 1)
	return nil
}

func (e *Engine) op1Sub() error {
	n, err := e.stack.PopInt(MaxScriptNumLen)
	if err != nil {
		return err
	}
	e.stack.PushInt(n - 1)
	return nil
}

func (e *Engine) opNegate() error {
	n, err := e.stack.PopInt(MaxScriptNumLen)
	if err != nil {
		return err
	}
	e.stack.PushInt(-n)
	return nil
}

func (e *Engine) opAbs() error {
	n, err := e.stack.PopInt(MaxScriptNumLen)
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
	n, err := e.stack.PopInt(MaxScriptNumLen)
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
	n, err := e.stack.PopInt(MaxScriptNumLen)
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
	b, _ := e.stack.PopInt(MaxScriptNumLen)
	a, err := e.stack.PopInt(MaxScriptNumLen)
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
	b, _ := e.stack.PopInt(MaxScriptNumLen)
	a, err := e.stack.PopInt(MaxScriptNumLen)
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
	b, _ := e.stack.PopInt(MaxScriptNumLen)
	a, err := e.stack.PopInt(MaxScriptNumLen)
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
	b, _ := e.stack.PopInt(MaxScriptNumLen)
	a, err := e.stack.PopInt(MaxScriptNumLen)
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
	b, _ := e.stack.PopInt(MaxScriptNumLen)
	a, err := e.stack.PopInt(MaxScriptNumLen)
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
	b, _ := e.stack.PopInt(MaxScriptNumLen)
	a, err := e.stack.PopInt(MaxScriptNumLen)
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
	b, _ := e.stack.PopInt(MaxScriptNumLen)
	a, err := e.stack.PopInt(MaxScriptNumLen)
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
	b, _ := e.stack.PopInt(MaxScriptNumLen)
	a, err := e.stack.PopInt(MaxScriptNumLen)
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
	b, _ := e.stack.PopInt(MaxScriptNumLen)
	a, err := e.stack.PopInt(MaxScriptNumLen)
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
	b, _ := e.stack.PopInt(MaxScriptNumLen)
	a, err := e.stack.PopInt(MaxScriptNumLen)
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
	b, _ := e.stack.PopInt(MaxScriptNumLen)
	a, err := e.stack.PopInt(MaxScriptNumLen)
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
	b, _ := e.stack.PopInt(MaxScriptNumLen)
	a, err := e.stack.PopInt(MaxScriptNumLen)
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
	max, _ := e.stack.PopInt(MaxScriptNumLen)
	min, _ := e.stack.PopInt(MaxScriptNumLen)
	x, err := e.stack.PopInt(MaxScriptNumLen)
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

	// Empty signature is always false (but not an error)
	if len(sigBytes) == 0 {
		e.stack.PushBool(false)
		return nil
	}

	// Extract sighash type (last byte of signature)
	hashType := SigHashType(sigBytes[len(sigBytes)-1])
	sig := sigBytes[:len(sigBytes)-1]

	// Compute sighash based on sig version
	var sighash [32]byte
	var valid bool

	switch e.sigVersion {
	case SigVersionBase:
		// For legacy, apply FindAndDelete to remove signature from script
		scriptCode := FindAndDelete(script, sigBytes)
		sighash, err = CalcSignatureHash(scriptCode, hashType, e.tx, e.txIdx)
		if err != nil {
			e.stack.PushBool(false)
			return nil
		}
		// Verify ECDSA signature
		pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
		if err != nil {
			e.stack.PushBool(false)
			return nil
		}
		valid = crypto.VerifyECDSA(pubKey, sighash, sig)

	case SigVersionWitnessV0:
		// For witness v0, use BIP143 sighash
		// Script is already the scriptCode (no FindAndDelete needed)
		sighash, err = CalcWitnessSignatureHash(script, hashType, e.tx, e.txIdx, e.amount)
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

	case SigVersionTapscript:
		// For tapscript, use Schnorr signature
		if len(pubKeyBytes) != 32 {
			e.stack.PushBool(false)
			return nil
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
			e.stack.PushBool(false)
			return nil
		}
		valid = crypto.VerifySchnorr(pubKeyBytes, sighash, sig)

	default:
		e.stack.PushBool(false)
		return nil
	}

	e.stack.PushBool(valid)
	return nil
}

func (e *Engine) opCheckMultiSig(script []byte) error {
	// Get number of public keys
	nPubKeys, err := e.stack.PopInt(MaxScriptNumLen)
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
	nSigs, err := e.stack.PopInt(MaxScriptNumLen)
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

	// Verify signatures
	success := true
	pubKeyIdx := 0
	for _, sigBytes := range sigs {
		if len(sigBytes) == 0 {
			success = false
			break
		}

		hashType := SigHashType(sigBytes[len(sigBytes)-1])
		sig := sigBytes[:len(sigBytes)-1]

		// Find a matching public key
		matched := false
		for pubKeyIdx < len(pubKeys) {
			pubKeyBytes := pubKeys[pubKeyIdx]
			pubKeyIdx++

			var sighash [32]byte
			switch e.sigVersion {
			case SigVersionBase:
				scriptCode := FindAndDelete(script, sigBytes)
				sighash, err = CalcSignatureHash(scriptCode, hashType, e.tx, e.txIdx)
			case SigVersionWitnessV0:
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
	n, err := e.stack.PopInt(MaxScriptNumLen)
	if err != nil {
		return err
	}
	sigBytes, err := e.stack.Pop()
	if err != nil {
		return err
	}

	// If signature is empty, just push n
	if len(sigBytes) == 0 {
		e.stack.PushInt(n)
		return nil
	}

	// Verify the signature
	if len(pubKeyBytes) != 32 {
		e.stack.PushInt(n)
		return nil
	}

	// Extract hash type
	var hashType SigHashType
	var sig []byte
	if len(sigBytes) == 64 {
		hashType = SigHashDefault
		sig = sigBytes
	} else if len(sigBytes) == 65 {
		hashType = SigHashType(sigBytes[64])
		sig = sigBytes[:64]
	} else {
		e.stack.PushInt(n)
		return nil
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
		e.stack.PushInt(n)
		return nil
	}

	if crypto.VerifySchnorr(pubKeyBytes, sighash, sig) {
		e.stack.PushInt(n + 1)
	} else {
		e.stack.PushInt(n)
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
	lockTime, err := ScriptNumDeserialize(lockTimeBytes, 5) // 5 bytes allowed for CLTV
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
	sequence, err := ScriptNumDeserialize(sequenceBytes, 5) // 5 bytes allowed for CSV
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
