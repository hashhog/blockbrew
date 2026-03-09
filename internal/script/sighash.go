package script

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Signature hash types
const (
	SigHashAll          SigHashType = 0x01
	SigHashNone         SigHashType = 0x02
	SigHashSingle       SigHashType = 0x03
	SigHashAnyOneCanPay SigHashType = 0x80

	// Taproot-specific
	SigHashDefault SigHashType = 0x00 // Taproot default (same as ALL)
)

// SigHashType is the final byte of a signature, indicating what parts of the tx are signed.
type SigHashType byte

// BaseType returns the base sighash type (without ANYONECANPAY flag).
func (s SigHashType) BaseType() SigHashType {
	return s & 0x1f
}

// HasAnyOneCanPay returns true if the ANYONECANPAY flag is set.
func (s SigHashType) HasAnyOneCanPay() bool {
	return s&SigHashAnyOneCanPay != 0
}

// CalcSignatureHash computes the legacy sighash for pre-segwit transactions (BIP66).
// This implements the SIGHASH algorithm used before BIP143.
func CalcSignatureHash(script []byte, hashType SigHashType, tx *wire.MsgTx, idx int) ([32]byte, error) {
	if idx >= len(tx.TxIn) {
		return [32]byte{}, ErrInvalidIndex
	}

	// Create a copy of the transaction
	txCopy := copyTx(tx)

	// Clear all input scripts
	for i := range txCopy.TxIn {
		txCopy.TxIn[i].SignatureScript = nil
	}

	// Set the script for the input being signed (after FindAndDelete)
	// For legacy, we apply FindAndDelete to remove any OP_CODESEPARATOR
	scriptCode := removeOpCodeSeparators(script)
	txCopy.TxIn[idx].SignatureScript = scriptCode

	baseType := hashType.BaseType()

	// Handle SIGHASH_NONE
	if baseType == SigHashNone {
		txCopy.TxOut = nil
		// Set sequence to 0 for all other inputs
		for i := range txCopy.TxIn {
			if i != idx {
				txCopy.TxIn[i].Sequence = 0
			}
		}
	}

	// Handle SIGHASH_SINGLE
	if baseType == SigHashSingle {
		if idx >= len(txCopy.TxOut) {
			// Bitcoin Core bug: return hash of 1 if no corresponding output
			var one [32]byte
			one[0] = 1
			return one, nil
		}
		// Resize outputs to idx+1
		txCopy.TxOut = txCopy.TxOut[:idx+1]
		// Set all outputs before idx to empty/max value
		for i := 0; i < idx; i++ {
			txCopy.TxOut[i] = &wire.TxOut{
				Value:    -1, // 0xffffffffffffffff as int64
				PkScript: nil,
			}
		}
		// Set sequence to 0 for all other inputs
		for i := range txCopy.TxIn {
			if i != idx {
				txCopy.TxIn[i].Sequence = 0
			}
		}
	}

	// Handle SIGHASH_ANYONECANPAY
	if hashType.HasAnyOneCanPay() {
		txCopy.TxIn = []*wire.TxIn{txCopy.TxIn[idx]}
	}

	// Serialize the modified transaction
	var buf bytes.Buffer
	txCopy.SerializeNoWitness(&buf)

	// Append sighash type as 4-byte little-endian
	wire.WriteUint32LE(&buf, uint32(hashType))

	// Double SHA256
	return crypto.DoubleSHA256(buf.Bytes()), nil
}

// CalcWitnessSignatureHash computes the BIP143 sighash for segwit v0 transactions.
func CalcWitnessSignatureHash(script []byte, hashType SigHashType, tx *wire.MsgTx, idx int, amount int64) ([32]byte, error) {
	if idx >= len(tx.TxIn) {
		return [32]byte{}, ErrInvalidIndex
	}

	var hashPrevouts, hashSequence, hashOutputs [32]byte
	baseType := hashType.BaseType()

	// hashPrevouts
	if !hashType.HasAnyOneCanPay() {
		var buf bytes.Buffer
		for _, in := range tx.TxIn {
			in.PreviousOutPoint.Serialize(&buf)
		}
		hashPrevouts = crypto.DoubleSHA256(buf.Bytes())
	}

	// hashSequence
	if !hashType.HasAnyOneCanPay() && baseType != SigHashSingle && baseType != SigHashNone {
		var buf bytes.Buffer
		for _, in := range tx.TxIn {
			wire.WriteUint32LE(&buf, in.Sequence)
		}
		hashSequence = crypto.DoubleSHA256(buf.Bytes())
	}

	// hashOutputs
	if baseType != SigHashSingle && baseType != SigHashNone {
		var buf bytes.Buffer
		for _, out := range tx.TxOut {
			out.Serialize(&buf)
		}
		hashOutputs = crypto.DoubleSHA256(buf.Bytes())
	} else if baseType == SigHashSingle && idx < len(tx.TxOut) {
		var buf bytes.Buffer
		tx.TxOut[idx].Serialize(&buf)
		hashOutputs = crypto.DoubleSHA256(buf.Bytes())
	}

	// Build the preimage
	var preimage bytes.Buffer

	// 1. nVersion (4 bytes LE)
	wire.WriteInt32LE(&preimage, tx.Version)

	// 2. hashPrevouts (32 bytes)
	preimage.Write(hashPrevouts[:])

	// 3. hashSequence (32 bytes)
	preimage.Write(hashSequence[:])

	// 4. outpoint (32 + 4 bytes)
	tx.TxIn[idx].PreviousOutPoint.Serialize(&preimage)

	// 5. scriptCode (varint + script)
	wire.WriteVarBytes(&preimage, script)

	// 6. value (8 bytes LE)
	wire.WriteInt64LE(&preimage, amount)

	// 7. nSequence (4 bytes LE)
	wire.WriteUint32LE(&preimage, tx.TxIn[idx].Sequence)

	// 8. hashOutputs (32 bytes)
	preimage.Write(hashOutputs[:])

	// 9. nLocktime (4 bytes LE)
	wire.WriteUint32LE(&preimage, tx.LockTime)

	// 10. sighash type (4 bytes LE)
	wire.WriteUint32LE(&preimage, uint32(hashType))

	return crypto.DoubleSHA256(preimage.Bytes()), nil
}

// TaprootSigHashOptions contains additional options for taproot signature hashing.
type TaprootSigHashOptions struct {
	AnnexHash    *[32]byte // SHA256 of annex, if present
	TapLeafHash  *[32]byte // Leaf hash for script path spending
	KeyVersion   byte      // Key version (0 for key path)
	CodeSepPos   uint32    // Position of last OP_CODESEPARATOR
}

// CalcTaprootSignatureHash computes the BIP341 sighash for taproot transactions.
func CalcTaprootSignatureHash(hashType SigHashType, tx *wire.MsgTx, idx int, prevOuts []*wire.TxOut, opts *TaprootSigHashOptions) ([32]byte, error) {
	if idx >= len(tx.TxIn) || idx >= len(prevOuts) {
		return [32]byte{}, ErrInvalidIndex
	}

	// Validate hash_type: must be one of 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83
	if !(hashType <= 0x03 || (hashType >= 0x81 && hashType <= 0x83)) {
		return [32]byte{}, fmt.Errorf("invalid taproot sighash type: 0x%02x", hashType)
	}

	// Determine output type for behavior: DEFAULT behaves like ALL
	outputType := hashType & 0x03
	if outputType == SigHashDefault {
		outputType = SigHashAll
	}
	anyoneCanPay := hashType.HasAnyOneCanPay()

	// Epoch (1 byte) - always 0 for taproot
	var preimage bytes.Buffer
	preimage.WriteByte(0x00)

	// hash_type (1 byte) - write the original value, not the mapped one
	preimage.WriteByte(byte(hashType))

	// nVersion (4 bytes LE)
	wire.WriteInt32LE(&preimage, tx.Version)

	// nLockTime (4 bytes LE)
	wire.WriteUint32LE(&preimage, tx.LockTime)

	// If not ANYONECANPAY
	if !anyoneCanPay {
		// sha_prevouts
		var buf bytes.Buffer
		for _, in := range tx.TxIn {
			in.PreviousOutPoint.Serialize(&buf)
		}
		h := sha256.Sum256(buf.Bytes())
		preimage.Write(h[:])

		// sha_amounts
		buf.Reset()
		for _, out := range prevOuts {
			wire.WriteInt64LE(&buf, out.Value)
		}
		h = sha256.Sum256(buf.Bytes())
		preimage.Write(h[:])

		// sha_scriptpubkeys
		buf.Reset()
		for _, out := range prevOuts {
			wire.WriteVarBytes(&buf, out.PkScript)
		}
		h = sha256.Sum256(buf.Bytes())
		preimage.Write(h[:])

		// sha_sequences
		buf.Reset()
		for _, in := range tx.TxIn {
			wire.WriteUint32LE(&buf, in.Sequence)
		}
		h = sha256.Sum256(buf.Bytes())
		preimage.Write(h[:])
	}

	// If not NONE or SINGLE
	if outputType != SigHashNone && outputType != SigHashSingle {
		var buf bytes.Buffer
		for _, out := range tx.TxOut {
			out.Serialize(&buf)
		}
		h := sha256.Sum256(buf.Bytes())
		preimage.Write(h[:])
	}

	// spend_type
	var spendType byte = 0
	if opts != nil && opts.AnnexHash != nil {
		spendType |= 1
	}
	if opts != nil && opts.TapLeafHash != nil {
		spendType |= 2
	}
	preimage.WriteByte(spendType)

	// Input-specific data
	if anyoneCanPay {
		// outpoint
		tx.TxIn[idx].PreviousOutPoint.Serialize(&preimage)
		// amount
		wire.WriteInt64LE(&preimage, prevOuts[idx].Value)
		// scriptPubKey
		wire.WriteVarBytes(&preimage, prevOuts[idx].PkScript)
		// nSequence
		wire.WriteUint32LE(&preimage, tx.TxIn[idx].Sequence)
	} else {
		// input_index (4 bytes LE)
		wire.WriteUint32LE(&preimage, uint32(idx))
	}

	// Annex hash if present
	if opts != nil && opts.AnnexHash != nil {
		preimage.Write(opts.AnnexHash[:])
	}

	// Output specific data for SIGHASH_SINGLE
	if outputType == SigHashSingle {
		if idx >= len(tx.TxOut) {
			return [32]byte{}, ErrInvalidIndex
		}
		var buf bytes.Buffer
		tx.TxOut[idx].Serialize(&buf)
		h := sha256.Sum256(buf.Bytes())
		preimage.Write(h[:])
	}

	// Script path data
	if opts != nil && opts.TapLeafHash != nil {
		preimage.Write(opts.TapLeafHash[:])
		preimage.WriteByte(opts.KeyVersion)
		wire.WriteUint32LE(&preimage, opts.CodeSepPos)
	}

	// Tagged hash: SHA256(SHA256("TapSighash") || SHA256("TapSighash") || preimage)
	return TapSighash(preimage.Bytes()), nil
}

// TapSighash computes the tagged hash for taproot sighash.
func TapSighash(data []byte) [32]byte {
	// BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
	tagHash := sha256.Sum256([]byte("TapSighash"))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(data)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// TapLeaf computes the tagged hash for a taproot leaf.
func TapLeaf(leafVersion byte, script []byte) [32]byte {
	tagHash := sha256.Sum256([]byte("TapLeaf"))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	// Mask leaf version with 0xFE to strip parity bit
	h.Write([]byte{leafVersion & 0xFE})
	// Script with compact size prefix
	var buf bytes.Buffer
	wire.WriteVarBytes(&buf, script)
	h.Write(buf.Bytes())
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// TapBranch computes the tagged hash for a taproot branch.
func TapBranch(left, right [32]byte) [32]byte {
	tagHash := sha256.Sum256([]byte("TapBranch"))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	// Lexicographically sort the two hashes
	if bytes.Compare(left[:], right[:]) < 0 {
		h.Write(left[:])
		h.Write(right[:])
	} else {
		h.Write(right[:])
		h.Write(left[:])
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// TapTweak computes the tagged hash for taproot key tweaking.
func TapTweak(pubKey []byte, merkleRoot []byte) [32]byte {
	tagHash := sha256.Sum256([]byte("TapTweak"))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(pubKey)
	if len(merkleRoot) > 0 {
		h.Write(merkleRoot)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// copyTx creates a deep copy of a transaction.
func copyTx(tx *wire.MsgTx) *wire.MsgTx {
	cp := &wire.MsgTx{
		Version:  tx.Version,
		LockTime: tx.LockTime,
		TxIn:     make([]*wire.TxIn, len(tx.TxIn)),
		TxOut:    make([]*wire.TxOut, len(tx.TxOut)),
	}

	for i, in := range tx.TxIn {
		cp.TxIn[i] = &wire.TxIn{
			PreviousOutPoint: in.PreviousOutPoint,
			SignatureScript:  make([]byte, len(in.SignatureScript)),
			Sequence:         in.Sequence,
		}
		copy(cp.TxIn[i].SignatureScript, in.SignatureScript)
		if len(in.Witness) > 0 {
			cp.TxIn[i].Witness = make([][]byte, len(in.Witness))
			for j, w := range in.Witness {
				cp.TxIn[i].Witness[j] = make([]byte, len(w))
				copy(cp.TxIn[i].Witness[j], w)
			}
		}
	}

	for i, out := range tx.TxOut {
		cp.TxOut[i] = &wire.TxOut{
			Value:    out.Value,
			PkScript: make([]byte, len(out.PkScript)),
		}
		copy(cp.TxOut[i].PkScript, out.PkScript)
	}

	return cp
}

// removeOpCodeSeparators removes all OP_CODESEPARATOR from a script.
func removeOpCodeSeparators(script []byte) []byte {
	result := make([]byte, 0, len(script))
	i := 0
	for i < len(script) {
		op := script[i]
		if op == OP_CODESEPARATOR {
			i++
			continue
		}

		// Handle push operations
		if op >= 0x01 && op <= 0x4b {
			// Direct push
			dataLen := int(op)
			if i+1+dataLen <= len(script) {
				result = append(result, script[i:i+1+dataLen]...)
				i += 1 + dataLen
			} else {
				result = append(result, op)
				i++
			}
		} else if op == OP_PUSHDATA1 && i+1 < len(script) {
			dataLen := int(script[i+1])
			if i+2+dataLen <= len(script) {
				result = append(result, script[i:i+2+dataLen]...)
				i += 2 + dataLen
			} else {
				result = append(result, script[i:i+2]...)
				i += 2
			}
		} else if op == OP_PUSHDATA2 && i+2 < len(script) {
			dataLen := int(script[i+1]) | int(script[i+2])<<8
			if i+3+dataLen <= len(script) {
				result = append(result, script[i:i+3+dataLen]...)
				i += 3 + dataLen
			} else {
				result = append(result, script[i:i+3]...)
				i += 3
			}
		} else if op == OP_PUSHDATA4 && i+4 < len(script) {
			dataLen := int(script[i+1]) | int(script[i+2])<<8 | int(script[i+3])<<16 | int(script[i+4])<<24
			if i+5+dataLen <= len(script) {
				result = append(result, script[i:i+5+dataLen]...)
				i += 5 + dataLen
			} else {
				result = append(result, script[i:i+5]...)
				i += 5
			}
		} else {
			result = append(result, op)
			i++
		}
	}
	return result
}

// FindAndDelete removes all occurrences of a push-encoded signature from scriptCode.
// Only applies to legacy (sig_version BASE) transactions.
func FindAndDelete(script []byte, sig []byte) []byte {
	if len(sig) == 0 {
		return script
	}

	// Build the push encoding of the signature
	var pushSig []byte
	if len(sig) < OP_PUSHDATA1 {
		pushSig = append([]byte{byte(len(sig))}, sig...)
	} else if len(sig) <= 0xff {
		pushSig = append([]byte{OP_PUSHDATA1, byte(len(sig))}, sig...)
	} else if len(sig) <= 0xffff {
		pushSig = append([]byte{OP_PUSHDATA2, byte(len(sig)), byte(len(sig) >> 8)}, sig...)
	} else {
		pushSig = append([]byte{OP_PUSHDATA4, byte(len(sig)), byte(len(sig) >> 8), byte(len(sig) >> 16), byte(len(sig) >> 24)}, sig...)
	}

	// Remove all occurrences
	for {
		idx := bytes.Index(script, pushSig)
		if idx == -1 {
			break
		}
		script = append(script[:idx], script[idx+len(pushSig):]...)
	}

	return script
}
