package crypto

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// SignECDSA signs a 32-byte hash with the private key, returning a DER-encoded signature.
// The signature is normalized to low-S form per BIP62.
func SignECDSA(privKey *PrivateKey, hash [32]byte) ([]byte, error) {
	// Sign the hash - this produces a signature that is already normalized to low-S
	sig := ecdsa.Sign(privKey.key, hash[:])
	return sig.Serialize(), nil
}

// VerifyECDSA verifies a DER-encoded ECDSA signature against a public key and hash.
func VerifyECDSA(pubKey *PublicKey, hash [32]byte, sig []byte) bool {
	// Parse the DER-encoded signature
	signature, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		return false
	}
	return signature.Verify(hash[:], pubKey.key)
}

// SignECDSACompact signs a 32-byte hash and returns a 64-byte compact signature (R || S).
func SignECDSACompact(privKey *PrivateKey, hash [32]byte) []byte {
	sig := ecdsa.Sign(privKey.key, hash[:])
	r := sig.R()
	s := sig.S()
	var rBytes, sBytes [32]byte
	r.PutBytesUnchecked(rBytes[:])
	s.PutBytesUnchecked(sBytes[:])
	result := make([]byte, 64)
	copy(result[:32], rBytes[:])
	copy(result[32:], sBytes[:])
	return result
}

// ParseDERSignature parses a DER-encoded ECDSA signature.
func ParseDERSignature(sig []byte) (*secp256k1.ModNScalar, *secp256k1.ModNScalar, error) {
	signature, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		return nil, nil, err
	}
	r := signature.R()
	s := signature.S()
	return &r, &s, nil
}

// secp256k1 curve order N
var curveN, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

// halfN is N/2, used for low-S normalization
var halfN = new(big.Int).Rsh(curveN, 1)

// parseAndNormalizeECDSA runs Bitcoin Core's lax-DER parse over sig, checks
// that R and S are in [1, N-1], and normalizes S to low-S form.  It returns
// the 32-byte big-endian R and S ready to feed a compact verifier, or
// ok=false if the signature is malformed or out of range.  This is the
// shared front-end for both the libsecp256k1 (VerifyECDSALax) and dcrec
// (verifyECDSALaxDcrec) back-ends so their accept/reject behaviour is
// identical up to the final curve-math step.
func parseAndNormalizeECDSA(sig []byte) (rPad, sPad [32]byte, ok bool) {
	rBytes, sBytes, parsed := parseDERLax(sig)
	if !parsed {
		return rPad, sPad, false
	}

	rInt := new(big.Int).SetBytes(rBytes)
	sInt := new(big.Int).SetBytes(sBytes)

	// R and S must be in [1, N-1]
	if rInt.Sign() <= 0 || rInt.Cmp(curveN) >= 0 {
		return rPad, sPad, false
	}
	if sInt.Sign() <= 0 || sInt.Cmp(curveN) >= 0 {
		return rPad, sPad, false
	}

	// Normalize S to low-S form
	if sInt.Cmp(halfN) > 0 {
		sInt.Sub(curveN, sInt)
	}

	rB := rInt.Bytes()
	sB := sInt.Bytes()
	copy(rPad[32-len(rB):], rB)
	copy(sPad[32-len(sB):], sB)
	return rPad, sPad, true
}

// VerifyECDSALax verifies a DER-encoded ECDSA signature using a lax DER parser.
// This accepts signatures that Bitcoin Core's OpenSSL-era parser accepted but
// that strict DER parsing rejects (e.g. extra padding, wrong sequence length).
//
// Backend: libsecp256k1 secp256k1_ecdsa_verify (Bitcoin Core's consensus
// engine).  The lax-DER parse and low-S normalization are done in Go
// (parseAndNormalizeECDSA) because libsecp256k1 has no lax-DER parser;
// feeding its strict parser here would change the accept set.  Verified
// bit-identical to the dcrec reference (verifyECDSALaxDcrec) over the
// differential corpus in libsecp_diff_test.go.
func VerifyECDSALax(pubKey *PublicKey, hash [32]byte, sig []byte) bool {
	rPad, sPad, ok := parseAndNormalizeECDSA(sig)
	if !ok {
		return false
	}

	var compact [64]byte
	copy(compact[0:32], rPad[:])
	copy(compact[32:64], sPad[:])

	// A valid dcrec-parsed point round-trips through the uncompressed SEC
	// encoding and secp256k1_ec_pubkey_parse without loss, so libsecp256k1
	// verifies against the identical curve point.
	return ecdsaVerifyCompactLibsecp(pubKey.key.SerializeUncompressed(), hash[:], compact[:])
}

// verifyECDSALaxDcrec is the pure-Go dcrec reference implementation of
// VerifyECDSALax, retained as the oracle for the differential-equivalence
// test (libsecp_diff_test.go) and as a fallback if the cgo backend is ever
// disabled.  It shares parseAndNormalizeECDSA with the libsecp path so the
// only behavioural difference under test is the final curve-math step.
func verifyECDSALaxDcrec(pubKey *PublicKey, hash [32]byte, sig []byte) bool {
	rPad, sPad, ok := parseAndNormalizeECDSA(sig)
	if !ok {
		return false
	}

	var rScalar, sScalar secp256k1.ModNScalar
	if rScalar.SetBytes(&rPad) != 0 {
		return false
	}
	if sScalar.SetBytes(&sPad) != 0 {
		return false
	}

	sig2 := ecdsa.NewSignature(&rScalar, &sScalar)
	return sig2.Verify(hash[:], pubKey.key)
}

// parseDERLax laxly parses a DER-encoded signature, returning R and S as byte slices.
// This mirrors Bitcoin Core's ecdsa_signature_parse_der_lax from pubkey.cpp.
func parseDERLax(sig []byte) (r, s []byte, ok bool) {
	if len(sig) < 1 {
		return nil, nil, false
	}
	pos := 0

	// Sequence tag
	if sig[pos] != 0x30 {
		return nil, nil, false
	}
	pos++

	// Sequence length (skip, don't validate)
	if pos >= len(sig) {
		return nil, nil, false
	}
	lenByte := sig[pos]
	pos++
	if lenByte&0x80 != 0 {
		// Long form length — skip the length bytes
		nLenBytes := int(lenByte & 0x7f)
		pos += nLenBytes
	}

	// R integer
	r, pos, ok = parseDERInt(sig, pos)
	if !ok {
		return nil, nil, false
	}

	// S integer
	s, pos, ok = parseDERInt(sig, pos)
	if !ok {
		return nil, nil, false
	}
	_ = pos

	return r, s, true
}

// parseDERInt parses one DER integer element starting at pos.
func parseDERInt(sig []byte, pos int) (val []byte, newPos int, ok bool) {
	if pos >= len(sig) || sig[pos] != 0x02 {
		return nil, pos, false
	}
	pos++

	if pos >= len(sig) {
		return nil, pos, false
	}

	// Parse length
	var length int
	lenByte := sig[pos]
	pos++
	if lenByte&0x80 != 0 {
		// Long form
		nLenBytes := int(lenByte & 0x7f)
		if nLenBytes > 4 || pos+nLenBytes > len(sig) {
			return nil, pos, false
		}
		for i := 0; i < nLenBytes; i++ {
			length = (length << 8) | int(sig[pos])
			pos++
		}
	} else {
		length = int(lenByte)
	}

	if length <= 0 || pos+length > len(sig) {
		return nil, pos, false
	}

	valBytes := sig[pos : pos+length]
	pos += length

	// Strip leading zeros (but keep at least one byte for the value)
	for len(valBytes) > 1 && valBytes[0] == 0x00 {
		valBytes = valBytes[1:]
	}

	// If top bit set after stripping zeros, it was a padding zero for sign — that's fine,
	// the value is just what remains
	return valBytes, pos, true
}
