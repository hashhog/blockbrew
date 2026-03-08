package crypto

import (
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
