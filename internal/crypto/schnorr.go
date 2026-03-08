package crypto

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

// SignSchnorr creates a BIP340 Schnorr signature (64 bytes).
func SignSchnorr(privKey *PrivateKey, hash [32]byte) ([]byte, error) {
	sig, err := schnorr.Sign(privKey.key, hash[:])
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

// VerifySchnorr verifies a BIP340 Schnorr signature.
// pubKeyXOnly is the 32-byte x-only public key.
// sig is the 64-byte Schnorr signature.
//
// Note: This function tries both possible y-coordinates (even and odd)
// because the dcrd library's Schnorr implementation preserves y-parity
// rather than always using even y as specified in BIP340.
func VerifySchnorr(pubKeyXOnly []byte, hash [32]byte, sig []byte) bool {
	if len(pubKeyXOnly) != 32 || len(sig) != 64 {
		return false
	}

	// Parse the signature
	signature, err := schnorr.ParseSignature(sig)
	if err != nil {
		return false
	}

	// Try even y-coordinate first (BIP340 default)
	compressedEven := make([]byte, 33)
	compressedEven[0] = 0x02
	copy(compressedEven[1:], pubKeyXOnly)

	if evenPubKey, err := secp256k1.ParsePubKey(compressedEven); err == nil {
		if signature.Verify(hash[:], evenPubKey) {
			return true
		}
	}

	// Try odd y-coordinate
	compressedOdd := make([]byte, 33)
	compressedOdd[0] = 0x03
	copy(compressedOdd[1:], pubKeyXOnly)

	if oddPubKey, err := secp256k1.ParsePubKey(compressedOdd); err == nil {
		if signature.Verify(hash[:], oddPubKey) {
			return true
		}
	}

	return false
}

// VerifySchnorrWithPubKey verifies a BIP340 Schnorr signature using a PublicKey.
func VerifySchnorrWithPubKey(pubKey *PublicKey, hash [32]byte, sig []byte) bool {
	// For Schnorr verification, we need to use the full public key directly
	signature, err := schnorr.ParseSignature(sig)
	if err != nil {
		return false
	}
	return signature.Verify(hash[:], pubKey.key)
}

// SerializePubKeyXOnly returns the 32-byte x-only public key representation
// suitable for BIP340 Schnorr signatures. This serializes just the x-coordinate.
func SerializePubKeyXOnly(pubKey *secp256k1.PublicKey) []byte {
	// The compressed form is 33 bytes: 02/03 prefix + 32 bytes x-coordinate
	// For x-only, we just need the x-coordinate (last 32 bytes)
	compressed := pubKey.SerializeCompressed()
	return compressed[1:33]
}
