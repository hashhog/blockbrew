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

// VerifyTaprootCommitment checks that outputKey == internalKey + tweak*G
// where tweak is derived from the internal key and merkle root.
// outputKeyXOnly is the 32-byte x-only output key from the scriptPubKey.
// internalKeyXOnly is the 32-byte x-only internal key from the control block.
// tweakHash is the 32-byte tap tweak hash.
// outputParity is the parity bit from the control block (0 = even, 1 = odd).
func VerifyTaprootCommitment(outputKeyXOnly, internalKeyXOnly []byte, tweakHash [32]byte, outputParity byte) bool {
	if len(outputKeyXOnly) != 32 || len(internalKeyXOnly) != 32 {
		return false
	}

	// Parse the internal key (assume even y for x-only key per BIP340)
	compressedInternal := make([]byte, 33)
	compressedInternal[0] = 0x02
	copy(compressedInternal[1:], internalKeyXOnly)

	internalKey, err := secp256k1.ParsePubKey(compressedInternal)
	if err != nil {
		return false
	}

	// Compute tweak*G
	tweakScalar := new(secp256k1.ModNScalar)
	if tweakScalar.SetByteSlice(tweakHash[:]) {
		// tweakHash overflowed the curve order — invalid
		return false
	}

	// tweakedKey = internalKey + tweak*G
	var tweakPoint secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(tweakScalar, &tweakPoint)

	var internalPoint secp256k1.JacobianPoint
	internalKey.AsJacobian(&internalPoint)

	var resultPoint secp256k1.JacobianPoint
	secp256k1.AddNonConst(&internalPoint, &tweakPoint, &resultPoint)
	resultPoint.ToAffine()

	// Convert result to public key and compare
	resultPubKey := secp256k1.NewPublicKey(&resultPoint.X, &resultPoint.Y)
	resultCompressed := resultPubKey.SerializeCompressed()

	// Check parity matches
	resultParity := resultCompressed[0] - 0x02 // 0=even, 1=odd
	if resultParity != outputParity {
		return false
	}

	// Compare x-coordinates
	resultXOnly := resultCompressed[1:33]
	for i := 0; i < 32; i++ {
		if resultXOnly[i] != outputKeyXOnly[i] {
			return false
		}
	}

	return true
}
