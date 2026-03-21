package crypto

import (
	"crypto/sha256"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
func taggedHash(tag string, msg []byte) [32]byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(msg)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// SignSchnorr creates a BIP340 Schnorr signature (64 bytes).
// This uses a simple deterministic nonce k = tagged_hash("BIP0340/aux", rand) XOR'd
// with the private key, following a simplified version of BIP340.
func SignSchnorr(privKey *PrivateKey, hash [32]byte) ([]byte, error) {
	// Get the private key scalar
	d := privKey.key

	// Ensure the public key has even Y (negate d if needed)
	pubKey := d.PubKey()
	pubCompressed := pubKey.SerializeCompressed()
	if pubCompressed[0] == 0x03 {
		// Negate the private key
		var dScalar secp256k1.ModNScalar
		dScalar.Set(&d.Key)
		dScalar.Negate()
		d = secp256k1.NewPrivateKey(&dScalar)
	}

	pubXOnly := pubCompressed[1:33]

	// Deterministic nonce: k = tagged_hash("BIP0340/nonce", d_bytes || pubXOnly || msg) mod n
	var nonceInput []byte
	dBytes := d.Serialize()
	nonceInput = append(nonceInput, dBytes[:]...)
	nonceInput = append(nonceInput, pubXOnly...)
	nonceInput = append(nonceInput, hash[:]...)
	kHash := taggedHash("BIP0340/nonce", nonceInput)

	var kScalar secp256k1.ModNScalar
	kScalar.SetByteSlice(kHash[:])
	if kScalar.IsZero() {
		// Extremely unlikely but handle it
		kScalar.SetInt(1)
	}

	// R = k*G
	var R secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&kScalar, &R)
	R.ToAffine()

	// If R.y is odd, negate k
	rPubKey := secp256k1.NewPublicKey(&R.X, &R.Y)
	rCompressed := rPubKey.SerializeCompressed()
	if rCompressed[0] == 0x03 {
		kScalar.Negate()
	}
	rXOnly := rCompressed[1:33]

	// e = tagged_hash("BIP0340/challenge", R.x || P || m) mod n
	var challengeInput []byte
	challengeInput = append(challengeInput, rXOnly...)
	challengeInput = append(challengeInput, pubXOnly...)
	challengeInput = append(challengeInput, hash[:]...)
	eHash := taggedHash("BIP0340/challenge", challengeInput)

	var eScalar secp256k1.ModNScalar
	eScalar.SetByteSlice(eHash[:])

	// s = k + e*d mod n
	var dNScalar secp256k1.ModNScalar
	dNScalar.Set(&d.Key)
	eScalar.Mul(&dNScalar)
	sScalar := kScalar
	sScalar.Add(&eScalar)

	// Signature = r_bytes || s_bytes
	sig := make([]byte, 64)
	copy(sig[0:32], rXOnly)
	sBytes := sScalar.Bytes()
	copy(sig[32:64], sBytes[:])

	return sig, nil
}

// VerifySchnorr verifies a BIP340 Schnorr signature.
// pubKeyXOnly is the 32-byte x-only public key.
// hash is the 32-byte message hash.
// sig is the 64-byte Schnorr signature (r || s).
//
// BIP340 verification algorithm:
// 1. P = lift_x(pk) — use even Y
// 2. r = int(sig[0:32]), s = int(sig[32:64])
// 3. e = int(tagged_hash("BIP0340/challenge", r_bytes || P_bytes || m)) mod n
// 4. R = s*G - e*P
// 5. Fail if R is infinite, or R.y is odd, or R.x != r
func VerifySchnorr(pubKeyXOnly []byte, hash [32]byte, sig []byte) bool {
	if len(pubKeyXOnly) != 32 || len(sig) != 64 {
		return false
	}

	// Parse public key as x-only with even Y (BIP340: lift_x)
	compressedPubKey := make([]byte, 33)
	compressedPubKey[0] = 0x02 // even Y
	copy(compressedPubKey[1:], pubKeyXOnly)

	pubKey, err := secp256k1.ParsePubKey(compressedPubKey)
	if err != nil {
		return false
	}

	// Parse r as a field element (first 32 bytes of sig)
	rBytes := sig[0:32]
	var rField secp256k1.FieldVal
	if overflow := rField.SetByteSlice(rBytes); overflow {
		return false
	}

	// Parse s as a scalar (last 32 bytes of sig)
	sBytes := sig[32:64]
	var sScalar secp256k1.ModNScalar
	if overflow := sScalar.SetByteSlice(sBytes); overflow {
		return false
	}

	// Compute e = tagged_hash("BIP0340/challenge", r_bytes || P_bytes || m) mod n
	var challengeInput []byte
	challengeInput = append(challengeInput, rBytes...)
	challengeInput = append(challengeInput, pubKeyXOnly...)
	challengeInput = append(challengeInput, hash[:]...)
	eHash := taggedHash("BIP0340/challenge", challengeInput)

	var eScalar secp256k1.ModNScalar
	eScalar.SetByteSlice(eHash[:])

	// R = s*G - e*P
	// Compute s*G
	var sG secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&sScalar, &sG)

	// Compute e*P
	var eP secp256k1.JacobianPoint
	var P secp256k1.JacobianPoint
	pubKey.AsJacobian(&P)
	secp256k1.ScalarMultNonConst(&eScalar, &P, &eP)

	// Negate e*P to get -e*P
	eP.Y.Negate(1).Normalize()

	// R = s*G + (-e*P) = s*G - e*P
	var R secp256k1.JacobianPoint
	secp256k1.AddNonConst(&sG, &eP, &R)

	// Fail if R is the point at infinity
	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		return false
	}

	// Convert R to affine coordinates
	R.ToAffine()

	// Fail if R.y is odd
	if R.Y.IsOdd() {
		return false
	}

	// Verify R.x == r
	R.X.Normalize()
	rField.Normalize()
	return R.X.Equals(&rField)
}

// VerifySchnorrWithPubKey verifies a BIP340 Schnorr signature using a PublicKey.
func VerifySchnorrWithPubKey(pubKey *PublicKey, hash [32]byte, sig []byte) bool {
	// Extract x-only public key
	xOnly := SerializePubKeyXOnly(pubKey.key)
	return VerifySchnorr(xOnly, hash, sig)
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

// ComputeTaprootOutputKey computes the tweaked output key from an internal key
// and tweak hash. Returns the 32-byte x-only output key and the parity byte
// (0=even, 1=odd).
func ComputeTaprootOutputKey(internalKeyXOnly []byte, tweakHash [32]byte) ([]byte, byte) {
	if len(internalKeyXOnly) != 32 {
		return nil, 0
	}

	// Parse the internal key (assume even y for x-only key per BIP340)
	compressedInternal := make([]byte, 33)
	compressedInternal[0] = 0x02
	copy(compressedInternal[1:], internalKeyXOnly)

	internalKey, err := secp256k1.ParsePubKey(compressedInternal)
	if err != nil {
		return nil, 0
	}

	// Compute tweak*G
	tweakScalar := new(secp256k1.ModNScalar)
	if tweakScalar.SetByteSlice(tweakHash[:]) {
		return nil, 0
	}

	// tweakedKey = internalKey + tweak*G
	var tweakPoint secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(tweakScalar, &tweakPoint)

	var internalPoint secp256k1.JacobianPoint
	internalKey.AsJacobian(&internalPoint)

	var resultPoint secp256k1.JacobianPoint
	secp256k1.AddNonConst(&internalPoint, &tweakPoint, &resultPoint)
	resultPoint.ToAffine()

	resultPubKey := secp256k1.NewPublicKey(&resultPoint.X, &resultPoint.Y)
	resultCompressed := resultPubKey.SerializeCompressed()

	parity := resultCompressed[0] - 0x02
	xOnly := make([]byte, 32)
	copy(xOnly, resultCompressed[1:33])
	return xOnly, parity
}
