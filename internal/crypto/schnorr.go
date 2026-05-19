package crypto

import (
	"crypto/sha256"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// errSchnorrZeroNonce is returned by SignSchnorr when BIP-340 RFC-6979 nonce
// derivation yields k' = 0.  BIP-340 mandates failure in this case; the prior
// silent fallback to k = 1 produced fixed-nonce signatures that leak the
// private key as d = (s − 1) · e^(−1) mod n.  W159 BUG-10 / W160 BUG-6.
var errSchnorrZeroNonce = errors.New("schnorr: BIP-340 nonce derivation yielded zero")

// W95 — BIP-340 Schnorr + tagged-hash audit (vs. Bitcoin Core's
// secp256k1/src/modules/schnorrsig/main_impl.h).
//
// Gate map (Core reference -> this file):
//   G1  sig length == 64 (verify) / 64-or-65 (consensus call-site)
//   G2  rx < p                    -> verify, line ~ rFieldOverflow check
//   G3  s  < n                    -> verify, ModNScalar.SetByteSlice overflow
//   G4  xonly pubkey lift_x even-Y -> verify, 0x02 prefix + dcrec ParsePubKey
//   G5  tagged hash =
//         SHA256(SHA256(tag) || SHA256(tag) || data)
//   G6  e  = int(tagged_hash("BIP0340/challenge", rx || P || m)) mod n
//   G7  R  = sG - eP    (computed as sG + neg(eP))
//   G8  reject R == infinity (Jacobian Z == 0)
//   G9  reject R.y odd
//   G10 require R.x == rx (both normalized)
//   G11 64-vs-65-byte sig parsing belongs to the script-engine call-site,
//       which strips the optional sighash byte before this fn is called
//       (interpreter.cpp:1726-1734).  This file rejects all sig.len != 64.
//   G12 hashtype range check (interpreter.cpp:1516) is enforced inside
//       CalcTaprootSignatureHash (sighash.go), which runs BEFORE we call
//       VerifySchnorr in tap-key / tap-script paths.

// ---------------------------------------------------------------------------
// Tagged hash with precomputed midstate prefix.
//
// Core caches the SHA256 midstate after consuming the 64-byte
// SHA256(tag)||SHA256(tag) prefix; we cache the 64-byte prefix itself and
// hash prefix||data with a single SHA256.New() instance per call.  This
// removes 2 SHA256-of-short-string invocations per Schnorr verify, which at
// ~10k schnorrsig verifies per modern block is a real IBD win.
//
// The values below are pre-derived as SHA256(tag) || SHA256(tag).  They are
// independently verifiable from BIP-340: see TestTaggedHashPrecomputed.

var (
	tagPrefixBIP0340Challenge = mustHexBIP340(
		"7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c" +
			"7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c")
	tagPrefixBIP0340Nonce = mustHexBIP340(
		"07497734a79bcb355b9b8c7d034f121cf434d73ef72dda19870061fb52bfeb2f" +
			"07497734a79bcb355b9b8c7d034f121cf434d73ef72dda19870061fb52bfeb2f")
	tagPrefixBIP0340Aux = mustHexBIP340(
		"f1ef4e5ec063cada6d94cafa9d987ea069265839ecc11f972d77a52ed8c1cc90" +
			"f1ef4e5ec063cada6d94cafa9d987ea069265839ecc11f972d77a52ed8c1cc90")
)

// mustHexBIP340 decodes a hex literal at package-init time; panics on
// malformed input.  Used only for the precomputed tag-prefix constants
// above.  Named distinctly from the test-only mustHex helper to avoid a
// collision in package crypto's test build.
func mustHexBIP340(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := bip340HexNibble(s[2*i])
		lo := bip340HexNibble(s[2*i+1])
		out[i] = (hi << 4) | lo
	}
	return out
}

func bip340HexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	panic("bad hex nibble in precomputed BIP-340 tag prefix")
}

// taggedHashWithPrefix computes SHA256(prefix || data) where prefix is the
// 64-byte SHA256(tag)||SHA256(tag) prefix as in BIP-340 §3.  Use one of the
// precomputed tagPrefix* constants for hot-path callers.
func taggedHashWithPrefix(prefix, data []byte) [32]byte {
	h := sha256.New()
	h.Write(prefix)
	h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// taggedHash computes the BIP-340 tagged hash
// SHA256(SHA256(tag) || SHA256(tag) || data).  Kept for callers that pass an
// arbitrary tag string; hot paths should use taggedHashWithPrefix with one
// of the precomputed prefixes above.
func taggedHash(tag string, data []byte) [32]byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// ---------------------------------------------------------------------------
// Signing
//
// Core does NOT use blockbrew's SignSchnorr for consensus, but wallet+psbt
// paths do, so we want the output to be byte-identical to libsecp256k1 when
// no aux_rand is supplied.  BIP-340 spec:
//
//   t   = bytes(d) XOR hash_aux(aux_rand)
//   k'  = hash_nonce(t || bytes(P) || m) mod n
//
// where hash_aux is the "BIP0340/aux" tagged hash.  With aux_rand absent
// (our API), aux_rand is treated as 32 zero bytes, and so t is masked with
// the fixed value tagged_hash("BIP0340/aux", zeros32) — the ZERO_MASK from
// Core's main_impl.h:70-74.
//
// Prior to W95 the implementation skipped this XOR entirely, producing
// valid signatures (verification still succeeds) but ones that diverge
// byte-for-byte from libsecp256k1's output — which prevents byte-identity
// against Core for the wallet's "sign deterministically with no aux_rand"
// path.

// zeroAuxMask is the precomputed value of
//
//	tagged_hash("BIP0340/aux", [32]byte{})  // 32 zero bytes
//
// also visible as ZERO_MASK in libsecp256k1
// (secp256k1/src/modules/schnorrsig/main_impl.h:70-75).  Derived once here
// and asserted equivalent to the on-the-fly computation in
// TestSchnorrZeroAuxMask.
var zeroAuxMask = func() [32]byte {
	var z [32]byte
	return taggedHashWithPrefix(tagPrefixBIP0340Aux, z[:])
}()

// SignSchnorr creates a BIP-340 Schnorr signature (64 bytes) using a
// no-aux-rand deterministic nonce derivation.  Output is byte-identical to
// libsecp256k1's secp256k1_schnorrsig_sign32(..., aux_rand32=NULL).
func SignSchnorr(privKey *PrivateKey, hash [32]byte) ([]byte, error) {
	// Get the private key scalar.
	d := privKey.key

	// Ensure the public key has even Y (negate d if needed) — BIP-340 step:
	// "Let P = d_secret*G.  Let d = d_secret if has_even_y(P), otherwise let
	// d = n - d_secret".
	pubKey := d.PubKey()
	pubCompressed := pubKey.SerializeCompressed()
	if pubCompressed[0] == 0x03 {
		var dScalar secp256k1.ModNScalar
		dScalar.Set(&d.Key)
		dScalar.Negate()
		d = secp256k1.NewPrivateKey(&dScalar)
	}

	pubXOnly := pubCompressed[1:33]
	dBytes := d.Serialize()

	// W95: BIP-340 nonce derivation — mask d with hash_aux(aux_rand).
	// With no aux_rand, aux_rand is 32 zero bytes, so the mask is the fixed
	// zeroAuxMask constant.  Without this XOR, signatures verify but are
	// not byte-identical to libsecp256k1.
	var maskedKey [32]byte
	for i := 0; i < 32; i++ {
		maskedKey[i] = dBytes[i] ^ zeroAuxMask[i]
	}

	// Deterministic nonce: k = tagged_hash("BIP0340/nonce", t || P || m) mod n
	nonceInput := make([]byte, 0, 32+32+32)
	nonceInput = append(nonceInput, maskedKey[:]...)
	nonceInput = append(nonceInput, pubXOnly...)
	nonceInput = append(nonceInput, hash[:]...)
	kHash := taggedHashWithPrefix(tagPrefixBIP0340Nonce, nonceInput)

	var kScalar secp256k1.ModNScalar
	kScalar.SetByteSlice(kHash[:])
	if kScalar.IsZero() {
		// BIP-340 mandates "Fail if k' = 0".  The prior fallback
		// (kScalar.SetInt(1)) was catastrophic: with k=1, R = 1·G is a
		// fixed point and s = 1 + e·d trivially reveals
		// d = (s − 1) · e^(−1) mod n to any observer of the signature.
		// libsecp256k1 (Bitcoin Core reference: secp256k1/src/modules/
		// schnorrsig/main_impl.h) also returns 0 (failure) in this case.
		// W159 BUG-10 / W160 BUG-6.
		return nil, errSchnorrZeroNonce
	}

	// R = k*G
	var R secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&kScalar, &R)
	R.ToAffine()

	// If R.y is odd, negate k (BIP-340: "Let k = k' if has_even_y(R), else k = n - k'").
	rPubKey := secp256k1.NewPublicKey(&R.X, &R.Y)
	rCompressed := rPubKey.SerializeCompressed()
	if rCompressed[0] == 0x03 {
		kScalar.Negate()
	}
	rXOnly := rCompressed[1:33]

	// e = tagged_hash("BIP0340/challenge", R.x || P || m) mod n
	challengeInput := make([]byte, 0, 32+32+32)
	challengeInput = append(challengeInput, rXOnly...)
	challengeInput = append(challengeInput, pubXOnly...)
	challengeInput = append(challengeInput, hash[:]...)
	eHash := taggedHashWithPrefix(tagPrefixBIP0340Challenge, challengeInput)

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

// ---------------------------------------------------------------------------
// Verification
//
// BIP-340 verification algorithm (one signature):
//   1. Fail if mlen != 32  (Bitcoin convention; lib supports variable mlen)
//   2. Let P = lift_x(int(pk)).  Fail if that does not yield a point.
//   3. Let r = int(sig[0:32]); fail if r >= p.
//   4. Let s = int(sig[32:64]); fail if s >= n.
//   5. Let e = int(hash_BIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
//   6. Let R = s*G - e*P.
//   7. Fail if not has_even_y(R).
//   8. Fail if x(R) != r.
//   9. Return success iff signature passes all checks.

// VerifySchnorr verifies a BIP-340 Schnorr signature with a 32-byte message
// (the Bitcoin sighash case).  pubKeyXOnly is the 32-byte x-only public
// key, hash is the 32-byte message, sig must be exactly 64 bytes (callers
// that handle the 65-byte sighash-byte form must strip it first; this is
// what the script engine does in opcodes_impl.go).
func VerifySchnorr(pubKeyXOnly []byte, hash [32]byte, sig []byte) bool {
	return VerifySchnorrMsg(pubKeyXOnly, hash[:], sig)
}

// VerifySchnorrMsg verifies a BIP-340 Schnorr signature with a
// variable-length message, as the BIP-340 spec allows.  Bitcoin's
// taproot/tapscript paths always pass a 32-byte sighash, but the BIP-340
// test vector file (added 2022-12) includes 0/1/17/100-byte messages too
// and we want to be able to run those against this implementation.
func VerifySchnorrMsg(pubKeyXOnly []byte, msg []byte, sig []byte) bool {
	// G1 — sig length must be exactly 64.  The optional sighash-byte form
	// (65 bytes) is split off by the caller before reaching this function.
	if len(pubKeyXOnly) != 32 || len(sig) != 64 {
		return false
	}

	// G4 — Parse public key as x-only with even Y (BIP340: lift_x).
	// dcrec's ParsePubKey enforces both x < p and on-curve, returning an
	// error if neither y-parity yields a point on the curve.
	compressedPubKey := make([]byte, 33)
	compressedPubKey[0] = 0x02 // even Y
	copy(compressedPubKey[1:], pubKeyXOnly)

	pubKey, err := secp256k1.ParsePubKey(compressedPubKey)
	if err != nil {
		return false
	}

	// G2 — Parse r as a field element (first 32 bytes of sig); reject if
	// r >= p.  dcrec's FieldVal.SetByteSlice returns true on overflow.
	rBytes := sig[0:32]
	var rField secp256k1.FieldVal
	if overflow := rField.SetByteSlice(rBytes); overflow {
		return false
	}

	// G3 — Parse s as a scalar (last 32 bytes of sig); reject if s >= n.
	// dcrec's ModNScalar.SetByteSlice reduces mod n and returns true if
	// reduction was required (i.e., the input was >= n).
	sBytes := sig[32:64]
	var sScalar secp256k1.ModNScalar
	if overflow := sScalar.SetByteSlice(sBytes); overflow {
		return false
	}

	// G5+G6 — e = tagged_hash("BIP0340/challenge", r || P || m) mod n.
	// Uses the precomputed prefix to avoid two SHA256-of-short-string
	// invocations per verify.
	challengeInput := make([]byte, 0, 64+len(msg))
	challengeInput = append(challengeInput, rBytes...)
	challengeInput = append(challengeInput, pubKeyXOnly...)
	challengeInput = append(challengeInput, msg...)
	eHash := taggedHashWithPrefix(tagPrefixBIP0340Challenge, challengeInput)

	var eScalar secp256k1.ModNScalar
	eScalar.SetByteSlice(eHash[:])

	// G7 — Compute R = s*G - e*P, via R = s*G + neg(e*P).
	//
	// We negate the point e*P rather than the scalar e because dcrec
	// exposes a constant-time scalar-mult-by-point API that is convenient
	// for the s*G + neg(e*P) form.  Equivalent to Core's
	// secp256k1_scalar_negate(&e) + secp256k1_ecmult(&rj, &pkj, &e, &s).
	var sG secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&sScalar, &sG)

	var eP, P secp256k1.JacobianPoint
	pubKey.AsJacobian(&P)
	secp256k1.ScalarMultNonConst(&eScalar, &P, &eP)

	// neg(eP): in Jacobian (X, Y, Z), the negation is (X, -Y, Z).
	// Negate(1) requires the input Y to be magnitude <=1; ScalarMultNonConst
	// guarantees the output point is normalized, so this precondition holds.
	eP.Y.Negate(1).Normalize()

	var R secp256k1.JacobianPoint
	secp256k1.AddNonConst(&sG, &eP, &R)

	// G8 — Reject R == point at infinity.  dcrec's AddNonConst marks
	// infinity as Z=0 (and additionally sets X=Y=0); we test Z=0 which is
	// the canonical Jacobian-infinity predicate.
	if R.Z.IsZero() {
		return false
	}

	// Convert R to affine coordinates so we can compare R.x with rx and
	// inspect the parity of R.y.
	R.ToAffine()

	// G9 — Reject if R.y is odd.
	if R.Y.IsOdd() {
		return false
	}

	// G10 — Require R.x == rx.  Normalize both before comparison; rField
	// was normalized on entry by SetByteSlice (Output Normalized: Yes if no
	// overflow, per dcrec docs), but ToAffine may not normalize, so do it
	// explicitly.
	R.X.Normalize()
	rField.Normalize()
	return R.X.Equals(&rField)
}

// VerifySchnorrWithPubKey verifies a BIP-340 Schnorr signature using a
// PublicKey (32-byte sighash convenience).
func VerifySchnorrWithPubKey(pubKey *PublicKey, hash [32]byte, sig []byte) bool {
	xOnly := SerializePubKeyXOnly(pubKey.key)
	return VerifySchnorr(xOnly, hash, sig)
}

// SerializePubKeyXOnly returns the 32-byte x-only public key representation
// suitable for BIP-340 Schnorr signatures — i.e., just the x-coordinate
// from the compressed (33-byte) encoding.
func SerializePubKeyXOnly(pubKey *secp256k1.PublicKey) []byte {
	compressed := pubKey.SerializeCompressed()
	return compressed[1:33]
}

// ---------------------------------------------------------------------------
// Taproot output-key tweaking (BIP-341 §3).  Kept here so the audit
// boundary for the BIP-340 family stays in one file.

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
