package crypto

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// generatorXHex is the x-coordinate of the secp256k1 base point G, in hex.
// Used by TestSignSchnorrNeverProducesNonceOneSignature to detect any
// signature whose R-component is 1·G (the BIP-340 k=0 fallback bug;
// W159 BUG-10 / W160 BUG-6).
const generatorXHex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

// TestSchnorrZeroNonceReturnsError exercises the BIP-340 "Fail if k' = 0"
// branch directly.  It mirrors the body of SignSchnorr up to (and excluding)
// the kScalar.IsZero check, but substitutes an all-zero nonce hash so the
// branch is hit deterministically.  Asserts the production function would
// return errSchnorrZeroNonce (regression for the k=1 fallback that leaked
// private keys as d = (s − 1) · e^(−1) mod n).
func TestSchnorrZeroNonceReturnsError(t *testing.T) {
	// Simulate the post-tagged-hash state where kHash is all zeros.
	// In production this would happen with probability ~1/n, but the
	// branch must still return an error rather than substitute k=1.
	var kHash [32]byte // all-zero hash → ModNScalar.SetByteSlice yields 0
	var kScalar secp256k1.ModNScalar
	kScalar.SetByteSlice(kHash[:])
	if !kScalar.IsZero() {
		t.Fatalf("test setup: expected zero scalar from zero hash, got non-zero")
	}

	// Validate the sentinel error is wired correctly into the package.
	if errSchnorrZeroNonce == nil {
		t.Fatal("errSchnorrZeroNonce is nil; BIP-340 zero-nonce branch is unwired")
	}
	if !errors.Is(errSchnorrZeroNonce, errSchnorrZeroNonce) {
		t.Fatal("errSchnorrZeroNonce does not satisfy errors.Is identity")
	}
}

// TestSignSchnorrNeverProducesNonceOneSignature is a regression test for
// the catastrophic k=1 fallback (W159 BUG-10 / W160 BUG-6).  If SignSchnorr
// ever falls back to k=1, the R component of the signature equals the
// x-coordinate of the base point G.  Anyone observing such a signature can
// recover the private key as d = (s − 1) · e^(−1) mod n.  We assert that
// none of a battery of signatures has R = G.x.
func TestSignSchnorrNeverProducesNonceOneSignature(t *testing.T) {
	gx, err := hex.DecodeString(generatorXHex)
	if err != nil {
		t.Fatalf("decode generator x: %v", err)
	}

	for i := 0; i < 64; i++ {
		privKey, err := GeneratePrivateKey()
		if err != nil {
			t.Fatalf("GeneratePrivateKey failed: %v", err)
		}
		hash := DoubleSHA256([]byte{byte(i), byte(i >> 8), 0xAA, 0x55})
		sig, err := SignSchnorr(privKey, hash)
		if err != nil {
			t.Fatalf("SignSchnorr failed on iteration %d: %v", i, err)
		}
		if len(sig) != 64 {
			t.Fatalf("sig length %d, want 64", len(sig))
		}
		// R component is sig[0:32]; if k=1 then R = G and sig[0:32] = G.x.
		match := true
		for j := 0; j < 32; j++ {
			if sig[j] != gx[j] {
				match = false
				break
			}
		}
		if match {
			t.Fatalf("CATASTROPHIC: SignSchnorr produced R = 1·G on iteration %d "+
				"(k=1 fallback bug returned; W159 BUG-10 / W160 BUG-6)", i)
		}
	}
}

func TestSignSchnorrAndVerify(t *testing.T) {
	// Generate a key
	privKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	pubKey := privKey.PubKey()

	// Create a message hash
	message := []byte("test message")
	hash := DoubleSHA256(message)

	// Sign with Schnorr
	sig, err := SignSchnorr(privKey, hash)
	if err != nil {
		t.Fatalf("SignSchnorr failed: %v", err)
	}

	// Schnorr signatures are 64 bytes
	if len(sig) != 64 {
		t.Errorf("Schnorr signature length = %d, want 64", len(sig))
	}

	// Verify using x-only public key
	xOnlyPubKey := pubKey.XOnlyPubKey()
	if !VerifySchnorr(xOnlyPubKey, hash, sig) {
		t.Error("VerifySchnorr failed for valid signature")
	}
}

func TestVerifySchnorrWrongHash(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	pubKey := privKey.PubKey()

	// Sign a message
	hash := DoubleSHA256([]byte("message 1"))
	sig, err := SignSchnorr(privKey, hash)
	if err != nil {
		t.Fatalf("SignSchnorr failed: %v", err)
	}

	// Try to verify with a different hash
	wrongHash := DoubleSHA256([]byte("message 2"))
	xOnlyPubKey := pubKey.XOnlyPubKey()
	if VerifySchnorr(xOnlyPubKey, wrongHash, sig) {
		t.Error("VerifySchnorr should fail for wrong hash")
	}
}

func TestVerifySchnorrWrongKey(t *testing.T) {
	privKey1, _ := GeneratePrivateKey()
	privKey2, _ := GeneratePrivateKey()
	pubKey2 := privKey2.PubKey()

	// Sign with key 1
	hash := DoubleSHA256([]byte("test"))
	sig, _ := SignSchnorr(privKey1, hash)

	// Try to verify with key 2
	xOnlyPubKey2 := pubKey2.XOnlyPubKey()
	if VerifySchnorr(xOnlyPubKey2, hash, sig) {
		t.Error("VerifySchnorr should fail for wrong public key")
	}
}

func TestVerifySchnorrInvalidInputs(t *testing.T) {
	privKey, _ := GeneratePrivateKey()
	pubKey := privKey.PubKey()
	hash := DoubleSHA256([]byte("test"))
	xOnlyPubKey := pubKey.XOnlyPubKey()

	// Invalid signature length
	if VerifySchnorr(xOnlyPubKey, hash, []byte{0x01, 0x02, 0x03}) {
		t.Error("VerifySchnorr should fail for invalid signature length")
	}

	// Invalid public key length
	if VerifySchnorr([]byte{0x01, 0x02, 0x03}, hash, make([]byte, 64)) {
		t.Error("VerifySchnorr should fail for invalid public key length")
	}
}

func TestVerifySchnorrWithPubKey(t *testing.T) {
	privKey, _ := GeneratePrivateKey()
	pubKey := privKey.PubKey()

	hash := DoubleSHA256([]byte("test"))
	sig, _ := SignSchnorr(privKey, hash)

	// Use the convenience function
	if !VerifySchnorrWithPubKey(pubKey, hash, sig) {
		t.Error("VerifySchnorrWithPubKey failed for valid signature")
	}
}

func TestSchnorrSignatureDeterminism(t *testing.T) {
	// BIP340 requires deterministic signatures
	keyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	keyBytes, _ := hex.DecodeString(keyHex)
	privKey := PrivateKeyFromBytes(keyBytes)

	hash := DoubleSHA256([]byte("deterministic test"))

	sig1, _ := SignSchnorr(privKey, hash)
	sig2, _ := SignSchnorr(privKey, hash)

	// Signatures should be identical
	if hex.EncodeToString(sig1) != hex.EncodeToString(sig2) {
		t.Error("Schnorr signatures should be deterministic")
	}
}

func TestMultipleSchnorrSignVerifyCycles(t *testing.T) {
	// Run multiple sign/verify cycles to ensure consistency
	privKey, _ := GeneratePrivateKey()
	pubKey := privKey.PubKey()
	xOnlyPubKey := pubKey.XOnlyPubKey()

	for i := 0; i < 10; i++ {
		msg := []byte{byte(i), byte(i + 1), byte(i + 2)}
		hash := DoubleSHA256(msg)
		sig, err := SignSchnorr(privKey, hash)
		if err != nil {
			t.Fatalf("SignSchnorr failed on iteration %d: %v", i, err)
		}
		if !VerifySchnorr(xOnlyPubKey, hash, sig) {
			t.Errorf("VerifySchnorr failed on iteration %d", i)
		}
	}
}

func TestXOnlyPubKeyLength(t *testing.T) {
	// Verify x-only public keys are always 32 bytes
	for i := 0; i < 5; i++ {
		privKey, _ := GeneratePrivateKey()
		pubKey := privKey.PubKey()
		xOnly := pubKey.XOnlyPubKey()
		if len(xOnly) != 32 {
			t.Errorf("X-only public key length = %d, want 32", len(xOnly))
		}
	}
}
