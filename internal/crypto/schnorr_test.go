package crypto

import (
	"encoding/hex"
	"testing"
)

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
