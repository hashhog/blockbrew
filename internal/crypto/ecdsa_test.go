package crypto

import (
	"encoding/hex"
	"testing"
)

func TestSignECDSAAndVerify(t *testing.T) {
	// Generate a key
	privKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	pubKey := privKey.PubKey()

	// Create a message hash
	message := []byte("test message")
	hash := DoubleSHA256(message)

	// Sign the hash
	sig, err := SignECDSA(privKey, hash)
	if err != nil {
		t.Fatalf("SignECDSA failed: %v", err)
	}

	// Verify the signature is DER-encoded (starts with 0x30)
	if len(sig) == 0 || sig[0] != 0x30 {
		t.Errorf("Signature doesn't appear to be DER-encoded: %x", sig)
	}

	// Verify the signature
	if !VerifyECDSA(pubKey, hash, sig) {
		t.Error("VerifyECDSA failed for valid signature")
	}
}

func TestVerifyECDSAWrongHash(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	pubKey := privKey.PubKey()

	// Sign a message
	hash := DoubleSHA256([]byte("message 1"))
	sig, err := SignECDSA(privKey, hash)
	if err != nil {
		t.Fatalf("SignECDSA failed: %v", err)
	}

	// Try to verify with a different hash
	wrongHash := DoubleSHA256([]byte("message 2"))
	if VerifyECDSA(pubKey, wrongHash, sig) {
		t.Error("VerifyECDSA should fail for wrong hash")
	}
}

func TestVerifyECDSAWrongKey(t *testing.T) {
	privKey1, _ := GeneratePrivateKey()
	privKey2, _ := GeneratePrivateKey()
	pubKey2 := privKey2.PubKey()

	// Sign with key 1
	hash := DoubleSHA256([]byte("test"))
	sig, _ := SignECDSA(privKey1, hash)

	// Try to verify with key 2
	if VerifyECDSA(pubKey2, hash, sig) {
		t.Error("VerifyECDSA should fail for wrong public key")
	}
}

func TestVerifyECDSAInvalidSignature(t *testing.T) {
	privKey, _ := GeneratePrivateKey()
	pubKey := privKey.PubKey()
	hash := DoubleSHA256([]byte("test"))

	// Invalid signature
	invalidSig := []byte{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}
	if VerifyECDSA(pubKey, hash, invalidSig) {
		t.Error("VerifyECDSA should fail for invalid signature")
	}
}

func TestVerifyECDSAMalformedSignature(t *testing.T) {
	privKey, _ := GeneratePrivateKey()
	pubKey := privKey.PubKey()
	hash := DoubleSHA256([]byte("test"))

	// Malformed signature (not DER)
	malformed := []byte{0x01, 0x02, 0x03}
	if VerifyECDSA(pubKey, hash, malformed) {
		t.Error("VerifyECDSA should fail for malformed signature")
	}
}

func TestECDSASignatureDeterminism(t *testing.T) {
	// RFC 6979 requires deterministic signatures
	// Same key + same hash should produce the same signature
	keyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	keyBytes, _ := hex.DecodeString(keyHex)
	privKey := PrivateKeyFromBytes(keyBytes)

	hash := DoubleSHA256([]byte("deterministic test"))

	sig1, _ := SignECDSA(privKey, hash)
	sig2, _ := SignECDSA(privKey, hash)

	// With RFC 6979, signatures should be identical
	if hex.EncodeToString(sig1) != hex.EncodeToString(sig2) {
		t.Error("ECDSA signatures should be deterministic (RFC 6979)")
	}
}

func TestSignECDSACompact(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}

	hash := DoubleSHA256([]byte("test message"))
	sig := SignECDSACompact(privKey, hash)

	// Compact signature should be 64 bytes (32 for R, 32 for S)
	if len(sig) != 64 {
		t.Errorf("Compact signature length = %d, want 64", len(sig))
	}
}

func TestMultipleSignVerifyCycles(t *testing.T) {
	// Run multiple sign/verify cycles to ensure consistency
	privKey, _ := GeneratePrivateKey()
	pubKey := privKey.PubKey()

	for i := 0; i < 10; i++ {
		msg := []byte{byte(i), byte(i + 1), byte(i + 2)}
		hash := DoubleSHA256(msg)
		sig, err := SignECDSA(privKey, hash)
		if err != nil {
			t.Fatalf("SignECDSA failed on iteration %d: %v", i, err)
		}
		if !VerifyECDSA(pubKey, hash, sig) {
			t.Errorf("VerifyECDSA failed on iteration %d", i)
		}
	}
}
