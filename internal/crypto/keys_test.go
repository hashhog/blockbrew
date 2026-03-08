package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("GeneratePrivateKey returned nil")
	}

	// Verify the key is 32 bytes
	serialized := key.Serialize()
	if len(serialized) != 32 {
		t.Errorf("PrivateKey.Serialize() returned %d bytes, want 32", len(serialized))
	}

	// Verify the key is not all zeros
	allZero := true
	for _, b := range serialized {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Generated private key is all zeros")
	}
}

func TestPrivateKeyFromBytes(t *testing.T) {
	// Use a known private key
	keyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	keyBytes, _ := hex.DecodeString(keyHex)

	key := PrivateKeyFromBytes(keyBytes)
	if key == nil {
		t.Fatal("PrivateKeyFromBytes returned nil")
	}

	// Verify serialization round-trip
	serialized := key.Serialize()
	if !bytes.Equal(serialized, keyBytes) {
		t.Errorf("Key serialization mismatch: got %x, want %x", serialized, keyBytes)
	}
}

func TestPrivateKeyFromBytesInvalidLength(t *testing.T) {
	// Test with wrong length
	key := PrivateKeyFromBytes([]byte{1, 2, 3})
	if key != nil {
		t.Error("PrivateKeyFromBytes should return nil for invalid length")
	}
}

func TestPublicKeyCompressed(t *testing.T) {
	// Use private key = 1, which has a known public key
	keyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	keyBytes, _ := hex.DecodeString(keyHex)
	privKey := PrivateKeyFromBytes(keyBytes)

	pubKey := privKey.PubKey()
	compressed := pubKey.SerializeCompressed()

	// Expected: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
	expected := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	got := hex.EncodeToString(compressed)
	if got != expected {
		t.Errorf("Public key compressed = %s, want %s", got, expected)
	}
}

func TestPublicKeyUncompressed(t *testing.T) {
	keyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	keyBytes, _ := hex.DecodeString(keyHex)
	privKey := PrivateKeyFromBytes(keyBytes)

	pubKey := privKey.PubKey()
	uncompressed := pubKey.SerializeUncompressed()

	// Should be 65 bytes starting with 04
	if len(uncompressed) != 65 {
		t.Errorf("Uncompressed key length = %d, want 65", len(uncompressed))
	}
	if uncompressed[0] != 0x04 {
		t.Errorf("Uncompressed key prefix = %02x, want 04", uncompressed[0])
	}
}

func TestXOnlyPubKey(t *testing.T) {
	keyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	keyBytes, _ := hex.DecodeString(keyHex)
	privKey := PrivateKeyFromBytes(keyBytes)

	pubKey := privKey.PubKey()
	xOnly := pubKey.XOnlyPubKey()

	// Should be 32 bytes (x-coordinate only)
	if len(xOnly) != 32 {
		t.Errorf("X-only public key length = %d, want 32", len(xOnly))
	}

	// Should be the x-coordinate from the compressed key (minus prefix)
	compressed := pubKey.SerializeCompressed()
	if !bytes.Equal(xOnly, compressed[1:]) {
		t.Error("X-only key doesn't match compressed key x-coordinate")
	}
}

func TestKeySerializationRoundTrip(t *testing.T) {
	// Generate a random key
	privKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}

	// Serialize and deserialize
	serialized := privKey.Serialize()
	restored := PrivateKeyFromBytes(serialized)

	// Verify they produce the same public key
	origPub := privKey.PubKey().SerializeCompressed()
	restoredPub := restored.PubKey().SerializeCompressed()
	if !bytes.Equal(origPub, restoredPub) {
		t.Error("Public key mismatch after key round-trip")
	}
}

func TestPublicKeyFromBytes(t *testing.T) {
	// Test parsing a compressed public key
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	pubKeyBytes, _ := hex.DecodeString(pubKeyHex)

	pubKey, err := PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}

	// Re-serialize and compare
	reserialized := pubKey.SerializeCompressed()
	if !bytes.Equal(reserialized, pubKeyBytes) {
		t.Errorf("Public key round-trip failed: got %x, want %x", reserialized, pubKeyBytes)
	}
}

func TestPublicKeyFromBytesUncompressed(t *testing.T) {
	// Generate a key and test parsing its uncompressed form
	privKey, _ := GeneratePrivateKey()
	pubKey := privKey.PubKey()
	uncompressed := pubKey.SerializeUncompressed()

	parsed, err := PublicKeyFromBytes(uncompressed)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes (uncompressed) failed: %v", err)
	}

	// Should produce the same compressed representation
	original := pubKey.SerializeCompressed()
	reparsed := parsed.SerializeCompressed()
	if !bytes.Equal(original, reparsed) {
		t.Error("Public key parsing from uncompressed format failed")
	}
}
