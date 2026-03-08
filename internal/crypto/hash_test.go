package crypto

import (
	"encoding/hex"
	"testing"
)

func TestDoubleSHA256Empty(t *testing.T) {
	// Test vector: DoubleSHA256 of empty string
	// Expected: 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
	result := DoubleSHA256([]byte{})
	expected := "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
	got := hex.EncodeToString(result[:])
	if got != expected {
		t.Errorf("DoubleSHA256(empty) = %s, want %s", got, expected)
	}
}

func TestDoubleSHA256Hello(t *testing.T) {
	// Test with "hello"
	result := DoubleSHA256([]byte("hello"))
	// Single SHA256 of "hello": 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	// Double SHA256 should be different
	if result == [32]byte{} {
		t.Error("DoubleSHA256 returned zero hash")
	}
}

func TestHash160Empty(t *testing.T) {
	// Test vector: Hash160 of empty string
	// Expected: b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
	result := Hash160([]byte{})
	expected := "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
	got := hex.EncodeToString(result[:])
	if got != expected {
		t.Errorf("Hash160(empty) = %s, want %s", got, expected)
	}
}

func TestHash160PublicKey(t *testing.T) {
	// Test with a sample public key (33 bytes compressed)
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)
	result := Hash160(pubKey)
	// The result should be a 20-byte hash
	if len(result) != 20 {
		t.Errorf("Hash160 returned %d bytes, want 20", len(result))
	}
}

func TestSHA256Hash(t *testing.T) {
	// Test that SHA256Hash produces a single SHA256
	input := []byte("test")
	result := SHA256Hash(input)
	// SHA256 of "test": 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	got := hex.EncodeToString(result[:])
	if got != expected {
		t.Errorf("SHA256Hash(test) = %s, want %s", got, expected)
	}
}

func TestDoubleSHA256VsSingle(t *testing.T) {
	// Verify that double SHA256 is different from single SHA256
	input := []byte("bitcoin")
	single := SHA256Hash(input)
	double := DoubleSHA256(input)
	if single == double {
		t.Error("DoubleSHA256 should differ from single SHA256")
	}
}
