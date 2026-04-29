package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestEllSwiftCreateRoundTrip verifies that an ElligatorSwift-encoded pubkey
// decodes back to the same x-coordinate that the underlying secp256k1
// public key would have.  This is the round-trip property libsecp256k1
// guarantees per the BIP-324 spec.
func TestEllSwiftCreateRoundTrip(t *testing.T) {
	for i := 0; i < 8; i++ {
		ek, err := GenerateEllSwiftPrivKey()
		if err != nil {
			t.Fatalf("iter %d: GenerateEllSwiftPrivKey: %v", i, err)
		}

		// Decode the ellswift back to a pubkey and compare its x-coordinate
		// to the x-coordinate of PrivKey.PubKey().
		decoded, err := DecodeToPubKey(ek.EllSwiftPubKey)
		if err != nil {
			t.Fatalf("iter %d: DecodeToPubKey: %v", i, err)
		}

		want := ek.PrivKey.PubKey().SerializeCompressed() // 33 bytes
		got := decoded.SerializeCompressed()              // 33 bytes
		// Compare x-only (skip the parity prefix byte) — BIP-324 only
		// uses the x-coordinate, and the ellswift encoding doesn't
		// preserve the y parity (decode picks one canonical lift).
		if !bytes.Equal(want[1:], got[1:]) {
			t.Fatalf("iter %d: x-coord mismatch\n  want: %x\n  got:  %x",
				i, want[1:], got[1:])
		}
	}
}

// TestEllSwiftXDHSymmetric verifies the BIP-324 ECDH symmetry: party A
// (initiator) and party B (responder) compute the same 32-byte shared
// secret from each other's ElligatorSwift pubkeys + their own seckey.
// This is the property the BIP-324 transport relies on; pre-libsecp256k1
// rewrite this test failed because the hand-rolled codec picked an
// incorrect candidate x-coordinate during decode.
func TestEllSwiftXDHSymmetric(t *testing.T) {
	for i := 0; i < 8; i++ {
		a, err := GenerateEllSwiftPrivKey()
		if err != nil {
			t.Fatalf("iter %d: keygen A: %v", i, err)
		}
		b, err := GenerateEllSwiftPrivKey()
		if err != nil {
			t.Fatalf("iter %d: keygen B: %v", i, err)
		}

		secretA := a.ComputeBIP324ECDHSecret(b.EllSwiftPubKey, true)
		secretB := b.ComputeBIP324ECDHSecret(a.EllSwiftPubKey, false)

		if secretA != secretB {
			t.Fatalf("iter %d: shared secrets diverge\n  A: %x\n  B: %x",
				i, secretA, secretB)
		}
		// Sanity: the secret must not be all-zero — that's the
		// ComputeBIP324ECDHSecret error sentinel.
		var zero [32]byte
		if secretA == zero {
			t.Fatalf("iter %d: shared secret was zero (libsecp256k1 XDH failed?)",
				i)
		}
	}
}

// TestEllSwiftDeterministicEncoding verifies that
// EllSwiftPrivKeyFromBytesWithEntropy is deterministic: same seckey + same
// entropy => same 64-byte encoding.  Useful for test vectors and for
// reproducing wire traces.
func TestEllSwiftDeterministicEncoding(t *testing.T) {
	seckey, err := hex.DecodeString(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	entropy := bytes.Repeat([]byte{0x42}, 32)

	a, err := EllSwiftPrivKeyFromBytesWithEntropy(seckey, entropy)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EllSwiftPrivKeyFromBytesWithEntropy(seckey, entropy)
	if err != nil {
		t.Fatal(err)
	}
	if a.EllSwiftPubKey != b.EllSwiftPubKey {
		t.Fatalf("encoding not deterministic\n  a: %x\n  b: %x",
			a.EllSwiftPubKey, b.EllSwiftPubKey)
	}
}
