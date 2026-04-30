package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestMessageHashKnownVector pins the message-hash framing to the byte string
// produced by Bitcoin Core. The expected hash below is the double-SHA256 of
// CompactSize("Bitcoin Signed Message:\n") || "Bitcoin Signed Message:\n" ||
// CompactSize("hello") || "hello", computed independently and frozen here so
// that any change to the framing (magic string, length encoding, hash
// algorithm) trips the test.
func TestMessageHashKnownVector(t *testing.T) {
	got := MessageHash("hello")

	// Reference: dsha256( 0x18 "Bitcoin Signed Message:\n" 0x05 "hello" )
	// Recomputed locally with Core's framing.
	wantHex := "cf0447ec85f0ce7150a257db32ebfcb7523dae17c36dbd1be598779fec0484f4"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("decode want: %v", err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("MessageHash(%q) = %x, want %s", "hello", got, wantHex)
	}
}

func TestMessageHashEmptyAndLong(t *testing.T) {
	// Two corpus entries that exercise the 1-byte and 3-byte CompactSize paths.
	// We don't pin exact bytes here — we just verify determinism and that
	// distinct inputs hash differently.
	a := MessageHash("")
	b := MessageHash(string(bytes.Repeat([]byte{'x'}, 300)))
	if bytes.Equal(a[:], b[:]) {
		t.Fatalf("distinct messages produced same hash")
	}
	if a == ([32]byte{}) {
		t.Fatalf("hash must not be all-zero")
	}
}

// TestSignAndRecover verifies the round-trip: a freshly generated key signs a
// message hash, and the recovered pubkey matches the signing pubkey. Mirrors
// Bitcoin Core's MessageVerify path.
func TestSignAndRecover(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pub := priv.PubKey()

	hash := MessageHash("the quick brown fox")

	sig := SignMessageCompact(priv, hash, true)
	if len(sig) != 65 {
		t.Fatalf("SignMessageCompact len = %d, want 65", len(sig))
	}

	recovered, compressed, err := RecoverPubKeyFromCompact(sig, hash)
	if err != nil {
		t.Fatalf("RecoverPubKeyFromCompact: %v", err)
	}
	if !compressed {
		t.Errorf("expected compressed flag = true")
	}
	if !bytes.Equal(pub.SerializeCompressed(), recovered.SerializeCompressed()) {
		t.Fatalf("recovered pubkey mismatch")
	}
}

func TestSignAndRecoverUncompressed(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pub := priv.PubKey()

	hash := MessageHash("uncompressed")
	sig := SignMessageCompact(priv, hash, false)

	recovered, compressed, err := RecoverPubKeyFromCompact(sig, hash)
	if err != nil {
		t.Fatalf("RecoverPubKeyFromCompact: %v", err)
	}
	if compressed {
		t.Errorf("expected compressed flag = false")
	}
	// The recovered point is the same regardless of compression flag.
	if !bytes.Equal(pub.SerializeCompressed(), recovered.SerializeCompressed()) {
		t.Fatalf("recovered pubkey mismatch")
	}
}

func TestRecoverWrongHashFails(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pub := priv.PubKey()

	hashA := MessageHash("message A")
	hashB := MessageHash("message B")

	sig := SignMessageCompact(priv, hashA, true)
	recovered, _, err := RecoverPubKeyFromCompact(sig, hashB)
	if err != nil {
		// Recovery itself can succeed on a different hash — it just yields a
		// different pubkey. Either path is acceptable; what matters is the
		// recovered key does not match.
		return
	}
	if bytes.Equal(pub.SerializeCompressed(), recovered.SerializeCompressed()) {
		t.Fatalf("recovery against wrong hash should not yield original pubkey")
	}
}

func TestRecoverInvalidLength(t *testing.T) {
	hash := MessageHash("x")
	if _, _, err := RecoverPubKeyFromCompact(make([]byte, 64), hash); err == nil {
		t.Errorf("expected error for 64-byte signature")
	}
	if _, _, err := RecoverPubKeyFromCompact(nil, hash); err == nil {
		t.Errorf("expected error for nil signature")
	}
}
