// Tests for the BIP-324 forward-secure ChaCha20 stream cipher and AEAD.
//
// FSChaCha20 vectors are lifted from
// bitcoin-core/src/test/crypto_tests.cpp::TestFSChaCha20 — they exercise the
// "continuous keystream within an epoch + key rotation" property that
// blockbrew's pre-fix implementation got wrong (every Crypt call started a
// fresh ChaCha20 at block 0 instead of advancing the epoch keystream).
//
// FSChaCha20Poly1305 round-trip tests confirm encrypt/decrypt symmetry and
// that the AEAD survives the 0xFFFFFFFF rekey nonce path (which the previous
// implementation also got wrong).
package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

// testFSChaCha20 mirrors bitcoin-core's TestFSChaCha20:
//  1. The first `rekey_interval` Crypt() calls must produce the same output as
//     a plain stateful ChaCha20 over the concatenation of all those plaintexts
//     (i.e. the keystream is continuous within an epoch).
//  2. The (rekey_interval+1)-th Crypt() must NOT match plain ChaCha20 — it
//     uses the rotated key.
//  3. The final ciphertext must match the published vector.
func testFSChaCha20(t *testing.T, hexPlain, hexKey string, rekeyInterval uint32, expectedAfterRotation string) {
	t.Helper()

	plain := mustHex(t, hexPlain)
	key := mustHex(t, hexKey)
	if len(key) != 32 {
		t.Fatalf("key must be 32 bytes, got %d", len(key))
	}

	fsc := NewFSChaCha20(key, rekeyInterval)

	// Plain ChaCha20 reference cipher: stateful, one nonce of all zeros,
	// matches the FSChaCha20 epoch nonce LE32(0)||LE64(0).
	var refNonce [12]byte
	ref, err := chacha20.NewUnauthenticatedCipher(key, refNonce[:])
	if err != nil {
		t.Fatalf("ref cipher: %v", err)
	}

	fscOut := make([]byte, len(plain))
	refOut := make([]byte, len(plain))

	for i := uint32(0); i < rekeyInterval; i++ {
		fsc.Crypt(plain, fscOut)
		ref.XORKeyStream(refOut, plain)
		if !bytes.Equal(fscOut, refOut) {
			t.Fatalf("epoch step %d: FSChaCha20 keystream desync from plain ChaCha20\n"+
				"  fsc: %x\n  ref: %x", i, fscOut, refOut)
		}
	}

	// The (rekey_interval+1)-th call should differ from plain ChaCha20 —
	// FSChaCha20 has rotated to a new key.
	fsc.Crypt(plain, fscOut)
	ref.XORKeyStream(refOut, plain)
	if bytes.Equal(fscOut, refOut) {
		t.Fatalf("expected FSChaCha20 to diverge from plain ChaCha20 after rotation, got match")
	}

	want := mustHex(t, expectedAfterRotation)
	if !bytes.Equal(fscOut, want) {
		t.Fatalf("post-rotation ciphertext mismatch\n  got:  %x\n  want: %x", fscOut, want)
	}
}

// TestFSChaCha20Vectors exercises the three vectors from
// bitcoin-core/src/test/crypto_tests.cpp.  These would all fail under the
// pre-W90 implementation because every Crypt() call restarted ChaCha20 at
// block 0 with a different nonce.
func TestFSChaCha20Vectors(t *testing.T) {
	testFSChaCha20(t,
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"0000000000000000000000000000000000000000000000000000000000000000",
		256,
		"a93df4ef03011f3db95f60d996e1785df5de38fc39bfcb663a47bb5561928349")

	testFSChaCha20(t,
		"01",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		5,
		"ea")

	testFSChaCha20(t,
		"e93fdb5c762804b9a706816aca31e35b11d2aa3080108ef46a5b1f1508819c0a",
		"8ec4c3ccdaea336bdeb245636970be01266509b33f3d2642504eaf412206207a",
		4096,
		"8bfaa4eacff308fdb4a94a5ff25bd9d0c1f84b77f81239f67ff39d6e1ac280c9")
}

// TestFSChaCha20ContinuousKeystream specifically verifies the bug class that
// regression-tested the old implementation: encrypting two consecutive
// 3-byte chunks (the BIP-324 length-field shape) must equal a single
// 6-byte ChaCha20 keystream draw, NOT two independent 3-byte draws each
// from block 0.
func TestFSChaCha20ContinuousKeystream(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	fsc := NewFSChaCha20(key, 224)

	// Encrypt two 3-byte chunks (three calls would still be inside the
	// first 64-byte ChaCha20 block; we deliberately span two chunks to
	// catch the bug where each Crypt restarts at block 0).
	chunk1Plain := []byte{0x11, 0x22, 0x33}
	chunk2Plain := []byte{0x44, 0x55, 0x66}
	chunk1Out := make([]byte, 3)
	chunk2Out := make([]byte, 3)
	fsc.Crypt(chunk1Plain, chunk1Out)
	fsc.Crypt(chunk2Plain, chunk2Out)

	// Reference: single stateful ChaCha20 over the concatenation.
	var refNonce [12]byte
	ref, err := chacha20.NewUnauthenticatedCipher(key, refNonce[:])
	if err != nil {
		t.Fatalf("ref cipher: %v", err)
	}
	refIn := append(append([]byte{}, chunk1Plain...), chunk2Plain...)
	refOut := make([]byte, 6)
	ref.XORKeyStream(refOut, refIn)

	got := append(append([]byte{}, chunk1Out...), chunk2Out...)
	if !bytes.Equal(got, refOut) {
		t.Fatalf("split chunks did NOT produce a continuous keystream\n"+
			"  got:  %x\n  ref:  %x\n"+
			"This is the bug clearbit cb04a1f / blockbrew W90 fixed.", got, refOut)
	}
}

// TestFSChaCha20DecryptInverts confirms a freshly-keyed cipher round-trips
// through 600 Crypt() calls (~3 epochs at the BIP-324 default rekey
// interval) — so the rekey schedule itself is symmetric.
func TestFSChaCha20DecryptInverts(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xAA ^ i)
	}

	enc := NewFSChaCha20(key, 224)
	dec := NewFSChaCha20(key, 224)

	for i := 0; i < 600; i++ {
		// Three-byte chunks mirror the BIP-324 length-field workload.
		plain := []byte{byte(i), byte(i >> 1), byte(i >> 2)}
		ct := make([]byte, 3)
		enc.Crypt(plain, ct)

		pt := make([]byte, 3)
		dec.Crypt(ct, pt)

		if !bytes.Equal(pt, plain) {
			t.Fatalf("packet %d: decrypt didn't invert encrypt\n"+
				"  plain: %x\n  ct:    %x\n  pt:    %x", i, plain, ct, pt)
		}
	}
}

// TestFSChaCha20Poly1305RoundTrip exercises the contents AEAD across the
// 224-packet rekey boundary (the 0xFFFFFFFF nonce path) to confirm
// encrypt/decrypt remain symmetric after a key rotation.
func TestFSChaCha20Poly1305RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*7 + 3)
	}

	enc := NewFSChaCha20Poly1305(key, 224)
	dec := NewFSChaCha20Poly1305(key, 224)

	for i := 0; i < 500; i++ {
		plain := []byte("hello bip324 packet ")
		// Vary aad slightly so we exercise authentication too.
		aad := []byte{byte(i), byte(i >> 8)}
		out := make([]byte, len(plain)+1+Expansion)
		enc.Encrypt(0x01, plain, aad, out)

		header, contents, ok := dec.Decrypt(out, aad)
		if !ok {
			t.Fatalf("packet %d: AEAD decrypt failed", i)
		}
		if header != 0x01 {
			t.Fatalf("packet %d: header byte mismatch: got 0x%02x want 0x01", i, header)
		}
		if !bytes.Equal(contents, plain) {
			t.Fatalf("packet %d: plaintext mismatch\n  got:  %x\n  want: %x", i, contents, plain)
		}
	}
}
