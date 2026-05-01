// Tests for MuHash3072.
//
// Vectors come straight from bitcoin-core/src/test/crypto_tests.cpp's
// muhash_tests case (the "FromInt" helper, the order-invariance check, and
// the expected SHA256 over the canonical Num3072 form).

package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestMuHashFromIntCoreVector is the literal vector from
// bitcoin-core/src/test/crypto_tests.cpp:1245-1249:
//
//	MuHash3072 acc = FromInt(0);
//	acc *= FromInt(1);
//	acc /= FromInt(2);
//	acc.Finalize(out);
//	BOOST_CHECK_EQUAL(out, uint256{
//	  "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"});
//
// uint256 in Core prints in display (reversed) order via ToString(); the
// hex literal here is also the display string. Our Finalize returns the raw
// 32-byte SHA256 (internal byte order), so the test reverses the display
// string before comparing.
func TestMuHashFromIntCoreVector(t *testing.T) {
	acc := MuHashFromInt(0)
	acc.Combine(MuHashFromInt(1))
	acc.Difference(MuHashFromInt(2))

	got := acc.Finalize()

	wantDisplay := "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"
	want := mustHexReverse(t, wantDisplay)

	if !bytes.Equal(got[:], want) {
		t.Fatalf("MuHash FromInt(0)*FromInt(1)/FromInt(2) mismatch\n  got:  %x\n  want: %x", got[:], want)
	}
}

// TestMuHashInsertRemoveCoreVector is the second half of the Core vector at
// crypto_tests.cpp:1251-1257:
//
//	MuHash3072 acc2 = FromInt(0);
//	unsigned char tmp[32]  = {1, 0};  acc2.Insert(tmp);
//	unsigned char tmp2[32] = {2, 0};  acc2.Remove(tmp2);
//	acc2.Finalize(out);
//	BOOST_CHECK_EQUAL(out, ... same value as above ...);
//
// This proves Insert/Remove on raw 32-byte buffers match the FromInt path
// (FromInt(i) IS Insert(i || 31 zeros) by definition).
func TestMuHashInsertRemoveCoreVector(t *testing.T) {
	acc := MuHashFromInt(0)
	var one32 [32]byte
	one32[0] = 1
	acc.Insert(one32[:])
	var two32 [32]byte
	two32[0] = 2
	acc.Remove(two32[:])

	got := acc.Finalize()

	wantDisplay := "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"
	want := mustHexReverse(t, wantDisplay)

	if !bytes.Equal(got[:], want) {
		t.Fatalf("Insert/Remove vector mismatch\n  got:  %x\n  want: %x", got[:], want)
	}
}

// TestMuHashOrderInvariance: the multiset hash is order-independent. This is
// the property that makes MuHash useful for UTXO snapshot validation; if we
// got it wrong the hash would depend on iteration order. Vector source:
// crypto_tests.cpp:1205-1227 (the iter loop).
func TestMuHashOrderInvariance(t *testing.T) {
	// Pick a small mixed sequence: insert a, insert b, remove c, insert d.
	// Then do the same operations in a permuted order. The Finalize digests
	// must match.
	a := MuHashFromInt(7)
	b := MuHashFromInt(3)
	c := MuHashFromInt(12)
	d := MuHashFromInt(255)

	acc1 := NewMuHash3072()
	acc1.Combine(a).Combine(b).Difference(c).Combine(d)

	acc2 := NewMuHash3072()
	acc2.Combine(d).Combine(b).Difference(c).Combine(a)

	acc3 := NewMuHash3072()
	acc3.Difference(c).Combine(d).Combine(a).Combine(b)

	got1 := acc1.Finalize()
	got2 := acc2.Finalize()
	got3 := acc3.Finalize()

	if !bytes.Equal(got1[:], got2[:]) {
		t.Errorf("order invariance failed (1 vs 2):\n  1: %x\n  2: %x", got1, got2)
	}
	if !bytes.Equal(got1[:], got3[:]) {
		t.Errorf("order invariance failed (1 vs 3):\n  1: %x\n  3: %x", got1, got3)
	}
}

// TestMuHashEmptyEqualsRoundTrip: the second loop in crypto_tests.cpp lines
// 1229-1242 shows that Finalize on an empty MuHash equals the result of
// Insert(X)+Insert(Y)+Remove(Y)+Remove(X) — i.e. the "round-trip through
// nothing" identity.
func TestMuHashEmptyEqualsRoundTrip(t *testing.T) {
	x := MuHashFromInt(42)
	y := MuHashFromInt(99)

	z := NewMuHash3072()
	z.Combine(x)
	z.Combine(y)

	// Now fold y into x ("y *= x") then divide z by that combined object:
	// z gets numerator(y)*denom(y) and similarly for the others, ending
	// up at (1,1). The Combine(x) here mutates x — which is fine for this
	// test since we're done with it.
	yx := NewMuHash3072()
	yx.Combine(y).Combine(x)
	z.Difference(yx)

	got := z.Finalize()
	want := NewMuHash3072().Finalize()
	if !bytes.Equal(got[:], want[:]) {
		t.Fatalf("round-trip identity failed\n  got:  %x\n  want: %x", got[:], want[:])
	}
}

// TestNum3072FromBigRoundtrip checks the LE serialization helpers used by
// Finalize.
func TestNum3072FromBigRoundtrip(t *testing.T) {
	// Build a few non-trivial Num3072 values, run them through the big.Int
	// round trip, and confirm the LE bytes are stable.
	cases := []Num3072{
		Num3072One(),
		func() Num3072 {
			var n Num3072
			for i := range n {
				n[i] = byte(i & 0xff)
			}
			return n
		}(),
	}
	for i, n := range cases {
		x := n.toBig()
		var back Num3072
		back.fromBig(x)
		if back != n {
			t.Errorf("case %d: roundtrip changed bytes\n  in:   %x\n  out:  %x", i, n, back)
		}
	}
}

// TestMuHashSerializeRoundtrip checks that we can dump and reload an
// accumulator without changing its Finalize output.
func TestMuHashSerializeRoundtrip(t *testing.T) {
	acc := MuHashFromInt(5)
	acc.Combine(MuHashFromInt(11))
	acc.Difference(MuHashFromInt(3))

	blob := acc.MuHashSerialize()
	if len(blob) != 768 {
		t.Fatalf("serialized length = %d, want 768", len(blob))
	}

	loaded, err := MuHashDeserialize(blob)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}

	a := acc.Finalize()
	b := loaded.Finalize()
	if !bytes.Equal(a[:], b[:]) {
		t.Fatalf("roundtrip Finalize mismatch:\n  before: %x\n  after:  %x", a[:], b[:])
	}
}

// mustHexReverse decodes a 64-char hex string into 32 bytes and reverses it
// (display order -> internal order).
func mustHexReverse(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("hex decoded len = %d, want 32", len(raw))
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = raw[31-i]
	}
	return out
}
