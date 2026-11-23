package wire

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"testing"
)

// measureAlloc returns the bytes allocated (TotalAlloc delta) by fn.
func measureAlloc(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestReadVarBytesAllocBoundedByInput: a 5-byte input declaring a
// MaxCompactSize (32 MiB) byte vector with no body must fail without
// allocating anything near the declared length. Core bounds the bytes it
// allocates by the bytes the stream actually delivers (serialize.h,
// MAX_VECTOR_ALLOCATE batches); blockbrew used to make([]byte, 32 MiB) up
// front, so ~100 bytes of a non-critical P2P message bought a 32 MiB
// allocation, repeatable from every peer.
func TestReadVarBytesAllocBoundedByInput(t *testing.T) {
	input := []byte{0xFE, 0x00, 0x00, 0x00, 0x02} // CompactSize 0x02000000, no body
	var decErr error
	var got []byte
	alloc := measureAlloc(func() {
		got, decErr = ReadVarBytes(bytes.NewReader(input), MaxCompactSize)
	})
	if decErr == nil {
		t.Fatalf("decode of a body-less 32 MiB vector succeeded (len %d)", len(got))
	}
	if !errors.Is(decErr, io.EOF) && !errors.Is(decErr, io.ErrUnexpectedEOF) {
		t.Fatalf("unexpected error %v", decErr)
	}
	const limit = 1 << 20
	if alloc >= limit {
		t.Fatalf("ReadVarBytes allocated %d bytes for a 5-byte input, want < %d", alloc, limit)
	}
}

// TestReadVarBytesLargeRoundTrip: vectors larger than one growth chunk still
// decode byte-exact (e.g. multi-MB inscription witness items).
func TestReadVarBytesLargeRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 65535, 65536, 65537, 300_000, 4_000_000} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*7 + 3)
		}
		var buf bytes.Buffer
		if err := WriteVarBytes(&buf, data); err != nil {
			t.Fatal(err)
		}
		buf.WriteByte(0xAB) // trailing byte must be left unread
		r := bytes.NewReader(buf.Bytes())
		got, err := ReadVarBytes(r, MaxCompactSize)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
		if r.Len() != 1 {
			t.Fatalf("n=%d: consumed wrong number of bytes, %d left", n, r.Len())
		}
	}
}

// TestReadVarBytesTruncatedAfterFirstChunk: a body cut off after some data
// reports io.ErrUnexpectedEOF, as a single io.ReadFull of the whole body did.
func TestReadVarBytesTruncatedAfterFirstChunk(t *testing.T) {
	for _, have := range []int{0, 1, 65536, 200_000} {
		var buf bytes.Buffer
		if err := WriteCompactSize(&buf, 1_000_000); err != nil {
			t.Fatal(err)
		}
		buf.Write(make([]byte, have))
		_, err := ReadVarBytes(bytes.NewReader(buf.Bytes()), MaxCompactSize)
		want := io.ErrUnexpectedEOF
		if have == 0 {
			want = io.EOF
		}
		if err != want {
			t.Fatalf("have=%d: err %v, want %v", have, err, want)
		}
	}
}
