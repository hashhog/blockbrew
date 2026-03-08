package wire

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
)

func TestWriteReadUint8(t *testing.T) {
	tests := []uint8{0, 1, 127, 128, 255}
	for _, v := range tests {
		var buf bytes.Buffer
		if err := WriteUint8(&buf, v); err != nil {
			t.Fatalf("WriteUint8(%d) error: %v", v, err)
		}
		got, err := ReadUint8(&buf)
		if err != nil {
			t.Fatalf("ReadUint8 error: %v", err)
		}
		if got != v {
			t.Errorf("ReadUint8: got %d, want %d", got, v)
		}
	}
}

func TestWriteReadUint16LE(t *testing.T) {
	tests := []struct {
		val  uint16
		want []byte
	}{
		{0x0000, []byte{0x00, 0x00}},
		{0x0001, []byte{0x01, 0x00}},
		{0x0100, []byte{0x00, 0x01}},
		{0x1234, []byte{0x34, 0x12}},
		{0xFFFF, []byte{0xFF, 0xFF}},
	}
	for _, tc := range tests {
		var buf bytes.Buffer
		if err := WriteUint16LE(&buf, tc.val); err != nil {
			t.Fatalf("WriteUint16LE(%d) error: %v", tc.val, err)
		}
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Errorf("WriteUint16LE(%d): got %x, want %x", tc.val, buf.Bytes(), tc.want)
		}
		got, err := ReadUint16LE(&buf)
		if err != nil {
			t.Fatalf("ReadUint16LE error: %v", err)
		}
		if got != tc.val {
			t.Errorf("ReadUint16LE: got %d, want %d", got, tc.val)
		}
	}
}

func TestWriteReadUint32LE(t *testing.T) {
	tests := []struct {
		val  uint32
		want []byte
	}{
		{0x00000000, []byte{0x00, 0x00, 0x00, 0x00}},
		{0x00000001, []byte{0x01, 0x00, 0x00, 0x00}},
		{0x01020304, []byte{0x04, 0x03, 0x02, 0x01}},
		{0xFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
	}
	for _, tc := range tests {
		var buf bytes.Buffer
		if err := WriteUint32LE(&buf, tc.val); err != nil {
			t.Fatalf("WriteUint32LE(%d) error: %v", tc.val, err)
		}
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Errorf("WriteUint32LE(%d): got %x, want %x", tc.val, buf.Bytes(), tc.want)
		}
		got, err := ReadUint32LE(&buf)
		if err != nil {
			t.Fatalf("ReadUint32LE error: %v", err)
		}
		if got != tc.val {
			t.Errorf("ReadUint32LE: got %d, want %d", got, tc.val)
		}
	}
}

func TestWriteReadUint64LE(t *testing.T) {
	tests := []struct {
		val  uint64
		want []byte
	}{
		{0x0000000000000000, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{0x0000000000000001, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{0x0102030405060708, []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}},
		{0xFFFFFFFFFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
	}
	for _, tc := range tests {
		var buf bytes.Buffer
		if err := WriteUint64LE(&buf, tc.val); err != nil {
			t.Fatalf("WriteUint64LE(%d) error: %v", tc.val, err)
		}
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Errorf("WriteUint64LE(%d): got %x, want %x", tc.val, buf.Bytes(), tc.want)
		}
		got, err := ReadUint64LE(&buf)
		if err != nil {
			t.Fatalf("ReadUint64LE error: %v", err)
		}
		if got != tc.val {
			t.Errorf("ReadUint64LE: got %d, want %d", got, tc.val)
		}
	}
}

func TestWriteReadInt32LE(t *testing.T) {
	tests := []struct {
		val  int32
		want []byte
	}{
		{0, []byte{0x00, 0x00, 0x00, 0x00}},
		{1, []byte{0x01, 0x00, 0x00, 0x00}},
		{-1, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{0x7FFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0x7F}},
		{-0x80000000, []byte{0x00, 0x00, 0x00, 0x80}},
	}
	for _, tc := range tests {
		var buf bytes.Buffer
		if err := WriteInt32LE(&buf, tc.val); err != nil {
			t.Fatalf("WriteInt32LE(%d) error: %v", tc.val, err)
		}
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Errorf("WriteInt32LE(%d): got %x, want %x", tc.val, buf.Bytes(), tc.want)
		}
		got, err := ReadInt32LE(&buf)
		if err != nil {
			t.Fatalf("ReadInt32LE error: %v", err)
		}
		if got != tc.val {
			t.Errorf("ReadInt32LE: got %d, want %d", got, tc.val)
		}
	}
}

func TestWriteReadInt64LE(t *testing.T) {
	tests := []struct {
		val  int64
		want []byte
	}{
		{0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{1, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{-1, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{0x7FFFFFFFFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}},
	}
	for _, tc := range tests {
		var buf bytes.Buffer
		if err := WriteInt64LE(&buf, tc.val); err != nil {
			t.Fatalf("WriteInt64LE(%d) error: %v", tc.val, err)
		}
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Errorf("WriteInt64LE(%d): got %x, want %x", tc.val, buf.Bytes(), tc.want)
		}
		got, err := ReadInt64LE(&buf)
		if err != nil {
			t.Fatalf("ReadInt64LE error: %v", err)
		}
		if got != tc.val {
			t.Errorf("ReadInt64LE: got %d, want %d", got, tc.val)
		}
	}
}

func TestCompactSizeRoundTrip(t *testing.T) {
	// Test boundary values for CompactSize encoding
	// Note: MaxCompactSize is 0x02000000 (32 MB), so we only test values within range
	tests := []struct {
		name string
		val  uint64
		size int // expected byte size
	}{
		{"zero", 0, 1},
		{"one", 1, 1},
		{"max_single_byte", 252, 1},
		{"min_two_byte", 253, 3},
		{"two_byte_mid", 0x1234, 3},
		{"max_two_byte", 0xFFFF, 3},
		{"min_four_byte", 0x10000, 5},
		{"max_compact_size", MaxCompactSize, 5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteCompactSize(&buf, tc.val); err != nil {
				t.Fatalf("WriteCompactSize(%d) error: %v", tc.val, err)
			}
			if buf.Len() != tc.size {
				t.Errorf("WriteCompactSize(%d) size: got %d, want %d", tc.val, buf.Len(), tc.size)
			}
			got, err := ReadCompactSize(&buf)
			if err != nil {
				t.Fatalf("ReadCompactSize error: %v", err)
			}
			if got != tc.val {
				t.Errorf("ReadCompactSize: got %d, want %d", got, tc.val)
			}
		})
	}
}

func TestCompactSizeEncoding(t *testing.T) {
	// Test specific byte encoding
	tests := []struct {
		val  uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{252, []byte{0xFC}},
		{253, []byte{0xFD, 0xFD, 0x00}},
		{0xFFFF, []byte{0xFD, 0xFF, 0xFF}},
		{0x10000, []byte{0xFE, 0x00, 0x00, 0x01, 0x00}},
		{0xFFFFFFFF, []byte{0xFE, 0xFF, 0xFF, 0xFF, 0xFF}},
		{0x100000000, []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}},
	}

	for _, tc := range tests {
		var buf bytes.Buffer
		if err := WriteCompactSize(&buf, tc.val); err != nil {
			t.Fatalf("WriteCompactSize(%d) error: %v", tc.val, err)
		}
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Errorf("WriteCompactSize(%d): got %x, want %x", tc.val, buf.Bytes(), tc.want)
		}
	}
}

func TestCompactSizeTooLarge(t *testing.T) {
	// Create a buffer with a value larger than MaxCompactSize
	var buf bytes.Buffer
	buf.Write([]byte{0xFE, 0x01, 0x00, 0x00, 0x02}) // 0x02000001, larger than MaxCompactSize

	_, err := ReadCompactSize(&buf)
	if err != ErrCompactSizeTooLarge {
		t.Errorf("ReadCompactSize: expected ErrCompactSizeTooLarge, got %v", err)
	}
}

func TestWriteReadVarBytes(t *testing.T) {
	tests := [][]byte{
		{},
		{0x01},
		{0x01, 0x02, 0x03},
		bytes.Repeat([]byte{0xAB}, 252),
		bytes.Repeat([]byte{0xCD}, 253),
		bytes.Repeat([]byte{0xEF}, 1000),
	}

	for i, tc := range tests {
		var buf bytes.Buffer
		if err := WriteVarBytes(&buf, tc); err != nil {
			t.Fatalf("test %d: WriteVarBytes error: %v", i, err)
		}
		got, err := ReadVarBytes(&buf, 10000)
		if err != nil {
			t.Fatalf("test %d: ReadVarBytes error: %v", i, err)
		}
		if !bytes.Equal(got, tc) {
			t.Errorf("test %d: ReadVarBytes: got %x, want %x", i, got, tc)
		}
	}
}

func TestWriteReadVarString(t *testing.T) {
	tests := []string{
		"",
		"a",
		"hello",
		"The quick brown fox jumps over the lazy dog",
		string(bytes.Repeat([]byte{'x'}, 300)),
	}

	for i, tc := range tests {
		var buf bytes.Buffer
		if err := WriteVarString(&buf, tc); err != nil {
			t.Fatalf("test %d: WriteVarString error: %v", i, err)
		}
		got, err := ReadVarString(&buf, 10000)
		if err != nil {
			t.Fatalf("test %d: ReadVarString error: %v", i, err)
		}
		if got != tc {
			t.Errorf("test %d: ReadVarString: got %q, want %q", i, got, tc)
		}
	}
}

func TestReadBytesEOF(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x01, 0x02})
	_, err := ReadBytes(buf, 5)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("ReadBytes: expected io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestVarBytesMaxSize(t *testing.T) {
	// Create a buffer claiming to have 1000 bytes but only allow 100
	var buf bytes.Buffer
	WriteCompactSize(&buf, 1000)
	buf.Write(make([]byte, 1000))

	_, err := ReadVarBytes(bytes.NewReader(buf.Bytes()), 100)
	if err != ErrCompactSizeTooLarge {
		t.Errorf("ReadVarBytes: expected ErrCompactSizeTooLarge, got %v", err)
	}
}

// Benchmark tests
func BenchmarkWriteCompactSize(b *testing.B) {
	values := []uint64{0, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF}
	var buf bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		for _, v := range values {
			WriteCompactSize(&buf, v)
		}
	}
}

func BenchmarkReadCompactSize(b *testing.B) {
	// Pre-encode some values
	var encoded bytes.Buffer
	values := []uint64{0, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF}
	for _, v := range values {
		WriteCompactSize(&encoded, v)
	}
	data := encoded.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(data)
		for range values {
			ReadCompactSize(r)
		}
	}
}

// Helper for hex decoding in tests
func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
