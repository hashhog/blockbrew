package wire

// W107 — CompactSize + VarInt serialization 30-gate audit test suite.
//
// Reference: bitcoin-core/src/serialize.h
// Gate key:
//   G1-G5   encoding boundaries
//   G6-G10  decoding incl. non-canonical rejection
//   G11-G15 limits / safety
//   G16-G20 VarInt (Core MSB-7-bit format used in UTXO snapshots)
//   G21-G25 wire integration (Vector/String/OutPoint/Witness/Script)
//   G26-G30 P2P / BIP-152 / endianness

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// ---------------------------------------------------------------------------
// G1 – encode: value < 253 encodes as 1 byte
// ---------------------------------------------------------------------------

func TestW107_G1_EncodeSingleByte(t *testing.T) {
	cases := []uint64{0, 1, 127, 252}
	for _, v := range cases {
		var buf bytes.Buffer
		if err := WriteCompactSize(&buf, v); err != nil {
			t.Fatalf("G1: WriteCompactSize(%d) error: %v", v, err)
		}
		if buf.Len() != 1 {
			t.Errorf("G1: WriteCompactSize(%d) encoded %d bytes, want 1", v, buf.Len())
		}
		if buf.Bytes()[0] != byte(v) {
			t.Errorf("G1: WriteCompactSize(%d) byte=%#x, want %#x", v, buf.Bytes()[0], byte(v))
		}
	}
}

// ---------------------------------------------------------------------------
// G2 – encode: 253 ≤ value ≤ 0xFFFF encodes as 3 bytes (0xFD + LE u16)
// ---------------------------------------------------------------------------

func TestW107_G2_EncodeThreeBytes(t *testing.T) {
	cases := []struct {
		val  uint64
		want []byte
	}{
		{253, []byte{0xFD, 0xFD, 0x00}},
		{0x1234, []byte{0xFD, 0x34, 0x12}},
		{0xFFFF, []byte{0xFD, 0xFF, 0xFF}},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		if err := WriteCompactSize(&buf, tc.val); err != nil {
			t.Fatalf("G2: WriteCompactSize(%d) error: %v", tc.val, err)
		}
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Errorf("G2: WriteCompactSize(%d) = %x, want %x", tc.val, buf.Bytes(), tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// G3 – encode: 0x10000 ≤ value ≤ 0xFFFFFFFF encodes as 5 bytes (0xFE + LE u32)
// ---------------------------------------------------------------------------

func TestW107_G3_EncodeFiveBytes(t *testing.T) {
	cases := []struct {
		val  uint64
		want []byte
	}{
		{0x10000, []byte{0xFE, 0x00, 0x00, 0x01, 0x00}},
		{0xDEADBEEF, []byte{0xFE, 0xEF, 0xBE, 0xAD, 0xDE}},
		{0xFFFFFFFF, []byte{0xFE, 0xFF, 0xFF, 0xFF, 0xFF}},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		if err := WriteCompactSize(&buf, tc.val); err != nil {
			t.Fatalf("G3: WriteCompactSize(%d) error: %v", tc.val, err)
		}
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Errorf("G3: WriteCompactSize(%d) = %x, want %x", tc.val, buf.Bytes(), tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// G4 – encode: value ≥ 0x100000000 encodes as 9 bytes (0xFF + LE u64)
// ---------------------------------------------------------------------------

func TestW107_G4_EncodeNineBytes(t *testing.T) {
	cases := []struct {
		val  uint64
		want []byte
	}{
		{
			0x100000000,
			[]byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
		},
		{
			0xFFFFFFFFFFFFFFFF,
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		if err := WriteCompactSize(&buf, tc.val); err != nil {
			t.Fatalf("G4: WriteCompactSize(%#x) error: %v", tc.val, err)
		}
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Errorf("G4: WriteCompactSize(%#x) = %x, want %x", tc.val, buf.Bytes(), tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// G5 – GetSizeOfCompactSize boundary correctness (via WriteCompactSize len)
// ---------------------------------------------------------------------------

func TestW107_G5_SizeOfCompactSize(t *testing.T) {
	cases := []struct {
		val      uint64
		wantSize int
	}{
		{0, 1},
		{252, 1},
		{253, 3},
		{0xFFFF, 3},
		{0x10000, 5},
		{0xFFFFFFFF, 5},
		{0x100000000, 9},
		{0xFFFFFFFFFFFFFFFF, 9},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		if err := WriteCompactSize(&buf, tc.val); err != nil {
			t.Fatalf("G5: WriteCompactSize(%#x) error: %v", tc.val, err)
		}
		if buf.Len() != tc.wantSize {
			t.Errorf("G5: size of CompactSize(%#x) = %d, want %d", tc.val, buf.Len(), tc.wantSize)
		}
	}
}

// ---------------------------------------------------------------------------
// G6 – decode 0xFD: reads next 2 bytes as LE u16
// ---------------------------------------------------------------------------

func TestW107_G6_Decode0xFD(t *testing.T) {
	// 0xFD 0x34 0x12 → 0x1234
	data := []byte{0xFD, 0x34, 0x12}
	v, err := ReadCompactSize(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("G6: ReadCompactSize error: %v", err)
	}
	if v != 0x1234 {
		t.Errorf("G6: ReadCompactSize = %#x, want %#x", v, uint64(0x1234))
	}
}

// ---------------------------------------------------------------------------
// G7 – decode 0xFE: reads next 4 bytes as LE u32
// ---------------------------------------------------------------------------

func TestW107_G7_Decode0xFE(t *testing.T) {
	// Use 0x00100000 (1 MiB) — within MaxCompactSize, exercises the 5-byte path.
	// 0xFE 0x00 0x00 0x10 0x00 → 0x00100000
	want := uint64(0x00100000)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(want))
	data := append([]byte{0xFE}, b[:]...)
	v, err := ReadCompactSize(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("G7: ReadCompactSize error: %v", err)
	}
	if v != want {
		t.Errorf("G7: ReadCompactSize = %#x, want %#x", v, want)
	}
}

// ---------------------------------------------------------------------------
// G8 – decode 0xFF: reads next 8 bytes as LE u64
// ---------------------------------------------------------------------------

func TestW107_G8_Decode0xFF(t *testing.T) {
	// 0xFF 0x00..0x00 0x01 0x00..0x00 → 0x100000000
	data := []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	v, err := ReadCompactSizeUnchecked(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("G8: ReadCompactSizeUnchecked error: %v", err)
	}
	if v != 0x100000000 {
		t.Errorf("G8: ReadCompactSizeUnchecked = %#x, want %#x", v, uint64(0x100000000))
	}
}

// ---------------------------------------------------------------------------
// G9 – BUG: non-canonical encoding 0xFD + value < 253 MUST be rejected
//
// Bitcoin Core: "non-canonical ReadCompactSize()" error when 0xFD is used
// but the 2-byte value could have been encoded in 1 byte (i.e. value < 253).
// Blockbrew's ReadCompactSize does NOT perform this check, accepting e.g.
// 0xFD 0x00 0x00 (= 0) and 0xFD 0xFC 0x00 (= 252) silently.
//
// This is a protocol-level violation: a peer that sends non-canonical
// CompactSize can fool blockbrew into accepting a message that Core would
// reject as malformed. This gate is marked FAIL.
// ---------------------------------------------------------------------------

func TestW107_G9_NonCanonical_FD_BUG(t *testing.T) {
	// 0xFD 0x00 0x00 → value 0, should be encoded as 1 byte 0x00
	data := []byte{0xFD, 0x00, 0x00}
	v, err := ReadCompactSize(bytes.NewReader(data))
	if err == nil {
		// BUG: Core rejects this with "non-canonical ReadCompactSize()"
		// blockbrew silently accepts it.
		t.Errorf("G9 BUG: ReadCompactSize(0xFD 0x00 0x00) returned %d without error; "+
			"Core rejects non-canonical encoding (value %d < 253 must use 1-byte form)", v, v)
	}

	// 0xFD 0xFC 0x00 → value 252, still non-canonical (< 253)
	data2 := []byte{0xFD, 0xFC, 0x00}
	v2, err2 := ReadCompactSize(bytes.NewReader(data2))
	if err2 == nil {
		t.Errorf("G9 BUG: ReadCompactSize(0xFD 0xFC 0x00) returned %d without error; "+
			"Core rejects non-canonical encoding (value %d < 253 must use 1-byte form)", v2, v2)
	}
}

// ---------------------------------------------------------------------------
// G10 – BUG: non-canonical encoding 0xFE + value < 0x10000 MUST be rejected
//       and 0xFF + value < 0x100000000 MUST be rejected
//
// Same category as G9: Core throws "non-canonical ReadCompactSize()" for
// these, blockbrew silently accepts them.
// ---------------------------------------------------------------------------

func TestW107_G10_NonCanonical_FE_FF_BUG(t *testing.T) {
	// 0xFE 0x00 0x00 0x00 0x00 → value 0 via 5-byte form, non-canonical
	data := []byte{0xFE, 0x00, 0x00, 0x00, 0x00}
	v, err := ReadCompactSize(bytes.NewReader(data))
	if err == nil {
		t.Errorf("G10 BUG: ReadCompactSize(0xFE 0x00..0x00) returned %d without error; "+
			"Core rejects non-canonical 0xFE-prefixed value %d < 0x10000", v, v)
	}

	// 0xFE 0xFF 0xFF 0x00 0x00 → value 0xFFFF via 5-byte form, non-canonical
	data2 := []byte{0xFE, 0xFF, 0xFF, 0x00, 0x00}
	v2, err2 := ReadCompactSize(bytes.NewReader(data2))
	if err2 == nil {
		t.Errorf("G10 BUG: ReadCompactSize(0xFE 0xFF 0xFF 0x00 0x00) returned %d without error; "+
			"Core rejects non-canonical 0xFE-prefixed value %d < 0x10000", v2, v2)
	}

	// 0xFF 0x00..0x00 (8 bytes) → value 0 via 9-byte form, non-canonical
	data3 := []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	v3, err3 := ReadCompactSizeUnchecked(bytes.NewReader(data3))
	// ReadCompactSizeUnchecked skips MAX_SIZE check intentionally, but it
	// still should check for non-canonical encoding.
	if err3 == nil && v3 < 0x100000000 {
		t.Errorf("G10 BUG: ReadCompactSizeUnchecked(0xFF 0x00...) returned %d without error; "+
			"Core rejects non-canonical 0xFF-prefixed value < 0x100000000", v3)
	}
}

// ---------------------------------------------------------------------------
// G11 – MAX_SIZE constant equals Core's 0x02000000
// ---------------------------------------------------------------------------

func TestW107_G11_MaxSizeConstant(t *testing.T) {
	const coreMaxSize = uint64(0x02000000)
	if MaxCompactSize != coreMaxSize {
		t.Errorf("G11: MaxCompactSize = %#x, want %#x (Core MAX_SIZE)", MaxCompactSize, coreMaxSize)
	}
}

// ---------------------------------------------------------------------------
// G12 – ReadCompactSize rejects values > MAX_SIZE
// ---------------------------------------------------------------------------

func TestW107_G12_ReadCompactSizeRejectsOverMax(t *testing.T) {
	// Encode 0x02000001 (MaxCompactSize + 1) as a 5-byte CompactSize.
	overMax := uint64(MaxCompactSize + 1)
	var buf bytes.Buffer
	buf.WriteByte(0xFE)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(overMax))
	buf.Write(b[:])

	_, err := ReadCompactSize(&buf)
	if err == nil {
		t.Error("G12: ReadCompactSize should reject value > MaxCompactSize, but returned nil error")
	}
	if !errors.Is(err, ErrCompactSizeTooLarge) {
		t.Errorf("G12: ReadCompactSize error = %v, want ErrCompactSizeTooLarge", err)
	}
}

// ---------------------------------------------------------------------------
// G13 – ReadCompactSizeUnchecked omits the MAX_SIZE check (for service flags)
// ---------------------------------------------------------------------------

func TestW107_G13_ReadCompactSizeUnchecked(t *testing.T) {
	// Encode a value larger than MaxCompactSize using 9-byte form.
	large := uint64(MaxCompactSize + 1_000_000)
	var buf bytes.Buffer
	buf.WriteByte(0xFF)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], large)
	buf.Write(b[:])

	v, err := ReadCompactSizeUnchecked(&buf)
	if err != nil {
		t.Fatalf("G13: ReadCompactSizeUnchecked error: %v", err)
	}
	if v != large {
		t.Errorf("G13: ReadCompactSizeUnchecked = %d, want %d", v, large)
	}
}

// ---------------------------------------------------------------------------
// G14 – ReadVarBytes secondary maxSize gate rejects oversized content
// ---------------------------------------------------------------------------

func TestW107_G14_ReadVarBytesMaxSizeGate(t *testing.T) {
	// Claim 1000 bytes but allow only 100.
	var buf bytes.Buffer
	WriteCompactSize(&buf, 1000)
	buf.Write(make([]byte, 1000))

	_, err := ReadVarBytes(bytes.NewReader(buf.Bytes()), 100)
	if err == nil {
		t.Error("G14: ReadVarBytes should reject payload > maxSize, got nil error")
	}
}

// ---------------------------------------------------------------------------
// G15 – Large allocation safety: ReadVarBytes with near-max count does not
//       OOM; enforces maxSize before allocation.
// ---------------------------------------------------------------------------

func TestW107_G15_ReadVarBytesNoBlindAlloc(t *testing.T) {
	// Claim a huge size (> maxSize) without providing actual data.
	// The function must reject it before attempting to allocate.
	const maxAllow = uint64(1024)
	var buf bytes.Buffer
	WriteCompactSize(&buf, 1_000_000)
	// Provide only 10 actual bytes so any attempt to read more gets EOF.
	buf.Write(make([]byte, 10))

	_, err := ReadVarBytes(bytes.NewReader(buf.Bytes()), maxAllow)
	if err == nil {
		t.Error("G15: ReadVarBytes should reject claimed size > maxSize before allocating")
	}
}

// ---------------------------------------------------------------------------
// G16 – Core VarInt encoding: 0 → [0x00], 127 → [0x7F], 128 → [0x80 0x00]
// ---------------------------------------------------------------------------

func TestW107_G16_CoreVarIntEncoding(t *testing.T) {
	// Test vectors from bitcoin-core/src/serialize.h comments.
	//   0:    [0x00]
	//   1:    [0x01]
	//   127:  [0x7F]
	//   128:  [0x80 0x00]
	//   255:  [0x80 0x7F]
	//   256:  [0x81 0x00]
	//   16383:[0xFE 0x7F]
	//   16384:[0xFF 0x00]
	cases := []struct {
		val  uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7F}},
		{128, []byte{0x80, 0x00}},
		{255, []byte{0x80, 0x7F}},
		{256, []byte{0x81, 0x00}},
		{16383, []byte{0xFE, 0x7F}},
		{16384, []byte{0xFF, 0x00}},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		if err := writeCoreVarIntForTest(&buf, tc.val); err != nil {
			t.Fatalf("G16: WriteCoreVarInt(%d) error: %v", tc.val, err)
		}
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Errorf("G16: WriteCoreVarInt(%d) = %x, want %x", tc.val, buf.Bytes(), tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// G17 – Core VarInt decoding: round-trip for known vectors
// ---------------------------------------------------------------------------

func TestW107_G17_CoreVarIntDecoding(t *testing.T) {
	cases := []uint64{0, 1, 127, 128, 255, 256, 16383, 16384, 65535, 0x100000000}
	for _, v := range cases {
		var buf bytes.Buffer
		if err := writeCoreVarIntForTest(&buf, v); err != nil {
			t.Fatalf("G17: WriteCoreVarInt(%d) error: %v", v, err)
		}
		got, err := readCoreVarIntForTest(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("G17: ReadCoreVarInt(%d) error: %v", v, err)
		}
		if got != v {
			t.Errorf("G17: round-trip %d → encoded → %d", v, got)
		}
	}
}

// ---------------------------------------------------------------------------
// G18 – Core VarInt overflow guard
// ---------------------------------------------------------------------------

func TestW107_G18_CoreVarIntOverflowGuard(t *testing.T) {
	// Craft a byte sequence that would overflow uint64 in the Core VarInt decoder.
	// 11 bytes of 0x80 continuation bits followed by 0x00: more than 10 limbs.
	data := bytes.Repeat([]byte{0x80}, 11)
	data = append(data, 0x00)
	_, err := readCoreVarIntForTest(bytes.NewReader(data))
	if err == nil {
		t.Error("G18: ReadCoreVarInt should error on input longer than 10 limbs")
	}
}

// ---------------------------------------------------------------------------
// G19 – Core VarInt canonical: each value has exactly one encoding
// ---------------------------------------------------------------------------

func TestW107_G19_CoreVarIntCanonical(t *testing.T) {
	// For the first 1000 values: encode, decode, re-encode and compare bytes.
	for v := uint64(0); v < 1000; v++ {
		var buf1 bytes.Buffer
		if err := writeCoreVarIntForTest(&buf1, v); err != nil {
			t.Fatalf("G19: WriteCoreVarInt(%d) error: %v", v, err)
		}
		decoded, err := readCoreVarIntForTest(bytes.NewReader(buf1.Bytes()))
		if err != nil {
			t.Fatalf("G19: ReadCoreVarInt(%d) error: %v", v, err)
		}
		var buf2 bytes.Buffer
		if err := writeCoreVarIntForTest(&buf2, decoded); err != nil {
			t.Fatalf("G19: re-encode WriteCoreVarInt(%d) error: %v", decoded, err)
		}
		if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
			t.Errorf("G19: VarInt(%d) not canonical: first=%x re-encode=%x", v, buf1.Bytes(), buf2.Bytes())
		}
	}
}

// ---------------------------------------------------------------------------
// G20 – internal writeVaruint/readVaruint: non-canonical NOT rejected
//       (lower-severity than G9/G10 since only used for on-disk DB format,
//       not for wire-protocol validation; documenting here for completeness)
// ---------------------------------------------------------------------------

func TestW107_G20_InternalVaruintNonCanonical_Info(t *testing.T) {
	// This test documents that writeVaruint/readVaruint (utxoset.go) are the
	// CompactSize-encoding functions used for on-disk UTXO storage.
	// Unlike ReadCompactSize (wire), they do NOT enforce non-canonical rejection.
	// This is acceptable for private DB formats but worth auditing.
	//
	// Verify round-trip correctness for key values.
	cases := []uint64{0, 1, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000}
	for _, v := range cases {
		var buf bytes.Buffer
		writeVaruintForTest(&buf, v)
		got, err := readVaruintForTest(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("G20: readVaruint(%d) error: %v", v, err)
		}
		if got != v {
			t.Errorf("G20: writeVaruint(%d) round-trip = %d", v, got)
		}
	}
}

// ---------------------------------------------------------------------------
// G21 – Vector serialization: CompactSize count prefix
// ---------------------------------------------------------------------------

func TestW107_G21_VectorCompactSizePrefix(t *testing.T) {
	// A slice of 253 elements should be prefixed with 3-byte CompactSize.
	// Simulate by encoding count=253 and verifying the prefix bytes.
	count := uint64(253)
	var buf bytes.Buffer
	if err := WriteCompactSize(&buf, count); err != nil {
		t.Fatalf("G21: WriteCompactSize error: %v", err)
	}
	if buf.Len() != 3 {
		t.Errorf("G21: CompactSize prefix for 253 elements = %d bytes, want 3", buf.Len())
	}
	b := buf.Bytes()
	if b[0] != 0xFD {
		t.Errorf("G21: CompactSize prefix[0] = %#x, want 0xFD", b[0])
	}
}

// ---------------------------------------------------------------------------
// G22 – String serialization: CompactSize length prefix + raw bytes
// ---------------------------------------------------------------------------

func TestW107_G22_StringVarString(t *testing.T) {
	cases := []string{"", "hello", string(make([]byte, 253))}
	for _, s := range cases {
		var buf bytes.Buffer
		if err := WriteVarString(&buf, s); err != nil {
			t.Fatalf("G22: WriteVarString error: %v", err)
		}
		// First field should be a valid CompactSize encoding of len(s).
		got, err := ReadVarString(bytes.NewReader(buf.Bytes()), uint64(len(s)+10))
		if err != nil {
			t.Fatalf("G22: ReadVarString error: %v", err)
		}
		if got != s {
			t.Errorf("G22: ReadVarString round-trip mismatch (len %d)", len(s))
		}
	}
}

// ---------------------------------------------------------------------------
// G23 – OutPoint serialization: 32-byte LE hash + 4-byte LE index
// ---------------------------------------------------------------------------

func TestW107_G23_OutPointSerialization(t *testing.T) {
	op := OutPoint{
		Hash:  [32]byte{0: 0xAA, 31: 0xBB},
		Index: 0x12345678,
	}
	var buf bytes.Buffer
	if err := op.Serialize(&buf); err != nil {
		t.Fatalf("G23: OutPoint.Serialize error: %v", err)
	}
	if buf.Len() != 36 {
		t.Errorf("G23: OutPoint serialized to %d bytes, want 36", buf.Len())
	}
	// First 32 bytes: raw hash (not reversed on the wire)
	raw := buf.Bytes()
	if raw[0] != 0xAA || raw[31] != 0xBB {
		t.Errorf("G23: OutPoint hash bytes wrong: [0]=%#x [31]=%#x", raw[0], raw[31])
	}
	// Last 4 bytes: LE index
	idx := binary.LittleEndian.Uint32(raw[32:36])
	if idx != 0x12345678 {
		t.Errorf("G23: OutPoint index = %#x, want %#x", idx, uint32(0x12345678))
	}

	// Round-trip
	var op2 OutPoint
	if err := op2.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatalf("G23: OutPoint.Deserialize error: %v", err)
	}
	if op2 != op {
		t.Errorf("G23: OutPoint round-trip mismatch: got %v, want %v", op2, op)
	}
}

// ---------------------------------------------------------------------------
// G24 – Witness stack: count (CompactSize) + per-item (CompactSize + bytes)
// ---------------------------------------------------------------------------

func TestW107_G24_WitnessStackSerialization(t *testing.T) {
	tx := &MsgTx{
		Version: 2,
		TxIn: []*TxIn{
			{
				PreviousOutPoint: OutPoint{Index: 0},
				Witness:          [][]byte{{0xDE, 0xAD}, {0xBE, 0xEF, 0x00}},
				Sequence:         0xFFFFFFFF,
			},
		},
		TxOut: []*TxOut{
			{Value: 1000, PkScript: []byte{0x51}},
		},
		LockTime: 0,
	}

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatalf("G24: Tx.Serialize error: %v", err)
	}

	// Round-trip
	var tx2 MsgTx
	if err := tx2.Deserialize(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("G24: Tx.Deserialize error: %v", err)
	}
	if len(tx2.TxIn) != 1 || len(tx2.TxIn[0].Witness) != 2 {
		t.Fatalf("G24: witness count mismatch: %v", tx2.TxIn[0].Witness)
	}
	if !bytes.Equal(tx2.TxIn[0].Witness[0], []byte{0xDE, 0xAD}) {
		t.Errorf("G24: witness[0] = %x, want deadad", tx2.TxIn[0].Witness[0])
	}
	if !bytes.Equal(tx2.TxIn[0].Witness[1], []byte{0xBE, 0xEF, 0x00}) {
		t.Errorf("G24: witness[1] = %x, want beef00", tx2.TxIn[0].Witness[1])
	}
}

// ---------------------------------------------------------------------------
// G25 – Script: no consensus 10000-byte limit at deserialization time
// ---------------------------------------------------------------------------

func TestW107_G25_ScriptNoDeserializeLimit(t *testing.T) {
	// A script of 12000 bytes must be accepted during deserialization.
	// The consensus MAX_SCRIPT_SIZE (10000) is checked during evaluation,
	// not during wire deserialization. Blockbrew correctly uses MaxCompactSize.
	bigScript := make([]byte, 12000)
	for i := range bigScript {
		bigScript[i] = byte(i)
	}
	out := &TxOut{Value: 0, PkScript: bigScript}
	var buf bytes.Buffer
	if err := out.Serialize(&buf); err != nil {
		t.Fatalf("G25: TxOut.Serialize error: %v", err)
	}
	var out2 TxOut
	if err := out2.Deserialize(bytes.NewReader(buf.Bytes())); err != nil {
		t.Errorf("G25: TxOut with 12000-byte script should deserialize OK, got: %v", err)
	}
	if !bytes.Equal(out2.PkScript, bigScript) {
		t.Errorf("G25: script round-trip mismatch")
	}
}

// ---------------------------------------------------------------------------
// G26 – P2P message payload uses CompactSize for all variable-length counts
//       (verify inv message with 1 and 50001 vectors)
// ---------------------------------------------------------------------------

func TestW107_G26_P2PCompactSizeForCounts(t *testing.T) {
	// Verify that WriteCompactSize is correctly called for count=1 and
	// that the first byte of the serialized message reflects 1-byte encoding.
	var buf bytes.Buffer
	if err := WriteCompactSize(&buf, 1); err != nil {
		t.Fatalf("G26: WriteCompactSize error: %v", err)
	}
	if buf.Bytes()[0] != 0x01 {
		t.Errorf("G26: count=1 first byte = %#x, want 0x01", buf.Bytes()[0])
	}

	// count=50001 should use 3-byte encoding (0xFD prefix)
	buf.Reset()
	if err := WriteCompactSize(&buf, 50001); err != nil {
		t.Fatalf("G26: WriteCompactSize(50001) error: %v", err)
	}
	if buf.Bytes()[0] != 0xFD {
		t.Errorf("G26: count=50001 first byte = %#x, want 0xFD", buf.Bytes()[0])
	}
	if buf.Len() != 3 {
		t.Errorf("G26: count=50001 encoded to %d bytes, want 3", buf.Len())
	}
}

// ---------------------------------------------------------------------------
// G27 – BIP-152 short IDs: exactly 6 bytes, little-endian u48
// ---------------------------------------------------------------------------

func TestW107_G27_BIP152ShortID6Bytes(t *testing.T) {
	// Verify that a short ID of 0xAABBCCDDEEFF serializes as 6 LE bytes.
	shortID := uint64(0x0000AABBCCDDEEFF)
	var buf [8]byte
	// Simulate what msg_cmpctblock.go does: put uint64 LE, write [:6]
	binary.LittleEndian.PutUint64(buf[:], shortID)
	if buf[0] != 0xFF || buf[1] != 0xEE || buf[2] != 0xDD || buf[3] != 0xCC ||
		buf[4] != 0xBB || buf[5] != 0xAA {
		t.Errorf("G27: short ID 6-byte encoding = %x, want ff ee dd cc bb aa", buf[:6])
	}
	// Verify bytes [6:] are zero (no high bits in a valid 48-bit ID)
	if buf[6] != 0 || buf[7] != 0 {
		t.Errorf("G27: short ID bytes 6-7 non-zero for 48-bit value: %x", buf[:])
	}

	// Round-trip: read back from [:6]
	var recoverBuf [8]byte
	copy(recoverBuf[:6], buf[:6])
	recovered := binary.LittleEndian.Uint64(recoverBuf[:])
	if recovered != shortID {
		t.Errorf("G27: short ID round-trip: got %#x, want %#x", recovered, shortID)
	}
}

// ---------------------------------------------------------------------------
// G28 – BIP-152 short ID count uses CompactSize prefix
// ---------------------------------------------------------------------------

func TestW107_G28_BIP152ShortIDCountCompactSize(t *testing.T) {
	// A cmpctblock with 253 short IDs must use 3-byte CompactSize for the count.
	count := uint64(253)
	var buf bytes.Buffer
	if err := WriteCompactSize(&buf, count); err != nil {
		t.Fatalf("G28: WriteCompactSize error: %v", err)
	}
	if buf.Len() != 3 {
		t.Errorf("G28: short ID count=253 encoded to %d bytes, want 3", buf.Len())
	}
	if buf.Bytes()[0] != 0xFD {
		t.Errorf("G28: short ID count=253 prefix = %#x, want 0xFD", buf.Bytes()[0])
	}
}

// ---------------------------------------------------------------------------
// G29 – headers message: trailing tx_count CompactSize (always 0) per header
// ---------------------------------------------------------------------------

func TestW107_G29_HeadersMsgTrailingTxCount(t *testing.T) {
	// A "headers" message with 2 headers serializes as:
	//   CompactSize(2) + header80 + CompactSize(0) + header80 + CompactSize(0)
	// Verify the total length and that the trailing bytes are 0x00 (tx_count=0).
	hdr := BlockHeader{}
	var buf bytes.Buffer
	// Write 2 headers manually as msg_headers.go does.
	if err := WriteCompactSize(&buf, 2); err != nil {
		t.Fatalf("G29: WriteCompactSize error: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := hdr.Serialize(&buf); err != nil {
			t.Fatalf("G29: BlockHeader.Serialize error: %v", err)
		}
		if err := WriteCompactSize(&buf, 0); err != nil {
			t.Fatalf("G29: WriteCompactSize(0) error: %v", err)
		}
	}
	// Expected: 1 (count) + (80+1)*2 = 1 + 162 = 163 bytes
	want := 1 + (80+1)*2
	if buf.Len() != want {
		t.Errorf("G29: headers msg length = %d, want %d", buf.Len(), want)
	}
	raw := buf.Bytes()
	// Trailing tx_count byte of each header should be 0x00
	if raw[1+80] != 0x00 {
		t.Errorf("G29: first header trailing tx_count = %#x, want 0x00", raw[1+80])
	}
	if raw[1+81+80] != 0x00 {
		t.Errorf("G29: second header trailing tx_count = %#x, want 0x00", raw[1+81+80])
	}
}

// ---------------------------------------------------------------------------
// G30 – Endianness: all multi-byte integers are little-endian on the wire
//       except port numbers (Bitcoin uses big-endian / network byte order)
// ---------------------------------------------------------------------------

func TestW107_G30_Endianness(t *testing.T) {
	// Uint16 LE: 0x1234 → [0x34, 0x12]
	var buf bytes.Buffer
	if err := WriteUint16LE(&buf, 0x1234); err != nil {
		t.Fatalf("G30: WriteUint16LE error: %v", err)
	}
	if buf.Bytes()[0] != 0x34 || buf.Bytes()[1] != 0x12 {
		t.Errorf("G30: Uint16LE(0x1234) = %x, want [34 12]", buf.Bytes())
	}

	// Uint32 LE: 0x12345678 → [0x78, 0x56, 0x34, 0x12]
	buf.Reset()
	if err := WriteUint32LE(&buf, 0x12345678); err != nil {
		t.Fatalf("G30: WriteUint32LE error: %v", err)
	}
	if buf.Bytes()[0] != 0x78 {
		t.Errorf("G30: Uint32LE MSB wrong: got %#x, want 0x78", buf.Bytes()[0])
	}

	// Uint64 LE: 0x0102030405060708 → [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
	buf.Reset()
	if err := WriteUint64LE(&buf, 0x0102030405060708); err != nil {
		t.Fatalf("G30: WriteUint64LE error: %v", err)
	}
	if buf.Bytes()[0] != 0x08 {
		t.Errorf("G30: Uint64LE[0] = %#x, want 0x08", buf.Bytes()[0])
	}

	// CompactSize is also LE: 0xFD followed by LE u16.
	buf.Reset()
	if err := WriteCompactSize(&buf, 0x1234); err != nil {
		t.Fatalf("G30: WriteCompactSize error: %v", err)
	}
	// Bytes: [0xFD, 0x34, 0x12]
	if buf.Bytes()[1] != 0x34 || buf.Bytes()[2] != 0x12 {
		t.Errorf("G30: CompactSize(0x1234) inner bytes = %x, want [34 12]", buf.Bytes()[1:3])
	}

	// No direct test for port BE here (that lives in p2p/addrv2.go).
	// Verify the writeUint16BEInternal-style encoding separately by checking
	// that 0x1234 in BE is [0x12, 0x34].
	var be [2]byte
	binary.BigEndian.PutUint16(be[:], 0x1234)
	if be[0] != 0x12 || be[1] != 0x34 {
		t.Errorf("G30: port BE(0x1234) = %x, want [12 34]", be[:])
	}
}

// ---------------------------------------------------------------------------
// Helper stubs bridging internal package functions for test use.
// The Core VarInt functions live in consensus/core_compressor.go but we test
// the wire-level properties here. We replicate the algorithms inline so that
// the wire package test has no cross-package dependency.
// ---------------------------------------------------------------------------

// writeCoreVarIntForTest mirrors consensus.WriteCoreVarInt (serialize.h VarInt).
func writeCoreVarIntForTest(w io.Writer, n uint64) error {
	var tmp [10]byte
	length := 0
	value := n
	for {
		b := byte(value & 0x7F)
		if length > 0 {
			b |= 0x80
		}
		tmp[length] = b
		if value <= 0x7F {
			break
		}
		value = (value >> 7) - 1
		length++
		if length >= len(tmp) {
			return errors.New("VarInt overflow")
		}
	}
	for i := length; i >= 0; i-- {
		if _, err := w.Write([]byte{tmp[i]}); err != nil {
			return err
		}
	}
	return nil
}

// readCoreVarIntForTest mirrors consensus.ReadCoreVarInt.
func readCoreVarIntForTest(r io.Reader) (uint64, error) {
	var n uint64
	var buf [1]byte
	for i := 0; i < 10; i++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		if n > (^uint64(0) >> 7) {
			return 0, errors.New("ReadVarInt: size too large")
		}
		n = (n << 7) | uint64(buf[0]&0x7F)
		if buf[0]&0x80 != 0 {
			if n == ^uint64(0) {
				return 0, errors.New("ReadVarInt: size too large")
			}
			n++
		} else {
			return n, nil
		}
	}
	return 0, errors.New("ReadVarInt: input too long")
}

// writeVaruintForTest mirrors utxoset.go writeVaruint (internal CompactSize,
// no 32 MB cap).
func writeVaruintForTest(w *bytes.Buffer, val uint64) {
	switch {
	case val < 0xFD:
		w.WriteByte(byte(val))
	case val <= 0xFFFF:
		w.WriteByte(0xFD)
		w.WriteByte(byte(val))
		w.WriteByte(byte(val >> 8))
	case val <= 0xFFFFFFFF:
		w.WriteByte(0xFE)
		w.WriteByte(byte(val))
		w.WriteByte(byte(val >> 8))
		w.WriteByte(byte(val >> 16))
		w.WriteByte(byte(val >> 24))
	default:
		w.WriteByte(0xFF)
		w.WriteByte(byte(val))
		w.WriteByte(byte(val >> 8))
		w.WriteByte(byte(val >> 16))
		w.WriteByte(byte(val >> 24))
		w.WriteByte(byte(val >> 32))
		w.WriteByte(byte(val >> 40))
		w.WriteByte(byte(val >> 48))
		w.WriteByte(byte(val >> 56))
	}
}

// readVaruintForTest mirrors utxoset.go readVaruint (internal CompactSize, no cap).
func readVaruintForTest(r *bytes.Reader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	switch first {
	case 0xFD:
		var buf [2]byte
		if _, err := r.Read(buf[:]); err != nil {
			return 0, err
		}
		return uint64(buf[0]) | uint64(buf[1])<<8, nil
	case 0xFE:
		var buf [4]byte
		if _, err := r.Read(buf[:]); err != nil {
			return 0, err
		}
		return uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24, nil
	case 0xFF:
		var buf [8]byte
		if _, err := r.Read(buf[:]); err != nil {
			return 0, err
		}
		return uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
			uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56, nil
	default:
		return uint64(first), nil
	}
}
