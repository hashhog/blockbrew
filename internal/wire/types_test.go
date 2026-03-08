package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// mustDecodeHex decodes a hex string and panics on error.
func mustDecodeHexTypes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestHash256String(t *testing.T) {
	// Test that String() reverses bytes for display
	var h Hash256
	// Internal bytes: 0x01, 0x02, ..., 0x20
	for i := 0; i < 32; i++ {
		h[i] = byte(i + 1)
	}
	got := h.String()
	// Should be reversed: 0x20, 0x1f, ..., 0x01
	want := "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201"
	if got != want {
		t.Errorf("Hash256.String(): got %s, want %s", got, want)
	}
}

func TestHash256IsZero(t *testing.T) {
	var zero Hash256
	if !zero.IsZero() {
		t.Error("zero hash should return true for IsZero")
	}

	nonZero := Hash256{1}
	if nonZero.IsZero() {
		t.Error("non-zero hash should return false for IsZero")
	}
}

func TestHash256SetBytes(t *testing.T) {
	var h Hash256
	input := make([]byte, 32)
	for i := range input {
		input[i] = byte(i)
	}
	h.SetBytes(input)
	for i := 0; i < 32; i++ {
		if h[i] != byte(i) {
			t.Errorf("SetBytes: h[%d] = %d, want %d", i, h[i], i)
		}
	}
}

func TestNewHash256FromHex(t *testing.T) {
	// Bitcoin genesis block hash in display order (reversed)
	displayHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	h, err := NewHash256FromHex(displayHex)
	if err != nil {
		t.Fatalf("NewHash256FromHex error: %v", err)
	}

	// Verify it reverses properly
	if h.String() != displayHex {
		t.Errorf("NewHash256FromHex round-trip failed: got %s, want %s", h.String(), displayHex)
	}

	// Test invalid inputs
	_, err = NewHash256FromHex("abc") // too short
	if err == nil {
		t.Error("NewHash256FromHex should fail for short input")
	}

	_, err = NewHash256FromHex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") // invalid hex
	if err == nil {
		t.Error("NewHash256FromHex should fail for invalid hex")
	}
}

func TestHash256Serialize(t *testing.T) {
	var h Hash256
	for i := 0; i < 32; i++ {
		h[i] = byte(i)
	}

	var buf bytes.Buffer
	if err := h.Serialize(&buf); err != nil {
		t.Fatalf("Serialize error: %v", err)
	}

	if buf.Len() != 32 {
		t.Errorf("Serialize: got %d bytes, want 32", buf.Len())
	}

	var h2 Hash256
	if err := h2.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize error: %v", err)
	}

	if h != h2 {
		t.Error("Hash256 round-trip failed")
	}
}

func TestDoubleHashB(t *testing.T) {
	// Test double hash of empty input
	// SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	// SHA256(SHA256("")) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
	h := DoubleHashB([]byte{})
	want := mustDecodeHexTypes("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
	for i := 0; i < 32; i++ {
		if h[i] != want[i] {
			t.Errorf("DoubleHashB: byte %d: got %02x, want %02x", i, h[i], want[i])
		}
	}
}

func TestGenesisBlockHeader(t *testing.T) {
	// Genesis block header hex (80 bytes)
	genesisHeaderHex := "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
	genesisHeaderBytes := mustDecodeHexTypes(genesisHeaderHex)

	// Deserialize the header
	var header BlockHeader
	buf := bytes.NewReader(genesisHeaderBytes)
	if err := header.Deserialize(buf); err != nil {
		t.Fatalf("Deserialize error: %v", err)
	}

	// Verify fields
	if header.Version != 1 {
		t.Errorf("Version: got %d, want 1", header.Version)
	}
	if !header.PrevBlock.IsZero() {
		t.Error("PrevBlock should be zero for genesis block")
	}
	if header.Timestamp != 1231006505 {
		t.Errorf("Timestamp: got %d, want 1231006505", header.Timestamp)
	}
	if header.Bits != 0x1d00ffff {
		t.Errorf("Bits: got %x, want 1d00ffff", header.Bits)
	}
	if header.Nonce != 2083236893 {
		t.Errorf("Nonce: got %d, want 2083236893", header.Nonce)
	}

	// Serialize and verify round-trip
	var serialized bytes.Buffer
	if err := header.Serialize(&serialized); err != nil {
		t.Fatalf("Serialize error: %v", err)
	}
	if !bytes.Equal(serialized.Bytes(), genesisHeaderBytes) {
		t.Errorf("Serialized header mismatch:\ngot  %x\nwant %x", serialized.Bytes(), genesisHeaderBytes)
	}

	// Verify block hash
	blockHash := header.BlockHash()

	// Expected hash in internal byte order (not reversed)
	internalHashHex := "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
	expectedInternal := mustDecodeHexTypes(internalHashHex)
	for i := 0; i < 32; i++ {
		if blockHash[i] != expectedInternal[i] {
			t.Errorf("BlockHash internal byte %d: got %02x, want %02x", i, blockHash[i], expectedInternal[i])
		}
	}

	// Expected hash in display order (reversed)
	displayHashHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	if blockHash.String() != displayHashHex {
		t.Errorf("BlockHash display: got %s, want %s", blockHash.String(), displayHashHex)
	}
}

func TestBlockHeaderSize(t *testing.T) {
	// Block header should always be exactly 80 bytes
	var header BlockHeader
	header.Version = 1
	header.Timestamp = 12345
	header.Bits = 0x1d00ffff
	header.Nonce = 67890

	var buf bytes.Buffer
	if err := header.Serialize(&buf); err != nil {
		t.Fatalf("Serialize error: %v", err)
	}

	if buf.Len() != 80 {
		t.Errorf("BlockHeader size: got %d bytes, want 80", buf.Len())
	}
}

func TestOutPointSerialize(t *testing.T) {
	op := OutPoint{
		Hash:  Hash256{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Index: 0x12345678,
	}

	var buf bytes.Buffer
	if err := op.Serialize(&buf); err != nil {
		t.Fatalf("Serialize error: %v", err)
	}

	// 32 bytes hash + 4 bytes index = 36 bytes
	if buf.Len() != 36 {
		t.Errorf("OutPoint size: got %d bytes, want 36", buf.Len())
	}

	var op2 OutPoint
	if err := op2.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize error: %v", err)
	}

	if op.Hash != op2.Hash || op.Index != op2.Index {
		t.Error("OutPoint round-trip failed")
	}
}

func TestTxInSerialize(t *testing.T) {
	ti := &TxIn{
		PreviousOutPoint: OutPoint{
			Hash:  Hash256{1, 2, 3},
			Index: 0,
		},
		SignatureScript: []byte{0x01, 0x02, 0x03},
		Sequence:        0xFFFFFFFF,
	}

	var buf bytes.Buffer
	if err := ti.Serialize(&buf); err != nil {
		t.Fatalf("Serialize error: %v", err)
	}

	var ti2 TxIn
	if err := ti2.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize error: %v", err)
	}

	if ti.PreviousOutPoint.Hash != ti2.PreviousOutPoint.Hash ||
		ti.PreviousOutPoint.Index != ti2.PreviousOutPoint.Index ||
		!bytes.Equal(ti.SignatureScript, ti2.SignatureScript) ||
		ti.Sequence != ti2.Sequence {
		t.Error("TxIn round-trip failed")
	}
}

func TestTxOutSerialize(t *testing.T) {
	to := &TxOut{
		Value:    5000000000, // 50 BTC
		PkScript: []byte{0x76, 0xa9, 0x14}, // OP_DUP OP_HASH160 ...
	}

	var buf bytes.Buffer
	if err := to.Serialize(&buf); err != nil {
		t.Fatalf("Serialize error: %v", err)
	}

	var to2 TxOut
	if err := to2.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize error: %v", err)
	}

	if to.Value != to2.Value || !bytes.Equal(to.PkScript, to2.PkScript) {
		t.Error("TxOut round-trip failed")
	}
}

func TestMsgTxHasWitness(t *testing.T) {
	// Transaction without witness
	txNoWitness := &MsgTx{
		Version: 1,
		TxIn: []*TxIn{
			{
				PreviousOutPoint: OutPoint{Index: 0},
				SignatureScript:  []byte{0x01},
				Sequence:         0xFFFFFFFF,
			},
		},
		TxOut: []*TxOut{
			{Value: 1000, PkScript: []byte{0x76}},
		},
		LockTime: 0,
	}
	if txNoWitness.HasWitness() {
		t.Error("Transaction without witness should return false")
	}

	// Transaction with witness
	txWithWitness := &MsgTx{
		Version: 2,
		TxIn: []*TxIn{
			{
				PreviousOutPoint: OutPoint{Index: 0},
				SignatureScript:  []byte{},
				Witness:          [][]byte{{0x30, 0x44}, {0x02, 0x21}},
				Sequence:         0xFFFFFFFF,
			},
		},
		TxOut: []*TxOut{
			{Value: 1000, PkScript: []byte{0x00, 0x14}},
		},
		LockTime: 0,
	}
	if !txWithWitness.HasWitness() {
		t.Error("Transaction with witness should return true")
	}
}

func TestMsgTxSerializeLegacy(t *testing.T) {
	// Create a simple legacy transaction
	tx := &MsgTx{
		Version: 1,
		TxIn: []*TxIn{
			{
				PreviousOutPoint: OutPoint{
					Hash:  Hash256{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
					Index: 0,
				},
				SignatureScript: []byte{0x01, 0x02, 0x03},
				Sequence:        0xFFFFFFFF,
			},
		},
		TxOut: []*TxOut{
			{Value: 5000000000, PkScript: []byte{0x76, 0xa9}},
		},
		LockTime: 0,
	}

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatalf("Serialize error: %v", err)
	}

	var tx2 MsgTx
	if err := tx2.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize error: %v", err)
	}

	// Verify fields
	if tx.Version != tx2.Version {
		t.Errorf("Version mismatch: got %d, want %d", tx2.Version, tx.Version)
	}
	if len(tx.TxIn) != len(tx2.TxIn) {
		t.Errorf("TxIn count mismatch: got %d, want %d", len(tx2.TxIn), len(tx.TxIn))
	}
	if len(tx.TxOut) != len(tx2.TxOut) {
		t.Errorf("TxOut count mismatch: got %d, want %d", len(tx2.TxOut), len(tx.TxOut))
	}
	if tx.LockTime != tx2.LockTime {
		t.Errorf("LockTime mismatch: got %d, want %d", tx2.LockTime, tx.LockTime)
	}
}

func TestMsgTxSerializeSegwit(t *testing.T) {
	// Create a segwit transaction
	tx := &MsgTx{
		Version: 2,
		TxIn: []*TxIn{
			{
				PreviousOutPoint: OutPoint{
					Hash:  Hash256{1, 2, 3},
					Index: 0,
				},
				SignatureScript: []byte{},
				Witness: [][]byte{
					{0x30, 0x44, 0x02, 0x20}, // signature part
					{0x02, 0x21},             // pubkey part
				},
				Sequence: 0xFFFFFFFD,
			},
		},
		TxOut: []*TxOut{
			{Value: 1000, PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03}},
		},
		LockTime: 500000,
	}

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatalf("Serialize error: %v", err)
	}

	// Check that marker and flag bytes are present
	serialized := buf.Bytes()
	// Version (4 bytes) + marker (1) + flag (1)
	if len(serialized) < 6 {
		t.Fatal("Serialized segwit tx too short")
	}
	if serialized[4] != 0x00 || serialized[5] != 0x01 {
		t.Errorf("Missing segwit marker/flag: got %02x %02x, want 00 01", serialized[4], serialized[5])
	}

	var tx2 MsgTx
	if err := tx2.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize error: %v", err)
	}

	// Verify witness data preserved
	if len(tx2.TxIn) != 1 {
		t.Fatalf("TxIn count: got %d, want 1", len(tx2.TxIn))
	}
	if len(tx2.TxIn[0].Witness) != 2 {
		t.Fatalf("Witness count: got %d, want 2", len(tx2.TxIn[0].Witness))
	}
	if !bytes.Equal(tx2.TxIn[0].Witness[0], tx.TxIn[0].Witness[0]) {
		t.Error("Witness[0] mismatch")
	}
	if !bytes.Equal(tx2.TxIn[0].Witness[1], tx.TxIn[0].Witness[1]) {
		t.Error("Witness[1] mismatch")
	}
}

func TestMsgTxTxHashVsWTxHash(t *testing.T) {
	// For a segwit transaction, TxHash != WTxHash
	tx := &MsgTx{
		Version: 2,
		TxIn: []*TxIn{
			{
				PreviousOutPoint: OutPoint{Hash: Hash256{1}, Index: 0},
				SignatureScript:  []byte{},
				Witness:          [][]byte{{0x30, 0x44}, {0x02, 0x21}},
				Sequence:         0xFFFFFFFF,
			},
		},
		TxOut: []*TxOut{
			{Value: 1000, PkScript: []byte{0x00, 0x14}},
		},
		LockTime: 0,
	}

	txHash := tx.TxHash()
	wtxHash := tx.WTxHash()

	if txHash == wtxHash {
		t.Error("TxHash and WTxHash should differ for segwit transaction")
	}

	// For a non-witness transaction, TxHash == WTxHash
	txLegacy := &MsgTx{
		Version: 1,
		TxIn: []*TxIn{
			{
				PreviousOutPoint: OutPoint{Hash: Hash256{1}, Index: 0},
				SignatureScript:  []byte{0x01, 0x02},
				Sequence:         0xFFFFFFFF,
			},
		},
		TxOut: []*TxOut{
			{Value: 1000, PkScript: []byte{0x76, 0xa9}},
		},
		LockTime: 0,
	}

	legacyTxHash := txLegacy.TxHash()
	legacyWTxHash := txLegacy.WTxHash()

	if legacyTxHash != legacyWTxHash {
		t.Error("TxHash and WTxHash should be equal for legacy transaction")
	}
}

func TestMsgBlockSerialize(t *testing.T) {
	block := &MsgBlock{
		Header: BlockHeader{
			Version:    1,
			PrevBlock:  Hash256{},
			MerkleRoot: Hash256{1, 2, 3},
			Timestamp:  1231006505,
			Bits:       0x1d00ffff,
			Nonce:      2083236893,
		},
		Transactions: []*MsgTx{
			{
				Version: 1,
				TxIn: []*TxIn{
					{
						PreviousOutPoint: OutPoint{},
						SignatureScript:  []byte{0x04, 0xFF, 0xFF, 0x00, 0x1D},
						Sequence:         0xFFFFFFFF,
					},
				},
				TxOut: []*TxOut{
					{Value: 5000000000, PkScript: []byte{0x76, 0xa9}},
				},
				LockTime: 0,
			},
		},
	}

	var buf bytes.Buffer
	if err := block.Serialize(&buf); err != nil {
		t.Fatalf("Serialize error: %v", err)
	}

	var block2 MsgBlock
	if err := block2.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize error: %v", err)
	}

	// Verify header
	if block.Header.Version != block2.Header.Version {
		t.Error("Header version mismatch")
	}
	if block.Header.Timestamp != block2.Header.Timestamp {
		t.Error("Header timestamp mismatch")
	}

	// Verify transactions
	if len(block.Transactions) != len(block2.Transactions) {
		t.Errorf("Transaction count: got %d, want %d", len(block2.Transactions), len(block.Transactions))
	}
}

func TestMerkleRootValue(t *testing.T) {
	// Genesis block merkle root in display order
	merkleRootDisplay := "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

	// Verify we can parse it
	_, err := NewHash256FromHex(merkleRootDisplay)
	if err != nil {
		t.Fatalf("NewHash256FromHex error: %v", err)
	}
}

// Benchmark tests
func BenchmarkBlockHeaderSerialize(b *testing.B) {
	header := BlockHeader{
		Version:    1,
		Timestamp:  1231006505,
		Bits:       0x1d00ffff,
		Nonce:      2083236893,
	}
	var buf bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		header.Serialize(&buf)
	}
}

func BenchmarkBlockHeaderDeserialize(b *testing.B) {
	genesisHeaderBytes := mustDecodeHexTypes("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var header BlockHeader
		header.Deserialize(bytes.NewReader(genesisHeaderBytes))
	}
}

func BenchmarkDoubleHashB(b *testing.B) {
	data := make([]byte, 80) // block header size
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DoubleHashB(data)
	}
}

func BenchmarkTxHash(b *testing.B) {
	tx := &MsgTx{
		Version: 1,
		TxIn: []*TxIn{
			{
				PreviousOutPoint: OutPoint{Hash: Hash256{1}, Index: 0},
				SignatureScript:  make([]byte, 100),
				Sequence:         0xFFFFFFFF,
			},
		},
		TxOut: []*TxOut{
			{Value: 1000, PkScript: make([]byte, 25)},
		},
		LockTime: 0,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx.TxHash()
	}
}
