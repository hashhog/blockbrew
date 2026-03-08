package consensus

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// createTestOutpoint creates a test outpoint with a unique hash.
func createTestOutpoint(seed byte, index uint32) wire.OutPoint {
	var hash wire.Hash256
	for i := range hash {
		hash[i] = seed
	}
	return wire.OutPoint{Hash: hash, Index: index}
}

// createTestEntry creates a test UTXO entry.
func createTestEntry(amount int64, height int32, isCoinbase bool, pkScript []byte) *UTXOEntry {
	return &UTXOEntry{
		Amount:     amount,
		PkScript:   pkScript,
		Height:     height,
		IsCoinbase: isCoinbase,
	}
}

func TestUTXOSetBasicOperations(t *testing.T) {
	// Create an in-memory database
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	outpoint := createTestOutpoint(0x01, 0)
	entry := createTestEntry(50_00000000, 100, true, []byte{0x76, 0xa9}) // coinbase

	// Test Add and Get
	utxoSet.AddUTXO(outpoint, entry)
	retrieved := utxoSet.GetUTXO(outpoint)
	if retrieved == nil {
		t.Fatal("expected UTXO to be found")
	}
	if retrieved.Amount != entry.Amount {
		t.Errorf("amount mismatch: got %d, want %d", retrieved.Amount, entry.Amount)
	}
	if retrieved.Height != entry.Height {
		t.Errorf("height mismatch: got %d, want %d", retrieved.Height, entry.Height)
	}
	if retrieved.IsCoinbase != entry.IsCoinbase {
		t.Errorf("isCoinbase mismatch: got %v, want %v", retrieved.IsCoinbase, entry.IsCoinbase)
	}

	// Test HasUTXO
	if !utxoSet.HasUTXO(outpoint) {
		t.Error("expected HasUTXO to return true")
	}

	// Test Size
	if utxoSet.Size() != 1 {
		t.Errorf("expected size 1, got %d", utxoSet.Size())
	}
}

func TestUTXOSetSpend(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	outpoint := createTestOutpoint(0x02, 0)
	entry := createTestEntry(100_000, 200, false, []byte{0x00, 0x14})

	// Add and spend
	utxoSet.AddUTXO(outpoint, entry)
	err := utxoSet.SpendUTXOChecked(outpoint)
	if err != nil {
		t.Fatalf("SpendUTXOChecked failed: %v", err)
	}

	// Verify it's gone
	if utxoSet.GetUTXO(outpoint) != nil {
		t.Error("expected UTXO to be nil after spending")
	}
	if utxoSet.HasUTXO(outpoint) {
		t.Error("expected HasUTXO to return false after spending")
	}
}

func TestUTXOSetDoubleSpend(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	outpoint := createTestOutpoint(0x03, 0)
	entry := createTestEntry(100_000, 200, false, []byte{0x00, 0x14})

	// Add and spend
	utxoSet.AddUTXO(outpoint, entry)
	err := utxoSet.SpendUTXOChecked(outpoint)
	if err != nil {
		t.Fatalf("first SpendUTXOChecked failed: %v", err)
	}

	// Try to spend again
	err = utxoSet.SpendUTXOChecked(outpoint)
	if err != ErrUTXOAlreadySpent {
		t.Errorf("expected ErrUTXOAlreadySpent, got %v", err)
	}
}

func TestUTXOSetSpendNonexistent(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	outpoint := createTestOutpoint(0x04, 0)

	// Try to spend a non-existent UTXO
	err := utxoSet.SpendUTXOChecked(outpoint)
	if err != ErrUTXONotFound {
		t.Errorf("expected ErrUTXONotFound, got %v", err)
	}
}

func TestUTXOSetFlush(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	outpoint := createTestOutpoint(0x05, 0)
	entry := createTestEntry(50_00000000, 100, true, []byte{0x76, 0xa9, 0x14})

	// Add and flush
	utxoSet.AddUTXO(outpoint, entry)
	err := utxoSet.Flush()
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// Create new UTXOSet to simulate restart
	utxoSet2 := NewUTXOSet(chainDB)

	// Verify persisted data
	retrieved := utxoSet2.GetUTXO(outpoint)
	if retrieved == nil {
		t.Fatal("expected UTXO to be found after reload")
	}
	if retrieved.Amount != entry.Amount {
		t.Errorf("amount mismatch after reload: got %d, want %d", retrieved.Amount, entry.Amount)
	}
}

func TestUTXOSetFlushDelete(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	outpoint := createTestOutpoint(0x06, 0)
	entry := createTestEntry(50_00000000, 100, true, []byte{0x76, 0xa9, 0x14})

	// Add, flush, spend, flush again
	utxoSet.AddUTXO(outpoint, entry)
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("first flush failed: %v", err)
	}

	if err := utxoSet.SpendUTXOChecked(outpoint); err != nil {
		t.Fatalf("spend failed: %v", err)
	}

	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("second flush failed: %v", err)
	}

	// Create new UTXOSet and verify deletion persisted
	utxoSet2 := NewUTXOSet(chainDB)
	if utxoSet2.GetUTXO(outpoint) != nil {
		t.Error("expected UTXO to be deleted after flush")
	}
}

// Test UTXO serialization round-trip
func TestUTXOEntrySerialization(t *testing.T) {
	testCases := []struct {
		name  string
		entry *UTXOEntry
	}{
		{
			name: "coinbase",
			entry: &UTXOEntry{
				Amount:     50_00000000,
				PkScript:   []byte{0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x88, 0xac},
				Height:     100,
				IsCoinbase: true,
			},
		},
		{
			name: "regular",
			entry: &UTXOEntry{
				Amount:     12345678,
				PkScript:   []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
				Height:     500000,
				IsCoinbase: false,
			},
		},
		{
			name: "zero_amount",
			entry: &UTXOEntry{
				Amount:     0,
				PkScript:   []byte{0xa9, 0x14},
				Height:     0,
				IsCoinbase: false,
			},
		},
		{
			name: "large_height",
			entry: &UTXOEntry{
				Amount:     21_000_000_00000000,
				PkScript:   []byte{0x51, 0x20},
				Height:     2_000_000,
				IsCoinbase: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := SerializeUTXOEntry(tc.entry)
			restored, err := DeserializeUTXOEntry(data)
			if err != nil {
				t.Fatalf("deserialization failed: %v", err)
			}

			if restored.Amount != tc.entry.Amount {
				t.Errorf("amount mismatch: got %d, want %d", restored.Amount, tc.entry.Amount)
			}
			if restored.Height != tc.entry.Height {
				t.Errorf("height mismatch: got %d, want %d", restored.Height, tc.entry.Height)
			}
			if restored.IsCoinbase != tc.entry.IsCoinbase {
				t.Errorf("isCoinbase mismatch: got %v, want %v", restored.IsCoinbase, tc.entry.IsCoinbase)
			}
			// Note: Scripts are compressed/decompressed, so we compare the decompressed versions
			if !bytes.Equal(DecompressScript(CompressScript(tc.entry.PkScript)), DecompressScript(CompressScript(restored.PkScript))) {
				t.Errorf("pkScript mismatch after round-trip")
			}
		})
	}
}

// Test script compression for all 5 types + unknown
func TestScriptCompression(t *testing.T) {
	testCases := []struct {
		name           string
		script         []byte
		expectedType   byte
		compressedLen  int
	}{
		{
			name: "P2PKH",
			script: []byte{
				0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH20
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
				0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
				0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
			},
			expectedType:  scriptTypeP2PKH,
			compressedLen: 21,
		},
		{
			name: "P2SH",
			script: []byte{
				0xa9, 0x14, // OP_HASH160 PUSH20
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
				0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
				0x87, // OP_EQUAL
			},
			expectedType:  scriptTypeP2SH,
			compressedLen: 21,
		},
		{
			name: "P2WPKH",
			script: []byte{
				0x00, 0x14, // OP_0 PUSH20
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
				0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
			},
			expectedType:  scriptTypeP2WPKH,
			compressedLen: 21,
		},
		{
			name: "P2WSH",
			script: []byte{
				0x00, 0x20, // OP_0 PUSH32
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
				0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
				0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
				0x1f, 0x20,
			},
			expectedType:  scriptTypeP2WSH,
			compressedLen: 33,
		},
		{
			name: "P2TR",
			script: []byte{
				0x51, 0x20, // OP_1 PUSH32
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
				0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
				0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
				0x1f, 0x20,
			},
			expectedType:  scriptTypeP2TR,
			compressedLen: 33,
		},
		{
			name: "Unknown",
			script: []byte{
				0x52, 0x21, // OP_2 PUSH33 (multisig or other)
				0x01, 0x02, 0x03, 0x04, 0x05,
			},
			expectedType:  scriptTypeUnknown,
			compressedLen: 8, // 1 (type) + 7 (script)
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			compressed := CompressScript(tc.script)

			// Check type byte
			if compressed[0] != tc.expectedType {
				t.Errorf("expected type %d, got %d", tc.expectedType, compressed[0])
			}

			// Check compressed length
			if len(compressed) != tc.compressedLen {
				t.Errorf("expected compressed len %d, got %d", tc.compressedLen, len(compressed))
			}

			// Round-trip test
			decompressed := DecompressScript(compressed)
			if !bytes.Equal(decompressed, tc.script) {
				t.Errorf("script mismatch after round-trip\noriginal:     %x\ndecompressed: %x", tc.script, decompressed)
			}
		})
	}
}

func TestScriptTypeDetection(t *testing.T) {
	// P2PKH
	p2pkh := []byte{0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac}
	if !IsP2PKH(p2pkh) {
		t.Error("expected IsP2PKH to return true")
	}
	if IsP2SH(p2pkh) || IsP2WPKH(p2pkh) || IsP2WSH(p2pkh) || IsP2TR(p2pkh) {
		t.Error("P2PKH misidentified as another type")
	}

	// P2SH
	p2sh := []byte{0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87}
	if !IsP2SH(p2sh) {
		t.Error("expected IsP2SH to return true")
	}
	if IsP2PKH(p2sh) || IsP2WPKH(p2sh) || IsP2WSH(p2sh) || IsP2TR(p2sh) {
		t.Error("P2SH misidentified as another type")
	}

	// P2WPKH
	p2wpkh := []byte{0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !IsP2WPKH(p2wpkh) {
		t.Error("expected IsP2WPKH to return true")
	}
	if IsP2PKH(p2wpkh) || IsP2SH(p2wpkh) || IsP2WSH(p2wpkh) || IsP2TR(p2wpkh) {
		t.Error("P2WPKH misidentified as another type")
	}

	// P2WSH
	p2wsh := make([]byte, 34)
	p2wsh[0] = 0x00
	p2wsh[1] = 0x20
	if !IsP2WSH(p2wsh) {
		t.Error("expected IsP2WSH to return true")
	}
	if IsP2PKH(p2wsh) || IsP2SH(p2wsh) || IsP2WPKH(p2wsh) || IsP2TR(p2wsh) {
		t.Error("P2WSH misidentified as another type")
	}

	// P2TR
	p2tr := make([]byte, 34)
	p2tr[0] = 0x51
	p2tr[1] = 0x20
	if !IsP2TR(p2tr) {
		t.Error("expected IsP2TR to return true")
	}
	if IsP2PKH(p2tr) || IsP2SH(p2tr) || IsP2WPKH(p2tr) || IsP2WSH(p2tr) {
		t.Error("P2TR misidentified as another type")
	}
}

// Test undo block serialization
func TestUndoBlockSerialization(t *testing.T) {
	undo := &UndoBlock{
		SpentOutputs: []SpentOutput{
			{
				OutPoint: createTestOutpoint(0x10, 0),
				Entry: UTXOEntry{
					Amount:     50_00000000,
					PkScript:   []byte{0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x88, 0xac},
					Height:     100,
					IsCoinbase: true,
				},
			},
			{
				OutPoint: createTestOutpoint(0x20, 1),
				Entry: UTXOEntry{
					Amount:     12345,
					PkScript:   []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
					Height:     200,
					IsCoinbase: false,
				},
			},
		},
	}

	data := undo.Serialize()
	restored, err := DeserializeUndoBlock(data)
	if err != nil {
		t.Fatalf("deserialization failed: %v", err)
	}

	if len(restored.SpentOutputs) != len(undo.SpentOutputs) {
		t.Fatalf("spent outputs count mismatch: got %d, want %d", len(restored.SpentOutputs), len(undo.SpentOutputs))
	}

	for i := range undo.SpentOutputs {
		orig := undo.SpentOutputs[i]
		rest := restored.SpentOutputs[i]

		if orig.OutPoint != rest.OutPoint {
			t.Errorf("outpoint mismatch at index %d", i)
		}
		if orig.Entry.Amount != rest.Entry.Amount {
			t.Errorf("amount mismatch at index %d: got %d, want %d", i, rest.Entry.Amount, orig.Entry.Amount)
		}
		if orig.Entry.Height != rest.Entry.Height {
			t.Errorf("height mismatch at index %d", i)
		}
		if orig.Entry.IsCoinbase != rest.Entry.IsCoinbase {
			t.Errorf("isCoinbase mismatch at index %d", i)
		}
	}
}

// Test connect and disconnect block
func TestConnectDisconnectBlock(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	// Create a P2PKH script for testing
	p2pkhScript := []byte{
		0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH20
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
	}

	// Create a "previous" coinbase output that we'll spend
	prevTxHash := wire.Hash256{0xaa}
	prevOutpoint := wire.OutPoint{Hash: prevTxHash, Index: 0}
	prevEntry := &UTXOEntry{
		Amount:     50_00000000,
		PkScript:   p2pkhScript,
		Height:     100,
		IsCoinbase: true,
	}
	utxoSet.AddUTXO(prevOutpoint, prevEntry)

	// Create a simple block with:
	// - A coinbase transaction
	// - A regular transaction that spends the previous coinbase output
	coinbaseTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{}, // null hash
					Index: 0xFFFFFFFF,
				},
				SignatureScript: []byte{0x04, 0x01, 0x02, 0x03, 0x04}, // valid coinbase scriptSig
				Sequence:        0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 50_00000000, PkScript: p2pkhScript},
		},
		LockTime: 0,
	}

	regularTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: prevOutpoint,
				SignatureScript:  []byte{0x00},
				Sequence:         0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 25_00000000, PkScript: p2pkhScript},
			{Value: 24_99990000, PkScript: p2pkhScript}, // Fee: 10000
		},
		LockTime: 0,
	}

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1},
		Transactions: []*wire.MsgTx{coinbaseTx, regularTx},
	}

	// Connect the block
	undo, err := utxoSet.ConnectBlockUTXOs(block, 201)
	if err != nil {
		t.Fatalf("ConnectBlockUTXOs failed: %v", err)
	}

	// Verify the previous output is now spent
	if utxoSet.HasUTXO(prevOutpoint) {
		t.Error("expected previous output to be spent")
	}

	// Verify new outputs exist
	coinbaseHash := coinbaseTx.TxHash()
	regularHash := regularTx.TxHash()

	if !utxoSet.HasUTXO(wire.OutPoint{Hash: coinbaseHash, Index: 0}) {
		t.Error("expected coinbase output to exist")
	}
	if !utxoSet.HasUTXO(wire.OutPoint{Hash: regularHash, Index: 0}) {
		t.Error("expected regular tx output 0 to exist")
	}
	if !utxoSet.HasUTXO(wire.OutPoint{Hash: regularHash, Index: 1}) {
		t.Error("expected regular tx output 1 to exist")
	}

	// Verify undo data is correct
	if len(undo.SpentOutputs) != 1 {
		t.Fatalf("expected 1 spent output in undo, got %d", len(undo.SpentOutputs))
	}
	if undo.SpentOutputs[0].OutPoint != prevOutpoint {
		t.Error("undo spent output has wrong outpoint")
	}
	if undo.SpentOutputs[0].Entry.Amount != prevEntry.Amount {
		t.Errorf("undo spent output has wrong amount: got %d, want %d",
			undo.SpentOutputs[0].Entry.Amount, prevEntry.Amount)
	}

	// Disconnect the block
	err = utxoSet.DisconnectBlockUTXOs(block, undo)
	if err != nil {
		t.Fatalf("DisconnectBlockUTXOs failed: %v", err)
	}

	// Verify the previous output is restored
	if !utxoSet.HasUTXO(prevOutpoint) {
		t.Error("expected previous output to be restored")
	}
	restored := utxoSet.GetUTXO(prevOutpoint)
	if restored == nil {
		t.Fatal("expected to get restored UTXO")
	}
	if restored.Amount != prevEntry.Amount {
		t.Errorf("restored amount mismatch: got %d, want %d", restored.Amount, prevEntry.Amount)
	}
	if restored.Height != prevEntry.Height {
		t.Errorf("restored height mismatch: got %d, want %d", restored.Height, prevEntry.Height)
	}

	// Verify block outputs are gone
	if utxoSet.HasUTXO(wire.OutPoint{Hash: coinbaseHash, Index: 0}) {
		t.Error("expected coinbase output to be removed")
	}
	if utxoSet.HasUTXO(wire.OutPoint{Hash: regularHash, Index: 0}) {
		t.Error("expected regular tx output 0 to be removed")
	}
	if utxoSet.HasUTXO(wire.OutPoint{Hash: regularHash, Index: 1}) {
		t.Error("expected regular tx output 1 to be removed")
	}
}

func TestUTXOSetNilDB(t *testing.T) {
	// Test with nil database (pure in-memory mode)
	utxoSet := NewUTXOSet(nil)

	outpoint := createTestOutpoint(0x50, 0)
	entry := createTestEntry(12345, 10, false, []byte{0x00})

	utxoSet.AddUTXO(outpoint, entry)

	if !utxoSet.HasUTXO(outpoint) {
		t.Error("expected UTXO to exist")
	}

	// Flush should not panic with nil db
	err := utxoSet.Flush()
	if err != nil {
		t.Errorf("flush with nil db failed: %v", err)
	}
}

func TestOPReturnNotAdded(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	// Create a transaction with an OP_RETURN output
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
				SignatureScript:  []byte{0x04, 0x01, 0x02, 0x03, 0x04},
				Sequence:         0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 50_00000000, PkScript: []byte{0x76, 0xa9}},           // Regular output
			{Value: 0, PkScript: []byte{0x6a, 0x04, 0x01, 0x02, 0x03}},   // OP_RETURN
			{Value: 10_00000000, PkScript: []byte{0x00, 0x14, 0x01}},     // Another regular output
		},
		LockTime: 0,
	}

	utxoSet.AddTxOutputs(tx, 100)

	txHash := tx.TxHash()

	// Regular outputs should be added
	if !utxoSet.HasUTXO(wire.OutPoint{Hash: txHash, Index: 0}) {
		t.Error("expected output 0 to be added")
	}
	if !utxoSet.HasUTXO(wire.OutPoint{Hash: txHash, Index: 2}) {
		t.Error("expected output 2 to be added")
	}

	// OP_RETURN should NOT be added
	if utxoSet.HasUTXO(wire.OutPoint{Hash: txHash, Index: 1}) {
		t.Error("OP_RETURN output should not be added to UTXO set")
	}
}

func TestEmptyScript(t *testing.T) {
	// Test compression of empty script
	empty := []byte{}
	compressed := CompressScript(empty)
	decompressed := DecompressScript(compressed)
	if !bytes.Equal(decompressed, empty) {
		t.Errorf("empty script round-trip failed: got %x", decompressed)
	}
}

func TestUTXOSetConcurrency(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	// Test concurrent access
	done := make(chan bool, 10)

	// Concurrent adds
	for i := 0; i < 5; i++ {
		go func(seed byte) {
			for j := 0; j < 100; j++ {
				outpoint := createTestOutpoint(seed, uint32(j))
				entry := createTestEntry(int64(j), int32(j), false, []byte{seed})
				utxoSet.AddUTXO(outpoint, entry)
			}
			done <- true
		}(byte(i))
	}

	// Concurrent reads
	for i := 0; i < 5; i++ {
		go func(seed byte) {
			for j := 0; j < 100; j++ {
				outpoint := createTestOutpoint(seed, uint32(j))
				utxoSet.GetUTXO(outpoint)
				utxoSet.HasUTXO(outpoint)
			}
			done <- true
		}(byte(i))
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Just verify we didn't panic or deadlock
	t.Log("Concurrency test passed without panics or deadlocks")
}
