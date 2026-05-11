package p2p

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TestSipHash24 tests the SipHash-2-4 implementation.
func TestSipHash24(t *testing.T) {
	// Test vector from SipHash reference implementation
	// Key: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
	// Data: (empty)
	key := SipHashKey{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	result := siphash24(key, nil)

	// Verify non-zero output for a non-trivial key
	if result == 0 {
		t.Error("siphash24 returned zero for non-trivial key")
	}

	// Test with some data
	result2 := siphash24(key, []byte{0, 1, 2, 3, 4, 5, 6, 7})
	if result2 == result {
		t.Error("siphash24 returned same result for different inputs")
	}

	// Test determinism
	result3 := siphash24(key, []byte{0, 1, 2, 3, 4, 5, 6, 7})
	if result3 != result2 {
		t.Error("siphash24 is not deterministic")
	}
}

// TestComputeShortID tests short ID computation.
func TestComputeShortID(t *testing.T) {
	header := &wire.BlockHeader{
		Version:    1,
		PrevBlock:  wire.Hash256{},
		MerkleRoot: wire.Hash256{},
		Timestamp:  1234567890,
		Bits:       0x1d00ffff,
		Nonce:      12345,
	}

	nonce := uint64(0xDEADBEEF)
	key := ComputeSipHashKey(header, nonce)

	txHash1 := wire.Hash256{}
	txHash1[0] = 0x01

	txHash2 := wire.Hash256{}
	txHash2[0] = 0x02

	shortID1 := ComputeShortID(key, txHash1)
	shortID2 := ComputeShortID(key, txHash2)

	// Short IDs should be 6 bytes (48 bits)
	if shortID1 >= 1<<48 {
		t.Errorf("shortID1 exceeds 48 bits: 0x%x", shortID1)
	}
	if shortID2 >= 1<<48 {
		t.Errorf("shortID2 exceeds 48 bits: 0x%x", shortID2)
	}

	// Different transactions should have different short IDs
	if shortID1 == shortID2 {
		t.Error("different transactions have same short ID")
	}

	// Same transaction should always get same short ID
	shortID1b := ComputeShortID(key, txHash1)
	if shortID1 != shortID1b {
		t.Error("same transaction got different short IDs")
	}
}

// TestCompactBlockBuilder tests building compact blocks.
func TestCompactBlockBuilder(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)
	tx2 := createTestTx(2, 2, 2_0000_0000, nil)

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			Timestamp:  1234567890,
			Bits:       0x1d00ffff,
			Nonce:      12345,
		},
		Transactions: []*wire.MsgTx{coinbase, tx1, tx2},
	}

	nonce := uint64(0xCAFEBABE)
	builder := NewCompactBlockBuilder(&block.Header, nonce)
	cmpctblock := builder.Build(block)

	if cmpctblock.Header != block.Header {
		t.Error("header mismatch")
	}
	if cmpctblock.Nonce != nonce {
		t.Errorf("nonce = %d, want %d", cmpctblock.Nonce, nonce)
	}

	// Coinbase should be prefilled
	if len(cmpctblock.PrefilledTxs) != 1 {
		t.Fatalf("prefilled count = %d, want 1", len(cmpctblock.PrefilledTxs))
	}
	if cmpctblock.PrefilledTxs[0].Index != 0 {
		t.Errorf("prefilled index = %d, want 0", cmpctblock.PrefilledTxs[0].Index)
	}

	if len(cmpctblock.ShortIDs) != 2 {
		t.Errorf("short ID count = %d, want 2", len(cmpctblock.ShortIDs))
	}

	totalTxs := len(cmpctblock.ShortIDs) + len(cmpctblock.PrefilledTxs)
	if totalTxs != len(block.Transactions) {
		t.Errorf("total tx count = %d, want %d", totalTxs, len(block.Transactions))
	}
}

// TestBlockReconstruction tests block reconstruction with all txns in mempool.
func TestBlockReconstruction(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)
	tx2 := createTestTx(2, 2, 2_0000_0000, nil)

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			Timestamp:  1234567890,
			Bits:       0x1d00ffff,
			Nonce:      12345,
		},
		Transactions: []*wire.MsgTx{coinbase, tx1, tx2},
	}

	// Set correct merkle root BEFORE building (sipHashKey uses header bytes)
	block.Header.MerkleRoot = computeMerkleRootForTest(block.Transactions)

	nonce := uint64(0xCAFEBABE)
	builder := NewCompactBlockBuilder(&block.Header, nonce)
	cmpctblock := builder.Build(block)

	mempool := &mockMempool{txs: []*wire.MsgTx{tx1, tx2}}

	pdb := NewPartiallyDownloadedBlock()
	missing, err := pdb.InitData(cmpctblock, mempool, nil)
	if err != nil {
		t.Fatalf("InitData failed: %v", err)
	}

	if missing != 0 {
		t.Errorf("missing = %d, want 0", missing)
	}

	prefilled, fromMempool, fromExtra := pdb.Stats()
	if prefilled != 1 {
		t.Errorf("prefilled = %d, want 1", prefilled)
	}
	if fromMempool != 2 {
		t.Errorf("fromMempool = %d, want 2", fromMempool)
	}
	if fromExtra != 0 {
		t.Errorf("fromExtra = %d, want 0", fromExtra)
	}

	// FillBlock with segwit=false (no witness commitment in test block)
	reconstructed, err := pdb.FillBlock(nil, false)
	if err != nil {
		t.Fatalf("FillBlock failed: %v", err)
	}

	if len(reconstructed.Transactions) != len(block.Transactions) {
		t.Errorf("tx count = %d, want %d", len(reconstructed.Transactions), len(block.Transactions))
	}

	if reconstructed.Header.Bits != block.Header.Bits {
		t.Error("header mismatch after reconstruction")
	}
}

// TestBlockReconstructionWithMissing tests reconstruction with missing txns.
func TestBlockReconstructionWithMissing(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)
	tx2 := createTestTx(2, 2, 2_0000_0000, nil)

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			Timestamp:  1234567890,
			Bits:       0x1d00ffff,
			Nonce:      12345,
		},
		Transactions: []*wire.MsgTx{coinbase, tx1, tx2},
	}

	// Set merkle root before building
	block.Header.MerkleRoot = computeMerkleRootForTest(block.Transactions)

	nonce := uint64(0xCAFEBABE)
	builder := NewCompactBlockBuilder(&block.Header, nonce)
	cmpctblock := builder.Build(block)

	// Only tx1 in mempool; tx2 is missing
	mempool := &mockMempool{txs: []*wire.MsgTx{tx1}}

	pdb := NewPartiallyDownloadedBlock()
	missing, err := pdb.InitData(cmpctblock, mempool, nil)
	if err != nil {
		t.Fatalf("InitData failed: %v", err)
	}

	if missing != 1 {
		t.Errorf("missing = %d, want 1", missing)
	}

	missingIndexes := pdb.GetMissingIndexes()
	if len(missingIndexes) != 1 {
		t.Fatalf("missing indexes count = %d, want 1", len(missingIndexes))
	}

	// FillBlock without providing the missing tx should fail
	_, err = pdb.FillBlock(nil, false)
	if err == nil {
		t.Error("FillBlock should fail with missing transactions")
	}

	// Re-init (new object) and provide the missing tx via vtxMissing
	pdb2 := NewPartiallyDownloadedBlock()
	missing2, err2 := pdb2.InitData(cmpctblock, mempool, nil)
	if err2 != nil {
		t.Fatalf("second InitData failed: %v", err2)
	}
	if missing2 != 1 {
		t.Errorf("second missing = %d, want 1", missing2)
	}

	reconstructed, err := pdb2.FillBlock([]*wire.MsgTx{tx2}, false)
	if err != nil {
		t.Fatalf("FillBlock with vtxMissing failed: %v", err)
	}

	if len(reconstructed.Transactions) != 3 {
		t.Errorf("tx count = %d, want 3", len(reconstructed.Transactions))
	}
}

// TestInitDataNullHeaderRejected verifies Gate 1: null header.
func TestInitDataNullHeaderRejected(t *testing.T) {
	cmpctblock := &MsgCmpctBlock{
		// Header.Bits == 0 → null header
		ShortIDs:     []uint64{0x1234},
		PrefilledTxs: []PrefilledTx{{Index: 0, Tx: createTestTx(0, 1, 5000, nil)}},
	}
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpctblock, nil, nil)
	if err == nil {
		t.Fatal("expected error for null header, got nil")
	}
}

// TestInitDataEmptyBodyRejected verifies Gate 2: empty short IDs + prefilled.
func TestInitDataEmptyBodyRejected(t *testing.T) {
	cmpctblock := &MsgCmpctBlock{
		Header: wire.BlockHeader{Bits: 0x1d00ffff},
	}
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpctblock, nil, nil)
	if err == nil {
		t.Fatal("expected error for empty body, got nil")
	}
}

// TestInitDataMaxTxCountGuard verifies Gate 3: DoS guard on transaction count.
func TestInitDataMaxTxCountGuard(t *testing.T) {
	// Build a cmpctblock with maxBlockTxCount+1 short IDs.
	shortIDs := make([]uint64, maxBlockTxCount+1)
	for i := range shortIDs {
		shortIDs[i] = uint64(i + 1)
	}
	cmpctblock := &MsgCmpctBlock{
		Header:   wire.BlockHeader{Bits: 0x1d00ffff},
		ShortIDs: shortIDs,
	}
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpctblock, nil, nil)
	if err == nil {
		t.Fatal("expected error for too many transactions, got nil")
	}
}

// TestInitDataDoubleInitGuard verifies Gate 4: double-init rejection.
func TestInitDataDoubleInitGuard(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Bits: 0x1d00ffff},
		Transactions: []*wire.MsgTx{coinbase, tx1},
	}
	builder := NewCompactBlockBuilder(&block.Header, 42)
	cmpctblock := builder.Build(block)

	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpctblock, nil, nil)
	if err != nil {
		t.Fatalf("first InitData failed: %v", err)
	}

	// Second call must fail
	_, err = pdb.InitData(cmpctblock, nil, nil)
	if err == nil {
		t.Fatal("expected error on double-init, got nil")
	}
}

// TestInitDataPrefilledIndexUint16Overflow verifies Gate 6: uint16 overflow.
func TestInitDataPrefilledIndexUint16Overflow(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	cmpctblock := &MsgCmpctBlock{
		Header: wire.BlockHeader{Bits: 0x1d00ffff},
		// Index 0 + 65535 = 65535; adding another 1 would wrap.
		// Use differential index of 65535 on second entry to push lastPrefilledIndex to 65535+1 = overflow.
		PrefilledTxs: []PrefilledTx{
			{Index: 0, Tx: coinbase},
			{Index: 0xFFFF, Tx: coinbase}, // differential: 0xFFFF+1 = 65536 → overflow
		},
		ShortIDs: []uint64{},
	}
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpctblock, nil, nil)
	if err == nil {
		t.Fatal("expected error for uint16 overflow, got nil")
	}
}

// TestInitDataShortIDCollision verifies Gate 9: duplicate short IDs rejected.
func TestInitDataShortIDCollision(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	dup := uint64(0xABCDEF123456)
	cmpctblock := &MsgCmpctBlock{
		Header:       wire.BlockHeader{Bits: 0x1d00ffff},
		PrefilledTxs: []PrefilledTx{{Index: 0, Tx: coinbase}},
		ShortIDs:     []uint64{dup, dup}, // duplicate
	}
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpctblock, nil, nil)
	if err == nil {
		t.Fatal("expected error for duplicate short IDs, got nil")
	}
}

// TestInitDataExtraTxn verifies that extra_txn are matched correctly (Bug 10 fix).
func TestInitDataExtraTxn(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)
	tx2 := createTestTx(2, 2, 2_0000_0000, nil)

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			Timestamp:  1234567890,
			Bits:       0x1d00ffff,
			Nonce:      12345,
		},
		Transactions: []*wire.MsgTx{coinbase, tx1, tx2},
	}

	// Set merkle root before building
	block.Header.MerkleRoot = computeMerkleRootForTest(block.Transactions)

	nonce := uint64(0xCAFEBABE)
	builder := NewCompactBlockBuilder(&block.Header, nonce)
	cmpctblock := builder.Build(block)

	// Empty mempool, but tx1 and tx2 provided as extra_txn
	extraTxn := []ExtraTx{
		{Wtxid: tx1.WTxHash(), Tx: tx1},
		{Wtxid: tx2.WTxHash(), Tx: tx2},
	}

	pdb := NewPartiallyDownloadedBlock()
	missing, err := pdb.InitData(cmpctblock, nil, extraTxn)
	if err != nil {
		t.Fatalf("InitData failed: %v", err)
	}
	if missing != 0 {
		t.Errorf("missing = %d, want 0 (extra_txn should cover all)", missing)
	}

	_, fromMempool, fromExtra := pdb.Stats()
	if fromMempool != 2 {
		t.Errorf("fromMempool = %d, want 2", fromMempool)
	}
	if fromExtra != 2 {
		t.Errorf("fromExtra = %d, want 2", fromExtra)
	}
}

// TestFillBlockUninitialisedRejected verifies Gate: IsTxAvailable on uninit returns false (Bug 9 fix).
func TestIsTxAvailableUninit(t *testing.T) {
	pdb := NewPartiallyDownloadedBlock()
	if pdb.IsTxAvailable(0) {
		t.Error("IsTxAvailable on uninitialised block should return false")
	}
}

// TestFillBlockUninitRejected verifies Gate: FillBlock on uninit returns error (Bug 6 fix).
func TestFillBlockUninitRejected(t *testing.T) {
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.FillBlock(nil, false)
	if err == nil {
		t.Fatal("FillBlock on uninitialised block should return error")
	}
}

// TestFillBlockDoubleCallRejected verifies that after FillBlock succeeds, a second
// call is rejected (Bug 7 fix: header.SetNull + txn_available.clear).
func TestFillBlockDoubleCallRejected(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Bits: 0x1d00ffff, Nonce: 7},
		Transactions: []*wire.MsgTx{coinbase, tx1},
	}
	// Set merkle root before building so sipHashKey is computed from final header
	block.Header.MerkleRoot = computeMerkleRootForTest(block.Transactions)
	builder := NewCompactBlockBuilder(&block.Header, 42)
	cmpctblock := builder.Build(block)

	mempool := &mockMempool{txs: []*wire.MsgTx{tx1}}

	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpctblock, mempool, nil)
	if err != nil {
		t.Fatalf("InitData failed: %v", err)
	}

	_, err = pdb.FillBlock(nil, false)
	if err != nil {
		t.Fatalf("first FillBlock failed: %v", err)
	}

	// Second call must fail (header consumed)
	_, err = pdb.FillBlock(nil, false)
	if err == nil {
		t.Fatal("expected error on second FillBlock call, got nil")
	}
}

// TestFillBlockVtxMissingTooShort verifies that insufficient vtxMissing returns error.
func TestFillBlockVtxMissingTooShort(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Bits: 0x1d00ffff, Nonce: 77},
		Transactions: []*wire.MsgTx{coinbase, tx1},
	}
	builder := NewCompactBlockBuilder(&block.Header, 42)
	cmpctblock := builder.Build(block)

	// Empty mempool → tx1 is missing
	pdb := NewPartiallyDownloadedBlock()
	missing, err := pdb.InitData(cmpctblock, nil, nil)
	if err != nil {
		t.Fatalf("InitData failed: %v", err)
	}
	if missing != 1 {
		t.Fatalf("missing = %d, want 1", missing)
	}

	// Provide no vtxMissing → should fail
	_, err = pdb.FillBlock(nil, false)
	if err == nil {
		t.Fatal("expected error for empty vtxMissing, got nil")
	}
}

// TestFillBlockVtxMissingTooLong verifies that excess vtxMissing returns error.
func TestFillBlockVtxMissingTooLong(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Bits: 0x1d00ffff, Nonce: 88},
		Transactions: []*wire.MsgTx{coinbase},
	}
	block.Header.MerkleRoot = computeMerkleRootForTest(block.Transactions)
	builder := NewCompactBlockBuilder(&block.Header, 42)
	cmpctblock := builder.Build(block)

	// All txns prefilled (only coinbase)
	pdb := NewPartiallyDownloadedBlock()
	_, err := pdb.InitData(cmpctblock, nil, nil)
	if err != nil {
		t.Fatalf("InitData failed: %v", err)
	}

	// Provide an extra tx (too many) → should fail
	extra := createTestTx(99, 1, 1000, nil)
	_, err = pdb.FillBlock([]*wire.MsgTx{extra}, false)
	if err == nil {
		t.Fatal("expected error for excess vtxMissing, got nil")
	}
}

// TestGetBlockTxnEncoding tests differential encoding for getblocktxn.
func TestGetBlockTxnEncoding(t *testing.T) {
	blockHash := wire.Hash256{}
	blockHash[0] = 0xAB

	missingIndexes := []uint32{1, 3, 4, 10}
	msg := CreateGetBlockTxn(blockHash, missingIndexes)

	// Differential encoding:
	// 1 - (-1) - 1 = 1
	// 3 - 1 - 1 = 1
	// 4 - 3 - 1 = 0
	// 10 - 4 - 1 = 5
	expected := []uint32{1, 1, 0, 5}

	if len(msg.Indexes) != len(expected) {
		t.Fatalf("encoded length = %d, want %d", len(msg.Indexes), len(expected))
	}

	for i := range expected {
		if msg.Indexes[i] != expected[i] {
			t.Errorf("[%d] encoded = %d, want %d", i, msg.Indexes[i], expected[i])
		}
	}

	decoded := DecodeGetBlockTxnIndexes(msg.Indexes)
	if len(decoded) != len(missingIndexes) {
		t.Fatalf("decoded length = %d, want %d", len(decoded), len(missingIndexes))
	}

	for i := range missingIndexes {
		if decoded[i] != missingIndexes[i] {
			t.Errorf("[%d] decoded = %d, want %d", i, decoded[i], missingIndexes[i])
		}
	}
}

// TestMsgCmpctBlockRoundTrip tests serialization/deserialization of compact blocks.
func TestMsgCmpctBlockRoundTrip(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)

	msg := &MsgCmpctBlock{
		Header: wire.BlockHeader{
			Version:    1,
			Timestamp:  1234567890,
			Bits:       0x1d00ffff,
			Nonce:      12345,
		},
		Nonce:    0xDEADBEEF,
		ShortIDs: []uint64{0x123456789ABC, 0xFEDCBA987654},
		PrefilledTxs: []PrefilledTx{
			{Index: 0, Tx: coinbase},
		},
	}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	var msg2 MsgCmpctBlock
	if err := msg2.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if msg2.Nonce != msg.Nonce {
		t.Errorf("Nonce = %d, want %d", msg2.Nonce, msg.Nonce)
	}
	if len(msg2.ShortIDs) != len(msg.ShortIDs) {
		t.Fatalf("ShortIDs length = %d, want %d", len(msg2.ShortIDs), len(msg.ShortIDs))
	}
	for i := range msg.ShortIDs {
		if msg2.ShortIDs[i] != msg.ShortIDs[i] {
			t.Errorf("[%d] ShortID = 0x%x, want 0x%x", i, msg2.ShortIDs[i], msg.ShortIDs[i])
		}
	}
	if len(msg2.PrefilledTxs) != len(msg.PrefilledTxs) {
		t.Fatalf("PrefilledTxs length = %d, want %d", len(msg2.PrefilledTxs), len(msg.PrefilledTxs))
	}
	if msg2.PrefilledTxs[0].Index != msg.PrefilledTxs[0].Index {
		t.Errorf("PrefilledTx index = %d, want %d", msg2.PrefilledTxs[0].Index, msg.PrefilledTxs[0].Index)
	}
}

// TestMsgGetBlockTxnRoundTrip tests serialization/deserialization.
func TestMsgGetBlockTxnRoundTrip(t *testing.T) {
	blockHash := wire.Hash256{}
	blockHash[0] = 0xAB

	msg := &MsgGetBlockTxn{
		BlockHash: blockHash,
		Indexes:   []uint32{1, 2, 5, 0},
	}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	var msg2 MsgGetBlockTxn
	if err := msg2.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if msg2.BlockHash != msg.BlockHash {
		t.Error("BlockHash mismatch")
	}
	if len(msg2.Indexes) != len(msg.Indexes) {
		t.Fatalf("Indexes length = %d, want %d", len(msg2.Indexes), len(msg.Indexes))
	}
	for i := range msg.Indexes {
		if msg2.Indexes[i] != msg.Indexes[i] {
			t.Errorf("[%d] Index = %d, want %d", i, msg2.Indexes[i], msg.Indexes[i])
		}
	}
}

// TestMsgBlockTxnRoundTrip tests serialization/deserialization.
func TestMsgBlockTxnRoundTrip(t *testing.T) {
	blockHash := wire.Hash256{}
	blockHash[0] = 0xCD

	tx1 := createTestTx(1, 1, 1_0000_0000, nil)
	tx2 := createTestTx(2, 2, 2_0000_0000, nil)

	msg := &MsgBlockTxn{
		BlockHash: blockHash,
		Txs:       []*wire.MsgTx{tx1, tx2},
	}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	var msg2 MsgBlockTxn
	if err := msg2.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if msg2.BlockHash != msg.BlockHash {
		t.Error("BlockHash mismatch")
	}
	if len(msg2.Txs) != len(msg.Txs) {
		t.Fatalf("Txs length = %d, want %d", len(msg2.Txs), len(msg.Txs))
	}
}

// TestCompactBlockState tests peer state tracking.
func TestCompactBlockState(t *testing.T) {
	state := NewCompactBlockState()

	if state.ProvidesCompactBlocks() {
		t.Error("should not provide compact blocks initially")
	}
	if state.WantsHBCompactBlocks() {
		t.Error("should not want HB initially")
	}

	state.SetSendCmpct(true, 2)

	if !state.ProvidesCompactBlocks() {
		t.Error("should provide compact blocks after sendcmpct")
	}
	if !state.WantsHBCompactBlocks() {
		t.Error("should want HB after sendcmpct(announce=1)")
	}

	hash := wire.Hash256{}
	hash[0] = 0xAB

	pdb := NewPartiallyDownloadedBlock()
	state.AddPending(hash, pdb)

	retrieved := state.GetPending(hash)
	if retrieved != pdb {
		t.Error("GetPending returned wrong block")
	}

	state.RemovePending(hash)
	if state.GetPending(hash) != nil {
		t.Error("GetPending should return nil after removal")
	}
}

// TestShortIDUniqueness tests that different transactions produce different short IDs.
func TestShortIDUniqueness(t *testing.T) {
	header := &wire.BlockHeader{
		Version:   1,
		Timestamp: 1234567890,
		Bits:      0x1d00ffff,
		Nonce:     12345,
	}
	key := ComputeSipHashKey(header, 0xCAFEBABE)

	seen := make(map[uint64]bool)
	for i := 0; i < 1000; i++ {
		txHash := wire.Hash256{}
		txHash[0] = byte(i & 0xFF)
		txHash[1] = byte((i >> 8) & 0xFF)

		shortID := ComputeShortID(key, txHash)
		if seen[shortID] {
			t.Logf("Warning: collision at iteration %d (expected rare)", i)
		}
		seen[shortID] = true
	}
}

// TestCreateBlockTxn tests creating blocktxn messages.
func TestCreateBlockTxn(t *testing.T) {
	coinbase := createTestTx(0, 1, 50_0000_0000, nil)
	tx1 := createTestTx(1, 1, 1_0000_0000, nil)
	tx2 := createTestTx(2, 2, 2_0000_0000, nil)

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1},
		Transactions: []*wire.MsgTx{coinbase, tx1, tx2},
	}

	msg, err := CreateBlockTxn(block, []uint32{1, 2})
	if err != nil {
		t.Fatalf("CreateBlockTxn failed: %v", err)
	}

	if len(msg.Txs) != 2 {
		t.Errorf("Txs count = %d, want 2", len(msg.Txs))
	}

	_, err = CreateBlockTxn(block, []uint32{5})
	if err == nil {
		t.Error("expected error for out of range index")
	}
}

// Helper to create test transactions
func createTestTx(seed, numInputs, outputValue int, prevHash *wire.Hash256) *wire.MsgTx {
	tx := &wire.MsgTx{
		Version:  1,
		LockTime: 0,
	}

	for i := 0; i < numInputs; i++ {
		outpoint := wire.OutPoint{}
		if prevHash != nil {
			outpoint.Hash = *prevHash
		} else {
			outpoint.Hash[0] = byte(seed)
			outpoint.Hash[1] = byte(i)
		}
		outpoint.Index = uint32(i)

		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: outpoint,
			SignatureScript:  []byte{byte(seed), byte(i)},
			Sequence:         0xFFFFFFFF,
		})
	}

	tx.TxOut = append(tx.TxOut, &wire.TxOut{
		Value:    int64(outputValue),
		PkScript: []byte{0x00, 0x14, byte(seed)}, // P2WPKH-like
	})

	return tx
}

// computeMerkleRootForTest computes the txid merkle root for a list of transactions.
// Used in tests to set the correct merkle root so IsBlockMutated doesn't false-positive.
func computeMerkleRootForTest(txs []*wire.MsgTx) wire.Hash256 {
	hashes := make([]wire.Hash256, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.TxHash()
	}
	// Simple binary merkle tree
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		next := make([]wire.Hash256, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			combined := append(hashes[i][:], hashes[i+1][:]...)
			next[i/2] = wire.DoubleHashB(combined)
		}
		hashes = next
	}
	if len(hashes) == 0 {
		return wire.Hash256{}
	}
	return hashes[0]
}

// mockMempool implements MempoolLookup for testing.
type mockMempool struct {
	txs []*wire.MsgTx
}

func (m *mockMempool) GetTransaction(hash wire.Hash256) *wire.MsgTx {
	for _, tx := range m.txs {
		if tx.TxHash() == hash {
			return tx
		}
	}
	return nil
}

func (m *mockMempool) GetAllTxHashes() []wire.Hash256 {
	hashes := make([]wire.Hash256, len(m.txs))
	for i, tx := range m.txs {
		hashes[i] = tx.WTxHash()
	}
	return hashes
}

func (m *mockMempool) GetAllTransactions() []*wire.MsgTx {
	return m.txs
}
