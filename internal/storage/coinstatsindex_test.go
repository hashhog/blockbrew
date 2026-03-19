package storage

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

func TestCoinStatsIndex(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	idx := NewCoinStatsIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Initially should have no data
	if idx.BestHeight() != -1 {
		t.Errorf("expected best height -1, got %d", idx.BestHeight())
	}

	// Create a test block
	block := createTestBlockForStats(0)
	hash := block.Header.BlockHash()

	// Write block to index
	if err := idx.WriteBlock(block, 0, hash, nil); err != nil {
		t.Fatalf("WriteBlock failed: %v", err)
	}

	// Best height should be updated
	if idx.BestHeight() != 0 {
		t.Errorf("expected best height 0, got %d", idx.BestHeight())
	}

	// Get stats
	stats, err := idx.GetStats(0)
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	// Verify stats
	if stats.Height != 0 {
		t.Errorf("expected height 0, got %d", stats.Height)
	}
	if stats.BlockHash != hash {
		t.Errorf("expected block hash %s, got %s", hash.String(), stats.BlockHash.String())
	}
	if stats.TxCount != 2 {
		t.Errorf("expected 2 transactions, got %d", stats.TxCount)
	}
	// One coinbase output (5 BTC) + one regular output (0.01 BTC)
	// OP_RETURN outputs are not counted (unspendable)
	if stats.UTXOCount != 2 {
		t.Errorf("expected 2 UTXOs, got %d", stats.UTXOCount)
	}
	// Total amount = 5 BTC + 0.01 BTC = 5.01 BTC = 501,000,000 satoshis
	expectedAmount := int64(5_000_000_000 + 1_000_000)
	if stats.TotalAmount != expectedAmount {
		t.Errorf("expected total amount %d, got %d", expectedAmount, stats.TotalAmount)
	}
	// Block subsidy at height 0 = 50 BTC
	if stats.TotalSubsidy != 5_000_000_000 {
		t.Errorf("expected subsidy 5000000000, got %d", stats.TotalSubsidy)
	}
}

func TestCoinStatsIndexMultipleBlocks(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	idx := NewCoinStatsIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Write multiple blocks
	var prevHash wire.Hash256
	for i := int32(0); i < 5; i++ {
		block := createTestBlockForStats(i)
		block.Header.PrevBlock = prevHash
		hash := block.Header.BlockHash()

		if err := idx.WriteBlock(block, i, hash, nil); err != nil {
			t.Fatalf("WriteBlock %d failed: %v", i, err)
		}

		prevHash = hash
	}

	// Verify final stats
	stats, err := idx.GetStats(4)
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	// Should have 5 blocks * 2 txs = 10 transactions
	if stats.TxCount != 10 {
		t.Errorf("expected 10 transactions, got %d", stats.TxCount)
	}

	// Should have 5 blocks * 2 outputs = 10 UTXOs (no spending in these test blocks)
	if stats.UTXOCount != 10 {
		t.Errorf("expected 10 UTXOs, got %d", stats.UTXOCount)
	}

	// Subsidy for 5 blocks at height 0-4 = 5 * 50 BTC = 250 BTC
	if stats.TotalSubsidy != 5*5_000_000_000 {
		t.Errorf("expected subsidy %d, got %d", 5*5_000_000_000, stats.TotalSubsidy)
	}
}

func TestCoinStatsIndexWithUndo(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	idx := NewCoinStatsIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Write block 0 (creates UTXOs)
	block0 := createTestBlockForStats(0)
	hash0 := block0.Header.BlockHash()
	if err := idx.WriteBlock(block0, 0, hash0, nil); err != nil {
		t.Fatalf("WriteBlock 0 failed: %v", err)
	}

	// Create block 1 that spends outputs from block 0
	block1 := createTestBlockForStats(1)
	block1.Header.PrevBlock = hash0
	hash1 := block1.Header.BlockHash()

	// Create undo data for block 1 (spent outputs)
	undo := &BlockUndo{
		TxUndos: []TxUndo{
			{
				SpentCoins: []SpentCoin{
					{
						TxOut: wire.TxOut{
							Value:    1_000_000, // 0.01 BTC being spent
							PkScript: []byte{0x76, 0xa9, 0x14},
						},
						Height:   0,
						Coinbase: false,
					},
				},
			},
		},
	}

	if err := idx.WriteBlock(block1, 1, hash1, undo); err != nil {
		t.Fatalf("WriteBlock 1 failed: %v", err)
	}

	// Get stats at height 1
	stats, err := idx.GetStats(1)
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	// Should have 4 txs total
	if stats.TxCount != 4 {
		t.Errorf("expected 4 transactions, got %d", stats.TxCount)
	}

	// UTXOs: 2 from block 0 + 2 from block 1 - 1 spent = 3
	if stats.UTXOCount != 3 {
		t.Errorf("expected 3 UTXOs, got %d", stats.UTXOCount)
	}

	// Total amount: (5 BTC + 0.01 BTC) + (5 BTC + 0.01 BTC) - 0.01 BTC spent
	expectedAmount := int64(5_000_000_000+1_000_000) + int64(5_000_000_000+1_000_000) - 1_000_000
	if stats.TotalAmount != expectedAmount {
		t.Errorf("expected total amount %d, got %d", expectedAmount, stats.TotalAmount)
	}
}

func TestCoinStatsIndexRevert(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	idx := NewCoinStatsIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Write blocks 0 and 1
	block0 := createTestBlockForStats(0)
	hash0 := block0.Header.BlockHash()
	if err := idx.WriteBlock(block0, 0, hash0, nil); err != nil {
		t.Fatalf("WriteBlock 0 failed: %v", err)
	}

	block1 := createTestBlockForStats(1)
	block1.Header.PrevBlock = hash0
	hash1 := block1.Header.BlockHash()
	if err := idx.WriteBlock(block1, 1, hash1, nil); err != nil {
		t.Fatalf("WriteBlock 1 failed: %v", err)
	}

	// Get stats at height 0 for comparison
	stats0, _ := idx.GetStats(0)

	// Revert block 1
	if err := idx.RevertBlock(block1, 1, hash1, nil); err != nil {
		t.Fatalf("RevertBlock failed: %v", err)
	}

	// Best height should be 0
	if idx.BestHeight() != 0 {
		t.Errorf("expected best height 0, got %d", idx.BestHeight())
	}

	// Stats at height 1 should be gone
	_, err := idx.GetStats(1)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for reverted stats, got %v", err)
	}

	// Internal state should match stats0
	// We can verify by writing another block and checking the stats are correct
	block1b := createTestBlockForStats(1)
	block1b.Header.PrevBlock = hash0
	block1b.Header.Nonce = 999 // Different nonce to get different hash
	hash1b := block1b.Header.BlockHash()
	if err := idx.WriteBlock(block1b, 1, hash1b, nil); err != nil {
		t.Fatalf("WriteBlock 1b failed: %v", err)
	}

	stats1b, _ := idx.GetStats(1)
	// Should have same accumulated values as writing fresh after block 0
	expectedTxCount := stats0.TxCount + 2
	if stats1b.TxCount != expectedTxCount {
		t.Errorf("expected tx count %d after revert+rewrite, got %d", expectedTxCount, stats1b.TxCount)
	}
}

func TestCoinStatsIndexPersistence(t *testing.T) {
	dir := t.TempDir()
	db, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatalf("Failed to create PebbleDB: %v", err)
	}

	idx := NewCoinStatsIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Write some data
	block := createTestBlockForStats(5)
	hash := block.Header.BlockHash()
	if err := idx.WriteBlock(block, 5, hash, nil); err != nil {
		t.Fatalf("WriteBlock failed: %v", err)
	}

	db.Close()

	// Reopen database
	db2, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatalf("Failed to reopen PebbleDB: %v", err)
	}
	defer db2.Close()

	idx2 := NewCoinStatsIndex(db2)
	if err := idx2.Init(); err != nil {
		t.Fatalf("Init2 failed: %v", err)
	}

	// State should be restored
	if idx2.BestHeight() != 5 {
		t.Errorf("expected best height 5, got %d", idx2.BestHeight())
	}

	// Stats should still be accessible
	stats, err := idx2.GetStats(5)
	if err != nil {
		t.Errorf("GetStats failed after reopen: %v", err)
	} else if stats.BlockHash != hash {
		t.Errorf("block hash mismatch after reopen")
	}
}

func TestBlockSubsidy(t *testing.T) {
	tests := []struct {
		height  int32
		subsidy int64
	}{
		{0, 5_000_000_000},
		{209999, 5_000_000_000},
		{210000, 2_500_000_000},
		{419999, 2_500_000_000},
		{420000, 1_250_000_000},
		{630000, 625_000_000},
	}

	for _, tc := range tests {
		got := calcBlockSubsidy(tc.height)
		if got != tc.subsidy {
			t.Errorf("height %d: expected subsidy %d, got %d", tc.height, tc.subsidy, got)
		}
	}
}

func TestIsUnspendable(t *testing.T) {
	tests := []struct {
		script      []byte
		unspendable bool
	}{
		{[]byte{}, true},
		{[]byte{0x6a}, true},                           // OP_RETURN
		{[]byte{0x6a, 0x04, 0xde, 0xad}, true},         // OP_RETURN with data
		{[]byte{0x76, 0xa9, 0x14}, false},              // P2PKH start
		{[]byte{0x00, 0x14}, false},                    // P2WPKH
		{[]byte{0xa9, 0x14}, false},                    // P2SH start
	}

	for i, tc := range tests {
		got := isUnspendable(tc.script)
		if got != tc.unspendable {
			t.Errorf("test %d: expected %v, got %v", i, tc.unspendable, got)
		}
	}
}

// createTestBlockForStats creates a test block for coin stats testing.
func createTestBlockForStats(height int32) *wire.MsgBlock {
	// Coinbase with one spendable output and one OP_RETURN
	coinbase := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{},
					Index: 0xffffffff,
				},
				SignatureScript: []byte{byte(height), 0x04, 0xff, 0xff, 0x00, 0x1d},
				Sequence:        0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value: 5_000_000_000, // 50 BTC
				PkScript: []byte{0x76, 0xa9, 0x14,
					byte(height), 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13,
					0x88, 0xac},
			},
			{
				Value:    0, // OP_RETURN (unspendable, not counted)
				PkScript: []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef},
			},
		},
		LockTime: 0,
	}

	// Regular tx with one output
	regularTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash256{byte(height), 0x01},
					Index: 0,
				},
				SignatureScript: []byte{0x00, byte(height)},
				Sequence:        0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    1_000_000, // 0.01 BTC
				PkScript: []byte{0x76, 0xa9, 0x14, byte(height), 0x21, 0x88, 0xac},
			},
		},
		LockTime: 0,
	}

	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  wire.Hash256{},
			MerkleRoot: wire.Hash256{},
			Timestamp:  uint32(1231006505 + int(height)*600),
			Bits:       0x1d00ffff,
			Nonce:      uint32(height),
		},
		Transactions: []*wire.MsgTx{coinbase, regularTx},
	}
}
