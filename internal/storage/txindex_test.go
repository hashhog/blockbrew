package storage

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

func TestTxIndex(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	idx := NewTxIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Initially should have no data
	if idx.BestHeight() != -1 {
		t.Errorf("expected best height -1, got %d", idx.BestHeight())
	}

	// Create a test block with some transactions.
	// Use height > 0: WriteBlock skips indexing for height 0 (genesis).
	block := createTestBlock(1)
	hash := block.Header.BlockHash()

	// Write block to index
	if err := idx.WriteBlock(block, 1, hash, nil); err != nil {
		t.Fatalf("WriteBlock failed: %v", err)
	}

	// Best height should be updated
	if idx.BestHeight() != 1 {
		t.Errorf("expected best height 1, got %d", idx.BestHeight())
	}

	// Look up each transaction
	for i, tx := range block.Transactions {
		txid := tx.TxHash()
		data, err := idx.GetTx(txid)
		if err != nil {
			t.Errorf("GetTx failed for tx %d: %v", i, err)
			continue
		}
		if data.BlockHash != hash {
			t.Errorf("tx %d: expected block hash %s, got %s", i, hash.String(), data.BlockHash.String())
		}
		if data.TxIndex != uint32(i) {
			t.Errorf("tx %d: expected index %d, got %d", i, i, data.TxIndex)
		}
	}

	// Unknown transaction should return ErrNotFound
	unknownTxid := wire.Hash256{0xff, 0xfe, 0xfd}
	_, err := idx.GetTx(unknownTxid)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestTxIndexRevert(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	idx := NewTxIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Create and write block 1
	block1 := createTestBlock(1)
	hash1 := block1.Header.BlockHash()
	if err := idx.WriteBlock(block1, 1, hash1, nil); err != nil {
		t.Fatalf("WriteBlock 1 failed: %v", err)
	}

	// Create and write block 2
	block2 := createTestBlock(2)
	block2.Header.PrevBlock = hash1
	hash2 := block2.Header.BlockHash()
	if err := idx.WriteBlock(block2, 2, hash2, nil); err != nil {
		t.Fatalf("WriteBlock 2 failed: %v", err)
	}

	// Both blocks' transactions should be in the index
	if idx.BestHeight() != 2 {
		t.Errorf("expected best height 2, got %d", idx.BestHeight())
	}

	// Revert block 2
	if err := idx.RevertBlock(block2, 2, hash2, nil); err != nil {
		t.Fatalf("RevertBlock failed: %v", err)
	}

	// Best height should be 1
	if idx.BestHeight() != 1 {
		t.Errorf("expected best height 1, got %d", idx.BestHeight())
	}

	// Block 2 transactions should be gone
	for _, tx := range block2.Transactions {
		txid := tx.TxHash()
		_, err := idx.GetTx(txid)
		if err != ErrNotFound {
			t.Errorf("expected tx from block 2 to be removed, got err=%v", err)
		}
	}

	// Block 1 transactions should still be there
	for _, tx := range block1.Transactions {
		txid := tx.TxHash()
		_, err := idx.GetTx(txid)
		if err != nil {
			t.Errorf("expected tx from block 1 to still exist, got err=%v", err)
		}
	}
}

func TestTxIndexPersistence(t *testing.T) {
	dir := t.TempDir()
	db, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatalf("Failed to create PebbleDB: %v", err)
	}

	idx := NewTxIndex(db)
	if err := idx.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Write some data
	block := createTestBlock(5)
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

	idx2 := NewTxIndex(db2)
	if err := idx2.Init(); err != nil {
		t.Fatalf("Init2 failed: %v", err)
	}

	// State should be restored
	if idx2.BestHeight() != 5 {
		t.Errorf("expected best height 5, got %d", idx2.BestHeight())
	}

	// Transactions should still be accessible
	for _, tx := range block.Transactions {
		txid := tx.TxHash()
		data, err := idx2.GetTx(txid)
		if err != nil {
			t.Errorf("GetTx failed after reopen: %v", err)
		} else if data.BlockHash != hash {
			t.Errorf("block hash mismatch after reopen")
		}
	}
}

// createTestBlock creates a test block with some transactions.
func createTestBlock(height int32) *wire.MsgBlock {
	// Create coinbase transaction
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
				Value:    5_000_000_000,
				PkScript: []byte{0x76, 0xa9, 0x14, byte(height)}, // P2PKH-like
			},
		},
		LockTime: 0,
	}

	// Create a regular transaction
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
				Value:    1_000_000,
				PkScript: []byte{0x76, 0xa9, 0x14, byte(height), 0x01},
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
