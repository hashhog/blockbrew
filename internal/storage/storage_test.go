package storage

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// runDBTests runs all DB interface tests against the given database.
func runDBTests(t *testing.T, db DB) {
	t.Run("GetPutDelete", func(t *testing.T) {
		key := []byte("testkey")
		value := []byte("testvalue")

		// Initially not present
		val, err := db.Get(key)
		if err != nil {
			t.Fatalf("Get error: %v", err)
		}
		if val != nil {
			t.Fatalf("expected nil, got %v", val)
		}

		has, err := db.Has(key)
		if err != nil {
			t.Fatalf("Has error: %v", err)
		}
		if has {
			t.Fatal("expected Has to return false")
		}

		// Put value
		if err := db.Put(key, value); err != nil {
			t.Fatalf("Put error: %v", err)
		}

		// Now present
		has, err = db.Has(key)
		if err != nil {
			t.Fatalf("Has error: %v", err)
		}
		if !has {
			t.Fatal("expected Has to return true")
		}

		val, err = db.Get(key)
		if err != nil {
			t.Fatalf("Get error: %v", err)
		}
		if !bytes.Equal(val, value) {
			t.Fatalf("expected %v, got %v", value, val)
		}

		// Delete
		if err := db.Delete(key); err != nil {
			t.Fatalf("Delete error: %v", err)
		}

		// Gone
		has, err = db.Has(key)
		if err != nil {
			t.Fatalf("Has error: %v", err)
		}
		if has {
			t.Fatal("expected Has to return false after delete")
		}
	})

	t.Run("BatchWrite", func(t *testing.T) {
		batch := db.NewBatch()

		batch.Put([]byte("batch1"), []byte("value1"))
		batch.Put([]byte("batch2"), []byte("value2"))
		batch.Put([]byte("batch3"), []byte("value3"))

		if batch.Len() != 3 {
			t.Fatalf("expected batch len 3, got %d", batch.Len())
		}

		if err := batch.Write(); err != nil {
			t.Fatalf("Batch Write error: %v", err)
		}

		// Verify all written
		for i := 1; i <= 3; i++ {
			key := []byte("batch" + string(rune('0'+i)))
			val, err := db.Get(key)
			if err != nil {
				t.Fatalf("Get error: %v", err)
			}
			expected := []byte("value" + string(rune('0'+i)))
			if !bytes.Equal(val, expected) {
				t.Fatalf("expected %s, got %s", expected, val)
			}
		}

		// Test batch delete
		batch.Reset()
		batch.Delete([]byte("batch1"))
		batch.Delete([]byte("batch2"))
		if err := batch.Write(); err != nil {
			t.Fatalf("Batch Write error: %v", err)
		}

		// batch1 and batch2 gone, batch3 still there
		has, _ := db.Has([]byte("batch1"))
		if has {
			t.Fatal("batch1 should be deleted")
		}
		has, _ = db.Has([]byte("batch2"))
		if has {
			t.Fatal("batch2 should be deleted")
		}
		has, _ = db.Has([]byte("batch3"))
		if !has {
			t.Fatal("batch3 should still exist")
		}

		// Cleanup
		db.Delete([]byte("batch3"))
	})

	t.Run("Iterator", func(t *testing.T) {
		// Put some data with prefix
		db.Put([]byte("prefix_a"), []byte("va"))
		db.Put([]byte("prefix_b"), []byte("vb"))
		db.Put([]byte("prefix_c"), []byte("vc"))
		db.Put([]byte("other_x"), []byte("vx"))

		// Iterate with prefix
		iter := db.NewIterator([]byte("prefix_"))
		defer iter.Release()

		var keys []string
		for iter.Next() {
			keys = append(keys, string(iter.Key()))
		}
		if err := iter.Error(); err != nil {
			t.Fatalf("Iterator error: %v", err)
		}

		if len(keys) != 3 {
			t.Fatalf("expected 3 keys with prefix, got %d: %v", len(keys), keys)
		}

		// Verify order (should be sorted)
		expected := []string{"prefix_a", "prefix_b", "prefix_c"}
		for i, k := range keys {
			if k != expected[i] {
				t.Fatalf("expected %s at index %d, got %s", expected[i], i, k)
			}
		}

		// Cleanup
		db.Delete([]byte("prefix_a"))
		db.Delete([]byte("prefix_b"))
		db.Delete([]byte("prefix_c"))
		db.Delete([]byte("other_x"))
	})

	t.Run("IteratorNoPrefix", func(t *testing.T) {
		// Put some data
		db.Put([]byte("aaa"), []byte("1"))
		db.Put([]byte("bbb"), []byte("2"))
		db.Put([]byte("ccc"), []byte("3"))

		// Iterate all
		iter := db.NewIterator(nil)
		defer iter.Release()

		count := 0
		for iter.Next() {
			count++
		}
		if err := iter.Error(); err != nil {
			t.Fatalf("Iterator error: %v", err)
		}

		if count < 3 {
			t.Fatalf("expected at least 3 keys, got %d", count)
		}

		// Cleanup
		db.Delete([]byte("aaa"))
		db.Delete([]byte("bbb"))
		db.Delete([]byte("ccc"))
	})
}

func TestMemDB(t *testing.T) {
	db := NewMemDB()
	defer db.Close()
	runDBTests(t, db)
}

func TestPebbleDB(t *testing.T) {
	dir := t.TempDir()
	db, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatalf("Failed to create PebbleDB: %v", err)
	}
	defer db.Close()
	runDBTests(t, db)
}

func TestChainDB(t *testing.T) {
	memdb := NewMemDB()
	defer memdb.Close()
	chaindb := NewChainDB(memdb)

	t.Run("BlockHeader", func(t *testing.T) {
		header := &wire.BlockHeader{
			Version:    1,
			PrevBlock:  wire.Hash256{0x01, 0x02, 0x03},
			MerkleRoot: wire.Hash256{0x04, 0x05, 0x06},
			Timestamp:  1231006505,
			Bits:       0x1d00ffff,
			Nonce:      2083236893,
		}

		hash := header.BlockHash()

		// Store
		if err := chaindb.StoreBlockHeader(hash, header); err != nil {
			t.Fatalf("StoreBlockHeader error: %v", err)
		}

		// Retrieve
		retrieved, err := chaindb.GetBlockHeader(hash)
		if err != nil {
			t.Fatalf("GetBlockHeader error: %v", err)
		}

		// Compare
		if retrieved.Version != header.Version ||
			retrieved.PrevBlock != header.PrevBlock ||
			retrieved.MerkleRoot != header.MerkleRoot ||
			retrieved.Timestamp != header.Timestamp ||
			retrieved.Bits != header.Bits ||
			retrieved.Nonce != header.Nonce {
			t.Fatal("retrieved header does not match stored header")
		}
	})

	t.Run("Block", func(t *testing.T) {
		block := &wire.MsgBlock{
			Header: wire.BlockHeader{
				Version:    1,
				PrevBlock:  wire.Hash256{},
				MerkleRoot: wire.Hash256{},
				Timestamp:  1231006505,
				Bits:       0x1d00ffff,
				Nonce:      2083236893,
			},
			Transactions: []*wire.MsgTx{
				{
					Version: 1,
					TxIn: []*wire.TxIn{
						{
							PreviousOutPoint: wire.OutPoint{
								Hash:  wire.Hash256{},
								Index: 0xffffffff,
							},
							SignatureScript: []byte{0x04, 0xff, 0xff, 0x00, 0x1d},
							Sequence:        0xffffffff,
						},
					},
					TxOut: []*wire.TxOut{
						{
							Value:    5000000000,
							PkScript: []byte{0x76, 0xa9},
						},
					},
					LockTime: 0,
				},
			},
		}

		hash := block.Header.BlockHash()

		// Store
		if err := chaindb.StoreBlock(hash, block); err != nil {
			t.Fatalf("StoreBlock error: %v", err)
		}

		// Retrieve
		retrieved, err := chaindb.GetBlock(hash)
		if err != nil {
			t.Fatalf("GetBlock error: %v", err)
		}

		// Compare basic properties
		if retrieved.Header.Nonce != block.Header.Nonce {
			t.Fatal("retrieved block header does not match")
		}
		if len(retrieved.Transactions) != len(block.Transactions) {
			t.Fatal("retrieved block tx count does not match")
		}
	})

	t.Run("BlockHeight", func(t *testing.T) {
		hash := wire.Hash256{0xaa, 0xbb, 0xcc}

		// Set height mapping
		if err := chaindb.SetBlockHeight(100, hash); err != nil {
			t.Fatalf("SetBlockHeight error: %v", err)
		}

		// Retrieve
		retrieved, err := chaindb.GetBlockHashByHeight(100)
		if err != nil {
			t.Fatalf("GetBlockHashByHeight error: %v", err)
		}

		if retrieved != hash {
			t.Fatal("retrieved hash does not match")
		}

		// Non-existent height
		_, err = chaindb.GetBlockHashByHeight(999)
		if err != ErrNotFound {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("ChainState", func(t *testing.T) {
		state := &ChainState{
			BestHash:   wire.Hash256{0x11, 0x22, 0x33, 0x44},
			BestHeight: 500000,
		}

		// Store
		if err := chaindb.SetChainState(state); err != nil {
			t.Fatalf("SetChainState error: %v", err)
		}

		// Retrieve
		retrieved, err := chaindb.GetChainState()
		if err != nil {
			t.Fatalf("GetChainState error: %v", err)
		}

		if retrieved.BestHash != state.BestHash {
			t.Fatal("retrieved BestHash does not match")
		}
		if retrieved.BestHeight != state.BestHeight {
			t.Fatalf("retrieved BestHeight %d does not match %d", retrieved.BestHeight, state.BestHeight)
		}
	})
}

func TestChainStateSerialize(t *testing.T) {
	state := &ChainState{
		BestHash:   wire.Hash256{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		BestHeight: 123456,
	}

	data := state.Serialize()

	// Should be 32 bytes for hash + 4 bytes for height = 36 bytes
	if len(data) != 36 {
		t.Fatalf("expected 36 bytes, got %d", len(data))
	}

	// Deserialize
	restored, err := DeserializeChainState(data)
	if err != nil {
		t.Fatalf("DeserializeChainState error: %v", err)
	}

	if restored.BestHash != state.BestHash {
		t.Fatal("BestHash mismatch")
	}
	if restored.BestHeight != state.BestHeight {
		t.Fatal("BestHeight mismatch")
	}
}

func TestKeyFunctions(t *testing.T) {
	t.Run("MakeBlockHeaderKey", func(t *testing.T) {
		hash := wire.Hash256{0x01, 0x02, 0x03}
		key := MakeBlockHeaderKey(hash)
		if len(key) != 33 {
			t.Fatalf("expected 33 bytes, got %d", len(key))
		}
		if key[0] != 'H' {
			t.Fatalf("expected prefix 'H', got %c", key[0])
		}
	})

	t.Run("MakeBlockDataKey", func(t *testing.T) {
		hash := wire.Hash256{0x01, 0x02, 0x03}
		key := MakeBlockDataKey(hash)
		if len(key) != 33 {
			t.Fatalf("expected 33 bytes, got %d", len(key))
		}
		if key[0] != 'B' {
			t.Fatalf("expected prefix 'B', got %c", key[0])
		}
	})

	t.Run("MakeBlockHeightKey", func(t *testing.T) {
		key := MakeBlockHeightKey(100)
		if len(key) != 5 {
			t.Fatalf("expected 5 bytes, got %d", len(key))
		}
		if key[0] != 'N' {
			t.Fatalf("expected prefix 'N', got %c", key[0])
		}
		// Big-endian 100 = 0x00000064
		if key[4] != 0x64 {
			t.Fatalf("expected last byte 0x64, got 0x%02x", key[4])
		}
	})

	t.Run("MakeTxIndexKey", func(t *testing.T) {
		txid := wire.Hash256{0xaa, 0xbb}
		key := MakeTxIndexKey(txid)
		if len(key) != 33 {
			t.Fatalf("expected 33 bytes, got %d", len(key))
		}
		if key[0] != 'T' {
			t.Fatalf("expected prefix 'T', got %c", key[0])
		}
	})

	t.Run("MakeUTXOKey", func(t *testing.T) {
		outpoint := wire.OutPoint{
			Hash:  wire.Hash256{0x01, 0x02},
			Index: 5,
		}
		key := MakeUTXOKey(outpoint)
		if len(key) != 37 {
			t.Fatalf("expected 37 bytes, got %d", len(key))
		}
		if key[0] != 'U' {
			t.Fatalf("expected prefix 'U', got %c", key[0])
		}
		// Big-endian 5 = 0x00000005
		if key[36] != 0x05 {
			t.Fatalf("expected last byte 0x05, got 0x%02x", key[36])
		}
	})
}

func TestPrefixUpperBound(t *testing.T) {
	tests := []struct {
		name     string
		prefix   []byte
		expected []byte
	}{
		{"simple", []byte{0x01}, []byte{0x02}},
		{"multiple", []byte{0x01, 0x02}, []byte{0x01, 0x03}},
		{"overflow", []byte{0x01, 0xff}, []byte{0x02, 0x00}},
		{"all_ff", []byte{0xff, 0xff}, nil},
		{"empty", []byte{}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := prefixUpperBound(tt.prefix)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("prefixUpperBound(%v) = %v, expected %v", tt.prefix, result, tt.expected)
			}
		})
	}
}
