package storage

import (
	"fmt"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

func BenchmarkMemDBPut(b *testing.B) {
	db := NewMemDB()
	defer db.Close()

	value := make([]byte, 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := []byte(fmt.Sprintf("key%d", i))
		db.Put(key, value)
	}
}

func BenchmarkMemDBGet(b *testing.B) {
	db := NewMemDB()
	defer db.Close()

	// Pre-populate
	value := make([]byte, 100)
	for i := 0; i < 10000; i++ {
		key := []byte(fmt.Sprintf("key%d", i))
		db.Put(key, value)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := []byte(fmt.Sprintf("key%d", i%10000))
		db.Get(key)
	}
}

func BenchmarkMemDBHas(b *testing.B) {
	db := NewMemDB()
	defer db.Close()

	// Pre-populate
	value := make([]byte, 100)
	for i := 0; i < 10000; i++ {
		key := []byte(fmt.Sprintf("key%d", i))
		db.Put(key, value)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := []byte(fmt.Sprintf("key%d", i%10000))
		db.Has(key)
	}
}

func BenchmarkMemDBDelete(b *testing.B) {
	db := NewMemDB()
	defer db.Close()

	// Pre-populate
	value := make([]byte, 100)
	for i := 0; i < b.N; i++ {
		key := []byte(fmt.Sprintf("key%d", i))
		db.Put(key, value)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := []byte(fmt.Sprintf("key%d", i))
		db.Delete(key)
	}
}

func BenchmarkMemDBBatch(b *testing.B) {
	db := NewMemDB()
	defer db.Close()

	value := make([]byte, 100)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		batch := db.NewBatch()
		for j := 0; j < 100; j++ {
			key := []byte(fmt.Sprintf("key%d_%d", i, j))
			batch.Put(key, value)
		}
		batch.Write()
	}
}

func BenchmarkPebbleDBPut(b *testing.B) {
	db, err := NewPebbleDB(b.TempDir())
	if err != nil {
		b.Fatalf("failed to create PebbleDB: %v", err)
	}
	defer db.Close()

	value := make([]byte, 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := []byte(fmt.Sprintf("key%d", i))
		db.Put(key, value)
	}
}

func BenchmarkPebbleDBGet(b *testing.B) {
	db, err := NewPebbleDB(b.TempDir())
	if err != nil {
		b.Fatalf("failed to create PebbleDB: %v", err)
	}
	defer db.Close()

	// Pre-populate
	value := make([]byte, 100)
	for i := 0; i < 10000; i++ {
		key := []byte(fmt.Sprintf("key%d", i))
		db.Put(key, value)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := []byte(fmt.Sprintf("key%d", i%10000))
		db.Get(key)
	}
}

func BenchmarkPebbleDBBatch(b *testing.B) {
	db, err := NewPebbleDB(b.TempDir())
	if err != nil {
		b.Fatalf("failed to create PebbleDB: %v", err)
	}
	defer db.Close()

	value := make([]byte, 100)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		batch := db.NewBatch()
		for j := 0; j < 100; j++ {
			key := []byte(fmt.Sprintf("key%d_%d", i, j))
			batch.Put(key, value)
		}
		batch.Write()
	}
}

func BenchmarkPebbleDBIterator(b *testing.B) {
	db, err := NewPebbleDB(b.TempDir())
	if err != nil {
		b.Fatalf("failed to create PebbleDB: %v", err)
	}
	defer db.Close()

	// Pre-populate with prefixed keys
	value := make([]byte, 100)
	for i := 0; i < 1000; i++ {
		key := []byte(fmt.Sprintf("prefix_%04d", i))
		db.Put(key, value)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		iter := db.NewIterator([]byte("prefix_"))
		count := 0
		for iter.Next() {
			_ = iter.Key()
			_ = iter.Value()
			count++
		}
		iter.Release()
	}
}

func BenchmarkChainDBStoreBlock(b *testing.B) {
	db := NewMemDB()
	chainDB := NewChainDB(db)

	// Create a minimal test block
	block := createBenchBlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use different hashes for each iteration
		block.Header.Nonce = uint32(i)
		hash := block.Header.BlockHash()
		chainDB.StoreBlock(hash, block)
	}
}

func BenchmarkChainDBGetBlock(b *testing.B) {
	db := NewMemDB()
	chainDB := NewChainDB(db)

	// Store blocks first
	type storedBlock struct {
		hash  wire.Hash256
		block *wire.MsgBlock
	}
	blocks := make([]storedBlock, 100)
	for i := 0; i < 100; i++ {
		block := createBenchBlock()
		block.Header.Nonce = uint32(i)
		hash := block.Header.BlockHash()
		blocks[i] = storedBlock{hash: hash, block: block}
		chainDB.StoreBlock(hash, block)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % 100
		chainDB.GetBlock(blocks[idx].hash)
	}
}

func BenchmarkChainDBStoreHeader(b *testing.B) {
	db := NewMemDB()
	chainDB := NewChainDB(db)

	header := &wire.BlockHeader{
		Version:   1,
		Timestamp: 1296688602,
		Bits:      0x207fffff,
		Nonce:     0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header.Nonce = uint32(i)
		hash := header.BlockHash()
		chainDB.StoreBlockHeader(hash, header)
	}
}

func BenchmarkChainDBGetHeader(b *testing.B) {
	db := NewMemDB()
	chainDB := NewChainDB(db)

	// Store headers first
	hashes := make([]wire.Hash256, 100)
	for i := 0; i < 100; i++ {
		header := &wire.BlockHeader{
			Version:   1,
			Timestamp: 1296688602,
			Bits:      0x207fffff,
			Nonce:     uint32(i),
		}
		hash := header.BlockHash()
		hashes[i] = hash
		chainDB.StoreBlockHeader(hash, header)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % 100
		chainDB.GetBlockHeader(hashes[idx])
	}
}

// createBenchBlock creates a minimal test block for benchmarking.
func createBenchBlock() *wire.MsgBlock {
	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			Timestamp: 1296688602,
			Bits:      0x207fffff,
			Nonce:     0,
		},
		Transactions: []*wire.MsgTx{
			{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{
							Hash:  wire.Hash256{},
							Index: 0xFFFFFFFF,
						},
						SignatureScript: []byte{0x04, 0xff, 0xff, 0x00, 0x1d},
						Sequence:        0xFFFFFFFF,
					},
				},
				TxOut: []*wire.TxOut{
					{
						Value:    5000000000,
						PkScript: make([]byte, 25),
					},
				},
				LockTime: 0,
			},
		},
	}
}
