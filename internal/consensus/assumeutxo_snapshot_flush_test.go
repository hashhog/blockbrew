package consensus

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestLoadSnapshotCoinsRespectsCacheBudget is the control for the 2026-09-20
// --load-snapshot memory bomb: 124,650,863 coins from a 6.23 GB file sat at
// 33-35 GB RSS because LoadSnapshotCoins accumulated the whole set and logged
// "deferred flush". Core PopulateAndValidateSnapshot flushes when the coins
// cache is CRITICAL (validation.cpp:5846-5856). This test loads several
// thousand coins against a budget of tens of entries: before the fix, peak
// cacheBytes scales with N; after, it stays within a small multiple of the
// budget and the coins are still durable + hash-identical.
func TestLoadSnapshotCoinsRespectsCacheBudget(t *testing.T) {
	const nCoins = 4000
	const baseHeight int32 = 1000
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	var blockHash wire.Hash256
	blockHash[0] = 0x51

	pkScript := bytes.Repeat([]byte{0x51}, 25) // P2PKH-sized; estimateEntrySize ~174 B
	srcDB := storage.NewChainDB(storage.NewMemDB())
	src := NewUTXOSet(srcDB)
	ops := make([]wire.OutPoint, nCoins)
	for i := 0; i < nCoins; i++ {
		var h wire.Hash256
		binary.BigEndian.PutUint32(h[:], uint32(i+1))
		ops[i] = wire.OutPoint{Hash: h, Index: 0}
		src.AddUTXO(ops[i], &UTXOEntry{
			Amount:     50_00000000,
			PkScript:   pkScript,
			Height:     100,
			IsCoinbase: i == 0,
		})
	}

	var buf bytes.Buffer
	if _, err := WriteSnapshot(&buf, src, blockHash, netMagic); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	probe := NewUTXOSet(storage.NewChainDB(storage.NewMemDB()))
	probe.AddUTXO(ops[0], &UTXOEntry{Amount: 1, PkScript: pkScript, Height: 1})
	entryBytes := probe.CacheBytes()
	if entryBytes <= 0 {
		t.Fatalf("probe entry size must be > 0, got %d", entryBytes)
	}
	const budgetEntries = 20
	budget := entryBytes * budgetEntries
	fullSetBytes := entryBytes * int64(nCoins)
	if fullSetBytes < budget*8 {
		t.Fatalf("test fixture too small to discriminate: full set %d, budget %d", fullSetBytes, budget)
	}

	sr, err := NewSnapshotReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("NewSnapshotReader: %v", err)
	}
	dstDB := storage.NewChainDB(storage.NewMemDB())
	loaded, stats, err := LoadSnapshotCoinsWithCache(sr, dstDB, baseHeight, budget)
	if err != nil {
		t.Fatalf("LoadSnapshotCoinsWithCache: %v", err)
	}
	if stats.CoinsLoaded != uint64(nCoins) {
		t.Fatalf("CoinsLoaded = %d, want %d", stats.CoinsLoaded, nCoins)
	}

	// Discriminating assertion: peak residency must not scale with N.
	// Slack of 4x budget covers the check-interval remainder plus map jitter.
	if stats.PeakCacheBytes > budget*4 {
		t.Fatalf("peak cacheBytes = %d (%.1fx budget %d) over %d coins — snapshot load is still accumulating the whole set (deferred flush). Core flushes on CRITICAL so RSS tracks -dbcache, not the file.",
			stats.PeakCacheBytes, float64(stats.PeakCacheBytes)/float64(budget), budget, nCoins)
	}
	if stats.Flushes == 0 {
		t.Fatalf("expected mid-load batch flushes with budget %d over %d coins, got 0 (deferred flush)", budget, nCoins)
	}

	// Results-neutral: every coin is still readable after the cache was
	// discarded (re-read from the backing store). A lost coin here is a
	// consensus bug, not a cache-policy miss.
	for i, op := range ops {
		got := loaded.GetUTXO(op)
		if got == nil {
			t.Fatalf("coin %d lost after budgeted snapshot load: %x", i, op.Hash[:4])
		}
		if got.Amount != 50_00000000 || got.Height != 100 {
			t.Fatalf("coin %d mismatch: amount=%d height=%d", i, got.Amount, got.Height)
		}
	}

	count, err := loaded.ScanUTXOs(func(wire.OutPoint, *UTXOEntry) bool { return true })
	if err != nil {
		t.Fatalf("ScanUTXOs: %v", err)
	}
	if count != uint64(nCoins) {
		t.Fatalf("ScanUTXOs count = %d, want %d", count, nCoins)
	}
}

// TestLoadSnapshotCoinsBudgetedHashMatchesUnbounded: incremental flush must
// not change HASH_SERIALIZED. Same file, tiny budget vs default budget.
func TestLoadSnapshotCoinsBudgetedHashMatchesUnbounded(t *testing.T) {
	const nCoins = 800
	const baseHeight int32 = 1000
	netMagic := [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	var blockHash wire.Hash256
	blockHash[0] = 0x52
	pkScript := []byte{0x76, 0xa9, 0x14, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x88, 0xac}

	src := NewUTXOSet(storage.NewChainDB(storage.NewMemDB()))
	for i := 0; i < nCoins; i++ {
		var h wire.Hash256
		binary.BigEndian.PutUint32(h[:], uint32(i+1))
		src.AddUTXO(wire.OutPoint{Hash: h, Index: 0}, &UTXOEntry{
			Amount:   int64(1000 + i),
			PkScript: pkScript,
			Height:   50,
		})
	}
	var buf bytes.Buffer
	if _, err := WriteSnapshot(&buf, src, blockHash, netMagic); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	raw := buf.Bytes()

	load := func(budget int64) wire.Hash256 {
		t.Helper()
		sr, err := NewSnapshotReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("NewSnapshotReader: %v", err)
		}
		loaded, _, err := LoadSnapshotCoinsWithCache(sr, storage.NewChainDB(storage.NewMemDB()), baseHeight, budget)
		if err != nil {
			t.Fatalf("LoadSnapshotCoinsWithCache budget=%d: %v", budget, err)
		}
		h, n, err := ComputeHashSerialized(loaded)
		if err != nil {
			t.Fatalf("ComputeHashSerialized budget=%d: %v", budget, err)
		}
		if n != uint64(nCoins) {
			t.Fatalf("hashed %d coins, want %d (budget %d)", n, nCoins, budget)
		}
		return h
	}

	probe := NewUTXOSet(storage.NewChainDB(storage.NewMemDB()))
	probe.AddUTXO(wire.OutPoint{}, &UTXOEntry{Amount: 1, PkScript: pkScript, Height: 1})
	tiny := probe.CacheBytes() * 15

	full := load(DefaultCacheMaxBytes)
	budgeted := load(tiny)
	if full != budgeted {
		t.Fatalf("HASH_SERIALIZED diverged under budgeted flush:\n  unbounded %s\n  budgeted  %s", full, budgeted)
	}
}
