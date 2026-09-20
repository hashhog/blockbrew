package consensus

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestCacheBytesUndercountsDirtyAndFreshMaps pins the first half of the
// 2026-09-20 ~3x peak-RSS / UTXO-cache bound.
//
// estimateEntrySize's +100 is one map (the coins cache). AddUTXO also
// inserts dirty and fresh, so live Go heap with a filled snapshot-style
// batch is ~2x cacheBytes — not a leak, and not GOGC failing to return
// pages (this samples after runtime.GC). The remaining ~1x on the live
// 6.57 GB / 2.01 GB measurement is Pebble write buffers overlapping the
// still-resident cache until flushLockedDiscard replaces the maps.
func TestCacheBytesUndercountsDirtyAndFreshMaps(t *testing.T) {
	pkScript := bytes.Repeat([]byte{0x51}, 25)
	const nCoins = 200_000

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	u := NewUTXOSetWithMaxCache(storage.NewChainDB(storage.NewMemDB()), 1<<62)
	for i := 0; i < nCoins; i++ {
		var h wire.Hash256
		binary.BigEndian.PutUint32(h[:], uint32(i+1))
		u.AddUTXO(wire.OutPoint{Hash: h, Index: 0}, &UTXOEntry{
			Amount:   50_00000000,
			PkScript: pkScript,
			Height:   100,
		})
	}
	if got := len(u.cache); got != nCoins {
		t.Fatalf("cache=%d, want %d", got, nCoins)
	}
	if got := len(u.dirty); got != nCoins {
		t.Fatalf("dirty=%d, want %d (snapshot load marks every coin dirty)", got, nCoins)
	}
	if got := len(u.fresh); got != nCoins {
		t.Fatalf("fresh=%d, want %d (AddUTXO marks every coin fresh)", got, nCoins)
	}

	cb := u.CacheBytes()
	if cb <= 0 {
		t.Fatal("cacheBytes must be > 0")
	}
	runtime.GC()
	var end runtime.MemStats
	runtime.ReadMemStats(&end)
	heapΔ := int64(end.HeapAlloc) - int64(base.HeapAlloc)
	if heapΔ < 0 {
		heapΔ = int64(end.HeapAlloc)
	}
	ratio := float64(heapΔ) / float64(cb)
	t.Logf("%d coins: cacheBytes=%d heapΔ=%d (%.2fx) heap/coin=%d est/coin=%d maps cache/dirty/fresh=%d/%d/%d",
		nCoins, cb, heapΔ, ratio, heapΔ/nCoins, cb/nCoins, len(u.cache), len(u.dirty), len(u.fresh))
	if heapΔ < cb*3/2 {
		t.Fatalf("live heap after GC is only %.2fx cacheBytes — expected ≥1.5x when dirty+fresh are populated (the map undercount that makes -dbcache a bound, not a budget)", ratio)
	}
}
