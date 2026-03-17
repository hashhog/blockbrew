package consensus

import (
	"sync"
	"testing"

	"github.com/hashhog/blockbrew/internal/script"
)

func TestSigCache_InsertAndLookup(t *testing.T) {
	cache := NewSigCache(100)

	txid := [32]byte{1, 2, 3, 4}
	inputIndex := uint32(0)
	flags := script.ScriptFlags(script.ScriptVerifyP2SH | script.ScriptVerifyWitness)

	// Lookup before insert should return false
	if cache.Lookup(txid, inputIndex, flags) {
		t.Error("expected Lookup to return false for unknown key")
	}

	// Insert
	cache.Insert(txid, inputIndex, flags)

	// Lookup after insert should return true
	if !cache.Lookup(txid, inputIndex, flags) {
		t.Error("expected Lookup to return true after Insert")
	}

	// Lookup with different flags should return false
	differentFlags := script.ScriptFlags(script.ScriptVerifyP2SH)
	if cache.Lookup(txid, inputIndex, differentFlags) {
		t.Error("expected Lookup to return false for different flags")
	}

	// Lookup with different input index should return false
	if cache.Lookup(txid, 1, flags) {
		t.Error("expected Lookup to return false for different input index")
	}

	// Lookup with different txid should return false
	differentTxid := [32]byte{5, 6, 7, 8}
	if cache.Lookup(differentTxid, inputIndex, flags) {
		t.Error("expected Lookup to return false for different txid")
	}
}

func TestSigCache_LookupUnknownKey(t *testing.T) {
	cache := NewSigCache(100)

	// Various unknown keys should all return false
	for i := 0; i < 10; i++ {
		txid := [32]byte{byte(i)}
		if cache.Lookup(txid, uint32(i), script.ScriptFlags(i)) {
			t.Errorf("expected Lookup to return false for unknown key %d", i)
		}
	}

	// Size should be 0
	if cache.Size() != 0 {
		t.Errorf("expected empty cache, got size %d", cache.Size())
	}
}

func TestSigCache_EvictionAtCapacity(t *testing.T) {
	maxSize := 10
	cache := NewSigCache(maxSize)

	// Insert maxSize entries
	for i := 0; i < maxSize; i++ {
		txid := [32]byte{byte(i)}
		cache.Insert(txid, 0, 0)
	}

	// Should be at capacity
	if cache.Size() != maxSize {
		t.Errorf("expected size %d, got %d", maxSize, cache.Size())
	}

	// Insert one more entry - should trigger eviction
	newTxid := [32]byte{byte(maxSize + 1)}
	cache.Insert(newTxid, 0, 0)

	// Size should still be maxSize (one evicted, one added)
	if cache.Size() != maxSize {
		t.Errorf("expected size %d after eviction, got %d", maxSize, cache.Size())
	}

	// The new entry should be present
	if !cache.Lookup(newTxid, 0, 0) {
		t.Error("expected new entry to be present after eviction")
	}
}

func TestSigCache_Clear(t *testing.T) {
	cache := NewSigCache(100)

	// Insert some entries
	for i := 0; i < 50; i++ {
		txid := [32]byte{byte(i)}
		cache.Insert(txid, 0, 0)
	}

	if cache.Size() != 50 {
		t.Errorf("expected size 50, got %d", cache.Size())
	}

	// Clear the cache
	cache.Clear()

	// Size should be 0
	if cache.Size() != 0 {
		t.Errorf("expected size 0 after Clear, got %d", cache.Size())
	}

	// Previous entries should not be found
	for i := 0; i < 50; i++ {
		txid := [32]byte{byte(i)}
		if cache.Lookup(txid, 0, 0) {
			t.Errorf("expected entry %d to be gone after Clear", i)
		}
	}
}

func TestSigCache_ConcurrentAccess(t *testing.T) {
	cache := NewSigCache(1000)
	var wg sync.WaitGroup

	// Spawn multiple goroutines doing inserts
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				txid := [32]byte{byte(gid), byte(i)}
				cache.Insert(txid, uint32(i), script.ScriptFlags(gid))
			}
		}(g)
	}

	// Spawn multiple goroutines doing lookups
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				txid := [32]byte{byte(gid), byte(i)}
				cache.Lookup(txid, uint32(i), script.ScriptFlags(gid))
			}
		}(g)
	}

	// Wait for all goroutines
	wg.Wait()

	// Cache should have entries (exact count depends on timing)
	if cache.Size() == 0 {
		t.Error("expected cache to have entries after concurrent inserts")
	}
}

func TestSigCache_DuplicateInsert(t *testing.T) {
	cache := NewSigCache(100)

	txid := [32]byte{1, 2, 3, 4}
	inputIndex := uint32(5)
	flags := script.ScriptFlags(script.ScriptVerifyWitness)

	// Insert same entry multiple times
	for i := 0; i < 5; i++ {
		cache.Insert(txid, inputIndex, flags)
	}

	// Size should be 1 (duplicates ignored)
	if cache.Size() != 1 {
		t.Errorf("expected size 1 after duplicate inserts, got %d", cache.Size())
	}

	// Entry should be present
	if !cache.Lookup(txid, inputIndex, flags) {
		t.Error("expected entry to be present")
	}
}

func TestSigCache_DefaultSize(t *testing.T) {
	// Test that 0 or negative size uses default
	cache1 := NewSigCache(0)
	if cache1.maxSize != DefaultSigCacheSize {
		t.Errorf("expected default size %d for 0, got %d", DefaultSigCacheSize, cache1.maxSize)
	}

	cache2 := NewSigCache(-1)
	if cache2.maxSize != DefaultSigCacheSize {
		t.Errorf("expected default size %d for -1, got %d", DefaultSigCacheSize, cache2.maxSize)
	}
}

func BenchmarkSigCache_Insert(b *testing.B) {
	cache := NewSigCache(DefaultSigCacheSize)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		txid := [32]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
		cache.Insert(txid, uint32(i%10), script.ScriptFlags(i%100))
	}
}

func BenchmarkSigCache_Lookup(b *testing.B) {
	cache := NewSigCache(DefaultSigCacheSize)

	// Pre-populate cache
	for i := 0; i < 10000; i++ {
		txid := [32]byte{byte(i), byte(i >> 8)}
		cache.Insert(txid, 0, 0)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		txid := [32]byte{byte(i), byte(i >> 8)}
		cache.Lookup(txid, 0, 0)
	}
}

func BenchmarkSigCache_ConcurrentLookup(b *testing.B) {
	cache := NewSigCache(DefaultSigCacheSize)

	// Pre-populate cache
	for i := 0; i < 10000; i++ {
		txid := [32]byte{byte(i), byte(i >> 8)}
		cache.Insert(txid, 0, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			txid := [32]byte{byte(i), byte(i >> 8)}
			cache.Lookup(txid, 0, 0)
			i++
		}
	})
}
