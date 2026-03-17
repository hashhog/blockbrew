package consensus

import (
	"sync"

	"github.com/hashhog/blockbrew/internal/script"
)

// DefaultSigCacheSize is the default number of entries in the signature cache.
const DefaultSigCacheSize = 50000

// CacheKey uniquely identifies a validated script execution.
// The combination of txid, input index, and script flags ensures that
// cache entries are only reused when the exact same validation would occur.
type CacheKey struct {
	TxID       [32]byte
	InputIndex uint32
	Flags      script.ScriptFlags
}

// SigCache caches successful script validation results to avoid redundant work.
// When a transaction is validated for the mempool and later included in a block,
// the cache allows skipping the expensive script verification on block connection.
// Uses a simple map with random eviction when capacity is reached.
type SigCache struct {
	mu      sync.RWMutex
	entries map[CacheKey]struct{}
	maxSize int
}

// NewSigCache creates a new signature cache with the specified maximum size.
// If maxSize is 0 or negative, DefaultSigCacheSize is used.
func NewSigCache(maxSize int) *SigCache {
	if maxSize <= 0 {
		maxSize = DefaultSigCacheSize
	}
	return &SigCache{
		entries: make(map[CacheKey]struct{}),
		maxSize: maxSize,
	}
}

// Lookup checks if a script validation result is cached.
// Returns true if the validation was previously successful with the same flags.
func (sc *SigCache) Lookup(txid [32]byte, inputIndex uint32, flags script.ScriptFlags) bool {
	key := CacheKey{
		TxID:       txid,
		InputIndex: inputIndex,
		Flags:      flags,
	}
	sc.mu.RLock()
	_, found := sc.entries[key]
	sc.mu.RUnlock()
	return found
}

// Insert adds a successful script validation result to the cache.
// If the cache is at capacity, a random entry is evicted first.
func (sc *SigCache) Insert(txid [32]byte, inputIndex uint32, flags script.ScriptFlags) {
	key := CacheKey{
		TxID:       txid,
		InputIndex: inputIndex,
		Flags:      flags,
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Check if already present
	if _, found := sc.entries[key]; found {
		return
	}

	// Evict a random entry if at capacity
	// Go's map iteration order is randomized, so ranging and breaking
	// on the first key gives us pseudo-random eviction
	if len(sc.entries) >= sc.maxSize {
		for k := range sc.entries {
			delete(sc.entries, k)
			break
		}
	}

	sc.entries[key] = struct{}{}
}

// Clear removes all entries from the cache.
// Called during block disconnection since cached entries may no longer be valid.
func (sc *SigCache) Clear() {
	sc.mu.Lock()
	sc.entries = make(map[CacheKey]struct{})
	sc.mu.Unlock()
}

// Size returns the current number of entries in the cache.
func (sc *SigCache) Size() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return len(sc.entries)
}
