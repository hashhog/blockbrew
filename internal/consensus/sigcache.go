package consensus

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"github.com/hashhog/blockbrew/internal/script"
)

// DefaultSigCacheSize is the default number of entries in the signature cache.
const DefaultSigCacheSize = 50000

// SigCache caches successful script validation results to avoid redundant work.
// When a transaction is validated for the mempool and later included in a block,
// the cache allows skipping the expensive script verification on block connection.
//
// Key derivation mirrors Bitcoin Core's script execution cache
// (validation.cpp / script/sigcache.h): each entry is keyed on
//
//	SHA256(nonce[32] || wtxhash[32] || inputIndex[4] || flags[4])
//
// where nonce is a random 32-byte value drawn from crypto/rand at construction.
// Using the witness transaction hash (wtxhash / wtxid) rather than the
// non-witness txid ensures that two segwit transactions sharing a txid but
// carrying different witness data are never confused — a malleated witness
// cannot inherit a cache hit from the canonical form (BUG W105-B8B).
// The random nonce makes cache entries unpredictable across process restarts,
// preventing timing-based probing of cache state (BUG W105-B8A).
//
// The 16-byte map key is the first 16 bytes of the SHA256 output; this is
// sufficient for collision resistance in a cache context (same approach as
// Core's CuckooCache with 256-bit entries truncated for storage).
type SigCache struct {
	mu      sync.RWMutex
	entries map[[16]byte]struct{}
	maxSize int
	nonce   [32]byte // random salt initialised at construction from crypto/rand
}

// NewSigCache creates a new signature cache with the specified maximum size.
// If maxSize is 0 or negative, DefaultSigCacheSize is used.
// Panics if crypto/rand is unavailable (should never happen on supported
// platforms).
func NewSigCache(maxSize int) *SigCache {
	if maxSize <= 0 {
		maxSize = DefaultSigCacheSize
	}
	sc := &SigCache{
		entries: make(map[[16]byte]struct{}),
		maxSize: maxSize,
	}
	if _, err := rand.Read(sc.nonce[:]); err != nil {
		panic("sigcache: failed to read random nonce: " + err.Error())
	}
	return sc
}

// computeKey derives the cache entry key for the given witness transaction
// hash, input index, and script flags.
//
//	key = SHA256(nonce || wtxhash || inputIndex_le32 || flags_le32)[0:16]
func (sc *SigCache) computeKey(wtxhash [32]byte, inputIndex uint32, flags script.ScriptFlags) [16]byte {
	var buf [32 + 32 + 4 + 4]byte
	copy(buf[0:32], sc.nonce[:])
	copy(buf[32:64], wtxhash[:])
	binary.LittleEndian.PutUint32(buf[64:68], inputIndex)
	binary.LittleEndian.PutUint32(buf[68:72], uint32(flags))
	h := sha256.Sum256(buf[:])
	var key [16]byte
	copy(key[:], h[:16])
	return key
}

// Lookup checks if a script validation result is cached.
// wtxhash must be the witness transaction hash (wtxid), not the stripped txid.
// Returns true if the validation was previously successful with the same
// (wtxhash, inputIndex, flags) triple under this cache's nonce.
func (sc *SigCache) Lookup(wtxhash [32]byte, inputIndex uint32, flags script.ScriptFlags) bool {
	key := sc.computeKey(wtxhash, inputIndex, flags)
	sc.mu.RLock()
	_, found := sc.entries[key]
	sc.mu.RUnlock()
	return found
}

// Insert adds a successful script validation result to the cache.
// wtxhash must be the witness transaction hash (wtxid), not the stripped txid.
// If the cache is at capacity, a random entry is evicted first.
func (sc *SigCache) Insert(wtxhash [32]byte, inputIndex uint32, flags script.ScriptFlags) {
	key := sc.computeKey(wtxhash, inputIndex, flags)

	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Check if already present
	if _, found := sc.entries[key]; found {
		return
	}

	// Evict a random entry if at capacity.
	// Go's map iteration order is randomized, so ranging and breaking
	// on the first key gives us pseudo-random eviction.
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
	sc.entries = make(map[[16]byte]struct{})
	sc.mu.Unlock()
}

// Size returns the current number of entries in the cache.
func (sc *SigCache) Size() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return len(sc.entries)
}
