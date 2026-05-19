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
// Key derivation mirrors Bitcoin Core's signature cache
// (src/script/sigcache.cpp::ComputeEntryECDSA / ComputeEntrySchnorr): the
// per-input key must commit to ALL inputs to script evaluation, not merely
// the (wtxid, inputIdx, flags) script-evaluation CONTEXT. Specifically the
// key includes the prevOut pkScript and amount so that the cache hit
// guarantees the **sighash, pubkey, sig** material that the verifier saw
// would also be identical (W160 BUG-11: "sigcache-omits-sighash"). Without
// committing to pkScript + amount, a cache PASS keyed on (wtxhash, inputIdx,
// flags) is necessary-but-not-sufficient for "this exact script-evaluation
// passed" — a tx whose pkScript-input changes across reorgs (e.g. via
// OP_CODESEPARATOR producing different sighashes per branch) could replay
// a stale PASS.
//
//	key = SHA256(nonce[32] || wtxhash[32] || inputIndex[4] || flags[4] ||
//	             amount[8] || pkScriptLen[4] || pkScript)
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

// computeKey derives the cache entry key. It commits to:
//   - nonce (random salt, anti-probing)
//   - wtxhash (witness txid: full witness + tx structure)
//   - inputIndex (which input within the tx)
//   - flags (script verify flags)
//   - amount + pkScript (prevOut: closes W160 BUG-11 "sigcache-omits-sighash"
//     by committing to the only script-eval inputs not already covered by wtxhash)
//
//	key = SHA256(nonce[32] || wtxhash[32] || inputIndex_le32 || flags_le32 ||
//	             amount_le64 || pkScriptLen_le32 || pkScript)[0:16]
//
// pkScript + amount are the inputs to sighash computation that come from the
// UTXO being spent, not from the spending tx. Without them, an evaluation
// against a different prevOut (e.g. on reorg replay where the UTXO was
// recomputed) could replay a stale PASS. Core's
// `ComputeEntryECDSA(entry, sighash, sig, pubkey)` commits to the actual
// sighash; this Go-level analog commits to the inputs that uniquely determine
// every sighash that the script will compute.
func (sc *SigCache) computeKey(wtxhash [32]byte, inputIndex uint32, flags script.ScriptFlags, amount int64, pkScript []byte) [16]byte {
	buf := make([]byte, 0, 32+32+4+4+8+4+len(pkScript))
	buf = append(buf, sc.nonce[:]...)
	buf = append(buf, wtxhash[:]...)
	var tmp [8]byte
	binary.LittleEndian.PutUint32(tmp[:4], inputIndex)
	buf = append(buf, tmp[:4]...)
	binary.LittleEndian.PutUint32(tmp[:4], uint32(flags))
	buf = append(buf, tmp[:4]...)
	binary.LittleEndian.PutUint64(tmp[:8], uint64(amount))
	buf = append(buf, tmp[:8]...)
	binary.LittleEndian.PutUint32(tmp[:4], uint32(len(pkScript)))
	buf = append(buf, tmp[:4]...)
	buf = append(buf, pkScript...)
	h := sha256.Sum256(buf)
	var key [16]byte
	copy(key[:], h[:16])
	return key
}

// Lookup checks if a script validation result is cached.
// wtxhash must be the witness transaction hash (wtxid), not the stripped txid.
// amount and pkScript are the prevOut being spent — these MUST commit to the
// script-evaluation inputs that determine the sighash (W160 BUG-11). Returns
// true if the validation was previously successful with the same
// (wtxhash, inputIndex, flags, amount, pkScript) tuple under this cache's nonce.
func (sc *SigCache) Lookup(wtxhash [32]byte, inputIndex uint32, flags script.ScriptFlags, amount int64, pkScript []byte) bool {
	key := sc.computeKey(wtxhash, inputIndex, flags, amount, pkScript)
	sc.mu.RLock()
	_, found := sc.entries[key]
	sc.mu.RUnlock()
	return found
}

// Insert adds a successful script validation result to the cache.
// wtxhash must be the witness transaction hash (wtxid), not the stripped txid.
// amount and pkScript are the prevOut being spent — these MUST commit to the
// script-evaluation inputs that determine the sighash (W160 BUG-11).
// If the cache is at capacity, a random entry is evicted first.
func (sc *SigCache) Insert(wtxhash [32]byte, inputIndex uint32, flags script.ScriptFlags, amount int64, pkScript []byte) {
	key := sc.computeKey(wtxhash, inputIndex, flags, amount, pkScript)

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
