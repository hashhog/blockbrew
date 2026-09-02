package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// UTXO set errors.
var (
	ErrUTXONotFound     = errors.New("utxo not found")
	ErrUTXOAlreadySpent = errors.New("utxo already spent")
)

// DefaultCacheMaxEntries is the maximum number of UTXO entries to cache in memory.
// This corresponds roughly to 450 MB of memory usage.
const DefaultCacheMaxEntries = 5_000_000

// DefaultCacheMaxBytes is the maximum approximate cache size in bytes (2GB).
const DefaultCacheMaxBytes = 2 * 1024 * 1024 * 1024

// IBDFlushInterval is the number of blocks between forced UTXO flushes during IBD.
// Larger values improve IBD performance but use more memory.
const IBDFlushInterval = 2000

// UTXOCacheStats tracks cache performance metrics.
type UTXOCacheStats struct {
	Hits       uint64 // Cache hits
	Misses     uint64 // Cache misses (required DB lookup)
	Flushes    uint64 // Number of flush operations
	CacheSize  int    // Current cache entry count
	CacheBytes int64  // Approximate memory usage
}

// UTXOSet manages the set of unspent transaction outputs with caching and persistence.
type UTXOSet struct {
	mu    sync.RWMutex
	db    *storage.ChainDB
	cache map[wire.OutPoint]*UTXOEntry // In-memory cache for performance
	dirty map[wire.OutPoint]bool       // Modified entries needing flush
	// Track deletions separately since deleted entries should be flushed too
	deleted map[wire.OutPoint]bool
	// FRESH flag: entries created since the last flush that have never been
	// written to the database. If a FRESH entry is spent before the next
	// flush, we can skip both the write and the delete — a major IBD win.
	fresh map[wire.OutPoint]bool

	// Performance tracking
	cacheBytes       int64  // Approximate memory usage of cache
	maxCacheBytes    int64  // Maximum cache size in bytes
	hits             uint64 // Cache hits
	misses           uint64 // Cache misses
	flushes          uint64 // Number of flush operations
	freshHits        uint64 // Spends of FRESH entries (saved a write+delete)
	blocksSinceFlush int    // Blocks connected since last flush

	// appliedHash/appliedHeight name the block through which THIS set's
	// mutations are reflected — the in-memory analogue of Core's
	// CCoinsViewCache::GetBestBlock (coins.h). Every flush writes it into
	// the same batch as the coins (see flushLocked / FlushBatch), so the
	// on-disk marker always describes exactly the on-disk set: Core's
	// DB_BEST_BLOCK discipline (txdb.cpp:158-159).
	//
	// appliedSet stays false until a caller supplies a tip, so a set that
	// nobody tracks writes no marker at all rather than claiming genesis.
	// The value is only ever advanced by ChainManager AFTER a block's
	// mutations have been applied to this set, so it can lag the true state
	// (harmless: recovery then re-connects) but never lead it (which would
	// let recovery skip a block that was never applied).
	appliedHash   wire.Hash256
	appliedHeight int32
	appliedSet    bool

	// appliedFloorHeight is a raise-only LOWER BOUND on the block height the
	// PERSISTED set may already reflect, held separately from
	// appliedHash/appliedHeight because "how much is on disk" and "which block
	// is on disk" are different questions with different evidence.
	//
	// The second question can be unanswerable while the first still has a
	// sound answer. When an interrupted multi-batch coin flush is recorded
	// (storage.CoinsFlushKey, Core's DB_HEAD_BLOCKS — txdb.cpp:128-129), the
	// on-disk marker names a block that does NOT describe the set, so nothing
	// may be adopted from it; but the two ends of the recorded window are
	// still hard evidence that the set may contain mutations up to the higher
	// of them. Discarding that evidence — which is what leaving appliedSet
	// false does — switches off AdvanceAppliedTip's raise-only guard in
	// precisely the failure case the guard exists for.
	//
	// So the floor is installed even when the marker is refused, and
	// AdvanceAppliedTip refuses to publish a marker at or below it. It is
	// RESET (not raised) by SetAppliedTip, the authoritative restatement:
	// those four callers know the whole answer, including a genuine rewind.
	appliedFloorHeight int32
	appliedFloorSet    bool

	// reorgJournal, when non-nil, records the pre-mutation state of every
	// outpoint touched since BeginReorgJournal (first-write-wins). It lets a
	// multi-block reorg that fails partway (ChainManager.ReorgTo) restore the
	// exact pre-reorg in-memory UTXO view without a full-cache wipe — critical
	// because at tip the freshly-connected coins live ONLY in this cache (the
	// per-block on-disk flush is deferred), so a blind cache discard would
	// lose committed state. nil on the hot path (single nil-check per mutation).
	reorgJournal map[wire.OutPoint]utxoPreimage
}

// utxoPreimage is the snapshot of one outpoint's cache + tracking-flag state
// captured before its first mutation within an active reorg journal.
type utxoPreimage struct {
	cached  bool
	entry   *UTXOEntry // prior cache entry (immutable; safe to retain by pointer)
	dirty   bool
	deleted bool
	fresh   bool
}

// NewUTXOSet creates a new UTXO set backed by the given database.
func NewUTXOSet(db *storage.ChainDB) *UTXOSet {
	return NewUTXOSetWithMaxCache(db, DefaultCacheMaxBytes)
}

// NewUTXOSetWithMaxCache creates a UTXO set with a custom cache size limit.
func NewUTXOSetWithMaxCache(db *storage.ChainDB, maxCacheBytes int64) *UTXOSet {
	// Pre-size maps to reduce rehashing during IBD.
	// 500k is a reasonable initial size for testnet4/mainnet UTXOs.
	const initialCacheSize = 500_000
	const initialDirtySize = 100_000
	return &UTXOSet{
		db:            db,
		cache:         make(map[wire.OutPoint]*UTXOEntry, initialCacheSize),
		dirty:         make(map[wire.OutPoint]bool, initialDirtySize),
		deleted:       make(map[wire.OutPoint]bool, initialDirtySize),
		fresh:         make(map[wire.OutPoint]bool, initialDirtySize),
		maxCacheBytes: maxCacheBytes,
	}
}

// GetUTXO retrieves a UTXO by outpoint. Checks cache first, then database.
func (u *UTXOSet) GetUTXO(outpoint wire.OutPoint) *UTXOEntry {
	u.mu.RLock()

	// Check if deleted
	if u.deleted[outpoint] {
		u.mu.RUnlock()
		return nil
	}

	// Check cache first
	if entry, ok := u.cache[outpoint]; ok {
		u.hits++
		u.mu.RUnlock()
		return entry
	}
	u.mu.RUnlock()

	// Not in cache, try database
	if u.db == nil {
		return nil
	}

	key := storage.MakeUTXOKey(outpoint)
	data, err := u.db.DB().Get(key)
	if err != nil || data == nil {
		return nil
	}

	entry, err := DeserializeUTXOEntry(data)
	if err != nil {
		return nil
	}

	// Cache the entry for future lookups
	u.mu.Lock()
	u.cache[outpoint] = entry
	u.cacheBytes += estimateEntrySize(entry)
	u.misses++
	u.mu.Unlock()

	return entry
}

// estimateEntrySize estimates the memory usage of a UTXO entry in bytes.
// Includes: OutPoint (36 bytes), Amount (8), PkScript (len + header), Height (4), IsCoinbase (1), map overhead (~100)
func estimateEntrySize(entry *UTXOEntry) int64 {
	return int64(36 + 8 + len(entry.PkScript) + 4 + 1 + 100)
}

// AddUTXO adds a new UTXO to the set.
func (u *UTXOSet) AddUTXO(outpoint wire.OutPoint, entry *UTXOEntry) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.journalPre(outpoint)

	// Track size change
	if existing, ok := u.cache[outpoint]; ok {
		u.cacheBytes -= estimateEntrySize(existing)
	}
	u.cacheBytes += estimateEntrySize(entry)

	u.cache[outpoint] = entry
	u.dirty[outpoint] = true
	// Mark as FRESH: this entry has never been written to disk.
	// If it's spent before the next flush, we skip the write entirely.
	u.fresh[outpoint] = true
	delete(u.deleted, outpoint) // Clear any pending deletion
}

// SpendUTXO marks a UTXO as spent (removes it from the set).
// This implements the UpdatableUTXOView interface.
func (u *UTXOSet) SpendUTXO(outpoint wire.OutPoint) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.journalPre(outpoint)

	// Track size change
	if existing, ok := u.cache[outpoint]; ok {
		u.cacheBytes -= estimateEntrySize(existing)
	}

	delete(u.cache, outpoint)
	delete(u.dirty, outpoint)

	// FRESH optimization: if this UTXO was created since the last flush,
	// it was never written to disk, so we don't need to delete it either.
	if u.fresh[outpoint] {
		delete(u.fresh, outpoint)
		u.freshHits++
		return
	}

	u.deleted[outpoint] = true
}

// SpendUTXOChecked marks a UTXO as spent and returns an error if it doesn't exist.
// Use this for double-spend detection.
func (u *UTXOSet) SpendUTXOChecked(outpoint wire.OutPoint) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.journalPre(outpoint)

	// Check if already deleted
	if u.deleted[outpoint] {
		return ErrUTXOAlreadySpent
	}

	// Check if in cache
	if existing, ok := u.cache[outpoint]; ok {
		u.cacheBytes -= estimateEntrySize(existing)
		delete(u.cache, outpoint)
		delete(u.dirty, outpoint)

		// FRESH optimization: never written to disk, skip writing a tombstone.
		// Still mark as deleted in memory so double-spend detection works within
		// this UTXOSet instance's lifetime.
		if u.fresh[outpoint] {
			delete(u.fresh, outpoint)
			u.freshHits++
			u.deleted[outpoint] = true
			return nil
		}

		u.deleted[outpoint] = true
		return nil
	}

	// Check if in database
	if u.db != nil {
		key := storage.MakeUTXOKey(outpoint)
		exists, err := u.db.DB().Has(key)
		if err != nil {
			return err
		}
		if exists {
			u.deleted[outpoint] = true
			return nil
		}
	}

	return ErrUTXONotFound
}

// HasUTXO checks if a UTXO exists.
func (u *UTXOSet) HasUTXO(outpoint wire.OutPoint) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	// Check if deleted
	if u.deleted[outpoint] {
		return false
	}

	// Check cache
	if _, ok := u.cache[outpoint]; ok {
		return true
	}

	// Check database
	if u.db == nil {
		return false
	}

	key := storage.MakeUTXOKey(outpoint)
	exists, err := u.db.DB().Has(key)
	return err == nil && exists
}

// HasUTXODurable reports whether an outpoint is present in the DURABLE (on-disk)
// UTXO set, deliberately bypassing both the in-memory cache and the pending
// `deleted` set.
//
// This exists for crash-state evidence probes (AdoptAppliedBlock). Those probes
// must attest what a PRIOR session actually committed to disk, and the cached
// view is contaminated by the CURRENT session's own in-flight work — including
// the residue of the very connect attempt that just failed. A probe reading
// through HasUTXO/GetUTXO will happily confirm its own uncommitted writes,
// turning the evidence gate into a false-positive machine (nimrod hit exactly
// this: its first-cut probe read the cached view, "proved" a block was applied
// off in-memory residue, and wedged the next block).
//
// Do NOT use this for consensus reads — it ignores pending spends and will
// report already-spent-this-session coins as present. It answers precisely one
// question: "is this outpoint on disk right now?"
func (u *UTXOSet) HasUTXODurable(outpoint wire.OutPoint) bool {
	if u.db == nil {
		return false
	}
	key := storage.MakeUTXOKey(outpoint)
	exists, err := u.db.DB().Has(key)
	return err == nil && exists
}

// SetAppliedTip RESTATES, authoritatively, the block through which this set's
// mutations are reflected. It may move the marker in EITHER direction, so it
// is reserved for the four callers that genuinely know the whole answer:
//
//   - boot seeding from the durable on-disk marker (ChainManager's
//     seedAppliedTipFromMarker — Core's Chainstate::LoadChainTip taking the
//     tip from coins_cache.GetBestBlock(), validation.cpp:4546);
//   - DisconnectBlock, whose undo removed a block's mutations (a real rewind);
//   - ReorgTo's rollbackToOriginalTip, which restores the journal to the
//     pre-reorg tip (a real restatement, up OR down);
//   - -load-snapshot, where the set IS the snapshot's base block.
//
// Everything else must use AdvanceAppliedTip. Lowering this marker while the
// persisted set still reflects a HIGHER block is corruption, not caution: the
// next boot re-applies blocks the set already contains, and a coinbase-only
// block among them resurrects a coin a later block already spent.
func (u *UTXOSet) SetAppliedTip(hash wire.Hash256, height int32) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.appliedHash = hash
	u.appliedHeight = height
	u.appliedSet = true
	// An authoritative restatement RESETS the floor rather than raising it.
	// A DisconnectBlock or a ReorgTo rollback genuinely removes coins, so a
	// floor left standing above the restated tip would block every subsequent
	// forward advance and strand the marker BELOW its own coins — the exact
	// corruption the floor exists to prevent, arrived at from the other side.
	u.appliedFloorHeight = height
	u.appliedFloorSet = true
}

// RaiseAppliedFloor records that the PERSISTED set may already reflect blocks
// up to `height`, without naming the block. Raise-only: a floor is a lower
// bound and evidence only ever accumulates. Reports whether the floor moved.
//
// This is the half of Core's boot-time coins-database reading that survives an
// unusable marker. Core repairs that state instead (ReplayBlocks,
// validation.cpp:4773, rolls forward to hashHeads[0] — it never publishes a
// best block below the recorded window); blockbrew has no ReplayBlocks, fails
// closed on adoption, and keeps the bound so the monotonicity guard still has
// something to stand on.
func (u *UTXOSet) RaiseAppliedFloor(height int32) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.appliedFloorSet && height <= u.appliedFloorHeight {
		return false
	}
	u.appliedFloorHeight = height
	u.appliedFloorSet = true
	return true
}

// AppliedFloor reports the raise-only lower bound on what the persisted set
// may reflect, and whether one has ever been installed.
func (u *UTXOSet) AppliedFloor() (int32, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.appliedFloorHeight, u.appliedFloorSet
}

// AdvanceAppliedTip raises the applied-through marker to (hash, height) and
// REFUSES to lower it. It is the only mutator the forward paths may use —
// ConnectBlock, AdoptAppliedBlock, AdoptFlushedBlock — because none of them
// can prove the set does not already reflect something higher.
//
// The refusal is the point. Crash recovery walks the tip UP from the
// chain-state pointer, which is only a LOWER bound on what the persisted set
// reflects (coins are flushed without advancing it: cache pressure,
// scantxoutset, the IBD cadence). Adopting block 9 out of a set that is
// durable through 121 must leave the marker at 121; stamping 9 would publish
// a marker BELOW the coins it describes, and the next boot would re-apply
// blocks 10..121 — the resurrection this whole mechanism exists to prevent
// (see ChainManager.AdoptFlushedBlock).
//
// Returns true when the marker moved.
func (u *UTXOSet) AdvanceAppliedTip(hash wire.Hash256, height int32) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.appliedSet && height <= u.appliedHeight {
		return false
	}
	// The floor is the SAME refusal standing on weaker evidence. appliedSet
	// is false on exactly the boots where the marker could not be trusted, so
	// the guard above cannot fire there — and those are the boots where the
	// persisted set is most likely to lead the tip. Refuse on the bound too.
	if u.appliedFloorSet && height <= u.appliedFloorHeight {
		return false
	}
	u.appliedHash = hash
	u.appliedHeight = height
	u.appliedSet = true
	return true
}

// AppliedTip reports the in-memory applied-through marker, and whether one
// has ever been set.
func (u *UTXOSet) AppliedTip() (wire.Hash256, int32, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.appliedHash, u.appliedHeight, u.appliedSet
}

// stageAppliedTip stages the applied-through marker into a batch. Callers
// MUST already hold u.mu, and MUST stage it into the SAME batch as the coin
// writes it describes. Mirrors Core txdb.cpp:159, which writes DB_BEST_BLOCK
// into the final CDBBatch of CCoinsViewDB::BatchWrite.
func (u *UTXOSet) stageAppliedTip(batch storage.Batch) {
	if !u.appliedSet {
		return
	}
	batch.Put(storage.CoinsTipKey, (&storage.ChainState{
		BestHash:   u.appliedHash,
		BestHeight: u.appliedHeight,
	}).Serialize())
}

// flushMaxBatchBytes caps each coin-flush batch around 2 GiB, leaving plenty
// of slack under Pebble's 4 GiB ErrBatchTooLarge limit. With typical ~50-100
// byte serialized entries that is tens of millions of entries per batch — fast
// for normal IBD flushes (which fit in one batch) and chunked-but-bounded for
// snapshot imports. A var, not a const, so the flush-ordering tests can shrink
// it and exercise the multi-batch paths without allocating gigabytes.
var flushMaxBatchBytes = 2 * 1024 * 1024 * 1024 // 2 GiB

// Flush writes all dirty entries to the database.
func (u *UTXOSet) Flush() error {
	if u.db == nil {
		return nil
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	return u.flushLocked()
}

// flushLocked performs flush while holding the lock.
//
// Pebble enforces a hard 4 GiB cap on a single batch (open.go:47,
// batch.go:1413, ErrBatchTooLarge). A normal block-connect produces dozens
// of dirty entries — well under the cap — but a -load-snapshot import
// hands flushLocked all 165M coins in one shot, easily 8+ GiB serialized,
// which used to panic mid-import. We now split the writes into chunks
// well below the cap so loadSnapshotFromFile can durably commit a Core-
// format UTXO snapshot in one go without a Pebble panic.
func (u *UTXOSet) flushLocked() error {
	if u.db == nil {
		return nil
	}

	batch := u.db.DB().NewBatch()
	chunks := 0
	flushChunk := func() error {
		if batch.Len() == 0 {
			return nil
		}
		if err := batch.Write(); err != nil {
			return err
		}
		chunks++
		batch = u.db.DB().NewBatch()
		return nil
	}
	approxBatchBytes := 0

	// PHASE 1 — adds and updates. These MAY span batches.
	//
	// A tear in this phase is repairable by construction: no delete has
	// landed yet, so the persisted set is the old set plus a prefix of the
	// new entries. The marker is still at its old (lower) value, recovery
	// re-connects that span, every AddUTXO re-writes the same key with the
	// same bytes, and every SpendUTXO still finds its coin present.
	for outpoint := range u.dirty {
		entry := u.cache[outpoint]
		if entry != nil {
			key := storage.MakeUTXOKey(outpoint)
			data := SerializeUTXOEntry(entry)
			batch.Put(key, data)
			// Pebble's batch encoding adds a few bytes of header per
			// entry on top of len(key)+len(value). Over-estimate
			// slightly to stay well below the 4 GiB hard cap.
			approxBatchBytes += len(key) + len(data) + 16
			if approxBatchBytes >= flushMaxBatchBytes {
				if err := flushChunk(); err != nil {
					return err
				}
				approxBatchBytes = 0
			}
		}
	}

	// Close the add phase so the deletes start on a batch of their own.
	if err := flushChunk(); err != nil {
		return err
	}
	approxBatchBytes = 0

	// PHASE 2 — deletes (spends) AND the applied-through marker, together,
	// in ONE batch. This ordering is what makes "a marker that lags the set
	// is safe" TRUE rather than merely hoped for.
	//
	// The unrepairable tear is a landed DELETE under a marker that still
	// names a lower block: recovery then re-connects the span, and a
	// coinbase-only block in it re-adds an output whose spend is already
	// durable — 166,180,925 -> 166,180,926, the live signature this
	// mechanism exists to prevent. Keeping every delete in the same atomic
	// batch as the marker makes that combination unrepresentable.
	//
	// Core reaches the same guarantee differently: it lets BatchWrite span
	// CDBBatches but records the window in DB_HEAD_BLOCKS first
	// (txdb.cpp:128-129) and erases it in the last batch (txdb.cpp:157-159),
	// so an interrupted flush is detected on boot and repaired by
	// ReplayBlocks (validation.cpp:4773). blockbrew does not have a
	// ReplayBlocks, so it removes the tear instead of repairing it — except
	// in the one case where it cannot (below).
	deleteBytes := 0
	if n := len(u.deleted); n > 0 {
		var probe wire.OutPoint
		for op := range u.deleted {
			probe = op
			break
		}
		deleteBytes = n * (len(storage.MakeUTXOKey(probe)) + 16)
	}

	// The escape hatch: if the deletes ALONE cannot fit one batch, the tear
	// is unavoidable, so make it DETECTABLE — Core's DB_HEAD_BLOCKS. Written
	// before the first delete lands, erased in the same batch as the final
	// marker. A boot that finds it fails closed (durableCoinsTip refuses the
	// marker and recovery refuses to guess) instead of silently re-applying
	// over a half-deleted set. In practice unreachable during IBD: a 2000-
	// block flush stages a few million deletes, ~2 orders of magnitude under
	// the cap, and a snapshot import has no deletes at all.
	tornWindow := deleteBytes >= flushMaxBatchBytes && u.appliedSet
	if tornWindow {
		old, err := u.db.DB().Get(storage.CoinsTipKey)
		if err != nil {
			return fmt.Errorf("coins flush: read previous coins marker: %w", err)
		}
		if old == nil {
			old = (&storage.ChainState{}).Serialize()
		}
		rec := append(append([]byte{}, old...), (&storage.ChainState{
			BestHash:   u.appliedHash,
			BestHeight: u.appliedHeight,
		}).Serialize()...)
		batch.Put(storage.CoinsFlushKey, rec)
		log.Printf("utxoset: coin flush deletes (%d entries, ~%d bytes) exceed the "+
			"per-batch cap and must span batches; recording an interrupted-flush "+
			"window (Core DB_HEAD_BLOCKS) so a crash here is detected, not guessed at",
			len(u.deleted), deleteBytes)
		if err := flushChunk(); err != nil {
			return err
		}
	}

	for outpoint := range u.deleted {
		key := storage.MakeUTXOKey(outpoint)
		batch.Delete(key)
		approxBatchBytes += len(key) + 16
		if tornWindow && approxBatchBytes >= flushMaxBatchBytes {
			if err := flushChunk(); err != nil {
				return err
			}
			approxBatchBytes = 0
		}
	}

	// Final chunk: the marker, and (when one was opened) the erasure of the
	// interrupted-flush record — exactly as Core writes DB_BEST_BLOCK and
	// erases DB_HEAD_BLOCKS in the same, last CDBBatch (txdb.cpp:157-159).
	if tornWindow {
		batch.Delete(storage.CoinsFlushKey)
	}
	u.stageAppliedTip(batch)
	if err := flushChunk(); err != nil {
		return err
	}

	// Clear dirty, deleted, and fresh tracking (pre-size for next batch)
	u.dirty = make(map[wire.OutPoint]bool, 100_000)
	u.deleted = make(map[wire.OutPoint]bool, 100_000)
	u.fresh = make(map[wire.OutPoint]bool, 100_000)
	u.flushes++
	u.blocksSinceFlush = 0

	// Post-flush the entire cache is clean (persisted to disk), so it is SAFE
	// to keep serving every entry from memory until we actually exceed the
	// operator's configured budget. Mirror Bitcoin Core: CCoinsViewCache is
	// flushed to disk but NOT shrunk to a fraction of m_coinstip_cache_size_bytes
	// (coins.cpp Flush/Sync). Only evict when strictly OVER budget, and only
	// down TO the budget — never to a quarter of it. This keeps the warm working
	// set the operator paid for via -dbcache resident, cutting cold Pebble
	// re-reads on the IBD connect path. (Read-path only; results unchanged —
	// eviction drops only clean, already-flushed entries.)
	if u.cacheBytes > u.maxCacheBytes {
		// Rebuild the cache map with only entries we want to keep.
		// Go maps never shrink their hash table on delete(), so we must
		// allocate a new map to actually free memory.
		target := u.maxCacheBytes
		newCache := make(map[wire.OutPoint]*UTXOEntry, len(u.cache))
		var newBytes int64
		for op, entry := range u.cache {
			if newBytes >= target {
				continue // At budget — drop the remainder
			}
			newCache[op] = entry
			newBytes += estimateEntrySize(entry)
		}
		u.cache = newCache
		u.cacheBytes = newBytes
	}

	return nil
}

// MaybeFlush flushes if cache exceeds size limit or after forceAfterBlocks blocks.
// This is used during IBD to control memory usage while batching writes.
func (u *UTXOSet) MaybeFlush(forceAfterBlocks int) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.blocksSinceFlush++

	// Flush if cache exceeds size limit or we've connected enough blocks
	if u.cacheBytes > u.maxCacheBytes || u.blocksSinceFlush >= forceAfterBlocks {
		return u.flushLocked()
	}
	return nil
}

// MaybeFlushIBD is a convenience method for IBD flushing using default interval.
func (u *UTXOSet) MaybeFlushIBD() error {
	return u.MaybeFlush(IBDFlushInterval)
}

// PreloadUTXOs loads multiple UTXOs from the database into cache.
// This is used to batch database reads before block validation.
func (u *UTXOSet) PreloadUTXOs(outpoints []wire.OutPoint) {
	if u.db == nil {
		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	for _, op := range outpoints {
		// Skip if already cached or deleted
		if _, ok := u.cache[op]; ok {
			continue
		}
		if u.deleted[op] {
			continue
		}

		key := storage.MakeUTXOKey(op)
		data, err := u.db.DB().Get(key)
		if err != nil || data == nil {
			continue
		}

		entry, err := DeserializeUTXOEntry(data)
		if err != nil {
			continue
		}

		u.cache[op] = entry
		u.cacheBytes += estimateEntrySize(entry)
	}
}

// Stats returns current cache statistics.
func (u *UTXOSet) Stats() UTXOCacheStats {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return UTXOCacheStats{
		Hits:       u.hits,
		Misses:     u.misses,
		Flushes:    u.flushes,
		CacheSize:  len(u.cache),
		CacheBytes: u.cacheBytes,
	}
}

// CacheBytes returns the approximate memory usage of the cache.
func (u *UTXOSet) CacheBytes() int64 {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.cacheBytes
}

// MaxCacheBytes returns the configured maximum size of the in-memory coins
// (UTXO) cache in bytes. This is the analogue of Bitcoin Core's
// m_coinstip_cache_size_bytes — the budget for the chainstate's in-memory coin
// cache (CCoinsViewCache), reported by the getchainstates RPC as
// coins_tip_cache_bytes. Set once at construction (NewUTXOSetWithMaxCache) and
// never mutated, so no lock is required.
func (u *UTXOSet) MaxCacheBytes() int64 {
	return u.maxCacheBytes
}

// FlushBatch writes all dirty entries using a provided batch (for atomic block connection).
func (u *UTXOSet) FlushBatch(batch storage.Batch) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Write all dirty entries
	for outpoint := range u.dirty {
		entry := u.cache[outpoint]
		if entry != nil {
			key := storage.MakeUTXOKey(outpoint)
			data := SerializeUTXOEntry(entry)
			batch.Put(key, data)
		}
	}

	// Delete all deleted entries
	for outpoint := range u.deleted {
		key := storage.MakeUTXOKey(outpoint)
		batch.Delete(key)
	}

	// The applied-through marker rides the caller's batch, atomically with
	// the coins it describes (Core: txdb.cpp:158-159). ChainManager passes
	// the same batch that carries the block body, the height row and the
	// chain-tip pointer, so all four commit or none do.
	u.stageAppliedTip(batch)

	// Clear dirty, deleted, and fresh tracking (caller will write the batch)
	u.dirty = make(map[wire.OutPoint]bool, 100_000)
	u.deleted = make(map[wire.OutPoint]bool, 100_000)
	u.fresh = make(map[wire.OutPoint]bool, 100_000)
	u.flushes++
	u.blocksSinceFlush = 0

	// Evict clean cache entries to bring memory under the limit, same as
	// Flush(). After the caller writes the batch, all entries are persisted
	// and can be safely re-read from disk. Keep the warm working set resident
	// up to the configured -dbcache budget (Core CCoinsViewCache parity); only
	// evict when strictly OVER budget and only down TO it — not to a quarter.
	// Kept byte-for-byte in sync with flushLocked's eviction block.
	if u.cacheBytes > u.maxCacheBytes {
		target := u.maxCacheBytes
		newCache := make(map[wire.OutPoint]*UTXOEntry, len(u.cache))
		var newBytes int64
		for op, entry := range u.cache {
			if newBytes >= target {
				continue
			}
			newCache[op] = entry
			newBytes += estimateEntrySize(entry)
		}
		u.cache = newCache
		u.cacheBytes = newBytes
	}

	return nil
}

// journalPre records the pre-mutation state of op the first time it is touched
// under an active reorg journal. Callers MUST already hold u.mu. No-op (one
// map-nil comparison) when no journal is active — i.e. the entire hot path.
func (u *UTXOSet) journalPre(op wire.OutPoint) {
	if u.reorgJournal == nil {
		return
	}
	if _, seen := u.reorgJournal[op]; seen {
		return
	}
	e, cached := u.cache[op]
	u.reorgJournal[op] = utxoPreimage{
		cached:  cached,
		entry:   e,
		dirty:   u.dirty[op],
		deleted: u.deleted[op],
		fresh:   u.fresh[op],
	}
}

// BeginReorgJournal starts recording UTXO pre-images so the mutations of a
// multi-block reorg can be rolled back exactly. Idempotent-guarded: a second
// begin without an intervening commit/rollback is a programming error and
// panics rather than silently dropping the outer journal.
func (u *UTXOSet) BeginReorgJournal() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.reorgJournal != nil {
		panic("consensus: BeginReorgJournal called with a journal already active")
	}
	u.reorgJournal = make(map[wire.OutPoint]utxoPreimage, 4096)
}

// CommitReorgJournal discards the recorded pre-images, making the mutations
// applied since BeginReorgJournal permanent. Called on a successful reorg.
func (u *UTXOSet) CommitReorgJournal() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reorgJournal = nil
}

// RollbackReorgJournal reverts every outpoint touched since BeginReorgJournal
// to its recorded pre-image, restoring the exact pre-reorg in-memory UTXO view
// (cache contents + dirty/deleted/fresh tracking + byte accounting). Untouched
// entries — including coins merely read into the cache during the reorg — are
// left in place. Mirrors Bitcoin Core discarding its per-activation
// CCoinsViewCache when ConnectTip fails in ActivateBestChainStep.
func (u *UTXOSet) RollbackReorgJournal() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.reorgJournal == nil {
		return
	}
	setBool := func(m map[wire.OutPoint]bool, op wire.OutPoint, v bool) {
		if v {
			m[op] = true
		} else {
			delete(m, op)
		}
	}
	for op, pre := range u.reorgJournal {
		var curSize int64
		if cur, ok := u.cache[op]; ok {
			curSize = estimateEntrySize(cur)
		}
		var preSize int64
		if pre.cached {
			preSize = estimateEntrySize(pre.entry)
		}
		u.cacheBytes += preSize - curSize

		if pre.cached {
			u.cache[op] = pre.entry
		} else {
			delete(u.cache, op)
		}
		setBool(u.dirty, op, pre.dirty)
		setBool(u.deleted, op, pre.deleted)
		setBool(u.fresh, op, pre.fresh)
	}
	u.reorgJournal = nil
}

// Size returns the number of cached UTXOs.
func (u *UTXOSet) Size() int {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return len(u.cache)
}

// ScanUTXOs iterates the entire current UTXO set, invoking visit for every
// unspent output. It returns the total number of UTXOs scanned.
//
// To present a complete and consistent view of the set, it first flushes the
// in-memory cache (dirty creations + deletions) to the backing database, then
// walks the database by UTXOPrefix. After the flush the database is the
// authoritative copy of the whole set, so a pure prefix scan visits every
// live coin exactly once with no need to overlay the cache. This mirrors the
// approach Bitcoin Core's scantxoutset takes — ForceFlushStateToDisk followed
// by a CoinsDB cursor walk (rpc/blockchain.cpp::scantxoutset).
//
// If visit returns false the scan stops early (count reflects only the coins
// visited so far). A nil database (e.g. a memory-only set used in tests with
// no db) makes this a no-op returning 0.
func (u *UTXOSet) ScanUTXOs(visit func(outpoint wire.OutPoint, entry *UTXOEntry) bool) (uint64, error) {
	if u.db == nil {
		return 0, nil
	}

	// Flush so the database holds the complete, current set.
	if err := u.Flush(); err != nil {
		return 0, err
	}

	it := u.db.DB().NewIterator(storage.UTXOPrefix)
	defer it.Release()

	var count uint64
	for it.Next() {
		key := it.Key()
		// Key layout: "U" + 32-byte txid + 4-byte big-endian vout index.
		if len(key) != 1+32+4 {
			continue
		}
		var outpoint wire.OutPoint
		copy(outpoint.Hash[:], key[1:33])
		outpoint.Index = binary.BigEndian.Uint32(key[33:37])

		entry, err := DeserializeUTXOEntry(it.Value())
		if err != nil {
			return count, err
		}
		count++
		if !visit(outpoint, entry) {
			break
		}
	}
	if err := it.Error(); err != nil {
		return count, err
	}
	return count, nil
}

// maybeFlush flushes if cache exceeds the maximum size.
func (u *UTXOSet) maybeFlush() error {
	u.mu.RLock()
	shouldFlush := len(u.cache) > DefaultCacheMaxEntries || u.cacheBytes > u.maxCacheBytes
	u.mu.RUnlock()

	if shouldFlush {
		return u.Flush()
	}
	return nil
}

// AddTxOutputs adds all outputs from a transaction to the UTXO set.
// Skips provably unspendable outputs (OP_RETURN, oversized scripts).
//
// Uses IsUnspendable for the skip predicate so ConnectBlock and DisconnectBlock
// share the same filter — otherwise a >10k-byte script would be admitted by
// ConnectBlock but skipped by DisconnectBlock on reorg, leaving a stale UTXO
// behind. Mirrors Core's validation.cpp:2218 reverse-check of the same set
// of outputs that ConnectBlock skipped.
func (u *UTXOSet) AddTxOutputs(tx *wire.MsgTx, height int32) {
	txHash := tx.TxHash()
	isCoinbase := IsCoinbaseTx(tx)

	for i, out := range tx.TxOut {
		// Skip provably unspendable outputs (OP_RETURN, oversized scripts).
		if IsUnspendable(out.PkScript) {
			continue
		}

		outpoint := wire.OutPoint{
			Hash:  txHash,
			Index: uint32(i),
		}
		u.AddUTXO(outpoint, &UTXOEntry{
			Amount:     out.Value,
			PkScript:   bytes.Clone(out.PkScript),
			Height:     height,
			IsCoinbase: isCoinbase,
		})
	}
}

// SpendTxInputs removes all inputs of a transaction from the UTXO set.
func (u *UTXOSet) SpendTxInputs(tx *wire.MsgTx) {
	if IsCoinbaseTx(tx) {
		return // Coinbase has no real inputs to spend
	}
	for _, in := range tx.TxIn {
		u.SpendUTXO(in.PreviousOutPoint)
	}
}

// Ensure UTXOSet implements UpdatableUTXOView
var _ UpdatableUTXOView = (*UTXOSet)(nil)

// Script type constants for compression
const (
	scriptTypeP2PKH   = 0x00
	scriptTypeP2SH    = 0x01
	scriptTypeP2WPKH  = 0x02
	scriptTypeP2WSH   = 0x03
	scriptTypeP2TR    = 0x04
	scriptTypeUnknown = 0x05
)

// IsP2PKH checks if script is Pay-to-Public-Key-Hash.
// Format: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
func IsP2PKH(script []byte) bool {
	return len(script) == 25 &&
		script[0] == 0x76 && // OP_DUP
		script[1] == 0xa9 && // OP_HASH160
		script[2] == 0x14 && // Push 20 bytes
		script[23] == 0x88 && // OP_EQUALVERIFY
		script[24] == 0xac // OP_CHECKSIG
}

// IsP2SH checks if script is Pay-to-Script-Hash.
// Format: OP_HASH160 <20 bytes> OP_EQUAL
func IsP2SH(script []byte) bool {
	return len(script) == 23 &&
		script[0] == 0xa9 && // OP_HASH160
		script[1] == 0x14 && // Push 20 bytes
		script[22] == 0x87 // OP_EQUAL
}

// IsP2WPKH checks if script is Pay-to-Witness-Public-Key-Hash.
// Format: OP_0 <20 bytes>
func IsP2WPKH(script []byte) bool {
	return len(script) == 22 &&
		script[0] == 0x00 && // OP_0
		script[1] == 0x14 // Push 20 bytes
}

// IsP2WSH checks if script is Pay-to-Witness-Script-Hash.
// Format: OP_0 <32 bytes>
func IsP2WSH(script []byte) bool {
	return len(script) == 34 &&
		script[0] == 0x00 && // OP_0
		script[1] == 0x20 // Push 32 bytes
}

// IsP2TR checks if script is Pay-to-Taproot.
// Format: OP_1 <32 bytes>
func IsP2TR(script []byte) bool {
	return len(script) == 34 &&
		script[0] == 0x51 && // OP_1
		script[1] == 0x20 // Push 32 bytes
}

// IsPayToAnchor checks if script is Pay-to-Anchor.
// Format: OP_1 OP_PUSHBYTES_2 0x4e 0x73 (exactly 4 bytes)
// P2A is a standardized anyone-can-spend output for anchor outputs in L2 protocols.
func IsPayToAnchor(script []byte) bool {
	return len(script) == 4 &&
		script[0] == 0x51 && // OP_1
		script[1] == 0x02 && // Push 2 bytes
		script[2] == 0x4e &&
		script[3] == 0x73
}

// CompressScript compresses common script patterns for storage.
// - P2PKH (25 bytes) -> 21 bytes (type 0x00 + 20 byte hash)
// - P2SH (23 bytes) -> 21 bytes (type 0x01 + 20 byte hash)
// - P2WPKH (22 bytes) -> 21 bytes (type 0x02 + 20 byte hash)
// - P2WSH (34 bytes) -> 33 bytes (type 0x03 + 32 byte hash)
// - P2TR (34 bytes) -> 33 bytes (type 0x04 + 32 byte key)
// - Other scripts: type 0x05 + raw script
func CompressScript(script []byte) []byte {
	switch {
	case IsP2PKH(script):
		// Extract the 20-byte hash (bytes 3-22 inclusive)
		result := make([]byte, 21)
		result[0] = scriptTypeP2PKH
		copy(result[1:], script[3:23])
		return result

	case IsP2SH(script):
		// Extract the 20-byte hash (bytes 2-21 inclusive)
		result := make([]byte, 21)
		result[0] = scriptTypeP2SH
		copy(result[1:], script[2:22])
		return result

	case IsP2WPKH(script):
		// Extract the 20-byte hash (bytes 2-21 inclusive)
		result := make([]byte, 21)
		result[0] = scriptTypeP2WPKH
		copy(result[1:], script[2:22])
		return result

	case IsP2WSH(script):
		// Extract the 32-byte hash (bytes 2-33 inclusive)
		result := make([]byte, 33)
		result[0] = scriptTypeP2WSH
		copy(result[1:], script[2:34])
		return result

	case IsP2TR(script):
		// Extract the 32-byte key (bytes 2-33 inclusive)
		result := make([]byte, 33)
		result[0] = scriptTypeP2TR
		copy(result[1:], script[2:34])
		return result

	default:
		// Unknown script type - store as-is with type prefix
		result := make([]byte, 1+len(script))
		result[0] = scriptTypeUnknown
		copy(result[1:], script)
		return result
	}
}

// DecompressScript reverses script compression.
func DecompressScript(compressed []byte) []byte {
	if len(compressed) == 0 {
		return nil
	}

	scriptType := compressed[0]
	data := compressed[1:]

	switch scriptType {
	case scriptTypeP2PKH:
		if len(data) != 20 {
			return compressed // Invalid, return as-is
		}
		// Reconstruct: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
		script := make([]byte, 25)
		script[0] = 0x76 // OP_DUP
		script[1] = 0xa9 // OP_HASH160
		script[2] = 0x14 // Push 20 bytes
		copy(script[3:23], data)
		script[23] = 0x88 // OP_EQUALVERIFY
		script[24] = 0xac // OP_CHECKSIG
		return script

	case scriptTypeP2SH:
		if len(data) != 20 {
			return compressed
		}
		// Reconstruct: OP_HASH160 <20 bytes> OP_EQUAL
		script := make([]byte, 23)
		script[0] = 0xa9 // OP_HASH160
		script[1] = 0x14 // Push 20 bytes
		copy(script[2:22], data)
		script[22] = 0x87 // OP_EQUAL
		return script

	case scriptTypeP2WPKH:
		if len(data) != 20 {
			return compressed
		}
		// Reconstruct: OP_0 <20 bytes>
		script := make([]byte, 22)
		script[0] = 0x00 // OP_0
		script[1] = 0x14 // Push 20 bytes
		copy(script[2:22], data)
		return script

	case scriptTypeP2WSH:
		if len(data) != 32 {
			return compressed
		}
		// Reconstruct: OP_0 <32 bytes>
		script := make([]byte, 34)
		script[0] = 0x00 // OP_0
		script[1] = 0x20 // Push 32 bytes
		copy(script[2:34], data)
		return script

	case scriptTypeP2TR:
		if len(data) != 32 {
			return compressed
		}
		// Reconstruct: OP_1 <32 bytes>
		script := make([]byte, 34)
		script[0] = 0x51 // OP_1
		script[1] = 0x20 // Push 32 bytes
		copy(script[2:34], data)
		return script

	case scriptTypeUnknown:
		return data

	default:
		return compressed // Unknown type, return as-is
	}
}

// writeVaruint writes a variable-length unsigned integer without the 32MB limit.
// This is used for amounts and heights which can exceed the message size limits.
func writeVaruint(w *bytes.Buffer, val uint64) {
	switch {
	case val < 0xFD:
		w.WriteByte(byte(val))
	case val <= 0xFFFF:
		w.WriteByte(0xFD)
		var buf [2]byte
		buf[0] = byte(val)
		buf[1] = byte(val >> 8)
		w.Write(buf[:])
	case val <= 0xFFFFFFFF:
		w.WriteByte(0xFE)
		var buf [4]byte
		buf[0] = byte(val)
		buf[1] = byte(val >> 8)
		buf[2] = byte(val >> 16)
		buf[3] = byte(val >> 24)
		w.Write(buf[:])
	default:
		w.WriteByte(0xFF)
		var buf [8]byte
		buf[0] = byte(val)
		buf[1] = byte(val >> 8)
		buf[2] = byte(val >> 16)
		buf[3] = byte(val >> 24)
		buf[4] = byte(val >> 32)
		buf[5] = byte(val >> 40)
		buf[6] = byte(val >> 48)
		buf[7] = byte(val >> 56)
		w.Write(buf[:])
	}
}

// readVaruint reads a variable-length unsigned integer without the 32MB limit.
// Uses stack-allocated arrays to avoid heap allocations in the hot path.
func readVaruint(r *bytes.Reader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}

	var val uint64
	switch first {
	case 0xFD:
		var buf [2]byte
		if _, err := r.Read(buf[:]); err != nil {
			return 0, err
		}
		val = uint64(buf[0]) | uint64(buf[1])<<8
	case 0xFE:
		var buf [4]byte
		if _, err := r.Read(buf[:]); err != nil {
			return 0, err
		}
		val = uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24
	case 0xFF:
		var buf [8]byte
		if _, err := r.Read(buf[:]); err != nil {
			return 0, err
		}
		val = uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
			uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56
	default:
		val = uint64(first)
	}
	return val, nil
}

// SerializeUTXOEntry serializes a UTXO entry for storage.
// Format:
//   - Height and coinbase flag: varint (height << 1 | coinbase_flag)
//   - Amount: varint
//   - Script type and script: compressed script with varint length
func SerializeUTXOEntry(entry *UTXOEntry) []byte {
	var buf bytes.Buffer

	// Height and coinbase combined: height << 1 | coinbase
	heightCode := uint64(entry.Height) << 1
	if entry.IsCoinbase {
		heightCode |= 1
	}
	writeVaruint(&buf, heightCode)

	// Amount as varint (can exceed 32MB)
	writeVaruint(&buf, uint64(entry.Amount))

	// Script (compressed) with length prefix
	compressedScript := CompressScript(entry.PkScript)
	writeVaruint(&buf, uint64(len(compressedScript)))
	buf.Write(compressedScript)

	return buf.Bytes()
}

// DeserializeUTXOEntry deserializes a UTXO entry from storage.
func DeserializeUTXOEntry(data []byte) (*UTXOEntry, error) {
	r := bytes.NewReader(data)

	// Read height and coinbase flag
	heightCode, err := readVaruint(r)
	if err != nil {
		return nil, err
	}
	height := int32(heightCode >> 1)
	isCoinbase := (heightCode & 1) == 1

	// Read amount
	amount, err := readVaruint(r)
	if err != nil {
		return nil, err
	}

	// Read compressed script length and data
	scriptLen, err := readVaruint(r)
	if err != nil {
		return nil, err
	}
	if scriptLen > 10000 {
		return nil, errors.New("script too large")
	}
	compressedScript := make([]byte, scriptLen)
	if _, err := r.Read(compressedScript); err != nil {
		return nil, err
	}
	pkScript := DecompressScript(compressedScript)

	return &UTXOEntry{
		Amount:     int64(amount),
		PkScript:   pkScript,
		Height:     height,
		IsCoinbase: isCoinbase,
	}, nil
}

// SpentOutput records a UTXO that was spent, for undo purposes.
type SpentOutput struct {
	OutPoint wire.OutPoint
	Entry    UTXOEntry
}

// UndoBlock contains the data needed to undo a connected block.
type UndoBlock struct {
	SpentOutputs []SpentOutput // UTXOs consumed by this block
}

// Serialize serializes the undo block for storage.
func (ub *UndoBlock) Serialize() []byte {
	var buf bytes.Buffer

	// Write number of spent outputs
	wire.WriteCompactSize(&buf, uint64(len(ub.SpentOutputs)))

	// Write each spent output
	for _, so := range ub.SpentOutputs {
		// Write the outpoint
		so.OutPoint.Serialize(&buf)

		// Write the UTXO entry
		entryData := SerializeUTXOEntry(&so.Entry)
		wire.WriteVarBytes(&buf, entryData)
	}

	return buf.Bytes()
}

// DeserializeUndoBlock deserializes undo data.
func DeserializeUndoBlock(data []byte) (*UndoBlock, error) {
	r := bytes.NewReader(data)

	// Read number of spent outputs
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return nil, err
	}

	ub := &UndoBlock{
		SpentOutputs: make([]SpentOutput, 0, count),
	}

	// Read each spent output
	for i := uint64(0); i < count; i++ {
		var so SpentOutput

		// Read outpoint
		if err := so.OutPoint.Deserialize(r); err != nil {
			return nil, err
		}

		// Read UTXO entry
		entryData, err := wire.ReadVarBytes(r, 100000) // reasonable max
		if err != nil {
			return nil, err
		}
		entry, err := DeserializeUTXOEntry(entryData)
		if err != nil {
			return nil, err
		}
		so.Entry = *entry

		ub.SpentOutputs = append(ub.SpentOutputs, so)
	}

	return ub, nil
}

// ConnectBlockUTXOs connects a block's transactions to the UTXO set.
// Returns undo data for potential future disconnection.
// This is a helper method that properly tracks spent UTXOs for undo purposes.
func (u *UTXOSet) ConnectBlockUTXOs(block *wire.MsgBlock, height int32) (*UndoBlock, error) {
	undo := &UndoBlock{
		SpentOutputs: make([]SpentOutput, 0),
	}

	for i, tx := range block.Transactions {
		// For non-coinbase transactions, save spent UTXOs and then spend them
		if i > 0 {
			for _, in := range tx.TxIn {
				// Get the UTXO being spent
				entry := u.GetUTXO(in.PreviousOutPoint)
				if entry == nil {
					return nil, ErrUTXONotFound
				}

				// Record for undo.
				// W93 fix #6 (PkScript aliasing): *entry shallow-copies the
				// struct but the PkScript slice still aliases the UTXOSet's
				// cache entry. After SpendUTXO removes that entry from the
				// cache, Go's GC keeps the backing array alive as long as
				// the SpentOutput retains the slice — so this is safe today.
				// But the clone makes the contract explicit and matches the
				// W82/W92 audit pattern (slice aliasing across logical
				// ownership boundaries).
				recorded := *entry
				recorded.PkScript = bytes.Clone(recorded.PkScript)
				undo.SpentOutputs = append(undo.SpentOutputs, SpentOutput{
					OutPoint: in.PreviousOutPoint,
					Entry:    recorded,
				})

				// Spend it
				u.SpendUTXO(in.PreviousOutPoint)
			}
		}

		// Add outputs to UTXO set
		u.AddTxOutputs(tx, height)
	}

	return undo, nil
}

// DisconnectBlockUTXOs reverses the effects of ConnectBlockUTXOs.
// It removes outputs created by the block and restores spent UTXOs from undo data.
func (u *UTXOSet) DisconnectBlockUTXOs(block *wire.MsgBlock, undo *UndoBlock) error {
	// Index the undo records by outpoint. SpentOutput carries its own
	// OutPoint, so the flat list is self-describing and each tx can pick out
	// its own inputs inside the reverse walk below.
	spent := make(map[wire.OutPoint]*SpentOutput, len(undo.SpentOutputs))
	for i := range undo.SpentOutputs {
		spent[undo.SpentOutputs[i].OutPoint] = &undo.SpentOutputs[i]
	}
	restored := 0

	// Process transactions in reverse order, and for EACH tx remove its
	// created outputs and THEN restore its spent inputs before moving on —
	// Core validation.cpp:2205-2241.
	//
	// The per-tx interleave is load-bearing. This function previously removed
	// every tx's outputs in one pass and then restored every tx's inputs in a
	// second. That breaks on an intra-block chain (txA creates P, a later txB
	// in the same block spends it, so P is absent once the block is
	// connected): txA's removal of P finds nothing, and the later input pass
	// re-adds P and leaves it behind. The phantom coin then fails BIP-30 when
	// the winning branch re-creates it, refusing the reorg. rustoshi shipped
	// exactly this two-pass shape and sat wedged on mainnet at 963853 for ~19h
	// refusing the block the rest of the network had already accepted
	// (rustoshi d086a76).
	//
	// blockbrew's PRODUCTION disconnect is ChainManager.DisconnectBlock
	// (chainmanager.go:2005), which has always interleaved correctly. This
	// function has no production caller and is exercised only by tests — but a
	// second, wrong implementation of consensus-critical logic is precisely the
	// trap that produced four of this week's defects, so it is corrected rather
	// than left as a loaded gun for whoever wires it up next.
	for i := len(block.Transactions) - 1; i >= 0; i-- {
		tx := block.Transactions[i]
		txHash := tx.TxHash()

		// Remove outputs created by this transaction.
		for idx := range tx.TxOut {
			outpoint := wire.OutPoint{Hash: txHash, Index: uint32(idx)}
			u.SpendUTXO(outpoint)
		}

		// Coinbase (i == 0) has no inputs to restore.
		if i == 0 {
			continue
		}

		// Restore this tx's inputs in REVERSE order (Core:2233-2239).
		for j := len(tx.TxIn) - 1; j >= 0; j-- {
			outpoint := tx.TxIn[j].PreviousOutPoint
			so, ok := spent[outpoint]
			if !ok {
				return fmt.Errorf("disconnect: no undo record for %s:%d",
					outpoint.Hash.String()[:16], outpoint.Index)
			}
			// W93 fix #6 (PkScript aliasing on UTXO restore — W82/W92
			// pattern): `entry := so.Entry` shallow-copies the struct but its
			// PkScript slice header still points at the undo record's backing
			// array. Cloning ensures the restored cache entry holds its own
			// buffer so later mutations of `undo` cannot corrupt the UTXOSet.
			// Mirrors the clone discipline used by AddTxOutputs.
			entry := so.Entry // shallow copy
			entry.PkScript = bytes.Clone(entry.PkScript)
			u.AddUTXO(outpoint, &entry)
			restored++
		}
	}

	// Every undo record belongs to some input of some non-coinbase tx; if the
	// walk did not consume them all, block and undo disagree.
	if restored != len(undo.SpentOutputs) {
		return fmt.Errorf("disconnect: restored %d of %d undo records "+
			"(block and undo data disagree)", restored, len(undo.SpentOutputs))
	}

	return nil
}

// DisconnectResult mirrors Bitcoin Core validation.h:451-455 (DisconnectResult).
// The two-state success result is what surfaces "the disconnect rolled back the
// UTXO set, but at least one output was missing or its identity didn't match"
// up to the caller. ActivateBestChain treats DISCONNECT_UNCLEAN as success —
// the chainstate write still happens — but logs the inconsistency so the issue
// can be tracked.
type DisconnectResult int

const (
	// DisconnectOK means "All good." — no missing UTXOs, no identity
	// mismatches, all undo entries applied cleanly.
	DisconnectOK DisconnectResult = iota
	// DisconnectUnclean means "Rolled back, but UTXO set was inconsistent
	// with the block." This can happen for blocks that contain transactions
	// later overwritten by a duplicate (BIP-30 collisions h=91722/91812):
	// during reverse iteration we find an output already missing, or a coin
	// that records different height/coinbase metadata than the tx itself.
	// Mirrors Core's DISCONNECT_UNCLEAN return code (validation.h:453).
	DisconnectUnclean
)

// AccessByTxid mirrors Bitcoin Core coins.cpp::AccessByTxid. It scans the
// UTXO set looking for ANY unspent output of the given transaction id. Used
// by ApplyTxInUndo to recover missing per-coin metadata (height + coinbase
// flag) from a sibling output of the same transaction. Older undo records
// only included this metadata for the LAST spend of a tx's outputs; if we
// restore an earlier-spent output, we need to fish the metadata back out
// of whatever sibling output is still unspent.
//
// Returns nil if no unspent sibling exists. The scan caps at
// MAX_OUTPUTS_PER_BLOCK (≈80k) so a malformed undo record cannot pin us in
// an unbounded loop.
//
// NOTE: Core's AccessByTxid takes a CCoinsViewCache and scans by index
// inside the coins-per-tx structure. Our UTXOSet stores per-output entries
// keyed by (txid, vout), so we scan by walking vout = 0,1,2,... and probe
// until we miss MAX_PROBE_GAP consecutive outputs. Pragmatic but adequate
// for legacy undo metadata recovery; the path is only hit on undo records
// from Bitcoin Core <0.9 that round-tripped through us.
func (u *UTXOSet) AccessByTxid(txid wire.Hash256) *UTXOEntry {
	const maxProbe = 1 << 16 // hard cap (≈consensus MAX_TX_OUT count)
	const maxProbeGap = 256  // give up after this many consecutive misses
	gap := 0
	for vout := uint32(0); vout < maxProbe; vout++ {
		outpoint := wire.OutPoint{Hash: txid, Index: vout}
		if e := u.GetUTXO(outpoint); e != nil {
			return e
		}
		gap++
		if gap >= maxProbeGap {
			return nil
		}
	}
	return nil
}

// ApplyTxInUndo restores a single spent input back into the UTXO set during
// block disconnect. Mirrors Bitcoin Core validation.cpp:2149-2175.
//
// Gate A — HaveCoin overwrite detection: if the outpoint we're about to
// restore is somehow already present in the UTXO set, the result is
// "unclean" — we still proceed (Core's possible_overwrite=true path), but
// we signal DisconnectUnclean to the caller. Real chains never trigger
// this except in BIP-30 collision blocks.
//
// Gate B — Missing-metadata sibling recovery: if undo.Height == 0 (legacy
// undo blob from pre-0.9 Core, or any undo that elided per-coin metadata),
// scan the UTXO set for any sibling output of the same transaction and
// borrow its Height + IsCoinbase. If no sibling exists, the restore is
// impossible — return false (Core's DISCONNECT_FAILED).
//
// Gate C — pkScript aliasing: the undo blob we got from the database is a
// fresh allocation, but the caller is free to keep using it after we
// return. We bytes.Clone the script before installing into the UTXO cache
// (W82 pattern: blockbrew's FindAndDelete slice-aliasing bug taught us
// that holding a slice in the UTXO map while a separate code path mutates
// the backing array silently corrupts state).
//
// Returns (clean, ok). clean=true iff fully clean; ok=false iff the undo
// record was unrecoverable (sibling-recovery failed). A return of
// (false, true) means "restored, but unclean — caller should propagate
// DisconnectUnclean".
func (u *UTXOSet) ApplyTxInUndo(undo *UTXOEntry, outpoint wire.OutPoint) (clean bool, ok bool) {
	clean = true

	// Gate A: overwrite check. HaveCoin on Core; HasUTXO here.
	if u.HasUTXO(outpoint) {
		clean = false // overwriting an unspent UTXO — unclean but not fatal
	}

	// Gate B: missing-metadata sibling recovery for legacy undo records.
	if undo.Height == 0 {
		alt := u.AccessByTxid(outpoint.Hash)
		if alt == nil {
			// No sibling unspent output exists — we have no way to
			// reconstruct the per-coin metadata. Mirrors Core's
			// DISCONNECT_FAILED return at validation.cpp:2164.
			return false, false
		}
		undo.Height = alt.Height
		undo.IsCoinbase = alt.IsCoinbase
	}

	// Gate C: defensive clone of the script bytes before they enter the
	// UTXO cache. The undo blob's PkScript may alias storage owned by the
	// caller (e.g. a long-lived BlockUndo cached for retry); the UTXO map
	// outlives those callers. W82 pattern.
	entry := &UTXOEntry{
		Amount:     undo.Amount,
		PkScript:   bytes.Clone(undo.PkScript),
		Height:     undo.Height,
		IsCoinbase: undo.IsCoinbase,
	}
	u.AddUTXO(outpoint, entry)

	return clean, true
}

// SpendUTXOWithCoin marks a UTXO as spent and returns the coin that was
// removed, or nil if the outpoint was not present. Used by DisconnectBlock
// to verify output identity (height + coinbase + value + script) against
// the block being disconnected — Core's validation.cpp:2217-2218.
//
// Returns the pre-spend entry. If the outpoint did not exist the return is
// (nil, false). Concurrent callers see the same lock semantics as SpendUTXO.
func (u *UTXOSet) SpendUTXOWithCoin(outpoint wire.OutPoint) (*UTXOEntry, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.journalPre(outpoint)

	// Snapshot the existing entry (if any) before mutating cache state.
	// Use a deep-ish copy of the script so the returned entry doesn't alias
	// the now-deleted cache slot.
	var snapshot *UTXOEntry
	if existing, ok := u.cache[outpoint]; ok {
		snapshot = &UTXOEntry{
			Amount:     existing.Amount,
			PkScript:   bytes.Clone(existing.PkScript),
			Height:     existing.Height,
			IsCoinbase: existing.IsCoinbase,
		}
		u.cacheBytes -= estimateEntrySize(existing)
		delete(u.cache, outpoint)
		delete(u.dirty, outpoint)
		if u.fresh[outpoint] {
			delete(u.fresh, outpoint)
			u.freshHits++
			return snapshot, true
		}
		u.deleted[outpoint] = true
		return snapshot, true
	}

	// Fall back to a DB lookup — if the entry was already flushed we want
	// its metadata for the identity check before tombstoning it. Skip the
	// DB probe in tests that pass a nil ChainDB.
	if u.db != nil {
		if u.deleted[outpoint] {
			return nil, false
		}
		key := storage.MakeUTXOKey(outpoint)
		data, err := u.db.DB().Get(key)
		if err == nil && data != nil {
			if entry, derr := DeserializeUTXOEntry(data); derr == nil {
				snapshot = &UTXOEntry{
					Amount:     entry.Amount,
					PkScript:   bytes.Clone(entry.PkScript),
					Height:     entry.Height,
					IsCoinbase: entry.IsCoinbase,
				}
				u.deleted[outpoint] = true
				return snapshot, true
			}
		}
	}

	return nil, false
}
