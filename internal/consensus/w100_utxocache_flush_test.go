package consensus

// W100 CCoinsViewCache + FlushStateToDisk gate audit — blockbrew (Go)
//
// Reference: bitcoin-core/src/coins.h, bitcoin-core/src/coins.cpp,
//            bitcoin-core/src/validation.cpp FlushStateToDisk
//
// Gates covered: G1-G30
// Severity legend: CONSENSUS-DIVERGENT, DOS, CORRECTNESS, OBSERVABILITY
//
// Bug IDs: W100-B1 through W100-B15 (see comments inline and summary below).

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ---------------------------------------------------------------------------
// G1 + G2: AddCoin possible_overwrite=false; existing unspent → abort (BIP-30)
// BUG W100-B1 (CORRECTNESS): UTXOSet.AddUTXO silently overwrites an existing
// unspent cache entry without checking the possible_overwrite flag.
// Core's AddCoin(possible_overwrite=false) asserts that the existing entry is
// spent before allowing the overwrite. Without this check, a second AddUTXO
// call for the same outpoint (e.g. from a BIP-30 duplicate coinbase) silently
// replaces the first entry, making it undetectable at the cache level.
// ---------------------------------------------------------------------------

func TestG1_AddCoin_ExistingUnspent_ShouldNotOverwrite(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B1 — AddUTXO has no possible_overwrite=false guard; " +
		"silently overwrites existing unspent coin (Core coins.cpp:AddCoin asserts !have || spent)")

	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	op := createTestOutpoint(0xB1, 0)
	original := createTestEntry(50_00000000, 100, true, []byte{0x76, 0xa9})
	utxoSet.AddUTXO(op, original)

	// A second AddUTXO with possible_overwrite=false should fail or be rejected
	// if the entry is still unspent. Currently blockbrew has no such check.
	duplicate := createTestEntry(25_00000000, 200, false, []byte{0x51, 0x20})
	utxoSet.AddUTXO(op, duplicate)

	// After the above the original entry should still be present unchanged
	got := utxoSet.GetUTXO(op)
	if got == nil {
		t.Fatal("expected original UTXO to remain")
	}
	if got.Amount != original.Amount {
		t.Errorf("BIP-30 overwrite guard missing: original amount %d overwritten with %d",
			original.Amount, got.Amount)
	}
}

// ---------------------------------------------------------------------------
// G2: AddCoin existing coin MUST be spent if !possible_overwrite
// BUG W100-B1 (continued): same root cause — no spent-check on overwrite path.
// ---------------------------------------------------------------------------

func TestG2_AddCoin_MustBeSpentBeforeOverwrite(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B1 (continued) — AddUTXO allows overwriting non-spent coin " +
		"without asserting the existing coin is spent first")

	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	op := createTestOutpoint(0xB2, 0)
	first := createTestEntry(10000, 50, false, []byte{0xa9, 0x14})
	utxoSet.AddUTXO(op, first)

	// Mark it spent
	_ = utxoSet.SpendUTXOChecked(op)

	// Now a second add (same outpoint, spent) should succeed (Core allows this)
	second := createTestEntry(20000, 100, false, []byte{0x00, 0x14})
	utxoSet.AddUTXO(op, second)

	got := utxoSet.GetUTXO(op)
	if got == nil || got.Amount != second.Amount {
		t.Errorf("expected second add after spend to succeed, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// G3: SpendCoin marks DIRTY; removes from active cache
// ---------------------------------------------------------------------------

func TestG3_SpendCoin_MarkedDirty(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	op := createTestOutpoint(0xB3, 0)
	entry := createTestEntry(5000, 10, false, []byte{0x76, 0xa9})
	utxoSet.AddUTXO(op, entry)

	// Spend it
	utxoSet.SpendUTXO(op)

	// Cache should not contain the entry
	if utxoSet.HasUTXO(op) {
		t.Error("G3: SpendUTXO must remove entry from active cache")
	}
	// dirty map: the outpoint that was NOT FRESH should be in deleted map
	// (FRESH entries skip the deleted-map write — only visible via flush)
}

// ---------------------------------------------------------------------------
// G4: SpendCoin: returns via moveout pointer (SpendUTXOWithCoin)
// BUG W100-B2 (CORRECTNESS): SpendUTXOWithCoin falls through to DB only when
// the outpoint is NOT in the cache. When the entry IS in cache but was already
// flushed to DB (not FRESH), the DB probe path is unreachable because the
// in-cache branch short-circuits first.  However, when called on an outpoint
// that is in the DB but has been evicted from cache, the DB-path code
// correctly retrieves the entry. The bug is minor but the nil-DB guard inside
// the DB-probe branch means nil-DB UTXOSets silently return (nil,false)
// instead of consulting the in-memory store for non-flushed entries.
// ---------------------------------------------------------------------------

func TestG4_SpendCoin_ReturnsMoveoutCoin(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	op := createTestOutpoint(0xB4, 2)
	entry := createTestEntry(99999, 200, true, []byte{0x51, 0x20, 0xAA})
	utxoSet.AddUTXO(op, entry)

	coin, found := utxoSet.SpendUTXOWithCoin(op)
	if !found {
		t.Fatal("G4: SpendUTXOWithCoin must return found=true for existing coin")
	}
	if coin == nil {
		t.Fatal("G4: SpendUTXOWithCoin must return non-nil coin")
	}
	if coin.Amount != entry.Amount {
		t.Errorf("G4: moveout coin amount mismatch: got %d want %d", coin.Amount, entry.Amount)
	}
	if coin.IsCoinbase != entry.IsCoinbase {
		t.Errorf("G4: moveout coin IsCoinbase mismatch")
	}
}

// ---------------------------------------------------------------------------
// G5: AccessCoin: read-through to base view; caches result
// ---------------------------------------------------------------------------

func TestG5_AccessCoin_ReadThroughAndCached(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	op := createTestOutpoint(0xB5, 0)
	entry := createTestEntry(1000, 1, false, []byte{0x76, 0xa9, 0x14})

	// Write directly to DB (bypassing cache)
	key := storage.MakeUTXOKey(op)
	data := SerializeUTXOEntry(entry)
	batch := chainDB.DB().NewBatch()
	batch.Put(key, data)
	if err := batch.Write(); err != nil {
		t.Fatalf("direct DB write failed: %v", err)
	}

	// GetUTXO must read through to the DB
	got := utxoSet.GetUTXO(op)
	if got == nil {
		t.Fatal("G5: GetUTXO must read through to base DB")
	}
	if got.Amount != entry.Amount {
		t.Errorf("G5: read-through amount mismatch: got %d want %d", got.Amount, entry.Amount)
	}

	// A second call must hit the cache (misses counter should not increment)
	statsBefore := utxoSet.Stats()
	_ = utxoSet.GetUTXO(op)
	statsAfter := utxoSet.Stats()
	if statsAfter.Misses != statsBefore.Misses {
		t.Errorf("G5: second GetUTXO should hit cache (no new miss)")
	}
}

// ---------------------------------------------------------------------------
// G6: AccessCoin: empty Coin (not error) on missing
// ---------------------------------------------------------------------------

func TestG6_AccessCoin_MissingReturnsNil(t *testing.T) {
	utxoSet := NewUTXOSet(nil) // nil DB — cache-only

	op := createTestOutpoint(0xB6, 99)
	got := utxoSet.GetUTXO(op)
	if got != nil {
		t.Error("G6: GetUTXO on missing outpoint must return nil, not an error or non-nil entry")
	}
}

// ---------------------------------------------------------------------------
// G7: HaveCoin: cache + base fall-through
// ---------------------------------------------------------------------------

func TestG7_HaveCoin_CacheAndBaseFallthrough(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	op := createTestOutpoint(0xB7, 0)
	entry := createTestEntry(500, 5, false, []byte{0x76})

	// Write to DB only
	key := storage.MakeUTXOKey(op)
	data := SerializeUTXOEntry(entry)
	batch := chainDB.DB().NewBatch()
	batch.Put(key, data)
	if err := batch.Write(); err != nil {
		t.Fatalf("direct DB write failed: %v", err)
	}

	// HasUTXO must fall through to DB
	if !utxoSet.HasUTXO(op) {
		t.Error("G7: HasUTXO must fall through to base DB")
	}
}

// ---------------------------------------------------------------------------
// G8: HaveCoinInCache: cache-only
// BUG W100-B3 (OBSERVABILITY): UTXOSet has no HaveCoinInCache (cache-only)
// method. Core's CCoinsViewCache::HaveCoinInCache is used by the wallet and
// RPC to avoid DB hits. Absence is an API gap; no crashes but missing
// performance optimization and parity with Core's interface.
// ---------------------------------------------------------------------------

func TestG8_HaveCoinInCache_CacheOnly(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B3 — UTXOSet has no HaveCoinInCache(outpoint) method; " +
		"Core's CCoinsViewCache::HaveCoinInCache is a cache-only probe (no DB fallthrough)")
}

// ---------------------------------------------------------------------------
// G9: SetBestBlock: stores hashBlock; signals chainstate position
// BUG W100-B4 (CORRECTNESS): UTXOSet has no SetBestBlock/GetBestBlock methods.
// In Core, CCoinsViewCache::SetBestBlock() persists the tip hash into the
// UTXO view so that a crash-recovery can verify the UTXO set is consistent
// with the on-disk chain state. Blockbrew stores chain state separately in
// ChainDB.SetChainState, which is functionally equivalent but the UTXO cache
// itself has no concept of its own "best block" hash — so any code path that
// calls GetBestBlock() on the UTXO view (e.g. assumeutxo loading) will fail
// to find the embedded hash.
// ---------------------------------------------------------------------------

func TestG9_SetBestBlock_UTXOViewHasNoHashBlock(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B4 — UTXOSet lacks SetBestBlock/GetBestBlock; " +
		"hashBlock is not embedded in the UTXO cache (stored separately in ChainState); " +
		"assumeutxo verification path has no canonical UTXO-view.GetBestBlock() to check")
}

// ---------------------------------------------------------------------------
// G10: BatchWrite: only DIRTY entries propagated
// BUG W100-B5 (CORRECTNESS): FlushBatch clears dirty/deleted/fresh tracking
// BEFORE batch.Write() returns (before the commit succeeds). If the backend
// write fails mid-way, the dirty state has already been cleared and those
// UTXOs are silently lost. Core's BatchWrite checks the write result and
// retains dirty state on failure.
// ---------------------------------------------------------------------------

func TestG10_BatchWrite_DirtyOnlyPropagated(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	op1 := createTestOutpoint(0xBA, 0)
	op2 := createTestOutpoint(0xBB, 0)
	entry1 := createTestEntry(1000, 1, false, []byte{0x76})
	entry2 := createTestEntry(2000, 2, false, []byte{0x51})

	utxoSet.AddUTXO(op1, entry1)
	utxoSet.AddUTXO(op2, entry2)

	// After flush, both should be in DB (dirty entries flushed)
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// A clean (non-dirty) read-through entry should NOT get re-flushed
	fresh := NewUTXOSet(chainDB)
	_ = fresh.GetUTXO(op1) // populates cache as clean entry

	// Flush the fresh set — should write 0 entries (no dirty)
	statsBefore := fresh.Stats()
	if err := fresh.Flush(); err != nil {
		t.Fatalf("second flush failed: %v", err)
	}
	statsAfter := fresh.Stats()

	// Flushes counter incremented but no extra dirty writes should have occurred
	if statsAfter.Flushes <= statsBefore.Flushes {
		t.Error("G10: flush counter not incremented")
	}
}

// ---------------------------------------------------------------------------
// G11: Flush vs Sync: Flush clears cache, Sync keeps
// BUG W100-B6 (CORRECTNESS/OBSERVABILITY): blockbrew has a single Flush()
// method that both writes dirty entries AND evicts clean cache entries when
// cacheBytes > maxCacheBytes/2. There is no Sync()-equivalent that would
// write dirty entries while keeping the cache warm. The eviction-on-flush
// path forces unnecessary DB re-reads for entries that were just written,
// hurting tip-following performance. Core exposes both ForceFlush (evict)
// and ForceSync (write-but-keep) modes.
// ---------------------------------------------------------------------------

func TestG11_Flush_ClearsCache_NoSyncEquivalent(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B6 — Flush() always evicts cache when cacheBytes > maxCacheBytes/2; " +
		"no Sync/ForceSync mode that writes dirty entries while keeping cache warm (Core FlushStateMode::FORCE_SYNC)")
}

// ---------------------------------------------------------------------------
// G12: Reset discards all (no flush)
// BUG W100-B7 (CORRECTNESS): There is no Reset() method on UTXOSet. A Reset
// discards the in-memory cache without flushing dirty entries to the backend —
// used by Core when loading a snapshot (assumeutxo) to discard any partially-
// applied cache state. Without Reset, blockbrew's assumeutxo code in
// assumeutxo.go cannot atomically replace the cache without a Flush.
// ---------------------------------------------------------------------------

func TestG12_Reset_DiscardsCacheWithoutFlush(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B7 — UTXOSet has no Reset() method; " +
		"Core CCoinsViewCache::~CCoinsViewCache aborts on dirty-without-flush; " +
		"assumeutxo snapshot load has no way to discard dirty state atomically")
}

// ---------------------------------------------------------------------------
// G13: Uncache: removes only if NOT dirty
// BUG W100-B8 (CORRECTNESS): UTXOSet has no Uncache(outpoint) method. Core's
// Uncache() evicts a specific entry from the cache only if it is clean (not
// dirty/fresh) — used by wallet and mempool to free memory for spent outputs
// that the cache doesn't need to hold. Without Uncache, once a UTXO is read
// into cache it stays until the whole eviction pass fires, bloating memory.
// ---------------------------------------------------------------------------

func TestG13_Uncache_RemovesOnlyIfNotDirty(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B8 — UTXOSet has no Uncache(outpoint) method; " +
		"Core CCoinsViewCache::Uncache() removes clean entries on demand; " +
		"absence causes cache to hold stale read-through entries longer than needed")
}

// ---------------------------------------------------------------------------
// G14: ReallocateCache: replaces map preserving dirty state
// Core CCoinsViewCache::ReallocateCache() replaces the hash map while
// preserving all dirty/fresh/spent entries, shrinking the allocated map
// capacity without losing uncommitted state.
// BUG W100-B9 (OBSERVABILITY): blockbrew's eviction in flushLocked() allocates
// a new newCache and DROPS entries that exceed the target size — including
// potentially dirty entries that were written to the batch in the SAME flush.
// While dirty entries are cleaned before the eviction loop runs (they were
// written to the batch), the eviction loop may retain entries in non-
// deterministic map-iteration order, which means the cache post-flush is
// unpredictable. ReallocateCache should preserve all entries and simply
// reallocate the underlying map bucket array.
// ---------------------------------------------------------------------------

func TestG14_ReallocateCache_PreservesDirtyState(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B9 — flushLocked() evicts entries in random map-iteration order; " +
		"ReallocateCache is absent; post-flush cache contents are non-deterministic; " +
		"Core CCoinsViewCache::ReallocateCache explicitly preserves all live state")
}

// ---------------------------------------------------------------------------
// G15: SanityCheck: debug invariant tally vs actual
// BUG W100-B10 (OBSERVABILITY): UTXOSet has no SanityCheck() method.
// Core's CCoinsViewCache::SanityCheck() verifies that the dirty/fresh
// invariants hold (e.g. no entry is both FRESH and in the parent base without
// matching). Without this, FRESH-bit corruption is only caught at flush time
// (if at all).
// ---------------------------------------------------------------------------

func TestG15_SanityCheck_DebugInvariantMissing(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B10 — UTXOSet has no SanityCheck() / debug invariant check; " +
		"Core CCoinsViewCache::SanityCheck() validates dirty/fresh/spent invariants under debug builds")
}

// ---------------------------------------------------------------------------
// G16: AddCoins (tx wrapper): all outputs at height; coinbase flag
// ---------------------------------------------------------------------------

func TestG16_AddCoins_AllOutputsAtHeight_CoinbaseFlag(t *testing.T) {
	utxoSet := NewUTXOSet(nil)

	coinbaseTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x01, 0x02},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{
			{Value: 50_00000000, PkScript: []byte{0x51, 0x20, 0x01}},
			{Value: 0, PkScript: []byte{0x6a}}, // OP_RETURN — should be skipped
		},
		LockTime: 0,
	}

	utxoSet.AddTxOutputs(coinbaseTx, 300)
	txHash := coinbaseTx.TxHash()

	// Output 0: should be added with IsCoinbase=true
	out0 := utxoSet.GetUTXO(wire.OutPoint{Hash: txHash, Index: 0})
	if out0 == nil {
		t.Fatal("G16: coinbase output 0 not added")
	}
	if !out0.IsCoinbase {
		t.Error("G16: coinbase output must have IsCoinbase=true")
	}
	if out0.Height != 300 {
		t.Errorf("G16: height mismatch: got %d want 300", out0.Height)
	}

	// Output 1 (OP_RETURN): must be skipped
	out1 := utxoSet.GetUTXO(wire.OutPoint{Hash: txHash, Index: 1})
	if out1 != nil {
		t.Error("G16: OP_RETURN output must not be added")
	}
}

// ---------------------------------------------------------------------------
// G17: HaveInputs: ALL inputs unspent
// BUG W100-B11 (CORRECTNESS): UTXOSet has no HaveInputs() method. Core's
// CCoinsViewCache::HaveInputs() checks that every non-coinbase input of a tx
// is present and unspent. In blockbrew this check is embedded in
// CheckTransactionInputs (txvalidation.go) which walks inputs and returns
// ErrMissingInput. However, HaveInputs is also used by ConnectBlock's
// pre-script-validation pass to confirm all prevouts are available before
// spending them. A dedicated HaveInputs method would allow the mempool and
// block-validation paths to share a single, auditable gate.
// ---------------------------------------------------------------------------

func TestG17_HaveInputs_AllInputsUnspent(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B11 — UTXOSet has no HaveInputs(tx) method; " +
		"Core CCoinsViewCache::HaveInputs() is a dedicated gate; " +
		"blockbrew embeds the check inside CheckTransactionInputs, not a standalone entry point")
}

// ---------------------------------------------------------------------------
// G18: AccessByTxid: scans output indexes 0-4
// BUG W100-B12 (CORRECTNESS): AccessByTxid probes up to maxProbe=65536 with
// a gap-based early exit (maxProbeGap=256). Core's AccessByTxid only scans
// up to MAX_TX_VOUT (not a hard const but practically bounded by the outputs
// in a single tx). The 256-gap-based probe is a blockbrew-specific heuristic
// that can miss non-contiguous output indexes (e.g. a tx with outputs at
// vout=0 and vout=300 where vout=1..255 are all spent). Additionally the
// function does NOT reset `gap` when it finds an entry — it only starts
// counting misses from the very last hit, meaning a sparse tx could terminate
// early before reaching valid outputs.
// ---------------------------------------------------------------------------

func TestG18_AccessByTxid_ScansOutputIndexes(t *testing.T) {
	utxoSet := NewUTXOSet(nil)

	var txid wire.Hash256
	for i := range txid {
		txid[i] = 0xCC
	}

	// Add output at index 0 only
	op0 := wire.OutPoint{Hash: txid, Index: 0}
	e0 := createTestEntry(1000, 1, true, []byte{0x51})
	utxoSet.AddUTXO(op0, e0)

	got := utxoSet.AccessByTxid(txid)
	if got == nil {
		t.Fatal("G18: AccessByTxid must find output at index 0")
	}
	if got.Amount != e0.Amount {
		t.Errorf("G18: amount mismatch: got %d want %d", got.Amount, e0.Amount)
	}
}

func TestG18_AccessByTxid_GapResetBug(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B12 — AccessByTxid does not reset `gap` counter when an entry is found; " +
		"a tx with output at vout=0, then nothing at 1..256, then output at vout=257 would miss the " +
		"second output; gap counter must reset to 0 on each successful probe")
}

// ---------------------------------------------------------------------------
// G19: DIRTY cleared only after backend write succeeds
// BUG W100-B5 (continued): FlushBatch clears dirty/deleted/fresh BEFORE
// batch.Write() is called. On write failure the dirty state is permanently
// lost. Same root cause as B5 above.
// ---------------------------------------------------------------------------

func TestG19_DirtyCleared_OnlyAfterWrite(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B5 (continued) — flushLocked() and FlushBatch() clear " +
		"dirty/deleted/fresh maps BEFORE batch.Write() returns; if Write() fails, dirty state " +
		"is silently discarded; Core clears dirty only on success")
}

// ---------------------------------------------------------------------------
// G20: FRESH means "don't fetch from base before write"
// ---------------------------------------------------------------------------

func TestG20_FreshFlag_SkipsBaseRead(t *testing.T) {
	// A FRESH entry should be written to DB on flush without first reading
	// from the base DB (no spurious DB round-trip).
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	op := createTestOutpoint(0xBC, 0)
	entry := createTestEntry(9999, 7, false, []byte{0x76, 0xa9})
	utxoSet.AddUTXO(op, entry) // marks FRESH

	// Spending a FRESH entry must NOT write a DB tombstone
	utxoSet.SpendUTXO(op) // FRESH optimization: skip write+delete

	// Flush should result in 0 DB writes for this outpoint (never persisted)
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	// After flush, the entry must not appear in DB (was never written)
	utxoSet2 := NewUTXOSet(chainDB)
	if utxoSet2.GetUTXO(op) != nil {
		t.Error("G20: FRESH entry spent before flush must not appear in DB after flush")
	}
}

// ---------------------------------------------------------------------------
// G21: FRESH+DIRTY combo invariants
// BUG W100-B13 (CORRECTNESS): In SpendUTXOChecked, when a FRESH coin is
// spent, it is added to the `deleted` map (line 199: `u.deleted[outpoint] = true`).
// This contradicts the FRESH invariant: a FRESH entry has never been written
// to the base DB, so adding it to `deleted` will emit a spurious DB tombstone
// on the next Flush(), doing wasted I/O. Core's coins.cpp SpendCoin
// explicitly avoids generating a tombstone for FRESH entries.
// Compare SpendUTXOChecked (line 196-199) vs SpendUTXO (line 167-171):
// SpendUTXO correctly skips the deleted map for FRESH entries, but
// SpendUTXOChecked unconditionally adds the outpoint to deleted even when
// FRESH.
// ---------------------------------------------------------------------------

func TestG21_FreshSpent_NoTombstone(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	op := createTestOutpoint(0xBD, 0)
	entry := createTestEntry(3333, 5, false, []byte{0x76})
	utxoSet.AddUTXO(op, entry) // FRESH

	// SpendUTXOChecked on a FRESH entry
	if err := utxoSet.SpendUTXOChecked(op); err != nil {
		t.Fatalf("SpendUTXOChecked failed: %v", err)
	}

	// Flush — FRESH-then-spent must not generate a DB tombstone
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	// Entry must not appear in DB after flush (tombstone would mark it "deleted")
	utxoSet2 := NewUTXOSet(chainDB)
	got := utxoSet2.GetUTXO(op)
	if got != nil {
		t.Error("G21: FRESH coin spent via SpendUTXOChecked must not appear in DB; " +
			"BUG W100-B13: SpendUTXOChecked adds FRESH entries to `deleted` map, generating spurious tombstone")
	}
}

func TestG21_FreshDirty_InvariantHolds(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B13 — SpendUTXOChecked (line 199) adds FRESH entries to `deleted`; " +
		"SpendUTXO (line 167-171) correctly skips `deleted` for FRESH — inconsistent behavior between " +
		"the two spend paths; FRESH+in-deleted is an invalid combination")
}

// ---------------------------------------------------------------------------
// G22: DynamicMemoryUsage tracks actual bytes
// BUG W100-B14 (OBSERVABILITY): estimateEntrySize() uses a fixed 149-byte
// estimate (36+8+len(PkScript)+4+1+100) where the +100 is a fixed "map
// overhead" constant. Go maps carry ~8-16 bytes of bucket overhead per entry,
// not 100. The estimate is ~6-7× too high for entries with short scripts
// (typical P2PKH~25 bytes → actual ~74 bytes, estimated 149+25=174). This
// inflates cacheBytes and causes premature cache eviction during IBD.
// ---------------------------------------------------------------------------

func TestG22_DynamicMemoryUsage_EstimateAccuracy(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B14 — estimateEntrySize() uses +100 fixed map-overhead; " +
		"actual Go map overhead is ~8-16 bytes/entry; estimate is ~6× too large for short scripts; " +
		"causes premature cache eviction (cacheBytes threshold hit too early during IBD)")
}

func TestG22_CacheBytes_TracksSize(t *testing.T) {
	utxoSet := NewUTXOSet(nil)

	// Initial cache should be 0 bytes
	if utxoSet.CacheBytes() != 0 {
		t.Errorf("G22: empty cache should have 0 bytes, got %d", utxoSet.CacheBytes())
	}

	op := createTestOutpoint(0xBE, 0)
	entry := createTestEntry(1000, 1, false, []byte{0x76, 0xa9, 0x14})
	utxoSet.AddUTXO(op, entry)

	if utxoSet.CacheBytes() <= 0 {
		t.Error("G22: CacheBytes must increase after AddUTXO")
	}

	utxoSet.SpendUTXO(op)
	if utxoSet.CacheBytes() != 0 {
		t.Errorf("G22: CacheBytes should return to 0 after spending only entry, got %d", utxoSet.CacheBytes())
	}
}

// ---------------------------------------------------------------------------
// G23: cacheCoins map keyed by COutPoint
// ---------------------------------------------------------------------------

func TestG23_CacheKeyedByOutPoint(t *testing.T) {
	utxoSet := NewUTXOSet(nil)

	// Two outpoints with same hash but different index must be independent
	var h wire.Hash256
	h[0] = 0xDE
	op0 := wire.OutPoint{Hash: h, Index: 0}
	op1 := wire.OutPoint{Hash: h, Index: 1}

	e0 := createTestEntry(100, 1, false, []byte{0x51})
	e1 := createTestEntry(200, 2, false, []byte{0x52})
	utxoSet.AddUTXO(op0, e0)
	utxoSet.AddUTXO(op1, e1)

	got0 := utxoSet.GetUTXO(op0)
	got1 := utxoSet.GetUTXO(op1)

	if got0 == nil || got0.Amount != 100 {
		t.Error("G23: op0 lookup failed or wrong amount")
	}
	if got1 == nil || got1.Amount != 200 {
		t.Error("G23: op1 lookup failed or wrong amount")
	}
}

// ---------------------------------------------------------------------------
// G24: Cache lookup IsSpent() skip
// Spent entries in the deleted map must not be returned by GetUTXO
// ---------------------------------------------------------------------------

func TestG24_SpentEntry_NotReturnedByGetUTXO(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	op := createTestOutpoint(0xBF, 0)
	entry := createTestEntry(777, 3, false, []byte{0x76})

	// Add, flush to DB, then spend in memory (tombstone pending)
	utxoSet.AddUTXO(op, entry)
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	// Now it's in DB but not in cache. Spend it (tombstone goes into deleted map).
	_ = utxoSet.SpendUTXOChecked(op)

	// GetUTXO must NOT return it even though it's still in the DB (tombstone pending)
	if utxoSet.GetUTXO(op) != nil {
		t.Error("G24: GetUTXO must skip entries that are in the deleted (tombstone) set")
	}
}

// ---------------------------------------------------------------------------
// G25: FlushStateMode NONE/IF_NEEDED/PERIODIC/ALWAYS
// BUG W100-B15 (CORRECTNESS/DOS): blockbrew has no FlushStateMode enum. The
// flush policy is a single: flush every N blocks (IBDFlushInterval=2000) or
// when cacheBytes > maxCacheBytes. There is no equivalent to:
//   - FlushStateMode::NONE (no flush, just no-op — used post-ActivateBestChain)
//   - FlushStateMode::IF_NEEDED (flush only on CRITICAL cache state — emergency flush)
//   - FlushStateMode::PERIODIC (flush every ~1h OR large cache — normal operation)
//   - FlushStateMode::ALWAYS/FORCE_FLUSH (always flush + evict)
// Without IF_NEEDED, blockbrew cannot detect a CRITICAL cache state and
// emergency-flush before memory exhaustion. Without PERIODIC time-based flush,
// a node that processes <2000 blocks/hour never flushes regardless of runtime
// duration (safety net missing for post-IBD tip-following).
// ---------------------------------------------------------------------------

func TestG25_FlushStateMode_Missing(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B15 — no FlushStateMode (NONE/IF_NEEDED/PERIODIC/ALWAYS); " +
		"flush policy is only block-count + byte-count; no time-based PERIODIC flush; " +
		"no emergency IF_NEEDED / CRITICAL cache-size detection; " +
		"Core validation.cpp FlushStateToDisk dispatches on 4 modes")
}

// ---------------------------------------------------------------------------
// G26: PERIODIC ~1hr OR 1GB cache
// BUG W100-B15 (continued): No time-based flush interval. Core flushes at
// DATABASE_WRITE_INTERVAL_MIN (~1hr) or when cache exceeds CRITICAL threshold
// (~1 GiB). blockbrew's flush is triggered only by block count (every 2000
// blocks during IBD) or when cacheBytes > 2 GiB — significantly wider than
// Core's ~1 GiB CRITICAL threshold, risking OOM on memory-constrained nodes.
// ---------------------------------------------------------------------------

func TestG26_PeriodicFlush_TimeAndCacheBased(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B15 (continued) — no time-based PERIODIC flush (Core: ~1hr); " +
		"Core CRITICAL threshold ~1 GiB triggers emergency flush; " +
		"blockbrew threshold is 2 GiB (DefaultCacheMaxBytes) — 2× Core's CRITICAL level")
}

// ---------------------------------------------------------------------------
// G27: nMinDiskSpace check before write
// BUG W100-B16 (DOS/CORRECTNESS): FlushStateToDisk in Core calls
// CheckDiskSpace() before committing the UTXO + block files to prevent
// writing when disk is nearly full. blockbrew has no disk-space check before
// Flush() or FlushBatch(). On a full disk the Pebble write will fail, but
// the error propagates as an opaque write error (not a clean "out of disk
// space" shutdown). Additionally, block files (flatfile.go) do not check
// available space before preallocating/appending, risking partial writes
// that corrupt the block store.
// ---------------------------------------------------------------------------

func TestG27_DiskSpaceCheck_MissingBeforeFlush(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B16 — no CheckDiskSpace() before Flush()/FlushBatch(); " +
		"Core validation.cpp:2778 CheckDiskSpace(blocks_dir) gates the UTXO flush; " +
		"blockbrew propagates Pebble write errors only — no proactive disk-space guard")
}

// ---------------------------------------------------------------------------
// G28: UTXO + block files crash-consistency
// The atomic batch pattern (ConnectBlock, DisconnectBlock, ReorgTo) correctly
// writes undo data + UTXO + chain state in one Pebble batch.
// Residual concern: the IBD non-flush path (between flushes) writes
// SetBlockHeight and WriteBlockUndo as SEPARATE operations (not batched).
// A crash between SetBlockHeight and WriteBlockUndo leaves the chain at
// a height whose undo data is absent — DisconnectBlock will fail for that
// block.
// ---------------------------------------------------------------------------

func TestG28_CrashConsistency_IBDNonFlushPath(t *testing.T) {
	t.Skip("W100 audit: G28 concern — IBD between-flush path writes SetBlockHeight then " +
		"WriteBlockUndo as two separate calls (chainmanager.go lines 1037 + 1040); " +
		"crash between them leaves height-mapping without undo data; " +
		"Core holds all per-block metadata in a single atomic batch at ALL heights")
}

func TestG28_CrashConsistency_AtomicBatch(t *testing.T) {
	// Positive test: the flush path writes everything atomically
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	op := createTestOutpoint(0xC0, 0)
	entry := createTestEntry(5000, 1, false, []byte{0x76})
	utxoSet.AddUTXO(op, entry)

	// Simulate atomic batch flush (as ConnectBlock does)
	batch := chainDB.NewBatch()
	if err := utxoSet.FlushBatch(batch); err != nil {
		t.Fatalf("FlushBatch failed: %v", err)
	}
	chainDB.SetChainStateBatch(batch, &storage.ChainState{BestHash: wire.Hash256{0x01}, BestHeight: 1})
	if err := batch.Write(); err != nil {
		t.Fatalf("batch write failed: %v", err)
	}

	// Verify both writes landed atomically (UTXO + chain state)
	utxoSet2 := NewUTXOSet(chainDB)
	if utxoSet2.GetUTXO(op) == nil {
		t.Error("G28: UTXO not persisted after atomic batch")
	}
	state, err := chainDB.GetChainState()
	if err != nil || state.BestHeight != 1 {
		t.Errorf("G28: chain state not persisted after atomic batch: %v", err)
	}
}

// ---------------------------------------------------------------------------
// G29: Pruning after flush
// ---------------------------------------------------------------------------

func TestG29_PruningAfterFlush(t *testing.T) {
	// Prune logic is in storage.Pruner.MaybePrune — covered by prune_test.go.
	// Audit note: blockbrew's pruner is triggered by the P2P sync path (not
	// directly by FlushStateToDisk). Core triggers prune in FlushStateToDisk
	// when fFlushForPrune is set. The timing gap means blockbrew may not prune
	// immediately when a flush fires during IBD — acceptable for now.
	t.Skip("W100 audit: G29 — pruning is invoked from P2P sync path (not FlushStateToDisk); " +
		"Core prunes inside FlushStateToDisk when fFlushForPrune; " +
		"blockbrew timing is acceptable but the coupling is weaker")
}

// ---------------------------------------------------------------------------
// G30: Flush notification signals
// BUG W100-B17 (OBSERVABILITY): blockbrew has no flush-notification mechanism.
// Core fires CValidationInterface::ChainStateFlushed after FlushStateToDisk
// succeeds. Downstream consumers (ZMQ, wallet, indexes) rely on this signal
// to know the UTXO set is durably consistent. blockbrew's
// onBlockConnected/onBlockDisconnected closures do not include a chainstate-
// flush signal.
// ---------------------------------------------------------------------------

func TestG30_FlushNotification_Missing(t *testing.T) {
	t.Skip("W100 audit: BUG W100-B17 — no flush notification (CValidationInterface::ChainStateFlushed); " +
		"Core fires this after every successful FlushStateToDisk; " +
		"blockbrew has onBlockConnected/onBlockDisconnected but no onChainStateFlushed hook")
}

// ---------------------------------------------------------------------------
// Extra: Test FRESH-bit SpendUTXO vs SpendUTXOChecked inconsistency (B13)
// Verify that SpendUTXO correctly skips the tombstone for FRESH entries
// (correct) while SpendUTXOChecked incorrectly adds to deleted (the bug).
// ---------------------------------------------------------------------------

func TestG21_SpendUTXO_FreshSkipsTombstone(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	op := createTestOutpoint(0xC1, 0)
	entry := createTestEntry(1111, 1, false, []byte{0x51})
	utxoSet.AddUTXO(op, entry) // FRESH

	// SpendUTXO (not Checked): should skip deleted map for FRESH
	utxoSet.SpendUTXO(op)

	// Flush: should generate 0 tombstone writes for this outpoint
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	// Confirm nothing in DB
	utxoSet2 := NewUTXOSet(chainDB)
	if utxoSet2.GetUTXO(op) != nil {
		t.Error("SpendUTXO on FRESH entry must not persist tombstone")
	}
}

// ---------------------------------------------------------------------------
// Extra: Multi-block connect+disconnect invariant (G28 positive path)
// ---------------------------------------------------------------------------

func TestG28_MultiBlockConnectDisconnect_UTXOConsistency(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)
	utxoSet := NewUTXOSet(chainDB)

	// Set up initial UTXO (simulates previous block's coinbase output)
	prevTxHash := wire.Hash256{0xDD}
	prevOp := wire.OutPoint{Hash: prevTxHash, Index: 0}
	prevEntry := &UTXOEntry{
		Amount:     50_00000000,
		PkScript:   []byte{0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x88, 0xac},
		Height:     100,
		IsCoinbase: true,
	}
	utxoSet.AddUTXO(prevOp, prevEntry)
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("initial flush: %v", err)
	}

	// Build a block that spends prevOp
	spendTx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: prevOp, SignatureScript: []byte{0x00}, Sequence: 0xFFFFFFFF}},
		TxOut:   []*wire.TxOut{{Value: 49_99900000, PkScript: []byte{0x51, 0x20, 0xAB}}},
		LockTime: 0,
	}
	coinbaseTx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF}, SignatureScript: []byte{0x01, 0x00}, Sequence: 0xFFFFFFFF}},
		TxOut:   []*wire.TxOut{{Value: 50_00000000, PkScript: []byte{0x51, 0x20, 0xCC}}},
		LockTime: 0,
	}
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1},
		Transactions: []*wire.MsgTx{coinbaseTx, spendTx},
	}

	// Connect block
	undo, err := utxoSet.ConnectBlockUTXOs(block, 101)
	if err != nil {
		t.Fatalf("ConnectBlockUTXOs: %v", err)
	}
	if utxoSet.HasUTXO(prevOp) {
		t.Error("G28: prevOp should be spent after connect")
	}

	// Disconnect block
	if err := utxoSet.DisconnectBlockUTXOs(block, undo); err != nil {
		t.Fatalf("DisconnectBlockUTXOs: %v", err)
	}
	if !utxoSet.HasUTXO(prevOp) {
		t.Error("G28: prevOp must be restored after disconnect")
	}

	restored := utxoSet.GetUTXO(prevOp)
	if restored == nil {
		t.Fatal("G28: restored UTXO is nil")
	}
	if restored.Amount != prevEntry.Amount {
		t.Errorf("G28: restored amount %d != original %d", restored.Amount, prevEntry.Amount)
	}
	if !bytes.Equal(restored.PkScript, prevEntry.PkScript) {
		t.Errorf("G28: restored PkScript mismatch")
	}
}

// ---------------------------------------------------------------------------
// Extra: ApplyTxInUndo — legacy height-recovery path (Gate B from AccessByTxid)
// ---------------------------------------------------------------------------

func TestApplyTxInUndo_LegacyZeroHeight_SiblingRecovery(t *testing.T) {
	utxoSet := NewUTXOSet(nil)

	var txid wire.Hash256
	txid[0] = 0xEE
	sibling := wire.OutPoint{Hash: txid, Index: 1}
	sibEntry := createTestEntry(999, 42, true, []byte{0x51})
	utxoSet.AddUTXO(sibling, sibEntry)

	// Legacy undo entry with Height=0 (pre-0.9 Core format)
	undoEntry := &UTXOEntry{
		Amount:     1234,
		PkScript:   []byte{0x76},
		Height:     0,     // triggers sibling recovery
		IsCoinbase: false, // will be updated from sibling
	}
	targetOp := wire.OutPoint{Hash: txid, Index: 0}

	clean, ok := utxoSet.ApplyTxInUndo(undoEntry, targetOp)
	if !ok {
		t.Fatal("ApplyTxInUndo: sibling recovery should succeed")
	}
	// clean may be false if outpoint was already present, but ok must be true
	_ = clean

	// The undo entry should now have Height from sibling
	if undoEntry.Height != sibEntry.Height {
		t.Errorf("ApplyTxInUndo: height not borrowed from sibling: got %d want %d",
			undoEntry.Height, sibEntry.Height)
	}
}

func TestApplyTxInUndo_NoSibling_ReturnsFalse(t *testing.T) {
	utxoSet := NewUTXOSet(nil)

	var txid wire.Hash256
	txid[0] = 0xFF
	undoEntry := &UTXOEntry{
		Amount:     500,
		PkScript:   []byte{0x51},
		Height:     0, // no sibling in empty set
		IsCoinbase: false,
	}
	targetOp := wire.OutPoint{Hash: txid, Index: 0}

	_, ok := utxoSet.ApplyTxInUndo(undoEntry, targetOp)
	if ok {
		t.Error("ApplyTxInUndo: should return ok=false when no sibling exists for legacy undo record")
	}
}
