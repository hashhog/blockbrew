package consensus

// Verifies the post-flush cache-eviction change (keep warm cache resident up to
// the -dbcache budget instead of nuking to 25% of it; Core CCoinsViewCache
// parity). Two properties:
//
//	(1) RESULTS-NEUTRAL: under heavy multi-flush eviction (cache >> budget,
//	    repeated flushes), every coin remains correctly readable — eviction
//	    only ever drops CLEAN (already-flushed) entries, so a re-read from the
//	    backing store returns the identical coin. This is the consensus-safety
//	    gate for the change (the read-PATH changed, the read VALUES did not).
//
//	(2) RESIDENCY (the actual perf win): right after a flush that triggers
//	    eviction, the cache is kept populated up to ~the budget — NOT shrunk to
//	    a quarter of it. On the pre-fix code (`> maxCacheBytes/2` → target
//	    `maxCacheBytes/4`) this assertion FAILS (residency ≤ budget/4); on the
//	    fixed code it holds (residency in (budget/2, budget]).
//
// This is the executed before/after for the eviction change; a full mainnet
// IBD besthash==Core is blocked by an unrelated block-download bug (#30), so
// this unit-level proof stands in for it for the cache-residency change.

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

func TestEvictionResidency_ResultsNeutral_AndKeepsCacheToBudget(t *testing.T) {
	memDB := storage.NewMemDB()
	chainDB := storage.NewChainDB(memDB)

	// Derive a single-entry byte cost so we can size a small, deterministic
	// budget that holds ~20 entries.
	probe := NewUTXOSet(chainDB)
	probeOp := createTestOutpoint(0x01, 0)
	probeEntry := createTestEntry(1000, 1, false, []byte{0x76, 0xa9, 0x14, 0x00})
	probe.AddUTXO(probeOp, probeEntry)
	entryBytes := probe.CacheBytes()
	if entryBytes <= 0 {
		t.Fatalf("probe entry byte size must be > 0, got %d", entryBytes)
	}
	const budgetEntries = 20
	budget := entryBytes * budgetEntries

	u := NewUTXOSetWithMaxCache(chainDB, budget)

	// Add many more coins than the budget can hold, flushing periodically so the
	// eviction path runs repeatedly (cacheBytes crosses the budget each time).
	const N = 600
	want := make(map[wire.OutPoint]*UTXOEntry, N)
	for i := 0; i < N; i++ {
		op := createTestOutpoint(byte(i%256), uint32(i)) // unique (hash,index)
		e := createTestEntry(int64(1000+i), int32(i), false, []byte{0x76, 0xa9, 0x14, byte(i)})
		u.AddUTXO(op, e)
		want[op] = e
		if i%50 == 49 {
			if err := u.Flush(); err != nil {
				t.Fatalf("flush at i=%d: %v", i, err)
			}
		}
	}
	if err := u.Flush(); err != nil { // final flush triggers a final eviction
		t.Fatalf("final flush: %v", err)
	}

	// (2) RESIDENCY: right after a flush-with-eviction the cache must be kept
	// populated up to ~budget, not nuked to a quarter. This is the discriminating
	// assertion: the pre-fix 25%-nuke would leave residency <= budget/4.
	resident := u.CacheBytes()
	if resident > budget {
		t.Errorf("residency %d exceeds budget %d (eviction should cap at budget)", resident, budget)
	}
	if resident <= budget/2 {
		t.Errorf("RESIDENCY REGRESSION: post-flush cache %d <= budget/2 (%d) — the warm cache was "+
			"nuked below the configured -dbcache budget (%d). The fix keeps it resident up to budget.",
			resident, budget/2, budget)
	}

	// (1) RESULTS-NEUTRAL: every coin added must still read back correctly,
	// whether it survived in the warm cache or is re-read from the backing store
	// after eviction. A lost or corrupted coin here would be a consensus bug.
	for op, e := range want {
		got := u.GetUTXO(op)
		if got == nil {
			t.Fatalf("coin LOST after eviction: %v (height %d) — eviction must drop only clean "+
				"entries that are re-readable from the store", op, e.Height)
		}
		if got.Amount != e.Amount || got.Height != e.Height || got.IsCoinbase != e.IsCoinbase {
			t.Fatalf("coin CORRUPTED after eviction: op=%v got {amt=%d h=%d cb=%v} want {amt=%d h=%d cb=%v}",
				op, got.Amount, got.Height, got.IsCoinbase, e.Amount, e.Height, e.IsCoinbase)
		}
	}
}
