package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// FRESH-over-DIRTY regression guards.
//
// Bitcoin Core coins.cpp CCoinsViewCache::AddCoin: a coin may be marked FRESH
// only when the entry it replaces is not DIRTY ("If the coin exists in this
// cache as a spent coin and is DIRTY, then its spentness hasn't been flushed
// to the parent cache. We're re-adding the coin to this cache now but we
// can't mark it as FRESH."), and never when possible_overwrite is set.
// Marking such a coin FRESH lets a second spend drop the entry without the
// pending delete, so a spent coin survives on disk.
//
// Every test here runs against the real UTXOSet and a real ChainDB and
// asserts on the durable key, not on the cached view.

func freshTestSet(t *testing.T) (*UTXOSet, *storage.ChainDB) {
	t.Helper()
	chainDB := storage.NewChainDB(storage.NewMemDB())
	return NewUTXOSet(chainDB), chainDB
}

func onDisk(t *testing.T, db *storage.ChainDB, op wire.OutPoint) bool {
	t.Helper()
	ok, err := db.DB().Has(storage.MakeUTXOKey(op))
	if err != nil {
		t.Fatalf("db Has: %v", err)
	}
	return ok
}

func mustFlush(t *testing.T, u *UTXOSet) {
	t.Helper()
	if err := u.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

// Control: a coin created and spent between flushes never reaches disk, and
// the spend is taken by the FRESH shortcut (freshHits), so the test exercises
// the real FRESH path rather than some other deletion route.
func TestFreshCreateSpendFlushWritesNothing(t *testing.T) {
	u, db := freshTestSet(t)
	op := createTestOutpoint(0xA1, 0)

	u.AddUTXO(op, createTestEntry(1000, 10, false, []byte{0x51}))
	u.SpendUTXO(op)
	if u.freshHits != 1 {
		t.Fatalf("freshHits = %d, want 1 (FRESH shortcut not taken)", u.freshHits)
	}
	if len(u.deleted) != 0 || len(u.dirty) != 0 {
		t.Fatalf("pending writes after FRESH spend: dirty=%d deleted=%d", len(u.dirty), len(u.deleted))
	}
	mustFlush(t, u)
	if onDisk(t, db, op) {
		t.Fatal("fresh create+spend left the coin on disk")
	}
}

// The core sequence: on disk -> spend (dirty-spent, unflushed) -> re-add (as
// an undo would) -> spend again -> flush. The coin must be gone from disk.
func TestFreshNotSetOverDirtySpent(t *testing.T) {
	u, db := freshTestSet(t)
	op := createTestOutpoint(0xA2, 0)
	entry := createTestEntry(5000, 20, false, []byte{0x51})

	u.AddUTXO(op, entry)
	mustFlush(t, u)
	if !onDisk(t, db, op) {
		t.Fatal("setup: coin not on disk after flush")
	}

	u.SpendUTXO(op)      // spent in cache, delete pending
	u.AddUTXO(op, entry) // restored (disconnect / failed-connect rollback)
	u.SpendUTXO(op)      // spent again by the competing block
	mustFlush(t, u)

	if onDisk(t, db, op) {
		t.Fatal("UTXO DIVERGENCE: spent coin survived on disk (FRESH set over a DIRTY spent entry)")
	}
	if u.HasUTXO(op) {
		t.Fatal("HasUTXO reports a spent coin")
	}
}

// The same sequence through the production disconnect primitive,
// ApplyTxInUndo (ChainManager.DisconnectBlock), with SpendUTXOWithCoin for
// the two spends.
func TestFreshNotSetOverDirtySpentViaApplyTxInUndo(t *testing.T) {
	u, db := freshTestSet(t)
	op := createTestOutpoint(0xA3, 1)
	entry := createTestEntry(7000, 30, false, []byte{0x51})

	u.AddUTXO(op, entry)
	mustFlush(t, u)

	if _, ok := u.SpendUTXOWithCoin(op); !ok {
		t.Fatal("setup: first spend found nothing")
	}
	undo := *entry
	if clean, ok := u.ApplyTxInUndo(&undo, op); !ok || !clean {
		t.Fatalf("ApplyTxInUndo clean=%v ok=%v", clean, ok)
	}
	if _, ok := u.SpendUTXOWithCoin(op); !ok {
		t.Fatal("second spend found nothing")
	}
	mustFlush(t, u)
	if onDisk(t, db, op) {
		t.Fatal("UTXO DIVERGENCE: spent coin survived on disk after undo + respend")
	}
}

// SpendUTXOChecked is the third spend primitive with a FRESH shortcut.
func TestFreshNotSetOverDirtySpentChecked(t *testing.T) {
	u, db := freshTestSet(t)
	op := createTestOutpoint(0xA4, 0)
	entry := createTestEntry(9000, 40, false, []byte{0x51})

	u.AddUTXO(op, entry)
	mustFlush(t, u)
	if err := u.SpendUTXOChecked(op); err != nil {
		t.Fatal(err)
	}
	u.AddUTXO(op, entry)
	if err := u.SpendUTXOChecked(op); err != nil {
		t.Fatal(err)
	}
	mustFlush(t, u)
	if onDisk(t, db, op) {
		t.Fatal("UTXO DIVERGENCE: spent coin survived on disk (SpendUTXOChecked)")
	}
}

// Re-adding a coin that is on disk and sits CLEAN in the cache (read through,
// or retained after a flush) must not mark it FRESH either: Core would treat
// that as possible_overwrite (never FRESH). Reached by the roll-forward in
// ChainManager (which re-applies a block whose outputs may already be durable)
// and by an unclean undo.
func TestFreshNotSetOverCleanCachedCoin(t *testing.T) {
	u, db := freshTestSet(t)
	op := createTestOutpoint(0xA5, 0)
	entry := createTestEntry(1100, 50, false, []byte{0x51})

	u.AddUTXO(op, entry)
	mustFlush(t, u) // cache retains a clean copy
	u.AddUTXO(op, entry)
	u.SpendUTXO(op)
	mustFlush(t, u)
	if onDisk(t, db, op) {
		t.Fatal("UTXO DIVERGENCE: re-added clean coin, spent, survived on disk")
	}
}

// Roll-forward re-adds a block's outputs whose durable copy may exist while
// the cache holds nothing for them (fresh process). Those adds must use
// possible-overwrite semantics, so a later spend still deletes from disk.
func TestAddUTXOOverwriteNotFreshWhenUncached(t *testing.T) {
	chainDB := storage.NewChainDB(storage.NewMemDB())
	op := createTestOutpoint(0xA6, 0)
	entry := createTestEntry(1200, 60, false, []byte{0x51})

	first := NewUTXOSet(chainDB)
	first.AddUTXO(op, entry)
	mustFlush(t, first)

	u := NewUTXOSet(chainDB) // new process: empty cache, coin on disk
	u.AddUTXOOverwrite(op, entry)
	u.SpendUTXO(op)
	mustFlush(t, u)
	if onDisk(t, chainDB, op) {
		t.Fatal("UTXO DIVERGENCE: overwrite-add of an uncached durable coin was FRESH")
	}
}

// A FRESH entry that is re-added (still unflushed) stays FRESH: Core never
// clears FRESH in AddCoin. Guards against the fix over-correcting and losing
// the IBD optimisation.
func TestFreshPreservedOnReAddOfFreshEntry(t *testing.T) {
	u, db := freshTestSet(t)
	op := createTestOutpoint(0xA7, 0)
	entry := createTestEntry(1300, 70, false, []byte{0x51})

	u.AddUTXO(op, entry)
	u.AddUTXO(op, entry)
	u.SpendUTXO(op)
	if u.freshHits != 1 {
		t.Fatalf("freshHits = %d, want 1", u.freshHits)
	}
	mustFlush(t, u)
	if onDisk(t, db, op) {
		t.Fatal("fresh coin reached disk")
	}
}
