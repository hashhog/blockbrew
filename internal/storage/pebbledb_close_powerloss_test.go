package storage

// What the bounded close relies on: once Close has passed the abandon step,
// every acknowledged write is in the durable WAL, so exiting there (the
// daemon's 20 s backstop) or losing power there loses nothing acknowledged.
//
// A SIGKILL cannot test that: unsynced WAL bytes survive a process kill in the
// page cache. pebble's strict MemFS can: it keeps only what was synced, and
// ResetToSyncedState drops the rest, which is what a power loss does. These
// tests ignore every sync from the abandon step on (so pebble's own close-time
// WAL sync does not count) and then reset to the synced state.

import (
	"fmt"
	"testing"

	"github.com/cockroachdb/pebble/vfs"
)

func openStrictMemDB(t *testing.T, mem *vfs.MemFS) *PebbleDB {
	t.Helper()
	// A strict MemFS forgets a directory entry its parent never synced,
	// "/db" included: create and sync it first, or a power loss loses the
	// whole database and the tests below would measure nothing.
	if err := mem.MkdirAll("/db", 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := mem.OpenDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Sync(); err != nil {
		t.Fatal(err)
	}
	root.Close()
	cfg := DefaultPebbleDBConfig()
	cfg.BlockCacheSize = 8 << 20
	cfg.MemTableSize = 4 << 20
	cfg.fs = mem
	db, err := NewPebbleDBWithConfig("/db", cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return db
}

// closeThenLosePower closes db, ignoring every sync from the abandon step on,
// then drops whatever was not synced by then and reopens.
func closeThenLosePower(t *testing.T, mem *vfs.MemFS, db *PebbleDB) *PebbleDB {
	t.Helper()
	db.closeStage = func(stage string) {
		if stage == "abandoned" {
			mem.SetIgnoreSyncs(true)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	mem.ResetToSyncedState()
	mem.SetIgnoreSyncs(false)
	return openStrictMemDB(t, mem)
}

func powerLossKey(i int) []byte { return []byte(fmt.Sprintf("k%05d", i)) }

func checkPowerLossKeys(t *testing.T, db *PebbleDB, n int, what string) {
	t.Helper()
	for i := 0; i < n; i++ {
		v, err := db.Get(powerLossKey(i))
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		if v == nil {
			t.Fatalf("%s: key %d lost by a power loss after Close's abandon step", what, i)
		}
	}
}

// The shutdown shape: NoSync writes, then a Sync batch last. Close skips its
// own WAL sync here, and nothing is lost. The NoSync writes (~10 MB against a
// 4 MB memtable) span several WAL files, so this also covers the older WAL
// files being synced when they were rotated out.
func TestCloseSkippedSyncLosesNothingOnPowerLoss(t *testing.T) {
	mem := vfs.NewStrictMem()
	db := openStrictMemDB(t, mem)
	const noSyncKeys = 2500
	for i := 0; i < noSyncKeys; i++ {
		if err := db.Put(powerLossKey(i), closeTestVal(i)); err != nil {
			t.Fatal(err)
		}
	}
	b := db.NewBatch()
	for i := noSyncKeys; i < noSyncKeys+100; i++ {
		b.Put(powerLossKey(i), []byte("sync"))
	}
	if err := b.Write(); err != nil {
		t.Fatal(err)
	}
	if !db.walAlreadySynced() {
		t.Fatal("setup: the WAL should count as synced here (this run would not test the skip)")
	}
	logs := 0
	if ls, err := mem.List("/db"); err == nil {
		for _, n := range ls {
			if len(n) > 4 && n[len(n)-4:] == ".log" {
				logs++
			}
		}
	}
	t.Logf("WAL files before close: %d", logs)
	db2 := closeThenLosePower(t, mem, db)
	defer db2.Close()
	checkPowerLossKeys(t, db2, noSyncKeys+100, "skipped pre-close sync")
}

// NoSync writes last. Close must sync the WAL before abandoning.
//
// Negative control (the instrument sees an unsynced write): with Close's
// pre-close sync removed (`if !p.walAlreadySynced()` -> `if false`), the
// trailing NoSync keys are lost and the test fails.
func TestCloseSyncsTrailingNoSyncWritesBeforeAbandon(t *testing.T) {
	mem := vfs.NewStrictMem()
	db := openStrictMemDB(t, mem)
	b := db.NewBatch()
	for i := 0; i < 100; i++ {
		b.Put(powerLossKey(i), []byte("sync"))
	}
	if err := b.Write(); err != nil {
		t.Fatal(err)
	}
	for i := 100; i < 400; i++ {
		if err := db.Put(powerLossKey(i), []byte("nosync")); err != nil {
			t.Fatal(err)
		}
	}
	db2 := closeThenLosePower(t, mem, db)
	defer db2.Close()
	checkPowerLossKeys(t, db2, 400, "trailing NoSync writes")
}
