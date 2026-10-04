package storage

// Gate 5, 2026-10-04: the live close of 985c117 overran its 20 s budget. On a
// saturated disk every fsync costs seconds, and Close was a serial chain of
// them: an unconditional pre-abandon WAL sync (LogData Sync), then whatever
// the in-flight flush was syncing, then pebble's own WAL sync in
// LogWriter.Close. The pre-abandon sync is redundant whenever the last
// acknowledged write was a Sync commit, which is how the shutdown sequence
// ends (chainstate batch, block-store state batch).
//
// walSyncFS counts and delays durability syncs of WAL files so the tests can
// see how many Close performs.

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/vfs"
)

type walSyncFS struct {
	vfs.FS
	delay time.Duration
	syncs atomic.Int64 // Sync/SyncData calls on *.log files
}

func (fs *walSyncFS) wrap(name string, f vfs.File, err error) (vfs.File, error) {
	if err != nil || !strings.HasSuffix(name, ".log") {
		return f, err
	}
	return &walSyncFile{File: f, fs: fs}, nil
}

func (fs *walSyncFS) Create(name string) (vfs.File, error) {
	f, err := fs.FS.Create(name)
	return fs.wrap(name, f, err)
}

// pebble recycles old WAL files through ReuseForWrite.
func (fs *walSyncFS) ReuseForWrite(oldname, newname string) (vfs.File, error) {
	f, err := fs.FS.ReuseForWrite(oldname, newname)
	return fs.wrap(newname, f, err)
}

type walSyncFile struct {
	vfs.File
	fs *walSyncFS
}

func (f *walSyncFile) Sync() error {
	f.fs.syncs.Add(1)
	time.Sleep(f.fs.delay)
	return f.File.Sync()
}

func (f *walSyncFile) SyncData() error {
	f.fs.syncs.Add(1)
	time.Sleep(f.fs.delay)
	return f.File.SyncData()
}

func openWALSyncTestDB(t *testing.T, dir string, delay time.Duration) (*PebbleDB, *walSyncFS) {
	t.Helper()
	wfs := &walSyncFS{FS: vfs.Default, delay: delay}
	cfg := DefaultPebbleDBConfig()
	cfg.BlockCacheSize = 8 << 20
	cfg.MemTableSize = 4 << 20
	cfg.fs = wfs
	db, err := NewPebbleDBWithConfig(dir, cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return db, wfs
}

// TestCloseSkipsRedundantWALSync: when the last acknowledged write was a Sync
// batch, Close performs exactly one WAL sync (pebble's own, in
// LogWriter.Close), every key is there on reopen, and a slow fsync is paid
// once rather than twice.
//
// Negative control: with Close syncing the WAL unconditionally (the 985c117
// behaviour: `if !p.walAlreadySynced()` replaced by `if true`), Close makes
// two WAL syncs and the test fails.
func TestCloseSkipsRedundantWALSync(t *testing.T) {
	dir := t.TempDir()
	const delay = 300 * time.Millisecond
	db, wfs := openWALSyncTestDB(t, dir, delay)
	// NoSync writes first (undo data, block index), then the shutdown
	// sequence's synced batch, as at a daemon stop.
	for i := 0; i < 200; i++ {
		if err := db.Put(closeTestKey(i), closeTestVal(i)); err != nil {
			t.Fatal(err)
		}
	}
	b := db.NewBatch()
	for i := 200; i < 400; i++ {
		b.Put(closeTestKey(i), closeTestVal(i))
	}
	if err := b.Write(); err != nil {
		t.Fatal(err)
	}
	if !db.walAlreadySynced() {
		t.Fatalf("a completed Sync batch after the NoSync puts must leave the WAL marked synced")
	}

	before := wfs.syncs.Load()
	start := time.Now()
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	took := time.Since(start)
	n := wfs.syncs.Load() - before
	t.Logf("Close made %d WAL sync(s) in %s (each delayed %s)", n, took, delay)
	if n != 1 {
		t.Fatalf("Close made %d WAL syncs, want 1 (pebble's own): the pre-close sync was not skipped although every write was already synced", n)
	}

	db2, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	for i := 0; i < 400; i++ {
		if v, _ := db2.Get(closeTestKey(i)); v == nil {
			t.Fatalf("key %d lost across a clean close", i)
		}
	}
}

// TestCloseSyncsWALWhenANoSyncWriteIsUnsynced: when a NoSync write returned
// after the last Sync commit, Close still syncs the WAL before abandoning
// anything (the guarantee the bounded close relies on), so it makes two WAL
// syncs.
//
// Negative control: with the pre-close sync removed altogether (`if
// !p.walAlreadySynced()` replaced by `if false`), Close makes one sync and the
// test fails. TestKillDuringCloseKeepsDBConsistent checks the consequence:
// NoSync keys survive a SIGKILL after the abandon step.
func TestCloseSyncsWALWhenANoSyncWriteIsUnsynced(t *testing.T) {
	dir := t.TempDir()
	db, wfs := openWALSyncTestDB(t, dir, 0)
	b := db.NewBatch()
	b.Put([]byte("synced"), []byte("1"))
	if err := b.Write(); err != nil {
		t.Fatal(err)
	}
	if err := db.Put([]byte("nosync"), []byte("1")); err != nil {
		t.Fatal(err)
	}
	if db.walAlreadySynced() {
		t.Fatalf("a NoSync put after the last Sync batch must leave the WAL marked unsynced")
	}
	before := wfs.syncs.Load()
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if n := wfs.syncs.Load() - before; n != 2 {
		t.Fatalf("Close made %d WAL syncs, want 2 (the pre-abandon sync of the NoSync write, then pebble's own)", n)
	}
}

// An empty Sync batch commits without touching the WAL (pebble returns early),
// so it must not mark earlier NoSync writes as synced.
//
// Negative control: with the `empty` check removed from pebbleBatch.Write the
// empty batch marks the WAL synced and the test fails.
func TestEmptySyncBatchDoesNotMarkWALSynced(t *testing.T) {
	dir := t.TempDir()
	db, _ := openWALSyncTestDB(t, dir, 0)
	defer db.Close()
	if err := db.Put([]byte("nosync"), []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := db.NewBatch().Write(); err != nil {
		t.Fatal(err)
	}
	if db.walAlreadySynced() {
		t.Fatalf("an empty Sync batch marked an unsynced NoSync write as synced")
	}
	nb := db.NewBatchNoSync()
	nb.Put([]byte("nosync2"), []byte("1"))
	if err := nb.Write(); err != nil {
		t.Fatal(err)
	}
	b := db.NewBatch()
	b.Put([]byte("synced"), []byte("1"))
	if err := b.Write(); err != nil {
		t.Fatal(err)
	}
	if !db.walAlreadySynced() {
		t.Fatalf("a non-empty Sync batch after every NoSync write must mark the WAL synced")
	}
}
