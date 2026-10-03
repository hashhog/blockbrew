package storage

import (
	"path/filepath"
	"testing"
)

// The bounded wait for a slow close lives in cmd/blockbrew (closeWithin under
// the time left before shutdownDeadline); the close itself no longer waits for
// compactions (TestCloseDoesNotWaitForRunningCompaction). This keeps the plain
// property that a DB with nothing in flight closes cleanly and a batch
// committed with Sync is readable after reopen.
func TestCloseOnAQuietDBIsDurable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db")
	db, err := NewPebbleDB(path)
	if err != nil {
		t.Fatal(err)
	}
	b := db.NewBatch()
	b.Put([]byte("k"), []byte("durable"))
	if err := b.Write(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("quiet close: %v", err)
	}
	if n := db.fs.refused.Load(); n != 0 {
		t.Fatalf("quiet close refused %d sstable ops; nothing was running", n)
	}

	db2, err := NewPebbleDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	got, err := db2.Get([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "durable" {
		t.Fatalf("reopen got %q, want durable", got)
	}
}
