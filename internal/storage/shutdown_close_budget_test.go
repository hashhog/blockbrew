package storage

import (
	"path/filepath"
	"testing"
	"time"
)

// Gate 5 (mainnet 2026-10-02): pebble.DB.Close waits until every in-flight
// compaction and flush finishes (pebble db.go, compact.cond). That wait was
// 30s at 20:08Z and still running at 51s at 23:31Z, so the 80s shutdown
// deadline fired and the process logged "exit (forced)" even though the
// chainstate batch, mempool, wallet and block store were already durable
// and the restart was clean.
//
// testClose blocks the way that wait does. CloseForShutdown must return
// within its budget with finished=false, not sit in Close until the
// compaction ends.
func TestCloseForShutdownDoesNotWaitOutAStalledCompaction(t *testing.T) {
	dir := t.TempDir()
	db, err := NewPebbleDB(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}

	release := make(chan struct{})
	started := make(chan struct{})
	closeReturned := make(chan struct{})
	db.testClose = func() error {
		close(started)
		<-release
		close(closeReturned)
		return nil
	}
	defer func() {
		close(release)
		select {
		case <-closeReturned:
		case <-time.After(2 * time.Second):
		}
		if db.db != nil {
			_ = db.db.Close()
		}
		if db.cache != nil {
			db.cache.Unref()
			db.cache = nil
		}
	}()

	// A synced batch is what shutdown has already done before it closes.
	b := db.NewBatch()
	b.Put([]byte("k"), []byte("durable"))
	if err := b.Write(); err != nil {
		t.Fatal(err)
	}

	const budget = 400 * time.Millisecond
	done := make(chan struct{})
	var closeErr error
	var finished bool
	t0 := time.Now()
	go func() {
		closeErr, finished = db.CloseForShutdown(budget)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("CloseForShutdown never started the DB close (WAL sync blocked?)")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("CloseForShutdown still blocked after 3s while Close waited on a compaction")
	}
	took := time.Since(t0)
	if finished {
		t.Fatalf("CloseForShutdown reported the close finished while it was still blocked (took %s)", took)
	}
	if took > 2*time.Second {
		t.Fatalf("CloseForShutdown took %s; budget was %s", took, budget)
	}
	if closeErr != nil {
		t.Fatalf("abandoned close returned error %v", closeErr)
	}
}

// A DB with nothing in flight must still close cleanly inside the budget,
// and a batch committed with Sync must be readable after reopen.
func TestCloseForShutdownOnAQuietDBIsDurable(t *testing.T) {
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
	err, finished := db.CloseForShutdown(10 * time.Second)
	if err != nil || !finished {
		t.Fatalf("quiet close: err=%v finished=%v", err, finished)
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
