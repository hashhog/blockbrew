package storage

import (
	"errors"
	"path/filepath"
	"testing"
)

// Gate 5 (testnet4 real-peer repro, 2026-10-02): a peer goroutine still
// unwinding after SIGTERM stored a block after the DB had been closed and the
// process died "panic: pebble: closed" (exit 2) in StoreBlockAt ->
// PebbleDB.Put. Use after Close must be an error the caller can drop.
func TestPebbleDBUseAfterCloseIsAnError(t *testing.T) {
	db, err := NewPebbleDB(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put([]byte("k"), []byte("v")); err != nil {
		t.Fatal(err)
	}
	b := db.NewBatch()
	b.Put([]byte("k2"), []byte("v2"))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("use after Close panicked: %v", r)
		}
	}()
	if err := db.Put([]byte("k"), []byte("v")); !errors.Is(err, ErrDBClosed) {
		t.Errorf("Put after Close: %v, want ErrDBClosed", err)
	}
	if err := db.Delete([]byte("k")); !errors.Is(err, ErrDBClosed) {
		t.Errorf("Delete after Close: %v, want ErrDBClosed", err)
	}
	if _, err := db.Get([]byte("k")); !errors.Is(err, ErrDBClosed) {
		t.Errorf("Get after Close: %v, want ErrDBClosed", err)
	}
	if _, err := db.Has([]byte("k")); !errors.Is(err, ErrDBClosed) {
		t.Errorf("Has after Close: %v, want ErrDBClosed", err)
	}
	if err := b.Write(); !errors.Is(err, ErrDBClosed) {
		t.Errorf("batch Write after Close: %v, want ErrDBClosed", err)
	}
}

// Writers queued behind Close must not each do their own state commit.
func TestBlockStoreRefusesWritesAfterClose(t *testing.T) {
	db := NewMemDB()
	defer db.Close()
	bs, err := NewBlockStore(t.TempDir(), testMagic, db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bs.WriteBlock([]byte{1, 2, 3}, 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := bs.WriteBlock([]byte{4, 5, 6}, 2, 0); !errors.Is(err, ErrBlockStoreClosed) {
		t.Fatalf("WriteBlock after Close: %v, want ErrBlockStoreClosed", err)
	}
	if _, err := bs.WriteUndo(0, []byte{7}); !errors.Is(err, ErrBlockStoreClosed) {
		t.Fatalf("WriteUndo after Close: %v, want ErrBlockStoreClosed", err)
	}
}

func TestBlockStoreBeginCloseStopsWritesButCloseStillFlushes(t *testing.T) {
	db := NewMemDB()
	defer db.Close()
	bs, err := NewBlockStore(t.TempDir(), testMagic, db)
	if err != nil {
		t.Fatal(err)
	}
	bs.BeginClose()
	if _, err := bs.WriteBlock([]byte{1}, 1, 0); !errors.Is(err, ErrBlockStoreClosed) {
		t.Fatalf("WriteBlock after BeginClose: %v, want ErrBlockStoreClosed", err)
	}
	if err := bs.Close(); err != nil {
		t.Fatalf("Close after BeginClose: %v", err)
	}
}
