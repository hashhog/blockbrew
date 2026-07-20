package storage

import "testing"

// TestPebbleFlushPersistsAndReadable verifies PebbleDB.Flush() issues a
// synchronous memtable flush without error and that written data survives it.
// This backs the flushchainstate RPC used by stop_mainnet.sh to shrink the
// memtable before a graceful stop (receipts/GEN-BREW-pebble-corruption-sigkill).
func TestPebbleFlushPersistsAndReadable(t *testing.T) {
	dir := t.TempDir()
	db, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatalf("NewPebbleDB: %v", err)
	}
	defer db.Close()

	if err := db.Put([]byte("k1"), []byte("v1")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// A second flush with nothing new pending must also be a clean no-op.
	if err := db.Flush(); err != nil {
		t.Fatalf("second Flush: %v", err)
	}
	got, err := db.Get([]byte("k1"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "v1" {
		t.Fatalf("Get after Flush = %q, want v1", got)
	}
}

// TestChainDBFlushDelegates verifies ChainDB.Flush() delegates to the backend
// and that the in-memory backend's Flush is a clean no-op.
func TestChainDBFlushDelegates(t *testing.T) {
	cdb := NewChainDB(NewMemDB())
	if err := cdb.Flush(); err != nil {
		t.Fatalf("ChainDB.Flush (memdb) = %v, want nil", err)
	}
}
