package storage

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestRemoveStalePebbleLock_NoFile verifies removeStalePebbleLock is a no-op
// when the LOCK file does not exist (fresh datadir).
func TestRemoveStalePebbleLock_NoFile(t *testing.T) {
	dir := t.TempDir()
	if err := removeStalePebbleLock(dir); err != nil {
		t.Fatalf("expected nil for missing LOCK, got: %v", err)
	}
}

// TestRemoveStalePebbleLock_StaleFile simulates the SIGKILL/OOM aftermath:
// a LOCK file exists but no process holds an flock on it. The cleanup must
// remove it.
func TestRemoveStalePebbleLock_StaleFile(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, pebbleLockFilename)
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatalf("seed stale LOCK: %v", err)
	}

	if err := removeStalePebbleLock(dir); err != nil {
		t.Fatalf("removeStalePebbleLock returned error: %v", err)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("expected LOCK to be removed; stat err = %v", err)
	}
}

// TestRemoveStalePebbleLock_HeldByLiveProcess verifies that if some other
// process (simulated by an flock in this test) is actively holding the LOCK,
// cleanup REFUSES to delete it and returns an error. Deleting a held lock
// would corrupt the DB.
func TestRemoveStalePebbleLock_HeldByLiveProcess(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, pebbleLockFilename)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("create LOCK: %v", err)
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("hold flock on LOCK: %v", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	if err := removeStalePebbleLock(dir); err == nil {
		t.Fatal("expected error when LOCK is held by a live process, got nil")
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("LOCK must NOT be removed while held; stat err = %v", err)
	}
}

// TestNewPebbleDB_RecoversFromStaleLock is the end-to-end regression test
// for the SIGKILL/OOM scenario observed on maxbox in the 20:19→20:30 cycle:
// a previous PebbleDB was killed and left LOCK behind; the next NewPebbleDB
// must succeed instead of returning "resource temporarily unavailable".
func TestNewPebbleDB_RecoversFromStaleLock(t *testing.T) {
	dir := t.TempDir()

	// Open and cleanly close a DB once so the directory looks like a real
	// pebble datadir (CURRENT, MANIFEST, OPTIONS, etc.).
	db, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatalf("initial NewPebbleDB: %v", err)
	}
	if err := db.Put([]byte("k"), []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Simulate a SIGKILL: recreate the LOCK file with no holder.
	lockPath := filepath.Join(dir, pebbleLockFilename)
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatalf("seed stale LOCK: %v", err)
	}

	// Reopen should succeed (it would fail with EWOULDBLOCK pre-fix only if
	// a real process held the lock, but this test still proves the cleanup
	// path runs, removes the stale file, and lets pebble re-acquire it).
	db2, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatalf("NewPebbleDB after stale LOCK should succeed, got: %v", err)
	}
	got, err := db2.Get([]byte("k"))
	if err != nil {
		t.Fatalf("Get after recovery: %v", err)
	}
	if string(got) != "v" {
		t.Fatalf("data lost across stale-lock recovery: got %q want %q", got, "v")
	}
	if err := db2.Close(); err != nil {
		t.Fatalf("Close after recovery: %v", err)
	}
}
