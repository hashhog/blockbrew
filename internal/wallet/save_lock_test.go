package wallet

import (
	"testing"
	"time"
)

// Gate 5 (testnet4 real-peer repro, 2026-10-02): a goroutine dump taken while
// a SIGTERM was overrunning its deadline showed the block-connect worker in
// Wallet.ScanBlock waiting for w.mu while the 5 s auto-flush sat in
// atomicWriteWallet's fsync/rename holding the read lock. SyncManager.Stop
// waits for that worker, so a slow disk turned into a slow (forced) shutdown.
// The durable write must run WITHOUT the wallet lock.
func TestSaveDoesNotHoldWalletLockDuringWrite(t *testing.T) {
	w := newTestWallet(t)

	entered := make(chan struct{})
	release := make(chan struct{})
	orig := writeWalletFile
	writeWalletFile = func(dataDir string, ciphertext []byte) error {
		close(entered)
		<-release // a write stuck behind a slow fsync
		return orig(dataDir, ciphertext)
	}
	defer func() { writeWalletFile = orig }()

	saved := make(chan error, 1)
	go func() { saved <- w.SaveToFile("") }()

	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("save never reached the file write")
	}

	// What ScanBlock does for every connected block.
	locked := make(chan struct{})
	go func() {
		w.mu.Lock()
		w.mu.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(2 * time.Second):
		close(release)
		<-saved
		t.Fatal("wallet write lock unavailable while the save's file write was blocked: ScanBlock (block connect) waits on wallet I/O")
	}

	close(release)
	if err := <-saved; err != nil {
		t.Fatalf("save: %v", err)
	}
}

// Two saves must not interleave: the second waits for the first to finish
// writing, so an older snapshot can never land after a newer one.
func TestConcurrentSavesAreSerialised(t *testing.T) {
	w := newTestWallet(t)

	var inWrite, maxInWrite int32
	gate := make(chan struct{})
	orig := writeWalletFile
	writeWalletFile = func(dataDir string, ciphertext []byte) error {
		inWrite++
		if inWrite > maxInWrite {
			maxInWrite = inWrite
		}
		<-gate
		inWrite--
		return orig(dataDir, ciphertext)
	}
	defer func() { writeWalletFile = orig }()

	done := make(chan error, 2)
	go func() { done <- w.SaveToFile("") }()
	go func() { done <- w.SaveToFile("") }()
	time.Sleep(500 * time.Millisecond)
	close(gate)
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	if maxInWrite != 1 {
		t.Fatalf("%d saves were inside the file write at once; want 1", maxInWrite)
	}
}
