package wallet

import (
	"log"
	"time"
)

// This file implements the wallet's save-on-mutation durability layer (the
// DATA-LOSS fix, sweep wa0fq5wtk). The legacy wallet previously persisted only
// at clean shutdown + backupwallet, so a SIGKILL/OOM/power-loss lost every
// mutation since the last clean exit. We mirror Bitcoin Core's CWallet, which
// flushes to its BerkeleyBatch on every state change: every mutating method now
// marks the wallet dirty, and a background goroutine durably writes the dirty
// wallet at a short interval. Combined with the atomic+durable SaveToFile and
// fault-tolerant LoadFromFile in storage.go, this guarantees an unclean restart
// recovers all but at most the last autoFlushInterval of mutations.

// markDirtyLocked records that the wallet has unpersisted mutations. The caller
// MUST hold w.mu (read or write — it only sets a bool). It is a no-op-cheap
// signal consumed by the background flusher; it never performs I/O itself, so
// it is safe to call from inside any locked mutation path (including ScanBlock,
// which holds the write lock).
func (w *Wallet) markDirtyLocked() {
	w.dirty = true
}

// MarkDirty is the exported, lock-taking variant for callers that mutate the
// wallet through an exported method that does not already flag dirty (e.g. the
// RPC layer after a higher-level operation). Idempotent.
func (w *Wallet) MarkDirty() {
	w.mu.Lock()
	w.dirty = true
	w.mu.Unlock()
}

// SetSavePassword sets the password the auto-flush + Flush path encrypts the
// wallet with. The legacy unencrypted wallet uses "" (the historical behaviour
// of SaveToFile(\"\")); encryptwallet wires the user passphrase through here so
// subsequent auto-flushes stay encrypted. Marks dirty so the new on-disk form
// is written promptly.
func (w *Wallet) SetSavePassword(password string) {
	w.mu.Lock()
	w.savePassword = password
	w.dirty = true
	w.mu.Unlock()
}

// LastSyncedHeight returns the active-chain height the wallet's UTXO ledger has
// been scanned through. Used by the startup reconcile to bound the rescan gap.
func (w *Wallet) LastSyncedHeight() int32 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.lastSyncedHeight
}

// SetLastSyncedHeight records the height the wallet has been scanned to. Called
// by the startup reconcile after it brings the ledger up to the chain tip.
// Monotonic: never lowers the cursor (a reorg disconnect is handled by
// UnscanBlock, not by rewinding this cursor below the surviving tip).
func (w *Wallet) SetLastSyncedHeight(height int32) {
	w.mu.Lock()
	if height > w.lastSyncedHeight {
		w.lastSyncedHeight = height
		w.dirty = true
	}
	w.mu.Unlock()
}

// Flush persists the wallet to disk now if it has unsaved mutations, using the
// configured save password. It is safe to call concurrently with mutations
// (SaveToFile takes the read lock). The dirty flag is cleared optimistically
// before the write and re-set on failure so a transient I/O error is retried on
// the next tick rather than silently dropped.
func (w *Wallet) Flush() error {
	w.mu.Lock()
	if !w.dirty {
		w.mu.Unlock()
		return nil
	}
	w.dirty = false
	pw := w.savePassword
	w.mu.Unlock()

	if err := w.SaveToFile(pw); err != nil {
		// Re-arm dirty so the next tick retries; don't lose the signal.
		w.mu.Lock()
		w.dirty = true
		w.mu.Unlock()
		return err
	}
	return nil
}

// StartAutoFlush launches the background flusher. interval <= 0 falls back to
// DefaultAutoFlushInterval. Idempotent: a second call while already running is a
// no-op. The flusher writes the wallet whenever it is dirty, and does a final
// flush when StopAutoFlush is called so a graceful shutdown loses nothing.
func (w *Wallet) StartAutoFlush(interval time.Duration) {
	if interval <= 0 {
		interval = DefaultAutoFlushInterval
	}
	w.mu.Lock()
	if w.autoFlushOn {
		w.mu.Unlock()
		return
	}
	w.autoFlushOn = true
	w.flushInterval = interval
	w.flushStop = make(chan struct{})
	w.flushDone = make(chan struct{})
	stop := w.flushStop
	done := w.flushDone
	w.mu.Unlock()

	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := w.Flush(); err != nil {
					log.Printf("wallet auto-flush: %v", err)
				}
			case <-stop:
				// Final drain on shutdown so a clean stop is durable.
				if err := w.Flush(); err != nil {
					log.Printf("wallet auto-flush (final): %v", err)
				}
				return
			}
		}
	}()
}

// StopAutoFlush signals the background flusher to do a final flush and exit,
// blocking until it has. Idempotent and safe to call even if StartAutoFlush was
// never called.
func (w *Wallet) StopAutoFlush() {
	w.mu.Lock()
	if !w.autoFlushOn {
		w.mu.Unlock()
		return
	}
	w.autoFlushOn = false
	stop := w.flushStop
	done := w.flushDone
	w.flushStop = nil
	w.flushDone = nil
	w.mu.Unlock()

	close(stop)
	<-done
}
