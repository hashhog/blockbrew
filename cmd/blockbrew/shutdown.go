package main

import (
	"sync"
	"time"
)

// forcedCloseBudget bounds how long a FORCED exit (deadline watchdog, second
// signal) may spend on its best-effort DB close before exiting anyway.
//
// Pebble's Close waits for every running compaction and flush and takes the
// commit-pipeline lock, so on a busy mainnet datadir it can take minutes. On
// 2026-10-02 the watchdog's unbounded db.Close() was still running at
// stop_mainnet.sh's 120 s grace and the node was SIGKILLed: the forced exit
// never exited. Exiting without Close is crash-safe — every chainstate batch is
// written with Sync, so the WAL already holds it — which is the same guarantee a
// SIGKILL relies on, minus the SIGKILL.
const forcedCloseBudget = 10 * time.Second

// closeWithin runs closeFn on its own goroutine and waits at most budget for it.
// finished reports whether it returned in time; if not, its error is unknown
// and closeFn keeps running in the background (the caller is about to exit).
func closeWithin(closeFn func() error, budget time.Duration) (err error, finished bool) {
	done := make(chan error, 1)
	go func() { done <- closeFn() }()
	t := time.NewTimer(budget)
	defer t.Stop()
	select {
	case err = <-done:
		return err, true
	case <-t.C:
		return nil, false
	}
}

// runConcurrently runs every fn on its own goroutine and waits for all of them.
// The auxiliary shutdown saves (fee estimates, mempool.dat, wallet) touch only
// their own files, and each one fsyncs; run one after another they took 2 + 16
// + 20 s on mainnet under load (2026-10-02), on their own longer than the whole
// shutdown deadline.
func runConcurrently(fns ...func()) {
	var wg sync.WaitGroup
	for _, fn := range fns {
		wg.Add(1)
		go func(f func()) {
			defer wg.Done()
			f()
		}(fn)
	}
	wg.Wait()
}
