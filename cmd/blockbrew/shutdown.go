package main

import (
	"log"
	"runtime"
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
	return closeWithinObserved(closeFn, budget, 0, func(string) {})
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

// closeMargin is what the graceful DB close leaves before shutdownDeadline for
// the rest of the sequence (ZMQ stop, pid file).
const closeMargin = 5 * time.Second

// slowCloseDumpAfter is when a DB close that is still running gets its
// goroutine stacks written to the log once, even if it then finishes inside
// its budget (a close that takes 30 s and succeeds is still worth knowing
// about).
const slowCloseDumpAfter = 15 * time.Second

// closeStatusReporter is implemented by storage.PebbleDB.
type closeStatusReporter interface{ CloseStatus() string }

// closeWithinObserved is closeWithin plus diagnostics: if closeFn is still
// running after slowAfter (0 = never) it calls report("slow") once, and if the
// budget expires it calls report("expired") before returning. It changes
// nothing about how long it waits.
func closeWithinObserved(closeFn func() error, budget, slowAfter time.Duration, report func(why string)) (err error, finished bool) {
	done := make(chan error, 1)
	go func() { done <- closeFn() }()
	t := time.NewTimer(budget)
	defer t.Stop()
	var slow <-chan time.Time
	if slowAfter > 0 && slowAfter < budget {
		st := time.NewTimer(slowAfter)
		defer st.Stop()
		slow = st.C
	}
	for {
		select {
		case err = <-done:
			return err, true
		case <-slow:
			slow = nil
			report("slow")
		case <-t.C:
			report("expired")
			return nil, false
		}
	}
}

// logDBCloseDiagnostics writes where a DB close is waiting (the step it is in,
// pebble's background work, in-flight fsyncs) and every goroutine's stack to
// the log, so a close that overruns says what it waited on.
func logDBCloseDiagnostics(db any, why string, after time.Duration) {
	if r, ok := db.(closeStatusReporter); ok {
		log.Printf("DB close %s after %s: %s", why, after.Round(time.Millisecond), r.CloseStatus())
	}
	stacks := goroutineStacks()
	log.Printf("DB close %s: goroutine dump (%d bytes) follows\n%s\n--- end of goroutine dump", why, len(stacks), stacks)
}

// goroutineStacks returns every goroutine's stack (runtime.Stack, all=true),
// growing the buffer up to 64 MiB.
func goroutineStacks() []byte {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) || len(buf) >= 64<<20 {
			return buf[:n]
		}
		buf = make([]byte, 2*len(buf))
	}
}
