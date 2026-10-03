package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Gate 5: a SIGTERM on mainnet (2026-10-02) logged "shutdown deadline (30s)
// exceeded, forcing exit" and the process was STILL alive at stop_mainnet.sh's
// 120 s grace -> SIGKILL. The forced exit's db.Close() was unbounded.

func TestCloseWithinBoundsABlockedClose(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	blocked := func() error { <-release; return nil } // a Close that never finishes

	t0 := time.Now()
	_, finished := closeWithin(blocked, 200*time.Millisecond)
	if finished {
		t.Fatal("closeWithin reported a blocked close as finished")
	}
	if took := time.Since(t0); took > 2*time.Second {
		t.Fatalf("closeWithin waited %s on a blocked close; budget was 200ms", took)
	}

	want := errors.New("close failed")
	err, finished := closeWithin(func() error { return want }, time.Second)
	if !finished || err != want {
		t.Fatalf("fast close: err=%v finished=%v, want %v true", err, finished, want)
	}
}

func TestRunConcurrentlyOverlapsTheSaves(t *testing.T) {
	var a, b, c bool
	t0 := time.Now()
	runConcurrently(
		func() { time.Sleep(300 * time.Millisecond); a = true },
		func() { time.Sleep(300 * time.Millisecond); b = true },
		func() { time.Sleep(300 * time.Millisecond); c = true },
	)
	took := time.Since(t0)
	if !a || !b || !c {
		t.Fatal("runConcurrently returned before every fn finished")
	}
	if took > 750*time.Millisecond {
		t.Fatalf("three 300ms saves took %s: they ran one after another", took)
	}
}

// main's signal/watchdog path is not unit-reachable, so pin its shape: the
// forced exit closes the DB only through the bounded helper, the deadline plus
// that budget fits inside stop_mainnet.sh's blockbrew grace, and the auxiliary
// saves no longer run serially in front of the chainstate flush.
func TestShutdownFitsInsideTheStopGrace(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(w124RepoRoot(t), "cmd/blockbrew/main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(body)

	fe := strings.Index(src, "forceExit := func() {")
	if fe < 0 {
		t.Fatal("forceExit helper missing")
	}
	feBody := src[fe : fe+strings.Index(src[fe:], "\n\t}\n")]
	if !strings.Contains(feBody, "closeWithin(db.Close, forcedCloseBudget)") {
		t.Fatalf("forced exit does not bound its DB close:\n%s", feBody)
	}
	if strings.Contains(feBody, "= db.Close()") {
		t.Fatalf("forced exit still makes an unbounded db.Close():\n%s", feBody)
	}

	m := regexp.MustCompile(`const shutdownDeadline = (\d+) \* time\.Second`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("shutdownDeadline constant not found")
	}
	deadline, _ := strconv.Atoi(m[1])
	const stopMainnetGrace = 120 // tools/stop_mainnet.sh GRACE_SEC for blockbrew
	const systemdDefaultStop = 90
	worst := time.Duration(deadline)*time.Second + forcedCloseBudget
	if worst >= stopMainnetGrace*time.Second {
		t.Fatalf("worst-case exit %s is not inside the %ds stop grace", worst, stopMainnetGrace)
	}
	if time.Duration(deadline)*time.Second >= systemdDefaultStop*time.Second {
		t.Fatalf("shutdownDeadline %ds is not inside systemd's default %ds TimeoutStopSec", deadline, systemdDefaultStop)
	}

	lock := strings.Index(src, "dbFinalMu.Lock()")
	flush := strings.Index(src, "utxoSet.FlushBatch(shutBatch)")
	aux := strings.Index(src, "runConcurrently(")
	dump := strings.Index(src, "mp.Dump(cfg.DataDir)")
	wait := strings.Index(src, "<-auxDone")
	if aux < 0 || dump < aux || dump > lock {
		t.Fatalf("mempool.dat dump is not inside the concurrent aux saves (aux=%d dump=%d lock=%d)", aux, dump, lock)
	}
	if wait < flush {
		t.Fatalf("shutdown waits for the aux saves before the chainstate flush (wait=%d flush=%d)", wait, flush)
	}
}

// The graceful path's pebble Close is what blew the 80s deadline on mainnet
// (30s at 20:08Z, still running at 51s at 23:31Z → "exit (forced)"). It must
// be CloseForShutdown, and the budget must be the time still left before
// shutdownDeadline so the close itself cannot trip the watchdog.
func TestGracefulCloseCannotOutliveTheShutdownDeadline(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(w124RepoRoot(t), "cmd/blockbrew/main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(body)
	if !strings.Contains(src, "shutdownStart := time.Now()") {
		t.Fatal("shutdown does not record when the deadline started")
	}
	closeLog := strings.Index(src, `log.Printf("closing DB")`)
	if closeLog < 0 {
		t.Fatal(`log "closing DB" not found`)
	}
	// The first zmqPub.Stop is the startup-failure path, above this log.
	zmqRel := strings.Index(src[closeLog:], "zmqPub.Stop()")
	if zmqRel < 0 {
		t.Fatal("no zmqPub.Stop() after the DB close")
	}
	span := src[closeLog : closeLog+zmqRel]
	if !strings.Contains(span, "db.CloseForShutdown(") {
		t.Fatal("graceful shutdown does not bound the DB close; unbounded pebble Close waits for compactions")
	}
	if strings.Contains(span, "db.Close()") {
		t.Fatalf("graceful path still calls unbounded db.Close():\n%s", span)
	}
	if !strings.Contains(span, "shutdownDeadline - time.Since(shutdownStart)") {
		t.Fatal("close budget is not clamped to the time remaining before shutdownDeadline")
	}
}
