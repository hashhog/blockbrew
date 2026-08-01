package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The OnTx handler crashed the live mainnet node ~86 times in one day with:
//
//	panic: runtime error: invalid memory address or nil pointer dereference
//	[signal SIGSEGV: code=0x1 addr=0x28]
//	main.run.func7(...)             cmd/blockbrew/main.go:1580
//	p2p.(*Peer).handleMessage       internal/p2p/peer.go:785
//	p2p.(*Peer).readHandler         internal/p2p/peer.go:678
//
// Cause: AcceptToMemoryPool succeeds, then mp.GetEntry(txHash) returns nil
// because another goroutine evicted / RBF-replaced / expired the entry in
// between. The handler correctly guarded the first three uses with
// `if entry != nil`, then dereferenced entry.Fee and entry.Size in a log
// statement placed AFTER the closing brace.
//
// It went unnoticed for a long time because systemd restarts the node in ~15s,
// so fleet monitoring saw "active" and at-tip the whole time. A crash-restart
// loop is invisible to a liveness check.
//
// WHAT THIS TEST IS, HONESTLY: a structural guard over the source, not a
// behavioural test. The handler is a closure built inside run() with ~15 wired
// dependencies (mempool, peer manager, sync manager, fee estimator, ZMQ
// publisher), so exercising it for real means constructing all of them. This
// test instead asserts the shape that made the crash possible cannot return.
// It would NOT catch a nil dereference introduced through a differently-named
// variable — a limitation worth stating rather than papering over.
//
// The repo already uses source-assertion tests for main.go wiring
// (see w124_operator_test.go), so this follows an established convention.

func ontxRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// cmd/blockbrew -> repo root
	return filepath.Dir(filepath.Dir(wd))
}

// ontxHandlerBody returns the source of the syncListeners.OnTx closure.
func ontxHandlerBody(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(ontxRepoRoot(t), "cmd/blockbrew/main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	body := string(src)

	start := strings.Index(body, "syncListeners.OnTx = func(")
	if start < 0 {
		t.Fatal("could not locate `syncListeners.OnTx = func(` in main.go — " +
			"the handler moved or was renamed; re-anchor this test rather than deleting it")
	}
	// The closure ends at the first line that is exactly "\t}" — one tab then
	// brace — which is the closing brace of the assignment at this nesting.
	rest := body[start:]
	end := strings.Index(rest, "\n\t}\n")
	if end < 0 {
		t.Fatal("could not find the end of the OnTx closure")
	}
	return rest[:end]
}

// TestOnTxNeverDereferencesEntryOutsideNilGuard is the regression pin.
//
// Discriminator: reverting the fix (moving the log.Printf that uses entry.Fee /
// entry.Size back below the `if entry != nil` block) puts an `entry.` reference
// at brace depth 1 and fails this test.
func TestOnTxNeverDereferencesEntryOutsideNilGuard(t *testing.T) {
	handler := ontxHandlerBody(t)

	// Track brace depth relative to the closure body. `entry` is only safe to
	// dereference inside the `if entry != nil {` block, i.e. at depth >= 1.
	depth := 0
	inGuard := false
	guardDepth := -1

	deref := regexp.MustCompile(`\bentry\.[A-Za-z]`)

	for i, raw := range strings.Split(handler, "\n") {
		line := raw
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = line[:idx] // ignore comments (this file's own header quotes entry.Fee)
		}
		trimmed := strings.TrimSpace(line)

		// Entering the nil guard?
		if strings.HasPrefix(trimmed, "if entry != nil") {
			inGuard = true
			guardDepth = depth
		}

		if deref.MatchString(line) && !inGuard {
			t.Errorf("main.go OnTx handler line %d dereferences `entry` OUTSIDE the "+
				"`if entry != nil` guard:\n\t%s\n\n"+
				"mp.GetEntry can return nil for a transaction that was just accepted "+
				"(evicted / RBF-replaced / expired between accept and readback). "+
				"This exact shape crashed the mainnet node ~86 times in one day. "+
				"Move the statement inside the guard.", i+1, trimmed)
		}

		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if inGuard && depth <= guardDepth {
			inGuard = false
		}
	}
}

// TestOnTxHandlesNilEntryExplicitly asserts the nil case is handled rather than
// silently skipped — an accepted-then-evicted transaction is worth a log line,
// and a high rate of them is a real signal that the mempool is thrashing.
func TestOnTxHandlesNilEntryExplicitly(t *testing.T) {
	handler := ontxHandlerBody(t)
	if !strings.Contains(handler, "evicted before readback") {
		t.Error("OnTx no longer logs the accepted-but-evicted case. If this was " +
			"removed deliberately, replace this assertion with whatever now marks " +
			"that path — do not leave it silent, because the rate of it is the " +
			"symptom that led here.")
	}
}
