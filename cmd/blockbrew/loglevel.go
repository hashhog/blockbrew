package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

// debugCategories is the canonical set of `-debug=<cat>` categories
// blockbrew accepts. Mirrors the BCLog::LogFlags map in
// `bitcoin-core/src/logging.cpp:LOG_CATEGORIES_BY_STR`. Categories that
// are meaningful only inside Bitcoin Core's process model (qt, libevent,
// lock, ipc, walletdb, kernel) are still parsed and accepted as no-ops
// so operator config files copied from a Core install don't error out.
//
// "all" / "1" enables every category (Core: BCLog::ALL).
// "none" / "0" disables every category.
//
// Multiple `-debug=` flags are additive — same as Core. Negative
// categories are accepted with a leading "-": `-debug=-net` removes net.
//
// Mapping to blockbrew's structured logger categories: this is currently
// a soft mapping — blockbrew uses the stdlib `log` package as a single
// stream. The category set is recorded in the global enabled map and
// queried from inside any module that wants to gate verbose output via
// IsDebugEnabled().  Future work: thread an explicit logger handle into
// each subsystem.
var debugCategories = map[string]bool{
	"net":              true,
	"tor":              true,
	"mempool":          true,
	"http":             true,
	"bench":            true,
	"zmq":              true,
	"walletdb":         true,
	"rpc":              true,
	"estimatefee":      true,
	"addrman":          true,
	"selectcoins":      true,
	"reindex":          true,
	"cmpctblock":       true,
	"rand":             true,
	"prune":            true,
	"proxy":            true,
	"mempoolrej":       true,
	"libevent":         true,
	"coindb":           true,
	"qt":               true,
	"leveldb":          true,
	"validation":       true,
	"i2p":              true,
	"ipc":              true,
	"lock":             true,
	"blockstorage":     true,
	"txreconciliation": true,
	"scan":             true,
	"txpackages":       true,
	"kernel":           true,
}

// debugState holds the active set of `-debug` categories.  Protected by
// a mutex so SIGHUP-triggered re-parses don't race with reads.
type debugState struct {
	mu       sync.RWMutex
	enabled  map[string]bool
	all      bool
}

var globalDebug = &debugState{enabled: map[string]bool{}}

// applyDebugCategories parses the user-supplied `-debug` value (which
// may be a comma-separated list, repeated on the CLI, or a single token)
// and updates globalDebug.  Returns the list of category strings it
// actually accepted as known and a list of warnings about unknown ones.
func applyDebugCategories(values []string) (accepted []string, warnings []string) {
	d := globalDebug
	d.mu.Lock()
	defer d.mu.Unlock()

	d.enabled = map[string]bool{}
	d.all = false

	for _, raw := range values {
		for _, tok := range strings.Split(raw, ",") {
			t := strings.TrimSpace(strings.ToLower(tok))
			if t == "" {
				continue
			}
			negate := false
			if strings.HasPrefix(t, "-") {
				negate = true
				t = strings.TrimPrefix(t, "-")
			}
			switch t {
			case "all", "1":
				if negate {
					d.enabled = map[string]bool{}
					d.all = false
				} else {
					d.all = true
				}
				accepted = append(accepted, "all")
				continue
			case "none", "0":
				d.enabled = map[string]bool{}
				d.all = false
				accepted = append(accepted, "none")
				continue
			}
			if !debugCategories[t] {
				warnings = append(warnings, fmt.Sprintf("unknown debug category %q (Bitcoin Core compatible set: net, mempool, validation, rpc, ...)", t))
				continue
			}
			if negate {
				delete(d.enabled, t)
			} else {
				d.enabled[t] = true
			}
			accepted = append(accepted, t)
		}
	}
	return accepted, warnings
}

// IsDebugEnabled reports whether the given category was enabled via -debug.
// Safe for concurrent use. Cheap (one RLock + one map lookup); callers
// inside hot paths should still gate construction of the message string
// (e.g. with a cheap level check).
func IsDebugEnabled(cat string) bool {
	d := globalDebug
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.all {
		return true
	}
	return d.enabled[strings.ToLower(cat)]
}

// debugCategoriesSnapshot returns a sorted slice of currently enabled
// categories, primarily for logging at startup / SIGHUP. Cheap.
func debugCategoriesSnapshot() (categories []string, all bool) {
	d := globalDebug
	d.mu.RLock()
	defer d.mu.RUnlock()
	all = d.all
	for k := range d.enabled {
		categories = append(categories, k)
	}
	return categories, all
}

// ---------------------------------------------------------------------------
// Runtime (RPC-mutable) category control — backs the `logging` RPC.
// ---------------------------------------------------------------------------
//
// The `logging` RPC (Bitcoin Core rpc/node.cpp:218 + logging.cpp Enable/Disable
// Category) reads and MUTATES the running node's per-category debug mask in
// memory, taking effect immediately with no restart. blockbrew already holds
// that live mask in globalDebug (an enabled-set + an `all` bool, mutex-guarded,
// consulted by IsDebugEnabled on EVERY call). The methods below let the RPC
// layer flip individual categories on that SAME live state, so the toggle is
// genuinely live — IsDebugEnabled (and therefore every gated debug log site)
// observes the change on its very next read. This deliberately avoids the
// snapshot trap: the RPC never copies the category set into the logger at
// construction time; it mutates globalDebug, which the logger consults per
// record. (Core: m_categories is the single source of truth the logger checks.)
//
// *debugState satisfies rpc.DebugLogController; main.go injects globalDebug into
// the RPC server via rpc.WithDebugLogController(globalDebug).

// Categories returns the full set of REAL category names blockbrew exposes,
// matching the `-debug=<cat>` set in debugCategories. Order is unspecified
// (the RPC sorts); the special tokens all/1/none/0/"" are NOT real categories
// and are never returned here.
func (d *debugState) Categories() []string {
	out := make([]string, 0, len(debugCategories))
	for k := range debugCategories {
		out = append(out, k)
	}
	return out
}

// IsCategoryActive reports whether the named category is currently being debug
// logged — i.e. exactly what IsDebugEnabled would return for it (honouring the
// `all` mask). The name must be a real category (the RPC validates first).
func (d *debugState) IsCategoryActive(name string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.all {
		return true
	}
	return d.enabled[name]
}

// EnableCategory turns a single real category on. Live: the next IsDebugEnabled
// read sees it. When the `all` mask is active, enabling an individual category
// is a no-op (it is already on) — mirroring Core's bit-set on an all-mask.
func (d *debugState) EnableCategory(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enabled[name] = true
}

// DisableCategory turns a single real category off. Live. If the `all` mask is
// active we must first expand it to the explicit per-category set (every real
// category minus the one being disabled) so that "everything except <cat>" is
// faithfully representable — Core clears one bit out of the ALL mask the same
// way (m_categories &= ~flag). This makes `logging ["all"], ["net"]` report
// every category true EXCEPT net (exclude-wins), exactly as Core does.
func (d *debugState) DisableCategory(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.all {
		d.all = false
		d.enabled = map[string]bool{}
		for k := range debugCategories {
			d.enabled[k] = true
		}
	}
	delete(d.enabled, name)
}

// EnableAll turns every category on (Core: BCLog::ALL). Live.
func (d *debugState) EnableAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.all = true
}

// DisableAll clears every category (Core: DisableCategory of the ALL flag, and
// blockbrew's `-debug=none`/`0`). Live.
func (d *debugState) DisableAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.all = false
	d.enabled = map[string]bool{}
}

// IsKnownCategory reports whether name is one of the real exposed categories
// (NOT a special token). The RPC uses this to raise Core's -8 "unknown logging
// category <cat>" for anything outside the exposed set.
func (d *debugState) IsKnownCategory(name string) bool {
	return debugCategories[name]
}

// logFileHandle wraps the stdlib log package's output sink with a SIGHUP
// reopen mechanism. The default sink is os.Stderr (matching the previous
// behaviour); when -logfile=<path> is provided we open that file and
// route stdlib log output through us.  On SIGHUP the file is closed and
// reopened, so log-rotation utilities can rename/compress the old file
// without losing writes.
//
// Mirrors Bitcoin Core `init.cpp` which calls `LogInstance().StartLogging()`
// on SIGHUP via the file_descriptor watcher in noui.
type logFileHandle struct {
	mu   sync.Mutex
	path string
	file *os.File
	// fallback is where we route writes when path is empty (no logfile),
	// or temporarily during a reopen race. Default os.Stderr.
	fallback io.Writer
}

func newLogFileHandle(path string) (*logFileHandle, error) {
	h := &logFileHandle{path: path, fallback: os.Stderr}
	if path == "" {
		return h, nil
	}
	f, err := openAppend(path)
	if err != nil {
		return nil, err
	}
	h.file = f
	return h, nil
}

// openAppend opens (or creates) the file for append in 0644 mode. Kept
// as a function so tests can substitute it.
var openAppend = func(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
}

// Write satisfies io.Writer so the log package can be retargeted with
// log.SetOutput(h). Routes to the file when one is open; otherwise to
// the fallback stderr.
func (h *logFileHandle) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file != nil {
		return h.file.Write(p)
	}
	return h.fallback.Write(p)
}

// Reopen closes the current file (if any) and opens a fresh handle to
// the same path. Called from the SIGHUP handler; safe to call from
// any goroutine.  Returns nil if no file was configured (effectively a
// no-op). Logs failures using the stdlib logger and falls back to
// stderr to keep us writing somewhere.
func (h *logFileHandle) Reopen() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.path == "" {
		return nil
	}
	if h.file != nil {
		_ = h.file.Close()
		h.file = nil
	}
	f, err := openAppend(h.path)
	if err != nil {
		log.Printf("logfile reopen failed (continuing on stderr): %v", err)
		return err
	}
	h.file = f
	return nil
}

// Close releases the open file handle. Idempotent.
func (h *logFileHandle) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file == nil {
		return nil
	}
	err := h.file.Close()
	h.file = nil
	return err
}
