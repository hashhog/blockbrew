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
