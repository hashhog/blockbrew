package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// pidFileManager owns the on-disk PID file. Mirrors Bitcoin Core's
// `init/common.cpp:CreatePidFile` / `RemovePidFile` semantics:
//
//   - Path defaults to <datadir>/blockbrew.pid (Core: bitcoind.pid).
//   - The file contains a single ASCII decimal PID followed by a newline.
//   - Stale PID files (process no longer running, or running but with a
//     different binary path on /proc) are silently overwritten — never
//     refuse to start because of a leftover file. Refusing to start is
//     `start_mainnet.sh`'s job (it checks the listening socket).
//   - On graceful shutdown the file is removed. SIGKILL leaves it
//     behind; that's expected.
type pidFileManager struct {
	path    string
	written bool
}

// newPidFileManager resolves the effective pid-file path. If `explicit`
// is non-empty it is used verbatim (interpreted as relative to the cwd
// if not absolute), matching Core's `-pid=<file>` behaviour. Otherwise
// the default `<datadir>/blockbrew.pid` is used.
func newPidFileManager(explicit, datadir string) *pidFileManager {
	path := explicit
	if path == "" {
		path = filepath.Join(datadir, "blockbrew.pid")
	}
	return &pidFileManager{path: path}
}

// Path returns the resolved pid-file path, useful for logging.
func (m *pidFileManager) Path() string { return m.path }

// Write writes the current process's PID to the file, creating it 0644
// (matching Core). Any pre-existing file is overwritten.  Returns the
// path written to and any error.
func (m *pidFileManager) Write() (string, error) {
	pid := os.Getpid()
	body := strconv.Itoa(pid) + "\n"
	if err := os.WriteFile(m.path, []byte(body), 0644); err != nil {
		return m.path, fmt.Errorf("write pid file: %w", err)
	}
	m.written = true
	return m.path, nil
}

// Remove deletes the pid file if Write succeeded earlier. Errors are
// returned but are typically informational (e.g. file already removed
// by a sibling process). Idempotent — second call is a no-op.
func (m *pidFileManager) Remove() error {
	if !m.written {
		return nil
	}
	m.written = false
	if err := os.Remove(m.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove pid file: %w", err)
	}
	return nil
}

// readPidFile reads and parses an existing pid file, returning the PID
// or an error if the file is missing or malformed. Used by tests and by
// the daemon parent to verify the child actually wrote one.
func readPidFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("malformed pid file %s: %v", path, err)
	}
	return pid, nil
}

// isProcessAlive returns true if a process with the given PID exists.
// Used for the "stale pid file" hueristic in tests; not currently called
// from the launch path because we always overwrite. Kept here so the
// helper is one place.
func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, signal 0 is the standard "is the process alive?" probe.
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	return true
}
