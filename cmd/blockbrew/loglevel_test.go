package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyDebugCategoriesBasic(t *testing.T) {
	defer resetGlobalDebug()
	accepted, warnings := applyDebugCategories([]string{"net,mempool", "rpc"})
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	for _, want := range []string{"net", "mempool", "rpc"} {
		if !contains(accepted, want) {
			t.Errorf("category %q not accepted (got %v)", want, accepted)
		}
	}
	if !IsDebugEnabled("net") || !IsDebugEnabled("mempool") || !IsDebugEnabled("rpc") {
		t.Error("expected categories enabled")
	}
	if IsDebugEnabled("validation") {
		t.Error("did not enable validation")
	}
}

func TestApplyDebugCategoriesAll(t *testing.T) {
	defer resetGlobalDebug()
	applyDebugCategories([]string{"all"})
	if !IsDebugEnabled("net") || !IsDebugEnabled("validation") || !IsDebugEnabled("zmq") {
		t.Error("`all` should enable every category")
	}
}

func TestApplyDebugCategoriesNoneAndNegate(t *testing.T) {
	defer resetGlobalDebug()
	applyDebugCategories([]string{"all"})
	applyDebugCategories([]string{"none"})
	if IsDebugEnabled("net") {
		t.Error("`none` should clear")
	}
	applyDebugCategories([]string{"net,mempool", "-net"})
	if IsDebugEnabled("net") {
		t.Error("`-net` should remove net")
	}
	if !IsDebugEnabled("mempool") {
		t.Error("mempool should remain enabled")
	}
}

func TestApplyDebugCategoriesUnknownWarns(t *testing.T) {
	defer resetGlobalDebug()
	_, warnings := applyDebugCategories([]string{"unknown_thing"})
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
}

func TestLogFileHandleWriteAndReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logfile.log")
	h, err := newLogFileHandle(path)
	if err != nil {
		t.Fatalf("newLogFileHandle: %v", err)
	}
	defer h.Close()

	if _, err := h.Write([]byte("first\n")); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	// Simulate logrotate: rename the live file out from under us.
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := h.Reopen(); err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	if _, err := h.Write([]byte("second\n")); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	a, err := os.ReadFile(rotated)
	if err != nil {
		t.Fatalf("read rotated: %v", err)
	}
	if !strings.Contains(string(a), "first") {
		t.Errorf("rotated file missing first write: %q", a)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read new file: %v", err)
	}
	if !strings.Contains(string(b), "second") {
		t.Errorf("new file missing second write: %q", b)
	}
	if strings.Contains(string(b), "first") {
		t.Errorf("new file should not contain first write: %q", b)
	}
}

func TestLogFileHandleEmptyPathFallback(t *testing.T) {
	h, err := newLogFileHandle("")
	if err != nil {
		t.Fatalf("newLogFileHandle: %v", err)
	}
	if h.path != "" {
		t.Error("expected empty path")
	}
	if err := h.Reopen(); err != nil {
		t.Errorf("Reopen on empty handle should be no-op: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Errorf("Close on empty handle should be no-op: %v", err)
	}
}

// resetGlobalDebug clears the package-level debug state so tests don't
// leak into each other when run in sequence.
func resetGlobalDebug() {
	globalDebug.mu.Lock()
	globalDebug.enabled = map[string]bool{}
	globalDebug.all = false
	globalDebug.mu.Unlock()
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
