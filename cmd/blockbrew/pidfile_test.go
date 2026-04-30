package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPidFileWriteRemove(t *testing.T) {
	dir := t.TempDir()
	mgr := newPidFileManager("", dir)
	wantPath := filepath.Join(dir, "blockbrew.pid")
	if mgr.Path() != wantPath {
		t.Errorf("Path()=%q want %q", mgr.Path(), wantPath)
	}
	gotPath, err := mgr.Write()
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if gotPath != wantPath {
		t.Errorf("Write returned %q, want %q", gotPath, wantPath)
	}
	pid, err := readPidFile(gotPath)
	if err != nil {
		t.Fatalf("readPidFile: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("pid=%d, want %d", pid, os.Getpid())
	}
	if err := mgr.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(gotPath); !os.IsNotExist(err) {
		t.Errorf("pid file still exists after Remove: err=%v", err)
	}
	// Idempotent Remove.
	if err := mgr.Remove(); err != nil {
		t.Errorf("second Remove: %v", err)
	}
}

func TestPidFileExplicitPath(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom.pid")
	mgr := newPidFileManager(custom, "/should/be/ignored")
	if mgr.Path() != custom {
		t.Errorf("explicit path ignored: got %q want %q", mgr.Path(), custom)
	}
	if _, err := mgr.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(custom); err != nil {
		t.Errorf("expected file at custom path: %v", err)
	}
}

func TestReadPidFileMalformed(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pid")
	if err := os.WriteFile(bad, []byte("not-a-number\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPidFile(bad); err == nil {
		t.Error("expected parse error")
	}
}

func TestIsProcessAliveSelf(t *testing.T) {
	if !isProcessAlive(os.Getpid()) {
		t.Error("self process should be alive")
	}
	if isProcessAlive(0) {
		t.Error("pid 0 should not be reported alive")
	}
	if isProcessAlive(-1) {
		t.Error("negative pid should not be reported alive")
	}
}
