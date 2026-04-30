package main

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSdNotifyUnsetSocket(t *testing.T) {
	old := os.Getenv("NOTIFY_SOCKET")
	os.Unsetenv("NOTIFY_SOCKET")
	defer os.Setenv("NOTIFY_SOCKET", old)
	ok, err := sdNotify("READY=1\n")
	if err != nil {
		t.Errorf("expected no error when NOTIFY_SOCKET unset, got %v", err)
	}
	if ok {
		t.Error("expected ok=false when NOTIFY_SOCKET unset")
	}
}

func TestSdNotifyDeliversPayload(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "n.sock")
	addr := &net.UnixAddr{Net: "unixgram", Name: sock}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer conn.Close()
	defer os.Remove(sock)

	old := os.Getenv("NOTIFY_SOCKET")
	os.Setenv("NOTIFY_SOCKET", sock)
	defer os.Setenv("NOTIFY_SOCKET", old)

	var (
		wg   sync.WaitGroup
		buf  = make([]byte, 1024)
		n    int
		rerr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, rerr = conn.ReadFromUnix(buf)
	}()

	ok, err := sdNotify("READY=1\nSTATUS=ok\n")
	if err != nil {
		t.Fatalf("sdNotify: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	wg.Wait()
	if rerr != nil {
		t.Fatalf("ReadFromUnix: %v", rerr)
	}
	got := string(buf[:n])
	if got != "READY=1\nSTATUS=ok\n" {
		t.Errorf("payload mismatch: got %q", got)
	}
}

func TestWatchdogIntervalParse(t *testing.T) {
	cases := []struct {
		env  string
		want time.Duration
	}{
		{"", 0},
		{"abc", 0},
		{"0", 0},
		{"-1000", 0},
		{"2000000", time.Microsecond * 1_000_000}, // half of 2s = 1s
	}
	for _, c := range cases {
		t.Run(c.env, func(t *testing.T) {
			old := os.Getenv("WATCHDOG_USEC")
			defer os.Setenv("WATCHDOG_USEC", old)
			os.Setenv("WATCHDOG_USEC", c.env)
			got := watchdogInterval()
			if got != c.want {
				t.Errorf("watchdogInterval() = %v, want %v", got, c.want)
			}
		})
	}
}
