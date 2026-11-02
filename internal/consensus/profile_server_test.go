package consensus

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// Security audit 2026-10-30 M2 / H3 item 2: the pprof server used a bare
// http.ListenAndServe on http.DefaultServeMux with no timeouts, so a client
// that half-sends a request holds a connection and goroutine forever.

func startTestProfileServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	StartProfileServer(addr)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pprof server on %s never came up", addr)
	return ""
}

func TestProfileServer_ServesPprofIndex(t *testing.T) {
	addr := startTestProfileServer(t)
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET /debug/pprof/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("GET /debug/pprof/: status line %q, err %v; want HTTP/1.1 200", line, err)
	}
}

func TestProfileServer_HalfSentRequestClosed(t *testing.T) {
	addr := startTestProfileServer(t)
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("GET /debug/pprof/ HTTP/1.1\r\nHost: x\r\n")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	limit := 15 * time.Second
	c.SetReadDeadline(start.Add(limit))
	buf := make([]byte, 512)
	for {
		_, err := c.Read(buf)
		if err == nil {
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("half-sent request still open after %v; want the server to close it", limit)
		}
		t.Logf("half-sent request closed by server after %v (%v)", time.Since(start).Round(time.Millisecond), err)
		return
	}
}
