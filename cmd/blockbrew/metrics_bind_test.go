package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Security audit 2026-10-30 H3: the Prometheus listener was hard-bound to
// 0.0.0.0, had no bind flag and served with a bare http.ListenAndServe (no
// timeouts), so anyone who could route to the port could hold fds and
// goroutines forever with half-sent requests.
//
// These tests boot the real node (main()) on regtest in a child copy of the
// test binary, because the metrics server is started from run() and main()
// parses the global flag.CommandLine. The parent observes the listener from
// outside, the way an attacker would.

const metricsBindChildEnv = "BLOCKBREW_METRICSBIND_CHILD_ARGS"

func TestMetricsBindNodeChild(t *testing.T) {
	raw := os.Getenv(metricsBindChildEnv)
	if raw == "" {
		t.Skip("helper for the TestMetricsServer_* tests")
	}
	os.Args = append([]string{"blockbrew"}, strings.Split(raw, "\x1f")...)
	flag.CommandLine = flag.NewFlagSet("blockbrew", flag.ExitOnError)
	main()
	os.Exit(0)
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// lockedBuffer collects the child's output while it is still running.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type metricsNode struct {
	cmd    *exec.Cmd
	out    *lockedBuffer
	port   int
	exited chan struct{}
}

// startMetricsNode boots a scratch regtest node whose metrics server listens
// on a fresh port, with every other listener on loopback and no peers.
func startMetricsNode(t *testing.T, extra ...string) *metricsNode {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("reads listening sockets from /proc/net/tcp*")
	}
	n := &metricsNode{out: &lockedBuffer{}, port: freeTCPPort(t), exited: make(chan struct{})}
	args := []string{
		"-network=regtest",
		"-datadir=" + t.TempDir(),
		fmt.Sprintf("-listen=127.0.0.1:%d", freeTCPPort(t)),
		fmt.Sprintf("-rpcbind=127.0.0.1:%d", freeTCPPort(t)),
		fmt.Sprintf("-metricsport=%d", n.port),
		"-nodnsseed",
		"-fixedseeds=0",
		"-maxoutbound=0",
		"-dbcache=16",
	}
	args = append(args, extra...)
	n.cmd = exec.Command(os.Args[0], "-test.run=^TestMetricsBindNodeChild$")
	n.cmd.Env = append(os.Environ(), metricsBindChildEnv+"="+strings.Join(args, "\x1f"))
	n.cmd.Stdout, n.cmd.Stderr = n.out, n.out
	if err := n.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { n.cmd.Wait(); close(n.exited) }()
	t.Cleanup(func() {
		n.cmd.Process.Kill()
		<-n.exited
		if t.Failed() {
			t.Logf("node output:\n%s", n.out.String())
		}
	})
	return n
}

// listenAddrs returns the local addresses of every LISTEN socket on port,
// from /proc/net/tcp and /proc/net/tcp6 (state 0A).
func listenAddrs(t *testing.T, port int) []net.IP {
	t.Helper()
	var ips []net.IP
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Scan() // header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			hostPort := strings.SplitN(fields[1], ":", 2)
			p, err := strconv.ParseUint(hostPort[1], 16, 16)
			if err != nil || int(p) != port {
				continue
			}
			raw, err := hex.DecodeString(hostPort[0])
			if err != nil {
				continue
			}
			// The kernel prints each 32-bit word in host (little-endian) order.
			ip := make(net.IP, len(raw))
			for i := 0; i+4 <= len(raw); i += 4 {
				ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
			}
			ips = append(ips, ip)
		}
	}
	return ips
}

// waitListening waits until something listens on the node's metrics port.
func (n *metricsNode) waitListening(t *testing.T) []net.IP {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if ips := listenAddrs(t, n.port); len(ips) > 0 {
			return ips
		}
		select {
		case <-n.exited:
			t.Fatalf("node exited before the metrics port %d was listening", n.port)
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("metrics port %d never started listening", n.port)
	return nil
}

func TestMetricsServer_BindsLoopbackByDefault(t *testing.T) {
	n := startMetricsNode(t)
	for _, ip := range n.waitListening(t) {
		if !ip.IsLoopback() {
			t.Errorf("metrics listener on port %d is bound to %s; want loopback by default", n.port, ip)
		}
	}
}

func TestMetricsServer_MetricsBindFlag(t *testing.T) {
	n := startMetricsNode(t, "-metricsbind=127.0.0.2")
	ips := n.waitListening(t)
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.2")) {
		t.Fatalf("metrics listener bound to %v; want exactly 127.0.0.2 from -metricsbind", ips)
	}
}

// A client that sends part of a request header and then goes silent must be
// dropped by the server's header timeout, not held forever.
func TestMetricsServer_HalfSentRequestClosed(t *testing.T) {
	n := startMetricsNode(t)
	n.waitListening(t)
	addr := fmt.Sprintf("127.0.0.1:%d", n.port)

	// The listener works: a complete request is answered.
	ok, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(ok, "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	ok.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(ok).ReadString('\n')
	ok.Close()
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("full request: status line %q, err %v; want HTTP/1.1 200", line, err)
	}

	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("GET /metrics HTTP/1.1\r\nHost: x\r\n")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	limit := 15 * time.Second
	c.SetReadDeadline(start.Add(limit))
	buf := make([]byte, 512)
	for {
		_, err := c.Read(buf)
		if err == nil {
			continue // e.g. a 408 before close
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("half-sent request still open after %v; want the server to close it", limit)
		}
		t.Logf("half-sent request closed by server after %v (%v)", time.Since(start).Round(time.Millisecond), err)
		return
	}
}
