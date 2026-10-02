package rpc

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
)

// Gate 5 (clean stop inside stop_mainnet.sh's grace). On mainnet 2026-10-02 a
// SIGTERM logged "RPC server stop error: context deadline exceeded": Stop's
// http.Server.Shutdown waited its full 5 s for a request still in flight and
// then returned WITHOUT closing that connection. These tests drive a real
// listening server, as the daemon does, with the two kinds of request that
// can outlive Shutdown: a long-poll that only a new block would end, and a
// client that never finishes sending its request.

func startStopTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	params := consensus.MainnetParams()
	idx := consensus.NewHeaderIndex(params)
	chainMgr := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		UTXOSet:     consensus.NewInMemoryUTXOView(),
	})
	chainMgr.SetTipNotifier(consensus.NewTipNotifier()) // as main.go wires it
	if chainMgr.TipNotifier() == nil {
		t.Fatal("test chain manager has no tip notifier: waitfornewblock would return at once and this test would prove nothing")
	}
	s := NewServer(RPCConfig{ListenAddr: addr},
		WithChainParams(params), WithHeaderIndex(idx), WithChainManager(chainMgr))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never listened on %s", addr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return s, addr
}

// An unbounded waitfornewblock in flight must not hold Stop: Core's wait loop
// ends when RPC stops and returns the current block.
func TestStopEndsInFlightWaitForNewBlock(t *testing.T) {
	s, addr := startStopTestServer(t)

	body, _ := json.Marshal(RPCRequest{JSONRPC: "1.0", ID: "lp", Method: "waitfornewblock", Params: json.RawMessage(`[0]`)})
	type reply struct {
		resp *RPCResponse
		err  error
	}
	got := make(chan reply, 1)
	go func() {
		client := &http.Client{Timeout: 60 * time.Second}
		r, err := client.Post("http://"+addr+"/", "application/json", bytes.NewReader(body))
		if err != nil {
			got <- reply{err: err}
			return
		}
		defer r.Body.Close()
		var resp RPCResponse
		err = json.NewDecoder(r.Body).Decode(&resp)
		got <- reply{resp: &resp, err: err}
	}()

	// The long-poll must actually be parked before we stop, or the test
	// measures nothing.
	select {
	case rep := <-got:
		t.Fatalf("waitfornewblock returned before any block or stop: %+v", rep)
	case <-time.After(500 * time.Millisecond):
	}

	t0 := time.Now()
	err := s.Stop()
	took := time.Since(t0)
	if err != nil {
		t.Errorf("Stop with a long-poll in flight: %v (took %s) — the long-poll held http.Server.Shutdown", err, took)
	}
	if took > 3*time.Second {
		t.Errorf("Stop took %s with a long-poll in flight; want < 3s", took)
	}
	select {
	case rep := <-got:
		if rep.err != nil {
			t.Fatalf("long-poll client: %v", rep.err)
		}
		if rep.resp.Error != nil {
			t.Fatalf("long-poll answered with an error: %+v", rep.resp.Error)
		}
		m, ok := rep.resp.Result.(map[string]interface{})
		if !ok || m["height"] != float64(0) {
			t.Fatalf("long-poll result = %#v, want the current tip (height 0)", rep.resp.Result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long-poll client still waiting 3s after Stop: the handler ignored shutdown")
	}
}

// A client that sent half a request keeps its handler blocked reading the
// body. Stop must give up on it and CLOSE the connection rather than leave it
// open until the 30 s read timeout.
func TestStopClosesConnectionOfStalledRequest(t *testing.T) {
	s, addr := startStopTestServer(t)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"method\":"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // handler is now parked in the body read

	t0 := time.Now()
	stopped := make(chan struct{})
	go func() { _ = s.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return within 10s with a stalled client")
	}

	// The server side must have closed the connection: a read sees EOF/reset
	// promptly, not after the 30 s server ReadTimeout.
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	for {
		_, rerr := c.Read(buf)
		if rerr == nil {
			continue // e.g. an error response; keep reading until close
		}
		if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
			t.Fatalf("connection still open %s after Stop began: Stop left the stalled request's connection open", time.Since(t0))
		}
		break // EOF or reset: closed
	}
}
