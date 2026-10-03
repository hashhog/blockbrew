package rpc

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/storage"
)

// blockingFlushDB is a DB whose Flush blocks until released, standing in for
// a pebble memtable flush on an I/O-saturated disk.
type blockingFlushDB struct {
	*storage.MemDB
	entered chan struct{}
	release chan struct{}
}

func (d *blockingFlushDB) Flush() error {
	close(d.entered)
	<-d.release
	return nil
}

// On mainnet every stop logged "RPC server stop error: context deadline
// exceeded" ~5 s after SIGTERM. stop_mainnet.sh calls flushchainstate with a
// 10 s curl and then SIGTERMs; on the saturated disk the flush outlived the
// curl, so Stop's Shutdown waited its whole drain timeout for that handler.
// The handler must return as soon as shutdown begins.
//
// Negative control: with the old handler (a plain synchronous chainDB.Flush)
// Stop takes the full 5 s drain timeout and this test fails.
func TestStopDoesNotWaitForFlushChainState(t *testing.T) {
	s, addr := startStopTestServer(t)
	db := &blockingFlushDB{MemDB: storage.NewMemDB(), entered: make(chan struct{}), release: make(chan struct{})}
	defer close(db.release)
	s.chainDB = storage.NewChainDB(db)

	body, _ := json.Marshal(RPCRequest{JSONRPC: "1.0", ID: "f", Method: "flushchainstate", Params: json.RawMessage(`[]`)})
	got := make(chan *RPCResponse, 1)
	go func() {
		client := &http.Client{Timeout: 30 * time.Second}
		r, err := client.Post("http://"+addr+"/", "application/json", bytes.NewReader(body))
		if err != nil {
			got <- nil
			return
		}
		defer r.Body.Close()
		var resp RPCResponse
		if json.NewDecoder(r.Body).Decode(&resp) != nil {
			got <- nil
			return
		}
		got <- &resp
	}()
	select {
	case <-db.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("flushchainstate never reached the DB flush: the test would measure nothing")
	}

	t0 := time.Now()
	err := s.Stop()
	took := time.Since(t0)
	if err != nil {
		t.Errorf("Stop: %v", err)
	}
	if took > 2*time.Second {
		t.Fatalf("Stop took %s with a flushchainstate in flight; want < 2s (the flush held Shutdown)", took)
	}
	select {
	case resp := <-got:
		if resp == nil || resp.Error == nil || !strings.Contains(resp.Error.Message, "shutting down") {
			t.Fatalf("flushchainstate reply = %+v, want an error saying the node is shutting down", resp)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("flushchainstate client got no reply after Stop")
	}
}

// When Stop has to cut a connection, it says which request it was instead of
// returning a bare "context deadline exceeded".
func TestStopNamesTheRequestsItCuts(t *testing.T) {
	s, addr := startStopTestServer(t)

	var mu sync.Mutex
	var buf bytes.Buffer
	log.SetOutput(&lockedWriter{mu: &mu, w: &buf})
	defer log.SetOutput(os.Stderr)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Half a request: the handler is parked reading the body.
	if _, err := io.WriteString(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"method\":"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	if err := s.Stop(); err != nil {
		t.Errorf("Stop returned %v; cutting a stuck request is the designed outcome, not an error", err)
	}
	mu.Lock()
	out := buf.String()
	mu.Unlock()
	if !strings.Contains(out, "1 request(s) still running") || !strings.Contains(out, "/ (") {
		t.Fatalf("Stop did not name the request it cut; log:\n%s", out)
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
