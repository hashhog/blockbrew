package rpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// callGetTxOutSetInfo runs the handler directly and decodes the omap result.
func callGetTxOutSetInfo(t *testing.T, s *Server) map[string]interface{} {
	t.Helper()
	res, rpcErr := s.handleGetTxOutSetInfo(json.RawMessage(`[]`))
	if rpcErr != nil {
		t.Fatalf("gettxoutsetinfo: %+v", rpcErr)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return out
}

// TestGetTxOutSetInfoLabelComesFromWalkedSnapshot: a block connected while
// gettxoutsetinfo walks must neither leak into the totals nor relabel them.
//
// The hook fires after the handler has fixed which set it reports and before
// the walk starts, and connects block 6 on top of a 5-block chain (one
// spendable coinbase output per block, so txouts == height). The paused walk
// must report exactly what a quiet call at height 5 reports — height,
// bestblock, txouts, hash_serialized_3. Connecting the block from inside the
// hook also proves the walk holds no lock ConnectBlock needs (a held lock
// would deadlock; the hook times out instead of hanging the test).
//
// NEGATIVE CONTROL: on 75aa909 (tip read via BestBlock() before
// ComputeUTXOSetInfo flushes and iterates), with the hook placed between the
// two, this test FAILS: the walk reports height 5 with 6 txouts.
func TestGetTxOutSetInfoLabelComesFromWalkedSnapshot(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 5)

	quiet := callGetTxOutSetInfo(t, rig.server)
	if quiet["height"].(float64) != 5 || quiet["txouts"].(float64) != 5 {
		t.Fatalf("quiet call: height=%v txouts=%v, want 5/5", quiet["height"], quiet["txouts"])
	}

	next := buildRegtestBlock(t, rig.params, rig.tips[4])
	hookRan := false
	txoutsetWalkHook = func() {
		hookRan = true
		if _, err := rig.idx.AddHeader(next.Header, true); err != nil {
			t.Errorf("AddHeader: %v", err)
			return
		}
		if err := rig.db.StoreBlock(next.Header.BlockHash(), next); err != nil {
			t.Errorf("StoreBlock: %v", err)
			return
		}
		done := make(chan error, 1)
		go func() { done <- rig.cm.ConnectBlock(next) }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("ConnectBlock mid-walk: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("ConnectBlock blocked for 10s while gettxoutsetinfo was walking: the walk holds a lock block connection needs")
		}
	}
	defer func() { txoutsetWalkHook = nil }()

	during := callGetTxOutSetInfo(t, rig.server)
	txoutsetWalkHook = nil
	if !hookRan {
		t.Fatal("walk hook never ran — the test measured nothing")
	}
	if _, h := rig.cm.BestBlock(); h != 6 {
		t.Fatalf("block 6 did not connect during the walk (tip height %d)", h)
	}

	for _, k := range []string{"height", "bestblock", "txouts", "hash_serialized_3", "total_amount", "transactions"} {
		if fmt.Sprint(during[k]) != fmt.Sprint(quiet[k]) {
			t.Errorf("%s: walk with a block connected mid-walk reported %v, the set at height 5 is %v",
				k, during[k], quiet[k])
		}
	}
	if during["txouts"].(float64) != during["height"].(float64) {
		t.Errorf("label and set disagree: height %v but txouts %v (one coin per block)",
			during["height"], during["txouts"])
	}

	after := callGetTxOutSetInfo(t, rig.server)
	if after["height"].(float64) != 6 || after["txouts"].(float64) != 6 {
		t.Errorf("fresh call after the block: height=%v txouts=%v, want 6/6", after["height"], after["txouts"])
	}
	if after["bestblock"] != next.Header.BlockHash().String() {
		t.Errorf("fresh call bestblock %v, want %s", after["bestblock"], next.Header.BlockHash())
	}
	if after["hash_serialized_3"] == quiet["hash_serialized_3"] {
		t.Error("hash_serialized_3 did not change after a block added a coin — the hash is not measuring the set")
	}
}

// TestGetTxOutSetInfoAbortsOnShutdown: a walk in flight when the server stops
// returns an error instead of reading on, and Stop waits for it.
func TestGetTxOutSetInfoAbortsOnShutdown(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 3)
	txoutsetWalkHook = func() { close(rig.server.shutdown) }
	defer func() { txoutsetWalkHook = nil }()
	_, rpcErr := rig.server.handleGetTxOutSetInfo(json.RawMessage(`[]`))
	if rpcErr == nil || rpcErr.Message != "Shutting down" {
		t.Fatalf("walk with shutdown closed: got %+v, want 'Shutting down'", rpcErr)
	}
}

// TestLongRunningRPCOutlivesServerWriteTimeout: gettxoutsetinfo must be able
// to run longer than the server-wide write deadline and still deliver its
// reply. On mainnet the walk took 4,901 s against a 3,600 s WriteTimeout and
// the client got an empty reply (curl rc=52). Scaled down: WriteTimeout
// 300 ms, a walk that takes 1.2 s.
//
// NEGATIVE CONTROL: with the per-request SetWriteDeadline(time.Time{}) in
// handleRPC removed, the POST fails with EOF (empty reply) — verified on the
// fix branch by deleting that block.
func TestLongRunningRPCOutlivesServerWriteTimeout(t *testing.T) {
	rig := newDumpTxOutSetTestRig(t, 3)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	rig.server.config.ListenAddr = addr
	rig.server.config.WriteTimeout = 300 * time.Millisecond
	if err := rig.server.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = rig.server.Stop() }()
	waitReachable(t, addr)

	txoutsetWalkHook = func() { time.Sleep(1200 * time.Millisecond) }
	defer func() { txoutsetWalkHook = nil }()

	client := &http.Client{Timeout: 30 * time.Second}
	body := []byte(`{"jsonrpc":"1.0","id":1,"method":"gettxoutsetinfo","params":[]}`)
	resp, err := client.Post("http://"+addr+"/", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("gettxoutsetinfo outlasting the 300ms write timeout: %v (empty reply)", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	var out struct {
		Result map[string]interface{} `json:"result"`
		Error  *RPCError              `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode reply %q: %v", raw, err)
	}
	if out.Error != nil || out.Result["height"].(float64) != 3 {
		t.Fatalf("reply: %s", raw)
	}

	// The ordinary deadline still applies to everything else: the server's
	// own WriteTimeout is what we configured, not unbounded.
	if rig.server.httpServer.WriteTimeout != 300*time.Millisecond {
		t.Errorf("server WriteTimeout = %v, want the configured 300ms", rig.server.httpServer.WriteTimeout)
	}
}
