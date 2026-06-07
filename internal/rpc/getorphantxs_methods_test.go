package rpc

// getorphantxs RPC — proven-teeth contract test.
//
// Mirrors Bitcoin Core rpc/mempool.cpp::getorphantxs (added v28, EXPERIMENTAL):
//   - verbosity 0: array of txid strings
//   - verbosity 1: array of objects {txid, wtxid, bytes, vsize, weight, from}
//   - verbosity 2: verbosity-1 object plus a `hex` field (serialized tx)
//   - invalid verbosity -> RPC_INVALID_PARAMETER (-8), "Invalid verbosity value <n>"
//
// The test inserts real orphans into a live Mempool by submitting txs whose
// inputs are absent from the UTXO view (so AddTransactionFrom parks them), then
// drives the RPC end-to-end through handleRPC and asserts the decoded JSON shape
// and field values. This exercises the genuine orphan-pool -> RPC path, not a
// stub.
//
// References: bitcoin-core/src/rpc/mempool.cpp (getorphantxs, OrphanToJSON,
// OrphanDescription); bitcoin-core/src/node/txorphanage.cpp (GetOrphanTransactions).

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// makeOrphan builds a tx whose single input references a missing parent outpoint
// (keyed by seed so each orphan has a distinct txid), submits it via
// AddTransactionFrom (which parks it in the orphan pool because the parent is
// absent from the empty UTXO view), and returns the parked tx.
func makeOrphan(t *testing.T, mp *mempool.Mempool, seed byte, fromPeer string) *wire.MsgTx {
	t.Helper()
	// Mirror the proven-working orphan shape from
	// mempool/mempool_test.go::createTestTransaction (used by the
	// orphan_eraseforpeer_test): a standard P2WPKH output + a fake 107-byte
	// scriptSig, spending a single missing-parent outpoint keyed by seed so each
	// orphan has a distinct txid. This shape passes the pre-orphan standardness
	// gates and parks cleanly because the parent is absent from the UTXO view.
	var parentHash wire.Hash256
	parentHash[0] = seed
	pkScript := make([]byte, 22)
	pkScript[0] = 0x00 // OP_0
	pkScript[1] = 0x14 // push 20 bytes
	for j := 2; j < 22; j++ {
		pkScript[j] = byte(seed) + byte(j)
	}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 0},
			SignatureScript:  make([]byte, 107), // fake signature
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    99_000,
			PkScript: pkScript,
		}},
		LockTime: 0,
	}
	// Missing parent -> AddTransactionFrom returns an error and parks the orphan.
	if err := mp.AddTransactionFrom(tx, fromPeer); err == nil {
		t.Fatalf("seed %d: expected missing-inputs error (tx should be parked as orphan)", seed)
	}
	return tx
}

func TestGetOrphanTxs_Shape(t *testing.T) {
	// Empty UTXO view -> every submitted tx is an orphan.
	utxoView := consensus.NewInMemoryUTXOView()
	mp := mempool.New(mempool.DefaultConfig(), utxoView)

	const peerA = "10.0.0.1:8333"
	txA := makeOrphan(t, mp, 0x21, peerA) // announced by a peer
	txLocal := makeOrphan(t, mp, 0x22, "") // locally-originated (no announcer)

	if got := mp.OrphanCount(); got != 2 {
		t.Fatalf("setup: expected 2 orphans, got %d", got)
	}

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithMempool(mp),
	)

	// Expected txids/wtxids for membership checks (map-iteration order is
	// unspecified, matching Core's no-order contract).
	wantTxids := map[string]bool{
		txA.TxHash().String():     true,
		txLocal.TxHash().String(): true,
	}

	// ---- verbosity 0 : array of txid strings ---------------------------------
	resp := testRPCRequest(t, server.handleRPC, "getorphantxs", []interface{}{0}, "", "")
	if resp.Error != nil {
		t.Fatalf("verbosity 0 returned error: %+v", resp.Error)
	}
	arr, ok := resp.Result.([]interface{})
	if !ok {
		t.Fatalf("verbosity 0 result is %T, want array", resp.Result)
	}
	if len(arr) != 2 {
		t.Fatalf("verbosity 0 returned %d entries, want 2", len(arr))
	}
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			t.Fatalf("verbosity 0 entry is %T, want string txid", e)
		}
		if !wantTxids[s] {
			t.Errorf("verbosity 0 unexpected txid %q", s)
		}
	}

	// ---- default verbosity (no arg) must equal verbosity 0 -------------------
	respDef := testRPCRequest(t, server.handleRPC, "getorphantxs", []interface{}{}, "", "")
	if respDef.Error != nil {
		t.Fatalf("default verbosity returned error: %+v", respDef.Error)
	}
	if defArr, ok := respDef.Result.([]interface{}); !ok || len(defArr) != 2 {
		t.Fatalf("default verbosity result = %v (%T), want 2-element array", respDef.Result, respDef.Result)
	}

	// ---- verbosity 1 : array of detail objects -------------------------------
	resp = testRPCRequest(t, server.handleRPC, "getorphantxs", []interface{}{1}, "", "")
	if resp.Error != nil {
		t.Fatalf("verbosity 1 returned error: %+v", resp.Error)
	}
	arr, ok = resp.Result.([]interface{})
	if !ok || len(arr) != 2 {
		t.Fatalf("verbosity 1 result = %v (%T), want 2-element array", resp.Result, resp.Result)
	}

	// Index objects by txid so we can assert per-orphan field values.
	byTxid := map[string]map[string]interface{}{}
	for _, e := range arr {
		o, ok := e.(map[string]interface{})
		if !ok {
			t.Fatalf("verbosity 1 entry is %T, want object", e)
		}
		// Every Core field must be present.
		for _, f := range []string{"txid", "wtxid", "bytes", "vsize", "weight", "from"} {
			if _, present := o[f]; !present {
				t.Errorf("verbosity 1 object missing field %q: %v", f, o)
			}
		}
		// verbosity 1 must NOT carry the hex field (that is verbosity 2 only).
		if _, present := o["hex"]; present {
			t.Errorf("verbosity 1 object must not include `hex`: %v", o)
		}
		txidStr, _ := o["txid"].(string)
		if !wantTxids[txidStr] {
			t.Errorf("verbosity 1 unexpected txid %q", txidStr)
		}
		byTxid[txidStr] = o
	}

	// Field-value checks against the known tx (peer-announced orphan).
	oA := byTxid[txA.TxHash().String()]
	if oA == nil {
		t.Fatalf("verbosity 1 missing object for peer-announced orphan")
	}
	if got, want := oA["wtxid"].(string), txA.WTxHash().String(); got != want {
		t.Errorf("wtxid = %q, want %q", got, want)
	}
	var buf bytes.Buffer
	_ = txA.Serialize(&buf)
	if got, want := oA["bytes"].(float64), float64(buf.Len()); got != want {
		t.Errorf("bytes = %v, want %v", got, want)
	}
	wantWeight := consensus.CalcTxWeight(txA)
	wantVsize := (wantWeight + 3) / 4
	if got := oA["weight"].(float64); got != float64(wantWeight) {
		t.Errorf("weight = %v, want %v", got, wantWeight)
	}
	if got := oA["vsize"].(float64); got != float64(wantVsize) {
		t.Errorf("vsize = %v, want %v", got, wantVsize)
	}
	// `from` for the peer-announced orphan = 1-element array with the peer addr.
	fromA, ok := oA["from"].([]interface{})
	if !ok {
		t.Fatalf("from is %T, want array", oA["from"])
	}
	if len(fromA) != 1 || fromA[0] != peerA {
		t.Errorf("from = %v, want [%q]", fromA, peerA)
	}

	// `from` for the locally-originated orphan must be an EMPTY array (not null).
	oLocal := byTxid[txLocal.TxHash().String()]
	if oLocal == nil {
		t.Fatalf("verbosity 1 missing object for locally-originated orphan")
	}
	fromLocal, ok := oLocal["from"].([]interface{})
	if !ok {
		t.Fatalf("local from is %T, want array (empty, not null)", oLocal["from"])
	}
	if len(fromLocal) != 0 {
		t.Errorf("local from = %v, want []", fromLocal)
	}

	// ---- verbosity 2 : verbosity-1 object + hex ------------------------------
	resp = testRPCRequest(t, server.handleRPC, "getorphantxs", []interface{}{2}, "", "")
	if resp.Error != nil {
		t.Fatalf("verbosity 2 returned error: %+v", resp.Error)
	}
	arr, ok = resp.Result.([]interface{})
	if !ok || len(arr) != 2 {
		t.Fatalf("verbosity 2 result = %v (%T), want 2-element array", resp.Result, resp.Result)
	}
	for _, e := range arr {
		o := e.(map[string]interface{})
		hexStr, present := o["hex"].(string)
		if !present || hexStr == "" {
			t.Errorf("verbosity 2 object missing/empty `hex`: %v", o)
		}
		// verbosity-1 fields must still be present.
		for _, f := range []string{"txid", "wtxid", "bytes", "vsize", "weight", "from"} {
			if _, ok := o[f]; !ok {
				t.Errorf("verbosity 2 object missing field %q", f)
			}
		}
	}

	// ---- invalid verbosity -> RPC_INVALID_PARAMETER (-8) ---------------------
	resp = testRPCRequest(t, server.handleRPC, "getorphantxs", []interface{}{3}, "", "")
	if resp.Error == nil {
		t.Fatalf("verbosity 3 should error, got result %v", resp.Result)
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Errorf("verbosity 3 error code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
	if resp.Error.Message != "Invalid verbosity value 3" {
		t.Errorf("verbosity 3 error message = %q, want %q", resp.Error.Message, "Invalid verbosity value 3")
	}

	// ---- boolean verbosity arg -> REJECTED (Core ParseVerbosity allow_bool=
	// false; a bool must NOT be silently coerced to 0/1). Any error is acceptable
	// as long as the arg is not accepted.
	for _, b := range []bool{true, false} {
		resp = testRPCRequest(t, server.handleRPC, "getorphantxs", []interface{}{b}, "", "")
		if resp.Error == nil {
			t.Errorf("boolean verbosity %v should error (allow_bool=false), got result %v", b, resp.Result)
		}
	}
}

// TestGetOrphanTxs_Empty asserts the call returns an empty JSON array (not null)
// when the orphan pool is empty — matching Core's empty-array contract.
func TestGetOrphanTxs_Empty(t *testing.T) {
	mp := mempool.New(mempool.DefaultConfig(), consensus.NewInMemoryUTXOView())
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mp))

	resp := testRPCRequest(t, server.handleRPC, "getorphantxs", []interface{}{0}, "", "")
	if resp.Error != nil {
		t.Fatalf("empty-pool call returned error: %+v", resp.Error)
	}
	arr, ok := resp.Result.([]interface{})
	if !ok {
		t.Fatalf("empty-pool result is %T, want array", resp.Result)
	}
	if len(arr) != 0 {
		t.Fatalf("empty-pool result = %v, want empty array", arr)
	}
}
