package rpc

// FIX-72 RPC layer — prioritisetransaction + getprioritisedtransactions.
//
// Tests the JSON-RPC contract surface:
//   - argument validation (txid type, dummy=0|null, fee_delta integer)
//   - dispatch table wires both methods
//   - getprioritisedtransactions shape (modified_fee omitted when not in
//     mempool — Core mining.cpp:558).
//   - getmempoolentry.fees.modified reflects the operator delta.
//
// References: bitcoin-core/src/rpc/mining.cpp.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

func TestFIX72_PrioritiseTransactionRPC_Dispatch(t *testing.T) {
	mp := mempool.New(mempool.Config{
		MaxSize:                10_000_000,
		MinRelayFeeRate:        1000,
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, nil)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithMempool(mp),
	)

	// Valid call: txid + dummy=0 + fee_delta=10000 → true.
	txidStr := "0000000000000000000000000000000000000000000000000000000000000001"
	resp := testRPCRequest(t, server.handleRPC, "prioritisetransaction",
		[]interface{}{txidStr, 0, 10000}, "", "")
	if resp.Error != nil {
		t.Fatalf("valid call returned error: %+v", resp.Error)
	}
	if b, ok := resp.Result.(bool); !ok || !b {
		t.Errorf("valid call result = %v (%T), want true", resp.Result, resp.Result)
	}

	// Delta should be visible in the mempool layer.
	txid, _ := wire.NewHash256FromHex(txidStr)
	if got := mp.GetFeeDelta(txid); got != 10000 {
		t.Errorf("post-RPC mempool delta = %d, want 10000", got)
	}

	// Stacking: second call adds.
	resp = testRPCRequest(t, server.handleRPC, "prioritisetransaction",
		[]interface{}{txidStr, 0, -3000}, "", "")
	if resp.Error != nil {
		t.Fatalf("stack call returned error: %+v", resp.Error)
	}
	if got := mp.GetFeeDelta(txid); got != 7000 {
		t.Errorf("post-stack delta = %d, want 7000", got)
	}

	// dummy=null is also accepted.
	resp = testRPCRequest(t, server.handleRPC, "prioritisetransaction",
		[]interface{}{txidStr, nil, 500}, "", "")
	if resp.Error != nil {
		t.Fatalf("dummy=null returned error: %+v", resp.Error)
	}
	if got := mp.GetFeeDelta(txid); got != 7500 {
		t.Errorf("after dummy=null +500 delta = %d, want 7500", got)
	}
}

func TestFIX72_PrioritiseTransactionRPC_ArgValidation(t *testing.T) {
	mp := mempool.New(mempool.DefaultConfig(), nil)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithMempool(mp),
	)

	cases := []struct {
		name   string
		params []interface{}
	}{
		{"missing all", []interface{}{}},
		{"missing fee_delta", []interface{}{"0000000000000000000000000000000000000000000000000000000000000001", 0}},
		{"txid not string", []interface{}{123, 0, 1000}},
		{"txid bad hex", []interface{}{"not_a_txid", 0, 1000}},
		{"dummy non-zero", []interface{}{"0000000000000000000000000000000000000000000000000000000000000001", 5, 1000}},
		{"fee_delta fractional", []interface{}{"0000000000000000000000000000000000000000000000000000000000000001", 0, 1.5}},
		{"fee_delta string", []interface{}{"0000000000000000000000000000000000000000000000000000000000000001", 0, "1000"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			resp := testRPCRequest(t, server.handleRPC, "prioritisetransaction",
				tc.params, "", "")
			if resp.Error == nil {
				t.Errorf("expected error for case %q, got result %v", tc.name, resp.Result)
			}
		})
	}
}

func TestFIX72_GetPrioritisedTransactionsRPC_Shape(t *testing.T) {
	mp := mempool.New(mempool.DefaultConfig(), nil)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithMempool(mp),
	)

	// Phantom txid: prioritise without a pool entry.
	phantomStr := "0000000000000000000000000000000000000000000000000000000000000099"
	resp := testRPCRequest(t, server.handleRPC, "prioritisetransaction",
		[]interface{}{phantomStr, 0, 250}, "", "")
	if resp.Error != nil {
		t.Fatalf("prep call returned error: %+v", resp.Error)
	}

	// Now read back.
	resp = testRPCRequest(t, server.handleRPC, "getprioritisedtransactions",
		[]interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("get returned error: %+v", resp.Error)
	}
	m, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map[string]interface{}", resp.Result)
	}
	entry, ok := m[phantomStr].(map[string]interface{})
	if !ok {
		t.Fatalf("phantom entry missing or wrong type: %v", m[phantomStr])
	}

	// fee_delta survives JSON round trip as float64.
	if delta, ok := entry["fee_delta"].(float64); !ok || int64(delta) != 250 {
		t.Errorf("phantom fee_delta = %v (%T), want 250", entry["fee_delta"], entry["fee_delta"])
	}
	if inPool, ok := entry["in_mempool"].(bool); !ok || inPool {
		t.Errorf("phantom in_mempool = %v, want false", entry["in_mempool"])
	}
	// modified_fee MUST be omitted when not in mempool. Core mining.cpp:558:
	// "Only returned if in_mempool=true".
	if _, present := entry["modified_fee"]; present {
		t.Errorf("phantom entry should OMIT modified_fee when in_mempool=false; "+
			"got %v", entry["modified_fee"])
	}
}

// TestFIX72_GetMempoolEntry_ModifiedFee asserts the fees.modified field of
// getmempoolentry / getrawmempool(verbose) actually reflects the operator
// delta. Without FIX-72 fees.modified was hardcoded to equal fees.base.
func TestFIX72_GetMempoolEntry_ModifiedFee(t *testing.T) {
	mp := mempool.New(mempool.Config{
		MaxSize:                10_000_000,
		MinRelayFeeRate:        1000,
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, nil)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithMempool(mp),
	)

	// Seed a tx — directly inject; we don't need the full ATMP path.
	var seedHash wire.Hash256
	seedHash[0] = 0xAA
	tx := &wire.MsgTx{Version: 2}
	tx.TxIn = []*wire.TxIn{{
		PreviousOutPoint: wire.OutPoint{Hash: seedHash, Index: 0},
		Sequence:         0xFFFFFFFD,
	}}
	tx.TxOut = []*wire.TxOut{{
		Value:    100_000,
		PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}}
	txHash := tx.TxHash()
	entry := &mempool.TxEntry{
		Tx:      tx,
		TxHash:  txHash,
		Fee:     100_000_000, // 1 BTC
		Size:    150,
		FeeRate: 100_000_000.0 / 150.0,
		Time:    time.Now(),
	}
	mempool.InjectTestEntry(mp, entry)

	// Without prioritisation: modifiedfee == fee = 1.0 BTC.
	resp := testRPCRequest(t, server.handleRPC, "getmempoolentry",
		[]interface{}{txHash.String()}, "", "")
	if resp.Error != nil {
		t.Fatalf("getmempoolentry returned error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	var got MempoolEntry
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Fees.Modified != 1.0 {
		t.Errorf("pre-delta fees.modified = %v, want 1.0", got.Fees.Modified)
	}

	// Apply +50_000_000 sat delta → fees.modified = 1.5 BTC.
	if _, e := mp.GetEntry(txHash), mp.GetFeeDelta(txHash); e != 0 {
		t.Fatalf("expected zero starting delta, got %d", e)
	}
	mp.PrioritiseTransaction(txHash, 50_000_000)

	resp = testRPCRequest(t, server.handleRPC, "getmempoolentry",
		[]interface{}{txHash.String()}, "", "")
	if resp.Error != nil {
		t.Fatalf("getmempoolentry returned error: %+v", resp.Error)
	}
	raw, _ = json.Marshal(resp.Result)
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Fees.Base != 1.0 {
		t.Errorf("base fee changed unexpectedly: fees.base = %v, want 1.0", got.Fees.Base)
	}
	if got.Fees.Modified != 1.5 {
		t.Errorf("post-delta fees.modified = %v, want 1.5", got.Fees.Modified)
	}
}
