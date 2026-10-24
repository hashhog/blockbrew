package rpc

// Core 31 cluster RBF at the RPC surface: what testmempoolaccept and
// sendrawtransaction answer for the Core regtest harness's rbf scenarios
// (tools/core-regtest harness/scenarios/rbf.py).
//
// Core reference:
//   rpc/mempool.cpp testmempoolaccept — "reject-reason" = state.GetRejectReason(),
//     "reject-details" = state.ToString(); an allowed single tx carries
//     fees.effective-feerate = CFeeRate(modified fee, vsize).GetFeePerK() and
//     fees.effective-includes = [its wtxid]
//   node/transaction.cpp BroadcastTransaction — MEMPOOL_REJECTED →
//     RPC_TRANSACTION_REJECTED (-26), message state.ToString()

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

const clusterRBFValue = 5_000_000_000

// clusterRBFScript is P2SH(OP_TRUE), spent with scriptSig "push OP_TRUE".
func clusterRBFScript() []byte {
	return []byte{0xa9, 0x14,
		0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a,
		0x56, 0x99, 0x71, 0xc7, 0x7e, 0xba, 0x30, 0xcd, 0x5a, 0x4b,
		0x87}
}

type clusterRBFView map[wire.OutPoint]*consensus.UTXOEntry

func (v clusterRBFView) GetUTXO(op wire.OutPoint) *consensus.UTXOEntry { return v[op] }

func clusterRBFServer(n int) (*Server, []wire.OutPoint) {
	view := clusterRBFView{}
	ops := make([]wire.OutPoint, n)
	for i := range ops {
		var h wire.Hash256
		h[0], h[1] = 0xC2, byte(i)
		ops[i] = wire.OutPoint{Hash: h, Index: 0}
		view[ops[i]] = &consensus.UTXOEntry{Amount: clusterRBFValue, PkScript: clusterRBFScript(), Height: 1}
	}
	mp := mempool.New(mempool.Config{
		MaxSize:                10_000_000,
		MinRelayFeeRate:        1000,
		MaxOrphanTxs:           100,
		ChainParams:            consensus.RegtestParams(),
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, view)
	mp.SetChainHeight(800_000)
	return NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mp)), ops
}

// clusterRBFTx spends ins (BIP125-signalling) into outs equal-ish outputs
// worth total.
func clusterRBFTx(ins []wire.OutPoint, total int64, outs int) *wire.MsgTx {
	tx := &wire.MsgTx{Version: 2}
	for _, in := range ins {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{PreviousOutPoint: in, SignatureScript: []byte{0x01, 0x51}, Sequence: 0xfffffffd})
	}
	each := total / int64(outs)
	for i := 0; i < outs; i++ {
		tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: each, PkScript: clusterRBFScript()})
	}
	tx.TxOut[0].Value += total - each*int64(outs)
	return tx
}

func clusterRBFHex(t *testing.T, tx *wire.MsgTx) string {
	t.Helper()
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf.Bytes())
}

func clusterRBFSend(t *testing.T, srv *Server, tx *wire.MsgTx) *RPCResponse {
	t.Helper()
	return testRPCRequest(t, srv.handleRPC, "sendrawtransaction", []interface{}{clusterRBFHex(t, tx)}, "", "")
}

// clusterRBFAccept returns testmempoolaccept's single result as a JSON map,
// so the test sees exactly the fields the RPC client sees.
func clusterRBFAccept(t *testing.T, srv *Server, tx *wire.MsgTx) map[string]interface{} {
	t.Helper()
	resp := testRPCRequest(t, srv.handleRPC, "testmempoolaccept", []interface{}{[]interface{}{clusterRBFHex(t, tx)}}, "", "")
	if resp.Error != nil {
		t.Fatalf("testmempoolaccept: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	var out []map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil || len(out) != 1 {
		t.Fatalf("testmempoolaccept result %s: %v", raw, err)
	}
	return out[0]
}

// TestClusterRBF_RPC_DiagramRefusal: rbf/diagram. Core answers
// reject-reason "replacement-failed" with details, and sendrawtransaction
// -26 "replacement-failed, insufficient feerate: does not improve feerate
// diagram". blockbrew answered "insufficient fee", no details, and -25.
func TestClusterRBF_RPC_DiagramRefusal(t *testing.T) {
	srv, ops := clusterRBFServer(1)
	if resp := clusterRBFSend(t, srv, clusterRBFTx(ops, clusterRBFValue-5_000, 1)); resp.Error != nil {
		t.Fatalf("original: %+v", resp.Error)
	}
	wide := clusterRBFTx(ops, clusterRBFValue-5_200, 40)
	const details = "replacement-failed, insufficient feerate: does not improve feerate diagram"

	got := clusterRBFAccept(t, srv, wide)
	if got["allowed"] != false || got["reject-reason"] != "replacement-failed" || got["reject-details"] != details {
		t.Errorf("testmempoolaccept = %v, want allowed=false reject-reason=%q reject-details=%q",
			got, "replacement-failed", details)
	}

	resp := clusterRBFSend(t, srv, wide)
	if resp.Error == nil || resp.Error.Code != -26 || resp.Error.Message != details {
		t.Errorf("sendrawtransaction error = %+v, want code -26 message %q", resp.Error, details)
	}
}

// TestClusterRBF_RPC_FiveClusterReplacement: rbf/clusters. Five clusters of
// 21 transactions, one sweep. Core: allowed with vsize and fees (incl.
// effective-feerate / effective-includes), sendrawtransaction returns the
// txid, and the pool holds only the sweep. blockbrew refused with -25
// "replacement would evict too many transactions".
func TestClusterRBF_RPC_FiveClusterReplacement(t *testing.T) {
	srv, ops := clusterRBFServer(5)
	for _, op := range ops {
		root := clusterRBFTx([]wire.OutPoint{op}, clusterRBFValue-1_000, 20)
		if resp := clusterRBFSend(t, srv, root); resp.Error != nil {
			t.Fatalf("root: %+v", resp.Error)
		}
		for i, out := range root.TxOut {
			child := clusterRBFTx([]wire.OutPoint{{Hash: root.TxHash(), Index: uint32(i)}}, out.Value-1_000, 1)
			if resp := clusterRBFSend(t, srv, child); resp.Error != nil {
				t.Fatalf("child %d: %+v", i, resp.Error)
			}
		}
	}
	if n := srv.mempool.Count(); n != 105 {
		t.Fatalf("fixture: pool holds %d, want 105", n)
	}

	sweep := clusterRBFTx(ops, int64(len(ops))*clusterRBFValue-200_000, 1)
	vsize := (consensus.CalcTxWeight(sweep) + 3) / 4
	got := clusterRBFAccept(t, srv, sweep)
	fees, _ := got["fees"].(map[string]interface{})
	includes, _ := fees["effective-includes"].([]interface{})
	wantRate := float64(200_000*1000/vsize) / 1e8
	if got["allowed"] != true || got["vsize"] != float64(vsize) || fees["base"] != 0.002 ||
		fees["effective-feerate"] != wantRate ||
		len(includes) != 1 || includes[0] != sweep.WTxHash().String() {
		t.Errorf("testmempoolaccept = %v, want allowed, vsize %d, fees {base 0.002, effective-feerate %v, effective-includes [%s]}",
			got, vsize, wantRate, sweep.WTxHash())
	}

	resp := clusterRBFSend(t, srv, sweep)
	if resp.Error != nil || resp.Result != sweep.TxHash().String() {
		t.Fatalf("sendrawtransaction = (%v, %+v), want txid %s", resp.Result, resp.Error, sweep.TxHash())
	}
	if n := srv.mempool.Count(); n != 1 || !srv.mempool.HasTransaction(sweep.TxHash()) {
		t.Errorf("pool holds %d txs after the sweep, want only the sweep", n)
	}
}

// TestClusterRBF_RPC_TooLargeCluster: a replacement that merges two
// 40-transaction chains into an 81-transaction cluster. Core's
// CheckMemPoolPolicyLimits refuses it TX_MEMPOOL_POLICY "too-large-cluster"
// (validation.cpp ReplacementChecks): testmempoolaccept reject-reason and
// reject-details "too-large-cluster", sendrawtransaction -26
// "too-large-cluster". blockbrew answered "txn-mempool-conflict" and -25
// "Transaction rejected: too-large-cluster".
func TestClusterRBF_RPC_TooLargeCluster(t *testing.T) {
	srv, ops := clusterRBFServer(2)
	var ins []wire.OutPoint
	var total int64
	for _, op := range ops {
		prev, value := op, int64(clusterRBFValue)
		for i := 0; i < 40; i++ {
			value -= 1_000
			tx := clusterRBFTx([]wire.OutPoint{prev}, value, 1)
			if resp := clusterRBFSend(t, srv, tx); resp.Error != nil {
				t.Fatalf("chain tx %d: %+v", i, resp.Error)
			}
			prev = wire.OutPoint{Hash: tx.TxHash(), Index: 0}
		}
		if resp := clusterRBFSend(t, srv, clusterRBFTx([]wire.OutPoint{prev}, value-1_000, 1)); resp.Error != nil {
			t.Fatalf("child: %+v", resp.Error)
		}
		ins = append(ins, prev)
		total += value
	}
	r := clusterRBFTx(ins, total-1_000_000, 1)

	got := clusterRBFAccept(t, srv, r)
	if got["allowed"] != false || got["reject-reason"] != "too-large-cluster" || got["reject-details"] != "too-large-cluster" {
		t.Errorf("testmempoolaccept = %v, want allowed=false reject-reason/reject-details %q", got, "too-large-cluster")
	}
	resp := clusterRBFSend(t, srv, r)
	if resp.Error == nil || resp.Error.Code != -26 || resp.Error.Message != "too-large-cluster" {
		t.Errorf("sendrawtransaction error = %+v, want code -26 message %q", resp.Error, "too-large-cluster")
	}
}
