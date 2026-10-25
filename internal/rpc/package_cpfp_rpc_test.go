package rpc

// submitpackage / testmempoolaccept result shape for CPFP packages, Core v31
// parity (bitcoin-core/src/rpc/mempool.cpp testmempoolaccept l.343-407,
// submitpackage l.1302-1511).
//
// Fixture: a confirmed anyone-can-spend P2SH(OP_TRUE) coin; parent and child
// are 85-vbyte spends of it. min relay feerate 1000 sat/kvB, so Core's
// CheckFeeRate floor for 85 vB is 85 sat.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

const pkgFunding = 1_000_000

func pkgACSScript() []byte {
	// P2SH(OP_TRUE): HASH160(0x51) = da1745e9b549bd0bfa1a569971c77eba30cd5a4b.
	s, _ := hex.DecodeString("a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87")
	return s
}

func pkgSpend(in wire.OutPoint, value int64) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: in,
			SignatureScript:  []byte{0x01, 0x51},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: value, PkScript: pkgACSScript()}},
	}
}

func pkgHex(t *testing.T, tx *wire.MsgTx) string {
	t.Helper()
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return hex.EncodeToString(buf.Bytes())
}

// pkgServer returns a server whose mempool sees one confirmed ACS coin.
func pkgServer(t *testing.T, seed byte) (*Server, *mempool.Mempool, wire.OutPoint) {
	t.Helper()
	view := consensus.NewInMemoryUTXOView()
	var h wire.Hash256
	h[0] = seed
	op := wire.OutPoint{Hash: h, Index: 0}
	view.AddUTXO(op, &consensus.UTXOEntry{Amount: pkgFunding, PkScript: pkgACSScript(), Height: 1})
	mp := mempool.New(mempool.Config{
		MaxSize:                10_000_000,
		MinRelayFeeRate:        1000,
		MaxOrphanTxs:           100,
		ChainParams:            consensus.RegtestParams(),
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, view)
	mp.SetChainHeight(800_000)
	return NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mp)), mp, op
}

func pkgPair(op wire.OutPoint, parentFee, childFee int64) (*wire.MsgTx, *wire.MsgTx) {
	parent := pkgSpend(op, pkgFunding-parentFee)
	child := pkgSpend(wire.OutPoint{Hash: parent.TxHash(), Index: 0}, pkgFunding-parentFee-childFee)
	return parent, child
}

func asObj(t *testing.T, v interface{}, what string) map[string]interface{} {
	t.Helper()
	m, ok := v.(map[string]interface{})
	if !ok {
		t.Fatalf("%s: not an object: %#v", what, v)
	}
	return m
}

// TestSubmitPackageCPFPCoreShape: 1-sat parent + 20,000-sat child. Core:
// package_msg "success"; each tx-results entry is {txid, vsize, fees: {base,
// effective-feerate, effective-includes}} with no wtxid key;
// effective-feerate is CFeeRate(20001, 170).GetFeePerK() = 117652 sat/kvB,
// truncated, as BTC; replaced-transactions is present and empty.
func TestSubmitPackageCPFPCoreShape(t *testing.T) {
	s, mp, op := pkgServer(t, 0xd1)
	parent, child := pkgPair(op, 1, 20_000)

	resp := testRPCRequest(t, s.handleRPC, "submitpackage",
		[]interface{}{[]string{pkgHex(t, parent), pkgHex(t, child)}}, "", "")
	if resp.Error != nil {
		t.Fatalf("submitpackage error: %+v", resp.Error)
	}
	res := asObj(t, resp.Result, "result")
	if res["package_msg"] != "success" {
		t.Fatalf("package_msg = %v, want success", res["package_msg"])
	}
	if !mp.HasTransaction(parent.TxHash()) || !mp.HasTransaction(child.TxHash()) {
		t.Fatal("package members not in mempool")
	}
	rt, ok := res["replaced-transactions"]
	if !ok {
		t.Error("replaced-transactions missing; Core always returns it")
	} else if arr, ok := rt.([]interface{}); !ok || len(arr) != 0 {
		t.Errorf("replaced-transactions = %#v, want []", rt)
	}

	includes := []interface{}{parent.WTxHash().String(), child.WTxHash().String()}
	txResults := asObj(t, res["tx-results"], "tx-results")
	for _, c := range []struct {
		tx   *wire.MsgTx
		base float64
	}{{parent, 0.00000001}, {child, 0.0002}} {
		e := asObj(t, txResults[c.tx.WTxHash().String()], "tx-results entry")
		want := map[string]interface{}{
			"txid":  c.tx.TxHash().String(),
			"vsize": float64(85),
			"fees": map[string]interface{}{
				"base":               c.base,
				"effective-feerate":  0.00117652,
				"effective-includes": includes,
			},
		}
		if !reflect.DeepEqual(e, want) {
			t.Errorf("tx-results[%s]\n got  %#v\n want %#v", c.tx.TxHash(), e, want)
		}
	}
}

// TestSubmitPackageCPFPFailureCoreShape: the aggregate feerate is below min
// relay. Core: package_msg "transaction failed"; the parent keeps its
// individual CheckFeeRate failure, the child carries the package's.
func TestSubmitPackageCPFPFailureCoreShape(t *testing.T) {
	s, mp, op := pkgServer(t, 0xd2)
	parent, child := pkgPair(op, 1, 100)

	resp := testRPCRequest(t, s.handleRPC, "submitpackage",
		[]interface{}{[]string{pkgHex(t, parent), pkgHex(t, child)}}, "", "")
	if resp.Error != nil {
		t.Fatalf("submitpackage error: %+v", resp.Error)
	}
	res := asObj(t, resp.Result, "result")
	if res["package_msg"] != "transaction failed" {
		t.Errorf("package_msg = %v, want \"transaction failed\"", res["package_msg"])
	}
	if mp.Count() != 0 {
		t.Errorf("mempool has %d txs, want 0", mp.Count())
	}
	txResults := asObj(t, res["tx-results"], "tx-results")
	for _, c := range []struct {
		tx  *wire.MsgTx
		err string
	}{
		{parent, "min relay fee not met, 1 < 85"},
		{child, "min relay fee not met, 101 < 170"},
	} {
		e := asObj(t, txResults[c.tx.WTxHash().String()], "tx-results entry")
		want := map[string]interface{}{"txid": c.tx.TxHash().String(), "error": c.err}
		if !reflect.DeepEqual(e, want) {
			t.Errorf("tx-results[%s]\n got  %#v\n want %#v", c.tx.TxHash(), e, want)
		}
	}
}

// TestTestMempoolAcceptPackageParentChild: Core evaluates a multi-tx
// testmempoolaccept as a package (parent outputs visible to the child), each
// member at its own feerate, effective-includes = its own wtxid.
func TestTestMempoolAcceptPackageParentChild(t *testing.T) {
	s, mp, op := pkgServer(t, 0xd3)
	parent, child := pkgPair(op, 1_000, 1_000)

	resp := testRPCRequest(t, s.handleRPC, "testmempoolaccept",
		[]interface{}{[]string{pkgHex(t, parent), pkgHex(t, child)}}, "", "")
	if resp.Error != nil {
		t.Fatalf("testmempoolaccept error: %+v", resp.Error)
	}
	arr, ok := resp.Result.([]interface{})
	if !ok || len(arr) != 2 {
		t.Fatalf("result = %#v, want 2 entries", resp.Result)
	}
	for i, tx := range []*wire.MsgTx{parent, child} {
		e := asObj(t, arr[i], "entry")
		want := map[string]interface{}{
			"txid":    tx.TxHash().String(),
			"wtxid":   tx.WTxHash().String(),
			"allowed": true,
			"vsize":   float64(85),
			"fees": map[string]interface{}{
				"base":               0.00001,
				"effective-feerate":  0.00011764,
				"effective-includes": []interface{}{tx.WTxHash().String()},
			},
		}
		if !reflect.DeepEqual(e, want) {
			t.Errorf("[%d]\n got  %#v\n want %#v", i, e, want)
		}
	}
	if mp.Count() != 0 {
		t.Errorf("testmempoolaccept changed the mempool: %d txs", mp.Count())
	}
}

// TestTestMempoolAcceptPackageLowParentStopsEarly: package testmempoolaccept
// does not use package feerates, so the 1-sat parent fails "min relay fee not
// met" and the child is left unvalidated: only txid and wtxid, no allowed key.
func TestTestMempoolAcceptPackageLowParentStopsEarly(t *testing.T) {
	s, _, op := pkgServer(t, 0xd4)
	parent, child := pkgPair(op, 1, 20_000)

	resp := testRPCRequest(t, s.handleRPC, "testmempoolaccept",
		[]interface{}{[]string{pkgHex(t, parent), pkgHex(t, child)}}, "", "")
	if resp.Error != nil {
		t.Fatalf("testmempoolaccept error: %+v", resp.Error)
	}
	arr, ok := resp.Result.([]interface{})
	if !ok || len(arr) != 2 {
		t.Fatalf("result = %#v, want 2 entries", resp.Result)
	}
	want0 := map[string]interface{}{
		"txid":           parent.TxHash().String(),
		"wtxid":          parent.WTxHash().String(),
		"allowed":        false,
		"reject-reason":  "min relay fee not met",
		"reject-details": "min relay fee not met, 1 < 85",
	}
	if e := asObj(t, arr[0], "entry 0"); !reflect.DeepEqual(e, want0) {
		t.Errorf("[0]\n got  %#v\n want %#v", e, want0)
	}
	want1 := map[string]interface{}{
		"txid":  child.TxHash().String(),
		"wtxid": child.WTxHash().String(),
	}
	if e := asObj(t, arr[1], "entry 1"); !reflect.DeepEqual(e, want1) {
		t.Errorf("[1]\n got  %#v\n want %#v", e, want1)
	}
}

// TestTestMempoolAcceptPackageBadScriptChild: the child's script fails. The
// package path must run script checks (the per-tx path reported the child
// "missing-inputs" without ever reaching them) and refuse it.
func TestTestMempoolAcceptPackageBadScriptChild(t *testing.T) {
	s, _, op := pkgServer(t, 0xd5)
	parent, child := pkgPair(op, 1_000, 1_000)
	child.TxIn[0].SignatureScript = []byte{0x01, 0x52} // wrong redeem script

	resp := testRPCRequest(t, s.handleRPC, "testmempoolaccept",
		[]interface{}{[]string{pkgHex(t, parent), pkgHex(t, child)}}, "", "")
	if resp.Error != nil {
		t.Fatalf("testmempoolaccept error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	arr, ok := resp.Result.([]interface{})
	if !ok || len(arr) != 2 {
		t.Fatalf("result = %s, want 2 entries", raw)
	}
	if e := asObj(t, arr[0], "entry 0"); e["allowed"] != true {
		t.Errorf("[0] allowed = %v, want true: %s", e["allowed"], raw)
	}
	e1 := asObj(t, arr[1], "entry 1")
	if e1["allowed"] != false {
		t.Errorf("[1] allowed = %v, want false: %s", e1["allowed"], raw)
	}
	if e1["reject-reason"] == "missing-inputs" {
		t.Errorf("[1] reported missing-inputs: the parent's outputs were not visible: %s", raw)
	}
}
