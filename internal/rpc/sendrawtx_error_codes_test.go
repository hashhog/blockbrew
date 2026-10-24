package rpc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Core BroadcastTransaction (node/transaction.cpp) / MemPoolAccept::PreChecks:
//   - a tx whose outputs are already coins: -27 "Transaction outputs already in
//     utxo set" (sendrawtransaction), "txn-already-known" (testmempoolaccept);
//   - a tx with missing inputs: -25 "bad-txns-inputs-missingorspent", and ATMP
//     never enrols it in an orphan pool.

func srtxServer(view consensus.UTXOView) (*Server, *mempool.Mempool) {
	mp := mempool.New(mempool.Config{
		MaxSize:         10_000_000,
		MinRelayFeeRate: 1000,
		MaxOrphanTxs:    100,
		ChainParams:     consensus.RegtestParams(),
	}, view)
	mp.SetChainHeight(800_000)
	return NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mp)), mp
}

func srtxTx(prev wire.Hash256) (*wire.MsgTx, string) {
	tx := &wire.MsgTx{Version: 2}
	tx.TxIn = []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: prev, Index: 0}, Sequence: 0xffffffff}}
	tx.TxOut = []*wire.TxOut{{Value: 990_000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}}
	var buf bytes.Buffer
	_ = tx.Serialize(&buf)
	return tx, hex.EncodeToString(buf.Bytes())
}

func TestSendRawTransaction_ConfirmedTx_Minus27(t *testing.T) {
	var parent wire.Hash256
	parent[0] = 0xc0
	tx, txHex := srtxTx(parent)
	// The parent is spent (absent) and the tx's own output is a coin: confirmed.
	view := unbroadcastUTXOView{{Hash: tx.TxHash(), Index: 0}: {Amount: 990_000, PkScript: tx.TxOut[0].PkScript, Height: 5}}
	server, _ := srtxServer(view)

	resp := testRPCRequest(t, server.handleRPC, "sendrawtransaction", []interface{}{txHex}, "", "")
	if resp.Error == nil {
		t.Fatal("sendrawtransaction of a confirmed tx succeeded")
	}
	if resp.Error.Code != -27 || resp.Error.Message != "Transaction outputs already in utxo set" {
		t.Errorf("got %d %q, want -27 \"Transaction outputs already in utxo set\"", resp.Error.Code, resp.Error.Message)
	}
}

func TestTestMempoolAccept_ConfirmedTx_TxnAlreadyKnown(t *testing.T) {
	var parent wire.Hash256
	parent[0] = 0xc1
	tx, txHex := srtxTx(parent)
	view := unbroadcastUTXOView{{Hash: tx.TxHash(), Index: 0}: {Amount: 990_000, PkScript: tx.TxOut[0].PkScript, Height: 5}}
	server, _ := srtxServer(view)

	r := runTMA(t, server, txHex)
	if r.Allowed || r.RejectReason != "txn-already-known" {
		t.Errorf("allowed=%v reject-reason=%q, want false \"txn-already-known\"", r.Allowed, r.RejectReason)
	}
}

func TestSendRawTransaction_MissingInputs_CoreTextNoOrphan(t *testing.T) {
	var parent wire.Hash256
	parent[0] = 0xc2
	_, txHex := srtxTx(parent)
	server, mp := srtxServer(unbroadcastUTXOView{})

	resp := testRPCRequest(t, server.handleRPC, "sendrawtransaction", []interface{}{txHex}, "", "")
	if resp.Error == nil {
		t.Fatal("sendrawtransaction with missing inputs succeeded")
	}
	if resp.Error.Code != -25 || resp.Error.Message != "bad-txns-inputs-missingorspent" {
		t.Errorf("got %d %q, want -25 \"bad-txns-inputs-missingorspent\"", resp.Error.Code, resp.Error.Message)
	}
	if n := mp.OrphanCount(); n != 0 {
		t.Errorf("orphan pool holds %d txs after an RPC submission, want 0", n)
	}
}

// P2P-originated txs still park in the orphan pool.
func TestMempoolAccept_P2POrphanStillParked(t *testing.T) {
	var parent wire.Hash256
	parent[0] = 0xc3
	tx, _ := srtxTx(parent)
	_, mp := srtxServer(unbroadcastUTXOView{})
	if err := mp.AcceptToMemoryPoolFrom(tx, "1.2.3.4:8333"); err == nil {
		t.Fatal("want missing-inputs error")
	}
	if n := mp.OrphanCount(); n != 1 {
		t.Errorf("orphan count = %d, want 1", n)
	}
}
