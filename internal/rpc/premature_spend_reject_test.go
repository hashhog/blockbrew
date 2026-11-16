package rpc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// A spend of a coinbase output at depth 99 is refused by Core's
// Consensus::CheckTxInputs (src/consensus/tx_verify.cpp) with
// state.Invalid(TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
// "tried to spend coinbase at depth 99"). sendrawtransaction turns that
// MEMPOOL_REJECTED state into RPC_TRANSACTION_REJECTED (-26) with
// state.ToString() as the message (src/node/transaction.cpp, rpc/util.cpp
// RPCErrorFromTransactionError); testmempoolaccept reports reject-reason
// plus reject-details = state.ToString() (src/rpc/mempool.cpp).

const prematureSpendWant = "bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth 99"

// prematureSpendSetup returns a tx spending a coinbase confirmed at height 102
// with the tip at 200: spend height 201, depth 99 < COINBASE_MATURITY (100).
func prematureSpendSetup(t *testing.T) (string, *Server) {
	t.Helper()
	prevOut := wire.OutPoint{Hash: wire.Hash256{0x99}, Index: 0}
	tx := &wire.MsgTx{
		Version:  2,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: prevOut, Sequence: 0xFFFFFFFF}},
		TxOut:    []*wire.TxOut{{Value: 50_000, PkScript: tmaP2WPKHScript(0x60)}},
		LockTime: 0,
	}
	view := consensus.NewInMemoryUTXOView()
	view.AddUTXO(prevOut, &consensus.UTXOEntry{
		Amount:     100_000,
		PkScript:   tmaP2WPKHScript(0x61),
		Height:     102,
		IsCoinbase: true,
	})
	cfg := mempool.DefaultConfig()
	cfg.ChainState = &tmaFakeChainState{height: 200, mtp: 1_600_000_000}
	mp := mempool.New(cfg, view)
	return txToHex(t, tx), NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mp))
}

func TestSendRawTransactionPrematureCoinbaseSpendIsCoreReject(t *testing.T) {
	txHex, srv := prematureSpendSetup(t)
	params, _ := json.Marshal([]interface{}{txHex})
	_, rpcErr := srv.handleSendRawTransaction(json.RawMessage(params))
	if rpcErr == nil {
		t.Fatal("sendrawtransaction accepted a depth-99 coinbase spend")
	}
	if rpcErr.Code != RPCErrVerifyRejected {
		t.Errorf("code = %d, want %d (RPC_TRANSACTION_REJECTED)", rpcErr.Code, RPCErrVerifyRejected)
	}
	if rpcErr.Message != prematureSpendWant {
		t.Errorf("message = %q, want %q", rpcErr.Message, prematureSpendWant)
	}
}

func TestTestMempoolAcceptPrematureCoinbaseSpendRejectDetails(t *testing.T) {
	txHex, srv := prematureSpendSetup(t)
	r := runTMA(t, srv, txHex)
	if r.Allowed {
		t.Fatal("testmempoolaccept allowed a depth-99 coinbase spend")
	}
	if r.RejectReason != "bad-txns-premature-spend-of-coinbase" {
		t.Errorf("reject-reason = %q", r.RejectReason)
	}
	if r.RejectDetails != prematureSpendWant {
		t.Errorf("reject-details = %q, want %q", r.RejectDetails, prematureSpendWant)
	}
}

// Depth exactly COINBASE_MATURITY is spendable in both paths (Core:
// nSpendHeight - coin.nHeight < COINBASE_MATURITY rejects only below 100).
func TestTestMempoolAcceptCoinbaseAtDepth100NotPremature(t *testing.T) {
	prevOut := wire.OutPoint{Hash: wire.Hash256{0x98}, Index: 0}
	tx := &wire.MsgTx{
		Version:  2,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: prevOut, Sequence: 0xFFFFFFFF}},
		TxOut:    []*wire.TxOut{{Value: 50_000, PkScript: tmaP2WPKHScript(0x62)}},
		LockTime: 0,
	}
	view := consensus.NewInMemoryUTXOView()
	view.AddUTXO(prevOut, &consensus.UTXOEntry{
		Amount: 100_000, PkScript: tmaP2WPKHScript(0x63), Height: 101, IsCoinbase: true,
	})
	cfg := mempool.DefaultConfig()
	cfg.ChainState = &tmaFakeChainState{height: 200, mtp: 1_600_000_000}
	srv := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mempool.New(cfg, view)))
	r := runTMA(t, srv, txToHex(t, tx))
	if r.RejectReason == "bad-txns-premature-spend-of-coinbase" {
		t.Errorf("depth-100 coinbase spend rejected as premature: %+v", r)
	}
}

// The real accept path at depth exactly 100 must not refuse as premature
// (it may still refuse later, e.g. on the unsigned input's script).
func TestSendRawTransactionCoinbaseAtDepth100NotPremature(t *testing.T) {
	prevOut := wire.OutPoint{Hash: wire.Hash256{0x97}, Index: 0}
	tx := &wire.MsgTx{
		Version:  2,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: prevOut, Sequence: 0xFFFFFFFF}},
		TxOut:    []*wire.TxOut{{Value: 50_000, PkScript: tmaP2WPKHScript(0x64)}},
		LockTime: 0,
	}
	view := consensus.NewInMemoryUTXOView()
	view.AddUTXO(prevOut, &consensus.UTXOEntry{
		Amount: 100_000, PkScript: tmaP2WPKHScript(0x65), Height: 101, IsCoinbase: true,
	})
	cfg := mempool.DefaultConfig()
	cfg.ChainState = &tmaFakeChainState{height: 200, mtp: 1_600_000_000}
	srv := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mempool.New(cfg, view)))
	params, _ := json.Marshal([]interface{}{txToHex(t, tx)})
	_, rpcErr := srv.handleSendRawTransaction(json.RawMessage(params))
	if rpcErr != nil && (strings.Contains(rpcErr.Message, "premature") || strings.Contains(rpcErr.Message, "immature")) {
		t.Errorf("depth-100 coinbase spend refused as premature: %+v", rpcErr)
	}
}
