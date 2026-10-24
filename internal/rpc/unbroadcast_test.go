package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

type unbroadcastUTXOView map[wire.OutPoint]*consensus.UTXOEntry

func (u unbroadcastUTXOView) GetUTXO(op wire.OutPoint) *consensus.UTXOEntry { return u[op] }

func unbroadcastCount(t *testing.T, server *Server) int {
	t.Helper()
	resp := testRPCRequest(t, server.handleRPC, "getmempoolinfo", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("getmempoolinfo: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	var info MempoolInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatal(err)
	}
	return info.UnbroadcastCount
}

// TestUnbroadcast_SendRawTransactionMarksUnbroadcast: Core's
// BroadcastTransaction (node/transaction.cpp) calls AddUnbroadcastTx for a tx
// the node itself submitted, so getmempoolentry.unbroadcast and
// getmempoolinfo.unbroadcastcount report it until a peer fetches it.
func TestUnbroadcast_SendRawTransactionMarksUnbroadcast(t *testing.T) {
	var fund wire.Hash256
	fund[0], fund[1] = 0xf0, 0x0d
	op := wire.OutPoint{Hash: fund, Index: 0}
	view := unbroadcastUTXOView{op: {Amount: 1_000_000, PkScript: []byte{0x51}, Height: 1}}
	mp := mempool.New(mempool.Config{
		MaxSize:         10_000_000,
		MinRelayFeeRate: 1000,
		MaxOrphanTxs:    100,
		ChainParams:     consensus.RegtestParams(),
	}, view)
	mp.SetChainHeight(800_000)
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mp))

	tx := &wire.MsgTx{Version: 2}
	tx.TxIn = []*wire.TxIn{{PreviousOutPoint: op, Sequence: 0xffffffff}}
	tx.TxOut = []*wire.TxOut{{Value: 990_000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}}
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	txid := tx.TxHash()

	resp := testRPCRequest(t, server.handleRPC, "sendrawtransaction",
		[]interface{}{hex.EncodeToString(buf.Bytes())}, "", "")
	if resp.Error != nil {
		t.Fatalf("sendrawtransaction: %+v", resp.Error)
	}

	resp = testRPCRequest(t, server.handleRPC, "getmempoolentry", []interface{}{txid.String()}, "", "")
	if resp.Error != nil {
		t.Fatalf("getmempoolentry: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	var entry MempoolEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatal(err)
	}
	if !entry.Unbroadcast {
		t.Errorf("getmempoolentry.unbroadcast = false after sendrawtransaction, want true")
	}
	if n := unbroadcastCount(t, server); n != 1 {
		t.Errorf("getmempoolinfo.unbroadcastcount = %d, want 1", n)
	}

	// A peer fetching the tx (net_processing.cpp RemoveUnbroadcastTx) clears it.
	mp.RemoveUnbroadcastTx(txid)
	if n := unbroadcastCount(t, server); n != 0 {
		t.Errorf("unbroadcastcount after peer fetch = %d, want 0", n)
	}
}
