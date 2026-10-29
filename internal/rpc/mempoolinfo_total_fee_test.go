package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// totalFeeServer returns a server whose mempool holds one tx per fee in
// fees, accepted in the order given. Each tx spends its own 1,000,000-sat
// coin, so the mempool entries are independent.
func totalFeeServer(t *testing.T, fees []int64) *Server {
	t.Helper()
	view := unbroadcastUTXOView{}
	mp := mempool.New(mempool.Config{
		MaxSize:         10_000_000,
		MinRelayFeeRate: 1000,
		MaxOrphanTxs:    100,
		ChainParams:     consensus.RegtestParams(),
	}, view)
	mp.SetChainHeight(800_000)
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mp))

	for i, fee := range fees {
		var fund wire.Hash256
		fund[0] = 0x7f
		op := wire.OutPoint{Hash: fund, Index: uint32(i)} // distinct coin per tx
		view[op] = &consensus.UTXOEntry{Amount: 1_000_000, PkScript: []byte{0x51}, Height: 1}

		tx := &wire.MsgTx{Version: 2}
		tx.TxIn = []*wire.TxIn{{PreviousOutPoint: op, Sequence: 0xffffffff}}
		tx.TxOut = []*wire.TxOut{{Value: 1_000_000 - fee, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}}
		var buf bytes.Buffer
		if err := tx.Serialize(&buf); err != nil {
			t.Fatal(err)
		}
		resp := testRPCRequest(t, server.handleRPC, "sendrawtransaction",
			[]interface{}{hex.EncodeToString(buf.Bytes())}, "", "")
		if resp.Error != nil {
			t.Fatalf("sendrawtransaction (fee %d): %+v", fee, resp.Error)
		}
	}
	return server
}

// mempoolInfoTotalFeeJSON returns getmempoolinfo's total_fee exactly as it
// goes on the wire, read from the raw JSON-RPC response body. It also checks
// that /rest/mempool/info.json, which shares the handler, sends the same text.
func mempoolInfoTotalFeeJSON(t *testing.T, server *Server) string {
	t.Helper()
	body := `{"jsonrpc":"1.0","id":"t","method":"getmempoolinfo","params":[]}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	server.handleRPC(rr, req)
	var resp struct {
		Result map[string]json.RawMessage `json:"result"`
		Error  json.RawMessage            `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("getmempoolinfo body %q: %v", rr.Body.String(), err)
	}
	if resp.Result == nil {
		t.Fatalf("getmempoolinfo: %s", resp.Error)
	}
	rpcText := string(resp.Result["total_fee"])

	rest := testRESTRequest(t, server.handleRESTMempoolInfo, http.MethodGet, "/rest/mempool/info.json")
	var restFields map[string]json.RawMessage
	if err := json.Unmarshal(rest.Body.Bytes(), &restFields); err != nil {
		t.Fatalf("/rest/mempool/info.json body %q: %v", rest.Body.String(), err)
	}
	if restText := string(restFields["total_fee"]); restText != rpcText {
		t.Errorf("REST total_fee = %s, RPC total_fee = %s; want the same text", restText, rpcText)
	}
	return rpcText
}

// TestGetMempoolInfo_TotalFee_IntegerSum: Core keeps m_total_fee as a
// CAmount (integer satoshis) and renders it once with ValueFromAmount
// (rpc/mempool.cpp MempoolInfoToJSON), always with 8 decimals. Ten 10,000-sat
// fees are 100,000 sat, 0.00100000 BTC. Summing 0.0001 ten times in float64 gives 0.0010000000000000002
// whatever the order.
func TestGetMempoolInfo_TotalFee_IntegerSum(t *testing.T) {
	fees := make([]int64, 10)
	for i := range fees {
		fees[i] = 10_000
	}
	server := totalFeeServer(t, fees)
	if got := mempoolInfoTotalFeeJSON(t, server); got != "0.00100000" {
		t.Errorf("getmempoolinfo.total_fee = %s, want 0.00100000 (Core: ValueFromAmount(100000))", got)
	}
}

// TestGetMempoolInfo_TotalFee_OrderIndependent: these five fees total
// 728,200 sat (0.007282 BTC, the value in Core regtest row
// seed_warden_e/invalidate/info:total_fee). A float64 running sum lands on
// 0.007281999999999999 for some orders and 0.007282 for others, so the
// answer used to depend on Go's randomized map iteration. Every insertion
// order must give Core's exact value, 0.00728200.
func TestGetMempoolInfo_TotalFee_OrderIndependent(t *testing.T) {
	base := []int64{12345, 67890, 111111, 203040, 333814}
	orders := [][]int{
		{0, 1, 2, 3, 4}, {4, 3, 2, 1, 0}, {2, 0, 4, 1, 3},
		{1, 3, 0, 4, 2}, {3, 4, 1, 2, 0}, {0, 4, 1, 3, 2},
	}
	for _, order := range orders {
		fees := make([]int64, len(order))
		for i, j := range order {
			fees[i] = base[j]
		}
		server := totalFeeServer(t, fees)
		// Query several times: the handler walks a map, so one query
		// samples only one iteration order.
		for q := 0; q < 20; q++ {
			if got := mempoolInfoTotalFeeJSON(t, server); got != "0.00728200" {
				t.Fatalf("order %v query %d: getmempoolinfo.total_fee = %s, want 0.00728200 (Core: ValueFromAmount(728200))", order, q, got)
			}
		}
	}
}

// TestGetMempoolInfo_TotalFee_EmptyCoreFormat: an empty mempool renders
// ValueFromAmount(0) = 0.00000000. encoding/json writes a float64 zero as
// the integer 0, which Core regtest rows such as
// warden_f/f-conflict/info:total_fee report as a mismatch.
func TestGetMempoolInfo_TotalFee_EmptyCoreFormat(t *testing.T) {
	server := totalFeeServer(t, nil)
	if got := mempoolInfoTotalFeeJSON(t, server); got != "0.00000000" {
		t.Errorf("getmempoolinfo.total_fee on an empty pool = %s, want 0.00000000 (Core: ValueFromAmount(0))", got)
	}
}
