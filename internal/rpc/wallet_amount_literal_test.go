package rpc

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Wallet RPC amounts are printed the way Core prints them.
//
// Core renders every BTC amount through ValueFromAmount (core_io.cpp), which
// builds the number from "%s%d.%08d": 1 BTC is the literal 1.00000000, never
// 1. getbalance (wallet/rpc/coins.cpp), getbalances, listunspent,
// listtransactions and gettransaction (wallet/rpc/transactions.cpp, its
// "amount", "fee" and details[].amount / .fee) all go through it.
// encoding/json prints a float64 holding 1.0 as 1, so a client that reads the
// literal (or the Core regtest harness, which keeps int and float apart) saw a
// different value.

var coreAmountLiteral = regexp.MustCompile(`^-?[0-9]+\.[0-9]{8}$`)

// amountLiteralKeys are the BTC-amount fields of the wallet RPCs under test.
var amountLiteralKeys = map[string]bool{
	"amount": true, "fee": true, "trusted": true, "untrusted_pending": true, "immature": true,
}

// rawWalletRPC returns the "result" member of the reply as the bytes the
// server wrote, so the number literals can be inspected.
func rawWalletRPC(t *testing.T, s *Server, method string, params []interface{}) json.RawMessage {
	t.Helper()
	p, _ := json.Marshal(params)
	body, _ := json.Marshal(RPCRequest{JSONRPC: "1.0", ID: "t", Method: method, Params: p})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleRPC(rr, req)
	var reply struct {
		Result json.RawMessage  `json:"result"`
		Error  *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &reply); err != nil {
		t.Fatalf("%s: decode reply: %v (%s)", method, err, rr.Body.String())
	}
	if reply.Error != nil && string(*reply.Error) != "null" {
		t.Fatalf("%s: error %s", method, *reply.Error)
	}
	return reply.Result
}

// amountLiterals walks a JSON value and returns "path=literal" for every
// number found under one of amountLiteralKeys (or the bare top-level number).
func amountLiterals(t *testing.T, raw json.RawMessage) map[string]string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	out := map[string]string{}
	var walk func(path, key string, v interface{})
	walk = func(path, key string, v interface{}) {
		switch x := v.(type) {
		case json.Number:
			if key == "$" || amountLiteralKeys[key] {
				out[path] = x.String()
			}
		case map[string]interface{}:
			for k, e := range x {
				walk(path+"."+k, k, e)
			}
		case []interface{}:
			for i, e := range x {
				walk(path+"["+strconv.Itoa(i)+"]", key, e)
			}
		}
	}
	walk("$", "$", v)
	return out
}

func requireCoreLiterals(t *testing.T, method string, raw json.RawMessage, wantAtLeast int) {
	t.Helper()
	lits := amountLiterals(t, raw)
	if len(lits) < wantAtLeast {
		t.Fatalf("%s: found %d amount fields, want at least %d (reply %s)", method, len(lits), wantAtLeast, raw)
	}
	for path, lit := range lits {
		if !coreAmountLiteral.MatchString(lit) {
			t.Errorf("%s %s = %s, Core prints amounts with 8 decimals (ValueFromAmount)", method, path, lit)
		}
	}
}

// amountLiteralServer: regtest chain at height 3, a wallet funded with a
// 50 BTC payment at height 1 that sends 1 BTC to itself at height 2 with
// 48.9999 BTC change. Whole-valued (50, 1, -1) and fractional amounts both
// appear in the replies.
func amountLiteralServer(t *testing.T) (*Server, wire.Hash256) {
	t.Helper()
	params, cm := immatureTestChain(t, 3)
	mgr := wallet.NewManager(t.TempDir(), address.Regtest, params)
	s := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithChainManager(cm),
		WithWalletManager(mgr),
	)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"w"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	w, err := mgr.GetWallet("w")
	if err != nil {
		t.Fatalf("GetWallet: %v", err)
	}
	spk := func(a string, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatalf("address: %v", err)
		}
		d, err := address.DecodeAddress(a, address.Regtest)
		if err != nil {
			t.Fatalf("DecodeAddress: %v", err)
		}
		return d.ScriptPubKey()
	}
	recv := spk(w.NewAddress())
	second := spk(w.NewAddress())
	change := spk(w.NewChangeAddress())

	// Each block leads with a foreign coinbase so the wallet's transactions
	// are ordinary (index > 0), not coinbase outputs.
	coinbase := func(h byte) *wire.MsgTx {
		return &wire.MsgTx{
			Version: 1,
			TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, SignatureScript: []byte{0x01, h}, Sequence: 0xffffffff}},
			TxOut:   []*wire.TxOut{{Value: 50_0000_0000, PkScript: []byte{0x51}}},
		}
	}
	fund := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x77}, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 50_0000_0000, PkScript: recv}},
	}
	w.ScanBlock(&wire.MsgBlock{Header: wire.BlockHeader{Timestamp: 1}, Transactions: []*wire.MsgTx{coinbase(1), fund}}, 1)
	spend := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: fund.TxHash(), Index: 0}, Sequence: 0xffffffff}},
		TxOut: []*wire.TxOut{
			{Value: 1_0000_0000, PkScript: second},
			{Value: 48_9999_0000, PkScript: change},
		},
	}
	w.ScanBlock(&wire.MsgBlock{Header: wire.BlockHeader{Timestamp: 2}, Transactions: []*wire.MsgTx{coinbase(2), spend}}, 2)
	return s, spend.TxHash()
}

func TestWalletAmountLiteral_GetTransaction(t *testing.T) {
	s, txid := amountLiteralServer(t)
	raw := rawWalletRPC(t, s, "gettransaction", []interface{}{txid.String()})
	// amount, fee, and the amount of each of the two details (+ the send's fee).
	requireCoreLiterals(t, "gettransaction", raw, 4)
}

func TestWalletAmountLiteral_ListTransactions(t *testing.T) {
	s, _ := amountLiteralServer(t)
	requireCoreLiterals(t, "listtransactions", rawWalletRPC(t, s, "listtransactions", []interface{}{}), 2)
}

func TestWalletAmountLiteral_GetBalance(t *testing.T) {
	s, _ := amountLiteralServer(t)
	requireCoreLiterals(t, "getbalance", rawWalletRPC(t, s, "getbalance", []interface{}{}), 1)
}

func TestWalletAmountLiteral_GetBalances(t *testing.T) {
	s, _ := amountLiteralServer(t)
	requireCoreLiterals(t, "getbalances", rawWalletRPC(t, s, "getbalances", []interface{}{}), 3)
}

func TestWalletAmountLiteral_ListUnspent(t *testing.T) {
	s, _ := amountLiteralServer(t)
	requireCoreLiterals(t, "listunspent", rawWalletRPC(t, s, "listunspent", []interface{}{}), 2)
}

// Control: the value is unchanged, only its literal. 48.9999 BTC change plus
// the 1 BTC self-send are the confirmed balance.
func TestWalletAmountLiteral_ValueUnchanged(t *testing.T) {
	s, _ := amountLiteralServer(t)
	raw := rawWalletRPC(t, s, "getbalance", []interface{}{})
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("getbalance %s: %v", raw, err)
	}
	if f != 49.9999 {
		t.Fatalf("getbalance = %v, want 49.9999", f)
	}
}
