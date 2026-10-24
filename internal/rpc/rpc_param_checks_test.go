package rpc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Core's RPC argument type checks (rpc/util.cpp RPCTypeCheckArgument,
// AmountFromValue) and testmempoolaccept's 1..25 bound (rpc/mempool.cpp).

func TestGetBlockHeaderVerboseWrongType(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "getblockheader",
		[]interface{}{zero64, "x"}, "", "")
	if resp.Error == nil {
		t.Fatalf("verbose \"x\": expected error, got result %v", resp.Result)
	}
	if resp.Error.Code != RPCErrTypeError {
		t.Errorf("code = %d, want -3", resp.Error.Code)
	}
	want := "Wrong type passed:\n{\n    \"Position 2 (verbose)\": \"JSON value of type string is not of expected type bool\"\n}"
	if resp.Error.Message != want {
		t.Errorf("message = %q, want %q", resp.Error.Message, want)
	}
}

func TestSendRawTransactionMaxFeeRateInvalidAmount(t *testing.T) {
	server := w125TestServer(t)
	// A decodable tx: the amount error must come back before the tx is
	// accepted, relayed or even looked up.
	mtx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Index: 0}, Sequence: 0xfffffffd}},
		TxOut:   []*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}},
	}
	var buf bytes.Buffer
	if err := mtx.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	tx := hex.EncodeToString(buf.Bytes())
	resp := testRPCRequest(t, server.handleRPC, "sendrawtransaction",
		[]interface{}{tx, "x"}, "", "")
	if resp.Error == nil {
		t.Fatalf("maxfeerate \"x\": expected error, got result %v", resp.Result)
	}
	if resp.Error.Code != RPCErrTypeError || resp.Error.Message != "Invalid amount" {
		t.Errorf("got %d %q, want -3 \"Invalid amount\"", resp.Error.Code, resp.Error.Message)
	}
}

func TestTestMempoolAcceptRawtxsChecks(t *testing.T) {
	server := w125TestServer(t)

	t.Run("string-rawtxs", func(t *testing.T) {
		resp := testRPCRequest(t, server.handleRPC, "testmempoolaccept",
			[]interface{}{"00"}, "", "")
		if resp.Error == nil {
			t.Fatalf("expected error, got %v", resp.Result)
		}
		want := "Wrong type passed:\n{\n    \"Position 1 (rawtxs)\": \"JSON value of type string is not of expected type array\"\n}"
		if resp.Error.Code != RPCErrTypeError || resp.Error.Message != want {
			t.Errorf("got %d %q, want -3 %q", resp.Error.Code, resp.Error.Message, want)
		}
	})

	t.Run("empty-array", func(t *testing.T) {
		resp := testRPCRequest(t, server.handleRPC, "testmempoolaccept",
			[]interface{}{[]interface{}{}}, "", "")
		if resp.Error == nil {
			t.Fatalf("expected error, got %v", resp.Result)
		}
		if resp.Error.Code != RPCErrInvalidParameter ||
			resp.Error.Message != "Array must contain between 1 and 25 transactions." {
			t.Errorf("got %d %q, want -8 bounds error", resp.Error.Code, resp.Error.Message)
		}
	})

	t.Run("26-entries", func(t *testing.T) {
		arr := make([]interface{}, 26)
		for i := range arr {
			arr[i] = "00"
		}
		resp := testRPCRequest(t, server.handleRPC, "testmempoolaccept",
			[]interface{}{arr}, "", "")
		if resp.Error == nil || resp.Error.Code != RPCErrInvalidParameter {
			t.Errorf("26 entries: got %+v, want -8", resp.Error)
		}
	})
}
