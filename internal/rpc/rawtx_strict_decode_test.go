package rpc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Core's DecodeHexTx (core_io.cpp) accepts a decoding only if it consumes the
// whole input, and decoderawtransaction's iswitness restricts which decoding is
// tried. These pin the -22 answers of decoderawtransaction, sendrawtransaction
// and testmempoolaccept; before the fix each of them accepted trailing bytes
// and decoderawtransaction ignored iswitness=false on a segwit tx.

func strictDecodeSegwitTx(t *testing.T) string {
	t.Helper()
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Sequence:         0xfffffffd,
			Witness:          [][]byte{bytes.Repeat([]byte{7}, 64)},
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: append([]byte{0x00, 0x14}, make([]byte, 20)...)}},
	}
	var b bytes.Buffer
	if err := tx.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b.Bytes())
}

func requireDecode22(t *testing.T, method string, params []interface{}) {
	t.Helper()
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, method, params, "", "")
	if resp.Error == nil {
		t.Fatalf("%s: expected -22, call succeeded: %+v", method, resp.Result)
	}
	if resp.Error.Code != RPCErrDeserialization {
		t.Fatalf("%s: code = %d (%s), want -22", method, resp.Error.Code, resp.Error.Message)
	}
}

func TestRawTxStrictDecode_DecodeTrailingByte(t *testing.T) {
	requireDecode22(t, "decoderawtransaction", []interface{}{strictDecodeSegwitTx(t) + "00"})
}

func TestRawTxStrictDecode_DecodeIsWitnessFalseOnSegwit(t *testing.T) {
	requireDecode22(t, "decoderawtransaction", []interface{}{strictDecodeSegwitTx(t), false})
}

func TestRawTxStrictDecode_SendTrailingByte(t *testing.T) {
	requireDecode22(t, "sendrawtransaction", []interface{}{strictDecodeSegwitTx(t) + "00"})
}

func TestRawTxStrictDecode_TestMempoolAcceptTrailingByte(t *testing.T) {
	requireDecode22(t, "testmempoolaccept", []interface{}{[]string{strictDecodeSegwitTx(t) + "00"}})
}

// Controls: the same tx without trailing bytes still decodes, with and without
// iswitness=true; iswitness=false on a legacy tx still decodes.
func TestRawTxStrictDecode_Controls(t *testing.T) {
	server := w125TestServer(t)
	seg := strictDecodeSegwitTx(t)
	for _, params := range [][]interface{}{{seg}, {seg, true}} {
		resp := testRPCRequest(t, server.handleRPC, "decoderawtransaction", params, "", "")
		if resp.Error != nil {
			t.Fatalf("decoderawtransaction(%v): unexpected error %+v", params[1:], resp.Error)
		}
	}
	legacy := "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000"
	resp := testRPCRequest(t, server.handleRPC, "decoderawtransaction", []interface{}{legacy, false}, "", "")
	if resp.Error != nil {
		t.Fatalf("decoderawtransaction(legacy,false): unexpected error %+v", resp.Error)
	}
}
