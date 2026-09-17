// R5 "returns a different result than Core" class.
// Probe source: tools/r5-probes.jsonl + tools/r5-probes.d/{rawtx-psbt,mining-relay}.jsonl
package rpc

import (
	"encoding/json"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
)

// Probe: validateaddress exact-invalid — params=["notanaddress"].
// Core key_io.cpp:126: "Invalid checksum or length of Base58 address (P2PKH or P2SH)".
func TestR5_ValidateAddress_ExactInvalid(t *testing.T) {
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
	)
	resp := testRPCRequest(t, server.handleRPC, "validateaddress", []interface{}{"notanaddress"}, "", "")
	if resp.Error != nil {
		t.Fatalf("validateaddress(notanaddress) errored: %+v", resp.Error)
	}
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["isvalid"] != false {
		t.Errorf("isvalid = %v, want false", got["isvalid"])
	}
	want := "Invalid checksum or length of Base58 address (P2PKH or P2SH)"
	if got["error"] != want {
		t.Errorf("error = %q, want %q", got["error"], want)
	}
}

// Probe: analyzepsbt analyze-exact — unsigned PSBT, no UTXO.
// Core: inputs[].is_final (not is_finalized), no missing, no top-level complete.
func TestR5_AnalyzePSBT_Exact(t *testing.T) {
	server := w125TestServer(t)
	const psbt = "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"
	resp := testRPCRequest(t, server.handleRPC, "analyzepsbt", []interface{}{psbt}, "", "")
	if resp.Error != nil {
		t.Fatalf("analyzepsbt errored: %+v", resp.Error)
	}
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := got["complete"]; ok {
		t.Errorf("unexpected top-level complete: %v", got["complete"])
	}
	inputs, _ := got["inputs"].([]interface{})
	if len(inputs) != 1 {
		t.Fatalf("inputs len = %d, want 1", len(inputs))
	}
	in, _ := inputs[0].(map[string]interface{})
	if _, ok := in["is_finalized"]; ok {
		t.Errorf("input still has is_finalized; Core names it is_final")
	}
	if in["is_final"] != false {
		t.Errorf("is_final = %v, want false", in["is_final"])
	}
	if in["has_utxo"] != false {
		t.Errorf("has_utxo = %v, want false", in["has_utxo"])
	}
	if in["next"] != "updater" {
		t.Errorf("next = %v, want updater", in["next"])
	}
	if _, ok := in["missing"]; ok {
		t.Errorf("unexpected missing object: %v", in["missing"])
	}
	if got["next"] != "updater" {
		t.Errorf("top-level next = %v, want updater", got["next"])
	}
}

// Probe: testmempoolaccept missing-inputs-exact — Core always emits wtxid.
func TestR5_TestMempoolAccept_MissingInputsExact(t *testing.T) {
	server := w125TestServer(t)
	const raw = "020000000101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000"
	resp := testRPCRequest(t, server.handleRPC, "testmempoolaccept", []interface{}{[]string{raw}}, "", "")
	if resp.Error != nil {
		t.Fatalf("testmempoolaccept errored: %+v", resp.Error)
	}
	rawJSON, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got []map[string]interface{}
	if err := json.Unmarshal(rawJSON, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	row := got[0]
	wantTxid := "5df91f99045afe09848faea0ccad4f30937be5775bf19044c4ba1fbedca54a62"
	if row["txid"] != wantTxid {
		t.Errorf("txid = %v, want %s", row["txid"], wantTxid)
	}
	if row["wtxid"] != wantTxid {
		t.Errorf("wtxid = %v, want %s (Core always emits wtxid, even when equal to txid)", row["wtxid"], wantTxid)
	}
	if row["allowed"] != false {
		t.Errorf("allowed = %v, want false", row["allowed"])
	}
	if row["reject-reason"] != "missing-inputs" {
		t.Errorf("reject-reason = %v, want missing-inputs", row["reject-reason"])
	}
}

// Probe: testmempoolaccept decode-error — params=[["deadbeef"]], expect -22.
func TestR5_TestMempoolAccept_DecodeError(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "testmempoolaccept", []interface{}{[]string{"deadbeef"}}, "", "")
	if resp.Error == nil {
		t.Fatal("testmempoolaccept([deadbeef]): expected error, call succeeded")
	}
	if resp.Error.Code != RPCErrDeserialization {
		t.Fatalf("code = %d, want %d (Core RPC_DESERIALIZATION_ERROR)", resp.Error.Code, RPCErrDeserialization)
	}
}
