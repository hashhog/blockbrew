// R5 error-code parity: Core's code for the same bad input.
package rpc

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
)

func TestR5_GetBlockStats_NotFound(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "getblockstats",
		[]interface{}{"0000000000000000000000000000000000000000000000000000000000000001"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidAddressOrKey {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidAddressOrKey)
	}
}

func TestR5_AddNode_InvalidCommand(t *testing.T) {
	server := w125TestServerWithPeerMgr(t)
	resp := testRPCRequest(t, server.handleRPC, "addnode",
		[]interface{}{"192.0.2.1:8333", "notacommand"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrMisc {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrMisc)
	}
}

func TestR5_DecodeScript_NonHex(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "decodescript", []interface{}{"zz"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestR5_VerifyTxOutProof_NonHex(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "verifytxoutproof", []interface{}{"zz"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestR5_GetTxSpendingPrevout_MissingVout(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "gettxspendingprevout",
		[]interface{}{[]interface{}{map[string]interface{}{"txid": "0000000000000000000000000000000000000000000000000000000000000000"}}}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrTypeError {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrTypeError)
	}
}

func TestR5_PrioritiseTransaction_BadTxid(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "prioritisetransaction",
		[]interface{}{"zz", 0, 1000}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestR5_ScanBlocks_BadAction(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "scanblocks", []interface{}{"bogus"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestR5_ScanTxOutSet_BadAction(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "scantxoutset", []interface{}{"bogus"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestR5_CombinePSBT_EmptyArray(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "combinepsbt", []interface{}{[]string{}}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestR5_SubmitPackage_EmptyArray(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "submitpackage", []interface{}{[]string{}}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestR5_CreateMultisig_InvalidPubkey(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "createmultisig",
		[]interface{}{1, []string{"deadbeef"}}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidAddressOrKey {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidAddressOrKey)
	}
}

func TestR5_CreateMultisig_NotEnoughKeys(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "createmultisig",
		[]interface{}{3, []string{
			"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd",
			"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626",
		}}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestR5_GetDescriptorInfo_Invalid(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "getdescriptorinfo", []interface{}{"notadescriptor"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidAddressOrKey {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidAddressOrKey)
	}
}

func TestR5_GetDescriptorInfo_BadChecksum(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "getdescriptorinfo",
		[]interface{}{"wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)#00000000"}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidAddressOrKey {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidAddressOrKey)
	}
}

func TestR5_CreatePSBT_CanonicalExact(t *testing.T) {
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
	)
	resp := testRPCRequest(t, server.handleRPC, "createpsbt",
		[]interface{}{
			[]interface{}{map[string]interface{}{"txid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "vout": 0}},
			map[string]interface{}{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 0.001},
		}, "", "")
	if resp.Error != nil {
		t.Fatalf("createpsbt errored: %+v", resp.Error)
	}
	want := "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"
	if resp.Result != want {
		t.Fatalf("createpsbt = %v, want %s", resp.Result, want)
	}
}

func TestR5_CreatePSBT_BadTxid(t *testing.T) {
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
	)
	resp := testRPCRequest(t, server.handleRPC, "createpsbt",
		[]interface{}{
			[]interface{}{map[string]interface{}{"txid": "zz", "vout": 0}},
			map[string]interface{}{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 0.001},
		}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidParameter)
	}
}

func TestR5_JoinPSBTs_Exact(t *testing.T) {
	server := w125TestServer(t)
	a := "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"
	b := "cHNidP8BACkCAAAAAAGghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAAAAAA"
	resp := testRPCRequest(t, server.handleRPC, "joinpsbts", []interface{}{[]string{a, b}}, "", "")
	if resp.Error != nil {
		t.Fatalf("joinpsbts errored: %+v", resp.Error)
	}
	want := "cHNidP8BAHECAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AqCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9aghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAAAAAAAAA="
	if resp.Result != want {
		t.Fatalf("joinpsbts = %v, want %s", resp.Result, want)
	}
}

func TestR5_DescriptorProcessPSBT_BadDescriptor(t *testing.T) {
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
	)
	psbt := "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"
	resp := testRPCRequest(t, server.handleRPC, "descriptorprocesspsbt",
		[]interface{}{psbt, []string{"nonsense(desc)"}}, "", "")
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != RPCErrInvalidAddressOrKey {
		t.Fatalf("code = %d, want %d", resp.Error.Code, RPCErrInvalidAddressOrKey)
	}
}

func TestR5_DescriptorProcessPSBT_UpdateExact(t *testing.T) {
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
	)
	psbt := "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"
	desc := []string{"wpkh(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn)"}
	resp := testRPCRequest(t, server.handleRPC, "descriptorprocesspsbt",
		[]interface{}{psbt, desc}, "", "")
	if resp.Error != nil {
		t.Fatalf("descriptorprocesspsbt errored: %+v", resp.Error)
	}
	got, _ := resp.Result.(map[string]interface{})
	if got["complete"] != false {
		t.Errorf("complete = %v, want false", got["complete"])
	}
	wantPSBT := "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAiAgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAR1HnboAA=="
	if got["psbt"] != wantPSBT {
		t.Errorf("psbt = %v, want %s", got["psbt"], wantPSBT)
	}
}

func TestR5_HelpListsClearbannedAndCreaterawtransaction(t *testing.T) {
	server := w125TestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "help", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("help errored: %+v", resp.Error)
	}
	text, _ := resp.Result.(string)
	// Live probe 20260917T070153Z on 13ea105: these 16 answer Core-correctly
	// but fail help-parity. clearbanned/createrawtransaction were the previous
	// two; keep them so a regression in either class is visible.
	want := []string{
		"clearbanned",
		"createrawtransaction",
		"analyzepsbt",
		"combinepsbt",
		"combinerawtransaction",
		"createmultisig",
		"createpsbt",
		"deriveaddresses",
		"getdescriptorinfo",
		"getnetworkhashps",
		"gettxspendingprevout",
		"joinpsbts",
		"prioritisetransaction",
		"scanblocks",
		"scantxoutset",
		"submitpackage",
		"validateaddress",
		"verifytxoutproof",
	}
	for _, m := range want {
		found := false
		for _, line := range splitHelpLines(text) {
			line = trimHelpLine(line)
			if line == m || (len(line) > len(m) && line[:len(m)] == m && (line[len(m)] == ' ' || line[len(m)] == '(')) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("help does not list %s", m)
		}
	}
}

func trimHelpLine(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
}

func splitHelpLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if line != "" {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
