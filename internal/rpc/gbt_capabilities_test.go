package rpc

import (
	"reflect"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
)

// Core rpc/mining.cpp:948 always emits "capabilities": ["proposal"] in a
// block template (aCaps.push_back("proposal")); BIP-23 clients read it to
// learn that mode=proposal is supported.
func TestGBTCapabilitiesListsProposal(t *testing.T) {
	server := gbtRulesTestSetup(t, consensus.RegtestParams())
	resp := testRPCRequest(t, server.handleRPC, "getblocktemplate", gbtSegwitRequest(), "", "")
	if resp.Error != nil {
		t.Fatalf("getblocktemplate error: %v", resp.Error)
	}
	m, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type %T", resp.Result)
	}
	caps, present := m["capabilities"]
	if !present {
		t.Fatal("capabilities missing; Core always emits [\"proposal\"]")
	}
	want := []interface{}{"proposal"}
	if !reflect.DeepEqual(caps, want) {
		t.Fatalf("capabilities = %v, want %v", caps, want)
	}
}
