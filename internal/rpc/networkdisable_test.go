package rpc

import (
	"encoding/json"
	"testing"
)

// TestNetworkDisableFlagRoundTrip exercises the RAII contract: networkDisable
// sets the flag and the returned closure clears it. Mirrors Bitcoin Core's
// NetworkDisable RAII semantics around TemporaryRollback in
// rpc/blockchain.cpp::dumptxoutset.
func TestNetworkDisableFlagRoundTrip(t *testing.T) {
	s := &Server{}
	if s.IsBlockSubmissionPaused() {
		t.Fatalf("default flag must be false")
	}

	restore := s.networkDisable()
	if !s.IsBlockSubmissionPaused() {
		t.Fatalf("networkDisable() must set the pause flag")
	}

	restore()
	if s.IsBlockSubmissionPaused() {
		t.Fatalf("restore() must clear the pause flag")
	}
}

// TestNetworkDisableDeferRestore confirms a deferred restore in a function
// scope behaves like Core's NetworkDisable destructor.
func TestNetworkDisableDeferRestore(t *testing.T) {
	s := &Server{}
	func() {
		defer s.networkDisable()()
		if !s.IsBlockSubmissionPaused() {
			t.Fatalf("inside defer scope: pause flag must be set")
		}
	}()
	if s.IsBlockSubmissionPaused() {
		t.Fatalf("after defer scope: pause flag must be cleared")
	}
}

// TestSubmitBlockRefusesWhilePaused proves handleSubmitBlock short-circuits
// with a "rejected: ... paused" reason while the rollback dance is in
// progress. We don't need a real chain — the gate runs before any
// deserialization.
func TestSubmitBlockRefusesWhilePaused(t *testing.T) {
	s := &Server{}
	restore := s.networkDisable()
	defer restore()

	// Any params: gate runs before parsing.
	rawParams := json.RawMessage(`["00"]`)
	res, rpcErr := s.handleSubmitBlock(rawParams)
	if rpcErr != nil {
		t.Fatalf("expected ok-with-reject-string, got rpc error: %v", rpcErr)
	}
	reason, ok := res.(string)
	if !ok {
		t.Fatalf("expected reject string, got %T %v", res, res)
	}
	if !contains(reason, "paused") {
		t.Fatalf("expected 'paused' in reject reason, got %q", reason)
	}
}

func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
