package rpc

import (
	"encoding/json"
	"testing"
)

// Dispatcher arity check — Core rpc/util.cpp:644 / IsValidNumArgs (:733).
//
// Fails at the parent commit: without checkCoreArity the surplus-argument calls
// are simply dispatched and succeed. savemempool failed this in 10 of 10 fleet
// implementations, clearbanned in 9 of 10.

func TestCoreArityTableLoaded(t *testing.T) {
	// Guards every other assertion here: they are all vacuous if the embedded
	// table failed to load.
	if len(coreArity) < 80 {
		t.Fatalf("arity table looks empty: %d entries", len(coreArity))
	}
	for _, m := range []string{"savemempool", "clearbanned"} {
		if _, ok := coreArity[m]; !ok {
			t.Fatalf("%s missing from the arity table", m)
		}
	}
}

func TestExtraArgumentIsRejectedWithCoreCode(t *testing.T) {
	for _, m := range []string{"savemempool", "clearbanned"} {
		err := checkCoreArity(m, json.RawMessage(`["r5-probe-extra-arg"]`))
		if err == nil {
			t.Fatalf("%s: surplus argument accepted; Core rejects it", m)
		}
		if err.Code != RPCErrMisc {
			t.Fatalf("%s: code %d, want %d (Core's arity failure)", m, err.Code, RPCErrMisc)
		}
	}
}

func TestCorrectCallsStillAccepted(t *testing.T) {
	// CONTROL. Without this, a dispatcher that rejected everything would pass
	// the test above.
	for _, m := range []string{"savemempool", "clearbanned"} {
		if err := checkCoreArity(m, json.RawMessage(`[]`)); err != nil {
			t.Fatalf("%s: correct zero-arg call rejected: %v", m, err.Message)
		}
		if err := checkCoreArity(m, nil); err != nil {
			t.Fatalf("%s: absent params rejected: %v", m, err.Message)
		}
	}
}

func TestEveryLegalArgumentCountAccepted(t *testing.T) {
	// CONTROL. gettxout takes 2 required, 3 declared; getblockhash exactly 1.
	ok := []struct {
		method string
		params string
	}{
		{"getblockhash", `[100000]`},
		{"gettxout", `["ab",0]`},
		{"gettxout", `["ab",0,true]`},
	}
	for _, c := range ok {
		if err := checkCoreArity(c.method, json.RawMessage(c.params)); err != nil {
			t.Fatalf("%s%s rejected: %v", c.method, c.params, err.Message)
		}
	}
	bad := []struct {
		method string
		params string
	}{
		{"gettxout", `["ab",0,true,"x"]`}, // one too many
		{"gettxout", `["ab"]`},            // one too few
	}
	for _, c := range bad {
		if err := checkCoreArity(c.method, json.RawMessage(c.params)); err == nil {
			t.Fatalf("%s%s accepted; Core rejects it", c.method, c.params)
		}
	}
}

func TestUnknownMethodFailsOpen(t *testing.T) {
	// Coverage is 87 of 103. Treating an unknown method as zero-arg would
	// reject calls Core accepts — worse than the gap being closed.
	if err := checkCoreArity("definitely-not-an-rpc", json.RawMessage(`["a","b"]`)); err != nil {
		t.Fatalf("unknown method should not be checked, got: %v", err.Message)
	}
}

func TestNamedParamsAreNotPositionallyChecked(t *testing.T) {
	if err := checkCoreArity("savemempool", json.RawMessage(`{"unexpected":1}`)); err != nil {
		t.Fatalf("object params should be exempt, got: %v", err.Message)
	}
}
