// Package rpc — ParseHashV (-8) parity test for malformed txid/blockhash args.
//
// Mirrors Bitcoin Core's ParseHashV (bitcoin-core/src/rpc/util.cpp:117):
// a MALFORMED hash (wrong length, OR right length but non-hex) is rejected at
// the parse boundary with RPC_INVALID_PARAMETER (-8) BEFORE any lookup. A
// WELL-FORMED 64-hex hash that is simply absent keeps the handler's -5
// (RPC_INVALID_ADDRESS_OR_KEY), or null for gettxout.
//
// This test pins BOTH directions for every method whose hash-parse boundary
// was aligned to -8: getrawtransaction, gettxout, getblock, getblockheader,
// getmempoolentry. The two malformed flavors exercised per method:
//   - too-short hex  ("abc")        -> wrong length -> -8
//   - 64-char non-hex (64 'z' chars) -> right length, bad chars -> -8
package rpc

import (
	"strings"
	"testing"
)

// zero64 is a well-formed (64-char, all-hex) but absent hash.
const zero64 = "0000000000000000000000000000000000000000000000000000000000000000"

// badNonHex64 is right length (64) but contains non-hex characters.
var badNonHex64 = strings.Repeat("z", 64)

// malformedHashCases: the two malformed flavors Core's ParseHashV distinguishes.
var malformedHashCases = []struct {
	name string
	hash string
}{
	{"too-short-hex", "abc"},
	{"len64-non-hex", badNonHex64},
}

// parseHashMethods drives each fixed RPC with a hash in the named arg slot.
// argsFor builds the params slice given the hash to inject.
var parseHashMethods = []struct {
	method  string
	argName string
	argsFor func(hash string) []interface{}
}{
	{"getrawtransaction", "txid", func(h string) []interface{} { return []interface{}{h} }},
	{"gettxout", "txid", func(h string) []interface{} { return []interface{}{h, float64(0)} }},
	{"getblock", "blockhash", func(h string) []interface{} { return []interface{}{h} }},
	{"getblockheader", "blockhash", func(h string) []interface{} { return []interface{}{h} }},
	{"getmempoolentry", "txid", func(h string) []interface{} { return []interface{}{h} }},
}

// TestParseHashV_Malformed_Minus8 — direction (a): malformed hash -> -8.
func TestParseHashV_Malformed_Minus8(t *testing.T) {
	server := w125TestServer(t)
	for _, m := range parseHashMethods {
		for _, c := range malformedHashCases {
			t.Run(m.method+"/"+c.name, func(t *testing.T) {
				resp := testRPCRequest(t, server.handleRPC, m.method, m.argsFor(c.hash), "", "")
				if resp.Error == nil {
					t.Fatalf("%s(%q): expected error, got nil", m.method, c.hash)
				}
				if resp.Error.Code != RPCErrInvalidParameter {
					t.Errorf("%s(%q): code = %d, want %d (-8 RPC_INVALID_PARAMETER)",
						m.method, c.hash, resp.Error.Code, RPCErrInvalidParameter)
				}
				// Message must name the arg, Core-style (ParseHashV strprintf).
				if !strings.Contains(resp.Error.Message, m.argName) {
					t.Errorf("%s(%q): message = %q, want it to mention %q",
						m.method, c.hash, resp.Error.Message, m.argName)
				}
			})
		}
	}
}

// TestParseHashV_WellFormedAbsent_Minus5OrNull — direction (b):
// a well-formed-but-absent 64-zero hash keeps the handler's -5 (or null for
// gettxout). This guards against the fix over-reaching into the lookup path.
func TestParseHashV_WellFormedAbsent_Minus5OrNull(t *testing.T) {
	server := w125TestServer(t)

	// gettxout: absent output -> null result, NO error.
	t.Run("gettxout/absent-null", func(t *testing.T) {
		resp := testRPCRequest(t, server.handleRPC, "gettxout",
			[]interface{}{zero64, float64(0)}, "", "")
		if resp.Error != nil {
			t.Fatalf("gettxout(absent): unexpected error code=%d msg=%q (want null result)",
				resp.Error.Code, resp.Error.Message)
		}
		if resp.Result != nil {
			t.Errorf("gettxout(absent): result = %v, want null", resp.Result)
		}
	})

	// getrawtransaction / getblock / getblockheader / getmempoolentry:
	// absent well-formed hash -> -5 (RPC_INVALID_ADDRESS_OR_KEY).
	for _, method := range []string{"getrawtransaction", "getblock", "getblockheader", "getmempoolentry"} {
		t.Run(method+"/absent-minus5", func(t *testing.T) {
			resp := testRPCRequest(t, server.handleRPC, method,
				[]interface{}{zero64}, "", "")
			if resp.Error == nil {
				t.Fatalf("%s(absent): expected -5 error, got nil", method)
			}
			if resp.Error.Code != RPCErrInvalidAddressOrKey {
				t.Errorf("%s(absent well-formed): code = %d, want %d (-5 RPC_INVALID_ADDRESS_OR_KEY)",
					method, resp.Error.Code, RPCErrInvalidAddressOrKey)
			}
		})
	}
}
