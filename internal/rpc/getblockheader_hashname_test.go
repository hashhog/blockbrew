package rpc

import "testing"

// Core's getblockheader parses its first argument with
// ParseHashV(request.params[0], "hash") (rpc/blockchain.cpp:639), so the
// -8 messages name the argument "hash", not "blockhash".
func TestGetBlockHeaderMalformedHashNamesArgHash(t *testing.T) {
	server := w125TestServer(t)
	cases := []struct{ in, want string }{
		{"00", "hash must be of length 64 (not 2, for '00')"},
		{"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			"hash must be hexadecimal string (not 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz')"},
	}
	for _, c := range cases {
		resp := testRPCRequest(t, server.handleRPC, "getblockheader", []interface{}{c.in}, "", "")
		if resp.Error == nil {
			t.Fatalf("getblockheader(%q): expected error", c.in)
		}
		if resp.Error.Code != RPCErrInvalidParameter || resp.Error.Message != c.want {
			t.Errorf("getblockheader(%q): got %d %q, want %d %q", c.in,
				resp.Error.Code, resp.Error.Message, RPCErrInvalidParameter, c.want)
		}
	}
}
