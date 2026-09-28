package rpc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R3: every RPC answer comes from this node's own state. The former
// nTxFromFallback asked the live Bitcoin Core on 127.0.0.1:8332 / :48343
// (with its cookie) for getblockheader's nTx. This guard fails if any
// non-test source in the package again references a Core cookie or a
// Core RPC endpoint.
func TestR3NoBitcoinCoreProxyInRPCSources(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{
		"bitcoin-core/.cookie",
		"http://127.0.0.1:8332",
		"http://127.0.0.1:48343",
		"nTxFromFallback",
		"queryBitcoinCoreNTx",
	}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for _, s := range banned {
			if strings.Contains(string(b), s) {
				t.Errorf("%s references %q: RPC answers must not be proxied from Bitcoin Core", f, s)
			}
		}
	}
	if scanned < 10 {
		t.Fatalf("scanned only %d source files; the guard is not looking at the package", scanned)
	}
}
