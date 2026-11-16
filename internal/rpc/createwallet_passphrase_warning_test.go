package rpc

import (
	"testing"
)

// Core's createwallet adds "Empty string given as passphrase, wallet will not
// be encrypted." only when the passphrase argument is supplied and is the empty
// string (bitcoin-core/src/wallet/rpc/wallet.cpp, createwallet:
// `if (!request.params[3].isNull()) { ... if (passphrase.empty())
// warnings.emplace_back(...) }`). An absent or null passphrase means "not
// encrypted" without a warning.

const emptyPassphraseWarning = "Empty string given as passphrase, wallet will not be encrypted."

func createWalletWarnings(t *testing.T, params []interface{}) []interface{} {
	t.Helper()
	server := newMnemonicTestServer(t)
	resp := testRPCRequest(t, server.handleRPC, "createwallet", params, "", "")
	if resp.Error != nil {
		t.Fatalf("createwallet %v: %+v", params, resp.Error)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("createwallet result is %T, want object", resp.Result)
	}
	warnings, _ := result["warnings"].([]interface{})
	return warnings
}

func hasWarning(warnings []interface{}, want string) bool {
	for _, w := range warnings {
		if s, ok := w.(string); ok && s == want {
			return true
		}
	}
	return false
}

func TestCreateWalletNoEmptyPassphraseWarningWhenPassphraseAbsent(t *testing.T) {
	cases := map[string][]interface{}{
		"name only":       {"w"},
		"passphrase null": {"w", false, false, nil},
	}
	for label, params := range cases {
		if w := createWalletWarnings(t, params); hasWarning(w, emptyPassphraseWarning) {
			t.Errorf("%s: createwallet warned about an empty passphrase it was never given: %v", label, w)
		}
	}
}

func TestCreateWalletEmptyPassphraseWarningWhenPassphraseIsEmptyString(t *testing.T) {
	w := createWalletWarnings(t, []interface{}{"w", false, false, ""})
	if !hasWarning(w, emptyPassphraseWarning) {
		t.Errorf("createwallet with passphrase \"\" must warn like Core: %v", w)
	}
}
