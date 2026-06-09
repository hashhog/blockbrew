package rpc

import (
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wallet"
)

// Tests for the W161 BUG-15/17 funds-loss fix at the RPC surface:
//
//   - createwallet returns the freshly GENERATED mnemonic exactly once
//     (non-Core extension, btcd/lnd convention) plus a back-it-up warning;
//   - getmnemonic re-exports the words, unlock-gated like Core's
//     listdescriptors private=true (bitcoin-core/src/wallet/rpc/backup.cpp);
//   - the restore path does NOT echo the caller's own words back;
//   - blank wallets report "no mnemonic stored" rather than demanding an
//     unlock that could never reveal anything.

const testRPCMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func newMnemonicTestServer(t *testing.T) *Server {
	t.Helper()
	mgr := wallet.NewManager(t.TempDir(), address.Mainnet, consensus.MainnetParams())
	return NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
		WithWalletManager(mgr),
	)
}

func TestRPCCreateWalletReturnsMnemonicAndGetMnemonicRoundTrips(t *testing.T) {
	server := newMnemonicTestServer(t)

	// createwallet "bug15" — fresh wallet, auto-generated mnemonic.
	resp := testRPCRequest(t, server.handleRPC, "createwallet", []interface{}{"bug15"}, "", "")
	if resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("createwallet result is %T, want object", resp.Result)
	}

	// The generated words must be in the response (the user's one shot to see
	// them at creation) and must be a valid 24-word BIP-39 phrase.
	mnemonic, _ := result["mnemonic"].(string)
	if mnemonic == "" {
		t.Fatalf("FUNDS-LOSS (W161 BUG-15): createwallet response has no mnemonic — result: %v", result)
	}
	if !wallet.ValidateMnemonic(mnemonic) {
		t.Fatalf("createwallet returned an invalid mnemonic: %q", mnemonic)
	}
	if got := len(strings.Fields(mnemonic)); got != 24 {
		t.Errorf("createwallet mnemonic has %d words, want 24", got)
	}

	// A back-it-up warning must accompany the words.
	warnings, _ := result["warnings"].([]interface{})
	foundWarning := false
	for _, w := range warnings {
		if s, ok := w.(string); ok && strings.Contains(s, "Write down the mnemonic") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Errorf("createwallet warnings missing the back-up-the-mnemonic warning: %v", warnings)
	}

	// getmnemonic must round-trip the same words (W161 BUG-17: the export
	// surface, so the words stay recoverable after the createwallet response
	// is gone).
	resp = testRPCRequest(t, server.handleRPC, "getmnemonic", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("getmnemonic: %+v", resp.Error)
	}
	if got, _ := resp.Result.(string); got != mnemonic {
		t.Fatalf("getmnemonic = %q, want the createwallet mnemonic %q", got, mnemonic)
	}

	// Unlock gating: once the wallet is encrypted (and therefore locked),
	// getmnemonic must refuse with -13 walletpassphrase-first, mirroring
	// Core's EnsureWalletIsUnlocked gate on listdescriptors private=true.
	resp = testRPCRequest(t, server.handleRPC, "encryptwallet", []interface{}{"pw"}, "", "")
	if resp.Error != nil {
		t.Fatalf("encryptwallet: %+v", resp.Error)
	}
	resp = testRPCRequest(t, server.handleRPC, "getmnemonic", []interface{}{}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrWalletUnlockNeeded {
		t.Fatalf("getmnemonic on locked wallet: want error %d, got %+v", RPCErrWalletUnlockNeeded, resp.Error)
	}

	// After walletpassphrase the export works again.
	resp = testRPCRequest(t, server.handleRPC, "walletpassphrase", []interface{}{"pw", float64(60)}, "", "")
	if resp.Error != nil {
		t.Fatalf("walletpassphrase: %+v", resp.Error)
	}
	resp = testRPCRequest(t, server.handleRPC, "getmnemonic", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("getmnemonic after unlock: %+v", resp.Error)
	}
	if got, _ := resp.Result.(string); got != mnemonic {
		t.Fatalf("getmnemonic after unlock = %q, want %q", got, mnemonic)
	}
}

func TestRPCCreateWalletRestoreOmitsMnemonicFromResponse(t *testing.T) {
	server := newMnemonicTestServer(t)

	// Restore path: args[9] carries the caller's own words — echoing them back
	// adds nothing and strict Core parity returns only name+warnings, so the
	// field must be absent (omitempty).
	args := []interface{}{"restored", false, false, "", false, true, false, false, "", testRPCMnemonic}
	resp := testRPCRequest(t, server.handleRPC, "createwallet", args, "", "")
	if resp.Error != nil {
		t.Fatalf("createwallet(restore): %+v", resp.Error)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("createwallet result is %T, want object", resp.Result)
	}
	if m, present := result["mnemonic"]; present {
		t.Errorf("restore-path createwallet echoed the mnemonic back: %v", m)
	}

	// But the restored words ARE persisted and exportable.
	resp = testRPCRequest(t, server.handleRPC, "getmnemonic", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("getmnemonic: %+v", resp.Error)
	}
	if got, _ := resp.Result.(string); got != testRPCMnemonic {
		t.Fatalf("getmnemonic = %q, want restored words %q", got, testRPCMnemonic)
	}
}

func TestRPCGetMnemonicUnavailableForBlankWallet(t *testing.T) {
	server := newMnemonicTestServer(t)

	// blank=true wallet has no keys and no mnemonic.
	resp := testRPCRequest(t, server.handleRPC, "createwallet", []interface{}{"blankw", false, true}, "", "")
	if resp.Error != nil {
		t.Fatalf("createwallet(blank): %+v", resp.Error)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("createwallet result is %T, want object", resp.Result)
	}
	if m, present := result["mnemonic"]; present {
		t.Errorf("blank-wallet createwallet returned a mnemonic: %v", m)
	}

	resp = testRPCRequest(t, server.handleRPC, "getmnemonic", []interface{}{}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrWalletError {
		t.Fatalf("getmnemonic on blank wallet: want error %d (no mnemonic stored), got %+v", RPCErrWalletError, resp.Error)
	}
}
