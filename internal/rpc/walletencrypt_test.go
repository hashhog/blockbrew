package rpc

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wallet"
)

// newEncTestWallet builds a fresh, unencrypted, unlocked wallet for the
// encryption RPC tests below.
func newEncTestWallet(t *testing.T) *wallet.Wallet {
	t.Helper()
	w := wallet.NewWallet(wallet.WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
		AddressType: wallet.AddressTypeP2WPKH,
	})
	if err := w.CreateFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"",
	); err != nil {
		t.Fatalf("CreateFromMnemonic: %v", err)
	}
	return w
}

// TestRPCEncryptWalletRoundTrip drives encryptwallet -> walletpassphrase ->
// walletlock end-to-end through the RPC dispatcher and asserts the wallet
// state transitions match Bitcoin Core's documented behaviour.
func TestRPCEncryptWalletRoundTrip(t *testing.T) {
	w := newEncTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
		WithWallet(w),
	)

	// encryptwallet "pw"
	resp := testRPCRequest(t, server.handleRPC, "encryptwallet", []interface{}{"pw"}, "", "")
	if resp.Error != nil {
		t.Fatalf("encryptwallet: %+v", resp.Error)
	}
	if !w.IsEncrypted() {
		t.Fatal("wallet should be encrypted")
	}
	if !w.IsLocked() {
		t.Fatal("wallet should be locked after encryptwallet")
	}

	// encryptwallet again -> -15 wrong enc state
	resp = testRPCRequest(t, server.handleRPC, "encryptwallet", []interface{}{"pw"}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrWalletWrongEncState {
		t.Fatalf("expected -15 wrong enc state on double encrypt, got %+v", resp.Error)
	}

	// walletpassphrase wrong pw -> -14
	resp = testRPCRequest(t, server.handleRPC, "walletpassphrase", []interface{}{"wrong", float64(60)}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrWalletPassphraseIncorrect {
		t.Fatalf("expected -14 incorrect on wrong passphrase, got %+v", resp.Error)
	}
	if !w.IsLocked() {
		t.Fatal("wallet must stay locked after a failed unlock")
	}

	// walletpassphrase right pw, 60s -> nil
	resp = testRPCRequest(t, server.handleRPC, "walletpassphrase", []interface{}{"pw", float64(60)}, "", "")
	if resp.Error != nil {
		t.Fatalf("walletpassphrase right pw: %+v", resp.Error)
	}
	if w.IsLocked() {
		t.Fatal("wallet should be unlocked after walletpassphrase with correct pw")
	}

	// walletlock -> nil and locked
	resp = testRPCRequest(t, server.handleRPC, "walletlock", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("walletlock: %+v", resp.Error)
	}
	if !w.IsLocked() {
		t.Fatal("wallet should be locked after walletlock")
	}
}

// TestRPCWalletLockUnencryptedRejected asserts walletlock rejects calls on
// unencrypted wallets with -15 (Core's RPC_WALLET_WRONG_ENC_STATE).
func TestRPCWalletLockUnencryptedRejected(t *testing.T) {
	w := newEncTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
		WithWallet(w),
	)

	resp := testRPCRequest(t, server.handleRPC, "walletlock", []interface{}{}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrWalletWrongEncState {
		t.Fatalf("expected -15 on walletlock for unencrypted wallet, got %+v", resp.Error)
	}
}

// TestRPCEncryptWalletEmptyPassphrase asserts the empty-passphrase guard
// matches Core's -8 RPC_INVALID_PARAMETER.
func TestRPCEncryptWalletEmptyPassphrase(t *testing.T) {
	w := newEncTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
		WithWallet(w),
	)

	resp := testRPCRequest(t, server.handleRPC, "encryptwallet", []interface{}{""}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("expected -8 invalid parameter on empty passphrase, got %+v", resp.Error)
	}
	if w.IsEncrypted() {
		t.Fatal("wallet must not be encrypted when input was rejected")
	}
}

// TestRPCWalletPassphraseAutoRelock exercises the time.AfterFunc auto-relock
// path through the RPC layer with a 1s timeout.
func TestRPCWalletPassphraseAutoRelock(t *testing.T) {
	w := newEncTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
		WithWallet(w),
	)

	if resp := testRPCRequest(t, server.handleRPC, "encryptwallet", []interface{}{"pw"}, "", ""); resp.Error != nil {
		t.Fatalf("encryptwallet: %+v", resp.Error)
	}
	if resp := testRPCRequest(t, server.handleRPC, "walletpassphrase", []interface{}{"pw", float64(1)}, "", ""); resp.Error != nil {
		t.Fatalf("walletpassphrase: %+v", resp.Error)
	}
	if w.IsLocked() {
		t.Fatal("wallet should be unlocked immediately after walletpassphrase")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if w.IsLocked() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !w.IsLocked() {
		t.Fatal("wallet should have auto-relocked after the timeout")
	}
}

// TestRPCWalletPassphraseNegativeTimeout asserts negative timeouts are rejected.
func TestRPCWalletPassphraseNegativeTimeout(t *testing.T) {
	w := newEncTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
		WithWallet(w),
	)

	if resp := testRPCRequest(t, server.handleRPC, "encryptwallet", []interface{}{"pw"}, "", ""); resp.Error != nil {
		t.Fatalf("encryptwallet: %+v", resp.Error)
	}
	resp := testRPCRequest(t, server.handleRPC, "walletpassphrase", []interface{}{"pw", float64(-1)}, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("expected -8 invalid parameter on negative timeout, got %+v", resp.Error)
	}
}
