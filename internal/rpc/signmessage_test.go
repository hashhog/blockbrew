package rpc

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	bbcrypto "github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wallet"
)

// genWalletWithP2PKH constructs an unlocked wallet whose default address type
// is legacy P2PKH (the only type Core's signmessage / verifymessage accept),
// and returns the wallet plus a freshly issued P2PKH address.
func genWalletWithP2PKH(t *testing.T) (*wallet.Wallet, string) {
	t.Helper()
	w := wallet.NewWallet(wallet.WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
		AddressType: wallet.AddressTypeP2PKH,
	})
	if err := w.CreateFromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", ""); err != nil {
		t.Fatalf("CreateFromMnemonic: %v", err)
	}
	addr, err := w.NewP2PKHAddress()
	if err != nil {
		t.Fatalf("NewP2PKHAddress: %v", err)
	}
	if !strings.HasPrefix(addr, "1") {
		t.Fatalf("expected P2PKH (mainnet '1...'), got %q", addr)
	}
	return w, addr
}

// TestSignAndVerifyMessageRoundTrip drives the public RPC surface end-to-end:
// signmessage produces a signature; verifymessage accepts it; tampering with
// either the message or the address makes verification fail. This is the
// minimum guarantee callers depend on.
func TestSignAndVerifyMessageRoundTrip(t *testing.T) {
	w, addr := genWalletWithP2PKH(t)

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
		WithWallet(w),
	)

	const msg = "blockbrew signmessage round-trip"

	resp := testRPCRequest(t, server.handleRPC, "signmessage", []interface{}{addr, msg}, "", "")
	if resp.Error != nil {
		t.Fatalf("signmessage error: %+v", resp.Error)
	}
	sigB64, ok := resp.Result.(string)
	if !ok || sigB64 == "" {
		t.Fatalf("signmessage result not a non-empty string: %#v", resp.Result)
	}
	if _, err := base64.StdEncoding.DecodeString(sigB64); err != nil {
		t.Fatalf("signmessage produced non-base64 result: %v", err)
	}

	// verifymessage should accept the produced signature.
	resp = testRPCRequest(t, server.handleRPC, "verifymessage", []interface{}{addr, sigB64, msg}, "", "")
	if resp.Error != nil {
		t.Fatalf("verifymessage error: %+v", resp.Error)
	}
	ok, _ = resp.Result.(bool)
	if !ok {
		t.Fatalf("expected verifymessage true, got %#v", resp.Result)
	}

	// Different message -> false.
	resp = testRPCRequest(t, server.handleRPC, "verifymessage", []interface{}{addr, sigB64, msg + "!"}, "", "")
	if resp.Error != nil {
		t.Fatalf("verifymessage tampered error: %+v", resp.Error)
	}
	if v, _ := resp.Result.(bool); v {
		t.Fatalf("verifymessage should reject tampered message, got true")
	}

	// Different address (regenerate a second one from the same wallet) -> false.
	addr2, err := w.NewP2PKHAddress()
	if err != nil {
		t.Fatalf("second NewP2PKHAddress: %v", err)
	}
	if addr2 == addr {
		t.Fatalf("second derived address must differ from first")
	}
	resp = testRPCRequest(t, server.handleRPC, "verifymessage", []interface{}{addr2, sigB64, msg}, "", "")
	if resp.Error != nil {
		t.Fatalf("verifymessage other-addr error: %+v", resp.Error)
	}
	if v, _ := resp.Result.(bool); v {
		t.Fatalf("verifymessage should reject signature from a different key, got true")
	}
}

// TestSignMessageRejectsSegwit pins the Core-compatible behavior that segwit
// addresses cannot be used with signmessage / verifymessage. A regression here
// (silently allowing P2WPKH) would diverge from Core and break interop with
// Electrum / hardware wallets that expect the P2PKH-only contract.
func TestSignMessageRejectsSegwit(t *testing.T) {
	w := wallet.NewWallet(wallet.WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
		AddressType: wallet.AddressTypeP2WPKH,
	})
	if err := w.CreateFromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", ""); err != nil {
		t.Fatalf("CreateFromMnemonic: %v", err)
	}
	segwit, err := w.NewP2WPKHAddress()
	if err != nil {
		t.Fatalf("NewP2WPKHAddress: %v", err)
	}

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
		WithWallet(w),
	)

	resp := testRPCRequest(t, server.handleRPC, "signmessage", []interface{}{segwit, "hi"}, "", "")
	if resp.Error == nil {
		t.Fatalf("signmessage should reject segwit address, got %#v", resp.Result)
	}
	if resp.Error.Code != RPCErrTypeError {
		t.Errorf("expected RPCErrTypeError (-3), got %d", resp.Error.Code)
	}
}

// TestVerifyMessageInvalidAddress: verifymessage with garbage address is an
// error, not "false". Matches Core's behavior (RPC_INVALID_ADDRESS_OR_KEY).
func TestVerifyMessageInvalidAddress(t *testing.T) {
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
	)
	resp := testRPCRequest(t, server.handleRPC, "verifymessage", []interface{}{"not-an-address", "AAAA", "msg"}, "", "")
	if resp.Error == nil {
		t.Fatalf("expected error for invalid address, got %#v", resp.Result)
	}
	if resp.Error.Code != RPCErrInvalidAddressOrKey {
		t.Errorf("expected RPCErrInvalidAddressOrKey (-5), got %d", resp.Error.Code)
	}
}

// TestSignMessageWithPrivKeyRoundTrip exercises the wallet-less RPC.
func TestSignMessageWithPrivKeyRoundTrip(t *testing.T) {
	priv, err := bbcrypto.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	// Encode the key as mainnet WIF (compressed).
	wif := wallet.EncodeWIF(priv, address.Mainnet, true)

	// Derive the matching mainnet P2PKH address: Hash160(compressed pubkey).
	pkh := bbcrypto.Hash160(priv.PubKey().SerializeCompressed())
	var pkhArr [20]byte
	copy(pkhArr[:], pkh[:])
	addrObj := address.NewP2PKHAddress(pkhArr, address.Mainnet)
	addrStr, err := addrObj.Encode()
	if err != nil {
		t.Fatalf("encode addr: %v", err)
	}

	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.MainnetParams()),
	)

	const msg = "wallet-less signing"
	resp := testRPCRequest(t, server.handleRPC, "signmessagewithprivkey", []interface{}{wif, msg}, "", "")
	if resp.Error != nil {
		t.Fatalf("signmessagewithprivkey error: %+v", resp.Error)
	}
	sigB64, ok := resp.Result.(string)
	if !ok || sigB64 == "" {
		t.Fatalf("signmessagewithprivkey returned %#v", resp.Result)
	}

	// Verify against the externally derived address.
	resp = testRPCRequest(t, server.handleRPC, "verifymessage", []interface{}{addrStr, sigB64, msg}, "", "")
	if resp.Error != nil {
		t.Fatalf("verifymessage error: %+v", resp.Error)
	}
	if v, _ := resp.Result.(bool); !v {
		t.Fatalf("verifymessage should accept signmessagewithprivkey output, got %#v", resp.Result)
	}
}

// TestEstimateRawFeeNoData: with an empty estimator, estimaterawfee returns a
// horizon entry whose `errors` array reports the failure mode. Pinning this
// behavior keeps callers (notably Core-compatible scripts) on the happy path.
func TestEstimateRawFeeNoData(t *testing.T) {
	fe := mempool.NewFeeEstimator()
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithFeeEstimator(fe),
	)

	resp := testRPCRequest(t, server.handleRPC, "estimaterawfee", []interface{}{6}, "", "")
	if resp.Error != nil {
		t.Fatalf("estimaterawfee error: %+v", resp.Error)
	}
	out, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("estimaterawfee result not an object: %#v", resp.Result)
	}
	medium, ok := out["medium"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing medium horizon: %#v", out)
	}
	if _, ok := medium["errors"]; !ok {
		t.Errorf("expected errors array in empty estimator, got %#v", medium)
	}
	if _, ok := medium["feerate"]; ok {
		t.Errorf("did not expect feerate in empty estimator, got %#v", medium)
	}
}

// TestEstimateRawFeeOutOfRange: target outside the tracked horizon returns an
// empty object, matching Core's "no horizon tracks this target" semantics.
func TestEstimateRawFeeOutOfRange(t *testing.T) {
	fe := mempool.NewFeeEstimator()
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithFeeEstimator(fe),
	)

	// 1008 is the default max; 1_000_000 must be rejected as out of range.
	resp := testRPCRequest(t, server.handleRPC, "estimaterawfee", []interface{}{1_000_000}, "", "")
	if resp.Error != nil {
		t.Fatalf("estimaterawfee error: %+v", resp.Error)
	}
	out, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("estimaterawfee result not an object: %#v", resp.Result)
	}
	if len(out) != 0 {
		t.Errorf("expected empty result for out-of-range target, got %#v", out)
	}
}

// TestEstimateRawFeeBadThreshold: the threshold parameter is bounded to (0,1].
func TestEstimateRawFeeBadThreshold(t *testing.T) {
	fe := mempool.NewFeeEstimator()
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithFeeEstimator(fe),
	)

	resp := testRPCRequest(t, server.handleRPC, "estimaterawfee", []interface{}{6, 1.5}, "", "")
	if resp.Error == nil {
		t.Fatalf("expected error for threshold>1, got %#v", resp.Result)
	}
	if resp.Error.Code != RPCErrInvalidParameter {
		t.Errorf("expected RPCErrInvalidParameter (-8), got %d", resp.Error.Code)
	}
}
