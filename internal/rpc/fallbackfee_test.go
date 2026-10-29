package rpc

import (
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wallet"
)

func newFallbackFeeServer(t *testing.T, fallback float64) *Server {
	t.Helper()
	mgr := wallet.NewManager(t.TempDir(), address.Regtest, consensus.RegtestParams())
	s := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0", FallbackFee: fallback},
		WithChainParams(consensus.RegtestParams()),
		WithWalletManager(mgr),
	)
	if resp := testRPCRequest(t, s.handleRPC, "createwallet", []interface{}{"ff"}, "", ""); resp.Error != nil {
		t.Fatalf("createwallet: %+v", resp.Error)
	}
	return s
}

const fallbackFeeDest = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

// Core: no estimate and no -fallbackfee => -6 "Fee estimation failed.
// Fallbackfee is disabled...", raised before coin selection.
func TestFallbackFee_SendToAddress_DisabledFailsLikeCore(t *testing.T) {
	s := newFallbackFeeServer(t, 0)
	resp := testRPCRequest(t, s.handleRPC, "sendtoaddress", []interface{}{fallbackFeeDest, 0.001}, "", "")
	if resp.Error == nil {
		t.Fatal("sendtoaddress: expected error")
	}
	if resp.Error.Code != -6 || !strings.Contains(resp.Error.Message, "Fallbackfee is disabled") {
		t.Fatalf("got %d %q, want -6 Fee estimation failed. Fallbackfee is disabled", resp.Error.Code, resp.Error.Message)
	}
}

func TestFallbackFee_Send_DisabledFailsLikeCore(t *testing.T) {
	s := newFallbackFeeServer(t, 0)
	resp := testRPCRequest(t, s.handleRPC, "send",
		[]interface{}{[]interface{}{map[string]interface{}{fallbackFeeDest: 0.001}}}, "", "")
	if resp.Error == nil {
		t.Fatal("send: expected error")
	}
	if resp.Error.Code != -6 || !strings.Contains(resp.Error.Message, "Fallbackfee is disabled") {
		t.Fatalf("got %d %q, want -6 Fallbackfee is disabled", resp.Error.Code, resp.Error.Message)
	}
}

// Control: with a fallback the fee step passes and the (empty) wallet then
// fails on funds, not on the fee.
func TestFallbackFee_SendToAddress_EnabledGetsPastFee(t *testing.T) {
	s := newFallbackFeeServer(t, 20)
	resp := testRPCRequest(t, s.handleRPC, "sendtoaddress", []interface{}{fallbackFeeDest, 0.001}, "", "")
	if resp.Error == nil {
		t.Fatal("expected insufficient-funds error from an empty wallet")
	}
	if strings.Contains(resp.Error.Message, "Fallbackfee") {
		t.Fatalf("fee step still failed with a fallback set: %q", resp.Error.Message)
	}
}

func TestFallbackFee_WalletFeeRate(t *testing.T) {
	s := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0", FallbackFee: 20})
	if r, err := s.walletFeeRate(); err != nil || r != 20 {
		t.Fatalf("walletFeeRate = %v, %v; want 20, nil", r, err)
	}
	s = NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"})
	if _, err := s.walletFeeRate(); err == nil || err.Code != -6 {
		t.Fatalf("walletFeeRate with nothing = %v; want -6", err)
	}
}
