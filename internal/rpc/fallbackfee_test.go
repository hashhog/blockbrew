package rpc

import (
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
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

// Core's send RPC checks the fallback itself, before CreateTransaction, and
// throws RPC_WALLET_ERROR (-4) (wallet/rpc/spend.cpp), not the -6 SendMoney
// uses for sendtoaddress/sendmany.
func TestFallbackFee_Send_DisabledFailsLikeCore(t *testing.T) {
	s := newFallbackFeeServer(t, 0)
	resp := testRPCRequest(t, s.handleRPC, "send",
		[]interface{}{[]interface{}{map[string]interface{}{fallbackFeeDest: 0.001}}}, "", "")
	if resp.Error == nil {
		t.Fatal("send: expected error")
	}
	if resp.Error.Code != -4 || !strings.Contains(resp.Error.Message, "Fallbackfee is disabled") {
		t.Fatalf("got %d %q, want -4 Fallbackfee is disabled", resp.Error.Code, resp.Error.Message)
	}
}

// fundrawtransaction surfaces FundTransaction's failure as RPC_WALLET_ERROR.
func TestFallbackFee_FundRawTransaction_DisabledIsWalletError(t *testing.T) {
	s := newFallbackFeeServer(t, 0)
	// An input-less tx paying 0.001 BTC to fallbackFeeDest (P2WPKH).
	raw := "0200000000" + "01" + "a086010000000000" + "16" + "0014" + "751e76e8199196d454941c45d1b3a323f1433bd6" + "00000000"
	resp := testRPCRequest(t, s.handleRPC, "fundrawtransaction", []interface{}{raw}, "", "")
	if resp.Error == nil {
		t.Fatal("fundrawtransaction: expected error")
	}
	if resp.Error.Code != -4 || !strings.Contains(resp.Error.Message, "Fallbackfee is disabled") {
		t.Fatalf("got %d %q, want -4 Fallbackfee is disabled", resp.Error.Code, resp.Error.Message)
	}
}

// GetMinimumFeeRate (wallet/fees.cpp) raises a non-zero estimate or fallback
// to the mempool minimum and then to the required feerate
// max(-mintxfee 1000 sat/kvB, -minrelaytxfee). -fallbackfee=0.000001 is
// 100 sat/kvB and must be spent at 1 sat/vB, not 0.1.
func TestFallbackFee_WalletFeeRate_RaisedToRequired(t *testing.T) {
	s := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0", FallbackFee: 0.1})
	if r, err := s.walletFeeRate(); err != nil || r != 1 {
		t.Fatalf("walletFeeRate = %v, %v; want 1 (required feerate), nil", r, err)
	}
}

func TestFallbackFee_WalletFeeRate_RaisedToMempoolMin(t *testing.T) {
	cfg := mempool.DefaultConfig()
	cfg.MinRelayFeeRate = 5000 // 5 sat/vB floor
	mp := mempool.New(cfg, consensus.NewInMemoryUTXOView())
	s := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0", FallbackFee: 2}, WithMempool(mp))
	if r, err := s.walletFeeRate(); err != nil || r != 5 {
		t.Fatalf("walletFeeRate = %v, %v; want 5 (mempool min), nil", r, err)
	}
	// A disabled fallback is not raised: it still fails.
	s = NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"}, WithMempool(mp))
	if _, err := s.walletFeeRate(); err == nil {
		t.Fatal("walletFeeRate with fallback disabled: expected error, got none")
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
