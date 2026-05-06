package rpc

import (
	"encoding/json"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// newWaveTestWallet builds a fresh, unlocked, regtest wallet with a known
// mnemonic so we can derive deterministic addresses across tests.
func newWaveTestWallet(t *testing.T) *wallet.Wallet {
	t.Helper()
	w := wallet.NewWallet(wallet.WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Regtest,
		ChainParams: consensus.RegtestParams(),
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

// addFakeUTXO derives a fresh wallet address, builds a P2WPKH scriptPubKey
// for it, and adds a fake confirmed UTXO of the requested amount.
func addFakeUTXO(t *testing.T, w *wallet.Wallet, amountSat int64, height int32, isCoinbase bool) wire.OutPoint {
	t.Helper()
	addr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	parsed, err := address.DecodeAddress(addr, w.Network())
	if err != nil {
		t.Fatalf("DecodeAddress: %v", err)
	}

	// Use a deterministic-looking but unique txid keyed off amount+height.
	var txid wire.Hash256
	txid[0] = byte(height)
	txid[1] = byte(amountSat & 0xff)
	txid[2] = byte((amountSat >> 8) & 0xff)
	txid[3] = byte((amountSat >> 16) & 0xff)
	txid[4] = byte((amountSat >> 24) & 0xff)
	op := wire.OutPoint{Hash: txid, Index: 0}

	w.AddUTXO(&wallet.WalletUTXO{
		OutPoint:   op,
		Amount:     amountSat,
		PkScript:   parsed.ScriptPubKey(),
		Address:    addr,
		Height:     height,
		IsCoinbase: isCoinbase,
		Confirmed:  true,
	})
	return op
}

// TestRPCLockUnspentRoundTrip exercises the lock → list → unlock → list
// cycle via the RPC dispatcher. Mirrors `lockunspent` semantics from
// bitcoin-core/src/wallet/rpc/coins.cpp::lockunspent.
func TestRPCLockUnspentRoundTrip(t *testing.T) {
	w := newWaveTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWallet(w),
	)

	op := addFakeUTXO(t, w, 100_000_000, 100, false)

	// 1. listlockunspent → empty.
	resp := testRPCRequest(t, server.handleRPC, "listlockunspent", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("listlockunspent: %+v", resp.Error)
	}
	asJSON, _ := json.Marshal(resp.Result)
	if string(asJSON) != "[]" {
		t.Fatalf("expected empty list, got %s", asJSON)
	}

	// 2. lockunspent false [{txid, vout: 0}] → true.
	lockArgs := []interface{}{
		false,
		[]interface{}{
			map[string]interface{}{
				"txid": op.Hash.String(),
				"vout": float64(op.Index),
			},
		},
	}
	resp = testRPCRequest(t, server.handleRPC, "lockunspent", lockArgs, "", "")
	if resp.Error != nil {
		t.Fatalf("lockunspent lock: %+v", resp.Error)
	}
	if resp.Result != true {
		t.Fatalf("lockunspent: expected true, got %v", resp.Result)
	}
	if !w.IsLockedCoin(op) {
		t.Fatal("UTXO should be locked")
	}

	// 3. lockunspent again with same UTXO + persistent=false → -8.
	resp = testRPCRequest(t, server.handleRPC, "lockunspent", lockArgs, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("expected -8 already locked, got %+v", resp.Error)
	}

	// 4. listlockunspent → 1 entry matching our outpoint.
	resp = testRPCRequest(t, server.handleRPC, "listlockunspent", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("listlockunspent: %+v", resp.Error)
	}
	asJSON, _ = json.Marshal(resp.Result)
	var list []LockedOutpoint
	if err := json.Unmarshal(asJSON, &list); err != nil {
		t.Fatalf("decode listlockunspent: %v (raw=%s)", err, asJSON)
	}
	if len(list) != 1 || list[0].TxID != op.Hash.String() || list[0].Vout != op.Index {
		t.Fatalf("listlockunspent mismatch: %+v", list)
	}

	// 5. lockunspent true [...] (unlock) → true; locked set empty.
	unlockArgs := []interface{}{
		true,
		[]interface{}{
			map[string]interface{}{
				"txid": op.Hash.String(),
				"vout": float64(op.Index),
			},
		},
	}
	resp = testRPCRequest(t, server.handleRPC, "lockunspent", unlockArgs, "", "")
	if resp.Error != nil {
		t.Fatalf("lockunspent unlock: %+v", resp.Error)
	}
	if w.IsLockedCoin(op) {
		t.Fatal("UTXO should be unlocked")
	}

	// 6. lockunspent true [...] again → -8 (expected locked output).
	resp = testRPCRequest(t, server.handleRPC, "lockunspent", unlockArgs, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("expected -8 unlocking unlocked, got %+v", resp.Error)
	}
}

// TestRPCLockUnspentUnknownTx ensures an unknown txid yields -8. Matches
// Core's "unknown transaction" branch in coins.cpp::lockunspent.
func TestRPCLockUnspentUnknownTx(t *testing.T) {
	w := newWaveTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWallet(w),
	)

	args := []interface{}{
		false,
		[]interface{}{
			map[string]interface{}{
				"txid": "0000000000000000000000000000000000000000000000000000000000000000",
				"vout": float64(0),
			},
		},
	}
	resp := testRPCRequest(t, server.handleRPC, "lockunspent", args, "", "")
	if resp.Error == nil || resp.Error.Code != RPCErrInvalidParameter {
		t.Fatalf("expected -8 unknown transaction, got %+v", resp.Error)
	}
}

// TestRPCLockUnspentUnlockAll exercises `lockunspent true` with no outputs
// array, which should clear all locks.
func TestRPCLockUnspentUnlockAll(t *testing.T) {
	w := newWaveTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWallet(w),
	)

	op1 := addFakeUTXO(t, w, 50_000_000, 100, false)
	op2 := addFakeUTXO(t, w, 25_000_000, 101, false)

	w.LockCoin(op1, false)
	w.LockCoin(op2, false)
	if !w.IsLockedCoin(op1) || !w.IsLockedCoin(op2) {
		t.Fatal("setup: both UTXOs should be locked")
	}

	// `lockunspent true` (single arg) → unlock all.
	resp := testRPCRequest(t, server.handleRPC, "lockunspent", []interface{}{true}, "", "")
	if resp.Error != nil {
		t.Fatalf("lockunspent unlock-all: %+v", resp.Error)
	}
	if w.IsLockedCoin(op1) || w.IsLockedCoin(op2) {
		t.Fatal("after unlock-all both UTXOs should be unlocked")
	}
}

// TestRPCGetBalances asserts the multi-state balance breakdown matches the
// wallet's UTXO mix: confirmed → trusted, unconfirmed → untrusted_pending,
// immature coinbase → immature.
func TestRPCGetBalances(t *testing.T) {
	w := newWaveTestWallet(t)

	// Build a fake tip: chain manager returns (zero hash, height=120).
	// We'll bake the height into wallet UTXOs to exercise immaturity.
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWallet(w),
	)

	// 1.0 BTC confirmed, non-coinbase.
	addFakeUTXO(t, w, 100_000_000, 50, false)
	// 0.5 BTC unconfirmed.
	addr, _ := w.NewAddress()
	parsed, _ := address.DecodeAddress(addr, w.Network())
	w.AddUTXO(&wallet.WalletUTXO{
		OutPoint:  wire.OutPoint{Hash: wire.Hash256{0xaa}, Index: 0},
		Amount:    50_000_000,
		PkScript:  parsed.ScriptPubKey(),
		Address:   addr,
		Height:    0,
		Confirmed: false,
	})
	// 6.25 BTC coinbase, height 0 — without a chain manager BestBlock is
	// (zero, 0), so confirmations = 0 - 0 + 1 = 1, well below maturity (100).
	addFakeUTXO(t, w, 625_000_000, 0, true)

	resp := testRPCRequest(t, server.handleRPC, "getbalances", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("getbalances: %+v", resp.Error)
	}
	asJSON, _ := json.Marshal(resp.Result)
	var got GetBalancesResult
	if err := json.Unmarshal(asJSON, &got); err != nil {
		t.Fatalf("decode getbalances: %v (raw=%s)", err, asJSON)
	}
	if got.Mine.Trusted != 1.0 {
		t.Errorf("Trusted: want 1.0 BTC, got %v", got.Mine.Trusted)
	}
	if got.Mine.UntrustedPending != 0.5 {
		t.Errorf("UntrustedPending: want 0.5 BTC, got %v", got.Mine.UntrustedPending)
	}
	if got.Mine.Immature != 6.25 {
		t.Errorf("Immature: want 6.25 BTC, got %v", got.Mine.Immature)
	}
	// lastprocessedblock must be present even with no chainMgr (zero hash, 0).
	if got.LastProcessedBlock.Height != 0 {
		t.Errorf("LastProcessedBlock.Height: want 0 (no chainMgr), got %d", got.LastProcessedBlock.Height)
	}
}

// TestRPCWalletCreateFundedPSBTAuto exercises the auto-coin-select path:
// caller passes empty inputs, two outputs, and the wallet must pick a UTXO
// that covers the target plus fees, emitting a valid base64 PSBT with a
// non-negative fee field.
func TestRPCWalletCreateFundedPSBTAuto(t *testing.T) {
	w := newWaveTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWallet(w),
	)

	// Fund the wallet with 1 BTC.
	addFakeUTXO(t, w, 100_000_000, 50, false)

	// Build a destination address (also wallet-owned for simplicity).
	destAddr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress (dest): %v", err)
	}

	args := []interface{}{
		[]interface{}{}, // empty inputs → auto-select
		[]interface{}{
			map[string]interface{}{destAddr: 0.5},
		},
		float64(0), // locktime
		map[string]interface{}{
			"fee_rate": float64(2), // 2 sat/vB
		},
	}
	resp := testRPCRequest(t, server.handleRPC, "walletcreatefundedpsbt", args, "", "")
	if resp.Error != nil {
		t.Fatalf("walletcreatefundedpsbt: %+v", resp.Error)
	}

	asJSON, _ := json.Marshal(resp.Result)
	var got WalletCreateFundedPSBTResult
	if err := json.Unmarshal(asJSON, &got); err != nil {
		t.Fatalf("decode: %v (raw=%s)", err, asJSON)
	}
	if got.PSBT == "" {
		t.Fatal("PSBT field empty")
	}
	if got.Fee <= 0 {
		t.Fatalf("fee should be positive, got %v", got.Fee)
	}
	// Sanity: the returned PSBT must round-trip through DecodePSBTBase64.
	decoded, err := wallet.DecodePSBTBase64(got.PSBT)
	if err != nil {
		t.Fatalf("DecodePSBTBase64: %v", err)
	}
	if len(decoded.UnsignedTx.TxIn) < 1 {
		t.Fatal("PSBT should have at least one input")
	}
	if len(decoded.UnsignedTx.TxOut) < 1 {
		t.Fatal("PSBT should have at least one output")
	}
	// Each input we own should have WitnessUTXO populated (so signing works).
	for i, in := range decoded.Inputs {
		if in.WitnessUTXO == nil {
			t.Errorf("input %d missing WitnessUTXO", i)
		}
	}
}

// TestRPCWalletCreateFundedPSBTLockUnspents asserts that lockUnspents=true
// in the options object causes the auto-selected UTXOs to be added to the
// wallet's locked set.
func TestRPCWalletCreateFundedPSBTLockUnspents(t *testing.T) {
	w := newWaveTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWallet(w),
	)

	op := addFakeUTXO(t, w, 100_000_000, 50, false)
	if w.IsLockedCoin(op) {
		t.Fatal("setup: UTXO must start unlocked")
	}

	destAddr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}

	args := []interface{}{
		[]interface{}{},
		[]interface{}{map[string]interface{}{destAddr: 0.1}},
		float64(0),
		map[string]interface{}{
			"fee_rate":     float64(1),
			"lockUnspents": true,
		},
	}
	resp := testRPCRequest(t, server.handleRPC, "walletcreatefundedpsbt", args, "", "")
	if resp.Error != nil {
		t.Fatalf("walletcreatefundedpsbt: %+v", resp.Error)
	}

	if !w.IsLockedCoin(op) {
		t.Fatal("UTXO should be locked after lockUnspents=true")
	}

	// listlockunspent should now return our outpoint.
	resp = testRPCRequest(t, server.handleRPC, "listlockunspent", []interface{}{}, "", "")
	if resp.Error != nil {
		t.Fatalf("listlockunspent: %+v", resp.Error)
	}
	asJSON, _ := json.Marshal(resp.Result)
	var list []LockedOutpoint
	if err := json.Unmarshal(asJSON, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, e := range list {
		if e.TxID == op.Hash.String() && e.Vout == op.Index {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("locked set %+v missing %s:%d", list, op.Hash.String(), op.Index)
	}
}
