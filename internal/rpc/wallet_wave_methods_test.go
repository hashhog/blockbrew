package rpc

import (
	"bytes"
	"encoding/hex"
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

// TestRPCFundRawTransactionAuto exercises the fundrawtransaction default path,
// which is the raw-tx sibling of walletcreatefundedpsbt and reuses the SAME
// coin-selection engine (fundTxSkeleton). We build a raw tx with one output
// and NO inputs, fund it, and assert the funded tx is genuine and valid:
//   - inputs were added (vin non-empty),
//   - a change output exists (changepos >= 0, since the funded UTXO is much
//     larger than the target),
//   - fee > 0,
//   - changepos is consistent with the returned hex,
//   - the hex decodes to a tx whose selected-input value covers outputs+fee
//     (sum(inputs) == sum(outputs) + fee, change = inputs - outputs - fee).
//
// Reference: bitcoin-core/src/wallet/rpc/spend.cpp::fundrawtransaction (L706).
func TestRPCFundRawTransactionAuto(t *testing.T) {
	w := newWaveTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWallet(w),
	)

	// Fund the wallet with a single 1 BTC UTXO (the regtest funded-wallet
	// fixture, the same way the walletcreatefundedpsbt tests do).
	addFakeUTXO(t, w, 100_000_000, 50, false)

	// Build a destination address (wallet-owned for simplicity).
	destAddr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress (dest): %v", err)
	}
	parsedDest, err := address.DecodeAddress(destAddr, w.Network())
	if err != nil {
		t.Fatalf("DecodeAddress (dest): %v", err)
	}

	// Build a raw tx: version 2, one 0.5 BTC output, NO inputs.
	const targetSat = int64(50_000_000)
	rawTx := &wire.MsgTx{
		Version: 2,
		TxOut: []*wire.TxOut{
			{Value: targetSat, PkScript: parsedDest.ScriptPubKey()},
		},
	}
	var rawBuf bytes.Buffer
	if err := rawTx.Serialize(&rawBuf); err != nil {
		t.Fatalf("serialize raw tx: %v", err)
	}
	rawHex := hex.EncodeToString(rawBuf.Bytes())

	args := []interface{}{
		rawHex,
		map[string]interface{}{
			"fee_rate": float64(2), // 2 sat/vB, deterministic fee
		},
	}
	resp := testRPCRequest(t, server.handleRPC, "fundrawtransaction", args, "", "")
	if resp.Error != nil {
		t.Fatalf("fundrawtransaction: %+v", resp.Error)
	}

	asJSON, _ := json.Marshal(resp.Result)
	var got FundRawTransactionResult
	if err := json.Unmarshal(asJSON, &got); err != nil {
		t.Fatalf("decode result: %v (raw=%s)", err, asJSON)
	}

	// fee must be a genuine positive value.
	if got.Fee <= 0 {
		t.Fatalf("fee should be positive, got %v", got.Fee)
	}
	feeSat := int64(got.Fee * 1e8)

	// The returned hex must decode to a valid tx.
	if got.Hex == "" {
		t.Fatal("hex field empty")
	}
	fundedBytes, err := hex.DecodeString(got.Hex)
	if err != nil {
		t.Fatalf("returned hex is not valid hex: %v", err)
	}
	funded := &wire.MsgTx{}
	if err := funded.Deserialize(bytes.NewReader(fundedBytes)); err != nil {
		t.Fatalf("returned hex did not decode to a tx: %v", err)
	}

	// Inputs were added (the raw tx had none).
	if len(funded.TxIn) < 1 {
		t.Fatalf("funded tx should have at least one input, got %d", len(funded.TxIn))
	}

	// A change output exists, and changepos is consistent with the hex.
	if got.ChangePos < 0 {
		t.Fatalf("expected a change output (changepos >= 0) for an over-funded tx, got %d", got.ChangePos)
	}
	if got.ChangePos >= len(funded.TxOut) {
		t.Fatalf("changepos %d out of range for %d outputs", got.ChangePos, len(funded.TxOut))
	}
	// The original recipient output must still be present and unmodified.
	foundRecipient := false
	for i, o := range funded.TxOut {
		if i == got.ChangePos {
			continue
		}
		if o.Value == targetSat && bytes.Equal(o.PkScript, parsedDest.ScriptPubKey()) {
			foundRecipient = true
		}
	}
	if !foundRecipient {
		t.Fatalf("original recipient output (%d sat) not preserved in funded tx", targetSat)
	}

	// Sum selected-input value by looking each vin up in the wallet UTXO set.
	var inSum int64
	for _, in := range funded.TxIn {
		u := walletUTXOByOutpoint(w, in.PreviousOutPoint)
		if u == nil {
			t.Fatalf("selected input %s:%d is not a wallet UTXO", in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
		}
		inSum += u.Amount
	}

	// Sum output value.
	var outSum int64
	for _, o := range funded.TxOut {
		outSum += o.Value
	}

	// The funded tx must balance: sum(inputs) == sum(outputs) + fee.
	if inSum != outSum+feeSat {
		t.Fatalf("tx does not balance: inputs=%d outputs=%d fee=%d (inputs should equal outputs+fee=%d)",
			inSum, outSum, feeSat, outSum+feeSat)
	}

	// Change == inputs - (non-change outputs) - fee, and matches the change output.
	changeVal := funded.TxOut[got.ChangePos].Value
	nonChangeOut := outSum - changeVal
	if changeVal != inSum-nonChangeOut-feeSat {
		t.Fatalf("change %d != inputs(%d) - nonChangeOutputs(%d) - fee(%d)",
			changeVal, inSum, nonChangeOut, feeSat)
	}

	// Input value must cover outputs + fee.
	if inSum < outSum+feeSat {
		t.Fatalf("input value %d does not cover outputs+fee %d", inSum, outSum+feeSat)
	}
}
