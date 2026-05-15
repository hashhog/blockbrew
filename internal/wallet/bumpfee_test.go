package wallet

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ──────────────────────────────────────────────────────────────────────────────
// FIX-61 Part 1 — BIP-125 sequence regression test (W118 BUG-1).
// ──────────────────────────────────────────────────────────────────────────────

// TestBIP125Sequence_NewTxIsReplaceable pins the post-fix invariant that
// CreateTransaction emits inputs with nSequence ≤ MAX_BIP125_RBF_SEQUENCE.
// Before FIX-61 this was 0xFFFFFFFE (anti-fee-sniping, NOT RBF). After
// FIX-61 it is BIP125RBFSequence = 0xFFFFFFFD per BIP-125 §"Summary".
//
// This test would FAIL on the pre-fix code: the off-by-one made every
// outgoing tx silently un-bumpable by peers that enforced strict BIP-125.
func TestBIP125Sequence_NewTxIsReplaceable(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	}
	w := NewWallet(config)
	if err := w.CreateFromMnemonic(testMnemonic, ""); err != nil {
		t.Fatalf("CreateFromMnemonic: %v", err)
	}

	addr, _ := w.NewAddress()
	w.AddUTXO(&WalletUTXO{
		OutPoint:  wire.OutPoint{Hash: wire.Hash256{0x42}, Index: 0},
		Amount:    1_000_000,
		Address:   addr,
		KeyPath:   "m/84'/0'/0'/0/0",
		Confirmed: true,
	})

	tx, err := w.CreateTransaction("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", 100_000, 1.0)
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}

	for i, in := range tx.TxIn {
		if in.Sequence > BIP125RBFSequence {
			t.Errorf("input %d Sequence=0x%08x violates BIP-125 RBF (must be ≤ 0xFFFFFFFD; pre-FIX-61 emitted 0xFFFFFFFE with comment 'Enable RBF (BIP125)')", i, in.Sequence)
		}
	}

	// Tighter: the canonical RBF marker is exactly MAX_BIP125_RBF_SEQUENCE.
	if tx.TxIn[0].Sequence != BIP125RBFSequence {
		t.Errorf("input 0 Sequence=0x%08x, want BIP125RBFSequence (0x%08x)", tx.TxIn[0].Sequence, BIP125RBFSequence)
	}
}

// TestBIP125Constant pins the constant value. If anyone "fixes" the constant
// to 0xfffffffe (the historical wrong value) this catches it immediately.
func TestBIP125Constant(t *testing.T) {
	if BIP125RBFSequence != 0xFFFFFFFD {
		t.Fatalf("BIP125RBFSequence = 0x%08x, want 0xFFFFFFFD (BIP-125 § Summary; bitcoin-core/src/policy/rbf.h MAX_BIP125_RBF_SEQUENCE)", BIP125RBFSequence)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// FIX-61 Part 2 — BumpFee helper (W118 BUG-2).
// ──────────────────────────────────────────────────────────────────────────────

// fundedWallet builds a wallet with one P2WPKH UTXO worth 1 BTC and returns it.
func fundedWallet(t *testing.T) (*Wallet, *WalletUTXO) {
	t.Helper()
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
		AddressType: AddressTypeP2WPKH,
	}
	w := NewWallet(config)
	if err := w.CreateFromMnemonic(testMnemonic, ""); err != nil {
		t.Fatalf("CreateFromMnemonic: %v", err)
	}

	addr, _ := w.NewAddress()
	parsed, err := address.DecodeAddress(addr, w.config.Network)
	if err != nil {
		t.Fatalf("DecodeAddress: %v", err)
	}
	utxo := &WalletUTXO{
		OutPoint:  wire.OutPoint{Hash: wire.Hash256{0x11}, Index: 0},
		Amount:    100_000_000, // 1 BTC
		Address:   addr,
		PkScript:  parsed.ScriptPubKey(),
		KeyPath:   w.addrToPath[addr],
		Confirmed: true,
	}
	w.AddUTXO(utxo)
	return w, utxo
}

// TestBumpFee_RoundTrip covers the happy path: build a real outgoing tx
// (so it carries a wallet-owned change output with an internal derivation
// path), then bump it. We verify:
//   - new fee > old fee
//   - change output value reduced by exactly fee_delta
//   - input sequence preserved (still RBF-signalling)
//   - inputs re-signed (non-empty witness data)
func TestBumpFee_RoundTrip(t *testing.T) {
	w, utxo := fundedWallet(t)

	// Step 1: build an outgoing tx via the production path so the change
	// output gets a derivation path the wallet recognises as internal.
	dest := "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	origTx, err := w.CreateTransaction(dest, 10_000_000, 1.0)
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	if len(origTx.TxOut) != 2 {
		t.Fatalf("expected 2 outputs (dest+change), got %d", len(origTx.TxOut))
	}

	// Step 2: BumpFee with a higher feerate.
	res, err := w.BumpFee(BumpFeeRequest{
		OrigTx: origTx,
		InputUTXOs: map[wire.OutPoint]*WalletUTXO{
			utxo.OutPoint: utxo,
		},
		FeeRate: 5.0, // 5 sat/vB (orig was 1 sat/vB)
	})
	if err != nil {
		t.Fatalf("BumpFee: %v", err)
	}

	if res.NewFee <= res.OldFee {
		t.Errorf("new fee %d not greater than old fee %d", res.NewFee, res.OldFee)
	}
	if res.NewFeeRate <= res.OrigFeeRate {
		t.Errorf("new feerate %.2f not greater than orig %.2f", res.NewFeeRate, res.OrigFeeRate)
	}
	if len(res.NewTx.TxIn) != len(origTx.TxIn) {
		t.Errorf("input count changed: %d → %d", len(origTx.TxIn), len(res.NewTx.TxIn))
	}
	if len(res.NewTx.TxOut) != len(origTx.TxOut) {
		t.Errorf("output count changed: %d → %d", len(origTx.TxOut), len(res.NewTx.TxOut))
	}

	// Total in − total out should equal new fee.
	var totalOut int64
	for _, out := range res.NewTx.TxOut {
		totalOut += out.Value
	}
	gotFee := utxo.Amount - totalOut
	if gotFee != res.NewFee {
		t.Errorf("derived fee from outputs = %d, BumpFee reported %d", gotFee, res.NewFee)
	}

	// Sequence must still signal RBF (so the replacement can itself be bumped).
	for i, in := range res.NewTx.TxIn {
		if in.Sequence > BIP125RBFSequence {
			t.Errorf("bumped input %d Sequence=0x%08x not RBF-signalling", i, in.Sequence)
		}
	}

	// Each input should be signed (non-empty witness for P2WPKH).
	for i, in := range res.NewTx.TxIn {
		if len(in.Witness) == 0 {
			t.Errorf("bumped input %d has no witness data (not re-signed)", i)
		}
	}
}

// TestBumpFee_RejectNoRBF verifies the wallet refuses to bump a tx whose
// inputs all carry nSequence > MAX_BIP125_RBF_SEQUENCE — per BIP-125
// §"Summary" such txs are not eligible for replacement.
func TestBumpFee_RejectNoRBF(t *testing.T) {
	w, utxo := fundedWallet(t)

	// Synthesize a tx with non-RBF sequence (0xFFFFFFFE = anti-fee-sniping).
	origTx := &wire.MsgTx{Version: 2}
	origTx.TxIn = append(origTx.TxIn, &wire.TxIn{
		PreviousOutPoint: utxo.OutPoint,
		Sequence:         0xFFFFFFFE, // NOT BIP-125
	})
	parsed, _ := address.DecodeAddress("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", address.Mainnet)
	origTx.TxOut = append(origTx.TxOut, &wire.TxOut{Value: 99_000_000, PkScript: parsed.ScriptPubKey()})

	_, err := w.BumpFee(BumpFeeRequest{
		OrigTx:     origTx,
		InputUTXOs: map[wire.OutPoint]*WalletUTXO{utxo.OutPoint: utxo},
		FeeRate:    5.0,
	})
	if err != ErrBumpFeeNoRBFSignal {
		t.Errorf("want ErrBumpFeeNoRBFSignal, got %v", err)
	}
}

// TestBumpFee_RejectNotOurs verifies the wallet refuses to bump a tx whose
// inputs are not all owned. Maps to Core's AllInputsMine + WALLET_ERROR.
func TestBumpFee_RejectNotOurs(t *testing.T) {
	w, _ := fundedWallet(t)

	foreign := wire.OutPoint{Hash: wire.Hash256{0xff, 0xff, 0xff}, Index: 0}
	origTx := &wire.MsgTx{Version: 2}
	origTx.TxIn = append(origTx.TxIn, &wire.TxIn{
		PreviousOutPoint: foreign,
		Sequence:         BIP125RBFSequence,
	})
	parsed, _ := address.DecodeAddress("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", address.Mainnet)
	origTx.TxOut = append(origTx.TxOut, &wire.TxOut{Value: 1000, PkScript: parsed.ScriptPubKey()})

	_, err := w.BumpFee(BumpFeeRequest{
		OrigTx:     origTx,
		InputUTXOs: map[wire.OutPoint]*WalletUTXO{}, // empty: nothing to look up
		FeeRate:    5.0,
	})
	if err != ErrBumpFeeNotOurs {
		t.Errorf("want ErrBumpFeeNotOurs, got %v", err)
	}
}

// TestBumpFee_RejectNoChange verifies the wallet refuses to bump a tx with
// no wallet-recognised change output (we'd have nowhere to take the fee
// delta from).
func TestBumpFee_RejectNoChange(t *testing.T) {
	w, utxo := fundedWallet(t)

	// A tx where the entire input goes to a non-wallet address — no change.
	origTx := &wire.MsgTx{Version: 2}
	origTx.TxIn = append(origTx.TxIn, &wire.TxIn{
		PreviousOutPoint: utxo.OutPoint,
		Sequence:         BIP125RBFSequence,
	})
	parsed, _ := address.DecodeAddress("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", address.Mainnet)
	origTx.TxOut = append(origTx.TxOut, &wire.TxOut{
		Value:    99_900_000,
		PkScript: parsed.ScriptPubKey(),
	})

	_, err := w.BumpFee(BumpFeeRequest{
		OrigTx:     origTx,
		InputUTXOs: map[wire.OutPoint]*WalletUTXO{utxo.OutPoint: utxo},
		FeeRate:    5.0,
	})
	if err != ErrBumpFeeNoChange {
		t.Errorf("want ErrBumpFeeNoChange, got %v", err)
	}
}

// TestBumpFee_RejectRateTooLow verifies that a fee_rate ≤ origFeeRate is
// rejected (BIP-125 Rule 4: replacement must pay more).
func TestBumpFee_RejectRateTooLow(t *testing.T) {
	w, utxo := fundedWallet(t)

	origTx, err := w.CreateTransaction("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", 10_000_000, 10.0)
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}

	_, err = w.BumpFee(BumpFeeRequest{
		OrigTx:     origTx,
		InputUTXOs: map[wire.OutPoint]*WalletUTXO{utxo.OutPoint: utxo},
		FeeRate:    1.0, // below the 10.0 origFeeRate
	})
	if err != ErrBumpFeeRateTooLow {
		t.Errorf("want ErrBumpFeeRateTooLow, got %v", err)
	}
}

// TestBumpFee_RejectDustAfterReduce verifies that when the fee delta would
// drive the change output below dust (546 sat), the wallet refuses.
func TestBumpFee_RejectDustAfterReduce(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
		AddressType: AddressTypeP2WPKH,
	}
	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")
	addr, _ := w.NewAddress()
	parsed, _ := address.DecodeAddress(addr, address.Mainnet)
	utxo := &WalletUTXO{
		OutPoint:  wire.OutPoint{Hash: wire.Hash256{0x77}, Index: 0},
		Amount:    100_000,
		Address:   addr,
		PkScript:  parsed.ScriptPubKey(),
		KeyPath:   w.addrToPath[addr],
		Confirmed: true,
	}
	w.AddUTXO(utxo)

	// Build a tx with a small change. Send 99,000 of 100,000 — change ~700
	// after fee, which is just above dust.
	origTx, err := w.CreateTransaction("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", 99_000, 1.0)
	if err != nil {
		t.Skipf("CreateTransaction failed (no change scenario, low UTXO): %v", err)
	}
	// If we got 1 output, there's no change → not the right scenario.
	if len(origTx.TxOut) < 2 {
		t.Skipf("test setup did not produce a change output (only %d outputs)", len(origTx.TxOut))
	}

	_, err = w.BumpFee(BumpFeeRequest{
		OrigTx:     origTx,
		InputUTXOs: map[wire.OutPoint]*WalletUTXO{utxo.OutPoint: utxo},
		FeeRate:    100.0, // very high — eats all of the small change
	})
	if err != ErrBumpFeeDustAfterReduce {
		t.Errorf("want ErrBumpFeeDustAfterReduce, got %v", err)
	}
}

// TestBumpFee_DefaultFeeRate verifies the +1 sat/vB default when FeeRate is 0.
func TestBumpFee_DefaultFeeRate(t *testing.T) {
	w, utxo := fundedWallet(t)

	origTx, err := w.CreateTransaction("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", 10_000_000, 1.0)
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}

	res, err := w.BumpFee(BumpFeeRequest{
		OrigTx:     origTx,
		InputUTXOs: map[wire.OutPoint]*WalletUTXO{utxo.OutPoint: utxo},
		FeeRate:    0, // explicit default
	})
	if err != nil {
		t.Fatalf("BumpFee with default rate: %v", err)
	}
	if res.NewFee <= res.OldFee {
		t.Errorf("default bump did not raise fee: old=%d new=%d", res.OldFee, res.NewFee)
	}
	// Default should bump by ~+1 sat/vB.
	expectedBump := int64(res.OldVSize)
	if delta := res.NewFee - res.OldFee; delta < expectedBump-1 || delta > expectedBump+1 {
		t.Errorf("default bump delta = %d sat, want ~%d sat (1 sat/vB × %d vbytes)", delta, expectedBump, res.OldVSize)
	}
}

// TestBumpFee_CommentClaimsCorrectCheck guards against W118 regression:
// any future "Enable RBF" comment in wallet.go must be backed by code
// that actually emits ≤ BIP125RBFSequence. This is a soft check via the
// public CreateTransaction path.
func TestBumpFee_CommentClaimsCorrectCheck(t *testing.T) {
	w, _ := fundedWallet(t)
	tx, err := w.CreateTransaction("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", 1_000_000, 1.0)
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	if tx.TxIn[0].Sequence > BIP125RBFSequence {
		t.Fatalf("W118 BUG-1 regression: CreateTransaction emits Sequence=0x%08x > BIP125RBFSequence (0x%08x). Comment-as-confession pattern returned.", tx.TxIn[0].Sequence, BIP125RBFSequence)
	}
}
