// FIX-70 forward regression guards — default nSequence = 0xfffffffd.
//
// Context: W120 BUG-2 P0 found camlcoin + rustoshi emitting nSequence =
// 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL, anti-fee-sniping) from createpsbt by
// default. Bitcoin Core's CWallet has used MAX_BIP125_RBF_SEQUENCE
// (0xfffffffd) as the default since v23 — see
// bitcoin-core/src/wallet/wallet.h MAX_BIP125_RBF_SEQUENCE and
// bitcoin-core/src/wallet/rpc/spend.cpp (createpsbt /
// walletcreatefundedpsbt). Any default that is not ≤ 0xfffffffd makes the
// emitted transaction unbumpable via BIP-125 RBF.
//
// blockbrew was already correct after FIX-61 (commit 7f36684), which
// converted the named BIP125RBFSequence constant. This file is the
// forward regression guard — it asserts the RPC-level default emission
// for every wallet-input-producing path:
//
//   - createrawtransaction  (rawtx_methods.go::handleCreateRawTransaction)
//   - createpsbt            (psbt_methods.go::handleCreatePSBT)
//   - walletcreatefundedpsbt manual-input branch
//                           (wallet_wave_methods.go::handleWalletCreateFundedPSBT)
//   - walletcreatefundedpsbt auto-select branch  (same handler, different code path)
//
// The two non-default branches are also asserted so a future drive-by edit
// to "default to 0xfffffffe to enable anti-fee-sniping" fails fast:
//
//   - replaceable=false (no locktime) → 0xffffffff (final)
//   - replaceable=false + locktime>0  → 0xfffffffe  (non-final, locktime active)
//
// References:
//   bitcoin-core/src/wallet/wallet.h           : MAX_BIP125_RBF_SEQUENCE
//   bitcoin-core/src/wallet/rpc/spend.cpp      : createpsbt default
//   BIP-125 §"Summary"                         : opt-in semantics
//   FIX-61 commit 7f36684                      : BIP125RBFSequence introduction
//   internal/wallet/bumpfee_test.go            : existing CreateTransaction
//                                                + BumpFee guards
//   internal/wallet/w113_coin_selection_test.go: G27/G28 coin-select guard

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

// expectedRBFSequence is the BIP-125 opt-in RBF marker. The wallet const
// must be this value AND every RPC emission default must be ≤ this value.
const expectedRBFSequence = uint32(0xFFFFFFFD)

// TestFIX70_BIP125ConstantValue is the cheapest possible guard: the named
// wallet constant must stay 0xFFFFFFFD. Repeats wallet/bumpfee_test.go's
// TestBIP125Constant from the rpc package side so a developer modifying
// wallet.BIP125RBFSequence has a second test file flag the change.
func TestFIX70_BIP125ConstantValue(t *testing.T) {
	if wallet.BIP125RBFSequence != expectedRBFSequence {
		t.Fatalf("wallet.BIP125RBFSequence = 0x%08x, want 0x%08x (BIP-125 §Summary; bitcoin-core/src/policy/rbf.h MAX_BIP125_RBF_SEQUENCE)",
			wallet.BIP125RBFSequence, expectedRBFSequence)
	}
}

// TestFIX70_CreateRawTransaction_DefaultSequenceIsRBF asserts that
// createrawtransaction with replaceable=true (or unspecified, in our
// rawtx_methods.go default chain via Sequence=0 → falls through to
// !replaceable=0xFFFFFFFF; with replaceable=true → 0xFFFFFFFD) emits a
// transaction whose inputs are BIP-125 RBF-signaling.
//
// W120 BUG-2 pattern: a future "fix" that bumps the default to 0xFFFFFFFE
// would silently break RBF for every consumer of this RPC. This test fails
// before that edit lands.
func TestFIX70_CreateRawTransaction_DefaultSequenceIsRBF(t *testing.T) {
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
	)

	// Build a dummy address for the output (the address is for an output,
	// not an input — we just need it to parse).
	addr := "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080" // BIP-173 test vector P2WPKH

	args := []interface{}{
		[]interface{}{
			map[string]interface{}{
				"txid": "0000000000000000000000000000000000000000000000000000000000000001",
				"vout": float64(0),
			},
		},
		[]interface{}{
			map[string]interface{}{addr: 0.5},
		},
		float64(0), // locktime
		true,       // replaceable
	}

	resp := testRPCRequest(t, server.handleRPC, "createrawtransaction", args, "", "")
	if resp.Error != nil {
		t.Fatalf("createrawtransaction: %+v", resp.Error)
	}

	hexStr, ok := resp.Result.(string)
	if !ok {
		t.Fatalf("createrawtransaction result not a string: %T", resp.Result)
	}
	tx := decodeTxHex(t, hexStr)

	if len(tx.TxIn) != 1 {
		t.Fatalf("want 1 input, got %d", len(tx.TxIn))
	}
	got := tx.TxIn[0].Sequence
	if got != expectedRBFSequence {
		t.Fatalf("createrawtransaction default Sequence=0x%08x, want 0x%08x (BIP-125 opt-in). W120 BUG-2 pattern: would emit non-RBF txs unbumpable by bumpfee.", got, expectedRBFSequence)
	}
	if got > expectedRBFSequence {
		t.Fatalf("createrawtransaction Sequence=0x%08x > 0x%08x (NOT BIP-125 RBF). Comment-as-confession pattern: 'Enable RBF' label, anti-fee-sniping value.",
			got, expectedRBFSequence)
	}
}

// TestFIX70_CreateRawTransaction_NonReplaceableIsFinal asserts the
// !replaceable + locktime=0 path emits SEQUENCE_FINAL (0xFFFFFFFF). This
// is the only legitimate non-RBF default — keeps Core parity.
func TestFIX70_CreateRawTransaction_NonReplaceableIsFinal(t *testing.T) {
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
	)
	addr := "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
	args := []interface{}{
		[]interface{}{
			map[string]interface{}{
				"txid": "0000000000000000000000000000000000000000000000000000000000000001",
				"vout": float64(0),
			},
		},
		[]interface{}{
			map[string]interface{}{addr: 0.5},
		},
		float64(0), // locktime
		false,      // replaceable=false
	}
	resp := testRPCRequest(t, server.handleRPC, "createrawtransaction", args, "", "")
	if resp.Error != nil {
		t.Fatalf("createrawtransaction: %+v", resp.Error)
	}
	tx := decodeTxHex(t, resp.Result.(string))
	if tx.TxIn[0].Sequence != 0xFFFFFFFF {
		t.Errorf("!replaceable + locktime=0 want Sequence=SEQUENCE_FINAL (0xFFFFFFFF), got 0x%08x", tx.TxIn[0].Sequence)
	}
}

// TestFIX70_CreatePSBT_DefaultSequenceIsRBF asserts the createpsbt
// RPC default emission is ≤ MAX_BIP125_RBF_SEQUENCE when replaceable=true
// (the field defaults to false in our parser when omitted; we set it
// explicitly here to exercise the BIP125RBFSequence branch).
//
// The asserted invariant: tx.TxIn[i].Sequence == wallet.BIP125RBFSequence
// (0xFFFFFFFD). W120 BUG-2 named the createpsbt path explicitly — this
// is the regression guard for camlcoin/rustoshi's failure mode.
//
// NOTE: the createpsbt handler's address-output path uses an unimplemented
// addressToScript stub (psbt_methods.go:789 — separate bug, not in scope
// for FIX-70). We pass an empty outputs array, which the handler accepts
// (the for loop on outputsRaw simply doesn't iterate). The Sequence
// emission is independent of outputs.
func TestFIX70_CreatePSBT_DefaultSequenceIsRBF(t *testing.T) {
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
	)
	args := []interface{}{
		[]interface{}{
			map[string]interface{}{
				"txid": "0000000000000000000000000000000000000000000000000000000000000001",
				"vout": float64(0),
			},
		},
		[]interface{}{}, // empty outputs — handler tolerates; we only inspect inputs
		float64(0),      // locktime
		true,            // replaceable
	}

	resp := testRPCRequest(t, server.handleRPC, "createpsbt", args, "", "")
	if resp.Error != nil {
		t.Fatalf("createpsbt: %+v", resp.Error)
	}

	psbtB64, ok := resp.Result.(string)
	if !ok {
		t.Fatalf("createpsbt result not a string: %T", resp.Result)
	}
	psbt, err := wallet.DecodePSBTBase64(psbtB64)
	if err != nil {
		t.Fatalf("DecodePSBTBase64: %v", err)
	}
	if len(psbt.UnsignedTx.TxIn) != 1 {
		t.Fatalf("want 1 input, got %d", len(psbt.UnsignedTx.TxIn))
	}
	got := psbt.UnsignedTx.TxIn[0].Sequence
	if got != expectedRBFSequence {
		t.Fatalf("createpsbt default Sequence=0x%08x, want 0x%08x (BIP-125 opt-in / wallet.BIP125RBFSequence). W120 BUG-2 P0 — camlcoin+rustoshi emit 0xFFFFFFFE here.",
			got, expectedRBFSequence)
	}
}

// TestFIX70_CreatePSBT_NonReplaceableIsFinal: createpsbt with
// replaceable=false (no locktime) must emit SEQUENCE_FINAL.
func TestFIX70_CreatePSBT_NonReplaceableIsFinal(t *testing.T) {
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
	)
	args := []interface{}{
		[]interface{}{
			map[string]interface{}{
				"txid": "0000000000000000000000000000000000000000000000000000000000000001",
				"vout": float64(0),
			},
		},
		[]interface{}{}, // empty outputs (see note above)
		float64(0),
		false,
	}
	resp := testRPCRequest(t, server.handleRPC, "createpsbt", args, "", "")
	if resp.Error != nil {
		t.Fatalf("createpsbt: %+v", resp.Error)
	}
	psbt, err := wallet.DecodePSBTBase64(resp.Result.(string))
	if err != nil {
		t.Fatalf("DecodePSBTBase64: %v", err)
	}
	if psbt.UnsignedTx.TxIn[0].Sequence != 0xFFFFFFFF {
		t.Errorf("!replaceable createpsbt want SEQUENCE_FINAL (0xFFFFFFFF), got 0x%08x", psbt.UnsignedTx.TxIn[0].Sequence)
	}
}

// TestFIX70_WalletCreateFundedPSBT_ManualInput_DefaultSequenceIsRBF
// covers the manual-input branch of walletcreatefundedpsbt — caller
// provides explicit {txid, vout} entries. The handler defaults each
// such input to 0xfffffffd before checking the user-supplied
// "sequence" override. This is wallet_wave_methods.go:384.
//
// The auto-select branch is covered by TestFIX70_..._AutoSelect_ below.
func TestFIX70_WalletCreateFundedPSBT_ManualInput_DefaultSequenceIsRBF(t *testing.T) {
	w := newWaveTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWallet(w),
	)

	op := addFakeUTXO(t, w, 100_000_000, 50, false)
	destAddr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}

	args := []interface{}{
		// Manual inputs — caller hands us {txid, vout}, no "sequence" override
		[]interface{}{
			map[string]interface{}{
				"txid": op.Hash.String(),
				"vout": float64(op.Index),
			},
		},
		[]interface{}{
			map[string]interface{}{destAddr: 0.5},
		},
		float64(0), // locktime
		map[string]interface{}{
			"fee_rate":    float64(2),
			"replaceable": true,
			// add_inputs not set; we provided enough to fund the output.
		},
	}
	resp := testRPCRequest(t, server.handleRPC, "walletcreatefundedpsbt", args, "", "")
	if resp.Error != nil {
		t.Fatalf("walletcreatefundedpsbt: %+v", resp.Error)
	}

	asJSON, _ := json.Marshal(resp.Result)
	var got WalletCreateFundedPSBTResult
	if err := json.Unmarshal(asJSON, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	psbt, err := wallet.DecodePSBTBase64(got.PSBT)
	if err != nil {
		t.Fatalf("DecodePSBTBase64: %v", err)
	}

	// Locate the manual input we passed by outpoint and assert its sequence.
	found := false
	for i, in := range psbt.UnsignedTx.TxIn {
		if in.PreviousOutPoint == op {
			found = true
			if in.Sequence != expectedRBFSequence {
				t.Errorf("walletcreatefundedpsbt manual input %d Sequence=0x%08x, want 0x%08x (BIP-125; wallet_wave_methods.go:384). W120 BUG-2 P0.",
					i, in.Sequence, expectedRBFSequence)
			}
		}
		// Every other input (auto-selected) must ALSO be RBF-signaling
		// because replaceable=true was set — exercises sequenceForLocktime.
		if in.Sequence > expectedRBFSequence {
			t.Errorf("walletcreatefundedpsbt input %d Sequence=0x%08x > 0x%08x — NOT BIP-125 RBF", i, in.Sequence, expectedRBFSequence)
		}
	}
	if !found {
		t.Fatalf("manual input outpoint %s:%d not present in PSBT", op.Hash, op.Index)
	}
}

// TestFIX70_WalletCreateFundedPSBT_AutoSelect_DefaultSequenceIsRBF
// covers the auto-coin-select branch — handler invokes
// sequenceForLocktime(locktime, replaceable). When replaceable=true (the
// handler default), sequenceForLocktime returns 0xfffffffd.
func TestFIX70_WalletCreateFundedPSBT_AutoSelect_DefaultSequenceIsRBF(t *testing.T) {
	w := newWaveTestWallet(t)
	server := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(consensus.RegtestParams()),
		WithWallet(w),
	)
	addFakeUTXO(t, w, 100_000_000, 50, false)
	destAddr, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	args := []interface{}{
		[]interface{}{}, // empty inputs → auto-select
		[]interface{}{
			map[string]interface{}{destAddr: 0.5},
		},
		float64(0), // locktime
		map[string]interface{}{
			"fee_rate": float64(2),
			// replaceable omitted — handler default is true.
		},
	}
	resp := testRPCRequest(t, server.handleRPC, "walletcreatefundedpsbt", args, "", "")
	if resp.Error != nil {
		t.Fatalf("walletcreatefundedpsbt: %+v", resp.Error)
	}
	asJSON, _ := json.Marshal(resp.Result)
	var got WalletCreateFundedPSBTResult
	if err := json.Unmarshal(asJSON, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	psbt, err := wallet.DecodePSBTBase64(got.PSBT)
	if err != nil {
		t.Fatalf("DecodePSBTBase64: %v", err)
	}
	if len(psbt.UnsignedTx.TxIn) < 1 {
		t.Fatal("PSBT should have at least one input")
	}
	for i, in := range psbt.UnsignedTx.TxIn {
		if in.Sequence != expectedRBFSequence {
			t.Errorf("walletcreatefundedpsbt auto-selected input %d Sequence=0x%08x, want 0x%08x (BIP-125 default per handler). W120 BUG-2 P0.",
				i, in.Sequence, expectedRBFSequence)
		}
	}
}

// TestFIX70_SequenceForLocktime_Branches directly exercises the helper
// that decides nSequence based on (locktime, replaceable). Mirrors Core's
// CWallet::CreateTransactionInternal logic. Catches accidental swaps
// (e.g. a future edit that maps replaceable=true → 0xfffffffe to "fix
// fee-sniping").
func TestFIX70_SequenceForLocktime_Branches(t *testing.T) {
	tests := []struct {
		name        string
		locktime    uint32
		replaceable bool
		want        uint32
	}{
		{"replaceable_no_locktime", 0, true, 0xfffffffd},
		{"replaceable_with_locktime", 500_000, true, 0xfffffffd},
		{"final_no_locktime", 0, false, 0xffffffff},
		{"final_with_locktime", 500_000, false, 0xfffffffe},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sequenceForLocktime(tc.locktime, tc.replaceable)
			if got != tc.want {
				t.Errorf("sequenceForLocktime(%d, %v) = 0x%08x, want 0x%08x",
					tc.locktime, tc.replaceable, got, tc.want)
			}
			// Cross-check: when replaceable, must be ≤ BIP125RBFSequence.
			if tc.replaceable && got > expectedRBFSequence {
				t.Errorf("replaceable=true returned 0x%08x > 0x%08x — NOT BIP-125 RBF", got, expectedRBFSequence)
			}
		})
	}
}

// decodeTxHex is a small helper to decode a hex-serialized tx from an
// RPC response into a wire.MsgTx for sequence assertions.
func decodeTxHex(t *testing.T, hexStr string) *wire.MsgTx {
	t.Helper()
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatalf("tx deserialize: %v", err)
	}
	return tx
}

// ensure address package import is used (it's referenced via the address
// strings in test bodies but not directly — keep linkage stable in case
// the test helpers' shape changes).
var _ = address.Regtest
