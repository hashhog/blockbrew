package mempool

// r3fix-blockbrew-areinputsstandard-solver: Core's ValidateInputsStandardness
// (policy/policy.cpp, called from PreChecks at validation.cpp:903) runs
// Solver on every prevout and refuses NONSTANDARD and WITNESS_UNKNOWN; for a
// P2SH prevout it evaluates the scriptSig with SCRIPT_VERIFY_NONE and refuses
// one that fails or leaves an empty stack. blockbrew ran only the two sigop
// limits, so it admitted (and relayed) spends of e.g. a bare OP_1 output.
//
// Every expected value below is what Core v31.1 does for that prevout /
// scriptSig. The tests use only APIs that exist on master, so they compile
// there and fail by name on the assertion.
//
// newTestMempool does run the input scripts, so on master most refusal cases
// end in a later script failure (or are admitted outright, as bare OP_1 is).
// The controls therefore assert only that the answer is NOT
// bad-txns-nonstandard-inputs; whatever comes after standardness is not
// this item's rule.

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

func aisRepeat(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

// aisKey returns a 33-byte compressed-key-shaped push body with header hdr.
func aisKey(hdr byte, seed byte) []byte {
	k := aisRepeat(seed, 33)
	k[0] = hdr
	return k
}

func aisPush(data []byte) []byte {
	switch {
	case len(data) <= 75:
		return append([]byte{byte(len(data))}, data...)
	case len(data) <= 255:
		return append([]byte{0x4c, byte(len(data))}, data...)
	default:
		return append([]byte{0x4d, byte(len(data)), byte(len(data) >> 8)}, data...)
	}
}

func aisCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func aisP2SH() []byte { return aisCat([]byte{0xa9, 0x14}, aisRepeat(0x22, 20), []byte{0x87}) }

// aisSpend spends one prevout locked by prevScript with scriptSig, paying a
// standard P2WPKH output and a 10,000 sat fee. Returns the mempool's answer.
func aisSpend(t *testing.T, seed byte, prevScript, scriptSig []byte) error {
	t.Helper()
	utxos := newTestUTXOSet()
	op := wire.OutPoint{Hash: wire.Hash256{0xa1, seed}, Index: 0}
	utxos.AddUTXO(op, &consensus.UTXOEntry{Amount: 1_000_000, PkScript: prevScript, Height: 1})
	mp := newTestMempool(utxos)
	tx := buildMinimalSpendTx(op, scriptSig, p2wpkhOutput(seed))
	tx.TxOut[0].Value = 990_000
	return mp.AddTransaction(tx)
}

// aisNonStandardInputs reports whether err is Core's
// "bad-txns-nonstandard-inputs" state, and returns its rendered string.
func aisNonStandardInputs(err error) (string, bool) {
	var rej *RBFRejectError
	if errors.As(err, &rej) && rej.Reason == "bad-txns-nonstandard-inputs" {
		return rej.Error(), true
	}
	return "", false
}

// TestR3fixAreInputsStandardSolverRefuses: prevouts and P2SH scriptSigs Core
// refuses with bad-txns-nonstandard-inputs, with Core's debug string.
func TestR3fixAreInputsStandardSolverRefuses(t *testing.T) {
	cases := []struct {
		name       string
		prevScript []byte
		scriptSig  []byte
		wantDetail string
	}{
		// R106 minimised case: bare OP_1, empty scriptSig.
		{"bare-OP_1", []byte{0x51}, nil, "input 0 script unknown"},
		{"bare-OP_TRUE-OP_VERIFY", []byte{0x51, 0x69, 0x51}, nil, "input 0 script unknown"},
		{"empty-scriptPubKey", []byte{}, nil, "input 0 script unknown"},
		// Witness program v0 of a size other than 20/32: Solver NONSTANDARD.
		{"witness-v0-25-bytes", aisCat([]byte{0x00, 25}, aisRepeat(0x33, 25)), nil, "input 0 script unknown"},
		// v2 program: WITNESS_UNKNOWN.
		{"witness-v2-32-bytes", aisCat([]byte{0x52, 32}, aisRepeat(0x33, 32)), nil, "input 0 witness program is undefined"},
		// v1 of 20 bytes is neither taproot nor P2A: WITNESS_UNKNOWN.
		{"witness-v1-20-bytes", aisCat([]byte{0x51, 20}, aisRepeat(0x33, 20)), nil, "input 0 witness program is undefined"},
		// P2PK whose key header is not 02/03/04/06/07: CPubKey::ValidSize fails.
		{"p2pk-bad-header", aisCat(aisPush(aisKey(0x05, 1)), []byte{0xac}), nil, "input 0 script unknown"},
		// Multisig whose second key has a bad header.
		{"multisig-bad-key", aisCat([]byte{0x51}, aisPush(aisKey(0x02, 1)), aisPush(aisKey(0x05, 2)), []byte{0x52, 0xae}), nil, "input 0 script unknown"},
		// Multisig m > n.
		{"multisig-m-gt-n", aisCat([]byte{0x52}, aisPush(aisKey(0x02, 1)), []byte{0x51, 0xae}), nil, "input 0 script unknown"},
		// Multisig m pushed non-minimally (push 0x01 instead of OP_1).
		{"multisig-nonminimal-m", aisCat([]byte{0x01, 0x01}, aisPush(aisKey(0x02, 1)), []byte{0x51, 0xae}), nil, "input 0 script unknown"},
		// OP_RETURN followed by a truncated push is not NULL_DATA.
		{"op_return-truncated-push", []byte{0x6a, 0x05, 0x01}, nil, "input 0 script unknown"},
		// P2SH, empty scriptSig: EvalScript leaves an empty stack.
		{"p2sh-empty-scriptsig", aisP2SH(), nil, "input 0 P2SH redeemscript missing"},
		// P2SH, a 521-byte push (R16 PUSH_SIZE).
		{"p2sh-push-521", aisP2SH(), aisPush(aisRepeat(0x51, 521)), "p2sh scriptsig malformed (input 0: Push value size limit exceeded)"},
		// P2SH, OP_RESERVED is push-only (<= OP_16) but not executable.
		{"p2sh-op_reserved", aisP2SH(), []byte{0x50}, "p2sh scriptsig malformed (input 0: Opcode missing or not understood)"},
		// P2SH, 1001 OP_0 pushes: stack size limit 1000.
		{"p2sh-stack-1001", aisP2SH(), aisRepeat(0x00, 1001), "p2sh scriptsig malformed (input 0: Stack size limit exceeded)"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := aisSpend(t, byte(i+1), tc.prevScript, tc.scriptSig)
			got, ok := aisNonStandardInputs(err)
			if !ok {
				t.Fatalf("AddTransaction = %v, want Core's bad-txns-nonstandard-inputs", err)
			}
			want := "bad-txns-nonstandard-inputs, " + tc.wantDetail
			if got != want {
				t.Errorf("reject = %q, want %q", got, want)
			}
		})
	}
}

// TestR3fixAreInputsStandardSolverAdmits: controls. Each prevout is a type
// Solver recognises (or a P2SH scriptSig that evaluates to a redeemScript of
// <= 15 sigops), so Core's ValidateInputsStandardness passes it. Several of
// them are NOT standard outputs (P2PK is, but 1-of-4 multisig, 20-key
// multisig, OP_RETURN and unknown-type-shaped ones are judged as outputs
// elsewhere): the input rule is the Solver type, not IsStandard. Some of
// them then fail the script check (no signatures); that is not what is
// asserted here.
func TestR3fixAreInputsStandardSolverAdmits(t *testing.T) {
	keys4 := aisCat(aisPush(aisKey(0x02, 1)), aisPush(aisKey(0x03, 2)), aisPush(aisKey(0x02, 3)), aisPush(aisKey(0x03, 4)))
	var keys20 []byte
	for k := 0; k < 20; k++ {
		keys20 = append(keys20, aisPush(aisKey(0x02, byte(k+1)))...)
	}
	cases := []struct {
		name       string
		prevScript []byte
		scriptSig  []byte
	}{
		{"p2pkh", aisCat([]byte{0x76, 0xa9, 0x14}, aisRepeat(0x44, 20), []byte{0x88, 0xac}), nil},
		{"p2pk-compressed", aisCat(aisPush(aisKey(0x02, 7)), []byte{0xac}), nil},
		{"p2pk-uncompressed", aisCat(aisPush(aisCat([]byte{0x04}, aisRepeat(0x55, 64))), []byte{0xac}), nil},
		{"multisig-1-of-4", aisCat([]byte{0x51}, keys4, []byte{0x54, 0xae}), nil},
		// m and n of 20 keys: n = 20 must be pushed as a minimal CScriptNum (0x14).
		{"multisig-20-of-20-pushed-n", aisCat([]byte{0x01, 0x14}, keys20, []byte{0x01, 0x14, 0xae}), nil},
		{"null-data", []byte{0x6a, 0x02, 0xbe, 0xef}, nil},
		{"p2wpkh", aisCat([]byte{0x00, 0x14}, aisRepeat(0x66, 20)), nil},
		{"p2wsh", aisCat([]byte{0x00, 0x20}, aisRepeat(0x66, 32)), nil},
		{"p2tr", aisCat([]byte{0x51, 0x20}, aisRepeat(0x66, 32)), nil},
		{"p2a", []byte{0x51, 0x02, 0x4e, 0x73}, nil},
		{"p2sh-redeem-15-sigops", aisP2SH(), aisPush(aisRepeat(0xac, 15))},
		{"p2sh-push-520", aisP2SH(), aisPush(aisRepeat(0x51, 520))},
		{"p2sh-redeem-op_0", aisP2SH(), []byte{0x00}},
		{"p2sh-stack-1000", aisP2SH(), aisRepeat(0x00, 1000)},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := aisSpend(t, byte(0x80+i), tc.prevScript, tc.scriptSig)
			if got, ok := aisNonStandardInputs(err); ok {
				t.Fatalf("AddTransaction refused as %q; Core's ValidateInputsStandardness passes this input", got)
			}
			if err != nil && strings.Contains(err.Error(), "nonstandard-inputs") {
				t.Fatalf("AddTransaction = %v; Core passes this input", err)
			}
		})
	}
}

// TestR3fixAreInputsStandardSolverOrder: Core runs ValidateInputsStandardness
// after the missing-inputs check and CheckTxInputs (validation.cpp:857-903),
// so a tx that also fails one of those gets that earlier reason.
func TestR3fixAreInputsStandardSolverOrder(t *testing.T) {
	t.Run("outputs-above-inputs-is-in-belowout", func(t *testing.T) {
		utxos := newTestUTXOSet()
		op := wire.OutPoint{Hash: wire.Hash256{0xa2, 1}, Index: 0}
		utxos.AddUTXO(op, &consensus.UTXOEntry{Amount: 1_000_000, PkScript: []byte{0x51}, Height: 1})
		mp := newTestMempool(utxos)
		tx := buildMinimalSpendTx(op, nil, p2wpkhOutput(1))
		tx.TxOut[0].Value = 2_000_000
		err := mp.AddTransaction(tx)
		if !errors.Is(err, ErrNegativeFee) {
			t.Fatalf("AddTransaction = %v, want ErrNegativeFee (Core bad-txns-in-belowout comes first)", err)
		}
	})
	t.Run("missing-second-input-is-missing-inputs", func(t *testing.T) {
		utxos := newTestUTXOSet()
		op := wire.OutPoint{Hash: wire.Hash256{0xa2, 2}, Index: 0}
		utxos.AddUTXO(op, &consensus.UTXOEntry{Amount: 1_000_000, PkScript: []byte{0x51}, Height: 1})
		mp := newTestMempool(utxos)
		tx := buildMinimalSpendTx(op, nil, p2wpkhOutput(2))
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xa2, 3}, Index: 0},
			Sequence:         0xffffffff,
		})
		tx.TxOut[0].Value = 990_000
		err := mp.AddTransaction(tx)
		if !errors.Is(err, ErrMissingInputs) {
			t.Fatalf("AddTransaction = %v, want ErrMissingInputs (Core TX_MISSING_INPUTS comes first)", err)
		}
	})
	t.Run("second-input-nonstandard-names-input-1", func(t *testing.T) {
		utxos := newTestUTXOSet()
		op0 := wire.OutPoint{Hash: wire.Hash256{0xa2, 4}, Index: 0}
		op1 := wire.OutPoint{Hash: wire.Hash256{0xa2, 5}, Index: 0}
		utxos.AddUTXO(op0, &consensus.UTXOEntry{Amount: 1_000_000, PkScript: p2wpkhOutput(9), Height: 1})
		utxos.AddUTXO(op1, &consensus.UTXOEntry{Amount: 1_000_000, PkScript: []byte{0x51}, Height: 1})
		mp := newTestMempool(utxos)
		tx := buildMinimalSpendTx(op0, nil, p2wpkhOutput(3))
		tx.TxIn = append(tx.TxIn, &wire.TxIn{PreviousOutPoint: op1, Sequence: 0xffffffff})
		tx.TxOut[0].Value = 1_990_000
		got, ok := aisNonStandardInputs(mp.AddTransaction(tx))
		if !ok || got != "bad-txns-nonstandard-inputs, input 1 script unknown" {
			t.Fatalf("reject = %q (nonstandard=%v), want %q", got, ok, "bad-txns-nonstandard-inputs, input 1 script unknown")
		}
	})
}
