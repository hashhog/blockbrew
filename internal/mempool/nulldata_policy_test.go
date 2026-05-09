package mempool

// Regression tests for W58-2: isNullData / isStandardOutputScript propagation
// into the mempool policy gate.
//
// Background: W56 (44c0a18) fixed blockbrew's isNullData in the RPC
// decodescript path to match Core's Solver NULL_DATA classification
// (OP_RETURN + IsPushOnly remainder; truncated pushes → NONSTANDARD).
// W58-2 audited whether that fix also reached the mempool acceptance path
// (AcceptToMemoryPool / AddTransaction).  It did not — no IsStandard gate
// existed in AddTransaction at all.
//
// PATH B fixes applied:
//  1. consensus.IsNullData extracted as the shared canonical classifier.
//  2. isDust fixed: OP_RETURN / unspendable outputs now return false (never
//     dust), matching Core's GetDustThreshold → 0 for IsUnspendable().
//  3. isStandardOutputScript gate added in AddTransaction (step 5a) to reject
//     nonstandard scripts including malformed OP_RETURN.
//  4. isNullData in rpc/decodepsbt_helpers.go delegates to consensus.IsNullData.

import (
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ---------------------------------------------------------------------------
// consensus.IsNullData unit tests (shared classifier)
// ---------------------------------------------------------------------------

func TestIsNullData(t *testing.T) {
	cases := []struct {
		name string
		hex  []byte
		want bool
	}{
		{
			name: "bare OP_RETURN (empty payload)",
			hex:  []byte{0x6a},
			want: true,
		},
		{
			name: "OP_RETURN 4-byte push (6a04deadbeef)",
			hex:  []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef},
			want: true,
		},
		{
			name: "OP_RETURN OP_0 (push empty)",
			hex:  []byte{0x6a, 0x00},
			want: true,
		},
		{
			// OP_RETURN + push-9 opcode but only 4 bytes of data follow → truncated
			name: "malformed OP_RETURN truncated push (6a09deadbeef) → NONSTANDARD",
			hex:  []byte{0x6a, 0x09, 0xde, 0xad, 0xbe, 0xef},
			want: false,
		},
		{
			// OP_RETURN + a non-push opcode (OP_DUP = 0x76) → NONSTANDARD
			name: "OP_RETURN non-push opcode → NONSTANDARD",
			hex:  []byte{0x6a, 0x76},
			want: false,
		},
		{
			name: "not OP_RETURN (P2PKH-ish)",
			hex:  []byte{0x76, 0xa9, 0x14},
			want: false,
		},
		{
			name: "empty script",
			hex:  []byte{},
			want: false,
		},
		{
			name: "OP_RETURN + OP_PUSHDATA1 + length + data (well-formed)",
			// 0x6a OP_RETURN, 0x4c OP_PUSHDATA1, 0x04 length, 0xdeadbeef data
			hex:  []byte{0x6a, 0x4c, 0x04, 0xde, 0xad, 0xbe, 0xef},
			want: true,
		},
		{
			name: "OP_RETURN + OP_PUSHDATA1 + missing length byte → NONSTANDARD",
			hex:  []byte{0x6a, 0x4c},
			want: false,
		},
		{
			name: "OP_RETURN + OP_1NEGATE (valid push)",
			hex:  []byte{0x6a, 0x4f},
			want: true,
		},
		{
			name: "OP_RETURN + OP_16 (valid push)",
			hex:  []byte{0x6a, 0x60},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := consensus.IsNullData(tc.hex)
			if got != tc.want {
				t.Errorf("IsNullData(%x) = %v, want %v", tc.hex, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isStandardOutputScript unit tests (mempool-internal)
// ---------------------------------------------------------------------------

func TestIsStandardOutputScript(t *testing.T) {
	cases := []struct {
		name string
		s    []byte
		want bool
	}{
		{
			name: "P2WPKH (v0 keyhash) — standard",
			// OP_0 <20-byte push>
			s:    append([]byte{0x00, 0x14}, make([]byte, 20)...),
			want: true,
		},
		{
			name: "P2WSH (v0 scripthash) — standard",
			// OP_0 <32-byte push>
			s:    append([]byte{0x00, 0x20}, make([]byte, 32)...),
			want: true,
		},
		{
			name: "P2TR (v1 taproot) — standard",
			// OP_1 <32-byte push>
			s:    append([]byte{0x51, 0x20}, make([]byte, 32)...),
			want: true,
		},
		{
			name: "P2PKH — standard",
			// OP_DUP OP_HASH160 <20-byte push> OP_EQUALVERIFY OP_CHECKSIG
			s: func() []byte {
				s := []byte{0x76, 0xa9, 0x14}
				s = append(s, make([]byte, 20)...)
				s = append(s, 0x88, 0xac)
				return s
			}(),
			want: true,
		},
		{
			name: "well-formed nulldata (OP_RETURN 4-byte push) — standard",
			s:    []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef},
			want: true,
		},
		{
			name: "bare OP_RETURN — standard (nulldata with empty payload)",
			s:    []byte{0x6a},
			want: true,
		},
		{
			name: "malformed OP_RETURN truncated push (6a09deadbeef) — NONSTANDARD",
			s:    []byte{0x6a, 0x09, 0xde, 0xad, 0xbe, 0xef},
			want: false,
		},
		{
			name: "OP_RETURN + non-push opcode — NONSTANDARD",
			s:    []byte{0x6a, 0x76},
			want: false,
		},
		{
			name: "completely unknown opcode stream — NONSTANDARD",
			s:    []byte{0xbb, 0xcc, 0xdd},
			want: false,
		},
		{
			name: "witness v2 program (future soft fork) — accepted as WITNESS_UNKNOWN",
			// OP_2 (0x52) <20-byte push>
			s:    append([]byte{0x52, 0x14}, make([]byte, 20)...),
			want: true,
		},
		{
			name: "empty script — NONSTANDARD",
			s:    []byte{},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isStandardOutputScript(tc.s)
			if got != tc.want {
				t.Errorf("isStandardOutputScript(%x) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isDust with OP_RETURN fix
// ---------------------------------------------------------------------------

func TestIsDustOpReturnExempt(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())

	t.Run("well-formed nulldata value=0 is not dust", func(t *testing.T) {
		txOut := &wire.TxOut{
			Value:    0,
			PkScript: []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef},
		}
		if mp.isDust(txOut) {
			t.Error("OP_RETURN output should never be dust (Core GetDustThreshold=0 for IsUnspendable)")
		}
	})

	t.Run("malformed nulldata value=0 is not dust (unspendable exemption)", func(t *testing.T) {
		// Malformed OP_RETURN also starts with 0x6a → IsUnspendable → not dust.
		// The standardness gate (isStandardOutputScript) rejects it as nonstandard
		// before the dust check is reached, but the dust function itself must
		// also not flag it.
		txOut := &wire.TxOut{
			Value:    0,
			PkScript: []byte{0x6a, 0x09, 0xde, 0xad, 0xbe, 0xef}, // truncated push
		}
		if mp.isDust(txOut) {
			t.Error("OP_RETURN output (even malformed) should not be flagged as dust")
		}
	})

	t.Run("bare OP_RETURN value=0 is not dust", func(t *testing.T) {
		txOut := &wire.TxOut{
			Value:    0,
			PkScript: []byte{0x6a},
		}
		if mp.isDust(txOut) {
			t.Error("bare OP_RETURN should not be dust")
		}
	})
}

// ---------------------------------------------------------------------------
// AcceptToMemoryPool end-to-end: malformed OP_RETURN vout → reject nonstandard
// ---------------------------------------------------------------------------

// buildTxWithOpReturnOut builds a minimal transaction that spends fundingOut
// and has one OP_RETURN output with the given script.  We skip signatures here
// because the unit-test mempool skips script validation; we only need to
// exercise the policy gate.
func buildTxWithOpReturnOut(fundingOut wire.OutPoint, pkScript []byte) *wire.MsgTx {
	tx := &wire.MsgTx{
		Version:  2,
		LockTime: 0,
	}
	// Spending input — dummy scriptSig, no RBF signal.
	tx.TxIn = []*wire.TxIn{{
		PreviousOutPoint: fundingOut,
		SignatureScript:  make([]byte, 107),
		Sequence:         0xffffffff,
	}}
	// OP_RETURN output (value must be 0; anything else is also fine per policy).
	tx.TxOut = []*wire.TxOut{{
		Value:    0,
		PkScript: pkScript,
	}}
	return tx
}

// newTestMempoolNoScript creates a test mempool with no ChainState (skips
// IsFinalTx / BIP-68 checks) and a MinRelayFeeRate that we can control.
// Script validation will fail unless the UTXO PkScript is empty (which the
// engine short-circuits).  We wire up real UTXOs with empty PkScript so that
// script validation passes without needing real signatures.
func newTestMempoolNoScript() (*Mempool, wire.OutPoint) {
	utxoSet := newTestUTXOSet()

	var fundingHash wire.Hash256
	fundingHash[0] = 0xf0
	fundingHash[1] = 0x0d

	outpoint := wire.OutPoint{Hash: fundingHash, Index: 0}
	// Use an empty PkScript so script engine immediately succeeds (no ops).
	entry := &consensus.UTXOEntry{
		Amount:     1_000_000, // 0.01 BTC — plenty for any fee
		PkScript:   []byte{},  // empty = immediately valid
		Height:     1,
		IsCoinbase: false,
	}
	utxoSet.AddUTXO(outpoint, entry)

	config := Config{
		MaxSize:         10_000_000,
		MinRelayFeeRate: 1000, // 1 sat/vB
		MaxOrphanTxs:    100,
		ChainParams:     consensus.RegtestParams(),
	}
	mp := New(config, utxoSet)
	mp.SetChainHeight(800_000)
	return mp, outpoint
}

func TestAcceptToMemoryPool_MalformedOpReturn(t *testing.T) {
	mp, fundingOut := newTestMempoolNoScript()

	// Script 6a09deadbeef: OP_RETURN (0x6a) + push-9 (0x09) + 4 bytes of data.
	// push-9 claims 9 bytes follow but only 4 are present → truncated.
	malformedScript := []byte{0x6a, 0x09, 0xde, 0xad, 0xbe, 0xef}

	tx := buildTxWithOpReturnOut(fundingOut, malformedScript)
	err := mp.AcceptToMemoryPool(tx)
	if err == nil {
		t.Fatal("expected AcceptToMemoryPool to reject tx with malformed OP_RETURN vout, but it was accepted")
	}

	// Must be rejected as nonstandard — not as dust (which was the pre-fix
	// behaviour when the missing IsStandard gate let the dust check fire first).
	if !strings.Contains(err.Error(), "nonstandard") {
		t.Errorf("expected 'nonstandard' rejection, got: %v", err)
	}
}

func TestAcceptToMemoryPool_WellFormedOpReturn(t *testing.T) {
	mp, fundingOut := newTestMempoolNoScript()

	// Well-formed nulldata: OP_RETURN + 4-byte push.
	// This should NOT be rejected as nonstandard or as dust.
	// It may still fail script validation (engine sees OP_RETURN in the tx
	// spending a blank PkScript — but the OP_RETURN is in the OUTPUT, not the
	// scriptPubKey being evaluated, so validation should pass for the input).
	wellFormedScript := []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef}

	tx := buildTxWithOpReturnOut(fundingOut, wellFormedScript)
	err := mp.AcceptToMemoryPool(tx)
	if err != nil {
		// The tx might fail for other reasons (e.g. cluster limits, fee in
		// edge case), but it must NOT fail due to nonstandard or dust.
		if strings.Contains(err.Error(), "nonstandard") {
			t.Errorf("well-formed nulldata vout incorrectly rejected as nonstandard: %v", err)
		}
		if strings.Contains(err.Error(), "dust") {
			t.Errorf("well-formed nulldata vout with value=0 incorrectly rejected as dust: %v", err)
		}
	}
}
