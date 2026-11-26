// Package mempool — r3fix-blockbrew-p2a-dust-threshold.
//
// Bitcoin Core has no dust carve-out for pay-to-anchor (P2A) outputs.
// GetDustThreshold (policy/policy.cpp:26-63) treats P2A (OP_1 <0x4e73>) like
// any other witness program: serialized txout 8+1+4 = 13 bytes, plus the
// segwit spending estimate 32+4+1+(107/4)+4 = 67, so 80 bytes at
// DUST_RELAY_TX_FEE 3000 sat/kvB = 240 sat. A P2A worth >= 240 sat is not
// dust; one worth < 240 sat (including the 0-sat ephemeral anchor) is dust,
// and is only allowed in a 0-fee tx (PreCheckEphemeralTx,
// policy/ephemeral_policy.cpp:27, "dust, tx with dust output must be 0-fee").
//
// blockbrew had the rule inverted (P2A dust iff value > 240), so the R3
// differential fuzzer (night 1, seed 739943) saw 545- and 546-sat anchors
// refused where Core accepts them; and a fee-paying tx with a 0-sat anchor
// would pass blockbrew's dust gate where Core refuses it.
package mempool

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Minimised night-1 case `mempool/verdict/accept|nonstandard`:
// tapscript script=[1 1 DROP] outs=[[545, P2A], [rest, P2WSH]].
// Core v31.1 accepts it; blockbrew refused it as dust.
const r3p2aMinimisedHex = "02000000000101a8c81fc84fc26ac7cb09fb2d60e4ea7601c7dae5b757618f6f14df29988828450000000000feffffff0221020000000000000451024e73d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260020351517521c179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000"

const r3p2aPrevAmount = int64(100_000)

var r3p2aScript = []byte{0x51, 0x02, 0x4e, 0x73}

// r3p2aSetup decodes the minimised tx and returns a mempool holding the P2TR
// prevout it spends (leaf [1 1 DROP] under internal key G, taken from the
// tx's own control block).
func r3p2aSetup(t *testing.T) (*Mempool, *wire.MsgTx) {
	t.Helper()
	raw, err := hex.DecodeString(r3p2aMinimisedHex)
	if err != nil {
		t.Fatal(err)
	}
	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatalf("decode minimised tx: %v", err)
	}
	wit := tx.TxIn[0].Witness
	if len(wit) != 2 {
		t.Fatalf("witness items = %d, want 2 (leaf, control)", len(wit))
	}
	leaf, control := wit[0], wit[1]
	leafHash := script.TapLeaf(control[0]&0xfe, leaf)
	internalKey := control[1:33]
	outKey, parity := crypto.ComputeTaprootOutputKey(internalKey, script.TapTweak(internalKey, leafHash[:]))
	if outKey == nil || parity != control[0]&1 {
		t.Fatalf("control block does not match leaf (parity %d vs %d)", parity, control[0]&1)
	}
	pk := append([]byte{0x51, 0x20}, outKey...)

	u := newTestUTXOSet()
	u.AddUTXO(tx.TxIn[0].PreviousOutPoint, &consensus.UTXOEntry{Amount: r3p2aPrevAmount, PkScript: pk, Height: 1})
	mp := newTestMempool(u)
	mp.SetChainHeight(200)

	if !consensus.IsPayToAnchor(tx.TxOut[0].PkScript) || tx.TxOut[0].Value != 545 {
		t.Fatalf("output 0 = %d sat %x, want 545 sat P2A", tx.TxOut[0].Value, tx.TxOut[0].PkScript)
	}
	return mp, tx
}

// TestR3Fix_P2ADustThresholdIsWitnessThreshold pins Core's GetDustThreshold
// for P2A (240 sat) and IsDust on both sides of it.
func TestR3Fix_P2ADustThresholdIsWitnessThreshold(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())
	p2a := &wire.TxOut{PkScript: r3p2aScript}
	if got := DustThreshold(p2a, consensus.DustRelayFeeRate); got != 240 {
		t.Fatalf("DustThreshold(P2A) = %d, want 240 ((13+67)*3, policy.cpp:26-63)", got)
	}
	cases := []struct {
		value int64
		dust  bool
	}{
		{0, true}, {1, true}, {239, true},
		{240, false}, {241, false}, {545, false}, {546, false}, {100_000, false},
	}
	for _, c := range cases {
		out := &wire.TxOut{Value: c.value, PkScript: r3p2aScript}
		if got := mp.isDust(out); got != c.dust {
			t.Errorf("isDust(P2A, %d sat) = %v, want %v (Core IsDust: value < 240)", c.value, got, c.dust)
		}
		// The testmempoolaccept dry-run reads the exported twin.
		if got := mp.IsDust(out); got != c.dust {
			t.Errorf("IsDust(P2A, %d sat) = %v, want %v", c.value, got, c.dust)
		}
	}
}

// TestR3Fix_P2AMinimisedCaseAccepted: the night-1 minimised tx (545-sat
// anchor, fee-paying) is accepted, as Core v31.1 accepts it.
func TestR3Fix_P2AMinimisedCaseAccepted(t *testing.T) {
	mp, tx := r3p2aSetup(t)
	if err := mp.AddTransaction(tx); err != nil {
		t.Fatalf("545-sat P2A tx rejected (Core v31.1 accepts it): %v", err)
	}
}

// TestR3Fix_P2AValuesAroundThreshold re-runs the same tx with other anchor
// values: >= 240 accepted, < 240 (and 0) refused in a fee-paying tx with
// Core's "tx with dust output must be 0-fee". Changing the anchor value does
// not touch the witness ([1 1 DROP] carries no signature).
func TestR3Fix_P2AValuesAroundThreshold(t *testing.T) {
	for _, c := range []struct {
		value  int64
		accept bool
	}{
		{546, true}, {241, true}, {240, true},
		{239, false}, {1, false}, {0, false},
	} {
		mp, tx := r3p2aSetup(t)
		tx.TxOut[0].Value = c.value
		err := mp.AddTransaction(tx)
		if c.accept {
			if err != nil {
				t.Errorf("P2A %d sat: rejected (Core accepts, value >= 240): %v", c.value, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("P2A %d sat in a fee-paying tx: accepted (Core refuses: dust, tx with dust output must be 0-fee)", c.value)
			continue
		}
		if !errors.Is(err, ErrDustOutput) || !errors.Is(err, ErrEphemeralDustNonZeroFee) {
			t.Errorf("P2A %d sat: rejected for the wrong reason (want dust/0-fee): %v", c.value, err)
		}
	}
}
