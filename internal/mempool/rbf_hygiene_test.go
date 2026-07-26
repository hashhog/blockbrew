package mempool

import (
	"errors"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TestSignalsRBFCoreParity covers the BIP-125 sequence-constant fix
// (Job 1 of the mempool RBF-hygiene wave). Bitcoin Core's
// MAX_BIP125_RBF_SEQUENCE = 0xfffffffd; nSequence = 0xfffffffe (the
// anti-fee-snipe value used by many wallets) must NOT be treated as
// signaling. Pre-fix the gate was `< 0xffffffff`, which incorrectly
// flagged 0xfffffffe as RBF. This test pins the fix.
func TestSignalsRBFCoreParity(t *testing.T) {
	mkTx := func(seqs ...uint32) *wire.MsgTx {
		tx := &wire.MsgTx{Version: 2}
		for i, s := range seqs {
			var h wire.Hash256
			h[0] = byte(0xA0 + i)
			tx.TxIn = append(tx.TxIn, &wire.TxIn{
				PreviousOutPoint: wire.OutPoint{Hash: h, Index: uint32(i)},
				Sequence:         s,
			})
		}
		tx.TxOut = []*wire.TxOut{{Value: 1, PkScript: []byte{0x00, 0x14}}}
		return tx
	}

	cases := []struct {
		name string
		seqs []uint32
		want bool
	}{
		{"all-final-no-signal", []uint32{0xFFFFFFFF}, false},
		{"anti-fee-snipe-no-signal", []uint32{0xFFFFFFFE}, false},
		{"max-rbf-signaling-boundary", []uint32{0xFFFFFFFD}, true},
		{"low-sequence-signals", []uint32{0}, true},
		{"mixed-one-anti-fee-snipe", []uint32{0xFFFFFFFE, 0xFFFFFFFE}, false},
		{"mixed-one-signaling", []uint32{0xFFFFFFFE, 0xFFFFFFFD}, true},
		{"mixed-final-and-rbf", []uint32{0xFFFFFFFF, 0x00000005}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := signalsRBF(mkTx(tc.seqs...))
			if got != tc.want {
				t.Fatalf("signalsRBF(seqs=%x) = %v, want %v", tc.seqs, got, tc.want)
			}
		})
	}
}

// TestRBFRule2RejectsNewUnconfirmedInput covers BIP-125 Rule 2
// (Job 2). The replacement transaction must not introduce new
// unconfirmed inputs that were not already known to the conflicting
// txs (i.e., not in conflicts ∪ ancestors-of-conflicts). Pre-fix the
// rule was a comment-only stub.
//
// Topology:
//
//	A (conflict, signals RBF)        B (independent unconfirmed)
//	   spends UTXO U_A                   spends UTXO U_B
//
// New tx N spends:  - U_A's input (so it conflicts with A), AND
//                   - an output of B (a NEW unconfirmed input that
//                     was not in A nor any ancestor of A)
// Expected: rejected with ErrRBFNewUnconfirmedInput.
func TestRBFRule2RejectsNewUnconfirmedInput(t *testing.T) {
	utxoSet := newTestUTXOSet()

	var hashUA, hashUB wire.Hash256
	hashUA[0] = 0xAA
	hashUB[0] = 0xBB
	opUA, eUA := createFundingUTXO(hashUA, 0, 100_000)
	opUB, eUB := createFundingUTXO(hashUB, 0, 100_000)
	utxoSet.AddUTXO(opUA, eUA)
	utxoSet.AddUTXO(opUB, eUB)

	mp := newTestMempool(utxoSet)

	// A: conflicting tx, signals RBF (sequence=0).
	txA := createTestTransaction([]wire.OutPoint{opUA}, 99_000, 1)
	txA.TxIn[0].Sequence = 0
	txAHash := txA.TxHash()

	// B: independent unconfirmed tx (does NOT conflict with anything yet).
	txB := createTestTransaction([]wire.OutPoint{opUB}, 99_500, 1)
	txB.TxIn[0].Sequence = 0
	txBHash := txB.TxHash()

	// Splice both into the pool manually.
	mp.mu.Lock()
	mp.pool[txAHash] = &TxEntry{
		Tx: txA, TxHash: txAHash, Fee: 1000, Size: 200,
		Time:        time.Now(),
		AncestorFee: 1000, AncestorSize: 200,
		DescendantFee: 1000, DescendantSize: 200,
	}
	for _, in := range txA.TxIn {
		mp.outpoints[in.PreviousOutPoint] = txAHash
	}
	mp.pool[txBHash] = &TxEntry{
		Tx: txB, TxHash: txBHash, Fee: 500, Size: 200,
		Time:        time.Now(),
		AncestorFee: 500, AncestorSize: 200,
		DescendantFee: 500, DescendantSize: 200,
	}
	for _, in := range txB.TxIn {
		mp.outpoints[in.PreviousOutPoint] = txBHash
	}
	mp.totalSize = 400
	mp.mu.Unlock()

	// Outpoint pointing at B's first output (a "new unconfirmed input").
	opB0 := wire.OutPoint{Hash: txBHash, Index: 0}

	// New tx spends U_A (conflicts with A) AND B's output.
	newTx := createTestTransaction(
		[]wire.OutPoint{opUA, opB0},
		180_000,
		1,
	)

	conflicts := map[wire.Hash256]bool{txAHash: true}

	mp.mu.Lock()
	defer mp.mu.Unlock()
	err := mp.checkRBFLocked(newTx, conflicts, 200_000)
	if !errors.Is(err, ErrRBFNewUnconfirmedInput) {
		t.Fatalf("expected ErrRBFNewUnconfirmedInput (Rule 2), got %v", err)
	}

	// Sanity: replacing without the foreign B-input should pass Rule 2
	// (it may still fail Rule 3/4 fee-bump checks, but those are wrapped
	// in different sentinel errors). We only assert it does NOT trip
	// Rule 2.
	cleanReplacement := createTestTransaction([]wire.OutPoint{opUA}, 50_000, 1)
	if err := mp.checkRBFNoNewUnconfirmedInputsLocked(cleanReplacement, conflicts); err != nil {
		t.Fatalf("clean replacement (no foreign mempool input) should pass Rule 2, got %v", err)
	}

	// Sanity: a replacement that pulls in A's own descendants is fine
	// because A is in the conflict set. (Encoded by re-using opUA — it
	// IS a conflict, not a "new unconfirmed input"; Rule 2 only fires
	// for inputs whose parent tx is in the mempool but NOT in the
	// allowed closure.) Confirmed UTXOs (U_A, U_B as confirmed) are
	// always fine: input previous-output hash not in pool ⇒ OK.
	confirmedOnlyTx := createTestTransaction([]wire.OutPoint{opUA, opUB}, 180_000, 1)
	if err := mp.checkRBFNoNewUnconfirmedInputsLocked(confirmedOnlyTx, conflicts); err != nil {
		t.Fatalf("confirmed-only inputs should pass Rule 2, got %v", err)
	}
}
