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

// TestAncestorSizeLimitRejectsAtCap covers Job 3 (size limits). A short
// ancestor chain whose vsize sum exceeds DEFAULT_ANCESTOR_SIZE_LIMIT_KVB
// (101 kvB = 101_000 vB) must be rejected with
// ErrAncestorSizeTooLarge, even though the count cap (25) is respected.
//
// Builds a 2-deep chain where the parent is 60_000 vB. A 50_000-vB
// candidate would push ancestor-sum to 110_000 vB > 101_000 vB, so it
// must be rejected.
func TestAncestorSizeLimitRejectsAtCap(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	var parentHash wire.Hash256
	parentHash[0] = 0xF0

	mp.mu.Lock()
	parent := &TxEntry{
		Tx:             &wire.MsgTx{},
		TxHash:         parentHash,
		Fee:            10_000,
		Size:           60_000, // 60 kvB
		Time:           time.Now(),
		AncestorFee:    10_000,
		AncestorSize:   60_000,
		DescendantFee:  10_000,
		DescendantSize: 60_000,
	}
	mp.pool[parentHash] = parent
	mp.mu.Unlock()

	// Candidate spends parent's output 0; its own vsize is 50_000 vB.
	candidate := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 0},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x00, 0x14}}},
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()

	// At 50_000 vB, ancestor-sum would be 110_000 vB > 101_000 vB → reject.
	if err := mp.checkChainLimitsWithSizeLocked(candidate, 50_000); !errors.Is(err, ErrAncestorSizeTooLarge) {
		t.Fatalf("expected ErrAncestorSizeTooLarge for 110 kvB chain, got %v", err)
	}

	// At 40_000 vB, ancestor-sum would be 100_000 vB ≤ 101_000 vB → accept.
	if err := mp.checkChainLimitsWithSizeLocked(candidate, 40_000); err != nil {
		t.Fatalf("expected 100-kvB chain to pass, got %v", err)
	}

	// Legacy entry-point (vsize=0) only checks ancestors-already-in-pool;
	// 60 kvB alone is under the cap.
	if err := mp.checkChainLimitsLocked(candidate); err != nil {
		t.Fatalf("legacy entry-point should pass with vsize=0, got %v", err)
	}

	// Confirm the new constants line up with Core defaults.
	if DefaultAncestorSizeLimitKvB != 101 || DefaultDescendantSizeLimitKvB != 101 {
		t.Fatalf("constants drifted from Core: ancestor=%d, descendant=%d",
			DefaultAncestorSizeLimitKvB, DefaultDescendantSizeLimitKvB)
	}
}

// TestDescendantSizeLimitRejectsAtCap exercises the descendant-size cap.
// A root tx with two large descendants pushes any new-sibling candidate
// over the 101 kvB descendant-size limit.
func TestDescendantSizeLimitRejectsAtCap(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	var rootHash wire.Hash256
	rootHash[0] = 0xE0

	mp.mu.Lock()
	root := &TxEntry{
		Tx:             &wire.MsgTx{},
		TxHash:         rootHash,
		Fee:            10_000,
		Size:           500, // small root
		Time:           time.Now(),
		AncestorFee:    10_000,
		AncestorSize:   500,
		DescendantFee:  10_000,
		DescendantSize: 500,
	}
	mp.pool[rootHash] = root

	// Two existing children, each 50_000 vB. Total under root including
	// self = 500 + 50_000 + 50_000 = 100_500 vB.
	for i := 0; i < 2; i++ {
		var h wire.Hash256
		h[0] = byte(0xE1 + i)
		entry := &TxEntry{
			Tx:             &wire.MsgTx{},
			TxHash:         h,
			Fee:            500,
			Size:           50_000,
			Time:           time.Now(),
			Depends:        []wire.Hash256{rootHash},
			AncestorFee:    10_500,
			AncestorSize:   50_500,
			DescendantFee:  500,
			DescendantSize: 50_000,
		}
		mp.pool[h] = entry
		root.SpentBy = append(root.SpentBy, h)
	}
	mp.mu.Unlock()

	// Candidate spends a third output of the root, vsize=1000.
	// Descendant-sum becomes 100_500 + 1000 = 101_500 vB > 101_000 vB.
	candidate := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: rootHash, Index: 2},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x00, 0x14}}},
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()
	if err := mp.checkChainLimitsWithSizeLocked(candidate, 1000); !errors.Is(err, ErrDescendantSizeTooLarge) {
		t.Fatalf("expected ErrDescendantSizeTooLarge, got %v", err)
	}

	// vsize=400 → descendant-sum 100_900 vB ≤ 101_000 vB → accept.
	if err := mp.checkChainLimitsWithSizeLocked(candidate, 400); err != nil {
		t.Fatalf("expected vsize=400 candidate to pass descendant-size cap, got %v", err)
	}
}
