package mempool

// FIX-72 — prioritisetransaction + modified-fee correctness (W120 BUG-10).
//
// Closes the BUG-10 audit gate. Test matrix (in this order):
//
//   1. PrioritiseTransaction stacks deltas; net-zero clears the entry.
//   2. Delta applied BEFORE the tx enters the pool still applies after.
//   3. GetModifiedFee returns base+delta both via top-level API and via
//      mempool-locked path.
//   4. Positive delta on the original WINS RBF Rule 3 (replacement that
//      barely beats raw fee is now rejected because modified > replacement
//      fee).
//   5. Negative delta on the original SURRENDERS Rule 3 — a replacement
//      paying less than raw fee is accepted because modified fee dropped.
//   6. Cancellation: applying opposite deltas removes the entry from
//      mapDeltas (Core txmempool.cpp:644).
//   7. Restart parity: deltas do NOT survive a Dump/Load round-trip.
//   8. Source-level regression guard — checkRBFLocked sums modified fees
//      (not raw fees) for conflict-fee tally in Rule 3.
//   9. GetPrioritisedTransactions snapshot shape (RPC contract).
//
// References:
//   bitcoin-core/src/rpc/mining.cpp::prioritisetransaction
//   bitcoin-core/src/txmempool.cpp::PrioritiseTransaction / ApplyDelta /
//     GetPrioritisedTransactions
//   bitcoin-core/src/policy/rbf.cpp::PaysMoreThanConflicts
//   bitcoin-core/src/kernel/mempool_entry.h::CTxMemPoolEntry::GetModifiedFee
//   BIP-125 §"Implementation".

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// --- Test 1: stacking + net-zero clear -----------------------------------

func TestFIX72_PrioritiseTransaction_StacksAndClears(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	var txid wire.Hash256
	txid[0] = 0x01

	// Initially zero.
	if got := mp.GetFeeDelta(txid); got != 0 {
		t.Fatalf("initial delta = %d, want 0", got)
	}

	// +1000 stacks onto +0 → 1000.
	mp.PrioritiseTransaction(txid, 1000)
	if got := mp.GetFeeDelta(txid); got != 1000 {
		t.Fatalf("after +1000 delta = %d, want 1000", got)
	}

	// +500 stacks → 1500.
	mp.PrioritiseTransaction(txid, 500)
	if got := mp.GetFeeDelta(txid); got != 1500 {
		t.Fatalf("after +500 stack delta = %d, want 1500", got)
	}

	// -500 stacks → 1000.
	mp.PrioritiseTransaction(txid, -500)
	if got := mp.GetFeeDelta(txid); got != 1000 {
		t.Fatalf("after -500 stack delta = %d, want 1000", got)
	}

	// -1000 → net-zero. Entry is REMOVED from the map (Core parity).
	mp.PrioritiseTransaction(txid, -1000)
	if got := mp.GetFeeDelta(txid); got != 0 {
		t.Fatalf("after -1000 (net zero) delta = %d, want 0", got)
	}
	// Snapshot the inner map directly: a net-zero must DELETE the key,
	// not leave a 0-valued entry (Core txmempool.cpp:644 deletes; we
	// match so GetPrioritisedTransactions doesn't leak phantom entries).
	mp.mu.RLock()
	_, present := mp.mapDeltas[txid]
	mp.mu.RUnlock()
	if present {
		t.Fatal("net-zero delta should have removed the map entry, not " +
			"left a 0-valued key (Core parity: txmempool.cpp:644)")
	}
}

// --- Test 2: prioritisation BEFORE the tx is in the pool -----------------

func TestFIX72_PrioritiseBeforeBroadcast(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0x02
	op, e := createFundingUTXO(seedHash, 0, 100_000)
	utxoSet.AddUTXO(op, e)

	mp := newTestMempool(utxoSet)

	tx := makeRBFTx([]wire.OutPoint{op}, 90_000)
	h := tx.TxHash()

	// Prioritise BEFORE the tx is added.
	mp.PrioritiseTransaction(h, 5000)
	if got := mp.GetFeeDelta(h); got != 5000 {
		t.Fatalf("pre-pool delta = %d, want 5000", got)
	}

	// Now seed the entry. Modified fee should include the previously-set
	// delta. Mirrors Core: PrioritiseTransaction writes mapDeltas
	// unconditionally; lookup at AcceptToMemoryPool reads modifier.
	mp.mu.Lock()
	addPoolEntry(mp, &TxEntry{TxHash: h, Tx: tx, Fee: 1000, Size: 150})
	mp.mu.Unlock()

	entry := mp.GetEntry(h)
	if entry == nil {
		t.Fatal("entry missing after addPoolEntry")
	}
	if got, want := mp.GetModifiedFee(entry), int64(6000); got != want {
		t.Fatalf("modified fee after late-arriving entry = %d, want %d", got, want)
	}
}

// --- Test 3: GetModifiedFee API contract ----------------------------------

func TestFIX72_GetModifiedFee_API(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	// nil entry → 0 (matches the entry-method semantics in Core).
	if got := mp.GetModifiedFee(nil); got != 0 {
		t.Fatalf("nil entry GetModifiedFee = %d, want 0", got)
	}

	var seedHash wire.Hash256
	seedHash[0] = 0x03
	op, e := createFundingUTXO(seedHash, 0, 100_000)
	utxoSet.AddUTXO(op, e)

	tx := makeRBFTx([]wire.OutPoint{op}, 90_000)
	h := tx.TxHash()
	mp.mu.Lock()
	addPoolEntry(mp, &TxEntry{TxHash: h, Tx: tx, Fee: 2500, Size: 150})
	mp.mu.Unlock()

	entry := mp.GetEntry(h)

	// No delta → modified == raw.
	if got, want := mp.GetModifiedFee(entry), int64(2500); got != want {
		t.Fatalf("zero-delta GetModifiedFee = %d, want %d", got, want)
	}

	mp.PrioritiseTransaction(h, 1500)
	if got, want := mp.GetModifiedFee(entry), int64(4000); got != want {
		t.Fatalf("after +1500 GetModifiedFee = %d, want %d", got, want)
	}

	// Negative delta below raw fee is allowed (Core allows arbitrary
	// signed deltas; the result can even be negative). The mempool does
	// not RE-EVICT on negative-delta-induced low feerate; it just
	// participates in fee comparisons.
	mp.PrioritiseTransaction(h, -3000) // net = -1500
	if got, want := mp.GetModifiedFee(entry), int64(1000); got != want {
		t.Fatalf("after net -1500 GetModifiedFee = %d, want %d", got, want)
	}
}

// --- Test 4: positive delta WINS RBF Rule 3 ------------------------------
//
// Setup:
//   Conflict C has Fee=2000 (signals RBF, sequence=0).
//   Replacement R offers fee = 2500 — barely beats C's raw fee.
//
// Without prioritisation: Rule 3 accepts (R 2500 > C 2000).
// After PrioritiseTransaction(C, +5000): Rule 3 must REJECT
// (R 2500 < modified C 7000).
//
// Uses the opt-in RBF mempool to exercise the legacy Rule 1 path, so
// Rule 3 actually fires (fullrbf=true short-circuits Rule 1 but the
// Rule 3 sum is the same code path). We use opt-in RBF for clarity.

func TestFIX72_PositiveDelta_WinsRule3(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0x04
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 500_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempoolOptInRBF(utxoSet)

	cTx := makeRBFTx([]wire.OutPoint{opSeed}, 200_000)
	cHash := cTx.TxHash()
	mp.mu.Lock()
	addPoolEntry(mp, &TxEntry{
		TxHash: cHash, Tx: cTx, Fee: 2000, Size: 150,
		FeeRate: 2000.0 / 150.0,
	})
	mp.mu.Unlock()

	// Sanity baseline: R fee=2500, no delta → Rule 3 PASSES (so the test
	// is isolating the delta effect, not some other gate).
	rTx := makeRBFTx([]wire.OutPoint{opSeed}, 200_000)
	totalInputValue := int64(202_500) // fee = 2500
	conflicts := map[wire.Hash256]bool{cHash: true}

	mp.mu.Lock()
	err := mp.checkRBFLocked(rTx, conflicts, totalInputValue)
	mp.mu.Unlock()
	// Rule 3 passes, but Rule 4 (incremental relay) requires fee bump >=
	// minBump. With incremental=1000 sat/kvB and vsize ~110 → minBump ~110.
	// Additional = 500 → Rule 4 also passes. ImprovesFeerateDiagram is
	// the variable here. Don't assert error == nil; assert error is NOT
	// ErrRBFInsufficientFee.
	if errors.Is(err, ErrRBFInsufficientFee) {
		t.Fatalf("baseline: R fee=2500, C fee=2000 should not fail Rule 3/4 "+
			"(got %v)", err)
	}

	// Apply +5000 delta to C. C's modified fee = 7000.
	mp.PrioritiseTransaction(cHash, 5000)

	mp.mu.Lock()
	err = mp.checkRBFLocked(rTx, conflicts, totalInputValue)
	mp.mu.Unlock()
	if !errors.Is(err, ErrRBFInsufficientFee) {
		t.Fatalf("positive delta should defend C: want ErrRBFInsufficientFee, "+
			"got %v (R fee=2500 vs modified C fee=7000)", err)
	}
	if err == nil || !strings.Contains(err.Error(), "less fees") {
		// Error string contract — log-grep friendly.
		t.Logf("error message: %v", err)
	}
}

// --- Test 5: negative delta SURRENDERS Rule 3 ----------------------------
//
// Setup:
//   Conflict C raw fee = 5000. Replacement R fee = 2000.
//   Without delta: Rule 3 REJECTS (R < C).
//   After PrioritiseTransaction(C, -4500): C modified = 500. R 2000 > 500
//   passes Rule 3.

func TestFIX72_NegativeDelta_LosesRule3(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0x05
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 500_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempoolOptInRBF(utxoSet)

	cTx := makeRBFTx([]wire.OutPoint{opSeed}, 200_000)
	cHash := cTx.TxHash()
	mp.mu.Lock()
	addPoolEntry(mp, &TxEntry{
		TxHash: cHash, Tx: cTx, Fee: 5000, Size: 150,
		FeeRate: 5000.0 / 150.0,
	})
	mp.mu.Unlock()

	rTx := makeRBFTx([]wire.OutPoint{opSeed}, 200_000)
	totalInputValue := int64(202_000) // fee = 2000
	conflicts := map[wire.Hash256]bool{cHash: true}

	// Baseline: Rule 3 rejects (R=2000 < C=5000).
	mp.mu.Lock()
	err := mp.checkRBFLocked(rTx, conflicts, totalInputValue)
	mp.mu.Unlock()
	if !errors.Is(err, ErrRBFInsufficientFee) {
		t.Fatalf("baseline: R fee=2000 < C fee=5000 should fail Rule 3 (got %v)", err)
	}

	// Apply -4500 → C modified = 500.
	mp.PrioritiseTransaction(cHash, -4500)

	mp.mu.Lock()
	err = mp.checkRBFLocked(rTx, conflicts, totalInputValue)
	mp.mu.Unlock()
	// Rule 3 must NOT reject for fee-too-low now (modified C 500 < R 2000).
	// Other gates (Rule 4 / diagram) may still reject — but not Rule 3's
	// "less fees" error.
	if errors.Is(err, ErrRBFInsufficientFee) && err != nil &&
		strings.Contains(err.Error(), "less fees") {
		t.Fatalf("negative delta should surrender Rule 3: want no 'less fees' "+
			"rejection, got %v", err)
	}
}

// --- Test 6: cancellation -------------------------------------------------

func TestFIX72_DeltaCancellation(t *testing.T) {
	utxoSet := newTestUTXOSet()
	mp := newTestMempool(utxoSet)

	var txid wire.Hash256
	txid[0] = 0x06

	mp.PrioritiseTransaction(txid, 3000)
	mp.PrioritiseTransaction(txid, -3000)

	if got := mp.GetFeeDelta(txid); got != 0 {
		t.Errorf("post-cancellation delta = %d, want 0", got)
	}

	mp.mu.RLock()
	_, present := mp.mapDeltas[txid]
	mp.mu.RUnlock()
	if present {
		t.Fatal("cancellation should DELETE the mapDeltas key " +
			"(matches Core txmempool.cpp:644)")
	}

	// GetPrioritisedTransactions must omit the cancelled entry — a
	// phantom 0-delta entry would leak into the operator-visible RPC.
	infos := mp.GetPrioritisedTransactions()
	for _, info := range infos {
		if info.TxID == txid {
			t.Errorf("cancelled txid %s leaked into GetPrioritisedTransactions: %+v",
				txid, info)
		}
	}
}

// --- Test 7: deltas LOST on restart --------------------------------------
//
// Core actually persists mapDeltas (mempool_persist.cpp:101). We deliberately
// emit ZERO deltas on Dump (persist.go) so operators must re-issue
// prioritisations on cold start — see Mempool.mapDeltas docs. This test
// pins that decision; if a later wave decides to persist deltas, this test
// must be updated alongside the persist.go change and the
// Mempool.mapDeltas / persist.go comments.

func TestFIX72_DeltasNotPersistedAcrossRestart(t *testing.T) {
	dir, err := os.MkdirTemp("", "fix72-persist-*")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	defer os.RemoveAll(dir)

	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0x07
	op, e := createFundingUTXO(seedHash, 0, 100_000)
	utxoSet.AddUTXO(op, e)

	// Build mempool A, seed a tx, prioritise.
	mpA := newTestMempool(utxoSet)
	tx := makeRBFTx([]wire.OutPoint{op}, 90_000)
	h := tx.TxHash()
	mpA.mu.Lock()
	addPoolEntry(mpA, &TxEntry{TxHash: h, Tx: tx, Fee: 1000, Size: 150})
	mpA.mu.Unlock()
	mpA.PrioritiseTransaction(h, 7777)

	if err := mpA.Dump(dir); err != nil {
		t.Fatalf("Dump: %v", err)
	}

	// Build mempool B from scratch, load the dump.
	utxoSetB := newTestUTXOSet()
	utxoSetB.AddUTXO(op, e)
	mpB := newTestMempool(utxoSetB)
	if _, err := mpB.Load(dir, LoadOptions{}); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := mpB.GetFeeDelta(h); got != 0 {
		t.Errorf("delta survived restart: got %d, want 0 (blockbrew "+
			"intentionally emits zero deltas in mempool.dat — see "+
			"persist.go + Mempool.mapDeltas docs)", got)
	}
}

// --- Test 8: source-level regression guard against raw-fee Rule 3 --------
//
// This test asserts that checkRBFLocked uses modified fees, NOT raw fees,
// for the Rule 3 totalConflictingFee sum.  Mechanism:
//
//   C raw fee = 1000. Apply delta = +9000. C modified = 10000.
//   R offers fee = 5000. If Rule 3 used RAW fees, R(5000) > C_raw(1000) —
//   accepted. With MODIFIED fees, R(5000) < C_modified(10000) — rejected.
//
// A regression that reverts to `totalConflictingFee += entry.Fee` would
// fail this test loudly (test name + assertion message points to
// PaysMoreThanConflicts).

func TestFIX72_Rule3UsesModifiedFee_RegressionGuard(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0x08
	opSeed, eSeed := createFundingUTXO(seedHash, 0, 500_000)
	utxoSet.AddUTXO(opSeed, eSeed)

	mp := newTestMempoolOptInRBF(utxoSet)

	cTx := makeRBFTx([]wire.OutPoint{opSeed}, 200_000)
	cHash := cTx.TxHash()
	mp.mu.Lock()
	addPoolEntry(mp, &TxEntry{
		TxHash: cHash, Tx: cTx, Fee: 1000, Size: 150,
		FeeRate: 1000.0 / 150.0,
	})
	mp.mu.Unlock()

	mp.PrioritiseTransaction(cHash, 9000)

	rTx := makeRBFTx([]wire.OutPoint{opSeed}, 200_000)
	totalInputValue := int64(205_000) // R fee = 5000
	conflicts := map[wire.Hash256]bool{cHash: true}

	mp.mu.Lock()
	err := mp.checkRBFLocked(rTx, conflicts, totalInputValue)
	mp.mu.Unlock()

	if !errors.Is(err, ErrRBFInsufficientFee) {
		t.Fatalf("REGRESSION: checkRBFLocked accepted a replacement that "+
			"beats raw conflict fee but loses to modified fee — Rule 3 "+
			"must use modified fees (Core PaysMoreThanConflicts uses "+
			"GetModifiedFee, src/policy/rbf.cpp:109-112).\n"+
			"  C raw=1000, delta=+9000, C modified=10000\n"+
			"  R fee=5000 — should fail Rule 3 against MODIFIED but pass "+
			"against RAW.\n"+
			"  Got err=%v", err)
	}
}

// --- Test 9: GetPrioritisedTransactions shape -----------------------------

func TestFIX72_GetPrioritisedTransactions_Shape(t *testing.T) {
	utxoSet := newTestUTXOSet()
	var seedHash wire.Hash256
	seedHash[0] = 0x09
	op, e := createFundingUTXO(seedHash, 0, 100_000)
	utxoSet.AddUTXO(op, e)

	mp := newTestMempool(utxoSet)

	tx := makeRBFTx([]wire.OutPoint{op}, 90_000)
	h := tx.TxHash()
	mp.mu.Lock()
	addPoolEntry(mp, &TxEntry{TxHash: h, Tx: tx, Fee: 1000, Size: 150})
	mp.mu.Unlock()

	// In-pool entry with delta.
	mp.PrioritiseTransaction(h, 500)

	// Pre-broadcast entry (no pool slot) with delta.
	var phantom wire.Hash256
	phantom[0] = 0xFE
	mp.PrioritiseTransaction(phantom, 100)

	infos := mp.GetPrioritisedTransactions()
	if len(infos) != 2 {
		t.Fatalf("GetPrioritisedTransactions len = %d, want 2", len(infos))
	}

	var inPoolInfo, phantomInfo *PrioritisedDeltaInfo
	for i := range infos {
		switch infos[i].TxID {
		case h:
			inPoolInfo = &infos[i]
		case phantom:
			phantomInfo = &infos[i]
		}
	}
	if inPoolInfo == nil {
		t.Fatal("in-pool entry not returned by GetPrioritisedTransactions")
	}
	if !inPoolInfo.InMempool {
		t.Errorf("in-pool entry InMempool = false, want true")
	}
	if inPoolInfo.FeeDelta != 500 {
		t.Errorf("in-pool entry FeeDelta = %d, want 500", inPoolInfo.FeeDelta)
	}
	if inPoolInfo.ModifiedFee != 1500 {
		t.Errorf("in-pool entry ModifiedFee = %d, want 1500", inPoolInfo.ModifiedFee)
	}

	if phantomInfo == nil {
		t.Fatal("phantom entry not returned by GetPrioritisedTransactions")
	}
	if phantomInfo.InMempool {
		t.Errorf("phantom entry InMempool = true, want false")
	}
	if phantomInfo.FeeDelta != 100 {
		t.Errorf("phantom entry FeeDelta = %d, want 100", phantomInfo.FeeDelta)
	}
	// ModifiedFee MUST be zero (or omitted at the RPC layer) when not
	// in pool. We expose it as 0; the RPC handler omits the field
	// entirely (per Core mining.cpp:558 "Only returned if in_mempool=true").
	if phantomInfo.ModifiedFee != 0 {
		t.Errorf("phantom entry ModifiedFee = %d, want 0 (not in pool)",
			phantomInfo.ModifiedFee)
	}
}
