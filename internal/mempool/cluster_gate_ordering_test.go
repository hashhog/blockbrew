package mempool

// Wave A follow-up — WHERE the cluster gate runs, and WHICH UNITS it sums.
//
// Two holes the adversarial review of the Wave A change found:
//
//  1. The too-large-cluster rejection was decided AFTER the RBF conflicts had
//     already been evicted, making it a zero-cost eviction primitive. Core
//     decides first: AcceptSingleTransactionInternal runs ReplacementChecks,
//     then CheckMemPoolPolicyLimits and `return Failure` (validation.cpp:
//     1341-1345), and only afterwards FinalizeSubpackage (:1393) — which is the
//     ONLY place conflicting transactions are removed from the pool
//     (validation.cpp:1198-1238).
//
//  2. Nothing on the LIVE admission path could tell "Σ unrounded weight vs
//     404000" apart from "Σ per-tx ⌈w/4⌉ vs 101000". Every live-path fixture
//     used legacy transactions, whose weight is always 4×size, so ⌈w/4⌉ == w/4
//     exactly and the per-transaction rounding error is identically zero. The
//     segwit fixture below makes it observable.
//
// Core reference:
//   validation.cpp:1019           StageRemoval(conflict) — staged, not applied
//   validation.cpp:1023, :1342    CheckMemPoolPolicyLimits → "too-large-cluster"
//   validation.cpp:1198-1238      FinalizeSubpackage — the actual eviction
//   txmempool.cpp:1072-1080       ChangeSet::CheckMemPoolPolicyLimits
//   txgraph.cpp:2059              strict ">" on both count and size

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// Helpers — multi-input legacy spends
// ============================================================================

// spendableTxMulti is spendableTx with more than one input. All inputs are
// anyone-can-spend P2SH(OP_TRUE), as in spendableTx.
func spendableTxMulti(ins []wire.OutPoint, valuePerOutput int64, numOutputs int) *wire.MsgTx {
	tx := &wire.MsgTx{Version: 2}
	for _, in := range ins {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: in,
			SignatureScript:  []byte{0x01, 0x51}, // push OP_TRUE
			Sequence:         0xffffffff,
		})
	}
	for i := 0; i < numOutputs; i++ {
		tx.TxOut = append(tx.TxOut, &wire.TxOut{
			Value:    valuePerOutput,
			PkScript: p2shAnyoneCanSpendScript(),
		})
	}
	return tx
}

// nearFullCluster fills the mempool with a single chain of fat legacy
// transactions, stopping while at least `headroomFloor` weight units of the
// cluster size cap are still unused. It returns the chain tip's txid, the
// value sitting on tip output 0, the number of transactions admitted and the
// cluster's total weight.
//
// The tip carries `outputsPerFatTx` spendable outputs, so callers can build a
// child that conflicts on output 0 while pulling in output 1 as well.
func nearFullCluster(t *testing.T, mp *Mempool, funding wire.OutPoint, fundingValue, headroomFloor int64) (tip wire.Hash256, tipValue int64, count int, weight int64) {
	t.Helper()

	const outputsPerFatTx = 90
	const padValue = 5_000
	const feePerTx = 100_000

	prevOut := funding
	value := fundingValue

	for count < MaxClusterCount {
		next := value - feePerTx - padValue*(outputsPerFatTx-1)
		tx := spendableTxMulti([]wire.OutPoint{prevOut}, padValue, outputsPerFatTx)
		tx.TxOut[0].Value = next

		w := consensus.CalcTxWeight(tx)
		if weight+w > MaxClusterSizeWeight-headroomFloor {
			break
		}
		if err := mp.AddTransaction(tx); err != nil {
			t.Fatalf("filling cluster: tx %d rejected: %v", count+1, err)
		}
		weight += w
		count++
		value = next
		tip = tx.TxHash()
		prevOut = wire.OutPoint{Hash: tip, Index: 0}
	}

	if count == 0 {
		t.Fatal("fixture broken: no filler transaction was admitted")
	}
	return tip, value, count, weight
}

// ============================================================================
// THE DEFECT: a too-large-cluster rejection must not evict its RBF conflicts
// ============================================================================

// TestTooLargeClusterRejectionMustNotEvictConflicts is the regression test for
// the zero-cost eviction / pinning vector.
//
// Attack: fill a cluster to just under the 404_000 WU size cap, park a victim
// transaction in it, then submit a transaction that (a) conflicts with the
// victim and satisfies every BIP-125 rule, and (b) is fat enough that admitting
// it would push the cluster over the cap. The submission is rejected
// "too-large-cluster" and therefore never enters the mempool and never pays a
// fee — so if the conflicts were evicted before that decision was reached, the
// attacker deleted the victim for free and can repeat it indefinitely.
//
// With the gate decided after the eviction, this test sees the mempool shrink
// by one and the victim gone. With the read-only probe placed ahead of the
// eviction — Core's ordering — the victim survives untouched.
func TestTooLargeClusterRejectionMustNotEvictConflicts(t *testing.T) {
	mp, funding := spendableMempool(0xF7, 2_000_000_000)

	// 1. A cluster filled to within one fat transaction of the size cap. The
	//    2_000 WU floor guarantees the small victim below still fits.
	tip, tipValue, chainLen, clusterWeight := nearFullCluster(t, mp, funding, 2_000_000_000, 2_000)

	tipOut0 := wire.OutPoint{Hash: tip, Index: 0}
	tipOut1 := wire.OutPoint{Hash: tip, Index: 1}

	// 2. The victim: a small child spending tip:0.
	victim := spendableTxMulti([]wire.OutPoint{tipOut0}, tipValue-50_000, 1)
	victimWeight := consensus.CalcTxWeight(victim)
	if clusterWeight+victimWeight > MaxClusterSizeWeight {
		t.Fatalf("fixture broken: cluster %d + victim %d already exceeds %d",
			clusterWeight, victimWeight, MaxClusterSizeWeight)
	}
	if err := mp.AddTransaction(victim); err != nil {
		t.Fatalf("victim should be accepted, got %v", err)
	}
	victimHash := victim.TxHash()

	poolBefore := mp.Count()
	if poolBefore != chainLen+1 {
		t.Fatalf("mempool holds %d txs, want %d", poolBefore, chainLen+1)
	}

	// 3. The attacker: spends tip:0 (conflicting with the victim) and tip:1.
	//    Pulling in tip:1 is what makes this a replacement rather than a plain
	//    child, and BIP-125 Rule 2 is satisfied because tip is an ancestor of
	//    the conflict (checkRBFNoNewUnconfirmedInputsLocked's allowed closure).
	//
	//    Its weight is sized from the cluster's actual headroom so the fixture
	//    cannot silently stop discriminating: even after the victim's weight is
	//    discounted (it is being replaced), the attacker overflows the cap.
	headroom := MaxClusterSizeWeight - clusterWeight
	const padValue = 5_000
	attackerOutputs := int(headroom/128) + 32 // each P2SH output is 32 B = 128 WU
	attacker := spendableTxMulti([]wire.OutPoint{tipOut0, tipOut1}, padValue, attackerOutputs)
	attackerWeight := consensus.CalcTxWeight(attacker)

	if attackerWeight <= headroom {
		t.Fatalf("fixture broken: attacker weight %d does not exceed the cluster's "+
			"headroom %d, so it would be accepted rather than rejected",
			attackerWeight, headroom)
	}
	if attackerWeight > consensus.MaxStandardTxWeight {
		t.Fatalf("fixture broken: attacker weight %d exceeds MAX_STANDARD_TX_WEIGHT %d",
			attackerWeight, consensus.MaxStandardTxWeight)
	}

	// 4. The submission must be rejected on the cluster SIZE axis...
	err := mp.AddTransaction(attacker)
	if !errors.Is(err, ErrClusterTooLarge) {
		t.Fatalf("attacker should be rejected with %q, got %v", ErrClusterTooLarge, err)
	}

	// ...and the rejection must have cost the attacker's target nothing.
	if !mp.HasTransaction(victimHash) {
		t.Fatal("VICTIM WAS EVICTED BY A REJECTED TRANSACTION. " +
			"The too-large-cluster decision ran after the RBF conflicts were " +
			"removed, so a transaction that pays nothing (it never enters the " +
			"mempool) deleted the transaction it claimed to replace. Core " +
			"decides first: CheckMemPoolPolicyLimits returns Failure at " +
			"validation.cpp:1341-1345, before FinalizeSubpackage at :1393 " +
			"performs the only eviction there is.")
	}
	if got := mp.Count(); got != poolBefore {
		t.Errorf("mempool went %d -> %d across a rejected submission; "+
			"a rejection must be side-effect free", poolBefore, got)
	}
	if mp.HasTransaction(attacker.TxHash()) {
		t.Error("rejected attacker is still in the mempool")
	}

	// The victim must still own the outpoint it spends, i.e. the pool's
	// double-spend index was not left dangling either.
	mp.mu.RLock()
	spender, spent := mp.outpoints[tipOut0]
	mp.mu.RUnlock()
	if !spent || spender != victimHash {
		t.Errorf("outpoint %v spender = %v (present=%v), want the victim %v",
			tipOut0, spender, spent, victimHash)
	}

	// And the cluster itself must be unchanged: same membership, same weight.
	mp.mu.RLock()
	gotWeight := mp.clusters.ClusterSizeWeight(victimHash)
	gotSize := 0
	if c := mp.clusters.GetCluster(victimHash); c != nil {
		gotSize = c.Size()
	}
	mp.mu.RUnlock()
	if gotSize != chainLen+1 {
		t.Errorf("cluster holds %d txs after the rejection, want %d", gotSize, chainLen+1)
	}
	if want := clusterWeight + victimWeight; gotWeight != want {
		t.Errorf("cluster weight after the rejection = %d, want %d", gotWeight, want)
	}
}

// TestReplacementIntoNearFullClusterStillSucceeds is the other half of the
// ordering fix, and guards against fixing the eviction vector by making the
// probe over-strict.
//
// Core's cluster check runs against a ChangeSet whose staged REMOVALS have
// already been taken out of TxGraph's staging level (StageRemoval →
// txgraph->RemoveTransaction, txmempool.cpp:1030-1034; IsOversized is then
// asked at :1072-1080). So a replacement that swaps a transaction for one of
// similar size is judged against the cluster WITHOUT the transaction it
// replaces. A probe that ignored the removals would reject every ordinary
// fee-bump into a near-full cluster — a policy divergence in the opposite
// direction, and a nastier one, because it silently breaks fee bumping exactly
// when users need it.
func TestReplacementIntoNearFullClusterStillSucceeds(t *testing.T) {
	mp, funding := spendableMempool(0xF8, 2_000_000_000)

	tip, tipValue, chainLen, clusterWeight := nearFullCluster(t, mp, funding, 2_000_000_000, 6_000)
	tipOut0 := wire.OutPoint{Hash: tip, Index: 0}
	headroom := MaxClusterSizeWeight - clusterWeight

	// The victim is deliberately FAT — about 90% of the remaining headroom — so
	// that it fits, but two of it do not. That is what makes this fixture
	// sensitive to the removal accounting rather than merely to the cap.
	const padValue = 5_000
	victimOutputs := 1
	for {
		probe := spendableTxMulti([]wire.OutPoint{tipOut0}, padValue, victimOutputs+1)
		if consensus.CalcTxWeight(probe) > headroom*9/10 {
			break
		}
		victimOutputs++
	}

	victim := spendableTxMulti([]wire.OutPoint{tipOut0}, padValue, victimOutputs)
	victim.TxOut[0].Value = tipValue - 50_000 - padValue*int64(victimOutputs-1)
	victimWeight := consensus.CalcTxWeight(victim)

	if clusterWeight+victimWeight > MaxClusterSizeWeight {
		t.Fatalf("fixture broken: cluster %d + victim %d exceeds %d",
			clusterWeight, victimWeight, MaxClusterSizeWeight)
	}
	// Prove the fixture is actually sensitive: counting the victim AND its
	// replacement — which is what a removal-blind probe does — breaches the cap.
	if clusterWeight+2*victimWeight <= MaxClusterSizeWeight {
		t.Fatalf("fixture broken: cluster %d + 2 x victim %d stays under %d, so a "+
			"removal-blind probe would not trip and this test proves nothing",
			clusterWeight, victimWeight, MaxClusterSizeWeight)
	}

	if err := mp.AddTransaction(victim); err != nil {
		t.Fatalf("victim should be accepted, got %v", err)
	}
	victimHash := victim.TxHash()

	// A same-shape replacement paying a much larger fee. Identical weight, so
	// the post-replacement cluster weighs exactly what it does now.
	replacement := spendableTxMulti([]wire.OutPoint{tipOut0}, padValue, victimOutputs)
	replacement.TxOut[0].Value = tipValue - 5_000_000 - padValue*int64(victimOutputs-1)
	if got, want := consensus.CalcTxWeight(replacement), victimWeight; got != want {
		t.Fatalf("fixture broken: replacement weight %d != victim weight %d", got, want)
	}

	if err := mp.AddTransaction(replacement); err != nil {
		t.Fatalf("a same-size fee bump into a near-full cluster must be accepted "+
			"— Core discounts the staged removals before asking IsOversized "+
			"(txmempool.cpp:1030, :1072) — got %v", err)
	}

	if mp.HasTransaction(victimHash) {
		t.Error("the replaced transaction is still in the mempool")
	}
	if !mp.HasTransaction(replacement.TxHash()) {
		t.Error("the replacement is not in the mempool")
	}
	if got := mp.Count(); got != chainLen+1 {
		t.Errorf("mempool holds %d txs after the replacement, want %d", got, chainLen+1)
	}
}

// TestClusterGateIsReadOnlyOnRejection pins the property directly at the
// ClusterManager, independent of the mempool: CheckLimits must not mutate.
func TestClusterGateIsReadOnlyOnRejection(t *testing.T) {
	cm := NewClusterManager()

	const perCluster = 40
	const perTxWeight = 400

	build := func(idBase int) wire.Hash256 {
		var prev wire.Hash256
		for i := 0; i < perCluster; i++ {
			h := makeTestHash(idBase + i)
			var parents []wire.Hash256
			if i > 0 {
				parents = []wire.Hash256{prev}
			}
			if _, err := cm.AddTransaction(h, 1000, 100, perTxWeight, parents); err != nil {
				t.Fatalf("building cluster at %d: %v", idBase+i, err)
			}
			prev = h
		}
		return prev
	}

	tipA, tipB := build(1000), build(2000)
	idA, idB := cm.GetCluster(tipA).ID, cm.GetCluster(tipB).ID
	if idA == idB {
		t.Fatal("fixture broken: the two chains must start in distinct clusters")
	}

	joiner := makeTestHash(9000)
	if err := cm.CheckLimits(perTxWeight, []wire.Hash256{tipA, tipB}, nil); !errors.Is(err, ErrClusterTooLarge) {
		t.Fatalf("CheckLimits should report %q for a 40+40+1 merge, got %v", ErrClusterTooLarge, err)
	}
	if cm.GetCluster(joiner) != nil {
		t.Error("CheckLimits clustered the candidate — it must not mutate")
	}
	if cm.GetCluster(tipA).ID != idA || cm.GetCluster(tipB).ID != idB {
		t.Error("CheckLimits fused the parent clusters — it must not mutate")
	}
	if got := cm.ClusterSizeWeight(tipA); got != perCluster*perTxWeight {
		t.Errorf("cluster A weight = %d after CheckLimits, want %d", got, perCluster*perTxWeight)
	}

	// A candidate that fits must report no error, and still not mutate.
	solo := makeTestHash(9500)
	if err := cm.CheckLimits(perTxWeight, []wire.Hash256{tipA}, nil); err != nil {
		t.Fatalf("CheckLimits should accept a 41st transaction in cluster A, got %v", err)
	}
	if cm.GetCluster(solo) != nil {
		t.Error("CheckLimits clustered a candidate it accepted — it must not mutate")
	}
	if got := cm.GetCluster(tipA).Size(); got != perCluster {
		t.Errorf("cluster A size = %d after an accepting CheckLimits, want %d", got, perCluster)
	}
}

// TestProspectiveClusterDiscountsRemovals pins the removal accounting, and in
// particular the component logic: a removal that DISCONNECTS a cluster leaves
// only the part the candidate re-anchors to.
//
// Layout: root → mid → leaf, plus root → side. Removing mid and leaf and
// admitting a candidate that spends side leaves the component {root, side}
// (4 members before, 2 survivors + candidate = 3), not the whole cluster.
func TestProspectiveClusterDiscountsRemovals(t *testing.T) {
	cm := NewClusterManager()

	const w = 1_000
	root := makeTestHash(1)
	mid := makeTestHash(2)
	leaf := makeTestHash(3)
	side := makeTestHash(4)

	for _, tc := range []struct {
		h       wire.Hash256
		parents []wire.Hash256
	}{
		{root, nil},
		{mid, []wire.Hash256{root}},
		{leaf, []wire.Hash256{mid}},
		{side, []wire.Hash256{root}},
	} {
		if _, err := cm.AddTransaction(tc.h, 1000, 250, w, tc.parents); err != nil {
			t.Fatalf("building fixture at %v: %v", tc.h, err)
		}
	}
	if got := cm.GetCluster(root).Size(); got != 4 {
		t.Fatalf("fixture broken: cluster holds %d txs, want 4", got)
	}

	// No removals: the whole cluster plus the candidate.
	if count, weight := cm.ProspectiveCluster(w, []wire.Hash256{side}, nil); count != 5 || weight != 5*w {
		t.Errorf("ProspectiveCluster(no removals) = (%d, %d), want (5, %d)", count, weight, 5*w)
	}

	// Removing mid+leaf disconnects them from {root, side}; the candidate
	// re-anchors to side, so only root and side count.
	removals := map[wire.Hash256]bool{mid: true, leaf: true}
	count, weight := cm.ProspectiveCluster(w, []wire.Hash256{side}, removals)
	if count != 3 || weight != 3*w {
		t.Errorf("ProspectiveCluster(removing mid+leaf) = (%d, %d), want (3, %d)",
			count, weight, 3*w)
	}

	// The probe must have mutated nothing.
	if got := cm.GetCluster(root).Size(); got != 4 {
		t.Errorf("cluster size = %d after ProspectiveCluster, want 4", got)
	}
	if got := cm.ClusterSizeWeight(root); got != 4*w {
		t.Errorf("cluster weight = %d after ProspectiveCluster, want %d", got, 4*w)
	}

	// And it must agree with what the mutating path actually produces: really
	// remove mid+leaf, add the candidate, and compare.
	cm.RemoveTransaction(leaf)
	cm.RemoveTransaction(mid)
	cand := makeTestHash(5)
	if _, err := cm.AddTransaction(cand, 1000, 250, w, []wire.Hash256{side}); err != nil {
		t.Fatalf("candidate should be accepted after the removals, got %v", err)
	}
	if got := cm.GetCluster(cand).Size(); got != count {
		t.Errorf("post-eviction cluster holds %d txs, probe predicted %d", got, count)
	}
	if got := cm.ClusterSizeWeight(cand); got != weight {
		t.Errorf("post-eviction cluster weighs %d, probe predicted %d", got, weight)
	}
}

// ============================================================================
// THE UNITS HOLE: a segwit fixture on the LIVE admission path
// ============================================================================

// p2wshDropTrueWitnessScript is `OP_DROP OP_TRUE`: it drops exactly one witness
// stack item and succeeds. Spending it needs a single padding item, which is
// what makes the transaction's weight tunable in 1-WU steps — and leaves the
// stack clean, so CLEANSTACK is satisfied.
func p2wshDropTrueWitnessScript() []byte { return []byte{0x75, 0x51} }

// p2wshDropTrueScript is the v0 P2WSH scriptPubKey committing to it.
func p2wshDropTrueScript() []byte {
	h := sha256.Sum256(p2wshDropTrueWitnessScript())
	s := make([]byte, 0, 34)
	s = append(s, 0x00, 0x20) // OP_0, push 32
	return append(s, h[:]...)
}

// segwitSpend builds a P2WSH(OP_DROP OP_TRUE) spend of `in` paying numOutputs
// equal P2WSH outputs, carrying padLen bytes of witness padding.
//
// Weight bookkeeping: the padding item serialises as one length byte plus its
// contents, so going from padLen=0 to padLen=n adds EXACTLY n weight units
// (witness bytes weigh 1). padLen must stay ≤ 80 to respect
// MAX_STANDARD_P2WSH_STACK_ITEM_SIZE (policy.h, IsWitnessStandard).
func segwitSpend(in wire.OutPoint, valuePerOutput int64, numOutputs, padLen int) *wire.MsgTx {
	tx := &wire.MsgTx{Version: 2}
	tx.TxIn = append(tx.TxIn, &wire.TxIn{
		PreviousOutPoint: in,
		Sequence:         0xffffffff,
		Witness: [][]byte{
			make([]byte, padLen),
			p2wshDropTrueWitnessScript(),
		},
	})
	for i := 0; i < numOutputs; i++ {
		tx.TxOut = append(tx.TxOut, &wire.TxOut{
			Value:    valuePerOutput,
			PkScript: p2wshDropTrueScript(),
		})
	}
	return tx
}

// segwitSpendAtMost returns the heaviest P2WSH spend of `in` whose weight is
// ≤ targetWeight and ≡ 1 (mod 4).
//
// The mod-4 congruence is the point of the whole fixture: ⌈w/4⌉ - w/4 = ¾ is
// the largest per-transaction rounding error there is, so a cluster of such
// transactions maximises the gap between the two candidate rules — Σw against
// 404_000 (Core's) and Σ⌈w/4⌉ against 101_000 (the plausible mis-port). Over 64
// transactions the gap is 64 × ¾ = 48 vB, i.e. 192 weight units, and that is
// the entire window in which the two rules can be told apart.
//
// Returns nil if no combination of output count and padding reaches the target.
func segwitSpendAtMost(in wire.OutPoint, valuePerOutput, targetWeight int64) (*wire.MsgTx, int64) {
	var best *wire.MsgTx
	var bestWeight int64

	for numOutputs := 1; numOutputs <= 400; numOutputs++ {
		bare := segwitSpend(in, valuePerOutput, numOutputs, 0)
		bareWeight := consensus.CalcTxWeight(bare)
		if bareWeight > targetWeight {
			break
		}
		pad := targetWeight - bareWeight
		if pad > 80 {
			pad = 80
		}
		// Steer down to w ≡ 1 (mod 4).
		if excess := (bareWeight + pad - 1) % 4; excess > 0 {
			if pad < excess {
				continue
			}
			pad -= excess
		}
		cand := segwitSpend(in, valuePerOutput, numOutputs, int(pad))
		w := consensus.CalcTxWeight(cand)
		if w <= targetWeight && w > bestWeight {
			best, bestWeight = cand, w
		}
	}
	return best, bestWeight
}

// segwitMempool returns a mempool plus one confirmed P2WSH(OP_DROP OP_TRUE)
// UTXO to seed a chain from.
func segwitMempool(seed byte, amount int64) (*Mempool, wire.OutPoint) {
	utxoSet := newTestUTXOSet()
	var fundingHash wire.Hash256
	fundingHash[0] = seed
	outpoint := wire.OutPoint{Hash: fundingHash, Index: 0}
	utxoSet.AddUTXO(outpoint, &consensus.UTXOEntry{
		Amount:   amount,
		PkScript: p2wshDropTrueScript(),
		Height:   1,
	})
	config := Config{
		MaxSize:                10_000_000,
		MinRelayFeeRate:        1000,
		MaxOrphanTxs:           100,
		ChainParams:            consensus.RegtestParams(),
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}
	mp := New(config, utxoSet)
	mp.SetChainHeight(800_000)
	return mp, outpoint
}

// TestSegwitClusterUnitsNoPerTxRoundingOnAdmissionPath closes the test hole the
// review found: it is the first fixture that can distinguish Core's rule from
// the rounded one ON THE LIVE PATH.
//
// It admits a 64-transaction segwit chain through Mempool.AddTransaction whose
// Σ weight is ≤ 404_000 — Core accepts it — but whose Σ⌈wᵢ/4⌉ exceeds 101_000.
// An implementation that ceilings each transaction into vbytes and sums those
// against 101_000 rejects somewhere before the 64th; Core admits all of them.
//
// The legacy P2SH(OP_TRUE) fixtures elsewhere in this package CANNOT do this.
// A legacy transaction has no witness, so weight == 4 × size exactly, ⌈w/4⌉ ==
// w/4, and the per-transaction rounding error is identically zero — the two
// rules agree on every legacy cluster, whatever the constants are.
func TestSegwitClusterUnitsNoPerTxRoundingOnAdmissionPath(t *testing.T) {
	// Core's numbers, written out rather than read from the local constants.
	// A fixture derived from MaxClusterSizeWeight would follow a mis-ported
	// constant down to 101_000 and rebuild itself into a cluster a quarter the
	// size — which the mis-port then accepts, and the test passes vacuously.
	// Pinned literals keep the fixture fixed while the implementation moves.
	//   kernel/mempool_limits.h:22  cluster_size_vbytes = 101 * 1'000
	//   txmempool.cpp:181           * WITNESS_SCALE_FACTOR  = 404_000 WU
	//   policy.h:72                 DEFAULT_CLUSTER_LIMIT   = 64
	const coreClusterSizeCapWU = int64(404_000)
	const coreClusterVbyteCap = int64(101_000)
	const coreClusterCountCap = 64

	const fundingValue = int64(1_000_000_000)
	const padValue = 10_000
	const feePerTx = 50_000

	mp, funding := segwitMempool(0x5A, fundingValue)

	prevOut := funding
	value := fundingValue
	remaining := coreClusterSizeCapWU

	var weights []int64
	var last wire.Hash256

	for i := 0; i < coreClusterCountCap; i++ {
		txsLeft := int64(coreClusterCountCap - i)
		target := remaining / txsLeft
		if txsLeft == 1 {
			target = remaining
		}

		tx, w := segwitSpendAtMost(prevOut, padValue, target)
		if tx == nil {
			t.Fatalf("fixture broken: no segwit transaction reaches weight ≤ %d at index %d", target, i)
		}
		// Carry the remaining value on output 0; the rest are padding outputs.
		// Output values do not affect weight (8 fixed bytes each).
		next := value - feePerTx - padValue*int64(len(tx.TxOut)-1)
		if next <= padValue {
			t.Fatalf("fixture broken: ran out of value at index %d", i)
		}
		tx.TxOut[0].Value = next

		if got := consensus.CalcTxWeight(tx); got != w {
			t.Fatalf("weight changed after setting output values: %d != %d", got, w)
		}
		if !tx.HasWitness() {
			t.Fatal("fixture broken: transaction carries no witness, so it cannot " +
				"exhibit per-transaction rounding error")
		}
		if w%4 != 1 {
			t.Fatalf("fixture broken: tx %d weighs %d ≢ 1 (mod 4); the ¾ vB "+
				"rounding error per transaction is what makes this discriminate", i, w)
		}

		if err := mp.AddTransaction(tx); err != nil {
			var sumSoFar, ceilSoFar int64
			for _, ww := range weights {
				sumSoFar += ww
				ceilSoFar += (ww + 3) / 4
			}
			sumSoFar += w
			ceilSoFar += (w + 3) / 4
			t.Fatalf("segwit tx %d/%d rejected: %v\n"+
				"  Σ weight       = %d (cap %d — WITHIN Core's bound)\n"+
				"  Σ ⌈weight/4⌉   = %d (vbyte cap %d)\n"+
				"this is the signature of summing per-transaction ceilinged vbytes "+
				"against the vbyte constant instead of unrounded weight against %d",
				i+1, coreClusterCountCap, err,
				sumSoFar, coreClusterSizeCapWU,
				ceilSoFar, coreClusterVbyteCap,
				coreClusterSizeCapWU)
		}

		weights = append(weights, w)
		remaining -= w
		value = next
		last = tx.TxHash()
		prevOut = wire.OutPoint{Hash: last, Index: 0}
	}

	var sumWeight, sumCeilVbytes int64
	for _, w := range weights {
		sumWeight += w
		sumCeilVbytes += (w + 3) / 4
	}

	// The fixture self-check. If either of these fails the test proves nothing,
	// so it must fail loudly rather than pass vacuously.
	if sumWeight > coreClusterSizeCapWU {
		t.Fatalf("fixture broken: Σweight = %d exceeds the cap %d, so acceptance "+
			"would have been wrong anyway", sumWeight, coreClusterSizeCapWU)
	}
	if sumCeilVbytes <= coreClusterVbyteCap {
		t.Fatalf("fixture does not discriminate: Σ⌈w/4⌉ = %d ≤ %d, so a rounded "+
			"implementation would have accepted this cluster too (Σweight = %d)",
			sumCeilVbytes, coreClusterVbyteCap, sumWeight)
	}
	if len(weights) != coreClusterCountCap {
		t.Fatalf("built %d transactions, want %d", len(weights), coreClusterCountCap)
	}

	t.Logf("64-tx segwit cluster: Σweight = %d ≤ %d (accepted, Core's rule); "+
		"Σ⌈w/4⌉ = %d > %d (a rounded implementation would have rejected)",
		sumWeight, coreClusterSizeCapWU, sumCeilVbytes, coreClusterVbyteCap)

	if got := mp.Count(); got != coreClusterCountCap {
		t.Errorf("mempool holds %d txs, want %d", got, coreClusterCountCap)
	}

	mp.mu.RLock()
	gotWeight := mp.clusters.ClusterSizeWeight(last)
	mp.mu.RUnlock()
	if gotWeight != sumWeight {
		t.Errorf("cluster weight = %d, want %d (the sum of unrounded weights)",
			gotWeight, sumWeight)
	}
	if gotWeight == sumCeilVbytes {
		t.Errorf("cluster weight = %d, which is Σ⌈w/4⌉ — the ClusterManager is "+
			"accumulating ceilinged vbytes, not weight", gotWeight)
	}
}
