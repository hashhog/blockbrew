package mempool

// Wave A — Core v31 cluster mempool limits.
//
// Pins the two cluster caps and, above all, the UNITS in which the size cap is
// evaluated.
//
// Core reference:
//   policy.h:50                 DEFAULT_BYTES_PER_SIGOP{20}
//   policy.h:72                 DEFAULT_CLUSTER_LIMIT{64}
//   policy.h:74                 DEFAULT_CLUSTER_SIZE_LIMIT_KVB{101}
//   kernel/mempool_limits.h:22  cluster_size_vbytes = 101 * 1'000
//   txmempool.cpp:181           max_cluster_size = cluster_size_vbytes * WITNESS_SCALE_FACTOR
//   txmempool.cpp:1017          TxGraph is fed GetSigOpsAdjustedWeight(weight, sigops, 20)
//   policy.cpp:390              GetSigOpsAdjustedWeight = max(weight, sigop_cost*bytes_per_sigop)
//   txgraph.cpp:2059            total_count > max_count || total_size > max_size   [STRICT >]
//   validation.cpp:1024 et al   reject token "too-large-cluster", EMPTY debug string

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// Constants and reject token
// ============================================================================

// TestClusterLimitConstants pins both caps and the derivation of the size cap
// from Core's kvB-denominated constant.
func TestClusterLimitConstants(t *testing.T) {
	if MaxClusterCount != 64 {
		t.Errorf("MaxClusterCount = %d, want 64 (Core DEFAULT_CLUSTER_LIMIT, policy.h:72)", MaxClusterCount)
	}
	if MaxClusterSizeWeight != 404_000 {
		t.Errorf("MaxClusterSizeWeight = %d, want 404000 weight units", MaxClusterSizeWeight)
	}
	// The size cap must be the kvB constant scaled to WEIGHT, not left in vbytes.
	want := int64(DefaultClusterSizeLimitKvB) * vbytesPerKvB * consensus.WitnessScaleFactor
	if MaxClusterSizeWeight != want {
		t.Errorf("MaxClusterSizeWeight = %d, want %d (= %d kvB * 1000 * %d)",
			MaxClusterSizeWeight, want, DefaultClusterSizeLimitKvB, consensus.WitnessScaleFactor)
	}
	// Guard against the single most likely wrong port: keeping the vbyte
	// constant as the enforced bound.
	if MaxClusterSizeWeight == 101_000 {
		t.Error("MaxClusterSizeWeight is 101000 — that is the VBYTE form; " +
			"the enforced bound is in weight units (txmempool.cpp:181)")
	}
}

// TestClusterRejectTokenMatchesCore pins the reject token. Core emits
// "too-large-cluster" with an EMPTY debug string for every cluster-limit
// failure (validation.cpp:1024, :1116, :1343, :1521), so the sentinel must
// carry exactly that text and nothing else.
func TestClusterRejectTokenMatchesCore(t *testing.T) {
	if got := ErrClusterTooLarge.Error(); got != "too-large-cluster" {
		t.Errorf("ErrClusterTooLarge = %q, want %q (Core reject token, empty debug string)",
			got, "too-large-cluster")
	}
}

// ============================================================================
// Count boundary: 64 accepts, 65 rejects
// ============================================================================

// TestClusterCountBoundary drives the ClusterManager gate directly: a linear
// chain of exactly MaxClusterCount transactions is accepted, and the next one
// is rejected. Core compares with a STRICT ">" (txgraph.cpp:2059).
func TestClusterCountBoundary(t *testing.T) {
	cm := NewClusterManager()

	const perTxWeight = 400 // far below the size cap; isolates the count axis

	var prev wire.Hash256
	for i := 0; i < MaxClusterCount; i++ {
		h := makeTestHash(i + 1)
		var parents []wire.Hash256
		if i > 0 {
			parents = []wire.Hash256{prev}
		}
		if _, err := cm.AddTransaction(h, 1000, 100, perTxWeight, parents); err != nil {
			t.Fatalf("tx %d of %d should be accepted (count axis), got %v", i+1, MaxClusterCount, err)
		}
		prev = h
	}

	c := cm.GetCluster(prev)
	if c.Size() != MaxClusterCount {
		t.Fatalf("cluster holds %d txs, want %d", c.Size(), MaxClusterCount)
	}

	// The 65th must be rejected.
	h65 := makeTestHash(MaxClusterCount + 1)
	_, err := cm.AddTransaction(h65, 1000, 100, perTxWeight, []wire.Hash256{prev})
	if !errors.Is(err, ErrClusterTooLarge) {
		t.Fatalf("tx %d should be rejected with ErrClusterTooLarge, got %v", MaxClusterCount+1, err)
	}

	// And the rejection must leave the cluster untouched.
	if got := cm.GetCluster(prev).Size(); got != MaxClusterCount {
		t.Errorf("cluster size after rejection = %d, want %d (rejection must be side-effect free)",
			got, MaxClusterCount)
	}
	if cm.GetCluster(h65) != nil {
		t.Error("rejected transaction must not be clustered")
	}
}

// ============================================================================
// Size boundary: 404000 accepts, 404001 rejects
// ============================================================================

// TestClusterWeightBoundaryExact builds a 2-transaction cluster whose total
// sigop-adjusted weight lands exactly on MaxClusterSizeWeight, then repeats the
// construction one weight unit heavier. Core's ">" makes the first accept and
// the second reject.
func TestClusterWeightBoundaryExact(t *testing.T) {
	tests := []struct {
		name       string
		secondTx   int64
		wantReject bool
	}{
		{"total 404000 accepts", MaxClusterSizeWeight - 200_000, false},
		{"total 404001 rejects", MaxClusterSizeWeight - 200_000 + 1, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm := NewClusterManager()

			parent := makeTestHash(1)
			if _, err := cm.AddTransaction(parent, 1000, 50_000, 200_000, nil); err != nil {
				t.Fatalf("parent should be accepted, got %v", err)
			}

			child := makeTestHash(2)
			_, err := cm.AddTransaction(child, 1000, 50_000, tc.secondTx, []wire.Hash256{parent})

			total := 200_000 + tc.secondTx
			if tc.wantReject {
				if !errors.Is(err, ErrClusterTooLarge) {
					t.Fatalf("total %d > %d should reject with ErrClusterTooLarge, got %v",
						total, MaxClusterSizeWeight, err)
				}
				if got := cm.ClusterSizeWeight(parent); got != 200_000 {
					t.Errorf("cluster weight after rejection = %d, want 200000", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("total %d == %d should be accepted, got %v", total, MaxClusterSizeWeight, err)
			}
			if got := cm.ClusterSizeWeight(parent); got != MaxClusterSizeWeight {
				t.Errorf("cluster weight = %d, want exactly %d", got, MaxClusterSizeWeight)
			}
		})
	}
}

// ============================================================================
// THE UNITS TEST
// ============================================================================

// TestClusterUnitsNoPerTxRounding is the test that catches a constant swap that
// forgets the unit change.
//
// It builds a 64-transaction cluster whose Σ weight is EXACTLY 404_000 — which
// Core accepts — but whose Σ⌈wᵢ/4⌉ is 101_048, i.e. above 101_000. An
// implementation that rounds each transaction into vbytes and sums those
// against 101_000 rejects this cluster; Core accepts it.
//
// The asymmetry is structural, not incidental: Σ⌈wᵢ/4⌉ ≥ (Σwᵢ)/4 always, so the
// rounded form is stricter than Core in one direction only, by up to 48 vB over
// a 64-transaction cluster.
func TestClusterUnitsNoPerTxRounding(t *testing.T) {
	// 63 transactions of weight 6313 plus one of weight 6281.
	//   Σ weight   = 63*6313 + 6281       = 404_000  (exactly the cap)
	//   Σ ⌈w/4⌉    = 63*1579 + 1571       = 101_048  (over the vbyte cap)
	weights := make([]int64, 0, MaxClusterCount)
	for i := 0; i < MaxClusterCount-1; i++ {
		weights = append(weights, 6313)
	}
	weights = append(weights, 6281)

	var sumWeight, sumCeilVbytes int64
	for _, w := range weights {
		sumWeight += w
		sumCeilVbytes += (w + 3) / 4
	}

	// Pin the construction itself, so a future edit cannot quietly defang it.
	if sumWeight != MaxClusterSizeWeight {
		t.Fatalf("fixture broken: Σweight = %d, want exactly %d", sumWeight, MaxClusterSizeWeight)
	}
	if sumCeilVbytes <= int64(DefaultClusterSizeLimitKvB)*vbytesPerKvB {
		t.Fatalf("fixture broken: Σceil(w/4) = %d, must exceed %d for this test to discriminate",
			sumCeilVbytes, int64(DefaultClusterSizeLimitKvB)*vbytesPerKvB)
	}

	cm := NewClusterManager()
	var prev wire.Hash256
	for i, w := range weights {
		h := makeTestHash(i + 1)
		var parents []wire.Hash256
		if i > 0 {
			parents = []wire.Hash256{prev}
		}
		if _, err := cm.AddTransaction(h, 1000, int32((w+3)/4), w, parents); err != nil {
			t.Fatalf("tx %d/%d rejected (%v) — Σweight so far is within %d; "+
				"this is the signature of summing per-transaction ceilinged vbytes "+
				"against %d instead of unrounded weight against %d",
				i+1, len(weights), err, MaxClusterSizeWeight,
				int64(DefaultClusterSizeLimitKvB)*vbytesPerKvB, MaxClusterSizeWeight)
		}
		prev = h
	}

	if got := cm.ClusterSizeWeight(prev); got != MaxClusterSizeWeight {
		t.Errorf("cluster weight = %d, want exactly %d", got, MaxClusterSizeWeight)
	}

	// One more weight unit must tip it over.
	over := makeTestHash(len(weights) + 1)
	if _, err := cm.AddTransaction(over, 1000, 1, 1, []wire.Hash256{prev}); !errors.Is(err, ErrClusterTooLarge) {
		t.Errorf("Σweight 404001 should reject with ErrClusterTooLarge, got %v", err)
	}
}

// ============================================================================
// Sigop-dominated contribution
// ============================================================================

// TestClusterSigopDominatedContribution pins the per-transaction quantity:
// max(weight, sigops_cost * DEFAULT_BYTES_PER_SIGOP). The fixture uses the same
// numbers as the cluster-sigop-bound corpus entry — a 1573-WU transaction with
// 10100 sigops contributes 202_000 WU, so two fit exactly and a third does not.
func TestClusterSigopDominatedContribution(t *testing.T) {
	const (
		txWeight = int64(1573)
		sigops   = int64(10_100)
	)

	adj := consensus.GetSigOpsAdjustedWeight(txWeight, sigops, consensus.DefaultBytesPerSigOp)
	if adj != 202_000 {
		t.Fatalf("GetSigOpsAdjustedWeight(%d, %d, %d) = %d, want 202000 (= sigops*20, which dominates weight)",
			txWeight, sigops, consensus.DefaultBytesPerSigOp, adj)
	}
	if adj == txWeight {
		t.Fatal("fixture broken: the sigop term must dominate for this test to discriminate")
	}

	cm := NewClusterManager()

	first := makeTestHash(1)
	if _, err := cm.AddTransaction(first, 1000, 100, adj, nil); err != nil {
		t.Fatalf("first sigop-heavy tx should be accepted, got %v", err)
	}
	second := makeTestHash(2)
	if _, err := cm.AddTransaction(second, 1000, 100, adj, []wire.Hash256{first}); err != nil {
		t.Fatalf("second sigop-heavy tx brings the cluster to exactly %d and should be accepted, got %v",
			MaxClusterSizeWeight, err)
	}
	if got := cm.ClusterSizeWeight(second); got != MaxClusterSizeWeight {
		t.Errorf("cluster weight = %d, want %d", got, MaxClusterSizeWeight)
	}

	// The third would make 606000 — rejected on the SIZE axis while the count
	// axis (3 of 64) is nowhere near its cap.
	third := makeTestHash(3)
	if _, err := cm.AddTransaction(third, 1000, 100, adj, []wire.Hash256{second}); !errors.Is(err, ErrClusterTooLarge) {
		t.Fatalf("third sigop-heavy tx should reject with ErrClusterTooLarge, got %v", err)
	}
}

// ============================================================================
// Live admission path
// ============================================================================

// p2shAnyoneCanSpendScript is a standard P2SH output whose redeem script is a
// bare OP_TRUE, so the matching scriptSig (a single push of OP_TRUE) satisfies
// it without a signature. That lets these tests chain real transactions through
// the full admission path — standardness, script validation and all — which the
// older helpers, funding P2WPKH outputs that nothing could actually spend,
// could not do.
//
// redeem script = OP_TRUE (0x51); HASH160(0x51) = da1745e9…30cd5a4b.
func p2shAnyoneCanSpendScript() []byte {
	hash160 := []byte{
		0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a,
		0x56, 0x99, 0x71, 0xc7, 0x7e, 0xba, 0x30, 0xcd, 0x5a, 0x4b,
	}
	s := make([]byte, 0, 23)
	s = append(s, 0xa9, 0x14) // OP_HASH160, push 20
	s = append(s, hash160...)
	return append(s, 0x87) // OP_EQUAL
}

// spendableTx builds a transaction spending `in` and paying `numOutputs`
// equal-value anyone-can-spend P2SH outputs.
func spendableTx(in wire.OutPoint, valuePerOutput int64, numOutputs int) *wire.MsgTx {
	tx := &wire.MsgTx{Version: 2}
	tx.TxIn = append(tx.TxIn, &wire.TxIn{
		PreviousOutPoint: in,
		SignatureScript:  []byte{0x01, 0x51}, // push OP_TRUE (push-only ⇒ standard)
		Sequence:         0xffffffff,
	})
	for i := 0; i < numOutputs; i++ {
		tx.TxOut = append(tx.TxOut, &wire.TxOut{
			Value:    valuePerOutput,
			PkScript: p2shAnyoneCanSpendScript(),
		})
	}
	return tx
}

// spendableMempool returns a mempool plus one confirmed anyone-can-spend UTXO.
func spendableMempool(seed byte, amount int64) (*Mempool, wire.OutPoint) {
	utxoSet := newTestUTXOSet()
	var fundingHash wire.Hash256
	fundingHash[0] = seed
	outpoint := wire.OutPoint{Hash: fundingHash, Index: 0}
	utxoSet.AddUTXO(outpoint, &consensus.UTXOEntry{
		Amount:   amount,
		PkScript: p2shAnyoneCanSpendScript(),
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

// TestClusterGateIsLiveOnAdmissionPath proves the gate actually executes on the
// path a real submission takes, rather than only in the ClusterManager unit
// tests above. It builds a linear chain through Mempool.AddTransaction — the
// entry point sendrawtransaction reaches via AcceptToMemoryPool — and checks
// that 64 are accepted and the 65th is rejected.
//
// This distinction matters: blockbrew's testmempoolaccept
// (internal/rpc/rawtx_methods.go) re-implements validation inline and calls
// neither cluster gate, so probing through that RPC reports allowed:true for a
// transaction sendrawtransaction rejects. A gate test written against
// testmempoolaccept would pass whether or not the gate existed.
func TestClusterGateIsLiveOnAdmissionPath(t *testing.T) {
	mp, funding := spendableMempool(0xA1, 100_000_000)

	prevOut := funding
	value := int64(100_000_000)

	for i := 0; i < MaxClusterCount; i++ {
		value -= 10_000 // leave a fee at each hop
		tx := spendableTx(prevOut, value, 1)
		if err := mp.AddTransaction(tx); err != nil {
			t.Fatalf("chain tx %d of %d should be accepted, got %v", i+1, MaxClusterCount, err)
		}
		prevOut = wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	}

	if got := mp.Count(); got != MaxClusterCount {
		t.Fatalf("mempool holds %d txs, want %d", got, MaxClusterCount)
	}

	// The 65th link must be rejected by the cluster COUNT cap.
	value -= 10_000
	overflow := spendableTx(prevOut, value, 1)
	if err := mp.AddTransaction(overflow); !errors.Is(err, ErrClusterTooLarge) {
		t.Fatalf("chain tx %d should be rejected with ErrClusterTooLarge, got %v",
			MaxClusterCount+1, err)
	}

	// The rejected transaction must not linger in the pool.
	if mp.HasTransaction(overflow.TxHash()) {
		t.Error("rejected transaction is still in the mempool")
	}
	if got := mp.Count(); got != MaxClusterCount {
		t.Errorf("mempool size after rejection = %d, want %d", got, MaxClusterCount)
	}
}

// TestAdmissionPathRecordsWeightNotVbytes checks the live path stores each
// transaction's cluster contribution in WEIGHT units. A mis-wired port that
// passed the ceilinged vsize would record roughly a quarter of the correct
// value — a 4x error, which this catches directly.
func TestAdmissionPathRecordsWeightNotVbytes(t *testing.T) {
	mp, funding := spendableMempool(0xB2, 100_000_000)

	tx := spendableTx(funding, 99_990_000, 1)
	if err := mp.AddTransaction(tx); err != nil {
		t.Fatalf("tx should be accepted, got %v", err)
	}

	txid := tx.TxHash()
	weight := consensus.CalcTxWeight(tx)
	vsize := (weight + 3) / 4

	mp.mu.Lock()
	got := mp.clusters.ClusterSizeWeight(txid)
	mp.mu.Unlock()

	if got == vsize {
		t.Fatalf("cluster contribution = %d, which is the ceilinged VSIZE; "+
			"Core sums unrounded sigop-adjusted WEIGHT (%d)", got, weight)
	}
	if got != weight {
		t.Errorf("cluster contribution = %d, want %d (tx weight; sigops do not dominate here)",
			got, weight)
	}
}

// TestClusterSizeGateIsLiveOnAdmissionPath drives the SIZE axis end-to-end.
// It chains fat transactions until one is rejected, then asserts the rejection
// was the size cap and not the count cap, and that the boundary sits exactly
// where Core's strict ">" over unrounded weights puts it.
//
// The assertions are computed from the transactions actually built, so the test
// pins the rule rather than a hard-coded fixture.
func TestClusterSizeGateIsLiveOnAdmissionPath(t *testing.T) {
	mp, funding := spendableMempool(0xE5, 1_000_000_000)

	// ~90 outputs ⇒ roughly 12 kWU per transaction, so the 404_000 WU size cap
	// is reached in ~34 transactions — well before the 64-transaction count cap.
	// Output 0 carries the chain forward; the rest are padding that only exists
	// to inflate the weight.
	const outputsPerTx = 90
	const padValue = 5_000

	prevOut := funding
	value := int64(1_000_000_000)

	var acceptedWeight int64
	var accepted int

	for i := 0; i < MaxClusterCount; i++ {
		value -= 100_000 + padValue*(outputsPerTx-1) // fee + padding outputs
		tx := spendableTx(prevOut, padValue, outputsPerTx)
		tx.TxOut[0].Value = value
		weight := consensus.CalcTxWeight(tx)

		err := mp.AddTransaction(tx)
		if err == nil {
			accepted++
			acceptedWeight += weight
			prevOut = wire.OutPoint{Hash: tx.TxHash(), Index: 0}
			continue
		}

		if !errors.Is(err, ErrClusterTooLarge) {
			t.Fatalf("tx %d rejected for the wrong reason: %v", i+1, err)
		}

		// The count axis must not be what tripped: proves the SIZE cap is live.
		if accepted >= MaxClusterCount {
			t.Fatalf("rejection at %d transactions is the COUNT cap, not the size cap", accepted)
		}
		// Core's rule, exactly: what fit is within the cap, and the next one
		// would have exceeded it.
		if acceptedWeight > MaxClusterSizeWeight {
			t.Errorf("accepted cluster weight %d exceeds the cap %d",
				acceptedWeight, MaxClusterSizeWeight)
		}
		if acceptedWeight+weight <= MaxClusterSizeWeight {
			t.Errorf("tx %d was rejected but the cluster would have totalled %d ≤ %d — "+
				"the bound in force is tighter than Core's, the signature of "+
				"summing per-transaction ceilinged vbytes against %d",
				i+1, acceptedWeight+weight, MaxClusterSizeWeight,
				int64(DefaultClusterSizeLimitKvB)*vbytesPerKvB)
		}
		if got := mp.Count(); got != accepted {
			t.Errorf("mempool holds %d txs after rejection, want %d", got, accepted)
		}
		return
	}

	t.Fatalf("no transaction was ever rejected: %d accepted totalling %d WU "+
		"against a cap of %d — the size gate is not live on this path",
		accepted, acceptedWeight, MaxClusterSizeWeight)
}

// ============================================================================
// Atomicity: a rejected merging transaction must not fuse its parents
// ============================================================================

// TestRejectedMergeDoesNotFuseClusters is a regression test for the ordering
// defect this wave fixed. ClusterManager.AddTransaction used to run
// mergeClusters — which deletes the source clusters and moves their
// transactions into the survivor — BEFORE checking the limit, and returned the
// error without rolling back. A single rejected transaction therefore fused its
// parents' clusters permanently and over-counted every later check.
//
// Two independent clusters of 40 transactions cannot merge (40+40+1 > 64).
// After the rejection they must still be two separate clusters of 40.
func TestRejectedMergeDoesNotFuseClusters(t *testing.T) {
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

	tipA := build(1000)
	tipB := build(2000)

	clusterA, clusterB := cm.GetCluster(tipA), cm.GetCluster(tipB)
	if clusterA.ID == clusterB.ID {
		t.Fatal("fixture broken: the two chains must start in distinct clusters")
	}

	// A child of both tips would produce 40+40+1 = 81 > 64.
	joiner := makeTestHash(9000)
	_, err := cm.AddTransaction(joiner, 1000, 100, perTxWeight, []wire.Hash256{tipA, tipB})
	if !errors.Is(err, ErrClusterTooLarge) {
		t.Fatalf("merging child should reject with ErrClusterTooLarge, got %v", err)
	}

	// The clusters must be exactly as they were.
	afterA, afterB := cm.GetCluster(tipA), cm.GetCluster(tipB)
	if afterA == nil || afterB == nil {
		t.Fatal("a rejected merge destroyed one of the source clusters")
	}
	if afterA.ID == afterB.ID {
		t.Fatal("a rejected merge permanently fused the two parent clusters")
	}
	if afterA.Size() != perCluster || afterB.Size() != perCluster {
		t.Errorf("cluster sizes after rejected merge = %d/%d, want %d/%d",
			afterA.Size(), afterB.Size(), perCluster, perCluster)
	}
	if got := cm.ClusterSizeWeight(tipA); got != perCluster*perTxWeight {
		t.Errorf("cluster A weight after rejected merge = %d, want %d",
			got, perCluster*perTxWeight)
	}
	if cm.GetCluster(joiner) != nil {
		t.Error("rejected transaction must not be clustered")
	}

	// And the failed merge must not have inflated later checks: cluster A still
	// has room for more transactions.
	next := makeTestHash(9100)
	if _, err := cm.AddTransaction(next, 1000, 100, perTxWeight, []wire.Hash256{tipA}); err != nil {
		t.Errorf("cluster A should still accept a 41st transaction, got %v", err)
	}
}

// ============================================================================
// Limits this wave must NOT have changed
// ============================================================================

// TestUnrelatedLimitsUnchanged guards the neighbouring caps. MAX_PACKAGE_COUNT
// is a different limit from the cluster count, and TRUC's 2/2 is the only
// surviving ancestor/descendant enforcement.
func TestUnrelatedLimitsUnchanged(t *testing.T) {
	if MaxPackageCount != 25 {
		t.Errorf("MaxPackageCount = %d, want 25 — this is NOT the cluster count limit", MaxPackageCount)
	}
	if MaxPackageWeight != 404_000 {
		t.Errorf("MaxPackageWeight = %d, want 404000", MaxPackageWeight)
	}
	if TRUCAncestorLimit != 2 {
		t.Errorf("TRUCAncestorLimit = %d, want 2 (only surviving ancestor enforcement)", TRUCAncestorLimit)
	}
	if TRUCDescendantLimit != 2 {
		t.Errorf("TRUCDescendantLimit = %d, want 2 (only surviving descendant enforcement)", TRUCDescendantLimit)
	}
}

// TestAncestorDescendantLimitsNoLongerEnforced pins the removal. A linear chain
// of 26 transactions exceeds the retired DEFAULT_ANCESTOR_LIMIT of 25 but sits
// well inside both cluster caps, so Core v31 accepts every one of them.
func TestAncestorDescendantLimitsNoLongerEnforced(t *testing.T) {
	mp, funding := spendableMempool(0xC3, 100_000_000)

	prevOut := funding
	value := int64(100_000_000)

	const chainLen = DefaultAncestorLimit + 1 // 26 — one past the retired cap
	for i := 0; i < chainLen; i++ {
		value -= 10_000
		tx := spendableTx(prevOut, value, 1)
		if err := mp.AddTransaction(tx); err != nil {
			t.Fatalf("chain tx %d of %d should be accepted — the ancestor limit is "+
				"retired in Core v31 and only cluster limits apply; got %v", i+1, chainLen, err)
		}
		prevOut = wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	}

	if got := mp.Count(); got != chainLen {
		t.Errorf("mempool holds %d txs, want %d", got, chainLen)
	}
}

// TestDescendantFanOutNoLongerLimited is the descendant-axis counterpart: one
// parent with 26 children exceeds the retired DEFAULT_DESCENDANT_LIMIT of 25
// and is now accepted, bounded only by the cluster caps.
func TestDescendantFanOutNoLongerLimited(t *testing.T) {
	mp, funding := spendableMempool(0xD4, 100_000_000)

	const children = DefaultDescendantLimit + 1 // 26 — one past the retired cap

	// Root paying `children` spendable outputs.
	root := spendableTx(funding, 3_000_000, children)
	if err := mp.AddTransaction(root); err != nil {
		t.Fatalf("root should be accepted, got %v", err)
	}
	rootHash := root.TxHash()

	for i := 0; i < children; i++ {
		child := spendableTx(wire.OutPoint{Hash: rootHash, Index: uint32(i)}, 2_990_000, 1)
		if err := mp.AddTransaction(child); err != nil {
			t.Fatalf("child %d of %d should be accepted — the descendant limit is "+
				"retired in Core v31; got %v", i+1, children, err)
		}
	}

	if got := mp.Count(); got != children+1 {
		t.Errorf("mempool holds %d txs, want %d", got, children+1)
	}
}
