package mempool

// W75: comprehensive ancestor/descendant/cluster limit tests.
//
// Gates under test (matching the 10-gate audit checklist):
//  1. DefaultAncestorLimit=25 constant existence + use
//  2. DefaultDescendantLimit=25 constant existence + use
//  3. Ancestor-count enforcement (self+ancestors ≤ 25 → reject ErrTooManyAncestors)
//  4. Descendant-count enforcement (for each parent: descendants+1 ≤ 25)
//  5. Cluster count limit (MaxClusterSize=64, cluster.go); size limit constant present
//  6. CPFP carve-out constant (ExtraDescendantTxSizeLimit=10000) documented
//  7. CalculateMemPoolAncestors recursive walk (addAncestors correctness)
//  8. CalculateMemPoolDescendants recursive walk (collectDescendantsLocked correctness)
//  9. Self-counts-as-ancestor convention (len(ancestorSet)+1)
// 10. NoLimits equivalent (NoLimitsConfig bypasses all chain-length checks)
//
// References:
//   src/policy/policy.h:72-90     — DEFAULT_CLUSTER_LIMIT, DEFAULT_ANCESTOR_LIMIT,
//                                   DEFAULT_DESCENDANT_LIMIT, EXTRA_DESCENDANT_TX_SIZE_LIMIT
//   src/kernel/mempool_limits.h   — MemPoolLimits struct and NoLimits()
//   src/txmempool.cpp:130-163     — CalculateMemPoolAncestors
//   src/txmempool.cpp:917-940     — CalculateAncestorData / CalculateDescendantData

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// Helpers
// ============================================================================

// buildLinearChain splices n entries into mp.pool in a linear parent→child chain.
// Returns the hashes in depth order (hashes[0] is the root with no parents).
// Must be called without mp.mu held.
func buildLinearChain(mp *Mempool, n int, seedByte byte) []wire.Hash256 {
	hashes := make([]wire.Hash256, n)
	mp.mu.Lock()
	defer mp.mu.Unlock()
	for i := 0; i < n; i++ {
		var h wire.Hash256
		h[0] = seedByte
		h[1] = byte(i)
		h[2] = byte(i >> 8)
		entry := &TxEntry{
			Tx:             &wire.MsgTx{},
			TxHash:         h,
			Fee:            1000,
			Size:           200,
			FeeRate:        5.0,
			Time:           time.Now(),
			Height:         0,
			AncestorFee:    int64(1000 * (i + 1)),
			AncestorSize:   int64(200 * (i + 1)),
			DescendantFee:  1000,
			DescendantSize: 200,
		}
		if i > 0 {
			entry.Depends = []wire.Hash256{hashes[i-1]}
			parent := mp.pool[hashes[i-1]]
			parent.SpentBy = append(parent.SpentBy, h)
		}
		mp.pool[h] = entry
		hashes[i] = h
	}
	return hashes
}

// buildFanOut splices one root plus n children into mp.pool.
// All children spend output index i of the root (each uses a distinct index).
// Returns rootHash.
func buildFanOut(mp *Mempool, n int, seedByte byte) wire.Hash256 {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	var rootHash wire.Hash256
	rootHash[0] = seedByte
	rootHash[1] = 0xFF
	root := &TxEntry{
		Tx:             &wire.MsgTx{},
		TxHash:         rootHash,
		Fee:            1000,
		Size:           200,
		FeeRate:        5.0,
		Time:           time.Now(),
		AncestorFee:    1000,
		AncestorSize:   200,
		DescendantFee:  1000,
		DescendantSize: 200,
	}
	mp.pool[rootHash] = root

	for i := 0; i < n; i++ {
		var h wire.Hash256
		h[0] = seedByte
		h[1] = byte(i)
		entry := &TxEntry{
			Tx:             &wire.MsgTx{},
			TxHash:         h,
			Fee:            500,
			Size:           150,
			FeeRate:        3.33,
			Time:           time.Now(),
			Depends:        []wire.Hash256{rootHash},
			AncestorFee:    1500,
			AncestorSize:   350,
			DescendantFee:  500,
			DescendantSize: 150,
		}
		mp.pool[h] = entry
		root.SpentBy = append(root.SpentBy, h)
	}
	return rootHash
}

// candidateTx returns a MsgTx that spends prevHash:prevIndex.
func candidateTx(prevHash wire.Hash256, prevIndex uint32) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: prevIndex},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 546, PkScript: []byte{0x00, 0x14}}},
	}
}

// newNoLimitsMempool returns a Mempool configured with NoLimitsConfig.
func newNoLimitsMempool() *Mempool {
	cfg := NoLimitsConfig()
	cfg.ChainParams = consensus.RegtestParams()
	return New(cfg, newTestUTXOSet())
}

// ============================================================================
// Gate 1+2: constant values
// ============================================================================

// TestW75_Constants verifies the Core-parity values of all limit constants.
func TestW75_Constants(t *testing.T) {
	// Core src/policy/policy.h:76
	if DefaultAncestorLimit != 25 {
		t.Errorf("DefaultAncestorLimit = %d, want 25", DefaultAncestorLimit)
	}
	// Core src/policy/policy.h:78
	if DefaultDescendantLimit != 25 {
		t.Errorf("DefaultDescendantLimit = %d, want 25", DefaultDescendantLimit)
	}
	// Core historical DEFAULT_ANCESTOR_SIZE_LIMIT_KVB
	if DefaultAncestorSizeLimitKvB != 101 {
		t.Errorf("DefaultAncestorSizeLimitKvB = %d, want 101", DefaultAncestorSizeLimitKvB)
	}
	// Core historical DEFAULT_DESCENDANT_SIZE_LIMIT_KVB
	if DefaultDescendantSizeLimitKvB != 101 {
		t.Errorf("DefaultDescendantSizeLimitKvB = %d, want 101", DefaultDescendantSizeLimitKvB)
	}
	// Core src/policy/policy.h:72
	if MaxClusterSize != 64 {
		t.Errorf("MaxClusterSize = %d, want 64 (Core DEFAULT_CLUSTER_LIMIT)", MaxClusterSize)
	}
	// Core src/policy/policy.h:74
	if DefaultClusterSizeLimitKvB != 101 {
		t.Errorf("DefaultClusterSizeLimitKvB = %d, want 101", DefaultClusterSizeLimitKvB)
	}
	// Core src/policy/policy.h:90
	if ExtraDescendantTxSizeLimit != 10_000 {
		t.Errorf("ExtraDescendantTxSizeLimit = %d, want 10000", ExtraDescendantTxSizeLimit)
	}
}

// ============================================================================
// Gate 3: ancestor-count enforcement
// ============================================================================

// TestW75_AncestorCountAccepts25 confirms a 24-ancestor chain allows a 25th
// (self + 24 ancestors = 25, exactly at the limit).
func TestW75_AncestorCountAccepts25(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())
	hashes := buildLinearChain(mp, 24, 0x30) // 24 in-mempool ancestors

	candidate := candidateTx(hashes[23], 0)
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if err := mp.checkChainLimitsLocked(candidate); err != nil {
		t.Fatalf("24-ancestor candidate (total=25) should pass, got %v", err)
	}
}

// TestW75_AncestorCountRejects26 confirms a 25-ancestor chain rejects the 26th
// (self + 25 ancestors = 26 > DefaultAncestorLimit=25).
func TestW75_AncestorCountRejects26(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())
	hashes := buildLinearChain(mp, 25, 0x31) // 25 in-mempool ancestors

	candidate := candidateTx(hashes[24], 0)
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if err := mp.checkChainLimitsLocked(candidate); !errors.Is(err, ErrTooManyAncestors) {
		t.Fatalf("25-ancestor candidate (total=26) should fail with ErrTooManyAncestors, got %v", err)
	}
}

// TestW75_AncestorCountExactBoundary verifies the boundary is ≤25 (not <25).
// A chain of exactly 25 (self + 24 ancestors) is accepted; 26 is rejected.
func TestW75_AncestorCountExactBoundary(t *testing.T) {
	t.Run("accept at 25", func(t *testing.T) {
		mp := newTestMempool(newTestUTXOSet())
		hashes := buildLinearChain(mp, 24, 0x32)
		cand := candidateTx(hashes[23], 0)
		mp.mu.Lock()
		defer mp.mu.Unlock()
		if err := mp.checkChainLimitsLocked(cand); err != nil {
			t.Fatalf("accept at 25 failed: %v", err)
		}
	})
	t.Run("reject at 26", func(t *testing.T) {
		mp := newTestMempool(newTestUTXOSet())
		hashes := buildLinearChain(mp, 25, 0x33)
		cand := candidateTx(hashes[24], 0)
		mp.mu.Lock()
		defer mp.mu.Unlock()
		if err := mp.checkChainLimitsLocked(cand); !errors.Is(err, ErrTooManyAncestors) {
			t.Fatalf("reject at 26 failed: %v", err)
		}
	})
}

// ============================================================================
// Gate 4: descendant-count enforcement
// ============================================================================

// TestW75_DescendantCountAccepts25 confirms a root with 23 children allows a
// 24th child (root + 24 children = 25, exactly at the limit).
func TestW75_DescendantCountAccepts25(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())
	rootHash := buildFanOut(mp, 23, 0x40) // root + 23 children = 24

	// 24th child spends root:24
	candidate := candidateTx(rootHash, 24)
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if err := mp.checkChainLimitsLocked(candidate); err != nil {
		t.Fatalf("root+23children+candidate=25 should pass, got %v", err)
	}
}

// TestW75_DescendantCountRejects26 confirms a root with 24 children rejects a
// 25th child (root + 25 children = 26 > DefaultDescendantLimit=25).
func TestW75_DescendantCountRejects26(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())
	rootHash := buildFanOut(mp, 24, 0x41) // root + 24 children = 25

	// Adding one more child: root would have 26 descendants-incl-self > 25.
	candidate := candidateTx(rootHash, 25)
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if err := mp.checkChainLimitsLocked(candidate); !errors.Is(err, ErrTooManyDescendants) {
		t.Fatalf("root+24children+candidate=26 should fail with ErrTooManyDescendants, got %v", err)
	}
}

// ============================================================================
// Gate 7+8: ancestor / descendant recursive walk correctness
// ============================================================================

// TestW75_AncestorWalkDiamond verifies the ancestor walk deduplicates correctly
// in a diamond: A→B, A→C, B→D, C→D. D's ancestors = {A,B,C} (3 unique).
// D+A+B+C = 4 ≤ 25, so it should pass.
func TestW75_AncestorWalkDiamond(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())
	mp.mu.Lock()

	var hA, hB, hC, hD wire.Hash256
	hA[0] = 0x50
	hB[0] = 0x51
	hC[0] = 0x52
	hD[0] = 0x53

	newEntry := func(h wire.Hash256, depends []wire.Hash256) *TxEntry {
		return &TxEntry{
			Tx:             &wire.MsgTx{},
			TxHash:         h,
			Fee:            1000,
			Size:           200,
			FeeRate:        5.0,
			Time:           time.Now(),
			Depends:        depends,
			AncestorFee:    1000,
			AncestorSize:   200,
			DescendantFee:  1000,
			DescendantSize: 200,
		}
	}

	entryA := newEntry(hA, nil)
	entryB := newEntry(hB, []wire.Hash256{hA})
	entryC := newEntry(hC, []wire.Hash256{hA})
	entryD := newEntry(hD, []wire.Hash256{hB, hC})

	mp.pool[hA] = entryA
	mp.pool[hB] = entryB
	mp.pool[hC] = entryC
	mp.pool[hD] = entryD

	entryA.SpentBy = []wire.Hash256{hB, hC}
	entryB.SpentBy = []wire.Hash256{hD}
	entryC.SpentBy = []wire.Hash256{hD}

	// Candidate spends D: ancestors = {A,B,C,D} = 4; self = 1; total = 5.
	candidate := candidateTx(hD, 0)
	if err := mp.checkChainLimitsLocked(candidate); err != nil {
		t.Fatalf("diamond 4-ancestor chain should pass, got %v", err)
	}
	mp.mu.Unlock()
}

// TestW75_AncestorWalkDeepDiamond verifies the walk correctly counts a shared
// 22-tx root so that the deduplicated ancestor set stays within the limit.
// Layout: 22-depth linear root-chain, then B and C both spend the tip; D spends B and C.
// D's ancestors: 22 (chain) + B + C = 24 unique + self = 25. Should pass.
func TestW75_AncestorWalkDeepDiamond(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())

	// Build 22-deep linear chain.
	chain := buildLinearChain(mp, 22, 0x54)
	tip := chain[21] // deepest entry; 22 ancestors in pool after candidate self.

	mp.mu.Lock()
	// B spends tip
	var hB wire.Hash256
	hB[0] = 0x55
	entryB := &TxEntry{
		Tx: &wire.MsgTx{}, TxHash: hB, Fee: 1000, Size: 200, FeeRate: 5.0,
		Time: time.Now(), Depends: []wire.Hash256{tip},
		AncestorFee: 1000, AncestorSize: 200, DescendantFee: 1000, DescendantSize: 200,
	}
	mp.pool[hB] = entryB
	mp.pool[tip].SpentBy = append(mp.pool[tip].SpentBy, hB)

	// C spends tip (different output index — same parent set as B)
	var hC wire.Hash256
	hC[0] = 0x56
	entryC := &TxEntry{
		Tx: &wire.MsgTx{}, TxHash: hC, Fee: 1000, Size: 200, FeeRate: 5.0,
		Time: time.Now(), Depends: []wire.Hash256{tip},
		AncestorFee: 1000, AncestorSize: 200, DescendantFee: 1000, DescendantSize: 200,
	}
	mp.pool[hC] = entryC
	mp.pool[tip].SpentBy = append(mp.pool[tip].SpentBy, hC)

	// Candidate spends B and C: ancestors = chain(22) + B + C = 24, self = 1, total = 25.
	candidate := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: hB, Index: 0}, Sequence: 0xFFFFFFFF},
			{PreviousOutPoint: wire.OutPoint{Hash: hC, Index: 0}, Sequence: 0xFFFFFFFF},
		},
		TxOut: []*wire.TxOut{{Value: 546, PkScript: []byte{0x00, 0x14}}},
	}
	if err := mp.checkChainLimitsLocked(candidate); err != nil {
		t.Fatalf("diamond with 24 dedup ancestors should pass (total=25), got %v", err)
	}
	mp.mu.Unlock()
}

// ============================================================================
// Gate 9: self-counts-as-ancestor convention
// ============================================================================

// TestW75_SelfCountsAsAncestor verifies that the lone tx in an empty mempool
// counts as 1 ancestor (self) and is well within the limit.
func TestW75_SelfCountsAsAncestor(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())

	// Candidate with no mempool parents: ancestorSet is empty; self+0 = 1.
	var prevHash wire.Hash256
	prevHash[0] = 0x60
	candidate := candidateTx(prevHash, 0) // prevHash not in pool

	mp.mu.Lock()
	defer mp.mu.Unlock()
	if err := mp.checkChainLimitsLocked(candidate); err != nil {
		t.Fatalf("no-ancestor candidate should pass (count=1), got %v", err)
	}
}

// ============================================================================
// Gate 10: NoLimits equivalent
// ============================================================================

// TestW75_NoLimitsConfigBypasses verifies NoLimitsConfig allows a chain far
// beyond the default limits to enter checkChainLimitsLocked without error.
func TestW75_NoLimitsConfigBypasses(t *testing.T) {
	mp := newNoLimitsMempool()

	// Build a 30-deep chain (5 beyond the normal 25 limit).
	hashes := buildLinearChain(mp, 30, 0x70)

	candidate := candidateTx(hashes[29], 0) // would be ancestor#31
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if err := mp.checkChainLimitsLocked(candidate); err != nil {
		t.Fatalf("NoLimitsConfig should bypass ancestor limit, got %v", err)
	}
}

// TestW75_NoLimitsConfigDescendants verifies NoLimitsConfig allows a fan-out
// far beyond the descendant limit.
func TestW75_NoLimitsConfigDescendants(t *testing.T) {
	mp := newNoLimitsMempool()

	// Root with 30 children (5 beyond the normal 25 limit).
	rootHash := buildFanOut(mp, 30, 0x71)

	candidate := candidateTx(rootHash, 31)
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if err := mp.checkChainLimitsLocked(candidate); err != nil {
		t.Fatalf("NoLimitsConfig should bypass descendant limit, got %v", err)
	}
}

// ============================================================================
// Ancestor SIZE limit tests
// ============================================================================

// TestW75_AncestorSizeLimitRejects verifies that a candidate is rejected when
// the sum of ancestor vsizes + candidate vsize exceeds 101 kvB (101_000 vB).
// We build a chain whose total size is just over the threshold.
func TestW75_AncestorSizeLimitRejects(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())

	// Splice 5 ancestors each 20_000 vB = 100_000 vB total.
	// Candidate vsize = 1_001 → total = 101_001 > 101_000.
	mp.mu.Lock()
	var prev wire.Hash256
	prev[0] = 0x80
	for i := 0; i < 5; i++ {
		var h wire.Hash256
		h[0] = 0x80
		h[1] = byte(i + 1)
		entry := &TxEntry{
			Tx: &wire.MsgTx{}, TxHash: h,
			Fee: 1000, Size: 20_000, FeeRate: 0.05,
			Time:           time.Now(),
			AncestorFee:    1000,
			AncestorSize:   20_000,
			DescendantFee:  1000,
			DescendantSize: 20_000,
		}
		if i > 0 {
			entry.Depends = []wire.Hash256{prev}
			mp.pool[prev].SpentBy = append(mp.pool[prev].SpentBy, h)
		}
		mp.pool[h] = entry
		prev = h
	}
	mp.mu.Unlock()

	candidate := candidateTx(prev, 0)
	// checkChainLimitsWithSizeLocked needs candidateVSize; use checkChainLimitsLocked
	// (passes 0) — the ancestor size check still triggers because 100_000 vB of
	// ancestors alone is within the 101_000 limit; only with candidateVSize > 1000 does it breach.
	// Use checkChainLimitsWithSizeLocked directly.
	mp.mu.Lock()
	defer mp.mu.Unlock()
	err := mp.checkChainLimitsWithSizeLocked(candidate, 1_001)
	if !errors.Is(err, ErrAncestorSizeTooLarge) {
		t.Fatalf("expected ErrAncestorSizeTooLarge (ancestor_total=101_001), got %v", err)
	}
}

// TestW75_AncestorSizeLimitAccepts verifies that a candidate is accepted when
// the sum of ancestor vsizes + candidate vsize equals exactly 101_000 vB.
func TestW75_AncestorSizeLimitAccepts(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())

	// 5 ancestors × 20_000 vB = 100_000 vB; candidate = 1_000 vB → total = 101_000.
	mp.mu.Lock()
	var prev wire.Hash256
	prev[0] = 0x81
	for i := 0; i < 5; i++ {
		var h wire.Hash256
		h[0] = 0x81
		h[1] = byte(i + 1)
		entry := &TxEntry{
			Tx: &wire.MsgTx{}, TxHash: h,
			Fee: 1000, Size: 20_000, FeeRate: 0.05,
			Time:           time.Now(),
			AncestorFee:    1000,
			AncestorSize:   20_000,
			DescendantFee:  1000,
			DescendantSize: 20_000,
		}
		if i > 0 {
			entry.Depends = []wire.Hash256{prev}
			mp.pool[prev].SpentBy = append(mp.pool[prev].SpentBy, h)
		}
		mp.pool[h] = entry
		prev = h
	}
	mp.mu.Unlock()

	candidate := candidateTx(prev, 0)
	mp.mu.Lock()
	defer mp.mu.Unlock()
	err := mp.checkChainLimitsWithSizeLocked(candidate, 1_000)
	if errors.Is(err, ErrAncestorSizeTooLarge) {
		t.Fatalf("ancestor+candidate=101_000 vB should pass, got %v", err)
	}
}

// ============================================================================
// Descendant SIZE limit tests
// ============================================================================

// TestW75_DescendantSizeLimitRejects verifies a candidate is rejected when it
// would push an ancestor's descendant set size over 101 kvB.
func TestW75_DescendantSizeLimitRejects(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())

	// Root (20_000 vB) + 4 children each 20_000 vB = root+children = 100_000 vB.
	// Adding candidate (1_001 vB) pushes root's descendant total to 101_001 > 101_000.
	mp.mu.Lock()
	var rootH wire.Hash256
	rootH[0] = 0x90
	root := &TxEntry{
		Tx: &wire.MsgTx{}, TxHash: rootH,
		Fee: 1000, Size: 20_000, FeeRate: 0.05,
		Time:           time.Now(),
		AncestorFee:    1000,
		AncestorSize:   20_000,
		DescendantFee:  1000,
		DescendantSize: 20_000,
	}
	mp.pool[rootH] = root

	for i := 0; i < 4; i++ {
		var h wire.Hash256
		h[0] = 0x90
		h[1] = byte(i + 1)
		child := &TxEntry{
			Tx: &wire.MsgTx{}, TxHash: h,
			Fee: 500, Size: 20_000, FeeRate: 0.025,
			Time:           time.Now(),
			Depends:        []wire.Hash256{rootH},
			AncestorFee:    1500,
			AncestorSize:   40_000,
			DescendantFee:  500,
			DescendantSize: 20_000,
		}
		mp.pool[h] = child
		root.SpentBy = append(root.SpentBy, h)
	}
	mp.mu.Unlock()

	candidate := candidateTx(rootH, 5)
	mp.mu.Lock()
	defer mp.mu.Unlock()
	err := mp.checkChainLimitsWithSizeLocked(candidate, 1_001)
	if !errors.Is(err, ErrDescendantSizeTooLarge) {
		t.Fatalf("expected ErrDescendantSizeTooLarge (desc_total=101_001), got %v", err)
	}
}

// TestW75_DescendantSizeLimitAccepts verifies a candidate is accepted at exactly
// 101_000 vB total descendant size.
func TestW75_DescendantSizeLimitAccepts(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())

	// Root (20_000 vB) + 4 children × 20_000 vB = 100_000 vB; candidate = 1_000 vB → 101_000.
	mp.mu.Lock()
	var rootH wire.Hash256
	rootH[0] = 0x91
	root := &TxEntry{
		Tx: &wire.MsgTx{}, TxHash: rootH,
		Fee: 1000, Size: 20_000, FeeRate: 0.05,
		Time:           time.Now(),
		AncestorFee:    1000,
		AncestorSize:   20_000,
		DescendantFee:  1000,
		DescendantSize: 20_000,
	}
	mp.pool[rootH] = root

	for i := 0; i < 4; i++ {
		var h wire.Hash256
		h[0] = 0x91
		h[1] = byte(i + 1)
		child := &TxEntry{
			Tx: &wire.MsgTx{}, TxHash: h,
			Fee: 500, Size: 20_000, FeeRate: 0.025,
			Time:           time.Now(),
			Depends:        []wire.Hash256{rootH},
			AncestorFee:    1500,
			AncestorSize:   40_000,
			DescendantFee:  500,
			DescendantSize: 20_000,
		}
		mp.pool[h] = child
		root.SpentBy = append(root.SpentBy, h)
	}
	mp.mu.Unlock()

	candidate := candidateTx(rootH, 5)
	mp.mu.Lock()
	defer mp.mu.Unlock()
	err := mp.checkChainLimitsWithSizeLocked(candidate, 1_000)
	if errors.Is(err, ErrDescendantSizeTooLarge) {
		t.Fatalf("desc_total=101_000 should pass, got %v", err)
	}
}

// ============================================================================
// Gate 5: cluster count limit (MaxClusterSize=64)
// ============================================================================

// TestW75_ClusterCountLimit verifies MaxClusterSize equals Core's DEFAULT_CLUSTER_LIMIT=64.
// We also verify that the ErrClusterTooLarge error is surfaced via AddTransaction
// through the ClusterManager path when a cluster would exceed 64 txs.
func TestW75_ClusterCountLimit(t *testing.T) {
	// Verify the constant directly (the authoritative test).
	if MaxClusterSize != 64 {
		t.Fatalf("MaxClusterSize = %d; want 64 (Core DEFAULT_CLUSTER_LIMIT)", MaxClusterSize)
	}

	// Verify ErrClusterTooLarge fires at 65 via ClusterManager.
	cm := NewClusterManager()
	fr := FeeFrac{Fee: 1000, Size: 200}

	var prevTxid wire.Hash256
	for i := 0; i < 64; i++ {
		var h wire.Hash256
		h[0] = 0xA0
		h[1] = byte(i)
		var parents []wire.Hash256
		if i > 0 {
			parents = []wire.Hash256{prevTxid}
		}
		if _, err := cm.AddTransaction(h, fr.Fee, int32(fr.Size), parents); err != nil {
			t.Fatalf("tx %d/64 should fit in cluster, got %v", i+1, err)
		}
		prevTxid = h
	}

	// 65th transaction.
	var h65 wire.Hash256
	h65[0] = 0xA1
	_, err := cm.AddTransaction(h65, fr.Fee, int32(fr.Size), []wire.Hash256{prevTxid})
	if !errors.Is(err, ErrClusterTooLarge) {
		t.Fatalf("65th tx should produce ErrClusterTooLarge, got %v", err)
	}
}

// ============================================================================
// Gate 6: CPFP carve-out constant documented
// ============================================================================

// TestW75_CPFPCarveOutConstant verifies the ExtraDescendantTxSizeLimit constant
// is present and equals Core's EXTRA_DESCENDANT_TX_SIZE_LIMIT=10000.
// The carve-out itself is deprecated in cluster-mempool mode (Core 27+) but the
// constant must remain for -limitancestorcount CLI compatibility documentation.
func TestW75_CPFPCarveOutConstant(t *testing.T) {
	if ExtraDescendantTxSizeLimit != 10_000 {
		t.Errorf("ExtraDescendantTxSizeLimit = %d, want 10000 (Core EXTRA_DESCENDANT_TX_SIZE_LIMIT)",
			ExtraDescendantTxSizeLimit)
	}
}

// ============================================================================
// Config-based limit overrides
// ============================================================================

// TestW75_ConfigAncestorLimitOverride verifies that a custom AncestorLimit in
// Config replaces DefaultAncestorLimit.
func TestW75_ConfigAncestorLimitOverride(t *testing.T) {
	// Create a mempool limited to 5 ancestors.
	cfg := Config{
		MaxSize:         10_000_000,
		MinRelayFeeRate: 1000,
		MaxOrphanTxs:    100,
		ChainParams:     consensus.RegtestParams(),
		AncestorLimit:   5,
	}
	mp := New(cfg, newTestUTXOSet())

	// Build 4 ancestors: candidate would be ancestor #5 (within limit).
	hashes := buildLinearChain(mp, 4, 0xB0)
	candidate := candidateTx(hashes[3], 0)
	mp.mu.Lock()
	if err := mp.checkChainLimitsLocked(candidate); err != nil {
		mp.mu.Unlock()
		t.Fatalf("4-ancestor chain with limit=5 should pass, got %v", err)
	}
	mp.mu.Unlock()

	// Build 5 ancestors: candidate would be ancestor #6 (exceeds custom limit of 5).
	mp2 := New(cfg, newTestUTXOSet())
	hashes2 := buildLinearChain(mp2, 5, 0xB1)
	candidate2 := candidateTx(hashes2[4], 0)
	mp2.mu.Lock()
	defer mp2.mu.Unlock()
	if err := mp2.checkChainLimitsLocked(candidate2); !errors.Is(err, ErrTooManyAncestors) {
		t.Fatalf("5-ancestor chain with limit=5 should fail, got %v", err)
	}
}

// TestW75_ConfigDescendantLimitOverride verifies custom DescendantLimit works.
func TestW75_ConfigDescendantLimitOverride(t *testing.T) {
	cfg := Config{
		MaxSize:         10_000_000,
		MinRelayFeeRate: 1000,
		MaxOrphanTxs:    100,
		ChainParams:     consensus.RegtestParams(),
		DescendantLimit: 5,
	}

	// Root + 3 children (total=4, within limit=5).
	mp := New(cfg, newTestUTXOSet())
	rootHash := buildFanOut(mp, 3, 0xC0)
	candidate := candidateTx(rootHash, 4)
	mp.mu.Lock()
	if err := mp.checkChainLimitsLocked(candidate); err != nil {
		mp.mu.Unlock()
		t.Fatalf("root+3children+candidate=5 with limit=5 should pass, got %v", err)
	}
	mp.mu.Unlock()

	// Root + 4 children (total=5); adding candidate → root would have 6 > limit=5.
	mp2 := New(cfg, newTestUTXOSet())
	rootHash2 := buildFanOut(mp2, 4, 0xC1)
	candidate2 := candidateTx(rootHash2, 5)
	mp2.mu.Lock()
	defer mp2.mu.Unlock()
	if err := mp2.checkChainLimitsLocked(candidate2); !errors.Is(err, ErrTooManyDescendants) {
		t.Fatalf("root+4children+candidate=6 with limit=5 should fail, got %v", err)
	}
}

// TestW75_NoLimitsConfigFields verifies NoLimitsConfig produces math.MaxInt fields.
func TestW75_NoLimitsConfigFields(t *testing.T) {
	cfg := NoLimitsConfig()
	if cfg.AncestorLimit != math.MaxInt {
		t.Errorf("NoLimitsConfig.AncestorLimit = %d, want math.MaxInt", cfg.AncestorLimit)
	}
	if cfg.DescendantLimit != math.MaxInt {
		t.Errorf("NoLimitsConfig.DescendantLimit = %d, want math.MaxInt", cfg.DescendantLimit)
	}
	if cfg.AncestorSizeLimitKvB != math.MaxInt {
		t.Errorf("NoLimitsConfig.AncestorSizeLimitKvB = %d, want math.MaxInt", cfg.AncestorSizeLimitKvB)
	}
	if cfg.DescendantSizeLimitKvB != math.MaxInt {
		t.Errorf("NoLimitsConfig.DescendantSizeLimitKvB = %d, want math.MaxInt", cfg.DescendantSizeLimitKvB)
	}
}
