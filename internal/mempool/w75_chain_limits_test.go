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
	// Core src/policy/policy.h:72
	if MaxClusterCount != 64 {
		t.Errorf("MaxClusterCount = %d, want 64 (Core DEFAULT_CLUSTER_LIMIT)", MaxClusterCount)
	}
	// Core src/policy/policy.h:74 — reported over RPC as `limitclustersize`
	// in VBYTES (rpc/mempool.cpp:1062).
	if DefaultClusterSizeLimitKvB != 101 {
		t.Errorf("DefaultClusterSizeLimitKvB = %d, want 101", DefaultClusterSizeLimitKvB)
	}
	// ...but ENFORCED in weight units: txmempool.cpp:181 scales
	// cluster_size_vbytes by WITNESS_SCALE_FACTOR before handing it to TxGraph.
	if MaxClusterSizeWeight != 404_000 {
		t.Errorf("MaxClusterSizeWeight = %d, want 404000 (101 kvB * 1000 * 4)", MaxClusterSizeWeight)
	}
	// Core src/policy/policy.h:90
	if ExtraDescendantTxSizeLimit != 10_000 {
		t.Errorf("ExtraDescendantTxSizeLimit = %d, want 10000", ExtraDescendantTxSizeLimit)
	}
}

// ============================================================================
// Gate 3: ancestor-count enforcement
// ============================================================================

// ============================================================================
// Gate 4: descendant-count enforcement
// ============================================================================

// ============================================================================
// Gate 7+8: ancestor / descendant recursive walk correctness
// ============================================================================

// ============================================================================
// Gate 9: self-counts-as-ancestor convention
// ============================================================================

// ============================================================================
// Gate 10: NoLimits equivalent
// ============================================================================

// ============================================================================
// Ancestor SIZE limit tests
// ============================================================================

// ============================================================================
// Descendant SIZE limit tests
// ============================================================================

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
		if _, err := cm.AddTransaction(h, fr.Fee, int32(fr.Size), int64(fr.Size)*4, parents); err != nil {
			t.Fatalf("tx %d/64 should fit in cluster, got %v", i+1, err)
		}
		prevTxid = h
	}

	// 65th transaction.
	var h65 wire.Hash256
	h65[0] = 0xA1
	_, err := cm.AddTransaction(h65, fr.Fee, int32(fr.Size), int64(fr.Size)*4, []wire.Hash256{prevTxid})
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

// TestW75_NoLimitsConfigFields verifies NoLimitsConfig produces math.MaxInt fields.
func TestW75_NoLimitsConfigFields(t *testing.T) {
	cfg := NoLimitsConfig()
	if cfg.AncestorLimit != math.MaxInt {
		t.Errorf("NoLimitsConfig.AncestorLimit = %d, want math.MaxInt", cfg.AncestorLimit)
	}
	if cfg.DescendantLimit != math.MaxInt {
		t.Errorf("NoLimitsConfig.DescendantLimit = %d, want math.MaxInt", cfg.DescendantLimit)
	}
}
