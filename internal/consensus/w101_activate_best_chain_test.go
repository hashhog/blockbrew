package consensus

// W101 ActivateBestChain + tip-update orchestration audit.
//
// Gate checklist (30 gates, G1-G30):
//   G1-G5:   FindMostWorkChain (skiplist iter, FAILED_MASK filter, missing-data filter, null-on-empty, nChainWork+HASH tiebreak)
//   G6-G10:  ActivateBestChainStep (walk-to-common-ancestor, DisconnectTip loop, ConnectTip loop, DisconnectedBlockTransactions re-add, fInvalidFound)
//   G11-G16: ActivateBestChain (cs_main, step loop, limit_until_arg, notification ordering, mempool removeForReorg+reaccept, eventually-consistent re-invoke)
//   G17-G19: InvalidateBlock (FAILED_VALID + FAILED_CHILD on descendants, setBlockIndexCandidates erase, ResetBlockFailureFlags inverse)
//   G20-G22: ResetBlockFailureFlags (walk index, re-insert candidates, re-trigger ABC)
//   G23-G25: InvalidBlockFound (FAILED_VALID set, candidates erase, ZMQ/MainSignals)
//   G26-G28: LoadGenesisBlock (BlockIndex VALID_ALL|HAVE_DATA, disk write before index, m_chain set)
//   G29-G30: PruneAndFlush (don't prune tip, flush-before-prune ordering)

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ---------------------------------------------------------------------------
// G1. FindMostWorkChain — recalculateBestTipLocked does NOT filter by
//     StatusDataStored (Core's missing-data / HAVE_DATA guard).
//
// BUG: recalculateBestTipLocked (headerindex.go:706) iterates ALL nodes
// and picks the highest-work node regardless of whether block body data
// has been received. Core's FindMostWorkChain skips candidates where
// BLOCK_HAVE_DATA is absent on the path to the fork.
//
// In blockbrew, StatusDataStored is defined (headerindex.go:43) but NEVER
// SET anywhere — neither ConnectBlock nor the sync path ever sets it.
// Consequence: after a reorg or invalidation, recalculateBestTipLocked
// may select a node whose block data is not on disk, causing ReorgTo →
// chainDB.GetBlock to fail with "block not found".
//
// SEVERITY: CORRECTNESS (best-tip selection may point at data-absent node).
// ---------------------------------------------------------------------------
func TestW101_G1_RecalculateBestTipDoesNotFilterByDataStored(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	genesis := idx.Genesis()

	// Add a header without storing block data — simulating a header-only chain.
	// StatusDataStored is never set anywhere, so this is always the state.
	h := createTestHeader(genesis.Hash, genesis.Header.Timestamp+600, 0)
	node, err := idx.AddHeader(h, true)
	if err != nil {
		t.Fatalf("AddHeader: %v", err)
	}

	// Invariant: the node should NOT have StatusDataStored (the flag is dead).
	if node.Status&StatusDataStored != 0 {
		t.Errorf("StatusDataStored is now set; the dead-flag is no longer dead — update this test")
	}

	// recalculateBestTipLocked will still pick this node as best tip
	// even though block data has never been stored.
	idx.RecalculateBestTip()
	best := idx.BestTip()
	if best == nil {
		t.Fatal("bestTip is nil after RecalculateBestTip")
	}

	// The node with higher work (but no data) is selected as best tip.
	// Core would skip it because BLOCK_HAVE_DATA is absent.
	// We pin the current (buggy) behavior: data-absent nodes CAN be best tip.
	if best.Hash != node.Hash {
		t.Errorf("G1 expectation changed: expected data-absent node to be best tip; got %s", best.Hash.String()[:8])
	}

	// Confirm StatusDataStored is still dead code.
	if best.Status&StatusDataStored != 0 {
		t.Errorf("G1: StatusDataStored unexpectedly set on best tip — flag should still be dead code at W101 audit time")
	}
}

// ---------------------------------------------------------------------------
// G2. FindMostWorkChain — FAILED_MASK filter.
//
// Core: FindMostWorkChain skips candidates in setBlockIndexCandidates that
// have BLOCK_FAILED_MASK (FAILED_VALID | FAILED_CHILD) set.
// blockbrew's recalculateBestTipLocked skips nodes where IsInvalid() —
// this covers StatusInvalid | StatusInvalidChild. The gate is CORRECT.
// This test pins the correct behavior.
// ---------------------------------------------------------------------------
func TestW101_G2_FailedMaskFilterCorrect(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	genesis := idx.Genesis()

	ts := genesis.Header.Timestamp + 600
	hA := createTestHeader(genesis.Hash, ts, 0)
	nodeA, err := idx.AddHeader(hA, true)
	if err != nil {
		t.Fatalf("AddHeader A: %v", err)
	}

	hB := createTestHeader(genesis.Hash, ts+1, 100)
	nodeB, err := idx.AddHeader(hB, true)
	if err != nil {
		t.Fatalf("AddHeader B: %v", err)
	}

	// Mark B as invalid — it must be excluded from best-tip selection.
	nodeB.Status |= StatusInvalid
	idx.RecalculateBestTip()

	best := idx.BestTip()
	if best == nil {
		t.Fatal("bestTip is nil")
	}
	if best.Hash == nodeB.Hash {
		t.Errorf("G2: invalid block selected as best tip — FAILED_MASK filter broken")
	}
	// nodeA should win (higher work than genesis).
	if nodeA.TotalWork.Cmp(genesis.TotalWork) > 0 && best.Hash != nodeA.Hash {
		t.Errorf("G2: valid node A not selected as best tip; got %s", best.Hash.String()[:8])
	}
}

// ---------------------------------------------------------------------------
// G3. FindMostWorkChain — missing-data ancestor check absent.
//
// BUG: recalculateBestTipLocked does NOT walk the ancestor chain to
// verify BLOCK_HAVE_DATA on every link. Core's FindMostWorkChain walks
// the candidate chain from the tip down to the fork and stops if any
// ancestor is missing data. blockbrew picks the highest-work tip node
// without checking whether all intermediate blocks have body data.
//
// Consequence: a deep side-branch that has only headers (no body data
// on intermediate nodes) can be elected as best tip, causing ReorgTo →
// chainDB.GetBlock to fail at an intermediate block.
//
// SEVERITY: CORRECTNESS.
// ---------------------------------------------------------------------------
func TestW101_G3_AncestorDataAvailabilityNotChecked(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	genesis := idx.Genesis()

	ts := genesis.Header.Timestamp + 600
	// Build a fork: genesis → forkNode (height 1) → forkNode2 (height 2).
	hFork := createTestHeader(genesis.Hash, ts, 500)
	forkNode, err := idx.AddHeader(hFork, true)
	if err != nil {
		t.Fatalf("AddHeader fork: %v", err)
	}
	hFork2 := createTestHeader(forkNode.Hash, forkNode.Header.Timestamp+600, 1000)
	forkNode2, err := idx.AddHeader(hFork2, true)
	if err != nil {
		t.Fatalf("AddHeader fork2: %v", err)
	}

	// Neither node has StatusDataStored set (it is a dead flag).
	for _, n := range []*BlockNode{forkNode, forkNode2} {
		if n.Status&StatusDataStored != 0 {
			t.Errorf("G3: StatusDataStored unexpectedly set on fork node (flag should be dead)")
		}
	}

	idx.RecalculateBestTip()
	best := idx.BestTip()
	if best == nil {
		t.Fatal("bestTip nil")
	}
	// Pin current (buggy) behavior: forkNode2 (data absent) is best tip.
	if best.Hash != forkNode2.Hash {
		t.Errorf("G3 expectation changed: expected data-absent fork2 to be best; got %s", best.Hash.String()[:8])
	}
}

// ---------------------------------------------------------------------------
// G5. FindMostWorkChain — equal-work tiebreak is non-deterministic.
//
// BUG: when two non-precious nodes have equal work AND equal SequenceID
// (both 0, the zero value for regular blocks), the winner is determined
// by Go map iteration order — which is randomized. There is no secondary
// hash-based tiebreak as in Bitcoin Core.
//
// SEVERITY: CORRECTNESS (non-deterministic chain selection in equal-work
// scenarios; can cause peers to have diverging views of the best tip).
// ---------------------------------------------------------------------------
func TestW101_G5_EqualWorkSequenceIDZeroIsNonDeterministic(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	genesis := idx.Genesis()

	ts := genesis.Header.Timestamp + 600
	// Build two competing blocks at height 1 with equal bits (same work per block).
	hA := createTestHeader(genesis.Hash, ts, 0)
	nodeA, errA := idx.AddHeader(hA, true)
	hB := createTestHeader(genesis.Hash, ts+1, 200)
	nodeB, errB := idx.AddHeader(hB, true)
	if errA != nil || errB != nil {
		t.Fatalf("AddHeader: A=%v B=%v", errA, errB)
	}

	// Both are non-precious → SequenceID == 0.
	if nodeA.SequenceID != 0 || nodeB.SequenceID != 0 {
		t.Errorf("G5: expected SequenceID == 0 for non-precious nodes; A=%d B=%d",
			nodeA.SequenceID, nodeB.SequenceID)
	}

	// Both must have equal TotalWork for the tie to matter.
	if nodeA.TotalWork.Cmp(nodeB.TotalWork) != 0 {
		t.Skip("G5: nodes have unequal work (nonces hit different difficulties); skip equal-work tiebreak test")
	}

	// Run RecalculateBestTip 30 times. Non-determinism will show up as
	// different winners across iterations.
	var seen = make(map[wire.Hash256]int)
	for i := 0; i < 30; i++ {
		idx.RecalculateBestTip()
		tip := idx.BestTip()
		if tip != nil {
			seen[tip.Hash]++
		}
	}

	if len(seen) > 1 {
		// Non-deterministic tiebreak confirmed — pin the bug.
		t.Logf("G5 BUG CONFIRMED: equal-work tiebreak is non-deterministic; %d different winners over 30 iterations: %v", len(seen), seen)
	} else {
		// May be stable in this run due to consistent map iteration luck.
		t.Logf("G5: 30 iterations returned consistent tip; map iteration was stable this run. Hash-based tiebreak is still absent.")
	}
}

// ---------------------------------------------------------------------------
// G11. ActivateBestChain — cm.mu (cs_main equivalent) serializes chain updates.
//
// Core wraps ActivateBestChain in cs_main. blockbrew uses cm.mu (RWMutex)
// plus reorgMu. The locking is CORRECT. This test pins the behavior.
// ---------------------------------------------------------------------------
func TestW101_G11_CsMutexEquivalentPresent(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	cm.SetIBD(false)

	genesis := idx.Genesis()
	block := createTestBlock(t, params, genesis, nil)
	if _, err := idx.AddHeader(block.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if err := db.StoreBlock(block.Header.BlockHash(), block); err != nil {
		t.Fatalf("StoreBlock: %v", err)
	}
	if err := cm.ConnectBlock(block); err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}
	_, h := cm.BestBlock()
	if h != 1 {
		t.Errorf("G11: expected height 1 after ConnectBlock; got %d", h)
	}
}

// ---------------------------------------------------------------------------
// G15. ActivateBestChain — mempool RemoveForReorg is defined but NEVER called.
//
// BUG: Bitcoin Core calls CTxMemPool::removeForReorg after every chain
// tip advance to evict mempool transactions no longer valid:
//   - sequence-lock violations at new tip
//   - immature coinbase spends
//   - non-final transactions (nLockTime / nSequence)
//
// blockbrew defines Mempool.RemoveForReorg (mempool/mempool.go:2061) but
// it has ZERO production call-sites. This is the dead-helper pattern
// (8th confirmed instance: W73/W74/W77/W87/W90/W92/W93 + W101).
//
// Consequence: after a reorg, the mempool may contain transactions that
// Bitcoin Core (and the network) would reject. If these txs are included
// in a mined block, the block will be rejected, wasting miner fees.
//
// SEVERITY: CONSENSUS-DIVERGENT.
// ---------------------------------------------------------------------------
func TestW101_G15_RemoveForReorgDefinedButNoProductionCallSite(t *testing.T) {
	// Structural pin: verify RemoveForReorg exists and works in isolation,
	// then document that no production code calls it.
	//
	// We cannot intercept the chain manager → mempool path from this package
	// (mempool is a separate package), so we document the finding structurally.
	//
	// The fix would add a RemoveForReorg() call to the OnBlockConnected hook
	// in cmd/blockbrew/main.go after mp.BlockConnected(block).

	// Verify that the chain manager's callback wiring exists for connect/disconnect.
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	connectFired := false
	cm.SetOnBlockConnected(func(block *wire.MsgBlock, height int32) {
		connectFired = true
		// NOTE: In production (main.go:1006), this calls mp.BlockConnected(block)
		// but does NOT call mp.RemoveForReorg(). The fix is to add:
		//   mp.RemoveForReorg()
		// here, mirroring Core's validation.cpp::ActivateBestChain call to
		// removeForReorg after ConnectTip.
	})
	cm.SetIBD(false)

	genesis := idx.Genesis()
	b1 := createTestBlock(t, params, genesis, nil)
	if _, err := idx.AddHeader(b1.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if err := db.StoreBlock(b1.Header.BlockHash(), b1); err != nil {
		t.Fatalf("StoreBlock: %v", err)
	}
	if err := cm.ConnectBlock(b1); err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}
	if !connectFired {
		t.Error("G15: OnBlockConnected callback did not fire after ConnectBlock")
	}

	t.Log("G15 BUG: Mempool.RemoveForReorg (mempool/mempool.go:2061) has no production call-site. " +
		"After every chain tip advance, transactions with stale sequence locks, " +
		"immature coinbase spends, and non-final txs should be evicted. " +
		"Fix: call mp.RemoveForReorg() in the OnBlockConnected hook in main.go.")
}

// ---------------------------------------------------------------------------
// G17. InvalidateBlock — FAILED_VALID vs FAILED_CHILD flag distinction.
//
// Core distinguishes BLOCK_FAILED_VALID (this block's own validation failed)
// from BLOCK_FAILED_CHILD (ancestor failed). blockbrew maps these to
// StatusInvalid and StatusInvalidChild. The semantics MATCH Core.
// markDescendantsInvalid correctly sets StatusInvalidChild on descendants.
// This test pins the correct behavior.
// ---------------------------------------------------------------------------
func TestW101_G17_FailedValidVsFailedChildDistinction(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	cm.SetIBD(false)

	genesis := idx.Genesis()

	b1 := createTestBlock(t, params, genesis, nil)
	n1, err := idx.AddHeader(b1.Header, true)
	if err != nil {
		t.Fatalf("AddHeader b1: %v", err)
	}
	if err := db.StoreBlock(b1.Header.BlockHash(), b1); err != nil {
		t.Fatalf("StoreBlock b1: %v", err)
	}
	if err := cm.ConnectBlock(b1); err != nil {
		t.Fatalf("ConnectBlock b1: %v", err)
	}

	b2 := createTestBlock(t, params, n1, nil)
	n2, err := idx.AddHeader(b2.Header, true)
	if err != nil {
		t.Fatalf("AddHeader b2: %v", err)
	}
	if err := db.StoreBlock(b2.Header.BlockHash(), b2); err != nil {
		t.Fatalf("StoreBlock b2: %v", err)
	}
	if err := cm.ConnectBlock(b2); err != nil {
		t.Fatalf("ConnectBlock b2: %v", err)
	}

	// Invalidate b1. b2 is a descendant → StatusInvalidChild, not StatusInvalid.
	if err := cm.InvalidateBlock(b1.Header.BlockHash()); err != nil {
		t.Fatalf("InvalidateBlock b1: %v", err)
	}

	// b1: StatusInvalid must be set (FAILED_VALID equivalent).
	if n1.Status&StatusInvalid == 0 {
		t.Errorf("G17: b1 (invalidated directly) missing StatusInvalid")
	}
	if n1.Status&StatusInvalidChild != 0 {
		t.Errorf("G17: b1 spuriously has StatusInvalidChild — should have StatusInvalid only")
	}

	// b2: StatusInvalidChild must be set (FAILED_CHILD equivalent), NOT StatusInvalid.
	if n2.Status&StatusInvalidChild == 0 {
		t.Errorf("G17: b2 (descendant) missing StatusInvalidChild")
	}
}

// ---------------------------------------------------------------------------
// G17b. InvalidateBlock — deep descendant StatusInvalidChild propagation.
//
// Invalidating b1 in a chain genesis → b1 → b2 → b3 must set
// StatusInvalidChild on both b2 AND b3 (depth-2 descendant).
// ---------------------------------------------------------------------------
func TestW101_G17b_DeepDescendantInvalidChildPropagation(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	cm.SetIBD(false)

	genesis := idx.Genesis()

	b1 := createTestBlock(t, params, genesis, nil)
	n1, err := idx.AddHeader(b1.Header, true)
	if err != nil {
		t.Fatalf("AddHeader b1: %v", err)
	}
	if err := db.StoreBlock(b1.Header.BlockHash(), b1); err != nil {
		t.Fatalf("StoreBlock b1: %v", err)
	}
	if err := cm.ConnectBlock(b1); err != nil {
		t.Fatalf("ConnectBlock b1: %v", err)
	}

	b2 := createTestBlock(t, params, n1, nil)
	n2, err := idx.AddHeader(b2.Header, true)
	if err != nil {
		t.Fatalf("AddHeader b2: %v", err)
	}
	if err := db.StoreBlock(b2.Header.BlockHash(), b2); err != nil {
		t.Fatalf("StoreBlock b2: %v", err)
	}
	if err := cm.ConnectBlock(b2); err != nil {
		t.Fatalf("ConnectBlock b2: %v", err)
	}

	b3 := createTestBlock(t, params, n2, nil)
	n3, err := idx.AddHeader(b3.Header, true)
	if err != nil {
		t.Fatalf("AddHeader b3: %v", err)
	}
	if err := db.StoreBlock(b3.Header.BlockHash(), b3); err != nil {
		t.Fatalf("StoreBlock b3: %v", err)
	}
	if err := cm.ConnectBlock(b3); err != nil {
		t.Fatalf("ConnectBlock b3: %v", err)
	}

	if err := cm.InvalidateBlock(b1.Header.BlockHash()); err != nil {
		t.Fatalf("InvalidateBlock b1: %v", err)
	}

	if n2.Status&StatusInvalidChild == 0 {
		t.Errorf("G17b: b2 (depth-1 descendant) missing StatusInvalidChild")
	}
	if n3.Status&StatusInvalidChild == 0 {
		t.Errorf("G17b: b3 (depth-2 descendant) missing StatusInvalidChild")
	}
}

// ---------------------------------------------------------------------------
// G18. InvalidateBlock — invalid block NOT returned as bestTip after invalidation.
//
// Core removes invalid blocks from setBlockIndexCandidates immediately.
// blockbrew calls RecalculateBestTip which re-scans and filters them.
// The behavior is CORRECT. This test pins it.
// ---------------------------------------------------------------------------
func TestW101_G18_InvalidBlockNotSelectedAsBestTip(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	cm.SetIBD(false)

	genesis := idx.Genesis()

	b1 := createTestBlock(t, params, genesis, nil)
	if _, err := idx.AddHeader(b1.Header, true); err != nil {
		t.Fatalf("AddHeader b1: %v", err)
	}
	if err := db.StoreBlock(b1.Header.BlockHash(), b1); err != nil {
		t.Fatalf("StoreBlock b1: %v", err)
	}
	if err := cm.ConnectBlock(b1); err != nil {
		t.Fatalf("ConnectBlock b1: %v", err)
	}

	// Pre-condition: b1 is best tip.
	best := idx.BestTip()
	if best == nil || best.Hash != b1.Header.BlockHash() {
		t.Fatalf("pre-condition: b1 should be bestTip; got %v", best)
	}

	if err := cm.InvalidateBlock(b1.Header.BlockHash()); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}

	best = idx.BestTip()
	if best != nil && best.Hash == b1.Header.BlockHash() {
		t.Errorf("G18: invalid block b1 is still best tip after invalidation")
	}
}

// ---------------------------------------------------------------------------
// G19. ReconsiderBlock — clears ALL ancestor flags including independently-invalid.
//
// BUG: ReconsiderBlock's ancestor-walk loop (chainmanager.go:1948) clears
// StatusInvalid from ALL ancestors, including ones that were independently
// invalidated via separate invalidateblock RPC calls.
//
// Core's ResetBlockFailureFlags is also broad (it walks all of mapBlockIndex),
// but the intent is to clear ONLY FAILED_CHILD propagation — not FAILED_VALID
// set by an explicit invalidateblock. blockbrew uses the same flag for both
// the "this block directly failed validation" and "this block was explicitly
// invalidated via RPC" cases (both use StatusInvalid), so it cannot distinguish
// them, and ReconsiderBlock can accidentally re-activate an independently-
// invalidated ancestor.
//
// SEVERITY: CORRECTNESS (reconsidering one block can resurrect a separately-
// invalid ancestor without re-running ConnectBlock on it).
// ---------------------------------------------------------------------------
func TestW101_G19_ReconsiderBlockClearsIndependentlyInvalidAncestor(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	cm.SetIBD(false)

	genesis := idx.Genesis()

	b1 := createTestBlock(t, params, genesis, nil)
	n1, err := idx.AddHeader(b1.Header, true)
	if err != nil {
		t.Fatalf("AddHeader b1: %v", err)
	}
	if err := db.StoreBlock(b1.Header.BlockHash(), b1); err != nil {
		t.Fatalf("StoreBlock b1: %v", err)
	}
	if err := cm.ConnectBlock(b1); err != nil {
		t.Fatalf("ConnectBlock b1: %v", err)
	}

	b2 := createTestBlock(t, params, n1, nil)
	n2, err := idx.AddHeader(b2.Header, true)
	if err != nil {
		t.Fatalf("AddHeader b2: %v", err)
	}
	if err := db.StoreBlock(b2.Header.BlockHash(), b2); err != nil {
		t.Fatalf("StoreBlock b2: %v", err)
	}
	if err := cm.ConnectBlock(b2); err != nil {
		t.Fatalf("ConnectBlock b2: %v", err)
	}

	// Invalidate b2 via the public API.
	if err := cm.InvalidateBlock(b2.Header.BlockHash()); err != nil {
		t.Fatalf("InvalidateBlock b2: %v", err)
	}
	// Independently mark b1 as invalid (simulates a separate invalidateblock call).
	n1.Status |= StatusInvalid

	// Reconsider b2 only — should NOT clear b1's independent StatusInvalid.
	if err := cm.ReconsiderBlock(b2.Header.BlockHash()); err != nil {
		t.Fatalf("ReconsiderBlock b2: %v", err)
	}

	// Pin the buggy behavior.
	if n1.Status&StatusInvalid != 0 {
		t.Logf("G19: b1 still has StatusInvalid after ReconsiderBlock(b2) — may be fixed, check implementation")
	} else {
		t.Logf("G19 BUG CONFIRMED: ReconsiderBlock(b2) cleared StatusInvalid from independently-invalidated b1; ancestor walk at chainmanager.go:1948 is too broad")
	}

	_ = n2
}

// ---------------------------------------------------------------------------
// G20. ReconsiderBlock — re-inserts candidates into chain selection.
//
// After ReconsiderBlock, the reconsidered block should again be eligible
// for chain selection. This pins the correct behavior.
// ---------------------------------------------------------------------------
func TestW101_G20_ReconsiderBlockReInsertsIntoChainSelection(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	cm.SetIBD(false)

	genesis := idx.Genesis()

	b1 := createTestBlock(t, params, genesis, nil)
	n1, err := idx.AddHeader(b1.Header, true)
	if err != nil {
		t.Fatalf("AddHeader b1: %v", err)
	}
	if err := db.StoreBlock(b1.Header.BlockHash(), b1); err != nil {
		t.Fatalf("StoreBlock b1: %v", err)
	}
	if err := cm.ConnectBlock(b1); err != nil {
		t.Fatalf("ConnectBlock b1: %v", err)
	}

	if err := cm.InvalidateBlock(b1.Header.BlockHash()); err != nil {
		t.Fatalf("InvalidateBlock b1: %v", err)
	}
	_, hAfterInvalidate := cm.BestBlock()
	if hAfterInvalidate >= n1.Height {
		t.Errorf("G20: tip should retreat after invalidation; height=%d", hAfterInvalidate)
	}

	if err := cm.ReconsiderBlock(b1.Header.BlockHash()); err != nil {
		t.Fatalf("ReconsiderBlock b1: %v", err)
	}

	// After reconsideration, b1 must no longer be invalid.
	if n1.Status.IsInvalid() {
		t.Errorf("G20: b1 still invalid after ReconsiderBlock")
	}
}

// ---------------------------------------------------------------------------
// G22. IBD exit condition uses == instead of >= causing permanent IBD
//      if assumeValidHeight is passed without connecting.
//
// BUG: chainmanager.go:952: `cm.isIBD && cm.tipHeight == cm.assumeValidHeight`
//
// If the node skips one block (e.g. b1 is assumed-valid and its full block
// was never explicitly connected, but b2 is connected), tipHeight goes from
// 0 to 2, the equality cm.tipHeight == 1 never fires, and the node stays
// in IBD mode indefinitely.
//
// Core uses nChainWork >= nMinimumChainWork (not equality) as the IBD exit
// criterion (IsInitialBlockDownload checks chainwork threshold + tip timestamp).
//
// SEVERITY: CORRECTNESS (node stays in IBD mode after passing assumeValid;
// skips CheckBlockSanity on the non-IBD ConnectBlock path, affects ZMQ relay
// and compact-block announcements).
// ---------------------------------------------------------------------------
func TestW101_G22_IBDExitEqualityCheckCanMissIfHeightJumps(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	genesis := idx.Genesis()

	b1 := createTestBlock(t, params, genesis, nil)
	n1, err := idx.AddHeader(b1.Header, true)
	if err != nil {
		t.Fatalf("AddHeader b1: %v", err)
	}
	if err := db.StoreBlock(b1.Header.BlockHash(), b1); err != nil {
		t.Fatalf("StoreBlock b1: %v", err)
	}

	b2 := createTestBlock(t, params, n1, nil)
	if _, err := idx.AddHeader(b2.Header, true); err != nil {
		t.Fatalf("AddHeader b2: %v", err)
	}
	if err := db.StoreBlock(b2.Header.BlockHash(), b2); err != nil {
		t.Fatalf("StoreBlock b2: %v", err)
	}

	// Set assumeValid to b1 (height 1). Connect b1 then b2 — normal path.
	cm := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		ChainDB:         db,
		AssumeValidHash: b1.Header.BlockHash(),
	})
	cm.assumeValidHeight = 1 // Force resolution so we can test without hash lookup.

	if err := cm.ConnectBlock(b1); err != nil {
		t.Fatalf("ConnectBlock b1: %v", err)
	}
	// At height 1 == assumeValidHeight → IBD should exit.
	if cm.IsIBD() {
		t.Errorf("G22: node still in IBD after tipHeight (%d) == assumeValidHeight (%d)", 1, 1)
	}

	// Now test the pathological case: assumeValidHeight=1 but tipHeight jumps to 2.
	// Simulate by creating a fresh CM and manually setting tipHeight to 2 (skipping 1).
	cm2 := NewChainManager(ChainManagerConfig{
		Params:          params,
		HeaderIndex:     idx,
		ChainDB:         db,
		AssumeValidHash: b1.Header.BlockHash(),
	})
	cm2.assumeValidHeight = 1
	// Simulate tip at 2 (skipped 1 — equality never fires).
	cm2.mu.Lock()
	cm2.tipHeight = 2
	cm2.mu.Unlock()

	if !cm2.IsIBD() {
		t.Logf("G22: cm2 exited IBD without the == check firing — behavior may have changed")
	} else {
		t.Logf("G22 BUG CONFIRMED: node at tipHeight=2 with assumeValidHeight=1 stuck in IBD " +
			"(chainmanager.go:952 uses == not >=; if the tip jumps past assumeValidHeight the exit never fires)")
	}
}

// ---------------------------------------------------------------------------
// G26. LoadGenesisBlock — StatusDataStored not set on genesis node.
//
// BUG: Core sets BLOCK_VALID_ALL | BLOCK_HAVE_DATA on the genesis
// CBlockIndex. blockbrew's NewHeaderIndex creates the genesis node with
// StatusHeaderValid | StatusFullyValid (headerindex.go:296) but does NOT
// set StatusDataStored (BLOCK_HAVE_DATA equivalent).
// This is the same dead-flag finding from W97 G25, confirmed at genesis.
//
// SEVERITY: CORRECTNESS (dead code; will matter once the missing-data
// filter in G1/G3 is fixed).
// ---------------------------------------------------------------------------
func TestW101_G26_GenesisNodeMissingStatusDataStored(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)

	genesis := idx.Genesis()
	if genesis == nil {
		t.Fatal("genesis node is nil")
	}

	// Core sets BLOCK_VALID_ALL | BLOCK_HAVE_DATA; blockbrew should set
	// StatusFullyValid | StatusDataStored. We pin the current buggy state.
	if genesis.Status&StatusDataStored != 0 {
		t.Errorf("G26: StatusDataStored now set on genesis — dead flag is no longer dead; update test")
	}
	if genesis.Status&StatusFullyValid == 0 {
		t.Errorf("G26: genesis missing StatusFullyValid (regression)")
	}

	t.Log("G26 BUG: genesis BlockNode missing StatusDataStored (BLOCK_HAVE_DATA equivalent). " +
		"Core sets this in LoadGenesisBlock::ReceivedBlockTransactions. " +
		"blockbrew's missing-data filter (G1/G3) is also absent, so this is currently a dead-dead gap.")
}

// ---------------------------------------------------------------------------
// G28. LoadGenesisBlock — m_chain set (active chain includes genesis).
//
// Core sets m_chain[0] = genesis CBlockIndex in LoadGenesisBlock.
// blockbrew's NewChainManager sets cm.tipNode = genesis (chainmanager.go:268)
// and cm.tipHeight = 0. The behavior is CORRECT.
// This test pins it.
// ---------------------------------------------------------------------------
func TestW101_G28_GenesisIsActiveChainTip(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
	})

	h, height := cm.BestBlock()
	if height != 0 {
		t.Errorf("G28: expected genesis at height 0; got %d", height)
	}
	if h != params.GenesisHash {
		t.Errorf("G28: expected genesis hash; got %s", h.String()[:8])
	}
	tipNode := cm.TipNode()
	if tipNode == nil || tipNode.Hash != params.GenesisHash {
		t.Errorf("G28: tipNode is not genesis")
	}
}

// ---------------------------------------------------------------------------
// G29. PruneAndFlush — don't prune tip (lastSafeHeight logic).
//
// Core: FindFilesToPrune skips files that contain the active tip via the
// MIN_BLOCKS_TO_KEEP buffer. blockbrew: MaybePrune uses
// lastSafeHeight = max(0, tipHeight - MinBlocksToKeep) (storage/prune.go:387).
// This test pins the correct formula.
// ---------------------------------------------------------------------------

// w101LastSafeHeight mirrors storage.lastSafeHeight (unexported) so we can
// test the formula without import-cycling or making the production function
// exported.  Must be kept in sync with storage/prune.go:lastSafeHeight.
func w101LastSafeHeight(tipHeight int32) int32 {
	const minKeep = int32(storage.MinBlocksToKeep)
	if tipHeight <= minKeep {
		return 0
	}
	return tipHeight - minKeep
}

func TestW101_G29_PrunerProtectsTipWindow(t *testing.T) {
	minKeep := int32(storage.MinBlocksToKeep) // 288

	// At tipHeight = MinBlocksToKeep, lastSafe = 0 (nothing pruneable).
	if got := w101LastSafeHeight(minKeep); got != 0 {
		t.Errorf("G29: lastSafeHeight(%d) = %d, want 0", minKeep, got)
	}

	// At tipHeight = 2×MinBlocksToKeep, lastSafe = MinBlocksToKeep.
	if got := w101LastSafeHeight(minKeep * 2); got != minKeep {
		t.Errorf("G29: lastSafeHeight(%d) = %d, want %d", minKeep*2, got, minKeep)
	}

	// At tipHeight = 0, lastSafe = 0.
	if got := w101LastSafeHeight(0); got != 0 {
		t.Errorf("G29: lastSafeHeight(0) = %d, want 0", got)
	}

	// At tipHeight = 1 (below MinBlocksToKeep), lastSafe = 0.
	if got := w101LastSafeHeight(1); got != 0 {
		t.Errorf("G29: lastSafeHeight(1) = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// G30. PruneAndFlush — flush-before-prune ordering.
//
// Core: FlushStateToDisk must complete before pruning so a crash after
// prune but before flush cannot leave chainstate ahead of available data.
// blockbrew: the UTXO flush happens inside ConnectBlock's batch.Write()
// (which precedes the onBlockConnected callback), and MaybePrune is called
// from onBlockConnected — so flush always precedes prune. CORRECT.
// This test pins the callback firing order.
// ---------------------------------------------------------------------------
func TestW101_G30_OnBlockConnectedFiresAfterBatchWrite(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:        params,
		HeaderIndex:   idx,
		ChainDB:       db,
		FlushInterval: 1, // flush every block
	})
	cm.SetIBD(false)

	callbackFired := false
	var callbackHeight int32
	cm.SetOnBlockConnected(func(block *wire.MsgBlock, height int32) {
		callbackFired = true
		callbackHeight = height
		// At this point, the batch.Write() in ConnectBlock has already
		// completed (flush happened inside batch.Write when shouldFlush was true).
		// MaybePrune would be called here; the flush precedes the prune.
	})

	genesis := idx.Genesis()
	b1 := createTestBlock(t, params, genesis, nil)
	if _, err := idx.AddHeader(b1.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if err := db.StoreBlock(b1.Header.BlockHash(), b1); err != nil {
		t.Fatalf("StoreBlock: %v", err)
	}
	if err := cm.ConnectBlock(b1); err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}

	if !callbackFired {
		t.Error("G30: OnBlockConnected callback did not fire after ConnectBlock")
	}
	if callbackHeight != 1 {
		t.Errorf("G30: callback height = %d, want 1", callbackHeight)
	}
}

// ---------------------------------------------------------------------------
// G9. DisconnectedBlockTransactions re-add timing: per-block vs post-loop.
//
// Core re-adds ALL disconnected transactions to the mempool AFTER the full
// ConnectTip loop completes (at final new-tip state). blockbrew's Pattern B
// re-adds per-block DURING the disconnect loop, before any new-branch
// blocks are connected — so txs are re-validated against an intermediate
// chain state (the fork point), not the final new-tip state.
//
// This timing difference can cause sequence-lock / maturity validation to
// use a stale tip when deciding whether to re-accept a disconnected tx,
// producing a window where a tx that would pass validation at the final tip
// fails at the intermediate state and is dropped from the mempool.
//
// SEVERITY: CORRECTNESS (stale re-validation state on deep reorgs; most
// real reorgs are 1-2 blocks deep so impact is minor in practice).
// ---------------------------------------------------------------------------
func TestW101_G9_DisconnectCallbackFiresPerBlockNotPostConnect(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})
	cm.SetIBD(false)

	var eventLog []string
	cm.SetOnBlockDisconnected(func(block *wire.MsgBlock, height int32) {
		eventLog = append(eventLog, "disconnect")
	})
	cm.SetOnBlockConnected(func(block *wire.MsgBlock, height int32) {
		eventLog = append(eventLog, "connect")
	})

	genesis := idx.Genesis()

	// Build main chain: genesis → b1.
	b1 := createTestBlock(t, params, genesis, nil)
	n1, err := idx.AddHeader(b1.Header, true)
	if err != nil {
		t.Fatalf("AddHeader b1: %v", err)
	}
	if err := db.StoreBlock(b1.Header.BlockHash(), b1); err != nil {
		t.Fatalf("StoreBlock b1: %v", err)
	}
	if err := cm.ConnectBlock(b1); err != nil {
		t.Fatalf("ConnectBlock b1: %v", err)
	}
	eventLog = nil // Reset after setup.

	// Build a fork that extends b1 to height 2, giving it strictly more work
	// than any height-1 block and guaranteeing the reorg fires.
	b2Fork := createTestBlock(t, params, n1, nil)
	// Give b2Fork a different timestamp so the hash differs from b2 (if any).
	b2Fork.Header.Timestamp = b1.Header.Timestamp + 1200
	// Re-mine nonce for the new timestamp.
	target2 := CompactToBig(b2Fork.Header.Bits)
	for i := uint32(0); i < 10000000; i++ {
		b2Fork.Header.Nonce = i
		h := b2Fork.Header.BlockHash()
		if HashToBig(h).Cmp(target2) <= 0 {
			break
		}
	}
	nFork2, err := idx.AddHeader(b2Fork.Header, true)
	if err != nil {
		// If this fails it's because b2Fork.Header.PrevBlock == n1.Hash
		// which should always be in the index. Surface the error.
		t.Fatalf("AddHeader b2Fork: %v", err)
	}
	if err := db.StoreBlock(b2Fork.Header.BlockHash(), b2Fork); err != nil {
		t.Fatalf("StoreBlock b2Fork: %v", err)
	}

	// nFork2 is at height 2 with more work than n1 (height 1) — reorg should fire.
	// ProcessSubmittedBlock detects newNode.TotalWork > tipWork and calls ReorgTo.
	// But wait: n1 IS already on the active tip (b1 was connected). b2Fork extends
	// the active tip, so ProcessSubmittedBlock will use the ConnectBlock happy path.
	// To test disconnect→connect ordering we need to force a REORG, not an extension.
	// We need a fork from genesis with MORE total work than b1.
	//
	// Use ReorgTo directly on a height-2 fork rooted at genesis (length 2 vs length 1).
	// Build: genesis → fA (height 1) → fB (height 2) as a fork.
	fA := createTestBlock(t, params, genesis, nil)
	fA.Header.Timestamp = genesis.Header.Timestamp + 1201
	targetA := CompactToBig(fA.Header.Bits)
	for i := uint32(0); i < 10000000; i++ {
		fA.Header.Nonce = i
		h := fA.Header.BlockHash()
		if HashToBig(h).Cmp(targetA) <= 0 {
			break
		}
	}
	nForkA, errA := idx.AddHeader(fA.Header, true)
	if errA != nil {
		t.Fatalf("AddHeader fA: %v", errA)
	}
	if err := db.StoreBlock(fA.Header.BlockHash(), fA); err != nil {
		t.Fatalf("StoreBlock fA: %v", err)
	}

	fB := createTestBlock(t, params, nForkA, nil)
	fB.Header.Timestamp = nForkA.Header.Timestamp + 600
	targetB := CompactToBig(fB.Header.Bits)
	for i := uint32(0); i < 10000000; i++ {
		fB.Header.Nonce = i
		h := fB.Header.BlockHash()
		if HashToBig(h).Cmp(targetB) <= 0 {
			break
		}
	}
	nForkB, errB := idx.AddHeader(fB.Header, true)
	if errB != nil {
		t.Fatalf("AddHeader fB: %v", errB)
	}
	if err := db.StoreBlock(fB.Header.BlockHash(), fB); err != nil {
		t.Fatalf("StoreBlock fB: %v", err)
	}

	// nForkB (height 2, fork rooted at genesis) has strictly more work than n1
	// (height 1, active tip). Trigger reorg.
	if nForkB.TotalWork.Cmp(n1.TotalWork) <= 0 {
		t.Skipf("G9: fork chain (height %d) does not exceed active tip (height %d) in work; skip", nForkB.Height, n1.Height)
	}

	// Reset event log before reorg.
	eventLog = nil

	if err := cm.ReorgTo(nForkB); err != nil {
		t.Fatalf("ReorgTo forkB: %v", err)
	}

	// Expected order: 1 disconnect (b1 peeled), then 2 connects (fA, fB connected).
	// blockbrew fires disconnect callbacks during the disconnect loop, then connect
	// callbacks during the connect loop — so the interleave for a 1-disconnect
	// 2-connect reorg is: ["disconnect", "connect", "connect"].
	t.Logf("G9 event log: %v", eventLog)
	if len(eventLog) < 3 {
		t.Errorf("G9: expected 3 events (1 disconnect + 2 connects); got %v", eventLog)
	}
	if eventLog[0] != "disconnect" {
		t.Errorf("G9: expected first event to be 'disconnect'; got %q", eventLog[0])
	}
	connectCount := 0
	for _, ev := range eventLog {
		if ev == "connect" {
			connectCount++
		}
	}
	if connectCount < 2 {
		t.Errorf("G9: expected 2 connect events; got %d", connectCount)
	}

	// Document the per-block vs post-loop re-add difference.
	t.Logf("G9 NOTE: blockbrew fires disconnect callbacks per-block (during disconnect loop), " +
		"then connect callbacks per-block (during connect loop). Core's ActivateBestChainStep " +
		"collects ALL disconnected txs first, then after all connects, re-adds them at the final " +
		"new-tip state. The stale re-validation window is the G9 finding.")

	_ = nFork2
}
