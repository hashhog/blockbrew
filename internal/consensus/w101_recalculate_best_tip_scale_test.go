package consensus

import (
	"math/big"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ---------------------------------------------------------------------------
// recalculateBestTipLocked — G3 ancestor-data walk must not be quadratic.
//
// The G3 check verifies StatusDataStored on every ancestor of a candidate.
// It used to re-walk the full ancestor chain to genesis for EVERY node in the
// index, making the pass O(nodes x height). On mainnet (~960k blocks) that is
// ~4.6e11 pointer chases on a single goroutine, held under idx.mu — and under
// cm.mu too when reached via ChainManager.InvalidateBlock. The observable
// effect is a wedged node: invalidateblock and reconsiderblock never return,
// and block processing stalls behind cm.mu.
//
// Found live on genesis-blockbrew (mainnet, tip 959902) while rolling back for
// a UTXO-set capture: `invalidateblock` pinned one core at 100% with zero
// progress for 11+ minutes, gdb showing every sample inside
// recalculateBestTipLocked.
//
// Core avoids this by iterating only setBlockIndexCandidates and by stopping
// the walk at the active chain (validation.cpp:3131).
//
// These tests pin BOTH properties of the memoised implementation:
//   - it is linear enough to finish a deep chain quickly (this file), and
//   - it selects exactly the tip the naive walk selected (equivalence test).
// ---------------------------------------------------------------------------

// buildLinearChain wires n synthetic nodes onto genesis, each with data stored,
// and registers them in idx.nodes. Nodes are built directly rather than through
// AddHeader so the test can reach mainnet-ish depth cheaply. Returns the tip.
func buildLinearChain(idx *HeaderIndex, n int) *BlockNode {
	parent := idx.Genesis()
	work := new(big.Int).Set(parent.TotalWork)
	for i := 1; i <= n; i++ {
		var h wire.Hash256
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		h[2] = byte(i >> 16)
		h[3] = 0xAA // domain-separate from the fork chain below

		work = new(big.Int).Add(work, big.NewInt(1))
		node := &BlockNode{
			Hash:      h,
			Height:    parent.Height + 1,
			Parent:    parent,
			TotalWork: work,
			Status:    StatusDataStored,
		}
		parent.Children = append(parent.Children, node)
		idx.nodes[h] = node
		parent = node
	}
	return parent
}

// TestRecalculateBestTip_NotQuadraticInChainHeight builds a deep chain and
// requires RecalculateBestTip to finish promptly.
//
// Discriminator, measured rather than assumed. The naive walk is O(n^2/2)
// pointer chases; on this box it ran 8.47s at depth 60k, so a 20s bound at
// that depth would NOT have separated the two. At depth 150k the naive walk
// extrapolates to ~53s ((150/60)^2 x 8.47) while the memoised walk touches
// each node once and finishes in tens of milliseconds. The 20s bound therefore
// sits ~2.6x below naive and ~500x above memoised — wide enough that a loaded
// box cannot flip it, and load only pushes naive further over.
func TestRecalculateBestTip_NotQuadraticInChainHeight(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test; skipped under -short")
	}

	const depth = 150000

	idx := NewHeaderIndex(RegtestParams())
	tip := buildLinearChain(idx, depth)

	start := time.Now()
	idx.RecalculateBestTip()
	elapsed := time.Since(start)

	best := idx.BestTip()
	if best == nil {
		t.Fatal("bestTip is nil after RecalculateBestTip")
	}
	if best.Hash != tip.Hash {
		t.Errorf("expected deepest node as best tip, got height %d", best.Height)
	}

	t.Logf("RecalculateBestTip over %d nodes took %v", depth+1, elapsed)
	if elapsed > 20*time.Second {
		t.Errorf("QUADRATIC G3 WALK REGRESSION: RecalculateBestTip took %v over a "+
			"%d-block chain. The G3 ancestor-data check must be memoised (or stop "+
			"at the active chain as Core does); re-walking to genesis per node "+
			"wedges a mainnet-height node under idx.mu/cm.mu.", elapsed, depth)
	}
}

// naiveRecalculateBestTip is the pre-fix algorithm, kept verbatim as the
// reference oracle. The memoised implementation must agree with it exactly —
// the fix is a pure speedup and must not move chain selection by one block.
func naiveRecalculateBestTip(idx *HeaderIndex) *BlockNode {
	var bestCandidate *BlockNode

	for _, node := range idx.nodes {
		if node.Status.IsInvalid() {
			continue
		}
		if node.Status&StatusDataStored == 0 {
			continue
		}
		missingAncestorData := false
		for anc := node.Parent; anc != nil; anc = anc.Parent {
			if anc.Status&StatusDataStored == 0 {
				missingAncestorData = true
				break
			}
		}
		if missingAncestorData {
			continue
		}

		if bestCandidate == nil {
			bestCandidate = node
			continue
		}
		switch node.TotalWork.Cmp(bestCandidate.TotalWork) {
		case 1:
			bestCandidate = node
		case 0:
			if node.SequenceID < bestCandidate.SequenceID {
				bestCandidate = node
				break
			}
			if node.SequenceID > bestCandidate.SequenceID {
				break
			}
			for i := 0; i < len(node.Hash); i++ {
				if node.Hash[i] < bestCandidate.Hash[i] {
					bestCandidate = node
					break
				}
				if node.Hash[i] > bestCandidate.Hash[i] {
					break
				}
			}
		}
	}
	return bestCandidate
}

// TestRecalculateBestTip_MatchesNaiveWalk drives the memoised implementation
// and the naive oracle over the same index across a matrix of shapes that
// exercise every way the G3 walk can terminate: clean chains, a data hole
// mid-chain (whole suffix disqualified), an invalid node, competing forks with
// equal work (hash tiebreak), and a data hole on one fork only.
func TestRecalculateBestTip_MatchesNaiveWalk(t *testing.T) {
	type shape struct {
		name  string
		build func(idx *HeaderIndex)
	}

	// forkFrom hangs a competing branch off `from`, tagged so its hashes differ
	// from the main chain's. equalWork makes the branch tie the main chain to
	// force the SequenceID/hash tiebreak path.
	forkFrom := func(idx *HeaderIndex, from *BlockNode, n int, tag byte, workStep int64) *BlockNode {
		parent := from
		work := new(big.Int).Set(from.TotalWork)
		for i := 1; i <= n; i++ {
			var h wire.Hash256
			h[0] = byte(i)
			h[1] = tag
			h[3] = 0xBB
			work = new(big.Int).Add(work, big.NewInt(workStep))
			node := &BlockNode{
				Hash:      h,
				Height:    parent.Height + 1,
				Parent:    parent,
				TotalWork: work,
				Status:    StatusDataStored,
			}
			parent.Children = append(parent.Children, node)
			idx.nodes[h] = node
			parent = node
		}
		return parent
	}

	// nodeAtHeight walks the main chain back from the tip.
	nodeAtHeight := func(tip *BlockNode, h int32) *BlockNode {
		for n := tip; n != nil; n = n.Parent {
			if n.Height == h {
				return n
			}
		}
		return nil
	}

	shapes := []shape{
		{"linear-clean", func(idx *HeaderIndex) {
			buildLinearChain(idx, 200)
		}},
		{"data-hole-midchain", func(idx *HeaderIndex) {
			tip := buildLinearChain(idx, 200)
			// Whole suffix above height 100 becomes ineligible.
			nodeAtHeight(tip, 100).Status &^= StatusDataStored
		}},
		{"invalid-node-midchain", func(idx *HeaderIndex) {
			tip := buildLinearChain(idx, 200)
			nodeAtHeight(tip, 150).Status |= StatusInvalid
		}},
		{"fork-more-work", func(idx *HeaderIndex) {
			tip := buildLinearChain(idx, 200)
			forkFrom(idx, nodeAtHeight(tip, 120), 100, 0x01, 2)
		}},
		{"fork-equal-work-hash-tiebreak", func(idx *HeaderIndex) {
			tip := buildLinearChain(idx, 200)
			// Same length and per-block work off the same parent => exact tie.
			forkFrom(idx, nodeAtHeight(tip, 199), 1, 0x02, 1)
		}},
		{"fork-with-data-hole", func(idx *HeaderIndex) {
			tip := buildLinearChain(idx, 200)
			forkTip := forkFrom(idx, nodeAtHeight(tip, 120), 100, 0x03, 2)
			// Punch the hole on the heavier fork: the main chain must win.
			nodeAtHeight(forkTip, 150).Status &^= StatusDataStored
		}},
		{"all-data-absent-above-genesis", func(idx *HeaderIndex) {
			tip := buildLinearChain(idx, 50)
			for n := tip; n != nil && n.Height > 0; n = n.Parent {
				n.Status &^= StatusDataStored
			}
		}},
	}

	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			idx := NewHeaderIndex(RegtestParams())
			s.build(idx)

			want := naiveRecalculateBestTip(idx)

			idx.RecalculateBestTip()
			got := idx.BestTip()

			switch {
			case want == nil && got == nil:
				// Both declined to pick; nothing to compare.
			case want == nil || got == nil:
				t.Fatalf("nil mismatch: naive=%v memoised=%v", want, got)
			case want.Hash != got.Hash:
				t.Errorf("SELECTION DIVERGED from the naive G3 walk: naive picked "+
					"height %d (%s), memoised picked height %d (%s). The memo is a "+
					"speedup only and must not change which tip wins.",
					want.Height, want.Hash.String()[:16],
					got.Height, got.Hash.String()[:16])
			}
		})
	}
}
