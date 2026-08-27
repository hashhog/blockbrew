package consensus

// #47 chain-selection tier — work-vs-length pure-predicate pins.
//
// Regtest cannot express these scenarios end-to-end (AddHeader's difficulty
// gate binds every header to the same expected bits, so all blocks carry
// identical work and length == work).  These tests therefore hand-build
// BlockNodes with divergent TotalWork and drive RecalculateBestTip — the
// FindMostWorkChain analogue (validation.cpp:3114) whose comparator is the
// single point where a height/length term could corrupt chain selection.
//
// The comparator is currently SOUND (work-only, sequence-id + hash
// tiebreaks).  These pins bind it: substituting a height comparison at
// headerindex.go's TotalWork switch makes both tests fail (verified during
// authoring — predicate-inversion A/B; see the #47 ledger entry).

import (
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// attachWorkNode appends a synthetic, fully-stored, valid node carrying
// parent.TotalWork + workDelta.  hashSeed must be unique per node.
func attachWorkNode(idx *HeaderIndex, parent *BlockNode, hashSeed byte, workDelta int64) *BlockNode {
	var hash wire.Hash256
	for i := range hash {
		hash[i] = hashSeed
	}
	node := &BlockNode{
		Hash:      hash,
		Height:    parent.Height + 1,
		Parent:    parent,
		TotalWork: new(big.Int).Add(parent.TotalWork, big.NewInt(workDelta)),
		Status:    StatusHeaderValid | StatusFullyValid | StatusDataStored,
	}
	node.buildSkip()
	parent.Children = append(parent.Children, node)
	idx.nodes[hash] = node
	return node
}

// A 5-block fork at 1 work/block loses to a 2-block fork at 10 work/block:
// the SHORTER chain has more cumulative work and must win.
func TestRecalculateBestTipHeavierButShorterForkWins(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	genesis := idx.Genesis()

	longTip := genesis
	for i := 0; i < 5; i++ {
		longTip = attachWorkNode(idx, longTip, byte(0x10+i), 1)
	}
	shortTip := genesis
	for i := 0; i < 2; i++ {
		shortTip = attachWorkNode(idx, shortTip, byte(0x20+i), 10)
	}

	idx.RecalculateBestTip()

	best := idx.BestTip()
	if best != shortTip {
		t.Fatalf("best tip = height %d work %s; want the SHORTER heavier fork (height %d work %s) — selection is not work-only",
			best.Height, best.TotalWork, shortTip.Height, shortTip.TotalWork)
	}
}

// Extending the light fork to 4x the heavy fork's length must NOT displace
// the heavy tip: length never beats work.
func TestRecalculateBestTipLongerButLighterForkRefused(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	genesis := idx.Genesis()

	heavyTip := genesis
	for i := 0; i < 2; i++ {
		heavyTip = attachWorkNode(idx, heavyTip, byte(0x20+i), 10)
	}
	idx.RecalculateBestTip()
	if idx.BestTip() != heavyTip {
		t.Fatalf("precondition: heavy fork should be best")
	}

	lightTip := genesis
	for i := 0; i < 8; i++ {
		lightTip = attachWorkNode(idx, lightTip, byte(0x40+i), 1)
	}

	idx.RecalculateBestTip()

	best := idx.BestTip()
	if best == lightTip {
		t.Fatalf("longer-but-lighter fork (height %d work %s) displaced the heavy tip (height %d work %s) — a length term is driving selection",
			lightTip.Height, lightTip.TotalWork, heavyTip.Height, heavyTip.TotalWork)
	}
	if best != heavyTip {
		t.Fatalf("best tip = height %d work %s; want heavy tip (height %d work %s)",
			best.Height, best.TotalWork, heavyTip.Height, heavyTip.TotalWork)
	}
}
