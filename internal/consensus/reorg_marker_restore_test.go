package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestFailedReorg_RestoresCoinsMarkerWithTip pins finding #2 (promoted from the
// reviewer's TestReviewProbe_FailedReorgLeavesMarkerBehind).
//
// NO CRASH IS REQUIRED for this one. A reorg that fails partway — an RPC
// invalidateblock/reconsiderblock round trip onto a branch whose first block is
// over-subsidy is enough — unwinds through rollbackToOriginalTip, which
// restored cm.tipNode and the UTXO journal but NOT the applied-through marker.
// The disconnect loop had already rewound the marker to the fork point, so the
// node carried on with tip=6 and marker=4, and the next flush made that
// disagreement durable.
//
// Core has no equivalent hole: ActivateBestChainStep connects against a
// throwaway CCoinsViewCache and only flushes on success
// (bitcoin-core/src/validation.cpp:3191-3262).
//
// The assertion is on the DURABLE marker after a flush, not on an in-memory
// field: this is about what the next boot will read.
func TestFailedReorg_RestoresCoinsMarkerWithTip(t *testing.T) {
	base := *RegtestParams()
	base.SubsidyHalvingInterval = 210000
	params := &base

	idx := NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())
	utxoSet := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxoSet,
	})
	cm.SetIBD(false)

	prev := idx.Genesis()
	var nodes []*BlockNode
	for h := 1; h <= 6; h++ {
		b := createTestBlock(t, params, prev, nil)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader: %v", err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock h=%d: %v", h, err)
		}
		prev = idx.GetNode(b.Header.BlockHash())
		nodes = append(nodes, prev)
	}
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	origTip := nodes[5] // height 6
	fork := nodes[3]    // height 4

	// A competing 3-block branch from the fork point whose FIRST block is
	// over-subsidy: the reorg disconnects 6 and 5, then fails on the branch.
	bp := fork
	var branchTip *BlockNode
	for i := 0; i < 3; i++ {
		var b *wire.MsgBlock
		if i == 0 {
			b = createTestBlockWithCoinbaseValue(t, params, bp, 99*100000000) // invalid
		} else {
			b = createTestBlock(t, params, bp, nil)
		}
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader branch: %v", err)
		}
		bp = idx.GetNode(b.Header.BlockHash())
		branchTip = bp
	}

	if err := cm.ReorgTo(branchTip); err == nil {
		t.Fatalf("expected the reorg to FAIL on the invalid branch block")
	}
	if _, h := cm.BestBlock(); h != origTip.Height {
		t.Fatalf("tip not restored: got %d want %d", h, origTip.Height)
	}

	gotHash, gotHeight, set := utxoSet.AppliedTip()
	t.Logf("after failed reorg: tip restored to %d, applied marker = %s@%d (set=%v)",
		origTip.Height, gotHash.String()[:16], gotHeight, set)

	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	m, err := chainDB.GetCoinsTip()
	if err != nil {
		t.Fatalf("GetCoinsTip: %v", err)
	}
	onChain, _ := chainDB.GetBlockHashByHeight(m.BestHeight)
	t.Logf("durable marker now %s@%d; height-map agrees=%v; true on-disk set reflects height %d",
		m.BestHash.String()[:16], m.BestHeight, onChain == m.BestHash, origTip.Height)

	if m.BestHeight != origTip.Height || m.BestHash != origTip.Hash {
		t.Errorf("MARKER WRONG after a failed reorg: durable coins marker = %s@%d, "+
			"but the UTXO set on disk reflects %s@%d (fork point was h=%d)",
			m.BestHash.String()[:16], m.BestHeight,
			origTip.Hash.String()[:16], origTip.Height, fork.Height)
	}
}
