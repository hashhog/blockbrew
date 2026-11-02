package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestInvalidateBlock_FailedSideBranchKeepsValidPrefix pins the Core regtest
// failed_reorg scenario B (KB-176 shape):
//
//	m1-m2-m3-m4-m5
//	      \-s3-s4-s5bad      (s5bad pays over the subsidy)
//
// The side blocks are stored unvalidated while m5 is the tip. After
// invalidateblock(m4), the most-work candidate is s5bad. Core's
// ActivateBestChain connects s3 and s4, fails s5bad (BLOCK_FAILED_VALID),
// and re-selects the best remaining valid candidate: s4, whose valid prefix
// has more work than m3. Before the fix blockbrew rolled the failed reorg
// back to m3 and stopped, so the node sat on a lighter chain than a stored
// valid one (bitcoin-core/src/validation.cpp ActivateBestChain loop,
// FindMostWorkChain after InvalidChainFound).
func TestInvalidateBlock_FailedSideBranchKeepsValidPrefix(t *testing.T) {
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
	var m []*BlockNode
	for h := 1; h <= 5; h++ {
		b := createTestBlock(t, params, prev, nil)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader: %v", err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock h=%d: %v", h, err)
		}
		prev = idx.GetNode(b.Header.BlockHash())
		m = append(m, prev)
	}

	// Side branch off m2: s3 (49 BTC so it differs from m3), s4, s5bad.
	sp := m[1]
	var s []*BlockNode
	for i := 0; i < 3; i++ {
		value := int64(49 * 100000000)
		if i == 2 {
			value = 99 * 100000000
		}
		b := createTestBlockWithCoinbaseValue(t, params, sp, value)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader side: %v", err)
		}
		if err := chainDB.StoreBlock(b.Header.BlockHash(), b); err != nil {
			t.Fatalf("StoreBlock side: %v", err)
		}
		idx.MarkDataStored(b.Header.BlockHash())
		sp = idx.GetNode(b.Header.BlockHash())
		s = append(s, sp)
	}

	if err := cm.InvalidateBlock(m[3].Hash); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}

	best, height := cm.BestBlock()
	if best != s[1].Hash || height != s[1].Height {
		t.Fatalf("tip after invalidateblock(m4) = %s@%d, want side prefix s4 %s@%d (m3 is %s@%d)",
			best.String()[:16], height, s[1].Hash.String()[:16], s[1].Height,
			m[2].Hash.String()[:16], m[2].Height)
	}
	if !s[2].Status.IsInvalid() {
		t.Errorf("s5bad not marked failed")
	}
	if s[1].Status.IsInvalid() || s[0].Status.IsInvalid() {
		t.Errorf("valid prefix s3/s4 wrongly marked failed")
	}
}

// TestReconsiderBlock_EqualWorkEarlierReceivedReturns pins failed_reorg
// scenario C: with m4 and s4 at equal work and m4 received first,
// invalidateblock(m4) moves the tip to s4 and reconsiderblock(m4) must move it
// back (Core orders equal-work candidates by receipt sequence id).
func TestReconsiderBlock_EqualWorkEarlierReceivedReturns(t *testing.T) {
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
	var m []*BlockNode
	for h := 1; h <= 4; h++ {
		b := createTestBlock(t, params, prev, nil)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader: %v", err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock h=%d: %v", h, err)
		}
		prev = idx.GetNode(b.Header.BlockHash())
		m = append(m, prev)
	}

	// Side branch off m2, same length as the main chain, received later.
	sp := m[1]
	var s []*BlockNode
	for i := 0; i < 2; i++ {
		b := createTestBlockWithCoinbaseValue(t, params, sp, 49*100000000)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader side: %v", err)
		}
		if err := chainDB.StoreBlock(b.Header.BlockHash(), b); err != nil {
			t.Fatalf("StoreBlock side: %v", err)
		}
		idx.MarkDataStored(b.Header.BlockHash())
		sp = idx.GetNode(b.Header.BlockHash())
		s = append(s, sp)
	}

	if err := cm.InvalidateBlock(m[3].Hash); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}
	if best, _ := cm.BestBlock(); best != s[1].Hash {
		t.Fatalf("after invalidateblock(m4) tip = %s, want s4 %s", best.String()[:16], s[1].Hash.String()[:16])
	}
	if err := cm.ReconsiderBlock(m[3].Hash); err != nil {
		t.Fatalf("ReconsiderBlock: %v", err)
	}
	if best, _ := cm.BestBlock(); best != m[3].Hash {
		t.Fatalf("after reconsiderblock(m4) tip = %s, want m4 %s (equal work, m4 received first)",
			best.String()[:16], m[3].Hash.String()[:16])
	}
}

// TestInvalidatedBlockWithUnflaggedParentSurvivesRestart pins failed_reorg
// scenario E: m1-m2-m3a-m4a is the chain and s3-s4 an equal-work side branch.
// invalidateblock(m4a) flags only m4a; its parent m3a stays unflagged and off
// the active chain. After a restart m4a used to be an orphan at header
// restore and was dropped, so getblockheader / reconsiderblock answered
// "Block not found" where Core still has the block.
func TestInvalidatedBlockWithUnflaggedParentSurvivesRestart(t *testing.T) {
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
	var m []*BlockNode
	for h := 1; h <= 4; h++ {
		b := createTestBlock(t, params, prev, nil)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader: %v", err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock h=%d: %v", h, err)
		}
		prev = idx.GetNode(b.Header.BlockHash())
		m = append(m, prev)
	}
	sp := m[1]
	var s []*BlockNode
	for i := 0; i < 2; i++ {
		b := createTestBlockWithCoinbaseValue(t, params, sp, 49*100000000)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader side: %v", err)
		}
		if err := chainDB.StoreBlock(b.Header.BlockHash(), b); err != nil {
			t.Fatalf("StoreBlock side: %v", err)
		}
		idx.MarkDataStored(b.Header.BlockHash())
		sp = idx.GetNode(b.Header.BlockHash())
		s = append(s, sp)
	}
	if err := cm.InvalidateBlock(m[3].Hash); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}
	cleanStop(t, cm, utxoSet, chainDB)

	cm2, _ := reboot(t, params, chainDB)
	for _, h := range []wire.Hash256{m[3].Hash, m[2].Hash} {
		if cm2.GetHeaderIndex().GetNode(h) == nil {
			t.Fatalf("after restart: block %s missing from the index", h.String()[:16])
		}
	}
	if n := cm2.GetHeaderIndex().GetNode(m[3].Hash); !n.Status.IsInvalid() {
		t.Errorf("after restart: invalidated m4 not marked invalid")
	}
	if err := cm2.ReconsiderBlock(m[3].Hash); err != nil {
		t.Fatalf("ReconsiderBlock after restart: %v", err)
	}
}
