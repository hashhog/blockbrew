package consensus

import (
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// newAdoptBoundRig: real ChainManager over a DB-backed UTXO set with block 1
// connected and flushed (so its coinbase is durable evidence) and block 2 —
// which re-includes nothing, but whose coinbase we plant on disk as "evidence"
// — header-indexed but not connected.
func newAdoptBoundRig(t *testing.T) (*ChainManager, *UTXOSet, *storage.ChainDB, *BlockNode, *wire.MsgBlock) {
	t.Helper()
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())
	utxoSet := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxoSet,
	})
	cm.SetIBD(false)

	block1 := createTestBlock(t, params, idx.Genesis(), nil)
	if _, err := idx.AddHeader(block1.Header, true); err != nil {
		t.Fatalf("AddHeader block1: %v", err)
	}
	if err := cm.ConnectBlock(block1); err != nil {
		t.Fatalf("ConnectBlock block1: %v", err)
	}
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	node1 := idx.GetNode(block1.Header.BlockHash())

	block2 := createTestBlock(t, params, node1, nil)
	if _, err := idx.AddHeader(block2.Header, true); err != nil {
		t.Fatalf("AddHeader block2: %v", err)
	}
	// Plant block 2's coinbase output on disk: the evidence probe will find it.
	// What it must NOT do is accept that evidence for a block above the view's
	// applied tip — durable outputs of a txid prove that SOME block confirmed
	// that transaction, not that THIS block was applied.
	cb2 := block2.Transactions[0]
	b := chainDB.NewBatch()
	b.Put(storage.MakeUTXOKey(wire.OutPoint{Hash: cb2.TxHash(), Index: 0}),
		SerializeUTXOEntry(&UTXOEntry{
			Amount: cb2.TxOut[0].Value, PkScript: cb2.TxOut[0].PkScript,
			Height: node1.Height + 1, IsCoinbase: true,
		}))
	if err := b.Write(); err != nil {
		t.Fatalf("plant: %v", err)
	}
	return cm, utxoSet, chainDB, node1, block2
}

// TestAdoptAppliedBlock_RefusesAboveAppliedTip: the view's applied-through
// marker is block 1 (the connect set it); block 2 sits above it, so it cannot
// have been applied in a prior session and must be refused even with durable
// output evidence. Pre-fix it was adopted and rolled forward unchecked.
func TestAdoptAppliedBlock_RefusesAboveAppliedTip(t *testing.T) {
	cm, utxoSet, _, node1, block2 := newAdoptBoundRig(t)
	if _, h, ok := utxoSet.AppliedTip(); !ok || h != node1.Height {
		t.Fatalf("precondition: applied tip = (%d,%v), want block 1", h, ok)
	}
	err := cm.AdoptAppliedBlock(block2)
	if err == nil || !strings.Contains(err.Error(), "above the UTXO view's applied tip") {
		t.Fatalf("AdoptAppliedBlock = %v, want the above-applied-tip refusal", err)
	}
	if cm.TipNode().Height != node1.Height {
		t.Fatalf("tip moved on a refused adoption: %d", cm.TipNode().Height)
	}
}

// TestAdoptAppliedBlock_AdoptsAtOrBelowFloor is the valid-block direction: the
// same block, once the view's bound covers it (an interrupted flush recorded up
// to block 2), is still adopted — marker-lag repair keeps working.
func TestAdoptAppliedBlock_AdoptsAtOrBelowFloor(t *testing.T) {
	cm, utxoSet, _, node1, block2 := newAdoptBoundRig(t)
	utxoSet.RaiseAppliedFloor(node1.Height + 1)
	if err := cm.AdoptAppliedBlock(block2); err != nil {
		t.Fatalf("AdoptAppliedBlock: %v", err)
	}
	if cm.TipNode().Height != node1.Height+1 {
		t.Fatalf("tip = %d, want %d", cm.TipNode().Height, node1.Height+1)
	}
}

// TestAdoptAppliedBlock_RefusesWithoutBound: a view with neither an applied
// tip nor a floor cannot bound what disk reflects; fail closed (no adoption),
// and not as a verdict on the block.
func TestAdoptAppliedBlock_RefusesWithoutBound(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: NewUTXOSet(chainDB),
	})
	block1 := createTestBlock(t, params, idx.Genesis(), nil)
	if _, err := idx.AddHeader(block1.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if err := cm.AdoptAppliedBlock(block1); err == nil || !strings.Contains(err.Error(), "no applied tip or floor") {
		t.Fatalf("AdoptAppliedBlock = %v, want the no-applied-bound refusal", err)
	}
}

// TestAdoptAppliedBlock_RefusesOffMarkerAncestry: a block at a height the
// applied tip covers, but not on the applied block's ancestry, is not what the
// view reflects — refuse it.
func TestAdoptAppliedBlock_RefusesOffMarkerAncestry(t *testing.T) {
	cm, utxoSet, chainDB, node1, block2 := newAdoptBoundRig(t)
	params := RegtestParams()
	node2 := cm.headerIndex.GetNode(block2.Header.BlockHash())
	block3 := createTestBlock(t, params, node2, nil)
	n3, err := cm.headerIndex.AddHeader(block3.Header, true)
	if err != nil {
		t.Fatalf("AddHeader block3: %v", err)
	}
	// A sibling of block 2 (same parent, different body) that the view's
	// marker (block 3, on block 2's branch) does not cover.
	sib := createTestBlockWithCoinbaseValue(t, params, node1, block2.Transactions[0].TxOut[0].Value-1)
	if _, err := cm.headerIndex.AddHeader(sib.Header, true); err != nil {
		t.Fatalf("AddHeader sibling: %v", err)
	}
	// Its coinbase output is on disk too, so output evidence alone would
	// "prove" it applied.
	cbs := sib.Transactions[0]
	b := chainDB.NewBatch()
	b.Put(storage.MakeUTXOKey(wire.OutPoint{Hash: cbs.TxHash(), Index: 0}),
		SerializeUTXOEntry(&UTXOEntry{
			Amount: cbs.TxOut[0].Value, PkScript: cbs.TxOut[0].PkScript,
			Height: node1.Height + 1, IsCoinbase: true,
		}))
	if err := b.Write(); err != nil {
		t.Fatalf("plant: %v", err)
	}
	utxoSet.SetAppliedTip(n3.Hash, n3.Height)
	if err := cm.AdoptAppliedBlock(sib); err == nil || !strings.Contains(err.Error(), "not an ancestor") {
		t.Fatalf("AdoptAppliedBlock(sibling) = %v, want the not-on-marker-ancestry refusal", err)
	}
	if cm.TipNode().Height != node1.Height {
		t.Fatalf("tip moved on a refused adoption: %d", cm.TipNode().Height)
	}
}
