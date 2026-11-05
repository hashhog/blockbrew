package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// reconsiderRestartFixture builds failed_reorg scenario E's shape:
//
//	m1-m2-m3a-m4a          (connected, m4a the tip)
//	    \-s3-s4            (equal-work side branch, stored, never connected)
//
// on a Pebble DB, and returns the chain manager, its parts, and both branches.
func reconsiderRestartFixture(t *testing.T) (*ChainParams, *ChainManager, *UTXOSet, *storage.ChainDB, []*BlockNode, []*BlockNode) {
	t.Helper()
	base := *RegtestParams()
	base.SubsidyHalvingInterval = 210000
	params := &base

	idx := NewHeaderIndex(params)
	// Pebble, not MemDB: MemDB's batch applies every delete after every put,
	// so a reorg's delete+re-put of the same height key ends up deleted and
	// the reboot below would come back at the fork point. Pebble keeps batch
	// order, as the daemon sees it.
	db, err := storage.NewPebbleDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewPebbleDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	chainDB := storage.NewChainDB(db)
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
	return params, cm, utxoSet, chainDB, m, s
}

func tipStatus(t *testing.T, cm *ChainManager, hash wire.Hash256) (string, int32) {
	t.Helper()
	for _, tip := range cm.ChainTips() {
		if tip.Hash == hash {
			return tip.Status, tip.BranchLen
		}
	}
	t.Fatalf("getchaintips: %s is not listed", hash.String()[:16])
	return "", 0
}

// TestReconsiderAfterRestart_ConnectedSideBranchIsValidFork pins failed_reorg
// scenario E (row failed_reorg/e-reconsider/tips:<e4a>.status): after
// invalidateblock(m4a) the node moves to s4; across a restart m4a and its
// unflagged parent m3a are rebuilt from disk; reconsiderblock(m4a) clears the
// flag and, on a tie, the node stays on s4. Core then lists m4a as a
// "valid-fork" tip with branchlen 2, because both blocks were connected and
// LoadBlockIndex restored BLOCK_HAVE_DATA and BLOCK_VALID_SCRIPTS from disk
// (validation.cpp ResetBlockFailureFlags leaves those bits alone;
// rpc/blockchain.cpp getchaintips: !HaveNumChainTxs -> headers-only,
// IsValid(BLOCK_VALID_SCRIPTS) -> valid-fork). blockbrew rebuilt m3a with no
// data flag and m4a with no validity flag and reported "headers-only".
func TestReconsiderAfterRestart_ConnectedSideBranchIsValidFork(t *testing.T) {
	params, cm, utxoSet, chainDB, m, s := reconsiderRestartFixture(t)
	if err := cm.InvalidateBlock(m[3].Hash); err != nil {
		t.Fatalf("InvalidateBlock: %v", err)
	}
	if best, _ := cm.BestBlock(); best != s[1].Hash {
		t.Fatalf("tip after invalidateblock(m4a) = %s, want s4 %s", best.String()[:16], s[1].Hash.String()[:16])
	}
	cleanStop(t, cm, utxoSet, chainDB)

	cm2, _ := reboot(t, params, chainDB)
	if st, _ := tipStatus(t, cm2, m[3].Hash); st != ChainTipInvalid {
		t.Errorf("after restart, before reconsider: m4a status %q, want %q", st, ChainTipInvalid)
	}
	if err := cm2.ReconsiderBlock(m[3].Hash); err != nil {
		t.Fatalf("ReconsiderBlock after restart: %v", err)
	}
	if best, _ := cm2.BestBlock(); best != s[1].Hash {
		t.Fatalf("tip after reconsiderblock(m4a) = %s, want s4 %s (equal work, tip stays)",
			best.String()[:16], s[1].Hash.String()[:16])
	}
	st, branchLen := tipStatus(t, cm2, m[3].Hash)
	if st != ChainTipValidFork || branchLen != 2 {
		t.Errorf("after reconsiderblock(m4a): m4a tip = %q branchlen %d, want %q branchlen 2 (Core)",
			st, branchLen, ChainTipValidFork)
	}
}

// TestReconsiderAfterRestart_NeverConnectedBranchIsValidHeaders is the
// negative control for the fix above: the restored flags must come from what
// is on disk, not be granted to every rebuilt block. s3-s4 are stored but were
// never connected (no undo). invalidateblock(s4), restart, reconsiderblock(s4)
// must leave s4 "valid-headers" as in Core (BLOCK_HAVE_DATA without
// BLOCK_VALID_SCRIPTS), never "valid-fork".
func TestReconsiderAfterRestart_NeverConnectedBranchIsValidHeaders(t *testing.T) {
	params, cm, utxoSet, chainDB, m, s := reconsiderRestartFixture(t)
	if err := cm.InvalidateBlock(s[1].Hash); err != nil {
		t.Fatalf("InvalidateBlock(s4): %v", err)
	}
	cleanStop(t, cm, utxoSet, chainDB)

	cm2, _ := reboot(t, params, chainDB)
	if err := cm2.ReconsiderBlock(s[1].Hash); err != nil {
		t.Fatalf("ReconsiderBlock(s4) after restart: %v", err)
	}
	if best, _ := cm2.BestBlock(); best != m[3].Hash {
		t.Fatalf("tip after reconsiderblock(s4) = %s, want m4a %s", best.String()[:16], m[3].Hash.String()[:16])
	}
	if st, _ := tipStatus(t, cm2, s[1].Hash); st != ChainTipValidHeaders {
		t.Errorf("after reconsiderblock(s4): s4 status %q, want %q (stored, never connected)", st, ChainTipValidHeaders)
	}
}

// TestReconsiderAfterRestart_HeaderOnlySideBlockStaysHeadersOnly pins the
// other edge of restoreStoredFlagsLocked: a rebuilt block whose body is NOT
// stored (a header-only side block: header store entry, no body, no undo)
// must come back with no data or validity flags. h3 forks off m2 and only its
// header is on disk. invalidateblock(h3), restart: h3 is rebuilt from the
// header store and is still "invalid". reconsiderblock(h3): the failure flag
// is cleared and Core lists it "headers-only" (rpc/blockchain.cpp
// getchaintips: !HaveNumChainTxs -> headers-only), so blockbrew must not
// claim block data (StatusDataStored) or validity it does not have.
func TestReconsiderAfterRestart_HeaderOnlySideBlockStaysHeadersOnly(t *testing.T) {
	params, cm, utxoSet, chainDB, m, _ := reconsiderRestartFixture(t)
	idx := cm.headerIndex
	b := createTestBlockWithCoinbaseValue(t, params, m[1], 48*100000000)
	h3 := b.Header.BlockHash()
	if _, err := idx.AddHeader(b.Header, true); err != nil {
		t.Fatalf("AddHeader h3: %v", err)
	}
	if err := chainDB.StoreBlockHeader(h3, &b.Header); err != nil {
		t.Fatalf("StoreBlockHeader h3: %v", err)
	}
	if chainDB.HasBlock(h3) {
		t.Fatalf("fixture: h3 must be header-only (no body)")
	}
	if u, err := chainDB.ReadBlockUndo(h3); err == nil && u != nil {
		t.Fatalf("fixture: h3 must be header-only (no undo)")
	}
	if err := cm.InvalidateBlock(h3); err != nil {
		t.Fatalf("InvalidateBlock(h3): %v", err)
	}
	if best, _ := cm.BestBlock(); best != m[3].Hash {
		t.Fatalf("tip after invalidateblock(h3) = %s, want m4a", best.String()[:16])
	}
	cleanStop(t, cm, utxoSet, chainDB)

	cm2, _ := reboot(t, params, chainDB)
	n := cm2.headerIndex.GetNode(h3)
	if n == nil {
		t.Fatalf("after restart: h3 was dropped from the index (header is on disk)")
	}
	if st, _ := tipStatus(t, cm2, h3); st != ChainTipInvalid {
		t.Errorf("after restart, before reconsider: h3 status %q, want %q", st, ChainTipInvalid)
	}
	if n.Status&(StatusDataStored|StatusHaveUndo|StatusFullyValid) != 0 {
		t.Errorf("after restart: header-only h3 status %#x claims data/undo/validity it does not have", n.Status)
	}
	if err := cm2.ReconsiderBlock(h3); err != nil {
		t.Fatalf("ReconsiderBlock(h3) after restart: %v", err)
	}
	if best, _ := cm2.BestBlock(); best != m[3].Hash {
		t.Fatalf("tip after reconsiderblock(h3) = %s, want m4a", best.String()[:16])
	}
	if st, _ := tipStatus(t, cm2, h3); st != ChainTipHeadersOnly {
		t.Errorf("after reconsiderblock(h3): h3 status %q, want %q (Core: no block data)", st, ChainTipHeadersOnly)
	}
	if n.Status&StatusDataStored != 0 {
		t.Errorf("after reconsiderblock(h3): StatusDataStored set on a header-only block (status %#x)", n.Status)
	}
	if n.Status&StatusInvalid != 0 {
		t.Errorf("after reconsiderblock(h3): failure flag not cleared (status %#x)", n.Status)
	}
}
