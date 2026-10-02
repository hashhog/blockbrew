package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// invalidateblock must survive a restart (Core: InvalidateBlock sets
// BLOCK_FAILED_VALID, the dirty block index is written by WriteBatchSync, and
// LoadBlockIndex reads it back), and reconsiderblock must clear it — for the
// block, its ancestors AND its descendants (ResetBlockFailureFlags) — also
// across a restart.
//
// Observed on regtest with tools/crash-restart-repro/intrablock-disconnect-probe.py
// before the fix: after invalidateblock(A2), invalidateblock(A1) and a clean
// restart, blockbrew came back at A2. Two causes: the flags lived in memory
// only, and DisconnectBlock left the height index entries N:<h> of the
// disconnected blocks behind, which the boot replay (RecoverFromPersistedBlocks)
// read as unflushed blocks ahead of the tip and reconnected.

// invalidateFixture: genesis..5 then A6, A7 connected; flushed.
func invalidateFixture(t *testing.T, params *ChainParams) (*storage.ChainDB, *ChainManager, *UTXOSet, []wire.Hash256) {
	t.Helper()
	idx := NewHeaderIndex(params)
	chainDB := storage.NewChainDB(storage.NewMemDB())
	utxoSet := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxoSet,
	})
	cm.SetIBD(false)
	var hashes []wire.Hash256
	prev := idx.Genesis()
	for h := 1; h <= 7; h++ {
		b := createTestBlock(t, params, prev, nil)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatalf("AddHeader %d: %v", h, err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatalf("ConnectBlock %d: %v", h, err)
		}
		prev = idx.GetNode(b.Header.BlockHash())
		hashes = append(hashes, prev.Hash)
	}
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	return chainDB, cm, utxoSet, hashes // hashes[i] is height i+1
}

// cleanStop mirrors the shutdown flush: coins + chainstate durable.
func cleanStop(t *testing.T, cm *ChainManager, utxoSet *UTXOSet, chainDB *storage.ChainDB) {
	t.Helper()
	if err := utxoSet.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	h, ht := cm.BestBlock()
	if err := chainDB.SetChainState(&storage.ChainState{BestHash: h, BestHeight: ht}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}
}

func TestInvalidateBlockSurvivesRestart(t *testing.T) {
	params := RegtestParams()
	chainDB, cm, utxoSet, hs := invalidateFixture(t, params)
	a1, a2 := hs[5], hs[6] // heights 6, 7

	if err := cm.InvalidateBlock(a2); err != nil {
		t.Fatalf("InvalidateBlock(A2): %v", err)
	}
	if err := cm.InvalidateBlock(a1); err != nil {
		t.Fatalf("InvalidateBlock(A1): %v", err)
	}
	if got, h := cm.BestBlock(); got != hs[4] || h != 5 {
		t.Fatalf("before restart: tip %d, want 5", h)
	}
	cleanStop(t, cm, utxoSet, chainDB)

	cm2, _ := reboot(t, params, chainDB)
	if got, h := cm2.BestBlock(); got != hs[4] || h != 5 {
		t.Fatalf("after restart: tip %s@%d, want height 5 — the invalidated branch was reconnected",
			got.String()[:16], h)
	}
	for i, hh := range []wire.Hash256{a1, a2} {
		n := cm2.GetHeaderIndex().GetNode(hh)
		if n == nil {
			t.Fatalf("after restart: invalidated block A%d missing from the index (reconsiderblock could not find it)", i+1)
		}
		if !n.Status.IsInvalid() {
			t.Errorf("after restart: A%d is not marked invalid (status %#x)", i+1, n.Status)
		}
	}
	if _, err := chainDB.GetBlockHashByHeight(6); err == nil {
		t.Errorf("height index still maps height 6 after it was disconnected")
	}
}

func TestReconsiderBlockClearsDescendantsAndSurvivesRestart(t *testing.T) {
	params := RegtestParams()
	chainDB, cm, utxoSet, hs := invalidateFixture(t, params)
	a1, a2 := hs[5], hs[6]

	if err := cm.InvalidateBlock(a2); err != nil {
		t.Fatalf("InvalidateBlock(A2): %v", err)
	}
	if err := cm.InvalidateBlock(a1); err != nil {
		t.Fatalf("InvalidateBlock(A1): %v", err)
	}
	cleanStop(t, cm, utxoSet, chainDB)

	// Restart while invalidated, then reconsider A1: Core clears A1 and its
	// explicitly-invalidated descendant A2 and returns to A2.
	cm2, utxo2 := reboot(t, params, chainDB)
	if err := cm2.ReconsiderBlock(a1); err != nil {
		t.Fatalf("ReconsiderBlock(A1) after restart: %v", err)
	}
	if got, h := cm2.BestBlock(); got != a2 {
		t.Fatalf("after reconsiderblock(A1): tip height %d, want A2 (7)", h)
	}
	cleanStop(t, cm2, utxo2, chainDB)

	cm3, _ := reboot(t, params, chainDB)
	if got, h := cm3.BestBlock(); got != a2 {
		t.Fatalf("after reconsider + restart: tip height %d, want A2 (7)", h)
	}
	if f, err := chainDB.ReadBlockFailures(); err != nil || len(f) != 0 {
		t.Errorf("persisted failure flags after reconsiderblock = %v (err %v), want none", f, err)
	}
}

// Without a restart: reconsiderblock(A1) must also clear the explicit flag on
// the descendant A2 (it used to clear only the child flag, leaving the tip at A1).
func TestReconsiderBlockClearsExplicitlyInvalidDescendant(t *testing.T) {
	params := RegtestParams()
	_, cm, _, hs := invalidateFixture(t, params)
	a1, a2 := hs[5], hs[6]
	if err := cm.InvalidateBlock(a2); err != nil {
		t.Fatal(err)
	}
	if err := cm.InvalidateBlock(a1); err != nil {
		t.Fatal(err)
	}
	if err := cm.ReconsiderBlock(a1); err != nil {
		t.Fatal(err)
	}
	if got, h := cm.BestBlock(); got != a2 {
		t.Fatalf("tip height %d, want A2 (7)", h)
	}
}
