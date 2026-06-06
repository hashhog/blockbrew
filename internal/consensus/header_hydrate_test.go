package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
)

// TestHeaderIndexHydrateFromDB verifies Fix D: a fresh header index can be
// rehydrated from the headers persisted in the chain DB, so that on restart
// ChainManager.loadChainState restores the saved tip immediately instead of
// marking the node pendingRecovery and re-downloading every header from peers.
func TestHeaderIndexHydrateFromDB(t *testing.T) {
	params := RegtestParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())

	// Build a valid header chain to height N and persist it the way normal
	// operation does: header-by-hash (StoreBlockHeader, written by header sync)
	// + height->hash (SetBlockHeight, written by connect) + the chainstate tip.
	const N = 30
	builder := NewHeaderIndex(params)
	prev := builder.Genesis()
	var tipHash [32]byte
	for i := 1; i <= N; i++ {
		blk := createTestBlock(t, params, prev, nil)
		node, err := builder.AddHeader(blk.Header, true)
		if err != nil {
			t.Fatalf("build header %d: %v", i, err)
		}
		if err := chainDB.StoreBlockHeader(node.Hash, &blk.Header); err != nil {
			t.Fatalf("StoreBlockHeader %d: %v", i, err)
		}
		if err := chainDB.SetBlockHeight(node.Height, node.Hash); err != nil {
			t.Fatalf("SetBlockHeight %d: %v", i, err)
		}
		prev = node
		tipHash = node.Hash
	}
	if err := chainDB.SetChainState(&storage.ChainState{BestHash: tipHash, BestHeight: N}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}

	// Fresh index (genesis only) — models a process restart.
	idx := NewHeaderIndex(params)
	if idx.BestHeight() != 0 {
		t.Fatalf("precondition: fresh index not at genesis (height=%d)", idx.BestHeight())
	}

	loaded, err := idx.HydrateFromDB(chainDB, N)
	if err != nil {
		t.Fatalf("HydrateFromDB: %v", err)
	}
	if loaded != N {
		t.Errorf("loaded %d headers, want %d", loaded, N)
	}
	if idx.BestHeight() != N {
		t.Errorf("hydrated index tip height = %d, want %d", idx.BestHeight(), N)
	}
	if idx.GetNode(tipHash) == nil {
		t.Errorf("hydrated index missing the saved tip %x", tipHash[:6])
	}

	// End-to-end: with the index hydrated, NewChainManager's loadChainState must
	// restore the tip immediately and NOT enter pendingRecovery (which is what
	// triggers the full network header re-download Fix D eliminates). Without
	// the HydrateFromDB call above, the index would be genesis-only here and the
	// tip would stay at 0 with pendingRecovery=true.
	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     chainDB,
	})
	if _, h := cm.BestBlock(); h != N {
		t.Errorf("after hydration, ChainManager tip height = %d, want %d "+
			"(loadChainState should restore the saved tip immediately)", h, N)
	}
	if cm.HasPendingRecovery() {
		t.Errorf("ChainManager still pendingRecovery after hydration — Fix D defeated")
	}
}

// TestHeaderIndexHydrateFromDB_NoPersistedHeaders verifies graceful degradation:
// a chainstate with no persisted height index (e.g. a fresh AssumeUTXO-snapshot
// chaindata) hydrates 0 headers and reports no error, so the node simply falls
// back to network header sync.
func TestHeaderIndexHydrateFromDB_NoPersistedHeaders(t *testing.T) {
	params := RegtestParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())
	idx := NewHeaderIndex(params)

	loaded, err := idx.HydrateFromDB(chainDB, 944183)
	if err != nil {
		t.Fatalf("HydrateFromDB on empty DB returned error: %v", err)
	}
	if loaded != 0 {
		t.Errorf("loaded %d headers from empty DB, want 0", loaded)
	}
	if idx.BestHeight() != 0 {
		t.Errorf("index advanced past genesis with no persisted headers (height=%d)", idx.BestHeight())
	}
}
