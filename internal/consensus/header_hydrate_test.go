package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// buildAndPersistHeaders builds a valid header chain to height n on a builder
// index and persists each header by hash (StoreBlockHeader, as header sync
// does). It returns the per-height nodes (index 0 = height 1) so callers can
// choose which auxiliary indexes to populate. The chainstate tip is NOT set.
func buildAndPersistHeaders(t *testing.T, params *ChainParams, chainDB *storage.ChainDB, n int) []*BlockNode {
	t.Helper()
	builder := NewHeaderIndex(params)
	prev := builder.Genesis()
	nodes := make([]*BlockNode, 0, n)
	for i := 1; i <= n; i++ {
		blk := createTestBlock(t, params, prev, nil)
		node, err := builder.AddHeader(blk.Header, true)
		if err != nil {
			t.Fatalf("build header %d: %v", i, err)
		}
		hdr := blk.Header
		if err := chainDB.StoreBlockHeader(node.Hash, &hdr); err != nil {
			t.Fatalf("StoreBlockHeader %d: %v", i, err)
		}
		nodes = append(nodes, node)
		prev = node
	}
	return nodes
}

// TestHeaderIndexHydrateFromDB verifies Fix D: a fresh header index can be
// rehydrated from headers persisted by hash, so on restart loadChainState
// restores the saved tip immediately instead of marking the node pendingRecovery
// and re-downloading every header from peers.
func TestHeaderIndexHydrateFromDB(t *testing.T) {
	params := RegtestParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())

	const N = 30
	nodes := buildAndPersistHeaders(t, params, chainDB, N)
	tipHash := nodes[N-1].Hash
	// Also write the height index (as a fully-IBD'd node would).
	for _, n := range nodes {
		if err := chainDB.SetBlockHeight(n.Height, n.Hash); err != nil {
			t.Fatalf("SetBlockHeight %d: %v", n.Height, err)
		}
	}
	if err := chainDB.SetChainState(&storage.ChainState{BestHash: tipHash, BestHeight: N}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}

	idx := NewHeaderIndex(params)
	loaded, err := idx.HydrateFromDB(chainDB, tipHash, N)
	if err != nil {
		t.Fatalf("HydrateFromDB: %v", err)
	}
	if loaded != N {
		t.Errorf("loaded %d headers, want %d", loaded, N)
	}
	if idx.BestHeight() != N || idx.GetNode(tipHash) == nil {
		t.Errorf("hydrated tip height = %d (node present=%v), want %d/true",
			idx.BestHeight(), idx.GetNode(tipHash) != nil, N)
	}

	// End-to-end: loadChainState must now restore the tip with no pendingRecovery.
	cm := NewChainManager(ChainManagerConfig{Params: params, HeaderIndex: idx, ChainDB: chainDB})
	if _, h := cm.BestBlock(); h != N {
		t.Errorf("after hydration ChainManager tip = %d, want %d", h, N)
	}
	if cm.HasPendingRecovery() {
		t.Errorf("ChainManager still pendingRecovery after hydration — Fix D defeated")
	}
}

// TestHeaderIndexHydrateFromDB_SnapshotHeightGap is the regression for the
// observed live failure: a snapshot-bootstrapped chaindata has a GAP in the
// height->hash index below the snapshot base, but a COMPLETE header-by-hash
// store (header sync re-downloads from genesis). The by-hash walk must hydrate
// the full chain regardless of the height-index gap. (The earlier height-walk
// implementation loaded 0 headers here.)
func TestHeaderIndexHydrateFromDB_SnapshotHeightGap(t *testing.T) {
	params := RegtestParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())

	const N = 30
	const snapshotBase = 20 // height->hash only exists for snapshotBase+1..N
	nodes := buildAndPersistHeaders(t, params, chainDB, N)
	tipHash := nodes[N-1].Hash
	for _, n := range nodes {
		if n.Height <= snapshotBase {
			continue // simulate the snapshot gap: no height index below the base
		}
		if err := chainDB.SetBlockHeight(n.Height, n.Hash); err != nil {
			t.Fatalf("SetBlockHeight %d: %v", n.Height, err)
		}
	}
	if err := chainDB.SetChainState(&storage.ChainState{BestHash: tipHash, BestHeight: N}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}

	idx := NewHeaderIndex(params)
	loaded, err := idx.HydrateFromDB(chainDB, tipHash, N)
	if err != nil {
		t.Fatalf("HydrateFromDB: %v", err)
	}
	if loaded != N {
		t.Errorf("loaded %d headers despite height-index gap, want %d (by-hash walk must ignore the gap)", loaded, N)
	}
	if idx.BestHeight() != N {
		t.Errorf("hydrated tip height = %d, want %d", idx.BestHeight(), N)
	}
}

// TestHeaderIndexHydrateFromDB_NoPersistedHeaders verifies graceful degradation:
// when the saved best block's header chain is not on disk, hydration loads 0 and
// returns no error, so the node falls back to network header sync.
func TestHeaderIndexHydrateFromDB_NoPersistedHeaders(t *testing.T) {
	params := RegtestParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())
	idx := NewHeaderIndex(params)

	missing := wire.Hash256{0x01, 0x02, 0x03}
	loaded, err := idx.HydrateFromDB(chainDB, missing, 944183)
	if err != nil {
		t.Fatalf("HydrateFromDB on empty DB returned error: %v", err)
	}
	if loaded != 0 || idx.BestHeight() != 0 {
		t.Errorf("empty DB: loaded=%d bestHeight=%d, want 0/0", loaded, idx.BestHeight())
	}
}
