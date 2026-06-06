package storage

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// buildTestChain creates a linked chain of `n` blocks (heights 0..n-1), stores
// each block body + its height->hash mapping in the ChainDB, and returns the
// per-height hashes. Each block's PrevBlock points at the previous block's
// hash so the rewind path (which follows PrevBlock) works.
func buildTestChain(t *testing.T, cdb *ChainDB, n int32) []wire.Hash256 {
	t.Helper()
	hashes := make([]wire.Hash256, n)
	var prev wire.Hash256
	for h := int32(0); h < n; h++ {
		block := createTestBlockWithScripts(h)
		block.Header.PrevBlock = prev
		hash := block.Header.BlockHash()
		if err := cdb.StoreBlock(hash, block); err != nil {
			t.Fatalf("StoreBlock height %d: %v", h, err)
		}
		if err := cdb.SetBlockHeight(h, hash); err != nil {
			t.Fatalf("SetBlockHeight %d: %v", h, err)
		}
		hashes[h] = hash
		prev = hash
	}
	return hashes
}

// TestIndexManagerCatchUpBehind is the core regression for the SLOW/INCORRECT
// resume gap: an index registered at startup that is BEHIND the chain tip must
// be walked forward to the tip by IndexManager.CatchUp (Core's
// BaseIndex::Sync). Pre-fix, no catch-up loop existed and the index would
// stay pinned at its persisted height until new live blocks arrived.
func TestIndexManagerCatchUpBehind(t *testing.T) {
	db := NewMemDB()
	defer db.Close()
	cdb := NewChainDB(db)

	const tip = int32(6)
	hashes := buildTestChain(t, cdb, tip+1) // heights 0..6

	// Register a blockfilterindex and seed only the genesis filter — exactly
	// what cmd/blockbrew/main.go does at startup before catch-up runs. This
	// leaves the index at height 0 while the chain is at height 6: the
	// "fell behind / freshly enabled on an already-synced node" scenario.
	mgr := NewIndexManager(cdb)
	idx := NewBlockFilterIndex(db)
	if err := mgr.RegisterIndex(idx); err != nil {
		t.Fatalf("RegisterIndex: %v", err)
	}
	if err := idx.WriteGenesis(createTestBlockWithScripts(0), hashes[0]); err != nil {
		t.Fatalf("WriteGenesis: %v", err)
	}
	if got := idx.BestHeight(); got != 0 {
		t.Fatalf("precondition: expected index at genesis (0), got %d", got)
	}

	// --- This is the assertion that FAILS pre-fix (no CatchUp existed). ---
	if err := mgr.CatchUp(tip, cdb.GetBlockHashByHeight); err != nil {
		t.Fatalf("CatchUp: %v", err)
	}

	if got := idx.BestHeight(); got != tip {
		t.Fatalf("after catch-up: expected index at tip %d, got %d", tip, got)
	}
	if got := idx.BestHash(); got != hashes[tip] {
		t.Fatalf("after catch-up: expected best hash %s, got %s",
			hashes[tip].String(), got.String())
	}

	// Every height in [0, tip] must now have a filter row.
	for h := int32(0); h <= tip; h++ {
		fd, err := idx.GetFilter(h)
		if err != nil {
			t.Fatalf("GetFilter height %d after catch-up: %v", h, err)
		}
		if fd.BlockHash != hashes[h] {
			t.Errorf("filter row height %d: block hash %s, want %s",
				h, fd.BlockHash.String(), hashes[h].String())
		}
	}

	// Idempotence: a second catch-up at the same tip must be a no-op.
	if err := mgr.CatchUp(tip, cdb.GetBlockHashByHeight); err != nil {
		t.Fatalf("second CatchUp: %v", err)
	}
	if got := idx.BestHeight(); got != tip {
		t.Fatalf("after idempotent catch-up: expected %d, got %d", tip, got)
	}
}

// TestIndexManagerCatchUpProducesLiveIdenticalFilters proves that a filter row
// written by the catch-up path is byte-identical to one written by the live
// WriteBlock hook for the same block. If catch-up fed real undo data while the
// live hook passes nil, the BIP-157 filter-header chain would diverge across a
// restart. This guards that they stay identical.
func TestIndexManagerCatchUpProducesLiveIdenticalFilters(t *testing.T) {
	db := NewMemDB()
	defer db.Close()
	cdb := NewChainDB(db)

	const tip = int32(4)
	hashes := buildTestChain(t, cdb, tip+1)

	// Reference index: written entirely through the live WriteBlock path
	// (genesis via WriteGenesis, then WriteBlock per height with nil undo,
	// exactly as the OnBlockConnected hook does).
	refDB := NewMemDB()
	defer refDB.Close()
	ref := NewBlockFilterIndex(refDB)
	if err := ref.Init(); err != nil {
		t.Fatalf("ref Init: %v", err)
	}
	if err := ref.WriteGenesis(createTestBlockWithScripts(0), hashes[0]); err != nil {
		t.Fatalf("ref WriteGenesis: %v", err)
	}
	for h := int32(1); h <= tip; h++ {
		blk, err := cdb.GetBlock(hashes[h])
		if err != nil {
			t.Fatalf("ref GetBlock %d: %v", h, err)
		}
		if err := ref.WriteBlock(blk, h, hashes[h], nil); err != nil {
			t.Fatalf("ref WriteBlock %d: %v", h, err)
		}
	}

	// Catch-up index: genesis seeded, then brought to tip by CatchUp.
	mgr := NewIndexManager(cdb)
	cu := NewBlockFilterIndex(db)
	if err := mgr.RegisterIndex(cu); err != nil {
		t.Fatalf("RegisterIndex: %v", err)
	}
	if err := cu.WriteGenesis(createTestBlockWithScripts(0), hashes[0]); err != nil {
		t.Fatalf("WriteGenesis: %v", err)
	}
	if err := mgr.CatchUp(tip, cdb.GetBlockHashByHeight); err != nil {
		t.Fatalf("CatchUp: %v", err)
	}

	// Filter headers must match height-for-height — this is the cross-restart
	// continuity guarantee.
	for h := int32(0); h <= tip; h++ {
		refHdr, err := ref.GetFilterHeader(h)
		if err != nil {
			t.Fatalf("ref GetFilterHeader %d: %v", h, err)
		}
		cuHdr, err := cu.GetFilterHeader(h)
		if err != nil {
			t.Fatalf("catchup GetFilterHeader %d: %v", h, err)
		}
		if refHdr != cuHdr {
			t.Fatalf("filter header height %d diverged: live=%s catchup=%s",
				h, refHdr.String(), cuHdr.String())
		}
	}
}

// TestIndexManagerCatchUpAhead exercises the rewind branch: an index that is
// AHEAD of the chain tip after an unclean exit must be walked back down to the
// tip (Core's BaseIndex::Rewind).
func TestIndexManagerCatchUpAhead(t *testing.T) {
	db := NewMemDB()
	defer db.Close()
	cdb := NewChainDB(db)

	const full = int32(6)
	hashes := buildTestChain(t, cdb, full+1) // heights 0..6

	mgr := NewIndexManager(cdb)
	idx := NewBlockFilterIndex(db)
	if err := mgr.RegisterIndex(idx); err != nil {
		t.Fatalf("RegisterIndex: %v", err)
	}
	if err := idx.WriteGenesis(createTestBlockWithScripts(0), hashes[0]); err != nil {
		t.Fatalf("WriteGenesis: %v", err)
	}
	// Advance the index all the way to height 6.
	if err := mgr.CatchUp(full, cdb.GetBlockHashByHeight); err != nil {
		t.Fatalf("initial CatchUp: %v", err)
	}
	if got := idx.BestHeight(); got != full {
		t.Fatalf("precondition: expected index at %d, got %d", full, got)
	}

	// Now simulate an unclean exit where the chainstate rolled back to height
	// 3 but the index committed past it. CatchUp must rewind the index to 3.
	const tip = int32(3)
	if err := mgr.CatchUp(tip, cdb.GetBlockHashByHeight); err != nil {
		t.Fatalf("rewind CatchUp: %v", err)
	}
	if got := idx.BestHeight(); got != tip {
		t.Fatalf("after rewind: expected index at tip %d, got %d", tip, got)
	}
	if got := idx.BestHash(); got != hashes[tip] {
		t.Fatalf("after rewind: expected best hash %s, got %s",
			hashes[tip].String(), got.String())
	}
	// The over-shot filter rows (heights 4..6) must be gone.
	for h := tip + 1; h <= full; h++ {
		if _, err := idx.GetFilter(h); err == nil {
			t.Errorf("filter row height %d should have been rewound away", h)
		}
	}
}
