package main

import (
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestPrepareImportChain_RefusesWhenCoinsMarkerLeadsTip pins finding #5.
//
// import-blocks gated purely on the chain-tip POINTER: any frame at or below it
// was skipped, everything above went to ConnectBlock. That pointer is only a
// LOWER bound on what the persisted UTXO set reflects — coins are also flushed
// without advancing it — so on a marker-lag datadir (the 2026-08-15 genesis rig
// booted with coins durable through 958,794 and the pointer at 958,000) every
// frame in (pointer, marker] was re-applied.
//
// It is also the one boot path that never ran crash recovery:
// RecoverFromPersistedBlocks has a single call site, normal daemon startup.
//
// Here the block BODIES for the gap are absent, so recovery cannot close it.
// prepareImportChain must then REFUSE rather than let the loop connect across
// the gap: there is nothing to adopt over, and connecting is the corruption.
func TestPrepareImportChain_RefusesWhenCoinsMarkerLeadsTip(t *testing.T) {
	params := consensus.RegtestParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())
	idx := consensus.NewHeaderIndex(params)

	genesis := idx.Genesis()
	if err := chainDB.StoreBlock(genesis.Hash, params.GenesisBlock); err != nil {
		t.Fatalf("StoreBlock genesis: %v", err)
	}
	if err := chainDB.SetBlockHeight(0, genesis.Hash); err != nil {
		t.Fatalf("SetBlockHeight: %v", err)
	}
	if err := chainDB.SetChainState(&storage.ChainState{BestHash: genesis.Hash, BestHeight: 0}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}

	// The coins marker says the persisted set is durable through height 500,
	// and the height map agrees about the hash there (so the marker is
	// trustworthy) — but no block body exists for 1..500.
	marker := wire.Hash256{0xab, 0xcd}
	if err := chainDB.SetBlockHeight(500, marker); err != nil {
		t.Fatalf("SetBlockHeight 500: %v", err)
	}
	batch := chainDB.NewBatch()
	chainDB.SetCoinsTipBatch(batch, &storage.ChainState{BestHash: marker, BestHeight: 500})
	if err := batch.Write(); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	chainMgr := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     chainDB,
		UTXOSet:     consensus.NewUTXOSet(chainDB),
	})

	if _, h, ok := chainMgr.DurableCoinsTip(); !ok || h != 500 {
		t.Fatalf("precondition: durable coins marker = %d (usable=%v), want 500/true", h, ok)
	}

	got, err := prepareImportChain(chainMgr)
	if err == nil {
		t.Fatalf("prepareImportChain returned tipHeight=%d and NO error, so the import "+
			"loop would connect blocks 1..500 over a UTXO set that already reflects "+
			"them — re-adding coinbases later blocks in that span already spent", got)
	}
	if !strings.Contains(err.Error(), "refusing to import") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// TestPrepareImportChain_AllowsCleanDatadir keeps the guard honest: an ordinary
// datadir whose marker does not lead the tip must import normally.
func TestPrepareImportChain_AllowsCleanDatadir(t *testing.T) {
	params := consensus.RegtestParams()
	chainDB := storage.NewChainDB(storage.NewMemDB())
	idx := consensus.NewHeaderIndex(params)

	genesis := idx.Genesis()
	if err := chainDB.StoreBlock(genesis.Hash, params.GenesisBlock); err != nil {
		t.Fatalf("StoreBlock genesis: %v", err)
	}
	if err := chainDB.SetBlockHeight(0, genesis.Hash); err != nil {
		t.Fatalf("SetBlockHeight: %v", err)
	}
	if err := chainDB.SetChainState(&storage.ChainState{BestHash: genesis.Hash, BestHeight: 0}); err != nil {
		t.Fatalf("SetChainState: %v", err)
	}
	batch := chainDB.NewBatch()
	chainDB.SetCoinsTipBatch(batch, &storage.ChainState{BestHash: genesis.Hash, BestHeight: 0})
	if err := batch.Write(); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	chainMgr := consensus.NewChainManager(consensus.ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     chainDB,
		UTXOSet:     consensus.NewUTXOSet(chainDB),
	})

	got, err := prepareImportChain(chainMgr)
	if err != nil {
		t.Fatalf("prepareImportChain refused a clean datadir: %v", err)
	}
	if got != 0 {
		t.Errorf("tipHeight = %d, want 0", got)
	}
}
