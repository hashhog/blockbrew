package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
)

// Tests for task #126: fold StoreBlockAt into the ConnectBlock atomic batch.
//
// The contract under test:
//   * ConnectBlock persists the block body as part of its own write batch.
//     A caller that has NOT pre-stored the body via chainDB.StoreBlock /
//     StoreBlockAt should still observe HasBlock(hash) == true after a
//     successful ConnectBlock returns.
//   * The body store is idempotent: pre-storing the body, then calling
//     ConnectBlock, must NOT double-write or surface an error.
//   * Genesis is included: ConnectBlock(genesis) folds the body in too.
//
// Pre-#126, the unsolicited-block arm in sync.go pre-stored the body via
// chainDB.StoreBlockAt; ConnectBlock did not. With #126 ConnectBlock
// becomes the canonical writer for the active-tip path. The
// StoreBlockAtBatch path runs idempotently from sync.go's retained
// pre-store on the inflight/queued arm (side-branch staging) and from
// ConnectBlock on the active-tip arm.

// TestW126_ConnectBlockStoresBodyWithoutPreStore verifies that a block
// connected without any prior chainDB.StoreBlock call still becomes
// retrievable via chainDB.GetBlock after a successful ConnectBlock.
// Models the post-#126 unsolicited-block arm behavior: validation is
// handed the block straight off the wire, and ConnectBlock owns the
// body persistence end-to-end.
func TestW126_ConnectBlockStoresBodyWithoutPreStore(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()
	block := createTestBlock(t, params, genesis, nil)
	blockHash := block.Header.BlockHash()

	// Add header — required precondition for ConnectBlock, mirrors the
	// sync.go path where headers-first sync registers the header before
	// the body arrives.
	if _, err := idx.AddHeader(block.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}

	// DELIBERATELY skip db.StoreBlock — this is the whole point of #126.
	if db.HasBlock(blockHash) {
		t.Fatalf("precondition violated: body unexpectedly already in storage")
	}

	if err := cm.ConnectBlock(block); err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}

	// Post-condition: body is now retrievable. Folded into the ConnectBlock
	// atomic batch alongside undo data + height map + UTXOs + chainstate.
	if !db.HasBlock(blockHash) {
		t.Errorf("HasBlock returned false after ConnectBlock — body not folded into atomic batch")
	}

	got, err := db.GetBlock(blockHash)
	if err != nil {
		t.Fatalf("GetBlock after ConnectBlock: %v", err)
	}
	if got.Header.BlockHash() != blockHash {
		t.Errorf("GetBlock returned different block hash: got %s want %s",
			got.Header.BlockHash().String()[:16], blockHash.String()[:16])
	}

	// Confirm StatusDataStored is reflected on the in-memory headerindex
	// node so recalculateBestTipLocked treats this tip as data-present.
	node := idx.GetNode(blockHash)
	if node == nil {
		t.Fatalf("header index lost node after ConnectBlock")
	}
	if node.Status&StatusDataStored == 0 {
		t.Errorf("StatusDataStored not set after ConnectBlock — in-memory flag must follow durable on-disk write")
	}
}

// TestW126_ConnectBlockBodyStoreIdempotent verifies the post-#126
// invariant that pre-storing the body (sync.go's retained inflight/queued
// arm pre-store) does NOT cause double-write or any error path when
// ConnectBlock subsequently fires.
func TestW126_ConnectBlockBodyStoreIdempotent(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	db := storage.NewChainDB(storage.NewMemDB())

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()
	block := createTestBlock(t, params, genesis, nil)
	blockHash := block.Header.BlockHash()

	if _, err := idx.AddHeader(block.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}

	// Pre-store the body (mirrors the inflight/queued arm in sync.go).
	if err := db.StoreBlock(blockHash, block); err != nil {
		t.Fatalf("StoreBlock: %v", err)
	}
	if !db.HasBlock(blockHash) {
		t.Fatalf("precondition violated: HasBlock returned false after StoreBlock")
	}

	// ConnectBlock must succeed — StoreBlockAtBatch's HasBlock fast-path
	// turns the body store into a no-op when the body is already on disk.
	if err := cm.ConnectBlock(block); err != nil {
		t.Fatalf("ConnectBlock with pre-stored body: %v", err)
	}

	// Block is still retrievable; no corruption from the second-write attempt.
	got, err := db.GetBlock(blockHash)
	if err != nil {
		t.Fatalf("GetBlock after double-write: %v", err)
	}
	if got.Header.BlockHash() != blockHash {
		t.Errorf("GetBlock returned different block hash: got %s want %s",
			got.Header.BlockHash().String()[:16], blockHash.String()[:16])
	}
}

// TestW126_FlatfileBackedConnectBlockStoresBody verifies the
// flat-file persistence path (production architecture): when the
// ChainDB has a BlockStore attached, ConnectBlock writes the block
// bytes to blk*.dat and stages the position-index PUT on the same
// Pebble batch as the chainstate.
func TestW126_FlatfileBackedConnectBlockStoresBody(t *testing.T) {
	dataDir := t.TempDir()
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	memDB := storage.NewMemDB()
	bs, err := storage.NewBlockStore(dataDir, 0xdeadbeef, memDB)
	if err != nil {
		t.Fatalf("NewBlockStore: %v", err)
	}
	db := storage.NewChainDB(memDB)
	db.SetBlockStore(bs)

	cm := NewChainManager(ChainManagerConfig{
		Params:      params,
		HeaderIndex: idx,
		ChainDB:     db,
	})

	genesis := idx.Genesis()
	block := createTestBlock(t, params, genesis, nil)
	blockHash := block.Header.BlockHash()

	if _, err := idx.AddHeader(block.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}

	if db.HasBlock(blockHash) {
		t.Fatalf("precondition violated: body unexpectedly already in storage")
	}

	if err := cm.ConnectBlock(block); err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}

	// On the flat-file path, HasBlock probes the block-position index in
	// Pebble (set via IndexBlockBatch → staged on the ConnectBlock batch).
	if !db.HasBlock(blockHash) {
		t.Errorf("flat-file: HasBlock false after ConnectBlock — position index not committed in batch")
	}
	if !bs.HasBlock(blockHash) {
		t.Errorf("flat-file: BlockStore.HasBlock false after ConnectBlock")
	}

	// And the body is actually readable end-to-end.
	got, err := db.GetBlock(blockHash)
	if err != nil {
		t.Fatalf("GetBlock from flat-file store: %v", err)
	}
	if got.Header.BlockHash() != blockHash {
		t.Errorf("GetBlock returned different block hash: got %s want %s",
			got.Header.BlockHash().String()[:16], blockHash.String()[:16])
	}
}
