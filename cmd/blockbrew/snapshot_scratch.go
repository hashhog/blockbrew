package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// -load-snapshot coin isolation (security audit H5).
//
// The snapshot's coins are loaded and hashed in a SCRATCH database, never in
// the live UTXO keyspace, and reach UTXOPrefix only after the hash matches the
// assumeutxo commitment. Core does the same with a separate
// chainstate_snapshot LevelDB (validation.cpp:5650-5714) and deletes it on any
// failure (DeleteCoinsDBFromDisk, validation.cpp:5548). Before this, a corrupt,
// truncated or OOM-interrupted file left every coin it had parsed durable in
// UTXOPrefix: the next boot saw tip=genesis plus foreign coins, refused the
// genuine snapshot forever (the leftovers hashed with it) and rejected valid
// block 1 with bad-txns-BIP30, so the only way out was to wipe the datadir.

// snapshotPromoteBatchBytes bounds one batch of the scratch -> live copy.
// A var so tests can force the multi-batch path.
var snapshotPromoteBatchBytes = 64 << 20

// snapshotScratchPath is where a -load-snapshot on a Pebble-backed chainDB
// stages its coins: a sibling of the live directory (chaindata ->
// chaindata_snapshot), Core's chainstate -> chainstate_snapshot. Empty for a
// backend with no directory (in-memory), which stages in memory instead.
func snapshotScratchPath(chainDB *storage.ChainDB) string {
	if p, ok := chainDB.DB().(interface{ Path() string }); ok && p.Path() != "" {
		return p.Path() + "_snapshot"
	}
	return ""
}

// openSnapshotScratch opens an EMPTY scratch coins database for a snapshot
// load. A directory left by an earlier load that crashed is removed first:
// its contents were never authenticated. The returned cleanup closes the
// database and deletes it, and must run on every exit path.
func openSnapshotScratch(chainDB *storage.ChainDB) (*storage.ChainDB, func(), error) {
	path := snapshotScratchPath(chainDB)
	if path == "" {
		return storage.NewChainDB(storage.NewMemDB()), func() {}, nil
	}
	if err := os.RemoveAll(path); err != nil {
		return nil, nil, fmt.Errorf("remove stale snapshot scratch %s: %w", path, err)
	}
	pdb, err := storage.NewPebbleDB(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open snapshot scratch %s: %w", path, err)
	}
	cleanup := func() {
		if err := pdb.Close(); err != nil {
			log.Printf("WARNING: [snapshot] closing scratch coins db %s: %v", path, err)
		}
		if err := os.RemoveAll(path); err != nil {
			log.Printf("WARNING: [snapshot] removing scratch coins db %s: %v", path, err)
		}
	}
	return storage.NewChainDB(pdb), cleanup, nil
}

// removeStaleSnapshotScratch deletes a scratch directory a crashed
// -load-snapshot left behind. Its coins were never authenticated and are never
// read; it is only reclaimed disk (mainnet: the size of the UTXO set).
func removeStaleSnapshotScratch(chainDB *storage.ChainDB) {
	path := snapshotScratchPath(chainDB)
	if path == "" {
		return
	}
	if _, err := os.Stat(path); err != nil {
		return
	}
	log.Printf("[snapshot] removing %s left by an interrupted -load-snapshot (never authenticated, never used)", path)
	if err := os.RemoveAll(path); err != nil {
		log.Printf("WARNING: [snapshot] could not remove %s: %v", path, err)
	}
}

// liveHasCoins reports whether the live UTXO keyspace holds any coin.
func liveHasCoins(chainDB *storage.ChainDB) (bool, error) {
	it := chainDB.DB().NewIterator(storage.UTXOPrefix)
	defer it.Release()
	found := it.Next()
	return found, it.Error()
}

// promoteSnapshotCoins copies the authenticated coins from the scratch
// database into the live UTXO keyspace, and in the LAST batch stamps the coins
// marker, the chain pointer and the base's height-index entry together, so the
// datadir names the base only once every coin is durable. A crash before that
// batch leaves coins with no marker and the chain at genesis, which
// discardOrphanCoinsAtGenesis clears on the next boot.
//
// The live keyspace must be empty: the hash was computed over the scratch set
// alone, and adding it onto existing coins would publish a set nobody
// authenticated.
func promoteSnapshotCoins(scratch, live *storage.ChainDB, baseHash wire.Hash256, baseHeight int32) (uint64, error) {
	if has, err := liveHasCoins(live); err != nil {
		return 0, fmt.Errorf("check live coin set: %w", err)
	} else if has {
		return 0, errors.New("refusing to promote snapshot coins: the live UTXO set is not empty " +
			"(the snapshot hash covers the snapshot's coins only)")
	}
	it := scratch.DB().NewIterator(storage.UTXOPrefix)
	defer it.Release()
	batch := live.DB().NewBatch()
	pending := 0
	var copied uint64
	for it.Next() {
		batch.Put(it.Key(), it.Value())
		pending += len(it.Key()) + len(it.Value())
		copied++
		if pending >= snapshotPromoteBatchBytes {
			if err := batch.Write(); err != nil {
				return copied, fmt.Errorf("write snapshot coins to the live set: %w", err)
			}
			batch = live.DB().NewBatch()
			pending = 0
		}
	}
	if err := it.Error(); err != nil {
		return copied, fmt.Errorf("read scratch snapshot coins: %w", err)
	}
	tip := &storage.ChainState{BestHash: baseHash, BestHeight: baseHeight}
	live.SetCoinsTipBatch(batch, tip)
	live.SetChainStateBatch(batch, tip)
	live.SetBlockHeightBatch(batch, baseHeight, baseHash)
	if err := batch.Write(); err != nil {
		return copied, fmt.Errorf("write snapshot coins marker and chain state: %w", err)
	}
	return copied, nil
}

// discardOrphanCoinsAtGenesis runs at boot on a chainstate at genesis. Such a
// chainstate has connected no block, so any coin in the live keyspace that no
// marker accounts for is foreign: a -load-snapshot that crashed while copying
// (or, before the scratch-DB load, any rejected or interrupted one). Left in
// place it poisons the datadir for good. Deleting it is always safe: with no
// marker, recovery reconnects from genesis anyway.
//
// Coins ARE kept when the coins marker is above genesis (an IBD flush landed
// before the chain pointer moved; recovery adopts those blocks from the
// marker) or when an interrupted multi-batch flush is recorded (recovery fails
// closed on that and says why). Returns the number of coins deleted.
func discardOrphanCoinsAtGenesis(chainDB *storage.ChainDB) (int, error) {
	if marker, err := chainDB.GetCoinsTip(); err == nil && marker != nil && marker.BestHeight > 0 {
		return 0, nil
	} else if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return 0, fmt.Errorf("read coins marker: %w", err)
	}
	if rec, err := chainDB.GetCoinsFlushWindow(); err != nil {
		return 0, fmt.Errorf("read interrupted-flush record: %w", err)
	} else if rec != nil {
		return 0, nil
	}

	deleted := 0
	for {
		// Collect a bounded batch of keys, then delete them outside the
		// iterator so no write races its own scan.
		it := chainDB.DB().NewIterator(storage.UTXOPrefix)
		var keys [][]byte
		for len(keys) < 100_000 && it.Next() {
			keys = append(keys, append([]byte(nil), it.Key()...))
		}
		err := it.Error()
		it.Release()
		if err != nil {
			return deleted, fmt.Errorf("scan orphan coins: %w", err)
		}
		if len(keys) == 0 {
			break
		}
		batch := chainDB.DB().NewBatch()
		for _, k := range keys {
			batch.Delete(k)
		}
		if err := batch.Write(); err != nil {
			return deleted, fmt.Errorf("delete orphan coins: %w", err)
		}
		deleted += len(keys)
	}
	return deleted, nil
}
