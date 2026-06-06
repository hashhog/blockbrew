package storage

import (
	"fmt"
	"log"
	"sync"

	"github.com/hashhog/blockbrew/internal/wire"
)

// IndexStatus represents the sync status of an index.
type IndexStatus struct {
	Name       string
	Synced     bool
	BestHeight int32
	BestHash   wire.Hash256
}

// Index is the interface for optional block indexes.
type Index interface {
	// Name returns the name of this index.
	Name() string

	// Init initializes the index, loading state from the database.
	Init() error

	// WriteBlock processes a newly connected block.
	WriteBlock(block *wire.MsgBlock, height int32, blockHash wire.Hash256, undo *BlockUndo) error

	// RevertBlock reverts a disconnected block.
	RevertBlock(block *wire.MsgBlock, height int32, blockHash wire.Hash256, undo *BlockUndo) error

	// BestHeight returns the height of the last indexed block.
	BestHeight() int32

	// BestHash returns the hash of the last indexed block.
	BestHash() wire.Hash256

	// IsSynced returns true if the index is caught up to the chain tip.
	IsSynced() bool

	// SetSynced marks the index as synced to the given height/hash.
	SetSynced(height int32, hash wire.Hash256)

	// Status returns the current index status.
	Status() IndexStatus
}

// BaseIndex provides common functionality for all indexes.
type BaseIndex struct {
	mu         sync.RWMutex
	name       string
	db         DB
	bestHeight int32
	bestHash   wire.Hash256
	synced     bool
}

// NewBaseIndex creates a new base index with the given name.
func NewBaseIndex(name string, db DB) *BaseIndex {
	return &BaseIndex{
		name:       name,
		db:         db,
		bestHeight: -1,
	}
}

// Name returns the index name.
func (b *BaseIndex) Name() string {
	return b.name
}

// BestHeight returns the height of the last indexed block.
func (b *BaseIndex) BestHeight() int32 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.bestHeight
}

// BestHash returns the hash of the last indexed block.
func (b *BaseIndex) BestHash() wire.Hash256 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.bestHash
}

// IsSynced returns true if the index is caught up to the chain tip.
func (b *BaseIndex) IsSynced() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.synced
}

// SetSynced marks the index as synced to the given height/hash.
func (b *BaseIndex) SetSynced(height int32, hash wire.Hash256) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bestHeight = height
	b.bestHash = hash
	b.synced = true
}

// UpdateBest updates the best height/hash after successful index update.
func (b *BaseIndex) UpdateBest(height int32, hash wire.Hash256) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bestHeight = height
	b.bestHash = hash
}

// Status returns the current index status.
func (b *BaseIndex) Status() IndexStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return IndexStatus{
		Name:       b.name,
		Synced:     b.synced,
		BestHeight: b.bestHeight,
		BestHash:   b.bestHash,
	}
}

// DB returns the underlying database.
func (b *BaseIndex) DB() DB {
	return b.db
}

// IndexManager manages all optional indexes.
type IndexManager struct {
	mu      sync.RWMutex
	indexes map[string]Index
	chainDB *ChainDB
}

// NewIndexManager creates a new index manager.
func NewIndexManager(chainDB *ChainDB) *IndexManager {
	return &IndexManager{
		indexes: make(map[string]Index),
		chainDB: chainDB,
	}
}

// RegisterIndex registers an index with the manager.
func (m *IndexManager) RegisterIndex(idx Index) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.indexes[idx.Name()]; exists {
		return fmt.Errorf("index %s already registered", idx.Name())
	}

	if err := idx.Init(); err != nil {
		return fmt.Errorf("failed to initialize index %s: %w", idx.Name(), err)
	}

	m.indexes[idx.Name()] = idx
	log.Printf("index: registered %s (best height: %d)", idx.Name(), idx.BestHeight())
	return nil
}

// GetIndex returns an index by name, or nil if not found.
func (m *IndexManager) GetIndex(name string) Index {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.indexes[name]
}

// AllIndexes returns all registered indexes.
func (m *IndexManager) AllIndexes() []Index {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Index, 0, len(m.indexes))
	for _, idx := range m.indexes {
		result = append(result, idx)
	}
	return result
}

// BlockConnected notifies all indexes of a newly connected block.
func (m *IndexManager) BlockConnected(block *wire.MsgBlock, height int32, hash wire.Hash256, undo *BlockUndo) error {
	m.mu.RLock()
	indexes := make([]Index, 0, len(m.indexes))
	for _, idx := range m.indexes {
		indexes = append(indexes, idx)
	}
	m.mu.RUnlock()

	for _, idx := range indexes {
		if err := idx.WriteBlock(block, height, hash, undo); err != nil {
			log.Printf("index: %s write block %s failed: %v", idx.Name(), hash.String()[:16], err)
			return err
		}
	}
	return nil
}

// BlockDisconnected notifies all indexes of a disconnected block.
func (m *IndexManager) BlockDisconnected(block *wire.MsgBlock, height int32, hash wire.Hash256, undo *BlockUndo) error {
	m.mu.RLock()
	indexes := make([]Index, 0, len(m.indexes))
	for _, idx := range m.indexes {
		indexes = append(indexes, idx)
	}
	m.mu.RUnlock()

	for _, idx := range indexes {
		if err := idx.RevertBlock(block, height, hash, undo); err != nil {
			log.Printf("index: %s revert block %s failed: %v", idx.Name(), hash.String()[:16], err)
			return err
		}
	}
	return nil
}

// CatchUp brings every registered index up to the active chain tip after a
// restart. It mirrors Bitcoin Core's BaseIndex::Sync / BaseIndex::Rewind
// (bitcoin-core/src/index/base.cpp): on startup Core spawns a per-index
// ThreadSync that walks from the index's persisted best block forward to the
// chain tip (Sync) and, if the index is ahead of the tip after an unclean
// exit, walks it back down to the common point (Rewind). blockbrew previously
// had no such loop — the live OnBlockConnected fan-out only fires for blocks
// connected *after* startup, so an index that fell behind the chainstate (a
// crash between the chainstate flush and the index batch commit, or simply a
// freshly enabled index on an already-synced node) was never brought current.
//
// tipHeight is the height of the active chain tip (chainMgr.BestBlock()).
// hashAt resolves a main-chain height to its block hash — pass
// chainDB.GetBlockHashByHeight; it is injected so the storage package does not
// need to import the consensus package (the IndexManager only holds chainDB).
//
// For each index:
//   - if best < tip: read each missing main-chain block by height and replay
//     it through idx.WriteBlock (the same entry point the live connect hook
//     uses), advancing the index to the tip.
//   - if best > tip: the index is AHEAD of the tip (only possible after an
//     unclean exit where the index committed past a chainstate that was then
//     rolled back). Walk the index back down to the tip via idx.RevertBlock,
//     reading each over-shot block by its on-disk hash and following
//     PrevBlock, exactly as Core's Rewind follows pprev.
//
// Errors are returned (not logged-and-swallowed) so the caller can decide
// whether a half-synced index is fatal; the caller currently logs and
// continues, matching the non-fatal posture of the live index hooks.
func (m *IndexManager) CatchUp(tipHeight int32, hashAt func(int32) (wire.Hash256, error)) error {
	m.mu.RLock()
	indexes := make([]Index, 0, len(m.indexes))
	for _, idx := range m.indexes {
		indexes = append(indexes, idx)
	}
	m.mu.RUnlock()

	for _, idx := range indexes {
		if err := m.catchUpOne(idx, tipHeight, hashAt); err != nil {
			return fmt.Errorf("index %s catch-up: %w", idx.Name(), err)
		}
	}
	return nil
}

// catchUpOne synchronises a single index to tipHeight. See CatchUp.
func (m *IndexManager) catchUpOne(idx Index, tipHeight int32, hashAt func(int32) (wire.Hash256, error)) error {
	best := idx.BestHeight()

	// AHEAD: index committed past the current chainstate tip (unclean exit).
	// Rewind it down to the tip, peeling one block at a time. We read each
	// over-shot block by the index's currently-recorded best hash and then
	// follow the block's PrevBlock pointer downward — the height->hash map
	// may no longer have entries above the chainstate tip, so we cannot rely
	// on hashAt here.
	if best > tipHeight {
		log.Printf("index: %s is ahead of chain tip (index=%d tip=%d); rewinding",
			idx.Name(), best, tipHeight)
		curHash := idx.BestHash()
		for h := best; h > tipHeight; h-- {
			block, err := m.chainDB.GetBlock(curHash)
			if err != nil {
				return fmt.Errorf("rewind: read block %s at height %d: %w",
					curHash.String(), h, err)
			}
			// nil undo to mirror the live OnBlockDisconnected hook (see the
			// forward path above for the filter-byte rationale).
			if err := idx.RevertBlock(block, h, curHash, nil); err != nil {
				return fmt.Errorf("rewind: revert block %s at height %d: %w",
					curHash.String(), h, err)
			}
			curHash = block.Header.PrevBlock
		}
		log.Printf("index: %s rewound to height %d", idx.Name(), idx.BestHeight())
		return nil
	}

	if best >= tipHeight {
		return nil // already caught up
	}

	// BEHIND: walk forward from best+1 to the chain tip, replaying each
	// main-chain block through the same WriteBlock entry point the live
	// connect hook uses.
	start := best + 1
	log.Printf("index: %s is behind chain tip (index=%d tip=%d); catching up from height %d",
		idx.Name(), best, tipHeight, start)
	for h := start; h <= tipHeight; h++ {
		hash, err := hashAt(h)
		if err != nil {
			return fmt.Errorf("resolve hash at height %d: %w", h, err)
		}
		block, err := m.chainDB.GetBlock(hash)
		if err != nil {
			return fmt.Errorf("read block %s at height %d: %w", hash.String(), h, err)
		}
		// Pass nil undo to mirror the live OnBlockConnected hook in
		// cmd/blockbrew/main.go exactly (it calls WriteBlock/WriteBlockBatch
		// with a nil undo). Feeding real undo data here would change the
		// blockfilterindex output for catch-up blocks (BIP-158 basic filters
		// include spent-input scriptPubKeys when undo is present), making
		// catch-up filters diverge from live-connected filters and breaking
		// the BIP-157 filter-header chain continuity. Keep them identical.
		if err := idx.WriteBlock(block, h, hash, nil); err != nil {
			return fmt.Errorf("write block %s at height %d: %w", hash.String(), h, err)
		}
	}
	log.Printf("index: %s caught up to height %d", idx.Name(), idx.BestHeight())
	return nil
}

// GetIndexInfo returns status information for all indexes.
func (m *IndexManager) GetIndexInfo() []IndexStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]IndexStatus, 0, len(m.indexes))
	for _, idx := range m.indexes {
		result = append(result, idx.Status())
	}
	return result
}
