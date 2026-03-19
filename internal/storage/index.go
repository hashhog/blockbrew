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
