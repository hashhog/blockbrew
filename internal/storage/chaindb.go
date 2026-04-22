package storage

import (
	"bytes"
	"errors"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ErrNotFound is returned when a requested item does not exist.
var ErrNotFound = errors.New("not found")

// ChainDB provides higher-level chain data access on top of DB.
//
// Block bodies are stored either in flat files (when blockStore is set,
// the production path) or inline in Pebble under the legacy "B" prefix
// (when blockStore is nil — used by tests/benchmarks against MemDB and
// for backwards compatibility with datadirs created before the flatfile
// migration). Reads always try the flat-file index first and fall back
// to the legacy Pebble blob, allowing pre-existing datadirs to keep
// working without an offline migration step.
type ChainDB struct {
	db         DB
	blockStore *BlockStore
}

// NewChainDB creates a new ChainDB wrapping the given database.
func NewChainDB(db DB) *ChainDB {
	return &ChainDB{db: db}
}

// DB returns the underlying database.
func (c *ChainDB) DB() DB {
	return c.db
}

// SetBlockStore attaches a flat-file block store. After this call,
// StoreBlock writes block bodies to blk*.dat files (and a 6-byte position
// index in Pebble) instead of inlining them under the "B" prefix.
// Existing "B"-prefixed blocks remain readable via the GetBlock fallback.
func (c *ChainDB) SetBlockStore(bs *BlockStore) {
	c.blockStore = bs
}

// BlockStore returns the attached flat-file block store, or nil.
func (c *ChainDB) BlockStore() *BlockStore {
	return c.blockStore
}

// StoreBlockHeader persists a block header.
func (c *ChainDB) StoreBlockHeader(hash wire.Hash256, header *wire.BlockHeader) error {
	key := MakeBlockHeaderKey(hash)

	buf := new(bytes.Buffer)
	if err := header.Serialize(buf); err != nil {
		return err
	}

	return c.db.Put(key, buf.Bytes())
}

// GetBlockHeader retrieves a block header by hash.
func (c *ChainDB) GetBlockHeader(hash wire.Hash256) (*wire.BlockHeader, error) {
	key := MakeBlockHeaderKey(hash)

	data, err := c.db.Get(key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrNotFound
	}

	header := &wire.BlockHeader{}
	if err := header.Deserialize(bytes.NewReader(data)); err != nil {
		return nil, err
	}

	return header, nil
}

// StoreBlock persists a full block. Equivalent to StoreBlockAt with
// height 0 (height is purely metadata for BlockFileInfo, not used on
// the read path).
func (c *ChainDB) StoreBlock(hash wire.Hash256, block *wire.MsgBlock) error {
	return c.StoreBlockAt(hash, block, 0)
}

// StoreBlockAt persists a full block, recording the height in
// BlockFileInfo metadata. The hot path (sync.go HandleBlock) calls this
// with the block's chain height; non-hot callers (genesis init, mining,
// RPC submitblock) can use StoreBlock with height 0 since the metadata
// is not consulted by reads.
func (c *ChainDB) StoreBlockAt(hash wire.Hash256, block *wire.MsgBlock, height int32) error {
	buf := new(bytes.Buffer)
	if err := block.Serialize(buf); err != nil {
		return err
	}

	if c.blockStore != nil {
		// Flat-file path: append the serialized block to blk*.dat and
		// write a 6-byte position index entry to Pebble. The "B" Pebble
		// blob is NOT written, keeping the LSM small.
		h := uint32(0)
		if height > 0 {
			h = uint32(height)
		}
		_, err := c.blockStore.WriteAndIndexBlock(hash, buf.Bytes(), h, uint64(block.Header.Timestamp))
		return err
	}

	// Legacy path (no flat-file store attached): inline the block under
	// the "B" prefix. Used by unit tests and benchmarks that wrap a
	// MemDB without a flat-file store.
	key := MakeBlockDataKey(hash)
	return c.db.Put(key, buf.Bytes())
}

// GetBlock retrieves a full block by hash. With a flat-file store
// attached the index is consulted first; if there is no flat-file
// position recorded the lookup falls back to the legacy "B"-prefix
// Pebble blob. The fallback lets pre-flatfile datadirs keep serving
// reads without a one-shot migration.
func (c *ChainDB) GetBlock(hash wire.Hash256) (*wire.MsgBlock, error) {
	if c.blockStore != nil {
		data, err := c.blockStore.ReadBlockByHash(hash)
		if err == nil {
			block := &wire.MsgBlock{}
			if derr := block.Deserialize(bytes.NewReader(data)); derr != nil {
				return nil, derr
			}
			return block, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		// fall through to legacy "B"-prefix lookup
	}

	key := MakeBlockDataKey(hash)
	data, err := c.db.Get(key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrNotFound
	}

	block := &wire.MsgBlock{}
	if err := block.Deserialize(bytes.NewReader(data)); err != nil {
		return nil, err
	}

	return block, nil
}

// SetBlockHeight maps a height to a block hash.
func (c *ChainDB) SetBlockHeight(height int32, hash wire.Hash256) error {
	key := MakeBlockHeightKey(height)
	return c.db.Put(key, hash[:])
}

// GetBlockHashByHeight retrieves the block hash at a given height.
func (c *ChainDB) GetBlockHashByHeight(height int32) (wire.Hash256, error) {
	key := MakeBlockHeightKey(height)

	data, err := c.db.Get(key)
	if err != nil {
		return wire.Hash256{}, err
	}
	if data == nil {
		return wire.Hash256{}, ErrNotFound
	}

	var hash wire.Hash256
	copy(hash[:], data)
	return hash, nil
}

// GetChainState retrieves the current chain state.
func (c *ChainDB) GetChainState() (*ChainState, error) {
	data, err := c.db.Get(ChainStateKey)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrNotFound
	}

	return DeserializeChainState(data)
}

// SetChainState persists the chain state.
func (c *ChainDB) SetChainState(state *ChainState) error {
	return c.db.Put(ChainStateKey, state.Serialize())
}

// SetChainStateBatch adds a chain state write to an existing batch (for atomic writes).
func (c *ChainDB) SetChainStateBatch(batch Batch, state *ChainState) {
	batch.Put(ChainStateKey, state.Serialize())
}

// SetBlockHeightBatch adds a height->hash mapping to an existing batch (for atomic writes).
func (c *ChainDB) SetBlockHeightBatch(batch Batch, height int32, hash wire.Hash256) {
	key := MakeBlockHeightKey(height)
	batch.Put(key, hash[:])
}

// WriteBlockUndoBatch adds undo data to an existing batch (for atomic writes).
func (c *ChainDB) WriteBlockUndoBatch(batch Batch, hash wire.Hash256, undo *BlockUndo) {
	key := MakeUndoBlockKey(hash)
	batch.Put(key, undo.Serialize())
}

// NewBatch creates a new write batch from the underlying database.
func (c *ChainDB) NewBatch() Batch {
	return c.db.NewBatch()
}

// NewBatchNoSync creates a batch that skips fsync on commit.
// Safe during IBD where chain-state checkpoints handle crash recovery.
func (c *ChainDB) NewBatchNoSync() Batch {
	type noSyncer interface {
		NewBatchNoSync() Batch
	}
	if ns, ok := c.db.(noSyncer); ok {
		return ns.NewBatchNoSync()
	}
	// Fallback to regular batch if backend doesn't support NoSync
	return c.db.NewBatch()
}

// Close closes the underlying database.
func (c *ChainDB) Close() error {
	return c.db.Close()
}

// WriteBlockUndo persists undo data for a block.
// The undo data is keyed by block hash since heights can change during reorgs.
func (c *ChainDB) WriteBlockUndo(hash wire.Hash256, undo *BlockUndo) error {
	key := MakeUndoBlockKey(hash)
	return c.db.Put(key, undo.Serialize())
}

// ReadBlockUndo retrieves undo data for a block.
// Returns ErrNotFound if no undo data exists for the block.
func (c *ChainDB) ReadBlockUndo(hash wire.Hash256) (*BlockUndo, error) {
	key := MakeUndoBlockKey(hash)

	data, err := c.db.Get(key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrNotFound
	}

	return DeserializeBlockUndo(data)
}

// DeleteBlockUndo removes undo data for a block.
func (c *ChainDB) DeleteBlockUndo(hash wire.Hash256) error {
	key := MakeUndoBlockKey(hash)
	return c.db.Delete(key)
}

// TxIndexEntry stores the block location for a transaction.
type TxIndexEntry struct {
	BlockHash wire.Hash256 // Hash of the block containing the transaction
}

// WriteTxIndex stores a mapping from txid to block hash.
func (c *ChainDB) WriteTxIndex(txid wire.Hash256, blockHash wire.Hash256) error {
	key := MakeTxIndexKey(txid)
	return c.db.Put(key, blockHash[:])
}

// GetTxIndex retrieves the block hash for a transaction.
// Returns ErrNotFound if the txid is not in the index.
func (c *ChainDB) GetTxIndex(txid wire.Hash256) (*TxIndexEntry, error) {
	key := MakeTxIndexKey(txid)

	data, err := c.db.Get(key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrNotFound
	}

	if len(data) < 32 {
		return nil, errors.New("invalid txindex entry")
	}

	entry := &TxIndexEntry{}
	copy(entry.BlockHash[:], data[:32])
	return entry, nil
}

// DeleteTxIndex removes a txid from the index.
func (c *ChainDB) DeleteTxIndex(txid wire.Hash256) error {
	key := MakeTxIndexKey(txid)
	return c.db.Delete(key)
}
