package storage

import (
	"bytes"
	"errors"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ErrNotFound is returned when a requested item does not exist.
var ErrNotFound = errors.New("not found")

// ChainDB provides higher-level chain data access on top of DB.
type ChainDB struct {
	db DB
}

// NewChainDB creates a new ChainDB wrapping the given database.
func NewChainDB(db DB) *ChainDB {
	return &ChainDB{db: db}
}

// DB returns the underlying database.
func (c *ChainDB) DB() DB {
	return c.db
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

// StoreBlock persists a full block.
func (c *ChainDB) StoreBlock(hash wire.Hash256, block *wire.MsgBlock) error {
	key := MakeBlockDataKey(hash)

	buf := new(bytes.Buffer)
	if err := block.Serialize(buf); err != nil {
		return err
	}

	return c.db.Put(key, buf.Bytes())
}

// GetBlock retrieves a full block by hash.
func (c *ChainDB) GetBlock(hash wire.Hash256) (*wire.MsgBlock, error) {
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

// Close closes the underlying database.
func (c *ChainDB) Close() error {
	return c.db.Close()
}
