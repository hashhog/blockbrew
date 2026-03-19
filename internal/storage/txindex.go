package storage

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TxIndex key prefixes.
// Uses the same "T" prefix as existing TxIndexPrefix in keys.go but with
// extended data format. The TxIndexStateKey stores the sync state.
var (
	// TxIndexStateKey stores the index state (best height/hash).
	TxIndexStateKey = []byte("txindex_state")
)

// TxIndexData stores the location of a transaction on disk.
type TxIndexData struct {
	BlockHash wire.Hash256 // Hash of the block containing this transaction
	TxIndex   uint32       // Index of this transaction within the block
}

// Serialize writes the TxIndexData to bytes.
func (d *TxIndexData) Serialize() []byte {
	buf := make([]byte, 36)
	copy(buf[:32], d.BlockHash[:])
	binary.BigEndian.PutUint32(buf[32:], d.TxIndex)
	return buf
}

// DeserializeTxIndexData reads a TxIndexData from bytes.
func DeserializeTxIndexData(data []byte) (*TxIndexData, error) {
	if len(data) < 36 {
		return nil, errors.New("txindex data too short")
	}
	d := &TxIndexData{}
	copy(d.BlockHash[:], data[:32])
	d.TxIndex = binary.BigEndian.Uint32(data[32:])
	return d, nil
}

// MakeTxIndexDataKey creates a key for txindex data.
// Uses the same "T" prefix as the existing TxIndexPrefix.
func MakeTxIndexDataKey(txid wire.Hash256) []byte {
	return MakeTxIndexKey(txid)
}

// TxIndex implements the transaction index.
// It maps each transaction ID to its location in a block.
type TxIndex struct {
	*BaseIndex
}

// NewTxIndex creates a new transaction index.
func NewTxIndex(db DB) *TxIndex {
	return &TxIndex{
		BaseIndex: NewBaseIndex("txindex", db),
	}
}

// Init initializes the txindex by loading state from the database.
func (idx *TxIndex) Init() error {
	data, err := idx.db.Get(TxIndexStateKey)
	if err != nil {
		return err
	}
	if data == nil {
		// No existing state, start fresh
		idx.bestHeight = -1
		return nil
	}

	state, err := DeserializeIndexState(data)
	if err != nil {
		return err
	}
	idx.bestHeight = state.BestHeight
	idx.bestHash = state.BestHash
	return nil
}

// WriteBlock indexes all transactions in a newly connected block.
func (idx *TxIndex) WriteBlock(block *wire.MsgBlock, height int32, blockHash wire.Hash256, _ *BlockUndo) error {
	// Skip genesis block - its coinbase is not spendable
	if height == 0 {
		idx.UpdateBest(height, blockHash)
		return idx.saveState()
	}

	batch := idx.db.NewBatch()

	// Index each transaction
	for i, tx := range block.Transactions {
		txid := tx.TxHash()
		data := &TxIndexData{
			BlockHash: blockHash,
			TxIndex:   uint32(i),
		}
		key := MakeTxIndexDataKey(txid)
		batch.Put(key, data.Serialize())
	}

	// Save state
	state := &IndexState{
		BestHeight: height,
		BestHash:   blockHash,
	}
	batch.Put(TxIndexStateKey, state.Serialize())

	if err := batch.Write(); err != nil {
		return err
	}

	idx.UpdateBest(height, blockHash)
	return nil
}

// RevertBlock removes all transactions from a disconnected block.
func (idx *TxIndex) RevertBlock(block *wire.MsgBlock, height int32, blockHash wire.Hash256, _ *BlockUndo) error {
	// Find previous block hash
	prevHash := block.Header.PrevBlock

	batch := idx.db.NewBatch()

	// Remove each transaction from the index
	for _, tx := range block.Transactions {
		txid := tx.TxHash()
		key := MakeTxIndexDataKey(txid)
		batch.Delete(key)
	}

	// Update state to previous block
	prevHeight := height - 1
	if prevHeight < 0 {
		prevHeight = -1
		prevHash = wire.Hash256{}
	}

	state := &IndexState{
		BestHeight: prevHeight,
		BestHash:   prevHash,
	}
	batch.Put(TxIndexStateKey, state.Serialize())

	if err := batch.Write(); err != nil {
		return err
	}

	idx.UpdateBest(prevHeight, prevHash)
	return nil
}

// saveState persists the current index state to the database.
func (idx *TxIndex) saveState() error {
	state := &IndexState{
		BestHeight: idx.bestHeight,
		BestHash:   idx.bestHash,
	}
	return idx.db.Put(TxIndexStateKey, state.Serialize())
}

// GetTx returns the block hash and transaction index for a given txid.
// Returns ErrNotFound if the transaction is not in the index.
func (idx *TxIndex) GetTx(txid wire.Hash256) (*TxIndexData, error) {
	key := MakeTxIndexDataKey(txid)
	data, err := idx.db.Get(key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrNotFound
	}
	return DeserializeTxIndexData(data)
}

// IndexState stores the state of an index.
type IndexState struct {
	BestHeight int32
	BestHash   wire.Hash256
}

// Serialize writes the index state to bytes.
func (s *IndexState) Serialize() []byte {
	buf := new(bytes.Buffer)
	wire.WriteInt32LE(buf, s.BestHeight)
	s.BestHash.Serialize(buf)
	return buf.Bytes()
}

// DeserializeIndexState reads an index state from bytes.
func DeserializeIndexState(data []byte) (*IndexState, error) {
	if len(data) < 36 {
		return nil, errors.New("index state data too short")
	}

	r := bytes.NewReader(data)
	s := &IndexState{}

	var err error
	s.BestHeight, err = wire.ReadInt32LE(r)
	if err != nil {
		return nil, err
	}

	if err := s.BestHash.Deserialize(r); err != nil {
		return nil, err
	}

	return s, nil
}
