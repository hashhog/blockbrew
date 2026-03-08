package storage

import (
	"encoding/binary"

	"github.com/hashhog/blockbrew/internal/wire"
)

var (
	// BlockHeaderPrefix is the prefix for block header storage. Key: "H" + block_hash
	BlockHeaderPrefix = []byte("H")

	// BlockDataPrefix is the prefix for full block data. Key: "B" + block_hash
	BlockDataPrefix = []byte("B")

	// BlockHeightPrefix maps height to block hash. Key: "N" + big-endian uint32 height
	BlockHeightPrefix = []byte("N")

	// TxIndexPrefix maps txid to block location. Key: "T" + txid
	TxIndexPrefix = []byte("T")

	// UTXOPrefix is the prefix for UTXO entries. Key: "U" + outpoint (txid + index)
	UTXOPrefix = []byte("U")

	// UndoBlockPrefix is the prefix for undo block data. Key: "R" + block_hash
	UndoBlockPrefix = []byte("R")

	// ChainStateKey stores the current chain tip hash and height.
	ChainStateKey = []byte("chainstate")

	// BestHeaderKey stores the best known header hash and height.
	BestHeaderKey = []byte("bestheader")
)

// MakeBlockHeaderKey creates a key for a block header.
func MakeBlockHeaderKey(hash wire.Hash256) []byte {
	key := make([]byte, 1+32)
	key[0] = BlockHeaderPrefix[0]
	copy(key[1:], hash[:])
	return key
}

// MakeBlockDataKey creates a key for full block data.
func MakeBlockDataKey(hash wire.Hash256) []byte {
	key := make([]byte, 1+32)
	key[0] = BlockDataPrefix[0]
	copy(key[1:], hash[:])
	return key
}

// MakeBlockHeightKey creates a key for height -> hash mapping.
func MakeBlockHeightKey(height int32) []byte {
	key := make([]byte, 1+4)
	key[0] = BlockHeightPrefix[0]
	binary.BigEndian.PutUint32(key[1:], uint32(height))
	return key
}

// MakeTxIndexKey creates a key for txid -> block location mapping.
func MakeTxIndexKey(txid wire.Hash256) []byte {
	key := make([]byte, 1+32)
	key[0] = TxIndexPrefix[0]
	copy(key[1:], txid[:])
	return key
}

// MakeUTXOKey creates a key for a UTXO entry.
func MakeUTXOKey(outpoint wire.OutPoint) []byte {
	key := make([]byte, 1+32+4)
	key[0] = UTXOPrefix[0]
	copy(key[1:33], outpoint.Hash[:])
	binary.BigEndian.PutUint32(key[33:], outpoint.Index)
	return key
}

// MakeUndoBlockKey creates a key for undo block data.
func MakeUndoBlockKey(hash wire.Hash256) []byte {
	key := make([]byte, 1+32)
	key[0] = UndoBlockPrefix[0]
	copy(key[1:], hash[:])
	return key
}
