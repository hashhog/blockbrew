package storage

import (
	"encoding/binary"

	"github.com/hashhog/blockbrew/internal/wire"
)

var (
	// BlockHeaderPrefix is the prefix for block header storage. Key: "H" + block_hash
	BlockHeaderPrefix = []byte("H")

	// BlockDataPrefix is the legacy prefix for full block data stored
	// inline in Pebble. Key: "B" + block_hash.
	//
	// New blocks are stored in flat files (blk*.dat) and referenced via
	// BlockPosPrefix ("P", defined in flatfile.go) — see ChainDB.StoreBlock
	// and ChainDB.GetBlock for the lazy-migration read fallback.
	BlockDataPrefix = []byte("B")

	// BlockHeightPrefix maps height to block hash. Key: "N" + big-endian uint32 height
	BlockHeightPrefix = []byte("N")

	// TxIndexPrefix maps txid to block location. Key: "T" + txid
	TxIndexPrefix = []byte("T")

	// UTXOPrefix is the prefix for UTXO entries. Key: "U" + outpoint (txid + index)
	UTXOPrefix = []byte("U")

	// UndoBlockPrefix is the prefix for undo block data. Key: "R" + block_hash
	UndoBlockPrefix = []byte("R")

	// ChainTxCountPrefix maps a main-chain height to the cumulative number of
	// transactions from genesis up to and including that height (Bitcoin Core's
	// CBlockIndex::m_chain_tx_count analogue). Key: "Q" + big-endian uint32
	// height, value: big-endian uint64. Populated lazily + self-healing by the
	// getchaintxstats RPC handler (see ChainDB.GetChainTxCount / PutChainTxCount);
	// not part of the consensus block-connect path.
	ChainTxCountPrefix = []byte("Q")

	// ChainStateKey stores the current chain tip hash and height.
	ChainStateKey = []byte("chainstate")

	// BestHeaderKey stores the best known header hash and height.
	BestHeaderKey = []byte("bestheader")

	// CoinsTipKey stores the block through which the ON-DISK UTXO set is
	// reflected — Bitcoin Core's DB_BEST_BLOCK ('B' in txdb.cpp:24).
	//
	// It is NOT the same thing as ChainStateKey. ChainStateKey is the active
	// chain tip pointer; CoinsTipKey is a property of the coin database
	// itself and is written in the SAME batch as the coin writes it
	// describes (Core: txdb.cpp:158-159 writes DB_BEST_BLOCK into the final
	// CDBBatch of BatchWrite). That makes it the only honest answer to
	// "which block's effects are already in the persisted set?" — the
	// question crash recovery has to answer before it re-applies anything.
	//
	// The two markers diverge whenever coins are flushed without advancing
	// the tip pointer (UTXOSet.Flush from cache pressure, scantxoutset, the
	// IBD flush cadence). The 2026-08-14 genesis rig booted with coins
	// flushed through 958,794 and ChainStateKey at 958,000.
	//
	// Value: the same encoding as ChainState (32-byte hash + int32 LE
	// height). Absent on datadirs written before this key existed; readers
	// MUST treat absence as "unknown" and fall back, never as height 0.
	CoinsTipKey = []byte("coinstip")
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

// MakeChainTxCountKey creates a key for the cumulative-tx-count-by-height map
// (the m_chain_tx_count analogue). Key: "Q" + big-endian uint32 height.
func MakeChainTxCountKey(height int32) []byte {
	key := make([]byte, 1+4)
	key[0] = ChainTxCountPrefix[0]
	binary.BigEndian.PutUint32(key[1:], uint32(height))
	return key
}
