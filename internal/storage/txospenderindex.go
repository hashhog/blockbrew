package storage

import (
	"encoding/binary"
	"errors"

	"github.com/hashhog/blockbrew/internal/wire"
)

// TxoSpenderIndex implements the transaction-output spender index. For every
// input of every non-coinbase transaction in a connected block it records a
// single key mapping the SPENT outpoint -> the SPENDING transaction's txid (and
// the hash of the block that confirmed the spend). It is the data source for
// the confirmed-spend path of the gettxspendingprevout RPC.
//
// This mirrors Bitcoin Core's TxoSpenderIndex (bitcoin-core/src/index/
// txospenderindex.{h,cpp}). Core stores the spending tx's on-disk LOCATION
// (CDiskTxPos) keyed by a per-DB-salted siphash(outpoint) and reads the tx back
// from the block files on lookup (a flat-file optimisation that also lets it
// disambiguate siphash collisions and serve the full spending tx). The
// txospenderindex.cpp header comment notes a from-scratch implementation may
// legitimately store outpoint -> spending-txid directly; that is the simpler,
// faithful equivalent and is what this index does. No salt and no separate undo
// data are needed: the disconnect path (RevertBlock) RE-DERIVES the exact same
// keys from the block's own inputs and erases them, exactly like Core's
// CustomRemove(BuildSpenderPositions(block)).
//
// Default-off, gated by -txospenderindex, matching Core's
// DEFAULT_TXOSPENDERINDEX{false}.
var (
	// TxoSpenderStateKey stores the index state (best height/hash). Mirrors the
	// txindex_state / coinstats_state convention.
	TxoSpenderStateKey = []byte("txospenderindex_state")

	// TxoSpenderPrefix is the per-spend KV prefix. Key layout:
	//   "s" + outpoint.Hash[32] + outpoint.Index(4 BE)
	// Value layout:
	//   spending-txid[32] ++ spending-block-hash[32]
	// The prefix byte 's' matches Core's DB_TXOSPENDERINDEX{'s'} for parity of
	// intent; it lives in this index's own column namespace (its own key
	// builder), distinct from the other storage prefixes in keys.go (H/B/N/T/
	// U/R/Q/c/m and the txindex/coinstats state keys), so there is no
	// collision. Confirmed against keys.go before assignment.
	TxoSpenderPrefix = []byte("s")
)

// MakeTxoSpenderKey builds the per-spend KV key for a spent outpoint:
// "s" + 32-byte outpoint hash + 4-byte big-endian index. Big-endian on the
// index keeps the on-disk ordering grouped by spending txid prefix, matching
// the MakeUTXOKey convention in keys.go.
func MakeTxoSpenderKey(outpoint wire.OutPoint) []byte {
	key := make([]byte, 1+32+4)
	key[0] = TxoSpenderPrefix[0]
	copy(key[1:33], outpoint.Hash[:])
	binary.BigEndian.PutUint32(key[33:], outpoint.Index)
	return key
}

// txoSpenderValue serialises the (spending txid, spending block hash) pair.
func txoSpenderValue(spendingTxid, blockHash wire.Hash256) []byte {
	buf := make([]byte, 64)
	copy(buf[:32], spendingTxid[:])
	copy(buf[32:], blockHash[:])
	return buf
}

// TxoSpender is the decoded value of a spender-index entry.
type TxoSpender struct {
	SpendingTxid wire.Hash256
	BlockHash    wire.Hash256
}

// deserializeTxoSpender decodes a spender-index value.
func deserializeTxoSpender(data []byte) (*TxoSpender, error) {
	if len(data) < 64 {
		return nil, errors.New("txospenderindex value too short")
	}
	s := &TxoSpender{}
	copy(s.SpendingTxid[:], data[:32])
	copy(s.BlockHash[:], data[32:64])
	return s, nil
}

// TxoSpenderIndex maps spent outpoints to their spending transaction.
type TxoSpenderIndex struct {
	*BaseIndex
}

// NewTxoSpenderIndex creates a new txo spender index.
func NewTxoSpenderIndex(db DB) *TxoSpenderIndex {
	return &TxoSpenderIndex{
		BaseIndex: NewBaseIndex("txospenderindex", db),
	}
}

// Init loads the persisted index state from the database.
func (idx *TxoSpenderIndex) Init() error {
	data, err := idx.db.Get(TxoSpenderStateKey)
	if err != nil {
		return err
	}
	if data == nil {
		// No existing state, start fresh.
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

// WriteBlock indexes every spend in a newly connected block: for each input of
// each non-coinbase transaction it writes (spent outpoint -> spending txid ||
// block hash). The undo argument is ignored on purpose — like Core's
// CustomAppend(BuildSpenderPositions(block)), every key is a pure function of
// the block's own inputs.
func (idx *TxoSpenderIndex) WriteBlock(block *wire.MsgBlock, height int32, blockHash wire.Hash256, _ *BlockUndo) error {
	// Skip genesis: its single coinbase tx has no spendable inputs (the coinbase
	// input is the null prevout), exactly like txindex/coinstatsindex skip it.
	if height == 0 {
		idx.UpdateBest(height, blockHash)
		return idx.saveState()
	}

	batch := idx.db.NewBatch()

	for i, tx := range block.Transactions {
		if i == 0 {
			continue // coinbase: null prevout, no real spend
		}
		spendingTxid := tx.TxHash()
		val := txoSpenderValue(spendingTxid, blockHash)
		for _, in := range tx.TxIn {
			key := MakeTxoSpenderKey(in.PreviousOutPoint)
			batch.Put(key, val)
		}
	}

	state := &IndexState{
		BestHeight: height,
		BestHash:   blockHash,
	}
	batch.Put(TxoSpenderStateKey, state.Serialize())

	if err := batch.Write(); err != nil {
		return err
	}

	idx.UpdateBest(height, blockHash)
	return nil
}

// RevertBlock erases every spend recorded for a disconnected block. The keys are
// RE-DERIVED from the block's inputs (no undo data needed), mirroring Core's
// CustomRemove(BuildSpenderPositions(block)). This is the reorg-safe undo.
func (idx *TxoSpenderIndex) RevertBlock(block *wire.MsgBlock, height int32, blockHash wire.Hash256, _ *BlockUndo) error {
	prevHash := block.Header.PrevBlock

	batch := idx.db.NewBatch()

	for i, tx := range block.Transactions {
		if i == 0 {
			continue // coinbase
		}
		for _, in := range tx.TxIn {
			key := MakeTxoSpenderKey(in.PreviousOutPoint)
			batch.Delete(key)
		}
	}

	prevHeight := height - 1
	if prevHeight < 0 {
		prevHeight = -1
		prevHash = wire.Hash256{}
	}

	state := &IndexState{
		BestHeight: prevHeight,
		BestHash:   prevHash,
	}
	batch.Put(TxoSpenderStateKey, state.Serialize())

	if err := batch.Write(); err != nil {
		return err
	}

	idx.UpdateBest(prevHeight, prevHash)
	return nil
}

// saveState persists the current index state to the database.
func (idx *TxoSpenderIndex) saveState() error {
	state := &IndexState{
		BestHeight: idx.bestHeight,
		BestHash:   idx.bestHash,
	}
	return idx.db.Put(TxoSpenderStateKey, state.Serialize())
}

// FindSpender looks up the on-chain transaction that spends the given outpoint.
// Returns (spender, true, nil) if a confirmed spend is recorded, (nil, false,
// nil) if the outpoint is unspent on-chain, or (nil, false, err) on a DB error.
// Mirrors Core's TxoSpenderIndex::FindSpender (returning std::nullopt when
// unspent).
func (idx *TxoSpenderIndex) FindSpender(outpoint wire.OutPoint) (*TxoSpender, bool, error) {
	key := MakeTxoSpenderKey(outpoint)
	data, err := idx.db.Get(key)
	if err != nil {
		return nil, false, err
	}
	if data == nil {
		return nil, false, nil
	}
	s, err := deserializeTxoSpender(data)
	if err != nil {
		return nil, false, err
	}
	return s, true, nil
}
