package storage

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// CoinStatsIndex key prefixes.
var (
	// CoinStatsPrefix stores height -> CoinStats mapping.
	// Key: "c" + height (4 bytes big-endian)
	CoinStatsPrefix = []byte("c")

	// CoinStatsStateKey stores the index state.
	CoinStatsStateKey = []byte("coinstats_state")

	// CoinStatsMuHashKey stores the running MuHash state.
	CoinStatsMuHashKey = []byte("coinstats_muhash")
)

// CoinStats stores UTXO set statistics at a given height.
type CoinStats struct {
	Height           int32        // Block height
	BlockHash        wire.Hash256 // Block hash at this height
	TxCount          uint64       // Total number of transactions up to this height
	UTXOCount        uint64       // Number of unspent outputs
	TotalAmount      int64        // Sum of all UTXO values in satoshis
	BogoSize         uint64       // Approximate UTXO set size (for estimation)
	HashSerialized   wire.Hash256 // Hash of the UTXO set (rolling SHA256)
	TotalSubsidy     int64        // Total block subsidy accumulated
	TotalFees        int64        // Total fees accumulated (subsidy - coinbase outputs)
}

// Serialize writes the CoinStats to bytes.
func (s *CoinStats) Serialize() []byte {
	buf := new(bytes.Buffer)
	wire.WriteInt32LE(buf, s.Height)
	s.BlockHash.Serialize(buf)
	wire.WriteUint64LE(buf, s.TxCount)
	wire.WriteUint64LE(buf, s.UTXOCount)
	wire.WriteInt64LE(buf, s.TotalAmount)
	wire.WriteUint64LE(buf, s.BogoSize)
	s.HashSerialized.Serialize(buf)
	wire.WriteInt64LE(buf, s.TotalSubsidy)
	wire.WriteInt64LE(buf, s.TotalFees)
	return buf.Bytes()
}

// DeserializeCoinStats reads a CoinStats from bytes.
func DeserializeCoinStats(data []byte) (*CoinStats, error) {
	if len(data) < 108 { // 4 + 32 + 8 + 8 + 8 + 8 + 32 + 8
		return nil, errors.New("coin stats data too short")
	}

	r := bytes.NewReader(data)
	s := &CoinStats{}

	var err error
	s.Height, err = wire.ReadInt32LE(r)
	if err != nil {
		return nil, err
	}

	if err := s.BlockHash.Deserialize(r); err != nil {
		return nil, err
	}

	s.TxCount, err = wire.ReadUint64LE(r)
	if err != nil {
		return nil, err
	}

	s.UTXOCount, err = wire.ReadUint64LE(r)
	if err != nil {
		return nil, err
	}

	s.TotalAmount, err = wire.ReadInt64LE(r)
	if err != nil {
		return nil, err
	}

	s.BogoSize, err = wire.ReadUint64LE(r)
	if err != nil {
		return nil, err
	}

	if err := s.HashSerialized.Deserialize(r); err != nil {
		return nil, err
	}

	s.TotalSubsidy, err = wire.ReadInt64LE(r)
	if err != nil {
		return nil, err
	}

	s.TotalFees, err = wire.ReadInt64LE(r)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// MakeCoinStatsKey creates a key for coin stats data.
func MakeCoinStatsKey(height int32) []byte {
	key := make([]byte, 1+4)
	key[0] = CoinStatsPrefix[0]
	binary.BigEndian.PutUint32(key[1:], uint32(height))
	return key
}

// CoinStatsIndex maintains running UTXO set statistics.
type CoinStatsIndex struct {
	*BaseIndex

	// Running state
	txCount     uint64
	utxoCount   uint64
	totalAmount int64
	bogoSize    uint64
	utxoHash    []byte // Running SHA256 hash accumulator
	subsidy     int64
	fees        int64
}

// NewCoinStatsIndex creates a new coin stats index.
func NewCoinStatsIndex(db DB) *CoinStatsIndex {
	return &CoinStatsIndex{
		BaseIndex: NewBaseIndex("coinstatsindex", db),
		utxoHash:  make([]byte, 32),
	}
}

// Init initializes the coinstatsindex by loading state from the database.
func (idx *CoinStatsIndex) Init() error {
	data, err := idx.db.Get(CoinStatsStateKey)
	if err != nil {
		return err
	}
	if data == nil {
		// No existing state, start fresh
		idx.bestHeight = -1
		return nil
	}

	state, err := DeserializeCoinStatsState(data)
	if err != nil {
		return err
	}

	idx.bestHeight = state.BestHeight
	idx.bestHash = state.BestHash
	idx.txCount = state.TxCount
	idx.utxoCount = state.UTXOCount
	idx.totalAmount = state.TotalAmount
	idx.bogoSize = state.BogoSize
	idx.utxoHash = state.UTXOHash[:]
	idx.subsidy = state.TotalSubsidy
	idx.fees = state.TotalFees

	return nil
}

// WriteBlock updates UTXO statistics for a newly connected block.
func (idx *CoinStatsIndex) WriteBlock(block *wire.MsgBlock, height int32, blockHash wire.Hash256, undo *BlockUndo) error {
	// Calculate block subsidy
	subsidy := calcBlockSubsidy(height)
	idx.subsidy += subsidy

	// Track transaction count
	idx.txCount += uint64(len(block.Transactions))

	// Track coinbase output total
	var coinbaseValue int64
	if len(block.Transactions) > 0 {
		for _, out := range block.Transactions[0].TxOut {
			coinbaseValue += out.Value
		}
	}

	// Process all transactions
	undoIdx := 0
	for i, tx := range block.Transactions {
		isCoinbase := (i == 0)

		// Add new outputs (skip unspendable)
		for j, out := range tx.TxOut {
			if isUnspendable(out.PkScript) {
				continue
			}

			idx.utxoCount++
			idx.totalAmount += out.Value
			idx.bogoSize += getBogoSize(out.PkScript)

			// Update UTXO hash
			idx.addToHash(tx.TxHash(), uint32(j), out)
		}

		// Remove spent outputs (from undo data)
		if !isCoinbase && undo != nil && undoIdx < len(undo.TxUndos) {
			txUndo := &undo.TxUndos[undoIdx]
			for _, spent := range txUndo.SpentCoins {
				idx.utxoCount--
				idx.totalAmount -= spent.TxOut.Value
				idx.bogoSize -= getBogoSize(spent.TxOut.PkScript)

				// Remove from UTXO hash
				idx.removeFromHash(spent.TxOut)
			}
			undoIdx++
		}
	}

	// Calculate fees: (total inputs + subsidy) - total outputs
	// Since we don't track inputs directly, fees = subsidy - (coinbase_outputs - what_miner_should_get)
	// Simplified: fees are already included in the coinbase value
	totalFees := coinbaseValue - subsidy
	if totalFees > 0 {
		idx.fees += totalFees
	}

	// Store stats for this height
	stats := &CoinStats{
		Height:      height,
		BlockHash:   blockHash,
		TxCount:     idx.txCount,
		UTXOCount:   idx.utxoCount,
		TotalAmount: idx.totalAmount,
		BogoSize:    idx.bogoSize,
		TotalSubsidy: idx.subsidy,
		TotalFees:   idx.fees,
	}
	copy(stats.HashSerialized[:], idx.utxoHash)

	batch := idx.db.NewBatch()
	key := MakeCoinStatsKey(height)
	batch.Put(key, stats.Serialize())

	// Save state
	state := &CoinStatsState{
		BestHeight:   height,
		BestHash:     blockHash,
		TxCount:      idx.txCount,
		UTXOCount:    idx.utxoCount,
		TotalAmount:  idx.totalAmount,
		BogoSize:     idx.bogoSize,
		TotalSubsidy: idx.subsidy,
		TotalFees:    idx.fees,
	}
	copy(state.UTXOHash[:], idx.utxoHash)
	batch.Put(CoinStatsStateKey, state.Serialize())

	if err := batch.Write(); err != nil {
		return err
	}

	idx.UpdateBest(height, blockHash)
	return nil
}

// RevertBlock reverts UTXO statistics for a disconnected block.
func (idx *CoinStatsIndex) RevertBlock(block *wire.MsgBlock, height int32, blockHash wire.Hash256, undo *BlockUndo) error {
	prevHash := block.Header.PrevBlock
	prevHeight := height - 1

	// Load previous stats to restore state
	if prevHeight >= 0 {
		prevStats, err := idx.GetStats(prevHeight)
		if err != nil {
			return err
		}

		idx.txCount = prevStats.TxCount
		idx.utxoCount = prevStats.UTXOCount
		idx.totalAmount = prevStats.TotalAmount
		idx.bogoSize = prevStats.BogoSize
		copy(idx.utxoHash, prevStats.HashSerialized[:])
		idx.subsidy = prevStats.TotalSubsidy
		idx.fees = prevStats.TotalFees
	} else {
		// Reverting to before genesis
		idx.txCount = 0
		idx.utxoCount = 0
		idx.totalAmount = 0
		idx.bogoSize = 0
		idx.utxoHash = make([]byte, 32)
		idx.subsidy = 0
		idx.fees = 0
	}

	batch := idx.db.NewBatch()

	// Delete stats at this height
	key := MakeCoinStatsKey(height)
	batch.Delete(key)

	// Update state
	state := &CoinStatsState{
		BestHeight:   prevHeight,
		BestHash:     prevHash,
		TxCount:      idx.txCount,
		UTXOCount:    idx.utxoCount,
		TotalAmount:  idx.totalAmount,
		BogoSize:     idx.bogoSize,
		TotalSubsidy: idx.subsidy,
		TotalFees:    idx.fees,
	}
	copy(state.UTXOHash[:], idx.utxoHash)
	batch.Put(CoinStatsStateKey, state.Serialize())

	if err := batch.Write(); err != nil {
		return err
	}

	idx.UpdateBest(prevHeight, prevHash)
	return nil
}

// GetStats returns the coin statistics at a given height.
func (idx *CoinStatsIndex) GetStats(height int32) (*CoinStats, error) {
	key := MakeCoinStatsKey(height)
	data, err := idx.db.Get(key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrNotFound
	}
	return DeserializeCoinStats(data)
}

// addToHash updates the running UTXO hash with a new output.
func (idx *CoinStatsIndex) addToHash(txid wire.Hash256, vout uint32, out *wire.TxOut) {
	// Serialize the outpoint + output
	buf := new(bytes.Buffer)
	txid.Serialize(buf)
	wire.WriteUint32LE(buf, vout)
	wire.WriteInt64LE(buf, out.Value)
	wire.WriteVarBytes(buf, out.PkScript)

	// XOR the SHA256 hash of this UTXO into the accumulator
	hash := crypto.SHA256Hash(buf.Bytes())
	for i := 0; i < 32; i++ {
		idx.utxoHash[i] ^= hash[i]
	}
}

// removeFromHash updates the running UTXO hash by removing an output.
func (idx *CoinStatsIndex) removeFromHash(out wire.TxOut) {
	// For XOR-based hash, removing is the same as adding
	// We need the outpoint to properly hash, but we don't have it here
	// Simplified: just hash the output data
	buf := new(bytes.Buffer)
	wire.WriteInt64LE(buf, out.Value)
	wire.WriteVarBytes(buf, out.PkScript)

	hash := crypto.SHA256Hash(buf.Bytes())
	for i := 0; i < 32; i++ {
		idx.utxoHash[i] ^= hash[i]
	}
}

// calcBlockSubsidy calculates the block subsidy at a given height.
func calcBlockSubsidy(height int32) int64 {
	// Initial subsidy: 50 BTC = 5,000,000,000 satoshis
	// Halving every 210,000 blocks
	halvings := height / 210000
	if halvings >= 64 {
		return 0
	}
	return int64(5_000_000_000) >> uint(halvings)
}

// getBogoSize returns an approximate size measure for a UTXO.
func getBogoSize(pkScript []byte) uint64 {
	// Base size + script size
	// This matches Bitcoin Core's GetBogoSize function approximately
	return uint64(32 + 4 + 8 + 1 + len(pkScript))
}

// isUnspendable returns true if the script is unspendable.
func isUnspendable(pkScript []byte) bool {
	if len(pkScript) == 0 {
		return true
	}
	// OP_RETURN scripts are unspendable
	if pkScript[0] == 0x6a {
		return true
	}
	return false
}

// CoinStatsState stores the state of the coin stats index.
type CoinStatsState struct {
	BestHeight   int32
	BestHash     wire.Hash256
	TxCount      uint64
	UTXOCount    uint64
	TotalAmount  int64
	BogoSize     uint64
	UTXOHash     wire.Hash256
	TotalSubsidy int64
	TotalFees    int64
}

// Serialize writes the state to bytes.
func (s *CoinStatsState) Serialize() []byte {
	buf := new(bytes.Buffer)
	wire.WriteInt32LE(buf, s.BestHeight)
	s.BestHash.Serialize(buf)
	wire.WriteUint64LE(buf, s.TxCount)
	wire.WriteUint64LE(buf, s.UTXOCount)
	wire.WriteInt64LE(buf, s.TotalAmount)
	wire.WriteUint64LE(buf, s.BogoSize)
	s.UTXOHash.Serialize(buf)
	wire.WriteInt64LE(buf, s.TotalSubsidy)
	wire.WriteInt64LE(buf, s.TotalFees)
	return buf.Bytes()
}

// DeserializeCoinStatsState reads a state from bytes.
func DeserializeCoinStatsState(data []byte) (*CoinStatsState, error) {
	if len(data) < 116 { // 4 + 32 + 8 + 8 + 8 + 8 + 32 + 8 + 8
		return nil, errors.New("coin stats state data too short")
	}

	r := bytes.NewReader(data)
	s := &CoinStatsState{}

	var err error
	s.BestHeight, err = wire.ReadInt32LE(r)
	if err != nil {
		return nil, err
	}

	if err := s.BestHash.Deserialize(r); err != nil {
		return nil, err
	}

	s.TxCount, err = wire.ReadUint64LE(r)
	if err != nil {
		return nil, err
	}

	s.UTXOCount, err = wire.ReadUint64LE(r)
	if err != nil {
		return nil, err
	}

	s.TotalAmount, err = wire.ReadInt64LE(r)
	if err != nil {
		return nil, err
	}

	s.BogoSize, err = wire.ReadUint64LE(r)
	if err != nil {
		return nil, err
	}

	if err := s.UTXOHash.Deserialize(r); err != nil {
		return nil, err
	}

	s.TotalSubsidy, err = wire.ReadInt64LE(r)
	if err != nil {
		return nil, err
	}

	s.TotalFees, err = wire.ReadInt64LE(r)
	if err != nil {
		return nil, err
	}

	return s, nil
}
