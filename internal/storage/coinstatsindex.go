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

// CoinStatsMuHashPrefix stores the per-height MuHash3072 accumulator
// (numerator||denominator, 768 bytes). Keyed "m" + height (4 bytes big-endian).
// This lets RevertBlock restore the exact accumulator state as of the previous
// height without replaying or needing undo data — the finalized 32-byte digest
// in the CoinStats row is one-way and cannot be resumed.
var CoinStatsMuHashPrefix = []byte("m")

// MakeCoinStatsMuHashKey creates a per-height MuHash accumulator key.
func MakeCoinStatsMuHashKey(height int32) []byte {
	key := make([]byte, 1+4)
	key[0] = CoinStatsMuHashPrefix[0]
	binary.BigEndian.PutUint32(key[1:], uint32(height))
	return key
}

// CoinStatsIndex maintains running UTXO set statistics.
//
// The per-block UTXO-set commitment is a MuHash3072 accumulator
// (internal/crypto/muhash.go), the same multiset hash Bitcoin Core's
// coinstatsindex uses (index/coinstatsindex.cpp + crypto/muhash.cpp). Coins are
// fed through the accumulator as the Core per-coin record (the exact byte layout
// of kernel/coinstats.cpp::TxOutSer: outpoint || (height<<1|coinbase) as uint32
// LE || value int64 LE || CompactSize(scriptLen) || script), Insert on connect,
// Remove on spend. Because MuHash is order-invariant and homomorphic, the
// running value at height H equals Core's muhash AS OF H, byte-for-byte — which
// is what gettxoutsetinfo(muhash, H) returns.
type CoinStatsIndex struct {
	*BaseIndex

	// Running state
	txCount     uint64
	utxoCount   uint64
	totalAmount int64
	bogoSize    uint64
	muhash      *crypto.MuHash3072 // running MuHash3072 over the UTXO set
	subsidy     int64
	fees        int64
}

// NewCoinStatsIndex creates a new coin stats index.
func NewCoinStatsIndex(db DB) *CoinStatsIndex {
	return &CoinStatsIndex{
		BaseIndex: NewBaseIndex("coinstatsindex", db),
		muhash:    crypto.NewMuHash3072(),
	}
}

// NeedsUndo reports that the coinstatsindex requires real per-block undo data
// during startup catch-up replay (to subtract spent coins from the running
// UTXO-set MuHash + counts). Satisfies the storage.undoNeeder capability that
// IndexManager.catchUpOne checks. blockfilterindex / txindex do not implement
// this, so they keep receiving nil undo on the forward path.
func (idx *CoinStatsIndex) NeedsUndo() bool { return true }

// Init initializes the coinstatsindex by loading state from the database.
func (idx *CoinStatsIndex) Init() error {
	data, err := idx.db.Get(CoinStatsStateKey)
	if err != nil {
		return err
	}
	if data == nil {
		// No existing state, start fresh
		idx.bestHeight = -1
		idx.muhash = crypto.NewMuHash3072()
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
	idx.subsidy = state.TotalSubsidy
	idx.fees = state.TotalFees

	// Restore the running MuHash3072 accumulator (numerator||denominator, 768
	// bytes). Persisted separately from CoinStatsState because the state row
	// only carries the finalized 32-byte digest; the accumulator is needed to
	// continue incremental Insert/Remove across restarts.
	mhData, err := idx.db.Get(CoinStatsMuHashKey)
	if err != nil {
		return err
	}
	if mhData == nil {
		idx.muhash = crypto.NewMuHash3072()
	} else {
		mh, derr := crypto.MuHashDeserialize(mhData)
		if derr != nil {
			return derr
		}
		idx.muhash = mh
	}

	return nil
}

// coinRecord builds the Core per-coin record fed to the MuHash3072 accumulator.
// Byte layout is identical to kernel/coinstats.cpp::TxOutSer (uncompressed):
//
//	outpoint (32B hash LE || 4B vout LE)
//	code = (height << 1) | coinbase, as uint32 LE  (NOT a varint)
//	value, int64 LE
//	CompactSize(len(scriptPubKey)) || scriptPubKey
//
// Mirrors internal/consensus/utxohash.go::WriteTxOutSer, replicated here because
// the storage package cannot import consensus (consensus imports storage).
func coinRecord(outpoint wire.OutPoint, height int32, coinbase bool, value int64, pkScript []byte) []byte {
	buf := new(bytes.Buffer)
	buf.Grow(36 + 4 + 8 + 5 + len(pkScript))
	_ = outpoint.Serialize(buf)
	code := uint32(height) << 1
	if coinbase {
		code |= 1
	}
	wire.WriteUint32LE(buf, code)
	wire.WriteInt64LE(buf, value)
	wire.WriteCompactSize(buf, uint64(len(pkScript)))
	buf.Write(pkScript)
	return buf.Bytes()
}

// bip30Hash91722 and bip30Hash91812 are the hashes of the two mainnet blocks
// whose coinbases duplicated earlier coinbases that still had unspent outputs.
// Byte order: wire.Hash256 is stored little-endian (reversed display form).
// Display form is "00000000000271a2..." and "00000000000af0ae..." respectively;
// parsed via wire.NewHash256FromHex which reverses on decode to match Core's
// uint256 storage (validation.cpp:6196-6198, IsBIP30Unspendable).
var (
	bip30Hash91722 = mustDecodeHash("00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e")
	bip30Hash91812 = mustDecodeHash("00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f")
)

func mustDecodeHash(displayHex string) wire.Hash256 {
	h, err := wire.NewHash256FromHex(displayHex)
	if err != nil {
		panic("coinstatsindex: invalid BIP30 hash constant: " + err.Error())
	}
	return h
}

// isBIP30Unspendable reports whether the block at the given height and hash is
// one of the two mainnet blocks whose coinbase is a duplicate of an earlier
// coinbase that still had unspent outputs at the time. Those outputs were
// permanently lost (the earlier coin was overwritten), so the duplicate
// coinbase must NOT be counted in the UTXO set hash or totals.
//
// Mirrors Bitcoin Core index/coinstatsindex.cpp:128-132 and
// validation.cpp:6195-6199 IsBIP30Unspendable. Heights and hashes are
// mainnet-only constants (no other network has BIP30 duplicate coinbases).
func isBIP30Unspendable(height int32, blockHash wire.Hash256) bool {
	return (height == 91722 && blockHash == bip30Hash91722) ||
		(height == 91812 && blockHash == bip30Hash91812)
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
		txid := tx.TxHash()

		// Skip the duplicate-coinbase BIP30 blocks on mainnet (heights 91722 and
		// 91812). Their coinbases duplicated earlier ones that still had unspent
		// outputs, so the earlier coins were permanently lost; the duplicate
		// outputs must NOT be added to the UTXO-set hash or totals.
		// Mirrors Bitcoin Core index/coinstatsindex.cpp:128-132.
		if isCoinbase && isBIP30Unspendable(height, blockHash) {
			continue
		}

		// Add new outputs (skip unspendable)
		for j, out := range tx.TxOut {
			if isUnspendable(out.PkScript) {
				continue
			}

			idx.utxoCount++
			idx.totalAmount += out.Value
			idx.bogoSize += getBogoSize(out.PkScript)

			// Insert the Core per-coin record into the MuHash accumulator.
			op := wire.OutPoint{Hash: txid, Index: uint32(j)}
			idx.muhash.Insert(coinRecord(op, height, isCoinbase, out.Value, out.PkScript))
		}

		// Remove spent outputs (from undo data). SpentCoin carries value,
		// pkScript, the creating height and coinbase flag, but NOT the outpoint
		// — the outpoint is the corresponding input's PreviousOutPoint, paired
		// by index. This is required for MuHash parity: the removed record must
		// be byte-identical to the one inserted when the coin was created.
		if !isCoinbase && undo != nil && undoIdx < len(undo.TxUndos) {
			txUndo := &undo.TxUndos[undoIdx]
			for k := range txUndo.SpentCoins {
				spent := &txUndo.SpentCoins[k]
				idx.utxoCount--
				idx.totalAmount -= spent.TxOut.Value
				idx.bogoSize -= getBogoSize(spent.TxOut.PkScript)

				var op wire.OutPoint
				if k < len(tx.TxIn) {
					op = tx.TxIn[k].PreviousOutPoint
				}
				idx.muhash.Remove(coinRecord(op, spent.Height, spent.Coinbase, spent.TxOut.Value, spent.TxOut.PkScript))
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

	// Finalize the running MuHash3072 into the 32-byte muhash digest for this
	// height. Finalize does not consume the accumulator, so subsequent blocks
	// continue from the same state.
	digest := idx.muhash.Finalize()

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
	copy(stats.HashSerialized[:], digest[:])

	batch := idx.db.NewBatch()
	key := MakeCoinStatsKey(height)
	batch.Put(key, stats.Serialize())
	// Snapshot the accumulator as of this height so RevertBlock can restore the
	// previous height's accumulator without undo data or a replay.
	mhSer := idx.muhash.MuHashSerialize()
	batch.Put(MakeCoinStatsMuHashKey(height), mhSer)

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
	copy(state.UTXOHash[:], digest[:])
	batch.Put(CoinStatsStateKey, state.Serialize())
	// Persist the full current accumulator (768B) so incremental hashing
	// survives a restart. The per-height digest above is not enough to resume
	// Insert/Remove.
	batch.Put(CoinStatsMuHashKey, mhSer)

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
	var prevDigest wire.Hash256
	if prevHeight >= 0 {
		prevStats, err := idx.GetStats(prevHeight)
		if err != nil {
			return err
		}

		idx.txCount = prevStats.TxCount
		idx.utxoCount = prevStats.UTXOCount
		idx.totalAmount = prevStats.TotalAmount
		idx.bogoSize = prevStats.BogoSize
		prevDigest = prevStats.HashSerialized
		idx.subsidy = prevStats.TotalSubsidy
		idx.fees = prevStats.TotalFees

		// Restore the MuHash3072 accumulator from the previous height's
		// snapshot. The 32-byte digest is one-way, so the full 768-byte
		// accumulator snapshot (written in WriteBlock) is what we resume from.
		mhData, err := idx.db.Get(MakeCoinStatsMuHashKey(prevHeight))
		if err != nil {
			return err
		}
		if mhData == nil {
			idx.muhash = crypto.NewMuHash3072()
		} else {
			mh, derr := crypto.MuHashDeserialize(mhData)
			if derr != nil {
				return derr
			}
			idx.muhash = mh
		}
	} else {
		// Reverting to before genesis
		idx.txCount = 0
		idx.utxoCount = 0
		idx.totalAmount = 0
		idx.bogoSize = 0
		idx.muhash = crypto.NewMuHash3072()
		idx.subsidy = 0
		idx.fees = 0
	}

	batch := idx.db.NewBatch()

	// Delete stats + per-height accumulator at this height
	batch.Delete(MakeCoinStatsKey(height))
	batch.Delete(MakeCoinStatsMuHashKey(height))

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
	state.UTXOHash = prevDigest
	batch.Put(CoinStatsStateKey, state.Serialize())
	// Re-point the global accumulator key at the restored accumulator.
	batch.Put(CoinStatsMuHashKey, idx.muhash.MuHashSerialize())

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

// getBogoSize returns the database-independent size metric for a UTXO.
// Mirrors Bitcoin Core kernel/coinstats.cpp:35-43 GetBogoSize exactly:
//
//	32 (txid) + 4 (vout index) + 4 (height+coinbase) + 8 (amount) +
//	2 (scriptPubKey varint) + len(scriptPubKey) = 50 + len.
func getBogoSize(pkScript []byte) uint64 {
	return uint64(32 + 4 + 4 + 8 + 2 + len(pkScript))
}

// isUnspendable reports whether a scriptPubKey is provably unspendable.
// Mirrors Bitcoin Core script.h:563-566 CScript::IsUnspendable():
//
//	return (size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE);
//
// Key divergences from the old implementation:
//   - Empty scripts are SPENDABLE (Core includes them in the UTXO set).
//   - Scripts longer than MAX_SCRIPT_SIZE (10000) are unspendable regardless
//     of their first byte (they can never be executed within consensus rules).
const maxScriptSize = 10000
const opReturn = 0x6a

func isUnspendable(pkScript []byte) bool {
	return (len(pkScript) > 0 && pkScript[0] == opReturn) || len(pkScript) > maxScriptSize
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
