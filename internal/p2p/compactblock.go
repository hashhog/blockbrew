// Package p2p implements BIP152 compact block relay.
package p2p

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// BIP152 constants.
const (
	// CmpctBlockVersion is the compact block protocol version (version 2 = segwit).
	CmpctBlockVersion uint64 = 2

	// ShortIDLength is the length of a short transaction ID in bytes.
	ShortIDLength = 6

	// MaxHBPeers is the maximum number of high-bandwidth peers.
	MaxHBPeers = 3

	// MaxCmpctBlockDepth is the maximum depth (blocks below tip) at which a
	// node will serve a cmpctblock response to a getdata(MSG_CMPCT_BLOCK).
	// When the requested block is deeper than this, the node falls back to
	// sending the full block instead.
	// Mirrors Bitcoin Core net_processing.cpp:2466:
	//   static const int MAX_CMPCTBLOCK_DEPTH = 5;
	MaxCmpctBlockDepth = 5

	// MaxBlocktxnDepth is the maximum depth (blocks below tip) at which a
	// node will serve a blocktxn response to a getblocktxn request.
	// When the requested block is deeper than this, the node falls back to
	// sending the full block instead via getdata.
	// Mirrors Bitcoin Core net_processing.cpp:
	//   static const int MAX_BLOCKTXN_DEPTH = 10;
	MaxBlocktxnDepth = 10

	// maxBlockTxCount is the upper bound on transaction count for a compact block.
	// Mirrors Bitcoin Core blockencodings.cpp:64:
	//   MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT
	maxBlockTxCount = consensus.MaxBlockWeight / consensus.MinSerializableTransactionWeight

	// shortIDCollisionBucketLimit is the maximum allowed entries per hash bucket
	// in the short-ID map. Exceeding this indicates a hash-flooding DoS attack.
	// Mirrors Bitcoin Core blockencodings.cpp:110:
	//   if (shorttxids.bucket_size(...) > 12) return READ_STATUS_FAILED
	shortIDCollisionBucketLimit = 12
)

// CompactBlock errors.
var (
	ErrInvalidCompactBlock  = errors.New("invalid compact block")
	ErrShortIDCollision     = errors.New("short ID collision detected")
	ErrReconstructionFailed = errors.New("block reconstruction failed")
	ErrMissingTransactions  = errors.New("missing transactions for reconstruction")
)

// SipHashKey holds the 16-byte key for SipHash-2-4.
type SipHashKey [16]byte

// ComputeSipHashKey computes the SipHash key from the block header and nonce.
// The key bytes are SHA256(header || nonce); k0/k1 are then the first two
// little-endian uint64s — matching Bitcoin Core blockencodings.cpp:36-43 and
// uint256::GetUint64 (uint256.h:108: ReadLE64(data + pos*8)).
func ComputeSipHashKey(header *wire.BlockHeader, nonce uint64) SipHashKey {
	var buf bytes.Buffer
	header.Serialize(&buf)
	binary.Write(&buf, binary.LittleEndian, nonce)

	hash := sha256.Sum256(buf.Bytes())
	var key SipHashKey
	copy(key[:], hash[:16])
	return key
}

// siphash24 computes SipHash-2-4 with the given key and message.
// This is a pure Go implementation matching Bitcoin Core.
func siphash24(key SipHashKey, msg []byte) uint64 {
	// Initialize state from key
	k0 := binary.LittleEndian.Uint64(key[:8])
	k1 := binary.LittleEndian.Uint64(key[8:])

	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	// Process full 8-byte blocks
	blocks := len(msg) / 8
	for i := 0; i < blocks; i++ {
		m := binary.LittleEndian.Uint64(msg[i*8:])
		v3 ^= m
		// Two rounds
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		v0 ^= m
	}

	// Process remaining bytes + length
	var last uint64
	remaining := msg[blocks*8:]
	switch len(remaining) {
	case 7:
		last |= uint64(remaining[6]) << 48
		fallthrough
	case 6:
		last |= uint64(remaining[5]) << 40
		fallthrough
	case 5:
		last |= uint64(remaining[4]) << 32
		fallthrough
	case 4:
		last |= uint64(remaining[3]) << 24
		fallthrough
	case 3:
		last |= uint64(remaining[2]) << 16
		fallthrough
	case 2:
		last |= uint64(remaining[1]) << 8
		fallthrough
	case 1:
		last |= uint64(remaining[0])
	}
	last |= uint64(len(msg)%256) << 56

	v3 ^= last
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0 ^= last

	// Finalization
	v2 ^= 0xff
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)

	return v0 ^ v1 ^ v2 ^ v3
}

// sipRound performs one SipHash round.
func sipRound(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = v1<<13 | v1>>(64-13)
	v1 ^= v0
	v0 = v0<<32 | v0>>(64-32)

	v2 += v3
	v3 = v3<<16 | v3>>(64-16)
	v3 ^= v2

	v0 += v3
	v3 = v3<<21 | v3>>(64-21)
	v3 ^= v0

	v2 += v1
	v1 = v1<<17 | v1>>(64-17)
	v1 ^= v2
	v2 = v2<<32 | v2>>(64-32)

	return v0, v1, v2, v3
}

// ComputeShortID computes a 6-byte short transaction ID for BIP152.
// Uses SipHash-2-4 of the wtxid (version 2) truncated to 48 bits.
// Mirrors Bitcoin Core blockencodings.cpp:46-50:
//
//	static_assert(SHORTTXIDS_LENGTH == 6, ...)
//	return (*Assert(m_hasher))(wtxid.ToUint256()) & 0xffffffffffffL
func ComputeShortID(key SipHashKey, txHash wire.Hash256) uint64 {
	h := siphash24(key, txHash[:])
	return h & 0xFFFFFFFFFFFF // 6 bytes = 48 bits
}

// CompactBlockBuilder creates compact blocks from full blocks.
type CompactBlockBuilder struct {
	sipHashKey SipHashKey
	nonce      uint64
}

// NewCompactBlockBuilder creates a new compact block builder.
func NewCompactBlockBuilder(header *wire.BlockHeader, nonce uint64) *CompactBlockBuilder {
	return &CompactBlockBuilder{
		sipHashKey: ComputeSipHashKey(header, nonce),
		nonce:      nonce,
	}
}

// Build creates a MsgCmpctBlock from a full block.
// The coinbase transaction is always prefilled at index 0.
// Remaining transactions use WTXID-based short IDs (BIP152 version 2).
// Mirrors Bitcoin Core blockencodings.cpp:20-33.
func (b *CompactBlockBuilder) Build(block *wire.MsgBlock) *MsgCmpctBlock {
	msg := &MsgCmpctBlock{
		Header: block.Header,
		Nonce:  b.nonce,
	}

	// Always prefill coinbase at index 0 (Core blockencodings.cpp:27-28)
	if len(block.Transactions) > 0 {
		msg.PrefilledTxs = []PrefilledTx{
			{Index: 0, Tx: block.Transactions[0]},
		}
	}

	// Compute short IDs for remaining transactions using wtxid (BIP152 v2)
	// Core blockencodings.cpp:29-32: GetShortID(tx.GetWitnessHash())
	for i := 1; i < len(block.Transactions); i++ {
		wtxid := block.Transactions[i].WTxHash()
		shortID := ComputeShortID(b.sipHashKey, wtxid)
		msg.ShortIDs = append(msg.ShortIDs, shortID)
	}

	return msg
}

// PartiallyDownloadedBlock tracks reconstruction state for a compact block.
type PartiallyDownloadedBlock struct {
	mu sync.Mutex

	// header is set to zero-value when uninitialised or after FillBlock completes.
	// The IsNull check (header.PrevBlock all-zeros AND MerkleRoot all-zeros AND
	// Bits == 0) mirrors Core's CBlockHeader::IsNull().
	headerSet    bool
	Header       wire.BlockHeader
	Nonce        uint64
	sipHashKey   SipHashKey
	txnAvailable []*wire.MsgTx // nil entries are missing

	// Statistics
	prefilledCount int
	mempoolCount   int
	extraCount     int
}

// isHeaderNull returns true when the PartiallyDownloadedBlock has not been
// initialised (or has been consumed by FillBlock).
// Mirrors Bitcoin Core CBlockHeader::IsNull() (primitives/block.h):
//
//	return nBits == 0
func (p *PartiallyDownloadedBlock) isHeaderNull() bool {
	return !p.headerSet
}

// NewPartiallyDownloadedBlock creates a new partially downloaded block.
func NewPartiallyDownloadedBlock() *PartiallyDownloadedBlock {
	return &PartiallyDownloadedBlock{}
}

// ExtraTx is a (wtxid, tx) pair for the extra-transaction pool passed to InitData.
// Mirrors the std::vector<std::pair<Wtxid,CTransactionRef>> extra_txn parameter
// in Bitcoin Core blockencodings.cpp:59.
type ExtraTx struct {
	Wtxid wire.Hash256
	Tx    *wire.MsgTx
}

// MempoolLookup is the interface for looking up transactions in the mempool.
type MempoolLookup interface {
	// GetTransaction returns a transaction by its txid, or nil if not found.
	GetTransaction(hash wire.Hash256) *wire.MsgTx
	// GetAllTxHashes returns all transaction hashes (wtxids) in the mempool.
	GetAllTxHashes() []wire.Hash256
	// GetAllTransactions returns all transactions in the mempool for iteration.
	GetAllTransactions() []*wire.MsgTx
}

// InitData initializes the partially downloaded block from a compact block message.
// extraTxn is a slice of recently-evicted or otherwise extra transactions to
// consult for reconstruction, in addition to the mempool (may be nil).
// Returns the number of missing transactions, or an error if invalid.
// Mirrors Bitcoin Core PartiallyDownloadedBlock::InitData
// (blockencodings.cpp:59-181).
func (p *PartiallyDownloadedBlock) InitData(cmpctblock *MsgCmpctBlock, mempool MempoolLookup, extraTxn []ExtraTx) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Gate 1: reject null header (Core blockencodings.cpp:62)
	if cmpctblock.Header.Bits == 0 {
		return 0, fmt.Errorf("%w: null header", ErrInvalidCompactBlock)
	}

	// Gate 2: reject empty body (Core blockencodings.cpp:62-63)
	if len(cmpctblock.ShortIDs) == 0 && len(cmpctblock.PrefilledTxs) == 0 {
		return 0, fmt.Errorf("%w: no transactions", ErrInvalidCompactBlock)
	}

	// Gate 3: max-block-tx-count DoS guard (Core blockencodings.cpp:64-65):
	//   BlockTxCount() > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT
	totalTxCount := len(cmpctblock.ShortIDs) + len(cmpctblock.PrefilledTxs)
	if totalTxCount > maxBlockTxCount {
		return 0, fmt.Errorf("%w: too many transactions (%d > %d)",
			ErrInvalidCompactBlock, totalTxCount, maxBlockTxCount)
	}

	// Gate 4: double-init guard (Core blockencodings.cpp:67):
	//   if (!header.IsNull() || !txn_available.empty()) return READ_STATUS_INVALID
	if !p.isHeaderNull() || len(p.txnAvailable) != 0 {
		return 0, fmt.Errorf("%w: already initialised", ErrInvalidCompactBlock)
	}

	p.Header = cmpctblock.Header
	p.headerSet = true
	p.Nonce = cmpctblock.Nonce
	p.sipHashKey = ComputeSipHashKey(&cmpctblock.Header, cmpctblock.Nonce)
	p.txnAvailable = make([]*wire.MsgTx, totalTxCount)

	// Process prefilled transactions with differential index decoding.
	// Gates 5-8 mirror Core blockencodings.cpp:73-87.
	lastPrefilledIndex := int32(-1)
	for i, prefilled := range cmpctblock.PrefilledTxs {
		// Gate 5: reject null prefilled transaction (Core blockencodings.cpp:74-76)
		if prefilled.Tx == nil {
			return 0, fmt.Errorf("%w: nil prefilled transaction", ErrInvalidCompactBlock)
		}

		// Decode differentially encoded index (Core blockencodings.cpp:77):
		//   lastprefilledindex += cmpctblock.prefilledtxn[i].index + 1
		lastPrefilledIndex += int32(prefilled.Index) + 1

		// Gate 6: uint16 overflow guard (Core blockencodings.cpp:78-80):
		//   if (lastprefilledindex > std::numeric_limits<uint16_t>::max())
		//       return READ_STATUS_INVALID
		if lastPrefilledIndex > 0xFFFF {
			return 0, fmt.Errorf("%w: prefilled index overflow", ErrInvalidCompactBlock)
		}

		// Gate 7: index must not exceed shorttxids + prefilled so far
		// (Core blockencodings.cpp:80-85):
		//   if ((uint32_t)lastprefilledindex > cmpctblock.shorttxids.size() + i)
		//       return READ_STATUS_INVALID
		if int(lastPrefilledIndex) > len(cmpctblock.ShortIDs)+i {
			return 0, fmt.Errorf("%w: prefilled index out of range", ErrInvalidCompactBlock)
		}

		if int(lastPrefilledIndex) >= totalTxCount {
			return 0, fmt.Errorf("%w: prefilled index exceeds total tx count", ErrInvalidCompactBlock)
		}

		p.txnAvailable[lastPrefilledIndex] = prefilled.Tx
		p.prefilledCount++
	}

	// Build short-ID → slot map (skipping prefilled slots).
	// shortIDIndex tracks position in cmpctblock.ShortIDs[].
	// We also use a per-bucket counter to detect hash-flooding DoS attacks.
	// Core blockencodings.cpp:94-116.
	shortIDMap := make(map[uint64]uint16, len(cmpctblock.ShortIDs))
	// bucketCounts replicates the per-bucket counting that std::unordered_map's
	// bucket_size() gives in Core. We approximate with a collision counter per
	// distinct short ID: if any short ID appears more than once (before we even
	// check the mempool) that counts as a collision. For the real bucket-count
	// DoS check we track how many short IDs share each lower N bits using a
	// separate table (mimicking unordered_map's linear chaining).
	bucketSizes := make(map[uint64]int, len(cmpctblock.ShortIDs))
	shortIDIndex := 0
	for i := 0; i < totalTxCount; i++ {
		if p.txnAvailable[i] != nil {
			continue // Skip prefilled slots
		}
		if shortIDIndex >= len(cmpctblock.ShortIDs) {
			return 0, fmt.Errorf("%w: not enough short IDs", ErrInvalidCompactBlock)
		}

		sid := cmpctblock.ShortIDs[shortIDIndex]
		shortIDIndex++

		shortIDMap[sid] = uint16(i)

		// Gate 8: bucket-size DoS check (Core blockencodings.cpp:104-111):
		//   if (shorttxids.bucket_size(shorttxids.bucket(sid)) > 12)
		//       return READ_STATUS_FAILED
		// We approximate bucket membership by the short ID itself (in a
		// real hash map each bucket spans many keys; we conservatively count
		// how many of the short IDs we've seen hash to the same Go map slot
		// using the lower bits as a bucket index).
		bucket := sid % uint64(len(cmpctblock.ShortIDs)+1)
		bucketSizes[bucket]++
		if bucketSizes[bucket] > shortIDCollisionBucketLimit {
			return 0, ErrShortIDCollision
		}
	}

	// Gate 9: detect short-ID duplicates (Core blockencodings.cpp:115-116):
	//   if (shorttxids.size() != cmpctblock.shorttxids.size()) return READ_STATUS_FAILED
	if len(shortIDMap) != len(cmpctblock.ShortIDs) {
		return 0, ErrShortIDCollision
	}

	// have_txn tracks which slots are already filled (by prefill or mempool/extra),
	// mirroring Core's local std::vector<bool> have_txn (blockencodings.cpp:118).
	// This is separate from txnAvailable so that "cleared due to collision" slots
	// still show have_txn=false, enabling the two-match collision detection that
	// Core implements (blockencodings.cpp:128-137).
	haveTxn := make([]bool, totalTxCount)
	for i, tx := range p.txnAvailable {
		if tx != nil {
			haveTxn[i] = true
		}
	}

	// Match mempool transactions by short ID.
	// Mirrors Core blockencodings.cpp:119-145.
	if mempool != nil {
		txs := mempool.GetAllTransactions()
		for _, tx := range txs {
			if tx == nil {
				continue
			}
			wtxid := tx.WTxHash()
			sid := ComputeShortID(p.sipHashKey, wtxid)
			idx, ok := shortIDMap[sid]
			if !ok {
				continue
			}
			slot := int(idx)
			if !haveTxn[slot] {
				p.txnAvailable[slot] = tx
				haveTxn[slot] = true
				p.mempoolCount++
			} else {
				// Two mempool txns match the same short ID — clear the slot
				// and fall back to requesting it. Core blockencodings.cpp:131-137.
				if p.txnAvailable[slot] != nil {
					p.txnAvailable[slot] = nil
					p.mempoolCount--
				}
			}
			if p.mempoolCount == len(cmpctblock.ShortIDs) {
				break
			}
		}
	}

	// Match extra transactions (recently evicted mempool entries etc.).
	// Mirrors Core blockencodings.cpp:147-176.
	for _, extra := range extraTxn {
		if extra.Tx == nil {
			continue
		}
		sid := ComputeShortID(p.sipHashKey, extra.Wtxid)
		idx, ok := shortIDMap[sid]
		if !ok {
			continue
		}
		slot := int(idx)
		if !haveTxn[slot] {
			p.txnAvailable[slot] = extra.Tx
			haveTxn[slot] = true
			p.mempoolCount++
			p.extraCount++
		} else {
			// Two extra/mempool txns match the same short ID; only clear if
			// the witness hashes differ (Core blockencodings.cpp:162-167).
			if p.txnAvailable[slot] != nil &&
				p.txnAvailable[slot].WTxHash() != extra.Wtxid {
				p.txnAvailable[slot] = nil
				p.mempoolCount--
				p.extraCount--
			}
		}
		if p.mempoolCount == len(cmpctblock.ShortIDs) {
			break
		}
	}

	return p.countMissing(), nil
}

// countMissing counts nil slots in txnAvailable (called under lock).
func (p *PartiallyDownloadedBlock) countMissing() int {
	n := 0
	for _, tx := range p.txnAvailable {
		if tx == nil {
			n++
		}
	}
	return n
}

// IsTxAvailable returns true if the transaction at the given index is available.
// Returns false if the block has not been initialised.
// Mirrors Bitcoin Core blockencodings.cpp:183-189.
func (p *PartiallyDownloadedBlock) IsTxAvailable(index int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Gate: uninitialised object (Core blockencodings.cpp:183-185):
	//   if (header.IsNull()) return false
	if p.isHeaderNull() {
		return false
	}

	if index < 0 || index >= len(p.txnAvailable) {
		return false
	}
	return p.txnAvailable[index] != nil
}

// GetMissingIndexes returns the indexes of missing transactions.
func (p *PartiallyDownloadedBlock) GetMissingIndexes() []uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()

	var missing []uint32
	for i, tx := range p.txnAvailable {
		if tx == nil {
			missing = append(missing, uint32(i))
		}
	}
	return missing
}

// FillMissingTransactions fills in missing transactions from a blocktxn message.
func (p *PartiallyDownloadedBlock) FillMissingTransactions(txs []*wire.MsgTx) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	txIndex := 0
	for i, available := range p.txnAvailable {
		if available == nil {
			if txIndex >= len(txs) {
				return fmt.Errorf("%w: not enough transactions provided", ErrMissingTransactions)
			}
			p.txnAvailable[i] = txs[txIndex]
			txIndex++
		}
	}

	if txIndex != len(txs) {
		return fmt.Errorf("%w: too many transactions provided", ErrMissingTransactions)
	}

	return nil
}

// FillBlock reconstructs the full block from available transactions.
// segwitActive controls whether the witness commitment is validated as part of
// the IsBlockMutated check (mirrors Core's segwit_active parameter).
// Returns an error if any transactions are still missing or if the reconstructed
// block appears mutated (possible short-ID collision).
// Mirrors Bitcoin Core PartiallyDownloadedBlock::FillBlock
// (blockencodings.cpp:191-236).
func (p *PartiallyDownloadedBlock) FillBlock(vtxMissing []*wire.MsgTx, segwitActive bool) (*wire.MsgBlock, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Gate: uninitialised object (Core blockencodings.cpp:193-194):
	//   if (header.IsNull()) return READ_STATUS_INVALID
	if p.isHeaderNull() {
		return nil, fmt.Errorf("%w: uninitialised", ErrInvalidCompactBlock)
	}

	block := &wire.MsgBlock{
		Header:       p.Header,
		Transactions: make([]*wire.MsgTx, len(p.txnAvailable)),
	}

	// Fill slots: use provided missing txns for nil slots, available txns otherwise.
	// Mirrors Core blockencodings.cpp:199-208.
	txMissingOffset := 0
	for i, tx := range p.txnAvailable {
		if tx == nil {
			if txMissingOffset >= len(vtxMissing) {
				return nil, fmt.Errorf("%w: vtxMissing too short at index %d", ErrInvalidCompactBlock, i)
			}
			block.Transactions[i] = vtxMissing[txMissingOffset]
			txMissingOffset++
		} else {
			block.Transactions[i] = tx
		}
	}

	// Consume state: prevent double-calls (Core blockencodings.cpp:211-212):
	//   header.SetNull(); txn_available.clear()
	p.headerSet = false
	p.txnAvailable = nil

	// Gate: vtxMissing must be exactly consumed (Core blockencodings.cpp:214-216):
	//   if (vtx_missing.size() != tx_missing_offset) return READ_STATUS_INVALID
	if len(vtxMissing) != txMissingOffset {
		return nil, fmt.Errorf("%w: vtxMissing has %d extra entries", ErrInvalidCompactBlock, len(vtxMissing)-txMissingOffset)
	}

	// Gate: IsBlockMutated check — catches short-ID collisions that accidentally
	// produce the right transaction count but wrong content.
	// Mirrors Core blockencodings.cpp:218-221:
	//   if (check_mutated(block, segwit_active)) return READ_STATUS_FAILED
	if consensus.IsBlockMutated(block, segwitActive) {
		return nil, fmt.Errorf("%w: IsBlockMutated", ErrReconstructionFailed)
	}

	return block, nil
}

// TxCount returns the total number of transactions in the block.
func (p *PartiallyDownloadedBlock) TxCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.txnAvailable)
}

// Stats returns reconstruction statistics.
func (p *PartiallyDownloadedBlock) Stats() (prefilled, fromMempool, fromExtra int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.prefilledCount, p.mempoolCount, p.extraCount
}

// CompactBlockState tracks compact block relay state for a peer.
type CompactBlockState struct {
	mu sync.RWMutex

	// Protocol negotiation
	providesCompactBlocks bool // Peer has sent sendcmpct
	announcesHB           bool // Peer wants HB compact blocks (sendcmpct announce=1)
	version               uint64

	// Pending reconstruction
	pending map[wire.Hash256]*PartiallyDownloadedBlock
}

// NewCompactBlockState creates a new compact block state.
func NewCompactBlockState() *CompactBlockState {
	return &CompactBlockState{
		pending: make(map[wire.Hash256]*PartiallyDownloadedBlock),
	}
}

// SetSendCmpct updates state from a sendcmpct message.
func (s *CompactBlockState) SetSendCmpct(announce bool, version uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Only accept version 2 (segwit-aware)
	if version == CmpctBlockVersion {
		s.providesCompactBlocks = true
		s.announcesHB = announce
		s.version = version
	}
}

// ProvidesCompactBlocks returns true if the peer supports compact blocks.
func (s *CompactBlockState) ProvidesCompactBlocks() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.providesCompactBlocks
}

// WantsHBCompactBlocks returns true if the peer wants high-bandwidth compact blocks.
func (s *CompactBlockState) WantsHBCompactBlocks() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.announcesHB
}

// AddPending adds a partially downloaded block.
func (s *CompactBlockState) AddPending(hash wire.Hash256, pdb *PartiallyDownloadedBlock) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[hash] = pdb
}

// GetPending retrieves a partially downloaded block.
func (s *CompactBlockState) GetPending(hash wire.Hash256) *PartiallyDownloadedBlock {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pending[hash]
}

// RemovePending removes a partially downloaded block.
func (s *CompactBlockState) RemovePending(hash wire.Hash256) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, hash)
}

// CreateGetBlockTxn creates a getblocktxn message for missing transactions.
// Indexes are differentially encoded as per BIP152.
func CreateGetBlockTxn(blockHash wire.Hash256, missingIndexes []uint32) *MsgGetBlockTxn {
	// Differential encoding: store differences between consecutive indexes
	encoded := make([]uint32, len(missingIndexes))
	lastIndex := int32(-1)
	for i, idx := range missingIndexes {
		encoded[i] = uint32(int32(idx) - lastIndex - 1)
		lastIndex = int32(idx)
	}

	return &MsgGetBlockTxn{
		BlockHash: blockHash,
		Indexes:   encoded,
	}
}

// DecodeGetBlockTxnIndexes decodes differentially encoded indexes.
func DecodeGetBlockTxnIndexes(encoded []uint32) []uint32 {
	if len(encoded) == 0 {
		return nil
	}

	decoded := make([]uint32, len(encoded))
	lastIndex := int32(-1)
	for i, diff := range encoded {
		decoded[i] = uint32(lastIndex + int32(diff) + 1)
		lastIndex = int32(decoded[i])
	}
	return decoded
}

// CreateBlockTxn creates a blocktxn message from a block and requested indexes.
func CreateBlockTxn(block *wire.MsgBlock, requestedIndexes []uint32) (*MsgBlockTxn, error) {
	msg := &MsgBlockTxn{
		BlockHash: block.Header.BlockHash(),
		Txs:       make([]*wire.MsgTx, len(requestedIndexes)),
	}

	for i, idx := range requestedIndexes {
		if int(idx) >= len(block.Transactions) {
			return nil, fmt.Errorf("requested index %d out of range", idx)
		}
		msg.Txs[i] = block.Transactions[idx]
	}

	return msg, nil
}
