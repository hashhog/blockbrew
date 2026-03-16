// Package p2p implements BIP152 compact block relay.
package p2p

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

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
)

// CompactBlock errors.
var (
	ErrInvalidCompactBlock = errors.New("invalid compact block")
	ErrShortIDCollision    = errors.New("short ID collision detected")
	ErrReconstructionFailed = errors.New("block reconstruction failed")
	ErrMissingTransactions = errors.New("missing transactions for reconstruction")
)

// SipHashKey holds the 16-byte key for SipHash-2-4.
type SipHashKey [16]byte

// ComputeSipHashKey computes the SipHash key from the block header and nonce.
// The key is SHA256(header || nonce)[0:16].
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
// Uses SipHash-2-4 of the wtxid (or txid for version 1), truncated to 6 bytes.
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
func (b *CompactBlockBuilder) Build(block *wire.MsgBlock) *MsgCmpctBlock {
	msg := &MsgCmpctBlock{
		Header: block.Header,
		Nonce:  b.nonce,
	}

	// Always prefill coinbase at index 0
	if len(block.Transactions) > 0 {
		msg.PrefilledTxs = []PrefilledTx{
			{Index: 0, Tx: block.Transactions[0]},
		}
	}

	// Compute short IDs for remaining transactions using wtxid
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

	Header       wire.BlockHeader
	Nonce        uint64
	sipHashKey   SipHashKey
	txnAvailable []*wire.MsgTx // nil entries are missing

	// Short ID to index mapping
	shortIDToIndex map[uint64]int

	// Statistics
	prefilledCount int
	mempoolCount   int
	missingCount   int
}

// NewPartiallyDownloadedBlock creates a new partially downloaded block.
func NewPartiallyDownloadedBlock() *PartiallyDownloadedBlock {
	return &PartiallyDownloadedBlock{
		shortIDToIndex: make(map[uint64]int),
	}
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
// Returns the number of missing transactions, or an error if invalid.
func (p *PartiallyDownloadedBlock) InitData(cmpctblock *MsgCmpctBlock, mempool MempoolLookup) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Validate basic structure - allow genesis block (prevBlock=0) but must have transactions
	// The block header's validity is checked elsewhere

	// Calculate total transaction count
	totalTxCount := len(cmpctblock.ShortIDs) + len(cmpctblock.PrefilledTxs)
	if totalTxCount == 0 {
		return 0, ErrInvalidCompactBlock
	}

	// Initialize state
	p.Header = cmpctblock.Header
	p.Nonce = cmpctblock.Nonce
	p.sipHashKey = ComputeSipHashKey(&cmpctblock.Header, cmpctblock.Nonce)
	p.txnAvailable = make([]*wire.MsgTx, totalTxCount)
	p.shortIDToIndex = make(map[uint64]int)

	// Process prefilled transactions (differential encoding)
	lastPrefilledIndex := -1
	for _, prefilled := range cmpctblock.PrefilledTxs {
		// Decode differentially encoded index
		index := lastPrefilledIndex + int(prefilled.Index) + 1
		if index < 0 || index >= totalTxCount {
			return 0, fmt.Errorf("%w: prefilled index out of range", ErrInvalidCompactBlock)
		}
		lastPrefilledIndex = index

		if prefilled.Tx == nil {
			return 0, fmt.Errorf("%w: nil prefilled transaction", ErrInvalidCompactBlock)
		}

		p.txnAvailable[index] = prefilled.Tx
		p.prefilledCount++
	}

	// Build short ID to index mapping (skipping prefilled positions)
	shortIDIndex := 0
	for i := 0; i < totalTxCount; i++ {
		if p.txnAvailable[i] != nil {
			continue // Skip prefilled
		}
		if shortIDIndex >= len(cmpctblock.ShortIDs) {
			return 0, fmt.Errorf("%w: not enough short IDs", ErrInvalidCompactBlock)
		}

		shortID := cmpctblock.ShortIDs[shortIDIndex]
		// Check for collision in mapping
		if _, exists := p.shortIDToIndex[shortID]; exists {
			return 0, ErrShortIDCollision
		}
		p.shortIDToIndex[shortID] = i
		shortIDIndex++
	}

	// Match mempool transactions by short ID
	if mempool != nil {
		p.matchMempool(mempool)
	}

	// Count missing
	p.missingCount = 0
	for _, tx := range p.txnAvailable {
		if tx == nil {
			p.missingCount++
		}
	}

	return p.missingCount, nil
}

// matchMempool matches mempool transactions against short IDs.
func (p *PartiallyDownloadedBlock) matchMempool(mempool MempoolLookup) {
	txs := mempool.GetAllTransactions()

	for _, tx := range txs {
		if tx == nil {
			continue
		}

		// Compute short ID using wtxid
		wtxid := tx.WTxHash()
		shortID := ComputeShortID(p.sipHashKey, wtxid)

		if index, ok := p.shortIDToIndex[shortID]; ok {
			if p.txnAvailable[index] == nil {
				p.txnAvailable[index] = tx
				p.mempoolCount++
				delete(p.shortIDToIndex, shortID)
			} else if p.txnAvailable[index].WTxHash() != wtxid {
				// Collision with different transaction - clear it
				p.txnAvailable[index] = nil
				p.mempoolCount--
			}
		}

		// Early exit if all matched
		if len(p.shortIDToIndex) == 0 {
			break
		}
	}
}

// IsTxAvailable returns true if the transaction at the given index is available.
func (p *PartiallyDownloadedBlock) IsTxAvailable(index int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

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

	p.missingCount = 0
	return nil
}

// FillBlock reconstructs the full block from available transactions.
// Returns an error if any transactions are still missing.
func (p *PartiallyDownloadedBlock) FillBlock() (*wire.MsgBlock, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check for missing transactions
	for i, tx := range p.txnAvailable {
		if tx == nil {
			return nil, fmt.Errorf("%w: transaction at index %d is missing", ErrReconstructionFailed, i)
		}
	}

	block := &wire.MsgBlock{
		Header:       p.Header,
		Transactions: make([]*wire.MsgTx, len(p.txnAvailable)),
	}

	for i, tx := range p.txnAvailable {
		block.Transactions[i] = tx
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
func (p *PartiallyDownloadedBlock) Stats() (prefilled, fromMempool, missing int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.prefilledCount, p.mempoolCount, p.missingCount
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
