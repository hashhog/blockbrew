package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"sort"
	"sync"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// AssumeUTXO errors.
var (
	ErrInvalidSnapshotMagic    = errors.New("invalid snapshot magic bytes")
	ErrUnsupportedVersion      = errors.New("unsupported snapshot version")
	ErrNetworkMismatch         = errors.New("snapshot network does not match node network")
	ErrUnknownSnapshotHeight   = errors.New("snapshot height not recognized in assumeutxo params")
	ErrSnapshotHashMismatch    = errors.New("snapshot UTXO hash does not match expected value")
	ErrSnapshotAlreadyLoaded   = errors.New("a snapshot chainstate is already loaded")
	ErrSnapshotBlockNotFound   = errors.New("snapshot base block not found in headers")
	ErrBackgroundValidationFailed = errors.New("background validation failed to match snapshot")
)

// SnapshotMagic is the magic bytes identifying a UTXO snapshot file.
// Matches Bitcoin Core: "utxo\xff"
var SnapshotMagic = [5]byte{'u', 't', 'x', 'o', 0xff}

// SnapshotVersion is the current snapshot format version.
const SnapshotVersion uint16 = 2

// SnapshotMetadata contains the header information for a UTXO snapshot.
type SnapshotMetadata struct {
	Magic        [5]byte
	Version      uint16
	NetworkMagic [4]byte // Message start bytes for the network
	BlockHash    wire.Hash256
	CoinsCount   uint64
}

// Serialize writes the snapshot metadata to a writer.
func (m *SnapshotMetadata) Serialize(w io.Writer) error {
	if _, err := w.Write(m.Magic[:]); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, m.Version); err != nil {
		return err
	}
	if _, err := w.Write(m.NetworkMagic[:]); err != nil {
		return err
	}
	if err := m.BlockHash.Serialize(w); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, m.CoinsCount); err != nil {
		return err
	}
	return nil
}

// Deserialize reads snapshot metadata from a reader.
func (m *SnapshotMetadata) Deserialize(r io.Reader) error {
	if _, err := io.ReadFull(r, m.Magic[:]); err != nil {
		return err
	}
	if m.Magic != SnapshotMagic {
		return ErrInvalidSnapshotMagic
	}
	if err := binary.Read(r, binary.LittleEndian, &m.Version); err != nil {
		return err
	}
	if m.Version != SnapshotVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, m.Version, SnapshotVersion)
	}
	if _, err := io.ReadFull(r, m.NetworkMagic[:]); err != nil {
		return err
	}
	if err := m.BlockHash.Deserialize(r); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &m.CoinsCount); err != nil {
		return err
	}
	return nil
}

// AssumeUTXOData contains the expected values for a known-good UTXO snapshot.
type AssumeUTXOData struct {
	Height       int32
	HashSerialized wire.Hash256 // SHA256 hash of the serialized UTXO set
	ChainTxCount uint64        // Total transactions in the chain up to this block
	BlockHash    wire.Hash256  // The block hash at this height
}

// AssumeUTXOParams maps heights to known-good snapshot data.
type AssumeUTXOParams struct {
	Data []AssumeUTXOData
}

// ForHeight returns the AssumeUTXO data for a given height, if available.
func (p *AssumeUTXOParams) ForHeight(height int32) *AssumeUTXOData {
	for i := range p.Data {
		if p.Data[i].Height == height {
			return &p.Data[i]
		}
	}
	return nil
}

// ForBlockHash returns the AssumeUTXO data for a given block hash, if available.
func (p *AssumeUTXOParams) ForBlockHash(hash wire.Hash256) *AssumeUTXOData {
	for i := range p.Data {
		if p.Data[i].BlockHash == hash {
			return &p.Data[i]
		}
	}
	return nil
}

// AvailableHeights returns all heights for which snapshot data is available.
func (p *AssumeUTXOParams) AvailableHeights() []int32 {
	heights := make([]int32, len(p.Data))
	for i, d := range p.Data {
		heights[i] = d.Height
	}
	return heights
}

// ChainstateRole indicates whether a chainstate is validated or snapshot-based.
type ChainstateRole int

const (
	// ChainstateRoleValidated means this chainstate has been fully validated from genesis.
	ChainstateRoleValidated ChainstateRole = iota
	// ChainstateRoleSnapshot means this chainstate was loaded from a snapshot and not yet validated.
	ChainstateRoleSnapshot
	// ChainstateRoleInvalid means the snapshot was found to be invalid during background validation.
	ChainstateRoleInvalid
)

// Chainstate represents a single chain state (UTXO set at a particular chain tip).
type Chainstate struct {
	mu sync.RWMutex

	// Core state
	utxoSet   *UTXOSet
	tipNode   *BlockNode
	tipHeight int32

	// Snapshot metadata (only set for snapshot-based chainstates)
	fromSnapshotBlockHash *wire.Hash256 // The block this snapshot was built from
	role                  ChainstateRole

	// Background validation target (only set for the IBD chainstate when validating a snapshot)
	targetBlockHash *wire.Hash256
}

// NewChainstate creates a new chainstate with the given UTXO set.
func NewChainstate(utxoSet *UTXOSet) *Chainstate {
	return &Chainstate{
		utxoSet: utxoSet,
		role:    ChainstateRoleValidated,
	}
}

// NewSnapshotChainstate creates a chainstate from a loaded snapshot.
func NewSnapshotChainstate(utxoSet *UTXOSet, snapshotBlockHash wire.Hash256) *Chainstate {
	return &Chainstate{
		utxoSet:               utxoSet,
		role:                  ChainstateRoleSnapshot,
		fromSnapshotBlockHash: &snapshotBlockHash,
	}
}

// Role returns the chainstate's role.
func (cs *Chainstate) Role() ChainstateRole {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.role
}

// IsValidated returns true if this chainstate has been fully validated.
func (cs *Chainstate) IsValidated() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.role == ChainstateRoleValidated
}

// SnapshotBlockHash returns the block hash this snapshot was built from, if any.
func (cs *Chainstate) SnapshotBlockHash() *wire.Hash256 {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.fromSnapshotBlockHash
}

// MarkValidated marks this chainstate as validated after background validation succeeds.
func (cs *Chainstate) MarkValidated() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.role = ChainstateRoleValidated
}

// MarkInvalid marks this chainstate as invalid.
func (cs *Chainstate) MarkInvalid() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.role = ChainstateRoleInvalid
}

// SnapshotWriter handles writing UTXO snapshots to disk.
type SnapshotWriter struct {
	w            io.Writer
	networkMagic [4]byte
	coinsWritten uint64
	hasher       hash.Hash
}

// NewSnapshotWriter creates a new snapshot writer.
func NewSnapshotWriter(w io.Writer, networkMagic [4]byte) *SnapshotWriter {
	h := sha256.New()
	return &SnapshotWriter{
		w:            io.MultiWriter(w, h), // Write to both file and hasher
		networkMagic: networkMagic,
		hasher:       h,
	}
}

// WriteSnapshot writes the entire UTXO set to a snapshot file.
// The UTXOs are written in deterministic order (sorted by outpoint).
func WriteSnapshot(w io.Writer, utxoSet *UTXOSet, blockHash wire.Hash256, networkMagic [4]byte) (*SnapshotStats, error) {
	stats := &SnapshotStats{}

	// Collect all UTXOs for deterministic ordering
	// Note: In production, this would iterate the database directly with a cursor
	utxoSet.mu.RLock()
	coins := make([]struct {
		outpoint wire.OutPoint
		entry    *UTXOEntry
	}, 0)

	// Collect from cache (in production, would use DB cursor)
	for op, entry := range utxoSet.cache {
		if entry != nil {
			coins = append(coins, struct {
				outpoint wire.OutPoint
				entry    *UTXOEntry
			}{op, entry})
		}
	}
	utxoSet.mu.RUnlock()

	// Sort by outpoint for deterministic ordering
	sort.Slice(coins, func(i, j int) bool {
		// Compare txid first
		for k := 0; k < 32; k++ {
			if coins[i].outpoint.Hash[k] != coins[j].outpoint.Hash[k] {
				return coins[i].outpoint.Hash[k] < coins[j].outpoint.Hash[k]
			}
		}
		// Then by output index
		return coins[i].outpoint.Index < coins[j].outpoint.Index
	})

	// Write metadata
	metadata := &SnapshotMetadata{
		Magic:        SnapshotMagic,
		Version:      SnapshotVersion,
		NetworkMagic: networkMagic,
		BlockHash:    blockHash,
		CoinsCount:   uint64(len(coins)),
	}
	if err := metadata.Serialize(w); err != nil {
		return nil, fmt.Errorf("failed to write metadata: %w", err)
	}

	// Group coins by txid for compact serialization
	// Bitcoin Core format: txid, count, [vout, coin]...
	var lastTxid wire.Hash256
	var txCoins []struct {
		vout  uint32
		entry *UTXOEntry
	}

	flushTxCoins := func() error {
		if len(txCoins) == 0 {
			return nil
		}
		// Write txid
		if err := lastTxid.Serialize(w); err != nil {
			return err
		}
		// Write count of coins for this txid
		if err := wire.WriteCompactSize(w, uint64(len(txCoins))); err != nil {
			return err
		}
		// Write each coin
		for _, tc := range txCoins {
			// Write vout as compact size
			if err := wire.WriteCompactSize(w, uint64(tc.vout)); err != nil {
				return err
			}
			// Write coin data (height+coinbase, amount, script)
			if err := writeCoin(w, tc.entry); err != nil {
				return err
			}
			stats.CoinsWritten++
		}
		return nil
	}

	for _, coin := range coins {
		if coin.outpoint.Hash != lastTxid && len(txCoins) > 0 {
			if err := flushTxCoins(); err != nil {
				return nil, err
			}
			txCoins = txCoins[:0]
		}
		lastTxid = coin.outpoint.Hash
		txCoins = append(txCoins, struct {
			vout  uint32
			entry *UTXOEntry
		}{coin.outpoint.Index, coin.entry})
	}
	// Flush remaining coins
	if err := flushTxCoins(); err != nil {
		return nil, err
	}

	stats.BlockHash = blockHash
	stats.Height = -1 // Caller should set this
	return stats, nil
}

// writeCoin writes a single coin in the snapshot format.
func writeCoin(w io.Writer, entry *UTXOEntry) error {
	// Height and coinbase flag: (height << 1) | coinbase
	code := uint64(entry.Height) << 1
	if entry.IsCoinbase {
		code |= 1
	}
	var buf bytes.Buffer
	writeVaruint(&buf, code)

	// Amount
	writeVaruint(&buf, uint64(entry.Amount))

	// Script (compressed)
	compressed := CompressScript(entry.PkScript)
	writeVaruint(&buf, uint64(len(compressed)))
	buf.Write(compressed)

	_, err := w.Write(buf.Bytes())
	return err
}

// SnapshotStats contains statistics about a snapshot operation.
type SnapshotStats struct {
	CoinsWritten uint64
	BlockHash    wire.Hash256
	Height       int32
	HashSerialized wire.Hash256 // SHA256 of the entire snapshot
}

// SnapshotReader handles reading UTXO snapshots from disk.
type SnapshotReader struct {
	r        io.Reader
	metadata SnapshotMetadata
}

// NewSnapshotReader creates a new snapshot reader.
func NewSnapshotReader(r io.Reader) (*SnapshotReader, error) {
	sr := &SnapshotReader{r: r}
	if err := sr.metadata.Deserialize(r); err != nil {
		return nil, err
	}
	return sr, nil
}

// Metadata returns the snapshot metadata.
func (sr *SnapshotReader) Metadata() *SnapshotMetadata {
	return &sr.metadata
}

// LoadSnapshot loads a UTXO snapshot into a UTXOSet.
// Returns the populated UTXO set and statistics.
func LoadSnapshot(r io.Reader, db *storage.ChainDB, expectedNetworkMagic [4]byte) (*UTXOSet, *SnapshotLoadStats, error) {
	sr, err := NewSnapshotReader(r)
	if err != nil {
		return nil, nil, err
	}

	// Verify network magic
	if sr.metadata.NetworkMagic != expectedNetworkMagic {
		return nil, nil, ErrNetworkMismatch
	}

	// Create new UTXO set for the snapshot
	utxoSet := NewUTXOSet(db)
	stats := &SnapshotLoadStats{
		BlockHash: sr.metadata.BlockHash,
	}

	coinsLeft := sr.metadata.CoinsCount
	coinsLoaded := uint64(0)

	for coinsLeft > 0 {
		// Read txid
		var txid wire.Hash256
		if err := txid.Deserialize(r); err != nil {
			return nil, nil, fmt.Errorf("failed to read txid at coin %d: %w", coinsLoaded, err)
		}

		// Read count of coins for this txid
		count, err := wire.ReadCompactSize(r)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read coin count at coin %d: %w", coinsLoaded, err)
		}
		if count > coinsLeft {
			return nil, nil, fmt.Errorf("coin count %d exceeds remaining %d", count, coinsLeft)
		}

		// Read each coin
		for i := uint64(0); i < count; i++ {
			// Read vout
			vout, err := wire.ReadCompactSize(r)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read vout at coin %d: %w", coinsLoaded, err)
			}

			// Read coin data
			entry, err := readCoin(r)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read coin at %d: %w", coinsLoaded, err)
			}

			// Add to UTXO set
			outpoint := wire.OutPoint{Hash: txid, Index: uint32(vout)}
			utxoSet.AddUTXO(outpoint, entry)

			coinsLeft--
			coinsLoaded++

			// Log progress periodically
			if coinsLoaded%1000000 == 0 {
				log.Printf("[snapshot] loaded %d coins (%.2f%%)",
					coinsLoaded, float64(coinsLoaded)*100/float64(sr.metadata.CoinsCount))
			}
		}
	}

	// Verify we consumed all coins
	stats.CoinsLoaded = coinsLoaded

	// Flush to database
	if err := utxoSet.Flush(); err != nil {
		return nil, nil, fmt.Errorf("failed to flush UTXO set: %w", err)
	}

	log.Printf("[snapshot] loaded %d coins from snapshot", coinsLoaded)
	return utxoSet, stats, nil
}

// readCoin reads a single coin from the snapshot.
func readCoin(r io.Reader) (*UTXOEntry, error) {
	// Read height and coinbase flag
	code, err := readVaruintReader(r)
	if err != nil {
		return nil, err
	}
	height := int32(code >> 1)
	isCoinbase := (code & 1) == 1

	// Read amount
	amount, err := readVaruintReader(r)
	if err != nil {
		return nil, err
	}
	if amount > uint64(MaxMoney) {
		return nil, fmt.Errorf("invalid coin amount: %d", amount)
	}

	// Read script
	scriptLen, err := readVaruintReader(r)
	if err != nil {
		return nil, err
	}
	if scriptLen > MaxScriptSize {
		return nil, fmt.Errorf("script too large: %d", scriptLen)
	}
	compressed := make([]byte, scriptLen)
	if _, err := io.ReadFull(r, compressed); err != nil {
		return nil, err
	}
	pkScript := DecompressScript(compressed)

	return &UTXOEntry{
		Amount:     int64(amount),
		PkScript:   pkScript,
		Height:     height,
		IsCoinbase: isCoinbase,
	}, nil
}

// readVaruintReader reads a varint from an io.Reader.
func readVaruintReader(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}

	switch first[0] {
	case 0xFD:
		var buf [2]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return uint64(buf[0]) | uint64(buf[1])<<8, nil
	case 0xFE:
		var buf [4]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24, nil
	case 0xFF:
		var buf [8]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
			uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56, nil
	default:
		return uint64(first[0]), nil
	}
}

// SnapshotLoadStats contains statistics about a snapshot load operation.
type SnapshotLoadStats struct {
	CoinsLoaded uint64
	BlockHash   wire.Hash256
	Height      int32
}

// ComputeUTXOHash computes a deterministic hash of the UTXO set.
// This is used to verify snapshot integrity.
func ComputeUTXOHash(utxoSet *UTXOSet) (wire.Hash256, uint64, error) {
	utxoSet.mu.RLock()
	defer utxoSet.mu.RUnlock()

	// Collect all UTXOs
	type coinEntry struct {
		outpoint wire.OutPoint
		entry    *UTXOEntry
	}
	coins := make([]coinEntry, 0, len(utxoSet.cache))
	for op, entry := range utxoSet.cache {
		if entry != nil {
			coins = append(coins, coinEntry{op, entry})
		}
	}

	// Sort deterministically
	sort.Slice(coins, func(i, j int) bool {
		for k := 0; k < 32; k++ {
			if coins[i].outpoint.Hash[k] != coins[j].outpoint.Hash[k] {
				return coins[i].outpoint.Hash[k] < coins[j].outpoint.Hash[k]
			}
		}
		return coins[i].outpoint.Index < coins[j].outpoint.Index
	})

	// Hash all coins
	h := sha256.New()
	for _, c := range coins {
		// Serialize outpoint
		var buf bytes.Buffer
		c.outpoint.Serialize(&buf)
		h.Write(buf.Bytes())

		// Serialize entry
		buf.Reset()
		writeCoin(&buf, c.entry)
		h.Write(buf.Bytes())
	}

	var hash wire.Hash256
	copy(hash[:], h.Sum(nil))
	return hash, uint64(len(coins)), nil
}

// DualChainstateManager manages both a snapshot chainstate and a background validation chainstate.
type DualChainstateManager struct {
	mu sync.RWMutex

	// The active chainstate (snapshot-based after loading, validated after completion)
	activeChainstate *Chainstate

	// The background chainstate (validates from genesis)
	backgroundChainstate *Chainstate

	// Snapshot validation state
	snapshotBlockHash *wire.Hash256
	snapshotHeight    int32
	snapshotValidated bool

	// Expected hash from assumeutxo params
	expectedHash wire.Hash256

	// Chain parameters
	params *ChainParams

	// Callback when background validation completes
	onValidationComplete func(success bool)
}

// NewDualChainstateManager creates a manager for dual chainstate operation.
func NewDualChainstateManager(
	activeCS *Chainstate,
	backgroundCS *Chainstate,
	snapshotBlockHash wire.Hash256,
	snapshotHeight int32,
	expectedHash wire.Hash256,
	params *ChainParams,
) *DualChainstateManager {
	return &DualChainstateManager{
		activeChainstate:     activeCS,
		backgroundChainstate: backgroundCS,
		snapshotBlockHash:    &snapshotBlockHash,
		snapshotHeight:       snapshotHeight,
		expectedHash:         expectedHash,
		params:               params,
	}
}

// ActiveChainstate returns the currently active chainstate.
func (m *DualChainstateManager) ActiveChainstate() *Chainstate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activeChainstate
}

// BackgroundChainstate returns the background validation chainstate.
func (m *DualChainstateManager) BackgroundChainstate() *Chainstate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.backgroundChainstate
}

// IsSnapshotValidated returns whether the snapshot has been validated.
func (m *DualChainstateManager) IsSnapshotValidated() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshotValidated
}

// CheckBackgroundValidation checks if background validation has reached the snapshot point.
// If so, it verifies the UTXO hash matches and marks validation complete.
func (m *DualChainstateManager) CheckBackgroundValidation() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.snapshotValidated {
		return nil // Already validated
	}

	if m.backgroundChainstate == nil {
		return nil // No background validation
	}

	// Check if background chainstate has reached snapshot height
	m.backgroundChainstate.mu.RLock()
	bgHeight := m.backgroundChainstate.tipHeight
	m.backgroundChainstate.mu.RUnlock()

	if bgHeight < m.snapshotHeight {
		return nil // Not yet at snapshot height
	}

	// Background validation has reached the snapshot point
	// Compute the UTXO hash and compare
	computedHash, _, err := ComputeUTXOHash(m.backgroundChainstate.utxoSet)
	if err != nil {
		return fmt.Errorf("failed to compute UTXO hash: %w", err)
	}

	if computedHash != m.expectedHash {
		// Snapshot is invalid!
		log.Printf("[snapshot] ERROR: UTXO hash mismatch at height %d", m.snapshotHeight)
		log.Printf("[snapshot] expected: %s", m.expectedHash.String())
		log.Printf("[snapshot] computed: %s", computedHash.String())

		m.activeChainstate.MarkInvalid()

		// Switch to the background chainstate
		m.activeChainstate = m.backgroundChainstate
		m.backgroundChainstate = nil
		m.snapshotValidated = false

		if m.onValidationComplete != nil {
			m.onValidationComplete(false)
		}

		return ErrBackgroundValidationFailed
	}

	// Success! Mark snapshot as validated
	log.Printf("[snapshot] background validation complete at height %d", m.snapshotHeight)
	log.Printf("[snapshot] UTXO hash verified: %s", computedHash.String())

	m.activeChainstate.MarkValidated()
	m.snapshotValidated = true

	// We can now discard the background chainstate
	m.backgroundChainstate = nil

	if m.onValidationComplete != nil {
		m.onValidationComplete(true)
	}

	return nil
}

// SetValidationCallback sets a callback to be invoked when validation completes.
func (m *DualChainstateManager) SetValidationCallback(cb func(success bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onValidationComplete = cb
}

// MainnetAssumeUTXOParams contains the assumeutxo data for mainnet.
// These are trusted values that will be verified by background validation.
var MainnetAssumeUTXOParams = AssumeUTXOParams{
	Data: []AssumeUTXOData{
		{
			Height:       840000,
			HashSerialized: mustParseHash("a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"),
			ChainTxCount: 991032194,
			BlockHash:    mustParseHash("0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"),
		},
		{
			Height:       880000,
			HashSerialized: mustParseHash("dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9"),
			ChainTxCount: 1145604538,
			BlockHash:    mustParseHash("000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"),
		},
		{
			Height:       910000,
			HashSerialized: mustParseHash("4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"),
			ChainTxCount: 1226586151,
			BlockHash:    mustParseHash("0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"),
		},
		{
			Height:       935000,
			HashSerialized: mustParseHash("e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050"),
			ChainTxCount: 1305397408,
			BlockHash:    mustParseHash("0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"),
		},
	},
}

// Testnet4AssumeUTXOParams contains the assumeutxo data for testnet4.
var Testnet4AssumeUTXOParams = AssumeUTXOParams{
	Data: []AssumeUTXOData{
		// Add testnet4 snapshot data as available
	},
}
