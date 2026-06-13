package consensus

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"math"
	"sort"
	"sync"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// AssumeUTXO errors.
var (
	ErrInvalidSnapshotMagic       = errors.New("invalid snapshot magic bytes")
	ErrUnsupportedVersion         = errors.New("unsupported snapshot version")
	ErrNetworkMismatch            = errors.New("snapshot network does not match node network")
	ErrUnknownSnapshotHeight      = errors.New("snapshot height not recognized in assumeutxo params")
	ErrSnapshotHashMismatch       = errors.New("snapshot UTXO hash does not match expected value")
	ErrSnapshotAlreadyLoaded      = errors.New("a snapshot chainstate is already loaded")
	ErrSnapshotBlockNotFound      = errors.New("snapshot base block not found in headers")
	ErrBackgroundValidationFailed = errors.New("background validation failed to match snapshot")
	// Per-coin guard errors (BUG-W102-01..03)
	ErrCoinHeightExceedsBase = errors.New("snapshot coin height exceeds snapshot base height")
	ErrCoinAmountOutOfRange  = errors.New("snapshot coin amount out of MoneyRange")
	ErrCoinOutpointIndexMax  = errors.New("snapshot coin outpoint index equals max uint32 (wrap-around risk)")
	// Trailing-bytes error (BUG-W102-04)
	ErrSnapshotTrailingBytes = errors.New("unexpected trailing bytes after snapshot coin data")
	// Precondition errors (BUG-W102-05..07)
	ErrSnapshotBaseBlockInvalid        = errors.New("snapshot base block is marked invalid")
	ErrSnapshotBaseBlockNotOnBestChain = errors.New("snapshot base block is not on the best header chain")
	ErrMempoolNotEmpty                 = errors.New("can't activate a snapshot when mempool is not empty")
	// Metadata cross-check error (BUG-W102-14)
	ErrSnapshotHeightMismatch = errors.New("snapshot file metadata height does not match assumeutxo table entry height")
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
	Height         int32
	HashSerialized wire.Hash256 // SHA256 hash of the serialized UTXO set
	ChainTxCount   uint64       // Total transactions in the chain up to this block
	BlockHash      wire.Hash256 // The block hash at this height
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

// writeCoin writes a single coin in the Bitcoin Core snapshot format.
//
// Layout (bytes-identical to Core's Coin::Serialize + TxOutCompression):
//
//	VARINT(code = (height<<1) | coinbase)
//	VARINT(CompressAmount(amount))
//	ScriptCompression: either special-tag (1+20 or 1+32 bytes) or
//	                   VARINT(size+6) followed by raw script bytes.
//
// Reference: bitcoin-core/src/coins.h, src/compressor.{h,cpp}.
func writeCoin(w io.Writer, entry *UTXOEntry) error {
	return CoreSerializeCoin(w, entry)
}

// SnapshotStats contains statistics about a snapshot operation.
type SnapshotStats struct {
	CoinsWritten   uint64
	BlockHash      wire.Hash256
	Height         int32
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

// LoadSnapshotCoins reads coins from an already-initialised SnapshotReader and
// populates a new UTXOSet.  baseHeight is the snapshot base block's height from
// the assumeutxo table (obtained by ForBlockHash BEFORE calling this function —
// see BUG-W102-15).  Per-coin guards mirror Bitcoin Core's
// PopulateAndValidateSnapshot (validation.cpp:5814–5883):
//
//   - BUG-W102-01: coin.nHeight > baseHeight → ErrCoinHeightExceedsBase
//   - BUG-W102-02: !MoneyRange(coin.out.nValue) → ErrCoinAmountOutOfRange
//   - BUG-W102-03: outpoint.n == UINT32_MAX → ErrCoinOutpointIndexMax
//   - BUG-W102-04: trailing bytes after coins_left==0 → ErrSnapshotTrailingBytes
//
// Returns the populated UTXOSet and load statistics.  Does NOT flush the set
// (see the deferred-flush note on LoadSnapshot).
func LoadSnapshotCoins(sr *SnapshotReader, db *storage.ChainDB, baseHeight int32) (*UTXOSet, *SnapshotLoadStats, error) {
	r := sr.r
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
			// BUG-W102-03: guard outpoint index against UINT32_MAX wrap-around
			// (Core validation.cpp:5828 — ApplyHash uses index as array key).
			vout, err := wire.ReadCompactSize(r)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read vout at coin %d: %w", coinsLoaded, err)
			}
			if vout >= uint64(math.MaxUint32) {
				return nil, nil, fmt.Errorf("%w: index %d at coin %d", ErrCoinOutpointIndexMax, vout, coinsLoaded)
			}

			// Read coin data
			entry, err := readCoin(r)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read coin at %d: %w", coinsLoaded, err)
			}

			// BUG-W102-01: per-coin height ≤ baseHeight
			// Core validation.cpp:5826 — coin.nHeight > snapshot_start_block->nHeight.
			if entry.Height > baseHeight {
				return nil, nil, fmt.Errorf("%w: coin %d has height %d > base %d",
					ErrCoinHeightExceedsBase, coinsLoaded, entry.Height, baseHeight)
			}

			// BUG-W102-02: MoneyRange per coin
			// Core validation.cpp:5835 — !MoneyRange(coin.out.nValue).
			if entry.Amount < 0 || entry.Amount > MaxMoney {
				return nil, nil, fmt.Errorf("%w: coin %d amount %d", ErrCoinAmountOutOfRange, coinsLoaded, entry.Amount)
			}

			// Add to UTXO set (all guards passed)
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

	// BUG-W102-04: trailing-bytes check after all coins have been consumed.
	// Core PopulateAndValidateSnapshot:5851-5864 tries to read one more byte and
	// expects io.EOF; any successful read is a format error.
	var probe [1]byte
	switch n, err := r.Read(probe[:]); {
	case n == 0 && err != nil:
		// io.EOF or wrapped io.EOF — expected; snapshot ends cleanly.
	case n > 0:
		return nil, nil, fmt.Errorf("%w after %d coins", ErrSnapshotTrailingBytes, coinsLoaded)
	case err == nil:
		// Read returned 0 bytes with no error — treat as trailing data present.
		return nil, nil, fmt.Errorf("%w after %d coins (zero-byte read without EOF)", ErrSnapshotTrailingBytes, coinsLoaded)
	}

	stats.CoinsLoaded = coinsLoaded
	log.Printf("[snapshot] loaded %d coins from snapshot (deferred flush)", coinsLoaded)
	return utxoSet, stats, nil
}

// LoadSnapshot loads a UTXO snapshot into a UTXOSet.
// Returns the populated UTXO set and statistics.
//
// IMPORTANT: For production use (loadtxoutset / -loadsnapshot), callers MUST
// perform the assumeutxo table lookup BEFORE calling this function to avoid
// UTXOSet pollution on error (BUG-W102-15).  Use LoadSnapshotCoins directly
// via NewSnapshotReader + ForBlockHash for that path.
//
// This wrapper is kept for tests and dump/load symmetry.  It uses baseHeight=0
// which disables the per-coin height guard; callers that know baseHeight should
// call LoadSnapshotCoins directly.
func LoadSnapshot(r io.Reader, db *storage.ChainDB, expectedNetworkMagic [4]byte) (*UTXOSet, *SnapshotLoadStats, error) {
	sr, err := NewSnapshotReader(r)
	if err != nil {
		return nil, nil, err
	}

	// Verify network magic
	if sr.metadata.NetworkMagic != expectedNetworkMagic {
		return nil, nil, ErrNetworkMismatch
	}

	// Delegate to LoadSnapshotCoins with baseHeight=math.MaxInt32 so the
	// per-coin height guard is a no-op for callers that don't have a table entry.
	// (Real production loads go through loadSnapshotFromFile which passes the
	// correct baseHeight from the assumeutxo table.)
	return LoadSnapshotCoins(sr, db, math.MaxInt32)
}

// readCoin reads a single coin from a Bitcoin Core-format snapshot.
// See writeCoin for the encoding.
func readCoin(r io.Reader) (*UTXOEntry, error) {
	return CoreDeserializeCoin(r)
}

// SnapshotLoadStats contains statistics about a snapshot load operation.
type SnapshotLoadStats struct {
	CoinsLoaded uint64
	BlockHash   wire.Hash256
	Height      int32
}

// ComputeUTXOHash computes the Bitcoin Core HASH_SERIALIZED commitment over the
// UTXO set. This is the value AssumeUTXO snapshot validation compares against
// (AssumeUTXOData.HashSerialized / Core's au_data.hash_serialized).
//
// HISTORY / STEP-0 FIX (2026-06-13): this function previously computed a plain
// single-SHA256 over (outpoint || compressed-coin) records — the WRONG hash
// flavour. That digest could never equal a real Core snapshot's
// hash_serialized, because Core (kernel/coinstats.cpp::TxOutSer + ApplyHash,
// finalized by HashWriter::GetHash) uses a DIFFERENT serialization and a DOUBLE
// SHA256:
//
//	per coin: outpoint(36) || uint32_LE(nHeight<<1 | fCoinBase) || nValue_i64_LE
//	          || CompactSize(len(scriptPubKey)) || scriptPubKey   (UNCOMPRESSED)
//	digest:   SHA256d over the whole stream (NOT single SHA256), in cursor order
//	          (txid ascending, then vout ascending), grouped per txid.
//
// A wrong hash flavour silently defeats AssumeUTXO authentication: the
// background validator (CheckBackgroundValidation) would compute one thing while
// the assumeutxo table pins another, so an honest replay could never match — or,
// worse, a coincidental collision could let a malicious snapshot through. The
// fix delegates to the canonical implementation in utxohash.go so the load-time
// gate (ComputeHashSerialized / ComputeUTXOSetInfo) and the background validator
// use byte-identical kernels. Cross-checked against lunarblock
// compute_utxo_hash (src/utxo.lua) and camlcoin compute_utxo_hash_from_db
// (lib/assume_utxo.ml).
//
// Note: ComputeHashSerialized iterates the in-memory cache. For a set that has
// spilled to disk, prefer ComputeUTXOSetInfo (full DB-cursor walk). The
// dual-chainstate background validator uses the DB-cursor walk (see
// runBackgroundToBase) so it is correct even after a flush.
func ComputeUTXOHash(utxoSet *UTXOSet) (wire.Hash256, uint64, error) {
	return ComputeHashSerialized(utxoSet)
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
			Height:         840000,
			HashSerialized: mustParseHash("a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"),
			ChainTxCount:   991032194,
			BlockHash:      mustParseHash("0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"),
		},
		{
			Height:         880000,
			HashSerialized: mustParseHash("dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9"),
			ChainTxCount:   1145604538,
			BlockHash:      mustParseHash("000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"),
		},
		{
			Height:         910000,
			HashSerialized: mustParseHash("4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"),
			ChainTxCount:   1226586151,
			BlockHash:      mustParseHash("0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"),
		},
		{
			Height:         935000,
			HashSerialized: mustParseHash("e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050"),
			ChainTxCount:   1305397408,
			BlockHash:      mustParseHash("0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"),
		},
		// hashhog-local snapshot at h=944183 (utxo-snapshot-raw.dat from
		// /data/nvme1/hashhog-mainnet/), used to recover blockbrew + lunarblock
		// + hotbuns mainnet nodes after chainstate corruption (chainstate-
		// corruption banner; sister bug to CAMLCOIN-EBADF-LEAK). NOT a Bitcoin
		// Core chainparams entry — the four 840k/880k/910k/935k entries above
		// ARE. Hash computed locally over the on-disk snapshot file
		// (165,095,935 coins) by tools/compute-snapshot-hash.py:
		//   raw HASH_SERIALIZED  = a888bcbc200384747c0813c8e7f4650d9bc0847b5147791c3ca869567271af2e
		//   display (uint256)    = 2eaf71725669a83c1c7947517b84c09b0d65f4e7c813087c74840320bcbc88a8
		// HashSerialized below is in display order to match the convention
		// used by the four Core entries above (mustParseHash reverses to
		// internal/raw order, which is what ComputeHashSerialized produces
		// from sha256.Sum256 — see internal/consensus/utxohash.go:139-142).
		{
			Height:         944183,
			HashSerialized: mustParseHash("2eaf71725669a83c1c7947517b84c09b0d65f4e7c813087c74840320bcbc88a8"),
			ChainTxCount:   1334000000,
			BlockHash:      mustParseHash("0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817"),
		},
	},
}

// Testnet4AssumeUTXOParams contains the assumeutxo data for testnet4.
var Testnet4AssumeUTXOParams = AssumeUTXOParams{
	Data: []AssumeUTXOData{
		// Add testnet4 snapshot data as available
	},
}

// ─────────────────────────────────────────────────────────────────────────────
// Regtest AssumeUTXO whitelist (runtime-registerable).
//
// Core's regtest chainparams DOES carry m_assumeutxo_data entries
// (bitcoin-core/src/kernel/chainparams.cpp:607-628, heights 110 / 200 / 299,
// explicitly "for use by test/functional/feature_assumeutxo.py" and the
// snapshot fuzz target). Those Core values are pinned to Core's deterministic
// regtest mining chain; blockbrew's snapshot tests build their own short
// regtest chains, so the regtest table is REGISTERABLE at runtime — exactly
// mirroring how Core's regtest is a mockable chain whose assumeutxo data is
// purpose-built for the snapshot tests rather than a permanent network
// commitment.
//
// This table is NEVER consulted for mainnet/testnet4 (their whitelists remain
// the hardcoded, immutable MainnetAssumeUTXOParams / Testnet4AssumeUTXOParams
// above); it only gates the regtest snapshot test path. Cross-impl reference:
// camlcoin 3140ab9 (register_regtest_assumeutxo, lib/assume_utxo.ml) and
// lunarblock a39dd42.
var (
	regtestAssumeUTXOMu   sync.Mutex
	regtestAssumeUTXOData []AssumeUTXOData
)

// RegisterRegtestAssumeUTXO adds (or replaces, keyed on (Height, BlockHash))
// an entry to the regtest AssumeUTXO whitelist so a regtest snapshot whose base
// block is BlockHash can be loaded via loadtxoutset. Regtest only — see the
// regtestAssumeUTXOData note. Safe for concurrent use.
func RegisterRegtestAssumeUTXO(d AssumeUTXOData) {
	regtestAssumeUTXOMu.Lock()
	defer regtestAssumeUTXOMu.Unlock()
	filtered := regtestAssumeUTXOData[:0:0]
	for _, e := range regtestAssumeUTXOData {
		if e.Height == d.Height && e.BlockHash == d.BlockHash {
			continue
		}
		filtered = append(filtered, e)
	}
	regtestAssumeUTXOData = append(filtered, d)
}

// ClearRegtestAssumeUTXO empties the regtest whitelist (test teardown hygiene
// so registrations never leak across test cases).
func ClearRegtestAssumeUTXO() {
	regtestAssumeUTXOMu.Lock()
	defer regtestAssumeUTXOMu.Unlock()
	regtestAssumeUTXOData = nil
}

// RegtestAssumeUTXOParams returns a snapshot of the current regtest whitelist
// as an *AssumeUTXOParams (ForBlockHash / ForHeight consumers). The returned
// params is a copy — mutating the live whitelist afterwards does not affect it.
func RegtestAssumeUTXOParams() *AssumeUTXOParams {
	regtestAssumeUTXOMu.Lock()
	defer regtestAssumeUTXOMu.Unlock()
	cp := make([]AssumeUTXOData, len(regtestAssumeUTXOData))
	copy(cp, regtestAssumeUTXOData)
	return &AssumeUTXOParams{Data: cp}
}

// ─────────────────────────────────────────────────────────────────────────────
// AssumeUTXO dual-chainstate (real background validation)
//
// Core reference: bitcoin-core/src/validation.cpp.
//   * ActivateSnapshot (5588) loads the snapshot coins into a NEW chainstate
//     which becomes the active/tip-serving chainstate (m_assumeutxo =
//     UNVALIDATED).
//   * AddChainstate (6170) DEMOTES the original genesis-validated chainstate to
//     a BACKGROUND chainstate by setting its m_target_blockhash to the snapshot
//     base. The background chainstate keeps its OWN coins DB and connects blocks
//     genesis -> base independently (prev_chainstate.m_assumeutxo == VALIDATED).
//   * MaybeCompleteSnapshotValidation (5967) runs once the background chainstate
//     reaches the base: it computes the HASH_SERIALIZED of the background
//     chainstate's OWN coins (ComputeUTXOStats / coinstats.cpp) and compares it
//     to au_data.hash_serialized. MATCH -> the snapshot chainstate's
//     m_assumeutxo flips to VALIDATED and the background chainstate is retired
//     (ValidatedSnapshotCleanup, 6280). MISMATCH -> snapshot marked INVALID and
//     fatalError/AbortNode (handle_invalid_snapshot, 6010-6017) — NEVER silently
//     accepted.
//
// The load-time HASH_SERIALIZED gate already authenticates the snapshot bytes.
// This background pass is the trustless re-verification by INDEPENDENT
// re-computation: it never trusts the loaded coins, it rebuilds the UTXO set
// from genesis in a SEPARATE coins store and checks that an honest replay
// arrives at the same committed hash.
//
// Cross-impl references for the same machinery: lunarblock a39dd42
// (activate_snapshot_with_background / BackgroundValidator, src/utxo.lua) and
// camlcoin 2675b31 (make_background_chainstate / run_background_to_completion,
// lib/assume_utxo.ml).
// ─────────────────────────────────────────────────────────────────────────────

// BackgroundValidationResult is the terminal verdict of the background pass.
type BackgroundValidationResult int

const (
	// BackgroundPending: the background pass has not yet reached the base.
	BackgroundPending BackgroundValidationResult = iota
	// BackgroundValidated: bg coins hash MATCHED the assumeutxo commitment.
	BackgroundValidated
	// BackgroundInvalid: bg coins hash MISMATCHED (snapshot is INVALID/abort) or
	// a block failed to connect.
	BackgroundInvalid
)

// BackgroundValidator owns the SECOND (background) chainstate for AssumeUTXO
// validation: a genesis-rooted chainstate with its OWN separate coins store (a
// distinct *UTXOSet over a distinct *storage.ChainDB — NOT the active snapshot
// chainstate's store / not the same keyspace). It re-connects every block
// genesis -> base into that store via REAL block connection (UTXOSet.
// ConnectBlockUTXOs — spend inputs, add outputs), then recomputes the
// HASH_SERIALIZED of its OWN coins and compares it to the assumeutxo commitment.
//
// This is Core's background (validated, genesis-rooted) chainstate from
// AddChainstate — it keeps its own m_coins_views and replays forward to
// m_target_blockhash (the snapshot base).
type BackgroundValidator struct {
	// bgUTXO is the background chainstate's OWN coins store, a genuinely
	// separate object from the active (snapshot) chainstate's UTXOSet. A write
	// to the active store is INVISIBLE here and vice-versa (proven by the
	// dual-chainstate falsification test).
	bgUTXO *UTXOSet

	// targetHeight is the snapshot base height (Core m_target_blockhash height).
	targetHeight int32
	// targetHash is the assumeutxo HASH_SERIALIZED commitment (au_data.
	// hash_serialized) the recomputed bg hash is compared against.
	targetHash wire.Hash256

	// getBlock reads canonical blocks from the node's block store for
	// genesis+1..base. The bg chainstate only owns its coins, not block bodies
	// (Core shares BlockManager across chainstates), so blocks come from the
	// shared store.
	getBlock func(height int32) (*wire.MsgBlock, error)

	currentHeight int32
	result        BackgroundValidationResult
	err           error
}

// NewBackgroundValidator constructs the background validator with its OWN coins
// store. bgUTXO MUST be a different object (over a different ChainDB / keyspace)
// from the active snapshot chainstate's UTXOSet; the caller (and the production
// orchestrator ActivateSnapshotWithBackground) is responsible for that
// separation. The bg store starts EMPTY at genesis (the genesis coinbase is
// unspendable and not in the UTXO set — exactly the height-0 state Core's
// background chainstate replays forward from).
//
//   - bgUTXO        the SEPARATE background coins store (must not alias active)
//   - targetHeight  snapshot base height to validate up to
//   - targetHash    assumeutxo HASH_SERIALIZED commitment at the base
//   - getBlock      fn(height) -> block for heights 1..targetHeight
func NewBackgroundValidator(
	bgUTXO *UTXOSet,
	targetHeight int32,
	targetHash wire.Hash256,
	getBlock func(height int32) (*wire.MsgBlock, error),
) *BackgroundValidator {
	return &BackgroundValidator{
		bgUTXO:        bgUTXO,
		targetHeight:  targetHeight,
		targetHash:    targetHash,
		getBlock:      getBlock,
		currentHeight: 0, // genesis-seeded: empty coins at height 0
		result:        BackgroundPending,
	}
}

// CurrentHeight returns the background chainstate's current tip height.
func (b *BackgroundValidator) CurrentHeight() int32 { return b.currentHeight }

// Result returns the terminal verdict (Pending until RunToBase completes).
func (b *BackgroundValidator) Result() BackgroundValidationResult { return b.result }

// Err returns the connection / mismatch error, if any.
func (b *BackgroundValidator) Err() error { return b.err }

// BackgroundUTXOSet exposes the background chainstate's OWN coins store. Used by
// tests to prove the store is genuinely separate from the active one (an
// active-store write is NOT visible here).
func (b *BackgroundValidator) BackgroundUTXOSet() *UTXOSet { return b.bgUTXO }

// connectNext connects exactly one block (currentHeight+1) into the background
// chainstate's OWN coins via REAL block connection. This is NOT a counter bump:
// ConnectBlockUTXOs spends every non-coinbase input out of bgUTXO and adds every
// new output into bgUTXO, mutating the independent coins set.
func (b *BackgroundValidator) connectNext() error {
	next := b.currentHeight + 1
	block, err := b.getBlock(next)
	if err != nil {
		return fmt.Errorf("background validation: failed to get block at height %d: %w", next, err)
	}
	if block == nil {
		return fmt.Errorf("background validation: nil block at height %d", next)
	}
	// REAL connection into the SEPARATE bg coins store. ConnectBlockUTXOs
	// returns ErrUTXONotFound on a spend of a coin absent from THIS store, so
	// an aliasing bug (reading the active store) or a gap would surface here.
	if _, err := b.bgUTXO.ConnectBlockUTXOs(block, next); err != nil {
		return fmt.Errorf("background validation: failed to connect block %d: %w", next, err)
	}
	b.currentHeight = next
	return nil
}

// finalizeAtBase recomputes the background chainstate's HASH_SERIALIZED at the
// base and applies the verdict (Core MaybeCompleteSnapshotValidation:6061-6076).
//
// It uses ComputeUTXOSetInfo, which FLUSHES the bg coins to its DB and walks the
// full DB cursor (txid asc, vout asc) — the faithful analogue of Core's
// ForceFlushStateToDisk + ComputeUTXOStats over the chainstate cursor. This is
// correct even if the bg cache has spilled to disk.
func (b *BackgroundValidator) finalizeAtBase() {
	info, err := ComputeUTXOSetInfo(b.bgUTXO)
	if err != nil {
		b.err = fmt.Errorf("background validation: failed to compute UTXO hash: %w", err)
		b.result = BackgroundInvalid
		return
	}
	if info.HashSerialized3 == b.targetHash {
		// MATCH: Core flips the snapshot chainstate to VALIDATED and retires bg.
		b.result = BackgroundValidated
		return
	}
	// MISMATCH: Core marks the snapshot INVALID and AbortNodes. Surface a hard
	// error; never silently accept. The word "mismatch" is kept in the message
	// so external tooling scraping it keeps working (cross-impl convention).
	b.err = fmt.Errorf("%w: background-recomputed HASH_SERIALIZED %s != assumeutxo %s",
		ErrBackgroundValidationFailed, info.HashSerialized3.String(), b.targetHash.String())
	b.result = BackgroundInvalid
}

// RunToBase synchronously drives the background validation to its terminal state:
// connect every block genesis+1..base into the bg coins store, then recompute
// the HASH_SERIALIZED and compare to the assumeutxo commitment. Returns the
// terminal result and error. Used by the in-process path and the functional
// test; a live node could instead tick connectNext from a maintenance loop and
// call finalizeAtBase on reaching the base.
func (b *BackgroundValidator) RunToBase() (BackgroundValidationResult, error) {
	if b.result != BackgroundPending {
		return b.result, b.err
	}
	for b.currentHeight < b.targetHeight {
		if err := b.connectNext(); err != nil {
			b.err = err
			b.result = BackgroundInvalid
			return b.result, b.err
		}
	}
	b.finalizeAtBase()
	return b.result, b.err
}

// SnapshotActivation pairs the active (snapshot) chainstate with the background
// validator that re-derives its UTXO hash. Mirrors Core's triple through
// ActivateSnapshot / AddChainstate: the UNVALIDATED snapshot chainstate, and the
// VALIDATED background chainstate targeting the snapshot base.
type SnapshotActivation struct {
	// Snapshot is the ACTIVE chainstate (snapshot-loaded). It starts
	// ChainstateRoleSnapshot (Core Assumeutxo::UNVALIDATED); the background
	// pass flips it to Validated (match) or Invalid (mismatch).
	Snapshot *Chainstate
	// Background is the genesis-rooted validator with its OWN separate coins.
	Background *BackgroundValidator
}

// ActivateSnapshotWithBackground wires up a real dual-chainstate validation for
// an already-loaded snapshot chainstate (Core ActivateSnapshot + AddChainstate).
//
//   - snapshotCS    the ACTIVE chainstate produced by loading the snapshot (its
//     coins live in its OWN UTXOSet). Marked role Snapshot here.
//   - bgUTXO        the BACKGROUND chainstate's OWN coins store — MUST be a
//     genuinely separate object (different ChainDB) from the
//     snapshot chainstate's UTXOSet. ActivateSnapshotWithBackground
//     refuses to proceed if it is the same object (aliasing guard,
//     mirroring lunarblock's "background storage must be separate"
//     check).
//   - au            the assumeutxo entry for the base (its HashSerialized is the
//     commitment the background pass re-derives and checks).
//   - getBlock      fn(height) -> block for genesis+1..base (shared block store).
//
// The activation performs NO block connection itself — exactly like Core's
// ActivateSnapshot, which returns after demoting the prior chainstate and lets
// the validation queue do the background work. Drive it with
// Background.RunToBase() and then call Finish.
func ActivateSnapshotWithBackground(
	snapshotCS *Chainstate,
	bgUTXO *UTXOSet,
	au *AssumeUTXOData,
	getBlock func(height int32) (*wire.MsgBlock, error),
) (*SnapshotActivation, error) {
	if snapshotCS == nil {
		return nil, errors.New("ActivateSnapshotWithBackground: nil snapshot chainstate")
	}
	if au == nil {
		return nil, errors.New("ActivateSnapshotWithBackground: nil assumeutxo data")
	}
	if bgUTXO == nil {
		return nil, errors.New("ActivateSnapshotWithBackground: nil background coins store")
	}
	// Aliasing guard: the bg coins store MUST be a different object from the
	// active store (Core's background chainstate keeps its OWN m_coins_views).
	if bgUTXO == snapshotCS.utxoSet {
		return nil, errors.New("ActivateSnapshotWithBackground: background coins store must be separate from the active (snapshot) chainstate store")
	}

	// The snapshot chainstate is the active, not-yet-validated one
	// (Core Assumeutxo::UNVALIDATED). NewSnapshotChainstate already sets role
	// Snapshot; enforce it in case the caller passed a validated chainstate.
	snapshotCS.mu.Lock()
	snapshotCS.role = ChainstateRoleSnapshot
	snapshotCS.mu.Unlock()

	bg := NewBackgroundValidator(bgUTXO, au.Height, au.HashSerialized, getBlock)
	return &SnapshotActivation{Snapshot: snapshotCS, Background: bg}, nil
}

// Finish applies the background verdict to the snapshot chainstate and returns
// it (Core's flip of unvalidated_cs.m_assumeutxo). On a Validated result the
// snapshot is marked Validated (and the background chainstate is logically
// retired). On an Invalid result the snapshot is marked Invalid and the error
// is returned — the snapshot is NEVER silently accepted on a mismatch.
//
//   - returns (true, nil)   snapshot validated (background hash MATCHED).
//   - returns (false, err)  snapshot invalid (mismatch / connect failure); the
//     caller should treat this as fatal (Core AbortNode).
//   - returns (false, nil)  background pass not yet run to its terminal state.
func (a *SnapshotActivation) Finish() (validated bool, err error) {
	switch a.Background.Result() {
	case BackgroundValidated:
		a.Snapshot.MarkValidated()
		return true, nil
	case BackgroundInvalid:
		a.Snapshot.MarkInvalid()
		if a.Background.Err() != nil {
			return false, a.Background.Err()
		}
		return false, ErrBackgroundValidationFailed
	default:
		// Still pending: not terminal. Do not flip the snapshot's role.
		return false, nil
	}
}
