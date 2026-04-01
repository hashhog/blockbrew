package consensus

import (
	"bytes"
	"errors"
	"sync"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// UTXO set errors.
var (
	ErrUTXONotFound   = errors.New("utxo not found")
	ErrUTXOAlreadySpent = errors.New("utxo already spent")
)

// DefaultCacheMaxEntries is the maximum number of UTXO entries to cache in memory.
// This corresponds roughly to 450 MB of memory usage.
const DefaultCacheMaxEntries = 5_000_000

// DefaultCacheMaxBytes is the maximum approximate cache size in bytes (256MB).
const DefaultCacheMaxBytes = 256 * 1024 * 1024

// IBDFlushInterval is the number of blocks between forced UTXO flushes during IBD.
// Larger values improve IBD performance but use more memory.
const IBDFlushInterval = 2000

// UTXOCacheStats tracks cache performance metrics.
type UTXOCacheStats struct {
	Hits       uint64 // Cache hits
	Misses     uint64 // Cache misses (required DB lookup)
	Flushes    uint64 // Number of flush operations
	CacheSize  int    // Current cache entry count
	CacheBytes int64  // Approximate memory usage
}

// UTXOSet manages the set of unspent transaction outputs with caching and persistence.
type UTXOSet struct {
	mu    sync.RWMutex
	db    *storage.ChainDB
	cache map[wire.OutPoint]*UTXOEntry // In-memory cache for performance
	dirty map[wire.OutPoint]bool        // Modified entries needing flush
	// Track deletions separately since deleted entries should be flushed too
	deleted map[wire.OutPoint]bool

	// Performance tracking
	cacheBytes   int64  // Approximate memory usage of cache
	maxCacheBytes int64 // Maximum cache size in bytes
	hits         uint64 // Cache hits
	misses       uint64 // Cache misses
	flushes      uint64 // Number of flush operations
	blocksSinceFlush int // Blocks connected since last flush
}

// NewUTXOSet creates a new UTXO set backed by the given database.
func NewUTXOSet(db *storage.ChainDB) *UTXOSet {
	return NewUTXOSetWithMaxCache(db, DefaultCacheMaxBytes)
}

// NewUTXOSetWithMaxCache creates a UTXO set with a custom cache size limit.
func NewUTXOSetWithMaxCache(db *storage.ChainDB, maxCacheBytes int64) *UTXOSet {
	// Pre-size maps to reduce rehashing during IBD.
	// 500k is a reasonable initial size for testnet4/mainnet UTXOs.
	const initialCacheSize = 500_000
	const initialDirtySize = 100_000
	return &UTXOSet{
		db:            db,
		cache:         make(map[wire.OutPoint]*UTXOEntry, initialCacheSize),
		dirty:         make(map[wire.OutPoint]bool, initialDirtySize),
		deleted:       make(map[wire.OutPoint]bool, initialDirtySize),
		maxCacheBytes: maxCacheBytes,
	}
}

// GetUTXO retrieves a UTXO by outpoint. Checks cache first, then database.
func (u *UTXOSet) GetUTXO(outpoint wire.OutPoint) *UTXOEntry {
	u.mu.RLock()

	// Check if deleted
	if u.deleted[outpoint] {
		u.mu.RUnlock()
		return nil
	}

	// Check cache first
	if entry, ok := u.cache[outpoint]; ok {
		u.hits++
		u.mu.RUnlock()
		return entry
	}
	u.mu.RUnlock()

	// Not in cache, try database
	if u.db == nil {
		return nil
	}

	key := storage.MakeUTXOKey(outpoint)
	data, err := u.db.DB().Get(key)
	if err != nil || data == nil {
		return nil
	}

	entry, err := DeserializeUTXOEntry(data)
	if err != nil {
		return nil
	}

	// Cache the entry for future lookups
	u.mu.Lock()
	u.cache[outpoint] = entry
	u.cacheBytes += estimateEntrySize(entry)
	u.misses++
	u.mu.Unlock()

	return entry
}

// estimateEntrySize estimates the memory usage of a UTXO entry in bytes.
// Includes: OutPoint (36 bytes), Amount (8), PkScript (len + header), Height (4), IsCoinbase (1), map overhead (~100)
func estimateEntrySize(entry *UTXOEntry) int64 {
	return int64(36 + 8 + len(entry.PkScript) + 4 + 1 + 100)
}

// AddUTXO adds a new UTXO to the set.
func (u *UTXOSet) AddUTXO(outpoint wire.OutPoint, entry *UTXOEntry) {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Track size change
	if existing, ok := u.cache[outpoint]; ok {
		u.cacheBytes -= estimateEntrySize(existing)
	}
	u.cacheBytes += estimateEntrySize(entry)

	u.cache[outpoint] = entry
	u.dirty[outpoint] = true
	delete(u.deleted, outpoint) // Clear any pending deletion
}

// SpendUTXO marks a UTXO as spent (removes it from the set).
// This implements the UpdatableUTXOView interface.
func (u *UTXOSet) SpendUTXO(outpoint wire.OutPoint) {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Track size change
	if existing, ok := u.cache[outpoint]; ok {
		u.cacheBytes -= estimateEntrySize(existing)
	}

	delete(u.cache, outpoint)
	delete(u.dirty, outpoint)
	u.deleted[outpoint] = true
}

// SpendUTXOChecked marks a UTXO as spent and returns an error if it doesn't exist.
// Use this for double-spend detection.
func (u *UTXOSet) SpendUTXOChecked(outpoint wire.OutPoint) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Check if already deleted
	if u.deleted[outpoint] {
		return ErrUTXOAlreadySpent
	}

	// Check if in cache
	if existing, ok := u.cache[outpoint]; ok {
		u.cacheBytes -= estimateEntrySize(existing)
		delete(u.cache, outpoint)
		delete(u.dirty, outpoint)
		u.deleted[outpoint] = true
		return nil
	}

	// Check if in database
	if u.db != nil {
		key := storage.MakeUTXOKey(outpoint)
		exists, err := u.db.DB().Has(key)
		if err != nil {
			return err
		}
		if exists {
			u.deleted[outpoint] = true
			return nil
		}
	}

	return ErrUTXONotFound
}

// HasUTXO checks if a UTXO exists.
func (u *UTXOSet) HasUTXO(outpoint wire.OutPoint) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	// Check if deleted
	if u.deleted[outpoint] {
		return false
	}

	// Check cache
	if _, ok := u.cache[outpoint]; ok {
		return true
	}

	// Check database
	if u.db == nil {
		return false
	}

	key := storage.MakeUTXOKey(outpoint)
	exists, err := u.db.DB().Has(key)
	return err == nil && exists
}

// Flush writes all dirty entries to the database.
func (u *UTXOSet) Flush() error {
	if u.db == nil {
		return nil
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	return u.flushLocked()
}

// flushLocked performs flush while holding the lock.
func (u *UTXOSet) flushLocked() error {
	if u.db == nil {
		return nil
	}

	batch := u.db.DB().NewBatch()

	// Write all dirty entries
	for outpoint := range u.dirty {
		entry := u.cache[outpoint]
		if entry != nil {
			key := storage.MakeUTXOKey(outpoint)
			data := SerializeUTXOEntry(entry)
			batch.Put(key, data)
		}
	}

	// Delete all deleted entries
	for outpoint := range u.deleted {
		key := storage.MakeUTXOKey(outpoint)
		batch.Delete(key)
	}

	if err := batch.Write(); err != nil {
		return err
	}

	// Clear dirty and deleted tracking (pre-size for next batch)
	u.dirty = make(map[wire.OutPoint]bool, 100_000)
	u.deleted = make(map[wire.OutPoint]bool, 100_000)
	u.flushes++
	u.blocksSinceFlush = 0

	// Evict clean cache entries to bring memory under the limit.
	// After flushing, all cache entries are clean (persisted to disk)
	// and can be safely evicted — they'll be re-read from LevelDB
	// on the next GetUTXO call.
	if u.cacheBytes > u.maxCacheBytes/2 {
		// Rebuild the cache map with only entries we want to keep.
		// Go maps never shrink their hash table on delete(), so we must
		// allocate a new map to actually free memory.
		target := u.maxCacheBytes / 4
		newCache := make(map[wire.OutPoint]*UTXOEntry, len(u.cache)/2)
		var newBytes int64
		for op, entry := range u.cache {
			if newBytes >= target {
				continue // Skip — already at target
			}
			newCache[op] = entry
			newBytes += estimateEntrySize(entry)
		}
		u.cache = newCache
		u.cacheBytes = newBytes
	}

	return nil
}

// MaybeFlush flushes if cache exceeds size limit or after forceAfterBlocks blocks.
// This is used during IBD to control memory usage while batching writes.
func (u *UTXOSet) MaybeFlush(forceAfterBlocks int) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.blocksSinceFlush++

	// Flush if cache exceeds size limit or we've connected enough blocks
	if u.cacheBytes > u.maxCacheBytes || u.blocksSinceFlush >= forceAfterBlocks {
		return u.flushLocked()
	}
	return nil
}

// MaybeFlushIBD is a convenience method for IBD flushing using default interval.
func (u *UTXOSet) MaybeFlushIBD() error {
	return u.MaybeFlush(IBDFlushInterval)
}

// PreloadUTXOs loads multiple UTXOs from the database into cache.
// This is used to batch database reads before block validation.
func (u *UTXOSet) PreloadUTXOs(outpoints []wire.OutPoint) {
	if u.db == nil {
		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	for _, op := range outpoints {
		// Skip if already cached or deleted
		if _, ok := u.cache[op]; ok {
			continue
		}
		if u.deleted[op] {
			continue
		}

		key := storage.MakeUTXOKey(op)
		data, err := u.db.DB().Get(key)
		if err != nil || data == nil {
			continue
		}

		entry, err := DeserializeUTXOEntry(data)
		if err != nil {
			continue
		}

		u.cache[op] = entry
		u.cacheBytes += estimateEntrySize(entry)
	}
}

// Stats returns current cache statistics.
func (u *UTXOSet) Stats() UTXOCacheStats {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return UTXOCacheStats{
		Hits:       u.hits,
		Misses:     u.misses,
		Flushes:    u.flushes,
		CacheSize:  len(u.cache),
		CacheBytes: u.cacheBytes,
	}
}

// CacheBytes returns the approximate memory usage of the cache.
func (u *UTXOSet) CacheBytes() int64 {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.cacheBytes
}

// FlushBatch writes all dirty entries using a provided batch (for atomic block connection).
func (u *UTXOSet) FlushBatch(batch storage.Batch) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Write all dirty entries
	for outpoint := range u.dirty {
		entry := u.cache[outpoint]
		if entry != nil {
			key := storage.MakeUTXOKey(outpoint)
			data := SerializeUTXOEntry(entry)
			batch.Put(key, data)
		}
	}

	// Delete all deleted entries
	for outpoint := range u.deleted {
		key := storage.MakeUTXOKey(outpoint)
		batch.Delete(key)
	}

	// Clear dirty and deleted tracking (caller will write the batch)
	u.dirty = make(map[wire.OutPoint]bool)
	u.deleted = make(map[wire.OutPoint]bool)

	return nil
}

// Size returns the number of cached UTXOs.
func (u *UTXOSet) Size() int {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return len(u.cache)
}

// maybeFlush flushes if cache exceeds the maximum size.
func (u *UTXOSet) maybeFlush() error {
	u.mu.RLock()
	shouldFlush := len(u.cache) > DefaultCacheMaxEntries || u.cacheBytes > u.maxCacheBytes
	u.mu.RUnlock()

	if shouldFlush {
		return u.Flush()
	}
	return nil
}

// AddTxOutputs adds all outputs from a transaction to the UTXO set.
// Skips provably unspendable outputs (OP_RETURN).
func (u *UTXOSet) AddTxOutputs(tx *wire.MsgTx, height int32) {
	txHash := tx.TxHash()
	isCoinbase := IsCoinbaseTx(tx)

	for i, out := range tx.TxOut {
		// Skip provably unspendable outputs (OP_RETURN)
		if len(out.PkScript) > 0 && out.PkScript[0] == 0x6a {
			continue
		}

		outpoint := wire.OutPoint{
			Hash:  txHash,
			Index: uint32(i),
		}
		u.AddUTXO(outpoint, &UTXOEntry{
			Amount:     out.Value,
			PkScript:   bytes.Clone(out.PkScript),
			Height:     height,
			IsCoinbase: isCoinbase,
		})
	}
}

// SpendTxInputs removes all inputs of a transaction from the UTXO set.
func (u *UTXOSet) SpendTxInputs(tx *wire.MsgTx) {
	if IsCoinbaseTx(tx) {
		return // Coinbase has no real inputs to spend
	}
	for _, in := range tx.TxIn {
		u.SpendUTXO(in.PreviousOutPoint)
	}
}

// Ensure UTXOSet implements UpdatableUTXOView
var _ UpdatableUTXOView = (*UTXOSet)(nil)

// Script type constants for compression
const (
	scriptTypeP2PKH   = 0x00
	scriptTypeP2SH    = 0x01
	scriptTypeP2WPKH  = 0x02
	scriptTypeP2WSH   = 0x03
	scriptTypeP2TR    = 0x04
	scriptTypeUnknown = 0x05
)

// IsP2PKH checks if script is Pay-to-Public-Key-Hash.
// Format: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
func IsP2PKH(script []byte) bool {
	return len(script) == 25 &&
		script[0] == 0x76 && // OP_DUP
		script[1] == 0xa9 && // OP_HASH160
		script[2] == 0x14 && // Push 20 bytes
		script[23] == 0x88 && // OP_EQUALVERIFY
		script[24] == 0xac // OP_CHECKSIG
}

// IsP2SH checks if script is Pay-to-Script-Hash.
// Format: OP_HASH160 <20 bytes> OP_EQUAL
func IsP2SH(script []byte) bool {
	return len(script) == 23 &&
		script[0] == 0xa9 && // OP_HASH160
		script[1] == 0x14 && // Push 20 bytes
		script[22] == 0x87 // OP_EQUAL
}

// IsP2WPKH checks if script is Pay-to-Witness-Public-Key-Hash.
// Format: OP_0 <20 bytes>
func IsP2WPKH(script []byte) bool {
	return len(script) == 22 &&
		script[0] == 0x00 && // OP_0
		script[1] == 0x14 // Push 20 bytes
}

// IsP2WSH checks if script is Pay-to-Witness-Script-Hash.
// Format: OP_0 <32 bytes>
func IsP2WSH(script []byte) bool {
	return len(script) == 34 &&
		script[0] == 0x00 && // OP_0
		script[1] == 0x20 // Push 32 bytes
}

// IsP2TR checks if script is Pay-to-Taproot.
// Format: OP_1 <32 bytes>
func IsP2TR(script []byte) bool {
	return len(script) == 34 &&
		script[0] == 0x51 && // OP_1
		script[1] == 0x20 // Push 32 bytes
}

// IsPayToAnchor checks if script is Pay-to-Anchor.
// Format: OP_1 OP_PUSHBYTES_2 0x4e 0x73 (exactly 4 bytes)
// P2A is a standardized anyone-can-spend output for anchor outputs in L2 protocols.
func IsPayToAnchor(script []byte) bool {
	return len(script) == 4 &&
		script[0] == 0x51 && // OP_1
		script[1] == 0x02 && // Push 2 bytes
		script[2] == 0x4e &&
		script[3] == 0x73
}

// CompressScript compresses common script patterns for storage.
// - P2PKH (25 bytes) -> 21 bytes (type 0x00 + 20 byte hash)
// - P2SH (23 bytes) -> 21 bytes (type 0x01 + 20 byte hash)
// - P2WPKH (22 bytes) -> 21 bytes (type 0x02 + 20 byte hash)
// - P2WSH (34 bytes) -> 33 bytes (type 0x03 + 32 byte hash)
// - P2TR (34 bytes) -> 33 bytes (type 0x04 + 32 byte key)
// - Other scripts: type 0x05 + raw script
func CompressScript(script []byte) []byte {
	switch {
	case IsP2PKH(script):
		// Extract the 20-byte hash (bytes 3-22 inclusive)
		result := make([]byte, 21)
		result[0] = scriptTypeP2PKH
		copy(result[1:], script[3:23])
		return result

	case IsP2SH(script):
		// Extract the 20-byte hash (bytes 2-21 inclusive)
		result := make([]byte, 21)
		result[0] = scriptTypeP2SH
		copy(result[1:], script[2:22])
		return result

	case IsP2WPKH(script):
		// Extract the 20-byte hash (bytes 2-21 inclusive)
		result := make([]byte, 21)
		result[0] = scriptTypeP2WPKH
		copy(result[1:], script[2:22])
		return result

	case IsP2WSH(script):
		// Extract the 32-byte hash (bytes 2-33 inclusive)
		result := make([]byte, 33)
		result[0] = scriptTypeP2WSH
		copy(result[1:], script[2:34])
		return result

	case IsP2TR(script):
		// Extract the 32-byte key (bytes 2-33 inclusive)
		result := make([]byte, 33)
		result[0] = scriptTypeP2TR
		copy(result[1:], script[2:34])
		return result

	default:
		// Unknown script type - store as-is with type prefix
		result := make([]byte, 1+len(script))
		result[0] = scriptTypeUnknown
		copy(result[1:], script)
		return result
	}
}

// DecompressScript reverses script compression.
func DecompressScript(compressed []byte) []byte {
	if len(compressed) == 0 {
		return nil
	}

	scriptType := compressed[0]
	data := compressed[1:]

	switch scriptType {
	case scriptTypeP2PKH:
		if len(data) != 20 {
			return compressed // Invalid, return as-is
		}
		// Reconstruct: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
		script := make([]byte, 25)
		script[0] = 0x76  // OP_DUP
		script[1] = 0xa9  // OP_HASH160
		script[2] = 0x14  // Push 20 bytes
		copy(script[3:23], data)
		script[23] = 0x88 // OP_EQUALVERIFY
		script[24] = 0xac // OP_CHECKSIG
		return script

	case scriptTypeP2SH:
		if len(data) != 20 {
			return compressed
		}
		// Reconstruct: OP_HASH160 <20 bytes> OP_EQUAL
		script := make([]byte, 23)
		script[0] = 0xa9 // OP_HASH160
		script[1] = 0x14 // Push 20 bytes
		copy(script[2:22], data)
		script[22] = 0x87 // OP_EQUAL
		return script

	case scriptTypeP2WPKH:
		if len(data) != 20 {
			return compressed
		}
		// Reconstruct: OP_0 <20 bytes>
		script := make([]byte, 22)
		script[0] = 0x00 // OP_0
		script[1] = 0x14 // Push 20 bytes
		copy(script[2:22], data)
		return script

	case scriptTypeP2WSH:
		if len(data) != 32 {
			return compressed
		}
		// Reconstruct: OP_0 <32 bytes>
		script := make([]byte, 34)
		script[0] = 0x00 // OP_0
		script[1] = 0x20 // Push 32 bytes
		copy(script[2:34], data)
		return script

	case scriptTypeP2TR:
		if len(data) != 32 {
			return compressed
		}
		// Reconstruct: OP_1 <32 bytes>
		script := make([]byte, 34)
		script[0] = 0x51 // OP_1
		script[1] = 0x20 // Push 32 bytes
		copy(script[2:34], data)
		return script

	case scriptTypeUnknown:
		return data

	default:
		return compressed // Unknown type, return as-is
	}
}

// writeVaruint writes a variable-length unsigned integer without the 32MB limit.
// This is used for amounts and heights which can exceed the message size limits.
func writeVaruint(w *bytes.Buffer, val uint64) {
	switch {
	case val < 0xFD:
		w.WriteByte(byte(val))
	case val <= 0xFFFF:
		w.WriteByte(0xFD)
		var buf [2]byte
		buf[0] = byte(val)
		buf[1] = byte(val >> 8)
		w.Write(buf[:])
	case val <= 0xFFFFFFFF:
		w.WriteByte(0xFE)
		var buf [4]byte
		buf[0] = byte(val)
		buf[1] = byte(val >> 8)
		buf[2] = byte(val >> 16)
		buf[3] = byte(val >> 24)
		w.Write(buf[:])
	default:
		w.WriteByte(0xFF)
		var buf [8]byte
		buf[0] = byte(val)
		buf[1] = byte(val >> 8)
		buf[2] = byte(val >> 16)
		buf[3] = byte(val >> 24)
		buf[4] = byte(val >> 32)
		buf[5] = byte(val >> 40)
		buf[6] = byte(val >> 48)
		buf[7] = byte(val >> 56)
		w.Write(buf[:])
	}
}

// readVaruint reads a variable-length unsigned integer without the 32MB limit.
func readVaruint(r *bytes.Reader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}

	var val uint64
	switch first {
	case 0xFD:
		buf := make([]byte, 2)
		if _, err := r.Read(buf); err != nil {
			return 0, err
		}
		val = uint64(buf[0]) | uint64(buf[1])<<8
	case 0xFE:
		buf := make([]byte, 4)
		if _, err := r.Read(buf); err != nil {
			return 0, err
		}
		val = uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24
	case 0xFF:
		buf := make([]byte, 8)
		if _, err := r.Read(buf); err != nil {
			return 0, err
		}
		val = uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
			uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56
	default:
		val = uint64(first)
	}
	return val, nil
}

// SerializeUTXOEntry serializes a UTXO entry for storage.
// Format:
//   - Height and coinbase flag: varint (height << 1 | coinbase_flag)
//   - Amount: varint
//   - Script type and script: compressed script with varint length
func SerializeUTXOEntry(entry *UTXOEntry) []byte {
	var buf bytes.Buffer

	// Height and coinbase combined: height << 1 | coinbase
	heightCode := uint64(entry.Height) << 1
	if entry.IsCoinbase {
		heightCode |= 1
	}
	writeVaruint(&buf, heightCode)

	// Amount as varint (can exceed 32MB)
	writeVaruint(&buf, uint64(entry.Amount))

	// Script (compressed) with length prefix
	compressedScript := CompressScript(entry.PkScript)
	writeVaruint(&buf, uint64(len(compressedScript)))
	buf.Write(compressedScript)

	return buf.Bytes()
}

// DeserializeUTXOEntry deserializes a UTXO entry from storage.
func DeserializeUTXOEntry(data []byte) (*UTXOEntry, error) {
	r := bytes.NewReader(data)

	// Read height and coinbase flag
	heightCode, err := readVaruint(r)
	if err != nil {
		return nil, err
	}
	height := int32(heightCode >> 1)
	isCoinbase := (heightCode & 1) == 1

	// Read amount
	amount, err := readVaruint(r)
	if err != nil {
		return nil, err
	}

	// Read compressed script length and data
	scriptLen, err := readVaruint(r)
	if err != nil {
		return nil, err
	}
	if scriptLen > 10000 {
		return nil, errors.New("script too large")
	}
	compressedScript := make([]byte, scriptLen)
	if _, err := r.Read(compressedScript); err != nil {
		return nil, err
	}
	pkScript := DecompressScript(compressedScript)

	return &UTXOEntry{
		Amount:     int64(amount),
		PkScript:   pkScript,
		Height:     height,
		IsCoinbase: isCoinbase,
	}, nil
}

// SpentOutput records a UTXO that was spent, for undo purposes.
type SpentOutput struct {
	OutPoint wire.OutPoint
	Entry    UTXOEntry
}

// UndoBlock contains the data needed to undo a connected block.
type UndoBlock struct {
	SpentOutputs []SpentOutput // UTXOs consumed by this block
}

// Serialize serializes the undo block for storage.
func (ub *UndoBlock) Serialize() []byte {
	var buf bytes.Buffer

	// Write number of spent outputs
	wire.WriteCompactSize(&buf, uint64(len(ub.SpentOutputs)))

	// Write each spent output
	for _, so := range ub.SpentOutputs {
		// Write the outpoint
		so.OutPoint.Serialize(&buf)

		// Write the UTXO entry
		entryData := SerializeUTXOEntry(&so.Entry)
		wire.WriteVarBytes(&buf, entryData)
	}

	return buf.Bytes()
}

// DeserializeUndoBlock deserializes undo data.
func DeserializeUndoBlock(data []byte) (*UndoBlock, error) {
	r := bytes.NewReader(data)

	// Read number of spent outputs
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return nil, err
	}

	ub := &UndoBlock{
		SpentOutputs: make([]SpentOutput, 0, count),
	}

	// Read each spent output
	for i := uint64(0); i < count; i++ {
		var so SpentOutput

		// Read outpoint
		if err := so.OutPoint.Deserialize(r); err != nil {
			return nil, err
		}

		// Read UTXO entry
		entryData, err := wire.ReadVarBytes(r, 100000) // reasonable max
		if err != nil {
			return nil, err
		}
		entry, err := DeserializeUTXOEntry(entryData)
		if err != nil {
			return nil, err
		}
		so.Entry = *entry

		ub.SpentOutputs = append(ub.SpentOutputs, so)
	}

	return ub, nil
}

// ConnectBlockUTXOs connects a block's transactions to the UTXO set.
// Returns undo data for potential future disconnection.
// This is a helper method that properly tracks spent UTXOs for undo purposes.
func (u *UTXOSet) ConnectBlockUTXOs(block *wire.MsgBlock, height int32) (*UndoBlock, error) {
	undo := &UndoBlock{
		SpentOutputs: make([]SpentOutput, 0),
	}

	for i, tx := range block.Transactions {
		// For non-coinbase transactions, save spent UTXOs and then spend them
		if i > 0 {
			for _, in := range tx.TxIn {
				// Get the UTXO being spent
				entry := u.GetUTXO(in.PreviousOutPoint)
				if entry == nil {
					return nil, ErrUTXONotFound
				}

				// Record for undo
				undo.SpentOutputs = append(undo.SpentOutputs, SpentOutput{
					OutPoint: in.PreviousOutPoint,
					Entry:    *entry,
				})

				// Spend it
				u.SpendUTXO(in.PreviousOutPoint)
			}
		}

		// Add outputs to UTXO set
		u.AddTxOutputs(tx, height)
	}

	return undo, nil
}

// DisconnectBlockUTXOs reverses the effects of ConnectBlockUTXOs.
// It removes outputs created by the block and restores spent UTXOs from undo data.
func (u *UTXOSet) DisconnectBlockUTXOs(block *wire.MsgBlock, undo *UndoBlock) error {
	// Process transactions in reverse order
	for i := len(block.Transactions) - 1; i >= 0; i-- {
		tx := block.Transactions[i]
		txHash := tx.TxHash()

		// Remove outputs created by this transaction
		for idx := range tx.TxOut {
			outpoint := wire.OutPoint{Hash: txHash, Index: uint32(idx)}
			u.SpendUTXO(outpoint)
		}
	}

	// Restore all spent UTXOs from undo data
	for _, so := range undo.SpentOutputs {
		entry := so.Entry // copy
		u.AddUTXO(so.OutPoint, &entry)
	}

	return nil
}
