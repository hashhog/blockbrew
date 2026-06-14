package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"sort"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// BIP158 basic filter parameters.
const (
	// BasicFilterP is the Golomb-Rice coding parameter for basic filters.
	BasicFilterP = 19
	// BasicFilterM is the false positive rate parameter for basic filters.
	BasicFilterM = 784931
)

// BlockFilterIndex key prefixes.
var (
	// BlockFilterPrefix stores height -> filter data mapping.
	// Key: "X" + height (4 bytes big-endian)
	//
	// Note: changed from "f" to "X" to avoid collision with blockFileInfoPrefix
	// ("f" + uint32 fileNum) in flatfile.go. Both key spaces live in the same
	// PebbleDB instance; using the same prefix caused silent data corruption
	// when -blockfilterindex was active (W109 BUG-G12 P0).
	BlockFilterPrefix = []byte("X")

	// BlockFilterStateKey stores the index state.
	BlockFilterStateKey = []byte("blockfilter_state")
)

// BlockFilterIndexFormatVersion tags the on-disk format of the BIP-158 GCS
// filter bytes. Bumped from 0 → 1 in FIX-83 when the GCS bit-stream codec
// was rewritten to be MSB-first (Bitcoin Core compatible). Old (version 0)
// filter bytes were LSB-first within each byte and byte-incompatible with
// Bitcoin Core's BlockFilter::GetEncoded() (W122 BUG-2).
//
// On Init(), if the state row carries an older version (or no version, the
// pre-FIX-83 layout) we log a loud notice and reset the index to height=-1
// so the IndexManager rebuilds every row from genesis with the new codec.
// The stale (orphan) filter rows under BlockFilterPrefix are overwritten as
// the rebuild progresses; operators who want to reclaim disk eagerly can
// delete <datadir>/<network>/chaindata and let the full chainstate +
// blockfilterindex rebuild together. Since the index is opt-in
// (`-blockfilterindex` flag, default OFF — see cmd/blockbrew/main.go:494),
// this auto-rebuild is the least surprising migration: an operator that
// already opted in gets correct bytes silently after the upgrade.
const BlockFilterIndexFormatVersion uint8 = 1

// BlockFilterData stores a compact block filter and its header.
type BlockFilterData struct {
	BlockHash    wire.Hash256 // Hash of the block
	FilterHash   wire.Hash256 // SHA256d of the encoded filter
	FilterHeader wire.Hash256 // Filter header chain: SHA256d(filterHash || prevFilterHeader)
	Filter       []byte       // Golomb-Rice encoded filter
}

// Serialize writes the BlockFilterData to bytes.
func (d *BlockFilterData) Serialize() []byte {
	buf := new(bytes.Buffer)
	d.BlockHash.Serialize(buf)
	d.FilterHash.Serialize(buf)
	d.FilterHeader.Serialize(buf)
	wire.WriteVarBytes(buf, d.Filter)
	return buf.Bytes()
}

// DeserializeBlockFilterData reads a BlockFilterData from bytes.
func DeserializeBlockFilterData(data []byte) (*BlockFilterData, error) {
	r := bytes.NewReader(data)
	d := &BlockFilterData{}

	if err := d.BlockHash.Deserialize(r); err != nil {
		return nil, err
	}
	if err := d.FilterHash.Deserialize(r); err != nil {
		return nil, err
	}
	if err := d.FilterHeader.Deserialize(r); err != nil {
		return nil, err
	}

	var err error
	d.Filter, err = wire.ReadVarBytes(r, 1<<20) // Max 1MB filter
	if err != nil {
		return nil, err
	}

	return d, nil
}

// MakeBlockFilterKey creates a key for block filter data.
func MakeBlockFilterKey(height int32) []byte {
	key := make([]byte, 1+4)
	key[0] = BlockFilterPrefix[0]
	binary.BigEndian.PutUint32(key[1:], uint32(height))
	return key
}

// BlockFilterIndex implements BIP157/158 compact block filters.
type BlockFilterIndex struct {
	*BaseIndex
	prevFilterHeader wire.Hash256 // Previous filter header for chain computation
}

// NewBlockFilterIndex creates a new block filter index.
func NewBlockFilterIndex(db DB) *BlockFilterIndex {
	return &BlockFilterIndex{
		BaseIndex: NewBaseIndex("blockfilterindex", db),
	}
}

// NeedsUndo reports that the blockfilterindex requires real per-block undo data
// on both the catch-up and live connect paths so that spent-prevout scriptPubKeys
// are included in the BIP-158 basic filter. Bitcoin Core's blockfilterindex sets
// options.connect_undo_data = true (index/blockfilterindex.cpp:94) for exactly
// this reason, and its CustomAppend asserts block.undo_data non-nil (line 252).
// Without undo the filter misses spent prevout scripts, breaking wallet rescans
// against the filter for any block that spends outputs.
func (idx *BlockFilterIndex) NeedsUndo() bool { return true }

// Init initializes the blockfilterindex by loading state from the database.
//
// FIX-83 / W122 migration: if the state row carries no
// BlockFilterIndexFormatVersion (i.e. it was written by a pre-FIX-83
// blockbrew using the broken LSB-first GCS codec), reset the index to
// height=-1 so the IndexManager rebuilds every filter row with the new
// MSB-first / Core-compatible codec. Stale filter rows on disk are
// overwritten as the rebuild progresses. Operators who notice their
// blockfilterindex restarting from genesis after the upgrade are
// experiencing this migration and need take no action.
func (idx *BlockFilterIndex) Init() error {
	data, err := idx.db.Get(BlockFilterStateKey)
	if err != nil {
		return err
	}
	if data == nil {
		// No existing state, start fresh
		idx.bestHeight = -1
		return nil
	}

	state, err := DeserializeBlockFilterState(data)
	if err != nil {
		// Could be old (pre-FIX-83) layout that doesn't carry a version
		// byte. Treat as obsolete and force a rebuild from genesis.
		log.Printf("blockfilterindex: pre-FIX-83 state-row layout detected (no version byte); "+
			"resetting to height=-1 to rebuild with MSB-first Core-compatible codec (W122 BUG-2 fix). "+
			"Filter index will repopulate as blocks are connected.")
		if err := idx.wipeStaleFilterRows(); err != nil {
			log.Printf("blockfilterindex: warning — stale-row cleanup failed: %v (rebuild will overwrite as it advances)", err)
		}
		idx.bestHeight = -1
		return nil
	}
	if state.FormatVersion != BlockFilterIndexFormatVersion {
		// Old codec format → reset, rebuild on next IndexManager pass.
		log.Printf("blockfilterindex: on-disk FormatVersion=%d but code expects %d; "+
			"resetting to height=-1 to rebuild with current GCS codec.",
			state.FormatVersion, BlockFilterIndexFormatVersion)
		if err := idx.wipeStaleFilterRows(); err != nil {
			log.Printf("blockfilterindex: warning — stale-row cleanup failed: %v (rebuild will overwrite as it advances)", err)
		}
		idx.bestHeight = -1
		return nil
	}
	idx.bestHeight = state.BestHeight
	idx.bestHash = state.BestHash
	idx.prevFilterHeader = state.PrevFilterHeader
	return nil
}

// wipeStaleFilterRows deletes every key under BlockFilterPrefix in a single
// batch. Called by Init when the on-disk format version doesn't match the
// running code — keeping stale rows would waste disk; overwriting them via
// the rebuild path is functionally correct but operators expect a clean
// rebuild to actually reclaim space promptly. The state-row is left alone;
// Init's caller will write a fresh state-row on the first WriteBlock.
//
// Best-effort: errors are logged at the call site, not fatal — even with
// stale rows, the IndexManager's rebuild path will overwrite each height
// with the new codec's bytes as it progresses.
func (idx *BlockFilterIndex) wipeStaleFilterRows() error {
	iter := idx.db.NewIterator(BlockFilterPrefix)
	defer iter.Release()
	batch := idx.db.NewBatch()
	count := 0
	for iter.Next() {
		// Copy because Pebble's Key() bytes are only valid until Next().
		k := append([]byte(nil), iter.Key()...)
		batch.Delete(k)
		count++
	}
	if err := iter.Error(); err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	if err := batch.Write(); err != nil {
		return err
	}
	log.Printf("blockfilterindex: wiped %d stale filter row(s) during FIX-83 / W122 codec migration", count)
	return nil
}

// WriteBlock builds and stores a compact block filter for a newly connected
// block. Opens its own write batch and commits it before returning.
//
// Used outside reorgs (the IBD / single-block-extend happy path). Inside a
// reorg, callers should prefer WriteBlockBatch + the chain manager's shared
// reorg batch so the multi-block disconnect+reconnect commits atomically
// (BIP-157 Phase 2 — see CORE-PARITY-AUDIT and ChainManager.CurrentReorgBatch).
func (idx *BlockFilterIndex) WriteBlock(block *wire.MsgBlock, height int32, blockHash wire.Hash256, undo *BlockUndo) error {
	batch := idx.db.NewBatch()
	if err := idx.WriteBlockBatch(batch, block, height, blockHash, undo); err != nil {
		return err
	}
	if err := batch.Write(); err != nil {
		return err
	}
	idx.commitWriteState(height, blockHash)
	return nil
}

// WriteBlockBatch is the batch-aware variant of WriteBlock.
//
// It computes the BIP-158 basic filter + filter-header chain entry for the
// given block and APPENDS the filter Put + state Put into the caller-owned
// batch. It does NOT commit the batch and does NOT mutate the index's
// in-memory best-height / prev-filter-header until commitWriteState is called.
//
// The intended call sequence inside a reorg is:
//
//	batch := chainMgr.CurrentReorgBatch() // shared with cm.reorgBatch
//	if err := idx.WriteBlockBatch(batch, blk, h, hash, undo); err != nil { ... }
//	// ... ReorgTo's commit eventually calls batch.Write()
//	idx.CommitWriteState(h, hash)         // POST-Write only
//
// Outside of a reorg (single-block extend) WriteBlock is the right entry
// point — it does open + delegate + commit + commitWriteState in one call.
//
// Cross-impl reference: bitcoin-core/src/index/blockfilterindex.cpp::CustomAppend.
func (idx *BlockFilterIndex) WriteBlockBatch(batch Batch, block *wire.MsgBlock, height int32, blockHash wire.Hash256, undo *BlockUndo) error {
	if batch == nil {
		return errors.New("blockfilterindex: WriteBlockBatch called with nil batch")
	}

	// Build the GCS filter
	filter := idx.buildBasicFilter(block, undo, blockHash)

	// Compute filter hash
	filterHash := wire.DoubleHashB(filter)

	// Compute filter header: SHA256d(filterHash || prevFilterHeader)
	prev := idx.PrevFilterHeader()
	headerData := make([]byte, 64)
	copy(headerData[:32], filterHash[:])
	copy(headerData[32:], prev[:])
	filterHeader := wire.DoubleHashB(headerData)

	// Filter-data entry keyed by height.
	filterData := &BlockFilterData{
		BlockHash:    blockHash,
		FilterHash:   filterHash,
		FilterHeader: filterHeader,
		Filter:       filter,
	}
	batch.Put(MakeBlockFilterKey(height), filterData.Serialize())

	// State entry pointing at the new tip. FormatVersion is stamped by
	// Serialize() if zero, so we get FIX-83 / W122 MSB-first tagging on
	// every fresh write — no risk of writing back the pre-FIX-83 layout.
	state := &BlockFilterState{
		FormatVersion:    BlockFilterIndexFormatVersion,
		BestHeight:       height,
		BestHash:         blockHash,
		PrevFilterHeader: filterHeader,
	}
	batch.Put(BlockFilterStateKey, state.Serialize())

	// Stash the freshly-computed filter-header on the index so the *next*
	// WriteBlockBatch call inside the same reorg can chain off it without
	// having to read the not-yet-committed batch back. The reorg batch
	// commits all entries atomically; if the caller never commits the batch
	// (e.g. ReorgTo errors before batch.Write()), the in-memory mutation
	// here is reverted by the chain manager's defer-rollback path that
	// re-Init's the index, OR — in the ChainManager.reorgBatch flow —
	// simply abandoning the batch leaves the on-disk state at the
	// pre-reorg tip while the index re-loads from disk on next Init.
	//
	// We deliberately do NOT call UpdateBest here: bestHeight / bestHash
	// changes only land via commitWriteState on the post-batch-Write path
	// so a crash between Put and Write doesn't leave the index in-memory
	// pointing at a tip that disk doesn't agree with.
	idx.setPrevFilterHeader(filterHeader)

	return nil
}

// WriteGenesis writes the BIP-158 basic filter row for the genesis block
// (height 0) when the index is fresh (best height still -1). Bitcoin Core's
// BaseIndex indexes EVERY connected block starting at the genesis block
// (index/base.cpp::Init seeds m_best_block_index from the genesis block, and
// the genesis filter is computed by BlockFilterIndex::CustomAppend like any
// other). The genesis filter header chains from the all-zero previous header
// (there is no parent), exactly as Core does — see
// bitcoin-core/src/index/blockfilterindex.cpp and BlockFilter::ComputeHeader,
// which is called with the all-zero prev for the first indexed block.
//
// blockbrew's connect hook is intentionally skipped for height 0 (the genesis
// coinbase is unspendable, so the txindex/UTXO hooks have nothing to do), so
// the filter index would otherwise never get a genesis row. That omission is
// not benign: without the genesis filter header on disk, the height-1 filter
// header would chain from all-zero instead of from the genesis filter header,
// making EVERY filter header byte-incompatible with Core from height 1 onward
// (the filter bytes themselves are unaffected; only the BIP-157 header chain
// breaks). This helper closes that gap.
//
// Idempotent + safe: it only acts when bestHeight is still -1 (a freshly
// initialised or migration-reset index). If the index already advanced past
// genesis it returns nil without touching anything.
//
// genesisBlock must be the network's genesis block; genesisHash its block hash.
// The genesis block has no spends, so undo data is nil (BasicFilterElements
// over the genesis is just its coinbase output scriptPubKey).
func (idx *BlockFilterIndex) WriteGenesis(genesisBlock *wire.MsgBlock, genesisHash wire.Hash256) error {
	if idx.BestHeight() >= 0 {
		// Already indexed at/past genesis; nothing to do.
		return nil
	}
	// At a fresh index the in-memory prevFilterHeader is the zero value
	// (all-zero), which is exactly the BIP-157 genesis-parent header. The
	// shared WriteBlock path computes the genesis filter, chains its header
	// off that all-zero prev, stores the row at height 0, advances
	// prevFilterHeader to the genesis filter header, and publishes
	// bestHeight=0 — so the height-1 connect chains correctly off genesis.
	return idx.WriteBlock(genesisBlock, 0, genesisHash, nil)
}

// commitWriteState publishes the post-Write best-height/best-hash on the
// in-memory index. Must be called only after the batch containing the
// WriteBlockBatch entries has been committed to disk.
func (idx *BlockFilterIndex) commitWriteState(height int32, blockHash wire.Hash256) {
	idx.UpdateBest(height, blockHash)
}

// CommitWriteState is the exported alias for callers driving the batch
// life-cycle from outside the package (e.g. the chain-manager hook which
// hands the shared reorg batch + commits via ReorgTo's batch.Write). The
// hook signals "the batch I gave you just landed on disk" by calling this.
//
// Symmetric pair: CommitRevertState for the disconnect path.
func (idx *BlockFilterIndex) CommitWriteState(height int32, blockHash wire.Hash256) {
	idx.commitWriteState(height, blockHash)
}

// RevertBlock removes a block filter from the index. Opens its own write
// batch and commits it before returning.
//
// Used outside reorgs (the rare single-tip-disconnect operator path). Inside
// a reorg, callers should prefer RevertBlockBatch + the chain manager's
// shared reorg batch so the multi-block disconnect+reconnect commits
// atomically (BIP-157 Phase 2). The batch helper is the cross-impl analog
// of bitcoin-core/src/index/blockfilterindex.cpp::CustomRemove which builds
// a CDBBatch, queues the deletion + state-row write, and commits.
func (idx *BlockFilterIndex) RevertBlock(block *wire.MsgBlock, height int32, blockHash wire.Hash256, undo *BlockUndo) error {
	batch := idx.db.NewBatch()
	prevHeight, prevHash, prevFilterHeader, err := idx.RevertBlockBatch(batch, block, height, blockHash, undo)
	if err != nil {
		return err
	}
	if err := batch.Write(); err != nil {
		return err
	}
	idx.commitRevertState(prevHeight, prevHash, prevFilterHeader)
	return nil
}

// RevertBlockBatch is the batch-aware variant of RevertBlock.
//
// It APPENDS the filter-row deletion + state-row write that mark the index
// as having peeled `height` off into the caller-owned batch and returns
// (prevHeight, prevHash, prevFilterHeader) so the caller can finish the
// post-Write state mutation by calling CommitRevertState once the batch has
// landed on disk.
//
// BIP-157 Phase 2 — reorg-aware filter chain (2026-05-06).
// The chain-manager hook for OnBlockDisconnected uses this when
// cm.CurrentReorgBatch() is non-nil so the filter rewind rides the same
// Pebble batch as the UTXO + chainstate + undo-data rewind. A crash before
// ReorgTo's final batch.Write() leaves the on-disk filter index at the
// pre-reorg tip; success leaves it at the post-reorg tip — there is no
// intermediate state where the consensus chain has reorged but the filter
// index still references the abandoned branch.
//
// Cross-impl reference: bitcoin-core/src/index/blockfilterindex.cpp::CustomRemove
// — Core also batches the deletion + state-row in a single CDBBatch, then
// commits via BaseIndex::Rewind. This helper is the blockbrew analog and
// composes with cm.reorgBatch the same way Core's CustomRemove composes
// with the surrounding ActivateBestChain CDBBatch.
//
// Returns (prevHeight, prevHash, prevFilterHeader, error). Even on error,
// no in-memory state on the index is mutated (the caller's batch may also
// be partially populated, and the Pebble batch semantics guarantee an
// abandoned batch is safely droppable).
func (idx *BlockFilterIndex) RevertBlockBatch(batch Batch, block *wire.MsgBlock, height int32, blockHash wire.Hash256, _ *BlockUndo) (int32, wire.Hash256, wire.Hash256, error) {
	if batch == nil {
		return 0, wire.Hash256{}, wire.Hash256{}, errors.New("blockfilterindex: RevertBlockBatch called with nil batch")
	}

	prevHash := block.Header.PrevBlock
	prevHeight := height - 1

	// Load previous filter header from the on-disk index. During a multi-
	// block disconnect, the prev-height filter row is still on disk because
	// we peel from tip backward and only the just-peeled block's row is
	// queued for deletion in the current batch. Successive peels read each
	// time from disk — this is the same read-from-disk pattern Bitcoin
	// Core's CustomRemove uses (it calls ReadFilterHeader directly off the
	// CDBWrapper, not via the in-flight batch).
	var prevFilterHeader wire.Hash256
	if prevHeight >= 0 {
		prevData, err := idx.GetFilter(prevHeight)
		if err == nil {
			prevFilterHeader = prevData.FilterHeader
		}
	}

	// Queue the deletion of the filter row at this height into the caller's
	// batch.
	batch.Delete(MakeBlockFilterKey(height))

	// Queue the state-row write so post-commit the index points at the
	// pre-disconnect parent. FormatVersion is FIX-83 / W122 v1.
	state := &BlockFilterState{
		FormatVersion:    BlockFilterIndexFormatVersion,
		BestHeight:       prevHeight,
		BestHash:         prevHash,
		PrevFilterHeader: prevFilterHeader,
	}
	batch.Put(BlockFilterStateKey, state.Serialize())

	return prevHeight, prevHash, prevFilterHeader, nil
}

// commitRevertState publishes the post-Write tip + prev-filter-header on
// the in-memory index. Must be called only after the batch containing the
// RevertBlockBatch entries has been committed to disk.
func (idx *BlockFilterIndex) commitRevertState(prevHeight int32, prevHash wire.Hash256, prevFilterHeader wire.Hash256) {
	idx.setPrevFilterHeader(prevFilterHeader)
	idx.UpdateBest(prevHeight, prevHash)
}

// CommitRevertState is the exported alias used by the chain-manager hook to
// signal "the batch I gave you just landed on disk".
//
// Symmetric pair: CommitWriteState for the connect path.
func (idx *BlockFilterIndex) CommitRevertState(prevHeight int32, prevHash wire.Hash256, prevFilterHeader wire.Hash256) {
	idx.commitRevertState(prevHeight, prevHash, prevFilterHeader)
}

// PrevFilterHeader returns the in-memory cached previous-filter-header used
// to chain the next block's filter header. Read under the BaseIndex lock so
// concurrent WriteBlockBatch + GetFilter calls see a consistent snapshot.
func (idx *BlockFilterIndex) PrevFilterHeader() wire.Hash256 {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.prevFilterHeader
}

// setPrevFilterHeader updates the in-memory cached previous-filter-header.
// Held under the BaseIndex lock to be consistent with the public reader.
func (idx *BlockFilterIndex) setPrevFilterHeader(h wire.Hash256) {
	idx.mu.Lock()
	idx.prevFilterHeader = h
	idx.mu.Unlock()
}

// GetFilter returns the filter data for a given height.
func (idx *BlockFilterIndex) GetFilter(height int32) (*BlockFilterData, error) {
	key := MakeBlockFilterKey(height)
	data, err := idx.db.Get(key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrNotFound
	}
	return DeserializeBlockFilterData(data)
}

// GetFilterHeader returns the filter header for a given height.
func (idx *BlockFilterIndex) GetFilterHeader(height int32) (wire.Hash256, error) {
	filterData, err := idx.GetFilter(height)
	if err != nil {
		return wire.Hash256{}, err
	}
	return filterData.FilterHeader, nil
}

// buildBasicFilter builds a BIP158 basic block filter.
// The filter includes:
// - scriptPubKeys of all outputs created in the block
// - scriptPubKeys of all outputs spent by inputs in the block
func (idx *BlockFilterIndex) buildBasicFilter(block *wire.MsgBlock, undo *BlockUndo, blockHash wire.Hash256) []byte {
	// Collect all script elements
	elements := make(map[string]struct{})

	// Add scriptPubKeys from outputs
	for _, tx := range block.Transactions {
		for _, out := range tx.TxOut {
			// Skip empty scripts and OP_RETURN outputs
			if len(out.PkScript) == 0 {
				continue
			}
			if out.PkScript[0] == 0x6a { // OP_RETURN
				continue
			}
			elements[string(out.PkScript)] = struct{}{}
		}
	}

	// Add scriptPubKeys from spent inputs (from undo data)
	if undo != nil {
		for _, txUndo := range undo.TxUndos {
			for _, spent := range txUndo.SpentCoins {
				if len(spent.TxOut.PkScript) == 0 {
					continue
				}
				elements[string(spent.TxOut.PkScript)] = struct{}{}
			}
		}
	}

	// Convert to sorted slice of elements
	sortedElements := make([][]byte, 0, len(elements))
	for elem := range elements {
		sortedElements = append(sortedElements, []byte(elem))
	}
	sort.Slice(sortedElements, func(i, j int) bool {
		return bytes.Compare(sortedElements[i], sortedElements[j]) < 0
	})

	// Build GCS filter
	return encodeGCS(sortedElements, blockHash)
}

// encodeGCS encodes elements as a Golomb-coded set (GCS) filter.
func encodeGCS(elements [][]byte, blockHash wire.Hash256) []byte {
	if len(elements) == 0 {
		// Empty filter: just the element count (0)
		return []byte{0}
	}

	// Derive SipHash key from block hash (first 16 bytes)
	k0 := binary.LittleEndian.Uint64(blockHash[:8])
	k1 := binary.LittleEndian.Uint64(blockHash[8:16])

	N := uint64(len(elements))
	F := N * BasicFilterM

	// Hash each element to a value in [0, F)
	hashes := make([]uint64, len(elements))
	for i, elem := range elements {
		h := siphash(k0, k1, elem)
		hashes[i] = fastRange64(h, F)
	}

	// Sort hashes
	sort.Slice(hashes, func(i, j int) bool { return hashes[i] < hashes[j] })

	// Encode as Golomb-Rice coded deltas
	var buf bytes.Buffer

	// Write element count as CompactSize
	wire.WriteCompactSize(&buf, N)

	// Write Golomb-Rice encoded deltas
	var bitWriter bitStreamWriter
	var prev uint64
	for _, h := range hashes {
		delta := h - prev
		prev = h
		golombRiceEncode(&bitWriter, BasicFilterP, delta)
	}
	bitWriter.flush()

	buf.Write(bitWriter.bytes)
	return buf.Bytes()
}

// fastRange64 computes (h * n) >> 64, which gives a value in [0, n).
func fastRange64(h, n uint64) uint64 {
	// Use 128-bit multiplication to get full precision
	hi, _ := bits128Mul(h, n)
	return hi
}

// bits128Mul computes the 128-bit product of two 64-bit values.
// Returns (high, low) where result = high * 2^64 + low.
func bits128Mul(a, b uint64) (uint64, uint64) {
	aLo := a & 0xFFFFFFFF
	aHi := a >> 32
	bLo := b & 0xFFFFFFFF
	bHi := b >> 32

	// Partial products
	p0 := aLo * bLo
	p1 := aLo * bHi
	p2 := aHi * bLo
	p3 := aHi * bHi

	// Combine partial products
	carry := ((p0 >> 32) + (p1 & 0xFFFFFFFF) + (p2 & 0xFFFFFFFF)) >> 32
	hi := p3 + (p1 >> 32) + (p2 >> 32) + carry
	lo := p0 + (p1 << 32) + (p2 << 32)

	return hi, lo
}

// siphash computes SipHash-2-4 of the given data with the provided key.
func siphash(k0, k1 uint64, data []byte) uint64 {
	// SipHash-2-4 implementation
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	// Process 8-byte blocks
	blocks := len(data) / 8
	for i := 0; i < blocks; i++ {
		m := binary.LittleEndian.Uint64(data[i*8:])
		v3 ^= m
		sipRound(&v0, &v1, &v2, &v3)
		sipRound(&v0, &v1, &v2, &v3)
		v0 ^= m
	}

	// Process remaining bytes
	var last uint64
	last = uint64(len(data)) << 56
	remaining := data[blocks*8:]
	for i := len(remaining) - 1; i >= 0; i-- {
		last |= uint64(remaining[i]) << (8 * uint(i))
	}

	v3 ^= last
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	v0 ^= last

	// Finalization
	v2 ^= 0xff
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)

	return v0 ^ v1 ^ v2 ^ v3
}

func sipRound(v0, v1, v2, v3 *uint64) {
	*v0 += *v1
	*v1 = rotl64(*v1, 13)
	*v1 ^= *v0
	*v0 = rotl64(*v0, 32)

	*v2 += *v3
	*v3 = rotl64(*v3, 16)
	*v3 ^= *v2

	*v0 += *v3
	*v3 = rotl64(*v3, 21)
	*v3 ^= *v0

	*v2 += *v1
	*v1 = rotl64(*v1, 17)
	*v1 ^= *v2
	*v2 = rotl64(*v2, 32)
}

func rotl64(x uint64, b uint) uint64 {
	return (x << b) | (x >> (64 - b))
}

// bitStreamWriter writes bits to a byte buffer.
//
// Packing is MSB-first within each byte, mirroring Bitcoin Core's
// BitStreamWriter (bitcoin-core/src/streams.h:303-358). The first bit
// written to an empty byte lands in bit 7 (the most-significant bit);
// subsequent bits fill leftward → rightward within the same byte. This
// is byte-exactly compatible with Core's `BlockFilter::GetEncoded()` and
// with the BIP-158 test vectors in `bitcoin-core/src/test/data/
// blockfilters.json` — verified by TestW122_GenesisFilterByteExact
// (height-0: 019dfca8 = Core's exact bytes).
//
// History — FIX-83 (2026-05-17) replaced the prior LSB-first chunked-
// uint64 implementation that had two compounding P0-CDIV bugs:
//
//   - BUG-1: `accumBits |= v << numBits` silently truncated the top
//     `numBits` bits of v when v<<numBits overflowed the uint64
//     accumulator, dropping bits from golombRiceEncode's 64-ones unary
//     chunk whenever a prior element left numBits > 0.
//   - BUG-2: bytes were emitted LSB-first within each byte, so every
//     filter blockbrew produced was byte-incompatible with Core. The
//     existing TestBIP158Vectors deliberately opted out of byte-exact
//     comparison; that opt-out is now removed.
//
// The new MSB-first per-byte chunked Write closes both bugs in one
// rewrite — the per-iteration `bits = min(8 - offset, n)` clamp prevents
// any shift-width-overflow boundary.
type bitStreamWriter struct {
	bytes  []byte
	buffer uint8 // partial byte; high `offset` bits are written, low bits are 0
	offset uint  // number of bits already in `buffer`, 0..7
}

// writeBits writes the n least-significant bits of v to the stream,
// MSB-first within each byte (matching Bitcoin Core's BitStreamWriter).
//
// Core reference (bitcoin-core/src/streams.h:329-344):
//
//	while (nbits > 0) {
//	    int bits = std::min(8 - m_offset, nbits);
//	    m_buffer |= (data << (64 - nbits)) >> (64 - 8 + m_offset);
//	    m_offset += bits;
//	    nbits -= bits;
//	    if (m_offset == 8) { Flush(); }
//	}
//
// The per-iteration `bits = min(8 - offset, nbits)` clamp guarantees we
// never shift by 64 (or wider). The (64 - nbits) shift would underflow
// only if nbits > 64, which we reject up-front to match Core's
// std::out_of_range throw.
func (w *bitStreamWriter) writeBits(v uint64, n uint) {
	if n > 64 {
		// Defensive: Core throws std::out_of_range; we panic so callers
		// learn at the call site (golombRiceEncode never exceeds 64).
		panic("bitStreamWriter.writeBits: n must be 0..64")
	}
	remaining := n
	for remaining > 0 {
		bits := 8 - w.offset
		if bits > remaining {
			bits = remaining
		}
		// Core: m_buffer |= (data << (64 - nbits)) >> (64 - 8 + m_offset)
		// The `data << (64 - remaining)` puts the next bit we want to
		// consume into bit 63 of a uint64, then we shift right by
		// `64 - 8 + offset` to land it at bit `7 - offset` of buffer.
		var shifted uint64
		if remaining == 64 {
			// data << 0 — preserve all 64 bits intact (no shift overflow).
			shifted = v
		} else {
			shifted = v << (64 - remaining)
		}
		shifted >>= 64 - 8 + w.offset
		w.buffer |= uint8(shifted)
		w.offset += bits
		remaining -= bits
		if w.offset == 8 {
			w.bytes = append(w.bytes, w.buffer)
			w.buffer = 0
			w.offset = 0
		}
	}
}

// flush writes any remaining bits, padding the final byte with zeros to
// the next byte boundary (per BIP-158 — the unused low bits are 0).
//
// Core reference (bitcoin-core/src/streams.h:349-357): same shape.
func (w *bitStreamWriter) flush() {
	if w.offset == 0 {
		return
	}
	w.bytes = append(w.bytes, w.buffer)
	w.buffer = 0
	w.offset = 0
}

// golombRiceEncode encodes a value using Golomb-Rice coding.
func golombRiceEncode(w *bitStreamWriter, p uint, value uint64) {
	// Quotient and remainder
	q := value >> p
	r := value & ((1 << p) - 1)

	// Write q ones followed by a zero.
	//
	// Mirrors bitcoin-core/src/util/golombrice.h GolombRiceEncode:
	//
	//   while (q > 0) {
	//       int n = std::min<uint64_t>(q, 64);
	//       bitwriter.Write(
	//         std::bitset<64>(~uint64_t(0) << (64 - n)).to_ullong(), n);
	//       q -= n;
	//   }
	//   bitwriter.Write(0, 1);
	//   bitwriter.Write(r, p);
	//
	// Core's `bitset<64>(~0ULL << (64-n)).to_ullong()` produces a value
	// whose top n bits are 1 and bottom 64-n are 0, then BitStreamWriter
	// pulls "the n least-significant bits" — but with `to_ullong` the
	// high bits move down. The net effect is "n ones in the low n bits"
	// which is exactly `(1<<n)-1` for n<64, and `0xFFFFFFFFFFFFFFFF` for
	// n==64. We split the n==64 case explicitly so this code is correct
	// under Go's defined-but-tricky `1 << 64 == 0` shift semantics.
	for q > 0 {
		count := q
		if count > 64 {
			count = 64
		}
		var ones uint64
		if count == 64 {
			ones = ^uint64(0)
		} else {
			ones = (uint64(1) << count) - 1
		}
		w.writeBits(ones, uint(count))
		q -= count
	}
	w.writeBits(0, 1)

	// Write r in p bits
	w.writeBits(r, p)
}

// BlockFilterState stores the state of the block filter index.
//
// On-disk layout (current = FormatVersion 1, FIX-83 / W122):
//
//	1 byte   FormatVersion (== BlockFilterIndexFormatVersion)
//	4 bytes  BestHeight (int32 LE)
//	32 bytes BestHash (LE wire.Hash256)
//	32 bytes PrevFilterHeader (LE wire.Hash256)
//
// Pre-FIX-83 layout had no version byte (was 68 bytes total). Init()
// detects that case by length and forces a rebuild from genesis.
type BlockFilterState struct {
	FormatVersion    uint8
	BestHeight       int32
	BestHash         wire.Hash256
	PrevFilterHeader wire.Hash256
}

// Serialize writes the state to bytes.
func (s *BlockFilterState) Serialize() []byte {
	buf := new(bytes.Buffer)
	// FIX-83 / W122: emit FormatVersion byte first so future migrations
	// can detect obsolete on-disk filter encodings cleanly.
	if s.FormatVersion == 0 {
		s.FormatVersion = BlockFilterIndexFormatVersion
	}
	buf.WriteByte(s.FormatVersion)
	wire.WriteInt32LE(buf, s.BestHeight)
	s.BestHash.Serialize(buf)
	s.PrevFilterHeader.Serialize(buf)
	return buf.Bytes()
}

// DeserializeBlockFilterState reads a state from bytes.
func DeserializeBlockFilterState(data []byte) (*BlockFilterState, error) {
	if len(data) < 69 { // 1 + 4 + 32 + 32
		// Either truncated or pre-FIX-83 layout (68 bytes, no version).
		// Caller (Init) treats this as obsolete and triggers a rebuild.
		return nil, errors.New("block filter state data too short")
	}

	r := bytes.NewReader(data)
	s := &BlockFilterState{}

	ver, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	s.FormatVersion = ver

	s.BestHeight, err = wire.ReadInt32LE(r)
	if err != nil {
		return nil, err
	}

	if err := s.BestHash.Deserialize(r); err != nil {
		return nil, err
	}

	if err := s.PrevFilterHeader.Deserialize(r); err != nil {
		return nil, err
	}

	return s, nil
}

// MatchFilter checks if any of the given scripts match the filter.
func (idx *BlockFilterIndex) MatchFilter(height int32, scripts [][]byte) (bool, error) {
	filterData, err := idx.GetFilter(height)
	if err != nil {
		return false, err
	}

	if len(filterData.Filter) == 0 {
		return false, nil
	}

	// Decode filter and check for matches
	return matchGCS(filterData.Filter, filterData.BlockHash, scripts)
}

// matchGCS checks if any element in scripts matches the GCS filter.
func matchGCS(filter []byte, blockHash wire.Hash256, scripts [][]byte) (bool, error) {
	if len(filter) == 0 || len(scripts) == 0 {
		return false, nil
	}

	r := bytes.NewReader(filter)

	// Read element count
	N, err := wire.ReadCompactSize(r)
	if err != nil {
		return false, err
	}

	if N == 0 {
		return false, nil
	}

	// Derive SipHash key from block hash
	k0 := binary.LittleEndian.Uint64(blockHash[:8])
	k1 := binary.LittleEndian.Uint64(blockHash[8:16])

	F := N * BasicFilterM

	// Hash query elements and sort
	queryHashes := make([]uint64, len(scripts))
	for i, script := range scripts {
		h := siphash(k0, k1, script)
		queryHashes[i] = fastRange64(h, F)
	}
	sort.Slice(queryHashes, func(i, j int) bool { return queryHashes[i] < queryHashes[j] })

	// Read and decode filter elements
	bitReader := newBitStreamReader(r)
	var filterValue uint64
	queryIdx := 0

	for i := uint64(0); i < N && queryIdx < len(queryHashes); i++ {
		delta, err := golombRiceDecode(&bitReader, BasicFilterP)
		if err != nil {
			return false, err
		}
		filterValue += delta

		// Advance query index past smaller values
		for queryIdx < len(queryHashes) && queryHashes[queryIdx] < filterValue {
			queryIdx++
		}

		// Check for match
		if queryIdx < len(queryHashes) && queryHashes[queryIdx] == filterValue {
			return true, nil
		}
	}

	return false, nil
}

// bitStreamReader reads bits from a byte stream.
//
// Reads MSB-first within each byte, mirroring Bitcoin Core's
// BitStreamReader (bitcoin-core/src/streams.h:260-301). The first bit
// returned from a freshly-pulled byte is bit 7 (the most-significant
// bit). FIX-83 (2026-05-17) replaced the prior LSB-first reader to
// match the corresponding bitStreamWriter rewrite.
type bitStreamReader struct {
	r      *bytes.Reader
	buffer uint8 // current byte being unpacked
	offset uint  // number of bits already returned from `buffer`, 0..8
}

func newBitStreamReader(r *bytes.Reader) bitStreamReader {
	// offset=8 means "no byte buffered yet; read one on next readBits".
	return bitStreamReader{r: r, offset: 8}
}

// readBits reads n bits from the stream, MSB-first within each byte,
// returning them in the low n bits of the result.
//
// Core reference (bitcoin-core/src/streams.h:281-300):
//
//	uint64_t data = 0;
//	while (nbits > 0) {
//	    if (m_offset == 8) { m_istream >> m_buffer; m_offset = 0; }
//	    int bits = std::min(8 - m_offset, nbits);
//	    data <<= bits;
//	    data |= static_cast<uint8_t>(m_buffer << m_offset) >> (8 - bits);
//	    m_offset += bits;
//	    nbits -= bits;
//	}
//	return data;
func (br *bitStreamReader) readBits(n uint) (uint64, error) {
	if n > 64 {
		return 0, errors.New("bitStreamReader.readBits: n must be 0..64")
	}
	var data uint64
	remaining := n
	for remaining > 0 {
		if br.offset == 8 {
			b, err := br.r.ReadByte()
			if err != nil {
				return 0, err
			}
			br.buffer = b
			br.offset = 0
		}
		bits := 8 - br.offset
		if bits > remaining {
			bits = remaining
		}
		data <<= bits
		// `buffer << offset` shifts the already-consumed bits off the
		// top, leaving the next bit at bit 7. Then `>> (8 - bits)`
		// lands those `bits` bits into the low `bits` slots.
		shifted := uint8(br.buffer<<br.offset) >> (8 - bits)
		data |= uint64(shifted)
		br.offset += bits
		remaining -= bits
	}
	return data, nil
}

// golombRiceDecode decodes a Golomb-Rice encoded value.
func golombRiceDecode(br *bitStreamReader, p uint) (uint64, error) {
	// Count leading ones to get quotient
	var q uint64
	for {
		bit, err := br.readBits(1)
		if err != nil {
			return 0, err
		}
		if bit == 0 {
			break
		}
		q++
	}

	// Read p bits for remainder
	r, err := br.readBits(p)
	if err != nil {
		return 0, err
	}

	return (q << p) | r, nil
}

// Ensure unused import for crypto is used
var _ = crypto.DoubleSHA256
