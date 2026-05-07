package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	// Key: "f" + height (4 bytes big-endian)
	BlockFilterPrefix = []byte("f")

	// BlockFilterStateKey stores the index state.
	BlockFilterStateKey = []byte("blockfilter_state")
)

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

// Init initializes the blockfilterindex by loading state from the database.
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
		return err
	}
	idx.bestHeight = state.BestHeight
	idx.bestHash = state.BestHash
	idx.prevFilterHeader = state.PrevFilterHeader
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

	// State entry pointing at the new tip.
	state := &BlockFilterState{
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
	// pre-disconnect parent.
	state := &BlockFilterState{
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
type bitStreamWriter struct {
	bytes     []byte
	accumBits uint64
	numBits   uint
}

// writeBits writes the lowest n bits of v to the stream.
func (w *bitStreamWriter) writeBits(v uint64, n uint) {
	w.accumBits |= v << w.numBits
	w.numBits += n

	for w.numBits >= 8 {
		w.bytes = append(w.bytes, byte(w.accumBits))
		w.accumBits >>= 8
		w.numBits -= 8
	}
}

// flush writes any remaining bits.
func (w *bitStreamWriter) flush() {
	if w.numBits > 0 {
		w.bytes = append(w.bytes, byte(w.accumBits))
	}
}

// golombRiceEncode encodes a value using Golomb-Rice coding.
func golombRiceEncode(w *bitStreamWriter, p uint, value uint64) {
	// Quotient and remainder
	q := value >> p
	r := value & ((1 << p) - 1)

	// Write q ones followed by a zero
	for q > 0 {
		count := q
		if count > 64 {
			count = 64
		}
		w.writeBits((1<<count)-1, uint(count))
		q -= count
	}
	w.writeBits(0, 1)

	// Write r in p bits
	w.writeBits(r, p)
}

// BlockFilterState stores the state of the block filter index.
type BlockFilterState struct {
	BestHeight       int32
	BestHash         wire.Hash256
	PrevFilterHeader wire.Hash256
}

// Serialize writes the state to bytes.
func (s *BlockFilterState) Serialize() []byte {
	buf := new(bytes.Buffer)
	wire.WriteInt32LE(buf, s.BestHeight)
	s.BestHash.Serialize(buf)
	s.PrevFilterHeader.Serialize(buf)
	return buf.Bytes()
}

// DeserializeBlockFilterState reads a state from bytes.
func DeserializeBlockFilterState(data []byte) (*BlockFilterState, error) {
	if len(data) < 68 { // 4 + 32 + 32
		return nil, errors.New("block filter state data too short")
	}

	r := bytes.NewReader(data)
	s := &BlockFilterState{}

	var err error
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
type bitStreamReader struct {
	r         *bytes.Reader
	accumBits uint64
	numBits   uint
}

func newBitStreamReader(r *bytes.Reader) bitStreamReader {
	return bitStreamReader{r: r}
}

// readBits reads n bits from the stream.
func (br *bitStreamReader) readBits(n uint) (uint64, error) {
	for br.numBits < n {
		b, err := br.r.ReadByte()
		if err != nil {
			return 0, err
		}
		br.accumBits |= uint64(b) << br.numBits
		br.numBits += 8
	}

	val := br.accumBits & ((1 << n) - 1)
	br.accumBits >>= n
	br.numBits -= n
	return val, nil
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
