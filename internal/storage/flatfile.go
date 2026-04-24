package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Flat file storage constants matching Bitcoin Core.
const (
	// MaxBlockFileSize is the maximum size of a block data file (128 MiB).
	MaxBlockFileSize uint32 = 128 << 20

	// StorageHeaderSize is the size of the header before each block (magic + size).
	StorageHeaderSize = 8

	// BlockFilePrefix is the prefix for block data files.
	BlockFilePrefix = "blk"

	// UndoFilePrefix is the prefix for undo data files.
	UndoFilePrefix = "rev"
)

// FlatFilePos identifies a location in the flat file storage.
type FlatFilePos struct {
	FileNum int32  // File number (blk00000.dat = 0)
	Pos     uint32 // Byte offset within the file (after magic+size header)
}

// IsNull returns true if this is an invalid/unset position.
func (p FlatFilePos) IsNull() bool {
	return p.FileNum < 0
}

// String returns a human-readable representation.
func (p FlatFilePos) String() string {
	return fmt.Sprintf("FlatFilePos(file=%d, pos=%d)", p.FileNum, p.Pos)
}

// Serialize writes the position to a buffer for storage.
func (p *FlatFilePos) Serialize(w io.Writer) error {
	if err := wire.WriteInt32LE(w, p.FileNum); err != nil {
		return err
	}
	return wire.WriteUint32LE(w, p.Pos)
}

// Deserialize reads the position from a buffer.
func (p *FlatFilePos) Deserialize(r io.Reader) error {
	var err error
	p.FileNum, err = wire.ReadInt32LE(r)
	if err != nil {
		return err
	}
	p.Pos, err = wire.ReadUint32LE(r)
	return err
}

// BlockFileInfo tracks metadata about a block file.
type BlockFileInfo struct {
	NumBlocks    uint32 // Number of blocks stored in file
	Size         uint32 // Number of used bytes in block file
	UndoSize     uint32 // Number of used bytes in undo file
	HeightFirst  uint32 // Lowest height of block in file
	HeightLast   uint32 // Highest height of block in file
	TimeFirst    uint64 // Earliest time of block in file
	TimeLast     uint64 // Latest time of block in file
}

// AddBlock updates file info when a block is added.
func (fi *BlockFileInfo) AddBlock(height uint32, blockTime uint64) {
	if fi.NumBlocks == 0 || fi.HeightFirst > height {
		fi.HeightFirst = height
	}
	if fi.NumBlocks == 0 || fi.TimeFirst > blockTime {
		fi.TimeFirst = blockTime
	}
	fi.NumBlocks++
	if height > fi.HeightLast {
		fi.HeightLast = height
	}
	if blockTime > fi.TimeLast {
		fi.TimeLast = blockTime
	}
}

// Serialize writes the file info for storage.
func (fi *BlockFileInfo) Serialize(w io.Writer) error {
	if err := wire.WriteCompactSize(w, uint64(fi.NumBlocks)); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, uint64(fi.Size)); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, uint64(fi.UndoSize)); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, uint64(fi.HeightFirst)); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, uint64(fi.HeightLast)); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, fi.TimeFirst); err != nil {
		return err
	}
	return wire.WriteCompactSize(w, fi.TimeLast)
}

// DeserializeBlockFileInfo reads file info from storage.
func DeserializeBlockFileInfo(r io.Reader) (*BlockFileInfo, error) {
	fi := &BlockFileInfo{}
	var err error

	// All fields use ReadCompactSizeUnchecked: block-file Size / UndoSize routinely
	// exceed MaxCompactSize (32 MiB) since blk*.dat files cap at 128 MiB and undo
	// files are uncapped.  HeightFirst/HeightLast are uint32 heights (~946k today,
	// but unbounded long-term) and timestamps are Unix epoch seconds (already well
	// past the 32-bit second cutoff).  Gating these with ReadCompactSize made
	// blockbrew unable to restart after any block file exceeded 32 MiB — a latent
	// W87 regression masked by blockbrew not being restarted post-flatfile ship.
	var v uint64
	v, err = wire.ReadCompactSizeUnchecked(r)
	if err != nil {
		return nil, err
	}
	fi.NumBlocks = uint32(v)

	v, err = wire.ReadCompactSizeUnchecked(r)
	if err != nil {
		return nil, err
	}
	fi.Size = uint32(v)

	v, err = wire.ReadCompactSizeUnchecked(r)
	if err != nil {
		return nil, err
	}
	fi.UndoSize = uint32(v)

	v, err = wire.ReadCompactSizeUnchecked(r)
	if err != nil {
		return nil, err
	}
	fi.HeightFirst = uint32(v)

	v, err = wire.ReadCompactSizeUnchecked(r)
	if err != nil {
		return nil, err
	}
	fi.HeightLast = uint32(v)

	fi.TimeFirst, err = wire.ReadCompactSizeUnchecked(r)
	if err != nil {
		return nil, err
	}

	fi.TimeLast, err = wire.ReadCompactSizeUnchecked(r)
	if err != nil {
		return nil, err
	}

	return fi, nil
}

// Errors for flat file operations.
var (
	ErrBadMagic       = errors.New("flatfile: bad network magic")
	ErrBlockTooLarge  = errors.New("flatfile: block too large")
	ErrCorruptedData  = errors.New("flatfile: corrupted data")
	ErrDiskFull       = errors.New("flatfile: disk full")
	ErrInvalidPos     = errors.New("flatfile: invalid position")
)

// BlockStore manages flat file block storage with blk*.dat and rev*.dat files.
type BlockStore struct {
	mu             sync.RWMutex
	dataDir        string
	magic          uint32
	maxFileSize    uint32
	currentFileNum int32
	currentPos     uint32
	fileInfo       []BlockFileInfo

	// Index maps block hash to file position (stored in LevelDB via DB interface)
	db DB
}

// NewBlockStore creates a new block store.
func NewBlockStore(dataDir string, magic uint32, db DB) (*BlockStore, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("flatfile: failed to create data dir: %w", err)
	}

	bs := &BlockStore{
		dataDir:        dataDir,
		magic:          magic,
		maxFileSize:    MaxBlockFileSize,
		currentFileNum: 0,
		currentPos:     0,
		fileInfo:       make([]BlockFileInfo, 1),
		db:             db,
	}

	// Try to load existing state
	if err := bs.loadState(); err != nil {
		// If not found, that's fine - we're starting fresh
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}

	return bs, nil
}

// blockFilename returns the filename for a block file.
func (bs *BlockStore) blockFilename(fileNum int32) string {
	return filepath.Join(bs.dataDir, fmt.Sprintf("%s%05d.dat", BlockFilePrefix, fileNum))
}

// undoFilename returns the filename for an undo file.
func (bs *BlockStore) undoFilename(fileNum int32) string {
	return filepath.Join(bs.dataDir, fmt.Sprintf("%s%05d.dat", UndoFilePrefix, fileNum))
}

// WriteBlock writes a serialized block to disk and returns its position.
// The block format is: [magic:4][size:4][block_data:size]
func (bs *BlockStore) WriteBlock(blockData []byte, height uint32, blockTime uint64) (FlatFilePos, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	blockSize := uint32(len(blockData))
	totalSize := StorageHeaderSize + blockSize

	if blockSize > bs.maxFileSize-StorageHeaderSize {
		return FlatFilePos{FileNum: -1}, ErrBlockTooLarge
	}

	// Check if we need to start a new file
	if bs.currentPos+totalSize > bs.maxFileSize {
		// Flush and finalize current file
		if err := bs.flushFile(bs.currentFileNum, true); err != nil {
			return FlatFilePos{FileNum: -1}, err
		}
		bs.currentFileNum++
		bs.currentPos = 0
		// Expand file info slice if needed
		for int32(len(bs.fileInfo)) <= bs.currentFileNum {
			bs.fileInfo = append(bs.fileInfo, BlockFileInfo{})
		}
	}

	// Pre-allocate space in the file
	if err := bs.allocateSpace(bs.currentFileNum, totalSize); err != nil {
		return FlatFilePos{FileNum: -1}, err
	}

	// Open file for writing
	file, err := os.OpenFile(bs.blockFilename(bs.currentFileNum), os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return FlatFilePos{FileNum: -1}, fmt.Errorf("flatfile: open failed: %w", err)
	}
	defer file.Close()

	// Seek to current position
	if _, err := file.Seek(int64(bs.currentPos), io.SeekStart); err != nil {
		return FlatFilePos{FileNum: -1}, fmt.Errorf("flatfile: seek failed: %w", err)
	}

	// Write header: magic (4 bytes LE) + size (4 bytes LE)
	var header [8]byte
	binary.LittleEndian.PutUint32(header[0:4], bs.magic)
	binary.LittleEndian.PutUint32(header[4:8], blockSize)
	if _, err := file.Write(header[:]); err != nil {
		return FlatFilePos{FileNum: -1}, fmt.Errorf("flatfile: write header failed: %w", err)
	}

	// Write block data
	if _, err := file.Write(blockData); err != nil {
		return FlatFilePos{FileNum: -1}, fmt.Errorf("flatfile: write data failed: %w", err)
	}

	// Sync to disk
	if err := file.Sync(); err != nil {
		return FlatFilePos{FileNum: -1}, fmt.Errorf("flatfile: sync failed: %w", err)
	}

	// Record position (points past the header to the block data)
	pos := FlatFilePos{
		FileNum: bs.currentFileNum,
		Pos:     bs.currentPos + StorageHeaderSize,
	}

	// Update file info
	fi := &bs.fileInfo[bs.currentFileNum]
	fi.AddBlock(height, blockTime)
	fi.Size = bs.currentPos + totalSize

	// Advance position
	bs.currentPos += totalSize

	// Save state
	if err := bs.saveState(); err != nil {
		return FlatFilePos{FileNum: -1}, err
	}

	return pos, nil
}

// ReadBlock reads a block from disk given its position.
func (bs *BlockStore) ReadBlock(pos FlatFilePos) ([]byte, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	if pos.IsNull() {
		return nil, ErrInvalidPos
	}

	// Position must be past the header (pointing to data)
	if pos.Pos < StorageHeaderSize {
		return nil, ErrInvalidPos
	}

	// Seek to header position (before block data)
	headerPos := pos.Pos - StorageHeaderSize

	file, err := os.Open(bs.blockFilename(pos.FileNum))
	if err != nil {
		return nil, fmt.Errorf("flatfile: open failed: %w", err)
	}
	defer file.Close()

	if _, err := file.Seek(int64(headerPos), io.SeekStart); err != nil {
		return nil, fmt.Errorf("flatfile: seek failed: %w", err)
	}

	// Read header
	var header [8]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		return nil, fmt.Errorf("flatfile: read header failed: %w", err)
	}

	// Verify magic
	magic := binary.LittleEndian.Uint32(header[0:4])
	if magic != bs.magic {
		return nil, ErrBadMagic
	}

	// Read size
	size := binary.LittleEndian.Uint32(header[4:8])
	if size > bs.maxFileSize {
		return nil, ErrBlockTooLarge
	}

	// Read block data
	data := make([]byte, size)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, fmt.Errorf("flatfile: read data failed: %w", err)
	}

	return data, nil
}

// WriteUndo writes undo data to the rev*.dat file corresponding to a block file.
func (bs *BlockStore) WriteUndo(fileNum int32, undoData []byte) (FlatFilePos, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if fileNum < 0 || int32(len(bs.fileInfo)) <= fileNum {
		return FlatFilePos{FileNum: -1}, ErrInvalidPos
	}

	undoSize := uint32(len(undoData))
	totalSize := StorageHeaderSize + undoSize

	fi := &bs.fileInfo[fileNum]
	pos := FlatFilePos{
		FileNum: fileNum,
		Pos:     fi.UndoSize + StorageHeaderSize,
	}

	// Open undo file for writing
	file, err := os.OpenFile(bs.undoFilename(fileNum), os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return FlatFilePos{FileNum: -1}, fmt.Errorf("flatfile: open undo failed: %w", err)
	}
	defer file.Close()

	// Seek to current undo position
	if _, err := file.Seek(int64(fi.UndoSize), io.SeekStart); err != nil {
		return FlatFilePos{FileNum: -1}, fmt.Errorf("flatfile: seek undo failed: %w", err)
	}

	// Write header: magic (4 bytes LE) + size (4 bytes LE)
	var header [8]byte
	binary.LittleEndian.PutUint32(header[0:4], bs.magic)
	binary.LittleEndian.PutUint32(header[4:8], undoSize)
	if _, err := file.Write(header[:]); err != nil {
		return FlatFilePos{FileNum: -1}, fmt.Errorf("flatfile: write undo header failed: %w", err)
	}

	// Write undo data
	if _, err := file.Write(undoData); err != nil {
		return FlatFilePos{FileNum: -1}, fmt.Errorf("flatfile: write undo data failed: %w", err)
	}

	// Sync to disk
	if err := file.Sync(); err != nil {
		return FlatFilePos{FileNum: -1}, fmt.Errorf("flatfile: sync undo failed: %w", err)
	}

	// Update undo size
	fi.UndoSize += totalSize

	// Save state
	if err := bs.saveState(); err != nil {
		return FlatFilePos{FileNum: -1}, err
	}

	return pos, nil
}

// ReadUndo reads undo data from disk given its position.
func (bs *BlockStore) ReadUndo(pos FlatFilePos) ([]byte, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	if pos.IsNull() {
		return nil, ErrInvalidPos
	}

	if pos.Pos < StorageHeaderSize {
		return nil, ErrInvalidPos
	}

	headerPos := pos.Pos - StorageHeaderSize

	file, err := os.Open(bs.undoFilename(pos.FileNum))
	if err != nil {
		return nil, fmt.Errorf("flatfile: open undo failed: %w", err)
	}
	defer file.Close()

	if _, err := file.Seek(int64(headerPos), io.SeekStart); err != nil {
		return nil, fmt.Errorf("flatfile: seek undo failed: %w", err)
	}

	// Read header
	var header [8]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		return nil, fmt.Errorf("flatfile: read undo header failed: %w", err)
	}

	// Verify magic
	magic := binary.LittleEndian.Uint32(header[0:4])
	if magic != bs.magic {
		return nil, ErrBadMagic
	}

	// Read size
	size := binary.LittleEndian.Uint32(header[4:8])

	// Read undo data
	data := make([]byte, size)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, fmt.Errorf("flatfile: read undo data failed: %w", err)
	}

	return data, nil
}

// allocateSpace pre-allocates space in a file for performance.
func (bs *BlockStore) allocateSpace(fileNum int32, addSize uint32) error {
	filename := bs.blockFilename(fileNum)

	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	currentSize := info.Size()
	neededSize := int64(bs.currentPos + addSize)

	// Pre-allocate in chunks (16 MiB)
	const chunkSize = 16 << 20
	if neededSize > currentSize {
		// Round up to chunk size
		newSize := ((neededSize + chunkSize - 1) / chunkSize) * chunkSize
		if newSize > int64(bs.maxFileSize) {
			newSize = int64(bs.maxFileSize)
		}
		if err := file.Truncate(newSize); err != nil {
			return err
		}
	}

	return nil
}

// flushFile flushes and optionally finalizes a block file.
func (bs *BlockStore) flushFile(fileNum int32, finalize bool) error {
	filename := bs.blockFilename(fileNum)

	file, err := os.OpenFile(filename, os.O_RDWR, 0644)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	// Sync data
	if err := file.Sync(); err != nil {
		return err
	}

	// Truncate to actual used size if finalizing
	if finalize && int32(len(bs.fileInfo)) > fileNum {
		fi := &bs.fileInfo[fileNum]
		if err := file.Truncate(int64(fi.Size)); err != nil {
			return err
		}
	}

	return nil
}

// State persistence keys
var (
	flatFileStateKey     = []byte("F") // Flat file state
	blockFileInfoPrefix  = []byte("f") // Block file info prefix
)

// saveState persists the current state to the database.
func (bs *BlockStore) saveState() error {
	if bs.db == nil {
		return nil
	}

	batch := bs.db.NewBatch()

	// Save current file number and position
	var buf bytes.Buffer
	if err := wire.WriteInt32LE(&buf, bs.currentFileNum); err != nil {
		return err
	}
	if err := wire.WriteUint32LE(&buf, bs.currentPos); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(&buf, uint64(len(bs.fileInfo))); err != nil {
		return err
	}
	batch.Put(flatFileStateKey, buf.Bytes())

	// Save each file info
	for i, fi := range bs.fileInfo {
		key := make([]byte, 1+4)
		key[0] = blockFileInfoPrefix[0]
		binary.BigEndian.PutUint32(key[1:], uint32(i))

		var fiBuf bytes.Buffer
		if err := fi.Serialize(&fiBuf); err != nil {
			return err
		}
		batch.Put(key, fiBuf.Bytes())
	}

	return batch.Write()
}

// loadState loads the persisted state from the database.
func (bs *BlockStore) loadState() error {
	if bs.db == nil {
		return ErrNotFound
	}

	data, err := bs.db.Get(flatFileStateKey)
	if err != nil {
		return err
	}
	if data == nil {
		return ErrNotFound
	}

	r := bytes.NewReader(data)
	bs.currentFileNum, err = wire.ReadInt32LE(r)
	if err != nil {
		return err
	}
	bs.currentPos, err = wire.ReadUint32LE(r)
	if err != nil {
		return err
	}
	numFiles, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}

	// Load file info
	bs.fileInfo = make([]BlockFileInfo, numFiles)
	for i := uint64(0); i < numFiles; i++ {
		key := make([]byte, 1+4)
		key[0] = blockFileInfoPrefix[0]
		binary.BigEndian.PutUint32(key[1:], uint32(i))

		fiData, err := bs.db.Get(key)
		if err != nil {
			return err
		}
		if fiData == nil {
			continue
		}

		fi, err := DeserializeBlockFileInfo(bytes.NewReader(fiData))
		if err != nil {
			return err
		}
		bs.fileInfo[i] = *fi
	}

	return nil
}

// GetFileInfo returns info about a specific block file.
func (bs *BlockStore) GetFileInfo(fileNum int32) *BlockFileInfo {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	if fileNum < 0 || int32(len(bs.fileInfo)) <= fileNum {
		return nil
	}
	fi := bs.fileInfo[fileNum]
	return &fi
}

// CurrentFile returns the current file number being written to.
func (bs *BlockStore) CurrentFile() int32 {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.currentFileNum
}

// Flush syncs all pending data to disk.
func (bs *BlockStore) Flush() error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	for i := int32(0); i <= bs.currentFileNum; i++ {
		if err := bs.flushFile(i, i < bs.currentFileNum); err != nil {
			return err
		}
	}
	return bs.saveState()
}

// Close flushes and closes the block store.
func (bs *BlockStore) Close() error {
	return bs.Flush()
}

// BlockIndex key prefixes for storing block positions.
var (
	// BlockPosPrefix maps block hash -> FlatFilePos for block data.
	// Key: "P" + block_hash (33 bytes)
	BlockPosPrefix = []byte("P")

	// UndoPosPrefix maps block hash -> FlatFilePos for undo data.
	// Key: "p" + block_hash (33 bytes)
	UndoPosPrefix = []byte("p")
)

// MakeBlockPosKey creates a key for storing block position.
func MakeBlockPosKey(hash wire.Hash256) []byte {
	key := make([]byte, 1+32)
	key[0] = BlockPosPrefix[0]
	copy(key[1:], hash[:])
	return key
}

// MakeUndoPosKey creates a key for storing undo position.
func MakeUndoPosKey(hash wire.Hash256) []byte {
	key := make([]byte, 1+32)
	key[0] = UndoPosPrefix[0]
	copy(key[1:], hash[:])
	return key
}

// IndexBlock stores the block position in the index.
func (bs *BlockStore) IndexBlock(hash wire.Hash256, pos FlatFilePos) error {
	if bs.db == nil {
		return nil
	}

	key := MakeBlockPosKey(hash)
	var buf bytes.Buffer
	if err := pos.Serialize(&buf); err != nil {
		return err
	}
	return bs.db.Put(key, buf.Bytes())
}

// IndexUndo stores the undo position in the index.
func (bs *BlockStore) IndexUndo(hash wire.Hash256, pos FlatFilePos) error {
	if bs.db == nil {
		return nil
	}

	key := MakeUndoPosKey(hash)
	var buf bytes.Buffer
	if err := pos.Serialize(&buf); err != nil {
		return err
	}
	return bs.db.Put(key, buf.Bytes())
}

// GetBlockPos retrieves the block position from the index.
func (bs *BlockStore) GetBlockPos(hash wire.Hash256) (FlatFilePos, error) {
	if bs.db == nil {
		return FlatFilePos{FileNum: -1}, ErrNotFound
	}

	key := MakeBlockPosKey(hash)
	data, err := bs.db.Get(key)
	if err != nil {
		return FlatFilePos{FileNum: -1}, err
	}
	if data == nil {
		return FlatFilePos{FileNum: -1}, ErrNotFound
	}

	var pos FlatFilePos
	if err := pos.Deserialize(bytes.NewReader(data)); err != nil {
		return FlatFilePos{FileNum: -1}, err
	}
	return pos, nil
}

// GetUndoPos retrieves the undo position from the index.
func (bs *BlockStore) GetUndoPos(hash wire.Hash256) (FlatFilePos, error) {
	if bs.db == nil {
		return FlatFilePos{FileNum: -1}, ErrNotFound
	}

	key := MakeUndoPosKey(hash)
	data, err := bs.db.Get(key)
	if err != nil {
		return FlatFilePos{FileNum: -1}, err
	}
	if data == nil {
		return FlatFilePos{FileNum: -1}, ErrNotFound
	}

	var pos FlatFilePos
	if err := pos.Deserialize(bytes.NewReader(data)); err != nil {
		return FlatFilePos{FileNum: -1}, err
	}
	return pos, nil
}

// WriteAndIndexBlock writes a block and indexes it by hash. Idempotent:
// if the block is already indexed, returns the existing position without
// re-appending to blk*.dat. Without this guard, duplicate receives
// (pipeline-saturation requeues in sync.go, reorg rediscovery, or a
// restart that dropped the index mid-write before IndexBlock ran) left
// orphaned block copies on disk. A mainnet run under this path reached
// ~3.5× the expected flatfile size before the 2026-04-24 disk-full
// incident forced a wipe.
func (bs *BlockStore) WriteAndIndexBlock(hash wire.Hash256, blockData []byte, height uint32, blockTime uint64) (FlatFilePos, error) {
	if bs.HasBlock(hash) {
		return bs.GetBlockPos(hash)
	}

	pos, err := bs.WriteBlock(blockData, height, blockTime)
	if err != nil {
		return FlatFilePos{FileNum: -1}, err
	}

	if err := bs.IndexBlock(hash, pos); err != nil {
		return FlatFilePos{FileNum: -1}, err
	}

	return pos, nil
}

// WriteAndIndexUndo writes undo data and indexes it by block hash.
// Idempotent for the same reason as WriteAndIndexBlock.
func (bs *BlockStore) WriteAndIndexUndo(hash wire.Hash256, fileNum int32, undoData []byte) (FlatFilePos, error) {
	if bs.HasUndo(hash) {
		return bs.GetUndoPos(hash)
	}

	pos, err := bs.WriteUndo(fileNum, undoData)
	if err != nil {
		return FlatFilePos{FileNum: -1}, err
	}

	if err := bs.IndexUndo(hash, pos); err != nil {
		return FlatFilePos{FileNum: -1}, err
	}

	return pos, nil
}

// ReadBlockByHash reads a block using its hash.
func (bs *BlockStore) ReadBlockByHash(hash wire.Hash256) ([]byte, error) {
	pos, err := bs.GetBlockPos(hash)
	if err != nil {
		return nil, err
	}
	return bs.ReadBlock(pos)
}

// ReadUndoByHash reads undo data using the block hash.
func (bs *BlockStore) ReadUndoByHash(hash wire.Hash256) ([]byte, error) {
	pos, err := bs.GetUndoPos(hash)
	if err != nil {
		return nil, err
	}
	return bs.ReadUndo(pos)
}

// HasBlock returns true if the block is indexed.
func (bs *BlockStore) HasBlock(hash wire.Hash256) bool {
	if bs.db == nil {
		return false
	}
	key := MakeBlockPosKey(hash)
	has, _ := bs.db.Has(key)
	return has
}

// HasUndo returns true if the undo data is indexed.
func (bs *BlockStore) HasUndo(hash wire.Hash256) bool {
	if bs.db == nil {
		return false
	}
	key := MakeUndoPosKey(hash)
	has, _ := bs.db.Has(key)
	return has
}

// DeleteBlockIndex removes a block from the index (but not from disk).
func (bs *BlockStore) DeleteBlockIndex(hash wire.Hash256) error {
	if bs.db == nil {
		return nil
	}
	return bs.db.Delete(MakeBlockPosKey(hash))
}

// DeleteUndoIndex removes undo data from the index (but not from disk).
func (bs *BlockStore) DeleteUndoIndex(hash wire.Hash256) error {
	if bs.db == nil {
		return nil
	}
	return bs.db.Delete(MakeUndoPosKey(hash))
}
