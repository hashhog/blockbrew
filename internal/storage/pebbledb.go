package storage

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
)

// pebbleLockFilename is the name pebble uses for its directory lockfile.
// See cockroachdb/pebble internal/base/filenames.go ("LOCK").
const pebbleLockFilename = "LOCK"

// removeStalePebbleLock detects and removes a stale pebble LOCK file left
// behind by a SIGKILL/OOM/crash. The strategy:
//
//  1. If <path>/LOCK does not exist, do nothing.
//  2. Open the LOCK file and attempt a non-blocking exclusive flock on it.
//     If the flock SUCCEEDS, no live process holds the lock — pebble's own
//     Open() would also acquire it, so the file is safe to remove. We unlock
//     and remove it so the subsequent pebble.Open() starts clean.
//  3. If the flock FAILS with EWOULDBLOCK/EAGAIN, another process (presumably
//     another blockbrew) is holding the DB. Return an error so startup aborts
//     loudly — never delete a held lock, that would corrupt the DB.
//
// Any other error (cannot open file, etc.) is returned as-is and pebble.Open()
// will surface it. We deliberately do NOT try to read a PID from the file:
// pebble's LOCK is a zero-byte flock'd file, not a PID file.
func removeStalePebbleLock(path string) error {
	lockPath := filepath.Join(path, pebbleLockFilename)

	info, err := os.Stat(lockPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat pebble lock %q: %w", lockPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("pebble lock path %q is a directory", lockPath)
	}

	f, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open pebble lock %q: %w", lockPath, err)
	}

	// Non-blocking exclusive flock probe. If this succeeds the lock was
	// not actually held — i.e. it is stale.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("pebble LOCK at %q is held by another live process; refusing to start", lockPath)
		}
		return fmt.Errorf("flock pebble lock %q: %w", lockPath, err)
	}

	// We hold the lock. Release before unlinking so we don't leave a dangling
	// flock entry in the kernel (it would be cleaned up on close anyway).
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		f.Close()
		return fmt.Errorf("unlock pebble lock %q: %w", lockPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close pebble lock %q: %w", lockPath, err)
	}

	log.Printf("storage: stale pebble lockfile detected at %q, removing", lockPath)
	if err := os.Remove(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale pebble lock %q: %w", lockPath, err)
	}
	return nil
}

// PebbleDB wraps a Pebble database to implement the DB interface.
type PebbleDB struct {
	db    *pebble.DB
	cache *pebble.Cache
}

// PebbleDBConfig contains Pebble database configuration options.
type PebbleDBConfig struct {
	// BlockCacheSize is the size of the block cache in bytes.
	// Default is 256MB. Larger values improve read performance.
	BlockCacheSize int64

	// MemTableSize is the size of each memtable in bytes.
	// Default is 64MB. Larger values reduce write amplification.
	MemTableSize int

	// MaxOpenFiles limits the number of open sstable file handles.
	// Default is 1000.
	MaxOpenFiles int

	// Sync controls whether writes are synchronous.
	// Default is true for durability.
	Sync bool
}

// DefaultPebbleDBConfig returns the default configuration optimized for Bitcoin workloads.
func DefaultPebbleDBConfig() PebbleDBConfig {
	return PebbleDBConfig{
		BlockCacheSize: 512 * 1024 * 1024, // 512MB block cache
		MemTableSize:   128 * 1024 * 1024, // 128MB memtable — reduces L0 write stalls
		MaxOpenFiles:   2000,
		Sync:           true,
	}
}

// NewPebbleDB opens or creates a Pebble database at the given path.
func NewPebbleDB(path string) (*PebbleDB, error) {
	return NewPebbleDBWithConfig(path, DefaultPebbleDBConfig())
}

// NewPebbleDBWithConfig opens or creates a Pebble database with custom configuration.
func NewPebbleDBWithConfig(path string, cfg PebbleDBConfig) (*PebbleDB, error) {
	// Best-effort cleanup of a stale LOCK file left by a SIGKILL/OOM/crash.
	// Safe: only removes the file if a non-blocking flock probe succeeds,
	// proving no live process is holding it. If another blockbrew is running,
	// this returns an error and we abort startup before pebble.Open() runs.
	// Pre-existing dir is required; if path doesn't exist yet pebble.Open()
	// will create it and there is no LOCK to clean up.
	if _, err := os.Stat(path); err == nil {
		if cleanupErr := removeStalePebbleLock(path); cleanupErr != nil {
			return nil, cleanupErr
		}
	}

	// Create block cache (shared across all SSTs)
	cache := pebble.NewCache(cfg.BlockCacheSize)

	// Configure level options with compression and bloom filters
	levelOpts := make([]pebble.LevelOptions, 7)
	for i := range levelOpts {
		levelOpts[i] = pebble.LevelOptions{
			Compression:    pebble.ZstdCompression,
			TargetFileSize: 64 * 1024 * 1024, // 64MB target file size
			FilterPolicy:   bloom.FilterPolicy(10), // Bloom filter with ~1% false positive rate
		}
	}

	opts := &pebble.Options{
		Cache:                       cache,
		MemTableSize:                uint64(cfg.MemTableSize),
		MemTableStopWritesThreshold: 4, // Allow 4 memtables before stalling
		Levels:                      levelOpts,
		MaxOpenFiles:                cfg.MaxOpenFiles,
		WALBytesPerSync:             1024 * 1024, // Sync WAL every 1MB

		// L0 compaction settings — relaxed for IBD write throughput.
		// Default of 2 triggers compaction too eagerly during bulk writes.
		L0CompactionThreshold: 4,  // Start compaction when L0 has 4 files
		L0StopWritesThreshold: 12, // Stop writes when L0 has 12 files
	}

	db, err := pebble.Open(path, opts)
	if err != nil {
		cache.Unref()
		return nil, fmt.Errorf("pebble open failed: %w", err)
	}

	return &PebbleDB{db: db, cache: cache}, nil
}

// Get retrieves a value by key. Returns nil, nil if key does not exist.
func (p *PebbleDB) Get(key []byte) ([]byte, error) {
	val, closer, err := p.db.Get(key)
	if err == pebble.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	// Copy value since it's only valid until closer.Close()
	result := make([]byte, len(val))
	copy(result, val)
	return result, nil
}

// Put stores a key-value pair.
// Uses NoSync by default — durable writes happen via batch Flush with Sync.
// During IBD, crash recovery replays from the last flushed chain-state
// checkpoint, so per-key durability is unnecessary.
func (p *PebbleDB) Put(key, value []byte) error {
	return p.db.Set(key, value, pebble.NoSync)
}

// Delete removes a key.
func (p *PebbleDB) Delete(key []byte) error {
	return p.db.Delete(key, pebble.NoSync)
}

// Has returns true if the key exists.
func (p *PebbleDB) Has(key []byte) (bool, error) {
	_, closer, err := p.db.Get(key)
	if err == pebble.ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	closer.Close()
	return true, nil
}

// NewBatch creates a new write batch for atomic operations.
func (p *PebbleDB) NewBatch() Batch {
	return &pebbleBatch{
		db:    p.db,
		batch: p.db.NewBatch(),
	}
}

// NewBatchNoSync creates a batch that skips fsync on commit.
// Use during IBD where crash recovery is handled by replaying from a
// persisted chain-state checkpoint.
func (p *PebbleDB) NewBatchNoSync() Batch {
	return &pebbleBatch{
		db:     p.db,
		batch:  p.db.NewBatch(),
		noSync: true,
	}
}

// NewIterator creates an iterator over a key range.
// If prefix is non-nil, iterates over keys with that prefix.
func (p *PebbleDB) NewIterator(prefix []byte) Iterator {
	opts := &pebble.IterOptions{}

	if prefix != nil {
		opts.LowerBound = prefix
		opts.UpperBound = prefixUpperBound(prefix)
	}

	iter, err := p.db.NewIter(opts)
	if err != nil {
		// Return an error iterator
		return &pebbleIterator{err: err}
	}

	return &pebbleIterator{
		iter:   iter,
		prefix: prefix,
		first:  true,
	}
}

// Close closes the database and releases resources.
func (p *PebbleDB) Close() error {
	err := p.db.Close()
	if p.cache != nil {
		p.cache.Unref()
	}
	return err
}

// prefixUpperBound computes the upper bound for prefix iteration.
// It increments the last byte of the prefix, handling overflow.
func prefixUpperBound(prefix []byte) []byte {
	if len(prefix) == 0 {
		return nil
	}

	upper := make([]byte, len(prefix))
	copy(upper, prefix)

	for i := len(upper) - 1; i >= 0; i-- {
		upper[i]++
		if upper[i] != 0 {
			return upper
		}
	}
	// prefix was all 0xFF, no upper bound possible
	return nil
}

// pebbleBatch wraps a Pebble batch.
type pebbleBatch struct {
	db     *pebble.DB
	batch  *pebble.Batch
	noSync bool // Skip fsync on commit (for IBD performance)
}

// Put adds a write operation to the batch.
func (b *pebbleBatch) Put(key, value []byte) {
	b.batch.Set(key, value, nil)
}

// Delete adds a delete operation to the batch.
func (b *pebbleBatch) Delete(key []byte) {
	b.batch.Delete(key, nil)
}

// Write atomically applies all operations in the batch.
func (b *pebbleBatch) Write() error {
	if b.noSync {
		return b.batch.Commit(pebble.NoSync)
	}
	return b.batch.Commit(pebble.Sync)
}

// Reset clears the batch for reuse.
func (b *pebbleBatch) Reset() {
	b.batch.Reset()
}

// Len returns the number of operations in the batch.
func (b *pebbleBatch) Len() int {
	return int(b.batch.Count())
}

// pebbleIterator wraps a Pebble iterator.
type pebbleIterator struct {
	iter   *pebble.Iterator
	prefix []byte
	first  bool
	err    error
}

// Next advances the iterator. Returns false when exhausted.
func (it *pebbleIterator) Next() bool {
	if it.iter == nil {
		return false
	}

	if it.first {
		it.first = false
		// Position at first key
		if it.prefix != nil {
			return it.iter.SeekGE(it.prefix)
		}
		return it.iter.First()
	}

	return it.iter.Next()
}

// Key returns the current key.
func (it *pebbleIterator) Key() []byte {
	if it.iter == nil || !it.iter.Valid() {
		return nil
	}
	// Copy the key since it's only valid until the next iterator operation
	key := it.iter.Key()
	result := make([]byte, len(key))
	copy(result, key)
	return result
}

// Value returns the current value.
func (it *pebbleIterator) Value() []byte {
	if it.iter == nil || !it.iter.Valid() {
		return nil
	}
	// Copy the value since it's only valid until the next iterator operation
	val, err := it.iter.ValueAndErr()
	if err != nil {
		it.err = err
		return nil
	}
	result := make([]byte, len(val))
	copy(result, val)
	return result
}

// Release releases the iterator resources.
func (it *pebbleIterator) Release() {
	if it.iter != nil {
		it.iter.Close()
		it.iter = nil
	}
}

// Error returns any accumulated error.
func (it *pebbleIterator) Error() error {
	if it.err != nil {
		return it.err
	}
	if it.iter != nil {
		return it.iter.Error()
	}
	return nil
}
