package storage

import (
	"fmt"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
)

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
		BlockCacheSize: 256 * 1024 * 1024, // 256MB block cache
		MemTableSize:   64 * 1024 * 1024,  // 64MB memtable
		MaxOpenFiles:   1000,
		Sync:           true,
	}
}

// NewPebbleDB opens or creates a Pebble database at the given path.
func NewPebbleDB(path string) (*PebbleDB, error) {
	return NewPebbleDBWithConfig(path, DefaultPebbleDBConfig())
}

// NewPebbleDBWithConfig opens or creates a Pebble database with custom configuration.
func NewPebbleDBWithConfig(path string, cfg PebbleDBConfig) (*PebbleDB, error) {
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

		// L0 compaction settings
		L0CompactionThreshold: 2, // Start compaction when L0 has 2 files
		L0StopWritesThreshold: 8, // Stop writes when L0 has 8 files
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
func (p *PebbleDB) Put(key, value []byte) error {
	return p.db.Set(key, value, pebble.Sync)
}

// Delete removes a key.
func (p *PebbleDB) Delete(key []byte) error {
	return p.db.Delete(key, pebble.Sync)
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
	db    *pebble.DB
	batch *pebble.Batch
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
