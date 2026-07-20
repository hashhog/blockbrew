package storage

// DB is the interface for a key-value database backend.
type DB interface {
	// Get retrieves a value by key. Returns nil, nil if key does not exist.
	Get(key []byte) ([]byte, error)

	// Put stores a key-value pair.
	Put(key, value []byte) error

	// Delete removes a key.
	Delete(key []byte) error

	// Has returns true if the key exists.
	Has(key []byte) (bool, error)

	// NewBatch creates a new write batch for atomic operations.
	NewBatch() Batch

	// NewIndexedBatch creates a write batch whose Get() reflects the batch's
	// own pending (uncommitted) writes layered over the committed DB state.
	// A plain NewBatch() is write-only and its Get() (where defined) sees only
	// the DB; an indexed batch is required when a reader needs to observe
	// writes staged earlier in the SAME batch before Write() lands them. Used
	// by the multi-block reorg path (ChainManager.ReorgTo): blocks connected
	// during a reorg stage their undo data into the shared reorg batch, and the
	// coinstatsindex connect hook must read that just-staged undo to subtract
	// spent coins from the running MuHash — see chaindb.go ReadBlockUndoFromBatch.
	NewIndexedBatch() Batch

	// NewIterator creates an iterator over a key range.
	// If prefix is non-nil, iterates over keys with that prefix.
	NewIterator(prefix []byte) Iterator

	// Close closes the database.
	Close() error

	// Flush durably persists buffered writes (the memtable) to disk. On the
	// pebble backend this issues a synchronous DB.Flush so the chainstate is
	// written to an sstable and fsync'd; the flushchainstate RPC calls it before
	// a graceful stop so pebble.Close() (and thus the SIGKILL-fallback window)
	// has less to write. No-op on in-memory backends.
	Flush() error
}

// Batch is an atomic write batch.
type Batch interface {
	Put(key, value []byte)
	Delete(key []byte)
	Write() error
	Reset()
	Len() int

	// Get reads a key, reflecting this batch's own pending writes/deletes
	// layered over the committed DB state when the batch is indexed (see
	// DB.NewIndexedBatch). For a plain (write-only) batch, Get falls through
	// to the committed DB and does NOT observe the batch's pending writes.
	// Returns (nil, nil) when the key is absent (or deleted in this batch).
	Get(key []byte) ([]byte, error)
}

// Iterator iterates over key-value pairs.
type Iterator interface {
	// Next advances the iterator. Returns false when exhausted.
	Next() bool
	// Key returns the current key.
	Key() []byte
	// Value returns the current value.
	Value() []byte
	// Release releases the iterator resources.
	Release()
	// Error returns any accumulated error.
	Error() error
}
