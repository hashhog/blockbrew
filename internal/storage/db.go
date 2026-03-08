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

	// NewIterator creates an iterator over a key range.
	// If prefix is non-nil, iterates over keys with that prefix.
	NewIterator(prefix []byte) Iterator

	// Close closes the database.
	Close() error
}

// Batch is an atomic write batch.
type Batch interface {
	Put(key, value []byte)
	Delete(key []byte)
	Write() error
	Reset()
	Len() int
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
