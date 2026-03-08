package storage

import (
	"bytes"
	"sort"
	"sync"
)

// MemDB is an in-memory implementation of the DB interface for testing.
type MemDB struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMemDB creates a new in-memory database.
func NewMemDB() *MemDB {
	return &MemDB{
		data: make(map[string][]byte),
	}
}

// Get retrieves a value by key. Returns nil, nil if key does not exist.
func (m *MemDB) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	val, ok := m.data[string(key)]
	if !ok {
		return nil, nil
	}
	// Return a copy to prevent modification
	result := make([]byte, len(val))
	copy(result, val)
	return result, nil
}

// Put stores a key-value pair.
func (m *MemDB) Put(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store a copy to prevent modification
	k := string(key)
	v := make([]byte, len(value))
	copy(v, value)
	m.data[k] = v
	return nil
}

// Delete removes a key.
func (m *MemDB) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, string(key))
	return nil
}

// Has returns true if the key exists.
func (m *MemDB) Has(key []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.data[string(key)]
	return ok, nil
}

// NewBatch creates a new write batch for atomic operations.
func (m *MemDB) NewBatch() Batch {
	return &memBatch{
		db:      m,
		writes:  make([]batchOp, 0),
		deletes: make([]string, 0),
	}
}

// NewIterator creates an iterator over a key range.
// If prefix is non-nil, iterates over keys with that prefix.
func (m *MemDB) NewIterator(prefix []byte) Iterator {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect matching keys and snapshot values
	var keys []string
	values := make(map[string][]byte)

	for k, v := range m.data {
		if prefix == nil || bytes.HasPrefix([]byte(k), prefix) {
			keys = append(keys, k)
			val := make([]byte, len(v))
			copy(val, v)
			values[k] = val
		}
	}

	// Sort keys for deterministic iteration
	sort.Strings(keys)

	return &memIterator{
		keys:   keys,
		values: values,
		index:  -1, // Start before first element
	}
}

// Close closes the database.
func (m *MemDB) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data = nil
	return nil
}

// batchOp represents a single write operation in a batch.
type batchOp struct {
	key   string
	value []byte
}

// memBatch is an in-memory write batch.
type memBatch struct {
	db      *MemDB
	writes  []batchOp
	deletes []string
}

// Put adds a write operation to the batch.
func (b *memBatch) Put(key, value []byte) {
	// Store a copy
	v := make([]byte, len(value))
	copy(v, value)
	b.writes = append(b.writes, batchOp{key: string(key), value: v})
}

// Delete adds a delete operation to the batch.
func (b *memBatch) Delete(key []byte) {
	b.deletes = append(b.deletes, string(key))
}

// Write atomically applies all operations in the batch.
func (b *memBatch) Write() error {
	b.db.mu.Lock()
	defer b.db.mu.Unlock()

	// Apply writes
	for _, op := range b.writes {
		b.db.data[op.key] = op.value
	}

	// Apply deletes
	for _, k := range b.deletes {
		delete(b.db.data, k)
	}

	return nil
}

// Reset clears the batch for reuse.
func (b *memBatch) Reset() {
	b.writes = b.writes[:0]
	b.deletes = b.deletes[:0]
}

// Len returns the number of operations in the batch.
func (b *memBatch) Len() int {
	return len(b.writes) + len(b.deletes)
}

// memIterator iterates over a snapshot of key-value pairs.
type memIterator struct {
	keys   []string
	values map[string][]byte
	index  int
	err    error
}

// Next advances the iterator. Returns false when exhausted.
func (it *memIterator) Next() bool {
	if it.index >= len(it.keys)-1 {
		return false
	}
	it.index++
	return true
}

// Key returns the current key.
func (it *memIterator) Key() []byte {
	if it.index < 0 || it.index >= len(it.keys) {
		return nil
	}
	return []byte(it.keys[it.index])
}

// Value returns the current value.
func (it *memIterator) Value() []byte {
	if it.index < 0 || it.index >= len(it.keys) {
		return nil
	}
	return it.values[it.keys[it.index]]
}

// Release releases the iterator resources.
func (it *memIterator) Release() {
	it.keys = nil
	it.values = nil
}

// Error returns any accumulated error.
func (it *memIterator) Error() error {
	return it.err
}
