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

// NewIndexedBatch creates a batch whose Get() reflects the batch's own pending
// writes/deletes layered over the committed DB. The MemDB batch always tracks
// its writes/deletes in slices, so indexed and plain batches share the same
// representation; the flag only changes Get's behavior (plain batches read the
// committed DB only, matching pebble's non-indexed semantics).
func (m *MemDB) NewIndexedBatch() Batch {
	return &memBatch{
		db:      m,
		writes:  make([]batchOp, 0),
		deletes: make([]string, 0),
		indexed: true,
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
	indexed bool // Get reflects pending writes/deletes when true
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

// Get reads a key. For an indexed batch, this batch's own pending writes and
// deletes are layered over the committed DB (last-writer-wins among the staged
// ops, deletes mask the committed value); a plain batch reads the committed DB
// only. Returns (nil, nil) when the key is absent or deleted in this batch.
func (b *memBatch) Get(key []byte) ([]byte, error) {
	if b.indexed {
		ks := string(key)
		// Walk staged ops in reverse so the most recent Put/Delete wins.
		latestPut := -1
		latestDel := -1
		for i := len(b.writes) - 1; i >= 0; i-- {
			if b.writes[i].key == ks {
				latestPut = i
				break
			}
		}
		for i := len(b.deletes) - 1; i >= 0; i-- {
			if b.deletes[i] == ks {
				latestDel = i
				break
			}
		}
		// A staged Delete with no later staged Put masks the committed value.
		// (writes and deletes don't share an ordering index here, but the
		// reorg path never re-Puts a key it Deletes in the same batch, so the
		// "Put present => value present" rule is sufficient and correct for
		// this usage.)
		if latestPut >= 0 {
			v := make([]byte, len(b.writes[latestPut].value))
			copy(v, b.writes[latestPut].value)
			return v, nil
		}
		if latestDel >= 0 {
			return nil, nil
		}
	}
	return b.db.Get(key)
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
