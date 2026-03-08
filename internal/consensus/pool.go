package consensus

import (
	"bytes"
	"sync"
)

// Buffer pools for reducing GC pressure in hot paths.
// These are used for serialization, hashing, and other frequently-allocated buffers.

// bufferPool provides reusable bytes.Buffer instances.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// GetBuffer returns a buffer from the pool.
// The buffer is reset and ready for use.
func GetBuffer() *bytes.Buffer {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// PutBuffer returns a buffer to the pool.
// Buffers larger than 1MB are discarded to prevent memory bloat.
func PutBuffer(buf *bytes.Buffer) {
	if buf == nil {
		return
	}
	// Discard oversized buffers to avoid holding onto large allocations
	if buf.Cap() > 1024*1024 {
		return
	}
	bufferPool.Put(buf)
}

// hash256Pool provides reusable [32]byte arrays for hash results.
var hash256Pool = sync.Pool{
	New: func() interface{} {
		return new([32]byte)
	},
}

// GetHash256 returns a hash array from the pool.
func GetHash256() *[32]byte {
	return hash256Pool.Get().(*[32]byte)
}

// PutHash256 returns a hash array to the pool.
func PutHash256(h *[32]byte) {
	if h == nil {
		return
	}
	hash256Pool.Put(h)
}

// byteSlicePool provides reusable byte slices of common sizes.
// Different pools for different size classes to reduce fragmentation.

var slice32Pool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32)
		return &b
	},
}

var slice64Pool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 64)
		return &b
	},
}

var slice256Pool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 256)
		return &b
	},
}

// GetSlice32 returns a 32-byte slice from the pool.
func GetSlice32() []byte {
	return *slice32Pool.Get().(*[]byte)
}

// PutSlice32 returns a 32-byte slice to the pool.
func PutSlice32(b []byte) {
	if len(b) != 32 {
		return
	}
	slice32Pool.Put(&b)
}

// GetSlice64 returns a 64-byte slice from the pool.
func GetSlice64() []byte {
	return *slice64Pool.Get().(*[]byte)
}

// PutSlice64 returns a 64-byte slice to the pool.
func PutSlice64(b []byte) {
	if len(b) != 64 {
		return
	}
	slice64Pool.Put(&b)
}

// GetSlice256 returns a 256-byte slice from the pool.
func GetSlice256() []byte {
	return *slice256Pool.Get().(*[]byte)
}

// PutSlice256 returns a 256-byte slice to the pool.
func PutSlice256(b []byte) {
	if len(b) != 256 {
		return
	}
	slice256Pool.Put(&b)
}

// txHashCachePool provides reusable maps for transaction hash caching.
var txHashCachePool = sync.Pool{
	New: func() interface{} {
		return make(map[int][32]byte, 16)
	},
}

// GetTxHashCache returns a transaction hash cache map from the pool.
func GetTxHashCache() map[int][32]byte {
	m := txHashCachePool.Get().(map[int][32]byte)
	// Clear the map before returning
	for k := range m {
		delete(m, k)
	}
	return m
}

// PutTxHashCache returns a transaction hash cache map to the pool.
func PutTxHashCache(m map[int][32]byte) {
	if m == nil {
		return
	}
	// Don't pool very large maps
	if len(m) > 1000 {
		return
	}
	txHashCachePool.Put(m)
}
