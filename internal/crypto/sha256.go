// Package crypto provides cryptographic primitives for Bitcoin.
// This file implements hardware-accelerated SHA256 with runtime CPU detection.
//
// Go 1.21+ automatically uses SHA-NI (x86_64) or SHA2 extensions (ARM64)
// when available. This module provides additional Bitcoin-specific optimizations:
// - Midstate computation for mining (precompute first 64 bytes of block header)
// - Batch double-SHA256 for merkle tree computation
// - Runtime CPU feature detection for diagnostics

package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"runtime"
	"sync"

	"golang.org/x/sys/cpu"
)

// SHA256Implementation describes the detected SHA256 implementation.
type SHA256Implementation struct {
	// Name is a human-readable name for the implementation.
	Name string
	// HasSHANI is true if SHA-NI (x86_64) or SHA2 (ARM64) hardware is available.
	HasSHANI bool
	// HasAVX2 is true if AVX2 is available (x86_64 only).
	HasAVX2 bool
	// Arch is the CPU architecture.
	Arch string
}

var (
	sha256Impl     SHA256Implementation
	sha256ImplOnce sync.Once
)

// DetectSHA256Implementation detects and returns the SHA256 implementation in use.
// Note: Go's crypto/sha256 automatically selects the best implementation at runtime.
// This function provides diagnostic information about what's available.
func DetectSHA256Implementation() SHA256Implementation {
	sha256ImplOnce.Do(func() {
		sha256Impl.Arch = runtime.GOARCH

		switch runtime.GOARCH {
		case "amd64":
			// We can detect AVX2 and other features, but golang.org/x/sys/cpu
			// doesn't expose SHA-NI detection directly. However, Go's stdlib
			// does use SHA-NI when available. We check the features that Go
			// requires for SHA-NI: AVX && SSE41 && SSSE3 (plus SHA bit from CPUID).
			// Since we can't check SHA bit directly, we report based on AVX2 availability.
			sha256Impl.HasAVX2 = cpu.X86.HasAVX && cpu.X86.HasAVX2 && cpu.X86.HasBMI2
			// SHA-NI is common on Intel Goldmont+ and AMD Zen+.
			// Go 1.21+ uses it automatically. We can't detect it directly from
			// golang.org/x/sys/cpu, so we leave HasSHANI as a best-effort indicator.
			// If the CPU has AVX + SSE41 + SSSE3, it might have SHA-NI too.
			sha256Impl.HasSHANI = cpu.X86.HasAVX && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3

			if sha256Impl.HasSHANI {
				sha256Impl.Name = "sha-ni(possible)"
			} else if sha256Impl.HasAVX2 {
				sha256Impl.Name = "avx2"
			} else {
				sha256Impl.Name = "generic"
			}

		case "arm64":
			// Go's crypto/sha256 uses ARM SHA2 extensions when available
			sha256Impl.HasSHANI = cpu.ARM64.HasSHA2
			sha256Impl.HasAVX2 = false

			if sha256Impl.HasSHANI {
				sha256Impl.Name = "arm-sha2"
			} else {
				sha256Impl.Name = "generic"
			}

		default:
			sha256Impl.Name = "generic"
			sha256Impl.HasSHANI = false
			sha256Impl.HasAVX2 = false
		}
	})

	return sha256Impl
}

// Sum256 computes a single SHA256 hash.
// Uses hardware acceleration when available.
func Sum256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// DoubleSum256 computes SHA256(SHA256(data)), used throughout Bitcoin.
// Uses hardware acceleration when available.
func DoubleSum256(data []byte) [32]byte {
	first := sha256.Sum256(data)
	return sha256.Sum256(first[:])
}

// SHA256Midstate represents a partially computed SHA256 state.
// This is used for mining optimization: the first 64 bytes of a block header
// don't change while iterating nonces, so we precompute the state after
// processing those bytes.
type SHA256Midstate struct {
	state [8]uint32
}

// ComputeMidstate computes the SHA256 midstate for the first 64 bytes of data.
// This is used for mining optimization where the first half of the block header
// is constant while iterating nonces.
//
// The data must be exactly 64 bytes (one SHA256 block).
func ComputeMidstate(data [64]byte) SHA256Midstate {
	// SHA256 initial state (H0-H7)
	h := [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}

	// Process one block
	blockGeneric(&h, data[:])

	return SHA256Midstate{state: h}
}

// FinishHash completes a SHA256 hash given a midstate and the remaining data.
// For Bitcoin mining, this is the second half of the block header (16 bytes of
// merkle root suffix, 4 bytes timestamp, 4 bytes bits, 4 bytes nonce) plus padding.
//
// The data must be exactly 16 bytes (the second part of the 80-byte header,
// after subtracting the 64 bytes used for midstate).
func (m *SHA256Midstate) FinishHash(data [16]byte) [32]byte {
	// Copy state
	h := m.state

	// Build the second block: 16 bytes of data + 1 byte 0x80 + padding + 8 bytes length
	var block [64]byte
	copy(block[:16], data[:])
	block[16] = 0x80
	// Length in bits: 80 bytes * 8 = 640 bits = 0x280
	binary.BigEndian.PutUint64(block[56:], 640)

	// Process second block
	blockGeneric(&h, block[:])

	// Convert state to bytes
	var result [32]byte
	binary.BigEndian.PutUint32(result[0:], h[0])
	binary.BigEndian.PutUint32(result[4:], h[1])
	binary.BigEndian.PutUint32(result[8:], h[2])
	binary.BigEndian.PutUint32(result[12:], h[3])
	binary.BigEndian.PutUint32(result[16:], h[4])
	binary.BigEndian.PutUint32(result[20:], h[5])
	binary.BigEndian.PutUint32(result[24:], h[6])
	binary.BigEndian.PutUint32(result[28:], h[7])

	return result
}

// DoubleHashBlockHeader computes SHA256(SHA256(header)) for an 80-byte block header.
// This is the standard block hash computation in Bitcoin.
func DoubleHashBlockHeader(header [80]byte) [32]byte {
	first := sha256.Sum256(header[:])
	return sha256.Sum256(first[:])
}

// DoubleHashBlockHeaderWithMidstate computes SHA256(SHA256(header)) using a
// precomputed midstate for the first 64 bytes. This is faster when iterating
// nonces since the midstate doesn't need to be recomputed.
func DoubleHashBlockHeaderWithMidstate(midstate SHA256Midstate, headerTail [16]byte) [32]byte {
	first := midstate.FinishHash(headerTail)
	return sha256.Sum256(first[:])
}

// BatchDoubleSum256 computes double SHA256 for multiple 64-byte inputs.
// This is optimized for merkle tree computation where we hash pairs of 32-byte hashes.
// Each input must be exactly 64 bytes.
//
// Returns one 32-byte hash per input.
func BatchDoubleSum256(inputs [][]byte) [][32]byte {
	results := make([][32]byte, len(inputs))
	for i, input := range inputs {
		if len(input) != 64 {
			// Invalid input size, compute anyway but this shouldn't happen
			first := sha256.Sum256(input)
			results[i] = sha256.Sum256(first[:])
			continue
		}
		first := sha256.Sum256(input)
		results[i] = sha256.Sum256(first[:])
	}
	return results
}

// MerklePairHash computes SHA256(SHA256(left || right)) for two 32-byte hashes.
// This is the standard merkle tree hash function in Bitcoin.
func MerklePairHash(left, right [32]byte) [32]byte {
	var combined [64]byte
	copy(combined[:32], left[:])
	copy(combined[32:], right[:])
	first := sha256.Sum256(combined[:])
	return sha256.Sum256(first[:])
}

// SHA256 round constants
var k = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// blockGeneric is a pure-Go implementation of SHA256 block processing.
// This is used for midstate computation where we need direct access to the state.
// For regular hashing, the standard library's hardware-accelerated version is used.
func blockGeneric(h *[8]uint32, data []byte) {
	var w [64]uint32

	// Unpack message into w[0:16]
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(data[i*4:])
	}

	// Extend to w[16:64]
	for i := 16; i < 64; i++ {
		v1 := w[i-2]
		t1 := (v1>>17 | v1<<15) ^ (v1>>19 | v1<<13) ^ (v1 >> 10)
		v2 := w[i-15]
		t2 := (v2>>7 | v2<<25) ^ (v2>>18 | v2<<14) ^ (v2 >> 3)
		w[i] = t1 + w[i-7] + t2 + w[i-16]
	}

	// Initialize working variables
	a, b, c, d, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]

	// Compression function
	for i := 0; i < 64; i++ {
		t1 := hh + ((e>>6 | e<<26) ^ (e>>11 | e<<21) ^ (e>>25 | e<<7)) + ((e & f) ^ (^e & g)) + k[i] + w[i]
		t2 := ((a>>2 | a<<30) ^ (a>>13 | a<<19) ^ (a>>22 | a<<10)) + ((a & b) ^ (a & c) ^ (b & c))
		hh = g
		g = f
		f = e
		e = d + t1
		d = c
		c = b
		b = a
		a = t1 + t2
	}

	// Update state
	h[0] += a
	h[1] += b
	h[2] += c
	h[3] += d
	h[4] += e
	h[5] += f
	h[6] += g
	h[7] += hh
}
