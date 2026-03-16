// Package crypto provides cryptographic primitives for Bitcoin.
// This file contains hash functions using hardware-accelerated SHA256
// when available (SHA-NI on x86_64, SHA2 extensions on ARM64).
package crypto

import (
	"golang.org/x/crypto/ripemd160"
)

// DoubleSHA256 computes SHA256(SHA256(data)).
// Uses hardware acceleration when available (SHA-NI on x86_64, SHA2 on ARM64).
func DoubleSHA256(data []byte) [32]byte {
	return DoubleSum256(data)
}

// Hash160 computes RIPEMD160(SHA256(data)), used for Bitcoin addresses.
func Hash160(data []byte) [20]byte {
	sha := Sum256(data)
	rip := ripemd160.New()
	rip.Write(sha[:])
	var result [20]byte
	copy(result[:], rip.Sum(nil))
	return result
}

// SHA256Hash computes a single SHA256.
// Uses hardware acceleration when available (SHA-NI on x86_64, SHA2 on ARM64).
func SHA256Hash(data []byte) [32]byte {
	return Sum256(data)
}
