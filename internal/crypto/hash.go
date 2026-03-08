// Package crypto provides cryptographic primitives for Bitcoin.
package crypto

import (
	"crypto/sha256"

	"golang.org/x/crypto/ripemd160"
)

// DoubleSHA256 computes SHA256(SHA256(data)).
func DoubleSHA256(data []byte) [32]byte {
	first := sha256.Sum256(data)
	return sha256.Sum256(first[:])
}

// Hash160 computes RIPEMD160(SHA256(data)), used for Bitcoin addresses.
func Hash160(data []byte) [20]byte {
	sha := sha256.Sum256(data)
	rip := ripemd160.New()
	rip.Write(sha[:])
	var result [20]byte
	copy(result[:], rip.Sum(nil))
	return result
}

// SHA256Hash computes a single SHA256.
func SHA256Hash(data []byte) [32]byte {
	return sha256.Sum256(data)
}
