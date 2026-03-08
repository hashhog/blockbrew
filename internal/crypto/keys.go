package crypto

import (
	"crypto/rand"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ErrInvalidPrivateKey is returned when private key bytes are invalid.
var ErrInvalidPrivateKey = errors.New("invalid private key")

// PrivateKey wraps a secp256k1 private key.
type PrivateKey struct {
	key *secp256k1.PrivateKey
}

// PublicKey wraps a secp256k1 public key.
type PublicKey struct {
	key *secp256k1.PublicKey
}

// GeneratePrivateKey creates a new random private key.
func GeneratePrivateKey() (*PrivateKey, error) {
	var keyBytes [32]byte
	for {
		_, err := rand.Read(keyBytes[:])
		if err != nil {
			return nil, err
		}

		// Check that the key is valid (non-zero and less than curve order)
		key := secp256k1.PrivKeyFromBytes(keyBytes[:])
		if key != nil {
			// Verify the key is valid by checking the scalar isn't zero
			serialized := key.Serialize()
			allZero := true
			for _, b := range serialized {
				if b != 0 {
					allZero = false
					break
				}
			}
			if !allZero {
				return &PrivateKey{key: key}, nil
			}
		}
	}
}

// PrivateKeyFromBytes creates a private key from raw 32-byte scalar.
func PrivateKeyFromBytes(b []byte) *PrivateKey {
	if len(b) != 32 {
		return nil
	}
	key := secp256k1.PrivKeyFromBytes(b)
	return &PrivateKey{key: key}
}

// Serialize returns the 32-byte big-endian scalar.
func (pk *PrivateKey) Serialize() []byte {
	return pk.key.Serialize()
}

// PubKey returns the corresponding public key.
func (pk *PrivateKey) PubKey() *PublicKey {
	return &PublicKey{key: pk.key.PubKey()}
}

// SerializeCompressed returns the 33-byte SEC compressed public key.
func (pub *PublicKey) SerializeCompressed() []byte {
	return pub.key.SerializeCompressed()
}

// SerializeUncompressed returns the 65-byte SEC uncompressed public key (04 || x || y).
func (pub *PublicKey) SerializeUncompressed() []byte {
	return pub.key.SerializeUncompressed()
}

// XOnlyPubKey returns the 32-byte x-only public key (BIP340).
func (pub *PublicKey) XOnlyPubKey() []byte {
	// The x-only public key is the first 32 bytes of the compressed key
	// minus the prefix byte (which indicates y parity)
	compressed := pub.key.SerializeCompressed()
	return compressed[1:]
}

// PublicKeyFromBytes parses a public key from compressed (33-byte) or
// uncompressed (65-byte) SEC format.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	key, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: key}, nil
}

// Inner returns the underlying secp256k1 private key.
// This is useful for signing operations.
func (pk *PrivateKey) Inner() *secp256k1.PrivateKey {
	return pk.key
}

// Inner returns the underlying secp256k1 public key.
// This is useful for verification operations.
func (pub *PublicKey) Inner() *secp256k1.PublicKey {
	return pub.key
}
