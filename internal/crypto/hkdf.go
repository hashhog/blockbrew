package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HKDF implements HKDF-SHA256 with a fixed output length of 32 bytes as used in BIP324.
// This implements RFC 5869 with HMAC-SHA256.
type HKDF struct {
	prk [32]byte // Pseudorandom key from extract phase
}

// NewHKDF creates a new HKDF instance with the given input key material and salt.
// This performs the HKDF-Extract step.
func NewHKDF(ikm []byte, salt string) *HKDF {
	h := &HKDF{}

	// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write(ikm)
	copy(h.prk[:], mac.Sum(nil))

	return h
}

// Expand32 derives 32 bytes of output key material using the given info string.
// This performs a single round of HKDF-Expand (sufficient for L=32 with SHA-256).
func (h *HKDF) Expand32(info string) [32]byte {
	// HKDF-Expand for single block (L <= HashLen):
	// T(1) = HMAC-Hash(PRK, info || 0x01)
	mac := hmac.New(sha256.New, h.prk[:])
	mac.Write([]byte(info))
	mac.Write([]byte{0x01})

	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}
