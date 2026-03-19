package crypto

import (
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// FSChaCha20 implements forward-secure ChaCha20 stream cipher as used in BIP324.
// It automatically increments the nonce after each encryption and rekeys
// after a specified number of operations.
type FSChaCha20 struct {
	key           [32]byte
	rekeyInterval uint32
	chunkCounter  uint32
	rekeyCounter  uint64
}

// NewFSChaCha20 creates a new forward-secure ChaCha20 cipher.
func NewFSChaCha20(key []byte, rekeyInterval uint32) *FSChaCha20 {
	fs := &FSChaCha20{
		rekeyInterval: rekeyInterval,
	}
	copy(fs.key[:], key)
	return fs
}

// Crypt encrypts or decrypts data in-place using ChaCha20.
// For BIP324, this is used to encrypt/decrypt the 3-byte length field.
func (fs *FSChaCha20) Crypt(input, output []byte) {
	// Build nonce: 4 bytes little-endian chunk counter + 8 bytes little-endian rekey counter
	var nonce [12]byte
	binary.LittleEndian.PutUint32(nonce[0:4], fs.chunkCounter)
	binary.LittleEndian.PutUint64(nonce[4:12], fs.rekeyCounter)

	cipher, _ := chacha20.NewUnauthenticatedCipher(fs.key[:], nonce[:])
	cipher.XORKeyStream(output, input)

	// Update counters
	fs.chunkCounter++
	if fs.chunkCounter == fs.rekeyInterval {
		fs.rekey()
	}
}

// rekey derives a new key from the current state.
func (fs *FSChaCha20) rekey() {
	// Generate 32 bytes of keystream as the new key
	var nonce [12]byte
	binary.LittleEndian.PutUint32(nonce[0:4], fs.chunkCounter)
	binary.LittleEndian.PutUint64(nonce[4:12], fs.rekeyCounter)

	cipher, _ := chacha20.NewUnauthenticatedCipher(fs.key[:], nonce[:])

	var newKey [32]byte
	cipher.XORKeyStream(newKey[:], newKey[:]) // XOR with zeros = keystream

	fs.key = newKey
	fs.chunkCounter = 0
	fs.rekeyCounter++
}

// FSChaCha20Poly1305 implements forward-secure ChaCha20-Poly1305 AEAD as used in BIP324.
// It automatically increments the nonce after each encryption/decryption and rekeys
// after a specified number of operations.
type FSChaCha20Poly1305 struct {
	key           [32]byte
	rekeyInterval uint32
	packetCounter uint32
	rekeyCounter  uint64
}

// Expansion is the number of bytes added to plaintext during encryption (16-byte tag).
const Expansion = chacha20poly1305.Overhead

// NewFSChaCha20Poly1305 creates a new forward-secure ChaCha20-Poly1305 AEAD.
func NewFSChaCha20Poly1305(key []byte, rekeyInterval uint32) *FSChaCha20Poly1305 {
	fs := &FSChaCha20Poly1305{
		rekeyInterval: rekeyInterval,
	}
	copy(fs.key[:], key)
	return fs
}

// Encrypt encrypts plaintext with associated data using ChaCha20-Poly1305.
// The header byte is prepended to the contents before encryption.
// Output must have len(contents) + 1 (header) + 16 (tag) bytes of space.
func (fs *FSChaCha20Poly1305) Encrypt(header byte, contents, aad, output []byte) {
	// Build plaintext: header || contents
	plaintext := make([]byte, 1+len(contents))
	plaintext[0] = header
	copy(plaintext[1:], contents)

	// Build nonce: 4 bytes little-endian packet counter + 8 bytes little-endian rekey counter
	var nonce [12]byte
	binary.LittleEndian.PutUint32(nonce[0:4], fs.packetCounter)
	binary.LittleEndian.PutUint64(nonce[4:12], fs.rekeyCounter)

	aead, _ := chacha20poly1305.New(fs.key[:])
	aead.Seal(output[:0], nonce[:], plaintext, aad)

	fs.nextPacket()
}

// Decrypt decrypts ciphertext with associated data using ChaCha20-Poly1305.
// Returns the header byte, decrypted contents, and whether decryption succeeded.
func (fs *FSChaCha20Poly1305) Decrypt(ciphertext, aad []byte) (header byte, contents []byte, ok bool) {
	if len(ciphertext) < Expansion+1 {
		return 0, nil, false
	}

	// Build nonce
	var nonce [12]byte
	binary.LittleEndian.PutUint32(nonce[0:4], fs.packetCounter)
	binary.LittleEndian.PutUint64(nonce[4:12], fs.rekeyCounter)

	aead, _ := chacha20poly1305.New(fs.key[:])
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return 0, nil, false
	}

	fs.nextPacket()

	return plaintext[0], plaintext[1:], true
}

// nextPacket updates counters and rekeys if necessary.
func (fs *FSChaCha20Poly1305) nextPacket() {
	fs.packetCounter++
	if fs.packetCounter == fs.rekeyInterval {
		fs.rekey()
	}
}

// rekey derives a new key from the current state using the AEAD's keystream.
func (fs *FSChaCha20Poly1305) rekey() {
	// Build nonce for rekeying
	var nonce [12]byte
	binary.LittleEndian.PutUint32(nonce[0:4], fs.packetCounter)
	binary.LittleEndian.PutUint64(nonce[4:12], fs.rekeyCounter)

	// Use ChaCha20 keystream (via AEAD encryption of zeros with no auth)
	aead, _ := chacha20poly1305.New(fs.key[:])

	// We need to extract the ChaCha20 keystream, not the full AEAD output.
	// Generate 32 bytes of keystream by encrypting zeros.
	// The AEAD adds a 16-byte tag, but we only need the first 32 bytes of ciphertext.
	zeros := make([]byte, 32)
	ciphertext := aead.Seal(nil, nonce[:], zeros, nil)
	copy(fs.key[:], ciphertext[:32])

	fs.packetCounter = 0
	fs.rekeyCounter++
}

// AEADChaCha20Poly1305 provides standard RFC 8439 ChaCha20-Poly1305 AEAD.
type AEADChaCha20Poly1305 struct {
	aead cipher.AEAD
}

// NewAEADChaCha20Poly1305 creates a new standard ChaCha20-Poly1305 AEAD.
func NewAEADChaCha20Poly1305(key []byte) (*AEADChaCha20Poly1305, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &AEADChaCha20Poly1305{aead: aead}, nil
}

// Seal encrypts and authenticates plaintext with associated data.
func (a *AEADChaCha20Poly1305) Seal(dst, nonce, plaintext, aad []byte) []byte {
	return a.aead.Seal(dst, nonce, plaintext, aad)
}

// Open decrypts and verifies ciphertext with associated data.
func (a *AEADChaCha20Poly1305) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	return a.aead.Open(dst, nonce, ciphertext, aad)
}
