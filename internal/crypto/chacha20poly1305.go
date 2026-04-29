package crypto

import (
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// FSChaCha20 implements forward-secure ChaCha20 stream cipher as used in BIP324.
//
// Per BIP-324 / Bitcoin Core (src/crypto/chacha20.cpp::FSChaCha20::Crypt) the
// keystream is CONTINUOUS within a rekey epoch: every Crypt() call draws the
// next chunk from a single stateful ChaCha20 instance whose 12-byte nonce is
// LE32(0) || LE64(rekey_counter) (constant within an epoch). After
// rekey_interval Crypt() calls the next 32 bytes of that keystream become the
// new key, rekey_counter increments, and the stateful cipher is re-seated at
// block 0 with the new key + nonce.
//
// The previous implementation built a fresh nonce per Crypt() call by stuffing
// chunk_counter into nonce[0:4] and starting ChaCha20 at block 0 every time.
// That produces a different keystream for every call — so packet N's
// ciphertext is NOT byte-N of a single epoch keystream, and any peer that
// follows the BIP-324 spec (Bitcoin Core, ouroboros, clearbit post-cb04a1f)
// will reject the second and later encrypted length prefixes. Live mainnet
// peers accepted our cipher version packet (decrypt at packet_counter=0
// happens to use a fresh block in either model) but rejected our app version
// packet, closing the connection right after we sent it.
//
// Reference: BIP-324 §"Wire format"; bitcoin-core/src/crypto/chacha20.cpp;
// ouroboros/src/ouroboros/transport_v2.py FSChaCha20.crypt.
type FSChaCha20 struct {
	key           [32]byte
	rekeyInterval uint32
	chunkCounter  uint32
	rekeyCounter  uint64
	// cipher is a stateful ChaCha20 instance scoped to the current epoch.
	// Nil until the first Crypt() of the epoch creates it. XORKeyStream
	// internally advances the block counter, so successive calls produce
	// a continuous keystream — exactly what BIP-324 requires.
	cipher *chacha20.Cipher
}

// NewFSChaCha20 creates a new forward-secure ChaCha20 cipher.
func NewFSChaCha20(key []byte, rekeyInterval uint32) *FSChaCha20 {
	fs := &FSChaCha20{
		rekeyInterval: rekeyInterval,
	}
	copy(fs.key[:], key)
	return fs
}

// epochNonce builds the 12-byte nonce for the current rekey epoch:
// LE32(0) || LE64(rekey_counter).  Constant within an epoch.
func (fs *FSChaCha20) epochNonce() [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:12], fs.rekeyCounter)
	return nonce
}

// ensureCipher lazily seats a stateful ChaCha20 instance for the current
// epoch, starting at block counter 0.
func (fs *FSChaCha20) ensureCipher() {
	if fs.cipher == nil {
		nonce := fs.epochNonce()
		fs.cipher, _ = chacha20.NewUnauthenticatedCipher(fs.key[:], nonce[:])
	}
}

// Crypt encrypts or decrypts a chunk by XORing it with the next bytes of the
// continuous epoch keystream.  For BIP-324 this is used to encrypt/decrypt
// the 3-byte length field of every packet on the wire.
func (fs *FSChaCha20) Crypt(input, output []byte) {
	fs.ensureCipher()
	fs.cipher.XORKeyStream(output, input)

	fs.chunkCounter++
	if fs.chunkCounter == fs.rekeyInterval {
		fs.rekey()
	}
}

// rekey rotates the epoch key by drawing the next 32 bytes of the current
// keystream, increments the rekey counter, and clears the cached cipher so
// the next Crypt() seats a fresh ChaCha20 at block 0 under the new key +
// new nonce.  Mirrors bitcoin-core's `m_chacha20.Seek({0, ++m_rekey_counter}, 0)`.
func (fs *FSChaCha20) rekey() {
	// Draw 32 keystream bytes from the current cipher (continuing the
	// epoch's stream) and use them as the next-epoch key.
	var newKey [32]byte
	fs.cipher.XORKeyStream(newKey[:], newKey[:]) // XOR with zeros = keystream

	fs.key = newKey
	fs.chunkCounter = 0
	fs.rekeyCounter++
	fs.cipher = nil // forces ensureCipher() to rebuild with new key + nonce
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

// rekey derives a new key by drawing 32 bytes of keystream from the AEAD
// under the dedicated rekey nonce {0xFFFFFFFF, rekey_counter} per
// bitcoin-core/src/crypto/chacha20poly1305.cpp::FSChaCha20Poly1305::NextPacket.
//
// The previous implementation reused `packetCounter` (which at this point has
// just incremented to rekey_interval) in nonce[0:4] instead of 0xFFFFFFFF.
// That diverged from BIP-324 silently — the bug only fires after 224
// successful packet operations (the default rekey interval), so it is rarely
// observed in interactive tests but is a guaranteed long-lived-connection
// desync.
func (fs *FSChaCha20Poly1305) rekey() {
	// Build the dedicated rekey nonce: 0xFFFFFFFF || LE64(rekey_counter).
	var nonce [12]byte
	binary.LittleEndian.PutUint32(nonce[0:4], 0xFFFFFFFF)
	binary.LittleEndian.PutUint64(nonce[4:12], fs.rekeyCounter)

	aead, _ := chacha20poly1305.New(fs.key[:])

	// AEAD over a 32-byte zero plaintext produces ciphertext = ChaCha20
	// keystream (block_counter starts at 1; block 0 is the Poly1305 key).
	// We discard the trailing 16-byte tag; only the first 32 bytes of
	// ciphertext form the new key.
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
