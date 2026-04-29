package p2p

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/hashhog/blockbrew/internal/crypto"
)

// BIP324 constants.
const (
	// SessionIDLen is the length of the session ID.
	SessionIDLen = 32

	// GarbageTerminatorLen is the length of the garbage terminator.
	GarbageTerminatorLen = 16

	// RekeyInterval is how often the cipher is rekeyed.
	RekeyInterval = 224

	// LengthLen is the size of the encrypted length field.
	LengthLen = 3

	// HeaderLen is the size of the decoy/ignore flag byte.
	HeaderLen = 1

	// BIP324Expansion is the total expansion when encrypting a message.
	// Length (3) + Header (1) + Poly1305 tag (16) = 20 bytes
	BIP324Expansion = LengthLen + HeaderLen + crypto.Expansion

	// MaxGarbageLen is the maximum length of garbage data.
	MaxGarbageLen = 4095

	// IgnoreBit indicates a decoy message that should be ignored.
	IgnoreBit = byte(0x80)

	// EllSwiftPubKeySize is the size of an ElligatorSwift public key.
	EllSwiftPubKeySize = 64

	// V1PrefixLen is the length of the v1 version prefix we check for.
	V1PrefixLen = 16
)

// BIP324 errors.
var (
	ErrBIP324NotInitialized = errors.New("bip324: cipher not initialized")
	ErrBIP324DecryptFailed  = errors.New("bip324: decryption failed")
	ErrBIP324InvalidLength  = errors.New("bip324: invalid message length")
)

// BIP324Cipher implements the BIP324 packet cipher.
type BIP324Cipher struct {
	sendLCipher *crypto.FSChaCha20       // For encrypting length
	recvLCipher *crypto.FSChaCha20       // For decrypting length
	sendPCipher *crypto.FSChaCha20Poly1305 // For encrypting payloads
	recvPCipher *crypto.FSChaCha20Poly1305 // For decrypting payloads

	ourKey     *crypto.EllSwiftPrivKey
	sessionID  [SessionIDLen]byte
	sendGarbageTerminator [GarbageTerminatorLen]byte
	recvGarbageTerminator [GarbageTerminatorLen]byte

	initialized bool
}

// NewBIP324Cipher creates a new BIP324 cipher with a randomly generated key.
func NewBIP324Cipher() (*BIP324Cipher, error) {
	key, err := crypto.GenerateEllSwiftPrivKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	return &BIP324Cipher{
		ourKey: key,
	}, nil
}

// NewBIP324CipherWithKey creates a new BIP324 cipher with a specific private key.
// This is primarily useful for testing with known keys.
func NewBIP324CipherWithKey(privKeyBytes, entropy []byte) (*BIP324Cipher, error) {
	key, err := crypto.EllSwiftPrivKeyFromBytesWithEntropy(privKeyBytes, entropy)
	if err != nil {
		return nil, fmt.Errorf("create key: %w", err)
	}

	return &BIP324Cipher{
		ourKey: key,
	}, nil
}

// GetOurPubKey returns our ElligatorSwift-encoded public key.
func (c *BIP324Cipher) GetOurPubKey() crypto.EllSwiftPubKey {
	return c.ourKey.EllSwiftPubKey
}

// IsInitialized returns true if the cipher is ready for encryption/decryption.
func (c *BIP324Cipher) IsInitialized() bool {
	return c.initialized
}

// Initialize completes the key exchange and initializes the encryption ciphers.
// theirPubKey is the peer's ElligatorSwift-encoded public key.
// initiator should be true if we initiated the connection.
func (c *BIP324Cipher) Initialize(theirPubKey crypto.EllSwiftPubKey, initiator bool) error {
	// Compute ECDH shared secret
	ecdhSecret := c.ourKey.ComputeBIP324ECDHSecret(theirPubKey, initiator)

	// Derive keys using HKDF
	// Salt: "bitcoin_v2_shared_secret" + network magic bytes (we'll use mainnet)
	magic := []byte{0xf9, 0xbe, 0xb4, 0xd9} // mainnet magic
	salt := "bitcoin_v2_shared_secret" + string(magic)
	hkdf := crypto.NewHKDF(ecdhSecret[:], salt)

	// Derive send/receive keys based on whether we're initiator or responder
	initiatorLKey := hkdf.Expand32("initiator_L")
	initiatorPKey := hkdf.Expand32("initiator_P")
	responderLKey := hkdf.Expand32("responder_L")
	responderPKey := hkdf.Expand32("responder_P")

	if initiator {
		c.sendLCipher = crypto.NewFSChaCha20(initiatorLKey[:], RekeyInterval)
		c.sendPCipher = crypto.NewFSChaCha20Poly1305(initiatorPKey[:], RekeyInterval)
		c.recvLCipher = crypto.NewFSChaCha20(responderLKey[:], RekeyInterval)
		c.recvPCipher = crypto.NewFSChaCha20Poly1305(responderPKey[:], RekeyInterval)
	} else {
		c.sendLCipher = crypto.NewFSChaCha20(responderLKey[:], RekeyInterval)
		c.sendPCipher = crypto.NewFSChaCha20Poly1305(responderPKey[:], RekeyInterval)
		c.recvLCipher = crypto.NewFSChaCha20(initiatorLKey[:], RekeyInterval)
		c.recvPCipher = crypto.NewFSChaCha20Poly1305(initiatorPKey[:], RekeyInterval)
	}

	// Derive garbage terminators
	garbageKey := hkdf.Expand32("garbage_terminators")
	if initiator {
		copy(c.sendGarbageTerminator[:], garbageKey[0:GarbageTerminatorLen])
		copy(c.recvGarbageTerminator[:], garbageKey[GarbageTerminatorLen:32])
	} else {
		copy(c.recvGarbageTerminator[:], garbageKey[0:GarbageTerminatorLen])
		copy(c.sendGarbageTerminator[:], garbageKey[GarbageTerminatorLen:32])
	}

	// Derive session ID
	sessionKey := hkdf.Expand32("session_id")
	copy(c.sessionID[:], sessionKey[:])

	c.initialized = true
	return nil
}

// InitializeWithMagic initializes with a specific network magic.
func (c *BIP324Cipher) InitializeWithMagic(theirPubKey crypto.EllSwiftPubKey, initiator bool, magic uint32) error {
	// Compute ECDH shared secret
	ecdhSecret := c.ourKey.ComputeBIP324ECDHSecret(theirPubKey, initiator)

	// Build salt with specific magic
	var magicBytes [4]byte
	binary.LittleEndian.PutUint32(magicBytes[:], magic)
	salt := "bitcoin_v2_shared_secret" + string(magicBytes[:])

	hkdf := crypto.NewHKDF(ecdhSecret[:], salt)

	// Derive keys
	initiatorLKey := hkdf.Expand32("initiator_L")
	initiatorPKey := hkdf.Expand32("initiator_P")
	responderLKey := hkdf.Expand32("responder_L")
	responderPKey := hkdf.Expand32("responder_P")

	if initiator {
		c.sendLCipher = crypto.NewFSChaCha20(initiatorLKey[:], RekeyInterval)
		c.sendPCipher = crypto.NewFSChaCha20Poly1305(initiatorPKey[:], RekeyInterval)
		c.recvLCipher = crypto.NewFSChaCha20(responderLKey[:], RekeyInterval)
		c.recvPCipher = crypto.NewFSChaCha20Poly1305(responderPKey[:], RekeyInterval)
	} else {
		c.sendLCipher = crypto.NewFSChaCha20(responderLKey[:], RekeyInterval)
		c.sendPCipher = crypto.NewFSChaCha20Poly1305(responderPKey[:], RekeyInterval)
		c.recvLCipher = crypto.NewFSChaCha20(initiatorLKey[:], RekeyInterval)
		c.recvPCipher = crypto.NewFSChaCha20Poly1305(initiatorPKey[:], RekeyInterval)
	}

	// Derive garbage terminators
	garbageKey := hkdf.Expand32("garbage_terminators")
	if initiator {
		copy(c.sendGarbageTerminator[:], garbageKey[0:GarbageTerminatorLen])
		copy(c.recvGarbageTerminator[:], garbageKey[GarbageTerminatorLen:32])
	} else {
		copy(c.recvGarbageTerminator[:], garbageKey[0:GarbageTerminatorLen])
		copy(c.sendGarbageTerminator[:], garbageKey[GarbageTerminatorLen:32])
	}

	// Derive session ID
	sessionKey := hkdf.Expand32("session_id")
	copy(c.sessionID[:], sessionKey[:])

	c.initialized = true
	return nil
}

// GetSessionID returns the session ID derived during key exchange.
func (c *BIP324Cipher) GetSessionID() [SessionIDLen]byte {
	return c.sessionID
}

// GetSendGarbageTerminator returns the garbage terminator to send.
func (c *BIP324Cipher) GetSendGarbageTerminator() [GarbageTerminatorLen]byte {
	return c.sendGarbageTerminator
}

// GetRecvGarbageTerminator returns the expected garbage terminator to receive.
func (c *BIP324Cipher) GetRecvGarbageTerminator() [GarbageTerminatorLen]byte {
	return c.recvGarbageTerminator
}

// Encrypt encrypts a message packet.
// contents is the plaintext message content.
// aad is additional authenticated data (typically the garbage during handshake).
// ignore indicates whether this is a decoy message.
// Returns the complete encrypted packet (length || ciphertext).
func (c *BIP324Cipher) Encrypt(contents, aad []byte, ignore bool) ([]byte, error) {
	if !c.initialized {
		return nil, ErrBIP324NotInitialized
	}

	// Build output: encrypted_length (3) || encrypted_payload+tag (len(contents)+1+16)
	output := make([]byte, LengthLen+len(contents)+HeaderLen+crypto.Expansion)

	// Encrypt length (3 bytes, little-endian)
	var lenBytes [LengthLen]byte
	lenBytes[0] = byte(len(contents) & 0xFF)
	lenBytes[1] = byte((len(contents) >> 8) & 0xFF)
	lenBytes[2] = byte((len(contents) >> 16) & 0xFF)
	c.sendLCipher.Crypt(lenBytes[:], output[0:LengthLen])

	// Set header byte
	var header byte
	if ignore {
		header = IgnoreBit
	}

	// Encrypt payload: header || contents with AEAD
	c.sendPCipher.Encrypt(header, contents, aad, output[LengthLen:])

	return output, nil
}

// DecryptLength decrypts the 3-byte length field from an encrypted packet.
// Returns the content length.
func (c *BIP324Cipher) DecryptLength(encryptedLen []byte) (uint32, error) {
	if !c.initialized {
		return 0, ErrBIP324NotInitialized
	}

	if len(encryptedLen) != LengthLen {
		return 0, ErrBIP324InvalidLength
	}

	var lenBytes [LengthLen]byte
	c.recvLCipher.Crypt(encryptedLen, lenBytes[:])

	length := uint32(lenBytes[0]) | (uint32(lenBytes[1]) << 8) | (uint32(lenBytes[2]) << 16)
	return length, nil
}

// Decrypt decrypts the payload portion of an encrypted packet.
// encryptedPayload should not include the length field (already decrypted separately).
// aad is additional authenticated data.
// Returns the decrypted contents and whether this is a decoy message.
func (c *BIP324Cipher) Decrypt(encryptedPayload, aad []byte) (contents []byte, ignore bool, err error) {
	if !c.initialized {
		return nil, false, ErrBIP324NotInitialized
	}

	header, contents, ok := c.recvPCipher.Decrypt(encryptedPayload, aad)
	if !ok {
		return nil, false, ErrBIP324DecryptFailed
	}

	ignore = (header & IgnoreBit) == IgnoreBit
	return contents, ignore, nil
}

// GenerateGarbage generates random garbage data of a random length (0 to MaxGarbageLen).
func GenerateGarbage() []byte {
	// Random length between 0 and MaxGarbageLen
	var lenByte [2]byte
	rand.Read(lenByte[:])
	length := int(binary.LittleEndian.Uint16(lenByte[:])) % (MaxGarbageLen + 1)

	garbage := make([]byte, length)
	rand.Read(garbage)
	return garbage
}

// CheckV1Magic checks if the first bytes look like a v1 protocol message.
// Returns true if the bytes match the v1 version message pattern.
func CheckV1Magic(data []byte, magic uint32) bool {
	if len(data) < V1PrefixLen {
		return false
	}

	// v1 prefix is: magic (4 bytes) + "version\x00\x00\x00\x00\x00" (12 bytes)
	expectedPrefix := make([]byte, V1PrefixLen)
	binary.LittleEndian.PutUint32(expectedPrefix[0:4], magic)
	copy(expectedPrefix[4:], []byte("version\x00\x00\x00\x00\x00"))

	return bytes.Equal(data[:V1PrefixLen], expectedPrefix)
}

// BIP324 short message type IDs (single-byte command encoding).
//
// This MUST mirror Bitcoin Core's V2_MESSAGE_IDS[1..28] in net.cpp
// (constexpr std::array<std::string, 33>) — the only commands that have a
// 1-byte short ID assigned by BIP-324.  Indices 29..32 are explicitly
// reserved as "Unimplemented" placeholders in BIP-324 and MUST NOT be
// emitted on the wire.  In particular, the handshake messages
// `version` and `verack`, plus the negotiation messages `wtxidrelay`,
// `sendaddrv2`, `sendheaders`, `sendtxrcncl`, and `getaddr`, are NOT in the
// short-ID table — they are sent with the long (12-byte) command-name
// form (first byte 0x00 followed by the padded command).  Sending one of
// these with a fabricated short ID (e.g. our previous 0x20 for version)
// causes BIP-324 peers to silently reject the packet as
// "invalid message type" (Core net.cpp:1426-1428,1474-1476): the cipher
// handshake completes, getpeerinfo reports `transport_protocol_type=v2`,
// but `subver=""` and `version=0` because the application-layer version
// message never decodes.
var shortMsgTypes = map[string]byte{
	"addr":         0x01,
	"block":        0x02,
	"blocktxn":     0x03,
	"cmpctblock":   0x04,
	"feefilter":    0x05,
	"filteradd":    0x06,
	"filterclear":  0x07,
	"filterload":   0x08,
	"getblocks":    0x09,
	"getblocktxn":  0x0a,
	"getdata":      0x0b,
	"getheaders":   0x0c,
	"headers":      0x0d,
	"inv":          0x0e,
	"mempool":      0x0f,
	"merkleblock":  0x10,
	"notfound":     0x11,
	"ping":         0x12,
	"pong":         0x13,
	"sendcmpct":    0x14,
	"tx":           0x15,
	"getcfilters":  0x16,
	"cfilter":      0x17,
	"getcfheaders": 0x18,
	"cfheaders":    0x19,
	"getcfcheckpt": 0x1a,
	"cfcheckpt":    0x1b,
	"addrv2":       0x1c,
}

var shortMsgTypesReverse = func() map[byte]string {
	m := make(map[byte]string)
	for k, v := range shortMsgTypes {
		m[v] = k
	}
	return m
}()

// EncodeV2Message encodes a message for v2 transport.
// Returns the content bytes (message type ID + payload).
func EncodeV2Message(command string, payload []byte) []byte {
	if id, ok := shortMsgTypes[command]; ok {
		// Use single-byte encoding
		content := make([]byte, 1+len(payload))
		content[0] = id
		copy(content[1:], payload)
		return content
	}

	// Use long-form encoding: 0x00 + command (12 bytes) + payload
	content := make([]byte, 1+12+len(payload))
	content[0] = 0x00
	copy(content[1:13], []byte(command))
	copy(content[13:], payload)
	return content
}

// DecodeV2Message decodes a message from v2 transport.
// Returns the command string and payload.
func DecodeV2Message(content []byte) (string, []byte, error) {
	if len(content) == 0 {
		return "", nil, errors.New("empty content")
	}

	firstByte := content[0]
	if firstByte == 0x00 {
		// Long-form encoding
		if len(content) < 13 {
			return "", nil, errors.New("short message content")
		}
		// Find null terminator in command
		cmdBytes := content[1:13]
		end := 0
		for i, b := range cmdBytes {
			if b == 0 {
				break
			}
			end = i + 1
		}
		command := string(cmdBytes[:end])
		return command, content[13:], nil
	}

	// Short-form encoding
	if command, ok := shortMsgTypesReverse[firstByte]; ok {
		return command, content[1:], nil
	}

	return "", nil, fmt.Errorf("unknown message type ID: 0x%02x", firstByte)
}
