package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// MessageMagic is the prefix used by Bitcoin's "signmessage" / "verifymessage"
// to ensure that a signed message cannot be confused with a transaction. It
// matches Bitcoin Core's MESSAGE_MAGIC in src/common/signmessage.cpp.
const MessageMagic = "Bitcoin Signed Message:\n"

// ErrInvalidCompactSig is returned when a compact signature has the wrong size
// or an out-of-range recovery byte.
var ErrInvalidCompactSig = errors.New("invalid compact signature")

// writeCompactSize encodes a CompactSize integer to buf. Local copy to avoid
// importing the wire package (which would create a dependency cycle).
func writeCompactSize(buf *bytes.Buffer, val uint64) {
	switch {
	case val < 0xFD:
		buf.WriteByte(byte(val))
	case val <= 0xFFFF:
		buf.WriteByte(0xFD)
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(val))
		buf.Write(b[:])
	case val <= 0xFFFFFFFF:
		buf.WriteByte(0xFE)
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(val))
		buf.Write(b[:])
	default:
		buf.WriteByte(0xFF)
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], val)
		buf.Write(b[:])
	}
}

// MessageHash returns the double-SHA256 hash of a signed message, using
// Bitcoin Core's framing:
//
//	dsha256(compactsize(len(magic)) || magic || compactsize(len(message)) || message)
//
// This matches src/common/signmessage.cpp::MessageHash exactly.
func MessageHash(message string) [32]byte {
	var buf bytes.Buffer
	writeCompactSize(&buf, uint64(len(MessageMagic)))
	buf.WriteString(MessageMagic)
	writeCompactSize(&buf, uint64(len(message)))
	buf.WriteString(message)
	return DoubleSHA256(buf.Bytes())
}

// SignMessageCompact signs a 32-byte hash using ECDSA and returns the 65-byte
// compact signature in Bitcoin Core's "signmessage" format:
//
//	[0]      — recovery byte (27 + recid + 4 if compressed)
//	[1..33]  — 32-byte R
//	[33..65] — 32-byte S
//
// `compressed` reflects whether the corresponding public key is the compressed
// 33-byte SEC encoding (which is what every modern wallet uses).
func SignMessageCompact(privKey *PrivateKey, hash [32]byte, compressed bool) []byte {
	return ecdsa.SignCompact(privKey.key, hash[:], compressed)
}

// RecoverPubKeyFromCompact recovers the public key that produced a 65-byte
// compact signature over hash. It returns the recovered key and a boolean
// indicating whether the signer used the compressed-pubkey form (recovery byte
// >= 31). Returns nil and ErrInvalidCompactSig on a malformed signature.
func RecoverPubKeyFromCompact(sig []byte, hash [32]byte) (*PublicKey, bool, error) {
	if len(sig) != 65 {
		return nil, false, ErrInvalidCompactSig
	}
	pub, compressed, err := ecdsa.RecoverCompact(sig, hash[:])
	if err != nil {
		return nil, false, err
	}
	return &PublicKey{key: pub}, compressed, nil
}
