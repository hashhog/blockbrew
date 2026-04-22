package storage

// Undo-blob compression.
//
// Legacy undo blobs (BlockUndo.Serialize prior to this change) start with a
// CompactSize TxUndo count.  The first byte of a legacy blob is therefore
// either 0x00..0xFC (count up to 252) or one of 0xFD/0xFE/0xFF marking a
// 2/4/8-byte length prefix.  A 0xFF first byte would imply a TxUndo count
// >= 2**32, which the legacy CompactSize reader caps at MaxCompactSize
// (32 MB) anyway — so a real on-disk blob can never start with 0xFF.
//
// We exploit that to dispatch on the very first byte without any extra
// magic.  New compressed blobs start with the 1-byte tag undoTagCompressedV1
// (0xFF).  ReadBlockUndo peeks byte 0 → if it's 0xFF dispatch to the
// compressed reader, otherwise fall through to the legacy DeserializeBlockUndo
// path.  This keeps already-written uncompressed undo blobs readable
// without an offline migration.
//
// Compressed format mirrors the UTXO writer in internal/consensus/utxoset.go:
// the 8-byte int64 amount becomes a varuint and the pkScript runs through
// CompressScript before being length-prefixed.  For typical IBD blocks this
// trims 40-60% off undo size — meaningful because undo still flows through
// Pebble (the W84+flatfile commit moved blocks out of Pebble but left undo
// behind, since reorgs need fast random access to it).
//
// The script-compression helpers below are an intentional duplicate of the
// ones in internal/consensus/utxoset.go.  Storage cannot import consensus
// (consensus imports storage), and lifting them into a shared package would
// be a larger refactor than this perf fix justifies.  TestStorageScriptCompressMatchesConsensus
// in storage_test.go pins the byte-level behaviour to consensus.

import (
	"bytes"
	"errors"
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// undoTagCompressedV1 is the leading byte of a v1 compressed BlockUndo blob.
// Chosen because legacy uncompressed blobs (which start with a CompactSize
// TxUndo count) can never begin with 0xFF in practice — that would imply
// the blob encodes a block with 2**32+ non-coinbase txs, which exceeds
// every protocol limit and would also be rejected by ReadCompactSize's
// MaxCompactSize check at read time.
const undoTagCompressedV1 byte = 0xFF

// Script type tags used by CompressScript / DecompressScript.  Identical
// to the constants in internal/consensus/utxoset.go (see comment at top of
// file for why this is duplicated rather than shared).
const (
	storageScriptTypeP2PKH   = 0x00
	storageScriptTypeP2SH    = 0x01
	storageScriptTypeP2WPKH  = 0x02
	storageScriptTypeP2WSH   = 0x03
	storageScriptTypeP2TR    = 0x04
	storageScriptTypeUnknown = 0x05
)

// isP2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG (25 bytes).
func isP2PKH(script []byte) bool {
	return len(script) == 25 &&
		script[0] == 0x76 &&
		script[1] == 0xa9 &&
		script[2] == 0x14 &&
		script[23] == 0x88 &&
		script[24] == 0xac
}

// isP2SH: OP_HASH160 <20 bytes> OP_EQUAL (23 bytes).
func isP2SH(script []byte) bool {
	return len(script) == 23 &&
		script[0] == 0xa9 &&
		script[1] == 0x14 &&
		script[22] == 0x87
}

// isP2WPKH: OP_0 <20 bytes> (22 bytes).
func isP2WPKH(script []byte) bool {
	return len(script) == 22 &&
		script[0] == 0x00 &&
		script[1] == 0x14
}

// isP2WSH: OP_0 <32 bytes> (34 bytes).
func isP2WSH(script []byte) bool {
	return len(script) == 34 &&
		script[0] == 0x00 &&
		script[1] == 0x20
}

// isP2TR: OP_1 <32 bytes> (34 bytes).
func isP2TR(script []byte) bool {
	return len(script) == 34 &&
		script[0] == 0x51 &&
		script[1] == 0x20
}

// compressScript compresses common script patterns.  Mirror of
// internal/consensus/utxoset.go CompressScript.
func compressScript(script []byte) []byte {
	switch {
	case isP2PKH(script):
		result := make([]byte, 21)
		result[0] = storageScriptTypeP2PKH
		copy(result[1:], script[3:23])
		return result
	case isP2SH(script):
		result := make([]byte, 21)
		result[0] = storageScriptTypeP2SH
		copy(result[1:], script[2:22])
		return result
	case isP2WPKH(script):
		result := make([]byte, 21)
		result[0] = storageScriptTypeP2WPKH
		copy(result[1:], script[2:22])
		return result
	case isP2WSH(script):
		result := make([]byte, 33)
		result[0] = storageScriptTypeP2WSH
		copy(result[1:], script[2:34])
		return result
	case isP2TR(script):
		result := make([]byte, 33)
		result[0] = storageScriptTypeP2TR
		copy(result[1:], script[2:34])
		return result
	default:
		result := make([]byte, 1+len(script))
		result[0] = storageScriptTypeUnknown
		copy(result[1:], script)
		return result
	}
}

// decompressScript reverses compressScript.  Mirror of
// internal/consensus/utxoset.go DecompressScript.
func decompressScript(compressed []byte) []byte {
	if len(compressed) == 0 {
		return nil
	}
	scriptType := compressed[0]
	data := compressed[1:]
	switch scriptType {
	case storageScriptTypeP2PKH:
		if len(data) != 20 {
			return compressed
		}
		script := make([]byte, 25)
		script[0] = 0x76
		script[1] = 0xa9
		script[2] = 0x14
		copy(script[3:23], data)
		script[23] = 0x88
		script[24] = 0xac
		return script
	case storageScriptTypeP2SH:
		if len(data) != 20 {
			return compressed
		}
		script := make([]byte, 23)
		script[0] = 0xa9
		script[1] = 0x14
		copy(script[2:22], data)
		script[22] = 0x87
		return script
	case storageScriptTypeP2WPKH:
		if len(data) != 20 {
			return compressed
		}
		script := make([]byte, 22)
		script[0] = 0x00
		script[1] = 0x14
		copy(script[2:22], data)
		return script
	case storageScriptTypeP2WSH:
		if len(data) != 32 {
			return compressed
		}
		script := make([]byte, 34)
		script[0] = 0x00
		script[1] = 0x20
		copy(script[2:34], data)
		return script
	case storageScriptTypeP2TR:
		if len(data) != 32 {
			return compressed
		}
		script := make([]byte, 34)
		script[0] = 0x51
		script[1] = 0x20
		copy(script[2:34], data)
		return script
	case storageScriptTypeUnknown:
		return data
	default:
		return compressed
	}
}

// writeUndoVaruint writes a variable-length unsigned integer without the
// 32 MB CompactSize cap.  Used for amounts and heights inside a compressed
// undo blob (matches utxoset.go writeVaruint for byte-level parity).
func writeUndoVaruint(w *bytes.Buffer, val uint64) {
	switch {
	case val < 0xFD:
		w.WriteByte(byte(val))
	case val <= 0xFFFF:
		w.WriteByte(0xFD)
		var buf [2]byte
		buf[0] = byte(val)
		buf[1] = byte(val >> 8)
		w.Write(buf[:])
	case val <= 0xFFFFFFFF:
		w.WriteByte(0xFE)
		var buf [4]byte
		buf[0] = byte(val)
		buf[1] = byte(val >> 8)
		buf[2] = byte(val >> 16)
		buf[3] = byte(val >> 24)
		w.Write(buf[:])
	default:
		w.WriteByte(0xFF)
		var buf [8]byte
		buf[0] = byte(val)
		buf[1] = byte(val >> 8)
		buf[2] = byte(val >> 16)
		buf[3] = byte(val >> 24)
		buf[4] = byte(val >> 32)
		buf[5] = byte(val >> 40)
		buf[6] = byte(val >> 48)
		buf[7] = byte(val >> 56)
		w.Write(buf[:])
	}
}

// readUndoVaruint reads a variable-length unsigned integer without the
// 32 MB CompactSize cap.  Mirror of utxoset.go readVaruint.
func readUndoVaruint(r *bytes.Reader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	switch first {
	case 0xFD:
		var buf [2]byte
		if _, err := r.Read(buf[:]); err != nil {
			return 0, err
		}
		return uint64(buf[0]) | uint64(buf[1])<<8, nil
	case 0xFE:
		var buf [4]byte
		if _, err := r.Read(buf[:]); err != nil {
			return 0, err
		}
		return uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24, nil
	case 0xFF:
		var buf [8]byte
		if _, err := r.Read(buf[:]); err != nil {
			return 0, err
		}
		return uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
			uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56, nil
	default:
		return uint64(first), nil
	}
}

// serializeBlockUndoCompressed returns the v1-compressed wire-form of a
// BlockUndo, leading byte = undoTagCompressedV1.  Format:
//
//	tag         (1 byte, == undoTagCompressedV1)
//	num_txundos (CompactSize)
//	for each TxUndo:
//	  num_coins (CompactSize)
//	  for each SpentCoin:
//	    height_code (varuint, height << 1 | coinbase_flag)
//	    amount      (varuint)
//	    script      (varuint length-prefixed compressed script)
func serializeBlockUndoCompressed(bu *BlockUndo) []byte {
	var buf bytes.Buffer
	buf.WriteByte(undoTagCompressedV1)

	wire.WriteCompactSize(&buf, uint64(len(bu.TxUndos)))
	for i := range bu.TxUndos {
		tu := &bu.TxUndos[i]
		wire.WriteCompactSize(&buf, uint64(len(tu.SpentCoins)))
		for j := range tu.SpentCoins {
			sc := &tu.SpentCoins[j]
			heightCode := uint64(sc.Height) << 1
			if sc.Coinbase {
				heightCode |= 1
			}
			writeUndoVaruint(&buf, heightCode)

			writeUndoVaruint(&buf, uint64(sc.TxOut.Value))

			compressed := compressScript(sc.TxOut.PkScript)
			writeUndoVaruint(&buf, uint64(len(compressed)))
			buf.Write(compressed)
		}
	}
	return buf.Bytes()
}

// deserializeBlockUndoCompressed reads a v1-compressed BlockUndo.  Caller
// must have already consumed (or verified) the leading undoTagCompressedV1
// byte — this function expects the reader positioned at num_txundos.
func deserializeBlockUndoCompressed(r *bytes.Reader) (*BlockUndo, error) {
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return nil, err
	}
	bu := &BlockUndo{TxUndos: make([]TxUndo, count)}

	for i := uint64(0); i < count; i++ {
		coinCount, err := wire.ReadCompactSize(r)
		if err != nil {
			return nil, err
		}
		tu := TxUndo{SpentCoins: make([]SpentCoin, coinCount)}
		for j := uint64(0); j < coinCount; j++ {
			heightCode, err := readUndoVaruint(r)
			if err != nil {
				return nil, err
			}
			amount, err := readUndoVaruint(r)
			if err != nil {
				return nil, err
			}
			scriptLen, err := readUndoVaruint(r)
			if err != nil {
				return nil, err
			}
			if scriptLen > 10000 {
				return nil, errors.New("undo: compressed script length too large")
			}
			compressed := make([]byte, scriptLen)
			if scriptLen > 0 {
				if _, err := io.ReadFull(r, compressed); err != nil {
					return nil, err
				}
			}
			pkScript := decompressScript(compressed)
			tu.SpentCoins[j] = SpentCoin{
				TxOut: wire.TxOut{
					Value:    int64(amount),
					PkScript: pkScript,
				},
				Height:   int32(heightCode >> 1),
				Coinbase: (heightCode & 1) == 1,
			}
		}
		bu.TxUndos[i] = tu
	}
	return bu, nil
}
