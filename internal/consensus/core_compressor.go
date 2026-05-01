package consensus

// Core-byte-compatible script and amount compression for UTXO snapshots.
//
// This file mirrors Bitcoin Core's `src/compressor.cpp` and is used ONLY for
// snapshot serialization (`dumptxoutset` / `loadtxoutset` and the
// `--load-snapshot` CLI flag).  The legacy `CompressScript` /
// `DecompressScript` / `SerializeUTXOEntry` / `DeserializeUTXOEntry`
// functions in `utxoset.go` continue to encode the on-disk chainstate;
// changing those tags would invalidate every existing chaindata directory.
//
// Reference: bitcoin-core/src/compressor.cpp + compressor.h.

import (
	"errors"
	"fmt"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Core's per-coin script encoding tags.
//   0x00 = P2PKH (20-byte pubkey hash)
//   0x01 = P2SH  (20-byte script hash)
//   0x02 = P2PK  with compressed pubkey, parity even (0x02 prefix)
//   0x03 = P2PK  with compressed pubkey, parity odd  (0x03 prefix)
//   0x04 = P2PK  with uncompressed pubkey, parity even (decompressed via secp256k1)
//   0x05 = P2PK  with uncompressed pubkey, parity odd  (decompressed via secp256k1)
//   nSize >= 6 = "size + nSpecialScripts" raw script of length nSize-6.
const (
	coreScriptP2PKH    = 0x00
	coreScriptP2SH     = 0x01
	coreScriptP2PKEven = 0x02
	coreScriptP2PKOdd  = 0x03
	coreScriptP2PKUEven = 0x04
	coreScriptP2PKUOdd  = 0x05

	// nSpecialScripts mirrors Core's compressor.h.  Anything below this
	// is a recognized special script; anything at-or-above encodes a raw
	// script of length (nSize - nSpecialScripts).
	coreNSpecialScripts = 6
)

// coreIsToKeyID checks for a P2PKH script and extracts the 20-byte hash.
func coreIsToKeyID(script []byte) ([]byte, bool) {
	if len(script) == 25 &&
		script[0] == 0x76 && // OP_DUP
		script[1] == 0xa9 && // OP_HASH160
		script[2] == 0x14 && // push 20
		script[23] == 0x88 && // OP_EQUALVERIFY
		script[24] == 0xac { // OP_CHECKSIG
		return script[3:23], true
	}
	return nil, false
}

// coreIsToScriptID checks for a P2SH script and extracts the 20-byte hash.
func coreIsToScriptID(script []byte) ([]byte, bool) {
	if len(script) == 23 &&
		script[0] == 0xa9 && // OP_HASH160
		script[1] == 0x14 && // push 20
		script[22] == 0x87 { // OP_EQUAL
		return script[2:22], true
	}
	return nil, false
}

// coreIsToPubKey checks for a P2PK script and returns the encoded pubkey
// (33 bytes for compressed, 65 bytes for uncompressed).  Mirrors
// IsToPubKey() in compressor.cpp; for uncompressed pubkeys we additionally
// require IsFullyValid (i.e. the (x,y) is on the curve), since invalid
// uncompressed pubkeys cannot be round-tripped through compression.
func coreIsToPubKey(script []byte) ([]byte, bool) {
	// 33-byte compressed: 33 <pubkey 33B> OP_CHECKSIG
	if len(script) == 35 && script[0] == 33 && script[34] == 0xac &&
		(script[1] == 0x02 || script[1] == 0x03) {
		return script[1:34], true
	}
	// 65-byte uncompressed: 65 <pubkey 65B> OP_CHECKSIG
	if len(script) == 67 && script[0] == 65 && script[66] == 0xac &&
		script[1] == 0x04 {
		// Validate the pubkey by parsing it.  An invalid (x,y) cannot
		// be round-tripped through compression.
		if _, err := secp256k1.ParsePubKey(script[1:66]); err != nil {
			return nil, false
		}
		return script[1:66], true
	}
	return nil, false
}

// CoreCompressScript returns (encoded, ok). When ok=true, encoded is a
// short-form representation (21 bytes for P2PKH/P2SH, 33 bytes for P2PK)
// whose first byte is the tag (0x00..0x05). When ok=false, the script is
// non-special and the caller must fall back to length-prefixed raw bytes.
//
// Mirrors CompressScript() in bitcoin-core/src/compressor.cpp.
func CoreCompressScript(script []byte) ([]byte, bool) {
	if hash, ok := coreIsToKeyID(script); ok {
		out := make([]byte, 21)
		out[0] = coreScriptP2PKH
		copy(out[1:], hash)
		return out, true
	}
	if hash, ok := coreIsToScriptID(script); ok {
		out := make([]byte, 21)
		out[0] = coreScriptP2SH
		copy(out[1:], hash)
		return out, true
	}
	if pubkey, ok := coreIsToPubKey(script); ok {
		out := make([]byte, 33)
		switch pubkey[0] {
		case 0x02, 0x03:
			// Already compressed: prefix is parity.
			out[0] = pubkey[0]
			copy(out[1:], pubkey[1:33])
			return out, true
		case 0x04:
			// Uncompressed: tag = 0x04 | (Y_lsb).
			// pubkey[64] is the last byte of Y; its low bit gives parity.
			out[0] = 0x04 | (pubkey[64] & 0x01)
			copy(out[1:], pubkey[1:33])
			return out, true
		}
	}
	return nil, false
}

// coreSpecialScriptSize returns the on-disk byte length of a tagged
// special script (i.e. how many bytes follow nSize when nSize is in
// 0..5).  Mirrors GetSpecialScriptSize() in compressor.cpp.
func coreSpecialScriptSize(nSize uint64) int {
	if nSize == 0 || nSize == 1 {
		return 20
	}
	if nSize >= 2 && nSize <= 5 {
		return 32
	}
	return 0
}

// CoreDecompressScript reconstructs the original script from a special-tag
// encoding (nSize in 0..5) and the body bytes.  Mirrors
// DecompressScript() in compressor.cpp.  For 0x04/0x05 (uncompressed
// pubkeys) we use libsecp256k1 to recover the full Y coordinate.
func CoreDecompressScript(nSize uint64, body []byte) ([]byte, error) {
	switch nSize {
	case 0x00:
		if len(body) != 20 {
			return nil, fmt.Errorf("P2PKH body len %d != 20", len(body))
		}
		out := make([]byte, 25)
		out[0] = 0x76 // OP_DUP
		out[1] = 0xa9 // OP_HASH160
		out[2] = 0x14
		copy(out[3:23], body)
		out[23] = 0x88 // OP_EQUALVERIFY
		out[24] = 0xac // OP_CHECKSIG
		return out, nil
	case 0x01:
		if len(body) != 20 {
			return nil, fmt.Errorf("P2SH body len %d != 20", len(body))
		}
		out := make([]byte, 23)
		out[0] = 0xa9 // OP_HASH160
		out[1] = 0x14
		copy(out[2:22], body)
		out[22] = 0x87 // OP_EQUAL
		return out, nil
	case 0x02, 0x03:
		// Already-compressed P2PK.
		if len(body) != 32 {
			return nil, fmt.Errorf("P2PK body len %d != 32", len(body))
		}
		out := make([]byte, 35)
		out[0] = 33
		out[1] = byte(nSize)
		copy(out[2:34], body)
		out[34] = 0xac
		return out, nil
	case 0x04, 0x05:
		// Uncompressed P2PK: rebuild the 33-byte compressed form, parse
		// it through secp256k1 to recover Y, then serialize uncompressed.
		if len(body) != 32 {
			return nil, fmt.Errorf("P2PK uncompressed body len %d != 32", len(body))
		}
		var compressed [33]byte
		compressed[0] = byte(nSize) - 2 // 0x04→0x02, 0x05→0x03
		copy(compressed[1:], body)
		pub, err := secp256k1.ParsePubKey(compressed[:])
		if err != nil {
			return nil, fmt.Errorf("decompress P2PK: %w", err)
		}
		uncompressed := pub.SerializeUncompressed()
		if len(uncompressed) != 65 {
			return nil, fmt.Errorf("SerializeUncompressed returned %d bytes", len(uncompressed))
		}
		out := make([]byte, 67)
		out[0] = 65
		copy(out[1:66], uncompressed)
		out[66] = 0xac
		return out, nil
	}
	return nil, fmt.Errorf("unknown special script tag %d", nSize)
}

// CompressAmount mirrors bitcoin-core/src/compressor.cpp CompressAmount().
//
// Encoding:
//   0  →  0
//   else: divide n by the largest power-of-10 e (max 9) such that the
//         result is still an integer.  If e<9, the trailing digit d∈[1,9],
//         drop it (n /= 10) and return 1 + 10*(9*n + d - 1) + e.  If e==9,
//         return 1 + 10*(n-1) + 9.
//
// Decodable because d ∈ [1..9] and e ∈ [0..9].
func CompressAmount(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	e := uint64(0)
	for (n%10) == 0 && e < 9 {
		n /= 10
		e++
	}
	if e < 9 {
		d := n % 10
		// d ∈ [1..9] by construction
		n /= 10
		return 1 + (n*9+d-1)*10 + e
	}
	return 1 + (n-1)*10 + 9
}

// DecompressAmount reverses CompressAmount.
func DecompressAmount(x uint64) uint64 {
	if x == 0 {
		return 0
	}
	x--
	e := x % 10
	x /= 10
	var n uint64
	if e < 9 {
		d := (x % 9) + 1
		x /= 9
		n = x*10 + d
	} else {
		n = x + 1
	}
	for e > 0 {
		n *= 10
		e--
	}
	return n
}

// WriteCoreVarInt writes a Bitcoin Core "VarInt" (the 7-bits-per-byte,
// big-endian-with-MSB-continuation encoding from serialize.h, NOT the
// "CompactSize" used on the wire).  Used inside snapshots for code,
// amount, and script-size fields.
func WriteCoreVarInt(w io.Writer, n uint64) error {
	var tmp [10]byte
	length := 0
	value := n
	for {
		b := byte(value & 0x7F)
		if length > 0 {
			b |= 0x80
		}
		tmp[length] = b
		if value <= 0x7F {
			break
		}
		value = (value >> 7) - 1
		length++
		if length >= len(tmp) {
			return errors.New("VarInt overflow")
		}
	}
	// Emit in reverse: MSB first, LSB last (Core writes tmp[len] down to 0).
	for i := length; i >= 0; i-- {
		if _, err := w.Write([]byte{tmp[i]}); err != nil {
			return err
		}
	}
	return nil
}

// ReadCoreVarInt reads a Core VarInt from r.
func ReadCoreVarInt(r io.Reader) (uint64, error) {
	var n uint64
	var buf [1]byte
	for i := 0; i < 10; i++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		// Overflow guard: matches Core's check.
		if n > (^uint64(0) >> 7) {
			return 0, errors.New("ReadVarInt: size too large")
		}
		n = (n << 7) | uint64(buf[0]&0x7F)
		if buf[0]&0x80 != 0 {
			if n == ^uint64(0) {
				return 0, errors.New("ReadVarInt: size too large")
			}
			n++
		} else {
			return n, nil
		}
	}
	return 0, errors.New("ReadVarInt: input too long")
}

// CoreSerializeCoin writes a single Coin (height, coinbase, amount, script)
// in Bitcoin Core's exact byte layout:
//   VARINT(code = (height<<1) | coinbase)
//   VARINT(CompressAmount(amount))
//   ScriptCompression: either CoreCompressScript (0x00..0x05 + 20/32 body)
//                      or VARINT(scriptSize + 6) + raw script bytes.
//
// Mirrors Coin::Serialize() + TxOutCompression in compressor.h.
func CoreSerializeCoin(w io.Writer, entry *UTXOEntry) error {
	code := (uint64(entry.Height) << 1)
	if entry.IsCoinbase {
		code |= 1
	}
	if err := WriteCoreVarInt(w, code); err != nil {
		return err
	}
	if entry.Amount < 0 {
		return fmt.Errorf("negative amount %d", entry.Amount)
	}
	if err := WriteCoreVarInt(w, CompressAmount(uint64(entry.Amount))); err != nil {
		return err
	}
	// Script: try special-form compression; on miss, write
	// VARINT(size + 6) + raw bytes.
	if compressed, ok := CoreCompressScript(entry.PkScript); ok {
		// In Core's ScriptCompression::Ser the compressed prevector is
		// written via Span(compr) — meaning: just the bytes, NO length
		// prefix, because Unser dispatches on nSize.  The first byte
		// of `compressed` IS the nSize tag (0x00..0x05).
		if _, err := w.Write(compressed); err != nil {
			return err
		}
		return nil
	}
	// Raw fallback path.
	size := uint64(len(entry.PkScript)) + coreNSpecialScripts
	if err := WriteCoreVarInt(w, size); err != nil {
		return err
	}
	if _, err := w.Write(entry.PkScript); err != nil {
		return err
	}
	return nil
}

// MaxCoreSnapshotScriptSize bounds the raw script body we'll accept on
// snapshot read.  Mirrors Core's MAX_SCRIPT_SIZE (10000) — anything longer
// is replaced with OP_RETURN by Core's ScriptCompression::Unser.  We
// follow the same policy: silently swap an over-large body for a
// 1-byte OP_RETURN script and skip past the remaining bytes.
const MaxCoreSnapshotScriptSize = 10000

// CoreDeserializeCoin reverses CoreSerializeCoin and returns a populated
// UTXOEntry.
func CoreDeserializeCoin(r io.Reader) (*UTXOEntry, error) {
	code, err := ReadCoreVarInt(r)
	if err != nil {
		return nil, fmt.Errorf("read code: %w", err)
	}
	height := int32(code >> 1)
	isCoinbase := (code & 1) == 1

	compressedAmount, err := ReadCoreVarInt(r)
	if err != nil {
		return nil, fmt.Errorf("read amount: %w", err)
	}
	amount := DecompressAmount(compressedAmount)
	if amount > uint64(MaxMoney) {
		return nil, fmt.Errorf("decompressed amount %d > MaxMoney", amount)
	}

	nSize, err := ReadCoreVarInt(r)
	if err != nil {
		return nil, fmt.Errorf("read script size: %w", err)
	}
	var script []byte
	if nSize < coreNSpecialScripts {
		// Special-tag path. Read the fixed-size body.
		bodyLen := coreSpecialScriptSize(nSize)
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, fmt.Errorf("read special body: %w", err)
		}
		script, err = CoreDecompressScript(nSize, body)
		if err != nil {
			return nil, err
		}
	} else {
		raw := nSize - coreNSpecialScripts
		if raw > MaxCoreSnapshotScriptSize {
			// Match Core: replace with OP_RETURN, skip the bytes.
			script = []byte{0x6a} // OP_RETURN
			if _, err := io.CopyN(io.Discard, r, int64(raw)); err != nil {
				return nil, fmt.Errorf("skip oversized script: %w", err)
			}
		} else {
			script = make([]byte, raw)
			if _, err := io.ReadFull(r, script); err != nil {
				return nil, fmt.Errorf("read raw script: %w", err)
			}
		}
	}
	return &UTXOEntry{
		Amount:     int64(amount),
		PkScript:   script,
		Height:     height,
		IsCoinbase: isCoinbase,
	}, nil
}
