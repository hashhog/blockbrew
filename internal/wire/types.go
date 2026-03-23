package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Serializable is the interface for types that can be serialized to and from
// the Bitcoin wire format.
type Serializable interface {
	Serialize(w io.Writer) error
	Deserialize(r io.Reader) error
}

// Hash256 is a 32-byte double-SHA256 hash.
type Hash256 [32]byte

// String returns the hash as a reversed hex string (Bitcoin display order).
func (h Hash256) String() string {
	// Reverse the bytes for display
	var reversed [32]byte
	for i := 0; i < 32; i++ {
		reversed[i] = h[31-i]
	}
	return hex.EncodeToString(reversed[:])
}

// IsZero returns true if the hash is all zeros.
func (h Hash256) IsZero() bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

// SetBytes sets the hash from a byte slice.
func (h *Hash256) SetBytes(b []byte) {
	copy(h[:], b)
}

// NewHash256FromHex creates a Hash256 from a reversed hex string (display order).
func NewHash256FromHex(s string) (Hash256, error) {
	var h Hash256
	if len(s) != 64 {
		return h, fmt.Errorf("invalid hash length: got %d, want 64", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, err
	}
	// Reverse the bytes from display order to internal order
	for i := 0; i < 32; i++ {
		h[i] = b[31-i]
	}
	return h, nil
}

// Serialize writes the hash to the writer in raw byte order.
func (h *Hash256) Serialize(w io.Writer) error {
	return WriteBytes(w, h[:])
}

// Deserialize reads the hash from the reader in raw byte order.
func (h *Hash256) Deserialize(r io.Reader) error {
	b, err := ReadBytes(r, 32)
	if err != nil {
		return err
	}
	copy(h[:], b)
	return nil
}

// DoubleHashB computes SHA256(SHA256(b)) and returns the result as a Hash256.
func DoubleHashB(b []byte) Hash256 {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	var h Hash256
	copy(h[:], second[:])
	return h
}

// OutPoint identifies a particular transaction output.
type OutPoint struct {
	Hash  Hash256
	Index uint32
}

// Serialize writes the outpoint to the writer.
func (op *OutPoint) Serialize(w io.Writer) error {
	if err := op.Hash.Serialize(w); err != nil {
		return err
	}
	return WriteUint32LE(w, op.Index)
}

// Deserialize reads the outpoint from the reader.
func (op *OutPoint) Deserialize(r io.Reader) error {
	if err := op.Hash.Deserialize(r); err != nil {
		return err
	}
	var err error
	op.Index, err = ReadUint32LE(r)
	return err
}

// TxIn represents a transaction input.
type TxIn struct {
	PreviousOutPoint OutPoint
	SignatureScript  []byte
	Witness          [][]byte
	Sequence         uint32
}

// serializeWithoutWitness writes the input without witness data.
func (ti *TxIn) serializeWithoutWitness(w io.Writer) error {
	if err := ti.PreviousOutPoint.Serialize(w); err != nil {
		return err
	}
	if err := WriteVarBytes(w, ti.SignatureScript); err != nil {
		return err
	}
	return WriteUint32LE(w, ti.Sequence)
}

// Serialize writes the input to the writer (without witness).
func (ti *TxIn) Serialize(w io.Writer) error {
	return ti.serializeWithoutWitness(w)
}

// Deserialize reads the input from the reader (without witness).
func (ti *TxIn) Deserialize(r io.Reader) error {
	if err := ti.PreviousOutPoint.Deserialize(r); err != nil {
		return err
	}
	var err error
	// scriptSig size limit during deserialization: use MaxCompactSize (32 MB).
	// The consensus MAX_SCRIPT_SIZE (10,000) is enforced during script evaluation,
	// NOT during deserialization. A valid block can contain scriptSigs larger than
	// 10KB (e.g. large P2SH redeemscripts, legacy multisig). Using a tight limit
	// here causes "compact size too large" errors and makes the node unable to
	// deserialize valid blocks.
	ti.SignatureScript, err = ReadVarBytes(r, MaxCompactSize)
	if err != nil {
		return err
	}
	ti.Sequence, err = ReadUint32LE(r)
	return err
}

// TxOut represents a transaction output.
type TxOut struct {
	Value    int64  // In satoshis
	PkScript []byte
}

// Serialize writes the output to the writer.
func (to *TxOut) Serialize(w io.Writer) error {
	if err := WriteInt64LE(w, to.Value); err != nil {
		return err
	}
	return WriteVarBytes(w, to.PkScript)
}

// Deserialize reads the output from the reader.
func (to *TxOut) Deserialize(r io.Reader) error {
	var err error
	to.Value, err = ReadInt64LE(r)
	if err != nil {
		return err
	}
	// pkScript size limit during deserialization: use MaxCompactSize (32 MB).
	// Like scriptSig, the consensus MAX_SCRIPT_SIZE is checked during evaluation.
	// Deserialization must accept whatever is in the block.
	to.PkScript, err = ReadVarBytes(r, MaxCompactSize)
	return err
}

// MsgTx represents a full Bitcoin transaction.
type MsgTx struct {
	Version  int32
	TxIn     []*TxIn
	TxOut    []*TxOut
	LockTime uint32
}

// HasWitness returns true if any input has non-empty witness data.
func (tx *MsgTx) HasWitness() bool {
	for _, in := range tx.TxIn {
		if len(in.Witness) > 0 {
			return true
		}
	}
	return false
}

// Serialize writes the transaction to the writer using BIP144 segwit format
// if the transaction has witness data.
func (tx *MsgTx) Serialize(w io.Writer) error {
	return tx.serialize(w, tx.HasWitness())
}

// SerializeNoWitness writes the transaction without witness data (for txid).
func (tx *MsgTx) SerializeNoWitness(w io.Writer) error {
	return tx.serialize(w, false)
}

func (tx *MsgTx) serialize(w io.Writer, withWitness bool) error {
	if err := WriteInt32LE(w, tx.Version); err != nil {
		return err
	}

	if withWitness {
		// Write marker and flag bytes for segwit
		if err := WriteUint8(w, 0x00); err != nil {
			return err
		}
		if err := WriteUint8(w, 0x01); err != nil {
			return err
		}
	}

	// Write inputs
	if err := WriteCompactSize(w, uint64(len(tx.TxIn))); err != nil {
		return err
	}
	for _, in := range tx.TxIn {
		if err := in.serializeWithoutWitness(w); err != nil {
			return err
		}
	}

	// Write outputs
	if err := WriteCompactSize(w, uint64(len(tx.TxOut))); err != nil {
		return err
	}
	for _, out := range tx.TxOut {
		if err := out.Serialize(w); err != nil {
			return err
		}
	}

	// Write witness data if present
	if withWitness {
		for _, in := range tx.TxIn {
			if err := WriteCompactSize(w, uint64(len(in.Witness))); err != nil {
				return err
			}
			for _, item := range in.Witness {
				if err := WriteVarBytes(w, item); err != nil {
					return err
				}
			}
		}
	}

	return WriteUint32LE(w, tx.LockTime)
}

// ErrUnexpectedWitness is returned when witness data is found in a non-segwit transaction.
var ErrUnexpectedWitness = errors.New("unexpected witness data")

// Deserialize reads the transaction from the reader, handling both legacy
// and BIP144 segwit formats.
func (tx *MsgTx) Deserialize(r io.Reader) error {
	var err error
	tx.Version, err = ReadInt32LE(r)
	if err != nil {
		return err
	}

	// Read input count or marker
	marker, err := ReadUint8(r)
	if err != nil {
		return err
	}

	var hasWitness bool
	var inputCount uint64

	if marker == 0x00 {
		// This might be a segwit transaction, read flag
		flag, err := ReadUint8(r)
		if err != nil {
			return err
		}
		if flag != 0x01 {
			return ErrUnexpectedWitness
		}
		hasWitness = true

		// Now read the actual input count
		inputCount, err = ReadCompactSize(r)
		if err != nil {
			return err
		}
	} else {
		// Legacy format: marker was actually the first byte of input count
		// We need to handle CompactSize properly
		if marker < 0xFD {
			inputCount = uint64(marker)
		} else if marker == 0xFD {
			v, err := ReadUint16LE(r)
			if err != nil {
				return err
			}
			inputCount = uint64(v)
		} else if marker == 0xFE {
			v, err := ReadUint32LE(r)
			if err != nil {
				return err
			}
			inputCount = uint64(v)
		} else {
			v, err := ReadUint64LE(r)
			if err != nil {
				return err
			}
			inputCount = v
		}
	}

	// Read inputs
	tx.TxIn = make([]*TxIn, inputCount)
	for i := range tx.TxIn {
		tx.TxIn[i] = &TxIn{}
		if err := tx.TxIn[i].Deserialize(r); err != nil {
			return err
		}
	}

	// Read outputs
	outputCount, err := ReadCompactSize(r)
	if err != nil {
		return err
	}
	tx.TxOut = make([]*TxOut, outputCount)
	for i := range tx.TxOut {
		tx.TxOut[i] = &TxOut{}
		if err := tx.TxOut[i].Deserialize(r); err != nil {
			return err
		}
	}

	// Read witness data if present
	if hasWitness {
		for _, in := range tx.TxIn {
			witnessCount, err := ReadCompactSize(r)
			if err != nil {
				return err
			}
			in.Witness = make([][]byte, witnessCount)
			for j := range in.Witness {
				// Witness items have no per-item consensus size limit beyond the
				// block weight limit (4M WU). Taproot scripts, inscriptions, and
				// other witness data can be very large. Use MaxCompactSize (32 MB)
				// as a safe upper bound to avoid rejecting valid blocks.
				in.Witness[j], err = ReadVarBytes(r, MaxCompactSize)
				if err != nil {
					return err
				}
			}
		}
	}

	tx.LockTime, err = ReadUint32LE(r)
	return err
}

// TxHash computes the transaction hash (txid) without witness data.
func (tx *MsgTx) TxHash() Hash256 {
	var buf []byte
	w := &sliceWriter{buf: &buf}
	tx.SerializeNoWitness(w)
	return DoubleHashB(buf)
}

// WTxHash computes the witness transaction hash (wtxid).
// For transactions without witness, this equals TxHash.
func (tx *MsgTx) WTxHash() Hash256 {
	var buf []byte
	w := &sliceWriter{buf: &buf}
	tx.Serialize(w)
	return DoubleHashB(buf)
}

// sliceWriter is a simple io.Writer that appends to a byte slice.
type sliceWriter struct {
	buf *[]byte
}

func (sw *sliceWriter) Write(p []byte) (int, error) {
	*sw.buf = append(*sw.buf, p...)
	return len(p), nil
}

// BlockHeader represents a Bitcoin block header (80 bytes).
type BlockHeader struct {
	Version    int32
	PrevBlock  Hash256
	MerkleRoot Hash256
	Timestamp  uint32
	Bits       uint32
	Nonce      uint32
}

// Serialize writes the 80-byte block header to the writer.
func (h *BlockHeader) Serialize(w io.Writer) error {
	if err := WriteInt32LE(w, h.Version); err != nil {
		return err
	}
	if err := h.PrevBlock.Serialize(w); err != nil {
		return err
	}
	if err := h.MerkleRoot.Serialize(w); err != nil {
		return err
	}
	if err := WriteUint32LE(w, h.Timestamp); err != nil {
		return err
	}
	if err := WriteUint32LE(w, h.Bits); err != nil {
		return err
	}
	return WriteUint32LE(w, h.Nonce)
}

// Deserialize reads the 80-byte block header from the reader.
func (h *BlockHeader) Deserialize(r io.Reader) error {
	var err error
	h.Version, err = ReadInt32LE(r)
	if err != nil {
		return err
	}
	if err := h.PrevBlock.Deserialize(r); err != nil {
		return err
	}
	if err := h.MerkleRoot.Deserialize(r); err != nil {
		return err
	}
	h.Timestamp, err = ReadUint32LE(r)
	if err != nil {
		return err
	}
	h.Bits, err = ReadUint32LE(r)
	if err != nil {
		return err
	}
	h.Nonce, err = ReadUint32LE(r)
	return err
}

// BlockHash computes the double-SHA256 hash of the block header.
func (h *BlockHeader) BlockHash() Hash256 {
	var buf [80]byte
	w := &fixedWriter{buf: buf[:]}
	h.Serialize(w)
	return DoubleHashB(buf[:])
}

// fixedWriter is a simple io.Writer that writes to a fixed-size buffer.
type fixedWriter struct {
	buf []byte
	off int
}

func (fw *fixedWriter) Write(p []byte) (int, error) {
	n := copy(fw.buf[fw.off:], p)
	fw.off += n
	return n, nil
}

// MsgBlock represents a full Bitcoin block.
type MsgBlock struct {
	Header       BlockHeader
	Transactions []*MsgTx
}

// Serialize writes the block to the writer.
func (b *MsgBlock) Serialize(w io.Writer) error {
	if err := b.Header.Serialize(w); err != nil {
		return err
	}
	if err := WriteCompactSize(w, uint64(len(b.Transactions))); err != nil {
		return err
	}
	for _, tx := range b.Transactions {
		if err := tx.Serialize(w); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the block from the reader.
func (b *MsgBlock) Deserialize(r io.Reader) error {
	if err := b.Header.Deserialize(r); err != nil {
		return err
	}
	txCount, err := ReadCompactSize(r)
	if err != nil {
		return err
	}
	b.Transactions = make([]*MsgTx, txCount)
	for i := range b.Transactions {
		b.Transactions[i] = &MsgTx{}
		if err := b.Transactions[i].Deserialize(r); err != nil {
			return err
		}
	}
	return nil
}
