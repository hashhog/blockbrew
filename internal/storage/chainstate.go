package storage

import (
	"bytes"
	"errors"
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// SpentCoin stores a UTXO that was spent by a transaction input.
// This is saved as part of undo data so the UTXO can be restored during reorgs.
type SpentCoin struct {
	TxOut    wire.TxOut // The output being spent (value + pkScript)
	Height   int32      // Block height where this output was created
	Coinbase bool       // Whether the creating tx was a coinbase
}

// TxUndo stores all UTXOs spent by a single transaction's inputs.
type TxUndo struct {
	SpentCoins []SpentCoin // One per input of the transaction
}

// BlockUndo stores all undo data needed to disconnect a block.
// Contains one TxUndo per non-coinbase transaction in the block.
type BlockUndo struct {
	TxUndos []TxUndo // One per non-coinbase tx (coinbase has no inputs to undo)
}

// Serialize writes a SpentCoin to the given buffer.
// Format: heightCode (varint: height << 1 | coinbase) + TxOut
func (sc *SpentCoin) Serialize(w *bytes.Buffer) error {
	// Height and coinbase combined: height << 1 | coinbase
	heightCode := uint64(sc.Height) << 1
	if sc.Coinbase {
		heightCode |= 1
	}
	wire.WriteCompactSize(w, heightCode)

	// Write the TxOut (value + pkScript)
	return sc.TxOut.Serialize(w)
}

// DeserializeSpentCoin reads a SpentCoin from the reader.
func DeserializeSpentCoin(r io.Reader) (*SpentCoin, error) {
	// Read height and coinbase flag
	heightCode, err := wire.ReadCompactSize(r)
	if err != nil {
		return nil, err
	}

	sc := &SpentCoin{
		Height:   int32(heightCode >> 1),
		Coinbase: (heightCode & 1) == 1,
	}

	// Read TxOut
	if err := sc.TxOut.Deserialize(r); err != nil {
		return nil, err
	}

	return sc, nil
}

// Serialize writes a TxUndo to the given buffer.
func (tu *TxUndo) Serialize(w *bytes.Buffer) error {
	// Write number of spent coins
	wire.WriteCompactSize(w, uint64(len(tu.SpentCoins)))

	// Write each spent coin
	for i := range tu.SpentCoins {
		if err := tu.SpentCoins[i].Serialize(w); err != nil {
			return err
		}
	}
	return nil
}

// DeserializeTxUndo reads a TxUndo from the reader.
func DeserializeTxUndo(r io.Reader) (*TxUndo, error) {
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return nil, err
	}

	tu := &TxUndo{
		SpentCoins: make([]SpentCoin, count),
	}

	for i := uint64(0); i < count; i++ {
		sc, err := DeserializeSpentCoin(r)
		if err != nil {
			return nil, err
		}
		tu.SpentCoins[i] = *sc
	}

	return tu, nil
}

// Serialize writes a BlockUndo to bytes.
//
// New blobs are written in the v1 compressed format (see undo_compress.go):
// pkScript runs through compressScript and the 8-byte int64 amount becomes
// a varuint, trimming 40-60% off undo size for typical IBD blocks.  The
// blob's leading byte is undoTagCompressedV1 (0xFF) so the read path can
// dispatch back to the legacy decoder when older datadirs serve up
// uncompressed blobs.
func (bu *BlockUndo) Serialize() []byte {
	return serializeBlockUndoCompressed(bu)
}

// serializeBlockUndoLegacy writes a BlockUndo in the pre-compression wire
// format.  Used only by the test suite to hand-construct a legacy blob and
// confirm the dispatch in DeserializeBlockUndo still handles it.
func serializeBlockUndoLegacy(bu *BlockUndo) []byte {
	var buf bytes.Buffer

	// Write number of TxUndo entries
	wire.WriteCompactSize(&buf, uint64(len(bu.TxUndos)))

	// Write each TxUndo
	for i := range bu.TxUndos {
		bu.TxUndos[i].Serialize(&buf)
	}

	return buf.Bytes()
}

// DeserializeBlockUndo reads a BlockUndo from bytes.  Dispatches on the
// first byte: undoTagCompressedV1 (0xFF) → v1 compressed format,
// anything else → legacy uncompressed format.  The legacy format starts
// with a CompactSize TxUndo count and can never produce a 0xFF first
// byte for a valid block, so the dispatch is unambiguous (see comment
// at top of undo_compress.go).
func DeserializeBlockUndo(data []byte) (*BlockUndo, error) {
	if len(data) == 0 {
		return nil, errors.New("undo: empty blob")
	}

	if data[0] == undoTagCompressedV1 {
		return deserializeBlockUndoCompressed(bytes.NewReader(data[1:]))
	}

	// Legacy uncompressed path: blob starts directly with a CompactSize
	// TxUndo count.
	r := bytes.NewReader(data)

	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return nil, err
	}

	bu := &BlockUndo{
		TxUndos: make([]TxUndo, count),
	}

	for i := uint64(0); i < count; i++ {
		tu, err := DeserializeTxUndo(r)
		if err != nil {
			return nil, err
		}
		bu.TxUndos[i] = *tu
	}

	return bu, nil
}

// ChainState holds the persisted chain state.
type ChainState struct {
	BestHash   wire.Hash256
	BestHeight int32
}

// Serialize writes the chain state to a byte slice.
func (cs *ChainState) Serialize() []byte {
	buf := new(bytes.Buffer)
	cs.BestHash.Serialize(buf)
	wire.WriteInt32LE(buf, cs.BestHeight)
	return buf.Bytes()
}

// DeserializeChainState reads a chain state from a byte slice.
func DeserializeChainState(data []byte) (*ChainState, error) {
	if len(data) < 36 {
		return nil, errors.New("chain state data too short")
	}

	r := bytes.NewReader(data)
	cs := &ChainState{}

	if err := cs.BestHash.Deserialize(r); err != nil {
		return nil, err
	}

	var err error
	cs.BestHeight, err = wire.ReadInt32LE(r)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return cs, nil
}
