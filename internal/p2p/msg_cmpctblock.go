package p2p

import (
	"encoding/binary"
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// MsgCmpctBlock is the "cmpctblock" message (BIP152) containing a compact block.
type MsgCmpctBlock struct {
	Header       wire.BlockHeader
	Nonce        uint64
	ShortIDs     []uint64 // 6-byte short transaction IDs (stored in uint64)
	PrefilledTxs []PrefilledTx
}

// PrefilledTx is a prefilled transaction in a compact block.
type PrefilledTx struct {
	Index uint32       // Differentially encoded index
	Tx    *wire.MsgTx
}

// Command returns the protocol command string for the message.
func (m *MsgCmpctBlock) Command() string { return "cmpctblock" }

// Serialize writes the cmpctblock message to w.
func (m *MsgCmpctBlock) Serialize(w io.Writer) error {
	if err := m.Header.Serialize(w); err != nil {
		return err
	}
	if err := wire.WriteUint64LE(w, m.Nonce); err != nil {
		return err
	}

	// Short IDs count
	if err := wire.WriteCompactSize(w, uint64(len(m.ShortIDs))); err != nil {
		return err
	}
	// Each short ID is 6 bytes (48 bits)
	for _, sid := range m.ShortIDs {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], sid)
		if _, err := w.Write(buf[:6]); err != nil {
			return err
		}
	}

	// Prefilled transactions
	if err := wire.WriteCompactSize(w, uint64(len(m.PrefilledTxs))); err != nil {
		return err
	}
	for _, ptx := range m.PrefilledTxs {
		if err := wire.WriteCompactSize(w, uint64(ptx.Index)); err != nil {
			return err
		}
		if err := ptx.Tx.Serialize(w); err != nil {
			return err
		}
	}

	return nil
}

// Deserialize reads the cmpctblock message from r.
func (m *MsgCmpctBlock) Deserialize(r io.Reader) error {
	if err := m.Header.Deserialize(r); err != nil {
		return err
	}
	var err error
	m.Nonce, err = wire.ReadUint64LE(r)
	if err != nil {
		return err
	}

	// Short IDs
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxInvVects {
		return ErrTooManyInvVects
	}
	m.ShortIDs = make([]uint64, count)
	for i := range m.ShortIDs {
		var buf [8]byte
		if _, err := io.ReadFull(r, buf[:6]); err != nil {
			return err
		}
		m.ShortIDs[i] = binary.LittleEndian.Uint64(buf[:])
	}

	// Prefilled transactions
	prefilledCount, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if prefilledCount > MaxInvVects {
		return ErrTooManyInvVects
	}
	m.PrefilledTxs = make([]PrefilledTx, prefilledCount)
	for i := range m.PrefilledTxs {
		idx, err := wire.ReadCompactSize(r)
		if err != nil {
			return err
		}
		m.PrefilledTxs[i].Index = uint32(idx)
		m.PrefilledTxs[i].Tx = &wire.MsgTx{}
		if err := m.PrefilledTxs[i].Tx.Deserialize(r); err != nil {
			return err
		}
	}

	return nil
}

// MsgGetBlockTxn is the "getblocktxn" message requesting missing transactions
// for compact block reconstruction.
type MsgGetBlockTxn struct {
	BlockHash wire.Hash256
	Indexes   []uint32 // Differentially encoded transaction indexes
}

// Command returns the protocol command string for the message.
func (m *MsgGetBlockTxn) Command() string { return "getblocktxn" }

// Serialize writes the getblocktxn message to w.
func (m *MsgGetBlockTxn) Serialize(w io.Writer) error {
	if err := m.BlockHash.Serialize(w); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, uint64(len(m.Indexes))); err != nil {
		return err
	}
	for _, idx := range m.Indexes {
		if err := wire.WriteCompactSize(w, uint64(idx)); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the getblocktxn message from r.
func (m *MsgGetBlockTxn) Deserialize(r io.Reader) error {
	if err := m.BlockHash.Deserialize(r); err != nil {
		return err
	}
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxInvVects {
		return ErrTooManyInvVects
	}
	m.Indexes = make([]uint32, count)
	for i := range m.Indexes {
		idx, err := wire.ReadCompactSize(r)
		if err != nil {
			return err
		}
		m.Indexes[i] = uint32(idx)
	}
	return nil
}

// MsgBlockTxn is the "blocktxn" message containing missing transactions
// for compact block reconstruction.
type MsgBlockTxn struct {
	BlockHash wire.Hash256
	Txs       []*wire.MsgTx
}

// Command returns the protocol command string for the message.
func (m *MsgBlockTxn) Command() string { return "blocktxn" }

// Serialize writes the blocktxn message to w.
func (m *MsgBlockTxn) Serialize(w io.Writer) error {
	if err := m.BlockHash.Serialize(w); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, uint64(len(m.Txs))); err != nil {
		return err
	}
	for _, tx := range m.Txs {
		if err := tx.Serialize(w); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the blocktxn message from r.
func (m *MsgBlockTxn) Deserialize(r io.Reader) error {
	if err := m.BlockHash.Deserialize(r); err != nil {
		return err
	}
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxInvVects {
		return ErrTooManyInvVects
	}
	m.Txs = make([]*wire.MsgTx, count)
	for i := range m.Txs {
		m.Txs[i] = &wire.MsgTx{}
		if err := m.Txs[i].Deserialize(r); err != nil {
			return err
		}
	}
	return nil
}
