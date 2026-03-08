package p2p

import (
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// MsgGetHeaders is the "getheaders" message for requesting block headers.
type MsgGetHeaders struct {
	ProtocolVersion uint32
	BlockLocators   []wire.Hash256 // Up to 101 block hashes
	HashStop        wire.Hash256   // Stop hash (zero = get as many as possible)
}

// Command returns the protocol command string for the message.
func (m *MsgGetHeaders) Command() string { return "getheaders" }

// Serialize writes the getheaders message to w.
func (m *MsgGetHeaders) Serialize(w io.Writer) error {
	if err := wire.WriteUint32LE(w, m.ProtocolVersion); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, uint64(len(m.BlockLocators))); err != nil {
		return err
	}
	for _, hash := range m.BlockLocators {
		if err := hash.Serialize(w); err != nil {
			return err
		}
	}
	return m.HashStop.Serialize(w)
}

// Deserialize reads the getheaders message from r.
func (m *MsgGetHeaders) Deserialize(r io.Reader) error {
	var err error
	m.ProtocolVersion, err = wire.ReadUint32LE(r)
	if err != nil {
		return err
	}
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxBlockLocators {
		return ErrTooManyLocators
	}
	m.BlockLocators = make([]wire.Hash256, count)
	for i := range m.BlockLocators {
		if err := m.BlockLocators[i].Deserialize(r); err != nil {
			return err
		}
	}
	return m.HashStop.Deserialize(r)
}

// AddBlockLocator adds a block locator hash to the message.
func (m *MsgGetHeaders) AddBlockLocator(hash wire.Hash256) error {
	if len(m.BlockLocators) >= MaxBlockLocators {
		return ErrTooManyLocators
	}
	m.BlockLocators = append(m.BlockLocators, hash)
	return nil
}
