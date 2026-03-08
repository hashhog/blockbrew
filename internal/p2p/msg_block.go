package p2p

import (
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// MsgBlock is the "block" message containing a full block.
type MsgBlock struct {
	Block *wire.MsgBlock
}

// Command returns the protocol command string for the message.
func (m *MsgBlock) Command() string { return "block" }

// Serialize writes the block message to w.
func (m *MsgBlock) Serialize(w io.Writer) error {
	if m.Block == nil {
		m.Block = &wire.MsgBlock{}
	}
	return m.Block.Serialize(w)
}

// Deserialize reads the block message from r.
func (m *MsgBlock) Deserialize(r io.Reader) error {
	m.Block = &wire.MsgBlock{}
	return m.Block.Deserialize(r)
}
