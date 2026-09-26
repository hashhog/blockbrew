package p2p

import (
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// MsgBlock is the "block" message containing a full block.
type MsgBlock struct {
	Block *wire.MsgBlock
	// NoWitness serializes every transaction without witness data. Set when
	// answering a getdata(MSG_BLOCK) (no witness flag): Bitcoin Core
	// ProcessGetBlockData sends TX_NO_WITNESS for MSG_BLOCK, so a pre-segwit
	// peer (e.g. version 70002) receives a block it can parse.
	NoWitness bool
}

// Command returns the protocol command string for the message.
func (m *MsgBlock) Command() string { return "block" }

// Serialize writes the block message to w.
func (m *MsgBlock) Serialize(w io.Writer) error {
	if m.Block == nil {
		m.Block = &wire.MsgBlock{}
	}
	if !m.NoWitness {
		return m.Block.Serialize(w)
	}
	if err := m.Block.Header.Serialize(w); err != nil {
		return err
	}
	if err := wire.WriteCompactSize(w, uint64(len(m.Block.Transactions))); err != nil {
		return err
	}
	for _, tx := range m.Block.Transactions {
		if err := tx.SerializeNoWitness(w); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the block message from r.
func (m *MsgBlock) Deserialize(r io.Reader) error {
	m.Block = &wire.MsgBlock{}
	return m.Block.Deserialize(r)
}
