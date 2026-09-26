package p2p

import (
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// MsgTx is the "tx" message containing a transaction.
type MsgTx struct {
	Tx *wire.MsgTx
	// NoWitness serializes the transaction without witness data. Set when
	// answering a getdata(MSG_TX) (no witness flag), as Bitcoin Core does
	// (ProcessGetData: inv.IsMsgTx() ? TX_NO_WITNESS : TX_WITH_WITNESS).
	NoWitness bool
}

// Command returns the protocol command string for the message.
func (m *MsgTx) Command() string { return "tx" }

// Serialize writes the transaction message to w.
func (m *MsgTx) Serialize(w io.Writer) error {
	if m.Tx == nil {
		m.Tx = &wire.MsgTx{}
	}
	if m.NoWitness {
		return m.Tx.SerializeNoWitness(w)
	}
	return m.Tx.Serialize(w)
}

// Deserialize reads the transaction message from r.
func (m *MsgTx) Deserialize(r io.Reader) error {
	m.Tx = &wire.MsgTx{}
	return m.Tx.Deserialize(r)
}
