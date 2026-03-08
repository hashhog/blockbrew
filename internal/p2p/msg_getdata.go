package p2p

import (
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// MsgGetData is the "getdata" message requesting specific data.
type MsgGetData struct {
	InvList []*InvVect
}

// Command returns the protocol command string for the message.
func (m *MsgGetData) Command() string { return "getdata" }

// Serialize writes the getdata message to w.
func (m *MsgGetData) Serialize(w io.Writer) error {
	if err := wire.WriteCompactSize(w, uint64(len(m.InvList))); err != nil {
		return err
	}
	for _, iv := range m.InvList {
		if err := iv.Serialize(w); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the getdata message from r.
func (m *MsgGetData) Deserialize(r io.Reader) error {
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxInvVects {
		return ErrTooManyInvVects
	}
	m.InvList = make([]*InvVect, count)
	for i := range m.InvList {
		m.InvList[i] = &InvVect{}
		if err := m.InvList[i].Deserialize(r); err != nil {
			return err
		}
	}
	return nil
}

// AddInvVect adds an inventory vector to the message.
func (m *MsgGetData) AddInvVect(iv *InvVect) error {
	if len(m.InvList) >= MaxInvVects {
		return ErrTooManyInvVects
	}
	m.InvList = append(m.InvList, iv)
	return nil
}
