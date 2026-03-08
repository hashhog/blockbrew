package p2p

import (
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// InvType identifies the type of inventory data.
type InvType uint32

// Inventory vector type constants.
const (
	InvTypeError         InvType = 0
	InvTypeTx            InvType = 1
	InvTypeBlock         InvType = 2
	InvTypeFilteredBlock InvType = 3
	InvTypeWitnessTx     InvType = 0x40000001 // MSG_WITNESS_TX
	InvTypeWitnessBlock  InvType = 0x40000002 // MSG_WITNESS_BLOCK
)

// InvWitnessFlag is the flag to OR with a type to request witness data.
const InvWitnessFlag InvType = 0x40000000

// InvVect represents an inventory vector.
type InvVect struct {
	Type InvType
	Hash wire.Hash256
}

// Serialize writes the inventory vector to w.
func (iv *InvVect) Serialize(w io.Writer) error {
	if err := wire.WriteUint32LE(w, uint32(iv.Type)); err != nil {
		return err
	}
	return iv.Hash.Serialize(w)
}

// Deserialize reads the inventory vector from r.
func (iv *InvVect) Deserialize(r io.Reader) error {
	t, err := wire.ReadUint32LE(r)
	if err != nil {
		return err
	}
	iv.Type = InvType(t)
	return iv.Hash.Deserialize(r)
}

// MsgInv is the "inv" message advertising known data.
type MsgInv struct {
	InvList []*InvVect
}

// Command returns the protocol command string for the message.
func (m *MsgInv) Command() string { return "inv" }

// Serialize writes the inv message to w.
func (m *MsgInv) Serialize(w io.Writer) error {
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

// Deserialize reads the inv message from r.
func (m *MsgInv) Deserialize(r io.Reader) error {
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
func (m *MsgInv) AddInvVect(iv *InvVect) error {
	if len(m.InvList) >= MaxInvVects {
		return ErrTooManyInvVects
	}
	m.InvList = append(m.InvList, iv)
	return nil
}
