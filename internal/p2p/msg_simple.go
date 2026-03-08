package p2p

import (
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// MsgVerAck is the "verack" message (empty payload).
type MsgVerAck struct{}

// Command returns the protocol command string for the message.
func (m *MsgVerAck) Command() string { return "verack" }

// Serialize writes the verack message to w (no payload).
func (m *MsgVerAck) Serialize(w io.Writer) error { return nil }

// Deserialize reads the verack message from r (no payload).
func (m *MsgVerAck) Deserialize(r io.Reader) error { return nil }

// MsgPing is the "ping" message containing a nonce.
type MsgPing struct {
	Nonce uint64
}

// Command returns the protocol command string for the message.
func (m *MsgPing) Command() string { return "ping" }

// Serialize writes the ping message to w.
func (m *MsgPing) Serialize(w io.Writer) error {
	return wire.WriteUint64LE(w, m.Nonce)
}

// Deserialize reads the ping message from r.
func (m *MsgPing) Deserialize(r io.Reader) error {
	var err error
	m.Nonce, err = wire.ReadUint64LE(r)
	return err
}

// MsgPong is the "pong" message containing the same nonce from ping.
type MsgPong struct {
	Nonce uint64
}

// Command returns the protocol command string for the message.
func (m *MsgPong) Command() string { return "pong" }

// Serialize writes the pong message to w.
func (m *MsgPong) Serialize(w io.Writer) error {
	return wire.WriteUint64LE(w, m.Nonce)
}

// Deserialize reads the pong message from r.
func (m *MsgPong) Deserialize(r io.Reader) error {
	var err error
	m.Nonce, err = wire.ReadUint64LE(r)
	return err
}

// MsgGetAddr is the "getaddr" message requesting peer addresses.
type MsgGetAddr struct{}

// Command returns the protocol command string for the message.
func (m *MsgGetAddr) Command() string { return "getaddr" }

// Serialize writes the getaddr message to w (no payload).
func (m *MsgGetAddr) Serialize(w io.Writer) error { return nil }

// Deserialize reads the getaddr message from r (no payload).
func (m *MsgGetAddr) Deserialize(r io.Reader) error { return nil }

// MsgAddr is the "addr" message containing a list of known peer addresses.
type MsgAddr struct {
	AddrList []NetAddress // Max 1,000 addresses
}

// Command returns the protocol command string for the message.
func (m *MsgAddr) Command() string { return "addr" }

// Serialize writes the addr message to w.
func (m *MsgAddr) Serialize(w io.Writer) error {
	if err := wire.WriteCompactSize(w, uint64(len(m.AddrList))); err != nil {
		return err
	}
	for _, addr := range m.AddrList {
		if err := addr.SerializeWithTimestamp(w); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the addr message from r.
func (m *MsgAddr) Deserialize(r io.Reader) error {
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxAddresses {
		return ErrTooManyAddresses
	}
	m.AddrList = make([]NetAddress, count)
	for i := range m.AddrList {
		if err := m.AddrList[i].DeserializeWithTimestamp(r); err != nil {
			return err
		}
	}
	return nil
}

// AddAddress adds an address to the message.
func (m *MsgAddr) AddAddress(addr NetAddress) error {
	if len(m.AddrList) >= MaxAddresses {
		return ErrTooManyAddresses
	}
	m.AddrList = append(m.AddrList, addr)
	return nil
}

// MsgSendHeaders is the "sendheaders" message (BIP130) requesting headers-first announcements.
type MsgSendHeaders struct{}

// Command returns the protocol command string for the message.
func (m *MsgSendHeaders) Command() string { return "sendheaders" }

// Serialize writes the sendheaders message to w (no payload).
func (m *MsgSendHeaders) Serialize(w io.Writer) error { return nil }

// Deserialize reads the sendheaders message from r (no payload).
func (m *MsgSendHeaders) Deserialize(r io.Reader) error { return nil }

// MsgSendCmpct is the "sendcmpct" message (BIP152) negotiating compact block relay.
type MsgSendCmpct struct {
	AnnounceUsingCmpctBlock bool
	CmpctBlockVersion       uint64
}

// Command returns the protocol command string for the message.
func (m *MsgSendCmpct) Command() string { return "sendcmpct" }

// Serialize writes the sendcmpct message to w.
func (m *MsgSendCmpct) Serialize(w io.Writer) error {
	var announce uint8
	if m.AnnounceUsingCmpctBlock {
		announce = 1
	}
	if err := wire.WriteUint8(w, announce); err != nil {
		return err
	}
	return wire.WriteUint64LE(w, m.CmpctBlockVersion)
}

// Deserialize reads the sendcmpct message from r.
func (m *MsgSendCmpct) Deserialize(r io.Reader) error {
	announce, err := wire.ReadUint8(r)
	if err != nil {
		return err
	}
	m.AnnounceUsingCmpctBlock = announce != 0
	m.CmpctBlockVersion, err = wire.ReadUint64LE(r)
	return err
}

// MsgFeeFilter is the "feefilter" message (BIP133) setting a minimum fee rate.
type MsgFeeFilter struct {
	MinFeeRate int64 // In satoshis per kB
}

// Command returns the protocol command string for the message.
func (m *MsgFeeFilter) Command() string { return "feefilter" }

// Serialize writes the feefilter message to w.
func (m *MsgFeeFilter) Serialize(w io.Writer) error {
	return wire.WriteInt64LE(w, m.MinFeeRate)
}

// Deserialize reads the feefilter message from r.
func (m *MsgFeeFilter) Deserialize(r io.Reader) error {
	var err error
	m.MinFeeRate, err = wire.ReadInt64LE(r)
	return err
}

// MsgNotFound is the "notfound" message indicating requested data was not found.
type MsgNotFound struct {
	InvList []*InvVect
}

// Command returns the protocol command string for the message.
func (m *MsgNotFound) Command() string { return "notfound" }

// Serialize writes the notfound message to w.
func (m *MsgNotFound) Serialize(w io.Writer) error {
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

// Deserialize reads the notfound message from r.
func (m *MsgNotFound) Deserialize(r io.Reader) error {
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

// MsgMempool is the "mempool" message requesting the peer's mempool txids.
type MsgMempool struct{}

// Command returns the protocol command string for the message.
func (m *MsgMempool) Command() string { return "mempool" }

// Serialize writes the mempool message to w (no payload).
func (m *MsgMempool) Serialize(w io.Writer) error { return nil }

// Deserialize reads the mempool message from r (no payload).
func (m *MsgMempool) Deserialize(r io.Reader) error { return nil }

// MsgGetBlocks is the "getblocks" message similar to getheaders but for blocks.
type MsgGetBlocks struct {
	ProtocolVersion uint32
	BlockLocators   []wire.Hash256
	HashStop        wire.Hash256
}

// Command returns the protocol command string for the message.
func (m *MsgGetBlocks) Command() string { return "getblocks" }

// Serialize writes the getblocks message to w.
func (m *MsgGetBlocks) Serialize(w io.Writer) error {
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

// Deserialize reads the getblocks message from r.
func (m *MsgGetBlocks) Deserialize(r io.Reader) error {
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
func (m *MsgGetBlocks) AddBlockLocator(hash wire.Hash256) error {
	if len(m.BlockLocators) >= MaxBlockLocators {
		return ErrTooManyLocators
	}
	m.BlockLocators = append(m.BlockLocators, hash)
	return nil
}
