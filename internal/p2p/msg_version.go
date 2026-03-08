package p2p

import (
	"io"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Service flags for node capabilities.
const (
	ServiceNodeNetwork        uint64 = 1 << 0  // Full node
	ServiceNodeGetUTXO        uint64 = 1 << 1  // BIP64
	ServiceNodeBloom          uint64 = 1 << 2  // BIP111
	ServiceNodeWitness        uint64 = 1 << 3  // BIP144
	ServiceNodeXThin          uint64 = 1 << 4  // XThin blocks
	ServiceNodeCompactFilters uint64 = 1 << 6  // BIP157/158
	ServiceNodeNetworkLimited uint64 = 1 << 10 // BIP159
)

// Protocol version constants.
const (
	ProtocolVersion = 70016 // Current protocol version
)

// MaxUserAgentLen is the maximum allowed user agent string length.
const MaxUserAgentLen = 256

// MsgVersion is the "version" handshake message.
type MsgVersion struct {
	ProtocolVersion int32      // Protocol version (e.g., 70016)
	Services        uint64     // Service flags bitfield
	Timestamp       int64      // Unix timestamp
	AddrRecv        NetAddress // Address of receiving node
	AddrFrom        NetAddress // Address of sending node
	Nonce           uint64     // Random nonce for detecting self-connections
	UserAgent       string     // User agent string (e.g., "/blockbrew:0.1.0/")
	StartHeight     int32      // Best block height of the sender
	Relay           bool       // Whether to relay transactions (BIP37)
}

// Command returns the protocol command string for the message.
func (m *MsgVersion) Command() string { return "version" }

// Serialize writes the version message to w.
func (m *MsgVersion) Serialize(w io.Writer) error {
	if err := wire.WriteInt32LE(w, m.ProtocolVersion); err != nil {
		return err
	}
	if err := wire.WriteUint64LE(w, m.Services); err != nil {
		return err
	}
	if err := wire.WriteInt64LE(w, m.Timestamp); err != nil {
		return err
	}
	// AddrRecv and AddrFrom are serialized without timestamp in version message
	if err := m.AddrRecv.Serialize(w); err != nil {
		return err
	}
	if err := m.AddrFrom.Serialize(w); err != nil {
		return err
	}
	if err := wire.WriteUint64LE(w, m.Nonce); err != nil {
		return err
	}
	if err := wire.WriteVarString(w, m.UserAgent); err != nil {
		return err
	}
	if err := wire.WriteInt32LE(w, m.StartHeight); err != nil {
		return err
	}

	// Relay field (1 byte bool)
	var relay uint8
	if m.Relay {
		relay = 1
	}
	return wire.WriteUint8(w, relay)
}

// Deserialize reads the version message from r.
func (m *MsgVersion) Deserialize(r io.Reader) error {
	var err error
	m.ProtocolVersion, err = wire.ReadInt32LE(r)
	if err != nil {
		return err
	}
	m.Services, err = wire.ReadUint64LE(r)
	if err != nil {
		return err
	}
	m.Timestamp, err = wire.ReadInt64LE(r)
	if err != nil {
		return err
	}
	if err := m.AddrRecv.Deserialize(r); err != nil {
		return err
	}
	if err := m.AddrFrom.Deserialize(r); err != nil {
		return err
	}
	m.Nonce, err = wire.ReadUint64LE(r)
	if err != nil {
		return err
	}
	m.UserAgent, err = wire.ReadVarString(r, MaxUserAgentLen)
	if err != nil {
		return err
	}
	m.StartHeight, err = wire.ReadInt32LE(r)
	if err != nil {
		return err
	}

	// Relay field (optional in older protocols, but we require it)
	relay, err := wire.ReadUint8(r)
	if err != nil {
		// If EOF, assume relay=true for older clients
		if err == io.EOF {
			m.Relay = true
			return nil
		}
		return err
	}
	m.Relay = relay != 0
	return nil
}
