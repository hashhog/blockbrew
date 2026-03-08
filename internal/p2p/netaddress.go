package p2p

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/hashhog/blockbrew/internal/wire"
)

// NetAddress represents a network address in the Bitcoin protocol.
type NetAddress struct {
	Timestamp uint32   // Only used in addr messages, not in version
	Services  uint64   // Service flags
	IP        net.IP   // 16 bytes (IPv4 is mapped to IPv6)
	Port      uint16   // Network port (big-endian in wire format!)
}

// NewNetAddress creates a NetAddress from a TCP address and services.
func NewNetAddress(addr *net.TCPAddr, services uint64) *NetAddress {
	na := &NetAddress{
		Services: services,
		Port:     uint16(addr.Port),
	}
	// Convert to 16-byte form
	na.IP = addr.IP.To16()
	if na.IP == nil {
		na.IP = net.IPv6zero
	}
	return na
}

// Serialize writes the NetAddress (without timestamp) as used in version message.
// Wire format: services (8) + IP (16) + port (2 BE) = 26 bytes
func (na *NetAddress) Serialize(w io.Writer) error {
	if err := wire.WriteUint64LE(w, na.Services); err != nil {
		return err
	}

	// Write IP as 16 bytes (IPv4-mapped IPv6 if needed)
	ip := na.IP.To16()
	if ip == nil {
		ip = net.IPv6zero
	}
	if err := wire.WriteBytes(w, ip); err != nil {
		return err
	}

	// Port is big-endian (network byte order) - the ONLY big-endian field in Bitcoin!
	return writeUint16BE(w, na.Port)
}

// SerializeWithTimestamp writes the NetAddress (with timestamp) as used in addr messages.
// Wire format: timestamp (4) + services (8) + IP (16) + port (2 BE) = 30 bytes
func (na *NetAddress) SerializeWithTimestamp(w io.Writer) error {
	if err := wire.WriteUint32LE(w, na.Timestamp); err != nil {
		return err
	}
	return na.Serialize(w)
}

// Deserialize reads a NetAddress (without timestamp).
func (na *NetAddress) Deserialize(r io.Reader) error {
	var err error
	na.Services, err = wire.ReadUint64LE(r)
	if err != nil {
		return err
	}

	ipBytes, err := wire.ReadBytes(r, 16)
	if err != nil {
		return err
	}
	na.IP = net.IP(ipBytes)

	// Port is big-endian
	na.Port, err = readUint16BE(r)
	return err
}

// DeserializeWithTimestamp reads a NetAddress (with timestamp).
func (na *NetAddress) DeserializeWithTimestamp(r io.Reader) error {
	var err error
	na.Timestamp, err = wire.ReadUint32LE(r)
	if err != nil {
		return err
	}
	return na.Deserialize(r)
}

// writeUint16BE writes a uint16 in big-endian order.
func writeUint16BE(w io.Writer, v uint16) error {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

// readUint16BE reads a uint16 in big-endian order.
func readUint16BE(r io.Reader) (uint16, error) {
	var buf [2]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}
