package p2p

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/hashhog/blockbrew/internal/wire"
)

// BIP155 network IDs for ADDRv2 messages.
const (
	NetIPv4  uint8 = 0x01 // 4 bytes
	NetIPv6  uint8 = 0x02 // 16 bytes
	NetTorV2 uint8 = 0x03 // 10 bytes (deprecated)
	NetTorV3 uint8 = 0x04 // 32 bytes (ed25519 pubkey)
	NetI2P   uint8 = 0x05 // 32 bytes (SHA256 of destination)
	NetCJDNS uint8 = 0x06 // 16 bytes (fc00::/8 address)
)

// Network address sizes for each network type.
const (
	IPv4AddrSize  = 4
	IPv6AddrSize  = 16
	TorV2AddrSize = 10
	TorV3AddrSize = 32
	I2PAddrSize   = 32
	CJDNSAddrSize = 16
)

// Maximum address size allowed in ADDRv2 (per BIP155).
const MaxAddrV2Size = 512

// Errors for ADDRv2 parsing.
var (
	ErrInvalidNetworkID   = errors.New("p2p: invalid network ID")
	ErrInvalidAddrSize    = errors.New("p2p: invalid address size for network type")
	ErrAddrTooLarge       = errors.New("p2p: address too large")
	ErrInvalidCJDNSPrefix = errors.New("p2p: CJDNS address must start with fc00::/8")
)

// NetAddressV2 represents an extended network address for BIP155 ADDRv2.
// It can hold addresses of varying lengths for different network types.
type NetAddressV2 struct {
	Time      uint32 // Last-seen timestamp
	Services  uint64 // Service flags (compact size encoded)
	NetworkID uint8  // Network type (NetIPv4, NetIPv6, NetTorV3, etc.)
	Addr      []byte // Raw address bytes (length varies by network type)
	Port      uint16 // Port number (big-endian in wire format)
}

// NewNetAddressV2FromIP creates a NetAddressV2 from a net.IP and port.
func NewNetAddressV2FromIP(ip net.IP, port uint16, services uint64) *NetAddressV2 {
	na := &NetAddressV2{
		Services: services,
		Port:     port,
	}

	// Determine network type from IP
	if ip4 := ip.To4(); ip4 != nil {
		na.NetworkID = NetIPv4
		na.Addr = make([]byte, IPv4AddrSize)
		copy(na.Addr, ip4)
	} else if ip6 := ip.To16(); ip6 != nil {
		// Check for CJDNS (fc00::/8)
		if ip6[0] == 0xfc {
			na.NetworkID = NetCJDNS
		} else {
			na.NetworkID = NetIPv6
		}
		na.Addr = make([]byte, IPv6AddrSize)
		copy(na.Addr, ip6)
	}
	return na
}

// NewNetAddressV2FromLegacy converts a legacy NetAddress to NetAddressV2.
func NewNetAddressV2FromLegacy(na *NetAddress) *NetAddressV2 {
	nav2 := &NetAddressV2{
		Time:     na.Timestamp,
		Services: na.Services,
		Port:     na.Port,
	}

	// Determine network type from IP
	if ip4 := na.IP.To4(); ip4 != nil {
		nav2.NetworkID = NetIPv4
		nav2.Addr = make([]byte, IPv4AddrSize)
		copy(nav2.Addr, ip4)
	} else if ip6 := na.IP.To16(); ip6 != nil {
		// Check for CJDNS (fc00::/8)
		if ip6[0] == 0xfc {
			nav2.NetworkID = NetCJDNS
		} else {
			nav2.NetworkID = NetIPv6
		}
		nav2.Addr = make([]byte, IPv6AddrSize)
		copy(nav2.Addr, ip6)
	}
	return nav2
}

// ToLegacy converts a NetAddressV2 to a legacy NetAddress.
// Returns nil if the address cannot be represented in legacy format (Tor, I2P).
func (na *NetAddressV2) ToLegacy() *NetAddress {
	switch na.NetworkID {
	case NetIPv4:
		if len(na.Addr) != IPv4AddrSize {
			return nil
		}
		// Convert to IPv4-mapped IPv6
		ip := net.IPv4(na.Addr[0], na.Addr[1], na.Addr[2], na.Addr[3])
		return &NetAddress{
			Timestamp: na.Time,
			Services:  na.Services,
			IP:        ip.To16(),
			Port:      na.Port,
		}
	case NetIPv6:
		if len(na.Addr) != IPv6AddrSize {
			return nil
		}
		return &NetAddress{
			Timestamp: na.Time,
			Services:  na.Services,
			IP:        net.IP(na.Addr),
			Port:      na.Port,
		}
	case NetCJDNS:
		if len(na.Addr) != CJDNSAddrSize {
			return nil
		}
		// CJDNS addresses are IPv6 in fc00::/8 range
		return &NetAddress{
			Timestamp: na.Time,
			Services:  na.Services,
			IP:        net.IP(na.Addr),
			Port:      na.Port,
		}
	default:
		// Tor v2/v3, I2P cannot be represented in legacy format
		return nil
	}
}

// IsAddrV1Compatible returns true if this address can be sent via legacy addr message.
func (na *NetAddressV2) IsAddrV1Compatible() bool {
	switch na.NetworkID {
	case NetIPv4, NetIPv6:
		return true
	default:
		return false
	}
}

// AddrSizeForNetwork returns the expected address size for a network type.
// Returns 0 for unknown network types (unknown types have variable length).
func AddrSizeForNetwork(networkID uint8) int {
	switch networkID {
	case NetIPv4:
		return IPv4AddrSize
	case NetIPv6:
		return IPv6AddrSize
	case NetTorV2:
		return TorV2AddrSize
	case NetTorV3:
		return TorV3AddrSize
	case NetI2P:
		return I2PAddrSize
	case NetCJDNS:
		return CJDNSAddrSize
	default:
		return 0 // Unknown network type
	}
}

// ValidateAddrSize checks if the address length matches the expected size for the network type.
func ValidateAddrSize(networkID uint8, addrLen int) error {
	expected := AddrSizeForNetwork(networkID)
	if expected == 0 {
		// Unknown network type - accept any length up to max
		if addrLen > MaxAddrV2Size {
			return ErrAddrTooLarge
		}
		return nil
	}
	if addrLen != expected {
		return fmt.Errorf("%w: network %d expects %d bytes, got %d",
			ErrInvalidAddrSize, networkID, expected, addrLen)
	}
	return nil
}

// Serialize writes the NetAddressV2 in BIP155 ADDRv2 format.
// Format: timestamp(4) + services(compactsize) + networkID(1) + addr_len(compactsize) + addr(variable) + port(2 BE)
func (na *NetAddressV2) Serialize(w io.Writer) error {
	// Write timestamp (4 bytes LE)
	if err := wire.WriteUint32LE(w, na.Time); err != nil {
		return err
	}

	// Write services as CompactSize
	if err := wire.WriteCompactSize(w, na.Services); err != nil {
		return err
	}

	// Write network ID (1 byte)
	if err := wire.WriteUint8(w, na.NetworkID); err != nil {
		return err
	}

	// Write address with length prefix (CompactSize + raw bytes)
	if err := wire.WriteVarBytes(w, na.Addr); err != nil {
		return err
	}

	// Write port (2 bytes, big-endian)
	return writeUint16BE(w, na.Port)
}

// Deserialize reads a NetAddressV2 in BIP155 ADDRv2 format.
func (na *NetAddressV2) Deserialize(r io.Reader) error {
	var err error

	// Read timestamp (4 bytes LE)
	na.Time, err = wire.ReadUint32LE(r)
	if err != nil {
		return err
	}

	// Read services as CompactSize (use unchecked variant since BIP155
	// service flags are uint64 values that may exceed MaxCompactSize)
	na.Services, err = wire.ReadCompactSizeUnchecked(r)
	if err != nil {
		return err
	}

	// Read network ID (1 byte)
	na.NetworkID, err = wire.ReadUint8(r)
	if err != nil {
		return err
	}

	// Read address with length prefix
	na.Addr, err = wire.ReadVarBytes(r, MaxAddrV2Size)
	if err != nil {
		return err
	}

	// Validate address size for known network types
	if err := ValidateAddrSize(na.NetworkID, len(na.Addr)); err != nil {
		return err
	}

	// Additional validation for CJDNS addresses
	if na.NetworkID == NetCJDNS && len(na.Addr) == CJDNSAddrSize {
		if na.Addr[0] != 0xfc {
			return ErrInvalidCJDNSPrefix
		}
	}

	// Read port (2 bytes, big-endian)
	na.Port, err = readUint16BE(r)
	return err
}

// NetworkName returns a human-readable name for the network type.
func (na *NetAddressV2) NetworkName() string {
	switch na.NetworkID {
	case NetIPv4:
		return "ipv4"
	case NetIPv6:
		return "ipv6"
	case NetTorV2:
		return "torv2"
	case NetTorV3:
		return "torv3"
	case NetI2P:
		return "i2p"
	case NetCJDNS:
		return "cjdns"
	default:
		return fmt.Sprintf("unknown(%d)", na.NetworkID)
	}
}

// MsgSendAddrv2 is the "sendaddrv2" message (BIP155).
// Sent during handshake (before verack) to indicate support for ADDRv2 messages.
// Empty payload.
type MsgSendAddrv2 struct{}

// Command returns the protocol command string for the message.
func (m *MsgSendAddrv2) Command() string { return "sendaddrv2" }

// Serialize writes the sendaddrv2 message to w (no payload).
func (m *MsgSendAddrv2) Serialize(w io.Writer) error { return nil }

// Deserialize reads the sendaddrv2 message from r (no payload).
func (m *MsgSendAddrv2) Deserialize(r io.Reader) error { return nil }

// MsgAddrv2 is the "addrv2" message (BIP155) containing a list of extended addresses.
type MsgAddrv2 struct {
	AddrList []NetAddressV2 // Max 1,000 addresses
}

// Command returns the protocol command string for the message.
func (m *MsgAddrv2) Command() string { return "addrv2" }

// Serialize writes the addrv2 message to w.
func (m *MsgAddrv2) Serialize(w io.Writer) error {
	// Write count as CompactSize
	if err := wire.WriteCompactSize(w, uint64(len(m.AddrList))); err != nil {
		return err
	}

	// Write each address
	for i := range m.AddrList {
		if err := m.AddrList[i].Serialize(w); err != nil {
			return err
		}
	}
	return nil
}

// Deserialize reads the addrv2 message from r.
func (m *MsgAddrv2) Deserialize(r io.Reader) error {
	// Read count
	count, err := wire.ReadCompactSize(r)
	if err != nil {
		return err
	}
	if count > MaxAddresses {
		return ErrTooManyAddresses
	}

	// Read each address
	m.AddrList = make([]NetAddressV2, count)
	for i := range m.AddrList {
		if err := m.AddrList[i].Deserialize(r); err != nil {
			return err
		}
	}
	return nil
}

// AddAddress adds an address to the message.
func (m *MsgAddrv2) AddAddress(addr NetAddressV2) error {
	if len(m.AddrList) >= MaxAddresses {
		return ErrTooManyAddresses
	}
	m.AddrList = append(m.AddrList, addr)
	return nil
}

// ToLegacyAddrs converts the ADDRv2 address list to a legacy MsgAddr.
// Only IPv4 and IPv6 addresses are included; Tor/I2P/CJDNS are filtered out.
func (m *MsgAddrv2) ToLegacyAddrs() *MsgAddr {
	legacyMsg := &MsgAddr{}
	for i := range m.AddrList {
		if legacy := m.AddrList[i].ToLegacy(); legacy != nil {
			// CJDNS addresses can't be sent via legacy addr
			if m.AddrList[i].NetworkID != NetCJDNS {
				legacyMsg.AddrList = append(legacyMsg.AddrList, *legacy)
			}
		}
	}
	return legacyMsg
}

// FromLegacyAddrs converts a legacy MsgAddr to MsgAddrv2.
func FromLegacyAddrs(msg *MsgAddr) *MsgAddrv2 {
	addrv2 := &MsgAddrv2{
		AddrList: make([]NetAddressV2, 0, len(msg.AddrList)),
	}
	for i := range msg.AddrList {
		nav2 := NewNetAddressV2FromLegacy(&msg.AddrList[i])
		addrv2.AddrList = append(addrv2.AddrList, *nav2)
	}
	return addrv2
}

// FilterByNetwork returns only addresses matching the specified network types.
func (m *MsgAddrv2) FilterByNetwork(networks ...uint8) []NetAddressV2 {
	netSet := make(map[uint8]bool)
	for _, n := range networks {
		netSet[n] = true
	}

	var result []NetAddressV2
	for _, addr := range m.AddrList {
		if netSet[addr.NetworkID] {
			result = append(result, addr)
		}
	}
	return result
}

// writeUint16BE writes a uint16 in big-endian order.
// This is defined here to avoid circular dependencies with netaddress.go.
// Port numbers in Bitcoin use big-endian (network byte order).
func writeUint16BEInternal(w io.Writer, v uint16) error {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

// readUint16BE reads a uint16 in big-endian order.
// This is defined here to avoid circular dependencies with netaddress.go.
func readUint16BEInternal(r io.Reader) (uint16, error) {
	var buf [2]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}
