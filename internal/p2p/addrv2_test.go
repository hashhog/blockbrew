package p2p

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNetAddressV2SerializeIPv4(t *testing.T) {
	// IPv4 address
	addr := NetAddressV2{
		Time:      1234567890,
		Services:  1033, // NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED
		NetworkID: NetIPv4,
		Addr:      []byte{192, 168, 1, 1},
		Port:      8333,
	}

	var buf bytes.Buffer
	if err := addr.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	// Deserialize and verify
	var decoded NetAddressV2
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if decoded.Time != addr.Time {
		t.Errorf("Time mismatch: got %d, want %d", decoded.Time, addr.Time)
	}
	if decoded.Services != addr.Services {
		t.Errorf("Services mismatch: got %d, want %d", decoded.Services, addr.Services)
	}
	if decoded.NetworkID != addr.NetworkID {
		t.Errorf("NetworkID mismatch: got %d, want %d", decoded.NetworkID, addr.NetworkID)
	}
	if !bytes.Equal(decoded.Addr, addr.Addr) {
		t.Errorf("Addr mismatch: got %v, want %v", decoded.Addr, addr.Addr)
	}
	if decoded.Port != addr.Port {
		t.Errorf("Port mismatch: got %d, want %d", decoded.Port, addr.Port)
	}
}

func TestNetAddressV2SerializeIPv6(t *testing.T) {
	// IPv6 address
	ipv6 := net.ParseIP("2001:db8::1")
	addr := NetAddressV2{
		Time:      1234567890,
		Services:  9,
		NetworkID: NetIPv6,
		Addr:      ipv6.To16(),
		Port:      8333,
	}

	var buf bytes.Buffer
	if err := addr.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	var decoded NetAddressV2
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if decoded.NetworkID != NetIPv6 {
		t.Errorf("NetworkID mismatch: got %d, want %d", decoded.NetworkID, NetIPv6)
	}
	if !bytes.Equal(decoded.Addr, addr.Addr) {
		t.Errorf("Addr mismatch: got %v, want %v", decoded.Addr, addr.Addr)
	}
}

func TestNetAddressV2SerializeTorV3(t *testing.T) {
	// Tor v3 address (32 bytes ed25519 pubkey)
	torV3Addr := make([]byte, TorV3AddrSize)
	for i := range torV3Addr {
		torV3Addr[i] = byte(i)
	}

	addr := NetAddressV2{
		Time:      1234567890,
		Services:  0,
		NetworkID: NetTorV3,
		Addr:      torV3Addr,
		Port:      9050,
	}

	var buf bytes.Buffer
	if err := addr.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	var decoded NetAddressV2
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if decoded.NetworkID != NetTorV3 {
		t.Errorf("NetworkID mismatch: got %d, want %d", decoded.NetworkID, NetTorV3)
	}
	if len(decoded.Addr) != TorV3AddrSize {
		t.Errorf("Addr length mismatch: got %d, want %d", len(decoded.Addr), TorV3AddrSize)
	}
	if !bytes.Equal(decoded.Addr, torV3Addr) {
		t.Errorf("Addr mismatch")
	}
}

func TestNetAddressV2SerializeI2P(t *testing.T) {
	// I2P address (32 bytes SHA256 hash)
	i2pAddr := make([]byte, I2PAddrSize)
	for i := range i2pAddr {
		i2pAddr[i] = byte(255 - i)
	}

	addr := NetAddressV2{
		Time:      1234567890,
		Services:  0,
		NetworkID: NetI2P,
		Addr:      i2pAddr,
		Port:      0, // I2P doesn't use ports
	}

	var buf bytes.Buffer
	if err := addr.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	var decoded NetAddressV2
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if decoded.NetworkID != NetI2P {
		t.Errorf("NetworkID mismatch: got %d, want %d", decoded.NetworkID, NetI2P)
	}
	if len(decoded.Addr) != I2PAddrSize {
		t.Errorf("Addr length mismatch: got %d, want %d", len(decoded.Addr), I2PAddrSize)
	}
}

func TestNetAddressV2SerializeCJDNS(t *testing.T) {
	// CJDNS address (16 bytes, must start with fc)
	cjdnsAddr := []byte{
		0xfc, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}

	addr := NetAddressV2{
		Time:      1234567890,
		Services:  0,
		NetworkID: NetCJDNS,
		Addr:      cjdnsAddr,
		Port:      8333,
	}

	var buf bytes.Buffer
	if err := addr.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	var decoded NetAddressV2
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if decoded.NetworkID != NetCJDNS {
		t.Errorf("NetworkID mismatch: got %d, want %d", decoded.NetworkID, NetCJDNS)
	}
	if len(decoded.Addr) != CJDNSAddrSize {
		t.Errorf("Addr length mismatch: got %d, want %d", len(decoded.Addr), CJDNSAddrSize)
	}
}

func TestNetAddressV2InvalidCJDNSPrefix(t *testing.T) {
	// CJDNS address must start with fc, this should fail
	cjdnsAddr := []byte{
		0xfe, 0x80, 0x00, 0x00, // Wrong prefix
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}

	addr := NetAddressV2{
		Time:      1234567890,
		Services:  0,
		NetworkID: NetCJDNS,
		Addr:      cjdnsAddr,
		Port:      8333,
	}

	var buf bytes.Buffer
	if err := addr.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	var decoded NetAddressV2
	err := decoded.Deserialize(&buf)
	if err != ErrInvalidCJDNSPrefix {
		t.Errorf("Expected ErrInvalidCJDNSPrefix, got %v", err)
	}
}

func TestNetAddressV2InvalidAddrSize(t *testing.T) {
	// IPv4 with wrong size should fail
	addr := NetAddressV2{
		Time:      1234567890,
		Services:  0,
		NetworkID: NetIPv4,
		Addr:      []byte{192, 168, 1}, // Only 3 bytes, should be 4
		Port:      8333,
	}

	var buf bytes.Buffer
	if err := addr.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	var decoded NetAddressV2
	err := decoded.Deserialize(&buf)
	if err == nil {
		t.Error("Expected error for invalid address size, got nil")
	}
}

func TestMsgAddrv2SerializeDeserialize(t *testing.T) {
	// Create a message with multiple address types
	msg := &MsgAddrv2{
		AddrList: []NetAddressV2{
			{
				Time:      1234567890,
				Services:  1,
				NetworkID: NetIPv4,
				Addr:      []byte{192, 168, 1, 1},
				Port:      8333,
			},
			{
				Time:      1234567891,
				Services:  9,
				NetworkID: NetIPv6,
				Addr:      net.ParseIP("2001:db8::1").To16(),
				Port:      8333,
			},
			{
				Time:      1234567892,
				Services:  0,
				NetworkID: NetTorV3,
				Addr:      make([]byte, TorV3AddrSize),
				Port:      9050,
			},
		},
	}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	decoded := &MsgAddrv2{}
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if len(decoded.AddrList) != len(msg.AddrList) {
		t.Fatalf("AddrList length mismatch: got %d, want %d", len(decoded.AddrList), len(msg.AddrList))
	}

	for i, addr := range decoded.AddrList {
		if addr.NetworkID != msg.AddrList[i].NetworkID {
			t.Errorf("Address %d: NetworkID mismatch: got %d, want %d",
				i, addr.NetworkID, msg.AddrList[i].NetworkID)
		}
	}
}

func TestMsgAddrv2Command(t *testing.T) {
	msg := &MsgAddrv2{}
	if msg.Command() != "addrv2" {
		t.Errorf("Command mismatch: got %q, want %q", msg.Command(), "addrv2")
	}
}

func TestMsgSendAddrv2Command(t *testing.T) {
	msg := &MsgSendAddrv2{}
	if msg.Command() != "sendaddrv2" {
		t.Errorf("Command mismatch: got %q, want %q", msg.Command(), "sendaddrv2")
	}
}

func TestMsgSendAddrv2SerializeDeserialize(t *testing.T) {
	msg := &MsgSendAddrv2{}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	// Empty message should have zero bytes
	if buf.Len() != 0 {
		t.Errorf("Expected 0 bytes, got %d", buf.Len())
	}

	decoded := &MsgSendAddrv2{}
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}
}

func TestMsgAddrv2AddAddress(t *testing.T) {
	msg := &MsgAddrv2{}

	// Add up to max
	for i := 0; i < MaxAddresses; i++ {
		err := msg.AddAddress(NetAddressV2{
			NetworkID: NetIPv4,
			Addr:      []byte{192, 168, byte(i / 256), byte(i % 256)},
			Port:      8333,
		})
		if err != nil {
			t.Fatalf("AddAddress failed at %d: %v", i, err)
		}
	}

	// Adding one more should fail
	err := msg.AddAddress(NetAddressV2{
		NetworkID: NetIPv4,
		Addr:      []byte{192, 168, 0, 1},
		Port:      8333,
	})
	if err != ErrTooManyAddresses {
		t.Errorf("Expected ErrTooManyAddresses, got %v", err)
	}
}

func TestNetAddressV2FromLegacy(t *testing.T) {
	// IPv4
	legacy := &NetAddress{
		Timestamp: 1234567890,
		Services:  1033,
		IP:        net.IPv4(192, 168, 1, 1).To16(),
		Port:      8333,
	}

	v2 := NewNetAddressV2FromLegacy(legacy)
	if v2.NetworkID != NetIPv4 {
		t.Errorf("NetworkID mismatch: got %d, want %d", v2.NetworkID, NetIPv4)
	}
	if !bytes.Equal(v2.Addr, []byte{192, 168, 1, 1}) {
		t.Errorf("Addr mismatch: got %v, want [192 168 1 1]", v2.Addr)
	}
	if v2.Port != 8333 {
		t.Errorf("Port mismatch: got %d, want 8333", v2.Port)
	}
}

func TestNetAddressV2ToLegacy(t *testing.T) {
	// IPv4
	v2 := &NetAddressV2{
		Time:      1234567890,
		Services:  1033,
		NetworkID: NetIPv4,
		Addr:      []byte{192, 168, 1, 1},
		Port:      8333,
	}

	legacy := v2.ToLegacy()
	if legacy == nil {
		t.Fatal("ToLegacy returned nil for IPv4")
	}
	if legacy.Timestamp != v2.Time {
		t.Errorf("Timestamp mismatch: got %d, want %d", legacy.Timestamp, v2.Time)
	}
	if legacy.Port != 8333 {
		t.Errorf("Port mismatch: got %d, want 8333", legacy.Port)
	}

	// Tor v3 should return nil
	torv3 := &NetAddressV2{
		NetworkID: NetTorV3,
		Addr:      make([]byte, TorV3AddrSize),
		Port:      9050,
	}
	if torv3.ToLegacy() != nil {
		t.Error("ToLegacy should return nil for Tor v3")
	}

	// I2P should return nil
	i2p := &NetAddressV2{
		NetworkID: NetI2P,
		Addr:      make([]byte, I2PAddrSize),
		Port:      0,
	}
	if i2p.ToLegacy() != nil {
		t.Error("ToLegacy should return nil for I2P")
	}
}

func TestNetAddressV2IsAddrV1Compatible(t *testing.T) {
	tests := []struct {
		networkID uint8
		want      bool
	}{
		{NetIPv4, true},
		{NetIPv6, true},
		{NetTorV2, false},
		{NetTorV3, false},
		{NetI2P, false},
		{NetCJDNS, false},
		{0xFF, false}, // Unknown
	}

	for _, tc := range tests {
		addr := &NetAddressV2{NetworkID: tc.networkID}
		got := addr.IsAddrV1Compatible()
		if got != tc.want {
			t.Errorf("NetworkID %d: IsAddrV1Compatible = %v, want %v", tc.networkID, got, tc.want)
		}
	}
}

func TestMsgAddrv2ToLegacyAddrs(t *testing.T) {
	msg := &MsgAddrv2{
		AddrList: []NetAddressV2{
			{
				Time:      1234567890,
				Services:  1,
				NetworkID: NetIPv4,
				Addr:      []byte{192, 168, 1, 1},
				Port:      8333,
			},
			{
				Time:      1234567891,
				Services:  9,
				NetworkID: NetIPv6,
				Addr:      net.ParseIP("2001:db8::1").To16(),
				Port:      8333,
			},
			{
				Time:      1234567892,
				Services:  0,
				NetworkID: NetTorV3, // This should be filtered out
				Addr:      make([]byte, TorV3AddrSize),
				Port:      9050,
			},
		},
	}

	legacy := msg.ToLegacyAddrs()
	if len(legacy.AddrList) != 2 {
		t.Errorf("Expected 2 addresses in legacy, got %d", len(legacy.AddrList))
	}
}

func TestFromLegacyAddrs(t *testing.T) {
	legacy := &MsgAddr{
		AddrList: []NetAddress{
			{
				Timestamp: 1234567890,
				Services:  1,
				IP:        net.IPv4(192, 168, 1, 1).To16(),
				Port:      8333,
			},
			{
				Timestamp: 1234567891,
				Services:  9,
				IP:        net.ParseIP("2001:db8::1"),
				Port:      8333,
			},
		},
	}

	v2 := FromLegacyAddrs(legacy)
	if len(v2.AddrList) != 2 {
		t.Errorf("Expected 2 addresses, got %d", len(v2.AddrList))
	}

	if v2.AddrList[0].NetworkID != NetIPv4 {
		t.Errorf("First address NetworkID mismatch: got %d, want %d", v2.AddrList[0].NetworkID, NetIPv4)
	}
	if v2.AddrList[1].NetworkID != NetIPv6 {
		t.Errorf("Second address NetworkID mismatch: got %d, want %d", v2.AddrList[1].NetworkID, NetIPv6)
	}
}

func TestNetAddressV2FilterByNetwork(t *testing.T) {
	msg := &MsgAddrv2{
		AddrList: []NetAddressV2{
			{NetworkID: NetIPv4, Addr: []byte{192, 168, 1, 1}},
			{NetworkID: NetIPv6, Addr: make([]byte, IPv6AddrSize)},
			{NetworkID: NetTorV3, Addr: make([]byte, TorV3AddrSize)},
			{NetworkID: NetI2P, Addr: make([]byte, I2PAddrSize)},
			{NetworkID: NetIPv4, Addr: []byte{10, 0, 0, 1}},
		},
	}

	// Filter IPv4 only
	ipv4Only := msg.FilterByNetwork(NetIPv4)
	if len(ipv4Only) != 2 {
		t.Errorf("Expected 2 IPv4 addresses, got %d", len(ipv4Only))
	}

	// Filter IPv4 and IPv6
	ipAll := msg.FilterByNetwork(NetIPv4, NetIPv6)
	if len(ipAll) != 3 {
		t.Errorf("Expected 3 IPv4/IPv6 addresses, got %d", len(ipAll))
	}

	// Filter Tor only
	torOnly := msg.FilterByNetwork(NetTorV3)
	if len(torOnly) != 1 {
		t.Errorf("Expected 1 Tor v3 address, got %d", len(torOnly))
	}
}

func TestNetAddressV2NetworkName(t *testing.T) {
	tests := []struct {
		networkID uint8
		want      string
	}{
		{NetIPv4, "ipv4"},
		{NetIPv6, "ipv6"},
		{NetTorV2, "torv2"},
		{NetTorV3, "torv3"},
		{NetI2P, "i2p"},
		{NetCJDNS, "cjdns"},
		{0xFF, "unknown(255)"},
	}

	for _, tc := range tests {
		addr := &NetAddressV2{NetworkID: tc.networkID}
		got := addr.NetworkName()
		if got != tc.want {
			t.Errorf("NetworkID %d: NetworkName = %q, want %q", tc.networkID, got, tc.want)
		}
	}
}

func TestAddrSizeForNetwork(t *testing.T) {
	tests := []struct {
		networkID uint8
		want      int
	}{
		{NetIPv4, IPv4AddrSize},
		{NetIPv6, IPv6AddrSize},
		{NetTorV2, TorV2AddrSize},
		{NetTorV3, TorV3AddrSize},
		{NetI2P, I2PAddrSize},
		{NetCJDNS, CJDNSAddrSize},
		{0xFF, 0}, // Unknown
	}

	for _, tc := range tests {
		got := AddrSizeForNetwork(tc.networkID)
		if got != tc.want {
			t.Errorf("AddrSizeForNetwork(%d) = %d, want %d", tc.networkID, got, tc.want)
		}
	}
}

func TestNewNetAddressV2FromIP(t *testing.T) {
	// IPv4
	ip4 := net.ParseIP("192.168.1.1")
	addr4 := NewNetAddressV2FromIP(ip4, 8333, 1)
	if addr4.NetworkID != NetIPv4 {
		t.Errorf("IPv4: NetworkID = %d, want %d", addr4.NetworkID, NetIPv4)
	}
	if len(addr4.Addr) != IPv4AddrSize {
		t.Errorf("IPv4: Addr len = %d, want %d", len(addr4.Addr), IPv4AddrSize)
	}

	// IPv6
	ip6 := net.ParseIP("2001:db8::1")
	addr6 := NewNetAddressV2FromIP(ip6, 8333, 1)
	if addr6.NetworkID != NetIPv6 {
		t.Errorf("IPv6: NetworkID = %d, want %d", addr6.NetworkID, NetIPv6)
	}

	// CJDNS (fc00::/8)
	ipCjdns := net.ParseIP("fc00::1")
	addrCjdns := NewNetAddressV2FromIP(ipCjdns, 8333, 0)
	if addrCjdns.NetworkID != NetCJDNS {
		t.Errorf("CJDNS: NetworkID = %d, want %d", addrCjdns.NetworkID, NetCJDNS)
	}
}

// TestADDRv2Negotiation tests that ADDRv2 support is properly negotiated during handshake.
func TestADDRv2Negotiation(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	config := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork | ServiceNodeWitness,
		UserAgent:       "/blockbrew:0.1.0/",
		BestHeight:      800000,
	}

	// Create peer with v1 transport
	peer := &Peer{
		config:            config,
		conn:              clientConn,
		transport:         NewV1Transport(clientConn, config.Network),
		addr:              "127.0.0.1:8333",
		state:             PeerStateConnecting,
		inbound:           false,
		sendQueue:         make(chan Message, SendQueueSize),
		quit:              make(chan struct{}),
		localNonce:        12345678,
		handshakeDone:     make(chan struct{}),
		startTime:         time.Now(),
		lastRecv:          time.Now(),
		lastSend:          time.Now(),
		compactBlockState: NewCompactBlockState(),
	}

	// Server that also supports ADDRv2
	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		// Read version from client
		msg, err := ReadMessage(serverConn, config.Network)
		if err != nil {
			return
		}
		if _, ok := msg.(*MsgVersion); !ok {
			return
		}

		// Send our version
		version := &MsgVersion{
			ProtocolVersion: ProtocolVersion,
			Services:        ServiceNodeNetwork | ServiceNodeWitness,
			Timestamp:       time.Now().Unix(),
			Nonce:           87654321,
			UserAgent:       "/mocknode:0.1.0/",
			StartHeight:     800001,
			Relay:           true,
		}
		WriteMessage(serverConn, config.Network, version)

		// Send sendaddrv2 (indicating server supports ADDRv2)
		WriteMessage(serverConn, config.Network, &MsgSendAddrv2{})

		// Send verack
		WriteMessage(serverConn, config.Network, &MsgVerAck{})

		// Read remaining messages until connection closes
		for {
			serverConn.SetReadDeadline(time.Now().Add(time.Second))
			_, err := ReadMessage(serverConn, config.Network)
			if err != nil {
				return
			}
		}
	}()

	// Start peer handshake
	errCh := make(chan error, 1)
	go func() {
		errCh <- peer.Start()
	}()

	// Wait for handshake
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("peer.Start() failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake timed out")
	}

	// Verify peer supports ADDRv2
	if !peer.WantsAddrv2() {
		t.Error("peer should support ADDRv2 after receiving sendaddrv2")
	}

	peer.Disconnect()
	serverWg.Wait()
}

// TestADDRv2NegotiationOldPeer tests that we don't mark ADDRv2 support for peers that don't send sendaddrv2.
func TestADDRv2NegotiationOldPeer(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	config := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork | ServiceNodeWitness,
		UserAgent:       "/blockbrew:0.1.0/",
		BestHeight:      800000,
	}

	// Create peer with v1 transport
	peer := &Peer{
		config:            config,
		conn:              clientConn,
		transport:         NewV1Transport(clientConn, config.Network),
		addr:              "127.0.0.1:8333",
		state:             PeerStateConnecting,
		inbound:           false,
		sendQueue:         make(chan Message, SendQueueSize),
		quit:              make(chan struct{}),
		localNonce:        12345678,
		handshakeDone:     make(chan struct{}),
		startTime:         time.Now(),
		lastRecv:          time.Now(),
		lastSend:          time.Now(),
		compactBlockState: NewCompactBlockState(),
	}

	// Old server that doesn't support ADDRv2
	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		// Read version
		msg, _ := ReadMessage(serverConn, config.Network)
		if _, ok := msg.(*MsgVersion); !ok {
			return
		}

		// Send version (no sendaddrv2)
		version := &MsgVersion{
			ProtocolVersion: 70015, // Older version
			Services:        ServiceNodeNetwork,
			Timestamp:       time.Now().Unix(),
			Nonce:           87654321,
			UserAgent:       "/oldnode:0.1.0/",
			StartHeight:     800001,
			Relay:           true,
		}
		WriteMessage(serverConn, config.Network, version)
		WriteMessage(serverConn, config.Network, &MsgVerAck{})

		// Read until closed
		for {
			serverConn.SetReadDeadline(time.Now().Add(time.Second))
			_, err := ReadMessage(serverConn, config.Network)
			if err != nil {
				return
			}
		}
	}()

	// Start handshake
	errCh := make(chan error, 1)
	go func() {
		errCh <- peer.Start()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("peer.Start() failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake timed out")
	}

	// Peer should NOT support ADDRv2
	if peer.WantsAddrv2() {
		t.Error("peer should NOT support ADDRv2 without receiving sendaddrv2")
	}

	peer.Disconnect()
	serverWg.Wait()
}

// TestSendAddrv2AfterVerackMisbehavior tests that sendaddrv2 after verack is a protocol violation.
func TestSendAddrv2AfterVerackMisbehavior(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	config := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork,
		UserAgent:       "/blockbrew:0.1.0/",
		BestHeight:      800000,
	}

	peer := &Peer{
		config:            config,
		conn:              clientConn,
		transport:         NewV1Transport(clientConn, config.Network),
		addr:              "127.0.0.1:8333",
		state:             PeerStateConnected, // Already connected (verack received)
		inbound:           false,
		sendQueue:         make(chan Message, SendQueueSize),
		quit:              make(chan struct{}),
		localNonce:        12345678,
		handshakeDone:     make(chan struct{}),
		startTime:         time.Now(),
		lastRecv:          time.Now(),
		lastSend:          time.Now(),
		verAckRecvd:       true, // Already received verack
		compactBlockState: NewCompactBlockState(),
	}
	close(peer.handshakeDone)

	// Start handlers
	peer.wg.Add(2)
	go peer.readHandler()
	go peer.writeHandler()

	// Send sendaddrv2 after handshake complete - this should trigger misbehavior
	go func() {
		WriteMessage(serverConn, config.Network, &MsgSendAddrv2{})
		// Keep reading to allow peer to process
		for {
			serverConn.SetReadDeadline(time.Now().Add(time.Second))
			_, err := ReadMessage(serverConn, config.Network)
			if err != nil {
				return
			}
		}
	}()

	// Wait for message to be processed
	time.Sleep(100 * time.Millisecond)

	// Peer should have misbehavior score
	if peer.MisbehaviorScore() == 0 {
		t.Error("peer should have misbehavior score for sendaddrv2 after verack")
	}

	// wantsAddrv2 should still be false
	if peer.WantsAddrv2() {
		t.Error("wantsAddrv2 should not be set when sendaddrv2 received after verack")
	}

	peer.Disconnect()
}
