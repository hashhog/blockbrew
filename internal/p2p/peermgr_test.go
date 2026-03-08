package p2p

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
)

func TestNewPeerManager(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.MainnetParams(),
		UserAgent:   "/blockbrew:0.1.0/",
	}

	pm := NewPeerManager(config)
	if pm == nil {
		t.Fatal("NewPeerManager returned nil")
	}

	// Check defaults were applied
	if pm.config.MaxOutbound != DefaultMaxOutbound {
		t.Errorf("expected MaxOutbound %d, got %d", DefaultMaxOutbound, pm.config.MaxOutbound)
	}
	if pm.config.MaxInbound != DefaultMaxInbound {
		t.Errorf("expected MaxInbound %d, got %d", DefaultMaxInbound, pm.config.MaxInbound)
	}
}

func TestPeerManagerCustomLimits(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		MaxOutbound: 4,
		MaxInbound:  50,
	}

	pm := NewPeerManager(config)
	if pm.config.MaxOutbound != 4 {
		t.Errorf("expected MaxOutbound 4, got %d", pm.config.MaxOutbound)
	}
	if pm.config.MaxInbound != 50 {
		t.Errorf("expected MaxInbound 50, got %d", pm.config.MaxInbound)
	}
}

func TestPeerManagerStartStop(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(), // No DNS seeds
		UserAgent:   "/blockbrew:0.1.0/",
	}

	pm := NewPeerManager(config)

	// Start should succeed
	err := pm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Start again should fail
	err = pm.Start()
	if err == nil {
		t.Error("double Start should fail")
	}

	// Give connection handler time to initialize
	time.Sleep(50 * time.Millisecond)

	// Stop should succeed
	pm.Stop()

	// Stop again should be idempotent
	pm.Stop()
}

func TestPeerManagerStartWithListener(t *testing.T) {
	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
		ListenAddr:  addr,
		UserAgent:   "/blockbrew:0.1.0/",
	}

	pm := NewPeerManager(config)

	err = pm.Start()
	if err != nil {
		t.Fatalf("Start with listener failed: %v", err)
	}

	// Give listener time to start
	time.Sleep(50 * time.Millisecond)

	pm.Stop()
}

func TestPeerManagerPeerCount(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
	}

	pm := NewPeerManager(config)

	outbound, inbound := pm.PeerCount()
	if outbound != 0 || inbound != 0 {
		t.Errorf("expected 0/0 peers, got %d/%d", outbound, inbound)
	}
}

func TestPeerManagerConnectedPeers(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
	}

	pm := NewPeerManager(config)

	peers := pm.ConnectedPeers()
	if len(peers) != 0 {
		t.Errorf("expected 0 connected peers, got %d", len(peers))
	}
}

func TestPeerManagerBanPeer(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
	}

	pm := NewPeerManager(config)

	// Ban a peer
	pm.BanPeer("192.168.1.1:8333", DefaultBanDuration, "test ban")

	// Check if banned
	if !pm.IsBanned("192.168.1.1:8333") {
		t.Error("peer should be banned")
	}

	// Same IP different port should also be banned
	if !pm.IsBanned("192.168.1.1:9999") {
		t.Error("same IP with different port should also be banned")
	}

	// Different IP should not be banned
	if pm.IsBanned("192.168.1.2:8333") {
		t.Error("different IP should not be banned")
	}
}

func TestPeerManagerBanExpiry(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
	}

	pm := NewPeerManager(config)

	// Ban with very short duration
	pm.BanPeer("192.168.1.1:8333", 1*time.Millisecond, "test ban")

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	// Should no longer be banned
	if pm.IsBanned("192.168.1.1:8333") {
		t.Error("ban should have expired")
	}
}

func TestPeerManagerBroadcastMessage(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
	}

	pm := NewPeerManager(config)

	// BroadcastMessage with no peers should not panic
	pm.BroadcastMessage(&MsgPing{Nonce: 12345})
}

func TestPeerManagerForEachPeer(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
	}

	pm := NewPeerManager(config)

	// ForEachPeer with no peers should not panic
	count := 0
	pm.ForEachPeer(func(p *Peer) {
		count++
	})

	if count != 0 {
		t.Errorf("expected 0 iterations, got %d", count)
	}
}

func TestPeerManagerAddressBook(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
	}

	pm := NewPeerManager(config)

	ab := pm.AddressBook()
	if ab == nil {
		t.Error("AddressBook returned nil")
	}
}

func TestPeerManagerGetPeer(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
	}

	pm := NewPeerManager(config)

	// Non-existent peer should return nil
	peer := pm.GetPeer("192.168.1.1:8333")
	if peer != nil {
		t.Error("expected nil for non-existent peer")
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1:8333", "192.168.1.1"},
		{"127.0.0.1:9999", "127.0.0.1"},
		{"[::1]:8333", "::1"},
		{"192.168.1.1", "192.168.1.1"},
	}

	for _, tc := range tests {
		result := extractIP(tc.input)
		if result != tc.expected {
			t.Errorf("extractIP(%s) = %s, expected %s", tc.input, result, tc.expected)
		}
	}
}

func TestPeerManagerInboundLimit(t *testing.T) {
	// Create a listener for the peer manager
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	config := PeerManagerConfig{
		Network:     RegtestMagic,
		ChainParams: consensus.RegtestParams(),
		ListenAddr:  addr,
		MaxInbound:  2, // Very low limit for testing
		UserAgent:   "/blockbrew:0.1.0/",
	}

	pm := NewPeerManager(config)
	err = pm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer pm.Stop()

	// Give listener time to start
	time.Sleep(50 * time.Millisecond)

	// Try to connect more clients than the limit
	var conns []net.Conn
	for i := 0; i < 5; i++ {
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err != nil {
			continue // Connection might be rejected
		}
		conns = append(conns, conn)
	}

	// Clean up connections
	defer func() {
		for _, conn := range conns {
			conn.Close()
		}
	}()

	// Wait a bit for connections to be processed
	time.Sleep(100 * time.Millisecond)

	_, inbound := pm.PeerCount()
	if inbound > config.MaxInbound {
		t.Errorf("inbound peers (%d) exceeded limit (%d)", inbound, config.MaxInbound)
	}
}

func TestPeerManagerCallbacks(t *testing.T) {
	var connected, disconnected int
	var mu sync.Mutex

	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
		OnPeerConnected: func(p *Peer) {
			mu.Lock()
			connected++
			mu.Unlock()
		},
		OnPeerDisconnected: func(p *Peer) {
			mu.Lock()
			disconnected++
			mu.Unlock()
		},
	}

	pm := NewPeerManager(config)
	err := pm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer pm.Stop()

	// Just verify the callbacks are set and the manager starts without error
	// Real callback testing would require mock peers
}

func TestPeerManagerMakePeerConfig(t *testing.T) {
	bestHeight := int32(100)
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.MainnetParams(),
		UserAgent:   "/blockbrew:0.1.0/",
		BestHeightFunc: func() int32 {
			return bestHeight
		},
	}

	pm := NewPeerManager(config)
	peerConfig := pm.makePeerConfig()

	if peerConfig.Network != MainnetMagic {
		t.Errorf("expected network %x, got %x", MainnetMagic, peerConfig.Network)
	}
	if peerConfig.ProtocolVersion != ProtocolVersion {
		t.Errorf("expected protocol version %d, got %d", ProtocolVersion, peerConfig.ProtocolVersion)
	}
	if peerConfig.UserAgent != "/blockbrew:0.1.0/" {
		t.Errorf("expected user agent /blockbrew:0.1.0/, got %s", peerConfig.UserAgent)
	}
	if peerConfig.BestHeight != bestHeight {
		t.Errorf("expected best height %d, got %d", bestHeight, peerConfig.BestHeight)
	}
	if peerConfig.Services&ServiceNodeNetwork == 0 {
		t.Error("expected ServiceNodeNetwork flag")
	}
	if peerConfig.Services&ServiceNodeWitness == 0 {
		t.Error("expected ServiceNodeWitness flag")
	}
}

func TestPeerManagerWrapListeners(t *testing.T) {
	var addrReceived bool
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
		Listeners: &PeerListeners{
			OnAddr: func(p *Peer, msg *MsgAddr) {
				addrReceived = true
			},
		},
	}

	pm := NewPeerManager(config)

	// Get wrapped listeners
	wrapped := pm.wrapListeners()

	// The wrapped OnAddr should exist
	if wrapped.OnAddr == nil {
		t.Error("wrapped OnAddr should not be nil")
	}

	// Test that addresses are added to the book
	pm.addrBook.AddAddress(NetAddress{
		IP:   net.ParseIP("10.0.0.1"),
		Port: 8333,
	}, "test")

	initialSize := pm.addrBook.Size()

	// Simulate receiving addresses
	msg := &MsgAddr{
		AddrList: []NetAddress{
			{IP: net.ParseIP("192.168.1.1"), Port: 8333},
			{IP: net.ParseIP("192.168.1.2"), Port: 8333},
		},
	}
	wrapped.OnAddr(nil, msg)

	// Check that addresses were added
	if pm.addrBook.Size() <= initialSize {
		t.Error("addresses should have been added to book")
	}

	// Check that original handler was called
	if !addrReceived {
		t.Error("original OnAddr handler should have been called")
	}
}

func TestPeerManagerCleanupBans(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
	}

	pm := NewPeerManager(config)

	// Add expired and non-expired bans
	pm.mu.Lock()
	pm.banned["192.168.1.1"] = &BanInfo{
		Expiry: time.Now().Add(-1 * time.Hour), // Expired
		Reason: "test",
	}
	pm.banned["192.168.1.2"] = &BanInfo{
		Expiry: time.Now().Add(1 * time.Hour), // Not expired
		Reason: "test",
	}
	pm.mu.Unlock()

	// Cleanup
	pm.cleanupBans()

	pm.mu.RLock()
	_, expired := pm.banned["192.168.1.1"]
	_, active := pm.banned["192.168.1.2"]
	pm.mu.RUnlock()

	if expired {
		t.Error("expired ban should have been cleaned up")
	}
	if !active {
		t.Error("active ban should not have been cleaned up")
	}
}
