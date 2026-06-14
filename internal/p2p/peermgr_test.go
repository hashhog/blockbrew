package p2p

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// makeFakePeer creates a minimal Peer that passes WantsTxRelay() and
// WantsAddrv2() checks so it can be added to a PeerManager's peer map for
// relay-gate tests.  No TCP connection is established; the sendQueue is a
// buffered channel we can drain.
func makeFakePeer(addr string) *Peer {
	p := &Peer{
		addr:          addr,
		state:         PeerStateConnected,
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		handshakeDone: make(chan struct{}),
		peerVersion:   &MsgVersion{Relay: true},
		wantsAddrv2:   true,
	}
	close(p.handshakeDone)
	return p
}

// TestRelayAddrSizeGate verifies that relayAddrToRandomPeers and
// relayAddrv2ToRandomPeers honour the Core net_processing.cpp:5688 gate:
// messages with >10 addresses MUST NOT be forwarded.
//
// Without the gate fix the function would relay any-size message to up to 2
// random peers. With the fix it returns early for len > 10.
func TestRelayAddrSizeGate(t *testing.T) {
	cfg := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.MainnetParams(),
	}
	pm := NewPeerManager(cfg)

	// Inject two fake peers so relay has candidates.
	p1 := makeFakePeer("1.2.3.4:8333")
	p2 := makeFakePeer("1.2.3.5:8333")
	pm.mu.Lock()
	pm.peers["1.2.3.4:8333"] = &PeerInfo{peer: p1}
	pm.peers["1.2.3.5:8333"] = &PeerInfo{peer: p2}
	pm.mu.Unlock()

	makeAddrs := func(n int) []NetAddress {
		addrs := make([]NetAddress, n)
		for i := range addrs {
			addrs[i] = NetAddress{IP: net.ParseIP("203.0.113.1"), Port: uint16(8333 + i)}
		}
		return addrs
	}
	makeAddrsV2 := func(n int) []NetAddressV2 {
		addrs := make([]NetAddressV2, n)
		for i := range addrs {
			addrs[i] = NetAddressV2{NetworkID: NetIPv4, Addr: []byte{203, 0, 113, byte(i)}, Port: 8333}
		}
		return addrs
	}

	drain := func(p *Peer) int {
		n := 0
		for {
			select {
			case <-p.sendQueue:
				n++
			default:
				return n
			}
		}
	}

	// addr: <=10 entries — MUST relay.
	pm.relayAddrToRandomPeers(nil, &MsgAddr{AddrList: makeAddrs(10)})
	sent1 := drain(p1) + drain(p2)
	if sent1 == 0 {
		t.Error("relayAddrToRandomPeers: expected relay for <=10 addrs, got none")
	}

	// addr: 11 entries — MUST NOT relay (Core gate).
	pm.relayAddrToRandomPeers(nil, &MsgAddr{AddrList: makeAddrs(11)})
	sent2 := drain(p1) + drain(p2)
	if sent2 != 0 {
		t.Errorf("relayAddrToRandomPeers: expected no relay for 11 addrs, got %d", sent2)
	}

	// addrv2: <=10 entries — MUST relay.
	pm.relayAddrv2ToRandomPeers(nil, &MsgAddrv2{AddrList: makeAddrsV2(10)})
	sent3 := drain(p1) + drain(p2)
	if sent3 == 0 {
		t.Error("relayAddrv2ToRandomPeers: expected relay for <=10 addrs, got none")
	}

	// addrv2: 11 entries — MUST NOT relay (Core gate).
	pm.relayAddrv2ToRandomPeers(nil, &MsgAddrv2{AddrList: makeAddrsV2(11)})
	sent4 := drain(p1) + drain(p2)
	if sent4 != 0 {
		t.Errorf("relayAddrv2ToRandomPeers: expected no relay for 11 addrs, got %d", sent4)
	}
}

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

// makeFakeConnectedPeer returns a *Peer with state=Connected and an empty
// outbound queue, suitable for unit-testing the peer-manager broadcast
// helpers.  Avoids the full handshake machinery in `peer.Start()`.
func makeFakeConnectedPeer(addr string, sendsHeaders bool) *Peer {
	p := &Peer{
		addr:          addr,
		state:         PeerStateConnected,
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		handshakeDone: make(chan struct{}),
		startTime:     time.Now(),
	}
	close(p.handshakeDone)
	if sendsHeaders {
		p.sendHeadersPreferred = true
	}
	return p
}

// TestPeerManagerAnnounceBlock verifies BIP-130 sendheaders honoring on the
// outbound block-announce path: peers that previously sent us a `sendheaders`
// message receive a `headers` message; other peers receive an `inv`.
//
// Reference: Bitcoin Core net_processing.cpp `MaybeSendInventory` (the
// fHeaderAnnounce branch); camlcoin `lib/peer_manager.ml::announce_block`.
func TestPeerManagerAnnounceBlock(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.RegtestParams(),
	}
	pm := NewPeerManager(config)

	hdrPeer := makeFakeConnectedPeer("10.0.0.1:8333", true)
	invPeer := makeFakeConnectedPeer("10.0.0.2:8333", false)

	pm.mu.Lock()
	pm.peers[hdrPeer.addr] = &PeerInfo{peer: hdrPeer, connType: ConnInbound, connectedAt: time.Now()}
	pm.peers[invPeer.addr] = &PeerInfo{peer: invPeer, connType: ConnInbound, connectedAt: time.Now()}
	pm.mu.Unlock()

	// Synthesize a block header + hash.
	header := wire.BlockHeader{
		Version:    1,
		PrevBlock:  wire.Hash256{},
		MerkleRoot: wire.Hash256{0xab, 0xcd},
		Timestamp:  1296688602,
		Bits:       0x207fffff,
		Nonce:      42,
	}
	hash := header.BlockHash()

	pm.AnnounceBlock(header, hash)

	// hdrPeer should have received exactly one MsgHeaders containing only this header.
	select {
	case msg := <-hdrPeer.sendQueue:
		hmsg, ok := msg.(*MsgHeaders)
		if !ok {
			t.Fatalf("hdrPeer queue: got %T, want *MsgHeaders", msg)
		}
		if len(hmsg.Headers) != 1 {
			t.Fatalf("hdrPeer headers len = %d, want 1", len(hmsg.Headers))
		}
		if hmsg.Headers[0].BlockHash() != hash {
			t.Fatalf("hdrPeer header hash = %s, want %s",
				hmsg.Headers[0].BlockHash().String(), hash.String())
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("hdrPeer did not receive any message")
	}

	// invPeer should have received exactly one MsgInv with InvTypeBlock.
	select {
	case msg := <-invPeer.sendQueue:
		imsg, ok := msg.(*MsgInv)
		if !ok {
			t.Fatalf("invPeer queue: got %T, want *MsgInv", msg)
		}
		if len(imsg.InvList) != 1 {
			t.Fatalf("invPeer InvList len = %d, want 1", len(imsg.InvList))
		}
		if imsg.InvList[0].Type != InvTypeBlock {
			t.Fatalf("invPeer inv type = %v, want InvTypeBlock", imsg.InvList[0].Type)
		}
		if imsg.InvList[0].Hash != hash {
			t.Fatalf("invPeer inv hash = %s, want %s",
				imsg.InvList[0].Hash.String(), hash.String())
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("invPeer did not receive any message")
	}

	// Each peer received exactly one message — make sure the inverse channel
	// did not also get the wrong type.
	select {
	case extra := <-hdrPeer.sendQueue:
		t.Fatalf("hdrPeer received an extra message: %T", extra)
	default:
	}
	select {
	case extra := <-invPeer.sendQueue:
		t.Fatalf("invPeer received an extra message: %T", extra)
	default:
	}
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

// TestMakePeerConfigFullNodeServiceFlags verifies that a non-pruned full node
// advertises the honest correct local service set: NODE_NETWORK |
// NODE_WITNESS | NODE_NETWORK_LIMITED | NODE_P2P_V2 == 0xC09.
//
// NODE_NETWORK_LIMITED (BIP-159, 1<<10) must be advertised UNCONDITIONALLY,
// NOT only in prune mode — Core init.cpp:863 seeds g_local_services with it on
// every run. NODE_P2P_V2 (BIP-324, 1<<11) is advertised because v2 transport
// runs by default (PreferV2 wired from cfg.BIP324V2, default ON), mirroring
// Core init.cpp:988-989.
func TestMakePeerConfigFullNodeServiceFlags(t *testing.T) {
	config := PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.MainnetParams(),
		UserAgent:   "/blockbrew:0.1.0/",
		// Non-pruned full node: NOT in prune mode.
		AdvertiseNodeNetworkLimited: false,
		// v2 transport enabled by default (cfg.BIP324V2 default true).
		PreferV2: true,
	}

	pm := NewPeerManager(config)
	cfg := pm.makePeerConfig()

	const (
		wantNetwork        = ServiceNodeNetwork        // 0x1
		wantWitness        = ServiceNodeWitness        // 0x8
		wantNetworkLimited = ServiceNodeNetworkLimited // 0x400
		wantP2PV2          = ServiceNodeP2PV2          // 0x800
	)
	wantServices := wantNetwork | wantWitness | wantNetworkLimited | wantP2PV2 // 0xC09

	if cfg.Services != wantServices {
		t.Fatalf("full-node Services = 0x%X, want 0x%X (NODE_NETWORK|NODE_WITNESS|NODE_NETWORK_LIMITED|NODE_P2P_V2)",
			cfg.Services, wantServices)
	}

	// Spell out each bit so a future regression names the exact dropped flag.
	if cfg.Services&ServiceNodeNetwork == 0 {
		t.Error("missing NODE_NETWORK (0x1)")
	}
	if cfg.Services&ServiceNodeWitness == 0 {
		t.Error("missing NODE_WITNESS (0x8)")
	}
	if cfg.Services&ServiceNodeNetworkLimited == 0 {
		t.Error("missing NODE_NETWORK_LIMITED (0x400) — must be set unconditionally for a full node, not gated on prune mode")
	}
	if cfg.Services&ServiceNodeP2PV2 == 0 {
		t.Error("missing NODE_P2P_V2 (0x800) — v2 transport runs by default, so the bit must be advertised")
	}

	// And confirm NODE_NETWORK_LIMITED is present even without prune mode and
	// even before any prune-mode signal — the regression this test guards
	// against was gating the bit on AdvertiseNodeNetworkLimited (prune).
	if config.AdvertiseNodeNetworkLimited {
		t.Fatal("test setup error: AdvertiseNodeNetworkLimited should be false here")
	}

	// When v2 is disabled (-bip324v2=false), NODE_P2P_V2 must NOT be advertised
	// (honest: do not claim a capability we are not running).
	config.PreferV2 = false
	pmNoV2 := NewPeerManager(config)
	cfgNoV2 := pmNoV2.makePeerConfig()
	if cfgNoV2.Services&ServiceNodeP2PV2 != 0 {
		t.Errorf("NODE_P2P_V2 advertised with v2 disabled: Services = 0x%X", cfgNoV2.Services)
	}
	// NODE_NETWORK_LIMITED stays set regardless of v2.
	if cfgNoV2.Services&ServiceNodeNetworkLimited == 0 {
		t.Error("NODE_NETWORK_LIMITED dropped when v2 disabled — it must always be set for a full node")
	}
	wantNoV2 := wantNetwork | wantWitness | wantNetworkLimited // 0x409
	if cfgNoV2.Services != wantNoV2 {
		t.Errorf("v2-disabled Services = 0x%X, want 0x%X", cfgNoV2.Services, wantNoV2)
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

	// Test that addresses are added to the book (must use routable IPs —
	// RFC1918/loopback are rejected by the BUG-27 IsRoutable fix).
	pm.addrBook.AddAddress(NetAddress{
		IP:   net.ParseIP("1.2.3.1"),
		Port: 8333,
	}, "test")

	initialSize := pm.addrBook.Size()

	// Simulate receiving routable addresses
	msg := &MsgAddr{
		AddrList: []NetAddress{
			{IP: net.ParseIP("1.2.3.2"), Port: 8333},
			{IP: net.ParseIP("1.2.3.3"), Port: 8333},
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
