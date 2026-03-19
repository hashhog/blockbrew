package p2p

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"
)

// TestConnTypeString verifies connection type string representations.
func TestConnTypeString(t *testing.T) {
	tests := []struct {
		ct   ConnType
		want string
	}{
		{ConnFullRelay, "full-relay"},
		{ConnBlockRelayOnly, "block-relay-only"},
		{ConnFeeler, "feeler"},
		{ConnInbound, "inbound"},
		{ConnType(999), "unknown"},
	}

	for _, tc := range tests {
		got := tc.ct.String()
		if got != tc.want {
			t.Errorf("ConnType(%d).String() = %q, want %q", tc.ct, got, tc.want)
		}
	}
}

// TestGetSubnet verifies subnet extraction for diversity tracking.
func TestGetSubnet(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.1.100", "192.168"},
		{"10.0.0.1", "10.0"},
		{"172.16.50.200", "172.16"},
		{"8.8.8.8", "8.8"},
		{"1.2.3.4", "1.2"},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		got := getSubnet(ip)
		if got != tc.want {
			t.Errorf("getSubnet(%s) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

// TestGetSubnetIPv6 verifies subnet extraction for IPv6 addresses.
func TestGetSubnetIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	subnet := getSubnet(ip)
	// Should return first 4 bytes as hex
	if subnet == "" || subnet == "unknown" {
		t.Errorf("getSubnet(IPv6) returned invalid: %q", subnet)
	}
}

// TestPoissonDuration verifies the Poisson duration generator.
func TestPoissonDuration(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	mean := 2 * time.Minute

	// Generate 1000 samples and check distribution
	var samples []time.Duration
	for i := 0; i < 1000; i++ {
		d := poissonDuration(mean, rng)
		samples = append(samples, d)

		// Should never be negative
		if d < 0 {
			t.Errorf("poissonDuration returned negative: %v", d)
		}

		// Should be capped at 4x mean
		if d > mean*4 {
			t.Errorf("poissonDuration exceeded 4x mean: %v > %v", d, mean*4)
		}
	}

	// Average should be roughly around the mean (with some tolerance)
	var total time.Duration
	for _, s := range samples {
		total += s
	}
	avg := total / time.Duration(len(samples))
	// Allow 50% tolerance due to distribution
	if avg < mean/2 || avg > mean*2 {
		t.Logf("warning: poissonDuration average %v differs significantly from mean %v", avg, mean)
	}
}

// TestPeerCountByType verifies detailed peer count tracking.
func TestPeerCountByType(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{
		Network: MainnetMagic,
	})

	// Initially all zeros
	fullRelay, blockRelayOnly, inbound := pm.PeerCountByType()
	if fullRelay != 0 || blockRelayOnly != 0 || inbound != 0 {
		t.Errorf("initial counts = %d/%d/%d, want 0/0/0", fullRelay, blockRelayOnly, inbound)
	}

	// Manually add peers to test counting
	pm.mu.Lock()
	pm.peers["1.2.3.4:8333"] = &PeerInfo{
		peer:     &Peer{addr: "1.2.3.4:8333"},
		connType: ConnFullRelay,
		subnet:   "1.2",
	}
	pm.outbound = 1
	pm.subnetCounts["1.2"] = 1

	pm.peers["5.6.7.8:8333"] = &PeerInfo{
		peer:     &Peer{addr: "5.6.7.8:8333"},
		connType: ConnBlockRelayOnly,
		subnet:   "5.6",
	}
	pm.blockRelayOnly = 1
	pm.subnetCounts["5.6"] = 1

	pm.peers["9.10.11.12:8333"] = &PeerInfo{
		peer:     &Peer{addr: "9.10.11.12:8333"},
		connType: ConnInbound,
		subnet:   "9.10",
	}
	pm.inbound = 1
	pm.mu.Unlock()

	fullRelay, blockRelayOnly, inbound = pm.PeerCountByType()
	if fullRelay != 1 {
		t.Errorf("fullRelay = %d, want 1", fullRelay)
	}
	if blockRelayOnly != 1 {
		t.Errorf("blockRelayOnly = %d, want 1", blockRelayOnly)
	}
	if inbound != 1 {
		t.Errorf("inbound = %d, want 1", inbound)
	}

	// Test PeerCount (combined outbound)
	outbound, inboundCount := pm.PeerCount()
	if outbound != 2 { // fullRelay + blockRelayOnly
		t.Errorf("outbound = %d, want 2", outbound)
	}
	if inboundCount != 1 {
		t.Errorf("inbound = %d, want 1", inboundCount)
	}
}

// TestIsBlockRelayOnly verifies block-relay-only connection detection.
func TestIsBlockRelayOnly(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{
		Network: MainnetMagic,
	})

	// Add a block-relay-only peer
	pm.mu.Lock()
	pm.peers["1.2.3.4:8333"] = &PeerInfo{
		peer:     &Peer{addr: "1.2.3.4:8333"},
		connType: ConnBlockRelayOnly,
	}
	pm.peers["5.6.7.8:8333"] = &PeerInfo{
		peer:     &Peer{addr: "5.6.7.8:8333"},
		connType: ConnFullRelay,
	}
	pm.mu.Unlock()

	if !pm.IsBlockRelayOnly("1.2.3.4:8333") {
		t.Error("1.2.3.4:8333 should be block-relay-only")
	}

	if pm.IsBlockRelayOnly("5.6.7.8:8333") {
		t.Error("5.6.7.8:8333 should not be block-relay-only")
	}

	if pm.IsBlockRelayOnly("unknown:8333") {
		t.Error("unknown peer should not be block-relay-only")
	}
}

// TestGetConnType verifies connection type retrieval.
func TestGetConnType(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{
		Network: MainnetMagic,
	})

	pm.mu.Lock()
	pm.peers["1.2.3.4:8333"] = &PeerInfo{
		peer:     &Peer{addr: "1.2.3.4:8333"},
		connType: ConnFeeler,
	}
	pm.mu.Unlock()

	if ct := pm.GetConnType("1.2.3.4:8333"); ct != ConnFeeler {
		t.Errorf("GetConnType() = %v, want ConnFeeler", ct)
	}

	// Unknown peers default to inbound
	if ct := pm.GetConnType("unknown:8333"); ct != ConnInbound {
		t.Errorf("GetConnType(unknown) = %v, want ConnInbound", ct)
	}
}

// TestMarkBlockReceived verifies block receipt tracking.
func TestMarkBlockReceived(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{
		Network: MainnetMagic,
	})

	now := time.Now()

	pm.mu.Lock()
	pm.peers["1.2.3.4:8333"] = &PeerInfo{
		peer:        &Peer{addr: "1.2.3.4:8333"},
		connType:    ConnInbound,
		connectedAt: now.Add(-time.Hour),
	}
	pm.mu.Unlock()

	// Mark block received
	pm.MarkBlockReceived("1.2.3.4:8333")

	pm.mu.RLock()
	info := pm.peers["1.2.3.4:8333"]
	pm.mu.RUnlock()

	if info.lastBlockTime.IsZero() {
		t.Error("lastBlockTime should be set after MarkBlockReceived")
	}

	if info.lastBlockTime.Before(now) {
		t.Error("lastBlockTime should be after test start time")
	}
}

// TestSubnetCounting verifies subnet diversity tracking.
func TestSubnetCounting(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{
		Network: MainnetMagic,
	})

	// Simulate adding peers from the same subnet
	info1 := &PeerInfo{
		peer:     &Peer{addr: "192.168.1.1:8333"},
		connType: ConnFullRelay,
		subnet:   "192.168",
	}
	info2 := &PeerInfo{
		peer:     &Peer{addr: "192.168.1.2:8333"},
		connType: ConnFullRelay,
		subnet:   "192.168",
	}
	info3 := &PeerInfo{
		peer:     &Peer{addr: "10.0.0.1:8333"},
		connType: ConnFullRelay,
		subnet:   "10.0",
	}

	pm.mu.Lock()
	pm.peers["192.168.1.1:8333"] = info1
	pm.updatePeerCounts(info1, +1)

	pm.peers["192.168.1.2:8333"] = info2
	pm.updatePeerCounts(info2, +1)

	pm.peers["10.0.0.1:8333"] = info3
	pm.updatePeerCounts(info3, +1)
	pm.mu.Unlock()

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.subnetCounts["192.168"] != 2 {
		t.Errorf("subnet 192.168 count = %d, want 2", pm.subnetCounts["192.168"])
	}
	if pm.subnetCounts["10.0"] != 1 {
		t.Errorf("subnet 10.0 count = %d, want 1", pm.subnetCounts["10.0"])
	}
	if pm.outbound != 3 {
		t.Errorf("outbound = %d, want 3", pm.outbound)
	}
}

// TestUpdatePeerCountsRemoval verifies subnet counts are decremented on removal.
func TestUpdatePeerCountsRemoval(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{
		Network: MainnetMagic,
	})

	info := &PeerInfo{
		peer:     &Peer{addr: "192.168.1.1:8333"},
		connType: ConnFullRelay,
		subnet:   "192.168",
	}

	pm.mu.Lock()
	pm.peers["192.168.1.1:8333"] = info
	pm.updatePeerCounts(info, +1)

	// Verify added
	if pm.subnetCounts["192.168"] != 1 {
		t.Errorf("after add: subnet count = %d, want 1", pm.subnetCounts["192.168"])
	}
	if pm.outbound != 1 {
		t.Errorf("after add: outbound = %d, want 1", pm.outbound)
	}

	// Remove
	pm.updatePeerCounts(info, -1)

	// Verify removed
	if pm.subnetCounts["192.168"] != 0 {
		t.Errorf("after remove: subnet count = %d, want 0", pm.subnetCounts["192.168"])
	}
	if _, exists := pm.subnetCounts["192.168"]; exists {
		t.Error("subnet entry should be deleted when count reaches 0")
	}
	if pm.outbound != 0 {
		t.Errorf("after remove: outbound = %d, want 0", pm.outbound)
	}
	pm.mu.Unlock()
}

// TestEvictionProtectsSubnetDiversity verifies that eviction logic protects
// peers from diverse subnets.
func TestEvictionProtectsSubnetDiversity(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{
		Network:    MainnetMagic,
		MaxInbound: 15,
	})

	now := time.Now()

	// Add inbound peers: a mix of subnets with enough peers that protection
	// slots don't cover everyone. We need >12 peers (4 block + 4 ping + 4 longest).
	pm.mu.Lock()

	// Unique subnet peers that should be protected by subnet diversity
	pm.peers["192.168.1.1:8333"] = &PeerInfo{
		peer:        &Peer{addr: "192.168.1.1:8333", state: PeerStateConnected, quit: make(chan struct{})},
		connType:    ConnInbound,
		subnet:      "192.168",
		connectedAt: now.Add(-1 * time.Minute), // newest
	}
	pm.inbound++

	pm.peers["172.16.0.1:8333"] = &PeerInfo{
		peer:        &Peer{addr: "172.16.0.1:8333", state: PeerStateConnected, quit: make(chan struct{})},
		connType:    ConnInbound,
		subnet:      "172.16",
		connectedAt: now.Add(-2 * time.Minute),
	}
	pm.inbound++

	// Over-represented subnet: many peers from 10.0.x.x
	for i := 0; i < 13; i++ {
		addr := fmt.Sprintf("10.0.0.%d:8333", i+1)
		pm.peers[addr] = &PeerInfo{
			peer:        &Peer{addr: addr, state: PeerStateConnected, quit: make(chan struct{})},
			connType:    ConnInbound,
			subnet:      "10.0",
			connectedAt: now.Add(-time.Duration(i+3) * time.Minute),
		}
		pm.inbound++
	}
	pm.mu.Unlock()

	// Try eviction
	evicted := pm.tryEvictInboundPeer()
	if !evicted {
		t.Fatal("should have evicted a peer")
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// The unique subnet peers should still exist (protected by subnet diversity)
	if _, exists := pm.peers["192.168.1.1:8333"]; !exists {
		t.Error("peer from unique subnet 192.168 should not have been evicted")
	}
	if _, exists := pm.peers["172.16.0.1:8333"]; !exists {
		t.Error("peer from unique subnet 172.16 should not have been evicted")
	}

	// One of the 10.0.x.x peers should be gone (it's the over-represented subnet)
	tenCount := 0
	for addr := range pm.peers {
		if len(addr) > 4 && addr[:4] == "10.0" {
			tenCount++
		}
	}
	if tenCount != 12 {
		t.Errorf("expected 12 peers from 10.0.x.x subnet remaining, got %d", tenCount)
	}
}

// TestEvictionPrefersNewestFromOverrepresentedSubnet verifies eviction logic
// prefers to evict the newest connection from an over-represented subnet.
func TestEvictionPrefersNewestFromOverrepresentedSubnet(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{
		Network:    MainnetMagic,
		MaxInbound: 5,
	})

	now := time.Now()

	// Add many peers from the same subnet
	pm.mu.Lock()
	for i := 0; i < 5; i++ {
		addr := fmt.Sprintf("10.0.0.%d:8333", i+1)
		pm.peers[addr] = &PeerInfo{
			peer:        &Peer{addr: addr, state: PeerStateConnected, quit: make(chan struct{})},
			connType:    ConnInbound,
			subnet:      "10.0",
			connectedAt: now.Add(-time.Duration(i) * time.Minute), // older peers first
		}
		pm.inbound++
	}
	pm.mu.Unlock()

	// Evict
	pm.tryEvictInboundPeer()

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// The newest peer (10.0.0.1) should have been evicted (connected most recently)
	// Actually, with i=0, 10.0.0.1 was connected now - 0 minutes = most recent
	if _, exists := pm.peers["10.0.0.1:8333"]; exists {
		t.Error("newest peer should have been evicted")
	}
}

// TestBlockRelayOnlyConfig verifies block-relay-only connection limits.
func TestBlockRelayOnlyConfig(t *testing.T) {
	// Test default
	pm := NewPeerManager(PeerManagerConfig{
		Network: MainnetMagic,
	})
	if pm.config.MaxBlockRelayOnly != DefaultMaxBlockRelayOnly {
		t.Errorf("default MaxBlockRelayOnly = %d, want %d",
			pm.config.MaxBlockRelayOnly, DefaultMaxBlockRelayOnly)
	}

	// Test custom
	pm2 := NewPeerManager(PeerManagerConfig{
		Network:           MainnetMagic,
		MaxBlockRelayOnly: 4,
	})
	if pm2.config.MaxBlockRelayOnly != 4 {
		t.Errorf("custom MaxBlockRelayOnly = %d, want 4", pm2.config.MaxBlockRelayOnly)
	}
}

// TestFeelerConstants verifies feeler-related constants.
func TestFeelerConstants(t *testing.T) {
	if FeelerInterval != 2*time.Minute {
		t.Errorf("FeelerInterval = %v, want 2m", FeelerInterval)
	}
	if ExtraBlockRelayInterval != 5*time.Minute {
		t.Errorf("ExtraBlockRelayInterval = %v, want 5m", ExtraBlockRelayInterval)
	}
	if MaxPeersPerSubnet != 2 {
		t.Errorf("MaxPeersPerSubnet = %d, want 2", MaxPeersPerSubnet)
	}
}

// TestPickAddressWithDiversityNoAddresses verifies behavior with empty address book.
func TestPickAddressWithDiversityNoAddresses(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{
		Network: MainnetMagic,
	})

	// Empty address book should return nil
	ka := pm.pickAddressWithDiversity(ConnFullRelay)
	if ka != nil {
		t.Error("expected nil with empty address book")
	}
}

// TestPickAddressWithDiversityFeeler verifies feelers don't check diversity.
func TestPickAddressWithDiversityFeeler(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{
		Network: MainnetMagic,
	})

	// Add an address
	pm.addrBook.AddAddress(NetAddress{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 8333,
	}, "test")

	// Saturate the subnet
	pm.mu.Lock()
	pm.subnetCounts["192.168"] = MaxPeersPerSubnet + 10
	pm.mu.Unlock()

	// Feelers should still pick this address (diversity not checked)
	ka := pm.pickAddressWithDiversity(ConnFeeler)
	if ka == nil {
		t.Error("feeler should pick address regardless of subnet saturation")
	}
}
