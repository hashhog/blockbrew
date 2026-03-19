package p2p

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ConnType represents the type of peer connection.
// Bitcoin Core: node/connection_types.h
type ConnType int

const (
	// ConnFullRelay is a standard outbound connection that relays blocks, txs, and addrs.
	// Target: 8 connections (MAX_OUTBOUND_FULL_RELAY_CONNECTIONS).
	ConnFullRelay ConnType = iota

	// ConnBlockRelayOnly is an outbound connection that only relays blocks.
	// Does not send/request tx inv, does not send addr/getaddr.
	// These connections are harder for attackers to detect, improving partition resistance.
	// Target: 2 connections (MAX_BLOCK_RELAY_ONLY_CONNECTIONS).
	ConnBlockRelayOnly

	// ConnFeeler is a short-lived connection to test if an address is reachable.
	// Disconnects after the version handshake completes.
	// Used to test-before-evict and move addresses from new to tried table.
	ConnFeeler

	// ConnInbound is a connection initiated by a remote peer.
	// Limit: 117 (DEFAULT_MAX_PEER_CONNECTIONS - MAX_OUTBOUND).
	ConnInbound
)

// Peer manager constants.
const (
	// DefaultMaxOutbound is the default target number of outbound connections.
	// Bitcoin Core: MAX_OUTBOUND_FULL_RELAY_CONNECTIONS = 8
	DefaultMaxOutbound = 8

	// DefaultMaxBlockRelayOnly is the default number of block-relay-only connections.
	// Bitcoin Core: MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2
	DefaultMaxBlockRelayOnly = 2

	// DefaultMaxInbound is the default maximum number of inbound connections.
	DefaultMaxInbound = 117

	// ConnectionAttemptInterval is how often to try connecting to new peers.
	ConnectionAttemptInterval = 30 * time.Second

	// FeelerInterval is how often to make feeler connections.
	// Bitcoin Core: FEELER_INTERVAL = 2min
	FeelerInterval = 2 * time.Minute

	// ExtraBlockRelayInterval is how often to make extra block-relay-only connections.
	// Bitcoin Core: EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL = 5min
	ExtraBlockRelayInterval = 5 * time.Minute

	// DNSSeedRefreshInterval is how often to re-query DNS seeds if address book is low.
	DNSSeedRefreshInterval = 11 * time.Minute

	// MinAddressesBeforeRefresh is the threshold below which we refresh DNS seeds.
	MinAddressesBeforeRefresh = 1000

	// DefaultBanDuration is the default time to ban a misbehaving peer.
	DefaultBanDuration = 24 * time.Hour

	// GetAddrInterval is the minimum time between getaddr requests to a peer.
	GetAddrInterval = 24 * time.Hour

	// MaxPeersPerSubnet is the maximum outbound connections to the same /16 subnet.
	// This provides ASN-like diversity without requiring ASN lookup tables.
	MaxPeersPerSubnet = 2
)

// PeerManagerConfig configures the peer manager.
type PeerManagerConfig struct {
	Network           uint32
	ChainParams       *consensus.ChainParams
	MaxOutbound       int             // Target full-relay outbound connections (default: 8)
	MaxBlockRelayOnly int             // Target block-relay-only connections (default: 2)
	MaxInbound        int             // Maximum inbound connections (default: 117)
	ListenAddr        string          // Address to listen for inbound (e.g., ":8333")
	UserAgent         string          // Our user agent string
	DataDir           string          // Data directory for persisting ban list
	BestHeightFunc    func() int32    // Callback to get current best height
	Listeners         *PeerListeners  // Callbacks for received messages
	OnPeerConnected    func(p *Peer)  // Called when a peer completes handshake
	OnPeerDisconnected func(p *Peer)  // Called when a peer disconnects
}

// BanInfo contains information about a banned peer.
type BanInfo struct {
	Expiry    time.Time `json:"ban_until"`
	Reason    string    `json:"ban_reason"`
	CreatedAt time.Time `json:"ban_created"`
}

// PeerInfo tracks per-peer metadata for connection management.
type PeerInfo struct {
	peer          *Peer
	connType      ConnType
	connectedAt   time.Time
	lastBlockTime time.Time // When we received the last block from this peer
	subnet        string    // /16 subnet key for diversity tracking
}

// PeerManager manages all peer connections.
type PeerManager struct {
	config          PeerManagerConfig
	mu              sync.RWMutex
	peers           map[string]*PeerInfo  // addr -> PeerInfo (all connected peers)
	outbound        int                   // Count of full-relay outbound peers
	blockRelayOnly  int                   // Count of block-relay-only outbound peers
	inbound         int                   // Count of inbound peers
	addrBook        *AddressBook          // Known addresses
	banned          map[string]*BanInfo   // IP -> ban info
	banDirty        bool                  // Whether ban list needs saving
	listener        net.Listener          // TCP listener for inbound
	quit            chan struct{}         // Signal to stop
	quitOnce        sync.Once             // Ensure quit is closed only once
	wg              sync.WaitGroup        // Wait for goroutines
	started         bool                  // Whether the manager has started
	subnetCounts    map[string]int        // subnet -> count of outbound connections (for diversity)
	rng             *rand.Rand            // Random number generator
}

// NewPeerManager creates a new peer manager.
func NewPeerManager(config PeerManagerConfig) *PeerManager {
	// Apply defaults
	if config.MaxOutbound == 0 {
		config.MaxOutbound = DefaultMaxOutbound
	}
	if config.MaxBlockRelayOnly == 0 {
		config.MaxBlockRelayOnly = DefaultMaxBlockRelayOnly
	}
	if config.MaxInbound == 0 {
		config.MaxInbound = DefaultMaxInbound
	}

	pm := &PeerManager{
		config:       config,
		peers:        make(map[string]*PeerInfo),
		addrBook:     NewAddressBook(),
		banned:       make(map[string]*BanInfo),
		subnetCounts: make(map[string]int),
		quit:         make(chan struct{}),
		rng:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	// Load ban list from disk
	pm.loadBanList()

	return pm
}

// Start begins DNS seed resolution, outbound connection attempts, and inbound listening.
func (pm *PeerManager) Start() error {
	pm.mu.Lock()
	if pm.started {
		pm.mu.Unlock()
		return fmt.Errorf("peer manager already started")
	}
	pm.started = true
	pm.mu.Unlock()

	// Start TCP listener if configured
	if pm.config.ListenAddr != "" {
		listener, err := net.Listen("tcp", pm.config.ListenAddr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", pm.config.ListenAddr, err)
		}
		pm.listener = listener

		pm.wg.Add(1)
		go pm.listenHandler()
	}

	// Start the connection manager
	pm.wg.Add(1)
	go pm.connectionHandler()

	return nil
}

// Stop gracefully disconnects all peers and stops the manager.
func (pm *PeerManager) Stop() {
	pm.quitOnce.Do(func() {
		close(pm.quit)

		// Close the listener to unblock Accept
		if pm.listener != nil {
			pm.listener.Close()
		}

		// Disconnect all peers
		pm.mu.RLock()
		peers := make([]*Peer, 0, len(pm.peers))
		for _, info := range pm.peers {
			peers = append(peers, info.peer)
		}
		pm.mu.RUnlock()

		for _, p := range peers {
			p.Disconnect()
		}

		// Wait for all goroutines
		pm.wg.Wait()
	})
}

// ConnectedPeers returns a snapshot of all connected peers.
func (pm *PeerManager) ConnectedPeers() []*Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	peers := make([]*Peer, 0, len(pm.peers))
	for _, info := range pm.peers {
		if info.peer.IsConnected() {
			peers = append(peers, info.peer)
		}
	}
	return peers
}

// BanPeer bans a peer's IP for a duration.
func (pm *PeerManager) BanPeer(addr string, duration time.Duration, reason string) {
	// Extract IP from addr (which may be "ip:port")
	ip := extractIP(addr)

	pm.mu.Lock()
	now := time.Now()
	pm.banned[ip] = &BanInfo{
		Expiry:    now.Add(duration),
		Reason:    reason,
		CreatedAt: now,
	}
	pm.banDirty = true

	// Find and disconnect any peers from this IP
	var toDisconnect []*Peer
	for peerAddr, info := range pm.peers {
		if extractIP(peerAddr) == ip {
			delete(pm.peers, peerAddr)
			pm.updatePeerCounts(info, -1)
			toDisconnect = append(toDisconnect, info.peer)
		}
	}
	pm.mu.Unlock()

	// Disconnect outside of lock
	for _, p := range toDisconnect {
		log.Printf("disconnecting peer %s: banned (%s)", p.Address(), reason)
		p.Disconnect()
	}

	// Persist ban list
	pm.saveBanList()
}

// updatePeerCounts adjusts peer counts when adding (+1) or removing (-1) a peer.
// Caller must hold pm.mu write lock.
func (pm *PeerManager) updatePeerCounts(info *PeerInfo, delta int) {
	switch info.connType {
	case ConnFullRelay:
		pm.outbound += delta
		if info.subnet != "" {
			pm.subnetCounts[info.subnet] += delta
			if pm.subnetCounts[info.subnet] <= 0 {
				delete(pm.subnetCounts, info.subnet)
			}
		}
	case ConnBlockRelayOnly:
		pm.blockRelayOnly += delta
		if info.subnet != "" {
			pm.subnetCounts[info.subnet] += delta
			if pm.subnetCounts[info.subnet] <= 0 {
				delete(pm.subnetCounts, info.subnet)
			}
		}
	case ConnFeeler:
		// Feelers don't count toward limits
		if info.subnet != "" {
			pm.subnetCounts[info.subnet] += delta
			if pm.subnetCounts[info.subnet] <= 0 {
				delete(pm.subnetCounts, info.subnet)
			}
		}
	case ConnInbound:
		pm.inbound += delta
	}
}

// Unban removes a ban for an IP address.
func (pm *PeerManager) Unban(ip string) bool {
	pm.mu.Lock()
	_, ok := pm.banned[ip]
	if ok {
		delete(pm.banned, ip)
		pm.banDirty = true
	}
	pm.mu.Unlock()

	if ok {
		pm.saveBanList()
	}
	return ok
}

// ListBanned returns a copy of the ban list.
func (pm *PeerManager) ListBanned() map[string]*BanInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// First clean up expired bans
	now := time.Now()
	result := make(map[string]*BanInfo)
	for ip, info := range pm.banned {
		if now.Before(info.Expiry) {
			result[ip] = &BanInfo{
				Expiry:    info.Expiry,
				Reason:    info.Reason,
				CreatedAt: info.CreatedAt,
			}
		}
	}
	return result
}

// ClearBanned removes all bans.
func (pm *PeerManager) ClearBanned() {
	pm.mu.Lock()
	pm.banned = make(map[string]*BanInfo)
	pm.banDirty = true
	pm.mu.Unlock()

	pm.saveBanList()
}

// SetBan adds or updates a ban. If duration is negative, the ban is removed.
func (pm *PeerManager) SetBan(ip string, duration time.Duration, reason string) {
	if duration < 0 {
		pm.Unban(ip)
		return
	}
	pm.BanPeer(ip, duration, reason)
}

// handlePeerBan is the callback invoked when a peer exceeds the misbehavior threshold.
func (pm *PeerManager) handlePeerBan(p *Peer) {
	pm.BanPeer(p.Address(), DefaultBanDuration, "misbehavior threshold exceeded")
}

// IsBanned checks if an IP is banned.
func (pm *PeerManager) IsBanned(addr string) bool {
	ip := extractIP(addr)
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.isBannedLocked(ip)
}

// isBannedLocked checks if an IP is banned (must hold read lock).
func (pm *PeerManager) isBannedLocked(ip string) bool {
	info, ok := pm.banned[ip]
	if !ok {
		return false
	}
	// Check if ban has expired
	if time.Now().After(info.Expiry) {
		return false
	}
	return true
}

// cleanupBans removes expired bans.
func (pm *PeerManager) cleanupBans() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	now := time.Now()
	for ip, info := range pm.banned {
		if now.After(info.Expiry) {
			delete(pm.banned, ip)
		}
	}
}

// PeerCount returns the number of connected peers (outbound, inbound).
// Outbound includes both full-relay and block-relay-only connections.
func (pm *PeerManager) PeerCount() (outbound, inbound int) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.outbound + pm.blockRelayOnly, pm.inbound
}

// PeerCountByType returns detailed peer counts by connection type.
func (pm *PeerManager) PeerCountByType() (fullRelay, blockRelayOnly, inbound int) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.outbound, pm.blockRelayOnly, pm.inbound
}

// BroadcastMessage sends a message to all connected peers.
func (pm *PeerManager) BroadcastMessage(msg Message) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, info := range pm.peers {
		if info.peer.IsConnected() {
			info.peer.SendMessage(msg)
		}
	}
}

// RelayTransaction sends an inv message for a transaction to all peers that want tx relay.
// This is called when a transaction is added to the mempool (e.g., via sendrawtransaction RPC).
// The fromPeer parameter is the address of the peer that sent us this transaction; we skip
// announcing back to them. Pass empty string if the transaction originated locally.
// fee is the transaction fee in satoshis, vsize is the virtual size in vbytes.
// These are used to filter by peer's feefilter (BIP133).
func (pm *PeerManager) RelayTransaction(txHash wire.Hash256, fee, vsize int64, fromPeer string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	inv := &MsgInv{
		InvList: []*InvVect{
			{Type: InvTypeWitnessTx, Hash: txHash},
		},
	}

	for addr, info := range pm.peers {
		// Skip the peer that sent us this transaction
		if addr == fromPeer {
			continue
		}

		// Only send to connected peers that want tx relay
		if !info.peer.IsConnected() || !info.peer.WantsTxRelay() {
			continue
		}

		// Check if the transaction meets the peer's feefilter (BIP133)
		if !info.peer.ShouldRelayTx(fee, vsize) {
			continue
		}

		info.peer.SendMessage(inv)
	}
}

// ForEachPeer calls the function for each connected peer.
func (pm *PeerManager) ForEachPeer(fn func(p *Peer)) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, info := range pm.peers {
		if info.peer.IsConnected() {
			fn(info.peer)
		}
	}
}

// GetPeer returns a peer by address, or nil if not found.
func (pm *PeerManager) GetPeer(addr string) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if info := pm.peers[addr]; info != nil {
		return info.peer
	}
	return nil
}

// GetPeerInfo returns the PeerInfo by address, or nil if not found.
func (pm *PeerManager) GetPeerInfo(addr string) *PeerInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.peers[addr]
}

// AddressBook returns the address book for external use.
func (pm *PeerManager) AddressBook() *AddressBook {
	return pm.addrBook
}

// MarkBlockReceived records that we received a block from a peer.
// This is used for eviction scoring - peers that send us blocks are more valuable.
func (pm *PeerManager) MarkBlockReceived(addr string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if info, ok := pm.peers[addr]; ok {
		info.lastBlockTime = time.Now()
	}
}

// IsBlockRelayOnly returns true if the peer is a block-relay-only connection.
func (pm *PeerManager) IsBlockRelayOnly(addr string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if info, ok := pm.peers[addr]; ok {
		return info.connType == ConnBlockRelayOnly
	}
	return false
}

// GetConnType returns the connection type for a peer.
func (pm *PeerManager) GetConnType(addr string) ConnType {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if info, ok := pm.peers[addr]; ok {
		return info.connType
	}
	return ConnInbound // Default
}

// String returns a string representation of the connection type.
func (ct ConnType) String() string {
	switch ct {
	case ConnFullRelay:
		return "full-relay"
	case ConnBlockRelayOnly:
		return "block-relay-only"
	case ConnFeeler:
		return "feeler"
	case ConnInbound:
		return "inbound"
	default:
		return "unknown"
	}
}

// connectionHandler manages outbound connection attempts.
func (pm *PeerManager) connectionHandler() {
	defer pm.wg.Done()

	// Initial DNS seed resolution
	pm.resolveDNSSeeds()

	// Random start offset for feeler timer to avoid synchronization
	feelerDelay := time.Duration(pm.rng.Int63n(int64(FeelerInterval)))
	nextFeeler := time.Now().Add(feelerDelay)

	blockRelayDelay := time.Duration(pm.rng.Int63n(int64(ExtraBlockRelayInterval)))
	nextBlockRelay := time.Now().Add(blockRelayDelay)

	ticker := time.NewTicker(ConnectionAttemptInterval)
	defer ticker.Stop()

	feelerTicker := time.NewTicker(10 * time.Second) // Check frequently, act based on nextFeeler
	defer feelerTicker.Stop()

	dnsRefreshTicker := time.NewTicker(DNSSeedRefreshInterval)
	defer dnsRefreshTicker.Stop()

	banCleanupTicker := time.NewTicker(1 * time.Hour)
	defer banCleanupTicker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.mu.RLock()
			needFullRelay := pm.outbound < pm.config.MaxOutbound
			needBlockRelay := pm.blockRelayOnly < pm.config.MaxBlockRelayOnly
			pm.mu.RUnlock()

			// Try to make a full-relay connection
			if needFullRelay {
				ka := pm.pickAddressWithDiversity(ConnFullRelay)
				if ka != nil {
					go pm.connectToPeerWithType(ka, ConnFullRelay)
				}
			}

			// Try to make a block-relay-only connection
			if needBlockRelay {
				ka := pm.pickAddressWithDiversity(ConnBlockRelayOnly)
				if ka != nil {
					go pm.connectToPeerWithType(ka, ConnBlockRelayOnly)
				}
			}

		case <-feelerTicker.C:
			now := time.Now()
			if now.After(nextFeeler) {
				// Schedule next feeler with exponential distribution
				nextFeeler = now.Add(poissonDuration(FeelerInterval, pm.rng))

				// Make a feeler connection
				ka := pm.addrBook.PickAddress()
				if ka != nil {
					go pm.connectToPeerWithType(ka, ConnFeeler)
				}
			}

			// Extra block-relay-only connections (for partition resistance)
			if now.After(nextBlockRelay) {
				nextBlockRelay = now.Add(poissonDuration(ExtraBlockRelayInterval, pm.rng))

				// Occasionally rotate a block-relay-only connection
				pm.maybeRotateBlockRelayPeer()
			}

		case <-dnsRefreshTicker.C:
			// Refresh DNS seeds if address book is too small
			if pm.addrBook.Size() < MinAddressesBeforeRefresh {
				pm.resolveDNSSeeds()
			}

		case <-banCleanupTicker.C:
			pm.cleanupBans()

		case <-pm.quit:
			return
		}
	}
}

// poissonDuration returns a random duration with exponential distribution.
// This provides unpredictable timing to prevent network-level analysis.
func poissonDuration(mean time.Duration, rng *rand.Rand) time.Duration {
	// Exponential distribution: -mean * ln(1-U) where U is uniform [0,1)
	u := rng.Float64()
	if u < 0.000001 {
		u = 0.000001 // Avoid log(0)
	}
	if u >= 1.0 {
		u = 0.999999
	}
	// Use -ln(u) since u is uniform (0,1), equivalent to -ln(1-u) for uniform [0,1)
	delay := -float64(mean) * (1.0 / (1.0 - u + 0.000001))
	if delay < 0 {
		delay = float64(mean)
	}
	// Cap at 4x mean to avoid extremely long delays
	if delay > float64(mean)*4 {
		delay = float64(mean) * 4
	}
	return time.Duration(delay)
}

// maybeRotateBlockRelayPeer disconnects a random block-relay-only peer to allow
// connecting to a new one. This improves partition resistance by regularly
// testing different parts of the network.
func (pm *PeerManager) maybeRotateBlockRelayPeer() {
	pm.mu.RLock()
	// Only rotate if we're at the limit
	if pm.blockRelayOnly < pm.config.MaxBlockRelayOnly {
		pm.mu.RUnlock()
		return
	}

	// Find a block-relay-only peer to disconnect
	var candidates []*PeerInfo
	for _, info := range pm.peers {
		if info.connType == ConnBlockRelayOnly {
			candidates = append(candidates, info)
		}
	}
	pm.mu.RUnlock()

	if len(candidates) == 0 {
		return
	}

	// Pick oldest block-relay-only connection to disconnect
	oldest := candidates[0]
	for _, c := range candidates[1:] {
		if c.connectedAt.Before(oldest.connectedAt) {
			oldest = c
		}
	}

	log.Printf("rotating block-relay-only peer %s", oldest.peer.Address())
	oldest.peer.Disconnect()
}

// resolveDNSSeeds queries DNS seeds and adds addresses to the address book.
func (pm *PeerManager) resolveDNSSeeds() {
	if pm.config.ChainParams == nil || len(pm.config.ChainParams.DNSSeeds) == 0 {
		return
	}

	ips := ResolveDNSSeeds(pm.config.ChainParams.DNSSeeds)
	for _, ip := range ips {
		netIP := net.ParseIP(ip)
		if netIP == nil {
			continue
		}
		pm.addrBook.AddAddress(NetAddress{
			IP:   netIP.To16(),
			Port: pm.config.ChainParams.DefaultPort,
		}, "dnsseed")
	}
}

// pickAddressWithDiversity selects an address that maintains subnet diversity.
// For feelers, we don't care about diversity (we're just testing reachability).
func (pm *PeerManager) pickAddressWithDiversity(connType ConnType) *KnownAddress {
	// Feelers don't need diversity checks
	if connType == ConnFeeler {
		return pm.addrBook.PickAddress()
	}

	pm.mu.RLock()
	subnetCounts := make(map[string]int)
	for k, v := range pm.subnetCounts {
		subnetCounts[k] = v
	}
	pm.mu.RUnlock()

	// Try to find an address from a subnet we don't have many connections to
	// Make up to 50 attempts to find a diverse address
	for i := 0; i < 50; i++ {
		ka := pm.addrBook.PickAddress()
		if ka == nil {
			return nil
		}

		subnet := getSubnet(ka.Addr.IP)
		count := subnetCounts[subnet]

		// Accept if we're under the per-subnet limit
		if count < MaxPeersPerSubnet {
			return ka
		}

		// With 10% chance, accept anyway to avoid getting stuck
		pm.mu.RLock()
		r := pm.rng.Float64()
		pm.mu.RUnlock()
		if r < 0.1 {
			return ka
		}
	}

	// Fallback to any address
	return pm.addrBook.PickAddress()
}

// getSubnet returns the /16 subnet key for an IP address.
// This provides a simple approximation of ASN diversity.
func getSubnet(ip net.IP) string {
	// Convert to IPv4 if it's an IPv4-mapped IPv6 address
	ipv4 := ip.To4()
	if ipv4 != nil {
		// Return first two octets as the /16 subnet
		return fmt.Sprintf("%d.%d", ipv4[0], ipv4[1])
	}

	// For IPv6, use the first 4 bytes (roughly /32)
	ip6 := ip.To16()
	if ip6 != nil && len(ip6) >= 4 {
		return fmt.Sprintf("[%x%x]", ip6[0:2], ip6[2:4])
	}

	return "unknown"
}

// connectToPeer attempts to connect to a known address (legacy, uses ConnFullRelay).
func (pm *PeerManager) connectToPeer(ka *KnownAddress) {
	pm.connectToPeerWithType(ka, ConnFullRelay)
}

// connectToPeerWithType attempts to connect to a known address with a specific connection type.
func (pm *PeerManager) connectToPeerWithType(ka *KnownAddress, connType ConnType) {
	addr := ka.Key()

	// Mark the attempt
	pm.addrBook.MarkAttempt(addr)

	// Check if already connected or banned
	pm.mu.RLock()
	if _, ok := pm.peers[addr]; ok {
		pm.mu.RUnlock()
		return
	}
	if pm.isBannedLocked(extractIP(addr)) {
		pm.mu.RUnlock()
		return
	}

	// Check if we still need this type of connection
	switch connType {
	case ConnFullRelay:
		if pm.outbound >= pm.config.MaxOutbound {
			pm.mu.RUnlock()
			return
		}
	case ConnBlockRelayOnly:
		if pm.blockRelayOnly >= pm.config.MaxBlockRelayOnly {
			pm.mu.RUnlock()
			return
		}
	case ConnFeeler:
		// Feelers always proceed
	}
	pm.mu.RUnlock()

	// Create peer config - block-relay-only peers don't relay txs
	peerConfig := pm.makePeerConfig()
	if connType == ConnBlockRelayOnly {
		peerConfig.DisableRelayTx = true
	}

	// Attempt connection
	peer, err := NewOutboundPeer(addr, peerConfig)
	if err != nil {
		// Connection failed
		return
	}
	peer.SetBanCallback(pm.handlePeerBan)

	// Create peer info
	peerInfo := &PeerInfo{
		peer:        peer,
		connType:    connType,
		connectedAt: time.Now(),
		subnet:      getSubnet(ka.Addr.IP),
	}

	// Register the peer before starting
	pm.mu.Lock()
	// Double-check we still need this connection
	switch connType {
	case ConnFullRelay:
		if pm.outbound >= pm.config.MaxOutbound {
			pm.mu.Unlock()
			peer.Disconnect()
			return
		}
	case ConnBlockRelayOnly:
		if pm.blockRelayOnly >= pm.config.MaxBlockRelayOnly {
			pm.mu.Unlock()
			peer.Disconnect()
			return
		}
	}
	pm.peers[addr] = peerInfo
	pm.updatePeerCounts(peerInfo, +1)
	pm.mu.Unlock()

	// Start the peer (this does the handshake)
	err = peer.Start()
	if err != nil {
		pm.removePeer(peer)
		return
	}

	// For feelers, disconnect immediately after successful handshake
	if connType == ConnFeeler {
		log.Printf("feeler connection to %s succeeded, disconnecting", addr)
		pm.addrBook.MarkSuccess(addr)
		peer.Disconnect()
		pm.removePeer(peer)
		return
	}

	// Mark success
	pm.addrBook.MarkSuccess(addr)

	// Notify listener
	if pm.config.OnPeerConnected != nil {
		pm.config.OnPeerConnected(peer)
	}

	// Request addresses from full-relay peers only (not block-relay-only)
	if connType == ConnFullRelay {
		peer.SendMessage(&MsgGetAddr{})
	}

	// Wait for peer to disconnect
	pm.waitForPeerDisconnect(peer)
}

// listenHandler accepts incoming connections.
func (pm *PeerManager) listenHandler() {
	defer pm.wg.Done()

	for {
		conn, err := pm.listener.Accept()
		if err != nil {
			select {
			case <-pm.quit:
				return
			default:
				// Temporary error, continue
				continue
			}
		}

		// Check limits and bans
		pm.mu.RLock()
		tooMany := pm.inbound >= pm.config.MaxInbound
		banned := pm.isBannedLocked(extractIP(conn.RemoteAddr().String()))
		pm.mu.RUnlock()

		if banned {
			conn.Close()
			continue
		}

		// If at capacity, try to evict a peer
		if tooMany {
			if !pm.tryEvictInboundPeer() {
				conn.Close()
				continue
			}
		}

		// Create inbound peer
		peer := NewInboundPeer(conn, pm.makePeerConfig())
		peer.SetBanCallback(pm.handlePeerBan)
		addr := peer.Address()

		// Get subnet for the inbound peer
		remoteIP := extractIP(conn.RemoteAddr().String())
		subnet := getSubnet(net.ParseIP(remoteIP))

		peerInfo := &PeerInfo{
			peer:        peer,
			connType:    ConnInbound,
			connectedAt: time.Now(),
			subnet:      subnet,
		}

		pm.mu.Lock()
		// Double-check limits
		if pm.inbound >= pm.config.MaxInbound {
			pm.mu.Unlock()
			conn.Close()
			continue
		}
		pm.peers[addr] = peerInfo
		pm.updatePeerCounts(peerInfo, +1)
		pm.mu.Unlock()

		// Start peer in a goroutine
		go func(p *Peer) {
			err := p.Start()
			if err != nil {
				pm.removePeer(p)
				return
			}

			// Notify listener
			if pm.config.OnPeerConnected != nil {
				pm.config.OnPeerConnected(p)
			}

			// Wait for disconnect
			pm.waitForPeerDisconnect(p)
		}(peer)
	}
}

// waitForPeerDisconnect waits for a peer to disconnect and cleans up.
func (pm *PeerManager) waitForPeerDisconnect(peer *Peer) {
	// Wait until the peer's quit channel is closed
	<-peer.quit

	pm.removePeer(peer)

	// Notify listener
	if pm.config.OnPeerDisconnected != nil {
		pm.config.OnPeerDisconnected(peer)
	}
}

// EvictionCandidate holds eviction scoring data for an inbound peer.
type EvictionCandidate struct {
	info         *PeerInfo
	addr         string
	connDuration time.Duration
	subnet       string
}

// tryEvictInboundPeer attempts to evict an inbound peer to make room for a new one.
// Returns true if a peer was evicted, false otherwise.
// Uses Bitcoin Core's eviction logic: protect peers from diverse subnets and
// those that have recently sent us useful data.
func (pm *PeerManager) tryEvictInboundPeer() bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Collect inbound candidates
	var candidates []*EvictionCandidate
	now := time.Now()

	for addr, info := range pm.peers {
		if info.connType != ConnInbound {
			continue
		}
		candidates = append(candidates, &EvictionCandidate{
			info:         info,
			addr:         addr,
			connDuration: now.Sub(info.connectedAt),
			subnet:       info.subnet,
		})
	}

	if len(candidates) == 0 {
		return false
	}

	// Bitcoin Core protects certain peers from eviction:
	// 1. Peers that recently sent us a block
	// 2. Peers with the lowest ping times
	// 3. Peers from unique subnets (for diversity)
	// 4. Peers that recently sent us a transaction

	// Group by subnet and protect the best peer from each subnet
	subnetBest := make(map[string]*EvictionCandidate)
	for _, c := range candidates {
		if existing, ok := subnetBest[c.subnet]; !ok {
			subnetBest[c.subnet] = c
		} else if c.info.lastBlockTime.After(existing.info.lastBlockTime) {
			// Keep the one with more recent block activity
			subnetBest[c.subnet] = c
		} else if c.connDuration > existing.connDuration {
			// Prefer longer-connected peers
			subnetBest[c.subnet] = c
		}
	}

	// Build protected set
	protected := make(map[string]bool)
	for _, c := range subnetBest {
		protected[c.addr] = true
	}

	// Also protect the 4 peers that sent us the most recent blocks
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].info.lastBlockTime.After(candidates[j].info.lastBlockTime)
	})
	for i := 0; i < 4 && i < len(candidates); i++ {
		if !candidates[i].info.lastBlockTime.IsZero() {
			protected[candidates[i].addr] = true
		}
	}

	// Also protect the 4 peers with the lowest ping times
	sort.Slice(candidates, func(i, j int) bool {
		iPing := candidates[i].info.peer.PingLatency()
		jPing := candidates[j].info.peer.PingLatency()
		// Peers that have not been pinged yet (zero latency) sort last
		if iPing == 0 {
			return false
		}
		if jPing == 0 {
			return true
		}
		return iPing < jPing
	})
	for i := 0; i < 4 && i < len(candidates); i++ {
		if candidates[i].info.peer.PingLatency() > 0 {
			protected[candidates[i].addr] = true
		}
	}

	// Also protect the 4 longest-connected peers
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].connDuration > candidates[j].connDuration
	})
	for i := 0; i < 4 && i < len(candidates); i++ {
		protected[candidates[i].addr] = true
	}

	// Find a non-protected candidate to evict
	// Prefer evicting peers from over-represented subnets
	subnetCountsLocal := make(map[string]int)
	for _, c := range candidates {
		subnetCountsLocal[c.subnet]++
	}

	var evictCandidate *EvictionCandidate
	maxSubnetCount := 0
	for _, c := range candidates {
		if protected[c.addr] {
			continue
		}
		count := subnetCountsLocal[c.subnet]
		if count > maxSubnetCount {
			maxSubnetCount = count
			evictCandidate = c
		} else if count == maxSubnetCount && evictCandidate != nil {
			// Tie-breaker: evict the newest connection
			if c.connDuration < evictCandidate.connDuration {
				evictCandidate = c
			}
		}
	}

	if evictCandidate == nil {
		return false
	}

	// Evict the candidate
	delete(pm.peers, evictCandidate.addr)
	pm.updatePeerCounts(evictCandidate.info, -1)

	// Disconnect outside of lock
	go func() {
		log.Printf("evicting inbound peer %s from subnet %s", evictCandidate.addr, evictCandidate.subnet)
		evictCandidate.info.peer.Disconnect()
	}()

	return true
}

// removePeer removes a peer from the manager.
func (pm *PeerManager) removePeer(peer *Peer) {
	addr := peer.Address()

	pm.mu.Lock()
	defer pm.mu.Unlock()

	info, ok := pm.peers[addr]
	if !ok {
		return // Already removed
	}

	delete(pm.peers, addr)
	pm.updatePeerCounts(info, -1)
}

// makePeerConfig creates a PeerConfig for new peers.
func (pm *PeerManager) makePeerConfig() PeerConfig {
	bestHeight := int32(0)
	if pm.config.BestHeightFunc != nil {
		bestHeight = pm.config.BestHeightFunc()
	}

	// Wrap the OnAddr listener to add addresses to our book
	listeners := pm.wrapListeners()

	return PeerConfig{
		Network:         pm.config.Network,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork | ServiceNodeWitness,
		UserAgent:       pm.config.UserAgent,
		BestHeight:      bestHeight,
		DisableRelayTx:  false,
		Listeners:       listeners,
	}
}

// wrapListeners wraps the configured listeners to add our own handlers.
func (pm *PeerManager) wrapListeners() *PeerListeners {
	listeners := &PeerListeners{}

	// Copy existing listeners if provided
	if pm.config.Listeners != nil {
		*listeners = *pm.config.Listeners
	}

	// Wrap OnAddr to add addresses to our book
	originalOnAddr := listeners.OnAddr
	listeners.OnAddr = func(p *Peer, msg *MsgAddr) {
		// Cap at MaxAddresses to prevent flooding
		addrs := msg.AddrList
		if len(addrs) > MaxAddresses {
			addrs = addrs[:MaxAddresses]
		}

		// Add to address book
		source := "unknown"
		if p != nil {
			source = p.Address()
		}
		pm.addrBook.AddAddresses(addrs, source)

		// Call original handler if set
		if originalOnAddr != nil {
			originalOnAddr(p, msg)
		}
	}

	// Wrap OnAddrv2 to add BIP155 addresses to our book
	originalOnAddrv2 := listeners.OnAddrv2
	listeners.OnAddrv2 = func(p *Peer, msg *MsgAddrv2) {
		// Cap at MaxAddresses to prevent flooding
		addrs := msg.AddrList
		if len(addrs) > MaxAddresses {
			addrs = addrs[:MaxAddresses]
		}

		// Add to address book
		source := "unknown"
		if p != nil {
			source = p.Address()
		}
		pm.addrBook.AddAddressesV2(addrs, source)

		// Call original handler if set
		if originalOnAddrv2 != nil {
			originalOnAddrv2(p, msg)
		}
	}

	return listeners
}

// extractIP extracts the IP address from an "ip:port" string.
func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Might already be just an IP
		return strings.TrimSpace(addr)
	}
	return host
}

// banListFile returns the path to the ban list file.
func (pm *PeerManager) banListFile() string {
	if pm.config.DataDir == "" {
		return ""
	}
	return filepath.Join(pm.config.DataDir, "banlist.json")
}

// banListData is the JSON structure for persisting the ban list.
type banListData struct {
	Bans map[string]*BanInfo `json:"bans"`
}

// saveBanList persists the ban list to disk.
func (pm *PeerManager) saveBanList() {
	path := pm.banListFile()
	if path == "" {
		return
	}

	pm.mu.RLock()
	if !pm.banDirty {
		pm.mu.RUnlock()
		return
	}

	// Make a copy of current bans
	data := banListData{
		Bans: make(map[string]*BanInfo),
	}
	now := time.Now()
	for ip, info := range pm.banned {
		// Only save non-expired bans
		if now.Before(info.Expiry) {
			data.Bans[ip] = info
		}
	}
	pm.mu.RUnlock()

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("failed to marshal ban list: %v", err)
		return
	}

	// Write atomically using temp file
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, jsonData, 0600); err != nil {
		log.Printf("failed to write ban list: %v", err)
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		log.Printf("failed to rename ban list: %v", err)
		os.Remove(tmpPath)
		return
	}

	pm.mu.Lock()
	pm.banDirty = false
	pm.mu.Unlock()

	log.Printf("saved ban list (%d entries)", len(data.Bans))
}

// loadBanList loads the ban list from disk.
func (pm *PeerManager) loadBanList() {
	path := pm.banListFile()
	if path == "" {
		return
	}

	jsonData, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("failed to read ban list: %v", err)
		}
		return
	}

	var data banListData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		log.Printf("failed to parse ban list: %v", err)
		return
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Load non-expired bans
	now := time.Now()
	loaded := 0
	for ip, info := range data.Bans {
		if now.Before(info.Expiry) {
			pm.banned[ip] = info
			loaded++
		}
	}

	if loaded > 0 {
		log.Printf("loaded %d banned addresses", loaded)
	}
}
