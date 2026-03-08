package p2p

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
)

// Peer manager constants.
const (
	// DefaultMaxOutbound is the default target number of outbound connections.
	DefaultMaxOutbound = 8

	// DefaultMaxInbound is the default maximum number of inbound connections.
	DefaultMaxInbound = 117

	// ConnectionAttemptInterval is how often to try connecting to new peers.
	ConnectionAttemptInterval = 30 * time.Second

	// DNSSeedRefreshInterval is how often to re-query DNS seeds if address book is low.
	DNSSeedRefreshInterval = 11 * time.Minute

	// MinAddressesBeforeRefresh is the threshold below which we refresh DNS seeds.
	MinAddressesBeforeRefresh = 1000

	// DefaultBanDuration is the default time to ban a misbehaving peer.
	DefaultBanDuration = 24 * time.Hour

	// GetAddrInterval is the minimum time between getaddr requests to a peer.
	GetAddrInterval = 24 * time.Hour
)

// PeerManagerConfig configures the peer manager.
type PeerManagerConfig struct {
	Network        uint32
	ChainParams    *consensus.ChainParams
	MaxOutbound    int             // Target outbound connections (default: 8)
	MaxInbound     int             // Maximum inbound connections (default: 117)
	ListenAddr     string          // Address to listen for inbound (e.g., ":8333")
	UserAgent      string          // Our user agent string
	BestHeightFunc func() int32    // Callback to get current best height
	Listeners      *PeerListeners  // Callbacks for received messages
	OnPeerConnected    func(p *Peer) // Called when a peer completes handshake
	OnPeerDisconnected func(p *Peer) // Called when a peer disconnects
}

// BanInfo contains information about a banned peer.
type BanInfo struct {
	Expiry time.Time
	Reason string
}

// PeerManager manages all peer connections.
type PeerManager struct {
	config   PeerManagerConfig
	mu       sync.RWMutex
	peers    map[string]*Peer     // addr -> Peer (all connected peers)
	outbound int                  // Count of outbound peers
	inbound  int                  // Count of inbound peers
	addrBook *AddressBook         // Known addresses
	banned   map[string]*BanInfo  // IP -> ban info
	listener net.Listener         // TCP listener for inbound
	quit     chan struct{}        // Signal to stop
	quitOnce sync.Once            // Ensure quit is closed only once
	wg       sync.WaitGroup       // Wait for goroutines
	started  bool                 // Whether the manager has started
}

// NewPeerManager creates a new peer manager.
func NewPeerManager(config PeerManagerConfig) *PeerManager {
	// Apply defaults
	if config.MaxOutbound == 0 {
		config.MaxOutbound = DefaultMaxOutbound
	}
	if config.MaxInbound == 0 {
		config.MaxInbound = DefaultMaxInbound
	}

	return &PeerManager{
		config:   config,
		peers:    make(map[string]*Peer),
		addrBook: NewAddressBook(),
		banned:   make(map[string]*BanInfo),
		quit:     make(chan struct{}),
	}
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
		for _, p := range pm.peers {
			peers = append(peers, p)
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
	for _, p := range pm.peers {
		if p.IsConnected() {
			peers = append(peers, p)
		}
	}
	return peers
}

// BanPeer bans a peer's IP for a duration.
func (pm *PeerManager) BanPeer(addr string, duration time.Duration, reason string) {
	// Extract IP from addr (which may be "ip:port")
	ip := extractIP(addr)

	pm.mu.Lock()
	pm.banned[ip] = &BanInfo{
		Expiry: time.Now().Add(duration),
		Reason: reason,
	}
	// Disconnect the peer if connected
	if p, ok := pm.peers[addr]; ok {
		delete(pm.peers, addr)
		if p.Inbound() {
			pm.inbound--
		} else {
			pm.outbound--
		}
		pm.mu.Unlock()
		p.Disconnect()
		return
	}
	pm.mu.Unlock()
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
func (pm *PeerManager) PeerCount() (outbound, inbound int) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.outbound, pm.inbound
}

// BroadcastMessage sends a message to all connected peers.
func (pm *PeerManager) BroadcastMessage(msg Message) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, p := range pm.peers {
		if p.IsConnected() {
			p.SendMessage(msg)
		}
	}
}

// ForEachPeer calls the function for each connected peer.
func (pm *PeerManager) ForEachPeer(fn func(p *Peer)) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, p := range pm.peers {
		if p.IsConnected() {
			fn(p)
		}
	}
}

// GetPeer returns a peer by address, or nil if not found.
func (pm *PeerManager) GetPeer(addr string) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.peers[addr]
}

// AddressBook returns the address book for external use.
func (pm *PeerManager) AddressBook() *AddressBook {
	return pm.addrBook
}

// connectionHandler manages outbound connection attempts.
func (pm *PeerManager) connectionHandler() {
	defer pm.wg.Done()

	// Initial DNS seed resolution
	pm.resolveDNSSeeds()

	ticker := time.NewTicker(ConnectionAttemptInterval)
	defer ticker.Stop()

	dnsRefreshTicker := time.NewTicker(DNSSeedRefreshInterval)
	defer dnsRefreshTicker.Stop()

	banCleanupTicker := time.NewTicker(1 * time.Hour)
	defer banCleanupTicker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.mu.RLock()
			needMore := pm.outbound < pm.config.MaxOutbound
			pm.mu.RUnlock()

			if needMore {
				ka := pm.addrBook.PickAddress()
				if ka != nil {
					go pm.connectToPeer(ka)
				}
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

// connectToPeer attempts to connect to a known address.
func (pm *PeerManager) connectToPeer(ka *KnownAddress) {
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
	// Check if we still need outbound peers
	if pm.outbound >= pm.config.MaxOutbound {
		pm.mu.RUnlock()
		return
	}
	pm.mu.RUnlock()

	// Attempt connection
	peer, err := NewOutboundPeer(addr, pm.makePeerConfig())
	if err != nil {
		// Connection failed
		return
	}

	// Register the peer before starting
	pm.mu.Lock()
	// Double-check we still need this connection
	if pm.outbound >= pm.config.MaxOutbound {
		pm.mu.Unlock()
		peer.Disconnect()
		return
	}
	pm.peers[addr] = peer
	pm.outbound++
	pm.mu.Unlock()

	// Start the peer (this does the handshake)
	err = peer.Start()
	if err != nil {
		pm.removePeer(peer)
		return
	}

	// Mark success
	pm.addrBook.MarkSuccess(addr)

	// Notify listener
	if pm.config.OnPeerConnected != nil {
		pm.config.OnPeerConnected(peer)
	}

	// Request addresses from this peer
	peer.SendMessage(&MsgGetAddr{})

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

		if tooMany || banned {
			conn.Close()
			continue
		}

		// Create inbound peer
		peer := NewInboundPeer(conn, pm.makePeerConfig())
		addr := peer.Address()

		pm.mu.Lock()
		// Double-check limits
		if pm.inbound >= pm.config.MaxInbound {
			pm.mu.Unlock()
			conn.Close()
			continue
		}
		pm.peers[addr] = peer
		pm.inbound++
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

// removePeer removes a peer from the manager.
func (pm *PeerManager) removePeer(peer *Peer) {
	addr := peer.Address()

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, ok := pm.peers[addr]; !ok {
		return // Already removed
	}

	delete(pm.peers, addr)
	if peer.Inbound() {
		pm.inbound--
	} else {
		pm.outbound--
	}
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
