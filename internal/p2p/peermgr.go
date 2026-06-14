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

	// ConnManual is a user-configured outbound connection added via addnode RPC.
	// Bitcoin Core: CONNECTION_TYPE::MANUAL (node/connection_types.h).
	// Manual connections are NEVER banned or discouraged, even on misbehavior,
	// because the operator explicitly requested them (anchor nodes, trusted peers).
	ConnManual
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

	// MinAddressesBeforeRefresh is the threshold below which we refresh DNS seeds
	// regardless of peer health. Acts as a hard floor — a book this small can't
	// supply diverse candidates.
	MinAddressesBeforeRefresh = 1000

	// MinGoodAddrsBeforeRefresh is the threshold of addresses with a prior
	// successful handshake below which we also refresh DNS. This catches the
	// stale-but-large-book case: a node with thousands of gossip-learned
	// addresses, none of which still accept connections, would otherwise
	// never re-seed. Set to roughly 2× the default outbound target.
	MinGoodAddrsBeforeRefresh = 16

	// DefaultBanDuration is the default time to ban a misbehaving peer.
	DefaultBanDuration = 24 * time.Hour

	// GetAddrInterval is the minimum time between getaddr requests to a peer.
	GetAddrInterval = 24 * time.Hour

	// MaxPeersPerSubnet is the maximum outbound connections to the same /16 subnet.
	// This provides ASN-like diversity without requiring ASN lookup tables.
	MaxPeersPerSubnet = 2

	// MaxBlockRelayOnlyAnchors is the maximum number of block-relay-only anchors
	// to persist across restarts. Reference: Bitcoin Core net.h MAX_BLOCK_RELAY_ONLY_ANCHORS.
	MaxBlockRelayOnlyAnchors = 2

	// AnchorsFilename is the file used to persist block-relay-only peer addresses.
	AnchorsFilename = "anchors.json"

	// ASMapHealthCheckInterval is how often to run the asmap health check.
	// Bitcoin Core uses 24h (net.h ASMAP_HEALTH_CHECK_INTERVAL); we use 1h
	// to surface stale-asmap warnings sooner on busy nodes.
	ASMapHealthCheckInterval = 3600 * time.Second

	// ASMapHealthCheckTopN is the number of top ASNs (by address count) to
	// include in the health-check log line.
	ASMapHealthCheckTopN = 5
)

// PeerManagerConfig configures the peer manager.
type PeerManagerConfig struct {
	Network            uint32
	ChainParams        *consensus.ChainParams
	MaxOutbound        int            // Target full-relay outbound connections (default: 8)
	MaxBlockRelayOnly  int            // Target block-relay-only connections (default: 2)
	MaxInbound         int            // Maximum inbound connections (default: 117)
	ListenAddr         string         // Address to listen for inbound (e.g., ":8333")
	UserAgent          string         // Our user agent string
	DataDir            string         // Data directory for persisting ban list
	BestHeightFunc     func() int32   // Callback to get current best height
	Listeners          *PeerListeners // Callbacks for received messages
	OnPeerConnected    func(p *Peer)  // Called when a peer completes handshake
	OnPeerDisconnected func(p *Peer)  // Called when a peer disconnects
	// PreferV2 enables BIP-324 v2 transport negotiation on both new outbound
	// connections AND incoming inbound connections.  Inbound classification
	// peeks 64 bytes; v1 peers fall through to legacy plaintext via the
	// prefixed-conn shim in transport.go.
	PreferV2 bool

	// EnablePackageRelay gates the BIP-331 "sendpackages" SEND in the version
	// handshake. Default OFF (Core v31.99 has no package-relay wire protocol);
	// opt in via cfg.EnablePackageRelay (-packagerelay / BLOCKBREW_PACKAGE_RELAY=1).
	EnablePackageRelay bool

	// AdvertiseNodeBloom controls whether NODE_BLOOM (BIP-111) is OR'd
	// into our advertised service bits in the version handshake.  This is
	// the gate Bitcoin Core uses for honoring BIP-35 "mempool" requests
	// (net_processing.cpp:4855 — `peer.m_our_services & NODE_BLOOM`).
	// Wired from the top-level `-peerbloomfilters` flag.  Default false
	// in this struct's zero value; main.go always sets it explicitly.
	AdvertiseNodeBloom bool

	// AdvertiseNodeNetworkLimited records whether this node is running in
	// prune mode (-prune > 0). NOTE: it does NOT gate the NODE_NETWORK_LIMITED
	// (BIP-159, 1<<10) advertisement — that bit is set UNCONDITIONALLY for a
	// full node in makePeerConfig, matching Core init.cpp:863 which seeds
	// g_local_services with `NODE_NETWORK_LIMITED | NODE_WITNESS` on every run
	// (prune and non-prune alike). NODE_NETWORK_LIMITED only asserts "I can
	// serve at least the most recent 288 blocks", which is trivially true for a
	// node serving the whole chain; the earlier "only when pruning" reading was
	// wrong. This field is retained for callers that need to know prune mode is
	// active (e.g. for the NODE_NETWORK distinction in future snapshot/IBD
	// gating, per Core init.cpp:1947-1952).
	AdvertiseNodeNetworkLimited bool

	// AdvertiseCompactFilters controls whether NODE_COMPACT_FILTERS (BIP-157,
	// 1<<6) is OR'd into our advertised service bits in the version handshake.
	// Set when -blockfilterindex is enabled, mirroring Bitcoin Core's
	// net_processing.cpp / init.cpp which adds NODE_COMPACT_FILTERS to
	// g_local_services when the block filter index is active.
	// When unset, blockbrew will still process incoming getcfilters /
	// getcfheaders / getcfcheckpt messages (if handlers are wired), but will
	// not advertise to peers that it can serve those requests proactively.
	AdvertiseCompactFilters bool

	// ASMapFile is the path to a Bitcoin Core-format asmap binary file used
	// for AS-level peer bucketing. When non-empty, blockbrew loads and
	// validates the file at startup and uses it to derive AS numbers for
	// eclipse-resistance diversity. Mirrors Bitcoin Core's `-asmap=<file>`
	// flag (init.cpp). Leave empty to use the legacy /16 subnet grouping.
	ASMapFile string

	// ConnectPeers, when non-empty, pins the node to ONLY these <ip:port>
	// peers: the connection manager dials each one as a manual connection,
	// re-dials any that drop, and skips BOTH DNS-seed resolution AND the
	// addrman/auto-outbound maintenance loop (full-relay, block-relay-only,
	// feeler, and the DNS-refresh trigger). Mirrors Bitcoin Core's
	// `-connect=<ip:port>` (init.cpp: implies -dnsseed=0 + turns off
	// automatic outbound connections) and clearbit's connect_address branch
	// (peer.zig:7009 skips dnsSeeds(); peer.zig:7050 gates outbound-fill on
	// connect_address==null). Empty (default) = normal peer discovery.
	ConnectPeers []string

	// NoDNSSeed suppresses DNS-seed resolution without otherwise changing
	// peer discovery (addrman/auto-outbound dialing still runs). Mirrors
	// Bitcoin Core's `-dnsseed=0` / `-nodnsseed` and clearbit's
	// `--nodnsseed` (dns_seed=false). Implied when ConnectPeers is set.
	NoDNSSeed bool

	// NoFixedSeeds disables the last-resort fixed-seed fallback. Mirrors
	// Bitcoin Core's `-fixedseeds=0` (DEFAULT_FIXEDSEEDS=true, so fixed seeds
	// are ON by default — net.h:97). The zero value (false) keeps fixed seeds
	// enabled. When true, a node whose DNS seeding fails and whose address
	// book is empty will NOT inject the curated bootstrap IPs (it relies
	// solely on -addnode / gossip / inbound). Suppressed unconditionally under
	// -connect, exactly like DNS seeding.
	NoFixedSeeds bool
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
	config         PeerManagerConfig
	mu             sync.RWMutex
	peers          map[string]*PeerInfo // addr -> PeerInfo (all connected peers)
	outbound       int                  // Count of full-relay outbound peers
	blockRelayOnly int                  // Count of block-relay-only outbound peers
	inbound        int                  // Count of inbound peers
	addrBook       *AddressBook         // Known addresses
	banned         map[string]*BanInfo  // IP -> ban info
	banDirty       bool                 // Whether ban list needs saving
	listener       net.Listener         // TCP listener for inbound
	quit           chan struct{}        // Signal to stop
	quitOnce       sync.Once            // Ensure quit is closed only once
	wg             sync.WaitGroup       // Wait for goroutines
	started        bool                 // Whether the manager has started
	subnetCounts   map[string]int       // subnet -> count of outbound connections (for diversity)
	rng            *rand.Rand           // Random number generator
	asmap          []byte               // Loaded asmap trie bytes (nil = disabled)

	// fixedSeedsAdded is the one-shot guard for the last-resort fixed-seed
	// fallback. Set true after addFixedSeeds() has injected the curated
	// bootstrap IPs so they are never re-injected (Core net.cpp:2641 sets
	// add_fixed_seeds=false after firing). Guarded by mu.
	fixedSeedsAdded bool
}

// UsingASMap returns true when an asmap was loaded at startup. Mirrors
// Bitcoin Core's NetGroupManager::UsingASMap() (`m_asmap.size() > 0`).
func (pm *PeerManager) UsingASMap() bool {
	return len(pm.asmap) > 0
}

// GetMappedASForAddr returns the ASN for the given peer address string
// (host:port or host). Returns 0 when asmap is not loaded or the IP has
// no entry. Mirrors Core's NetGroupManager::GetMappedAS().
func (pm *PeerManager) GetMappedASForAddr(addr string) uint32 {
	if !pm.UsingASMap() {
		return 0
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	return GetMappedAS(pm.asmap, ip)
}

// ASMapHealthCheckResult holds the statistics produced by ASMapHealthCheck.
type ASMapHealthCheckResult struct {
	Total    int        // total clearnet addresses sampled
	Mapped   int        // addresses with a non-zero ASN
	Unmapped int        // addresses with ASN == 0 (no trie entry)
	UniqueAS int        // distinct ASNs seen
	TopASNs  []ASNCount // top ASMapHealthCheckTopN ASNs by address count
}

// ASNCount pairs an ASN with its occurrence count in the sampled address set.
type ASNCount struct {
	ASN   uint32
	Count int
}

// ASMapHealthCheck iterates over all AddrMan entries plus currently-connected
// peers, maps each to an ASN via the loaded asmap trie, and logs a summary.
// Returns nil when no asmap is loaded (noop). Mirrors Bitcoin Core's
// NetGroupManager::ASMapHealthCheck() (netgroup.cpp:109) and
// CConnman::ASMapHealthCheck() (net.cpp:4178).
//
// Extends Core by:
//   - including currently-connected peers (not only AddrMan)
//   - de-duplicating addresses across both sources
//   - reporting top-N ASNs by entry count
func (pm *PeerManager) ASMapHealthCheck() *ASMapHealthCheckResult {
	if !pm.UsingASMap() {
		return nil
	}

	// Collect unique IPs from AddrMan entries.
	seen := make(map[string]struct{})
	var ips []net.IP

	for _, ka := range pm.addrBook.AllAddresses() {
		if ka.Addr.IP == nil {
			continue
		}
		key := ka.Addr.IP.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		ips = append(ips, ka.Addr.IP)
	}

	// Also include currently-connected peer IPs.
	pm.mu.RLock()
	for addr := range pm.peers {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		ips = append(ips, ip)
	}
	pm.mu.RUnlock()

	// Map each IP to an ASN and tally results.
	asnCounts := make(map[uint32]int)
	unmapped := 0
	for _, ip := range ips {
		asn := GetMappedAS(pm.asmap, ip)
		if asn == 0 {
			unmapped++
		} else {
			asnCounts[asn]++
		}
	}

	// Build sorted top-N list.
	type kv struct {
		asn   uint32
		count int
	}
	pairs := make([]kv, 0, len(asnCounts))
	for asn, cnt := range asnCounts {
		pairs = append(pairs, kv{asn, cnt})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].asn < pairs[j].asn
	})
	topN := ASMapHealthCheckTopN
	if len(pairs) < topN {
		topN = len(pairs)
	}
	top := make([]ASNCount, topN)
	for i := 0; i < topN; i++ {
		top[i] = ASNCount{ASN: pairs[i].asn, Count: pairs[i].count}
	}

	res := &ASMapHealthCheckResult{
		Total:    len(ips),
		Mapped:   len(ips) - unmapped,
		Unmapped: unmapped,
		UniqueAS: len(asnCounts),
		TopASNs:  top,
	}

	// Format top-ASN list for the log line.
	topStr := ""
	for i, ac := range top {
		if i > 0 {
			topStr += ", "
		}
		topStr += fmt.Sprintf("AS%d(%d)", ac.ASN, ac.Count)
	}
	if topStr == "" {
		topStr = "none"
	}

	log.Printf("ASMap Health Check: %d clearnet peers mapped to %d ASNs, %d unmapped; top %d: %s",
		res.Total, res.UniqueAS, res.Unmapped, len(top), topStr)

	return res
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

	// Load asmap if configured. Mirrors Core init.cpp:1603-1628.
	if config.ASMapFile != "" {
		data, err := LoadAsmap(config.ASMapFile)
		if err != nil {
			log.Printf("Warning: failed to load asmap from %s: %v — falling back to /16 subnet grouping", config.ASMapFile, err)
		} else {
			pm.asmap = data
			log.Printf("Using asmap version %s (%d bytes) from %s for IP bucketing",
				AsmapVersion(data), len(data), config.ASMapFile)
		}
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

	// Load anchor connections from previous session (block-relay-only peers)
	pm.loadAnchors()

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
		// Save block-relay-only peers as anchors before disconnecting
		pm.saveAnchors()

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
	case ConnManual:
		// Manual connections count toward outbound but bypass the cap check.
		pm.outbound += delta
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
//
// W99 G2 fix: mirrors Bitcoin Core MaybeDiscourageAndDisconnect (net_processing.cpp:5083):
//
//	if HasPermission(NoBan) → no-op (noBan already guarded in Peer.Misbehaving, but
//	                            double-check here for callers that bypass Misbehaving).
//	if IsManualConn()       → no-op (operator explicitly added this peer).
//	if addr.IsLocal()       → disconnect ONLY, do NOT add to discourage/ban list.
//	otherwise               → disconnect + discourage (BanPeer).
func (pm *PeerManager) handlePeerBan(p *Peer) {
	addr := p.Address()

	// Guard 1: NoBan permission — never disconnect or discourage.
	if p.IsNoBan() {
		log.Printf("handlePeerBan: peer %s has NoBan permission — skipping ban", addr)
		return
	}

	// Guard 2: Manual connection — never disconnect or discourage.
	pm.mu.RLock()
	info, exists := pm.peers[addr]
	isManual := exists && info.connType == ConnManual
	pm.mu.RUnlock()
	if isManual {
		log.Printf("handlePeerBan: peer %s is a manual connection — skipping ban", addr)
		return
	}

	// Guard 3: Local address — disconnect only, do NOT add to ban list.
	// Bitcoin Core: pnode.addr.IsLocal() → fDisconnect = true (no Discourage).
	if isLocalAddr(addr) {
		log.Printf("handlePeerBan: peer %s is a local address — disconnecting without banning", addr)
		pm.disconnectPeerOnly(addr)
		return
	}

	// Regular inbound/outbound peer: disconnect + add to discourage list.
	pm.BanPeer(addr, DefaultBanDuration, "misbehavior threshold exceeded")
}

// disconnectPeerOnly disconnects a peer without adding it to the ban list.
// Used for local-address peers that misbehave (Core: disconnect-but-don't-discourage).
func (pm *PeerManager) disconnectPeerOnly(addr string) {
	pm.mu.Lock()
	info, ok := pm.peers[addr]
	if ok {
		delete(pm.peers, addr)
		pm.updatePeerCounts(info, -1)
	}
	pm.mu.Unlock()
	if ok {
		log.Printf("disconnecting peer %s (local-addr misbehavior, no ban)", addr)
		info.peer.Disconnect()
	}
}

// isLocalAddr returns true if addr refers to a loopback or local (RFC1918 /
// link-local) address. Bitcoin Core's CNetAddr::IsLocal() covers loopback +
// link-local; we match that here.
func isLocalAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
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

// AnnounceBlock announces a newly accepted block to all connected peers,
// honoring BIP-130 (sendheaders).  Peers that previously sent us a
// `sendheaders` message receive a `headers` message containing the block
// header directly; others receive an `inv` for the block hash.
//
// This avoids the extra `inv -> getheaders -> headers -> getdata` round-trip
// for header-preferring peers and is what Bitcoin Core's net_processing.cpp
// `MaybeSendInventory` does for new tip announcements.  Reference:
// camlcoin `lib/peer_manager.ml::announce_block`.
func (pm *PeerManager) AnnounceBlock(header wire.BlockHeader, hash wire.Hash256) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	headersMsg := &MsgHeaders{Headers: []wire.BlockHeader{header}}
	invMsg := &MsgInv{
		InvList: []*InvVect{
			{Type: InvTypeBlock, Hash: hash},
		},
	}

	for _, info := range pm.peers {
		peer := info.peer
		if !peer.IsConnected() {
			continue
		}
		if peer.SendsHeaders() {
			peer.SendMessage(headersMsg)
		} else {
			peer.SendMessage(invMsg)
		}
	}
}

// RelayTransaction sends an inv message for a transaction to all peers that want tx relay.
// This is called when a transaction is added to the mempool (e.g., via sendrawtransaction RPC).
// The fromPeer parameter is the address of the peer that sent us this transaction; we skip
// announcing back to them. Pass empty string if the transaction originated locally.
// txHash is the txid (legacy hash), wtxHash is the witness txid (wtxid, BIP-339).
// fee is the transaction fee in satoshis, vsize is the virtual size in vbytes.
// These are used to filter by peer's feefilter (BIP133).
//
// Per BIP-339 and Bitcoin Core net_processing.cpp RelayTransaction:
//   - Peers with wtxidrelay negotiated: announce as inv{MSG_WTX=5, wtxid}
//   - Legacy peers:                     announce as inv{MSG_TX=1, txid}
//
// MSG_WITNESS_TX (0x40000001) is a BIP-144 getdata witness request flag and
// must NOT be used in inv announcements — Core peers log "Unknown inv type"
// and discard any inv with that type value.
func (pm *PeerManager) RelayTransaction(txHash, wtxHash wire.Hash256, fee, vsize int64, fromPeer string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

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

		// Select inv type and hash per BIP-339 / Core RelayTransaction logic:
		// wtxid-relay peers get MSG_WTX=5 + wtxid; legacy peers get MSG_TX=1 + txid.
		var invType InvType
		var hash wire.Hash256
		if info.peer.WTxidRelay() {
			invType = InvTypeWtx
			hash = wtxHash
		} else {
			invType = InvTypeTx
			hash = txHash
		}

		inv := &MsgInv{
			InvList: []*InvVect{
				{Type: invType, Hash: hash},
			},
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

// ConnectManualPeer adds an address to the address book and immediately
// attempts an outbound connection. Used by the addnode RPC.
func (pm *PeerManager) ConnectManualPeer(addr string) {
	// Parse the address
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Printf("addnode: invalid address %q: %v", addr, err)
		return
	}
	na := NetAddress{
		Services: 0,
		IP:       tcpAddr.IP,
		Port:     uint16(tcpAddr.Port),
	}
	pm.addrBook.AddAddress(na, "manual")
	ka := pm.addrBook.GetAddress(addr)
	if ka == nil {
		// Address may have been rejected (e.g., unspecified IP); create inline
		ka = &KnownAddress{
			Addr:     na,
			Source:   "manual",
			LastSeen: time.Now(),
		}
	}
	go pm.connectToPeerWithType(ka, ConnManual)
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
	case ConnManual:
		return "manual"
	default:
		return "unknown"
	}
}

// connectMode reports whether the operator pinned the node to a fixed set of
// peers via -connect. In connect mode the connection manager dials ONLY those
// peers and skips DNS-seed resolution + the addrman/auto-outbound maintenance
// loop. Mirrors Bitcoin Core's -connect and clearbit's connect_address branch.
func (pm *PeerManager) connectMode() bool {
	return len(pm.config.ConnectPeers) > 0
}

// dnsSeedingDisabled reports whether DNS-seed resolution must be skipped.
// True when -nodnsseed (-dnsseed=0) is set OR -connect pinned the peer set
// (Core: -connect implies -dnsseed=0).
func (pm *PeerManager) dnsSeedingDisabled() bool {
	return pm.config.NoDNSSeed || pm.connectMode()
}

// maybeResolveDNSSeeds calls resolveDNSSeeds() unless DNS seeding is disabled
// by -nodnsseed or -connect. Single choke point so every DNS-refresh path
// (startup + periodic) honours the suppression.
func (pm *PeerManager) maybeResolveDNSSeeds() {
	if pm.dnsSeedingDisabled() {
		return
	}
	pm.resolveDNSSeeds()
}

// dialConnectPeers (re-)dials every -connect-pinned peer that is not currently
// connected, as a capacity-cap-exempt manual connection. Called once at
// startup and on every connection-attempt tick so a dropped pinned peer is
// retried (matching clearbit's maintainManualConnections, peer.zig:7046).
func (pm *PeerManager) dialConnectPeers() {
	for _, addr := range pm.config.ConnectPeers {
		tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			log.Printf("connect: invalid -connect address %q: %v", addr, err)
			continue
		}
		na := NetAddress{
			Services: 0,
			IP:       tcpAddr.IP,
			Port:     uint16(tcpAddr.Port),
		}
		ka := &KnownAddress{
			Addr:     na,
			Source:   "connect",
			LastSeen: time.Now(),
		}

		// Skip if already connected (dialing is async; the registry is the
		// source of truth for "currently connected"). connectToPeerWithType
		// also re-checks under the lock, so this is just an early-out.
		pm.mu.RLock()
		_, connected := pm.peers[ka.Key()]
		pm.mu.RUnlock()
		if connected {
			continue
		}

		go pm.connectToPeerWithType(ka, ConnManual)
	}
}

// fixedSeedsEnabled reports whether the last-resort fixed-seed fallback is
// active. Off when -fixedseeds=0 (NoFixedSeeds) or when -connect pinned the
// peer set (Core: -connect implies no fixed seeds — the addrman is unused).
// Mirrors net.cpp:2569 (`add_fixed_seeds = GetBoolArg("-fixedseeds", true)`)
// combined with the -connect short-circuit that bypasses ThreadOpenConnections
// fixed-seed logic entirely.
func (pm *PeerManager) fixedSeedsEnabled() bool {
	return !pm.config.NoFixedSeeds && !pm.connectMode()
}

// maybeAddFixedSeeds implements the Bitcoin Core fixed-seed trigger
// (net.cpp ThreadOpenConnections, 2607-2643). It is called on every
// connection-attempt tick with the loop's start time. It injects the curated
// fixed-seed IPs (once) when ALL of the following hold:
//
//   - fixed seeds are enabled (-fixedseeds!=0 and not -connect),
//   - they have not already been injected (one-shot, Core sets
//     add_fixed_seeds=false after firing),
//   - the address book is empty (Core's GetReachableEmptyNetworks() proxy:
//     for our IPv4-only seed set, an empty book == the one reachable network
//     has zero addrman addresses), AND EITHER
//   - ~60s have elapsed since the connection loop started (the normal path —
//     gives DNS / -addnode 60s to populate the book first, Core net.cpp:2614),
//     OR
//   - DNS seeding is disabled (Core's `!dnsseed && !use_seednodes` cheap
//     shortcut, net.cpp:2620 — fire immediately, there's no point waiting on
//     DNS that's turned off).
//
// Returns true if the seeds were injected on this call (for tests / logging).
func (pm *PeerManager) maybeAddFixedSeeds(start time.Time) bool {
	if !pm.fixedSeedsEnabled() {
		return false
	}

	pm.mu.RLock()
	already := pm.fixedSeedsAdded
	pm.mu.RUnlock()
	if already {
		return false
	}

	// Core's "reachable network has zero addrman addresses" proxy. With an
	// IPv4-only seed set the single reachable network is IPv4, so an empty
	// book is exactly the GetReachableEmptyNetworks()-non-empty condition.
	if pm.addrBook.Size() != 0 {
		return false
	}

	// Fire after the 60s grace, OR immediately when DNS seeding is off (no
	// other peer source to wait for). dnsSeedingDisabled() already folds in
	// -connect, but connectMode() is excluded above via fixedSeedsEnabled().
	graceElapsed := time.Since(start) > time.Minute
	if !graceElapsed && !pm.dnsSeedingDisabled() {
		return false
	}

	return pm.addFixedSeeds()
}

// addFixedSeeds injects the curated fixed-seed IPs from the active chain
// params' FixedSeeds list into the address book, honouring the one-shot guard.
// Mirrors net.cpp:2628-2643: ConvertSeeds(m_params.FixedSeeds()) →
// addrman.Add(..., local="fixedseeds") → add_fixed_seeds=false. -onlynet
// filtering is trivial here (the curated set is IPv4-only and AddAddress
// already rejects non-routable IPs). Returns true if it injected (i.e. it was
// the firing call, not a no-op repeat). Safe to call concurrently with the
// connect loop — the one-shot flag is set under the write lock.
func (pm *PeerManager) addFixedSeeds() bool {
	cp := pm.config.ChainParams
	if cp == nil || len(cp.FixedSeeds) == 0 {
		return false
	}

	// One-shot under the write lock so a concurrent caller can't double-inject.
	pm.mu.Lock()
	if pm.fixedSeedsAdded {
		pm.mu.Unlock()
		return false
	}
	pm.fixedSeedsAdded = true
	pm.mu.Unlock()

	added := 0
	for _, addr := range cp.FixedSeeds {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// Tolerate a bare IP (no port) by falling back to the default port.
			host = addr
		}
		netIP := net.ParseIP(host)
		if netIP == nil {
			log.Printf("fixed seed: skipping unparseable seed %q", addr)
			continue
		}
		// AddAddress rejects non-routable IPs (Core only adds reachable nets);
		// it dedups and bounds the book. Source "fixedseeds" mirrors Core's
		// local.SetInternal("fixedseeds").
		before := pm.addrBook.Size()
		pm.addrBook.AddAddress(NetAddress{
			IP:   netIP.To16(),
			Port: cp.DefaultPort,
		}, "fixedseeds")
		if pm.addrBook.Size() > before {
			added++
		}
	}

	log.Printf("fixed seed: injected %d last-resort bootstrap address(es) (DNS empty / disabled, address book was empty)", added)
	return true
}

// connectionHandler manages outbound connection attempts.
func (pm *PeerManager) connectionHandler() {
	defer pm.wg.Done()

	// -connect peer-pinning (Core parity / clearbit peer.zig:7009). When the
	// operator pinned a fixed peer set we dial ONLY those peers and skip both
	// DNS-seed resolution and the addrman/auto-outbound maintenance loop. The
	// pinned peers are dialed up front and re-dialed on every tick below.
	// connStart anchors the fixed-seed 60s grace window (Core net.cpp:2562
	// `auto start = GetTime<microseconds>()`). Recorded before the initial DNS
	// resolution so the grace clock starts at loop entry, matching Core.
	connStart := time.Now()

	if pm.connectMode() {
		log.Printf("P2P: -connect set (%d peer(s)) — DNS seeds and auto-outbound dialing disabled; pinning to %s",
			len(pm.config.ConnectPeers), strings.Join(pm.config.ConnectPeers, ", "))
		pm.dialConnectPeers()
	} else {
		// Initial DNS seed resolution (skipped when -nodnsseed / -dnsseed=0).
		pm.maybeResolveDNSSeeds()

		// Immediate fixed-seed fallback when DNS seeding is disabled: there is
		// no other peer source to wait for, so fire right away rather than
		// idling for 60s (Core's `!dnsseed && !use_seednodes` shortcut,
		// net.cpp:2620). When DNS is enabled this is a no-op (the book is
		// non-empty after a successful resolve, or the 60s-grace path below
		// fires once DNS is confirmed dead). This is THE fix for the
		// DNS-failure hang: with DNS off (or unreachable) and an empty book,
		// the node now seeds itself instead of idling forever with zero peers.
		pm.maybeAddFixedSeeds(connStart)
	}

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

	// Fixed-seed fallback ticker. Core re-checks the trigger on every 500ms
	// loop tick (net.cpp:2594); we poll every 5s, which is far finer than the
	// 60s grace window and ensures the seeds are injected promptly once DNS is
	// confirmed dead and the book is still empty. One-shot: maybeAddFixedSeeds
	// no-ops after it fires (and immediately when fixed seeds are disabled or
	// already added), so this becomes a cheap flag check thereafter.
	fixedSeedsTicker := time.NewTicker(5 * time.Second)
	defer fixedSeedsTicker.Stop()

	// ASMap health-check ticker — only fires when asmap is loaded.
	// Mirrors Core's CConnman::Start() which calls ASMapHealthCheck() once at
	// startup then schedules it every ASMAP_HEALTH_CHECK_INTERVAL (net.cpp:3572).
	var asmapHealthTicker *time.Ticker
	var asmapHealthC <-chan time.Time
	if pm.UsingASMap() {
		// Run once immediately at startup (mirrors Core net.cpp:3572 direct call).
		pm.ASMapHealthCheck()
		asmapHealthTicker = time.NewTicker(ASMapHealthCheckInterval)
		defer asmapHealthTicker.Stop()
		asmapHealthC = asmapHealthTicker.C
	}

	for {
		select {
		case <-ticker.C:
			// -connect mode: re-dial pinned peers only; never fill outbound
			// slots from the addrman (Core parity / clearbit peer.zig:7050).
			if pm.connectMode() {
				pm.dialConnectPeers()
				continue
			}

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
			// In -connect mode we make no feeler or extra block-relay
			// connections — the addrman is intentionally unused.
			if pm.connectMode() {
				continue
			}
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

		case <-fixedSeedsTicker.C:
			// Last-resort fixed-seed fallback (Core net.cpp:2607-2643). One-shot:
			// injects the curated bootstrap IPs the first tick after the address
			// book is empty AND (60s elapsed since loop start OR DNS seeding is
			// disabled). This rescues a node whose DNS seeds were reachable at
			// startup but returned nothing useful (or began failing) — without
			// it, an empty book means pickAddressWithDiversity returns nil
			// forever and the node hangs with zero outbound peers.
			pm.maybeAddFixedSeeds(connStart)

		case <-dnsRefreshTicker.C:
			// Refresh DNS seeds when peer health is poor. Two triggers:
			//   (a) book is too small to provide candidates, or
			//   (b) too few addresses have a known-good handshake history
			//       (stale-but-large-book case).
			// (b) is essential — without it, a node whose entire book has
			// become stale after long downtime would accumulate failures on
			// every gossip entry and never replenish the pool.
			if pm.addrBook.Size() < MinAddressesBeforeRefresh ||
				len(pm.addrBook.Good()) < MinGoodAddrsBeforeRefresh {
				// Honours -nodnsseed / -dnsseed=0 and -connect (no-op when
				// DNS seeding is disabled).
				pm.maybeResolveDNSSeeds()
			}

		case <-banCleanupTicker.C:
			pm.cleanupBans()

		case <-asmapHealthC:
			pm.ASMapHealthCheck()

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

	// Don't rotate if we have very few total peers — rotating our only
	// peers during IBD would stall block download
	totalOutbound := pm.outbound + pm.blockRelayOnly
	if totalOutbound <= 2 {
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
		log.Printf("dns seed: no chain params or no seeds configured")
		return
	}

	log.Printf("dns seed: resolving %d seeds for %s (default port %d)",
		len(pm.config.ChainParams.DNSSeeds), pm.config.ChainParams.Name, pm.config.ChainParams.DefaultPort)

	ips := ResolveDNSSeeds(pm.config.ChainParams.DNSSeeds)
	log.Printf("dns seed: resolved %d addresses", len(ips))

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

	log.Printf("dns seed: address book now has %d entries", pm.addrBook.Size())
}

// pickAddressWithDiversity selects an address that maintains network-group
// diversity for outbound connections.
//
// When asmap is loaded, uses GetGroup (AS-derived group key) to enforce
// 1 connection per AS — mirroring Bitcoin Core's outbound_ipv46_peer_netgroups
// set in net.cpp ThreadOpenConnections which rejects candidates whose netgroup
// already appears among connected outbound IPv4/IPv6 peers.
//
// Without asmap, falls back to legacy /16 subnet diversity (MaxPeersPerSubnet=2).
//
// Feelers bypass diversity checks entirely (Core: FEELER connections are
// excluded from outbound_ipv46_peer_netgroups).
func (pm *PeerManager) pickAddressWithDiversity(connType ConnType) *KnownAddress {
	// Feelers don't need diversity checks (Core: FEELER excluded from netgroup tracking).
	if connType == ConnFeeler {
		return pm.addrBook.PickAddress()
	}

	pm.mu.RLock()
	// Snapshot current group counts for candidate evaluation.
	groupCounts := make(map[string]int)
	for k, v := range pm.subnetCounts {
		groupCounts[k] = v
	}
	pm.mu.RUnlock()

	limit := pm.maxPeersPerGroup()

	// Try up to 50 attempts to find a group-diverse address.
	for i := 0; i < 50; i++ {
		ka := pm.addrBook.PickAddress()
		if ka == nil {
			return nil
		}

		group := pm.getNetGroup(ka.Addr.IP)
		count := groupCounts[group]

		// Accept if we're under the per-group limit.
		if count < limit {
			return ka
		}

		// With 10% chance, accept anyway to avoid getting stuck.
		pm.mu.RLock()
		r := pm.rng.Float64()
		pm.mu.RUnlock()
		if r < 0.1 {
			return ka
		}
	}

	// Fallback to any address.
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

// getNetGroup returns the network-group key for an IP address used for
// eclipse-resistance diversity tracking. When an asmap is loaded, returns the
// AS-derived group key (5-byte slice from GetGroup encoded as hex). Otherwise
// falls back to the /16 subnet key from getSubnet.
//
// Mirrors Bitcoin Core's NetGroupManager::GetGroup() used in net.cpp
// outbound_ipv46_peer_netgroups: persistent outbound IPv4/IPv6 slots must
// belong to different netgroups (one connection per netgroup).
func (pm *PeerManager) getNetGroup(ip net.IP) string {
	if pm.UsingASMap() {
		group := GetGroup(pm.asmap, ip)
		if len(group) > 0 {
			// Encode as hex string for use as a map key.
			return fmt.Sprintf("%x", group)
		}
	}
	return getSubnet(ip)
}

// maxPeersPerGroup returns the connection limit per network group.
// When asmap is loaded, Core allows exactly 1 connection per AS group
// (outbound_ipv46_peer_netgroups is a set — no duplicates allowed).
// Without asmap, use the legacy MaxPeersPerSubnet=2 limit.
func (pm *PeerManager) maxPeersPerGroup() int {
	if pm.UsingASMap() {
		return 1 // 1 per AS group — mirrors Core's set-based uniqueness
	}
	return MaxPeersPerSubnet
}

// connectToPeer attempts to connect to a known address (legacy, uses ConnFullRelay).
func (pm *PeerManager) connectToPeer(ka *KnownAddress) {
	pm.connectToPeerWithType(ka, ConnFullRelay)
}

// connectToPeerWithType attempts to connect to a known address with a specific connection type.
func (pm *PeerManager) connectToPeerWithType(ka *KnownAddress, connType ConnType) {
	addr := ka.Key()

	// Mark the attempt (but not for feelers — feeler probes should not
	// prevent the address from being selected for full-relay or block-relay
	// connections, especially on networks with small address pools like testnet4)
	if connType != ConnFeeler {
		pm.addrBook.MarkAttempt(addr)
	}

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
	case ConnFeeler, ConnManual:
		// Feelers and manual connections always proceed (manual bypasses cap).
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
		// Connection failed. Mark the outcome so Attempts doesn't climb
		// unbounded toward the IsBad cliff (MarkAttempt already incremented
		// it at dial start for non-feelers).
		if connType != ConnFeeler {
			pm.addrBook.MarkFailed(addr)
		}
		return
	}
	peer.SetBanCallback(pm.handlePeerBan)

	// Create peer info. Use getNetGroup to derive the diversity key: AS-derived
	// when asmap is loaded, /16 subnet otherwise. This key is stored in
	// PeerInfo.subnet and tracked in pm.subnetCounts so that pickAddressWithDiversity
	// can enforce per-group limits (1 per AS or 2 per /16).
	peerInfo := &PeerInfo{
		peer:        peer,
		connType:    connType,
		connectedAt: time.Now(),
		subnet:      pm.getNetGroup(ka.Addr.IP),
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
	case ConnManual:
		// Manual connections bypass capacity limits — always proceed.
	}
	pm.peers[addr] = peerInfo
	pm.updatePeerCounts(peerInfo, +1)
	pm.mu.Unlock()

	// Start the peer (this does the handshake)
	err = peer.Start()
	if err != nil {
		pm.removePeer(peer)
		if connType != ConnFeeler {
			pm.addrBook.MarkFailed(addr)
		}
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

		// Get network-group key for the inbound peer (used in eviction diversity
		// scoring). Uses AS-level grouping when asmap is loaded, /16 otherwise.
		remoteIP := extractIP(conn.RemoteAddr().String())
		subnet := pm.getNetGroup(net.ParseIP(remoteIP))

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

	// Advertised service bits.  NODE_BLOOM (BIP-111) is OR'd in only when
	// `-peerbloomfilters` is on (default), mirroring Core's init.cpp:1104:
	//
	//     if (args.GetBoolArg("-peerbloomfilters", DEFAULT_PEERBLOOMFILTERS))
	//         g_local_services = ServiceFlags(g_local_services | NODE_BLOOM);
	//
	// Advertising NODE_BLOOM tells peers we will honor BIP-35 "mempool"
	// requests; main.go's OnMempool gate uses the same flag so the
	// advertisement and the handler stay in sync.
	// BIP-159 (NODE_NETWORK_LIMITED, 1<<10) is advertised UNCONDITIONALLY by a
	// full node, NOT only in prune mode. Core's init.cpp:863 seeds
	// g_local_services with `NODE_NETWORK_LIMITED | NODE_WITNESS` for every
	// run, then OR's in NODE_NETWORK for non-prune (init.cpp:1950). A
	// non-pruned full node therefore advertises NETWORK + NETWORK_LIMITED +
	// WITNESS: NODE_NETWORK_LIMITED means "I can serve at least the most
	// recent 288 blocks", which is trivially true for a node that serves the
	// whole chain. The earlier code gated this bit on prune mode, which was
	// backwards and dropped a flag Core always sets.
	services := uint64(ServiceNodeNetwork | ServiceNodeWitness | ServiceNodeNetworkLimited)
	if pm.config.AdvertiseNodeBloom {
		services |= ServiceNodeBloom
	}
	// BIP-324 (NODE_P2P_V2, 1<<11): signal v2 encrypted-transport support when
	// the v2 transport is enabled. PreferV2 is wired from cfg.BIP324V2 (default
	// ON), and when set blockbrew genuinely negotiates BIP-324 v2 on both
	// outbound and inbound connections (with v1 fall-through), so the
	// advertisement is honest. Mirrors Core init.cpp:988-989, which OR's
	// NODE_P2P_V2 when `-v2transport` (DEFAULT_V2_TRANSPORT = true) is on.
	if pm.config.PreferV2 {
		services |= ServiceNodeP2PV2
	}
	// BIP-157: signal compact filter serving when the blockfilterindex is
	// enabled, mirroring Core's net_processing.cpp handling where
	// NODE_COMPACT_FILTERS is added when the basic filter index is active.
	if pm.config.AdvertiseCompactFilters {
		services |= ServiceNodeCompactFilters
	}

	return PeerConfig{
		Network:            pm.config.Network,
		ProtocolVersion:    ProtocolVersion,
		Services:           services,
		UserAgent:          pm.config.UserAgent,
		BestHeight:         bestHeight,
		DisableRelayTx:     false,
		Listeners:          listeners,
		PreferV2:           pm.config.PreferV2,
		EnablePackageRelay: pm.config.EnablePackageRelay,
	}
}

// LocalServices returns the node's advertised service flags as reported by
// getnetworkinfo (Core's `g_local_services`). It mirrors the bits seeded in
// init.cpp:863 + 988-989 + 1950: NODE_NETWORK | NODE_WITNESS |
// NODE_NETWORK_LIMITED, plus NODE_P2P_V2 when v2 transport is enabled and
// NODE_COMPACT_FILTERS when the basic filter index is served. It deliberately
// EXCLUDES NODE_BLOOM: in modern Core NODE_BLOOM is not part of g_local_services
// — it is OR'd per-peer when the peer holds the BloomFilter permission
// (net_processing.cpp:1613-1614) — so it does not appear in getnetworkinfo's
// `localservices`. Kept in sync with makePeerConfig's `services` derivation.
func (pm *PeerManager) LocalServices() uint64 {
	services := uint64(ServiceNodeNetwork | ServiceNodeWitness | ServiceNodeNetworkLimited)
	if pm.config.PreferV2 {
		services |= ServiceNodeP2PV2
	}
	if pm.config.AdvertiseCompactFilters {
		services |= ServiceNodeCompactFilters
	}
	return services
}

// handleGetAddr answers an inbound getaddr with the full Bitcoin Core anti-DoS
// guards (net_processing.cpp:4816-4849):
//
//   - getaddr from an OUTBOUND peer is ignored — the asymmetric inbound-only
//     behaviour prevents a fingerprinting attack where an attacker seeds fake
//     addresses and later requests them back (Core: if (!pfrom.IsInboundConn())
//     return);
//   - only the FIRST getaddr per connection is answered; repeats are ignored
//     (Core m_getaddr_recvd, net_processing.cpp:4833);
//   - the response is capped at min(MaxAddresses, floor(23*size/100)) via
//     getaddrCap over the shareable pool (Core MAX_PCT_ADDR_TO_SEND = 23).
func (pm *PeerManager) handleGetAddr(p *Peer) {
	if p == nil {
		return
	}
	// Ignore getaddr from outbound peers (anti-fingerprinting).
	if !p.Inbound() {
		return
	}
	// Only answer the first getaddr per connection.
	if !p.markGetAddrRecvd() {
		return
	}
	// Build a capped, randomly-sampled response from the addr book.
	addrs := pm.addrBook.GetAddressesForGetAddr()
	if len(addrs) == 0 {
		// Core still sends an (empty) response set; we have nothing to share,
		// so we send nothing — sending an empty addr is a no-op for the peer.
		return
	}
	p.SendMessage(&MsgAddr{AddrList: addrs})
}

// admitAddrTokens applies the inbound-addr leaky token bucket to a slice of
// received addresses and returns the prefix that may be admitted. NoBan /
// whitelisted (manual) peers bypass the limit entirely (Core only rate-limits
// peers WITHOUT NetPermissionFlags::Addr; manual/whitelisted peers carry that
// permission). The bucket is per-peer and shared with admitAddrV2Tokens.
func (pm *PeerManager) admitAddrTokens(p *Peer, addrs []NetAddress) []NetAddress {
	if p == nil {
		return addrs
	}
	if p.IsNoBan() {
		return addrs
	}
	admit := p.takeAddrTokens(len(addrs))
	if admit >= len(addrs) {
		return addrs
	}
	return addrs[:admit]
}

// admitAddrV2Tokens is the addrv2 counterpart of admitAddrTokens. It draws from
// the SAME per-peer token bucket so a peer cannot evade the inbound-addr rate
// limit by sending addrv2 instead of addr.
func (pm *PeerManager) admitAddrV2Tokens(p *Peer, addrs []NetAddressV2) []NetAddressV2 {
	if p == nil {
		return addrs
	}
	if p.IsNoBan() {
		return addrs
	}
	admit := p.takeAddrTokens(len(addrs))
	if admit >= len(addrs) {
		return addrs
	}
	return addrs[:admit]
}

// wrapListeners wraps the configured listeners to add our own handlers.
func (pm *PeerManager) wrapListeners() *PeerListeners {
	listeners := &PeerListeners{}

	// Copy existing listeners if provided
	if pm.config.Listeners != nil {
		*listeners = *pm.config.Listeners
	}

	// Wrap OnGetAddr to answer a getaddr with the addr anti-DoS guards
	// (Bitcoin Core net_processing.cpp:4816-4849).
	originalOnGetAddr := listeners.OnGetAddr
	listeners.OnGetAddr = func(p *Peer, msg *MsgGetAddr) {
		pm.handleGetAddr(p)
		if originalOnGetAddr != nil {
			originalOnGetAddr(p, msg)
		}
	}

	// Wrap OnAddr to add addresses to our book
	originalOnAddr := listeners.OnAddr
	listeners.OnAddr = func(p *Peer, msg *MsgAddr) {
		// Cap at MaxAddresses to prevent flooding
		addrs := msg.AddrList
		if len(addrs) > MaxAddresses {
			addrs = addrs[:MaxAddresses]
		}

		// Inbound-addr leaky token bucket (Core ProcessAddrs rate limiter):
		// admit at most floor(bucket) addresses; drop the surplus for
		// non-NoBan / non-manual peers. The SAME per-peer bucket is shared
		// with the addrv2 handler so addrv2 cannot bypass the limit.
		addrs = pm.admitAddrTokens(p, addrs)

		// Add to address book
		source := "unknown"
		if p != nil {
			source = p.Address()
		}
		pm.addrBook.AddAddresses(addrs, source)

		// Relay to up to 2 random peers (not back to source)
		pm.relayAddrToRandomPeers(p, msg)

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

		// Inbound-addr leaky token bucket — shares ONE per-peer bucket with
		// the addr handler above so a peer cannot exceed the inbound-addr rate
		// limit by switching to addrv2 (Core uses one m_addr_token_bucket for
		// both the addr and addrv2 ProcessAddrs paths).
		addrs = pm.admitAddrV2Tokens(p, addrs)

		// Add to address book
		source := "unknown"
		if p != nil {
			source = p.Address()
		}
		pm.addrBook.AddAddressesV2(addrs, source)

		// Relay addrv2 to up to 2 random peers (not back to source)
		pm.relayAddrv2ToRandomPeers(p, msg)

		// Call original handler if set
		if originalOnAddrv2 != nil {
			originalOnAddrv2(p, msg)
		}
	}

	// Block inv handling is done by the sync manager, not here.
	// The sync manager uses headers-first download with its own getdata
	// pipeline. Requesting blocks from inv here during IBD causes
	// unsolicited tip blocks to arrive and corrupt the download queue.

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

// relayAddrToRandomPeers relays an addr message to up to 2 random connected
// peers, excluding the source peer. This implements Bitcoin Core's RelayAddress
// (net_processing.cpp:5688): only relay when the incoming message has at most 10
// addresses, matching Core's unsolicited-addr relay gate.
func (pm *PeerManager) relayAddrToRandomPeers(source *Peer, msg *MsgAddr) {
	// Core net_processing.cpp:5688 gates relay on vAddr.size() <= 10.
	// Messages with more entries are responses to GETADDR and should not
	// be forwarded — only spontaneous announcements (<=10) get relayed.
	if len(msg.AddrList) > 10 {
		return
	}

	pm.mu.RLock()
	var candidates []*Peer
	for _, pi := range pm.peers {
		if pi.peer != nil && pi.peer != source && pi.peer.WantsTxRelay() {
			candidates = append(candidates, pi.peer)
		}
	}
	pm.mu.RUnlock()

	if len(candidates) == 0 {
		return
	}
	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})
	n := 2
	if len(candidates) < n {
		n = len(candidates)
	}
	for _, p := range candidates[:n] {
		p.SendMessage(msg)
	}
}

// relayAddrv2ToRandomPeers relays an addrv2 message to up to 2 random connected
// peers that support addrv2, excluding the source peer. Applies the same
// Core net_processing.cpp:5688 size<=10 gate as relayAddrToRandomPeers since
// Core uses a single ProcessAddrs handler for both ADDR and ADDRV2.
func (pm *PeerManager) relayAddrv2ToRandomPeers(source *Peer, msg *MsgAddrv2) {
	// Core net_processing.cpp:4022 uses one handler for ADDR and ADDRV2;
	// the vAddr.size() <= 10 relay gate (line 5688) applies to both.
	if len(msg.AddrList) > 10 {
		return
	}

	pm.mu.RLock()
	var candidates []*Peer
	for _, pi := range pm.peers {
		if pi.peer != nil && pi.peer != source && pi.peer.WantsTxRelay() && pi.peer.WantsAddrv2() {
			candidates = append(candidates, pi.peer)
		}
	}
	pm.mu.RUnlock()

	if len(candidates) == 0 {
		return
	}
	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})
	n := 2
	if len(candidates) < n {
		n = len(candidates)
	}
	for _, p := range candidates[:n] {
		p.SendMessage(msg)
	}
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

// anchorsFilePath returns the path to the anchors file.
func (pm *PeerManager) anchorsFilePath() string {
	return filepath.Join(pm.config.DataDir, AnchorsFilename)
}

// anchorEntry is persisted to anchors.json for block-relay-only peers.
type anchorEntry struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

// saveAnchors persists block-relay-only peer addresses to disk on shutdown.
// Reference: Bitcoin Core net.cpp DumpAnchors / addrdb.cpp
func (pm *PeerManager) saveAnchors() {
	if pm.config.DataDir == "" {
		return
	}

	pm.mu.RLock()
	var anchors []anchorEntry
	for addr, info := range pm.peers {
		if info.connType == ConnBlockRelayOnly && info.peer.IsConnected() {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				continue
			}
			port := uint16(0)
			fmt.Sscanf(portStr, "%d", &port)
			anchors = append(anchors, anchorEntry{Address: host, Port: port})
			if len(anchors) >= MaxBlockRelayOnlyAnchors {
				break
			}
		}
	}
	pm.mu.RUnlock()

	data, err := json.MarshalIndent(anchors, "", "  ")
	if err != nil {
		log.Printf("failed to marshal anchors: %v", err)
		return
	}

	path := pm.anchorsFilePath()
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("failed to write anchors file %s: %v", path, err)
		return
	}

	log.Printf("saved %d block-relay-only anchor(s) to %s", len(anchors), path)
}

// loadAnchors reads anchor connections from disk and attempts to connect to them
// before DNS seeds. The file is rewritten on clean shutdown via saveAnchors,
// so it is preserved across restarts (including after a crash, where the
// previous anchor list is the best signal we have of known-good peers).
// Reference: Bitcoin Core net.cpp ReadAnchors.
func (pm *PeerManager) loadAnchors() {
	if pm.config.DataDir == "" {
		return
	}

	path := pm.anchorsFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		// No anchors file is normal on first run
		return
	}

	var anchors []anchorEntry
	if err := json.Unmarshal(data, &anchors); err != nil {
		log.Printf("failed to parse anchors file: %v", err)
		return
	}

	if len(anchors) > MaxBlockRelayOnlyAnchors {
		anchors = anchors[:MaxBlockRelayOnlyAnchors]
	}

	log.Printf("loaded %d anchor(s) from %s", len(anchors), path)

	for _, a := range anchors {
		// Connect as block-relay-only (same type they were saved as)
		ka := &KnownAddress{
			Addr: NetAddress{
				IP:   net.ParseIP(a.Address).To16(),
				Port: a.Port,
			},
		}
		go pm.connectToPeerWithType(ka, ConnBlockRelayOnly)
	}
}
