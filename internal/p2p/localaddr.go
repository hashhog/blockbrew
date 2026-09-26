package p2p

// Self-address advertisement (Bitcoin Core parity).
//
// A listening node must tell the network where it can be reached, or nobody
// ever dials it: peers only learn addresses from addr/addrv2 gossip, and the
// only gossip source for OUR address is us. Core does this in three parts,
// mirrored here:
//
//  1. A table of local addresses (Core net.cpp mapLocalHost / AddLocal /
//     SeenLocal). Entries come from -externalip (score LocalManual) and from
//     discovery: an outbound peer's VERSION carries addr_recv, the address it
//     sees us at. Core only uses that per-peer (GetLocalAddrForPeer); we also
//     record it in the table so getnetworkinfo.localaddresses and the VERSION
//     addr_from have something to show. A discovered entry's score is the
//     number of DISTINCT peer netgroups that confirmed it, so one peer (or one
//     /16) cannot talk us into advertising an address; it must be confirmed
//     by MinDiscoveredLocalScore groups before it is used, and it ages out
//     after DiscoveredLocalAddrTTL without a fresh confirmation, so a changed
//     public IP replaces the old one.
//  2. The per-peer choice of which address to advertise (Core net.cpp
//     GetLocalAddrForPeer): the best table entry, but if the peer itself told
//     us a routable address for us, use that instead when the table has
//     nothing routable, and otherwise sometimes (1/2, or 1/8 when the best
//     entry scores above LocalManual).
//  3. The send (Core net_processing.cpp MaybeSendAddr): only when listening
//     and out of IBD, one addr/addrv2 carrying just our address right after
//     the handshake, then again on a Poisson timer averaging 24h
//     (AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL). Never to block-relay-only or
//     feeler connections (Core: m_addr_relay_enabled is false for them).

import (
	"math"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Local address scores (Core net.h enum LOCAL_NONE..LOCAL_MANUAL).
const (
	LocalNone   = 0 // unknown / discovered
	LocalIf     = 1 // address a local interface listens on
	LocalBind   = 2 // address explicitly bound to
	LocalMapped = 3 // address reported by PCP/NAT-PMP
	LocalManual = 4 // address explicitly specified (-externalip=)
)

const (
	// AvgLocalAddressBroadcastInterval is the mean of the exponential delay
	// between self-announcements to one peer (Core net_processing.cpp:158).
	AvgLocalAddressBroadcastInterval = 24 * time.Hour

	// localAddrCheckInterval is how often the timer loop looks for peers
	// whose next self-announcement is due. Coarse is fine against a 24h mean.
	localAddrCheckInterval = time.Minute

	// DiscoveredLocalAddrTTL: a discovered (non-manual) entry not confirmed by
	// any peer for this long is dropped. Outbound churn (feelers every ~2min)
	// re-confirms a stable address many times per hour, so this only bites
	// after the public IP changes.
	DiscoveredLocalAddrTTL = 3 * time.Hour

	// MinDiscoveredLocalScore is how many distinct peer netgroups must
	// confirm a discovered address before it is advertised to OTHER peers.
	MinDiscoveredLocalScore = 2

	// maxDiscoveredLocalAddrs caps discovered entries so peers cannot grow
	// the table without bound; the weakest entry is evicted.
	maxDiscoveredLocalAddrs = 8

	// maxLocalAddrConfirmers caps the per-entry confirmer set (score ceiling).
	maxLocalAddrConfirmers = 64
)

// LocalAddress is one row of getnetworkinfo.localaddresses.
type LocalAddress struct {
	IP    net.IP
	Port  uint16
	Score int
}

type localAddrEntry struct {
	ip         net.IP
	port       uint16
	manual     bool
	baseScore  int                 // LocalManual for -externalip, else 0
	confirmers map[string]struct{} // distinct peer netgroups that confirmed it
	lastSeen   time.Time
}

func (e *localAddrEntry) score() int { return e.baseScore + len(e.confirmers) }

// localAddrTable is the node's set of known local addresses (Core
// mapLocalHost). Keyed by IP only, like Core (map<CNetAddr, ...>).
type localAddrTable struct {
	mu      sync.Mutex
	entries map[string]*localAddrEntry
}

func newLocalAddrTable() *localAddrTable {
	return &localAddrTable{entries: make(map[string]*localAddrEntry)}
}

func ipKey(ip net.IP) string { return ip.To16().String() }

// addManual records an operator-specified address (-externalip). Returns
// false for a non-routable address, which Core's AddLocal also refuses.
func (t *localAddrTable) addManual(ip net.IP, port uint16) bool {
	if !isRoutableIP(ip) {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[ipKey(ip)]
	if e == nil {
		e = &localAddrEntry{ip: ip.To16(), confirmers: make(map[string]struct{})}
		t.entries[ipKey(ip)] = e
	}
	e.manual = true
	e.baseScore = LocalManual
	e.port = port
	return true
}

// confirm records that a peer in netgroup `group` sees us at ip. When create
// is false (inbound peers, Core SeenLocal) only an existing entry is scored;
// when true (outbound addr_recv discovery) a new entry is created with port.
func (t *localAddrTable) confirm(ip net.IP, port uint16, group string, create bool, now time.Time) bool {
	if !isRoutableIP(ip) {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked(now)
	key := ipKey(ip)
	e := t.entries[key]
	if e == nil {
		if !create {
			return false
		}
		t.makeRoomLocked()
		e = &localAddrEntry{ip: ip.To16(), port: port, confirmers: make(map[string]struct{})}
		t.entries[key] = e
	}
	if len(e.confirmers) < maxLocalAddrConfirmers {
		e.confirmers[group] = struct{}{}
	}
	e.lastSeen = now
	return true
}

func (t *localAddrTable) expireLocked(now time.Time) {
	for k, e := range t.entries {
		if !e.manual && now.Sub(e.lastSeen) > DiscoveredLocalAddrTTL {
			delete(t.entries, k)
		}
	}
}

// makeRoomLocked evicts the weakest (lowest score, then oldest) discovered
// entry when the discovered set is full.
func (t *localAddrTable) makeRoomLocked() {
	var n int
	var worstKey string
	var worst *localAddrEntry
	for k, e := range t.entries {
		if e.manual {
			continue
		}
		n++
		if worst == nil || e.score() < worst.score() ||
			(e.score() == worst.score() && e.lastSeen.Before(worst.lastSeen)) {
			worst, worstKey = e, k
		}
	}
	if n >= maxDiscoveredLocalAddrs && worst != nil {
		delete(t.entries, worstKey)
	}
}

// usable reports whether an entry may be advertised to arbitrary peers.
func (e *localAddrEntry) usable() bool {
	return e.manual || len(e.confirmers) >= MinDiscoveredLocalScore
}

// best returns the best usable local address for a peer of the given IP
// family (Core GetLocal): same address family as the peer first, then the
// highest score, then the most recently confirmed. peerIP may be nil.
func (t *localAddrTable) best(peerIP net.IP, now time.Time) (LocalAddress, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked(now)
	peerV4 := peerIP != nil && peerIP.To4() != nil
	reach := func(e *localAddrEntry) int {
		if peerIP == nil {
			return 0
		}
		if (e.ip.To4() != nil) == peerV4 {
			return 1
		}
		return 0
	}
	var b *localAddrEntry
	for _, e := range t.entries {
		if !e.usable() {
			continue
		}
		if b == nil || reach(e) > reach(b) ||
			(reach(e) == reach(b) && (e.score() > b.score() ||
				(e.score() == b.score() && e.lastSeen.After(b.lastSeen)))) {
			b = e
		}
	}
	if b == nil {
		return LocalAddress{}, false
	}
	return LocalAddress{IP: b.ip, Port: b.port, Score: b.score()}, true
}

// list returns every entry, highest score first (getnetworkinfo).
func (t *localAddrTable) list(now time.Time) []LocalAddress {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked(now)
	out := make([]LocalAddress, 0, len(t.entries))
	for _, e := range t.entries {
		out = append(out, LocalAddress{IP: e.ip, Port: e.port, Score: e.score()})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].IP.String() < out[j].IP.String()
	})
	return out
}

// listenPort returns the port we accept connections on, parsed from
// ListenAddr (Core GetListenPort). 0 when not listening.
func (pm *PeerManager) listenPort() uint16 {
	if pm.config.ListenAddr == "" {
		return 0
	}
	_, portStr, err := net.SplitHostPort(pm.config.ListenAddr)
	if err != nil {
		return 0
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port)
}

// listening mirrors Core's fListen.
func (pm *PeerManager) listening() bool { return pm.listenPort() != 0 }

// AddExternalIP records an -externalip address. port 0 means the listen port.
func (pm *PeerManager) AddExternalIP(ip net.IP, port uint16) bool {
	if port == 0 {
		port = pm.listenPort()
	}
	return pm.localAddrs.addManual(ip, port)
}

// LocalAddresses returns the local address table for getnetworkinfo.
func (pm *PeerManager) LocalAddresses() []LocalAddress {
	return pm.localAddrs.list(time.Now())
}

// bestLocalAddress is the address used for VERSION addr_from.
func (pm *PeerManager) bestLocalAddress() (LocalAddress, bool) {
	if !pm.listening() {
		return LocalAddress{}, false
	}
	return pm.localAddrs.best(nil, time.Now())
}

// peerIP returns the remote peer's IP, or nil.
func peerIP(p *Peer) net.IP {
	return net.ParseIP(extractIP(p.Address()))
}

// noteVersionAddrRecv handles the addr_recv field of a peer's VERSION: an
// outbound peer's view of us is a discovery (only with -discover, only when
// both ends are routable, Core IsPeerAddrLocalGood); an inbound peer's view
// only scores an address we already know (Core SeenLocal).
func (pm *PeerManager) noteVersionAddrRecv(p *Peer, addrRecv NetAddress, now time.Time) {
	if !pm.config.Discover || !pm.listening() {
		return
	}
	rip := peerIP(p)
	if !isRoutableIP(rip) || !isRoutableIP(addrRecv.IP) {
		return
	}
	pm.localAddrs.confirm(addrRecv.IP, pm.listenPort(), pm.getNetGroup(rip), !p.Inbound(), now)
}

// localAddrForPeer picks the address to advertise to p (Core
// GetLocalAddrForPeer, net.cpp:240-268).
func (pm *PeerManager) localAddrForPeer(p *Peer, now time.Time) (net.IP, uint16, bool) {
	rip := peerIP(p)
	local, haveLocal := pm.localAddrs.best(rip, now)
	ip, port := local.IP, local.Port
	if !haveLocal {
		port = pm.listenPort()
	}
	seen := p.AddrLocal()
	peerGood := pm.config.Discover && isRoutableIP(rip) && isRoutableIP(seen.IP)
	if peerGood {
		bits := 1
		if local.Score > LocalManual {
			bits = 3
		}
		if !haveLocal || rand.Intn(1<<bits) == 0 {
			ip = seen.IP
			if p.Inbound() {
				// The peer dialed our listening port, so it saw it too.
				port = seen.Port
			}
		}
	}
	if !isRoutableIP(ip) || port == 0 {
		return nil, 0, false
	}
	return ip, port, true
}

// nextLocalAddrDelay draws the Poisson inter-announcement delay.
func nextLocalAddrDelay() time.Duration {
	return time.Duration(-math.Log(1-rand.Float64()) * float64(AvgLocalAddressBroadcastInterval))
}

// maybeSendLocalAddr is Core's MaybeSendAddr self-announcement block: if the
// peer is due, send it our address. Returns true when a message was sent.
func (pm *PeerManager) maybeSendLocalAddr(p *Peer, now time.Time) bool {
	if p == nil || !pm.listening() {
		return false
	}
	if !p.Inbound() {
		switch pm.GetConnType(p.Address()) {
		case ConnBlockRelayOnly, ConnFeeler:
			return false
		}
	}
	if pm.config.IsIBDFunc != nil && pm.config.IsIBDFunc() {
		return false // timer untouched: the first send happens once out of IBD
	}
	p.addrMu.Lock()
	due := p.nextLocalAddrSend.IsZero() || now.After(p.nextLocalAddrSend)
	if due {
		p.nextLocalAddrSend = now.Add(nextLocalAddrDelay())
	}
	p.addrMu.Unlock()
	if !due {
		return false
	}
	ip, port, ok := pm.localAddrForPeer(p, now)
	if !ok {
		return false
	}
	services := p.config.Services
	ts := uint32(now.Unix())
	if p.WantsAddrv2() {
		na := NewNetAddressV2FromIP(ip, port, services)
		na.Time = ts
		p.SendMessage(&MsgAddrv2{AddrList: []NetAddressV2{*na}})
	} else {
		p.SendMessage(&MsgAddr{AddrList: []NetAddress{{
			Timestamp: ts, Services: services, IP: ip.To16(), Port: port,
		}}})
	}
	return true
}

// localAddrHandler re-announces our address to each peer on its timer.
func (pm *PeerManager) localAddrHandler() {
	defer pm.wg.Done()
	ticker := time.NewTicker(localAddrCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-pm.quit:
			return
		case now := <-ticker.C:
			for _, p := range pm.ConnectedPeers() {
				pm.maybeSendLocalAddr(p, now)
			}
		}
	}
}
