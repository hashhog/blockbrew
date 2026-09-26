package p2p

import (
	"net"
	"testing"
	"time"
)

func newSelfAdvPM(t *testing.T, listen string, ibd bool) *PeerManager {
	t.Helper()
	return NewPeerManager(PeerManagerConfig{
		ListenAddr: listen,
		Discover:   true,
		IsIBDFunc:  func() bool { return ibd },
	})
}

// selfAdvPeer is a connected test peer registered with pm under connType,
// whose VERSION reported addrRecv as the address it sees us at.
func selfAdvPeer(pm *PeerManager, addr string, connType ConnType, addrRecv string, addrRecvPort uint16) *Peer {
	p := NewTestPeer(addr, 0)
	p.config.Services = ServiceNodeNetwork | ServiceNodeWitness
	p.inbound = connType == ConnInbound
	p.peerVersion.AddrRecv = NetAddress{IP: net.ParseIP(addrRecv), Port: addrRecvPort}
	pm.mu.Lock()
	pm.peers[addr] = &PeerInfo{peer: p, connType: connType, connectedAt: time.Now()}
	pm.mu.Unlock()
	return p
}

func drain(p *Peer) []Message {
	var out []Message
	for {
		select {
		case m := <-p.sendQueue:
			out = append(out, m)
		default:
			return out
		}
	}
}

func TestSelfAdvRoutableFilter(t *testing.T) {
	cases := map[string]bool{
		"1.2.3.4":         true,
		"8.8.8.8":         true,
		"76.38.7.169":     true,
		"2001:db9::1":     true,
		"10.0.0.1":        false, // RFC1918
		"172.16.5.5":      false, // RFC1918
		"192.168.1.128":   false, // RFC1918
		"127.0.0.1":       false, // loopback
		"100.64.0.1":      false, // RFC6598 CGNAT
		"100.127.255.254": false, // RFC6598 CGNAT
		"169.254.1.1":     false, // link-local
		"0.0.0.0":         false, // unspecified
		"203.0.113.5":     false, // RFC5737 TEST-NET-3 (Core rejects too)
		"198.18.0.1":      false, // RFC2544
		"::1":             false,
		"fe80::1":         false,
		"fd00::1":         false, // RFC4193
	}
	for s, want := range cases {
		if got := isRoutableIP(net.ParseIP(s)); got != want {
			t.Errorf("isRoutableIP(%s) = %v, want %v", s, got, want)
		}
	}
	tab := newLocalAddrTable()
	if tab.addManual(net.ParseIP("192.168.1.128"), 8455) {
		t.Error("addManual accepted an RFC1918 address")
	}
	if tab.confirm(net.ParseIP("100.64.1.1"), 8455, "g1", true, time.Now()) {
		t.Error("discovery accepted a CGNAT address")
	}
}

func TestSelfAdvDiscoveryFromAddrRecv(t *testing.T) {
	pm := newSelfAdvPM(t, "0.0.0.0:8455", false)
	onVersion := pm.wrapListeners().OnVersion
	ver := func(p *Peer) *MsgVersion { return &MsgVersion{AddrRecv: p.AddrLocal()} }

	// One outbound peer: recorded, but not yet usable (needs 2 netgroups).
	p1 := selfAdvPeer(pm, "8.8.8.8:8333", ConnFullRelay, "76.38.7.169", 50123)
	onVersion(p1, ver(p1))
	la := pm.LocalAddresses()
	if len(la) != 1 || la[0].IP.String() != "76.38.7.169" || la[0].Port != 8455 || la[0].Score != 1 {
		t.Fatalf("after 1 confirmation: %+v (want 76.38.7.169:8455 score 1; port is OUR listen port, not the peer-seen ephemeral one)", la)
	}
	if _, ok := pm.bestLocalAddress(); ok {
		t.Fatal("single-peer discovery must not be advertised to others")
	}
	// Same /16 again: no extra score.
	p1b := selfAdvPeer(pm, "8.8.4.4:8333", ConnFullRelay, "76.38.7.169", 50124)
	onVersion(p1b, ver(p1b))
	if la := pm.LocalAddresses(); la[0].Score != 1 {
		t.Fatalf("same-netgroup reconfirmation scored: %+v", la)
	}
	// A second netgroup confirms: now usable.
	p2 := selfAdvPeer(pm, "9.9.9.9:8333", ConnFullRelay, "76.38.7.169", 50125)
	onVersion(p2, ver(p2))
	if b, ok := pm.bestLocalAddress(); !ok || b.IP.String() != "76.38.7.169" || b.Port != 8455 || b.Score != 2 {
		t.Fatalf("best = %+v ok=%v", b, ok)
	}

	// Non-routable addr_recv, or a non-routable (LAN) peer: ignored.
	p3 := selfAdvPeer(pm, "1.1.1.1:8333", ConnFullRelay, "192.168.1.128", 1)
	onVersion(p3, ver(p3))
	p4 := selfAdvPeer(pm, "192.168.1.9:8333", ConnFullRelay, "5.5.5.5", 1)
	onVersion(p4, ver(p4))
	// Inbound peers never create an entry (Core SeenLocal).
	p5 := selfAdvPeer(pm, "4.4.4.4:50000", ConnInbound, "6.6.6.6", 8455)
	onVersion(p5, ver(p5))
	if la := pm.LocalAddresses(); len(la) != 1 {
		t.Fatalf("unexpected entries: %+v", la)
	}
	// ...but do score an existing one.
	p6 := selfAdvPeer(pm, "4.4.4.4:50001", ConnInbound, "76.38.7.169", 8455)
	onVersion(p6, ver(p6))
	if la := pm.LocalAddresses(); la[0].Score != 3 {
		t.Fatalf("inbound SeenLocal did not score: %+v", la)
	}

	// IP change: the new address takes over once the old one ages out.
	now := time.Now().Add(DiscoveredLocalAddrTTL + time.Minute)
	pm.localAddrs.confirm(net.ParseIP("76.38.7.200"), 8455, "a", true, now)
	pm.localAddrs.confirm(net.ParseIP("76.38.7.200"), 8455, "b", true, now)
	if b, ok := pm.localAddrs.best(nil, now); !ok || b.IP.String() != "76.38.7.200" {
		t.Fatalf("after IP change best = %+v ok=%v", b, ok)
	}
	if la := pm.localAddrs.list(now); len(la) != 1 {
		t.Fatalf("stale entry not expired: %+v", la)
	}

	// -discover=0: nothing learned.
	pm2 := NewPeerManager(PeerManagerConfig{ListenAddr: ":8455"})
	q := selfAdvPeer(pm2, "8.8.8.8:8333", ConnFullRelay, "76.38.7.169", 1)
	pm2.wrapListeners().OnVersion(q, ver(q))
	if la := pm2.LocalAddresses(); len(la) != 0 {
		t.Fatalf("discover off but learned %+v", la)
	}
}

func TestSelfAdvAddrMessageContents(t *testing.T) {
	pm := newSelfAdvPM(t, "0.0.0.0:8455", false)
	pm.config.Discover = false // only the manual address is a candidate
	if !pm.AddExternalIP(net.ParseIP("1.2.3.4"), 0) {
		t.Fatal("AddExternalIP rejected 1.2.3.4")
	}
	la := pm.LocalAddresses()
	if len(la) != 1 || la[0].Port != 8455 || la[0].Score != LocalManual {
		t.Fatalf("localaddresses = %+v, want 1.2.3.4:8455 score %d", la, LocalManual)
	}

	now := time.Unix(1_800_000_000, 0)
	// v1 peer -> addr
	p := selfAdvPeer(pm, "8.8.8.8:8333", ConnFullRelay, "76.38.7.169", 50000)
	if !pm.maybeSendLocalAddr(p, now) {
		t.Fatal("no self-announcement sent")
	}
	msgs := drain(p)
	if len(msgs) != 1 {
		t.Fatalf("sent %d messages", len(msgs))
	}
	am, ok := msgs[0].(*MsgAddr)
	if !ok || len(am.AddrList) != 1 {
		t.Fatalf("sent %T %+v, want addr with 1 entry", msgs[0], msgs[0])
	}
	a := am.AddrList[0]
	if !a.IP.Equal(net.ParseIP("1.2.3.4")) || a.Port != 8455 || a.Timestamp != uint32(now.Unix()) ||
		a.Services != p.config.Services {
		t.Fatalf("addr entry = %+v", a)
	}
	// Timer armed: not due again immediately.
	if pm.maybeSendLocalAddr(p, now.Add(time.Second)) {
		t.Fatal("resent before the Poisson timer elapsed")
	}
	p.addrMu.Lock()
	next := p.nextLocalAddrSend
	p.addrMu.Unlock()
	if !next.After(now) {
		t.Fatalf("next send %v not after %v", next, now)
	}
	if !pm.maybeSendLocalAddr(p, next.Add(time.Second)) {
		t.Fatal("not resent after the timer elapsed")
	}

	// addrv2 peer -> addrv2, wire round trip keeps IP + listen port.
	p2 := selfAdvPeer(pm, "9.9.9.9:8333", ConnFullRelay, "76.38.7.169", 50000)
	p2.wantsAddrv2 = true
	pm.maybeSendLocalAddr(p2, now)
	msgs = drain(p2)
	v2, ok := msgs[0].(*MsgAddrv2)
	if !ok || len(v2.AddrList) != 1 {
		t.Fatalf("sent %T, want addrv2", msgs[0])
	}
	e := v2.AddrList[0]
	if e.NetworkID != NetIPv4 || !net.IP(e.Addr).Equal(net.ParseIP("1.2.3.4")) || e.Port != 8455 || e.Time != uint32(now.Unix()) {
		t.Fatalf("addrv2 entry = %+v", e)
	}

	// Never to block-relay-only or feeler connections.
	for _, ct := range []ConnType{ConnBlockRelayOnly, ConnFeeler} {
		q := selfAdvPeer(pm, "7.7.7.7:8333", ct, "76.38.7.169", 1)
		if pm.maybeSendLocalAddr(q, now) || len(drain(q)) != 0 {
			t.Fatalf("self-announced to %v", ct)
		}
	}
	// Not listening: nothing.
	pmNL := NewPeerManager(PeerManagerConfig{})
	pmNL.AddExternalIP(net.ParseIP("1.2.3.4"), 8455)
	q := selfAdvPeer(pmNL, "7.7.7.7:8333", ConnFullRelay, "76.38.7.169", 1)
	if pmNL.maybeSendLocalAddr(q, now) {
		t.Fatal("self-announced while not listening")
	}
}

func TestSelfAdvIBDGate(t *testing.T) {
	ibd := true
	pm := NewPeerManager(PeerManagerConfig{ListenAddr: ":8455", IsIBDFunc: func() bool { return ibd }})
	pm.AddExternalIP(net.ParseIP("1.2.3.4"), 0)
	p := selfAdvPeer(pm, "8.8.8.8:8333", ConnFullRelay, "0.0.0.0", 0)
	now := time.Now()
	if pm.maybeSendLocalAddr(p, now) || len(drain(p)) != 0 {
		t.Fatal("self-announced during IBD")
	}
	p.addrMu.Lock()
	armed := !p.nextLocalAddrSend.IsZero()
	p.addrMu.Unlock()
	if armed {
		t.Fatal("IBD must not consume the first-send slot")
	}
	ibd = false
	if !pm.maybeSendLocalAddr(p, now) || len(drain(p)) != 1 {
		t.Fatal("no self-announcement after leaving IBD")
	}
}

// GetLocalAddrForPeer: with no usable table entry, a routable peer's view of
// us is used — the IP only for outbound (keeping our listen port), IP and
// port for inbound.
func TestSelfAdvPeerReportedAddress(t *testing.T) {
	pm := newSelfAdvPM(t, ":8455", false)
	out := selfAdvPeer(pm, "8.8.8.8:8333", ConnFullRelay, "76.38.7.169", 50000)
	ip, port, ok := pm.localAddrForPeer(out, time.Now())
	if !ok || ip.String() != "76.38.7.169" || port != 8455 {
		t.Fatalf("outbound: %v:%d ok=%v", ip, port, ok)
	}
	in := selfAdvPeer(pm, "9.9.9.9:40000", ConnInbound, "76.38.7.169", 18455)
	ip, port, ok = pm.localAddrForPeer(in, time.Now())
	if !ok || ip.String() != "76.38.7.169" || port != 18455 {
		t.Fatalf("inbound: %v:%d ok=%v", ip, port, ok)
	}
	// LAN peer, nothing known: no advertisement.
	lan := selfAdvPeer(pm, "192.168.1.5:8333", ConnFullRelay, "76.38.7.169", 1)
	if _, _, ok := pm.localAddrForPeer(lan, time.Now()); ok {
		t.Fatal("advertised with nothing routable")
	}
}

func TestSelfAdvVersionAddrFrom(t *testing.T) {
	pm := newSelfAdvPM(t, ":8455", false)
	cfg := pm.makePeerConfig()
	if _, _, ok := cfg.LocalAddrFunc(); ok {
		t.Fatal("addr_from filled with no local address")
	}
	pm.AddExternalIP(net.ParseIP("1.2.3.4"), 0)
	p := &Peer{config: pm.makePeerConfig()}
	na := p.localNetAddress()
	if !na.IP.Equal(net.ParseIP("1.2.3.4")) || na.Port != 8455 {
		t.Fatalf("addr_from = %+v", na)
	}
}
