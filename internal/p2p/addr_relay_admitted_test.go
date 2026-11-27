package p2p

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
)

// Tests for cffix-blockbrew-addr-relay-admitted-only.
//
// Bitcoin Core PeerManagerImpl::ProcessAddrs (net_processing.cpp:5658-5691)
// relays an address only when it passed the per-peer token bucket, its nTime
// is within the last 10 minutes, it IsRoutable(), the message held at most 10
// entries and we have not sent this peer a getaddr. RelayAddress / PushAddress
// (:2277-2315, :1127-1137) then drop it for any destination whose
// m_addr_known already holds it.
//
// These tests drive the OnAddr / OnAddrv2 handlers built by wrapListeners, so
// they compile against the pre-fix tree and fail there on their assertions.

// addrRelayRig is a PeerManager with one source peer and two relay
// destinations, all registered in pm.peers.
type addrRelayRig struct {
	pm       *PeerManager
	src      *Peer
	dstA     *Peer
	dstB     *Peer
	onAddr   func(*Peer, *MsgAddr)
	onAddrv2 func(*Peer, *MsgAddrv2)
}

func newAddrRelayRig(t *testing.T) *addrRelayRig {
	t.Helper()
	pm := NewPeerManager(PeerManagerConfig{
		Network:     MainnetMagic,
		ChainParams: consensus.MainnetParams(),
	})
	r := &addrRelayRig{
		pm:   pm,
		src:  makeFakePeer("8.8.4.4:8333"),
		dstA: makeFakePeer("9.9.9.9:8333"),
		dstB: makeFakePeer("1.0.0.1:8333"),
	}
	pm.mu.Lock()
	pm.peers[r.src.addr] = &PeerInfo{peer: r.src}
	pm.peers[r.dstA.addr] = &PeerInfo{peer: r.dstA}
	pm.peers[r.dstB.addr] = &PeerInfo{peer: r.dstB}
	pm.mu.Unlock()
	l := pm.wrapListeners()
	r.onAddr = l.OnAddr
	r.onAddrv2 = l.OnAddrv2
	return r
}

// drainAddrs empties p's send queue and returns the addr / addrv2 messages
// it held, flattened to "ip:port" strings, plus the number of messages.
func drainAddrs(p *Peer) (msgs int, entries []string) {
	for {
		select {
		case m := <-p.sendQueue:
			switch mm := m.(type) {
			case *MsgAddr:
				msgs++
				for _, a := range mm.AddrList {
					entries = append(entries, net.JoinHostPort(a.IP.String(), strconv.Itoa(int(a.Port))))
				}
			case *MsgAddrv2:
				msgs++
				for _, a := range mm.AddrList {
					if l := a.ToLegacy(); l != nil {
						entries = append(entries, net.JoinHostPort(l.IP.String(), strconv.Itoa(int(a.Port))))
					} else {
						entries = append(entries, a.NetworkName())
					}
				}
			}
		default:
			return msgs, entries
		}
	}
}

func v1Addr(ip string, port uint16, ts time.Time) NetAddress {
	return NetAddress{
		Timestamp: uint32(ts.Unix()),
		Services:  uint64(ServiceNodeNetwork | ServiceNodeWitness),
		IP:        net.ParseIP(ip).To16(),
		Port:      port,
	}
}

func v2Addr(ip string, port uint16, ts time.Time) NetAddressV2 {
	return NetAddressV2{
		Time:      uint32(ts.Unix()),
		Services:  uint64(ServiceNodeNetwork | ServiceNodeWitness),
		NetworkID: NetIPv4,
		Addr:      net.ParseIP(ip).To4(),
		Port:      port,
	}
}

// TestAddrRelayOnlyAdmittedFresh is the item's test: once the source's token
// bucket is spent, 100 one-entry addr messages carrying stale timestamps must
// not be relayed. Core relays nothing here (every entry is rate-limited, and
// each would also fail the 10-minute freshness test); the bound of 2 allows
// for the bucket refilling by a token during the run. Pre-fix, every message
// was forwarded raw to both destinations: 200 relays.
func TestAddrRelayOnlyAdmittedFresh(t *testing.T) {
	r := newAddrRelayRig(t)
	now := time.Now()

	// Exhaust the bucket (Core starts it at 1.0) with an 11-entry message,
	// which is over the relay size gate and so relays nothing by itself.
	big := make([]NetAddress, 11)
	for i := range big {
		big[i] = v1Addr("5.6.7.8", uint16(10000+i), now)
	}
	r.onAddr(r.src, &MsgAddr{AddrList: big})
	drainAddrs(r.dstA)
	drainAddrs(r.dstB)

	stale := now.Add(-3 * time.Hour)
	// Drain after every message: the fake peers' send queues hold only
	// SendQueueSize entries, and a full queue would hide relays.
	na, nb := 0, 0
	for i := 0; i < 100; i++ {
		r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{
			v1Addr("5.6.7.9", uint16(20000+i), stale),
		}})
		a, _ := drainAddrs(r.dstA)
		b, _ := drainAddrs(r.dstB)
		na, nb = na+a, nb+b
	}
	if total := na + nb; total > 2 {
		t.Fatalf("relayed %d addr messages (dstA=%d dstB=%d) for 100 stale, rate-limited "+
			"one-entry addrs; Core relays none (want <= 2)", total, na, nb)
	}
}

// TestAddrRelayFreshAdmittedIsRelayed is the positive control: a fresh,
// routable address that the bucket admits is relayed to both destinations
// and to nobody else. It passes before and after the fix.
func TestAddrRelayFreshAdmittedIsRelayed(t *testing.T) {
	r := newAddrRelayRig(t)
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{v1Addr("5.6.7.8", 8333, time.Now())}})
	for name, p := range map[string]*Peer{"dstA": r.dstA, "dstB": r.dstB} {
		n, got := drainAddrs(p)
		if n != 1 || len(got) != 1 || got[0] != "5.6.7.8:8333" {
			t.Errorf("%s got %d msgs %v, want one msg [5.6.7.8:8333]", name, n, got)
		}
	}
	if n, _ := drainAddrs(r.src); n != 0 {
		t.Errorf("relayed %d msgs back to the source", n)
	}
}

// TestAddrRelaySkipsStale: an admitted but stale address is stored, not
// relayed (Core: addr.nTime > current_time - 10min).
func TestAddrRelaySkipsStale(t *testing.T) {
	r := newAddrRelayRig(t)
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{
		v1Addr("5.6.7.8", 8333, time.Now().Add(-11*time.Minute)),
	}})
	na, ga := drainAddrs(r.dstA)
	nb, gb := drainAddrs(r.dstB)
	if na+nb != 0 {
		t.Fatalf("stale addr relayed: dstA=%v dstB=%v", ga, gb)
	}
}

// TestAddrRelaySkipsFutureTimestamp: Core rewrites nTime > now+10min to
// now-5d before the freshness test, so such an address is not relayed.
func TestAddrRelaySkipsFutureTimestamp(t *testing.T) {
	r := newAddrRelayRig(t)
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{
		v1Addr("5.6.7.8", 8333, time.Now().Add(time.Hour)),
	}})
	na, ga := drainAddrs(r.dstA)
	nb, gb := drainAddrs(r.dstB)
	if na+nb != 0 {
		t.Fatalf("future-dated addr relayed: dstA=%v dstB=%v", ga, gb)
	}
}

// TestAddrRelaySkipsUnroutable: a fresh RFC1918 address is not relayed
// (Core: addr.IsRoutable()).
func TestAddrRelaySkipsUnroutable(t *testing.T) {
	r := newAddrRelayRig(t)
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{v1Addr("10.1.2.3", 8333, time.Now())}})
	na, ga := drainAddrs(r.dstA)
	nb, gb := drainAddrs(r.dstB)
	if na+nb != 0 {
		t.Fatalf("unroutable addr relayed: dstA=%v dstB=%v", ga, gb)
	}
}

// TestAddrRelayOnlyRelaysAdmittedEntries: from a fresh bucket (1 token) a
// 3-entry message admits one address; only that one is relayed.
func TestAddrRelayOnlyRelaysAdmittedEntries(t *testing.T) {
	r := newAddrRelayRig(t)
	now := time.Now()
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{
		v1Addr("5.6.7.1", 8333, now),
		v1Addr("5.6.7.2", 8333, now),
		v1Addr("5.6.7.3", 8333, now),
	}})
	for name, p := range map[string]*Peer{"dstA": r.dstA, "dstB": r.dstB} {
		_, got := drainAddrs(p)
		if len(got) != 1 {
			t.Errorf("%s relayed %v; only the 1 rate-limit-admitted entry may be relayed", name, got)
		}
	}
}

// TestAddrRelayMixedMessageFiltersPerEntry: with the rate limit out of the
// way (NoBan source), a message mixing fresh-routable, stale and unroutable
// entries relays exactly the fresh routable one.
func TestAddrRelayMixedMessageFiltersPerEntry(t *testing.T) {
	r := newAddrRelayRig(t)
	r.src.SetNoBan(true)
	now := time.Now()
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{
		v1Addr("5.6.7.8", 8333, now),
		v1Addr("5.6.7.9", 8333, now.Add(-time.Hour)),
		v1Addr("192.168.1.1", 8333, now),
	}})
	for name, p := range map[string]*Peer{"dstA": r.dstA, "dstB": r.dstB} {
		_, got := drainAddrs(p)
		if len(got) != 1 || got[0] != "5.6.7.8:8333" {
			t.Errorf("%s relayed %v, want [5.6.7.8:8333]", name, got)
		}
	}
}

// TestAddrRelayDedupPerDestination: the same address announced twice is
// sent to each destination once (Core m_addr_known). This is what stops a
// fresh address bouncing between mutually connected nodes.
func TestAddrRelayDedupPerDestination(t *testing.T) {
	r := newAddrRelayRig(t)
	r.src.SetNoBan(true)
	a := v1Addr("5.6.7.8", 8333, time.Now())
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{a}})
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{a}})
	for name, p := range map[string]*Peer{"dstA": r.dstA, "dstB": r.dstB} {
		_, got := drainAddrs(p)
		if len(got) != 1 {
			t.Errorf("%s received %v, want the address exactly once", name, got)
		}
	}
}

// TestAddrRelayDroppedSendIsNotRemembered: when a destination's send queue
// is full and the relay is dropped, the destination must not count the
// address as known, so a later announcement still reaches it. This pins the
// dedup added by this fix against swallowing addresses; master has no dedup
// and passes it too.
func TestAddrRelayDroppedSendIsNotRemembered(t *testing.T) {
	r := newAddrRelayRig(t)
	r.src.SetNoBan(true)
	for i := 0; i < SendQueueSize; i++ {
		r.dstA.SendMessage(&MsgPing{})
		r.dstB.SendMessage(&MsgPing{})
	}
	a := v1Addr("5.6.7.8", 8333, time.Now())
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{a}})
	if n, _ := drainAddrs(r.dstA); n != 0 {
		t.Fatalf("dstA: %d addr msgs got through a full queue", n)
	}
	drainAddrs(r.dstB)
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{a}})
	for name, p := range map[string]*Peer{"dstA": r.dstA, "dstB": r.dstB} {
		_, got := drainAddrs(p)
		if len(got) != 1 {
			t.Errorf("%s received %v after its earlier relay was dropped, want [5.6.7.8:8333]", name, got)
		}
	}
}

// TestAddrRelayDedupAcrossAddrAndAddrv2: an IPv4 address already relayed via
// addr is not relayed again to the same destination via addrv2.
func TestAddrRelayDedupAcrossAddrAndAddrv2(t *testing.T) {
	r := newAddrRelayRig(t)
	r.src.SetNoBan(true)
	now := time.Now()
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{v1Addr("5.6.7.8", 8333, now)}})
	r.onAddrv2(r.src, &MsgAddrv2{AddrList: []NetAddressV2{v2Addr("5.6.7.8", 8333, now)}})
	for name, p := range map[string]*Peer{"dstA": r.dstA, "dstB": r.dstB} {
		_, got := drainAddrs(p)
		if len(got) != 1 {
			t.Errorf("%s received %v, want 5.6.7.8:8333 exactly once", name, got)
		}
	}
}

// TestAddrRelayNotBackToAnnouncer: an address a destination itself announced
// to us is never relayed back to it (Core adds it to that peer's m_addr_known
// on receipt).
func TestAddrRelayNotBackToAnnouncer(t *testing.T) {
	r := newAddrRelayRig(t)
	r.src.SetNoBan(true)
	r.dstA.SetNoBan(true)
	a := v1Addr("5.6.7.8", 8333, time.Now())
	r.onAddr(r.dstA, &MsgAddr{AddrList: []NetAddress{a}})
	drainAddrs(r.dstA)
	drainAddrs(r.dstB)
	drainAddrs(r.src)
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{a}})
	if _, got := drainAddrs(r.dstA); len(got) != 0 {
		t.Errorf("relayed %v back to the peer that announced it", got)
	}
}

// TestAddrv2RelayOnlyAdmittedFresh is the addrv2 twin of the item's test.
func TestAddrv2RelayOnlyAdmittedFresh(t *testing.T) {
	r := newAddrRelayRig(t)
	now := time.Now()
	big := make([]NetAddressV2, 11)
	for i := range big {
		big[i] = v2Addr("5.6.7.8", uint16(10000+i), now)
	}
	r.onAddrv2(r.src, &MsgAddrv2{AddrList: big})
	drainAddrs(r.dstA)
	drainAddrs(r.dstB)

	stale := now.Add(-3 * time.Hour)
	// Drain after every message: the fake peers' send queues hold only
	// SendQueueSize entries, and a full queue would hide relays.
	na, nb := 0, 0
	for i := 0; i < 100; i++ {
		r.onAddrv2(r.src, &MsgAddrv2{AddrList: []NetAddressV2{
			v2Addr("5.6.7.9", uint16(20000+i), stale),
		}})
		a, _ := drainAddrs(r.dstA)
		b, _ := drainAddrs(r.dstB)
		na, nb = na+a, nb+b
	}
	if total := na + nb; total > 2 {
		t.Fatalf("relayed %d addrv2 messages (dstA=%d dstB=%d) for 100 stale, rate-limited "+
			"one-entry addrs; Core relays none (want <= 2)", total, na, nb)
	}
}

// TestAddrv2RelayMixedMessageFiltersPerEntry is the addrv2 twin of the mixed
// test: only the fresh routable entry is relayed.
func TestAddrv2RelayMixedMessageFiltersPerEntry(t *testing.T) {
	r := newAddrRelayRig(t)
	r.src.SetNoBan(true)
	now := time.Now()
	r.onAddrv2(r.src, &MsgAddrv2{AddrList: []NetAddressV2{
		v2Addr("5.6.7.8", 8333, now),
		v2Addr("5.6.7.9", 8333, now.Add(-time.Hour)),
		v2Addr("172.16.0.1", 8333, now),
	}})
	for name, p := range map[string]*Peer{"dstA": r.dstA, "dstB": r.dstB} {
		_, got := drainAddrs(p)
		if len(got) != 1 || got[0] != "5.6.7.8:8333" {
			t.Errorf("%s relayed %v, want [5.6.7.8:8333]", name, got)
		}
	}
}

// getAddrSentMarker is the Core m_getaddr_sent state. It is looked up through
// an interface so this file compiles on the pre-fix tree, where the test
// then fails on the assertion instead of on compilation.
type getAddrSentMarker interface{ MarkGetAddrSent() }

// TestAddrRelaySkipsWhileGetAddrSent: an addr message from a peer we sent
// getaddr to is a (possibly small) getaddr answer, not gossip, and is not
// relayed (Core: !peer.m_getaddr_sent). Any message under 1000 entries ends
// that state, so the next announcement is relayed again.
func TestAddrRelaySkipsWhileGetAddrSent(t *testing.T) {
	r := newAddrRelayRig(t)
	r.src.SetNoBan(true)
	m, ok := interface{}(r.src).(getAddrSentMarker)
	if !ok {
		t.Fatal("Peer has no getaddr-sent state (Core Peer::m_getaddr_sent): " +
			"a small getaddr response is relayed as if it were gossip")
	}
	m.MarkGetAddrSent()
	now := time.Now()
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{v1Addr("5.6.7.8", 8333, now)}})
	na, ga := drainAddrs(r.dstA)
	nb, gb := drainAddrs(r.dstB)
	if na+nb != 0 {
		t.Fatalf("getaddr response relayed: dstA=%v dstB=%v", ga, gb)
	}
	r.onAddr(r.src, &MsgAddr{AddrList: []NetAddress{v1Addr("5.6.7.9", 8333, now)}})
	na, _ = drainAddrs(r.dstA)
	nb, _ = drainAddrs(r.dstB)
	if na != 1 || nb != 1 {
		t.Fatalf("after the getaddr response, next announcement relayed to dstA=%d dstB=%d msgs, want 1 each", na, nb)
	}
}
