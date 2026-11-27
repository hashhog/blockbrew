package p2p

import (
	"encoding/binary"
	"hash/maphash"
	"time"
)

// Address-relay admission rules from Bitcoin Core's ProcessAddrs and
// RelayAddress / PushAddress (net_processing.cpp:5658-5691, :2277-2323,
// :1121-1137).

// addrRelayMaxEntries is Core's vAddr.size() <= 10 relay gate: larger
// messages are getaddr answers, not gossip.
const addrRelayMaxEntries = 10

// addrRelayFreshWindow is Core's "addr.nTime > current_time - 10min".
const addrRelayFreshWindow = 10 * time.Minute

// addrKnownGeneration is the size of one generation of a peer's addr-known
// set. Two generations are kept, so the newest addrKnownGeneration keys are
// always remembered — the guarantee Core's CRollingBloomFilter(5000, 0.001)
// gives for m_addr_known.
const addrKnownGeneration = 5000

// addrRelayFresh reports whether an address with wire timestamp ts may be
// relayed at now. Core first rewrites a timestamp <= 100000000 or more than
// 10 minutes in the future to now-5d, which is never fresh; it then relays
// only when nTime > now-10min.
func addrRelayFresh(ts uint32, now time.Time) bool {
	t := int64(ts)
	n := now.Unix()
	if t <= 100000000 || t > n+int64(addrRelayFreshWindow/time.Second) {
		return false
	}
	return t > n-int64(addrRelayFreshWindow/time.Second)
}

// addrV2Routable mirrors CNetAddr::IsRoutable for a BIP155 entry: IP
// addresses go through the RFC range checks; Tor v3, I2P and CJDNS entries
// of the right length are routable; anything else is not.
func addrV2Routable(a *NetAddressV2) bool {
	switch a.NetworkID {
	case NetIPv4, NetIPv6:
		l := a.ToLegacy()
		return l != nil && isRoutableIP(l.IP)
	case NetTorV3:
		return len(a.Addr) == TorV3AddrSize
	case NetI2P:
		return len(a.Addr) == I2PAddrSize
	case NetCJDNS:
		return len(a.Addr) == CJDNSAddrSize && a.Addr[0] == 0xfc
	default:
		return false
	}
}

var addrKnownSeed = maphash.MakeSeed()

func addrKnownKey(netID uint8, addr []byte, port uint16) uint64 {
	var h maphash.Hash
	h.SetSeed(addrKnownSeed)
	h.WriteByte(netID)
	h.Write(addr)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	h.Write(p[:])
	return h.Sum64()
}

// addrKnownKeyV1 keys an addr entry. An IPv4-mapped address keys as IPv4 so
// the same address seen through addr and addrv2 is one entry.
func addrKnownKeyV1(a *NetAddress) uint64 {
	if ip4 := a.IP.To4(); ip4 != nil {
		return addrKnownKey(NetIPv4, ip4, a.Port)
	}
	return addrKnownKey(NetIPv6, a.IP.To16(), a.Port)
}

// addrKnownKeyV2 keys an addrv2 entry, normalising IPv4/IPv6 through the
// legacy form so it matches addrKnownKeyV1.
func addrKnownKeyV2(a *NetAddressV2) uint64 {
	if a.NetworkID == NetIPv4 || a.NetworkID == NetIPv6 {
		if l := a.ToLegacy(); l != nil {
			return addrKnownKeyV1(l)
		}
	}
	return addrKnownKey(a.NetworkID, a.Addr, a.Port)
}

// addrKnownSet is a peer's m_addr_known: the addresses the peer is known to
// have (it sent them to us, or we sent them to it). Two map generations make
// it a bounded rolling set; it is allocated on first use.
type addrKnownSet struct {
	cur, prev map[uint64]struct{}
}

func (s *addrKnownSet) contains(k uint64) bool {
	if _, ok := s.cur[k]; ok {
		return true
	}
	_, ok := s.prev[k]
	return ok
}

func (s *addrKnownSet) insert(k uint64) {
	if s.cur == nil {
		s.cur = make(map[uint64]struct{})
	}
	if len(s.cur) >= addrKnownGeneration {
		s.prev = s.cur
		s.cur = make(map[uint64]struct{})
	}
	s.cur[k] = struct{}{}
}

// addAddrKnown records that p knows the address keyed k (Core
// AddAddressKnown).
func (p *Peer) addAddrKnown(k uint64) {
	p.addrMu.Lock()
	p.addrKnown.insert(k)
	p.addrMu.Unlock()
}

// addAddrKnownIfNew records k for p and reports whether p did not know it
// already, i.e. whether the address should be sent (Core PushAddress's
// m_addr_known->contains test plus the insert made when it is sent).
func (p *Peer) addAddrKnownIfNew(k uint64) bool {
	p.addrMu.Lock()
	defer p.addrMu.Unlock()
	if p.addrKnown.contains(k) {
		return false
	}
	p.addrKnown.insert(k)
	return true
}

// forgetAddrKnown removes keys from p's addr-known set. Relay calls it when
// SendMessage drops the message, so the addresses can still be sent later
// (Core marks an address known only when MaybeSendAddr sends it).
func (p *Peer) forgetAddrKnown(keys []uint64) {
	p.addrMu.Lock()
	defer p.addrMu.Unlock()
	for _, k := range keys {
		delete(p.addrKnown.cur, k)
		delete(p.addrKnown.prev, k)
	}
}

// MarkGetAddrSent records that we sent this peer a getaddr (Core
// Peer::m_getaddr_sent = true when GETADDR is pushed). Until the peer sends
// an addr/addrv2 message of fewer than 1000 entries, its addresses are
// stored but not relayed.
func (p *Peer) MarkGetAddrSent() {
	p.addrMu.Lock()
	p.getaddrSent = true
	p.addrMu.Unlock()
}

// GetAddrSent reports whether a getaddr to this peer is still outstanding.
func (p *Peer) GetAddrSent() bool {
	p.addrMu.Lock()
	defer p.addrMu.Unlock()
	return p.getaddrSent
}

// noteAddrMessageDone ends the getaddr-sent state after an addr/addrv2
// message of fewer than MaxAddresses entries (Core: "if (vAddr.size() <
// 1000) peer.m_getaddr_sent = false;").
func (p *Peer) noteAddrMessageDone(received int) {
	if received >= MaxAddresses {
		return
	}
	p.addrMu.Lock()
	p.getaddrSent = false
	p.addrMu.Unlock()
}
