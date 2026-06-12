package p2p

import (
	"net"
	"testing"
	"time"
)

// getaddr / addr / addrv2 anti-DoS guards (Bitcoin Core net_processing.cpp).
//
// These tests EXECUTE the live message handlers (handleGetAddr,
// admitAddrTokens, admitAddrV2Tokens) and prove all three guards:
//
//  1. getaddr is answered ONCE per connection and IGNORED from outbound peers
//     (Core m_getaddr_recvd + IsInboundConn, net_processing.cpp:4822-4837);
//  2. the getaddr response is capped at min(MaxAddresses, floor(23*size/100))
//     using INTEGER division, NOT ceil (Core MAX_PCT_ADDR_TO_SEND = 23,
//     addrman.cpp:797-804);
//  3. the inbound-addr leaky token bucket (init 1.0, refill elapsed*0.1 cap
//     1000, spend 1/addr) rate-limits BOTH the addr and addrv2 handlers
//     through ONE shared per-peer bucket so addrv2 cannot bypass it
//     (Core m_addr_token_bucket, net_processing.cpp:5644-5671).

// newAntiDoSTestPeer builds a minimal in-package Peer whose SendMessage just
// queues to an inspectable buffered channel — no live TCP needed.
func newAntiDoSTestPeer(inbound bool) *Peer {
	return &Peer{
		addr:      "203.0.113.7:8333",
		inbound:   inbound,
		sendQueue: make(chan Message, 16),
		quit:      make(chan struct{}),
	}
}

// drainOneAddr returns the AddrList of the first MsgAddr queued, or nil if none.
func drainOneAddr(p *Peer) []NetAddress {
	select {
	case m := <-p.sendQueue:
		if am, ok := m.(*MsgAddr); ok {
			return am.AddrList
		}
		return nil
	default:
		return nil
	}
}

// seedShareable adds n distinct routable, successfully-connected addresses so
// they count toward the shareable pool (LastSuccess set).
func seedShareable(t *testing.T, ab *AddressBook, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		ip := net.IPv4(8, byte(i>>16), byte(i>>8), byte(i))
		na := NetAddress{IP: ip, Port: 8333, Services: 1}
		ab.AddAddress(na, "test")
		ab.MarkSuccess(net.JoinHostPort(ip.String(), "8333"))
	}
}

// ── Guard 1: getaddr-once + outbound-ignore ─────────────────────────────────

func TestGetAddrAnswerOncePerConnection(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{MaxOutbound: 1})
	seedShareable(t, pm.addrBook, 100)
	p := newAntiDoSTestPeer(true /* inbound */)

	// First getaddr → answered with a (capped) MsgAddr.
	pm.handleGetAddr(p)
	first := drainOneAddr(p)
	if len(first) == 0 {
		t.Fatalf("first getaddr from inbound peer must be answered with addresses, got %d", len(first))
	}
	if !p.GetAddrRecvd() {
		t.Fatal("getaddrRecvd flag must be set after the first getaddr")
	}

	// Second getaddr → ignored (no message queued).
	pm.handleGetAddr(p)
	if second := drainOneAddr(p); second != nil {
		t.Fatalf("second getaddr must be ignored, but %d addresses were sent", len(second))
	}
}

func TestGetAddrIgnoredFromOutboundPeer(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{MaxOutbound: 1})
	seedShareable(t, pm.addrBook, 100)
	p := newAntiDoSTestPeer(false /* outbound */)

	pm.handleGetAddr(p)
	if got := drainOneAddr(p); got != nil {
		t.Fatalf("getaddr from an OUTBOUND peer must be ignored, but %d addresses were sent", len(got))
	}
	// The one-time flag must NOT be consumed for an ignored outbound getaddr —
	// the outbound check returns before markGetAddrRecvd.
	if p.GetAddrRecvd() {
		t.Fatal("getaddrRecvd must not be set when getaddr is ignored for an outbound peer")
	}
}

// ── Guard 2: 23%-cap = min(1000, FLOOR(23*size/100)), integer division ───────

func TestGetAddrCapFormulaFloorNotCeil(t *testing.T) {
	cases := []struct {
		size int
		want int
	}{
		{0, 0},
		{1, 0},     // floor(23*1/100)   = floor(0.23) = 0   (NOT 1 — ceil would be 1)
		{4, 0},     // floor(23*4/100)   = floor(0.92) = 0   (proves FLOOR, not ceil)
		{5, 1},     // floor(23*5/100)   = floor(1.15) = 1
		{100, 23},  // floor(23*100/100) = 23
		{1000, 230},
		{100000, MaxAddresses}, // 23000 clamped to 1000
	}
	for _, c := range cases {
		if got := getaddrCap(c.size); got != c.want {
			t.Errorf("getaddrCap(%d) = %d, want %d (Core floor(23*size/100), clamp %d)",
				c.size, got, c.want, MaxAddresses)
		}
	}
}

func TestGetAddrResponseHonorsCap(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{MaxOutbound: 1})
	seedShareable(t, pm.addrBook, 100) // cap = floor(23*100/100) = 23
	p := newAntiDoSTestPeer(true)

	pm.handleGetAddr(p)
	got := drainOneAddr(p)
	wantCap := getaddrCap(pm.addrBook.ShareableCount())
	if wantCap != 23 {
		t.Fatalf("precondition: expected cap 23 for 100 shareable, got %d", wantCap)
	}
	if len(got) != wantCap {
		t.Fatalf("getaddr response = %d addresses, want exactly the cap %d", len(got), wantCap)
	}
	if len(got) > MaxAddresses {
		t.Fatalf("getaddr response %d exceeds MaxAddresses %d", len(got), MaxAddresses)
	}
}

// ── Guard 3: inbound-addr leaky token bucket (shared by addr + addrv2) ───────

func mkAddrs(n int) []NetAddress {
	out := make([]NetAddress, n)
	for i := range out {
		out[i] = NetAddress{IP: net.IPv4(9, 9, byte(i>>8), byte(i)), Port: 8333}
	}
	return out
}

func mkAddrV2(n int) []NetAddressV2 {
	out := make([]NetAddressV2, n)
	for i := range out {
		out[i] = NetAddressV2{NetworkID: NetIPv4, Addr: []byte{9, 9, byte(i >> 8), byte(i)}, Port: 8333}
	}
	return out
}

func TestAddrTokenBucketInitialAdmitOne(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{MaxOutbound: 1})
	p := newAntiDoSTestPeer(true)

	// Bucket starts at 1.0 → exactly ONE address admitted from the first batch.
	got := pm.admitAddrTokens(p, mkAddrs(50))
	if len(got) != 1 {
		t.Fatalf("first addr batch with bucket=1.0 must admit exactly 1, got %d", len(got))
	}
	// Bucket now ~0 → the next batch (same instant) admits 0.
	got2 := pm.admitAddrTokens(p, mkAddrs(50))
	if len(got2) != 0 {
		t.Fatalf("drained bucket must admit 0 on the next immediate batch, got %d", len(got2))
	}
}

// TestAddrV2DoesNotBypassBucket is the falsification guard: if addrv2 used a
// separate bucket (or none), a peer could send addr (drains the 1.0 token) and
// then addrv2 to get MORE addresses admitted in the same instant. With one
// shared bucket, the addrv2 batch must admit 0.
func TestAddrV2DoesNotBypassBucket(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{MaxOutbound: 1})
	p := newAntiDoSTestPeer(true)

	// Drain the initial 1.0 token via the addr path.
	if got := pm.admitAddrTokens(p, mkAddrs(10)); len(got) != 1 {
		t.Fatalf("addr path should admit the initial 1 token, got %d", len(got))
	}
	// addrv2 in the same instant shares the SAME (now-empty) bucket → 0 admitted.
	if got := pm.admitAddrV2Tokens(p, mkAddrV2(10)); len(got) != 0 {
		t.Fatalf("FALSIFICATION: addrv2 bypassed the shared bucket — admitted %d, want 0", len(got))
	}
}

func TestAddrTokenBucketRefill(t *testing.T) {
	p := newAntiDoSTestPeer(true)

	// Prime + drain the initial token.
	if p.takeAddrTokens(1) != 1 {
		t.Fatal("first token should be admitted")
	}
	// Force a 100s-old timestamp → refill = 100 * 0.1 = 10 tokens.
	p.addrMu.Lock()
	p.addrTokenTimestamp = time.Now().Add(-100 * time.Second)
	p.addrMu.Unlock()

	admit := p.takeAddrTokens(50)
	if admit != 10 {
		t.Fatalf("after 100s the bucket should refill 10 tokens (100*%.1f), admitted %d", MaxAddrRatePerSecond, admit)
	}
}

func TestAddrTokenBucketRefillCappedAt1000(t *testing.T) {
	p := newAntiDoSTestPeer(true)
	if p.takeAddrTokens(1) != 1 {
		t.Fatal("first token should be admitted")
	}
	// A huge elapsed time must NOT push the bucket past the soft cap (1000).
	p.addrMu.Lock()
	p.addrTokenTimestamp = time.Now().Add(-1_000_000 * time.Second)
	p.addrMu.Unlock()

	admit := p.takeAddrTokens(5000)
	if admit != int(MaxAddrProcessingTokenBucket) {
		t.Fatalf("time-based refill must cap at MaxAddrProcessingTokenBucket=%v, admitted %d",
			MaxAddrProcessingTokenBucket, admit)
	}
}

func TestAddrTokenBucketNoBanExempt(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{MaxOutbound: 1})
	p := newAntiDoSTestPeer(true)
	p.SetNoBan(true)

	// NoBan / whitelisted (manual) peers bypass the rate limit entirely:
	// a full 1000-address batch is admitted untouched.
	got := pm.admitAddrTokens(p, mkAddrs(1000))
	if len(got) != 1000 {
		t.Fatalf("NoBan peer must bypass the addr rate limit, admitted %d of 1000", len(got))
	}
}
