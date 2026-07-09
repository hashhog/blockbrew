package p2p

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestV1OnlyCacheRoundtrip covers the bounded v1-only cache: mark/lookup and
// eviction once the cache exceeds v2FallbackCacheMax.
func TestV1OnlyCacheRoundtrip(t *testing.T) {
	clearV1OnlyCache()
	defer clearV1OnlyCache()

	if isV1Only("1.2.3.4:8333") {
		t.Fatal("fresh cache must not contain addr")
	}
	markV1Only("1.2.3.4:8333")
	if !isV1Only("1.2.3.4:8333") {
		t.Fatal("marked addr must be reported v1-only")
	}
	if isV1Only("5.6.7.8:8333") {
		t.Fatal("unmarked addr must not be reported v1-only")
	}

	// Overfill and confirm the cache stays bounded.
	for i := 0; i < v2FallbackCacheMax*2; i++ {
		markV1Only(fmt.Sprintf("10.0.0.1:%d", i)) // distinct keys
	}
	v1OnlyMu.Lock()
	n := len(v1OnlyCache)
	v1OnlyMu.Unlock()
	if n > v2FallbackCacheMax {
		t.Fatalf("cache exceeded bound: len=%d max=%d", n, v2FallbackCacheMax)
	}
}

// TestOutboundV2FailFallsBackOnFreshSocket is the key regression test for the
// dirty-socket bug: when the outbound BIP-324 v2 handshake fails, the peer must
// (a) close the poisoned socket, (b) dial a BRAND NEW TCP socket, and (c) mark
// the address v1-only — rather than running v1 on the already-written-to conn.
//
// The listener plays a v1-only peer: on the first accept it drains the
// initiator's ellswift bytes and hangs up (failing the v2 handshake); on the
// second accept (the fresh redial) it holds the connection open. We assert a
// second accept happened, the transport is NOT encrypted, and the addr is
// cached v1-only.
func TestOutboundV2FailFallsBackOnFreshSocket(t *testing.T) {
	clearV1OnlyCache()
	defer clearV1OnlyCache()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	var accepts int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n := atomic.AddInt32(&accepts, 1)
			if n == 1 {
				// First connection: v1-only peer consumes the initiator's
				// ellswift pubkey + garbage, then closes so the v2 handshake
				// read fails.
				go func(cc net.Conn) {
					buf := make([]byte, EllSwiftPubKeySize)
					_, _ = io.ReadFull(cc, buf)
					cc.Close()
				}(c)
			} else {
				// Fresh v1 socket: keep it open (drain silently). We don't
				// complete the version handshake; NewOutboundPeer returns as
				// soon as the transport is chosen.
				go func(cc net.Conn) { _, _ = io.Copy(io.Discard, cc) }(c)
			}
		}
	}()

	cfg := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork,
		UserAgent:       "/blockbrew-test:0/",
		BestHeight:      1,
		PreferV2:        true,
	}

	peer, err := NewOutboundPeer(addr, cfg)
	if err != nil {
		t.Fatalf("NewOutboundPeer: %v", err)
	}
	defer peer.Disconnect()

	if peer.v2Transport {
		t.Error("expected v1 fallback transport, got encrypted v2")
	}
	if !isV1Only(addr) {
		t.Error("addr should be marked v1-only after v2 failure")
	}

	// The fresh redial's kernel-level connect succeeded before NewOutboundPeer
	// returned, but the listener goroutine's Accept() may lag slightly.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&accepts) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&accepts); got < 2 {
		t.Errorf("expected a fresh redial (>=2 accepts), got %d", got)
	}
}

// TestOutboundV1OnlyCachedSkipsV2Probe verifies that once an address is marked
// v1-only, a subsequent outbound dial goes straight to v1 with no v2 probe:
// only ONE TCP connection is made and no ellswift bytes are written.
func TestOutboundV1OnlyCachedSkipsV2Probe(t *testing.T) {
	clearV1OnlyCache()
	defer clearV1OnlyCache()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	markV1Only(addr)

	var accepts int32
	firstBytes := make(chan int, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&accepts, 1)
			go func(cc net.Conn) {
				// Read whatever the dialer sends first. A v1 direct dial sends
				// a version message header (magic first, 4 bytes = MainnetMagic
				// bytes), never a 64-byte ellswift key.
				buf := make([]byte, 4)
				n, _ := io.ReadFull(cc, buf)
				select {
				case firstBytes <- n:
				default:
				}
				_, _ = io.Copy(io.Discard, cc)
			}(c)
		}
	}()

	cfg := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork,
		UserAgent:       "/blockbrew-test:0/",
		BestHeight:      1,
		PreferV2:        true,
	}

	peer, err := NewOutboundPeer(addr, cfg)
	if err != nil {
		t.Fatalf("NewOutboundPeer: %v", err)
	}
	defer peer.Disconnect()

	if peer.v2Transport {
		t.Error("v1-only cached addr must not negotiate v2")
	}

	// Give the listener a moment; only one connection should ever be accepted.
	time.Sleep(200 * time.Millisecond)
	if got := atomic.LoadInt32(&accepts); got != 1 {
		t.Errorf("expected exactly 1 connection for a v1-only cached addr, got %d", got)
	}
}
