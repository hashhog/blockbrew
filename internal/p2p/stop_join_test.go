package p2p

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// Gate 5 (testnet4 real-peer repro, 2026-10-02): PeerManager.Stop called
// Disconnect() on one peer at a time, each with a 5 s join backstop. Peers
// whose read goroutine was still inside a slow handler (a block-store write
// queued behind an fsync) each cost the full 5 s: "Disconnect() timed out
// after 5s" repeated and P2P stop took 7-20 s of a 30 s shutdown budget.
// Stop must signal every peer and join them TOGETHER under one deadline.
func TestStopJoinsStuckPeersUnderOneDeadline(t *testing.T) {
	old := peerStopJoinTimeout
	peerStopJoinTimeout = 1 * time.Second
	defer func() { peerStopJoinTimeout = old }()

	pm := NewPeerManager(PeerManagerConfig{MaxOutbound: 8})
	release := make(chan struct{})
	defer close(release)

	const n = 4
	var peers []*Peer
	for i := 0; i < n; i++ {
		a, b := net.Pipe()
		defer b.Close()
		p := &Peer{
			conn:      a,
			addr:      fmt.Sprintf("10.0.0.%d:8333", i+1),
			state:     PeerStateConnected,
			sendQueue: make(chan Message, SendQueueSize),
			quit:      make(chan struct{}),
			transport: NewV1Transport(a, MainnetMagic),
		}
		// A read goroutine stuck in a handler that does not watch quit or
		// the socket.
		p.wg.Add(1)
		go func() { defer p.wg.Done(); <-release }()
		pm.InsertConnectedPeer(p)
		peers = append(peers, p)
	}

	t0 := time.Now()
	pm.Stop()
	took := time.Since(t0)
	// Serial joins: n x disconnectJoinTimeout (5 s) = 20 s.
	if took > 3*time.Second {
		t.Fatalf("Stop took %s with %d stuck peers; want one shared deadline (~%s), not %d x %s",
			took, n, peerStopJoinTimeout, n, disconnectJoinTimeout)
	}
	for _, p := range peers {
		select {
		case <-p.quit:
		default:
			t.Fatalf("peer %s was not signalled to disconnect", p.addr)
		}
	}
}

func TestWaitGroupWithin(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	if waitGroupWithin(&wg, 50*time.Millisecond) {
		t.Fatal("reported a pending WaitGroup as done")
	}
	wg.Done()
	if !waitGroupWithin(&wg, time.Second) {
		t.Fatal("reported a finished WaitGroup as pending")
	}
}
