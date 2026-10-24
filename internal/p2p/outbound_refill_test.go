package p2p

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// refillRig is a PeerManager whose dialer hands out in-memory peers, so the
// outbound refill can be driven pass by pass without a network.
type refillRig struct {
	pm *PeerManager

	mu        sync.Mutex
	started   int // dial attempts
	full      int // attempts configured as full-relay
	blockOnly int // attempts configured as block-relay-only
	inflight  int32
	servers   sync.WaitGroup
	conns     []net.Conn
}

// newRefillRig seeds the address book with n addresses, one per /16, of which
// failPct percent refuse the connection. latency delays every dial.
func newRefillRig(t *testing.T, n, failPct int, latency time.Duration) *refillRig {
	t.Helper()
	r := &refillRig{pm: NewPeerManager(PeerManagerConfig{Network: MainnetMagic})}
	r.pm.dialFn = func(addr string, cfg PeerConfig) (*Peer, error) {
		atomic.AddInt32(&r.inflight, 1)
		defer atomic.AddInt32(&r.inflight, -1)
		r.mu.Lock()
		r.started++
		if cfg.DisableRelayTx {
			r.blockOnly++
		} else {
			r.full++
		}
		r.mu.Unlock()
		time.Sleep(latency)
		var o1, o2 int
		fmt.Sscanf(addr, "%d.%d.", &o1, &o2)
		if o2%100 < failPct {
			return nil, fmt.Errorf("dial %s: connection refused", addr)
		}
		client, server := net.Pipe()
		r.mu.Lock()
		r.conns = append(r.conns, client, server)
		r.mu.Unlock()
		r.servers.Add(1)
		go func() {
			defer r.servers.Done()
			_ = mockServerHandshake(server, MainnetMagic)
		}()
		cfg.Network = MainnetMagic
		return &Peer{
			config:            cfg,
			conn:              client,
			transport:         NewV1Transport(client, cfg.Network),
			addr:              addr,
			state:             PeerStateConnecting,
			sendQueue:         make(chan Message, SendQueueSize),
			quit:              make(chan struct{}),
			localNonce:        uint64(len(addr)) + 1,
			handshakeDone:     make(chan struct{}),
			startTime:         time.Now(),
			lastRecv:          time.Now(),
			lastSend:          time.Now(),
			compactBlockState: NewCompactBlockState(),
		}, nil
	}
	for i := 0; i < n; i++ {
		r.pm.addrBook.AddAddress(NetAddress{
			Services: ServiceNodeNetwork | ServiceNodeWitness,
			IP:       net.IPv4(byte(11+i/200), byte(i%200), 1, 1),
			Port:     8333,
		}, "test")
	}
	t.Cleanup(func() {
		r.mu.Lock()
		for _, c := range r.conns {
			c.Close()
		}
		r.mu.Unlock()
		for _, info := range r.pm.peers {
			info.peer.Disconnect()
		}
	})
	return r
}

func (r *refillRig) counts() (full, blockOnly int) {
	r.pm.mu.RLock()
	defer r.pm.mu.RUnlock()
	return r.pm.outbound, r.pm.blockRelayOnly
}

func (r *refillRig) attempts() (full, blockOnly int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.full, r.blockOnly
}

// settle waits for every launched dial to finish.
func (r *refillRig) settle(t *testing.T) {
	t.Helper()
	time.Sleep(20 * time.Millisecond)
	waitUntil(t, 20*time.Second, func() bool { return atomic.LoadInt32(&r.inflight) == 0 })
	time.Sleep(50 * time.Millisecond)
}

// One refill pass with every slot empty must go after every empty slot, not
// one slot per type: with 8+2 empty slots and a 30 s pass interval, one dial
// per pass is minutes of recovery after a burst of disconnects.
func TestOutboundRefillPassFillsAllEmptySlots(t *testing.T) {
	r := newRefillRig(t, 60, 0, 0)
	r.pm.openConnectionsTick()
	r.settle(t)
	full, block := r.counts()
	if full != DefaultMaxOutbound || block != DefaultMaxBlockRelayOnly {
		af, ab := r.attempts()
		t.Fatalf("after one pass: full-relay=%d block-relay-only=%d, want %d and %d (dial attempts %d/%d)",
			full, block, DefaultMaxOutbound, DefaultMaxBlockRelayOnly, af, ab)
	}
}

// With most of the address book unreachable, the slots must still fill in a
// handful of passes. Before: 1 dial per type per pass at 30% success needs
// ~27 passes for 8 slots.
func TestOutboundRefillConvergesWithUnreachableAddresses(t *testing.T) {
	r := newRefillRig(t, 120, 70, 0)
	const maxPasses = 12
	passes := 0
	for ; passes < maxPasses; passes++ {
		full, block := r.counts()
		if full >= DefaultMaxOutbound && block >= DefaultMaxBlockRelayOnly {
			break
		}
		r.pm.openConnectionsTick()
		r.settle(t)
	}
	full, block := r.counts()
	if full != DefaultMaxOutbound || block != DefaultMaxBlockRelayOnly {
		t.Fatalf("after %d passes: full-relay=%d block-relay-only=%d, want %d and %d",
			passes, full, block, DefaultMaxOutbound, DefaultMaxBlockRelayOnly)
	}
}

// Passes that run while earlier dials are still in flight must count those
// dials against the target, or slow dials stack up beyond the slot count.
func TestOutboundRefillCountsDialsInFlight(t *testing.T) {
	r := newRefillRig(t, 60, 0, 300*time.Millisecond)
	for i := 0; i < 10; i++ {
		r.pm.openConnectionsTick()
		time.Sleep(10 * time.Millisecond)
	}
	r.settle(t)
	af, ab := r.attempts()
	if af > DefaultMaxOutbound || ab > DefaultMaxBlockRelayOnly {
		t.Fatalf("10 passes with slow dials started %d full-relay and %d block-relay-only dials; "+
			"want at most %d and %d", af, ab, DefaultMaxOutbound, DefaultMaxBlockRelayOnly)
	}
	full, block := r.counts()
	if full != DefaultMaxOutbound || block != DefaultMaxBlockRelayOnly {
		t.Fatalf("full-relay=%d block-relay-only=%d, want %d and %d",
			full, block, DefaultMaxOutbound, DefaultMaxBlockRelayOnly)
	}
}
