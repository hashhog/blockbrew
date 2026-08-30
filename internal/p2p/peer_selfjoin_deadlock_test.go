// Peer.Disconnect() must never be joined from a goroutine it is waiting for.
//
// THE DEFECT (pinned here)
// ------------------------
// `Disconnect()` was `signalDisconnect(); wg.Wait()`, and `p.wg` joins the
// peer's own readHandler / writeHandler / pingHandler. Every SyncManager
// message handler runs ON the readHandler goroutine, so a handler that
// disconnected its peer waited for itself and never returned — while holding
// the SyncManager mutex.
//
// Observed live on mainnet 2026-08-30. A peer sent a bad-PoW header for
// height 964713 at 05:45:55; the misbehaviour path called Disconnect() from
// inside addValidatedHeaders. From the goroutine dump taken 3h22m later
// (staged-patches/blockbrew-selfjoin-deadlock-2026-08-30/):
//
//	goroutine 881692 [sync.WaitGroup.Wait, 207 minutes]:
//	  p2p.(*Peer).Disconnect
//	  p2p.(*SyncManager).addValidatedHeaders
//	  p2p.(*SyncManager).HandleHeaders
//	  p2p.(*Peer).handleMessage
//	  p2p.(*Peer).readHandler        <-- the goroutine being waited for
//
// with 20 more goroutines on sync.Mutex.Lock and 2 on RWMutex.RLock behind
// it. The node stayed "up" — RPC answering, systemd active, NRestarts=0 — with
// zero peers, no log output, 21 blocks behind, permanently.
//
// WHAT MAKES THIS A PIN AND NOT A HANG
// ------------------------------------
// The pre-fix code does not fail these tests, it BLOCKS in them. Each one runs
// the call under test in its own goroutine and fails on a timeout, so at the
// parent commit the suite REPORTS A FAILURE instead of hanging until the
// go-test deadline kills the whole binary with no attribution.
package p2p

import (
	"sync"
	"testing"
	"time"
)

// selfJoinPeer returns a peer with one goroutine registered in its WaitGroup
// that never exits — standing in for a readHandler that is itself the caller.
func selfJoinPeer(t *testing.T) (*Peer, func()) {
	t.Helper()
	p := &Peer{
		addr:      "203.0.113.9:8333",
		sendQueue: make(chan Message, 4),
		quit:      make(chan struct{}),
	}
	release := make(chan struct{})
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		<-release // never returns until the test lets it
	}()
	return p, func() { close(release) }
}

// DisconnectAsync is what a message handler must call: it signals and returns,
// with no join at all, so a handler running inside p.wg cannot block itself.
func TestDisconnectAsyncDoesNotJoinItsOwnGoroutines(t *testing.T) {
	p, release := selfJoinPeer(t)
	defer release()

	done := make(chan struct{})
	go func() {
		p.DisconnectAsync()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("DisconnectAsync blocked — it must never wait on p.wg " +
			"(this is the mainnet wedge of 2026-08-30)")
	}

	// It must still have SIGNALLED: quit closed is what makes the peer's own
	// goroutines unwind. A no-op that returns fast would pass the timing
	// assertion above and leave the peer running forever.
	select {
	case <-p.quit:
	default:
		t.Fatal("DisconnectAsync returned without closing quit — the peer was " +
			"never actually told to stop")
	}
}

// The backstop: even the joining form must not block forever, so a call site
// that gets this wrong degrades into a bounded stall instead of a silent,
// permanent wedge.
func TestDisconnectJoinIsBounded(t *testing.T) {
	p, release := selfJoinPeer(t)
	defer release()

	done := make(chan struct{})
	go func() {
		p.Disconnect()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(disconnectJoinTimeout + 3*time.Second):
		t.Fatalf("Disconnect() never returned with a goroutine still in p.wg; "+
			"the join must be bounded by %s", disconnectJoinTimeout)
	}
}

// CONTROL: with nothing registered in the WaitGroup, Disconnect still joins
// promptly and still signals. Without this, a Disconnect() that had been
// gutted into a no-op would satisfy both assertions above.
func TestControlDisconnectStillJoinsAndSignalsWhenNothingIsRunning(t *testing.T) {
	p := &Peer{
		addr:      "203.0.113.10:8333",
		sendQueue: make(chan Message, 4),
		quit:      make(chan struct{}),
	}
	var exited sync.WaitGroup
	exited.Add(1)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer exited.Done()
		<-p.quit // a well-behaved peer goroutine: exits on the signal
	}()

	start := time.Now()
	p.Disconnect()
	elapsed := time.Since(start)

	if elapsed >= disconnectJoinTimeout {
		t.Fatalf("Disconnect() took %s — it should have joined immediately once "+
			"the goroutine observed quit, not run out the timeout", elapsed)
	}
	select {
	case <-p.quit:
	default:
		t.Fatal("Disconnect() did not close quit")
	}
	exited.Wait() // the goroutine really did unwind, not just get abandoned
}
