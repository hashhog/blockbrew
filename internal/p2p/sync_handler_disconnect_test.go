package p2p

import (
	"testing"
	"time"
)

// Shutdown leftover (2026-10-02): a message handler runs on the peer's read
// goroutine, and that goroutine is in p.wg. Peer.Disconnect joins p.wg, so a
// handler that disconnects its own peer waits out disconnectJoinTimeout (5s)
// for itself. The compact-filter handlers are installed on the sync manager's
// peer listeners (CreatePeerListeners, wired in cmd/blockbrew). The oversize
// inv/getdata path disconnects from readHandler directly, which is the same
// goroutine every sync-manager handler runs on.
//
// Both must signal and return immediately. A handler that merely returns
// without closing quit would also pass the timing check, so each test asserts
// the peer was actually told to stop.

func TestSyncListenerCFilterDisconnectDoesNotSelfJoin(t *testing.T) {
	p := &Peer{
		addr:      "203.0.113.50:8333",
		sendQueue: make(chan Message, 4),
		quit:      make(chan struct{}),
	}
	elapsed := make(chan time.Duration, 1)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t0 := time.Now()
		// Unsupported filter type: PrepareBlockFilterRequest disconnects
		// before it touches the header index.
		HandleGetCFilters(p, &MsgGetCFilters{FilterType: 0xff}, nil, nil)
		elapsed <- time.Since(t0)
	}()

	select {
	case d := <-elapsed:
		if d > time.Second {
			t.Fatalf("cfilter handler waited %s to disconnect its own peer; "+
				"joining Disconnect from the read goroutine burns %s on itself",
				d, disconnectJoinTimeout)
		}
	case <-time.After(disconnectJoinTimeout + 3*time.Second):
		t.Fatal("cfilter handler did not return")
	}
	select {
	case <-p.quit:
	default:
		t.Fatal("cfilter handler returned without closing quit")
	}
}

// oneErrTransport returns one error, then blocks. Enough to drive readHandler
// into the oversize-inv disconnect without a real socket.
type oneErrTransport struct {
	err  error
	n    int
	hold chan struct{}
}

func (t *oneErrTransport) ReadMessage() (Message, error) {
	t.n++
	if t.n == 1 {
		return nil, t.err
	}
	<-t.hold
	return nil, ErrPeerDisconnected
}

func (t *oneErrTransport) WriteMessage(Message) error       { return nil }
func (t *oneErrTransport) IsEncrypted() bool                { return false }
func (t *oneErrTransport) SessionID() []byte                { return nil }
func (t *oneErrTransport) Close() error                     { return nil }
func (t *oneErrTransport) SetReadDeadline(time.Time) error  { return nil }
func (t *oneErrTransport) SetWriteDeadline(time.Time) error { return nil }

func TestReadHandlerOversizeDisconnectDoesNotSelfJoin(t *testing.T) {
	hold := make(chan struct{})
	defer close(hold)
	p := &Peer{
		addr:      "203.0.113.51:8333",
		sendQueue: make(chan Message, 4),
		quit:      make(chan struct{}),
		transport: &oneErrTransport{
			err:  &NonFatalMessageError{Command: "inv", Err: ErrTooManyInvVects},
			hold: hold,
		},
	}
	elapsed := make(chan time.Duration, 1)
	p.wg.Add(1)
	go func() {
		t0 := time.Now()
		p.readHandler()
		elapsed <- time.Since(t0)
	}()

	select {
	case d := <-elapsed:
		if d > time.Second {
			t.Fatalf("readHandler waited %s to disconnect on an oversize inv; "+
				"that goroutine is in p.wg, so joining Disconnect waits %s for itself",
				d, disconnectJoinTimeout)
		}
	case <-time.After(disconnectJoinTimeout + 3*time.Second):
		t.Fatal("readHandler did not return")
	}
	select {
	case <-p.quit:
	default:
		t.Fatal("readHandler returned without closing quit")
	}
}

// The joining form itself must not burn the timeout when the caller is a
// peer handler. Call sites above use DisconnectAsync; this pins the backstop
// for a handler that still calls Disconnect.
func TestOwnedGoroutineDisconnectSkipsJoin(t *testing.T) {
	p := &Peer{
		addr:      "203.0.113.52:8333",
		sendQueue: make(chan Message, 1),
		quit:      make(chan struct{}),
	}
	elapsed := make(chan time.Duration, 1)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.enterPeerGoroutine()
		defer p.leavePeerGoroutine()
		t0 := time.Now()
		p.Disconnect()
		elapsed <- time.Since(t0)
	}()

	select {
	case d := <-elapsed:
		if d > time.Second {
			t.Fatalf("Disconnect from a peer goroutine waited %s; it must not join itself", d)
		}
	case <-time.After(disconnectJoinTimeout + 3*time.Second):
		t.Fatal("Disconnect from a peer goroutine did not return")
	}
	select {
	case <-p.quit:
	default:
		t.Fatal("Disconnect from a peer goroutine did not close quit")
	}
}
