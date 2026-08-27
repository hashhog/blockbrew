package p2p

import "testing"

// TestSendMessageReportsDrop pins #73/#74: SendMessage used to drop
// SILENTLY when the send queue was full ("could log this"). A dropped
// getdata left its block request InFlight against a request that never
// went on the wire — blockbrew's chronic 30s+ tip stalls (964241, 964255:
// every peer "failed to deliver" blocks they were never asked for).
// The contract now: true = queued, false = dropped, and requestBlocks
// reverts dropped batches to Pending immediately.
func TestSendMessageReportsDrop(t *testing.T) {
	p := &Peer{
		sendQueue: make(chan Message, 2),
		quit:      make(chan struct{}),
	}

	if !p.SendMessage(&MsgPing{Nonce: 1}) {
		t.Fatal("send into an empty queue must report queued (true)")
	}
	if !p.SendMessage(&MsgPing{Nonce: 2}) {
		t.Fatal("second send within capacity must report queued (true)")
	}
	// Queue now full.
	if p.SendMessage(&MsgPing{Nonce: 3}) {
		t.Fatal("send into a FULL queue must report dropped (false) — the silent drop was the 964255 wedge")
	}

	// Quitting peer: also a drop.
	close(p.quit)
	q := &Peer{sendQueue: make(chan Message, 2), quit: p.quit}
	if q.SendMessage(&MsgPing{Nonce: 4}) {
		t.Fatal("send to a quitting peer must report dropped (false)")
	}
}
