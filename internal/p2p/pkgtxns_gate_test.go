package p2p

// BIP-331 pkgtxns receive gate.
//
// pkgtxns used to be handed to the mempool (AcceptPackage) for any handshaken
// peer: no check of -packagerelay, of the peer's sendpackages, of
// block-relay-only status, or of whether we asked for the package. Core v31
// has no pkgtxns message at all, and BIP-331 allows pkgtxns only from a peer
// that negotiated sendpackages, and only as the reply to our getpkgtxns.
// Core's ProcessMessage also drops tx messages on block-relay-only links
// (m_tx_relay == nullptr).
//
// These tests drive Peer.handleMessage with a listener wired the way
// cmd/blockbrew/main.go wires OnPkgTxns (AcceptPackage, then relay every
// newly accepted tx), against a real mempool.

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// pkgP2SHTrue is P2SH(OP_TRUE): spent by the push-only scriptSig 0x01 0x51.
func pkgP2SHTrue() []byte {
	s := []byte{0xa9, 0x14}
	s = append(s,
		0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a,
		0x56, 0x99, 0x71, 0xc7, 0x7e, 0xba, 0x30, 0xcd, 0x5a, 0x4b)
	return append(s, 0x87)
}

func pkgSpend(in wire.OutPoint, value int64) *wire.MsgTx {
	tx := &wire.MsgTx{Version: 2}
	tx.TxIn = append(tx.TxIn, &wire.TxIn{
		PreviousOutPoint: in,
		SignatureScript:  []byte{0x01, 0x51},
		Sequence:         0xffffffff,
	})
	tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: value, PkScript: pkgP2SHTrue()})
	return tx
}

type pkgUTXOs map[wire.OutPoint]*consensus.UTXOEntry

func (u pkgUTXOs) GetUTXO(op wire.OutPoint) *consensus.UTXOEntry { return u[op] }

// pkgFixture returns an empty mempool over one confirmed anyone-can-spend
// coin, and a valid parent+child package spending it.
func pkgFixture() (*mempool.Mempool, []*wire.MsgTx) {
	const funding = 1_000_000
	op := wire.OutPoint{Hash: wire.Hash256{0x5a, 0x31}, Index: 0}
	utxos := pkgUTXOs{op: {Amount: funding, PkScript: pkgP2SHTrue(), Height: 1}}
	mp := mempool.New(mempool.Config{
		MaxSize:                10_000_000,
		MinRelayFeeRate:        1000,
		MaxOrphanTxs:           100,
		ChainParams:            consensus.RegtestParams(),
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, utxos)
	mp.SetChainHeight(800_000)
	parent := pkgSpend(op, funding-5_000)
	child := pkgSpend(wire.OutPoint{Hash: parent.TxHash(), Index: 0}, funding-10_000)
	return mp, []*wire.MsgTx{parent, child}
}

type pkgHarness struct {
	peer     *Peer
	mp       *mempool.Mempool
	pkg      []*wire.MsgTx
	relayed  int
	listened int
}

// newPkgHarness builds a handshaken peer whose OnPkgTxns listener mirrors
// main.go: AcceptPackage, then relay every newly accepted tx.
func newPkgHarness(cfg PeerConfig, negotiated bool) *pkgHarness {
	h := &pkgHarness{}
	h.mp, h.pkg = pkgFixture()
	cfg.Listeners = &PeerListeners{
		OnPkgTxns: func(p *Peer, msg *MsgPkgTxns) {
			h.listened++
			res, _ := h.mp.AcceptPackage(msg.Txs)
			if res == nil {
				return
			}
			for _, r := range res.TxResults {
				if r.Accepted && !r.AlreadyInMempool {
					h.relayed++
				}
			}
		},
	}
	h.peer = &Peer{
		addr:          "10.9.8.7:18444",
		state:         PeerStateConnected,
		versionRecvd:  true,
		verAckRecvd:   true,
		sendQueue:     make(chan Message, 8),
		quit:          make(chan struct{}),
		handshakeDone: make(chan struct{}),
		peerVersion:   &MsgVersion{ProtocolVersion: 70016, Relay: true},
		config:        cfg,
	}
	h.peer.wtxidRelaySupported = true
	// White-box: our side of the handshake is marked done even with the
	// flag off, so "flag off" is the only failing condition in that subtest.
	// TestRequestPkgTxnsNeedsOurSendPackages covers the real handshake path.
	h.setFlag("sentSendPackages", true)
	if negotiated {
		h.peer.packageVersions = PackageRelayVersionAncestor
	}
	return h
}

// setFlag sets a bool field of the peer by name through reflection, so this
// file still compiles on a tree without the field (it is then a no-op).
func (h *pkgHarness) setFlag(name string, v bool) {
	f := reflect.ValueOf(h.peer).Elem().FieldByName(name)
	if !f.IsValid() || f.Kind() != reflect.Bool {
		return
	}
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().SetBool(v)
}

func (h *pkgHarness) wtxids() []wire.Hash256 {
	out := make([]wire.Hash256, len(h.pkg))
	for i, tx := range h.pkg {
		out[i] = tx.WTxHash()
	}
	return out
}

// request calls Peer.RequestPkgTxns through an interface, so this file still
// compiles on a tree that predates the method (it then reports false).
func (h *pkgHarness) request(w []wire.Hash256) bool {
	r, ok := any(h.peer).(interface {
		RequestPkgTxns([]wire.Hash256) bool
	})
	if !ok {
		return false
	}
	return r.RequestPkgTxns(w)
}

// arm marks wtxids as an outstanding getpkgtxns without going through
// RequestPkgTxns, which refuses to send on a link failing conditions 1-3.
// That lets each receive-side condition be the only reason a pkgtxns is
// dropped. Reflection keeps this file compiling on a tree without the field
// (arm then reports false).
func (h *pkgHarness) arm(w []wire.Hash256) bool {
	f := reflect.ValueOf(h.peer).Elem().FieldByName("pkgTxnsRequested")
	if !f.IsValid() {
		return false
	}
	dst := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
	switch f.Kind() {
	case reflect.Slice: // ordered request (current layout)
		dst.Set(reflect.ValueOf(append([]wire.Hash256(nil), w...)))
	case reflect.Map: // earlier layout: a set of wtxids
		set := map[wire.Hash256]struct{}{}
		for _, x := range w {
			set[x] = struct{}{}
		}
		dst.Set(reflect.ValueOf(set))
	default:
		return false
	}
	return true
}

func (h *pkgHarness) pushTxs(txs ...*wire.MsgTx) {
	h.peer.handleMessage(&MsgPkgTxns{Txs: txs})
}

func (h *pkgHarness) push() {
	h.peer.handleMessage(&MsgPkgTxns{Txs: h.pkg})
}

func (h *pkgHarness) assertIgnored(t *testing.T) {
	t.Helper()
	if n := h.mp.Count(); n != 0 {
		t.Errorf("mempool has %d txs after an unsolicited pkgtxns, want 0", n)
	}
	if h.relayed != 0 {
		t.Errorf("relayed %d txs from an unsolicited pkgtxns, want 0", h.relayed)
	}
	if h.listened != 0 {
		t.Errorf("OnPkgTxns ran %d times for an unsolicited pkgtxns, want 0", h.listened)
	}
}

// Fixture control: the package is valid, so a mempool that is still empty
// afterwards means the gate dropped it, not that AcceptPackage refused it.
func TestPkgTxnsFixtureIsValidPackage(t *testing.T) {
	mp, pkg := pkgFixture()
	if _, err := mp.AcceptPackage(pkg); err != nil {
		t.Fatalf("fixture package refused: %v", err)
	}
	if n := mp.Count(); n != 2 {
		t.Fatalf("fixture package admitted %d txs, want 2", n)
	}
}

// The item's failing case: default config, a peer that never sent
// sendpackages pushes a valid 2-tx package. It must not reach the mempool.
func TestUnsolicitedPkgTxnsIgnored(t *testing.T) {
	h := newPkgHarness(PeerConfig{ProtocolVersion: 70016}, false)
	h.push()
	h.assertIgnored(t)
}

// Each condition on its own is enough to drop the message. In the first
// three subtests the request is armed directly, so the condition under test
// is the only one that fails.
func TestPkgTxnsGateEachCondition(t *testing.T) {
	t.Run("flag off, negotiated, request outstanding", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{}, true)
		if h.request(h.wtxids()) {
			t.Error("RequestPkgTxns sent with -packagerelay off")
		}
		if !h.arm(h.wtxids()) {
			t.Fatal("cannot arm an outstanding getpkgtxns")
		}
		h.push()
		h.assertIgnored(t)
	})
	t.Run("flag on, peer did not negotiate", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, false)
		if h.request(h.wtxids()) {
			t.Error("RequestPkgTxns sent to a peer without sendpackages")
		}
		if !h.arm(h.wtxids()) {
			t.Fatal("cannot arm an outstanding getpkgtxns")
		}
		h.push()
		h.assertIgnored(t)
	})
	t.Run("flag on, peer announced only a version we do not support", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, false)
		h.peer.packageVersions = PackageRelayVersionAncestor << 1
		if h.request(h.wtxids()) {
			t.Error("RequestPkgTxns sent to a peer sharing no package-relay version")
		}
		if !h.arm(h.wtxids()) {
			t.Fatal("cannot arm an outstanding getpkgtxns")
		}
		h.push()
		h.assertIgnored(t)
	})
	t.Run("flag on, negotiated, block-relay-only", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true, DisableRelayTx: true}, true)
		if h.request(h.wtxids()) {
			t.Error("RequestPkgTxns sent on a block-relay-only link")
		}
		if !h.arm(h.wtxids()) {
			t.Fatal("cannot arm an outstanding getpkgtxns")
		}
		h.push()
		h.assertIgnored(t)
	})
	t.Run("flag on, negotiated, we never sent sendpackages", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, true)
		h.setFlag("sentSendPackages", false)
		if h.request(h.wtxids()) {
			t.Error("RequestPkgTxns sent although we never announced sendpackages")
		}
		if !h.arm(h.wtxids()) {
			t.Fatal("cannot arm an outstanding getpkgtxns")
		}
		h.push()
		h.assertIgnored(t)
	})
	t.Run("flag on, negotiated, peer did not send wtxidrelay", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, true)
		h.peer.wtxidRelaySupported = false
		if h.request(h.wtxids()) {
			t.Error("RequestPkgTxns sent to a peer without wtxidrelay")
		}
		if !h.arm(h.wtxids()) {
			t.Fatal("cannot arm an outstanding getpkgtxns")
		}
		h.push()
		h.assertIgnored(t)
	})
	t.Run("flag on, negotiated, peer set fRelay=false", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, true)
		h.peer.peerVersion.Relay = false
		if h.request(h.wtxids()) {
			t.Error("RequestPkgTxns sent to a peer with fRelay=false")
		}
		if !h.arm(h.wtxids()) {
			t.Fatal("cannot arm an outstanding getpkgtxns")
		}
		h.push()
		h.assertIgnored(t)
	})
	t.Run("flag on, negotiated, no getpkgtxns outstanding", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, true)
		h.push()
		h.assertIgnored(t)
	})
	t.Run("flag on, negotiated, requested, empty reply", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, true)
		if !h.request(h.wtxids()) {
			t.Fatal("RequestPkgTxns refused on a qualifying link")
		}
		h.peer.handleMessage(&MsgPkgTxns{})
		h.assertIgnored(t)
	})
	t.Run("flag on, negotiated, reply carries a tx we did not ask for", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, true)
		if !h.request(h.wtxids()[:1]) { // asked for the parent only
			t.Fatal("RequestPkgTxns refused on a qualifying link")
		}
		h.push()
		h.assertIgnored(t)
	})
}

// Positive control: every condition met, the solicited reply is admitted and
// relayed, and the request is consumed so a replay is ignored.
func TestSolicitedPkgTxnsAccepted(t *testing.T) {
	h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, true)
	if !h.request(h.wtxids()) {
		t.Fatal("RequestPkgTxns refused on a qualifying link")
	}
	select {
	case m := <-h.peer.sendQueue:
		g, ok := m.(*MsgGetPkgTxns)
		if !ok || len(g.WTxIDs) != 2 || g.WTxIDs[0] != h.pkg[0].WTxHash() || g.WTxIDs[1] != h.pkg[1].WTxHash() {
			t.Fatalf("RequestPkgTxns queued %#v, want getpkgtxns for parent, child", m)
		}
	default:
		t.Fatal("RequestPkgTxns queued nothing")
	}
	h.push()
	if n := h.mp.Count(); n != 2 {
		t.Fatalf("solicited pkgtxns admitted %d txs, want 2", n)
	}
	if h.relayed != 2 {
		t.Errorf("relayed %d txs, want 2", h.relayed)
	}
	h.push()
	if h.listened != 1 {
		t.Errorf("OnPkgTxns ran %d times, want 1 (a replay must not reuse the consumed request)", h.listened)
	}
}

// BIP-331: a pkgtxns answers a getpkgtxns with all the requested
// transactions, in request order. A partial or reordered reply is not that
// reply, and since a getpkgtxns gets one reply, any rejected pkgtxns
// disarms the request: the peer cannot deliver the same wtxids later.
func TestPkgTxnsReplyMustMatchRequest(t *testing.T) {
	newReq := func(t *testing.T) *pkgHarness {
		t.Helper()
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, true)
		if !h.request(h.wtxids()) {
			t.Fatal("RequestPkgTxns refused on a qualifying link")
		}
		return h
	}
	t.Run("subset reply", func(t *testing.T) {
		h := newReq(t)
		h.pushTxs(h.pkg[0]) // parent only; it is valid alone
		h.assertIgnored(t)
	})
	t.Run("reordered reply", func(t *testing.T) {
		h := newReq(t)
		h.pushTxs(h.pkg[1], h.pkg[0])
		h.assertIgnored(t)
	})
	t.Run("empty reply disarms the request", func(t *testing.T) {
		h := newReq(t)
		h.pushTxs()
		h.push() // the correct reply, too late
		h.assertIgnored(t)
	})
	t.Run("reply with an extra tx disarms the request", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, true)
		if !h.request(h.wtxids()[:1]) {
			t.Fatal("RequestPkgTxns refused on a qualifying link")
		}
		h.push()            // parent + unrequested child
		h.pushTxs(h.pkg[0]) // the correct reply, too late
		h.assertIgnored(t)
	})
	t.Run("subset reply disarms the request", func(t *testing.T) {
		h := newReq(t)
		h.pushTxs(h.pkg[0])
		h.push()
		h.assertIgnored(t)
	})
}

// RequestPkgTxns arms the request only once getpkgtxns was queued. A
// dropped send must leave no request behind, and must not wipe an earlier
// request whose getpkgtxns did go out.
func TestRequestPkgTxnsDroppedSend(t *testing.T) {
	t.Run("dropped send arms nothing", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, true)
		close(h.peer.quit) // SendMessage now reports a drop
		if h.request(h.wtxids()) {
			t.Fatal("RequestPkgTxns reported success for a dropped send")
		}
		h.push()
		h.assertIgnored(t)
	})
	t.Run("dropped send keeps the earlier request", func(t *testing.T) {
		h := newPkgHarness(PeerConfig{EnablePackageRelay: true}, true)
		if !h.request(h.wtxids()) {
			t.Fatal("RequestPkgTxns refused on a qualifying link")
		}
		for len(h.peer.sendQueue) < cap(h.peer.sendQueue) {
			h.peer.sendQueue <- &MsgVerAck{}
		}
		if h.request(h.wtxids()[:1]) {
			t.Fatal("RequestPkgTxns reported success with a full send queue")
		}
		h.push() // answers the first request, which was sent
		if n := h.mp.Count(); n != 2 {
			t.Errorf("reply to the sent request admitted %d txs, want 2 (a dropped send wiped it)", n)
		}
	})
}

// Package relay needs our own sendpackages too. handleVersion sends it only
// when the common version reaches WTxidRelayVersion, so a peer at 70015 that
// still announces sendpackages has not negotiated package relay with us.
// These drive the real handshake path instead of setting the flag directly.
func TestRequestPkgTxnsNeedsOurSendPackages(t *testing.T) {
	try := func(peerProto int32) bool {
		p := newHandshakePeerForGate(true)
		p.handleVersion(&MsgVersion{ProtocolVersion: peerProto, Relay: true, Nonce: 0xdeadbeef})
		for len(p.sendQueue) > 0 {
			<-p.sendQueue
		}
		p.packageVersions = PackageRelayVersionAncestor
		p.wtxidRelaySupported = true
		r, ok := any(p).(interface {
			RequestPkgTxns([]wire.Hash256) bool
		})
		return ok && r.RequestPkgTxns([]wire.Hash256{{0x01}})
	}
	if !try(70016) {
		t.Error("RequestPkgTxns refused after we sent sendpackages in the handshake")
	}
	if try(70015) {
		t.Error("RequestPkgTxns sent although we never sent sendpackages (common version 70015)")
	}
}
