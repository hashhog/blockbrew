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
	if negotiated {
		h.peer.packageVersions = PackageRelayVersionAncestor
	}
	return h
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
	set := map[wire.Hash256]struct{}{}
	for _, x := range w {
		set[x] = struct{}{}
	}
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.ValueOf(set))
	return true
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
		if !ok || len(g.WTxIDs) != 2 {
			t.Fatalf("RequestPkgTxns queued %#v, want getpkgtxns with 2 wtxids", m)
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
