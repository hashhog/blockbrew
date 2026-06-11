package p2p

import (
	"testing"
	"time"
)

// Package-relay SEND default-off gate.
//
// Bitcoin Core v31.99 has no package-relay wire protocol (BIP-331 is still an
// open/draft proposal that has NOT been merged to Core's wire). A default
// `grep -rn "sendpackages|package_relay" bitcoin-core/src/` outside test/fuzz
// is EMPTY, so a default Core node never emits a "sendpackages" message.
//
// blockbrew previously sent MsgSendPackages UNCONDITIONALLY to every peer
// advertising protocol >= 70016 during the version handshake (peer.go
// handleVersion). These tests pin the honest-wire behavior: with the gate OFF
// (PeerConfig.EnablePackageRelay == false, the default) a default node must NOT
// emit sendpackages; with the gate ON it must. The Core-parity wtxidrelay /
// sendaddrv2 messages must be emitted regardless.
//
// The RECEIVE side (handleSendPackages, the pre-handshake allow-list, the
// packageVersions bitfield, OnGetPkgTxns/OnSendPackages listeners) is NOT
// gated and is exercised by w116_sendpackages_test.go / msg_packages_test.go.

// newHandshakePeerForGate builds a minimal outbound peer in the handshaking
// state, primed so that handleVersion runs the feature-negotiation send block
// (protocol >= 70016) without trying to send our own version (versionSent set)
// and without completing the handshake (verAckRecvd false → checkHandshake
// returns early). The buffered sendQueue captures every emitted message.
func newHandshakePeerForGate(enablePackageRelay bool) *Peer {
	p := &Peer{
		addr:              "1.2.3.4:8333",
		state:             PeerStateHandshaking,
		sendQueue:         make(chan Message, 32),
		quit:              make(chan struct{}),
		handshakeDone:     make(chan struct{}),
		compactBlockState: NewCompactBlockState(),
		inbound:           false,
		config: PeerConfig{
			ProtocolVersion:    70016,
			EnablePackageRelay: enablePackageRelay,
		},
	}
	// Outbound + versionSent => handleVersion skips sendVersionMessage().
	p.versionSent = true
	return p
}

// drainHandshakeSends drives handleVersion with a modern peer version and
// reports which negotiation messages were emitted.
func drainHandshakeSends(p *Peer) (sawSendPackages, sawWTxidRelay, sawSendAddrv2 bool) {
	p.handleVersion(&MsgVersion{ProtocolVersion: 70016, Nonce: 0xdeadbeef})

	deadline := time.After(100 * time.Millisecond)
loop:
	for {
		select {
		case msg := <-p.sendQueue:
			switch msg.(type) {
			case *MsgSendPackages:
				sawSendPackages = true
			case *MsgWTxidRelay:
				sawWTxidRelay = true
			case *MsgSendAddrv2:
				sawSendAddrv2 = true
			}
		case <-deadline:
			break loop
		}
	}
	return
}

// Default (no env, EnablePackageRelay false) => NO sendpackages emitted, but
// the Core-parity wtxidrelay + sendaddrv2 still are.
func TestPackageRelayGate_DefaultOff_NoSend(t *testing.T) {
	p := newHandshakePeerForGate(false)
	sawSendPackages, sawWTxidRelay, sawSendAddrv2 := drainHandshakeSends(p)

	if sawSendPackages {
		t.Error("default node (EnablePackageRelay=false) must NOT emit sendpackages " +
			"(Bitcoin Core v31.99 has no package-relay wire protocol)")
	}
	if !sawWTxidRelay {
		t.Error("wtxidrelay (Core-parity) must still be emitted with package relay off")
	}
	if !sawSendAddrv2 {
		t.Error("sendaddrv2 (Core-parity) must still be emitted with package relay off")
	}
}

// Opt-in (EnablePackageRelay true, set via -packagerelay / BLOCKBREW_PACKAGE_RELAY=1)
// => sendpackages IS emitted, so the BIP-331 extension still works when enabled.
func TestPackageRelayGate_FlagOn_Sends(t *testing.T) {
	p := newHandshakePeerForGate(true)
	sawSendPackages, sawWTxidRelay, sawSendAddrv2 := drainHandshakeSends(p)

	if !sawSendPackages {
		t.Error("with EnablePackageRelay=true the node must emit sendpackages " +
			"(BIP-331 opt-in extension)")
	}
	if !sawWTxidRelay {
		t.Error("wtxidrelay (Core-parity) must be emitted with package relay on")
	}
	if !sawSendAddrv2 {
		t.Error("sendaddrv2 (Core-parity) must be emitted with package relay on")
	}
}
