package p2p

// W116 — BIP-331 sendpackages after-verack penalty test (BUG-8 fix verification).
//
// The fix: handleSendPackages (peer.go) now calls Misbehaving(10, ...) when
// sendpackages is received after verack, matching the sendaddrv2 / sendtxrcncl
// pattern already present in peer.go.

import "testing"

// TestW116_G29_SendPackages_AfterVerack_Misbehaving verifies that a peer sending
// sendpackages after verack receives Misbehaving(10) per BIP-331 §sendpackages:
// "MUST only be sent prior to the receipt of verack."
//
// Mirrors the sendaddrv2 check (peer.go:817-820) and sendtxrcncl check
// (peer.go:838-841).
func TestW116_G29_SendPackages_AfterVerack_Misbehaving(t *testing.T) {
	p := &Peer{
		addr:      "1.2.3.4:8333",
		state:     PeerStateConnected,
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
	}
	p.versionRecvd = true
	p.versionSent = true
	p.verAckRecvd = true // handshake done

	msg := &MsgSendPackages{Versions: PackageRelayVersionAncestor}
	p.handleSendPackages(msg)

	if p.misbehaviorScore != 10 {
		t.Errorf("misbehaviorScore = %d after post-verack sendpackages, want 10 (BIP-331 violation)", p.misbehaviorScore)
	}
	// packageVersions must NOT be updated when the message is rejected
	if p.packageVersions != 0 {
		t.Errorf("packageVersions = %d after rejected sendpackages, want 0", p.packageVersions)
	}
}

// TestW116_G29_SendPackages_BeforeVerack_Accepted verifies that sendpackages
// received before verack is accepted normally (not penalised).
func TestW116_G29_SendPackages_BeforeVerack_Accepted(t *testing.T) {
	p := &Peer{
		addr:      "1.2.3.4:8333",
		state:     PeerStateHandshaking,
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
	}
	p.versionRecvd = true
	p.versionSent = true
	p.verAckRecvd = false // handshake NOT yet done

	msg := &MsgSendPackages{Versions: PackageRelayVersionAncestor}
	p.handleSendPackages(msg)

	if p.misbehaviorScore != 0 {
		t.Errorf("misbehaviorScore = %d after pre-verack sendpackages, want 0", p.misbehaviorScore)
	}
	if p.packageVersions != PackageRelayVersionAncestor {
		t.Errorf("packageVersions = %d after valid sendpackages, want %d", p.packageVersions, PackageRelayVersionAncestor)
	}
}
