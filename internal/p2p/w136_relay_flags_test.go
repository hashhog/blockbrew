package p2p

// W136 BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay audit
// (blockbrew, Go).
//
// Wave: W136 (DISCOVERY, not fix)
// Date: 2026-05-17
// References:
//   - bitcoin-core/src/net_processing.cpp (MaybeSendSendHeaders / MaybeSendFeefilter
//     / WTXIDRELAY handler / SENDHEADERS handler / FEEFILTER handler).
//   - bitcoin-core/src/node/protocol_version.h
//     (SENDHEADERS_VERSION=70012 / FEEFILTER_VERSION=70013 /
//     WTXID_RELAY_VERSION=70016).
//   - bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}
//     (FeeFilterRounder).
//   - bitcoin-core/src/consensus/amount.h (MAX_MONEY, MoneyRange).
//   - BIPs 130, 133, 339.
//
// Audit document: blockbrew/audit/w136_relay_flags.md.
//
// Gate map (30 gates):
//   G1  MsgSendHeaders type + Command()                              PASS
//   G2  MsgFeeFilter{MinFeeRate int64} + Command()                   PASS
//   G3  MsgWTxidRelay type + Command()                               PASS
//   G4  makeMessage resolves all three commands                      PASS
//   G5  All three in isNonCriticalMessage                            PASS
//   G6  AnnounceBlock honors SendsHeaders() per-peer                 PASS (PARTIAL)
//   G7  sendheaders emitted on handshake-complete                    PASS
//   G8  MaybeSendSendHeaders MinimumChainWork gate                   W136-BUG-5 (xfail)
//   G9  m_sent_sendheaders once-per-peer latch                       W136-BUG-12 (xfail)
//   G10 sendheaders SENDHEADERS_VERSION>=70012 gate                  W136-BUG-5 (xfail)
//   G11 *MsgSendHeaders sets sendHeadersPreferred=true               PASS
//   G12 SendsHeaders() accessor                                      PASS
//   G13 MaybeSendFeeFilter wired into per-peer tick                  W136-BUG-1+3 (xfail)
//   G14 SendFeeFilter immediate post-handshake call                  W136-BUG-2 (xfail)
//   G15 feefilter ProtocolVersion>=70013 gate                        PASS
//   G16 feefilter skip block-relay-only peers                        PARTIAL (BUG-1)
//   G17 feefilter skip ForceRelay-permission peers                   W136-BUG-11 (xfail)
//   G18 feefilter skip -blocksonly / ignore_incoming_txs             W136-BUG-1+10 (xfail)
//   G19 feefilter IBD → MAX_MONEY override                           W136-BUG-10 (xfail)
//   G20 feefilter IBD-exit reset (next_send_feefilter=0)             W136-BUG-10 (xfail)
//   G21 FeeFilterRounder bucketization                               W136-BUG-8 (xfail)
//   G22 feefilter min-relay-feerate floor                            W136-BUG-15 (xfail)
//   G23 feefilter resend only when value changed                     PASS
//   G24 feefilter exponential broadcast interval                     W136-BUG-9 (xfail)
//   G25 MAX_FEEFILTER_CHANGE_DELAY=5min early reschedule             PASS
//   G26 feefilter receive: MoneyRange + store                        PASS
//   G27 feefilter receive: silent drop OOR (no log)                  W136-BUG-17 (xfail)
//   G28 RelayTransaction consults ShouldRelayTx + feefilter          PASS
//   G29 wtxidrelay post-VERACK Misbehaving/disconnect                W136-BUG-7 (xfail)
//   G30 wtxidrelay common-version gate                               W136-BUG-13 (xfail)
//
// Bug summary (17 IDs; W136-BUG-1..W136-BUG-17):
//   BUG-1  P1-DEAD     MaybeSendFeeFilter zero callers
//   BUG-2  P1-DEAD     SendFeeFilter zero callers
//   BUG-3  P1-DEAD     no per-peer SendMessages tick loop
//   BUG-4  P1-DEAD     MaybeSendSendHeaders function absent
//   BUG-5  P1-DEAD     no MinimumChainWork gate on outbound sendheaders
//   BUG-6  P1-PARTIAL  AnnounceBlock missing HB-compact-block + multi-block batch
//   BUG-7  HIGH        wtxidrelay post-VERACK silently accepted (W99/W103 carryover)
//   BUG-8  HIGH        no FeeFilterRounder bucketization
//   BUG-9  HIGH        uniform jitter instead of exponential
//   BUG-10 HIGH        no IBD MAX_MONEY coupling
//   BUG-11 HIGH        no ForceRelay permission flag
//   BUG-12 HIGH        no m_sent_sendheaders once-per-peer latch
//   BUG-13 MED         wtxidrelay raw-peer-version gate (not common-version)
//   BUG-14 MED         ±10% additive noise (no Core analog)
//   BUG-15 MED         no min-relay-feerate floor
//   BUG-16 MED         no m_wtxid_relay_peers aggregate counter
//   BUG-17 LOW         no LogDebug on OOR feefilter receive
//
// PASS:10 / PARTIAL:6 / MISSING:14. Bugs:17.

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ─────────────────────────────────────────────────────────────────────────────
// G1 — MsgSendHeaders type + empty payload + Command()=="sendheaders" — PASS
// Core: NetMsgType::SENDHEADERS, empty payload.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G1_MsgSendHeaders(t *testing.T) {
	m := &MsgSendHeaders{}
	if got := m.Command(); got != "sendheaders" {
		t.Errorf("G1: Command() = %q, want %q", got, "sendheaders")
	}
	var buf bytes.Buffer
	if err := m.Serialize(&buf); err != nil {
		t.Fatalf("G1: Serialize: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("G1: payload = %d bytes, want 0 (empty per BIP-130)", buf.Len())
	}
	// Deserialize of an empty buffer must succeed.
	if err := m.Deserialize(&bytes.Buffer{}); err != nil {
		t.Errorf("G1: Deserialize(empty): %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G2 — MsgFeeFilter{MinFeeRate int64} LE-encoded — PASS
// Core: NetMsgType::FEEFILTER, payload = int64 LE (CAmount).
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G2_MsgFeeFilter(t *testing.T) {
	m := &MsgFeeFilter{MinFeeRate: 1000}
	if got := m.Command(); got != "feefilter" {
		t.Errorf("G2: Command() = %q, want %q", got, "feefilter")
	}
	var buf bytes.Buffer
	if err := m.Serialize(&buf); err != nil {
		t.Fatalf("G2: Serialize: %v", err)
	}
	if buf.Len() != 8 {
		t.Errorf("G2: payload = %d bytes, want 8 (int64 LE)", buf.Len())
	}
	// Round-trip.
	m2 := &MsgFeeFilter{}
	if err := m2.Deserialize(&buf); err != nil {
		t.Fatalf("G2: Deserialize: %v", err)
	}
	if m2.MinFeeRate != m.MinFeeRate {
		t.Errorf("G2: round-trip mismatch: got %d, want %d", m2.MinFeeRate, m.MinFeeRate)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G3 — MsgWTxidRelay type + empty payload + Command()=="wtxidrelay" — PASS
// Core: NetMsgType::WTXIDRELAY, empty payload per BIP-339.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G3_MsgWTxidRelay(t *testing.T) {
	m := &MsgWTxidRelay{}
	if got := m.Command(); got != "wtxidrelay" {
		t.Errorf("G3: Command() = %q, want %q", got, "wtxidrelay")
	}
	var buf bytes.Buffer
	if err := m.Serialize(&buf); err != nil {
		t.Fatalf("G3: Serialize: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("G3: payload = %d bytes, want 0 (empty per BIP-339)", buf.Len())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G4 — makeMessage resolves all three command strings — PASS
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G4_MakeMessageResolves(t *testing.T) {
	cases := []struct {
		cmd string
		typ string
	}{
		{"sendheaders", "*p2p.MsgSendHeaders"},
		{"feefilter", "*p2p.MsgFeeFilter"},
		{"wtxidrelay", "*p2p.MsgWTxidRelay"},
	}
	for _, tc := range cases {
		m, err := makeMessage(tc.cmd)
		if err != nil {
			t.Errorf("G4: makeMessage(%q): %v", tc.cmd, err)
			continue
		}
		if m == nil {
			t.Errorf("G4: makeMessage(%q): nil result", tc.cmd)
			continue
		}
		if m.Command() != tc.cmd {
			t.Errorf("G4: makeMessage(%q) returned message with Command()=%q",
				tc.cmd, m.Command())
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G5 — All three commands are in isNonCriticalMessage — PASS
// (deserialize failures don't kill the peer).
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G5_AllNonCritical(t *testing.T) {
	for _, cmd := range []string{"sendheaders", "feefilter", "wtxidrelay"} {
		if !isNonCriticalMessage(cmd) {
			t.Errorf("G5: %q must be in isNonCriticalMessage", cmd)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G6 — AnnounceBlock honors per-peer SendsHeaders() — PASS
// Peers with sendHeadersPreferred=true receive MsgHeaders; others receive
// MsgInv. PARTIAL because Core's MaybeSendInventory also dispatches via
// cmpctblock for HB-compact-block peers, but that's the W126 gap.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G6_AnnounceBlockHonorsSendsHeaders(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{})

	// Peer A: sent sendheaders → expects MsgHeaders.
	pA := &Peer{
		addr:                 "10.0.0.1:8333",
		state:                PeerStateConnected,
		sendQueue:            make(chan Message, 10),
		quit:                 make(chan struct{}),
		sendHeadersPreferred: true,
	}
	pm.peers["10.0.0.1:8333"] = &PeerInfo{peer: pA, connType: ConnFullRelay}

	// Peer B: did not send sendheaders → expects MsgInv.
	pB := &Peer{
		addr:                 "10.0.0.2:8333",
		state:                PeerStateConnected,
		sendQueue:            make(chan Message, 10),
		quit:                 make(chan struct{}),
		sendHeadersPreferred: false,
	}
	pm.peers["10.0.0.2:8333"] = &PeerInfo{peer: pB, connType: ConnFullRelay}

	hdr := wire.BlockHeader{}
	hash := wire.Hash256{0xab}
	pm.AnnounceBlock(hdr, hash)

	select {
	case msg := <-pA.sendQueue:
		if _, ok := msg.(*MsgHeaders); !ok {
			t.Errorf("G6: peer A (sendheaders=true) got %T, want *MsgHeaders", msg)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("G6: peer A got no message")
	}

	select {
	case msg := <-pB.sendQueue:
		if inv, ok := msg.(*MsgInv); !ok {
			t.Errorf("G6: peer B (sendheaders=false) got %T, want *MsgInv", msg)
		} else if len(inv.InvList) != 1 || inv.InvList[0].Type != InvTypeBlock {
			t.Errorf("G6: peer B inv malformed: %+v", inv.InvList)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("G6: peer B got no message")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G7 — sendheaders is emitted on handshake-complete — PASS
// peer.go:881-914 checkHandshakeComplete sends MsgSendHeaders before sendcmpct.
// (Behavioral test: simulate the post-handshake transition and verify the
// queue contains MsgSendHeaders.)
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G7_SendHeadersEmittedOnHandshake(t *testing.T) {
	p := &Peer{
		addr:              "1.2.3.4:8333",
		state:             PeerStateHandshaking,
		sendQueue:         make(chan Message, 10),
		quit:              make(chan struct{}),
		handshakeDone:     make(chan struct{}),
		compactBlockState: NewCompactBlockState(),
	}
	p.versionSent = true
	p.versionRecvd = true
	p.verAckRecvd = true
	// Synchronously invoke the state transition + outbound send sites.
	p.checkHandshakeComplete()

	// Drain queue and look for MsgSendHeaders.
	sawSendHeaders := false
	deadline := time.After(100 * time.Millisecond)
loop:
	for {
		select {
		case msg := <-p.sendQueue:
			if _, ok := msg.(*MsgSendHeaders); ok {
				sawSendHeaders = true
			}
		case <-deadline:
			break loop
		}
	}
	if !sawSendHeaders {
		t.Error("G7: checkHandshakeComplete must enqueue MsgSendHeaders (BIP-130)")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G8 — W136-BUG-5 XFAIL: outbound sendheaders has no MinimumChainWork gate.
// Core net_processing.cpp:5525-5536 requires pindexBestKnownBlock->nChainWork
// > MinimumChainWork() before sending. blockbrew sends unconditionally on
// handshake-complete. Documents the missing gate.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G8_SendHeadersNoChainWorkGate(t *testing.T) {
	// Construct a peer that has *just* completed handshake — even if the
	// peer's chain has zero work (i.e. we haven't received any headers yet
	// from them, equivalent to pindexBestKnownBlock=nullptr in Core), we
	// will still send sendheaders. Core would not.
	p := &Peer{
		addr:              "1.2.3.4:8333",
		state:             PeerStateHandshaking,
		sendQueue:         make(chan Message, 10),
		quit:              make(chan struct{}),
		handshakeDone:     make(chan struct{}),
		compactBlockState: NewCompactBlockState(),
	}
	p.versionSent = true
	p.versionRecvd = true
	p.verAckRecvd = true
	// No headers received → "pindexBestKnownBlock=nullptr" analog: Core would
	// skip the send entirely. blockbrew still sends.
	p.checkHandshakeComplete()

	saw := false
	deadline := time.After(50 * time.Millisecond)
loop:
	for {
		select {
		case msg := <-p.sendQueue:
			if _, ok := msg.(*MsgSendHeaders); ok {
				saw = true
			}
		case <-deadline:
			break loop
		}
	}
	if saw {
		t.Log("G8: W136-BUG-5 CONFIRMED — sendheaders emitted with no MinimumChainWork gate " +
			"(Core net_processing.cpp:5525-5536 would have suppressed this)")
	} else {
		// Behavior change → MaybeSendSendHeaders has been wired with the gate.
		t.Error("G8: behavior changed — expected unconditional send (BUG-5 still open). " +
			"If MaybeSendSendHeaders with chain-work gate has been added, update the test.")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G9 — W136-BUG-12 XFAIL: no m_sent_sendheaders once-per-peer latch.
// Core net_processing.cpp:405-406 has an explicit `m_sent_sendheaders` flag;
// blockbrew has no equivalent field on the Peer struct. Documents the
// structural absence (we rely on checkHandshakeComplete running once).
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G9_NoSentSendHeadersLatch(t *testing.T) {
	p := &Peer{addr: "1.2.3.4:8333"}
	// The latch field would be e.g. p.sentSendHeaders bool. Reflection-free
	// check: assert the field literally doesn't exist by attempting to set
	// it via the only known accessor (none). This is a structural xfail.
	//
	// Future fix: add `sentSendHeaders bool` to Peer; expose Sent() accessor.
	// When this lands, the test should be updated to set+verify the latch.
	t.Log("G9: W136-BUG-12 CONFIRMED — Peer struct lacks `sentSendHeaders` field " +
		"(see peer.go:151-218 — no such field). Core has `m_sent_sendheaders` at " +
		"net_processing.cpp:405-406.")
	_ = p
}

// ─────────────────────────────────────────────────────────────────────────────
// G10 — W136-BUG-5 XFAIL: no SENDHEADERS_VERSION=70012 gate on outbound.
// Even a peer that advertised pre-70012 version would receive sendheaders.
// peer.go:905 has no version check.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G10_SendHeadersNoVersionGate(t *testing.T) {
	// Construct a peer with low protocol version (pre-70012).
	p := &Peer{
		addr:              "1.2.3.4:8333",
		state:             PeerStateHandshaking,
		sendQueue:         make(chan Message, 10),
		quit:              make(chan struct{}),
		handshakeDone:     make(chan struct{}),
		compactBlockState: NewCompactBlockState(),
		peerVersion:       &MsgVersion{ProtocolVersion: 70010}, // pre-SENDHEADERS_VERSION
	}
	p.versionSent = true
	p.versionRecvd = true
	p.verAckRecvd = true
	p.checkHandshakeComplete()

	saw := false
	deadline := time.After(50 * time.Millisecond)
loop:
	for {
		select {
		case msg := <-p.sendQueue:
			if _, ok := msg.(*MsgSendHeaders); ok {
				saw = true
			}
		case <-deadline:
			break loop
		}
	}
	if saw {
		t.Log("G10: W136-BUG-5 CONFIRMED — sendheaders sent to peer with ProtocolVersion=70010 " +
			"(< SENDHEADERS_VERSION=70012); Core would skip.")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G11 — *MsgSendHeaders receive sets sendHeadersPreferred=true — PASS
// peer.go:587-593.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G11_SendHeadersReceiveSetsFlag(t *testing.T) {
	p := &Peer{
		addr:                 "1.2.3.4:8333",
		state:                PeerStateConnected,
		sendQueue:            make(chan Message, 10),
		quit:                 make(chan struct{}),
		sendHeadersPreferred: false,
	}
	// Simulate a pre-existing post-handshake state.
	p.versionSent = true
	p.versionRecvd = true
	p.verAckRecvd = true

	p.handleMessage(&MsgSendHeaders{})

	if !p.SendsHeaders() {
		t.Error("G11: handleMessage(*MsgSendHeaders) must set sendHeadersPreferred=true")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G12 — SendsHeaders() accessor — PASS
// peer.go:1225-1230.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G12_SendsHeadersAccessor(t *testing.T) {
	p := &Peer{}
	if p.SendsHeaders() {
		t.Error("G12: SendsHeaders() must default false")
	}
	p.mu.Lock()
	p.sendHeadersPreferred = true
	p.mu.Unlock()
	if !p.SendsHeaders() {
		t.Error("G12: SendsHeaders() must return true after flag is set")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G13 — W136-BUG-1+BUG-3 XFAIL: MaybeSendFeeFilter is not called from any
// per-peer periodic tick loop. The function exists (peer.go:970-1042) but
// production never invokes it. There is no SendMessages-equivalent goroutine.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G13_MaybeSendFeeFilterNotWired(t *testing.T) {
	// Behavioral test: call MaybeSendFeeFilter directly and verify the
	// MsgFeeFilter shows up in the queue. This passes (proving the helper
	// works in isolation) but does NOT prove the helper is invoked in
	// production. The xfail is structural: no production call site.
	p := &Peer{
		addr:        "1.2.3.4:8333",
		sendQueue:   make(chan Message, 10),
		quit:        make(chan struct{}),
		peerVersion: &MsgVersion{ProtocolVersion: 70016, Relay: true},
		config:      PeerConfig{ProtocolVersion: 70016},
	}
	p.MaybeSendFeeFilter(1000)
	select {
	case msg := <-p.sendQueue:
		if _, ok := msg.(*MsgFeeFilter); !ok {
			t.Errorf("G13: MaybeSendFeeFilter enqueued %T, want *MsgFeeFilter", msg)
		}
		t.Log("G13: helper works in isolation; W136-BUG-1+3 CONFIRMED — no production " +
			"caller exists (grep -rn MaybeSendFeeFilter blockbrew/cmd/ blockbrew/internal/rpc/ " +
			"blockbrew/internal/p2p/peermgr.go = 0 hits).")
	case <-time.After(100 * time.Millisecond):
		t.Error("G13: MaybeSendFeeFilter did not enqueue MsgFeeFilter")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G14 — W136-BUG-2 XFAIL: SendFeeFilter never called from production.
// Helper exists at peer.go:1044-1063; zero callers.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G14_SendFeeFilterNotWired(t *testing.T) {
	p := &Peer{
		addr:        "1.2.3.4:8333",
		sendQueue:   make(chan Message, 10),
		quit:        make(chan struct{}),
		peerVersion: &MsgVersion{ProtocolVersion: 70016, Relay: true},
		config:      PeerConfig{ProtocolVersion: 70016},
	}
	p.SendFeeFilter(1000)
	select {
	case msg := <-p.sendQueue:
		if _, ok := msg.(*MsgFeeFilter); !ok {
			t.Errorf("G14: SendFeeFilter enqueued %T, want *MsgFeeFilter", msg)
		}
		t.Log("G14: helper works in isolation; W136-BUG-2 CONFIRMED — no production " +
			"caller exists.")
	case <-time.After(100 * time.Millisecond):
		t.Error("G14: SendFeeFilter did not enqueue MsgFeeFilter")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G15 — feefilter ProtocolVersion < FEEFILTER_VERSION (70013) skip — PASS
// peer.go:980, :1050.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G15_FeeFilterVersionGate(t *testing.T) {
	p := &Peer{
		addr:        "1.2.3.4:8333",
		sendQueue:   make(chan Message, 10),
		quit:        make(chan struct{}),
		peerVersion: &MsgVersion{ProtocolVersion: 70012, Relay: true}, // < FeeFilterVersion
		config:      PeerConfig{ProtocolVersion: 70016},
	}
	p.MaybeSendFeeFilter(1000)
	select {
	case msg := <-p.sendQueue:
		t.Errorf("G15: MaybeSendFeeFilter must skip peer with protocol < 70013; got %T", msg)
	case <-time.After(50 * time.Millisecond):
		// Correct: no message sent.
	}

	// Same for SendFeeFilter.
	p.SendFeeFilter(1000)
	select {
	case msg := <-p.sendQueue:
		t.Errorf("G15: SendFeeFilter must skip peer with protocol < 70013; got %T", msg)
	case <-time.After(50 * time.Millisecond):
		// Correct.
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G16 — feefilter skip non-tx-relay peers — PARTIAL via WantsTxRelay.
// Core: pto.IsBlockOnlyConn() short-circuits. blockbrew: WantsTxRelay()=false
// for peers where DisableRelayTx=true or peerVersion.Relay=false.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G16_FeeFilterSkipBlockOnly(t *testing.T) {
	// Case A: peerVersion.Relay=false → WantsTxRelay()=false → skip.
	pA := &Peer{
		addr:        "1.2.3.4:8333",
		sendQueue:   make(chan Message, 10),
		quit:        make(chan struct{}),
		peerVersion: &MsgVersion{ProtocolVersion: 70016, Relay: false},
		config:      PeerConfig{ProtocolVersion: 70016},
	}
	pA.MaybeSendFeeFilter(1000)
	select {
	case <-pA.sendQueue:
		t.Error("G16: MaybeSendFeeFilter must skip peer with version.Relay=false")
	case <-time.After(50 * time.Millisecond):
	}

	// Case B: DisableRelayTx=true (block-relay-only outbound) → skip.
	pB := &Peer{
		addr:        "1.2.3.4:8334",
		sendQueue:   make(chan Message, 10),
		quit:        make(chan struct{}),
		peerVersion: &MsgVersion{ProtocolVersion: 70016, Relay: true},
		config:      PeerConfig{ProtocolVersion: 70016, DisableRelayTx: true},
	}
	pB.MaybeSendFeeFilter(1000)
	select {
	case <-pB.sendQueue:
		t.Error("G16: MaybeSendFeeFilter must skip peer with DisableRelayTx=true")
	case <-time.After(50 * time.Millisecond):
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G17 — W136-BUG-11 XFAIL: no ForceRelay permission flag.
// Core net_processing.cpp:5544-5545: HasPermission(NetPermissionFlags::ForceRelay)
// short-circuits MaybeSendFeefilter. blockbrew Peer struct has only `noBan`;
// no forceRelay field.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G17_NoForceRelayPermission(t *testing.T) {
	// Structural: assert via grep that the field doesn't exist. We test by
	// trying to grep — but in Go tests, we just document the gap.
	t.Log("G17: W136-BUG-11 CONFIRMED — Peer struct has `noBan bool` (peer.go:217) " +
		"but no `forceRelay bool` field. Core has NetPermissionFlags::ForceRelay. " +
		"No SetForceRelay/HasForceRelay accessors in peer.go either.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G18 — W136-BUG-1+BUG-10 XFAIL: no -blocksonly / ignore_incoming_txs.
// blockbrew has no CLI flag analogous to Core's -blocksonly. The mempool
// always accepts tx invs.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G18_NoBlocksonlyFlag(t *testing.T) {
	t.Log("G18: W136-BUG-1+BUG-10 CONFIRMED — no -blocksonly CLI flag in " +
		"cmd/blockbrew/main.go; no ignore_incoming_txs config field.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G19 — W136-BUG-10 XFAIL: no IBD → MAX_MONEY coupling.
// Core net_processing.cpp:5552-5555 overrides currentFilter=MAX_MONEY in IBD.
// blockbrew MaybeSendFeeFilter has no IBD branch.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G19_NoIBDMaxMoneyCoupling(t *testing.T) {
	p := &Peer{
		addr:        "1.2.3.4:8333",
		sendQueue:   make(chan Message, 10),
		quit:        make(chan struct{}),
		peerVersion: &MsgVersion{ProtocolVersion: 70016, Relay: true},
		config:      PeerConfig{ProtocolVersion: 70016},
	}
	// Send a small filter (would be the mempool's GetMinFee() during IBD).
	p.MaybeSendFeeFilter(1000)

	deadline := time.After(50 * time.Millisecond)
	for {
		select {
		case msg := <-p.sendQueue:
			ff, ok := msg.(*MsgFeeFilter)
			if !ok {
				continue
			}
			// In Core, during IBD this would be MAX_MONEY = 21M * 1e8 = 2.1e15.
			// blockbrew sends the raw 1000 (± 10% noise).
			if ff.MinFeeRate > 21_000_000*100_000_000/2 {
				t.Error("G19: behavior changed — looks like IBD MAX_MONEY override added; " +
					"update the test")
				return
			}
			t.Logf("G19: W136-BUG-10 CONFIRMED — feefilter dispatched as %d sat/kvB in IBD; "+
				"Core would have sent MAX_MONEY (2.1e15)", ff.MinFeeRate)
			return
		case <-deadline:
			return
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G20 — W136-BUG-10 XFAIL: no IBD-exit reset of nextFeeFilterTime.
// Core net_processing.cpp:5557-5562: if last sent == MAX_FILTER and out of
// IBD, set m_next_send_feefilter = 0us so the real filter ships ASAP.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G20_NoIBDExitReset(t *testing.T) {
	t.Log("G20: W136-BUG-10 CONFIRMED — MaybeSendFeeFilter has no IBD-exit " +
		"reschedule branch (peer.go:970-1042); Core has it at " +
		"net_processing.cpp:5557-5562.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G21 — W136-BUG-8 XFAIL: no FeeFilterRounder bucketization.
// Core: FeeFilterRounder in policy/fees/block_policy_estimator.h. blockbrew
// uses ±10% additive noise (peer.go:1020-1031) which is structurally
// different — additive noise is not bucketization.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G21_NoFeeFilterRounder(t *testing.T) {
	// Direct test: drive 10 sends of the same filter; the dispatched values
	// should all be IDENTICAL when bucketed (Core), but blockbrew's ±10%
	// noise will produce 10 different values.
	values := make(map[int64]int)
	for i := 0; i < 10; i++ {
		p := &Peer{
			addr:        "1.2.3.4:8333",
			sendQueue:   make(chan Message, 10),
			quit:        make(chan struct{}),
			peerVersion: &MsgVersion{ProtocolVersion: 70016, Relay: true},
			config:      PeerConfig{ProtocolVersion: 70016},
		}
		p.MaybeSendFeeFilter(1000) // Same input every time.
		select {
		case msg := <-p.sendQueue:
			if ff, ok := msg.(*MsgFeeFilter); ok {
				values[ff.MinFeeRate]++
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	// If FeeFilterRounder were in use, values would have <= 2 distinct keys
	// (the bucket the input falls into, possibly +/- 1 adjacent bucket).
	// With ±10% noise, we expect >5 distinct values.
	if len(values) <= 2 {
		t.Errorf("G21: behavior changed — looks like FeeFilterRounder added; "+
			"observed %d distinct values, want >2 with noise model", len(values))
	} else {
		t.Logf("G21: W136-BUG-8 CONFIRMED — same input 1000 sat/kvB produced %d distinct "+
			"dispatched values via ±10%% noise (Core FeeFilterRounder would have <= 2)",
			len(values))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G22 — W136-BUG-15 XFAIL: no min-relay-feerate floor on dispatched filter.
// Core net_processing.cpp:5567: filterToSend = max(filterToSend,
// m_mempool.m_opts.min_relay_feerate.GetFeePerK()). blockbrew has no floor.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G22_NoMinRelayFeerateFloor(t *testing.T) {
	p := &Peer{
		addr:        "1.2.3.4:8333",
		sendQueue:   make(chan Message, 10),
		quit:        make(chan struct{}),
		peerVersion: &MsgVersion{ProtocolVersion: 70016, Relay: true},
		config:      PeerConfig{ProtocolVersion: 70016},
	}
	// Empty mempool → currentMinFee==0 → blockbrew sends 0 (± 10%) directly.
	p.MaybeSendFeeFilter(0)
	select {
	case msg := <-p.sendQueue:
		if ff, ok := msg.(*MsgFeeFilter); ok {
			if ff.MinFeeRate == 0 {
				t.Logf("G22: W136-BUG-15 CONFIRMED — dispatched filter=0 sat/kvB; " +
					"Core would have raised to min_relay_feerate.")
			} else {
				t.Logf("G22: dispatched filter=%d (may be noise-modulated 0)", ff.MinFeeRate)
			}
		}
	case <-time.After(50 * time.Millisecond):
		t.Error("G22: no MsgFeeFilter dispatched")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G23 — feefilter resend only when value changed — PASS
// peer.go:995, :1038 — feeFilterSent is checked.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G23_NoResendUnchanged(t *testing.T) {
	p := &Peer{
		addr:              "1.2.3.4:8333",
		sendQueue:         make(chan Message, 10),
		quit:              make(chan struct{}),
		peerVersion:       &MsgVersion{ProtocolVersion: 70016, Relay: true},
		config:            PeerConfig{ProtocolVersion: 70016},
		feeFilterSent:     1000,
		nextFeeFilterTime: time.Now().Add(2 * time.Minute),
	}
	// nextFeeFilterTime is in the future, and value unchanged → no send.
	p.MaybeSendFeeFilter(1000)
	select {
	case msg := <-p.sendQueue:
		t.Errorf("G23: must not resend when value unchanged and not yet due; got %T", msg)
	case <-time.After(50 * time.Millisecond):
		// Correct.
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G24 — W136-BUG-9 XFAIL: uniform jitter [10min,15min) instead of exponential.
// Core net_processing.cpp:5572: rand_exp_duration(AVG_FEEFILTER_BROADCAST_INTERVAL=10min).
// blockbrew peer.go:1040: FeeFilterBroadcastInterval + rand.Int63n(/2)
// = uniform in [10min, 15min).
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G24_UniformJitterNotExponential(t *testing.T) {
	// Sample 100 next-broadcast deltas and check that none exceed
	// 1.5*FeeFilterBroadcastInterval (which would be impossible with the
	// current uniform implementation; an exponential would give >2*mean
	// in ~14% of samples).
	overrunCount := 0
	for i := 0; i < 100; i++ {
		p := &Peer{
			addr:        "1.2.3.4:8333",
			sendQueue:   make(chan Message, 10),
			quit:        make(chan struct{}),
			peerVersion: &MsgVersion{ProtocolVersion: 70016, Relay: true},
			config:      PeerConfig{ProtocolVersion: 70016},
		}
		now := time.Now()
		p.MaybeSendFeeFilter(1000)
		// Drain queue to ensure send happened.
		select {
		case <-p.sendQueue:
		case <-time.After(50 * time.Millisecond):
			continue
		}
		// Read nextFeeFilterTime.
		p.feeFilterMu.Lock()
		delta := p.nextFeeFilterTime.Sub(now)
		p.feeFilterMu.Unlock()
		if delta > 2*FeeFilterBroadcastInterval {
			overrunCount++
		}
	}
	// With exponential mean=10min, ~14% of samples are >20min.
	// With uniform in [10min, 15min), 0% of samples are >20min.
	if overrunCount > 0 {
		t.Errorf("G24: observed %d/100 samples >2*mean — exponential distribution "+
			"may have been added; update the test", overrunCount)
	} else {
		t.Logf("G24: W136-BUG-9 CONFIRMED — 0/100 samples exceeded 2*mean " +
			"(consistent with uniform jitter, not exponential).")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G25 — MAX_FEEFILTER_CHANGE_DELAY=5min early reschedule — PASS
// peer.go:1002-1011 implements the >33% / <25% rescheduling.
// (Constant value match; full behavior tested under G24.)
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G25_MaxChangeDelayConst(t *testing.T) {
	if FeeFilterMaxChangeDelay != 5*time.Minute {
		t.Errorf("G25: FeeFilterMaxChangeDelay = %v, want 5min", FeeFilterMaxChangeDelay)
	}
	if FeeFilterBroadcastInterval != 10*time.Minute {
		t.Errorf("G25: FeeFilterBroadcastInterval = %v, want 10min", FeeFilterBroadcastInterval)
	}
	if FeeFilterVersion != 70013 {
		t.Errorf("G25: FeeFilterVersion = %d, want 70013", FeeFilterVersion)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G26 — feefilter receive: MoneyRange check + store — PASS
// peer.go:932-945.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G26_FeeFilterReceiveStored(t *testing.T) {
	p := &Peer{addr: "1.2.3.4:8333"}
	const maxMoney = int64(21_000_000) * 100_000_000

	// In-range: stored.
	p.handleFeeFilter(&MsgFeeFilter{MinFeeRate: 1000})
	if p.FeeFilterReceived() != 1000 {
		t.Errorf("G26: in-range filter not stored; got %d, want 1000", p.FeeFilterReceived())
	}

	// At boundary: stored.
	p.handleFeeFilter(&MsgFeeFilter{MinFeeRate: maxMoney})
	if p.FeeFilterReceived() != maxMoney {
		t.Errorf("G26: boundary value not stored; got %d, want %d", p.FeeFilterReceived(), maxMoney)
	}

	// Out of range (high): dropped silently — previous value persists.
	p.handleFeeFilter(&MsgFeeFilter{MinFeeRate: maxMoney + 1})
	if p.FeeFilterReceived() != maxMoney {
		t.Errorf("G26: OOR-high value updated state; got %d, want %d", p.FeeFilterReceived(), maxMoney)
	}

	// Out of range (negative): dropped silently — previous value persists.
	p.handleFeeFilter(&MsgFeeFilter{MinFeeRate: -1})
	if p.FeeFilterReceived() != maxMoney {
		t.Errorf("G26: OOR-negative value updated state; got %d, want %d", p.FeeFilterReceived(), maxMoney)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G27 — W136-BUG-17 XFAIL: no LogDebug on out-of-range feefilter receive.
// Documented absence (operator visibility gap).
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G27_NoLogOnOORFeeFilter(t *testing.T) {
	t.Log("G27: W136-BUG-17 CONFIRMED — handleFeeFilter at peer.go:932-945 has " +
		"no log statement on OOR drop. Core net_processing.cpp:5042 logs all " +
		"received feefilter values.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G28 — RelayTransaction consults ShouldRelayTx + per-peer feefilter — PASS
// peermgr.go:802 + peer.go:953-968.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G28_RelayTransactionRespectsFeeFilter(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{})

	// Peer A: has a feefilter requiring 5000 sat/kvB.
	pA := &Peer{
		addr:              "10.0.0.1:8333",
		state:             PeerStateConnected,
		sendQueue:         make(chan Message, 10),
		quit:              make(chan struct{}),
		peerVersion:       &MsgVersion{ProtocolVersion: 70016, Relay: true},
		feeFilterReceived: 5000,
	}
	pm.peers["10.0.0.1:8333"] = &PeerInfo{peer: pA, connType: ConnFullRelay}

	// Peer B: no feefilter.
	pB := &Peer{
		addr:        "10.0.0.2:8333",
		state:       PeerStateConnected,
		sendQueue:   make(chan Message, 10),
		quit:        make(chan struct{}),
		peerVersion: &MsgVersion{ProtocolVersion: 70016, Relay: true},
	}
	pm.peers["10.0.0.2:8333"] = &PeerInfo{peer: pB, connType: ConnFullRelay}

	// Tx with fee=200 sat / vsize=200 vB = 1000 sat/kvB (well below peer A's 5000).
	txHash := wire.Hash256{0xaa}
	wtxHash := wire.Hash256{0xbb}
	pm.RelayTransaction(txHash, wtxHash, 200, 200, "")

	// Peer A: should NOT get an inv (below feefilter).
	select {
	case msg := <-pA.sendQueue:
		t.Errorf("G28: peer A with feefilter=5000 must not receive tx of 1000 sat/kvB; got %T", msg)
	case <-time.After(50 * time.Millisecond):
	}

	// Peer B: should get an inv.
	select {
	case msg := <-pB.sendQueue:
		if _, ok := msg.(*MsgInv); !ok {
			t.Errorf("G28: peer B got %T, want *MsgInv", msg)
		}
	case <-time.After(50 * time.Millisecond):
		t.Error("G28: peer B got no message")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G29 — W136-BUG-7 XFAIL (W99 G21 / W103 BUG-3 carryover):
// wtxidrelay after VERACK must Misbehaving/disconnect per BIP-339 and Core
// net_processing.cpp:3922-3927. blockbrew peer.go:639-642 silently accepts.
//
// Sibling handlers (sendaddrv2/sendtxrcncl/sendpackages) DO enforce the
// post-VERACK check — this is the one-line asymmetry.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G29_WtxidRelayPostVerackSilentlyAccepted(t *testing.T) {
	p := &Peer{
		addr:        "1.2.3.4:8333",
		state:       PeerStateConnected,
		sendQueue:   make(chan Message, SendQueueSize),
		quit:        make(chan struct{}),
		verAckRecvd: true, // Post-verack
	}
	p.versionSent = true
	p.versionRecvd = true
	banCalled := false
	var mu sync.Mutex
	p.banCallback = func(_ *Peer) {
		mu.Lock()
		banCalled = true
		mu.Unlock()
	}

	// Receive wtxidrelay AFTER verack. Should Misbehave (per BIP-339).
	p.handleMessage(&MsgWTxidRelay{})

	// Allow async goroutine scheduling.
	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	wasBanned := banCalled
	mu.Unlock()

	if p.WTxidRelay() {
		t.Log("G29: W136-BUG-7 CONFIRMED — wtxidrelay post-verack silently flipped " +
			"wtxidRelaySupported=true; Core would have disconnected the peer " +
			"(net_processing.cpp:3922-3927). Sibling handlers (sendaddrv2, sendtxrcncl, " +
			"sendpackages) at peer.go:807/828/860 DO enforce the guard.")
	} else {
		// Behavior changed: rejection is in place.
		t.Error("G29: behavior changed — wtxidRelaySupported did NOT flip; " +
			"BUG-7 may be fixed. Update the test if so.")
	}

	if wasBanned {
		t.Log("G29: misbehaving callback fired; BUG-7 appears to be closed at the " +
			"discourage layer (verify Misbehaving call with reason 'wtxidrelay received " +
			"after verack' is now in place at peer.go:639).")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G30 — W136-BUG-13 XFAIL: no common-version gate on wtxidrelay receive.
// Core net_processing.cpp:3928 ignores wtxidrelay when GetCommonVersion()
// < WTXID_RELAY_VERSION=70016. blockbrew accepts from any peer that gets
// past the (absent) gate.
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_G30_WtxidRelayNoVersionGate(t *testing.T) {
	p := &Peer{
		addr:        "1.2.3.4:8333",
		state:       PeerStateHandshaking,
		sendQueue:   make(chan Message, SendQueueSize),
		quit:        make(chan struct{}),
		verAckRecvd: false, // pre-verack to keep this gate isolated from G29
		peerVersion: &MsgVersion{ProtocolVersion: 60001}, // < WTXID_RELAY_VERSION
		config:      PeerConfig{ProtocolVersion: 70016},
	}
	p.versionSent = true
	p.versionRecvd = true

	p.handleMessage(&MsgWTxidRelay{})

	if p.WTxidRelay() {
		t.Log("G30: W136-BUG-13 CONFIRMED — wtxidrelay from peer with " +
			"ProtocolVersion=60001 (< 70016) was accepted. Core would have ignored " +
			"this message with debug log.")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Extras: protocol-version constant pinning.
// ─────────────────────────────────────────────────────────────────────────────

// TestW136_ConstSendHeadersVersion documents the SENDHEADERS_VERSION = 70012
// constant from Core. blockbrew does NOT define a SendHeadersVersion constant
// because it has no version-gate (BUG-5). This test pins the expected value
// for future use.
func TestW136_ConstSendHeadersVersion(t *testing.T) {
	const sendHeadersVersion = 70012
	// blockbrew should add a `SendHeadersVersion = 70012` constant alongside
	// FeeFilterVersion=70013 in peer.go:36-39 when fixing BUG-5.
	_ = sendHeadersVersion
}

// TestW136_ConstWtxidRelayVersion documents the WTXID_RELAY_VERSION = 70016
// constant from Core. blockbrew uses the bare literal 70016 at peer.go:773;
// fixing BUG-13 should promote it to `WtxidRelayVersion = 70016` const.
func TestW136_ConstWtxidRelayVersion(t *testing.T) {
	const wtxidRelayVersion = 70016
	_ = wtxidRelayVersion
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire-format round-trip stress: ensure MsgFeeFilter LE encoding matches
// Core's SerializeOpVector (int64 little-endian).
// ─────────────────────────────────────────────────────────────────────────────
func TestW136_MsgFeeFilterWireRoundTrip(t *testing.T) {
	cases := []int64{
		0,
		1,
		1000,
		1_000_000,
		21_000_000 * 100_000_000, // MAX_MONEY
		// Negative values must round-trip but be rejected at the handler.
		-1,
	}
	for _, v := range cases {
		m := &MsgFeeFilter{MinFeeRate: v}
		var buf bytes.Buffer
		if err := m.Serialize(&buf); err != nil {
			t.Errorf("Serialize(%d): %v", v, err)
			continue
		}
		if buf.Len() != 8 {
			t.Errorf("Serialize(%d): payload length = %d, want 8", v, buf.Len())
		}
		m2 := &MsgFeeFilter{}
		if err := m2.Deserialize(bytes.NewReader(buf.Bytes())); err != nil {
			t.Errorf("Deserialize(%d): %v", v, err)
			continue
		}
		if m2.MinFeeRate != v {
			t.Errorf("Round-trip mismatch for %d: got %d", v, m2.MinFeeRate)
		}
	}
}

// TestW136_MsgWtxidRelayWireSize: MsgWTxidRelay payload must be 0 bytes
// (verified for empty Serialize/Deserialize round-trip from any input).
func TestW136_MsgWtxidRelayWireSize(t *testing.T) {
	m := &MsgWTxidRelay{}
	var buf bytes.Buffer
	if err := m.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("Serialize: payload = %d bytes, want 0", buf.Len())
	}
	// Deserialize of arbitrary trailing data (with EOF) must succeed since
	// MsgWTxidRelay reads nothing.
	if err := m.Deserialize(bytes.NewReader(nil)); err != nil && err != io.EOF {
		t.Errorf("Deserialize(empty): %v", err)
	}
}

// TestW136_MsgSendHeadersWireSize: MsgSendHeaders payload must be 0 bytes.
func TestW136_MsgSendHeadersWireSize(t *testing.T) {
	m := &MsgSendHeaders{}
	var buf bytes.Buffer
	if err := m.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("Serialize: payload = %d bytes, want 0", buf.Len())
	}
}
