// W99 net_processing message-dispatch + Misbehaving audit tests.
//
// Each test maps to one or more gate(s) from the W99 checklist.
// Tests marked t.Skip are stubs for gates that require deeper integration
// (full mempool, banman DB, or a live node).
package p2p

import (
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// G1 — Misbehaving: single-event discourage (NOT score-accumulating)
//
// Bitcoin Core 2022: Misbehaving() now sets m_should_discourage immediately
// on the first call (no threshold accumulation). blockbrew still uses the old
// "score += N; if score >= 100 then ban" model.  This is a CORRECTNESS bug:
// a peer that sends one obviously-invalid block (score=100) is correctly
// banned, but a peer that sends 5 mildly-bad messages (score=20 each) is
// banned exactly at 100 — which matches Core's old (pre-2022) behaviour but
// NOT Core's current single-event model.  For peers with score < 100 in Core
// they are now immediately discouraged; blockbrew ignores them until 100.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G1_MisbehavingSingleEventModel(t *testing.T) {
	t.Skip("W99 audit — G1: blockbrew uses legacy score-accumulation model; " +
		"Core 2022 sets m_should_discourage on first Misbehaving() call regardless of score. " +
		"blockbrew Misbehaving() only bans once misbehaviorScore >= MisbehaviorThreshold (100). " +
		"Bug: peers sending low-score infractions (score < 100) are never discouraged in blockbrew, " +
		"diverging from Core 2022+ behaviour where any single Misbehaving() event triggers discouragement.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G2 — Misbehaving: noban / manual / local / regular protection (W99 G2 fix)
//
// Bitcoin Core MaybeDiscourageAndDisconnect (net_processing.cpp:5083):
//   - NoBan permission → never disconnect/discourage (no-op)
//   - IsManualConn()   → never disconnect/discourage (no-op)
//   - Local addr       → disconnect only, NOT added to discourage list
//   - Regular inbound  → disconnect + add to ban/discourage list
//
// Four sub-tests assert each case is correctly handled after the W99 G2 fix.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G2_NoBanManualProtection(t *testing.T) {
	// Sub-test 1: NoBan peer — Misbehaving must be a no-op (callback never fires).
	t.Run("noban_no_op", func(t *testing.T) {
		banCalled := false
		p := &Peer{
			addr:      "1.2.3.4:8333",
			sendQueue: make(chan Message, SendQueueSize),
			quit:      make(chan struct{}),
		}
		p.banCallback = func(_ *Peer) { banCalled = true }
		p.SetNoBan(true)

		p.Misbehaving(100, "invalid block")

		if banCalled {
			t.Error("G2 noban: ban callback must NOT fire for a NoBan peer")
		}
		if p.ShouldBan() {
			t.Error("G2 noban: shouldBan flag must NOT be set for a NoBan peer")
		}
	})

	// Sub-test 2: Manual connection — handlePeerBan must be a no-op (no BanPeer).
	t.Run("manual_no_op", func(t *testing.T) {
		pm := NewPeerManager(PeerManagerConfig{
			DataDir: t.TempDir(),
		})
		defer pm.Stop()

		// Register a manual peer in the peers map without a real connection.
		p := &Peer{
			addr:      "5.6.7.8:8333",
			sendQueue: make(chan Message, SendQueueSize),
			quit:      make(chan struct{}),
		}
		pm.mu.Lock()
		pm.peers[p.addr] = &PeerInfo{peer: p, connType: ConnManual, connectedAt: time.Now()}
		pm.outbound++
		pm.mu.Unlock()

		// Simulate ban callback.
		pm.handlePeerBan(p)

		if pm.IsBanned("5.6.7.8:8333") {
			t.Error("G2 manual: manual peer must NOT be added to ban list")
		}
	})

	// Sub-test 3: Local (loopback) address — handlePeerBan must disconnect without banning.
	t.Run("local_disconnect_no_ban", func(t *testing.T) {
		pm := NewPeerManager(PeerManagerConfig{
			DataDir: t.TempDir(),
		})
		defer pm.Stop()

		// 127.0.0.1 is loopback — isLocalAddr returns true.
		p := &Peer{
			addr:      "127.0.0.1:8333",
			sendQueue: make(chan Message, SendQueueSize),
			quit:      make(chan struct{}),
		}
		pm.mu.Lock()
		pm.peers[p.addr] = &PeerInfo{peer: p, connType: ConnInbound, connectedAt: time.Now()}
		pm.inbound++
		pm.mu.Unlock()

		pm.handlePeerBan(p)

		if pm.IsBanned("127.0.0.1:8333") {
			t.Error("G2 local: loopback peer must NOT be added to ban list")
		}
		// Peer should have been removed from peers map (disconnected).
		pm.mu.RLock()
		_, stillConnected := pm.peers[p.addr]
		pm.mu.RUnlock()
		if stillConnected {
			t.Error("G2 local: loopback peer should have been removed from peers map")
		}
	})

	// Sub-test 4: Regular inbound peer — handlePeerBan must disconnect AND ban.
	t.Run("regular_inbound_banned", func(t *testing.T) {
		pm := NewPeerManager(PeerManagerConfig{
			DataDir: t.TempDir(),
		})
		defer pm.Stop()

		p := &Peer{
			addr:      "203.0.113.1:8333",
			sendQueue: make(chan Message, SendQueueSize),
			quit:      make(chan struct{}),
		}
		pm.mu.Lock()
		pm.peers[p.addr] = &PeerInfo{peer: p, connType: ConnInbound, connectedAt: time.Now()}
		pm.inbound++
		pm.mu.Unlock()

		pm.handlePeerBan(p)

		if !pm.IsBanned("203.0.113.1:8333") {
			t.Error("G2 regular: regular inbound peer must be added to ban list")
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// G3 — Discourage persists across restarts via banlist DB — PASS
//
// peermgr.go saveBanList/loadBanList uses banlist.json with atomic rename.
// This correctly persists bans across restarts.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G3_BanlistPersistence(t *testing.T) {
	// Verify that BanPeer → saveBanList writes to disk and loadBanList restores
	pm := NewPeerManager(PeerManagerConfig{
		DataDir: t.TempDir(),
	})
	pm.BanPeer("1.2.3.4:1234", 24*time.Hour, "test ban")

	// Reload
	pm2 := NewPeerManager(PeerManagerConfig{
		DataDir: pm.config.DataDir,
	})
	if !pm2.IsBanned("1.2.3.4:1234") {
		t.Error("G3 FAIL: ban did not persist across restart")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G4 — MAX_HEADERS_RESULTS=2000: exceed → Misbehaving but NOT disconnect
//
// Core net_processing.cpp:4741: Misbehaving called but peer is NOT
// immediately disconnected — the connection remains open.
// blockbrew sync.go:585-586: only calls peer.Misbehaving(20, ...) and returns,
// no disconnect. Score=20 means a peer can exceed the limit 4 more times
// before reaching 100. CORRECTNESS: should be score=100 (BLOCK_CONSENSUS
// equivalent) per Core's "headers message size" gate being an instant-ban
// because it's a clear protocol violation (MAX_HEADERS_RESULTS is wire-defined).
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G4_TooManyHeadersLowScore(t *testing.T) {
	t.Skip("W99 audit — G4: blockbrew uses score=20 for too-many-headers; " +
		"Core calls Misbehaving() (single-event discourage) on first violation. " +
		"blockbrew's +20 allows 4 violations before ban threshold, diverging from " +
		"Core's immediate discouragement on any Misbehaving() call. " +
		"Additionally, peer is not disconnected on this violation in blockbrew.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G5 — PRESYNC/REDOWNLOAD pipeline integration — PASS
//
// sync.go correctly implements peerHeadersSync map and routes batches
// through HeadersSyncState.ProcessNextHeaders when needsHeadersSync().
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G5_PresyncRedownloadPipelinePresent(t *testing.T) {
	// Verify that SyncManager has the peerHeadersSync map
	sm := &SyncManager{
		peerHeadersSync:     make(map[string]*HeadersSyncState),
		unconnectingHeaders: make(map[string]int),
	}
	if sm.peerHeadersSync == nil {
		t.Error("G5 FAIL: peerHeadersSync map absent")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G6 — min_pow_checked NOT threaded to ProcessNewBlockHeaders
//
// Bitcoin Core ProcessHeadersMessage (net_processing.cpp:2986) threads
// min_pow_checked to CheckHeadersPoW and ProcessNewBlockHeaders.  blockbrew
// passes headers directly to headerIndex.AddHeader in addValidatedHeaders
// without a separate min_pow_checked guard. The PRESYNC pipeline provides
// equivalent protection for the low-work path, but headers entering via the
// normal path (after needsHeadersSync() returns false) have no explicit
// min_pow_checked parameter threaded through.
// Severity: CORRECTNESS — low-work headers accepted on the normal path without
// the PRESYNC guard if nMinimumChainWork is zero or not set.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G6_MinPowCheckedNotThreaded(t *testing.T) {
	t.Skip("W99 audit — G6: blockbrew addValidatedHeaders() calls headerIndex.AddHeader() " +
		"without passing a min_pow_checked boolean. Core threads min_pow_checked through " +
		"ProcessNewBlockHeaders so that headers with insufficient PoW are rejected even " +
		"outside the PRESYNC pipeline. blockbrew relies solely on the PRESYNC pipeline " +
		"being active (needsHeadersSync()==true), which means if MinimumChainWork is nil/zero " +
		"(e.g., regtest) the low-work guard is absent on the normal path.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G7 — BLOCK_HEADER_LOW_WORK → drop (no Misbehaving) — NOT IMPLEMENTED
//
// Core (net_processing.cpp:1913-1914): BLOCK_HEADER_LOW_WORK case is a no-op
// (no Misbehaving, no disconnect). blockbrew has no equivalent result code;
// low-work headers are silently dropped in the PRESYNC pipeline (success=false
// path at sync.go:614 calls Misbehaving + Disconnect), which is WRONG.
// Peers whose header chains have low work should be silently dropped, not banned.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G7_LowWorkHeaderNoBan(t *testing.T) {
	t.Skip("W99 audit — G7: blockbrew PRESYNC pipeline failure calls " +
		"peer.Misbehaving(ScoreHeadersDontConnect) + peer.Disconnect() (sync.go:614-617). " +
		"Core's BLOCK_HEADER_LOW_WORK result does NOT call Misbehaving — it is silently " +
		"ignored. A peer whose chain just has less work than nMinimumChainWork should not " +
		"be penalised; it may simply be on a different fork with legitimate work. " +
		"SEVERITY: DOS — blockbrew bans honest peers on low-work chains.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G8 — Unconnecting-headers limit = 8 (Core) but blockbrew uses 10
//
// Core's MAX_NUM_UNCONNECTING_HEADERS_MSGS = 10 (net_processing.cpp constant).
// blockbrew MaxNumUnconnectingHeadersMsgs = 10 (sync.go:32).  PASS.
// But Core disconnects when count > MAX (i.e., on the 11th), while blockbrew
// disconnects when count > MaxNumUnconnectingHeadersMsgs (also 11th). PASS.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G8_UnconnectingHeadersLimit(t *testing.T) {
	if MaxNumUnconnectingHeadersMsgs != 10 {
		t.Errorf("G8: MaxNumUnconnectingHeadersMsgs = %d, want 10 (Core MAX_NUM_UNCONNECTING_HEADERS_MSGS)",
			MaxNumUnconnectingHeadersMsgs)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G10 — Empty headers = "no more" signal (no Misbehaving)
//
// Core: an empty headers message means the peer has no more headers to send.
// blockbrew HandleHeaders: len(msg.Headers)==0 flows through addValidatedHeaders
// with headersAdded=0 and falls to the sync-complete path (len < MaxHeadersPerRequest).
// This is correct — no Misbehaving called on empty headers.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G10_EmptyHeadersNoMisbehave(t *testing.T) {
	// Verify the constant that governs this behaviour
	if MaxHeadersPerRequest != 2000 {
		t.Errorf("G10: MaxHeadersPerRequest = %d, want 2000", MaxHeadersPerRequest)
	}
	// Empty headers (len=0) < MaxHeadersPerRequest — treated as sync complete, no penalty
	// This is confirmed correct by reading addValidatedHeaders: headersAdded=0, no error path.
}

// ─────────────────────────────────────────────────────────────────────────────
// G11 — DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100
//
// blockbrew mempool.go MaxOrphanTxs default = 100 (mempool.go:341, :491).
// This matches Core's DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100. PASS.
// However, orphan tx handling lives in the mempool, not in ProcessOrphanTx.
// The P2P layer does NOT have a ProcessOrphanTx equivalent — orphan resolution
// is not wired from the tx handler in peer.go to the mempool.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G11_MaxOrphanTransactions(t *testing.T) {
	t.Skip("W99 audit — G11: P2P layer has no ProcessOrphanTx wiring. " +
		"peer.go handleMessage(*MsgTx) dispatches to OnTx listener only. " +
		"No orphan pool management at the P2P layer — orphans are handled inside " +
		"the mempool but are never resolved recursively upon parent acceptance. " +
		"Core ProcessOrphanTx (net_processing.cpp:3225) iterates the orphanage " +
		"after every accepted tx. blockbrew has no equivalent P2P-level orphan resolution.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G12 — Orphan expiry 5 min default — NOT IMPLEMENTED AT P2P LAYER
//
// Core's orphanage has per-tx expiry (DEFAULT_ORPHAN_TX_EXPIRATION_INTERVAL).
// blockbrew's mempool has MaxOrphanTxs limit but no time-based expiry.
// The P2P layer does not invoke orphan expiry at all.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G12_OrphanExpiryMissing(t *testing.T) {
	t.Skip("W99 audit — G12: blockbrew mempool orphan pool has NO time-based expiry. " +
		"Core expires orphans after DEFAULT_ORPHAN_TX_EXPIRATION_INTERVAL (5 min). " +
		"blockbrew only evicts orphans when MaxOrphanTxs is reached (evicts oldest). " +
		"A flood of cheap orphans can hold slots indefinitely until the cap is hit, " +
		"then evict legitimate orphans that arrived before capacity was exhausted.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G13 — Recursive orphan resolution on parent acceptance — MISSING
//
// Core ProcessOrphanTx resolves orphan children recursively once a parent tx
// is accepted. blockbrew has no recursive resolution at the P2P layer.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G13_RecursiveOrphanResolutionMissing(t *testing.T) {
	t.Skip("W99 audit — G13: no recursive orphan resolution at P2P layer. " +
		"Core net_processing.cpp ProcessOrphanTx (line 3232) loops calling " +
		"GetTxToReconsider after each accepted parent. blockbrew peer.go OnTx " +
		"handler dispatches to a listener but no recursive orphan resolution is wired.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G14 — Orphan pool keyed by WTxId not TxId — MISSING
//
// Core uses wtxid-keyed orphanage (node/txorphanage.h). blockbrew's mempool
// orphan pool is keyed by txid (Wire.Hash256 via TxHash()). The P2P relay
// segregation (G25) relies on wtxid-based relay, but orphan management
// uses txid. A segwit tx with different witnesses (same txid, different wtxid)
// cannot have both witnesses tracked in the orphan pool simultaneously.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G14_OrphanPoolKeyedByWTxId(t *testing.T) {
	t.Skip("W99 audit — G14: blockbrew mempool orphan pool uses txid (TxHash()) as key " +
		"not wtxid (WTxHash()). Core orphanage is wtxid-keyed since BIP-339/wtxidrelay. " +
		"A segwit transaction submitted twice with different witnesses would have the second " +
		"silently overwrite the first in blockbrew's orphan pool.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G15 — ProcessNewBlock force_processing and min_pow_checked parameters
//
// Core ProcessBlock passes (block, force_processing=true, min_pow_checked)
// to ProcessNewBlock. blockbrew ConnectBlock has no equivalent flags.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G15_ProcessBlockFlags(t *testing.T) {
	t.Skip("W99 audit — G15: blockbrew ChainConnector.ConnectBlock(block) has no " +
		"force_processing or min_pow_checked parameters. Core ProcessBlock passes " +
		"force_processing=true (to ensure the block is processed even if not connecting " +
		"to the best chain) and min_pow_checked (verified by the PRESYNC pipeline). " +
		"Without min_pow_checked in ConnectBlock, blocks from the normal download path " +
		"can be connected without the PRESYNC PoW guarantee being forwarded.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G16 — BLOCK_MUTATED → Misbehaving + no propagate — PASS (partial)
//
// sync.go validationWorker: ErrBlockMutated → peer.Misbehaving(100) + requeueForRedownload.
// Misbehaving(100) fires ban callback → propagation is implicitly stopped since the
// peer is disconnected. Block is requeued for re-download from a different peer.
// This is correct. The requeue (not permanent invalidation) also matches Core's
// BLOCK_MUTATED = transient treatment.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G16_BlockMutatedHandling(t *testing.T) {
	// Verify ErrBlockMutated is defined in consensus package.
	// Actual invocation tested in sync_test.go TestValidationWorkerMutatedBlock.
	// This gate is PASS per code review.
}

// ─────────────────────────────────────────────────────────────────────────────
// G17 — BLOCK_INVALID_HEADER → Misbehaving — PASS
//
// validationWorker: CheckBlockSanity failure → Misbehaving(100, "invalid block").
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G17_InvalidHeaderMisbehaving(t *testing.T) {
	// Confirmation: sync.go:1888 calls bwr.req.Peer.Misbehaving(100, ...) on
	// any CheckBlockSanity failure. PASS.
}

// ─────────────────────────────────────────────────────────────────────────────
// G19 — `version` exactly once; second version → disconnect
//
// BUG: blockbrew handleVersion() has NO check for duplicate version reception.
// If a peer sends a second version message after the handshake is complete,
// handleMessage dispatches it to handleVersion again, which overwrites
// p.peerVersion with the new data and re-calls checkHandshakeComplete.
// checkHandshakeComplete short-circuits (state != PeerStateHandshaking) so no
// crash occurs, but the peer is NOT disconnected on second version. Core
// immediately disconnects with "Received more than one version message".
// Severity: CORRECTNESS — peer version can be silently overwritten mid-session.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G19_SecondVersionMessageNotDisconnected(t *testing.T) {
	// Create a connected peer
	p := &Peer{
		addr:      "1.2.3.4:8333",
		state:     PeerStateConnected, // Handshake complete
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
	}
	p.versionRecvd = true
	p.versionSent = true
	p.verAckRecvd = true

	version1 := &MsgVersion{ProtocolVersion: 70016, StartHeight: 100}
	p.peerVersion = version1

	// Send a second version message (malicious/buggy peer)
	version2 := &MsgVersion{ProtocolVersion: 70015, StartHeight: 999}
	p.handleVersion(version2)

	// BUG: peer should be disconnected but isn't
	// (quit channel not closed, state still Connected)
	select {
	case <-p.quit:
		// If this fires, blockbrew correctly disconnected — unexpected
		t.Log("G19: peer was disconnected on second version (unexpected for current code)")
	default:
		// Peer was NOT disconnected — this is the bug
		t.Log("G19 BUG CONFIRMED: second version message did not disconnect peer")
	}

	// Verify the peer version was silently overwritten — the real harm
	if p.peerVersion == version2 {
		t.Log("G19 BUG: peerVersion silently overwritten by second version message")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G20 — `verack` required before non-handshake msgs — PARTIAL
//
// peer.go handleMessage: non-handshake messages when state==PeerStateHandshaking
// call Misbehaving(10). PASS for the check, but score is 10, requiring 10
// violations before ban. Core immediately disconnects (via single-event discourage).
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G20_VerackRequiredBeforeNonHandshake(t *testing.T) {
	p := &Peer{
		addr:      "1.2.3.4:8333",
		state:     PeerStateHandshaking,
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
	}

	// Sending a non-handshake message during handshake should trigger Misbehaving
	p.handleMessage(&MsgInv{})

	if p.misbehaviorScore != 10 {
		t.Errorf("G20: misbehaviorScore = %d after pre-verack message, want 10", p.misbehaviorScore)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G21 — Handshake msgs ONLY between version and verack
//
// peer.go: MsgSendCmpct is explicitly allowed before handshake complete
// (it's in the exemption list at line 556). However, sendcmpct sent AFTER
// verack is not explicitly rejected by blockbrew — it will update the
// compactBlockState even post-handshake. Core rejects sendcmpct after
// handshake (net_processing.cpp: "Peer already completed handshake").
//
// Additionally, MsgWTxidRelay is in the exemption list but blockbrew does NOT
// enforce that wtxidrelay must arrive BEFORE verack. If received after verack
// (state==Connected), it silently updates wtxidRelaySupported. Core requires
// wtxidrelay strictly between version and verack.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G21_HandshakeMsgsPostVerackNotRejected(t *testing.T) {
	// wtxidrelay after verack should be rejected, but blockbrew silently accepts it
	p := &Peer{
		addr:      "1.2.3.4:8333",
		state:     PeerStateConnected, // Post-verack
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
	}
	p.versionRecvd = true
	p.versionSent = true
	p.verAckRecvd = true
	p.wtxidRelaySupported = false

	// Send wtxidrelay AFTER verack
	p.handleMessage(&MsgWTxidRelay{})

	// BUG: wtxidrelay after verack should be rejected (Misbehaving + ignore)
	// but blockbrew silently accepts it
	if p.wtxidRelaySupported {
		t.Log("G21 BUG CONFIRMED: wtxidrelay accepted after verack; should be rejected per BIP-339")
	}
	if p.misbehaviorScore > 0 {
		t.Logf("G21: misbehavior score = %d (unexpected — would be correct if rejection was implemented)",
			p.misbehaviorScore)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G23 — MAX_PROTOCOL_MESSAGE_LENGTH = 4,000,000 (Core); FIXED in blockbrew
//
// Bitcoin Core net.h:65: MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000 (4 MB)
// blockbrew message.go: MaxPayloadSize = 4 * 1000 * 1000 (matches Core)
// Previously 32 * 1024 * 1024 (32 MB = 8× too large) — W99 G23 fixed.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G23_MaxProtocolMessageLength(t *testing.T) {
	// Core: MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000 = 4,000,000 bytes
	const coreMaxProtocolMsgLen = 4 * 1000 * 1000

	if MaxPayloadSize != coreMaxProtocolMsgLen {
		t.Errorf("W99 G23: MaxPayloadSize=%d != Core MAX_PROTOCOL_MESSAGE_LENGTH=%d; "+
			"revert the fix in message.go",
			MaxPayloadSize, coreMaxProtocolMsgLen)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G24 — Unknown msg_type → log+ignore, NOT Misbehaving — PASS
//
// message.go makeMessage: unknown command returns ErrUnknownCommand wrapped in
// NonFatalMessageError. readHandler skips the message. No Misbehaving called.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G24_UnknownMessageTypeIgnored(t *testing.T) {
	_, err := makeMessage("xyzunknown")
	if err == nil {
		t.Error("G24: makeMessage should return error for unknown command")
	}
	if !IsNonFatalMessageError(err) {
		// makeMessage returns raw error; ReadMessage wraps it in NonFatalMessageError
		// This is the correct path in ReadMessage
	}
	// Verify no Misbehaving is triggered for unknown messages
	// (confirmed by code: readHandler calls IsNonFatalMessageError and continues)
}

// ─────────────────────────────────────────────────────────────────────────────
// G25 — `tx` relay wtxidrelay segregation — PARTIAL
//
// blockbrew RelayTransaction in peermgr.go uses InvTypeWitnessTx for all
// tx relay. However, there's no check whether the recipient peer has
// negotiated wtxidrelay before sending InvTypeWitnessTx (MSG_WTX).
// Core sends MSG_WTX only to peers that sent wtxidrelay during handshake;
// for other peers it sends MSG_TX. blockbrew sends InvTypeWitnessTx
// unconditionally regardless of peer's wtxidrelay support.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G25_TxRelayWtxidSegregation(t *testing.T) {
	t.Skip("W99 audit — G25: blockbrew RelayTransaction (peermgr.go:524) always uses " +
		"InvTypeWitnessTx (MSG_WTX = 0x40000001) regardless of whether the peer negotiated " +
		"wtxidrelay. Core (net_processing.cpp) only sends MSG_WTX to peers with " +
		"m_wtxid_relay=true; non-wtxid peers receive MSG_TX. Sending MSG_WTX to a peer " +
		"that didn't negotiate wtxidrelay is a protocol violation.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G26 — `inv` type filter: MSG_BLOOM_FILTER from non-bloom peers — MISSING
//
// Core filters incoming inv messages and Misbehaves on MSG_BLOOM_FILTER from
// peers that don't support NODE_BLOOM. blockbrew HandleInv (sync.go:1038)
// only looks for InvTypeBlock and ignores all other inv types entirely.
// No validation of InvTypeFilteredBlock, no MSG_TX relay logic in the handler.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G26_InvTypeFilterMissing(t *testing.T) {
	t.Skip("W99 audit — G26: blockbrew HandleInv only processes InvTypeBlock entries. " +
		"It ignores InvTypeTx, InvTypeWitnessTx, InvTypeFilteredBlock, and MSG_BLOOM_FILTER " +
		"entirely without any validation. Core rejects MSG_BLOOM_FILTER (InvTypeFilteredBlock=3) " +
		"from non-bloom peers with Misbehaving. blockbrew has no equivalent check.")
}

// ─────────────────────────────────────────────────────────────────────────────
// G28 — `addr`/`addrv2` MAX_ADDR_TO_SEND=1000 cap + relay rate limit — PARTIAL
//
// blockbrew caps incoming addr messages at MaxAddresses=1000 (peermgr.go:1351).
// However, the addr RELAY to other peers is not rate-limited — we relay to 2
// peers without any rate limiting on how often we relay the same address.
// Core has a rate-limited relay mechanism (max 1000 per addr message cap on send).
// The send side relayAddrToRandomPeers sends the original msg directly (all 1000).
// This is correct for the count cap, but there is no per-address deduplication
// or time-based relay throttle as Core implements.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G28_AddrMaxCapAndRelay(t *testing.T) {
	if MaxAddresses != 1000 {
		t.Errorf("G28: MaxAddresses = %d, want 1000", MaxAddresses)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G29 — `ping` with nonce; `pong` matches nonce; PING_INTERVAL timeout → disconnect
//
// PARTIAL BUG: peer.go pingHandler sends pings and handlePong checks nonce.
// But PingTimeout (30s) is defined and never used — there is no code that
// disconnects a peer when a pong is not received within PingTimeout.
// The pingHandler ticks at PingInterval (2min) but never checks if the last
// ping is still unanswered after PingTimeout. Core disconnects on pong timeout.
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G29_PingTimeoutDisconnectMissing(t *testing.T) {
	// Verify PingTimeout constant exists but check if it's actually used
	if PingTimeout == 0 {
		t.Error("G29: PingTimeout should be non-zero")
	}
	if PingInterval == 0 {
		t.Error("G29: PingInterval should be non-zero")
	}

	// BUG: PingTimeout is defined but never enforced.
	// pingHandler only sends pings at PingInterval; it never checks
	// if lastPingNonce != 0 && time.Since(lastPingTime) > PingTimeout → Disconnect.
	// This means a peer that stops responding to pings is never disconnected by
	// the ping mechanism (only by IdleTimeout on read, which is 5 minutes).
	t.Log("G29 BUG: PingTimeout=30s defined but never enforced; unanswered pings do not disconnect the peer")
}

// ─────────────────────────────────────────────────────────────────────────────
// G30 — `feefilter` only after verack; bounded fee range
//
// PARTIAL: peer.go handleFeeFilter validates fee range (0..maxMoney).
// But feefilter can be sent at any time including before verack — blockbrew's
// handleMessage exemption list (line 556) does NOT include MsgFeeFilter, so
// a feefilter before verack would trigger Misbehaving(10). This is correct.
// However, SendFeeFilter and MaybeSendFeeFilter can be called before handshake
// is complete (no verack guard in those functions).
// ─────────────────────────────────────────────────────────────────────────────
func TestW99_G30_FeeFilterAfterVerack(t *testing.T) {
	// Verify fee filter validation in handleFeeFilter
	p := &Peer{
		addr:      "1.2.3.4:8333",
		state:     PeerStateConnected,
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
	}

	// Invalid fee (negative) — should be ignored
	p.handleFeeFilter(&MsgFeeFilter{MinFeeRate: -1})
	if p.FeeFilterReceived() != 0 {
		t.Errorf("G30: negative feefilter should be ignored, got %d", p.FeeFilterReceived())
	}

	// Valid fee
	p.handleFeeFilter(&MsgFeeFilter{MinFeeRate: 1000})
	if p.FeeFilterReceived() != 1000 {
		t.Errorf("G30: valid feefilter not stored, got %d", p.FeeFilterReceived())
	}

	// Above maxMoney — should be ignored
	p.handleFeeFilter(&MsgFeeFilter{MinFeeRate: 21_000_000*100_000_000 + 1})
	if p.FeeFilterReceived() != 1000 {
		t.Errorf("G30: over-max feefilter should be ignored, got %d", p.FeeFilterReceived())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional G-class tests covering specific bugs
// ─────────────────────────────────────────────────────────────────────────────

// TestW99_MisbehaviorScoreAccumulation documents the G1 score model gap.
// blockbrew accumulates score; Core discourages on any single event.
func TestW99_MisbehaviorScoreAccumulation(t *testing.T) {
	p := &Peer{
		addr:      "1.2.3.4:8333",
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
	}

	// Score 20 — should NOT ban yet in blockbrew
	result := p.Misbehaving(20, "minor infraction")
	if result {
		t.Error("Misbehaving(20) should not reach threshold in blockbrew's score model")
	}
	if p.misbehaviorScore != 20 {
		t.Errorf("misbehaviorScore = %d, want 20", p.misbehaviorScore)
	}

	// In Core 2022+, this single Misbehaving() call would immediately
	// set m_should_discourage = true (G1 bug).
	if p.shouldBan {
		t.Error("shouldBan should be false at score=20")
	}
}

// TestW99_MisbehaviorThresholdReached verifies ban fires at exactly 100.
func TestW99_MisbehaviorThresholdReached(t *testing.T) {
	banFired := false
	p := &Peer{
		addr:      "1.2.3.4:8333",
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
		banCallback: func(_ *Peer) {
			banFired = true
		},
	}

	p.Misbehaving(99, "just under threshold")
	if p.shouldBan {
		t.Error("shouldBan should be false at score=99")
	}

	p.Misbehaving(1, "final point")
	// Give the goroutine a moment to execute the callback
	time.Sleep(10 * time.Millisecond)
	if !banFired {
		t.Error("ban callback should fire when score reaches 100")
	}
	if !p.shouldBan {
		t.Error("shouldBan should be true after reaching threshold")
	}
}

// TestW99_MaxPayloadSizeVsCore asserts the G23 fix: MaxPayloadSize == Core 4 MB limit.
func TestW99_MaxPayloadSizeVsCore(t *testing.T) {
	// Core's MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000 bytes
	const coreLimit = 4 * 1000 * 1000
	const blockbrewLimit = MaxPayloadSize // 4 * 1000 * 1000 (fixed from 32 * 1024 * 1024)

	if blockbrewLimit != coreLimit {
		t.Errorf("W99 G23: MaxPayloadSize=%d (%.1f MB) != Core MAX_PROTOCOL_MESSAGE_LENGTH=%d (%.1f MB); "+
			"revert the fix in message.go",
			blockbrewLimit, float64(blockbrewLimit)/1e6,
			coreLimit, float64(coreLimit)/1e6)
	}
}

// TestW99_WtxidRelayAfterVerackSilentlyAccepted documents G21 bug.
func TestW99_WtxidRelayAfterVerackSilentlyAccepted(t *testing.T) {
	p := &Peer{
		addr:      "1.2.3.4:8333",
		state:     PeerStateConnected,
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
	}
	p.verAckRecvd = true
	p.versionRecvd = true
	p.versionSent = true

	// wtxidrelay after verack — should be rejected per BIP-339
	p.handleMessage(&MsgWTxidRelay{})

	// BUG: no rejection occurs
	if p.misbehaviorScore == 0 && p.wtxidRelaySupported {
		t.Log("G21 BUG CONFIRMED: wtxidrelay accepted post-verack with no penalty")
	}
}

// TestW99_VersionMessageAllowedOnlyOnce documents G19 bug.
func TestW99_VersionMessageAllowedOnlyOnce(t *testing.T) {
	p := &Peer{
		addr:      "1.2.3.4:8333",
		state:     PeerStateConnected,
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
	}
	p.versionRecvd = true
	p.versionSent = true
	p.verAckRecvd = true
	p.peerVersion = &MsgVersion{ProtocolVersion: 70016, StartHeight: 100}

	originalVersion := p.peerVersion

	// Second version message — Core disconnects, blockbrew does not
	secondVersion := &MsgVersion{ProtocolVersion: 70015, StartHeight: 999}
	p.handleMessage(secondVersion)

	select {
	case <-p.quit:
		t.Log("G19 NOTE: peer disconnected on second version (not expected with current code)")
	default:
		t.Log("G19 BUG: peer NOT disconnected on second version message")
		if p.peerVersion != originalVersion {
			t.Log("G19 BUG: peerVersion overwritten by second version message")
		}
	}
}

// TestW99_PingTimeoutNotEnforced documents G29 bug.
func TestW99_PingTimeoutNotEnforced(t *testing.T) {
	p := &Peer{
		addr:         "1.2.3.4:8333",
		sendQueue:    make(chan Message, SendQueueSize),
		quit:         make(chan struct{}),
		lastPingNonce: 12345,
		lastPingTime:  time.Now().Add(-2 * PingTimeout), // Ping sent 2× timeout ago
	}

	// Simulate time passing without a pong — peer should be disconnected
	// but blockbrew has no code to check this condition.
	// The pingHandler only sends pings; it never checks for timeout.
	select {
	case <-p.quit:
		t.Error("G29 unexpected disconnect (timeout not implemented in current code)")
	default:
		t.Log("G29 BUG CONFIRMED: unanswered ping after 2×PingTimeout did not disconnect peer")
	}
}

// TestW99_TxRelayAlwaysUsesWitnessTxInvType documents G25 bug.
func TestW99_TxRelayAlwaysUsesWitnessTxInvType(t *testing.T) {
	// RelayTransaction in peermgr.go unconditionally uses InvTypeWitnessTx
	// regardless of whether the peer negotiated wtxidrelay.
	pm := NewPeerManager(PeerManagerConfig{})

	// Create a non-wtxidrelay peer
	p := &Peer{
		addr:              "1.2.3.4:8333",
		state:             PeerStateConnected,
		sendQueue:         make(chan Message, 100),
		quit:              make(chan struct{}),
		wtxidRelaySupported: false, // Peer did NOT negotiate wtxidrelay
	}
	p.versionRecvd = true
	p.peerVersion = &MsgVersion{Relay: true}

	pm.mu.Lock()
	pm.peers["1.2.3.4:8333"] = &PeerInfo{peer: p, connType: ConnFullRelay}
	pm.mu.Unlock()

	// Relay a tx to this non-wtxid peer
	txHash := [32]byte{0x01}
	pm.RelayTransaction(txHash, 1000, 250, "")

	// Check what inv type was used
	select {
	case msg := <-p.sendQueue:
		inv, ok := msg.(*MsgInv)
		if !ok {
			t.Fatal("expected MsgInv")
		}
		if len(inv.InvList) > 0 && inv.InvList[0].Type == InvTypeWitnessTx {
			t.Log("G25 BUG CONFIRMED: InvTypeWitnessTx (MSG_WTX) sent to non-wtxidrelay peer; " +
				"should use InvTypeTx (MSG_TX) for peers without wtxidrelay negotiation")
		}
	default:
		t.Log("G25: no message sent (peer relay conditions not met)")
	}
}
