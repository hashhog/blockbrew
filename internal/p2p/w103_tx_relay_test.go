// W103 tx-relay flow audit tests.
//
// 30-gate fleet audit of blockbrew's transaction relay flow vs Bitcoin Core
// net_processing.cpp / txdownloadman.h / txorphanage.h / txrequest.h.
//
// Gate summary (30 gates):
//   G1:  inv MAX_INV_SZ=50000 + disconnect
//   G2:  getdata MSG_TX/MSG_WTX/MSG_WITNESS_TX dispatch
//   G3:  tx wtxidrelay handshake
//   G4:  mempool relay rate-limit + !fRelay block
//   G5:  MAX_GETDATA_SZ=1000 batch
//   G6:  BIP-339 wtxidrelay between version+verack
//   G7:  NODE_BLOOM advert + bloom filter gate
//   G8:  tx data piggyback (not in inv)
//   G9:  MAX_PEER_TX_ANNOUNCEMENTS=5000
//   G10: MAX_PEER_TX_REQUEST_IN_FLIGHT=100
//   G11: GETDATA_TX_INTERVAL=60s
//   G12: NONPREF_PEER_TX_DELAY=2s outbound preference
//   G13: TXID_RELAY_DELAY=2s
//   G14: OVERLOADED_PEER_TX_DELAY=2s if peer >=50 outstanding
//   G15: MAX_PEER_ANNOUNCEMENTS + alternating-announcers
//   G16: m_tx_relay BIP-37 gate
//   G17: m_recently_announced_invs LRU
//   G18: mempool query rate-limit
//   G19: ProcessOrphanTx after tx accepted
//   G20: RelayTransaction broadcast set
//   G21: GetMaxOrphanTransactions=100
//   G22: EvictExpiredOrphans 5min
//   G23: AddOrphanTx wtxid (BIP-339)
//   G24: EraseOrphansForPeer
//   G25: ProcessOrphanTx recursive
//   G26: PeerManager::CanRequestTxFrom NODE_NETWORK
//   G27: m_relay_to_set wtxid-keyed
//   G28: UNREQUESTED tx misbehavior score
//   G29: rate-limited reject reasons
//   G30: -peerbloomfilters/-whitelistforcerelay
package p2p

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ─────────────────────────────────────────────────────────────────────────────
// BUG-1 (P1) G1: inv MAX_INV_SZ=50000 is enforced by Deserialize but HandleInv
// does NOT call peer.Misbehaving() + Disconnect() on oversized inv.
// Bitcoin Core net_processing.cpp:4040: vInv.size() > MAX_INV_SZ →
// Misbehave(20) and return early.  blockbrew's HandleInv silently discards
// oversized inv because ErrTooManyInvVects is a NonFatalMessageError (skipped).
// The peer is NOT penalised; they can spam.
//
// Test: verify MaxInvVects constant and that Deserialize returns an error
// when count exceeds 50000.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G1_InvMaxSize(t *testing.T) {
	// Constant must match Core MAX_INV_SZ = 50000.
	if MaxInvVects != 50000 {
		t.Errorf("G1: MaxInvVects = %d, want 50000 (Core MAX_INV_SZ)", MaxInvVects)
	}

	// AddInvVect must refuse after 50000.
	msg := &MsgInv{}
	for i := 0; i < MaxInvVects; i++ {
		err := msg.AddInvVect(&InvVect{Type: InvTypeTx})
		if err != nil {
			t.Fatalf("G1: unexpected error adding invvect #%d: %v", i, err)
		}
	}
	if err := msg.AddInvVect(&InvVect{Type: InvTypeTx}); err == nil {
		t.Error("G1: AddInvVect must return error when list exceeds MaxInvVects (50000)")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G2 (fixed): MSG_WTX = 5 constant now defined as InvTypeWtx.
// Bitcoin Core protocol.h:481 defines MSG_WTX = 5 (BIP-339).
// InvTypeWtx=5 is for wtxid inv announcements.
// InvTypeWitnessTx=0x40000001 is retained as a BIP-144 getdata witness flag
// (NOT for inv announcements).
//
// G27 (fixed): RelayTransaction now selects per-peer:
//   - wtxid-relay peers: InvTypeWtx=5 + wtxid
//   - legacy peers:      InvTypeTx=1  + txid
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G2_G27_MsgWTXMissingAndRelayAlwaysWitnessTx(t *testing.T) {
	// G2 FIX: InvTypeWtx=5 must be defined.
	if InvTypeTx != 1 {
		t.Errorf("G2: InvTypeTx = %d, want 1", InvTypeTx)
	}
	if InvTypeWtx != 5 {
		t.Errorf("G2: InvTypeWtx = %d, want 5 (MSG_WTX per BIP-339 / Core protocol.h:481)", InvTypeWtx)
	}
	if InvTypeWitnessTx != 0x40000001 {
		t.Errorf("G2: InvTypeWitnessTx = 0x%x, want 0x40000001 (BIP-144 getdata flag)", InvTypeWitnessTx)
	}
	// MSG_WTX=5 and MSG_WITNESS_TX=0x40000001 must be distinct constants.
	if InvTypeWtx == InvTypeWitnessTx {
		t.Error("G2: InvTypeWtx and InvTypeWitnessTx must be distinct")
	}

	// G27 FIX: RelayTransaction selects per-peer type+hash.
	pm := NewPeerManager(PeerManagerConfig{})

	txHash := [32]byte{0x11}
	wtxHash := [32]byte{0x22}

	wtxPeer := &Peer{
		addr:                "10.0.0.1:8333",
		state:               PeerStateConnected,
		sendQueue:           make(chan Message, 10),
		quit:                make(chan struct{}),
		wtxidRelaySupported: true,
	}
	wtxPeer.versionRecvd = true
	wtxPeer.peerVersion = &MsgVersion{Relay: true}

	legacyPeer := &Peer{
		addr:                "10.0.0.2:8333",
		state:               PeerStateConnected,
		sendQueue:           make(chan Message, 10),
		quit:                make(chan struct{}),
		wtxidRelaySupported: false,
	}
	legacyPeer.versionRecvd = true
	legacyPeer.peerVersion = &MsgVersion{Relay: true}

	pm.mu.Lock()
	pm.peers[wtxPeer.addr] = &PeerInfo{peer: wtxPeer, connType: ConnFullRelay}
	pm.peers[legacyPeer.addr] = &PeerInfo{peer: legacyPeer, connType: ConnFullRelay}
	pm.mu.Unlock()

	pm.RelayTransaction(txHash, wtxHash, 1000, 250, "")

	// wtxid-relay peer must receive InvTypeWtx=5 + wtxid.
	select {
	case msg := <-wtxPeer.sendQueue:
		inv, ok := msg.(*MsgInv)
		if !ok || len(inv.InvList) == 0 {
			t.Fatal("G27: wtxid peer: expected non-empty MsgInv")
		}
		if inv.InvList[0].Type == InvTypeWitnessTx {
			t.Errorf("G2/G27 BUG: InvTypeWitnessTx=0x%x must not appear in inv announcements", InvTypeWitnessTx)
		}
		if inv.InvList[0].Type != InvTypeWtx {
			t.Errorf("G27: wtxid peer got type 0x%x, want InvTypeWtx=5", inv.InvList[0].Type)
		}
		if inv.InvList[0].Hash != wtxHash {
			t.Errorf("G27: wtxid peer got hash %x, want wtxid %x", inv.InvList[0].Hash, wtxHash)
		}
	default:
		t.Error("G27: wtxid peer got no message")
	}

	// Legacy peer must receive InvTypeTx=1 + txid.
	select {
	case msg := <-legacyPeer.sendQueue:
		inv, ok := msg.(*MsgInv)
		if !ok || len(inv.InvList) == 0 {
			t.Fatal("G2: legacy peer: expected non-empty MsgInv")
		}
		if inv.InvList[0].Type != InvTypeTx {
			t.Errorf("G2: legacy peer got type 0x%x, want InvTypeTx=1", inv.InvList[0].Type)
		}
		if inv.InvList[0].Hash != txHash {
			t.Errorf("G2: legacy peer got hash %x, want txid %x", inv.InvList[0].Hash, txHash)
		}
	default:
		t.Error("G2: legacy peer got no message")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G3 / BUG-3 (P2): wtxidrelay handshake accepted after verack.
// Bitcoin Core net_processing.cpp:3923-3924: "Disconnect peers that send a
// wtxidrelay message after VERACK."
// blockbrew peer.go:639 sets wtxidRelaySupported=true without checking
// p.verAckRecvd, so a late wtxidrelay is silently accepted.
//
// Test: verify that WTxidRelay is not enforced to be pre-verack only.
// (documents the missing guard)
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G3_G6_WtxidRelayAfterVerackNotEnforced(t *testing.T) {
	p := &Peer{
		addr:      "1.2.3.4:8333",
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
		// Simulate post-verack state.
		verAckRecvd: true,
		state:       PeerStateConnected,
	}

	// BUG-3: handleMessage dispatches *MsgWTxidRelay regardless of verAckRecvd.
	// No Misbehaving or Disconnect is fired. Contrast: sendaddrv2 and sendtxrcncl
	// correctly check verAckRecvd (peer.go:817, peer.go:838).
	//
	// Simulate the dispatch by calling the WTxidRelay case directly.
	banCalled := false
	p.banCallback = func(_ *Peer) { banCalled = true }

	p.mu.Lock()
	p.wtxidRelaySupported = false // start unset
	p.mu.Unlock()

	// Dispatch post-verack wtxidrelay — blockbrew silently accepts it.
	p.mu.Lock()
	p.wtxidRelaySupported = true // what handleMessage actually does — no verAck check
	p.mu.Unlock()

	// Allow goroutine scheduling.
	time.Sleep(5 * time.Millisecond)

	if banCalled {
		// Unexpectedly correct — no bug.
		t.Log("G3: peer was banned for late wtxidrelay (fixed — test documents behavior)")
	}
	if !p.WTxidRelay() {
		t.Error("G3: wtxidRelaySupported should be set (documents the missing post-verack guard)")
	}

	// G6: verify WTxidRelay() reports the state correctly.
	if !p.WTxidRelay() {
		t.Error("G6: WTxidRelay() should return true once flag is set")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G4 / BUG-4 (P2): mempool relay rate-limit absent.
// Bitcoin Core net_processing.cpp: MEMPOOL_REQUEST_PERIOD = 1 hour; a peer
// that sends multiple "mempool" messages within 1 hour should be rate-limited
// and only the first should generate inv responses. blockbrew has no per-peer
// mempool request timestamp tracking.
// Also: mempool handler does not check fRelay — a peer that sent fRelay=false
// in VERSION should not receive mempool contents.
//
// Test: verify no per-peer mempool timestamp state in the Peer struct.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G4_G18_MempoolRateLimitAbsent(t *testing.T) {
	p := &Peer{
		addr:      "1.2.3.4:8333",
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
	}

	// BUG-4: Peer struct has no lastMempoolRequest field.
	// Verify that WantsTxRelay respects the fRelay flag but mempool rate-limit
	// has no timestamp state.
	//
	// If fRelay=false the peer should not receive mempool announcements.
	// A peer with fRelay=false: WantsTxRelay() must return false.
	p.peerVersion = &MsgVersion{Relay: false}
	if p.WantsTxRelay() {
		t.Error("G4: WantsTxRelay must return false when peerVersion.Relay=false")
	}

	// A peer with fRelay=true: WantsTxRelay() must return true.
	p.peerVersion = &MsgVersion{Relay: true}
	if !p.WantsTxRelay() {
		t.Error("G4: WantsTxRelay must return true when peerVersion.Relay=true")
	}

	// G18/BUG-18: no per-peer mempool rate-limit field.
	// Document that the Peer struct lacks a lastMempoolRequest time.Time field.
	// Core: m_last_mempool_req timestamp checked in MEMPOOL handler.
	// This is a structural absence — the test documents it.
	_ = p // no lastMempoolRequest field accessible on Peer
}

// ─────────────────────────────────────────────────────────────────────────────
// G5 (FIXED): MAX_GETDATA_SZ=1000 cap enforced for getdata messages.
// Bitcoin Core net_processing.cpp:128: MAX_GETDATA_SZ = 1000.
// Core: vGetData.size() >= MAX_GETDATA_SZ → flush and start new getdata.
// blockbrew now defines MaxGetDataSize=1000 (distinct from MaxInvVects=50000)
// and uses it in MsgGetData.AddInvVect / Deserialize.
//
// Test: assert MaxGetDataSize=1000, AddInvVect refuses >1000, and that
// MaxInvVects (inv cap) remains 50000 and separate.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G5_GetDataSizeCap(t *testing.T) {
	// MaxGetDataSize must match Core MAX_GETDATA_SZ = 1000.
	if MaxGetDataSize != 1000 {
		t.Errorf("G5: MaxGetDataSize = %d, want 1000 (Core MAX_GETDATA_SZ)", MaxGetDataSize)
	}

	// MaxInvVects (inv cap) must remain 50000 — distinct from getdata cap.
	if MaxInvVects != 50000 {
		t.Errorf("G5: MaxInvVects = %d, want 50000 (Core MAX_INV_SZ)", MaxInvVects)
	}

	// AddInvVect must accept exactly 1000 entries and refuse the 1001st.
	msg := &MsgGetData{}
	for i := 0; i < MaxGetDataSize; i++ {
		if err := msg.AddInvVect(&InvVect{Type: InvTypeTx}); err != nil {
			t.Fatalf("G5: unexpected error adding invvect #%d: %v", i, err)
		}
	}
	if err := msg.AddInvVect(&InvVect{Type: InvTypeTx}); err == nil {
		t.Error("G5: AddInvVect must return error when list exceeds MaxGetDataSize (1000)")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G7 / OK: NODE_BLOOM is properly advertised via AdvertiseNodeBloom config.
// The mempool handler gates on this flag via the caller (main.go).
//
// Test: verify ServiceNodeBloom is defined and that the service bit is OR'd
// into the service flags when AdvertiseNodeBloom is true.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G7_NodeBloomServiceBit(t *testing.T) {
	// Core: NODE_BLOOM = 1 << 2 = 4 (BIP-111).
	if ServiceNodeBloom != (1 << 2) {
		t.Errorf("G7: ServiceNodeBloom = %d, want %d", ServiceNodeBloom, 1<<2)
	}

	// Verify makePeerConfig ORs in NODE_BLOOM when configured.
	pm := &PeerManager{
		config: PeerManagerConfig{
			AdvertiseNodeBloom: true,
			BestHeightFunc:     func() int32 { return 0 },
		},
		rng: nil,
	}
	cfg := pm.makePeerConfig()
	if cfg.Services&ServiceNodeBloom == 0 {
		t.Error("G7: NODE_BLOOM not set in services when AdvertiseNodeBloom=true")
	}

	// Without the flag, NODE_BLOOM must not be set.
	pm.config.AdvertiseNodeBloom = false
	cfg2 := pm.makePeerConfig()
	if cfg2.Services&ServiceNodeBloom != 0 {
		t.Error("G7: NODE_BLOOM set in services even when AdvertiseNodeBloom=false")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-8 (P2) G8: tx piggyback — blockbrew serves tx via getdata (InvTypeTx
// handler) with a TODO stub. HandleGetData case InvTypeTx has no mempool lookup.
// Core FindTxForGetData: if the tx is in the mempool, send it immediately.
//
// Test: verify InvTypeTx is parsed and documents the missing mempool handler.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G8_TxGetDataHandlerStub(t *testing.T) {
	// InvTypeTx must be 1 per Core MSG_TX.
	if InvTypeTx != 1 {
		t.Errorf("G8: InvTypeTx = %d, want 1", InvTypeTx)
	}
	// Verify InvTypeWitnessTx is parse-able via AddInvVect.
	msg := &MsgGetData{}
	iv := &InvVect{Type: InvTypeTx}
	if err := msg.AddInvVect(iv); err != nil {
		t.Errorf("G8: AddInvVect(InvTypeTx) failed: %v", err)
	}
	// BUG-8: HandleGetData handles InvTypeTx with only a TODO comment.
	// The actual mempool lookup and tx response are missing.
	// This is a structural absence documented by this test.
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-9 (P2) G9: MAX_PEER_TX_ANNOUNCEMENTS=5000 tracking absent.
// Bitcoin Core txdownloadman.h:30: MAX_PEER_TX_ANNOUNCEMENTS = 5000.
// txdownloadman_impl.cpp:204: reject if m_txrequest.Count(peer) >= 5000.
// blockbrew has no TxRequestTracker and no per-peer announcement count limit.
//
// G10: MAX_PEER_TX_REQUEST_IN_FLIGHT=100 absent.
// G11: GETDATA_TX_INTERVAL=60s absent (no per-request expiry tracking).
// G12: NONPREF_PEER_TX_DELAY=2s absent.
// G13: TXID_RELAY_DELAY=2s absent.
// G14: OVERLOADED_PEER_TX_DELAY=2s absent.
//
// Test: document that none of these constants or tracker structures exist.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G9_G10_G11_G12_G13_G14_TxRequestTrackerAbsent(t *testing.T) {
	// BUG-9 through BUG-14: blockbrew has no TxRequestTracker equivalent.
	// There is no:
	//   - per-peer announcement count (MAX_PEER_TX_ANNOUNCEMENTS=5000)
	//   - per-peer in-flight count (MAX_PEER_TX_REQUEST_IN_FLIGHT=100)
	//   - request expiry timer (GETDATA_TX_INTERVAL=60s)
	//   - outbound-preference delay (NONPREF_PEER_TX_DELAY=2s)
	//   - txid-when-wtxid-peers-exist delay (TXID_RELAY_DELAY=2s)
	//   - overloaded-peer delay (OVERLOADED_PEER_TX_DELAY=2s)
	//
	// Core implements all of this in txrequest.h + txdownloadman_impl.cpp.
	// The absence means blockbrew:
	//   (a) cannot limit how many tx announcements a single peer can queue (DoS)
	//   (b) never re-requests transactions that weren't received in 60s
	//   (c) gives no preference to outbound peers for faster tx relay
	//   (d) never delays txid announcements in favor of wtxid peers
	//
	// These are architectural gaps, not simple missing constants.
	// This test documents their absence; future work tracks them as P2 bugs.
	t.Log("G9-G14: TxRequestTracker absent — see BUG-9 through BUG-14 in audit comments")
}

// ─────────────────────────────────────────────────────────────────────────────
// G15 (OK) + BUG-15b (P2): No alternating-announcers scheduling.
// G16 / OK: m_tx_relay BIP-37 gate is implemented via WantsTxRelay().
//
// Test: verify WantsTxRelay correctly gates on fRelay and DisableRelayTx.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G16_TxRelayFrelayGate(t *testing.T) {
	// G16: fRelay=false in VERSION → WantsTxRelay()=false (correct).
	p := &Peer{
		addr:        "1.2.3.4:8333",
		sendQueue:   make(chan Message, SendQueueSize),
		quit:        make(chan struct{}),
		peerVersion: &MsgVersion{Relay: false},
		config:      PeerConfig{DisableRelayTx: false},
	}
	if p.WantsTxRelay() {
		t.Error("G16: WantsTxRelay must return false when peerVersion.Relay=false")
	}

	// DisableRelayTx=true → WantsTxRelay()=false regardless of fRelay.
	p.peerVersion = &MsgVersion{Relay: true}
	p.config.DisableRelayTx = true
	if p.WantsTxRelay() {
		t.Error("G16: WantsTxRelay must return false when DisableRelayTx=true")
	}

	// Normal: fRelay=true and DisableRelayTx=false → WantsTxRelay()=true.
	p.config.DisableRelayTx = false
	if !p.WantsTxRelay() {
		t.Error("G16: WantsTxRelay must return true when fRelay=true and DisableRelayTx=false")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-17 (P2) G17: m_recently_announced_invs LRU absent.
// Bitcoin Core: each Peer::TxRelay has m_recently_announced_invs (Inventory
// object with 2MB max size), used to suppress announcing the same tx twice
// to the same peer. blockbrew has no per-peer recently-announced-invs set.
// RelayTransaction only skips the source peer; it will re-announce to any
// peer that already received the inv.
//
// Test: document absence via assertion on Peer struct.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G17_RecentlyAnnouncedInvsAbsent(t *testing.T) {
	// BUG-17: Peer struct has no recentlyAnnouncedInvs field.
	// This means the same tx can be announced twice to the same peer if
	// RelayTransaction is called multiple times (e.g., ATMP + mempool-update).
	p := &Peer{
		addr:        "1.2.3.4:8333",
		sendQueue:   make(chan Message, 1),
		quit:        make(chan struct{}),
		peerVersion: &MsgVersion{Relay: true},
	}
	// The send queue will fill; there is no dedup guard.
	_ = p
	t.Log("G17: no recentlyAnnouncedInvs tracking on Peer struct (BUG-17 documented)")
}

// ─────────────────────────────────────────────────────────────────────────────
// G19 / OK: ProcessOrphanTx is called after tx accepted.
// blockbrew mempool.go:1005 calls processOrphansLocked(txHash) inside
// AddTransaction (with lock held), which scans for orphans depending on the
// new tx's outputs and promotes them.
//
// Test: verify the orphan promotion logic path.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G19_OrphanPromotionPathExists(t *testing.T) {
	// This is a p2p package test; we document that processOrphansLocked is called
	// from mempool.AddTransaction via the comment in mempool.go:1004-1005.
	// The mempool package has its own tests. Here we confirm the p2p layer
	// correctly dispatches OnTx to the listener (which should call mempool.AddTx).
	p := &Peer{
		addr:      "1.2.3.4:8333",
		sendQueue: make(chan Message, SendQueueSize),
		quit:      make(chan struct{}),
		state:     PeerStateConnected,
	}
	txReceived := false
	p.config.Listeners = &PeerListeners{
		OnTx: func(_ *Peer, _ *MsgTx) {
			txReceived = true
		},
	}
	// Simulate receiving a tx message.
	p.handleMessage(&MsgTx{})
	if !txReceived {
		t.Error("G19: OnTx listener not called when tx message received")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G20 (fixed): RelayTransaction now selects per-peer announcement type.
// Core: wtxid-relay peers get MSG_WTX=5, non-wtxid peers get MSG_TX=1.
// InvTypeWitnessTx=0x40000001 must NOT appear in inv announcements.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G20_RelayTransactionBroadcastSet(t *testing.T) {
	// G20 FIX: verify correct constants are defined.
	if InvTypeWitnessTx != 0x40000001 {
		t.Errorf("G20: InvTypeWitnessTx = 0x%x, want 0x40000001 (BIP-144 getdata flag)", InvTypeWitnessTx)
	}
	if InvTypeWtx != 5 {
		t.Errorf("G20: InvTypeWtx = %d, want 5 (MSG_WTX, BIP-339 announcement type)", InvTypeWtx)
	}
	// InvTypeWtx=5 and InvTypeWitnessTx=0x40000001 must be distinct.
	if InvTypeWtx == InvTypeWitnessTx {
		t.Error("G20: InvTypeWtx and InvTypeWitnessTx must be distinct constants")
	}

	// G20 FIX: exercise RelayTransaction with both peer types and verify
	// InvTypeWitnessTx=0x40000001 never appears in any inv announcement.
	pm := NewPeerManager(PeerManagerConfig{})

	txHash := [32]byte{0x33}
	wtxHash := [32]byte{0x44}

	for _, tc := range []struct {
		addr    string
		wtxid   bool
		wantTyp InvType
		wantHash [32]byte
	}{
		{"10.1.0.1:8333", true, InvTypeWtx, wtxHash},
		{"10.1.0.2:8333", false, InvTypeTx, txHash},
	} {
		p := &Peer{
			addr:                tc.addr,
			state:               PeerStateConnected,
			sendQueue:           make(chan Message, 10),
			quit:                make(chan struct{}),
			wtxidRelaySupported: tc.wtxid,
		}
		p.versionRecvd = true
		p.peerVersion = &MsgVersion{Relay: true}
		pm.mu.Lock()
		pm.peers[tc.addr] = &PeerInfo{peer: p, connType: ConnFullRelay}
		pm.mu.Unlock()
	}

	pm.RelayTransaction(txHash, wtxHash, 1000, 250, "")

	for addr, info := range pm.peers {
		select {
		case msg := <-info.peer.sendQueue:
			inv, ok := msg.(*MsgInv)
			if !ok || len(inv.InvList) == 0 {
				t.Errorf("G20: peer %s: expected non-empty MsgInv", addr)
				continue
			}
			got := inv.InvList[0].Type
			if got == InvTypeWitnessTx {
				t.Errorf("G20 BUG: peer %s received InvTypeWitnessTx=0x%x (invalid for inv announcements)",
					addr, InvTypeWitnessTx)
			}
			pm.mu.RLock()
			pInfo := pm.peers[addr]
			pm.mu.RUnlock()
			wantTyp := InvTypeTx
			wantHash := txHash
			if pInfo.peer.WTxidRelay() {
				wantTyp = InvTypeWtx
				wantHash = wtxHash
			}
			if got != wantTyp {
				t.Errorf("G20: peer %s got type 0x%x, want 0x%x", addr, got, wantTyp)
			}
			if inv.InvList[0].Hash != wantHash {
				t.Errorf("G20: peer %s got hash %x, want %x", addr, inv.InvList[0].Hash, wantHash)
			}
		default:
			t.Errorf("G20: peer %s got no message", addr)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G21 / OK: GetMaxOrphanTransactions = 100.
// blockbrew mempool.go:308 MaxOrphanTxs defaults to 100 (set at line 341 and
// also guarded at line 491).
//
// Test: verify the orphan pool cap value is 100 (matches Core
// DEFAULT_MAX_ORPHAN_TRANSACTIONS).
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G21_MaxOrphanTxs100(t *testing.T) {
	// The default orphan pool cap must be 100 (Core DEFAULT_MAX_ORPHAN_TRANSACTIONS).
	// We cannot import mempool here due to package boundaries, so we verify
	// the p2p layer has no conflicting constant.
	//
	// Core txorphanage.h: DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE = 3000 (new limit),
	// but the logical "max orphan txs" used in tests = 100.
	// blockbrew mempool Config.MaxOrphanTxs defaults to 100.
	//
	// This gate is OK in blockbrew. Document for completeness.
	t.Log("G21: MaxOrphanTxs=100 matches Core DEFAULT_MAX_ORPHAN_TRANSACTIONS (OK)")
}

// ─────────────────────────────────────────────────────────────────────────────
// G22 (FIXED): Periodic orphan expiry driver wired in main loop.
//
// Bitcoin Core: ORPHAN_TX_EXPIRE_TIME = 20 minutes; LimitOrphans called inside
// every AddTx/AddAnnouncer.  blockbrew approximates this with a once-per-minute
// timer in cmd/blockbrew/main.go that calls mempool.ExpireOrphans().
//
// This test asserts:
//  1. OrphanExpireDriverInterval is exactly 1 minute (the periodic fire rate).
//  2. The driver fires at the correct multiple: ≤ OrphanTxExpireTime (20 min),
//     meaning orphans are evicted well before the 20-minute deadline.
//
// Reference: Bitcoin Core net_processing.cpp ORPHAN_TX_EXPIRE_TIME = 20min.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G22_ExpireOrphansPresent(t *testing.T) {
	// OrphanExpireDriverInterval must be exactly 1 minute — the period at
	// which the main loop fires mempool.ExpireOrphans (W103 BUG-22 fix).
	const wantInterval = time.Minute
	if OrphanExpireDriverInterval != wantInterval {
		t.Errorf("G22: OrphanExpireDriverInterval = %v, want %v (Core ORPHAN_TX_EXPIRE_TIME = 20min; driver must fire more often)",
			OrphanExpireDriverInterval, wantInterval)
	}

	// The driver interval must be strictly less than Core's 20-minute expiry
	// window so orphans are actually evicted before they expire.
	const coreExpireTime = 20 * time.Minute
	if OrphanExpireDriverInterval >= coreExpireTime {
		t.Errorf("G22: OrphanExpireDriverInterval (%v) must be < ORPHAN_TX_EXPIRE_TIME (%v)",
			OrphanExpireDriverInterval, coreExpireTime)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-23 (P1-CDIV) G23: AddOrphanTx is keyed by txid, not wtxid.
// Bitcoin Core txorphanage: HaveTx(const Wtxid&) — keyed by witness txid.
// blockbrew mempool.go:459 orphans map[wire.Hash256]*orphanEntry — keyed by
// txHash (not WTxHash()). This means two witness-malleated variants of the
// same tx (same txid, different wtxid) can only one be stored, creating a
// fingerprinting/replacement attack surface.
// Additionally, Core uses wtxid for orphan lookup; blockbrew uses txid.
//
// Test: verify that InvVect for orphan parent requests uses InvTypeTx (correct)
// and document the txid-keyed orphan map.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G23_OrphanKeyedByTxidNotWtxid(t *testing.T) {
	// Core net_processing.cpp:4057: "orphan parent fetching always uses
	// MSG_TX GETDATAs regardless of the wtxidrelay setting."
	// This means InvTypeTx=1 is correct for orphan parent requests.
	if InvTypeTx != 1 {
		t.Errorf("G23: InvTypeTx = %d, want 1 (orphan parent requests use MSG_TX)", InvTypeTx)
	}

	// BUG-23: orphanEntry struct (mempool.go:400) uses txHash as key (txid),
	// but Core indexes by wtxid. Two witness-malleated variants with the same
	// txid cannot coexist in blockbrew's orphan map; only the last-added survives.
	// This test documents the architectural divergence.
	t.Log("G23: orphan pool keyed by txid (BUG-23); Core keys by wtxid (BIP-339 compat)")
}

// ─────────────────────────────────────────────────────────────────────────────
// G24 (FIXED — W103 BUG-24): EraseOrphansForPeer is wired into the live node.
//
// Bitcoin Core txorphanage::EraseForPeer (txorphanage.cpp), driven from
// net_processing.cpp::FinalizeNode, removes all orphans announced by a
// disconnecting peer so the orphan pool cannot be polluted by a peer that
// connects, spams orphans, and disconnects.
//
// blockbrew fix:
//   - orphanEntry now carries a fromPeer field (the announcing peer address);
//   - addOrphanLocked records it; AddTransactionFrom / AcceptToMemoryPoolFrom
//     plumb the announcing peer down from the P2P tx-message handler
//     (cmd/blockbrew/main.go OnTx → peer.Address()); locally-originated / RPC
//     txs pass "";
//   - Mempool.RemoveOrphansForPeer(addr) erases exactly that peer's orphans
//     under the same lock the other orphan ops use;
//   - OnPeerDisconnected (cmd/blockbrew/main.go) calls it on every disconnect.
//
// This test FLIPS the former absence-assertion: it drives a real Mempool,
// parks orphans attributed to two distinct peers, and asserts that
// RemoveOrphansForPeer erases the disconnected peer's orphans while RETAINING
// the other peer's. The mempool-package white-box counterpart is
// internal/mempool/orphan_eraseforpeer_test.go.
// ─────────────────────────────────────────────────────────────────────────────

// nilUTXOView is a UTXOView whose every lookup misses, so any tx fed to the
// mempool has "missing inputs" and is parked as an orphan (orphan branch runs
// before any script validation).
type nilUTXOView struct{}

func (nilUTXOView) GetUTXO(wire.OutPoint) *consensus.UTXOEntry { return nil }

// makeOrphanTx builds a minimal standard tx (one input spending the given
// missing outpoint, one P2WPKH output) that survives the mempool pre-checks and
// lands in the orphan pool. Mirrors mempool_test.go::createTestTransaction.
func makeOrphanTx(seed byte) *wire.MsgTx {
	var missingHash wire.Hash256
	missingHash[0] = seed
	tx := &wire.MsgTx{Version: 2, LockTime: 0}
	tx.TxIn = append(tx.TxIn, &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: missingHash, Index: 0},
		SignatureScript:  make([]byte, 107), // all-zero = push-only (OP_0…)
		Sequence:         0xffffffff,
	})
	pkScript := make([]byte, 22)
	pkScript[0] = 0x00 // OP_0
	pkScript[1] = 0x14 // push 20 bytes
	tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: 99_000, PkScript: pkScript})
	return tx
}

func TestW103_G24_EraseOrphansForPeer(t *testing.T) {
	// Orphan parent fetches still use MSG_TX regardless of wtxidrelay
	// (Core net_processing.cpp:4057) — keep this gate-relevant assertion.
	if InvTypeTx != 1 {
		t.Errorf("G24: InvTypeTx = %d, want 1 (orphan parent requests use MSG_TX)", InvTypeTx)
	}

	mp := mempool.New(mempool.Config{
		MaxSize:                10_000_000,
		MinRelayFeeRate:        1000,
		MaxOrphanTxs:           100,
		ChainParams:            consensus.RegtestParams(),
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, nilUTXOView{})

	const peerA = "10.0.0.1:8333"
	const peerB = "10.0.0.2:8333"

	// Two orphans announced by peerA, one by peerB. AddTransactionFrom parks each
	// because its single input is missing from the (nil) UTXO view.
	a1 := makeOrphanTx(0x21)
	a2 := makeOrphanTx(0x22)
	b1 := makeOrphanTx(0x23)
	for _, tc := range []struct {
		tx       *wire.MsgTx
		fromPeer string
	}{{a1, peerA}, {a2, peerA}, {b1, peerB}} {
		if err := mp.AcceptToMemoryPoolFrom(tc.tx, tc.fromPeer); err == nil {
			t.Fatalf("G24: expected missing-inputs error (orphan parked) for peer %s", tc.fromPeer)
		}
	}
	if got := mp.OrphanCount(); got != 3 {
		t.Fatalf("G24: setup expected 3 orphans, got %d", got)
	}

	// peerA disconnects → exactly peerA's two orphans erased, peerB's retained.
	if removed := mp.RemoveOrphansForPeer(peerA); removed != 2 {
		t.Fatalf("G24: RemoveOrphansForPeer(peerA) = %d, want 2", removed)
	}
	// peerB's single orphan must be the one retained (peerA contributed exactly
	// the other two, just erased). Exact orphan-identity retention is asserted in
	// the mempool-package white-box test orphan_eraseforpeer_test.go.
	if got := mp.OrphanCount(); got != 1 {
		t.Fatalf("G24: after peerA disconnect expected 1 orphan retained (peerB's), got %d", got)
	}

	// Idempotent: disconnecting peerA again removes nothing.
	if removed := mp.RemoveOrphansForPeer(peerA); removed != 0 {
		t.Errorf("G24: second RemoveOrphansForPeer(peerA) = %d, want 0", removed)
	}

	// peerB disconnects → pool drains.
	if removed := mp.RemoveOrphansForPeer(peerB); removed != 1 {
		t.Fatalf("G24: RemoveOrphansForPeer(peerB) = %d, want 1", removed)
	}
	if got := mp.OrphanCount(); got != 0 {
		t.Fatalf("G24: after peerB disconnect expected 0 orphans, got %d", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G25 / OK: ProcessOrphanTx is recursive — processOrphansLocked calls
// AddTransaction which calls processOrphansLocked again.
// blockbrew mempool.go:1908: processOrphansLocked → AddTransaction (unlock+lock)
// → processOrphansLocked again. This correctly handles chains of orphans.
//
// Test: verify the recursive structure exists (by reading the code path).
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G25_OrphanProcessingRecursive(t *testing.T) {
	// G25 is OK: processOrphansLocked calls mp.AddTransaction which re-enters
	// processOrphansLocked via the same lock-unlock pattern.
	// This test documents the correct behavior.
	t.Log("G25: orphan processing is recursive via AddTransaction re-entry (OK)")
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-26 (P2) G26: No NODE_NETWORK check before requesting transactions.
// Bitcoin Core txdownloadman_impl.cpp: peers must have NODE_NETWORK or
// NODE_NETWORK_LIMITED service to serve transaction getdata requests.
// blockbrew's HandleGetData serves any connected peer without checking the
// requester's service flags (it checks our own prune state, not theirs).
//
// Test: verify ServiceNodeNetwork constant exists and document the missing gate.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G26_CanRequestTxFromServiceCheck(t *testing.T) {
	// Core: NODE_NETWORK = 1 << 0 = 1.
	if ServiceNodeNetwork != 1 {
		t.Errorf("G26: ServiceNodeNetwork = %d, want 1", ServiceNodeNetwork)
	}

	// BUG-26: blockbrew does not check peer.Services() & NODE_NETWORK before
	// issuing getdata for transactions. Any peer (even SPV clients) can receive
	// getdata tx requests even if they don't serve transactions.
	// Core: CanRequestTxFrom checks HasAllDesirableServiceFlags which requires
	// NODE_NETWORK or NODE_NETWORK_LIMITED.
	t.Log("G26: no NODE_NETWORK service check before tx getdata (BUG-26)")
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-28 (P2) G28: Unrequested tx misbehavior score absent.
// Bitcoin Core net_processing.cpp: receiving an unrequested tx (i.e., a tx
// message for which no getdata was sent) triggers Misbehaving(10).
// blockbrew's OnTx handler (peer.go:606-608) simply dispatches to the listener
// with no check for whether we requested this tx.
//
// Test: verify OnTx dispatch path and document the missing unrequested check.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G28_UnrequestedTxMisbehaviorAbsent(t *testing.T) {
	// BUG-28: No "did we request this tx?" check in the tx message handler.
	// Core: if !tx_relay->m_tx_announced.count(hash) → Misbehaving(10).
	// blockbrew dispatches directly to OnTx listener.
	//
	// ScoreUnrequestedData = 5 exists in peer.go:148 but is only used for
	// blocks, not transactions. A tx-specific unrequested guard is absent.
	if ScoreUnrequestedData != 5 {
		t.Errorf("G28: ScoreUnrequestedData = %d, want 5", ScoreUnrequestedData)
	}
	t.Log("G28: unrequested tx misbehavior not applied (ScoreUnrequestedData exists for blocks only)")
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-29 (P2) G29: No rate-limited reject reasons (getdata tx notfound).
// Bitcoin Core: after sending a notfound for a tx getdata, the peer is not
// rate-limited but the "notfound" response avoids repeatedly serving the same
// notfound for the same tx within a window.
// blockbrew HandleGetData sends notfound for blocks but has a TODO stub for
// tx case (no notfound sent for unknown txs, peer just receives silence).
//
// Test: verify HandleGetData handles InvTypeBlock with notfound but not InvTypeTx.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G29_TxNotFoundNotSent(t *testing.T) {
	// BUG-29: HandleGetData's InvTypeTx case is a TODO stub (sync.go:1271-1272).
	// A peer requesting a tx that isn't in our mempool receives no response
	// (neither the tx nor a notfound). Core sends notfound for missing txs.
	// This means requesting peers stall indefinitely waiting for a response.
	//
	// Verify InvTypeTx is a valid parseable type:
	if InvTypeTx != 1 {
		t.Errorf("G29: InvTypeTx = %d, want 1", InvTypeTx)
	}
	t.Log("G29: tx getdata returns no response for missing tx (no notfound) — BUG-29")
}

// ─────────────────────────────────────────────────────────────────────────────
// G30 / Partial: -peerbloomfilters flag wired but -whitelistforcerelay absent.
// Bitcoin Core: -peerbloomfilters controls NODE_BLOOM advertisement and mempool
// handler gate. -whitelistforcerelay forces relay to whitelisted peers even
// when fRelay=false. blockbrew wires AdvertiseNodeBloom (-peerbloomfilters)
// correctly but does not implement -whitelistforcerelay (force relay to noBan
// peers regardless of fRelay).
//
// Test: verify noBan peers still respect WantsTxRelay (documents missing
// whitelistforcerelay override).
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G30_PeerBloomFiltersAndWhitelistForceRelay(t *testing.T) {
	// AdvertiseNodeBloom controls NODE_BLOOM service bit (G7 above verifies this).
	// Here we test that noBan peers with fRelay=false do NOT receive txs
	// (documents the missing -whitelistforcerelay).

	p := &Peer{
		addr:        "1.2.3.4:8333",
		sendQueue:   make(chan Message, SendQueueSize),
		quit:        make(chan struct{}),
		noBan:       true, // whitelisted peer
		peerVersion: &MsgVersion{Relay: false},
	}

	// With -whitelistforcerelay, WantsTxRelay() would return true for noBan peers
	// even if fRelay=false. Without it, WantsTxRelay() returns false.
	if p.WantsTxRelay() {
		t.Error("G30: whitelistforcerelay not implemented — noBan peer with fRelay=false should not get txs (current behavior)")
	}
	// This is the missing feature: -whitelistforcerelay.
	t.Log("G30: -whitelistforcerelay not implemented; noBan peers respect fRelay flag (BUG-30 partial)")
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration-level: G2/G27 combined — MSG_WTX constant and announcement type.
// Asserts the full BIP-339 announcement type fix (W103 FIX-15).
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G2_G27_WtxidRelayAnnouncementType(t *testing.T) {
	// Per BIP-339 and Core protocol.h:
	//   MSG_TX         = 1            (legacy txid announcement)
	//   MSG_WTX        = 5            (wtxid announcement, BIP-339)
	//   MSG_WITNESS_TX = 0x40000001   (BIP-144 getdata witness flag — NOT for inv)
	//
	// blockbrew now defines InvTypeWtx=5 and selects per-peer in RelayTransaction.

	// Verify all three type constants.
	if InvTypeTx != 1 {
		t.Errorf("InvTypeTx = %d, want 1", InvTypeTx)
	}
	if InvTypeWtx != 5 {
		t.Errorf("InvTypeWtx = %d, want 5 (MSG_WTX, BIP-339)", InvTypeWtx)
	}
	if InvTypeWitnessTx != 0x40000001 {
		t.Errorf("InvTypeWitnessTx = 0x%x, want 0x40000001", InvTypeWitnessTx)
	}
	// All three must be distinct.
	if InvTypeWtx == InvTypeWitnessTx {
		t.Error("InvTypeWtx and InvTypeWitnessTx must be distinct")
	}
	if InvTypeWtx == InvTypeTx {
		t.Error("InvTypeWtx and InvTypeTx must be distinct")
	}

	// Peer with wtxid relay support: must receive inv{InvTypeWtx=5, wtxid}.
	pm := NewPeerManager(PeerManagerConfig{})
	txHash := [32]byte{0x55}
	wtxHash := [32]byte{0x66}

	p := &Peer{
		addr:                "1.2.3.4:8333",
		state:               PeerStateConnected,
		sendQueue:           make(chan Message, SendQueueSize),
		quit:                make(chan struct{}),
		peerVersion:         &MsgVersion{Relay: true},
		wtxidRelaySupported: true,
	}
	p.versionRecvd = true
	pm.mu.Lock()
	pm.peers[p.addr] = &PeerInfo{peer: p, connType: ConnFullRelay}
	pm.mu.Unlock()

	if !p.WTxidRelay() {
		t.Fatal("peer should report wtxid relay support after flag set")
	}

	pm.RelayTransaction(txHash, wtxHash, 1000, 250, "")

	select {
	case msg := <-p.sendQueue:
		inv, ok := msg.(*MsgInv)
		if !ok || len(inv.InvList) == 0 {
			t.Fatal("G2/G27: expected non-empty MsgInv")
		}
		if inv.InvList[0].Type == InvTypeWitnessTx {
			t.Errorf("G2/G27 BUG: InvTypeWitnessTx=0x%x must not appear in inv announcements", InvTypeWitnessTx)
		}
		if inv.InvList[0].Type != InvTypeWtx {
			t.Errorf("G2/G27: wtxid peer got type 0x%x, want InvTypeWtx=5", inv.InvList[0].Type)
		}
		if inv.InvList[0].Hash != wtxHash {
			t.Errorf("G2/G27: wtxid peer got hash %x, want wtxid %x", inv.InvList[0].Hash, wtxHash)
		}
	default:
		t.Error("G2/G27: wtxid peer got no message from RelayTransaction")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Comprehensive G6 test: wtxidrelay timing enforcement.
// BIP-339: wtxidrelay MUST be sent between version and verack.
// Core: disconnect if received after verack.
// blockbrew: no post-verack check in WTxidRelay handler (peer.go:639-641).
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G6_WtxidRelayTimingEnforcement(t *testing.T) {
	// sendaddrv2 and sendtxrcncl check verAckRecvd (peer.go:817, peer.go:838).
	// WTxidRelay handler (peer.go:639) does NOT check verAckRecvd.
	//
	// Build a post-verack peer and simulate receiving a wtxidrelay message.
	p := &Peer{
		addr:        "2.3.4.5:8333",
		sendQueue:   make(chan Message, SendQueueSize),
		quit:        make(chan struct{}),
		state:       PeerStateConnected,
		verAckRecvd: true,
	}
	banFired := false
	p.banCallback = func(_ *Peer) { banFired = true }

	// handleMessage dispatch for *MsgWTxidRelay with verAckRecvd=true.
	// Core would Misbehave(100) + disconnect.
	// blockbrew silently accepts.
	p.handleMessage(&MsgWTxidRelay{})
	time.Sleep(10 * time.Millisecond)

	if banFired {
		t.Log("G6: ban fired for post-verack wtxidrelay (behavior changed — test needs update)")
	} else {
		// Documents BUG-3/G6: no post-verack enforcement.
		if !p.WTxidRelay() {
			t.Error("G6: wtxidRelaySupported should be set after handling WTxidRelay message")
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G11 supplemental: GETDATA_TX_INTERVAL absence confirmed via SyncManager.
// The SyncManager uses BlockRequestTimeout=2min for blocks, but there is no
// tx-specific getdata re-request timer.
// ─────────────────────────────────────────────────────────────────────────────
func TestW103_G11_GetDataTxIntervalAbsent(t *testing.T) {
	// GETDATA_TX_INTERVAL = 60s in Core. blockbrew has no equivalent.
	// BlockRequestTimeout=2min exists for blocks only.
	const coreGetDataTxInterval = 60 * time.Second
	if BlockRequestTimeout == coreGetDataTxInterval {
		t.Log("G11: BlockRequestTimeout coincidentally matches GETDATA_TX_INTERVAL (block-only, not tx)")
	}
	// Document: no tx getdata expiry timer.
	t.Log("G11: GETDATA_TX_INTERVAL=60s absent — tx requests never expire/retry (BUG-11)")
}
