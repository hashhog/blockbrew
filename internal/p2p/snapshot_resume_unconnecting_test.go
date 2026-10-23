package p2p

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// forwardGetHeaders returns the getheaders in gh that are forward requests
// (zero stop hash), as opposed to snapshot backfill requests (stop = band root).
func forwardGetHeaders(gh []*MsgGetHeaders) []*MsgGetHeaders {
	var out []*MsgGetHeaders
	for _, m := range gh {
		if m.HashStop == (wire.Hash256{}) {
			out = append(out, m)
		}
	}
	return out
}

// TestSnapshotResumeUnconnectingHeadersDoNotStarveBackfill reproduces the
// 940k R4 resume wedge (QUEUES 2026-10-05: three arms sat at block 940001 for
// ~43 min logging "block 940001 is validated; nudging connect path" with
// state=3).
//
// The node resumed from a snapshot base (a restart mid-range: the band is
// grafted at the base, detached from genesis), so block connection is held
// until the pre-base header backfill links the band to genesis. Its only peer
// served a header chain that does not connect at the tip (the replay server
// put Core's stale 963853 into its chain, so every forward getheaders reply
// started with a header whose parent the node does not have). blockbrew
// answered each such reply with another getheaders, got the same reply back
// within milliseconds, and on the 11th disconnected the peer — every ~30 s,
// right after each reconnect. The backfill only ran in the few seconds the
// peer stayed up, so the connect cursor sat at base+1 until the band finally
// linked ~43 min later.
//
// Core v31 neither counts nor punishes unconnecting headers: it re-asks with
// MaybeSendGetHeaders, which sends at most one getheaders per peer per
// HEADERS_RESPONSE_TIME (net_processing.cpp HandleUnconnectingHeaders,
// MaybeSendGetHeaders), and p2p_sendheaders.py part 5 sends 100 unconnecting
// headers in a row without a disconnect.
func TestSnapshotResumeUnconnectingHeadersDoNotStarveBackfill(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	hdrs := regtestChainHeaders(t, params, 23)
	const base = 20
	graftBand1(t, idx, hdrs, base)

	mock := &mockChainConnector{tipHash: hdrs[base].BlockHash(), tipHeight: base}
	var connected []int32
	mock.connectFn = func(b *wire.MsgBlock) error {
		n := idx.GetNode(b.Header.BlockHash())
		if n == nil {
			t.Fatalf("connect of a block whose header is not indexed")
		}
		connected = append(connected, n.Height)
		mock.tipHash, mock.tipHeight = n.Hash, n.Height
		return nil
	}

	pm := &PeerManager{peers: make(map[string]*PeerInfo)}
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params, HeaderIndex: idx, PeerManager: pm, ChainManager: mock,
	})
	peer := createMockPeer("127.0.0.1:29800", 23)
	pm.InsertConnectedPeer(peer)
	sm.mu.Lock()
	sm.syncPeer = peer
	sm.nextHeight = base + 1
	sm.maybeRequestBackfillLocked(peer, false)
	sm.mu.Unlock()
	if gh := drainBackfillGetHeaders(peer); len(gh) != 1 || gh[0].HashStop != hdrs[base].BlockHash() {
		t.Fatalf("want one backfill getheaders at boot, got %d", len(gh))
	}

	// Block base+1 is already downloaded and validated; connection is held.
	pending := map[int32]*blockWithRequest{}
	queueBody := func(h int) {
		pending[int32(h)] = &blockWithRequest{
			block: &wire.MsgBlock{Header: hdrs[h]},
			req:   &blockRequest{Hash: hdrs[h].BlockHash(), Height: int32(h), State: BlockDownloadValidated},
		}
	}
	queueBody(base + 1)
	sm.connectPendingBlocks(pending)
	if len(connected) != 0 || sm.nextHeight != base+1 {
		t.Fatalf("connected %v while the band is detached; want the hold", connected)
	}

	// The peer's forward replies do not connect: their first header builds on
	// a stale tip block the node never indexed. More of them than the old
	// MAX_NUM_UNCONNECTING_HEADERS_MSGS=10.
	stale := wire.Hash256{0x96, 0x38, 0x53}
	unconnecting := &MsgHeaders{Headers: []wire.BlockHeader{
		createTestBlockHeader(stale, hdrs[23].Timestamp+600, 963854),
	}}
	for i := 1; i <= 12; i++ {
		sm.HandleHeaders(peer, unconnecting)
		if !peer.IsConnected() {
			t.Fatalf("resume wedge: unconnecting headers message #%d disconnected the only peer, "+
				"so the snapshot backfill that releases block connection never finishes", i)
		}
	}
	if s := peer.MisbehaviorScore(); s != 0 {
		t.Fatalf("unconnecting headers scored the peer %d, want 0 (Core does not punish them)", s)
	}
	if fwd := forwardGetHeaders(drainBackfillGetHeaders(peer)); len(fwd) > 1 {
		t.Fatalf("%d forward getheaders for 12 unconnecting replies, want at most 1 "+
			"(Core MaybeSendGetHeaders: one in flight per peer per HEADERS_RESPONSE_TIME)", len(fwd))
	}
	if sm.SyncPeer() != peer {
		t.Fatalf("sync peer cleared by unconnecting headers")
	}

	// The backfill reply from the same peer links the band; the connect
	// cursor then moves past base+1.
	sm.HandleHeaders(peer, &MsgHeaders{Headers: hdrs[1 : base+1]})
	if idx.SnapshotHeadersPending() {
		t.Fatalf("band still detached after the backfill reply")
	}
	sm.HandleHeaders(peer, &MsgHeaders{Headers: hdrs[base+1 : 24]})
	if idx.BestHeight() != 23 {
		t.Fatalf("header tip %d after the forward re-request, want 23", idx.BestHeight())
	}
	queueBody(base + 2)
	sm.connectPendingBlocks(pending)
	if len(connected) != 2 || connected[0] != base+1 || connected[1] != base+2 {
		t.Fatalf("connected %v after the band linked, want [%d %d]", connected, base+1, base+2)
	}
	if sm.nextHeight != base+3 {
		t.Fatalf("connect cursor at %d, want %d", sm.nextHeight, base+3)
	}
}

// After a connecting batch the per-peer getheaders throttle is cleared (Core
// clears m_last_getheaders_timestamp when headers connect), so the next
// unconnecting announcement is answered straight away.
func TestUnconnectingHeadersThrottleClearsOnConnect(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	hdrs := regtestChainHeaders(t, params, 3)

	pm := &PeerManager{peers: make(map[string]*PeerInfo)}
	sm := NewSyncManager(SyncManagerConfig{ChainParams: params, HeaderIndex: idx, PeerManager: pm})
	peer := createMockPeer("10.0.0.1:8333", 3)
	pm.InsertConnectedPeer(peer)
	sm.mu.Lock()
	sm.syncPeer = peer
	sm.mu.Unlock()

	unconnecting := &MsgHeaders{Headers: []wire.BlockHeader{
		createTestBlockHeader(wire.Hash256{0xab}, hdrs[3].Timestamp+600, 77),
	}}
	sm.HandleHeaders(peer, unconnecting)
	sm.HandleHeaders(peer, unconnecting)
	if n := len(forwardGetHeaders(drainBackfillGetHeaders(peer))); n != 1 {
		t.Fatalf("%d getheaders for 2 back-to-back unconnecting messages, want 1", n)
	}

	sm.HandleHeaders(peer, &MsgHeaders{Headers: hdrs[1:3]})
	if idx.BestHeight() != 2 {
		t.Fatalf("header tip %d, want 2", idx.BestHeight())
	}
	drainBackfillGetHeaders(peer)

	sm.HandleHeaders(peer, unconnecting)
	fwd := forwardGetHeaders(drainBackfillGetHeaders(peer))
	if len(fwd) != 1 || fwd[0].BlockLocators[0] != hdrs[2].BlockHash() {
		t.Fatalf("want one getheaders from the new tip after a connecting batch, got %d", len(fwd))
	}
	if !peer.IsConnected() || peer.MisbehaviorScore() != 0 {
		t.Fatalf("peer punished for unconnecting headers")
	}
}
