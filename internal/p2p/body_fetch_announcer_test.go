package p2p

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Live 2026-11-15 04:14Z (mainnet 975896): the header arrived at 04:14:49,
// but blockbrew sent the getdata to 72.83.184.215, which had not announced
// the block. That peer kept relaying tx (six v2 "first-byte ... retracted —
// not a block body" lines) and never sent the body: Core's
// ProcessGetBlockData returns silently for a hash it does not know
// (net_processing.cpp, `if (!pindex) return;`). After the 16s mute timeout
// the round-robin picked [2001:bc8:30c8::], another non-announcer, with the
// same result; only the third pick (178.51.105.208) delivered, ~60s after
// the header. Core asks the peer that sent the header
// (HeadersDirectFetchBlocks) and only peers whose best-known block covers
// the request (FindNextBlocksToDownload / pindexBestKnownBlock).

// announcerFixture builds an at-tip SyncManager with one new header that
// `announcer` sent, `silent` connected peers that never announced it, and
// a Pending queue entry for that block (what StartBlockDownload queues).
func announcerFixture(t *testing.T, silent int) (*SyncManager, *Peer, []*Peer, *blockRequest) {
	t.Helper()
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	genesis := idx.Genesis()

	pm := &PeerManager{}
	announcer := createMockPeer("announcer.example:8333", 0)
	pm.InsertConnectedPeer(announcer)
	var others []*Peer
	for i := 0; i < silent; i++ {
		p := createMockPeer(fmt.Sprintf("silent%d.example:8333", i), 0)
		pm.InsertConnectedPeer(p)
		others = append(others, p)
	}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:    params,
		HeaderIndex:    idx,
		PeerManager:    pm,
		DownloadWindow: 8,
	})
	sm.mu.Lock()
	sm.headersSynced = true // at tip: announcements from any peer
	sm.mu.Unlock()

	hdr := createTestBlockHeader(genesis.Hash, genesis.Header.Timestamp+600, 0)
	sm.HandleHeaders(announcer, &MsgHeaders{Headers: []wire.BlockHeader{hdr}})
	node := idx.GetNode(hdr.BlockHash())
	if node == nil {
		t.Fatal("announced header was not added to the index")
	}

	req := &blockRequest{Hash: node.Hash, Height: node.Height, State: BlockDownloadPending}
	sm.mu.Lock()
	sm.blockQueue = []*blockRequest{req}
	sm.nextHeight = node.Height
	sm.mu.Unlock()
	return sm, announcer, others, req
}

// TestTipBodyRequestedFromAnnouncingPeerFirst: a new tip's body goes to
// the peer that sent its header, not to whichever peer the round-robin
// lands on. ConnectedPeers is map-ordered, so repeat with fresh fixtures:
// on the round-robin a 1-in-9 pick cannot pass 24 times.
func TestTipBodyRequestedFromAnnouncingPeerFirst(t *testing.T) {
	const trials = 24
	for i := 0; i < trials; i++ {
		sm, announcer, others, req := announcerFixture(t, 8)
		sm.requestBlocks()
		for _, p := range others {
			if got := drainGetData(p); len(got) != 0 {
				t.Fatalf("trial %d: getdata for height %d went to %s, which never announced it "+
					"(live 975896: a non-announcer relays tx and never sends the body)",
					i, req.Height, p.Address())
			}
		}
		got := drainGetData(announcer)
		if len(got) != 1 || got[0] != req.Hash {
			t.Fatalf("trial %d: announcer getdata = %v, want [%s]", i, got, req.Hash)
		}
	}
}

// TestTipBodyRotatesToAnotherAnnouncerBeforeSilentPeers: when the first
// announcer goes mute, the retry goes to another peer that has announced
// the block, not back to the round-robin over peers that never did.
func TestTipBodyRotatesToAnotherAnnouncerBeforeSilentPeers(t *testing.T) {
	const trials = 24
	for i := 0; i < trials; i++ {
		sm, announcer, others, req := announcerFixture(t, 8)
		// A second peer announces the same header later (BIP130 headers
		// for a hash we already have → Core UpdateBlockAvailability).
		second := others[0]
		silent := others[1:]
		sm.mu.Lock()
		hdr := sm.headerIndex.GetNode(req.Hash).Header
		sm.mu.Unlock()
		sm.HandleHeaders(second, &MsgHeaders{Headers: []wire.BlockHeader{hdr}})

		sm.requestBlocks()
		if got := drainGetData(announcer); len(got) != 1 {
			t.Fatalf("trial %d: first getdata did not go to the first announcer (got %v)", i, got)
		}
		drainGetData(second)
		for _, p := range silent {
			drainGetData(p)
		}

		// Announcer is mute past FirstByteTimeout.
		sm.mu.Lock()
		req.RequestAt = time.Now().Add(-FirstByteTimeout - time.Second)
		sm.mu.Unlock()
		sm.checkStaleRequests()

		sm.requestBlocks()
		for _, p := range silent {
			if got := drainGetData(p); len(got) != 0 {
				t.Fatalf("trial %d: retry went to %s, which never announced height %d, while %s had",
					i, p.Address(), req.Height, second.Address())
			}
		}
		if got := drainGetData(second); len(got) != 1 || got[0] != req.Hash {
			t.Fatalf("trial %d: second announcer getdata = %v, want [%s]", i, got, req.Hash)
		}
		if got := drainGetData(announcer); len(got) != 0 {
			t.Fatalf("trial %d: mute announcer asked again: %v", i, got)
		}
	}
}

// TestTipBodyFallsBackWhenNoPeerAnnounced: preference, not a hard rule.
// If no connected peer has announced the block (announcer disconnected),
// the request still goes out (liveness over avoidance).
func TestTipBodyFallsBackWhenNoPeerAnnounced(t *testing.T) {
	sm, announcer, others, req := announcerFixture(t, 3)
	announcer.mu.Lock()
	announcer.state = PeerStateDisconnected
	announcer.mu.Unlock()

	sm.requestBlocks()
	sent := 0
	for _, p := range others {
		sent += len(drainGetData(p))
	}
	if sent != 1 {
		t.Fatalf("getdata for height %d sent %d times with the announcer gone, want 1 fallback request",
			req.Height, sent)
	}
}

// TestUnrelatedInvTxBeforeBlockIsNotAFailedFetch: a peer that relays inv /
// tx between our getdata and the block body is alive, not a failed fetch.
// Each such message (v1 by command, v2 by an encrypted ≥80-byte payload
// that decodes as non-block) must leave the request in flight on that
// peer: no retry, no FailedPeers mark, no doubled stall window, and the
// mute clock still measured from the getdata.
//
// Only the announcer is connected here so the test isolates the
// inv/tx-vs-failed-fetch rule from peer choice. This already held on
// master (retractNonBlockFirstByte clears only the false stamp); the live
// 975896 rotations came from asking non-announcers, which the two tests
// above pin. Kept as a guard that the announcer-first change does not
// start penalising a chatty announcer.
func TestUnrelatedInvTxBeforeBlockIsNotAFailedFetch(t *testing.T) {
	sm, announcer, _, req := announcerFixture(t, 0)
	sm.requestBlocks()
	if got := drainGetData(announcer); len(got) != 1 {
		t.Fatalf("getdata = %v, want one request to the announcer", got)
	}
	listeners := sm.CreatePeerListeners()

	sm.mu.Lock()
	requestAt := req.RequestAt
	sm.mu.Unlock()

	// Live 975896 shapes: v2 payloads of 701, 193, 191, 1115, 372, 224
	// bytes, each decoding as inv/tx; plus the v1 equivalents.
	for _, size := range []uint32{701, 193, 191, 1115, 372, 224} {
		listeners.OnMessageHeader(announcer, "", size)
		listeners.OnNonBlockPayload(announcer)
	}
	for _, cmd := range []string{"inv", "tx"} {
		listeners.OnMessageHeader(announcer, cmd, 250)
		listeners.OnNonBlockPayload(announcer)
	}

	// Still inside the mute window measured from the getdata.
	sm.checkStaleRequests()

	sm.mu.Lock()
	defer sm.mu.Unlock()
	if req.State != BlockDownloadInFlight || req.Peer != announcer {
		t.Fatalf("after unrelated inv/tx: state=%d peer-is-announcer=%v, want InFlight on the announcer",
			req.State, req.Peer == announcer)
	}
	if _, ok := sm.inflight[req.Hash]; !ok {
		t.Fatal("unrelated inv/tx took the request out of flight")
	}
	if req.RetryCount != 0 {
		t.Fatalf("RetryCount=%d after unrelated inv/tx, want 0", req.RetryCount)
	}
	if _, failed := req.FailedPeers[announcer.Address()]; failed {
		t.Fatal("announcer marked failed for relaying inv/tx")
	}
	if !req.FirstByteAt.IsZero() || req.PayloadSize != 0 {
		t.Fatalf("unrelated payload left a first-byte stamp (at=%v size=%d)", req.FirstByteAt, req.PayloadSize)
	}
	if !req.RequestAt.Equal(requestAt) {
		t.Fatalf("RequestAt moved from %v to %v; the mute clock must stay anchored to the getdata",
			requestAt, req.RequestAt)
	}
	if st := sm.getStallTimeout(announcer); st != BaseStallTimeout {
		t.Fatalf("stall timeout=%s, want %s (inv/tx must not double it)", st, BaseStallTimeout)
	}
}

// TestIBDBodiesStillSpreadAcrossPeers: during IBD header catch-up only the
// sync peer has announced anything, so the synced-height preference must
// not apply there — otherwise every head-of-line body would queue on that
// one peer. The lowest heights still go to distinct peers, as before.
func TestIBDBodiesStillSpreadAcrossPeers(t *testing.T) {
	params := consensus.RegtestParams()
	pm := &PeerManager{}
	syncPeer := createMockPeer("sync.example:8333", 100)
	syncPeer.UpdateSyncedHeaders(100)
	pm.InsertConnectedPeer(syncPeer)
	for i := 0; i < 3; i++ {
		pm.InsertConnectedPeer(createMockPeer(fmt.Sprintf("ibd%d.example:8333", i), 100))
	}
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:    params,
		HeaderIndex:    consensus.NewHeaderIndex(params),
		PeerManager:    pm,
		DownloadWindow: 32,
	})
	sm.mu.Lock()
	sm.headersSynced = false
	sm.syncPeer = syncPeer
	for h := int32(1); h <= 32; h++ {
		var hash wire.Hash256
		hash[0], hash[1] = byte(h), 0xbb
		sm.blockQueue = append(sm.blockQueue, &blockRequest{Hash: hash, Height: h, State: BlockDownloadPending})
	}
	sm.mu.Unlock()

	sm.requestBlocks()

	sm.mu.Lock()
	defer sm.mu.Unlock()
	seen := map[*Peer]bool{}
	for _, req := range sm.blockQueue[:4] {
		if req.State != BlockDownloadInFlight || req.Peer == nil {
			t.Fatalf("height %d not requested (state=%d)", req.Height, req.State)
		}
		seen[req.Peer] = true
	}
	if len(seen) != 4 {
		t.Fatalf("lowest 4 IBD heights went to %d distinct peers, want 4 (round-robin, not funnelled to the sync peer)", len(seen))
	}
}
