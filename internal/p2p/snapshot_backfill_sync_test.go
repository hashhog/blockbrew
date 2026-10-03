package p2p

import (
	"math/big"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// regtestChainHeaders mines n headers on top of regtest genesis (index 0 is
// genesis, index h is height h).
func regtestChainHeaders(t *testing.T, params *consensus.ChainParams, n int) []wire.BlockHeader {
	t.Helper()
	hdrs := []wire.BlockHeader{params.GenesisBlock.Header}
	for h := 1; h <= n; h++ {
		prev := hdrs[h-1]
		hdrs = append(hdrs, createTestBlockHeader(prev.BlockHash(), prev.Timestamp+600, uint32(h)*7919))
	}
	return hdrs
}

// graftBand1 boots the index the way a base_header-only snapshot entry does:
// a one-header band at base, detached from genesis.
func graftBand1(t *testing.T, idx *consensus.HeaderIndex, hdrs []wire.BlockHeader, base int) {
	t.Helper()
	work := new(big.Int)
	for h := 0; h <= base; h++ {
		work.Add(work, consensus.CalcWork(hdrs[h].Bits))
	}
	if _, err := idx.GraftSnapshotBase(hdrs[base:base+1], int32(base), work); err != nil {
		t.Fatalf("graft: %v", err)
	}
	if !idx.SnapshotHeadersPending() {
		t.Fatalf("band-1 graft must leave the band detached")
	}
}

func drainBackfillGetHeaders(p *Peer) []*MsgGetHeaders {
	var out []*MsgGetHeaders
	for {
		select {
		case m := <-p.sendQueue:
			if gh, ok := m.(*MsgGetHeaders); ok {
				out = append(out, gh)
			}
		default:
			return out
		}
	}
}

// A forward header whose parent MTP window crosses a still-detached snapshot
// band is "cannot decide yet", not an invalid header: no misbehaviour, no
// disconnect (8af4590 scored it +100 and disconnected EVERY peer on a
// band-1 regtest snapshot boot, so the backfill reply never arrived and block
// connection was held forever). After the backfill links the band the
// forward headers are re-requested and accepted.
func TestSnapshotForwardHeaderDeferredNotPunished(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	hdrs := regtestChainHeaders(t, params, 23)
	graftBand1(t, idx, hdrs, 20)

	pm := &PeerManager{peers: make(map[string]*PeerInfo)}
	sm := NewSyncManager(SyncManagerConfig{ChainParams: params, HeaderIndex: idx, PeerManager: pm})
	peer := createMockPeer("10.0.0.1:18444", 23)
	pm.InsertConnectedPeer(peer)
	sm.mu.Lock()
	sm.syncPeer = peer
	sm.mu.Unlock()

	sm.HandleHeaders(peer, &MsgHeaders{Headers: hdrs[21:24]})
	if s := peer.MisbehaviorScore(); s != 0 {
		t.Fatalf("deferred forward header scored the peer %d, want 0", s)
	}
	if !peer.IsConnected() {
		t.Fatalf("deferred forward header disconnected the peer")
	}
	if idx.BestHeight() != 20 {
		t.Fatalf("best height %d, want 20 (forward headers deferred)", idx.BestHeight())
	}
	gh := drainBackfillGetHeaders(peer)
	if len(gh) != 1 || gh[0].HashStop != hdrs[20].BlockHash() {
		t.Fatalf("want one backfill getheaders stopping at the band root, got %d", len(gh))
	}

	// Backfill reply (genesis-rooted) links the band.
	sm.HandleHeaders(peer, &MsgHeaders{Headers: hdrs[1:21]})
	if idx.SnapshotHeadersPending() {
		t.Fatalf("band still detached after the backfill reply")
	}
	gh = drainBackfillGetHeaders(peer)
	if len(gh) != 1 || gh[0].HashStop != (wire.Hash256{}) || gh[0].BlockLocators[0] != hdrs[20].BlockHash() {
		t.Fatalf("want a forward getheaders from the base after the splice, got %d", len(gh))
	}

	// The re-requested forward headers now connect.
	sm.HandleHeaders(peer, &MsgHeaders{Headers: hdrs[21:24]})
	if idx.BestHeight() != 23 {
		t.Fatalf("best height %d after re-request, want 23", idx.BestHeight())
	}
	if s := peer.MisbehaviorScore(); s != 0 {
		t.Fatalf("peer score %d, want 0", s)
	}
}

// An unanswered backfill request is retried on a DIFFERENT peer (the
// lunarblock e4b11ef class: re-asking the silent peer holds block connection
// forever), and a rejected batch also moves to another peer.
func TestSnapshotBackfillRotatesPeers(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	hdrs := regtestChainHeaders(t, params, 20)
	graftBand1(t, idx, hdrs, 20)

	pm := &PeerManager{peers: make(map[string]*PeerInfo)}
	sm := NewSyncManager(SyncManagerConfig{ChainParams: params, HeaderIndex: idx, PeerManager: pm})
	a := createMockPeer("10.0.0.1:18444", 20)
	b := createMockPeer("10.0.0.2:18444", 20)
	pm.InsertConnectedPeer(a)
	pm.InsertConnectedPeer(b)

	sm.mu.Lock()
	sm.syncPeer = a
	sm.maybeRequestBackfillLocked(nil, false)
	sm.mu.Unlock()
	if len(drainBackfillGetHeaders(a)) != 1 || len(drainBackfillGetHeaders(b)) != 0 {
		t.Fatalf("first backfill request must go to the sync peer")
	}

	// Within the retry interval: nothing re-sent.
	sm.mu.Lock()
	sm.maybeRequestBackfillLocked(nil, false)
	sm.mu.Unlock()
	if len(drainBackfillGetHeaders(a))+len(drainBackfillGetHeaders(b)) != 0 {
		t.Fatalf("re-sent inside the retry interval")
	}

	// Silent past the interval: rotate to b.
	sm.mu.Lock()
	sm.backfillReqAt = time.Now().Add(-backfillRetryInterval - time.Second)
	sm.maybeRequestBackfillLocked(nil, false)
	sm.mu.Unlock()
	if len(drainBackfillGetHeaders(b)) != 1 || len(drainBackfillGetHeaders(a)) != 0 {
		t.Fatalf("timed-out backfill request was not rotated to the other peer")
	}

	// b feeds a backfill batch that breaks part-way (1 then 3): rejected,
	// and the next tick asks a.
	sm.HandleHeaders(b, &MsgHeaders{Headers: []wire.BlockHeader{hdrs[1], hdrs[3]}})
	if !idx.SnapshotHeadersPending() {
		t.Fatalf("a non-linking batch must not complete the backfill")
	}
	_ = drainBackfillGetHeaders(b)
	sm.mu.Lock()
	sm.maybeRequestBackfillLocked(nil, false)
	sm.mu.Unlock()
	if len(drainBackfillGetHeaders(a)) != 1 {
		t.Fatalf("after a rejected batch from b the retry must go to a")
	}
}
