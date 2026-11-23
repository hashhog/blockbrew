package p2p

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// notfoundFixture puts one block request in flight to peer A and returns
// the sync manager, the request and the two peers.
func notfoundFixture(t *testing.T) (*SyncManager, *blockRequest, *Peer, *Peer) {
	t.Helper()
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{ChainParams: params, HeaderIndex: idx})
	A := createMockPeer("127.0.0.2:18444", 1)
	B := createMockPeer("127.0.0.3:18444", 1)
	hash := wire.Hash256{0x42}
	req := &blockRequest{Hash: hash, Height: 1, Peer: A, State: BlockDownloadInFlight, RequestAt: time.Now()}
	sm.mu.Lock()
	sm.inflight[hash] = req
	sm.blockQueue = append(sm.blockQueue, req)
	sm.mu.Unlock()
	return sm, req, A, B
}

// TestNotFoundFromOtherPeerKeepsInflight: block H is requested from A; B
// answers notfound(H). B was never asked, so the request to A must stay in
// flight, untouched. Core: NOTFOUND only calls RemoveBlockRequest(hash,
// pfrom.GetId()), which removes the request made to the sending peer.
// Before the fix any peer could cancel every other peer's block requests.
func TestNotFoundFromOtherPeerKeepsInflight(t *testing.T) {
	sm, req, A, B := notfoundFixture(t)

	sm.HandleNotFound(B, &MsgNotFound{InvList: []*InvVect{{Type: InvTypeWitnessBlock, Hash: req.Hash}}})

	sm.mu.RLock()
	defer sm.mu.RUnlock()
	got, ok := sm.inflight[req.Hash]
	if !ok {
		t.Fatal("notfound from an unrelated peer removed the in-flight request")
	}
	if got.Peer != A {
		t.Errorf("in-flight request reassigned: peer=%v, want A", got.Peer)
	}
	if got.State != BlockDownloadInFlight {
		t.Errorf("state=%v, want BlockDownloadInFlight", got.State)
	}
	if got.RetryCount != 0 {
		t.Errorf("RetryCount=%d, want 0", got.RetryCount)
	}
	if _, failed := got.FailedPeers[B.Address()]; failed {
		t.Error("peer that was never asked recorded as a failed source")
	}
}

// TestNotFoundFromRequestedPeerFreesRequest: the control. notfound(H) from
// A, the peer H was requested from, still frees the request for retry
// elsewhere and records A as unable to serve it.
func TestNotFoundFromRequestedPeerFreesRequest(t *testing.T) {
	sm, req, A, _ := notfoundFixture(t)

	sm.HandleNotFound(A, &MsgNotFound{InvList: []*InvVect{{Type: InvTypeBlock, Hash: req.Hash}}})

	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if _, ok := sm.inflight[req.Hash]; ok {
		t.Fatal("notfound from the requested peer left the request in flight")
	}
	if req.State != BlockDownloadPending || req.RetryCount != 1 {
		t.Errorf("state=%v retry=%d, want Pending/1", req.State, req.RetryCount)
	}
	if _, failed := req.FailedPeers[A.Address()]; !failed {
		t.Error("requested peer not recorded as a failed source")
	}
}
