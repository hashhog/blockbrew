package p2p

import (
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Core's PeerManagerImpl::ProcessHeadersMessage checks EVERY headers message
// against GetAntiDoSWorkThreshold() (active tip work minus 144 blocks of
// proof, floored at MinimumChainWork; net_processing.cpp). A chain below it
// goes through TryLowWorkHeadersSync: a full message starts a bounded
// PRESYNC/REDOWNLOAD (HeadersSyncState), anything shorter is ignored, and in
// both cases nothing is stored. blockbrew only ran PRESYNC for the sync peer
// while its own tip was below MinimumChainWork; every other message reached
// AddHeader(hdr, true), so a low-work fork from any peer was indexed,
// persisted and reloaded on every boot.

// antiDoSFixture: a regtest header index `depth` headers deep, a chain
// manager whose active tip is that header, and MinimumChainWork lowered to 10
// blocks of regtest work so the node is past it.
func antiDoSFixture(t *testing.T, depth int) (*SyncManager, *consensus.HeaderIndex, *Peer) {
	t.Helper()
	params := *consensus.RegtestParams()
	params.MinimumChainWork = new(big.Int).Mul(big.NewInt(10), consensus.CalcWork(0x207fffff))
	idx := consensus.NewHeaderIndex(&params)

	prev := idx.Genesis()
	for i := 0; i < depth; i++ {
		hdr := createTestBlockHeader(prev.Hash, prev.Header.Timestamp+600, 0)
		n, err := idx.AddHeader(hdr, true)
		if err != nil {
			t.Fatalf("building main chain at %d: %v", i+1, err)
		}
		prev = n
	}

	pm := &PeerManager{}
	syncPeer := createMockPeer("sync.example:8333", int32(depth))
	other := createMockPeer("other.example:8333", int32(depth))
	pm.InsertConnectedPeer(syncPeer)
	pm.InsertConnectedPeer(other)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  &params,
		HeaderIndex:  idx,
		PeerManager:  pm,
		ChainManager: &mockChainConnector{tipHash: prev.Hash, tipHeight: prev.Height, postIBD: true},
	})
	sm.mu.Lock()
	sm.syncPeer = syncPeer
	sm.headersSynced = true
	sm.mu.Unlock()
	return sm, idx, other
}

// forkFromGenesis mines n valid-PoW regtest headers forking at genesis,
// with timestamps offset so none collides with the main chain.
func forkFromGenesis(idx *consensus.HeaderIndex, n int) []wire.BlockHeader {
	g := idx.Genesis()
	out := make([]wire.BlockHeader, 0, n)
	prevHash, ts := g.Hash, g.Header.Timestamp+1
	for i := 0; i < n; i++ {
		ts += 600
		hdr := createTestBlockHeader(prevHash, ts, 7)
		out = append(out, hdr)
		prevHash = hdr.BlockHash()
	}
	return out
}

func TestLowWorkForkHeadersNotStored(t *testing.T) {
	sm, idx, other := antiDoSFixture(t, 300)
	before := idx.NodeCount()

	sm.HandleHeaders(other, &MsgHeaders{Headers: forkFromGenesis(idx, 100)})

	if got := idx.NodeCount(); got != before {
		t.Fatalf("header index grew from %d to %d on a 101-block fork against a 300-block "+
			"active tip (anti-DoS threshold = tip - 144 blocks): low-work headers must not be stored",
			before, got)
	}
	if other.ShouldBan() {
		t.Fatal("a short low-work chain is ignored in Core, not a misbehaviour")
	}
}

// A full message of low-work headers starts PRESYNC for that peer (Core
// TryLowWorkHeadersSync) instead of being stored.
func TestLowWorkFullHeadersMessageStartsPresync(t *testing.T) {
	sm, idx, other := antiDoSFixture(t, MaxHeadersPerRequest+300)
	before := idx.NodeCount()

	// 2001 blocks of work against a 2300-block tip: below tip - 144.
	sm.HandleHeaders(other, &MsgHeaders{Headers: forkFromGenesis(idx, MaxHeadersPerRequest)})

	if got := idx.NodeCount(); got != before {
		t.Fatalf("header index grew from %d to %d: PRESYNC must not store headers", before, got)
	}
	sm.mu.Lock()
	hss := sm.peerHeadersSync[other.Address()]
	sm.mu.Unlock()
	if hss == nil {
		t.Fatal("no HeadersSyncState started for a full low-work headers message")
	}
	if hss.Phase() != HeadersSyncPresync {
		t.Fatalf("phase = %s, want PRESYNC", hss.DescribePhase())
	}
	gh := 0
	for len(other.sendQueue) > 0 {
		if _, ok := (<-other.sendQueue).(*MsgGetHeaders); ok {
			gh++
		}
	}
	if gh != 1 {
		t.Fatalf("PRESYNC sent %d getheaders to the peer, want 1", gh)
	}
}

// Negative control for the gate: a fork that forks within the 144-block
// buffer below the active tip is at or above the threshold and is stored,
// as Core stores it.
func TestNearTipForkHeadersStillStored(t *testing.T) {
	sm, idx, other := antiDoSFixture(t, 300)
	fork := idx.BestTip().GetAncestor(290)
	var hdrs []wire.BlockHeader
	prevHash, ts := fork.Hash, fork.Header.Timestamp+1
	for i := 0; i < 5; i++ {
		ts += 600
		h := createTestBlockHeader(prevHash, ts, 7)
		hdrs = append(hdrs, h)
		prevHash = h.BlockHash()
	}
	before := idx.NodeCount()
	sm.HandleHeaders(other, &MsgHeaders{Headers: hdrs})
	if got := idx.NodeCount(); got != before+5 {
		t.Fatalf("near-tip fork: index %d -> %d, want +5", before, got)
	}
}

// Negative control: a peer with the noban permission bypasses the gate
// (Core: HasPermission(NetPermissionFlags::NoBan) sets already_validated_work).
func TestLowWorkHeadersFromNoBanPeerStored(t *testing.T) {
	sm, idx, other := antiDoSFixture(t, 300)
	other.SetNoBan(true)
	before := idx.NodeCount()
	sm.HandleHeaders(other, &MsgHeaders{Headers: forkFromGenesis(idx, 100)})
	if got := idx.NodeCount(); got != before+100 {
		t.Fatalf("noban peer: index %d -> %d, want +100", before, got)
	}
}

// Consensus guard for the gate: a fork that ends up with MORE work than the
// active tip, delivered from genesis in full low-work messages, must not be
// lost. Its first message is below the threshold and starts PRESYNC; once the
// claimed work passes the threshold the pipeline re-downloads the chain and
// every header is stored, and the fork becomes the best header.
func TestHeavierForkThroughPresyncIsStored(t *testing.T) {
	sm, idx, other := antiDoSFixture(t, MaxHeadersPerRequest+300)
	before := idx.NodeCount()
	fork := forkFromGenesis(idx, MaxHeadersPerRequest+400) // 2401 > 2301 blocks of work
	first, rest := fork[:MaxHeadersPerRequest], fork[MaxHeadersPerRequest:]
	drain := func() {
		for len(other.sendQueue) > 0 {
			<-other.sendQueue
		}
	}

	// PRESYNC: both batches; nothing is stored yet.
	sm.HandleHeaders(other, &MsgHeaders{Headers: first})
	drain()
	sm.HandleHeaders(other, &MsgHeaders{Headers: rest})
	drain()
	if got := idx.NodeCount(); got != before {
		t.Fatalf("PRESYNC stored headers: %d -> %d", before, got)
	}
	sm.mu.Lock()
	hss := sm.peerHeadersSync[other.Address()]
	sm.mu.Unlock()
	if hss == nil || hss.Phase() != HeadersSyncRedownload {
		t.Fatalf("pipeline did not move to REDOWNLOAD after the fork passed the threshold (hss=%v)", hss)
	}

	// REDOWNLOAD: the same chain again; it is now stored.
	sm.HandleHeaders(other, &MsgHeaders{Headers: first})
	drain()
	sm.HandleHeaders(other, &MsgHeaders{Headers: rest})
	drain()
	if got := idx.NodeCount(); got != before+len(fork) {
		t.Fatalf("after REDOWNLOAD index %d -> %d, want +%d", before, got, len(fork))
	}
	if idx.BestTip().Hash != fork[len(fork)-1].BlockHash() {
		t.Fatalf("best header is not the heavier fork's tip")
	}
	if other.ShouldBan() {
		t.Fatal("an honest heavier fork got its peer punished")
	}
}

// The gate lets any peer start a low-work PRESYNC at tip. That pipeline owns
// only its own peer's header requests: the periodic getheaders must still go
// to every other peer, or one peer feeding a low-work chain would stop the
// node learning new blocks from the rest.
func TestLowWorkPresyncDoesNotSilenceOtherPeers(t *testing.T) {
	sm, idx, other := antiDoSFixture(t, MaxHeadersPerRequest+300)
	sm.HandleHeaders(other, &MsgHeaders{Headers: forkFromGenesis(idx, MaxHeadersPerRequest)})
	sm.mu.Lock()
	syncPeer := sm.syncPeer
	_, presync := sm.peerHeadersSync[other.Address()]
	sm.mu.Unlock()
	if !presync {
		t.Fatal("fixture: no PRESYNC started")
	}
	countGetHeaders := func(p *Peer) int {
		n := 0
		for len(p.sendQueue) > 0 {
			if _, ok := (<-p.sendQueue).(*MsgGetHeaders); ok {
				n++
			}
		}
		return n
	}
	countGetHeaders(other)
	countGetHeaders(syncPeer)

	sm.sendPeriodicGetHeaders()

	if n := countGetHeaders(syncPeer); n != 1 {
		t.Fatalf("periodic getheaders to a peer with no pipeline: got %d, want 1", n)
	}
	if n := countGetHeaders(other); n != 0 {
		t.Fatalf("periodic getheaders to the peer in PRESYNC: got %d, want 0 (its pipeline owns its requests)", n)
	}
}
