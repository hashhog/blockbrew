package p2p

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// fakeMempoolProvider is a minimal MempoolTxidProvider for unit tests.
type fakeMempoolProvider struct {
	hashes []wire.Hash256
}

func (f *fakeMempoolProvider) GetAllTxHashes() []wire.Hash256 { return f.hashes }

// makeHashes returns n distinct Hash256s — each value seeded by index so
// duplicates are caught if batching code accidentally reuses indices.
func makeHashes(n int) []wire.Hash256 {
	out := make([]wire.Hash256, n)
	for i := 0; i < n; i++ {
		out[i][0] = byte(i)
		out[i][1] = byte(i >> 8)
		out[i][2] = byte(i >> 16)
	}
	return out
}

func TestHandleMempoolRequest_Empty(t *testing.T) {
	peer := &Peer{addr: "127.0.0.1:8333"}
	provider := &fakeMempoolProvider{hashes: nil}
	invs := HandleMempoolRequest(peer, provider)
	if invs != nil {
		t.Fatalf("empty mempool: expected nil, got %d invs", len(invs))
	}
}

func TestHandleMempoolRequest_NilProvider(t *testing.T) {
	peer := &Peer{addr: "127.0.0.1:8333"}
	if got := HandleMempoolRequest(peer, nil); got != nil {
		t.Fatalf("nil provider: expected nil, got %v", got)
	}
	if got := HandleMempoolRequest(nil, &fakeMempoolProvider{}); got != nil {
		t.Fatalf("nil peer: expected nil, got %v", got)
	}
}

func TestHandleMempoolRequest_SmallBatch(t *testing.T) {
	peer := &Peer{addr: "127.0.0.1:8333"}
	hashes := makeHashes(5)
	provider := &fakeMempoolProvider{hashes: hashes}
	invs := HandleMempoolRequest(peer, provider)
	if len(invs) != 1 {
		t.Fatalf("expected 1 inv, got %d", len(invs))
	}
	if len(invs[0].InvList) != 5 {
		t.Fatalf("expected 5 inv vectors, got %d", len(invs[0].InvList))
	}
	for i, iv := range invs[0].InvList {
		if iv.Type != InvTypeWitnessTx {
			t.Errorf("inv[%d].Type = 0x%x, want InvTypeWitnessTx (0x%x)", i, iv.Type, InvTypeWitnessTx)
		}
		if iv.Hash != hashes[i] {
			t.Errorf("inv[%d].Hash mismatch", i)
		}
	}
}

func TestHandleMempoolRequest_ExactBoundary(t *testing.T) {
	peer := &Peer{addr: "127.0.0.1:8333"}
	provider := &fakeMempoolProvider{hashes: makeHashes(MaxInvVects)}
	invs := HandleMempoolRequest(peer, provider)
	if len(invs) != 1 {
		t.Fatalf("expected exactly 1 inv at boundary, got %d", len(invs))
	}
	if len(invs[0].InvList) != MaxInvVects {
		t.Fatalf("expected %d entries, got %d", MaxInvVects, len(invs[0].InvList))
	}
}

func TestHandleMempoolRequest_MultiBatch(t *testing.T) {
	peer := &Peer{addr: "127.0.0.1:8333"}
	// 2.5 batches → 3 inv messages.
	count := MaxInvVects*2 + MaxInvVects/2
	provider := &fakeMempoolProvider{hashes: makeHashes(count)}
	invs := HandleMempoolRequest(peer, provider)
	if len(invs) != 3 {
		t.Fatalf("expected 3 invs, got %d", len(invs))
	}
	if len(invs[0].InvList) != MaxInvVects {
		t.Errorf("inv[0] size = %d, want %d", len(invs[0].InvList), MaxInvVects)
	}
	if len(invs[1].InvList) != MaxInvVects {
		t.Errorf("inv[1] size = %d, want %d", len(invs[1].InvList), MaxInvVects)
	}
	if len(invs[2].InvList) != MaxInvVects/2 {
		t.Errorf("inv[2] size = %d, want %d", len(invs[2].InvList), MaxInvVects/2)
	}

	// Verify no hash is duplicated across batches.
	seen := make(map[wire.Hash256]bool, count)
	for _, inv := range invs {
		for _, iv := range inv.InvList {
			if seen[iv.Hash] {
				t.Fatalf("duplicate hash across batches: %x", iv.Hash)
			}
			seen[iv.Hash] = true
		}
	}
	if len(seen) != count {
		t.Errorf("expected %d unique hashes, got %d", count, len(seen))
	}
}

// TestPeerDispatchesMempool verifies the peer dispatcher invokes the
// OnMempool listener when a "mempool" message arrives.  This is the
// regression test for BIP35 — prior to W-mempool the message-type
// registry knew about MsgMempool but the dispatcher silently dropped it.
func TestPeerDispatchesMempool(t *testing.T) {
	var fired bool
	peer := &Peer{
		state: PeerStateConnected,
		config: PeerConfig{
			Listeners: &PeerListeners{
				OnMempool: func(_ *Peer, _ *MsgMempool) {
					fired = true
				},
			},
		},
	}
	peer.handleMessage(&MsgMempool{})
	if !fired {
		t.Fatal("OnMempool listener was not invoked by handleMessage")
	}
}
