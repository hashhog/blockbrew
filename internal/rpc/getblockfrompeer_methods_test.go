package rpc

import (
	"encoding/json"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/p2p"
	"github.com/hashhog/blockbrew/internal/wire"
)

// mockFetchPeer records every message SendMessage receives so the test can
// assert the genuine getdata reached the resolved peer. It satisfies the
// rpc-package fetchPeer interface (IsConnected + SendMessage).
type mockFetchPeer struct {
	connected bool
	sent      []p2p.Message
}

func (m *mockFetchPeer) IsConnected() bool           { return m.connected }
func (m *mockFetchPeer) SendMessage(msg p2p.Message) { m.sent = append(m.sent, msg) }

// mockFetchLister returns a fixed peer slice in a deterministic order, exactly
// mirroring how peerMgr.ConnectedPeers() feeds getpeerinfo's `id: i` indexing.
type mockFetchLister struct {
	peers []fetchPeer
}

func (l *mockFetchLister) ConnectedFetchPeers() []fetchPeer { return l.peers }

// newGetBlockFromPeerRig builds a Server with a header-only index (one extra
// header on top of regtest genesis, with NO block body stored) plus an
// injected peer list. Returning the known header hash lets the test exercise
// the success path; chainDB is left nil so the "Block already downloaded"
// short-circuit never fires (body genuinely absent — the realistic state in
// which an operator calls getblockfrompeer).
func newGetBlockFromPeerRig(t *testing.T, peers []fetchPeer) (*Server, wire.Hash256) {
	t.Helper()

	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// Register one header above genesis so HasHeader(knownHash) == true
	// but no body is stored anywhere.
	blk := buildRegtestBlock(t, params, idx.Genesis())
	if _, err := idx.AddHeader(blk.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	knownHash := blk.Header.BlockHash()

	srv := NewServer(
		RPCConfig{ListenAddr: "127.0.0.1:0"},
		WithChainParams(params),
		WithHeaderIndex(idx),
	)
	srv.blockFetchPeers = &mockFetchLister{peers: peers}

	return srv, knownHash
}

func callGetBlockFromPeer(t *testing.T, srv *Server, blockhash string, peerID int) (interface{}, *RPCError) {
	t.Helper()
	params, err := json.Marshal([]interface{}{blockhash, peerID})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	return srv.handleGetBlockFromPeer(params)
}

// (a) Unknown header -> RPC_MISC_ERROR(-1) "Block header missing".
func TestGetBlockFromPeerUnknownHeader(t *testing.T) {
	peer := &mockFetchPeer{connected: true}
	srv, _ := newGetBlockFromPeerRig(t, []fetchPeer{peer})

	// A hash that is NOT in the header index.
	var unknown wire.Hash256
	unknown[0] = 0xde
	unknown[1] = 0xad

	_, rpcErr := callGetBlockFromPeer(t, srv, unknown.String(), 0)
	if rpcErr == nil {
		t.Fatal("expected error for unknown header, got nil")
	}
	if rpcErr.Code != RPCErrMisc {
		t.Errorf("code = %d, want %d (RPC_MISC_ERROR)", rpcErr.Code, RPCErrMisc)
	}
	if rpcErr.Message != "Block header missing" {
		t.Errorf("message = %q, want %q", rpcErr.Message, "Block header missing")
	}
	if len(peer.sent) != 0 {
		t.Errorf("no getdata should be sent on error; got %d messages", len(peer.sent))
	}
}

// (b) peer_id out of range / disconnected -> RPC_MISC_ERROR(-1) "Peer does not exist".
func TestGetBlockFromPeerPeerNotFound(t *testing.T) {
	// One connected peer at index 0; index 1 is out of range.
	peer := &mockFetchPeer{connected: true}
	srv, knownHash := newGetBlockFromPeerRig(t, []fetchPeer{peer})

	t.Run("out of range", func(t *testing.T) {
		_, rpcErr := callGetBlockFromPeer(t, srv, knownHash.String(), 1)
		if rpcErr == nil {
			t.Fatal("expected error for out-of-range peer_id, got nil")
		}
		if rpcErr.Code != RPCErrMisc || rpcErr.Message != "Peer does not exist" {
			t.Errorf("got (%d, %q), want (%d, %q)", rpcErr.Code, rpcErr.Message, RPCErrMisc, "Peer does not exist")
		}
	})

	t.Run("negative", func(t *testing.T) {
		_, rpcErr := callGetBlockFromPeer(t, srv, knownHash.String(), -1)
		if rpcErr == nil || rpcErr.Message != "Peer does not exist" {
			t.Fatalf("want Peer does not exist, got %+v", rpcErr)
		}
	})

	t.Run("disconnected", func(t *testing.T) {
		// Valid index but the peer reports not-connected -> still "Peer does
		// not exist" (mirrors Core's GetPeerRef returning nullptr for a peer
		// that has been disconnected).
		gonePeer := &mockFetchPeer{connected: false}
		srv2, hash2 := newGetBlockFromPeerRig(t, []fetchPeer{gonePeer})
		_, rpcErr := callGetBlockFromPeer(t, srv2, hash2.String(), 0)
		if rpcErr == nil || rpcErr.Message != "Peer does not exist" {
			t.Fatalf("want Peer does not exist for disconnected peer, got %+v", rpcErr)
		}
		if len(gonePeer.sent) != 0 {
			t.Errorf("no getdata should be sent to a disconnected peer; got %d", len(gonePeer.sent))
		}
	})
}

// (c) Success: sends a witness-block getdata for the hash to the RESOLVED peer
// (and only that peer) and returns {} (empty object).
func TestGetBlockFromPeerSuccess(t *testing.T) {
	peer0 := &mockFetchPeer{connected: true}
	peer1 := &mockFetchPeer{connected: true}
	srv, knownHash := newGetBlockFromPeerRig(t, []fetchPeer{peer0, peer1})

	// Target peer index 1 to prove peer_id resolves to the correct slot
	// (the same index getpeerinfo would report).
	result, rpcErr := callGetBlockFromPeer(t, srv, knownHash.String(), 1)
	if rpcErr != nil {
		t.Fatalf("unexpected error: %+v", rpcErr)
	}

	// Returns {} — an empty JSON object, byte-for-byte.
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if string(raw) != "{}" {
		t.Errorf("result = %s, want {}", raw)
	}

	// The resolved peer (index 1) got exactly one message...
	if len(peer1.sent) != 1 {
		t.Fatalf("resolved peer got %d messages, want 1", len(peer1.sent))
	}
	// ...and NO other peer was touched (fire-and-forget to THAT peer only).
	if len(peer0.sent) != 0 {
		t.Errorf("non-targeted peer got %d messages, want 0", len(peer0.sent))
	}

	// The message is a getdata...
	gd, ok := peer1.sent[0].(*p2p.MsgGetData)
	if !ok {
		t.Fatalf("sent message type = %T, want *p2p.MsgGetData", peer1.sent[0])
	}
	if gd.Command() != "getdata" {
		t.Errorf("command = %q, want getdata", gd.Command())
	}
	// ...for exactly one inv vector: MSG_BLOCK | MSG_WITNESS_FLAG + the hash.
	if len(gd.InvList) != 1 {
		t.Fatalf("getdata has %d inv vectors, want 1", len(gd.InvList))
	}
	iv := gd.InvList[0]
	if iv.Type != p2p.InvTypeWitnessBlock {
		t.Errorf("inv type = %#x, want %#x (MSG_BLOCK|MSG_WITNESS_FLAG)", uint32(iv.Type), uint32(p2p.InvTypeWitnessBlock))
	}
	if iv.Hash != knownHash {
		t.Errorf("inv hash = %s, want %s", iv.Hash.String(), knownHash.String())
	}
}
