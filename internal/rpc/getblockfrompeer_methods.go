package rpc

import (
	"encoding/json"

	"github.com/hashhog/blockbrew/internal/p2p"
	"github.com/hashhog/blockbrew/internal/wire"
)

// getblockfrompeer mirrors Bitcoin Core's
// bitcoin-core/src/rpc/blockchain.cpp::getblockfrompeer +
// bitcoin-core/src/net_processing.cpp::PeerManagerImpl::FetchBlock.
//
// Contract (Core-faithful):
//
//   getblockfrompeer(blockhash hex, peer_id int) -> {}  (empty object)
//
//   1. The block's HEADER must already be known, else
//      RPC_MISC_ERROR(-1) "Block header missing"
//      (blockchain.cpp:547 — !LookupBlockIndex).
//   2. Resolve peer_id to a connected peer, else
//      RPC_MISC_ERROR(-1) "Peer does not exist"
//      (net_processing.cpp:1966 — GetPeerRef == nullptr).
//   3. If the block body is already stored, short-circuit with
//      RPC_MISC_ERROR(-1) "Block already downloaded"
//      (blockchain.cpp:558 — BLOCK_HAVE_DATA).
//   4. On success, fire-and-forget a getdata to THAT peer for
//      CInv(MSG_BLOCK | MSG_WITNESS_FLAG, hash) (net_processing.cpp:1981)
//      and return {} (blockchain.cpp:564 — UniValue::VOBJ).
//
// peer_id convention: blockbrew's Peer has no numeric id; getpeerinfo
// (methods.go::handleGetPeerInfo) assigns each connected peer the index i
// into peerMgr.ConnectedPeers() as its `id`. This handler resolves peer_id
// against the SAME slice so that the peer_id an operator passes is exactly
// the id they read from getpeerinfo.

// fetchPeer is the narrow capability getblockfrompeer needs from a peer:
// liveness plus the ability to enqueue an outbound message. *p2p.Peer
// satisfies it (IsConnected + SendMessage). The interface keeps the handler
// unit-testable without a live socket.
type fetchPeer interface {
	IsConnected() bool
	SendMessage(msg p2p.Message)
}

// fetchPeerLister enumerates the connected peers in the same order and with
// the same indexing getpeerinfo uses. *p2p.PeerManager is wrapped to satisfy
// it in production; tests inject a deterministic implementation.
type fetchPeerLister interface {
	ConnectedFetchPeers() []fetchPeer
}

// peerMgrFetchAdapter adapts the concrete *p2p.PeerManager to fetchPeerLister
// while preserving the exact ConnectedPeers() ordering getpeerinfo relies on.
type peerMgrFetchAdapter struct {
	pm *p2p.PeerManager
}

func (a peerMgrFetchAdapter) ConnectedFetchPeers() []fetchPeer {
	peers := a.pm.ConnectedPeers()
	out := make([]fetchPeer, len(peers))
	for i, p := range peers {
		out[i] = p
	}
	return out
}

// connectedFetchPeers returns the peer list to resolve peer_id against,
// preferring the test seam when present.
func (s *Server) connectedFetchPeers() []fetchPeer {
	if s.blockFetchPeers != nil {
		return s.blockFetchPeers.ConnectedFetchPeers()
	}
	if s.peerMgr == nil {
		return nil
	}
	return peerMgrFetchAdapter{pm: s.peerMgr}.ConnectedFetchPeers()
}

func (s *Server) handleGetBlockFromPeer(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters: [blockhash, peer_id]
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "getblockfrompeer requires blockhash and peer_id"}
	}

	hashStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid block hash"}
	}
	hash, err := wire.NewHash256FromHex(hashStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid block hash format"}
	}

	// peer_id arrives as a JSON number (float64 over the wire).
	peerIDF, ok := args[1].(float64)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid peer_id"}
	}
	peerID := int(peerIDF)

	// (1) Header must be known, else RPC_MISC_ERROR "Block header missing".
	// blockchain.cpp:546-548 — !LookupBlockIndex(block_hash).
	if s.headerIndex == nil || !s.headerIndex.HasHeader(hash) {
		return nil, &RPCError{Code: RPCErrMisc, Message: "Block header missing"}
	}

	// (3) If the body is already stored, short-circuit.
	// blockchain.cpp:556-559 — BLOCK_HAVE_DATA. (Core checks this before
	// resolving the peer; we mirror that ordering.)
	if s.chainDB != nil && s.chainDB.HasBlock(hash) {
		return nil, &RPCError{Code: RPCErrMisc, Message: "Block already downloaded"}
	}

	// (2) Resolve peer_id against the same slice getpeerinfo enumerates,
	// else RPC_MISC_ERROR "Peer does not exist".
	// net_processing.cpp:1964-1966 — GetPeerRef(peer_id) == nullptr.
	peers := s.connectedFetchPeers()
	if peerID < 0 || peerID >= len(peers) {
		return nil, &RPCError{Code: RPCErrMisc, Message: "Peer does not exist"}
	}
	peer := peers[peerID]
	if peer == nil || !peer.IsConnected() {
		return nil, &RPCError{Code: RPCErrMisc, Message: "Peer does not exist"}
	}

	// (4) Fire-and-forget a block getdata to THAT peer.
	// net_processing.cpp:1980-1987 — CInv(MSG_BLOCK | MSG_WITNESS_FLAG, hash)
	// pushed as a GETDATA. InvTypeWitnessBlock == 0x40000002 is exactly
	// MSG_BLOCK(2) | MSG_WITNESS_FLAG(0x40000000).
	getdata := &p2p.MsgGetData{
		InvList: []*p2p.InvVect{
			{Type: p2p.InvTypeWitnessBlock, Hash: hash},
		},
	}
	peer.SendMessage(getdata)

	// blockchain.cpp:564 — return UniValue::VOBJ (empty object).
	return map[string]interface{}{}, nil
}
