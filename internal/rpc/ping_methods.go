package rpc

import (
	"encoding/json"
)

// handlePing implements the ping RPC.
//
//	ping
//
// Faithful port of bitcoin-core/src/rpc/net.cpp:84-107 (ping) ->
// PeerManager::SendPings (net_processing.cpp). A side-effect-only control
// method: it requests that a BIP-31 PING be sent to every currently-connected
// peer to measure round-trip time, then returns immediately.
//
// SEMANTICS (Core parity):
//   - No params. RPCHelpMan declares {} (no arguments); any positional argument
//     is a dispatcher arity error, never a silent accept.
//   - Returns JSON null (Core UniValue::VNULL). It does NOT measure latency
//     synchronously and does NOT wait for the PONGs. Core only QUEUES a ping
//     per peer (sets m_ping_queued) and returns; blockbrew's equivalent is to
//     enqueue one MsgPing per peer on each peer's send queue (Peer.SendPing,
//     fire-and-forget). The round-trip results surface LATER via getpeerinfo's
//     pingtime / minping fields once the matching pong is received.
//   - Zero peers is a successful no-op (still returns null) — Core's
//     ForEachNode loop simply iterates nothing.
//   - A missing peer manager is P2P-disabled: -31 RPC_CLIENT_P2P_DISABLED
//     (Core EnsureConnman / EnsurePeerman, protocol.h:64), not an empty
//     success.
//
// NOT consensus.
func (s *Server) handlePing(params json.RawMessage) (interface{}, *RPCError) {
	// No params accepted. Tolerate an absent/empty list and the JSON-RPC
	// `null`/`[]` forms (the dispatcher passes either), but reject any
	// positional argument — Core's ping takes {} and a supplied arg is a
	// "too many parameters" error.
	if len(params) > 0 {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}
		if len(args) > 0 {
			return nil, &RPCError{
				Code:    RPCErrInvalidParams,
				Message: "ping takes no parameters",
			}
		}
	}

	// EnsurePeerman parity: a missing peer manager means P2P is disabled.
	if s.peerMgr == nil {
		return nil, &RPCError{
			Code:    RPCErrClientP2PDisabled,
			Message: "Error: Peer-to-peer functionality missing or disabled",
		}
	}

	// Request a ping from every connected peer (Core PeerManager::SendPings
	// iterates ForEachNode and flags m_ping_queued; the actual send happens on
	// the next message pass). blockbrew's SendPing is itself fire-and-forget
	// (it queues one MsgPing on the peer's send queue and returns), so a single
	// pass over the live peer set matches Core's observable behaviour: pingwait
	// goes non-zero now, pingtime/minping populate after the pongs land. A
	// per-peer failure (e.g. a peer dropping mid-iteration) cannot fail the RPC
	// — SendPing swallows its own errors and we never block on a response.
	for _, p := range s.peerMgr.ConnectedPeers() {
		p.SendPing()
	}

	// Core returns UniValue::VNULL -> JSON null. Returning a typed nil here
	// serialises as {"result": null}.
	return nil, nil
}
