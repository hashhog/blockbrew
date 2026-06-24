package rpc

import (
	"encoding/json"
)

// AddedNodeAddress is one entry in the per-node "addresses" array of the
// getaddednodeinfo response. Mirrors Bitcoin Core's inner OBJ in
// rpc/net.cpp:546-549 (pushKV order: address, connected). The inner
// "connected" is the bare DIRECTION string — "inbound" or "outbound"
// (net.cpp:548, info.fInbound ? "inbound" : "outbound") — NOT a connection
// subtype like "manual"/"feeler"/"outbound-full-relay".
type AddedNodeAddress struct {
	Address   string `json:"address"`   // resolved IP:port we're connected to
	Connected string `json:"connected"` // "inbound" | "outbound"
}

// AddedNodeInfo is one element of the getaddednodeinfo response array. Mirrors
// Bitcoin Core's per-node OBJ in rpc/net.cpp:541-552 (pushKV order: addednode,
// connected, addresses). "addresses" is ALWAYS present: empty when
// connected=false, exactly one entry when connected=true.
type AddedNodeInfo struct {
	AddedNode string             `json:"addednode"` // node string exactly as given to addnode
	Connected bool               `json:"connected"` // a current peer matches
	Addresses []AddedNodeAddress `json:"addresses"` // [] when not connected; one entry when connected
}

// handleGetAddedNodeInfo implements the getaddednodeinfo RPC.
//
//	getaddednodeinfo ( "node" )
//
// Faithful port of bitcoin-core/src/rpc/net.cpp:486-558 +
// CConnman::GetAddedNodeInfo (net.cpp:2914). PURE read of the addnode-managed
// persistent-peer list joined against the live peer table — no side effects.
// NOT consensus.
//
// Returns a JSON ARRAY of objects, one per persistent added node, in insertion
// order. Each element, keys in this order:
//
//	{ "addednode": <str>,   // node IP/hostname exactly as passed to addnode
//	  "connected": <bool>,  // true if a current peer matches
//	  "addresses": [        // ALWAYS present; [] when connected=false
//	    { "address": <str ip:port>,
//	      "connected": "inbound" | "outbound" }   // at most ONE entry
//	  ] }
//
// Empty [] when there are no persistent added nodes (the empty-state gate —
// byte-identical to Core). onetry adds are NOT on the list (Core parity:
// net.cpp OpenNetworkConnection only; blockbrew's handleAddNode "onetry" case
// calls ConnectManualPeer without AddAddedNode), so they never appear here.
//
// Optional positional "node" filter (STR): when provided, return only the
// single added node whose original string EXACTLY equals it (string equality
// against the value passed to addnode — net.cpp:527, NOT a resolved-address
// comparison). A requested node that is not on the added list raises -24
// RPC_CLIENT_NODE_NOT_ADDED with the exact message
// "Error: Node has not been added." (net.cpp:533-534). When "node" is omitted,
// no not-found is possible — [] is a valid answer.
func (s *Server) handleGetAddedNodeInfo(params json.RawMessage) (interface{}, *RPCError) {
	// Parse the optional positional "node" filter. Tolerate an empty/absent
	// param list. A supplied first argument must be a JSON string (Core's
	// node arg is STR); a non-string is the standard type error.
	var nodeFilter string
	haveFilter := false
	if len(params) > 0 {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}
		if len(args) > 0 && args[0] != nil {
			f, ok := args[0].(string)
			if !ok {
				return nil, &RPCError{
					Code:    RPCErrTypeError,
					Message: "JSON value is not a string as expected",
				}
			}
			nodeFilter = f
			haveFilter = true
		}
	}

	// Snapshot the persistent added-node list (insertion order, the raw
	// operator strings — Core's m_added_node_params). onetry adds are not on
	// this list (handleAddNode "onetry" never calls AddAddedNode), so they are
	// naturally excluded.
	var added []string
	if s.peerMgr != nil {
		added = s.peerMgr.AddedNodes()
	}

	// Build a lookup of currently-connected peers keyed by their resolved
	// remote address (IP:port) -> inbound? This is the live peer table Core's
	// GetAddedNodeInfo joins the added list against. blockbrew's peer map is
	// keyed by the same IP:port string a numeric addnode entry carries, so an
	// exact-string match of the added entry against a connected peer's
	// Address() decides connected/direction (net.cpp matches by resolved
	// CService for numeric entries / by addr_name for hostnames; blockbrew's
	// added strings for the verified case are numeric IP:port).
	connected := make(map[string]bool) // addr -> inbound?
	if s.peerMgr != nil {
		for _, p := range s.peerMgr.ConnectedPeers() {
			connected[p.Address()] = p.Inbound()
		}
	}

	// Apply the optional "node" filter: exact string equality against the
	// added list (Core net.cpp:527). Miss -> -24 "Error: Node has not been
	// added." When omitted, all added nodes are emitted in insertion order.
	if haveFilter {
		found := false
		for _, n := range added {
			if n == nodeFilter {
				found = true
				break
			}
		}
		if !found {
			return nil, &RPCError{
				Code:    RPCErrClientNodeNotAdded,
				Message: "Error: Node has not been added.",
			}
		}
		added = []string{nodeFilter}
	}

	// Emit one element per added node. addresses is ALWAYS present; it holds
	// exactly one entry when a live peer matches, and is empty otherwise.
	ret := make([]AddedNodeInfo, 0, len(added))
	for _, n := range added {
		inbound, isConnected := connected[n]
		addresses := []AddedNodeAddress{}
		if isConnected {
			direction := "outbound"
			if inbound {
				direction = "inbound"
			}
			addresses = append(addresses, AddedNodeAddress{
				Address:   n,
				Connected: direction,
			})
		}
		ret = append(ret, AddedNodeInfo{
			AddedNode: n,
			Connected: isConnected,
			Addresses: addresses,
		})
	}

	return ret, nil
}
