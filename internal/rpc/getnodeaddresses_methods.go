package rpc

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hashhog/blockbrew/internal/p2p"
)

// NodeAddressResult is one element of the getnodeaddresses response array.
//
// Mirrors Bitcoin Core's getnodeaddresses object shape exactly
// (bitcoin-core/src/rpc/net.cpp:958-965). The five keys are emitted in
// Core's pushKV order: time, services, address, port, network.
//
// Notably "services" is the RAW services bitfield as an INTEGER (e.g. 1033),
// NOT a hex string (getpeerinfo emits hex; getnodeaddresses does not). "time"
// is unix seconds as an integer.
type NodeAddressResult struct {
	Time     int64  `json:"time"`
	Services uint64 `json:"services"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Network  string `json:"network"`
}

// networkNameForIP maps a stored IP to the Core network-class string emitted by
// getnodeaddresses (GetNetworkName(addr.GetNetClass()), netbase.cpp:114-128).
//
// blockbrew's AddressBook stores IPv4/IPv6 addresses in net.IP form (Tor/I2P/
// CJDNS gossip-learned addresses are not persisted in the legacy book — see
// AddressBook.AddAddressV2), so a stored, routable address is "ipv4" or "ipv6".
// Non-routable / unspecified addresses map to Core's "not_publicly_routable",
// matching GetNetClass which returns NET_UNROUTABLE for non-routable hosts.
func networkNameForIP(ip net.IP) string {
	if ip == nil {
		return "not_publicly_routable"
	}
	if !p2p.IsRoutableIP(ip) {
		return "not_publicly_routable"
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

// parseNetworkFilter lowercases the requested network and returns the Core
// network-class string it maps to, mirroring ParseNetwork (netbase.cpp:100-112).
// Only ipv4|ipv6|onion|i2p|cjdns are valid input filters; anything else maps to
// NET_UNROUTABLE which the caller treats as an error. ok is false for the
// unrecognized case.
func parseNetworkFilter(net string) (canonical string, ok bool) {
	switch strings.ToLower(net) {
	case "ipv4":
		return "ipv4", true
	case "ipv6":
		return "ipv6", true
	case "onion":
		return "onion", true
	case "i2p":
		return "i2p", true
	case "cjdns":
		return "cjdns", true
	default:
		return "", false
	}
}

// handleGetNodeAddresses implements the getnodeaddresses RPC.
//
//	getnodeaddresses ( count "network" )
//
// Faithful port of bitcoin-core/src/rpc/net.cpp:911-968. Read-only addrman
// dump — NOT consensus. Returns a JSON array of {time, services, address,
// port, network} objects sourced from the address book.
//
// Semantics (Core, net.cpp:946-967):
//   - count (positional 0, default 1) = MAX addresses to return. count==0 means
//     "return ALL known". count<0 → error -8 "Address count out of range".
//   - network (positional 1, optional, default = all networks): ParseNetwork
//     lowercases and accepts only ipv4|ipv6|onion|i2p|cjdns; any other string →
//     error -8 "Network not recognized: <raw arg>". When set, filters output.
//   - On an empty addrman → [] (empty array, not an error).
//   - The returned order is non-deterministic (Core shuffles via
//     GetAddressesUnsafe); callers must treat ordering as undefined.
func (s *Server) handleGetNodeAddresses(params json.RawMessage) (interface{}, *RPCError) {
	// Parse positional args. Both optional.
	var args []interface{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}
	}

	// --- count (positional 0, default 1) ---
	count := 1
	if len(args) >= 1 && args[0] != nil {
		cf, ok := args[0].(float64)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "count must be a number"}
		}
		count = int(cf)
	}
	if count < 0 {
		// Core: RPC_INVALID_PARAMETER (-8), net.cpp:947.
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Address count out of range"}
	}

	// --- network (positional 1, optional) ---
	var filter string // "" = all networks
	if len(args) >= 2 && args[1] != nil {
		netArg, ok := args[1].(string)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "network must be a string"}
		}
		canonical, recognized := parseNetworkFilter(netArg)
		if !recognized {
			// Core: ParseNetwork returns NET_UNROUTABLE → RPC_INVALID_PARAMETER,
			// net.cpp:950-952. Message uses the RAW (un-lowercased) arg.
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: fmt.Sprintf("Network not recognized: %s", netArg),
			}
		}
		filter = canonical
	}

	// Empty/absent address book → [] (not an error). Return an empty,
	// non-nil slice so it marshals to "[]" rather than "null".
	ret := make([]NodeAddressResult, 0)
	if s.peerMgr == nil {
		return ret, nil
	}
	book := s.peerMgr.AddressBook()
	if book == nil {
		return ret, nil
	}

	// Walk the existing addrman (snapshot copy; order is map-iteration order,
	// which is already non-deterministic in Go — consistent with Core shuffling).
	for _, ka := range book.AllAddresses() {
		na := ka.Addr
		netName := networkNameForIP(na.IP)

		// Network filter (Core applies it inside GetAddressesUnsafe).
		if filter != "" && netName != filter {
			continue
		}

		// "time" — prefer the stored NetAddress.Timestamp (unix seconds, the
		// gossip nTime); fall back to LastSeen when the wire timestamp is unset.
		t := int64(na.Timestamp)
		if t == 0 && !ka.LastSeen.IsZero() {
			t = ka.LastSeen.Unix()
		}

		ret = append(ret, NodeAddressResult{
			Time:     t,
			Services: na.Services,
			Address:  addrStringForIP(na.IP),
			Port:     na.Port,
			Network:  netName,
		})

		// count==0 means "return ALL"; otherwise cap at count.
		if count != 0 && len(ret) >= count {
			break
		}
	}

	return ret, nil
}

// addrStringForIP renders the bare host literal Core would emit via
// ToStringAddr (netbase: ip literal, no port). For an IPv4-mapped IPv6 address
// blockbrew stores the 16-byte form; net.IP.String already prints the dotted
// IPv4 literal for those, matching Core.
func addrStringForIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// AddPeerAddressResult is the addpeeraddress response object
// (bitcoin-core/src/rpc/net.cpp:981-986). "error" is optional and only present
// when the address could not be added.
type AddPeerAddressResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// handleAddPeerAddress implements the addpeeraddress RPC.
//
//	addpeeraddress "address" port ( tried )
//
// Minimal Core-shaped companion to getnodeaddresses
// (bitcoin-core/src/rpc/net.cpp:972-1030). "This RPC is for testing only" —
// it injects {address, port, services, time} into the existing address book so
// the addrman is deterministically populated for differential tests.
//
// Core inserts with services NODE_NETWORK|NODE_WITNESS (= 9, net.cpp:1009) and
// nTime = now; blockbrew matches with ServiceNodeNetwork|ServiceNodeWitness
// (= 9). Returns {"success": bool}; on an invalid IP Core throws
// RPC_CLIENT_INVALID_IP_OR_SUBNET (-29) "Invalid IP address".
func (s *Server) handleAddPeerAddress(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}
	}
	if len(args) < 2 || args[0] == nil || args[1] == nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "addpeeraddress requires address and port"}
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrTypeError, Message: "address must be a string"}
	}
	portF, ok := args[1].(float64)
	if !ok {
		return nil, &RPCError{Code: RPCErrTypeError, Message: "port must be a number"}
	}
	port := uint16(portF)

	// tried (positional 2, default false). blockbrew has a single flat address
	// book (no new/tried split), so "tried" simply marks the entry as having a
	// successful connection. The Core-shaped param is accepted for parity.
	tried := false
	if len(args) >= 3 && args[2] != nil {
		if b, isBool := args[2].(bool); isBool {
			tried = b
		}
	}

	if s.peerMgr == nil {
		return nil, &RPCError{Code: RPCErrClientP2PDisabled, Message: "P2P networking is disabled"}
	}
	book := s.peerMgr.AddressBook()
	if book == nil {
		return nil, &RPCError{Code: RPCErrClientP2PDisabled, Message: "P2P networking is disabled"}
	}

	ip := net.ParseIP(addrStr)
	if ip == nil {
		// Core: RPC_CLIENT_INVALID_IP_OR_SUBNET (-29) "Invalid IP address".
		return nil, &RPCError{Code: RPCErrClientNodeNotConnected, Message: "Invalid IP address"}
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, &RPCError{Code: RPCErrClientNodeNotConnected, Message: "Invalid IP address"}
	}

	na := p2p.NetAddress{
		Timestamp: uint32(time.Now().Unix()),
		Services:  p2p.ServiceNodeNetwork | p2p.ServiceNodeWitness,
		IP:        ip16,
		Port:      port,
	}

	res := &AddPeerAddressResult{}

	// AddAddress rejects non-routable hosts (Core's addrman also rejects
	// non-routable additions). Detect that to report success=false faithfully.
	before := book.Size()
	book.AddAddress(na, "addpeeraddress")
	key := net.JoinHostPort(ip16.String(), fmt.Sprintf("%d", port))
	ka := book.GetAddress(key)
	if ka == nil {
		// Address rejected (non-routable) and not already present.
		res.Success = false
		res.Error = "failed-adding-to-new"
		return res, nil
	}
	_ = before
	res.Success = true

	if tried {
		// Best-effort "move to tried": mark the address as successfully
		// connected so it scores as a tried-table entry.
		book.MarkSuccess(key)
	}

	return res, nil
}
