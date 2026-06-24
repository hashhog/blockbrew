package rpc

import (
	"encoding/json"
)

// AddrmanNetworkInfo is one per-network value object in the getaddrmaninfo
// response. Mirrors Bitcoin Core's per-network OBJ in rpc/net.cpp:1103-1106
// (pushKV order: new, tried, total). All three are non-negative integer
// counts; total == new + tried by construction.
type AddrmanNetworkInfo struct {
	New   int `json:"new"`
	Tried int `json:"tried"`
	Total int `json:"total"`
}

// addrmanNetworkKeys is the FIXED, always-present routable-network key set
// emitted by getaddrmaninfo, in Core's enum order
// (NET_IPV4, NET_IPV6, NET_ONION, NET_I2P, NET_CJDNS — skipping
// NET_UNROUTABLE / NET_INTERNAL). Core emits a key for every routable network
// unconditionally, even when the count is zero (rpc/net.cpp:1100-1107), so an
// IPv4/IPv6-only impl still reports onion/i2p/cjdns as {0,0,0}. The final
// all_networks key is appended separately.
var addrmanNetworkKeys = []string{"ipv4", "ipv6", "onion", "i2p", "cjdns"}

// handleGetAddrmanInfo implements the getaddrmaninfo RPC.
//
//	getaddrmaninfo
//
// Faithful port of bitcoin-core/src/rpc/net.cpp:1080-1117. PURE read-only
// snapshot of the address manager — no params, no side effects (no mutate, no
// peers/sockets/disk, no node-state toggle). NOT consensus.
//
// Returns a JSON object keyed by network name. The key set is FIXED and always
// present, in this insertion order:
//
//	ipv4, ipv6, onion, i2p, cjdns, all_networks
//
// Each value is an object with exactly three integer keys, in order:
//
//	{ "new":   <count in new table>,    // Size(net, in_new=true)
//	  "tried": <count in tried table>,  // Size(net, in_new=false)
//	  "total": <new + tried> }          // Size(net)
//
// all_networks is the global sum across networks (new = Σ new, tried = Σ tried,
// total = Σ total). NET_UNROUTABLE (not_publicly_routable) and NET_INTERNAL
// (internal) are never emitted, matching Core's loop that skips those two enum
// values.
//
// new/tried split (see caveats): blockbrew stores addresses in a flat
// AddressBook rather than Core's bucketed new/tried tables, but the SAME
// semantic distinction is available per entry: an address we have successfully
// connected to in the past (KnownAddress.LastSuccess non-zero) is a "tried"
// entry; an address we have only discovered but not yet successfully connected
// to (LastSuccess zero) is a "new" entry. This mirrors Core's table semantics
// ("tried" = peers successfully connected to before; "new" = discovered
// potential peers) exactly, and is the same LastSuccess predicate the existing
// Good()/ShareableCount() helpers use. So the split is genuine, not lumped.
//
// Network classification reuses networkNameForIP (GetNetClass parity); entries
// that classify to not_publicly_routable / internal are skipped, matching
// Core. blockbrew's AddressBook only persists IPv4/IPv6 entries (Tor v3 / I2P /
// CJDNS are dropped at AddAddressV2), so onion/i2p/cjdns are always {0,0,0}
// here — but the keys are emitted regardless to preserve Core's exact shape.
func (s *Server) handleGetAddrmanInfo(params json.RawMessage) (interface{}, *RPCError) {
	// getaddrmaninfo takes NO params. Tolerate an empty/absent param list;
	// reject any supplied positional argument with the standard arity error.
	if len(params) > 0 {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}
		if len(args) > 0 {
			return nil, &RPCError{
				Code:    RPCErrInvalidParams,
				Message: "getaddrmaninfo takes no parameters",
			}
		}
	}

	// Pre-seed every routable network at {new:0, tried:0} so the key set is
	// always complete even when the addrman is empty or unavailable.
	newCounts := make(map[string]int, len(addrmanNetworkKeys))
	triedCounts := make(map[string]int, len(addrmanNetworkKeys))
	for _, k := range addrmanNetworkKeys {
		newCounts[k] = 0
		triedCounts[k] = 0
	}

	// Walk the address book (when available) and bucket each routable entry by
	// (network, table). An unavailable peer manager / address book is treated
	// the same as an empty addrman: all-zero counts, full key set still emitted
	// (Core would error with "address manager disabled" in that case, but
	// blockbrew always runs an in-process addrman, so the zero-snapshot is the
	// faithful steady-state answer; the never-disabled path keeps the RPC a
	// pure read).
	if s.peerMgr != nil {
		if book := s.peerMgr.AddressBook(); book != nil {
			for _, ka := range book.AllAddresses() {
				netName := networkNameForIP(ka.Addr.IP)
				// Skip not_publicly_routable / internal (and any non-routable
				// class), matching Core's loop that emits only the routable
				// networks.
				if _, ok := newCounts[netName]; !ok {
					continue
				}
				if !ka.LastSuccess.IsZero() {
					// Successfully connected before => tried table.
					triedCounts[netName]++
				} else {
					// Discovered but never connected => new table.
					newCounts[netName]++
				}
			}
		}
	}

	// Build the ordered result. Go's encoding/json marshals map keys in sorted
	// order, which would NOT preserve Core's enum insertion order, so emit an
	// ordered list of key/value pairs via json.RawMessage assembly.
	ret := newOrderedAddrmanInfo()
	totalNew, totalTried := 0, 0
	for _, k := range addrmanNetworkKeys {
		n, t := newCounts[k], triedCounts[k]
		ret.add(k, AddrmanNetworkInfo{New: n, Tried: t, Total: n + t})
		totalNew += n
		totalTried += t
	}
	ret.add("all_networks", AddrmanNetworkInfo{
		New:   totalNew,
		Tried: totalTried,
		Total: totalNew + totalTried,
	})

	return ret.build()
}

// orderedAddrmanInfo accumulates (network -> {new,tried,total}) pairs in
// insertion order and renders them to a single JSON object that preserves that
// order (Go maps would re-sort the keys). It is a tiny local helper rather than
// a general ordered-map type because getaddrmaninfo is the only caller.
type orderedAddrmanInfo struct {
	keys []string
	vals []AddrmanNetworkInfo
}

func newOrderedAddrmanInfo() *orderedAddrmanInfo {
	return &orderedAddrmanInfo{
		keys: make([]string, 0, len(addrmanNetworkKeys)+1),
		vals: make([]AddrmanNetworkInfo, 0, len(addrmanNetworkKeys)+1),
	}
}

func (o *orderedAddrmanInfo) add(key string, v AddrmanNetworkInfo) {
	o.keys = append(o.keys, key)
	o.vals = append(o.vals, v)
}

// build renders the accumulated pairs to a json.RawMessage object with the keys
// in insertion order. Returning json.RawMessage lets the RPC server emit the
// bytes verbatim, preserving Core's key ordering.
func (o *orderedAddrmanInfo) build() (interface{}, *RPCError) {
	buf := make([]byte, 0, 256)
	buf = append(buf, '{')
	for i, k := range o.keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: "Internal JSON-RPC error"}
		}
		buf = append(buf, kb...)
		buf = append(buf, ':')
		vb, err := json.Marshal(o.vals[i])
		if err != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: "Internal JSON-RPC error"}
		}
		buf = append(buf, vb...)
	}
	buf = append(buf, '}')
	return json.RawMessage(buf), nil
}
