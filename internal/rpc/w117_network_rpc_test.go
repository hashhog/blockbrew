package rpc

import "testing"

// W117 G29 / G9 moved here from internal/p2p/w117_bip155_networks_test.go:
// the p2p copies compared hardcoded literals ("gotNetworks", gotNet="ipv4")
// against the wanted values and could never observe production. These call
// the real handlers.

// TestW117_G29_GetNetworkInfoMissingI2PAndCJDNS: Core rpc/net.cpp
// GetNetworksInfo emits one entry per network in NET_IPV4..NET_CJDNS order:
// ipv4, ipv6, onion, i2p, cjdns.
func TestW117_G29_GetNetworkInfoMissingI2PAndCJDNS(t *testing.T) {
	server := NewServer(RPCConfig{ListenAddr: "127.0.0.1:0"})
	res, rpcErr := server.handleGetNetworkInfo()
	if rpcErr != nil {
		t.Fatalf("getnetworkinfo: %v", rpcErr)
	}
	info, ok := res.(*NetworkInfo)
	if !ok {
		t.Fatalf("getnetworkinfo result has type %T, want *NetworkInfo", res)
	}
	want := []string{"ipv4", "ipv6", "onion", "i2p", "cjdns"}
	if len(info.Networks) != len(want) {
		t.Fatalf("networks: got %d entries, want %d (Core rpc/net.cpp GetNetworksInfo)", len(info.Networks), len(want))
	}
	for i, n := range want {
		if info.Networks[i].Name != n {
			t.Errorf("networks[%d] = %q, want %q (Core NET_* enum order)", i, info.Networks[i].Name, n)
		}
	}
	// No proxy is configured for this server, so onion/i2p/cjdns must be
	// reported unreachable (Core init.cpp:1546/1800/2245 remove them without
	// -cjdnsreachable / -onion / -i2psam).
	for _, e := range info.Networks {
		switch e.Name {
		case "ipv4", "ipv6":
			if !e.Reachable {
				t.Errorf("%s reported unreachable", e.Name)
			}
		default:
			if e.Reachable {
				t.Errorf("%s reported reachable with no transport configured", e.Name)
			}
		}
	}
}

// TestW117_G9_GetPeerInfoNetworkFieldHardcoded: Core derives "network" from
// the peer address (rpc/net.cpp GetNetworkName(CNetAddr::GetNetClass())).
func TestW117_G9_GetPeerInfoNetworkFieldHardcoded(t *testing.T) {
	cases := []struct{ addr, want string }{
		{"1.2.3.4:8333", "ipv4"},
		{"[2001:db8::1]:8333", "ipv6"},
		{"[fc01:2:3:4:5:6:7:8]:8333", "cjdns"},
		{"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.onion:8333", "onion"},
		{"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.b32.i2p:0", "i2p"},
	}
	for _, tc := range cases {
		if got := peerNetworkFromAddr(tc.addr); got != tc.want {
			t.Errorf("peerNetworkFromAddr(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}
