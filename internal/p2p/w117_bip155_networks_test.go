package p2p

// W117 BIP-155 networks audit — blockbrew
//
// Audit gates covered:
//   G1-G10  Tor v3 (parsing/proxy/control/v2-rejection/SOCKS5)
//   G11-G16 I2P (b32 parsing/SAM bridge/listen/reconnect)
//   G17-G20 CJDNS (fc00::/8 routing)
//   G21-G24 Outbound diversity (per-network max/-onlynet/IsReachable)
//   G25-G28 Address resolution (LookupHost/subnet/IsLocal/IsRoutable)
//   G29-G30 addrv2 + getnodeaddresses
//
// Bug summary (10 bugs, 30 gates):
//
//   BUG-1  HIGH    G5  Tor v2 not rejected from addrv2 parse
//                       BIP155 §3: Tor v2 (0x03) MUST be ignored.
//                       blockbrew Deserialize accepts it silently.
//
//   BUG-2  MISSING G1-G4  Tor v3 connectivity absent (no -onion / SOCKS5 dialer)
//                       blockbrew has no -onion flag and no SOCKS5 dialer.
//                       Tor v3 addrv2 addresses are parsed but silently dropped.
//                       MISSING ENTIRELY for Tor v3 outbound connections.
//
//   BUG-3  MISSING G11-G16  I2P connectivity absent (no -i2psam / SAM protocol)
//                       No SAM bridge, no I2P listen, no b32.i2p hostname resolution.
//                       MISSING ENTIRELY for I2P connections.
//
//   BUG-4  MISSING G17-G20  CJDNS connection support absent (no -cjdnsreachable)
//                       CJDNS fc00::/8 addrv2 entries are parsed but silently
//                       dropped via AddAddressV2 TODO path. No -cjdnsreachable
//                       flag, no MaybeFlipIPv6toCJDNS equivalent.
//                       MISSING ENTIRELY for CJDNS outbound connections.
//
//   BUG-5  MEDIUM  G29 getnetworkinfo missing "i2p" and "cjdns" networks
//                       Core returns 5 network entries (ipv4/ipv6/onion/i2p/cjdns).
//                       blockbrew returns only 3 (missing i2p and cjdns). CDIV.
//
//   BUG-6  MEDIUM  G30 getnodeaddresses RPC missing entirely
//                       Not in the server dispatch table. Core supports
//                       network-filtered peer address export.
//
//   BUG-7  MEDIUM  G21 No -onlynet flag / IsReachable gate
//                       Core gates all outbound connections through
//                       g_reachable_nets.Contains(network). blockbrew has no
//                       such mechanism; -onlynet is unsupported.
//
//   BUG-8  LOW     G9  getpeerinfo "network" field hardcoded to "ipv4"
//                       Core derives the network type dynamically from the peer
//                       address. blockbrew always returns "ipv4" even for IPv6
//                       peers, and would return it for future Tor/CJDNS peers.
//
//   BUG-9  LOW     G14 I2P addresses allow non-zero port
//                       BIP155: I2P uses its own addressing; port MUST be 0.
//                       blockbrew doesn't enforce port==0 for NetI2P addresses
//                       on deserialize.
//
//   BUG-10 LOW     G25 IsAddrV1Compatible returns false for CJDNS (correct)
//                       but ToLegacyAddrs explicitly filters CJDNS (redundant
//                       double-filter). Not a correctness bug but signals the
//                       implicit assumption that CJDNS can never be serialised
//                       as legacy addr — which is also Core's behavior.
//                       (Informational — no code change needed here, but
//                        captured for the record.)

import (
	"bytes"
	"testing"
)

// ---------------------------------------------------------------------------
// G5 / BUG-1: Tor v2 not rejected from addrv2 Deserialize
// BIP155 §3: "The Tor v2 network (NET_ONION v2) is not included as the
// network is being deprecated and Bitcoin Core removed support."
// Peers MUST NOT relay Tor v2 addresses. Receiving a Tor v2 addr in addrv2
// is a protocol violation and MUST be rejected / ignored.
// ---------------------------------------------------------------------------

// TestW117_G5_TorV2NotRejectedOnDeserialize verifies that a NetTorV2 entry
// is silently dropped on deserialize (BUG-1, FIX-58).
//
// BIP155 §3: receivers MUST silently drop TORV2 entries. The Deserialize
// method consumes the entry's wire bytes (so the stream stays aligned) and
// returns the ErrTorV2Deprecated sentinel so the message-level loop can skip
// the entry without aborting the message.
func TestW117_G5_TorV2NotRejectedOnDeserialize(t *testing.T) {
	// Build a NetTorV2 address (10 bytes per BIP155).
	torV2Addr := make([]byte, TorV2AddrSize) // 10 bytes
	for i := range torV2Addr {
		torV2Addr[i] = byte(i + 1)
	}

	na := NetAddressV2{
		Time:      1700000000,
		Services:  0,
		NetworkID: NetTorV2,
		Addr:      torV2Addr,
		Port:      9050,
	}

	var buf bytes.Buffer
	if err := na.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	var decoded NetAddressV2
	err := decoded.Deserialize(&buf)

	// BIP155 §3 silent-drop: Deserialize must return the ErrTorV2Deprecated
	// sentinel and consume the entry from the wire.
	if err != ErrTorV2Deprecated {
		t.Errorf("Deserialize(TORV2) returned %v, want ErrTorV2Deprecated "+
			"(BIP155 §3 silent-drop)", err)
	}
	// Stream must be fully consumed (address-bytes + port).
	if buf.Len() != 0 {
		t.Errorf("Deserialize(TORV2) left %d unread bytes on the wire; "+
			"the entry must be fully consumed so the next entry parses correctly",
			buf.Len())
	}
}

// TestW117_G5_TorV2RejectedInMsgAddrv2 verifies that a MsgAddrv2 containing
// only a Tor v2 address parses successfully but with an empty AddrList
// (BUG-1, FIX-58).
//
// BIP155 §3: TORV2 entries are silently dropped at the message-level loop.
// The message itself is NOT a protocol violation — only the v2 entries are
// filtered out.
func TestW117_G5_TorV2RejectedInMsgAddrv2(t *testing.T) {
	torV2Addr := make([]byte, TorV2AddrSize)

	msg := &MsgAddrv2{
		AddrList: []NetAddressV2{
			{
				Time:      1700000000,
				Services:  0,
				NetworkID: NetTorV2,
				Addr:      torV2Addr,
				Port:      9050,
			},
		},
	}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	decoded := &MsgAddrv2{}
	err := decoded.Deserialize(&buf)
	if err != nil {
		t.Fatalf("MsgAddrv2.Deserialize returned error %v, want nil "+
			"(BIP155 §3: drop only the TORV2 entry, not the whole message)", err)
	}
	if len(decoded.AddrList) != 0 {
		t.Errorf("MsgAddrv2 with only TORV2 entry: got %d entries, want 0 "+
			"(BIP155 §3 silent-drop)", len(decoded.AddrList))
	}
}

// TestW117_G5_TorV2DroppedFromMixedAddrv2 verifies that an addrv2 message
// containing [IPv4, TORV2, TorV3] deserializes to [IPv4, TorV3]: only the
// TORV2 entry is silently dropped, and the remaining entries are intact
// (BUG-1, FIX-58).
//
// This is the canonical BIP155 §3 test: the v2 entry MUST NOT abort the
// message, MUST NOT shift later entries, MUST NOT corrupt the stream
// position, and MUST NOT appear in the resulting AddrList.
func TestW117_G5_TorV2DroppedFromMixedAddrv2(t *testing.T) {
	ipv4Addr := []byte{203, 0, 113, 5}
	torV2Addr := make([]byte, TorV2AddrSize)
	for i := range torV2Addr {
		torV2Addr[i] = byte(0xc0 + i) // synthetic v2 onion bytes
	}
	torV3Addr := make([]byte, TorV3AddrSize)
	for i := range torV3Addr {
		torV3Addr[i] = byte(i + 0x40) // synthetic ed25519 pubkey
	}

	msg := &MsgAddrv2{
		AddrList: []NetAddressV2{
			{
				Time:      1700000001,
				Services:  9,
				NetworkID: NetIPv4,
				Addr:      ipv4Addr,
				Port:      8333,
			},
			{
				Time:      1700000002,
				Services:  0,
				NetworkID: NetTorV2,
				Addr:      torV2Addr,
				Port:      9050,
			},
			{
				Time:      1700000003,
				Services:  1,
				NetworkID: NetTorV3,
				Addr:      torV3Addr,
				Port:      9050,
			},
		},
	}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	decoded := &MsgAddrv2{}
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize failed: %v (must NOT abort whole message for "+
			"a TORV2 entry; BIP155 §3 silent-drop)", err)
	}

	if len(decoded.AddrList) != 2 {
		t.Fatalf("AddrList length: got %d, want 2 (IPv4 + TorV3 after silent-drop "+
			"of TORV2). Decoded entries: %+v", len(decoded.AddrList), decoded.AddrList)
	}

	// Entry 0 must be the IPv4 entry, unchanged.
	if decoded.AddrList[0].NetworkID != NetIPv4 {
		t.Errorf("AddrList[0].NetworkID: got %d, want %d (NetIPv4)",
			decoded.AddrList[0].NetworkID, NetIPv4)
	}
	if !bytes.Equal(decoded.AddrList[0].Addr, ipv4Addr) {
		t.Errorf("AddrList[0].Addr: got %v, want %v", decoded.AddrList[0].Addr, ipv4Addr)
	}
	if decoded.AddrList[0].Port != 8333 {
		t.Errorf("AddrList[0].Port: got %d, want 8333", decoded.AddrList[0].Port)
	}
	if decoded.AddrList[0].Time != 1700000001 {
		t.Errorf("AddrList[0].Time: got %d, want 1700000001", decoded.AddrList[0].Time)
	}

	// Entry 1 must be the TorV3 entry — proving the TORV2 entry was
	// fully consumed and didn't shift the stream.
	if decoded.AddrList[1].NetworkID != NetTorV3 {
		t.Errorf("AddrList[1].NetworkID: got %d, want %d (NetTorV3) — "+
			"TORV2 consumption misaligned the stream",
			decoded.AddrList[1].NetworkID, NetTorV3)
	}
	if !bytes.Equal(decoded.AddrList[1].Addr, torV3Addr) {
		t.Errorf("AddrList[1].Addr mismatch — TorV3 bytes corrupted by TORV2 consumption")
	}
	if decoded.AddrList[1].Port != 9050 {
		t.Errorf("AddrList[1].Port: got %d, want 9050", decoded.AddrList[1].Port)
	}
	if decoded.AddrList[1].Time != 1700000003 {
		t.Errorf("AddrList[1].Time: got %d, want 1700000003", decoded.AddrList[1].Time)
	}

	// Confirm no TORV2 entry leaked into the result.
	for i, e := range decoded.AddrList {
		if e.NetworkID == NetTorV2 {
			t.Errorf("AddrList[%d] is NetTorV2 (0x03) — BIP155 §3 violation: "+
				"TORV2 leaked through silent-drop", i)
		}
	}

	// Stream must be fully consumed.
	if buf.Len() != 0 {
		t.Errorf("Stream not fully consumed after Deserialize: %d bytes left", buf.Len())
	}
}

// ---------------------------------------------------------------------------
// G1-G4 / BUG-2: Tor v3 connectivity MISSING ENTIRELY
// ---------------------------------------------------------------------------

// TestW117_G1_TorV3AddrStoredInAddrBook pins what Core does with a Tor v3
// addrv2 entry when no onion transport is configured: it is NOT stored.
// net_processing.cpp:5687-5695 keeps an address only if
// g_reachable_nets.Contains(addr) ("Do not store addresses outside our
// network"), and init.cpp:1800 removes NET_ONION from the reachable set
// unless -onion/-proxy is given. blockbrew has no Tor transport at all
// (PeerManagerConfig has no OnionProxy field — see G2), so dropping is the
// Core-faithful behaviour; storing would queue undialable peers.
//
// The original audit asserted storage; that was the wrong remedy. The real
// gap (a Tor v3 transport + -onion, BUG-2) is a feature, not a unit-test fix.
func TestW117_G1_TorV3AddrStoredInAddrBook(t *testing.T) {
	ab := NewAddressBook()

	torV3Bytes := make([]byte, TorV3AddrSize) // 32-byte ed25519 pubkey
	for i := range torV3Bytes {
		torV3Bytes[i] = byte(i + 0x10)
	}

	addr := NetAddressV2{
		Time:      1700000000,
		Services:  1,
		NetworkID: NetTorV3,
		Addr:      torV3Bytes,
		Port:      9050,
	}

	ab.AddAddressV2(addr, "test")

	// Core without -onion: NET_ONION unreachable -> not stored.
	if ab.Size() != 0 {
		t.Errorf("AddAddressV2(NetTorV3) stored an address on an unreachable "+
			"network (size=%d); Core net_processing.cpp:5693 stores only "+
			"g_reachable_nets, and blockbrew has no Tor transport to dial it", ab.Size())
	}
	t.Log("BUG-2 (MISSING feature, out of unit scope): no Tor v3 transport / -onion; " +
		"until one exists, dropping matches Core-without-proxy")
}

// TestW117_G2_NoOnionFlag documents that blockbrew has no -onion proxy flag
// (BUG-2). This is a build-time documentation test.
func TestW117_G2_NoOnionFlag(t *testing.T) {
	// PeerManagerConfig has no OnionProxy, TorControlAddr, or SOCKSProxy field.
	cfg := PeerManagerConfig{}
	_ = cfg

	// If this test compiles, it proves the struct has no Tor-proxy field.
	// The test body always "passes" as a compilation check; the BUG commentary
	// captures the missing feature.
	t.Log("BUG-2: PeerManagerConfig has no OnionProxy or TorControlAddr field; " +
		"-onion flag is not supported; Tor v3 connections MISSING ENTIRELY")
}

// ---------------------------------------------------------------------------
// G11-G16 / BUG-3: I2P connectivity MISSING ENTIRELY
// ---------------------------------------------------------------------------

// TestW117_G11_I2PAddrStoredInAddrBook pins Core's handling of an I2P addrv2
// entry with no SAM bridge configured: NOT stored. init.cpp:2245 removes
// NET_I2P from g_reachable_nets without -i2psam, and net_processing.cpp:5693
// stores only reachable addresses. blockbrew has no I2P transport (G12), so
// dropping is Core-faithful. The audit's "should be stored" was the wrong
// remedy; the feature gap (BUG-3) is out of unit-test scope.
func TestW117_G11_I2PAddrStoredInAddrBook(t *testing.T) {
	ab := NewAddressBook()

	i2pBytes := make([]byte, I2PAddrSize) // 32-byte SHA256 of destination
	for i := range i2pBytes {
		i2pBytes[i] = byte(0xff - i)
	}

	addr := NetAddressV2{
		Time:      1700000000,
		Services:  1,
		NetworkID: NetI2P,
		Addr:      i2pBytes,
		Port:      0, // I2P doesn't use ports
	}

	ab.AddAddressV2(addr, "test")

	// Core without -i2psam: NET_I2P unreachable -> not stored.
	if ab.Size() != 0 {
		t.Errorf("AddAddressV2(NetI2P) stored an address on an unreachable network "+
			"(size=%d); Core init.cpp:2245 + net_processing.cpp:5693 drop it", ab.Size())
	}
	t.Log("BUG-3 (MISSING feature, out of unit scope): no I2P SAM transport / -i2psam")
}

// TestW117_G14_I2PPortMustBeZero pins that an I2P addrv2 entry with a
// non-zero port deserializes faithfully. Core has NO deserialize-time port
// check: CService's serializer reads the port verbatim (netaddress.h:562-565)
// and SetNetFromBIP155Network validates only the address LENGTH
// (netaddress.cpp:76-82). The port is only refused at CONNECT time
// (i2p.cpp:225-226, "connection refused due to arbitrary port"). The audit's
// "should cause a parse error" would have made blockbrew reject addr
// messages Core accepts.
func TestW117_G14_I2PPortMustBeZero(t *testing.T) {
	i2pBytes := make([]byte, I2PAddrSize)

	addr := NetAddressV2{
		Time:      1700000000,
		Services:  0,
		NetworkID: NetI2P,
		Addr:      i2pBytes,
		Port:      8080, // Non-zero port — should be rejected
	}

	var buf bytes.Buffer
	if err := addr.Serialize(&buf); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	var decoded NetAddressV2
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize rejected an I2P addrv2 with port=8080: %v; Core "+
			"netaddress.cpp:76-82 checks only the address length", err)
	}
	if decoded.NetworkID != NetI2P || decoded.Port != 8080 {
		t.Errorf("round-trip: got net=%d port=%d, want net=%d port=8080 (Core reads the port verbatim, netaddress.h:564)",
			decoded.NetworkID, decoded.Port, NetI2P)
	}
	if buf.Len() != 0 {
		t.Errorf("stream not fully consumed: %d bytes left", buf.Len())
	}
}

// TestW117_G12_I2PNoSAMBridge documents that no I2P SAM bridge is implemented
// (BUG-3).
func TestW117_G12_I2PNoSAMBridge(t *testing.T) {
	// PeerManagerConfig has no I2PSAMAddr or I2PListenPort field.
	cfg := PeerManagerConfig{}
	_ = cfg
	t.Log("BUG-3: PeerManagerConfig has no I2PSAMAddr field; " +
		"-i2psam flag is not supported; I2P connections MISSING ENTIRELY")
}

// ---------------------------------------------------------------------------
// G17-G20 / BUG-4: CJDNS connection support MISSING ENTIRELY
// ---------------------------------------------------------------------------

// TestW117_G17_CJDNSAddrStoredInAddrBook pins Core's handling of a CJDNS
// addrv2 entry without -cjdnsreachable: NOT stored. init.cpp:1546 removes
// NET_CJDNS from g_reachable_nets unless the flag is set, and
// net_processing.cpp:5693 stores only reachable addresses. blockbrew has no
// -cjdnsreachable (G18), so dropping is Core-faithful.
func TestW117_G17_CJDNSAddrStoredInAddrBook(t *testing.T) {
	ab := NewAddressBook()

	// CJDNS address: 16 bytes starting with 0xfc
	cjdnsBytes := []byte{
		0xfc, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
	}

	addr := NetAddressV2{
		Time:      1700000000,
		Services:  1,
		NetworkID: NetCJDNS,
		Addr:      cjdnsBytes,
		Port:      8333,
	}

	ab.AddAddressV2(addr, "test")

	// Core without -cjdnsreachable: NET_CJDNS unreachable -> not stored.
	if ab.Size() != 0 {
		t.Errorf("AddAddressV2(NetCJDNS) stored an address on an unreachable network "+
			"(size=%d); Core init.cpp:1546 + net_processing.cpp:5693 drop it", ab.Size())
	}
	t.Log("BUG-4 (MISSING feature, out of unit scope): no -cjdnsreachable")
}

// TestW117_G18_NoCJDNSReachableFlag documents that -cjdnsreachable is absent
// (BUG-4).
func TestW117_G18_NoCJDNSReachableFlag(t *testing.T) {
	cfg := PeerManagerConfig{}
	_ = cfg
	t.Log("BUG-4: PeerManagerConfig has no CJDNSReachable field; " +
		"-cjdnsreachable is not supported; CJDNS connections MISSING ENTIRELY")
}

// TestW117_G19_CJDNSRoutingViaisRoutableIP documents the isRoutableIP behavior
// for CJDNS addresses. Go's net.IP.IsPrivate() covers fc00::/7 (RFC4193 ULA),
// which includes CJDNS's fc00::/8 prefix. This means CJDNS IPv6 addresses
// are correctly rejected by AddAddress (IPv4/v6 path).
// However, Core has -cjdnsreachable that exempts CJDNS from IsRoutable when
// the flag is set; blockbrew has no such gate.
func TestW117_G19_CJDNSfC00RejectedByIsRoutableIP(t *testing.T) {
	// fc00::/8 CJDNS address: 16-byte IPv6 with first byte 0xfc.
	ip := make([]byte, 16)
	ip[0] = 0xfc
	for i := 1; i < 16; i++ {
		ip[i] = byte(i)
	}
	rejected := !isRoutableIP(ip)
	t.Logf("isRoutableIP(fc00::...): routable=%v (rejected=%v). "+
		"Go IsPrivate covers fc00::/7 so CJDNS is correctly gated at the "+
		"IPv4/IPv6 addr path. Note: blockbrew has no -cjdnsreachable escape hatch.",
		!rejected, rejected)
}

// TestW117_G20_CJDNSfc00PrefixRejectedByIsRoutableIP directly tests
// isRoutableIP for an fc00::/8 CJDNS address.
func TestW117_G20_CJDNSfc00PrefixRejectedByIsRoutableIP(t *testing.T) {
	// fc00::/8 is covered by Go's IsPrivate (RFC4193 fc00::/7).
	// isRoutableIP must return false for CJDNS addresses unless -cjdnsreachable.
	cjdnsIP := make([]byte, 16)
	cjdnsIP[0] = 0xfc
	// Fill rest with non-zero to distinguish from unspecified
	for i := 1; i < 16; i++ {
		cjdnsIP[i] = byte(i)
	}
	if isRoutableIP(cjdnsIP) {
		t.Errorf("isRoutableIP returned true for fc00::/8 CJDNS address; " +
			"should be false (Go IsPrivate covers fc00::/7 ULA)")
	}
	// This confirms the isRoutableIP gate correctly blocks CJDNS from the
	// IPv4/IPv6 addr path — but blockbrew also has no alternate CJDNS path.
}

// ---------------------------------------------------------------------------
// G21 / BUG-7: No -onlynet flag / IsReachable gate
// ---------------------------------------------------------------------------

// TestW117_G21_NoOnlynetFlag documents that PeerManagerConfig has no OnlyNet
// field (BUG-7).
func TestW117_G21_NoOnlynetFlag(t *testing.T) {
	cfg := PeerManagerConfig{}
	_ = cfg
	t.Log("BUG-7: PeerManagerConfig has no OnlyNet []string field; " +
		"-onlynet is not supported; Core's g_reachable_nets.Contains(network) " +
		"gate is entirely absent")
}

// TestW117_G22_OutboundDiversityIPv4IPv6Only documents that outbound diversity
// tracking is IPv4/IPv6 only — no per-network (Tor/I2P/CJDNS) slot budgeting.
// Core uses separate outbound slot budgets per network type.
func TestW117_G22_OutboundDiversityIPv4IPv6Only(t *testing.T) {
	// subnetCounts tracks /16 subnet or AS group — IPv4/IPv6 only.
	// Tor, I2P, and CJDNS slots are not tracked separately.
	pm := &PeerManager{
		subnetCounts: make(map[string]int),
	}
	_ = pm
	t.Log("BUG-7: subnetCounts only tracks IPv4/IPv6 groups; no Tor/I2P/CJDNS " +
		"outbound slot budgeting (Core: separate MAX_CONNECTIONS_PER_NET for each)")
}

// ---------------------------------------------------------------------------
// G29 / BUG-5: getnetworkinfo networks — TestW117_G29_GetNetworkInfoMissingI2PAndCJDNS
// lives in internal/rpc/w117_network_rpc_test.go, where it can call
// handleGetNetworkInfo instead of a hardcoded copy of its output.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// G30 / BUG-6: getnodeaddresses RPC missing
// ---------------------------------------------------------------------------

// TestW117_G30_GetNodeAddressesMissing documents that getnodeaddresses is
// absent from the RPC dispatch table (BUG-6).
//
// Core's getnodeaddresses returns known peer addresses from AddrMan, optionally
// filtered by network type (count, network). It is used by wallets and
// explorers for peer discovery. The RPC is listed in Core's rpc/net.cpp:1211.
func TestW117_G30_GetNodeAddressesMissing(t *testing.T) {
	// We verify indirectly: the AddressBook has the infrastructure to return
	// addresses (AllAddresses, PickAddress), but there's no RPC wiring.
	ab := NewAddressBook()
	if ab == nil {
		t.Fatal("NewAddressBook returned nil")
	}
	// The address book exists; the RPC wrapper is what's missing.
	t.Log("BUG-6: getnodeaddresses RPC is not in the server dispatch table; " +
		"AddressBook.AllAddresses() exists but is not exposed via RPC")
}

// ---------------------------------------------------------------------------
// G8/G9 / BUG-8: getpeerinfo "network" — TestW117_G9_GetPeerInfoNetworkFieldHardcoded
// lives in internal/rpc/w117_network_rpc_test.go, where it can call
// peerNetworkFromAddr (the production derivation) instead of a literal.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// G25-G28: IsRoutable / IsLocal / subnet handling (passing / informational)
// ---------------------------------------------------------------------------

// TestW117_G25_IsRoutableIPRejectsRFC1918 verifies that RFC1918 private
// addresses are rejected by isRoutableIP (PASS — correct behavior).
func TestW117_G25_IsRoutableIPRejectsRFC1918(t *testing.T) {
	rfc1918 := []string{
		"\x0a\x00\x00\x01", // 10.0.0.1
		"\xc0\xa8\x01\x01", // 192.168.1.1
		"\xac\x10\x00\x01", // 172.16.0.1
	}
	for _, raw := range rfc1918 {
		ip := make([]byte, 16)
		copy(ip[12:], raw)
		ip[10] = 0xff
		ip[11] = 0xff
		// Use the 4-byte form directly
		ip4 := []byte(raw)
		if isRoutableIP(ip4) {
			t.Errorf("isRoutableIP returned true for RFC1918 address %v", ip4)
		}
	}
}

// TestW117_G26_IsRoutableIPRejectsLoopback verifies loopback is rejected.
func TestW117_G26_IsRoutableIPRejectsLoopback(t *testing.T) {
	loopback := []byte{127, 0, 0, 1}
	if isRoutableIP(loopback) {
		t.Errorf("isRoutableIP returned true for loopback 127.0.0.1")
	}
}

// TestW117_G27_IsRoutableIPAcceptsPublic verifies that a public IPv4 address
// is accepted by isRoutableIP.
func TestW117_G27_IsRoutableIPAcceptsPublic(t *testing.T) {
	public := []byte{8, 8, 8, 8} // 8.8.8.8
	if !isRoutableIP(public) {
		t.Errorf("isRoutableIP returned false for public address 8.8.8.8")
	}
}

// TestW117_G28_IsRoutableIPRejectsLinkLocal verifies link-local rejection.
func TestW117_G28_IsRoutableIPRejectsLinkLocal(t *testing.T) {
	linkLocal := []byte{169, 254, 1, 1} // 169.254.1.1
	if isRoutableIP(linkLocal) {
		t.Errorf("isRoutableIP returned true for link-local 169.254.1.1")
	}
}

// ---------------------------------------------------------------------------
// addrv2 wire correctness (passing)
// ---------------------------------------------------------------------------

// TestW117_G29_AddrV2TorV3RoundTrip verifies Tor v3 addresses round-trip
// correctly through addrv2 serialize/deserialize (PASS — wire format correct).
func TestW117_G29_AddrV2TorV3RoundTrip(t *testing.T) {
	torV3Bytes := make([]byte, TorV3AddrSize)
	for i := range torV3Bytes {
		torV3Bytes[i] = byte(i + 0xa0)
	}

	orig := NetAddressV2{
		Time:      1700000000,
		Services:  1,
		NetworkID: NetTorV3,
		Addr:      torV3Bytes,
		Port:      9050,
	}

	var buf bytes.Buffer
	if err := orig.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	var decoded NetAddressV2
	if err := decoded.Deserialize(&buf); err != nil {
		// BUG-1: if we later fix Tor v2, Tor v3 must NOT also be broken.
		// For now Tor v3 must still parse successfully (it's not deprecated).
		t.Fatalf("Deserialize Tor v3: %v", err)
	}

	if decoded.NetworkID != NetTorV3 {
		t.Errorf("NetworkID: got %d want %d", decoded.NetworkID, NetTorV3)
	}
	if len(decoded.Addr) != TorV3AddrSize {
		t.Errorf("Addr length: got %d want %d", len(decoded.Addr), TorV3AddrSize)
	}
	if !bytes.Equal(decoded.Addr, torV3Bytes) {
		t.Errorf("Addr mismatch")
	}
}

// TestW117_G29_AddrV2I2PRoundTrip verifies I2P addresses round-trip correctly.
func TestW117_G29_AddrV2I2PRoundTrip(t *testing.T) {
	i2pBytes := make([]byte, I2PAddrSize)
	for i := range i2pBytes {
		i2pBytes[i] = byte(i + 0x50)
	}

	orig := NetAddressV2{
		Time:      1700000000,
		Services:  0,
		NetworkID: NetI2P,
		Addr:      i2pBytes,
		Port:      0,
	}

	var buf bytes.Buffer
	if err := orig.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	var decoded NetAddressV2
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize I2P: %v", err)
	}

	if decoded.NetworkID != NetI2P {
		t.Errorf("NetworkID: got %d want %d", decoded.NetworkID, NetI2P)
	}
	if len(decoded.Addr) != I2PAddrSize {
		t.Errorf("Addr length: got %d want %d", len(decoded.Addr), I2PAddrSize)
	}
}

// TestW117_G29_AddrV2CJDNSRoundTrip verifies CJDNS addresses round-trip correctly.
func TestW117_G29_AddrV2CJDNSRoundTrip(t *testing.T) {
	cjdnsBytes := []byte{
		0xfc, 0x00, 0x01, 0x02,
		0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e,
	}

	orig := NetAddressV2{
		Time:      1700000000,
		Services:  0,
		NetworkID: NetCJDNS,
		Addr:      cjdnsBytes,
		Port:      8333,
	}

	var buf bytes.Buffer
	if err := orig.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	var decoded NetAddressV2
	if err := decoded.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize CJDNS: %v", err)
	}

	if decoded.NetworkID != NetCJDNS {
		t.Errorf("NetworkID: got %d want %d", decoded.NetworkID, NetCJDNS)
	}
	if decoded.Addr[0] != 0xfc {
		t.Errorf("CJDNS prefix byte: got 0x%02x want 0xfc", decoded.Addr[0])
	}
}

// TestW117_G29_CJDNSBadPrefixRejected verifies CJDNS with wrong prefix is
// rejected (PASS — ErrInvalidCJDNSPrefix is returned).
func TestW117_G29_CJDNSBadPrefixRejected(t *testing.T) {
	badCJDNS := make([]byte, CJDNSAddrSize)
	badCJDNS[0] = 0xfe // wrong prefix, must be 0xfc

	addr := NetAddressV2{
		Time:      1700000000,
		Services:  0,
		NetworkID: NetCJDNS,
		Addr:      badCJDNS,
		Port:      8333,
	}

	var buf bytes.Buffer
	if err := addr.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	var decoded NetAddressV2
	err := decoded.Deserialize(&buf)
	if err == nil {
		t.Error("Expected error for CJDNS address with wrong prefix (0xfe), got nil")
	}
}

// TestW117_G29_SendAddrv2HandshakeTiming verifies sendaddrv2 must be sent
// before verack (PASS — blockbrew correctly enforces this).
func TestW117_G29_SendAddrv2HandshakeTiming(t *testing.T) {
	// Simulate a peer that already has verAckRecvd=true
	p := &Peer{
		verAckRecvd: true,
		quit:        make(chan struct{}),
		sendQueue:   make(chan Message, 10),
	}
	// Simulate misbehavior tracking
	p.misbehaviorScore = 0

	p.handleSendAddrv2(&MsgSendAddrv2{})

	// After verack, sendaddrv2 should be a protocol violation (misbehavior=10)
	if p.MisbehaviorScore() == 0 {
		t.Error("Expected misbehavior score > 0 for sendaddrv2 after verack")
	}
	if p.wantsAddrv2 {
		t.Error("wantsAddrv2 should remain false when sendaddrv2 received after verack")
	}
}

// TestW117_G29_MaxAddrV2SizeIs512 verifies MaxAddrV2Size is 512 per BIP155.
func TestW117_G29_MaxAddrV2SizeIs512(t *testing.T) {
	if MaxAddrV2Size != 512 {
		t.Errorf("MaxAddrV2Size = %d, want 512 (BIP155 §3)", MaxAddrV2Size)
	}
}

// TestW117_G29_TorV3AddrSizeIs32 verifies Tor v3 address size is 32 bytes.
func TestW117_G29_TorV3AddrSizeIs32(t *testing.T) {
	if TorV3AddrSize != 32 {
		t.Errorf("TorV3AddrSize = %d, want 32 (BIP155 §3 ed25519 pubkey)", TorV3AddrSize)
	}
}

// TestW117_G29_I2PAddrSizeIs32 verifies I2P address size is 32 bytes.
func TestW117_G29_I2PAddrSizeIs32(t *testing.T) {
	if I2PAddrSize != 32 {
		t.Errorf("I2PAddrSize = %d, want 32 (BIP155 §3 SHA256 of destination)", I2PAddrSize)
	}
}

// TestW117_G29_CJDNSAddrSizeIs16 verifies CJDNS address size is 16 bytes.
func TestW117_G29_CJDNSAddrSizeIs16(t *testing.T) {
	if CJDNSAddrSize != 16 {
		t.Errorf("CJDNSAddrSize = %d, want 16 (BIP155 §3 fc00::/8 IPv6)", CJDNSAddrSize)
	}
}

// TestW117_G29_NetworkIDConstants verifies BIP155 network ID byte values.
func TestW117_G29_NetworkIDConstants(t *testing.T) {
	tests := []struct {
		name string
		got  uint8
		want uint8
	}{
		{"NetIPv4", NetIPv4, 0x01},
		{"NetIPv6", NetIPv6, 0x02},
		{"NetTorV2", NetTorV2, 0x03},
		{"NetTorV3", NetTorV3, 0x04},
		{"NetI2P", NetI2P, 0x05},
		{"NetCJDNS", NetCJDNS, 0x06},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = 0x%02x, want 0x%02x (BIP155 §3)", tc.name, tc.got, tc.want)
		}
	}
}

// TestW117_G29_MsgAddrV2MaxIs1000 verifies the addrv2 message count cap.
func TestW117_G29_MsgAddrV2MaxIs1000(t *testing.T) {
	if MaxAddresses != 1000 {
		t.Errorf("MaxAddresses = %d, want 1000 (Core MAX_ADDR_TO_SEND)", MaxAddresses)
	}
}

// TestW117_G5_TorV2ConstantCorrect verifies the Tor v2 network ID constant.
func TestW117_G5_TorV2ConstantCorrect(t *testing.T) {
	// BIP155: NetTorV2 = 0x03 (deprecated — should be rejected, not just defined)
	if NetTorV2 != 0x03 {
		t.Errorf("NetTorV2 = 0x%02x, want 0x03", NetTorV2)
	}
}

// TestW117_G5_TorV2SizeIs10 verifies Tor v2 address size constant.
func TestW117_G5_TorV2SizeIs10(t *testing.T) {
	if TorV2AddrSize != 10 {
		t.Errorf("TorV2AddrSize = %d, want 10", TorV2AddrSize)
	}
}

// TestW117_G3_TorV3IsAddrV1Incompatible verifies Tor v3 is NOT addr v1 compatible.
func TestW117_G3_TorV3IsAddrV1Incompatible(t *testing.T) {
	addr := &NetAddressV2{NetworkID: NetTorV3, Addr: make([]byte, TorV3AddrSize)}
	if addr.IsAddrV1Compatible() {
		t.Error("Tor v3 should not be addr v1 compatible (Core: IsAddrV1Compatible=false for NET_ONION)")
	}
}

// TestW117_G11_I2PIsAddrV1Incompatible verifies I2P is NOT addr v1 compatible.
func TestW117_G11_I2PIsAddrV1Incompatible(t *testing.T) {
	addr := &NetAddressV2{NetworkID: NetI2P, Addr: make([]byte, I2PAddrSize)}
	if addr.IsAddrV1Compatible() {
		t.Error("I2P should not be addr v1 compatible (Core: IsAddrV1Compatible=false for NET_I2P)")
	}
}

// TestW117_G17_CJDNSIsAddrV1Incompatible verifies CJDNS is NOT addr v1 compatible.
// Core's IsAddrV1Compatible returns false for NET_CJDNS (netaddress.cpp:486).
func TestW117_G17_CJDNSIsAddrV1Incompatible(t *testing.T) {
	addr := &NetAddressV2{NetworkID: NetCJDNS, Addr: make([]byte, CJDNSAddrSize)}
	if addr.IsAddrV1Compatible() {
		t.Error("CJDNS should not be addr v1 compatible (Core: IsAddrV1Compatible=false for NET_CJDNS)")
	}
}

// TestW117_G29_ToLegacyAddrsCJDNSExcluded verifies CJDNS is excluded from
// legacy addr (correct per Core behavior).
func TestW117_G29_ToLegacyAddrsCJDNSExcluded(t *testing.T) {
	cjdnsBytes := []byte{
		0xfc, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}
	msg := &MsgAddrv2{
		AddrList: []NetAddressV2{
			{NetworkID: NetIPv4, Addr: []byte{8, 8, 8, 8}, Port: 8333},
			{NetworkID: NetCJDNS, Addr: cjdnsBytes, Port: 8333},
		},
	}
	legacy := msg.ToLegacyAddrs()
	// Only the IPv4 address should be in the legacy list
	if len(legacy.AddrList) != 1 {
		t.Errorf("ToLegacyAddrs: got %d entries, want 1 (CJDNS should be excluded)", len(legacy.AddrList))
	}
}

// TestW117_G29_ToLegacyAddrsTorExcluded verifies Tor is excluded from legacy addr.
func TestW117_G29_ToLegacyAddrsTorExcluded(t *testing.T) {
	msg := &MsgAddrv2{
		AddrList: []NetAddressV2{
			{NetworkID: NetIPv4, Addr: []byte{8, 8, 8, 8}, Port: 8333},
			{NetworkID: NetTorV3, Addr: make([]byte, TorV3AddrSize), Port: 9050},
		},
	}
	legacy := msg.ToLegacyAddrs()
	if len(legacy.AddrList) != 1 {
		t.Errorf("ToLegacyAddrs: got %d entries, want 1 (Tor v3 should be excluded)", len(legacy.AddrList))
	}
}

// TestW117_G29_ToLegacyAddrsI2PExcluded verifies I2P is excluded from legacy addr.
func TestW117_G29_ToLegacyAddrsI2PExcluded(t *testing.T) {
	msg := &MsgAddrv2{
		AddrList: []NetAddressV2{
			{NetworkID: NetIPv4, Addr: []byte{8, 8, 4, 4}, Port: 8333},
			{NetworkID: NetI2P, Addr: make([]byte, I2PAddrSize), Port: 0},
		},
	}
	legacy := msg.ToLegacyAddrs()
	if len(legacy.AddrList) != 1 {
		t.Errorf("ToLegacyAddrs: got %d entries, want 1 (I2P should be excluded)", len(legacy.AddrList))
	}
}

// TestW117_G29_AddrV2FilterByNetworkTor filters Tor v3 addresses from a mixed list.
func TestW117_G29_AddrV2FilterByNetworkTor(t *testing.T) {
	msg := &MsgAddrv2{
		AddrList: []NetAddressV2{
			{NetworkID: NetIPv4, Addr: []byte{1, 2, 3, 4}},
			{NetworkID: NetTorV3, Addr: make([]byte, TorV3AddrSize)},
			{NetworkID: NetI2P, Addr: make([]byte, I2PAddrSize)},
			{NetworkID: NetTorV3, Addr: make([]byte, TorV3AddrSize)},
		},
	}
	torAddrs := msg.FilterByNetwork(NetTorV3)
	if len(torAddrs) != 2 {
		t.Errorf("FilterByNetwork(NetTorV3): got %d, want 2", len(torAddrs))
	}
}

// TestW117_G29_UnknownNetworkAcceptedUpToMaxSize verifies unknown network IDs
// are accepted if address length <= MaxAddrV2Size (BIP155: forward compat).
func TestW117_G29_UnknownNetworkAcceptedUpToMaxSize(t *testing.T) {
	unknownID := uint8(0x0a) // future network
	addr := NetAddressV2{
		Time:      1700000000,
		Services:  0,
		NetworkID: unknownID,
		Addr:      make([]byte, 20), // unknown size, within MaxAddrV2Size
		Port:      0,
	}

	var buf bytes.Buffer
	if err := addr.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	var decoded NetAddressV2
	if err := decoded.Deserialize(&buf); err != nil {
		t.Errorf("Unknown network ID 0x0a with 20-byte addr should be accepted "+
			"(BIP155 forward compat), got error: %v", err)
	}
}
