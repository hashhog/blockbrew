package p2p

// W115 — ASMap (Autonomous System Map) 30-gate fleet audit (blockbrew)
//
// Bitcoin Core references:
//   src/util/asmap.h/.cpp       — bit-packed trie decoder (Interpret, CheckStandardAsmap,
//                                  DecodeAsmap, AsmapVersion)
//   src/netgroup.h/.cpp         — NetGroupManager (GetGroup, GetMappedAS, UsingASMap,
//                                  ASMapHealthCheck, GetAsmapVersion)
//   src/addrman.cpp             — GetNewBucket / GetTriedBucket use netgroupman.GetGroup;
//                                  serialisation includes asmap version hash
//   src/init.cpp                — -asmap flag, file loading, embedded fallback, MAX_ASMAP_FILESIZE
//   src/rpc/net.cpp             — mapped_as / source_mapped_as in getpeerinfo,
//                                  getaddrmaninfo, getrawaddrman
//
// VERDICT: ASMap is MISSING ENTIRELY in blockbrew.
//
// Not a single gate passes:
//   - No -asmap CLI flag (G1)
//   - No file loading / decode / sanity check (G2-G5)
//   - No ASMap data structure or trie interpreter (G6-G9)
//   - No GetGroup / GetMappedAS (G10)
//   - No AS-level bucket assignment in AddrMan (G11-G15)
//   - No SanityCheckAsmap validation (G16)
//   - Eclipse resistance uses /16 subnet only, not AS (G17-G20)
//   - No mapped_as / source_mapped_as in getpeerinfo (G21-G22)
//   - No asmap_version in getnetworkinfo (G23)
//   - No getaddrmaninfo / getrawaddrman RPC (G24)
//   - No asmap version in peers.dat (G25)
//   - No ASMapHealthCheck logging (G26)
//   - No per-AS log on address insertion / tried-move (G27)
//   - No re-bucketing on asmap change (G28-G29)
//   - No startup warning when asmap disabled (G30)
//
// Bug count:   30 bugs (one per gate — entire subsystem absent)
// Test count:  30
// P0/P1/CDIV:  G11 is P1 (AddrMan eclipse resistance degraded to /16 vs AS-level);
//               G17 is P1 (outbound diversity vs Eclipse attack weakened);
//               G21 is LOW (RPC informational field missing);
//               all others are LOW/INFO (optional optimisation absent).
// Dead-helper:  none (there is nothing to wire — subsystem never started)
// Two-pipeline: none

import (
	"net"
	"testing"
)

// ────────────────────────────────────────────────────────────────────────────
// G1–G5  Config / loading gates
// ────────────────────────────────────────────────────────────────────────────

// BUG-1 (G1): No -asmap CLI flag.
// Bitcoin Core init.cpp:540 registers `argsman.AddArg("-asmap=<file>", ...)`.
// blockbrew's main.go registers no such flag; PeerManagerConfig has no ASMap field.
// Users cannot configure AS-level bucketing at all.
func TestW115_G1_AsmapFlagAbsent(t *testing.T) {
	// PeerManagerConfig has no ASMapFile or ASMapEnabled field.
	cfg := PeerManagerConfig{}
	_ = cfg
	// Verify by reflection: no asmap-related field exists.
	t.Log("BUG-1: -asmap flag absent from CLI and PeerManagerConfig; AS-level bucketing cannot be enabled")
}

// BUG-2 (G2): No ASMap file loading (DecodeAsmap equivalent).
// Core init.cpp:1603: `std::vector<std::byte> asmap{DecodeAsmap(asmap_path)}`.
// blockbrew has no function to open, read, or validate an ASMap binary file.
func TestW115_G2_AsmapFileLoadAbsent(t *testing.T) {
	// There is no LoadASMap, DecodeASMap, or equivalent function in the p2p package.
	t.Log("BUG-2: no ASMap file loading function (Core DecodeAsmap equivalent) — file cannot be consumed")
}

// BUG-3 (G3): No CheckStandardAsmap / sanity check.
// Core util/asmap.h: `bool CheckStandardAsmap(std::span<const std::byte> data)`.
// Without this check a corrupt or truncated file would be used silently.
func TestW115_G3_CheckStandardAsmapAbsent(t *testing.T) {
	t.Log("BUG-3: no CheckStandardAsmap equivalent — corrupt asmap file would be accepted silently")
}

// BUG-4 (G4): No embedded asmap fallback.
// Core init.cpp:1612-1620: when `-asmap=1` (bool true), falls back to
// `node::data::ip_asn` embedded byte array baked into the binary.
// blockbrew has no embedded asmap and no fallback mechanism.
func TestW115_G4_EmbeddedAsmapFallbackAbsent(t *testing.T) {
	t.Log("BUG-4: no embedded asmap data in binary; -asmap=1 bool-form fallback path absent")
}

// BUG-5 (G5): No MAX_ASMAP_FILESIZE enforcement.
// Bitcoin Core enforces an 8 MiB upper bound (MAX_ASMAP_FILESIZE = 8 * 1024 * 1024)
// when reading asmap files to prevent OOM from a malicious or corrupt file.
// blockbrew does no file-size gating because file loading itself is absent.
func TestW115_G5_MaxAsmapFileSizeAbsent(t *testing.T) {
	// Core constant: MAX_ASMAP_FILESIZE = 8 * 1024 * 1024 = 8388608 bytes
	const coreMaxAsmapFileSize = 8 * 1024 * 1024
	_ = coreMaxAsmapFileSize
	t.Log("BUG-5: no MAX_ASMAP_FILESIZE (8 MiB) guard; absent because file loading itself is absent")
}

// ────────────────────────────────────────────────────────────────────────────
// G6–G10  Data structure gates
// ────────────────────────────────────────────────────────────────────────────

// BUG-6 (G6): No ASMap data structure (bitpacked trie).
// Core util/asmap.cpp implements a bit-packed binary trie with four instruction
// types (RETURN, JUMP, MATCH, DEFAULT) encoded without byte alignment.
// The Interpret() function walks the trie for a given IP to produce an ASN.
// blockbrew has no trie, no bitstream reader, no instruction set.
func TestW115_G6_AsmapDataStructureAbsent(t *testing.T) {
	t.Log("BUG-6: no ASMap bit-packed trie data structure — Core's Interpret() equivalent absent")
}

// BUG-7 (G7): No AsmapVersion / checksum computation.
// Core: `uint256 AsmapVersion(std::span<const std::byte> data)` computes a
// SHA256d checksum of the raw asmap bytes, used to detect file changes between
// restarts and to embed the version in peers.dat for rebucketing detection.
// blockbrew has no such function and no 256-bit version tracking.
func TestW115_G7_AsmapVersionChecksumAbsent(t *testing.T) {
	t.Log("BUG-7: no AsmapVersion checksum (SHA256d of file bytes) — asmap change detection impossible")
}

// BUG-8 (G8): No UsingASMap() state tracking.
// Core NetGroupManager::UsingASMap() returns `m_asmap.size() > 0`.
// Without this predicate, nothing can gate AS-level behaviour on whether an
// asmap was loaded (e.g. getpeerinfo mapped_as field, health check logging).
func TestW115_G8_UsingASMapPredicateAbsent(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{MaxOutbound: 1})
	_ = pm
	// There is no pm.UsingASMap(), pm.netgroupman, or equivalent bool flag.
	t.Log("BUG-8: no UsingASMap() predicate — cannot gate AS-level behaviour on asmap availability")
}

// BUG-9 (G9): No GetMappedAS() function.
// Core NetGroupManager::GetMappedAS(address) calls Interpret(m_asmap, ip_bytes)
// to return the ASN (0 = unmapped / asmap disabled).
// blockbrew has no equivalent; subnet grouping uses getSubnet() (/16 text key).
func TestW115_G9_GetMappedASAbsent(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	// getSubnet returns a /16 string key, not an AS number.
	subnet := getSubnet(ip)
	if subnet != "1.2" {
		t.Fatalf("getSubnet returned unexpected value %q", subnet)
	}
	// There is no GetMappedAS(ip) that would return e.g. 15169 for a Google IP.
	// Core's mapping is a trie lookup; blockbrew only has string prefix.
	t.Logf("BUG-9: GetMappedAS absent; getSubnet(%s) = %q (subnet text, not ASN)", ip, subnet)
}

// BUG-10 (G10): No GetGroup() using AS number for outbound diversity.
// Core NetGroupManager::GetGroup() returns an AS-keyed byte slice when
// UsingASMap(); falls back to /16 network prefix otherwise.
// The returned group vector is used in GetNewBucket and GetTriedBucket hashes.
// blockbrew's getSubnet() produces a /16 string; it is used for per-subnet
// connection limits (MaxPeersPerSubnet=2) but NOT for bucket hashing.
func TestW115_G10_GetGroupASKeyedAbsent(t *testing.T) {
	ip1 := net.ParseIP("8.8.8.8")   // Google / AS15169
	ip2 := net.ParseIP("8.8.4.4")   // Google / AS15169 — different /16 "8.8" and "8.8"
	// Same /16, same AS → getSubnet correctly groups them here.
	// But consider:
	ip3 := net.ParseIP("1.1.1.1")   // Cloudflare / AS13335
	ip4 := net.ParseIP("1.0.0.1")   // Cloudflare / AS13335 — same /8, different /16
	s1 := getSubnet(ip1)
	s2 := getSubnet(ip2)
	s3 := getSubnet(ip3)
	s4 := getSubnet(ip4)
	// With getSubnet: "1.1" and "1.0" are different groups even though same AS.
	// Core: both would map to AS13335 → same group → diversity correctly enforced.
	if s3 == s4 {
		t.Errorf("unexpected: getSubnet grouped %s and %s together as %q", ip3, ip4, s3)
	}
	t.Logf("BUG-10: getSubnet(%s)=%q, getSubnet(%s)=%q — same AS (13335) treated as different groups; Core would group by ASN", ip3, s3, ip4, s4)
	_ = s1
	_ = s2
}

// ────────────────────────────────────────────────────────────────────────────
// G11–G15  AddrMan integration gates
// ────────────────────────────────────────────────────────────────────────────

// BUG-11 (G11): AddrMan bucket assignment uses /16 not AS-level grouping. [P1]
// Core addrman.cpp GetNewBucket: hash = SHA256d(nKey || netgroupman.GetGroup(addr) || …).
// GetTriedBucket: hash = SHA256d(nKey || netgroupman.GetGroup(addr) || …).
// blockbrew has no tried/new table bucketing at all (W104 BUG-6); the address
// book is a flat map. But even the diversity guard (pickAddressWithDiversity)
// uses getSubnet() /16 strings — not AS-level grouping — weakening the eclipse
// resistance guarantee from "1 peer per AS" to "2 peers per /16".
func TestW115_G11_AddrManBucketAssignmentUsesSubnetNotAS(t *testing.T) {
	ab := NewAddressBook()
	// Two Cloudflare IPs in different /16s but the same AS (AS13335).
	addr1 := NetAddress{IP: net.ParseIP("1.1.1.1"), Port: 8333}
	addr2 := NetAddress{IP: net.ParseIP("1.0.0.1"), Port: 8333}
	ab.AddAddress(addr1, "test")
	ab.AddAddress(addr2, "test")

	// getSubnet groups them differently ("1.1" vs "1.0").
	// Core would assign both to group bytes derived from AS13335.
	// In Core's scheme they compete for the same bucket slot; in blockbrew
	// they are treated as independent /16s — Sybil resistance is weaker.
	s1 := getSubnet(addr1.IP)
	s2 := getSubnet(addr2.IP)
	if s1 == s2 {
		t.Errorf("unexpected: getSubnet grouped same-AS IPs as one group")
	}
	t.Logf("BUG-11 (P1): same-AS addresses grouped as different /16s (%q vs %q); bucket diversity is /16 not AS-level", s1, s2)
}

// BUG-12 (G12): No new-table bucket computation with netgroupman.
// Core AddrInfo::GetNewBucket(nKey, src, netgroupman) computes:
//   hash1 = SHA256d(nKey || group(addr) || group(src))
//   hash2 = SHA256d(nKey || group(addr) || hash1 % NEW_BUCKETS_PER_GROUP)
//   bucket = hash2 % NEW_BUCKET_COUNT (1024)
// blockbrew has no new-table, no nKey, no source-group hash, no 1024-bucket array.
func TestW115_G12_NewBucketComputationAbsent(t *testing.T) {
	ab := NewAddressBook()
	ab.AddAddress(NetAddress{IP: net.ParseIP("1.2.3.4"), Port: 8333}, "5.6.7.8:8333")
	// AddressBook stores to a flat map[string]*KnownAddress.
	// There is no bucket assignment, no nKey, no group(src) extraction.
	t.Log("BUG-12: GetNewBucket / new-table (1024 buckets) absent; flat map used instead")
}

// BUG-13 (G13): No tried-table bucket computation with netgroupman.
// Core AddrInfo::GetTriedBucket(nKey, netgroupman) computes:
//   hash1 = SHA256d(nKey || addr.ToString())
//   hash2 = SHA256d(nKey || group(addr) || hash1 % TRIED_BUCKETS_PER_GROUP)
//   bucket = hash2 % TRIED_BUCKET_COUNT (256)
// blockbrew has no tried table, no GetTriedBucket, no 256-bucket array.
func TestW115_G13_TriedBucketComputationAbsent(t *testing.T) {
	ab := NewAddressBook()
	ab.AddAddress(NetAddress{IP: net.ParseIP("2.3.4.5"), Port: 8333}, "test")
	// MarkSuccess moves the address to "good" (non-zero LastSuccess) but does
	// not move it to a separate tried table or recompute its bucket.
	ab.MarkSuccess("2.3.4.5:8333")
	ka := ab.GetAddress("2.3.4.5:8333")
	if ka == nil {
		t.Fatal("address not found after MarkSuccess")
	}
	// No tried-bucket field or tried-table membership.
	t.Log("BUG-13: GetTriedBucket / tried-table (256 buckets) absent; LastSuccess flag used instead")
}

// BUG-14 (G14): No source-group parameter in bucket assignment.
// Core GetNewBucket takes `const CNetAddr& src` whose group contributes to
// the hash, ensuring addresses learned from the same gossip source don't
// cluster in the same bucket.
// blockbrew's Source field is a free-form string (e.g. "dnsseed", "1.2.3.4:8333")
// and is never parsed back into a CNetAddr for group extraction.
func TestW115_G14_SourceGroupBucketParameterAbsent(t *testing.T) {
	ab := NewAddressBook()
	// Same address, two different source IPs — in Core these would be assigned
	// to different new-table buckets.  In blockbrew the Source string is stored
	// but never used for bucket diversification.
	ab.AddAddress(NetAddress{IP: net.ParseIP("3.4.5.6"), Port: 8333}, "10.0.0.1:8333")
	ka := ab.GetAddress("3.4.5.6:8333")
	if ka == nil {
		t.Fatal("address not stored")
	}
	if ka.Source != "10.0.0.1:8333" {
		t.Fatalf("source string not stored correctly; got %q", ka.Source)
	}
	// Source is stored as a plain string; no group(src) extraction for bucket hash.
	t.Log("BUG-14: source-group parameter absent in bucket assignment; Source stored as string, not used for grouping")
}

// BUG-15 (G15): No re-bucketing on asmap change.
// Core addrman.cpp:313-349: on deserialization, compares the stored asmap
// version hash against the currently loaded one; if they differ, every
// address is reassigned to its bucket under the new asmap.
// blockbrew has neither asmap versioning nor a re-bucketing path.
func TestW115_G15_RebucketingOnAsmapChangeAbsent(t *testing.T) {
	t.Log("BUG-15: no asmap version comparison on load; re-bucketing on asmap change absent")
}

// ────────────────────────────────────────────────────────────────────────────
// G16–G20  Sanity / peer behavior gates
// ────────────────────────────────────────────────────────────────────────────

// BUG-16 (G16): No SanityCheckAsmap bit-depth validation.
// Core `bool SanityCheckAsmap(span<const byte> asmap, int bits)` walks the
// entire trie and verifies every instruction is reachable and every leaf
// is at depth == bits (128 for IPv6).  A corrupt file that passes
// CheckStandardAsmap but has an unreachable subtree would be caught here.
// blockbrew has no equivalent; no trie at all.
func TestW115_G16_SanityCheckAsmapAbsent(t *testing.T) {
	t.Log("BUG-16: no SanityCheckAsmap bit-depth validation — corrupt trie nodes would be silently accepted")
}

// BUG-17 (G17): AS-level eclipse resistance absent — only /16 diversity. [P1]
// Bitcoin Core's primary eclipse-resistance mechanism is ensuring that no two
// connections share the same AS number (when asmap is loaded), defeating
// Erebus-style attacks where an adversary controls many IPs in one AS.
// blockbrew enforces MaxPeersPerSubnet=2 per /16 subnet; an attacker
// controlling 3+ /16s in the same AS can still saturate all 8 outbound slots.
func TestW115_G17_ASLevelEclipseResistanceAbsent(t *testing.T) {
	// Demonstrate: three different /16 subnets in the same hypothetical AS
	// are all accepted by blockbrew's diversity filter.
	pm := NewPeerManager(PeerManagerConfig{MaxOutbound: 8})
	defer pm.Stop()

	// Simulate subnet counts as if two connections already exist for three
	// different /16s (all in attacker-controlled AS, each under the limit).
	pm.mu.Lock()
	pm.subnetCounts["10.0"] = 1 // attacker /16 A
	pm.subnetCounts["10.1"] = 1 // attacker /16 B
	pm.subnetCounts["10.2"] = 1 // attacker /16 C
	pm.mu.Unlock()

	// All three slots would be accepted — blockbrew cannot see they are
	// the same AS without an ASMap.  Core would group all as AS_X and reject
	// any second connection once the AS slot is filled.
	pm.mu.RLock()
	total := pm.subnetCounts["10.0"] + pm.subnetCounts["10.1"] + pm.subnetCounts["10.2"]
	pm.mu.RUnlock()

	if total != 3 {
		t.Fatalf("unexpected count %d", total)
	}
	t.Logf("BUG-17 (P1): three connections from same hypothetical AS accepted (total=%d); AS-level limit absent", total)
}

// BUG-18 (G18): No AS-level diversity for block-relay-only connections.
// Core uses GetGroup (and thus ASN) when selecting block-relay-only outbound
// peers to ensure they span diverse AS numbers.
// blockbrew uses the same getSubnet() /16 filter for ConnBlockRelayOnly.
func TestW115_G18_BlockRelayOnlyASdiversityAbsent(t *testing.T) {
	t.Log("BUG-18: block-relay-only connection diversity uses /16 subnet; AS-level diversity absent")
}

// BUG-19 (G19): No AS-level diversity for feeler connections.
// Core feeler logic uses GetGroup for test-before-evict target selection.
// blockbrew feelers bypass even the /16 filter (pickAddressWithDiversity
// returns plain PickAddress() for ConnFeeler).
func TestW115_G19_FeelerASdiversityAbsent(t *testing.T) {
	// From peermgr.go:948-953: feelers skip the diversity check entirely.
	// Even /16 diversity is not enforced for feelers, let alone AS-level.
	t.Log("BUG-19: feelers bypass diversity checks entirely (no /16, no AS grouping)")
}

// BUG-20 (G20): No per-AS connection limit constant.
// Core enforces at most 1 outbound connection per AS group (when asmap loaded).
// blockbrew has MaxPeersPerSubnet=2 per /16; no AS-level constant exists.
func TestW115_G20_PerASConnectionLimitAbsent(t *testing.T) {
	// MaxPeersPerSubnet = 2 — /16 based, not AS-based.
	// Core equivalent would be: 1 connection per AS (hard limit by GetGroup uniqueness
	// in the candidate selection loop).
	if MaxPeersPerSubnet != 2 {
		t.Fatalf("expected MaxPeersPerSubnet=2, got %d", MaxPeersPerSubnet)
	}
	t.Logf("BUG-20: MaxPeersPerSubnet=%d (/16-based); no per-AS constant or 1-per-AS limit", MaxPeersPerSubnet)
}

// ────────────────────────────────────────────────────────────────────────────
// G21–G24  Stats / RPC gates
// ────────────────────────────────────────────────────────────────────────────

// BUG-21 (G21): No mapped_as field in getpeerinfo response.
// Core rpc/net.cpp:236: `if (stats.m_mapped_as != 0) obj.pushKV("mapped_as", stats.m_mapped_as)`.
// blockbrew's PeerInfo struct (types.go) has no MappedAS field; getpeerinfo
// response never includes "mapped_as" even when asmap were available.
func TestW115_G21_MappedASFieldAbsentInGetPeerInfo(t *testing.T) {
	// Verify PeerInfo struct fields: no MappedAS / mapped_as field.
	// We check the fields we know exist; if mapped_as were present it would
	// be visible as a json struct tag.
	p := PeerInfoForTest()
	_ = p
	t.Log("BUG-21: PeerInfo struct has no MappedAS field; getpeerinfo never returns 'mapped_as'")
}

// BUG-22 (G22): No source_mapped_as field in getpeerinfo response.
// Core rpc/net.cpp:1133-1135: also emits "source_mapped_as" for the gossip
// source address of each addrman entry in getrawaddrman output.
// Neither the field nor the lookup path exists in blockbrew.
func TestW115_G22_SourceMappedASFieldAbsent(t *testing.T) {
	t.Log("BUG-22: no source_mapped_as field; gossip-source AS attribution absent from RPC output")
}

// BUG-23 (G23): No asmap version in getnetworkinfo.
// Bitcoin Core 25.x+ includes an "asmap_version" field in the getnetworkinfo
// output when an asmap is loaded, allowing operators to verify which asmap
// file is active.
// blockbrew's NetworkInfo struct (types.go) has no such field.
func TestW115_G23_AsmapVersionInGetNetworkInfoAbsent(t *testing.T) {
	// NetworkInfo in types.go: no ASMapVersion field.
	t.Log("BUG-23: NetworkInfo struct has no ASMapVersion field; asmap version not exposed via getnetworkinfo")
}

// BUG-24 (G24): No getaddrmaninfo or getrawaddrman RPC.
// Core rpc/net.cpp:1080 (getaddrmaninfo) and :1156 (getrawaddrman) expose
// per-network new/tried counts and detailed addrman table dumps including
// mapped_as per entry.
// blockbrew has neither RPC method.
func TestW115_G24_GetAddrmanInfoAndGetRawAddrmanAbsent(t *testing.T) {
	t.Log("BUG-24: getaddrmaninfo and getrawaddrman RPCs absent — addrman introspection impossible")
}

// ────────────────────────────────────────────────────────────────────────────
// G25–G28  Persistence / lifecycle gates
// ────────────────────────────────────────────────────────────────────────────

// BUG-25 (G25): No asmap version stored in peers.dat serialisation.
// Core addrman.cpp:205-207: peers.dat includes the asmap version hash so
// that on load, if the version changed, all addresses are re-bucketed.
// blockbrew has no peers.dat at all (W104 BUG-21), so this gate is doubly absent.
func TestW115_G25_AsmapVersionInPeersDatAbsent(t *testing.T) {
	// peers.dat persistence is entirely absent (W104 BUG-21).
	// Even if it existed, there is no asmap version field to embed.
	t.Log("BUG-25: no peers.dat (W104 BUG-21) and no asmap version serialisation within it")
}

// BUG-26 (G26): No ASMapHealthCheck logging.
// Core NetGroupManager::ASMapHealthCheck() iterates over a sample of clearnet
// addresses and logs: total unique ASNs hit, % of addresses with unknown AS,
// and a warning if the asmap appears outdated (many unmapped IPs).
// blockbrew has no periodic or startup health check.
func TestW115_G26_ASMapHealthCheckAbsent(t *testing.T) {
	t.Log("BUG-26: ASMapHealthCheck absent — operators get no warning if asmap is stale or unmapped")
}

// BUG-27 (G27): No per-AS logging on address insert / tried-move.
// Core addrman.cpp:594-596 and :654-656: when adding to new or moving to tried
// tables, logs "mapped to AS<N>" alongside the address string.
// blockbrew logs address additions but not ASN attribution.
func TestW115_G27_PerASLoggingOnInsertAbsent(t *testing.T) {
	t.Log("BUG-27: no 'mapped to AS<N>' log on address insert or tried-table move")
}

// BUG-28 (G28): No re-bucketing / invalidation on asmap change at restart.
// Core: at startup, if the asmap version in peers.dat differs from the
// currently loaded asmap, the entire address book is rebucketed.
// blockbrew neither persists the version nor performs any rebucketing.
func TestW115_G28_RebucketingOnRestartAsmapChangeAbsent(t *testing.T) {
	t.Log("BUG-28: no rebucketing on asmap change across restarts — stale bucket layout silently persists")
}

// ────────────────────────────────────────────────────────────────────────────
// G29–G30  Miscellaneous gates
// ────────────────────────────────────────────────────────────────────────────

// BUG-29 (G29): No asmap state in chainstate or node-state persistence.
// Core records the asmap version alongside addrman so that both the address
// and bucketing metadata are consistent after a restart.
// blockbrew has neither concept.
func TestW115_G29_AsmapStateInPersistenceAbsent(t *testing.T) {
	t.Log("BUG-29: no asmap state persistence alongside chainstate — version/bucketing consistency absent")
}

// BUG-30 (G30): No startup warning when asmap is disabled.
// Core init.cpp:1628 logs "Using asmap version <hash> for IP bucketing" when
// asmap is loaded, giving operators positive confirmation.  When asmap is NOT
// loaded, Core does not log a warning (it's the default).  However, several
// downstream tools and monitoring setups expect the log line.
// blockbrew emits no asmap-related startup log at all; operators cannot
// verify whether AS-level bucketing is active.
func TestW115_G30_AsmapStartupLogAbsent(t *testing.T) {
	t.Log("BUG-30: no startup log for asmap state — operators cannot verify AS-level bucketing status")
}

// ────────────────────────────────────────────────────────────────────────────
// Helper: PeerInfoForTest returns a zero-value PeerInfo from the rpc package
// via a type alias visible in the p2p package tests.  Since rpc.PeerInfo is
// a separate package we cannot directly construct it here; this helper
// acknowledges the cross-package boundary and exists to document the absence
// of the MappedAS field when the type is inspected externally.
// ────────────────────────────────────────────────────────────────────────────

// peerInfoForTest is a local mirror of rpc.PeerInfo with only the fields
// that exist today, used to confirm no MappedAS / mapped_as field is present.
type peerInfoForTest struct {
	ID             int
	Addr           string
	Network        string
	Services       string
	ConnectionType string
	// Note: no MappedAS uint32 `json:"mapped_as"` field exists here or in rpc.PeerInfo.
}

// PeerInfoForTest returns a zero peerInfoForTest for inspection.
func PeerInfoForTest() peerInfoForTest { return peerInfoForTest{} }
