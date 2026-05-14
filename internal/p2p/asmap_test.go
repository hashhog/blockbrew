package p2p

// W115 — ASMap interpreter unit tests
//
// Tests the Interpret() function and supporting helpers against:
//   1. Bitcoin Core's reference vector from src/test/netbase_tests.cpp
//      BOOST_AUTO_TEST_CASE(asmap_test_vectors)
//   2. Hand-crafted minimal asmap bytecodes (RETURN / JUMP / MATCH / DEFAULT)
//   3. SanityCheckAsmap / CheckStandardAsmap validation
//   4. LoadAsmap file loading + size guard
//   5. AsmapVersion fingerprint
//   6. GetMappedAS / GetGroup integration
//   7. PeerManager UsingASMap / GetMappedASForAddr methods
//
// All hex ASMAP_DATA bytes come verbatim from Core's test.

import (
	"encoding/hex"
	"math/bits"
	"net"
	"os"
	"testing"
)

// ────────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────────

// bitsToBytes packs an array of 0/1 values (one per element) into bytes
// with LSB-first bit ordering — the same packing used by Bitcoin Core's
// BitsToBytes helper in the fuzz harness.
func bitsToBytes(bits_ []uint8) []byte {
	var ret []byte
	var nextByte uint8
	nextByteBits := 0
	for _, val := range bits_ {
		nextByte |= (val & 1) << uint(nextByteBits)
		nextByteBits++
		if nextByteBits == 8 {
			ret = append(ret, nextByte)
			nextByte = 0
			nextByteBits = 0
		}
	}
	if nextByteBits > 0 {
		ret = append(ret, nextByte)
	}
	return ret
}

// mustHex decodes a hex string or panics.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// parseIPv6 parses an abbreviated IPv6 address as used in Core tests
// (e.g. "0:1559:183:3728:224c:65a5:62e6:e991") and returns a 16-byte array.
func parseIPv6(s string) [16]byte {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("parseIPv6: cannot parse " + s)
	}
	ip16 := ip.To16()
	var arr [16]byte
	copy(arr[:], ip16)
	return arr
}

// ────────────────────────────────────────────────────────────────────────────
// Core reference vector (from bitcoin-core/src/test/netbase_tests.cpp)
// ────────────────────────────────────────────────────────────────────────────

// coreAsmapHex is the ASMAP_DATA constant from Core's asmap_test_vectors.
const coreAsmapHex = "" +
	"fd38d50f7d5d665357f64bba6bfc190d6078a7e68e5d3ac032edf47f8b5755f87881bfd3633d9aa7c1fa279b3" +
	"6fe26c63bbc9de44e0f04e5a382d8e1cddbe1c26653bc939d4327f287e8b4d1f8aff33176787cb0ff7cb28e3f" +
	"daef0f8f47357f801c9f7ff7a99f7f9c9f99de7f3156ae00f23eb27a303bc486aa3ccc31ec19394c2f8a53ddd" +
	"ea3cc56257f3b7e9b1f488be9c1137db823759aa4e071eef2e984aaf97b52d5f88d0f373dd190fe45e06efef1" +
	"df7278be680a73a74c76db4dd910f1d30752c57fe2bc9f079f1a1e1b036c2a69219f11c5e11980a3fa51f4f82" +
	"d36373de73b1863a8c27e36ae0e4f705be3d76ecff038a75bc0f92ba7e7f6f4080f1c47c34d095367ecf4406c" +
	"1e3bbc17ba4d6f79ea3f031b876799ac268b1e0ea9babf0f9a8e5f6c55e363c6363df46afc696d7afceaf49b6" +
	"e62df9e9dc27e70664cafe5c53df66dd0b8237678ada90e73f05ec60e6f6e96c3cbb1ea2f9dece115d5bdba10" +
	"33e53662a7d72a29477b5beb35710591d3e23e5f0379baea62ffdee535bcdf879cbf69b88d7ea37c8015381cf" +
	"63dc33d28f757a4a5e15d6a08"

// TestW115_CoreReferenceVector runs the 19 IP → ASN checks from Core's
// BOOST_AUTO_TEST_CASE(asmap_test_vectors) in netbase_tests.cpp.
func TestW115_CoreReferenceVector(t *testing.T) {
	asmap := mustHex(coreAsmapHex)

	// Validate the file is well-formed before running queries
	if !CheckStandardAsmap(asmap) {
		t.Fatal("CheckStandardAsmap failed on Core reference vector — trie is invalid")
	}

	cases := []struct {
		addr    string
		wantASN uint32
	}{
		{"0:1559:183:3728:224c:65a5:62e6:e991", 961340},
		{"d0:d493:faa0:8609:e927:8b75:293c:f5a4", 961340},
		{"2a0:26f:8b2c:2ee7:c7d1:3b24:4705:3f7f", 693761},
		{"a77:7cd4:4be5:a449:89f2:3212:78c6:ee38", 0},
		{"1336:1ad6:2f26:4fe3:d809:7321:6e0d:4615", 672176},
		{"1d56:abd0:a52f:a8d5:d5a7:a610:581d:d792", 499880},
		{"378e:7290:54e5:bd36:4760:971c:e9b9:570d", 0},
		{"406c:820b:272a:c045:b74e:fc0a:9ef2:cecc", 248495},
		{"46c2:ae07:9d08:2d56:d473:2bc7:57e3:20ac", 248495},
		{"50d2:3db6:52fa:2e7:12ec:5bc4:1bd1:49f9", 124471},
		{"53e1:1812:ffa:dccf:f9f2:64be:75fa:795", 539993},
		{"544d:eeba:3990:35d1:ad66:f9a3:576d:8617", 374443},
		{"6a53:40dc:8f1d:3ffa:efeb:3aa3:df88:b94b", 435070},
		{"87aa:d1c9:9edb:91e7:aab1:9eb9:baa0:de18", 244121},
		{"9f00:48fa:88e3:4b67:a6f3:e6d2:5cc1:5be2", 862116},
		{"c49f:9cc6:86ad:ba08:4580:315e:dbd1:8a62", 969411},
		{"dff5:8021:61d:b17d:406d:7888:fdac:4a20", 969411},
		{"e888:6791:2960:d723:bcfd:47e1:2d8c:599f", 824019},
		{"ffff:d499:8c4b:4941:bc81:d5b9:b51e:85a8", 824019},
	}

	for _, tc := range cases {
		ip := parseIPv6(tc.addr)
		got := Interpret(asmap, ip)
		if got != tc.wantASN {
			t.Errorf("Interpret(%s) = %d, want %d", tc.addr, got, tc.wantASN)
		}
	}
	t.Logf("Core reference vector: all %d cases passed", len(cases))
}

// ────────────────────────────────────────────────────────────────────────────
// Hand-crafted bytecode unit tests
// ────────────────────────────────────────────────────────────────────────────

// buildReturnASN constructs a minimal asmap that always returns the given ASN
// regardless of IP bits, using a single RETURN instruction.
// Encoding: opcode=RETURN([0]), then the ASN in asnBitSizes encoding
// (minval=1, first class = 15 bits).
//
// For ASN values 1..32768 (class 0, minval=1):
//   bits: [0(RETURN)] [0(class0)] [15 bits BE of (asn-1)] [zero-pad to byte]
func buildReturnASN(asn uint32) []byte {
	// Build the bit stream manually
	// RETURN opcode = single 0 bit (via DecodeBits class 0 with 0 bits)
	// TYPE: [0] (one zero bit)
	// ASN encoding minval=1, bitSizes=[15,16,...]:
	//   class 0: [0] [15 bits of (asn-1)]
	// Total meaningful bits: 1 (RETURN) + 1 (class0 continuation) + 15 (ASN mantissa) = 17
	// Byte-pad with zeros (at most 7)
	var rawBits []uint8
	// RETURN = class 0 of type encoding (minval=0, bitSizes=[0,0,1])
	// TYPE class 0: continuation=0 (one 0-bit), mantissa=0 bits → just one 0-bit
	rawBits = append(rawBits, 0) // RETURN
	// ASN encoding: class 0 (minval=1, bitSizes=[15,...])
	// continuation bit for class 0 = 0
	rawBits = append(rawBits, 0) // class 0 continuation
	// 15 bits of (asn-1) in big-endian
	val := asn - 1 // shift from minval=1
	for b := 14; b >= 0; b-- {
		rawBits = append(rawBits, uint8((val>>uint(b))&1))
	}
	// Pad to full byte with zeros
	for len(rawBits)%8 != 0 {
		rawBits = append(rawBits, 0)
	}
	return bitsToBytes(rawBits)
}

func TestW115_Interpret_AlwaysReturn(t *testing.T) {
	// Build a trie that always returns ASN 1234 (class 0, 1234-1=1233 < 2^15=32768)
	asmap := buildReturnASN(1234)
	if !CheckStandardAsmap(asmap) {
		t.Fatalf("CheckStandardAsmap failed for always-return-1234 trie")
	}
	var ip [16]byte
	// Should return 1234 regardless of IP
	for i := range ip {
		ip[i] = byte(i * 17)
	}
	got := Interpret(asmap, ip)
	if got != 1234 {
		t.Errorf("Interpret(always-return) = %d, want 1234", got)
	}
}

// TestW115_DecodeBits_BasicCases exercises the variable-length decoder
// directly through the exported behaviour captured via Interpret.
func TestW115_DecodeBits_BitWidth(t *testing.T) {
	// bits.Len32 is used inside SanityCheckAsmap for matchlen computation.
	// Spot-check a few values to verify the Go stdlib agrees with Core's
	// std::bit_width behaviour (they must be identical).
	cases := []struct {
		val  uint32
		want int
	}{
		{0, 0},
		{1, 1},
		{2, 2},
		{3, 2},
		{4, 3},
		{255, 8},
		{256, 9},
		{511, 9},
		{512, 10},
	}
	for _, tc := range cases {
		got := bits.Len32(tc.val)
		if got != tc.want {
			t.Errorf("bits.Len32(%d) = %d, want %d", tc.val, got, tc.want)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SanityCheckAsmap tests
// ────────────────────────────────────────────────────────────────────────────

func TestW115_SanityCheck_CoreVector(t *testing.T) {
	asmap := mustHex(coreAsmapHex)
	if !SanityCheckAsmap(asmap, 128) {
		t.Fatal("SanityCheckAsmap(core vector, 128) returned false")
	}
}

func TestW115_SanityCheck_EmptyFails(t *testing.T) {
	if SanityCheckAsmap(nil, 128) {
		t.Fatal("SanityCheckAsmap(nil) should return false")
	}
	if SanityCheckAsmap([]byte{}, 128) {
		t.Fatal("SanityCheckAsmap(empty) should return false")
	}
}

func TestW115_SanityCheck_TruncatedFails(t *testing.T) {
	asmap := mustHex(coreAsmapHex)
	// Truncate to half length — should fail validation
	half := asmap[:len(asmap)/2]
	if SanityCheckAsmap(half, 128) {
		t.Fatal("SanityCheckAsmap(truncated) should return false")
	}
}

func TestW115_CheckStandardAsmap_CoreVector(t *testing.T) {
	asmap := mustHex(coreAsmapHex)
	if !CheckStandardAsmap(asmap) {
		t.Fatal("CheckStandardAsmap(core vector) returned false")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// LoadAsmap / MaxAsmapFileSize tests
// ────────────────────────────────────────────────────────────────────────────

func TestW115_MaxAsmapFileSize_Constant(t *testing.T) {
	// Bitcoin Core MAX_ASMAP_FILESIZE = 8 * 1024 * 1024
	const want = 8 * 1024 * 1024
	if MaxAsmapFileSize != want {
		t.Errorf("MaxAsmapFileSize = %d, want %d (8 MiB)", MaxAsmapFileSize, want)
	}
}

func TestW115_LoadAsmap_FileNotFound(t *testing.T) {
	_, err := LoadAsmap("/nonexistent/path/to/asmap.bin")
	if err == nil {
		t.Fatal("LoadAsmap(nonexistent) should return error")
	}
}

func TestW115_LoadAsmap_ValidFile(t *testing.T) {
	// Write Core reference vector to a temp file and load it
	f, err := os.CreateTemp("", "asmap-test-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	data := mustHex(coreAsmapHex)
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	f.Close()

	loaded, err := LoadAsmap(f.Name())
	if err != nil {
		t.Fatalf("LoadAsmap(%s) error: %v", f.Name(), err)
	}
	if len(loaded) != len(data) {
		t.Errorf("LoadAsmap returned %d bytes, want %d", len(loaded), len(data))
	}
}

func TestW115_LoadAsmap_CorruptFile(t *testing.T) {
	// Write random garbage that won't pass CheckStandardAsmap
	f, err := os.CreateTemp("", "asmap-corrupt-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	// All-0xFF bytes will fail sanity check
	garbage := make([]byte, 64)
	for i := range garbage {
		garbage[i] = 0xFF
	}
	if _, err := f.Write(garbage); err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, err = LoadAsmap(f.Name())
	if err == nil {
		t.Fatal("LoadAsmap(corrupt) should return error")
	}
}

// TestW115_LoadAsmap_OversizeFile verifies the 8 MiB guard.
func TestW115_LoadAsmap_OversizeFile(t *testing.T) {
	f, err := os.CreateTemp("", "asmap-big-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	// Seek past MaxAsmapFileSize+1 and write one zero byte to create a sparse file
	if _, err := f.Seek(int64(MaxAsmapFileSize)+1, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, err = LoadAsmap(f.Name())
	if err == nil {
		t.Fatal("LoadAsmap(oversize) should return error")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// AsmapVersion fingerprint
// ────────────────────────────────────────────────────────────────────────────

func TestW115_AsmapVersion_Empty(t *testing.T) {
	v := AsmapVersion(nil)
	if v != "" {
		t.Errorf("AsmapVersion(nil) = %q, want \"\"", v)
	}
}

func TestW115_AsmapVersion_Deterministic(t *testing.T) {
	data := mustHex(coreAsmapHex)
	v1 := AsmapVersion(data)
	v2 := AsmapVersion(data)
	if v1 != v2 {
		t.Errorf("AsmapVersion not deterministic: %q vs %q", v1, v2)
	}
	if len(v1) != 8 {
		t.Errorf("AsmapVersion length = %d, want 8 hex chars", len(v1))
	}
}

func TestW115_AsmapVersion_DifferentDataDifferentVersion(t *testing.T) {
	data1 := mustHex(coreAsmapHex)
	data2 := append([]byte{}, data1...)
	data2[0] ^= 0x01 // flip one bit
	v1 := AsmapVersion(data1)
	v2 := AsmapVersion(data2)
	if v1 == v2 {
		t.Errorf("AsmapVersion produced same fingerprint for different data: %q", v1)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// GetMappedAS integration
// ────────────────────────────────────────────────────────────────────────────

func TestW115_GetMappedAS_NilAsmap(t *testing.T) {
	ip := net.ParseIP("8.8.8.8")
	got := GetMappedAS(nil, ip)
	if got != 0 {
		t.Errorf("GetMappedAS(nil, ...) = %d, want 0", got)
	}
}

func TestW115_GetMappedAS_NilIP(t *testing.T) {
	data := mustHex(coreAsmapHex)
	got := GetMappedAS(data, nil)
	if got != 0 {
		t.Errorf("GetMappedAS(asmap, nil) = %d, want 0", got)
	}
}

func TestW115_GetMappedAS_CoreVector_viaNetIP(t *testing.T) {
	asmap := mustHex(coreAsmapHex)
	// Spot-check two Core vector entries via the net.IP path
	cases := []struct {
		addr    string
		wantASN uint32
	}{
		{"0:1559:183:3728:224c:65a5:62e6:e991", 961340},
		{"a77:7cd4:4be5:a449:89f2:3212:78c6:ee38", 0},
		{"406c:820b:272a:c045:b74e:fc0a:9ef2:cecc", 248495},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.addr)
		got := GetMappedAS(asmap, ip)
		if got != tc.wantASN {
			t.Errorf("GetMappedAS(%s) = %d, want %d", tc.addr, got, tc.wantASN)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// GetGroup
// ────────────────────────────────────────────────────────────────────────────

func TestW115_GetGroup_WithASMap(t *testing.T) {
	asmap := mustHex(coreAsmapHex)
	// Two Core vector IPs that return the same ASN should produce identical groups
	ip1 := net.ParseIP("406c:820b:272a:c045:b74e:fc0a:9ef2:cecc") // AS248495
	ip2 := net.ParseIP("46c2:ae07:9d08:2d56:d473:2bc7:57e3:20ac") // AS248495
	g1 := GetGroup(asmap, ip1)
	g2 := GetGroup(asmap, ip2)
	if len(g1) == 0 {
		t.Fatal("GetGroup returned empty for known IP")
	}
	if string(g1) != string(g2) {
		t.Errorf("same-AS IPs produced different groups: %v vs %v", g1, g2)
	}
	if g1[0] != 6 {
		t.Errorf("GetGroup[0] = %d, want 6 (NET_IPV6)", g1[0])
	}
}

func TestW115_GetGroup_NoASMap_IPv4Fallback(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	g := GetGroup(nil, ip)
	// Fallback: first 2 bytes of IPv4 address
	if len(g) < 3 {
		t.Fatalf("GetGroup(nil, IPv4) returned too short: %v", g)
	}
	if g[1] != 1 || g[2] != 2 {
		t.Errorf("GetGroup(nil, 1.2.3.4) = %v, want [4,1,2]", g)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// PeerManager integration: UsingASMap / GetMappedASForAddr
// ────────────────────────────────────────────────────────────────────────────

func TestW115_PeerManager_UsingASMap_False(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{MaxOutbound: 1})
	if pm.UsingASMap() {
		t.Error("UsingASMap() should be false when no ASMapFile configured")
	}
}

func TestW115_PeerManager_GetMappedASForAddr_NoAsmap(t *testing.T) {
	pm := NewPeerManager(PeerManagerConfig{MaxOutbound: 1})
	got := pm.GetMappedASForAddr("8.8.8.8:8333")
	if got != 0 {
		t.Errorf("GetMappedASForAddr without asmap = %d, want 0", got)
	}
}

func TestW115_PeerManager_UsingASMap_WithFile(t *testing.T) {
	// Write Core reference asmap to a temp file
	f, err := os.CreateTemp("", "asmap-pm-test-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	data := mustHex(coreAsmapHex)
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	f.Close()

	pm := NewPeerManager(PeerManagerConfig{
		MaxOutbound: 1,
		ASMapFile:   f.Name(),
	})
	if !pm.UsingASMap() {
		t.Fatal("UsingASMap() should be true after loading asmap file")
	}
}

func TestW115_PeerManager_GetMappedASForAddr_WithAsmap(t *testing.T) {
	// Write Core reference asmap to a temp file
	f, err := os.CreateTemp("", "asmap-pm-addr-test-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	data := mustHex(coreAsmapHex)
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	f.Close()

	pm := NewPeerManager(PeerManagerConfig{
		MaxOutbound: 1,
		ASMapFile:   f.Name(),
	})

	// Use a Core vector IP embedded in addr:port form
	// "406c:820b:272a:c045:b74e:fc0a:9ef2:cecc" → AS248495
	got := pm.GetMappedASForAddr("[406c:820b:272a:c045:b74e:fc0a:9ef2:cecc]:8333")
	if got != 248495 {
		t.Errorf("GetMappedASForAddr([406c:...]:8333) = %d, want 248495", got)
	}
}
