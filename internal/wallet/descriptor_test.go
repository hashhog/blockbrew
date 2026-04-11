package wallet

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
)

func TestDescriptorChecksum(t *testing.T) {
	tests := []struct {
		desc     string
		checksum string
	}{
		// Test vectors computed using Bitcoin Core INPUT_CHARSET (descriptor.cpp)
		{"pk(020000000000000000000000000000000000000000000000000000000000000001)", "e80tdz4l"},
		{"pkh(020000000000000000000000000000000000000000000000000000000000000002)", "ma7nspkf"},
		{"wpkh(020000000000000000000000000000000000000000000000000000000000000003)", "tawwvenc"},
		// Simple descriptors
		{"addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)", "uyjndxcw"},
	}

	for _, tt := range tests {
		t.Run(tt.desc[:20]+"...", func(t *testing.T) {
			checksum := DescriptorChecksum(tt.desc)
			if checksum != tt.checksum {
				t.Errorf("DescriptorChecksum(%q) = %q, want %q", tt.desc, checksum, tt.checksum)
			}
		})
	}
}

func TestValidateDescriptorChecksum(t *testing.T) {
	tests := []struct {
		desc  string
		valid bool
		body  string
	}{
		{"pk(020000000000000000000000000000000000000000000000000000000000000001)#e80tdz4l", true, "pk(020000000000000000000000000000000000000000000000000000000000000001)"},
		{"pk(020000000000000000000000000000000000000000000000000000000000000001)#badcheck", false, ""},
		{"pk(020000000000000000000000000000000000000000000000000000000000000001)", true, "pk(020000000000000000000000000000000000000000000000000000000000000001)"},
	}

	for _, tt := range tests {
		t.Run(tt.desc[:20]+"...", func(t *testing.T) {
			body, valid := ValidateDescriptorChecksum(tt.desc)
			if valid != tt.valid {
				t.Errorf("ValidateDescriptorChecksum(%q) valid = %v, want %v", tt.desc, valid, tt.valid)
			}
			if valid && body != tt.body {
				t.Errorf("ValidateDescriptorChecksum(%q) body = %q, want %q", tt.desc, body, tt.body)
			}
		})
	}
}

func TestAddChecksum(t *testing.T) {
	desc := "pk(020000000000000000000000000000000000000000000000000000000000000001)"
	want := "pk(020000000000000000000000000000000000000000000000000000000000000001)#e80tdz4l"

	result := AddChecksum(desc)
	if result != want {
		t.Errorf("AddChecksum(%q) = %q, want %q", desc, result, want)
	}

	// Test that adding checksum twice doesn't double it
	result2 := AddChecksum(result)
	if result2 != want {
		t.Errorf("AddChecksum(AddChecksum(desc)) = %q, want %q", result2, want)
	}
}

func TestParseDescriptorPK(t *testing.T) {
	// Compressed public key
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "pk(" + pubKeyHex + ")"

	parsed, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error: %v", desc, err)
	}

	if parsed.Type != DescPK {
		t.Errorf("Type = %v, want %v", parsed.Type, DescPK)
	}
	if len(parsed.Keys) != 1 {
		t.Fatalf("len(Keys) = %d, want 1", len(parsed.Keys))
	}
	if parsed.Keys[0].IsRange() {
		t.Errorf("Key should not be ranged")
	}

	// Expand
	scripts, err := parsed.Expand(0)
	if err != nil {
		t.Fatalf("Expand() error: %v", err)
	}
	if len(scripts) != 1 {
		t.Fatalf("len(scripts) = %d, want 1", len(scripts))
	}

	// P2PK script: <pubkey> OP_CHECKSIG
	script := scripts[0]
	if script[len(script)-1] != 0xac { // OP_CHECKSIG
		t.Errorf("Script should end with OP_CHECKSIG")
	}
}

func TestParseDescriptorPKH(t *testing.T) {
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "pkh(" + pubKeyHex + ")"

	parsed, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error: %v", desc, err)
	}

	if parsed.Type != DescPKH {
		t.Errorf("Type = %v, want %v", parsed.Type, DescPKH)
	}

	scripts, err := parsed.Expand(0)
	if err != nil {
		t.Fatalf("Expand() error: %v", err)
	}

	// P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
	script := scripts[0]
	if len(script) != 25 {
		t.Errorf("P2PKH script length = %d, want 25", len(script))
	}
	if script[0] != 0x76 { // OP_DUP
		t.Errorf("Script[0] = %02x, want 0x76 (OP_DUP)", script[0])
	}
}

func TestParseDescriptorWPKH(t *testing.T) {
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "wpkh(" + pubKeyHex + ")"

	parsed, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error: %v", desc, err)
	}

	if parsed.Type != DescWPKH {
		t.Errorf("Type = %v, want %v", parsed.Type, DescWPKH)
	}

	scripts, err := parsed.Expand(0)
	if err != nil {
		t.Fatalf("Expand() error: %v", err)
	}

	// P2WPKH: OP_0 <20>
	script := scripts[0]
	if len(script) != 22 {
		t.Errorf("P2WPKH script length = %d, want 22", len(script))
	}
	if script[0] != 0x00 { // OP_0
		t.Errorf("Script[0] = %02x, want 0x00 (OP_0)", script[0])
	}
	if script[1] != 0x14 { // Push 20 bytes
		t.Errorf("Script[1] = %02x, want 0x14", script[1])
	}

	// Check address derivation
	addrs, err := parsed.ExpandToAddresses(0)
	if err != nil {
		t.Fatalf("ExpandToAddresses() error: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("len(addrs) = %d, want 1", len(addrs))
	}
	if !strings.HasPrefix(addrs[0], "bc1q") {
		t.Errorf("Address = %q, want prefix bc1q", addrs[0])
	}
}

func TestParseDescriptorSH_WPKH(t *testing.T) {
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "sh(wpkh(" + pubKeyHex + "))"

	parsed, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error: %v", desc, err)
	}

	if parsed.Type != DescSH {
		t.Errorf("Type = %v, want %v", parsed.Type, DescSH)
	}
	if parsed.Subdesc == nil {
		t.Fatalf("Subdesc is nil")
	}
	if parsed.Subdesc.Type != DescWPKH {
		t.Errorf("Subdesc.Type = %v, want %v", parsed.Subdesc.Type, DescWPKH)
	}

	scripts, err := parsed.Expand(0)
	if err != nil {
		t.Fatalf("Expand() error: %v", err)
	}

	// P2SH: OP_HASH160 <20> OP_EQUAL
	script := scripts[0]
	if len(script) != 23 {
		t.Errorf("P2SH script length = %d, want 23", len(script))
	}
	if script[0] != 0xa9 { // OP_HASH160
		t.Errorf("Script[0] = %02x, want 0xa9 (OP_HASH160)", script[0])
	}

	// Check address
	addrs, err := parsed.ExpandToAddresses(0)
	if err != nil {
		t.Fatalf("ExpandToAddresses() error: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("len(addrs) = %d, want 1", len(addrs))
	}
	if !strings.HasPrefix(addrs[0], "3") {
		t.Errorf("Address = %q, want prefix 3 (P2SH mainnet)", addrs[0])
	}
}

func TestParseDescriptorMulti(t *testing.T) {
	pk1 := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	pk2 := "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	desc := "multi(1," + pk1 + "," + pk2 + ")"

	parsed, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error: %v", desc, err)
	}

	if parsed.Type != DescMulti {
		t.Errorf("Type = %v, want %v", parsed.Type, DescMulti)
	}
	if parsed.Threshold != 1 {
		t.Errorf("Threshold = %d, want 1", parsed.Threshold)
	}
	if len(parsed.Keys) != 2 {
		t.Fatalf("len(Keys) = %d, want 2", len(parsed.Keys))
	}

	scripts, err := parsed.Expand(0)
	if err != nil {
		t.Fatalf("Expand() error: %v", err)
	}

	// Multisig: OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
	script := scripts[0]
	if script[0] != 0x51 { // OP_1
		t.Errorf("Script[0] = %02x, want 0x51 (OP_1)", script[0])
	}
	if script[len(script)-1] != 0xae { // OP_CHECKMULTISIG
		t.Errorf("Script should end with OP_CHECKMULTISIG")
	}
}

func TestParseDescriptorSortedMulti(t *testing.T) {
	// Keys in reverse order
	pk2 := "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	pk1 := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "sortedmulti(1," + pk2 + "," + pk1 + ")"

	parsed, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error: %v", desc, err)
	}

	if parsed.Type != DescSortedMulti {
		t.Errorf("Type = %v, want %v", parsed.Type, DescSortedMulti)
	}

	scripts, err := parsed.Expand(0)
	if err != nil {
		t.Fatalf("Expand() error: %v", err)
	}

	script := scripts[0]
	// After sorting, pk1 should come before pk2 (lexicographically)
	// pk1 starts with 0279, pk2 starts with 02c6
	if len(script) < 35 {
		t.Fatalf("Script too short")
	}
	// First key should be pk1 (starts at byte 1)
	firstKeyStart := script[2:35]
	if hex.EncodeToString(firstKeyStart) != pk1 {
		t.Errorf("First key should be sorted pk1")
	}
}

func TestParseDescriptorTR(t *testing.T) {
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "tr(" + pubKeyHex + ")"

	parsed, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error: %v", desc, err)
	}

	if parsed.Type != DescTR {
		t.Errorf("Type = %v, want %v", parsed.Type, DescTR)
	}
	if parsed.TapTree != nil {
		t.Errorf("TapTree should be nil for key-only spend")
	}

	scripts, err := parsed.Expand(0)
	if err != nil {
		t.Fatalf("Expand() error: %v", err)
	}

	// P2TR: OP_1 <32>
	script := scripts[0]
	if len(script) != 34 {
		t.Errorf("P2TR script length = %d, want 34", len(script))
	}
	if script[0] != 0x51 { // OP_1
		t.Errorf("Script[0] = %02x, want 0x51 (OP_1)", script[0])
	}
	if script[1] != 0x20 { // Push 32 bytes
		t.Errorf("Script[1] = %02x, want 0x20", script[1])
	}

	// Check address
	addrs, err := parsed.ExpandToAddresses(0)
	if err != nil {
		t.Fatalf("ExpandToAddresses() error: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("len(addrs) = %d, want 1", len(addrs))
	}
	if !strings.HasPrefix(addrs[0], "bc1p") {
		t.Errorf("Address = %q, want prefix bc1p", addrs[0])
	}
}

func TestParseDescriptorCombo(t *testing.T) {
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "combo(" + pubKeyHex + ")"

	parsed, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error: %v", desc, err)
	}

	if parsed.Type != DescCombo {
		t.Errorf("Type = %v, want %v", parsed.Type, DescCombo)
	}

	scripts, err := parsed.Expand(0)
	if err != nil {
		t.Fatalf("Expand() error: %v", err)
	}

	// combo() should produce 4 scripts: P2PK, P2PKH, P2WPKH, P2SH-P2WPKH
	if len(scripts) != 4 {
		t.Errorf("len(scripts) = %d, want 4", len(scripts))
	}
}

func TestParseDescriptorRaw(t *testing.T) {
	// OP_RETURN <data>
	rawHex := "6a0548656c6c6f"
	desc := "raw(" + rawHex + ")"

	parsed, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error: %v", desc, err)
	}

	if parsed.Type != DescRaw {
		t.Errorf("Type = %v, want %v", parsed.Type, DescRaw)
	}

	scripts, err := parsed.Expand(0)
	if err != nil {
		t.Fatalf("Expand() error: %v", err)
	}

	if hex.EncodeToString(scripts[0]) != rawHex {
		t.Errorf("Script = %x, want %s", scripts[0], rawHex)
	}
}

func TestParseDescriptorAddr(t *testing.T) {
	tests := []struct {
		addr   string
		net    address.Network
		prefix string
	}{
		{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", address.Mainnet, "bc1q"},
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", address.Mainnet, "1"},
	}

	for _, tt := range tests {
		t.Run(tt.addr[:10]+"...", func(t *testing.T) {
			desc := "addr(" + tt.addr + ")"
			parsed, err := ParseDescriptor(desc, tt.net)
			if err != nil {
				t.Fatalf("ParseDescriptor(%q) error: %v", desc, err)
			}

			if parsed.Type != DescAddr {
				t.Errorf("Type = %v, want %v", parsed.Type, DescAddr)
			}

			addrs, err := parsed.ExpandToAddresses(0)
			if err != nil {
				t.Fatalf("ExpandToAddresses() error: %v", err)
			}
			if len(addrs) != 1 {
				t.Fatalf("len(addrs) = %d, want 1", len(addrs))
			}
			if addrs[0] != tt.addr {
				t.Errorf("Address = %q, want %q", addrs[0], tt.addr)
			}
		})
	}
}

func TestParseDescriptorXpub(t *testing.T) {
	// Test xpub with derivation path
	xpub := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	desc := "wpkh(" + xpub + "/0/*)"

	parsed, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error: %v", desc, err)
	}

	if parsed.Type != DescWPKH {
		t.Errorf("Type = %v, want %v", parsed.Type, DescWPKH)
	}
	if !parsed.IsRange() {
		t.Errorf("Descriptor should be ranged")
	}

	// Derive a few addresses
	for i := uint32(0); i < 3; i++ {
		addrs, err := parsed.ExpandToAddresses(i)
		if err != nil {
			t.Fatalf("ExpandToAddresses(%d) error: %v", i, err)
		}
		if len(addrs) != 1 {
			t.Fatalf("ExpandToAddresses(%d) len = %d, want 1", i, len(addrs))
		}
		if !strings.HasPrefix(addrs[0], "bc1q") {
			t.Errorf("Address[%d] = %q, want prefix bc1q", i, addrs[0])
		}
		t.Logf("Address[%d] = %s", i, addrs[0])
	}
}

func TestDescriptorString(t *testing.T) {
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "wpkh(" + pubKeyHex + ")"

	parsed, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error: %v", desc, err)
	}

	// String() should return descriptor with checksum
	str := parsed.String()
	if !strings.Contains(str, "#") {
		t.Errorf("String() = %q, should contain checksum", str)
	}

	// Round-trip: parse the stringified descriptor
	reparsed, err := ParseDescriptor(str, address.Mainnet)
	if err != nil {
		t.Fatalf("ParseDescriptor(String()) error: %v", err)
	}

	// Both should expand to same script
	scripts1, _ := parsed.Expand(0)
	scripts2, _ := reparsed.Expand(0)
	if hex.EncodeToString(scripts1[0]) != hex.EncodeToString(scripts2[0]) {
		t.Errorf("Round-trip produced different scripts")
	}
}

func TestGetDescriptorInfo(t *testing.T) {
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "wpkh(" + pubKeyHex + ")"

	info, err := GetDescriptorInfo(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("GetDescriptorInfo(%q) error: %v", desc, err)
	}

	if info.IsRange {
		t.Errorf("IsRange = true, want false")
	}
	if len(info.Checksum) != 8 {
		t.Errorf("Checksum length = %d, want 8", len(info.Checksum))
	}
	if !strings.Contains(info.Descriptor, "#") {
		t.Errorf("Descriptor should contain checksum")
	}
}

func TestDeriveAddresses(t *testing.T) {
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

	// Non-ranged descriptor
	t.Run("non-ranged", func(t *testing.T) {
		desc := "wpkh(" + pubKeyHex + ")"
		addrs, err := DeriveAddresses(desc, address.Mainnet, 0, 0)
		if err != nil {
			t.Fatalf("DeriveAddresses error: %v", err)
		}
		if len(addrs) != 1 {
			t.Errorf("len(addrs) = %d, want 1", len(addrs))
		}
	})

	// Ranged descriptor
	t.Run("ranged", func(t *testing.T) {
		xpub := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
		desc := "wpkh(" + xpub + "/0/*)"
		addrs, err := DeriveAddresses(desc, address.Mainnet, 0, 4)
		if err != nil {
			t.Fatalf("DeriveAddresses error: %v", err)
		}
		if len(addrs) != 5 { // 0, 1, 2, 3, 4
			t.Errorf("len(addrs) = %d, want 5", len(addrs))
		}

		// Each address should be unique
		seen := make(map[string]bool)
		for _, addr := range addrs {
			if seen[addr] {
				t.Errorf("Duplicate address: %s", addr)
			}
			seen[addr] = true
		}
	})
}

func TestParseDescriptorInvalidChecksum(t *testing.T) {
	desc := "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#badcheck"

	_, err := ParseDescriptor(desc, address.Mainnet)
	if err == nil {
		t.Errorf("Expected error for invalid checksum")
	}
}

func TestParseDescriptorInvalidKey(t *testing.T) {
	// Invalid hex key
	desc := "wpkh(invalidhexkey)"

	_, err := ParseDescriptor(desc, address.Mainnet)
	if err == nil {
		t.Errorf("Expected error for invalid key")
	}
}

func TestWIF(t *testing.T) {
	// Test mainnet WIF (compressed)
	wif := "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
	privKey, err := decodeWIF(wif, address.Mainnet)
	if err != nil {
		t.Fatalf("decodeWIF error: %v", err)
	}

	// Re-encode
	reencoded := EncodeWIF(privKey, address.Mainnet, true)
	if reencoded != wif {
		t.Errorf("EncodeWIF = %q, want %q", reencoded, wif)
	}
}
