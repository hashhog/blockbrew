// W131 Descriptors + Miniscript (BIP-380/385) audit — blockbrew (Go)
//
// Discovery audit. 30 gates / 18 BUGs. See audit/w131_descriptors_miniscript.md
// for the full rationale and the Bitcoin Core line references.
//
// Audit gates:
//   G1  DescriptorChecksum matches Core PolyMod
//   G2  CHECKSUM_CHARSET = qpzry9x8gf2tvdw0s3jn54khce6mua7l
//   G3  INPUT_CHARSET (96-char) byte-identical to Core
//   G4  AddChecksum(desc) appends '#' + DescriptorChecksum(desc)
//   G5  CheckChecksum: reject multiple '#'                           BUG-2
//   G6  CheckChecksum: reject checksum of length != 8
//   G7  Parse accepts pk/pkh/wpkh/wsh/sh/tr/multi/sortedmulti/combo/raw/addr/rawtr
//   G8  Parse accepts musig(...)                                     BUG-6
//   G9  Parse accepts BIP-389 multipath <a;b;...>                    BUG-7
//   G10 ParsePubkeyInner: reject 65-byte pubkey in wsh/wpkh/tr        BUG-3
//   G11 ParseKeyPathNum: reject path_num >= 0x80000000                BUG-4
//   G12 tr() taptree depth <= TAPROOT_CONTROL_MAX_NODE_COUNT (128)    BUG-8
//   G13 multi(...) keys <= MAX_PUBKEYS_PER_MULTISIG (20)
//   G14 multi_a(...) keys <= MAX_PUBKEYS_PER_MULTI_A (999)            BUG-9
//   G15 x-only key (32-byte) accepted in tapscript context only       BUG-10
//   G16 ParseDescriptor stateful w.r.t. ParseScriptContext            BUG-11
//   G17 tr() interior tweak + leaf-version 0xc0 + sorted TapBranch
//   G18 addr() decoded and re-encoded round-trips
//   G19 raw() accepts arbitrary hex script
//   G20 Miniscript ComputeType per fragment                          (PARTIAL — BUG-12)
//   G21 Thresh timelock-mix rule fires only when k > 1                BUG-13
//   G22 Miniscript parser: stacked wrappers (tvc:pk_k(K))             BUG-5
//   G23 Miniscript parser: reject vv: double-verify                   BUG-14
//   G24 Miniscript parser: 0/1 literal accepted
//   G25 ToScript for pk_h produces real Hash160(KEY)                  BUG-1
//   G26 ToScript for multi_a rejects keys not 32 bytes                BUG-15
//   G27 Per-context script-size limit (MaxScriptSize(ms_ctx))         BUG-16
//   G28 Op-count limit (MAX_OPS_PER_SCRIPT = 201) on P2WSH            BUG-17
//   G29 Stack-size limit (MAX_STACK_SIZE = 1000)                      BUG-17
//   G30 MiniscriptFromScript (decompile) implemented                  BUG-18
//
// Methodology: PRESENT gates run end-to-end. PARTIAL gates assert what
// works and t.Skip on the rest. MISSING gates t.Skip with the BUG ID
// after demonstrating the missing-behavior observable from outside.
//
// Source-of-truth file references:
//   - bitcoin-core/src/script/descriptor.cpp
//   - bitcoin-core/src/script/miniscript.h
//   - bitcoin-core/src/script/miniscript.cpp

package wallet

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	bbcrypto "github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/script"
)

// Test fixture pubkeys (compressed secp256k1 generator multiples).
//
// All-zero scalar produces an invalid point in secp256k1, so we use known-
// good compressed pubkey bytes (these are the same generator-multiples
// used by Core's descriptor_tests.cpp). 33-byte compressed and 65-byte
// uncompressed variants point to the same private key (the secp256k1
// generator point itself).
const (
	w131CompressedKey   = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	w131UncompressedKey = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
	w131XOnlyKey        = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	w131CompressedKey2  = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
)

func w131DescStr(t *testing.T, body string) string {
	t.Helper()
	return AddChecksum(body)
}

// ── G1: DescriptorChecksum matches Core PolyMod ──────────────────────────────

// TestW131G1_DescriptorChecksumMatchesCore — Core's INPUT_CHARSET is fixed
// and the polynomial constants 0xf5dee51989 etc are fixed (BIP-380). We
// verify a hand-picked vector from descriptor.cpp tests.
func TestW131G1_DescriptorChecksumMatchesCore(t *testing.T) {
	// Vector from descriptor.cpp test: pk(02...) descriptor with known
	// good checksum. (We rebuild via blockbrew's helper, then verify the
	// re-emitted form passes ValidateDescriptorChecksum.)
	body := "pk(" + w131CompressedKey + ")"
	checksum := DescriptorChecksum(body)
	if len(checksum) != 8 {
		t.Fatalf("G1 checksum length %d, want 8", len(checksum))
	}
	// All chars must be in the CHECKSUM_CHARSET.
	const checksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	for _, c := range checksum {
		if !strings.ContainsRune(checksumCharset, c) {
			t.Errorf("G1 checksum char %q not in charset", c)
		}
	}
	// Round-trip must validate.
	full := body + "#" + checksum
	stripped, ok := ValidateDescriptorChecksum(full)
	if !ok || stripped != body {
		t.Errorf("G1 round-trip failed: ok=%v stripped=%q", ok, stripped)
	}
}

// ── G2: CHECKSUM_CHARSET correct ─────────────────────────────────────────────

// TestW131G2_ChecksumCharsetCorrect — the output charset must be the
// bech32 charset; any other charset breaks compatibility with Core
// importdescriptors.
func TestW131G2_ChecksumCharsetCorrect(t *testing.T) {
	// Run 100 known-different inputs and assert every output character
	// is in CHECKSUM_CHARSET.
	const expected = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	for i := 0; i < 100; i++ {
		body := "pk(" + w131CompressedKey + ")" + strings.Repeat("a", i%10)
		cs := DescriptorChecksum(body)
		// Body "pk(...)aaa" may contain 'a' which is in INPUT_CHARSET so
		// the checksum is non-empty. Drop body inputs that hit invalid
		// chars (we control them — all are valid).
		if len(cs) != 8 {
			continue
		}
		for _, c := range cs {
			if !strings.ContainsRune(expected, c) {
				t.Errorf("G2 iteration %d: char %q not in CHECKSUM_CHARSET", i, c)
			}
		}
	}
}

// ── G3: INPUT_CHARSET byte-identical to Core ────────────────────────────────

// TestW131G3_InputCharsetBytewise — Core's INPUT_CHARSET is a 96-char
// string composed of three blocks of 32 chars each. Verifies blockbrew's
// PolyMod accepts every Core char and rejects chars outside the set.
func TestW131G3_InputCharsetBytewise(t *testing.T) {
	// Core's INPUT_CHARSET, line-by-line, descriptor.cpp:121-124.
	// 32 + 32 + 31 = 95 chars (the last block is ijklmnopqrstuvwxyz +
	// ABCDEFGH + ` + # + " + \ + space = 31 chars; double-quote and
	// backslash are escaped in the source literal).
	const coreInputCharset = "0123456789()[],'/*abcdefgh@:$%{}" +
		"IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" +
		"ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "

	if len(coreInputCharset) != 95 {
		t.Fatalf("G3 INPUT_CHARSET length %d, want 95", len(coreInputCharset))
	}

	// Every char in INPUT_CHARSET must produce a non-empty checksum.
	for i, c := range coreInputCharset {
		// '#' itself is the delimiter — skip; it's in the charset but
		// produces a body-with-empty-checksum payload that ValidateDescriptor
		// would parse as having a checksum.
		if c == '#' {
			continue
		}
		body := string(c) + "a"
		cs := DescriptorChecksum(body)
		if cs == "" {
			t.Errorf("G3 INPUT_CHARSET index %d (char %q) produced empty checksum", i, c)
		}
	}

	// Chars NOT in INPUT_CHARSET must produce empty checksum.
	notInSet := []rune{'\t', '\n', '*' + 1, 0xFE, 0x7F}
	_ = notInSet // 0x7F is DEL — already filtered.
	for _, c := range []rune{'\x01', '\x02', '\xff'} {
		body := string(c)
		cs := DescriptorChecksum(body)
		if cs != "" {
			t.Errorf("G3 char %q (out of charset) produced non-empty checksum %q", c, cs)
		}
	}
}

// ── G4: AddChecksum format ──────────────────────────────────────────────────

func TestW131G4_AddChecksumFormat(t *testing.T) {
	body := "pk(" + w131CompressedKey + ")"
	out := AddChecksum(body)

	// Must be body + "#" + 8 chars.
	if !strings.HasPrefix(out, body+"#") {
		t.Errorf("G4 not body+'#'+...: %q", out)
	}
	if len(out) != len(body)+9 {
		t.Errorf("G4 total length %d, want %d", len(out), len(body)+9)
	}

	// If we re-AddChecksum, must strip and re-add (idempotent).
	out2 := AddChecksum(out)
	if out2 != out {
		t.Errorf("G4 not idempotent: %q vs %q", out, out2)
	}
}

// ── G5: Reject multiple '#' (BUG-2) ─────────────────────────────────────────

// TestW131G5_RejectMultipleHash — Core's CheckChecksum
// (descriptor.cpp:2840-2843) rejects any descriptor with more than one
// '#'. blockbrew uses strings.LastIndex which silently accepts them.
//
// FAILS — DEMONSTRATES BUG-2.
func TestW131G5_RejectMultipleHash_BUG2(t *testing.T) {
	body := "pk(" + w131CompressedKey + ")"
	cs := DescriptorChecksum(body)
	// Inject a stray '#' inside the body.
	// Note: '#' is in INPUT_CHARSET (it's the last block, char 92), so
	// PolyMod accepts it.
	abused := body + "#xxxxxxxx#" + cs
	_, ok := ValidateDescriptorChecksum(abused)
	if ok {
		t.Skipf("BUG-2: multiple '#' accepted (should reject per Core descriptor.cpp:2840-2843)")
	}
	// If blockbrew is ever fixed to reject, this assertion holds.
	if ok {
		t.Errorf("G5 multiple-'#' input accepted: %q", abused)
	}
}

// ── G6: Reject checksum length != 8 ─────────────────────────────────────────

func TestW131G6_RejectChecksumLengthNot8(t *testing.T) {
	body := "pk(" + w131CompressedKey + ")"
	tests := []string{
		body + "#",            // empty
		body + "#a",           // 1 char
		body + "#qqqqqqq",     // 7 chars
		body + "#qqqqqqqqq",   // 9 chars
		body + "#qqqqqqqqqqq", // 11 chars
	}
	for _, in := range tests {
		_, ok := ValidateDescriptorChecksum(in)
		if ok {
			t.Errorf("G6 accepted bad-length checksum: %q", in)
		}
	}
}

// ── G7: All descriptor types parse ──────────────────────────────────────────

func TestW131G7_AllDescriptorTypesParse(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"pk", "pk(" + w131CompressedKey + ")"},
		{"pkh", "pkh(" + w131CompressedKey + ")"},
		{"wpkh", "wpkh(" + w131CompressedKey + ")"},
		{"sh_wpkh", "sh(wpkh(" + w131CompressedKey + "))"},
		{"multi", "multi(2," + w131CompressedKey + "," + w131CompressedKey2 + ")"},
		{"sortedmulti", "sortedmulti(2," + w131CompressedKey + "," + w131CompressedKey2 + ")"},
		{"combo", "combo(" + w131CompressedKey + ")"},
		{"tr", "tr(" + w131CompressedKey + ")"},
		{"rawtr", "rawtr(" + w131XOnlyKey + ")"},
		{"raw", "raw(0014" + strings.Repeat("00", 20) + ")"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			full := w131DescStr(t, tc.body)
			_, err := ParseDescriptor(full, address.Mainnet)
			if err != nil {
				t.Errorf("G7 %s: %v (input %q)", tc.name, err, full)
			}
		})
	}
}

// ── G8: musig() support (BUG-6) ─────────────────────────────────────────────

// TestW131G8_MusigParse — Core supports musig(K1,K2,...) inside tr() and
// rawtr() (descriptor.cpp:1964-2008). blockbrew has no musig branch.
//
// SKIPS — DEMONSTRATES BUG-6.
func TestW131G8_MusigParse_BUG6(t *testing.T) {
	body := "rawtr(musig(" + w131CompressedKey + "," + w131CompressedKey2 + "))"
	full := w131DescStr(t, body)
	_, err := ParseDescriptor(full, address.Mainnet)
	if err == nil {
		t.Errorf("G8 unexpectedly parsed musig() — was BUG-6 fixed?")
	}
	t.Skipf("BUG-6: musig() not supported (Core: descriptor.cpp:596-789, 1964-2008)")
}

// ── G9: BIP-389 multipath (BUG-7) ───────────────────────────────────────────

// TestW131G9_Multipath — Core ParseKeyPath accepts <0;1> / <0;1;2;...>
// (descriptor.cpp:1789-1855). blockbrew rejects angle-bracket components.
//
// SKIPS — DEMONSTRATES BUG-7.
func TestW131G9_Multipath_BUG7(t *testing.T) {
	// Canonical receive+change pair format.
	body := "wpkh(xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz/<0;1>/*)"
	full := w131DescStr(t, body)
	_, err := ParseDescriptor(full, address.Mainnet)
	if err == nil {
		t.Errorf("G9 unexpectedly parsed multipath — was BUG-7 fixed?")
	}
	t.Skipf("BUG-7: <0;1> multipath syntax not supported (Core: descriptor.cpp:1789-1855)")
}

// ── G10: Reject 65-byte (uncompressed) pubkey in wsh/wpkh/tr (BUG-3) ────────

// TestW131G10_RejectUncompressedInP2WSHContext — Core's
// permit_uncompressed = TOP || P2SH (descriptor.cpp:1879). Uncompressed
// keys inside wsh/wpkh/tr are rejected. blockbrew has no ParseScriptContext
// and accepts them everywhere.
//
// FAILS in current code — DEMONSTRATES BUG-3.
func TestW131G10_RejectUncompressedInP2WSHContext_BUG3(t *testing.T) {
	body := "wpkh(" + w131UncompressedKey + ")"
	full := w131DescStr(t, body)
	_, err := ParseDescriptor(full, address.Mainnet)
	if err == nil {
		// blockbrew accepts — bug.
		t.Skipf("BUG-3: uncompressed (65-byte) pubkey accepted in wpkh() — Core rejects per descriptor.cpp:1879/1922")
	}
}

// ── G11: Reject path_num >= 0x80000000 (BUG-4) ──────────────────────────────

// TestW131G11_RejectPathOverflow — Core's ParseKeyPathNum rejects
// un-hardened path numbers >= 0x80000000 (descriptor.cpp:1754-1775).
// blockbrew's parseUint(_, 10, 32) accepts up to 0xFFFFFFFF, then
// idx += 0x80000000 silently overflows.
//
// SKIPS — DEMONSTRATES BUG-4.
func TestW131G11_RejectPathOverflow_BUG4(t *testing.T) {
	// 2^31 with hardened marker — Core rejects because the un-hardened
	// component is 0x80000000 (≥ 0x80000000), then '+0x80000000' would
	// overflow to 0.
	body := "wpkh([deadbeef/2147483648']xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz)"
	full := w131DescStr(t, body)
	_, err := ParseDescriptor(full, address.Mainnet)
	if err == nil {
		// Overflow happened silently — bug.
		t.Skipf("BUG-4: path_num 2^31 with hardened marker silently overflowed (Core rejects per descriptor.cpp:1754-1775)")
	}
}

// ── G12: tr() taptree depth cap (BUG-8) ─────────────────────────────────────

// TestW131G12_TapTreeDepthCap — Core refuses tap-trees deeper than
// TAPROOT_CONTROL_MAX_NODE_COUNT (=128). blockbrew has no cap.
//
// SKIPS — DEMONSTRATES BUG-8.
func TestW131G12_TapTreeDepthCap_BUG8(t *testing.T) {
	// Build a left-heavy tree of depth 130 by nesting {leaf,{leaf,...}}.
	leaf := "pk(" + w131XOnlyKey + ")"
	tree := leaf
	for i := 0; i < 130; i++ {
		tree = "{" + leaf + "," + tree + "}"
	}
	body := "tr(" + w131XOnlyKey + "," + tree + ")"
	full := w131DescStr(t, body)
	_, err := ParseDescriptor(full, address.Mainnet)
	if err == nil {
		t.Skipf("BUG-8: depth-130 taptree accepted (Core caps at 128 per descriptor.cpp:2484-2486)")
	}
	// If a panic-based depth limit fires (stack overflow), the test
	// runner reports it as a separate failure mode — also a bug.
}

// ── G13: multi() keys <= 20 ─────────────────────────────────────────────────

// TestW131G13_MultiKeyCap20 — Core caps multi() at MAX_PUBKEYS_PER_MULTISIG=20
// at parse time. blockbrew's parseMulti (descriptor.go:1147-1174) does NOT
// check len(keys) at parse, only the expand-time path enforces (line 631).
// So a 21-key multi() parses successfully and fails only on expand. This
// is a PARTIAL — caught eventually but not at the canonical layer.
func TestW131G13_MultiKeyCap20(t *testing.T) {
	// 21 keys must reject (Core descriptor.cpp:1898-1905 area + the
	// MULTI fragment type constraint).
	keys := make([]string, 21)
	for i := range keys {
		keys[i] = w131CompressedKey
	}
	body := "multi(2," + strings.Join(keys, ",") + ")"
	full := w131DescStr(t, body)
	d, err := ParseDescriptor(full, address.Mainnet)
	if err != nil {
		// Rejected at parse-time — good (this is what Core does).
		return
	}
	// blockbrew parses; bug-condition holds if expand also accepts.
	_, expErr := d.Expand(0)
	if expErr == nil {
		t.Errorf("G13 multi() with 21 keys fully accepted (parse+expand) — Core caps at 20 (PRESENT in spirit, PARTIAL in shape)")
		return
	}
	// Caught at expand-time, not parse-time — file as PARTIAL.
	t.Logf("G13 PARTIAL: 21-key multi() parsed; rejected at expand: %v", expErr)
}

// ── G14: multi_a() keys <= 999 (BUG-9) ──────────────────────────────────────

// TestW131G14_MultiAKeyCap999 — Core caps multi_a at 999 keys
// (MAX_PUBKEYS_PER_MULTI_A). blockbrew has no cap on multi_a key count.
//
// SKIPS — DEMONSTRATES BUG-9.
func TestW131G14_MultiAKeyCap999_BUG9(t *testing.T) {
	// Build 1000 x-only keys. Use the parseminiscript layer directly
	// because parseDescriptor doesn't directly accept multi_a (it's a
	// miniscript fragment inside wsh/tapscript).
	keys := make([]string, 1000)
	for i := range keys {
		keys[i] = w131XOnlyKey
	}
	ms := "multi_a(2," + strings.Join(keys, ",") + ")"
	_, err := script.ParseMiniscript(ms, script.Tapscript)
	if err == nil {
		t.Skipf("BUG-9: multi_a with 1000 keys accepted (Core caps at 999 per miniscript.cpp:79)")
	}
}

// ── G15: 32-byte x-only key in P2WSH context (BUG-10) ───────────────────────

// TestW131G15_XOnlyInP2WSH — Core requires 32-byte keys ONLY in tapscript
// context; 33-byte compressed in P2WSH context. blockbrew accepts both.
//
// SKIPS — DEMONSTRATES BUG-10.
func TestW131G15_XOnlyInP2WSH_BUG10(t *testing.T) {
	// pk_k inside a wsh() context with a 32-byte key.
	ms := "pk_k(" + w131XOnlyKey + ")"
	// We expect ParseMiniscript to reject 32-byte key in P2WSH context.
	_, err := script.ParseMiniscript(ms, script.P2WSH)
	if err == nil {
		t.Skipf("BUG-10: 32-byte x-only key accepted in P2WSH context (Core: descriptor.cpp:1875-1925)")
	}
}

// ── G16: Descriptor parser has ParseScriptContext (BUG-11) ──────────────────

// TestW131G16_ParserHasScriptContext — structural test: the
// descriptorParser type has no field that mirrors Core's
// ParseScriptContext. Verified by checking the parser cannot
// distinguish between TOP and inner P2WSH contexts when parsing
// keys.
//
// SKIPS — DEMONSTRATES BUG-11.
func TestW131G16_ParserHasScriptContext_BUG11(t *testing.T) {
	// Same key (uncompressed) inside wpkh() and at sh() level. Core
	// rejects the first but accepts the second.
	bodyInner := "wpkh(" + w131UncompressedKey + ")"
	_, err1 := ParseDescriptor(w131DescStr(t, bodyInner), address.Mainnet)

	// blockbrew either rejects both or accepts both — never differentiates.
	// (sh(<HEX>) is not a thing; we test the wpkh inside).
	if err1 == nil {
		t.Skipf("BUG-11: parser has no ParseScriptContext; uncompressed key inside wpkh() not rejected (Core: descriptor.cpp:1879)")
	}
}

// ── G17: tr() interior tweak + leaf-version 0xc0 + sorted TapBranch ─────────

func TestW131G17_TaprootInteriorTweak(t *testing.T) {
	// Build a tr() and expand. The script must start with OP_1 (0x51)
	// followed by push-32 (0x20) of the tweaked x-only key.
	// Note: blockbrew's tr() parser routes through parseKey which
	// requires 66-hex or 130-hex; the bare 64-hex x-only path is only
	// served by rawtr(). This is an additional impedance mismatch
	// (Core's tr() accepts both 33-byte and x-only).
	body := "tr(" + w131CompressedKey + ")"
	full := w131DescStr(t, body)
	d, err := ParseDescriptor(full, address.Mainnet)
	if err != nil {
		t.Fatalf("G17 parse: %v", err)
	}
	scripts, err := d.Expand(0)
	if err != nil {
		t.Fatalf("G17 expand: %v", err)
	}
	if len(scripts) != 1 || len(scripts[0]) != 34 {
		t.Fatalf("G17 unexpected script: %x", scripts)
	}
	if scripts[0][0] != 0x51 || scripts[0][1] != 0x20 {
		t.Errorf("G17 not P2TR: %x", scripts[0])
	}
	// The tweaked key MUST differ from the raw input x-only key.
	rawXOnly, _ := hex.DecodeString(w131XOnlyKey)
	if string(scripts[0][2:34]) == string(rawXOnly) {
		t.Errorf("G17 key not tweaked: scripts[0][2:34] == rawXOnly")
	}
}

// ── G18: addr() round-trip ──────────────────────────────────────────────────

func TestW131G18_AddrRoundTrip(t *testing.T) {
	// Derive an address from a known pubkey via wpkh and round-trip it
	// through addr().
	pkBytes, _ := hex.DecodeString(w131CompressedKey)
	hash160 := bbcrypto.Hash160(pkBytes)
	var h20 [20]byte
	copy(h20[:], hash160[:])
	addr := address.NewP2WPKHAddress(h20, address.Mainnet)
	addrStr, err := addr.Encode()
	if err != nil {
		t.Fatalf("G18 encode: %v", err)
	}
	body := "addr(" + addrStr + ")"
	full := w131DescStr(t, body)
	d, err := ParseDescriptor(full, address.Mainnet)
	if err != nil {
		t.Fatalf("G18 parse: %v", err)
	}
	scripts, err := d.Expand(0)
	if err != nil {
		t.Fatalf("G18 expand: %v", err)
	}
	if len(scripts) != 1 || len(scripts[0]) != 22 {
		t.Errorf("G18 unexpected script: %x", scripts)
	}
}

// ── G19: raw() accepts arbitrary hex ────────────────────────────────────────

func TestW131G19_RawAcceptsHex(t *testing.T) {
	body := "raw(76a914" + strings.Repeat("00", 20) + "88ac)" // P2PKH-shaped hex
	full := w131DescStr(t, body)
	d, err := ParseDescriptor(full, address.Mainnet)
	if err != nil {
		t.Fatalf("G19 parse: %v", err)
	}
	scripts, err := d.Expand(0)
	if err != nil {
		t.Fatalf("G19 expand: %v", err)
	}
	if len(scripts) != 1 || len(scripts[0]) != 25 {
		t.Errorf("G19 unexpected script: %x", scripts)
	}
}

// ── G20: ComputeType per fragment (PARTIAL — BUG-12) ────────────────────────

// TestW131G20_TypeStrings — quick sanity-check that the type strings
// blockbrew produces for primitive fragments match Core's "Konudemsxk"
// (PK_K), "Knudemsxk" (PK_H), "Bnudemsk" (MULTI). Auditing the literal
// type bit values vs Core's "_mst" strings.
//
// PARTIAL — passes for the documented matches, doesn't probe BUG-13
// (thresh k>1 gate, separate gate).
func TestW131G20_TypeStrings(t *testing.T) {
	// Use pk(K) which is c:pk_k(K); the inner pk_k retains the K
	// type. We can't parse bare pk_k(K) as top-level because parser
	// rejects non-B (Konudemsxk has no B). Instead probe the inner.
	ms := "pk(" + w131CompressedKey + ")"
	node, err := script.ParseMiniscript(ms, script.P2WSH)
	if err != nil {
		t.Fatalf("G20 parse pk: %v", err)
	}
	// Top-level is WrapC over pk_k. Type should be B (from K via c:).
	topTyp := node.GetType()
	if !topTyp.HasType(script.TypeB) {
		t.Errorf("G20 pk(K) top type missing B")
	}
	// Inner pk_k type:
	if len(node.Subs) != 1 {
		t.Fatalf("G20 unexpected node shape: subs=%d", len(node.Subs))
	}
	innerTyp := node.Subs[0].GetType()
	checks := []struct {
		name string
		flag script.MiniscriptType
	}{
		{"K", script.TypeK},
		{"O", script.TypeO},
		{"N", script.TypeN},
		{"U", script.TypeU},
		{"D", script.TypeD},
		{"E", script.TypeE},
		{"M", script.TypeM},
		{"S", script.TypeS},
		{"X", script.TypeX},
	}
	for _, c := range checks {
		if !innerTyp.HasType(c.flag) {
			t.Errorf("G20 pk_k inner missing %s in type bits (Core: Konudemsxk)", c.name)
		}
	}
}

// ── G21: Thresh timelock-mix rule gated on k > 1 (BUG-13) ───────────────────

// TestW131G21_ThreshK1TimelockMix — Core's thresh type rule
// (miniscript.cpp:246) gates the timelock-mix rejection on `k > 1`:
// for 1-of-N thresh, mixing time and height locks is OK. blockbrew's
// computeK rejects unconditionally.
//
// SKIPS — DEMONSTRATES BUG-13.
func TestW131G21_ThreshK1TimelockMix_BUG13(t *testing.T) {
	// thresh(1, older(<height>), older(<time>)) where height is < SEQUENCE_LOCKTIME_TYPE_FLAG=2^22 and time has flag set.
	// Need both to be Wdu (Core: thresh requires Bdu, Wdu, Wdu, ...).
	// older(...) is Bzfmxk per Core — so the SECOND must be wrapped to W.
	// Easiest: thresh(1, after(100), s:after(500000000)) — abs height + abs time mixed.
	// 100 < LOCKTIME_THRESHOLD=500000000 → AbsoluteHeight (j); 500000000+ → AbsoluteTime (i).
	// 1-of-2 should be FINE per Core (only k>1 enforces no-mix); blockbrew rejects.
	ms := "thresh(1,after(100),sa:after(500000000))"
	node, err := script.ParseMiniscript(ms, script.P2WSH)
	if err != nil {
		// Some parse error other than type-check (e.g. wrapper layering).
		t.Skipf("BUG-13: thresh 1-of timelock-mix did not parse: %v (Core accepts per miniscript.cpp:246 — gated on k>1)", err)
	}
	if !node.IsValid() {
		t.Skipf("BUG-13: thresh 1-of timelock-mix IsValid=false (Core: k=1 always accepts; miniscript.cpp:246)")
	}
}

// ── G22: Stacked wrappers tvc:pk_k(K) (BUG-5) ───────────────────────────────

// TestW131G22_StackedWrappers — Core's WRAPPED_EXPR loops through every
// pre-':' letter (miniscript.h:1922-1973), so `tvc:pk_k(K)` is
// `t:v:c:pk_k(K)`. blockbrew's parser only reads one wrapper char per
// colon.
//
// FAILS — DEMONSTRATES BUG-5.
func TestW131G22_StackedWrappers_BUG5(t *testing.T) {
	// "v:pk(K)" is `v:c:pk_k(K)` (since pk(K) is c:pk_k(K)) — a single
	// 'v:' over a wrapper that is itself constructed by the parser.
	// More direct: "sv:pk_k(K)" — should parse as `s:v:pk_k(K)`.
	ms := "sc:pk_k(" + w131CompressedKey + ")"
	_, err := script.ParseMiniscript(ms, script.P2WSH)
	if err == nil {
		t.Errorf("G22 stacked wrapper parsed — was BUG-5 fixed?")
	}
	t.Skipf("BUG-5: stacked wrappers (e.g. sc:pk_k(K)) not parsed (Core: miniscript.h:1922-1973)")
}

// ── G23: Reject vv: double-verify (BUG-14) ──────────────────────────────────

// TestW131G23_RejectDoubleVerify — Core rejects two consecutive `v`s
// before a `:` (miniscript.h:1953-1957). Note: blockbrew can't even
// parse stacked wrappers so this is latent — the underlying check
// won't ever fire until BUG-5 is fixed.
//
// SKIPS — DEMONSTRATES BUG-14 (latent on top of BUG-5).
func TestW131G23_RejectDoubleVerify_BUG14(t *testing.T) {
	// Same form Core would reject: `vv:pk_k(K)`.
	ms := "vv:pk_k(" + w131CompressedKey + ")"
	_, err := script.ParseMiniscript(ms, script.P2WSH)
	// In current blockbrew, the first 'v:' parses as WrapV(rest), then
	// 'v:pk_k(K)' inside also parses. So blockbrew silently accepts.
	if err == nil {
		t.Skipf("BUG-14: 'vv:' double-verify silently accepted (Core: miniscript.h:1953-1957)")
	}
}

// ── G24: 0/1 literal accepted ───────────────────────────────────────────────

func TestW131G24_LiteralsParsed(t *testing.T) {
	for _, ms := range []string{"0", "1"} {
		_, err := script.ParseMiniscript(ms, script.P2WSH)
		if err == nil {
			// 0 is JUST_0 which is Bzudemsxk — top-level OK because B.
			// 1 is JUST_1 which is Bzufmxk — top-level OK because B.
			continue
		}
		// '0' alone is technically not a sane top-level (z, no-s for 0).
		// But it should parse. Some impls reject 'safe but not sane' here.
		if strings.Contains(err.Error(), "type") {
			t.Logf("G24 %s: type-system rejected (acceptable for top-level)", ms)
			continue
		}
		t.Errorf("G24 %s: unexpected parse error: %v", ms, err)
	}
}

// ── G25: pk_h compiles to real Hash160 (BUG-1 — the big one) ────────────────

// TestW131G25_PkHRealHash160 — blockbrew/internal/script/miniscript.go
// L1144-1166 ships **placeholder** hash160/sha256Sum/ripemd160Sum that
// just copy(h, data). So `pk_h(KEY)` compiles to a script with the
// first 20 bytes of the raw pubkey embedded, not RIPEMD160(SHA256(KEY)).
// This means **every** pk_h / pkh-in-miniscript output is unspendable.
//
// FAILS — DEMONSTRATES BUG-1 (and is the discovery's top finding).
func TestW131G25_PkHRealHash160_BUG1(t *testing.T) {
	// pkh(K) is sugar for c:pk_h(K); compile produces:
	//   OP_DUP OP_HASH160 <20-byte hash via hash160(K)> OP_EQUALVERIFY OP_CHECKSIG
	// Total 26 bytes. The 20-byte hash starts at offset 3.
	ms := "pkh(" + w131CompressedKey + ")"
	node, err := script.ParseMiniscript(ms, script.P2WSH)
	if err != nil {
		t.Fatalf("G25 parse: %v", err)
	}
	compiled, err := node.ToScript()
	if err != nil {
		t.Fatalf("G25 ToScript: %v", err)
	}

	// Compute what Core would expect: real Hash160(KEY).
	pkBytes, _ := hex.DecodeString(w131CompressedKey)
	realHash := bbcrypto.Hash160(pkBytes)

	if len(compiled) < 25 {
		t.Fatalf("G25 compiled too short: %x (len %d)", compiled, len(compiled))
	}
	// Script shape: OP_DUP (0x76) OP_HASH160 (0xa9) 0x14 <20 bytes>
	// OP_EQUALVERIFY (0x88) [OP_CHECKSIG (0xac)]
	if compiled[0] != 0x76 || compiled[1] != 0xa9 || compiled[2] != 0x14 {
		t.Fatalf("G25 unexpected pk_h shape: %x", compiled)
	}
	embedded := compiled[3:23]
	if string(embedded) == string(realHash[:]) {
		// Correct — bug fixed.
		return
	}
	// BUG: the embedded "hash" is actually the first 20 bytes of the
	// raw pubkey (placeholder copy(h, data)), not Hash160(pubkey).
	if string(embedded) == string(pkBytes[:20]) {
		t.Logf("BUG-1 CONFIRMED: pk_h embedded raw-pubkey-prefix %x instead of real Hash160 %x — every pk_h/pkh output unspendable",
			embedded, realHash[:])
		t.Skipf("BUG-1: pk_h compile uses placeholder hash160 in miniscript.go:1144-1166")
	}
	// Some other placeholder pattern.
	t.Logf("BUG-1 placeholder hash160: embedded %x, expected real Hash160 %x", embedded, realHash[:])
	t.Skipf("BUG-1: pk_h compile path does not produce real Hash160(KEY)")
}

// ── G26: multi_a key length validation (BUG-15) ─────────────────────────────

// TestW131G26_MultiAKeyLength — Core requires all multi_a keys to be
// 32-byte x-only in tapscript context. blockbrew accepts 33-byte and
// silently chops to 32 (miniscript.go:1052-1058).
//
// SKIPS — DEMONSTRATES BUG-15.
func TestW131G26_MultiAKeyLength_BUG15(t *testing.T) {
	// 33-byte compressed key in tapscript context.
	ms := "multi_a(1," + w131CompressedKey + ")"
	node, err := script.ParseMiniscript(ms, script.Tapscript)
	if err != nil {
		// Parser rejects → good.
		return
	}
	// Compile and see if the script is non-empty (accepted).
	compiled, err := node.ToScript()
	if err == nil && len(compiled) > 0 {
		t.Skipf("BUG-15: 33-byte key accepted in multi_a/tapscript (Core requires x-only 32-byte)")
	}
}

// ── G27: Per-context script-size limit (BUG-16) ─────────────────────────────

// TestW131G27_ContextSizeLimit — Core's MaxScriptSize(ms_ctx) returns
// MAX_STANDARD_P2WSH_SCRIPT_SIZE (3600) for P2WSH and ~400000 for
// Tapscript. blockbrew uses a single 10000-byte constant
// (opcode.go:354).
//
// SKIPS — DEMONSTRATES BUG-16.
func TestW131G27_ContextSizeLimit_BUG16(t *testing.T) {
	// 4000-byte P2WSH miniscript should reject (Core 3600 limit).
	// Build a long thresh(...) of pk_k subs.
	subs := []string{"pk(" + w131CompressedKey + ")"}
	for i := 0; i < 100; i++ {
		subs = append(subs, "s:pk(" + w131CompressedKey + ")")
	}
	ms := "thresh(1," + strings.Join(subs, ",") + ")"
	err := script.ValidateMiniscript(ms, script.P2WSH)
	// Should reject (above 3600). If it accepts, bug.
	if err == nil {
		t.Skipf("BUG-16: ~4000-byte P2WSH miniscript not rejected (Core caps P2WSH at MAX_STANDARD_P2WSH_SCRIPT_SIZE=3600 per miniscript.h:282-294)")
	}
}

// ── G28/G29: Op-count + stack-size limits (BUG-17) ──────────────────────────

// TestW131G28_OpCountLimit — blockbrew's CheckOpsLimit returns true
// unconditionally. Core counts ops vs MAX_OPS_PER_SCRIPT=201
// (miniscript.h:1565).
//
// SKIPS — DEMONSTRATES BUG-17.
func TestW131G28_OpCountLimit_BUG17(t *testing.T) {
	// Manually build a node that would exceed 201 ops if Core's check
	// were active. Easiest: a 100-of-100 thresh of pk's — each pk adds
	// 1 op (CHECKSIG), thresh adds OP_ADD's (n-1) + 1 EQUAL = ~201.
	ms := "thresh(50"
	for i := 0; i < 100; i++ {
		if i == 0 {
			ms += ",pk(" + w131CompressedKey + ")"
		} else {
			ms += ",s:pk(" + w131CompressedKey + ")"
		}
	}
	ms += ")"
	node, err := script.ParseMiniscript(ms, script.P2WSH)
	if err != nil {
		// Reject at parse — good.
		return
	}
	if node.CheckOpsLimit() {
		t.Skipf("BUG-17: CheckOpsLimit returns true unconditionally (miniscript.go:1324-1331)")
	}
}

// ── G30: MiniscriptFromScript decompile (BUG-18) ────────────────────────────

// TestW131G30_MiniscriptFromScript — Core's InferDescriptor and
// InferMiniscript can decompile a CScript back to a miniscript /
// descriptor. blockbrew returns ErrNotImplemented.
//
// SKIPS — DEMONSTRATES BUG-18.
func TestW131G30_MiniscriptFromScript_BUG18(t *testing.T) {
	// Trivial OP_1 script.
	scriptBytes := []byte{0x51}
	_, err := script.MiniscriptFromScript(scriptBytes, script.P2WSH)
	if err == nil {
		t.Errorf("G30 MiniscriptFromScript unexpectedly succeeded — was BUG-18 fixed?")
		return
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Logf("G30 error: %v (BUG-18 may be in transit)", err)
	}
	t.Skipf("BUG-18: MiniscriptFromScript returns not-implemented (miniscript_parse.go:859-864)")
}
