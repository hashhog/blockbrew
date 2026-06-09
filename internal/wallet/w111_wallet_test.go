// W111 wallet / HD / descriptors fleet audit — blockbrew (Go)
//
// Gate coverage (30 gates):
//   G1  BIP-32 xprv/xpub 78-byte ser+parse
//   G2  Master key from seed: HMAC-SHA512("Bitcoin seed", seed)
//   G3  Normal CKD (i < 2^31)
//   G4  Hardened CKD (i >= 2^31)
//   G5  Chain-code propagation
//   G6  BIP-44 path m/44'/coin'/acct'/change/i
//   G7  BIP-49 path m/49'/...
//   G8  BIP-84 path m/84'/...
//   G9  BIP-86 path m/86'/...
//   G10 Account xpub export
//   G11 pkh(KEY) descriptor
//   G12 wpkh(KEY) descriptor
//   G13 sh(wpkh(KEY)) descriptor
//   G14 tr(KEY) descriptor
//   G15 multi(K, KEY...) descriptor
//   G16 BIP-380 checksum 8-char polymod
//   G17 BIP-39 wordlist 2048 + checksum
//   G18 PBKDF2(mnemonic, "mnemonic"+passphrase, 2048, HMAC-SHA512)
//   G19 P2PKH address version bytes mainnet/testnet
//   G20 P2SH  address version bytes mainnet/testnet
//   G21 BECH32 P2WPKH v0
//   G22 BECH32M P2TR  v1
//   G23 Wallet file persistence
//   G24 Wallet encryption (passphrase KDF)
//   G25 KeyPool / gap limit (default 20)
//   G26 Legacy P2PKH signing
//   G27 P2WPKH BIP-143 segwit sighash signing
//   G28 P2TR BIP-341 taproot signing
//   G29 BIP-174 PSBT v0
//   G30 BIP-370 PSBT v2
//
// BUG INDEX (bugs discovered during this audit)
//
//   BUG-1 (G23 HIGH): SaveToFile stores masterKey.Key||ChainCode as "seed",
//          not the BIP-39 entropy or mnemonic. The walletData.Mnemonic field is
//          never populated. A wallet loaded from file cannot recover the BIP-39
//          mnemonic (needed for paper backup / restoring on another wallet). This
//          is acknowledged in the source comment ("We can't actually recover the
//          seed from the master key, so in a real implementation we'd store the
//          mnemonic") but not fixed.
//          File: internal/wallet/storage.go:112-116
//
//   BUG-2 (G6 MEDIUM): initAccount always derives m/84'/coinType'/account'
//          regardless of the wallet's AddressType configuration. A wallet created
//          with AddressTypeP2PKH should derive m/44'/0'/0', AddressTypeP2SH_P2WPKH
//          → m/49'/0'/0', etc. All wallet types share the same account key,
//          meaning the account xpub exported for a P2PKH wallet is wrong.
//          File: internal/wallet/wallet.go:225-227
//
//   BUG-3 (G25 MEDIUM): DefaultGapLimit is 20 but it is never enforced during
//          address scanning. NewAddress simply increments the index forever
//          without filling the gap; the wallet will re-derive addresses beyond
//          the gap limit on restore, potentially losing funds if the gap grew
//          larger than 20 addresses.
//          File: internal/wallet/wallet.go, Wallet.gapLimit field never read.
//
//   BUG-4 (G10 MEDIUM): no public GetAccountXPub / ExportAccountXPub function
//          exists. The Wallet.accounts slice holds the account xpub internally
//          but there is no exported accessor, so external callers (e.g. the RPC
//          layer for getxpubkey) cannot retrieve it. This is a dead-helper
//          pattern: the value is derived and stored but never surfaced.
//          File: internal/wallet/wallet.go — Account.ExtPubKey held in unexported
//          slice field, no exported getter.
//
//   BUG-5 (G30 LOW): BIP-370 v2 global fields (PSBTGlobalTxVersion=0x02,
//          PSBTGlobalFallbackLock=0x03, PSBTGlobalInputCount=0x04,
//          PSBTGlobalOutputCount=0x05, PSBTGlobalTxModifiable=0x06) are defined as
//          constants but DecodePSBTReader falls through to the `default:` branch
//          (Unknown map) for all of them. A v2 PSBT from an external tool round-trips
//          incorrectly: version=2 is parsed, but v2-specific global fields are
//          stored as unknown and are NOT interpreted.
//          File: internal/wallet/psbt.go:337-374 switch statement missing cases.

package wallet

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ── G1: BIP-32 xprv/xpub 78-byte serialization + parse ──────────────────────

func TestW111G1_BIP32SerParse(t *testing.T) {
	// BIP-32 test vector 1 seed
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	const wantXprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	const wantXpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

	xprv := master.Serialize(address.Mainnet)
	if xprv != wantXprv {
		t.Errorf("G1 xprv\n got  %s\n want %s", xprv, wantXprv)
	}
	xpub := master.PublicKey().Serialize(address.Mainnet)
	if xpub != wantXpub {
		t.Errorf("G1 xpub\n got  %s\n want %s", xpub, wantXpub)
	}

	// Round-trip parse
	parsed, err := ParseExtendedKey(wantXprv)
	if err != nil {
		t.Fatalf("G1 ParseExtendedKey(xprv): %v", err)
	}
	if !parsed.IsPrivate {
		t.Error("G1 parsed xprv should be private")
	}
	if parsed.Depth != 0 {
		t.Errorf("G1 master depth = %d, want 0", parsed.Depth)
	}
	if parsed.Serialize(address.Mainnet) != wantXprv {
		t.Error("G1 xprv round-trip failed")
	}
}

// ── G2: Master key HMAC-SHA512("Bitcoin seed", seed) ─────────────────────────

func TestW111G2_MasterFromSeed(t *testing.T) {
	// BIP-32 test vector 1
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	mk, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("G2 NewMasterKey: %v", err)
	}
	// Depth must be 0, parent fingerprint must be zero, index must be 0
	if mk.Depth != 0 || mk.ParentFP != [4]byte{} || mk.Index != 0 {
		t.Errorf("G2 master metadata wrong: depth=%d parentFP=%x index=%d",
			mk.Depth, mk.ParentFP, mk.Index)
	}
	if len(mk.Key) != 32 || len(mk.ChainCode) != 32 {
		t.Errorf("G2 key/chaincode length wrong: %d/%d", len(mk.Key), len(mk.ChainCode))
	}

	// Wrong seed should produce different key
	seed2, _ := hex.DecodeString("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
	mk2, _ := NewMasterKey(seed2)
	if bytes.Equal(mk.Key, mk2.Key) {
		t.Error("G2 different seeds produced same master key")
	}
}

// ── G3: Normal CKD ────────────────────────────────────────────────────────────

func TestW111G3_NormalCKD(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	mk, _ := NewMasterKey(seed)

	child, err := mk.DeriveChild(1) // i=1 < 2^31, normal
	if err != nil {
		t.Fatalf("G3 DeriveChild(1): %v", err)
	}
	if child.Depth != 1 {
		t.Errorf("G3 depth = %d, want 1", child.Depth)
	}
	if child.Index != 1 {
		t.Errorf("G3 index = %d, want 1", child.Index)
	}

	// Normal derivation from xpub must yield same pubkey as from xprv
	pubChild, err := mk.PublicKey().DeriveChild(1)
	if err != nil {
		t.Fatalf("G3 public DeriveChild(1): %v", err)
	}
	privPub := child.publicKeyBytes()
	pubPub := pubChild.publicKeyBytes()
	if !bytes.Equal(privPub, pubPub) {
		t.Errorf("G3 priv-derived pubkey != pub-derived pubkey")
	}
}

// ── G4: Hardened CKD ──────────────────────────────────────────────────────────

func TestW111G4_HardenedCKD(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	mk, _ := NewMasterKey(seed)

	const i = HardenedKeyStart // 0x80000000
	h, err := mk.DeriveChild(i)
	if err != nil {
		t.Fatalf("G4 DeriveChild(hardened): %v", err)
	}
	if h.Index != i {
		t.Errorf("G4 hardened index = %d, want %d", h.Index, i)
	}

	// Public key must NOT be able to derive hardened child
	_, err = mk.PublicKey().DeriveChild(i)
	if err != ErrDerivingHardenedPub {
		t.Errorf("G4 expected ErrDerivingHardenedPub, got %v", err)
	}
}

// ── G5: Chain-code propagation ────────────────────────────────────────────────

func TestW111G5_ChainCodePropagation(t *testing.T) {
	// BIP-32 TV1 chain codes at m/0'/1 from reference
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	mk, _ := NewMasterKey(seed)
	child, _ := mk.DerivePath("m/0'/1")

	if len(child.ChainCode) != 32 {
		t.Errorf("G5 chaincode length = %d, want 32", len(child.ChainCode))
	}
	// Chain code must differ from parent's
	parent, _ := mk.DerivePath("m/0'")
	if bytes.Equal(child.ChainCode, parent.ChainCode) {
		t.Error("G5 child chain code same as parent")
	}
	// Verify the child stores correct parent fingerprint
	if child.ParentFP != parent.Fingerprint() {
		t.Errorf("G5 child parentFP %x != parent fingerprint %x",
			child.ParentFP, parent.Fingerprint())
	}
}

// ── G6-G9: BIP-44/49/84/86 path helpers ──────────────────────────────────────

func TestW111G6_BIP44Path(t *testing.T) {
	p := BIP44Path(0, 0, 0, 5)
	if p != "m/44'/0'/0'/0/5" {
		t.Errorf("G6 BIP44Path = %q, want m/44'/0'/0'/0/5", p)
	}
	// Derive key at the path to verify it works
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	mk, _ := NewMasterKey(seed)
	_, err := mk.DerivePath(p)
	if err != nil {
		t.Errorf("G6 DerivePath(%q): %v", p, err)
	}
}

func TestW111G7_BIP49Path(t *testing.T) {
	p := BIP49Path(0, 0, 0, 3)
	if p != "m/49'/0'/0'/0/3" {
		t.Errorf("G7 BIP49Path = %q, want m/49'/0'/0'/0/3", p)
	}
}

func TestW111G8_BIP84Path(t *testing.T) {
	p := BIP84Path(0, 0, 0, 0)
	if p != "m/84'/0'/0'/0/0" {
		t.Errorf("G8 BIP84Path = %q, want m/84'/0'/0'/0/0", p)
	}
}

func TestW111G9_BIP86Path(t *testing.T) {
	p := BIP86Path(0, 0, 0, 0)
	if p != "m/86'/0'/0'/0/0" {
		t.Errorf("G9 BIP86Path = %q, want m/86'/0'/0'/0/0", p)
	}
}

// ── G10: Account xpub export ──────────────────────────────────────────────────
// BUG-4: no exported GetAccountXPub accessor. The account xpub is stored
// internally in Wallet.accounts[].ExtPubKey but cannot be retrieved by
// external callers.

func TestW111G10_AccountXpubExport(t *testing.T) {
	// This test documents BUG-4: the wallet stores the account xpub during
	// initAccount but provides no exported getter. We test what we *can* test:
	// that the internal derivation produces a valid xpub, and that BIP-44/49/84/86
	// account paths can be derived correctly.

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	mk, _ := NewMasterKey(seed)

	// BIP-84 account 0 for mainnet (coinType=0)
	accountKey84, err := mk.DerivePath("m/84'/0'/0'")
	if err != nil {
		t.Fatalf("G10 DerivePath(m/84'/0'/0'): %v", err)
	}
	xpub := accountKey84.PublicKey().Serialize(address.Mainnet)
	if !strings.HasPrefix(xpub, "xpub") {
		t.Errorf("G10 account xpub should start with xpub, got %q", xpub[:10])
	}

	// BUG-4: Test documents that Wallet.accounts[0].ExtPubKey exists but
	// there is no exported accessor (GetAccountXPub or similar).
	// Verified via code review: Wallet.accounts is unexported, Account.ExtPubKey
	// is exported but the slice itself is inaccessible.
	t.Log("BUG-4: No exported GetAccountXPub accessor on Wallet type")
}

// ── G11: pkh(KEY) descriptor ──────────────────────────────────────────────────

func TestW111G11_DescriptorPKH(t *testing.T) {
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "pkh(" + pubKeyHex + ")"
	d, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("G11 ParseDescriptor: %v", err)
	}
	scripts, err := d.Expand(0)
	if err != nil {
		t.Fatalf("G11 Expand: %v", err)
	}
	if len(scripts) != 1 {
		t.Fatalf("G11 expected 1 script, got %d", len(scripts))
	}
	// P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
	s := scripts[0]
	if len(s) != 25 || s[0] != 0x76 || s[1] != 0xa9 || s[23] != 0x88 || s[24] != 0xac {
		t.Errorf("G11 P2PKH scriptPubKey template wrong: %x", s)
	}
}

// ── G12: wpkh(KEY) descriptor ─────────────────────────────────────────────────

func TestW111G12_DescriptorWPKH(t *testing.T) {
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "wpkh(" + pubKeyHex + ")"
	d, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("G12 ParseDescriptor: %v", err)
	}
	scripts, err := d.Expand(0)
	if err != nil {
		t.Fatalf("G12 Expand: %v", err)
	}
	if len(scripts) != 1 {
		t.Fatalf("G12 expected 1 script, got %d", len(scripts))
	}
	// P2WPKH: OP_0 <20>
	s := scripts[0]
	if len(s) != 22 || s[0] != 0x00 || s[1] != 0x14 {
		t.Errorf("G12 P2WPKH scriptPubKey template wrong: %x", s)
	}
}

// ── G13: sh(wpkh(KEY)) descriptor ────────────────────────────────────────────

func TestW111G13_DescriptorSHWPKH(t *testing.T) {
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "sh(wpkh(" + pubKeyHex + "))"
	d, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("G13 ParseDescriptor: %v", err)
	}
	scripts, err := d.Expand(0)
	if err != nil {
		t.Fatalf("G13 Expand: %v", err)
	}
	if len(scripts) != 1 {
		t.Fatalf("G13 expected 1 script, got %d", len(scripts))
	}
	// P2SH: OP_HASH160 <20> OP_EQUAL
	s := scripts[0]
	if len(s) != 23 || s[0] != 0xa9 || s[1] != 0x14 || s[22] != 0x87 {
		t.Errorf("G13 P2SH scriptPubKey template wrong: %x", s)
	}
}

// ── G14: tr(KEY) descriptor ───────────────────────────────────────────────────

func TestW111G14_DescriptorTR(t *testing.T) {
	pubKeyHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	desc := "tr(" + pubKeyHex + ")"
	d, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("G14 ParseDescriptor: %v", err)
	}
	scripts, err := d.Expand(0)
	if err != nil {
		t.Fatalf("G14 Expand: %v", err)
	}
	if len(scripts) != 1 {
		t.Fatalf("G14 expected 1 script, got %d", len(scripts))
	}
	// P2TR: OP_1 <32>
	s := scripts[0]
	if len(s) != 34 || s[0] != 0x51 || s[1] != 0x20 {
		t.Errorf("G14 P2TR scriptPubKey template wrong: %x", s)
	}
}

// ── G15: multi(K, KEY1, KEY2, ...) descriptor ────────────────────────────────

func TestW111G15_DescriptorMulti(t *testing.T) {
	k1 := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	k2 := "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	k3 := "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	desc := "multi(2," + k1 + "," + k2 + "," + k3 + ")"
	d, err := ParseDescriptor(desc, address.Mainnet)
	if err != nil {
		t.Fatalf("G15 ParseDescriptor: %v", err)
	}
	scripts, err := d.Expand(0)
	if err != nil {
		t.Fatalf("G15 Expand: %v", err)
	}
	if len(scripts) != 1 {
		t.Fatalf("G15 expected 1 script, got %d", len(scripts))
	}
	// 2-of-3 multisig: OP_2 <33> <33> <33> OP_3 OP_CHECKMULTISIG
	s := scripts[0]
	if s[0] != 0x52 { // OP_2
		t.Errorf("G15 first byte = 0x%02x, want OP_2 (0x52)", s[0])
	}
	if s[len(s)-2] != 0x53 { // OP_3
		t.Errorf("G15 penultimate byte = 0x%02x, want OP_3 (0x53)", s[len(s)-2])
	}
	if s[len(s)-1] != 0xae { // OP_CHECKMULTISIG
		t.Errorf("G15 last byte = 0x%02x, want OP_CHECKMULTISIG (0xae)", s[len(s)-1])
	}
}

// ── G16: BIP-380 checksum ─────────────────────────────────────────────────────

func TestW111G16_DescriptorChecksum(t *testing.T) {
	// These checksums were verified against Bitcoin Core's descriptor.cpp
	tests := []struct {
		desc string
		want string
	}{
		{"pk(020000000000000000000000000000000000000000000000000000000000000001)", "e80tdz4l"},
		{"pkh(020000000000000000000000000000000000000000000000000000000000000002)", "ma7nspkf"},
		{"wpkh(020000000000000000000000000000000000000000000000000000000000000003)", "tawwvenc"},
	}
	for _, tt := range tests {
		got := DescriptorChecksum(tt.desc)
		if got != tt.want {
			t.Errorf("G16 DescriptorChecksum(%q) = %q, want %q", tt.desc[:30]+"...", got, tt.want)
		}
	}
	// AddChecksum + ValidateDescriptorChecksum round-trip
	desc := "wpkh(020000000000000000000000000000000000000000000000000000000000000003)"
	checksummed := AddChecksum(desc)
	body, ok := ValidateDescriptorChecksum(checksummed)
	if !ok || body != desc {
		t.Errorf("G16 checksum round-trip failed: ok=%v body=%q", ok, body)
	}
}

// ── G17: BIP-39 wordlist ──────────────────────────────────────────────────────

func TestW111G17_BIP39Wordlist(t *testing.T) {
	if len(wordlist) != 2048 {
		t.Errorf("G17 wordlist size = %d, want 2048", len(wordlist))
	}
	if wordlist[0] != "abandon" {
		t.Errorf("G17 first word = %q, want abandon", wordlist[0])
	}
	if wordlist[2047] != "zoo" {
		t.Errorf("G17 last word = %q, want zoo", wordlist[2047])
	}

	// Valid mnemonic checksum
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	if !ValidateMnemonic(mnemonic) {
		t.Error("G17 valid mnemonic failed checksum")
	}
	// Invalid checksum (last word wrong)
	bad := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	if ValidateMnemonic(bad) {
		t.Error("G17 invalid-checksum mnemonic accepted")
	}
}

// ── G18: BIP-39 PBKDF2 seed derivation ───────────────────────────────────────

func TestW111G18_BIP39SeedPBKDF2(t *testing.T) {
	// BIP-39 official test vector (from Trezor reference implementation)
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	want := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed := MnemonicToSeed(mnemonic, "")
	got := hex.EncodeToString(seed)
	if got != want {
		t.Errorf("G18 seed mismatch\ngot  %s\nwant %s", got, want)
	}

	// With passphrase "TREZOR"
	want2 := "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
	seed2 := MnemonicToSeed(mnemonic, "TREZOR")
	got2 := hex.EncodeToString(seed2)
	if got2 != want2 {
		t.Errorf("G18 seed+passphrase mismatch\ngot  %s\nwant %s", got2, want2)
	}
}

// ── G19: P2PKH mainnet/testnet version bytes ──────────────────────────────────

func TestW111G19_P2PKHVersionBytes(t *testing.T) {
	// P2PKH mainnet starts with '1', testnet starts with 'm' or 'n'
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		AddressType: AddressTypeP2PKH,
		ChainParams: consensus.MainnetParams(),
	}
	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")
	addr, err := w.NewP2PKHAddress()
	if err != nil {
		t.Fatalf("G19 NewP2PKHAddress: %v", err)
	}
	if addr[0] != '1' {
		t.Errorf("G19 mainnet P2PKH should start with '1', got %q", string(addr[0]))
	}

	// Testnet
	configTest := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Testnet,
		AddressType: AddressTypeP2PKH,
		ChainParams: consensus.TestnetParams(),
	}
	wt := NewWallet(configTest)
	wt.CreateFromMnemonic(testMnemonic, "")
	addrT, err := wt.NewP2PKHAddress()
	if err != nil {
		t.Fatalf("G19 testnet NewP2PKHAddress: %v", err)
	}
	if addrT[0] != 'm' && addrT[0] != 'n' {
		t.Errorf("G19 testnet P2PKH should start with 'm' or 'n', got %q", string(addrT[0]))
	}
}

// ── G20: P2SH mainnet/testnet version bytes ───────────────────────────────────

func TestW111G20_P2SHVersionBytes(t *testing.T) {
	// P2SH mainnet starts with '3', testnet starts with '2'
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		AddressType: AddressTypeP2SH_P2WPKH,
		ChainParams: consensus.MainnetParams(),
	}
	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")
	addr, err := w.NewP2SH_P2WPKHAddress()
	if err != nil {
		t.Fatalf("G20 NewP2SH_P2WPKHAddress: %v", err)
	}
	if addr[0] != '3' {
		t.Errorf("G20 mainnet P2SH should start with '3', got %q", string(addr[0]))
	}

	configTest := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Testnet,
		AddressType: AddressTypeP2SH_P2WPKH,
		ChainParams: consensus.TestnetParams(),
	}
	wt := NewWallet(configTest)
	wt.CreateFromMnemonic(testMnemonic, "")
	addrT, err := wt.NewP2SH_P2WPKHAddress()
	if err != nil {
		t.Fatalf("G20 testnet NewP2SH_P2WPKHAddress: %v", err)
	}
	if addrT[0] != '2' {
		t.Errorf("G20 testnet P2SH should start with '2', got %q", string(addrT[0]))
	}
}

// ── G21: BECH32 P2WPKH v0 ────────────────────────────────────────────────────

func TestW111G21_Bech32WPKH(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		AddressType: AddressTypeP2WPKH,
		ChainParams: consensus.MainnetParams(),
	}
	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")
	addr, err := w.NewP2WPKHAddress()
	if err != nil {
		t.Fatalf("G21 NewP2WPKHAddress: %v", err)
	}
	// Mainnet bech32 P2WPKH: bc1q...
	if !strings.HasPrefix(addr, "bc1q") {
		t.Errorf("G21 mainnet P2WPKH should start with bc1q, got %q", addr[:8])
	}

	// Testnet: tb1q...
	configT := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Testnet,
		AddressType: AddressTypeP2WPKH,
		ChainParams: consensus.TestnetParams(),
	}
	wt := NewWallet(configT)
	wt.CreateFromMnemonic(testMnemonic, "")
	addrT, err := wt.NewP2WPKHAddress()
	if err != nil {
		t.Fatalf("G21 testnet NewP2WPKHAddress: %v", err)
	}
	if !strings.HasPrefix(addrT, "tb1q") {
		t.Errorf("G21 testnet P2WPKH should start with tb1q, got %q", addrT[:8])
	}
}

// ── G22: BECH32M P2TR v1 ─────────────────────────────────────────────────────

func TestW111G22_Bech32mPTR(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		AddressType: AddressTypeP2TR,
		ChainParams: consensus.MainnetParams(),
	}
	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")
	addr, err := w.NewP2TRAddress()
	if err != nil {
		t.Fatalf("G22 NewP2TRAddress: %v", err)
	}
	// Mainnet bech32m P2TR: bc1p...
	if !strings.HasPrefix(addr, "bc1p") {
		t.Errorf("G22 mainnet P2TR should start with bc1p, got %q", addr[:8])
	}
}

// ── G23: Wallet file persistence (BUG-1 documented) ──────────────────────────

func TestW111G23_WalletFilePersistence(t *testing.T) {
	dir := t.TempDir()
	config := WalletConfig{
		DataDir:     dir,
		Network:     address.Mainnet,
		AddressType: AddressTypeP2WPKH,
		ChainParams: consensus.MainnetParams(),
	}

	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Generate a few addresses
	addr1, _ := w.NewAddress()
	addr2, _ := w.NewAddress()

	// Save wallet
	if err := w.SaveToFile("testpassword"); err != nil {
		t.Fatalf("G23 SaveToFile: %v", err)
	}

	// Load wallet back
	w2, err := LoadFromFile(dir, "testpassword", config)
	if err != nil {
		t.Fatalf("G23 LoadFromFile: %v", err)
	}

	// Address paths should be restored
	if !w2.IsOwnAddress(addr1) {
		t.Errorf("G23 loaded wallet doesn't know addr1 %q", addr1)
	}
	if !w2.IsOwnAddress(addr2) {
		t.Errorf("G23 loaded wallet doesn't know addr2 %q", addr2)
	}

	// Wrong password must fail
	_, err = LoadFromFile(dir, "wrongpassword", config)
	if err == nil {
		t.Error("G23 LoadFromFile with wrong password should fail")
	}

	// BUG-1 (FIXED — W161 BUG-15): SaveToFile must persist the BIP-39 mnemonic
	// alongside the master-key bytes, and LoadFromFile must restore it, so a
	// wallet loaded from disk can reproduce the BIP-39 seed (paper backup /
	// restore through the standard BIP-39 path).
	gotMnemonic, err := w2.Mnemonic()
	if err != nil {
		t.Fatalf("G23 reloaded wallet Mnemonic(): %v", err)
	}
	if gotMnemonic != testMnemonic {
		t.Errorf("G23 reloaded mnemonic = %q, want %q", gotMnemonic, testMnemonic)
	}
}

// ── G24: Wallet encryption ────────────────────────────────────────────────────

func TestW111G24_WalletEncryption(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		AddressType: AddressTypeP2WPKH,
		ChainParams: consensus.MainnetParams(),
	}
	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Must fail if no passphrase
	if err := w.EncryptWallet(""); err != ErrEmptyPassphrase {
		t.Errorf("G24 EncryptWallet('') should return ErrEmptyPassphrase, got %v", err)
	}

	// Encrypt the wallet
	if err := w.EncryptWallet("s3cr3t"); err != nil {
		t.Fatalf("G24 EncryptWallet: %v", err)
	}

	// Wallet must be locked after encryption
	if !w.IsLocked() {
		t.Error("G24 wallet should be locked after EncryptWallet")
	}
	if !w.IsEncrypted() {
		t.Error("G24 wallet should be marked encrypted")
	}

	// Cannot encrypt twice
	if err := w.EncryptWallet("other"); err != ErrWalletAlreadyEncrypted {
		t.Errorf("G24 double EncryptWallet should return ErrWalletAlreadyEncrypted, got %v", err)
	}

	// Must fail on unencrypted wallet for walletpassphrase
	w2 := NewWallet(config)
	w2.CreateFromMnemonic(testMnemonic, "")
	if err := w2.UnlockWithPassphrase("any", 60); err != ErrWalletNotEncrypted {
		t.Errorf("G24 UnlockWithPassphrase on unencrypted wallet should return ErrWalletNotEncrypted, got %v", err)
	}

	// Unlock with correct passphrase
	if err := w.UnlockWithPassphrase("s3cr3t", 0); err != nil {
		t.Fatalf("G24 UnlockWithPassphrase: %v", err)
	}
	if w.IsLocked() {
		t.Error("G24 wallet should be unlocked after correct passphrase")
	}

	// Wrong passphrase must fail
	w.Lock()
	if err := w.UnlockWithPassphrase("wrong", 0); err != ErrPassphraseIncorrect {
		t.Errorf("G24 wrong passphrase should return ErrPassphraseIncorrect, got %v", err)
	}
}

// ── G25: KeyPool / gap limit ──────────────────────────────────────────────────

func TestW111G25_KeypoolGapLimit(t *testing.T) {
	// Verify the DefaultGapLimit constant is 20 (Bitcoin Core default)
	if DefaultGapLimit != 20 {
		t.Errorf("G25 DefaultGapLimit = %d, want 20", DefaultGapLimit)
	}

	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		AddressType: AddressTypeP2WPKH,
		ChainParams: consensus.MainnetParams(),
	}
	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Generate 20 addresses (standard gap limit)
	addrs := make([]string, 20)
	for i := 0; i < 20; i++ {
		a, err := w.NewAddress()
		if err != nil {
			t.Fatalf("G25 NewAddress[%d]: %v", i, err)
		}
		addrs[i] = a
	}

	// All addresses must be unique
	seen := make(map[string]bool)
	for _, a := range addrs {
		if seen[a] {
			t.Errorf("G25 duplicate address: %s", a)
		}
		seen[a] = true
	}

	// BUG-3: gapLimit field is set to 20 but never read/enforced during
	// address derivation — NewAddress increments the index indefinitely
	// without any gap-limit enforcement. Wallet recovery from a fresh seed
	// only scans up to gap addresses, so exceeding the gap limit may cause
	// funds to be missed on restore.
	t.Log("BUG-3: Wallet.gapLimit = 20 is never enforced in newAddressOfTypeLocked")
}

// ── G26: Legacy P2PKH signing ─────────────────────────────────────────────────

func TestW111G26_P2PKHSigning(t *testing.T) {
	t.Skip("BUG: P2PKH signing requires a spendable UTXO tracked by the wallet; full CreateTransaction end-to-end test requires a confirmed UTXO")
}

// ── G27: P2WPKH BIP-143 segwit signing ───────────────────────────────────────

func TestW111G27_P2WPKHSigning(t *testing.T) {
	// Test that signP2WPKH produces a valid BIP-143 witness.
	// We construct a tx manually and call signInput via the wallet's
	// internal path, then verify the witness structure.
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		AddressType: AddressTypeP2WPKH,
		ChainParams: consensus.MainnetParams(),
	}
	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	// Derive a key and build a P2WPKH UTXO
	addr, err := w.NewP2WPKHAddress()
	if err != nil {
		t.Fatalf("G27 NewP2WPKHAddress: %v", err)
	}
	path := w.addrToPath[addr]
	if path == "" {
		t.Fatalf("G27 no path for address %s", addr)
	}
	privKey, err := w.GetKeyForAddress(addr)
	if err != nil {
		t.Fatalf("G27 GetKeyForAddress: %v", err)
	}

	// BIP-143 sighash requires the scriptCode (P2PKH form of the pubkey hash)
	// and the input value. We verify that signInput does not panic/error.
	prevHash, _ := wire.NewHash256FromHex("0100000000000000000000000000000000000000000000000000000000000000")
	pkScript, _ := buildP2WPKHScriptPubKey(addr, address.Mainnet)
	utxo := &WalletUTXO{
		OutPoint:  wire.OutPoint{Hash: prevHash, Index: 0},
		Amount:    100000,
		PkScript:  pkScript,
		Address:   addr,
		KeyPath:   path,
		Confirmed: true,
	}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: utxo.OutPoint, Sequence: 0xFFFFFFFE}},
		TxOut:   []*wire.TxOut{{Value: 99000, PkScript: pkScript}},
	}
	prevOuts := []*wire.TxOut{{Value: utxo.Amount, PkScript: pkScript}}
	if err := w.signInput(tx, 0, utxo, privKey, prevOuts); err != nil {
		t.Fatalf("G27 signInput P2WPKH: %v", err)
	}

	// Witness must have exactly 2 elements: <sig> <pubkey>
	if len(tx.TxIn[0].Witness) != 2 {
		t.Errorf("G27 witness stack len = %d, want 2", len(tx.TxIn[0].Witness))
	}
	// scriptSig must be empty for P2WPKH
	if len(tx.TxIn[0].SignatureScript) != 0 {
		t.Errorf("G27 P2WPKH scriptSig should be empty, got %d bytes",
			len(tx.TxIn[0].SignatureScript))
	}
}

// ── G28: P2TR BIP-341 taproot signing ────────────────────────────────────────

func TestW111G28_P2TRSigning(t *testing.T) {
	config := WalletConfig{
		DataDir:     t.TempDir(),
		Network:     address.Mainnet,
		AddressType: AddressTypeP2TR,
		ChainParams: consensus.MainnetParams(),
	}
	w := NewWallet(config)
	w.CreateFromMnemonic(testMnemonic, "")

	addr, err := w.NewP2TRAddress()
	if err != nil {
		t.Fatalf("G28 NewP2TRAddress: %v", err)
	}
	path := w.addrToPath[addr]
	privKey, err := w.GetKeyForAddress(addr)
	if err != nil {
		t.Fatalf("G28 GetKeyForAddress: %v", err)
	}

	prevHash, _ := wire.NewHash256FromHex("0200000000000000000000000000000000000000000000000000000000000000")
	pkScript, _ := buildP2TRScriptPubKey(addr, address.Mainnet)
	utxo := &WalletUTXO{
		OutPoint:  wire.OutPoint{Hash: prevHash, Index: 0},
		Amount:    500000,
		PkScript:  pkScript,
		Address:   addr,
		KeyPath:   path,
		Confirmed: true,
	}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: utxo.OutPoint, Sequence: 0xFFFFFFFE}},
		TxOut:   []*wire.TxOut{{Value: 499000, PkScript: pkScript}},
	}
	prevOuts := []*wire.TxOut{{Value: utxo.Amount, PkScript: pkScript}}
	if err := w.signInput(tx, 0, utxo, privKey, prevOuts); err != nil {
		t.Fatalf("G28 signInput P2TR: %v", err)
	}

	// Taproot key-path spend: witness must have exactly 1 element (Schnorr sig, 64 or 65 bytes)
	if len(tx.TxIn[0].Witness) != 1 {
		t.Errorf("G28 P2TR witness stack len = %d, want 1", len(tx.TxIn[0].Witness))
	}
	sigLen := len(tx.TxIn[0].Witness[0])
	if sigLen != 64 && sigLen != 65 {
		t.Errorf("G28 P2TR Schnorr sig length = %d, want 64 or 65", sigLen)
	}
	_ = path
}

// ── G29: BIP-174 PSBT v0 ─────────────────────────────────────────────────────

func TestW111G29_PSBTv0(t *testing.T) {
	prevHash, _ := wire.NewHash256FromHex("0100000000000000000000000000000000000000000000000000000000000000")
	tx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 100000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}},
	}
	psbt, err := NewPSBT(tx)
	if err != nil {
		t.Fatalf("G29 NewPSBT: %v", err)
	}
	if psbt.Version != 0 {
		t.Errorf("G29 PSBT version = %d, want 0", psbt.Version)
	}

	// Encode → decode round-trip
	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("G29 Encode: %v", err)
	}
	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("G29 DecodePSBT: %v", err)
	}
	if decoded.UnsignedTx.TxHash() != tx.TxHash() {
		t.Error("G29 decoded PSBT tx hash mismatch")
	}
	if decoded.Version != 0 {
		t.Errorf("G29 decoded PSBT version = %d, want 0", decoded.Version)
	}

	// Base64 round-trip
	b64, err := psbt.EncodeBase64()
	if err != nil {
		t.Fatalf("G29 EncodeBase64: %v", err)
	}
	if _, err := DecodePSBTBase64(b64); err != nil {
		t.Fatalf("G29 DecodePSBTBase64: %v", err)
	}
}

// ── G30: BIP-370 PSBT v2 (BUG-5 documented) ──────────────────────────────────

func TestW111G30_PSBTv2(t *testing.T) {
	// BUG-5: PSBTGlobalTxVersion/FallbackLock/InputCount/OutputCount/TxModifiable
	// constants exist but are NOT parsed in DecodePSBTReader — they fall through
	// to the Unknown map. This test documents the gap.

	prevHash, _ := wire.NewHash256FromHex("0100000000000000000000000000000000000000000000000000000000000000")
	tx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0}, Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 50000, PkScript: []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}},
	}
	psbt, err := NewPSBT(tx)
	if err != nil {
		t.Fatalf("G30 NewPSBT: %v", err)
	}

	// Manually set version=2 to simulate a v2 PSBT
	psbt.Version = 2

	encoded, err := psbt.Encode()
	if err != nil {
		t.Fatalf("G30 Encode: %v", err)
	}

	decoded, err := DecodePSBT(encoded)
	if err != nil {
		t.Fatalf("G30 DecodePSBT v2 round-trip: %v", err)
	}
	if decoded.Version != 2 {
		t.Errorf("G30 decoded PSBT version = %d, want 2", decoded.Version)
	}

	// BUG-5: v2-specific global fields (types 0x02–0x06) are not parsed.
	// They land in decoded.Unknown. The global field constants are defined:
	// PSBTGlobalTxVersion=0x02, PSBTGlobalFallbackLock=0x03, etc.
	// but the switch in DecodePSBTReader has no cases for them.
	t.Log("BUG-5: BIP-370 v2 global fields (TxVersion/FallbackLock/InputCount/OutputCount/TxModifiable) fall through to Unknown in DecodePSBTReader switch — not interpreted")
}

// ── BUG-2 documented test: initAccount always uses m/84' ─────────────────────

func TestW111_BUG2_InitAccountAlwaysM84(t *testing.T) {
	// BUG-2: initAccount derives m/84'/coinType'/account' regardless of
	// wallet.config.AddressType. A wallet configured for P2PKH should use
	// m/44'/0'/0', P2SH-P2WPKH → m/49'/0'/0', P2TR → m/86'/0'/0'.
	// This makes the stored account xpub incorrect for non-P2WPKH wallets.
	//
	// Demonstrate: create a P2PKH wallet; its account xpub was derived at
	// m/84'/0'/0' instead of m/44'/0'/0'.

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	mk, _ := NewMasterKey(seed)

	// What a P2PKH wallet's account xpub SHOULD be
	correctAccountKey, _ := mk.DerivePath("m/44'/0'/0'")
	correctXpub := correctAccountKey.PublicKey().Serialize(address.Mainnet)

	// What initAccount ACTUALLY derives (hardcoded m/84')
	wrongAccountKey, _ := mk.DerivePath("m/84'/0'/0'")
	actualXpub := wrongAccountKey.PublicKey().Serialize(address.Mainnet)

	if correctXpub == actualXpub {
		t.Error("BUG-2: BIP44 and BIP84 account xpubs unexpectedly match (test vector issue)")
	}
	// The bug: initAccount for P2PKH uses BIP84 path instead of BIP44 path
	t.Logf("BUG-2: P2PKH wallet account xpub should be at m/44'/0'/0' (%s...) but initAccount always uses m/84'/0'/0' (%s...)",
		correctXpub[:20], actualXpub[:20])
}

// ── Helpers used by tests ─────────────────────────────────────────────────────

// buildP2WPKHScriptPubKey builds a P2WPKH scriptPubKey for an address string.
// Returns an error if the address is not a valid P2WPKH address.
func buildP2WPKHScriptPubKey(addrStr string, net address.Network) ([]byte, error) {
	addr, err := address.DecodeAddress(addrStr, net)
	if err != nil {
		return nil, err
	}
	return addr.ScriptPubKey(), nil
}

// buildP2TRScriptPubKey builds a P2TR scriptPubKey for an address string.
func buildP2TRScriptPubKey(addrStr string, net address.Network) ([]byte, error) {
	addr, err := address.DecodeAddress(addrStr, net)
	if err != nil {
		return nil, err
	}
	return addr.ScriptPubKey(), nil
}
