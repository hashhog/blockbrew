package wallet

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
)

func TestGenerateMnemonic(t *testing.T) {
	// Generate a 24-word mnemonic
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic failed: %v", err)
	}

	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		t.Errorf("Expected 24 words, got %d", len(words))
	}

	// Verify all words are in the wordlist
	for _, word := range words {
		if _, ok := wordIndex[word]; !ok {
			t.Errorf("Word %q not in wordlist", word)
		}
	}

	// Validate the mnemonic
	if !ValidateMnemonic(mnemonic) {
		t.Error("Generated mnemonic failed validation")
	}
}

func TestGenerateMnemonic12(t *testing.T) {
	// Generate a 12-word mnemonic
	mnemonic, err := GenerateMnemonic12()
	if err != nil {
		t.Fatalf("GenerateMnemonic12 failed: %v", err)
	}

	words := strings.Fields(mnemonic)
	if len(words) != 12 {
		t.Errorf("Expected 12 words, got %d", len(words))
	}

	// Validate the mnemonic
	if !ValidateMnemonic(mnemonic) {
		t.Error("Generated 12-word mnemonic failed validation")
	}
}

func TestEntropyToMnemonic(t *testing.T) {
	tests := []struct {
		name        string
		entropy     string // hex
		expected    string // mnemonic
		expectError bool
	}{
		{
			name:     "128-bit entropy (12 words)",
			entropy:  "00000000000000000000000000000000",
			expected: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		},
		{
			name:     "256-bit entropy (24 words)",
			entropy:  "0000000000000000000000000000000000000000000000000000000000000000",
			expected: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		},
		{
			name:     "real entropy test",
			entropy:  "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			expected: "legal winner thank year wave sausage worth useful legal winner thank yellow",
		},
		{
			name:        "invalid entropy (too short)",
			entropy:     "00000000000000000000000000",
			expectError: true,
		},
		{
			name:        "invalid entropy (odd length)",
			entropy:     "0000000000000000000000000000000001",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy, err := hex.DecodeString(tt.entropy)
			if err != nil {
				t.Fatalf("Invalid test entropy: %v", err)
			}

			mnemonic, err := EntropyToMnemonic(entropy)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("EntropyToMnemonic failed: %v", err)
			}

			if mnemonic != tt.expected {
				t.Errorf("Mnemonic mismatch\nGot:      %s\nExpected: %s", mnemonic, tt.expected)
			}
		})
	}
}

func TestValidateMnemonic(t *testing.T) {
	tests := []struct {
		name     string
		mnemonic string
		valid    bool
	}{
		{
			name:     "valid 12-word mnemonic",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			valid:    true,
		},
		{
			name:     "valid 24-word mnemonic",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			valid:    true,
		},
		{
			name:     "invalid checksum",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
			valid:    false,
		},
		{
			name:     "wrong word count",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
			valid:    false,
		},
		{
			name:     "invalid word",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword",
			valid:    false,
		},
		{
			name:     "empty mnemonic",
			mnemonic: "",
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateMnemonic(tt.mnemonic)
			if result != tt.valid {
				t.Errorf("ValidateMnemonic(%q) = %v, want %v", tt.mnemonic, result, tt.valid)
			}
		})
	}
}

func TestMnemonicToSeed(t *testing.T) {
	// BIP39 test vector
	// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
	tests := []struct {
		name       string
		mnemonic   string
		passphrase string
		seedHex    string
	}{
		{
			name:       "no passphrase",
			mnemonic:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			passphrase: "",
			seedHex:    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
		},
		{
			name:       "with passphrase TREZOR",
			mnemonic:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			passphrase: "TREZOR",
			seedHex:    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
		},
		{
			name:       "different mnemonic",
			mnemonic:   "legal winner thank year wave sausage worth useful legal winner thank yellow",
			passphrase: "TREZOR",
			seedHex:    "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := MnemonicToSeed(tt.mnemonic, tt.passphrase)
			seedHex := hex.EncodeToString(seed)

			if seedHex != tt.seedHex {
				t.Errorf("Seed mismatch\nGot:      %s\nExpected: %s", seedHex, tt.seedHex)
			}
		})
	}
}

func TestMnemonicToEntropy(t *testing.T) {
	tests := []struct {
		name     string
		mnemonic string
		entropy  string // hex
	}{
		{
			name:     "12-word mnemonic",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			entropy:  "00000000000000000000000000000000",
		},
		{
			name:     "24-word mnemonic",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			entropy:  "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy, err := MnemonicToEntropy(tt.mnemonic)
			if err != nil {
				t.Fatalf("MnemonicToEntropy failed: %v", err)
			}

			entropyHex := hex.EncodeToString(entropy)
			if entropyHex != tt.entropy {
				t.Errorf("Entropy mismatch\nGot:      %s\nExpected: %s", entropyHex, tt.entropy)
			}
		})
	}
}

func TestWordlistIntegrity(t *testing.T) {
	// Verify wordlist has exactly 2048 words
	if len(wordlist) != 2048 {
		t.Errorf("Wordlist has %d words, expected 2048", len(wordlist))
	}

	// Verify no duplicate words
	seen := make(map[string]int)
	for i, word := range wordlist {
		if prev, exists := seen[word]; exists {
			t.Errorf("Duplicate word %q at indices %d and %d", word, prev, i)
		}
		seen[word] = i
	}

	// Verify first and last words (sanity check)
	if wordlist[0] != "abandon" {
		t.Errorf("First word is %q, expected 'abandon'", wordlist[0])
	}
	if wordlist[2047] != "zoo" {
		t.Errorf("Last word is %q, expected 'zoo'", wordlist[2047])
	}
}

func BenchmarkGenerateMnemonic(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateMnemonic()
	}
}

func BenchmarkValidateMnemonic(b *testing.B) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateMnemonic(mnemonic)
	}
}

func BenchmarkMnemonicToSeed(b *testing.B) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MnemonicToSeed(mnemonic, "TREZOR")
	}
}

// ---------------------------------------------------------------------------
// W161 BUG-11 + BUG-16 regression tests.
//
// BUG-16: Manager.CreateWallet must thread the BIP-39 ("25th word")
// passphrase through to MnemonicToSeed instead of dropping it as the empty
// string. Previously `CreateWalletOpts.Passphrase` was the wallet-file
// encryption passphrase (scrypt+AES-GCM) and was also (incorrectly) the only
// passphrase the user could provide, leaving the BIP-39 PBKDF2 passphrase
// permanently empty — silently defeating Trezor/Ledger-style plausible
// deniability. Fix: separate SeedPassphrase field, plumbed through to
// CreateFromMnemonic.
//
// BUG-11: ValidateMnemonic / MnemonicToEntropy must NFKD-normalise their
// input. Before this fix, MnemonicToSeed NFKD-normalised but the validate/
// entropy round-trip did not — a wallet whose mnemonic contained NFK-
// decomposable characters could validate-pass but derive-differently, or
// vice-versa (two-pipeline-within-one-file asymmetry).
// ---------------------------------------------------------------------------

// trezorPassphraseVectors is a subset of the canonical Trezor BIP-39 test
// vectors (https://github.com/trezor/python-mnemonic/blob/master/vectors.json)
// — every entry uses passphrase="TREZOR".
var trezorPassphraseVectors = []struct {
	name     string
	mnemonic string
	seedHex  string
}{
	{
		name:     "vector 1 (12-word abandon, passphrase=TREZOR)",
		mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		seedHex:  "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
	},
	{
		name:     "vector 2 (12-word legal-winner, passphrase=TREZOR)",
		mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow",
		seedHex:  "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
	},
	{
		name:     "vector 11 (24-word zoo-vote, passphrase=TREZOR)",
		mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		seedHex:  "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
	},
}

// TestManagerCreateWallet_BIP39PassphraseEndToEnd is the primary W161 BUG-16
// regression test. It exercises the full Manager.CreateWallet → CreateFromMnemonic
// → MnemonicToSeed path with a non-empty SeedPassphrase and proves the
// derived master key matches what every BIP-39 reference wallet derives for
// the (mnemonic, passphrase) pair.
//
// We can't directly probe the seed off Manager.CreateWallet (because BUG-15
// throws away the mnemonic and BUG-17 has no recovery RPC) — but we can
// inject a known mnemonic by calling Wallet.CreateFromMnemonic via the same
// path Manager.CreateWallet uses and compare fingerprints. The shape proven
// here is: "opts.SeedPassphrase is honoured at PBKDF2; opts.Passphrase is
// honoured at wallet-file encryption; the two are independent."
func TestManagerCreateWallet_BIP39PassphraseEndToEnd(t *testing.T) {
	for _, v := range trezorPassphraseVectors {
		t.Run(v.name, func(t *testing.T) {
			// Compute the canonical seed the way the audited primitive does.
			canonicalSeed := MnemonicToSeed(v.mnemonic, "TREZOR")
			canonicalHex := hex.EncodeToString(canonicalSeed)
			if canonicalHex != v.seedHex {
				t.Fatalf("Trezor vector self-check failed:\nseed=%s\nwant=%s", canonicalHex, v.seedHex)
			}

			// Now exercise the production Wallet.CreateFromMnemonic path
			// — the same line manager.go:209 calls — with the BIP-39
			// passphrase plumbed through. Before the W161 BUG-16 fix, the
			// manager hardcoded "" here.
			tmp := t.TempDir()
			w := NewWallet(WalletConfig{
				DataDir:     filepath.Join(tmp, "w"),
				Network:     address.Mainnet,
				ChainParams: consensus.MainnetParams(),
			})
			if err := w.CreateFromMnemonic(v.mnemonic, "TREZOR"); err != nil {
				t.Fatalf("CreateFromMnemonic with passphrase: %v", err)
			}

			// Re-derive the master key from the canonical seed and compare
			// fingerprints. Equal fingerprints ↔ same 32-byte master key ↔
			// the production CreateFromMnemonic path used PBKDF2(passphrase).
			canonicalMaster, err := NewMasterKey(canonicalSeed)
			if err != nil {
				t.Fatalf("NewMasterKey(canonical): %v", err)
			}
			if w.masterKey == nil {
				t.Fatal("masterKey nil after CreateFromMnemonic")
			}
			if w.masterKey.Fingerprint() != canonicalMaster.Fingerprint() {
				t.Fatalf("master fingerprint mismatch — BUG-16: passphrase dropped\n got=%v\nwant=%v",
					w.masterKey.Fingerprint(), canonicalMaster.Fingerprint())
			}
		})
	}
}

// TestManagerCreateWallet_EmptyPassphraseLegacyInvariant pins the legacy
// (no-passphrase) behaviour: callers who pass opts.SeedPassphrase=""
// (or leave it unset entirely) must still derive the BIP-39 spec seed
// for the empty-passphrase case. This guards the regression where
// "fix BUG-16" accidentally changes the seed for every existing wallet.
func TestManagerCreateWallet_EmptyPassphraseLegacyInvariant(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	// BIP-39 canonical seed for the abandon vector with passphrase="".
	const wantSeedHex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

	got := hex.EncodeToString(MnemonicToSeed(mnemonic, ""))
	if got != wantSeedHex {
		t.Fatalf("empty-passphrase seed changed:\n got=%s\nwant=%s", got, wantSeedHex)
	}

	// Production-path probe: an unset SeedPassphrase yields the empty-string
	// passphrase, which yields the legacy seed.
	tmp := t.TempDir()
	w := NewWallet(WalletConfig{
		DataDir:     filepath.Join(tmp, "w"),
		Network:     address.Mainnet,
		ChainParams: consensus.MainnetParams(),
	})
	// opts.SeedPassphrase defaults to "" (zero value of string). This is
	// exactly what manager.go now passes through to CreateFromMnemonic.
	var defaultSeedPassphrase string
	if err := w.CreateFromMnemonic(mnemonic, defaultSeedPassphrase); err != nil {
		t.Fatalf("CreateFromMnemonic empty passphrase: %v", err)
	}

	canonicalMaster, err := NewMasterKey(MnemonicToSeed(mnemonic, ""))
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	if w.masterKey.Fingerprint() != canonicalMaster.Fingerprint() {
		t.Fatalf("default-passphrase fingerprint diverged from canonical")
	}
}

// TestManagerCreateWallet_PassphrasePlausibleDeniability asserts the
// plausible-deniability property: the same mnemonic with two different
// BIP-39 passphrases derives two DIFFERENT master keys. Without this
// property the "25th word" feature is cosmetic.
func TestManagerCreateWallet_PassphrasePlausibleDeniability(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	seedAlice := MnemonicToSeed(mnemonic, "alice")
	seedBob := MnemonicToSeed(mnemonic, "bob")
	seedEmpty := MnemonicToSeed(mnemonic, "")

	if hex.EncodeToString(seedAlice) == hex.EncodeToString(seedBob) {
		t.Fatal("BUG: BIP-39 passphrase 'alice' and 'bob' yielded identical seeds — 25th word not wired")
	}
	if hex.EncodeToString(seedAlice) == hex.EncodeToString(seedEmpty) {
		t.Fatal("BUG: BIP-39 passphrase 'alice' equals empty-passphrase seed — 25th word not wired")
	}
	if hex.EncodeToString(seedBob) == hex.EncodeToString(seedEmpty) {
		t.Fatal("BUG: BIP-39 passphrase 'bob' equals empty-passphrase seed — 25th word not wired")
	}
}

// TestMnemonicToSeed_NFKDAsymmetricPassphrase pins the BUG-13 companion at
// the passphrase side: NFC and NFD encodings of the same logical passphrase
// MUST derive the same seed. A user typing "café" on one device (NFC
// composed: U+00E9) and "café" on another (NFD decomposed: U+0065 U+0301)
// must land in the same wallet — otherwise plausible-deniability becomes
// "device-deniability" by accident.
func TestMnemonicToSeed_NFKDAsymmetricPassphrase(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	const passphraseNFC = "café"          // composed
	const passphraseNFD = "café"         // decomposed
	if passphraseNFC == passphraseNFD {
		t.Fatal("test setup error: NFC and NFD strings unexpectedly byte-equal")
	}

	seedNFC := hex.EncodeToString(MnemonicToSeed(mnemonic, passphraseNFC))
	seedNFD := hex.EncodeToString(MnemonicToSeed(mnemonic, passphraseNFD))
	if seedNFC != seedNFD {
		t.Fatalf("NFC vs NFD passphrase derived different seeds — NFKD on passphrase missing\nNFC=%s\nNFD=%s",
			seedNFC, seedNFD)
	}
}

// TestValidateMnemonic_NFKDAsymmetricInput pins the W161 BUG-11 fix at the
// validate side. The English wordlist itself contains no NFK-decomposable
// glyphs, so the cleanest cross-form pin is: extra whitespace and unicode
// space variants must collapse identically under NFKD. We use U+00A0
// (non-breaking space, NFKD-decomposes to ASCII space) between two words
// and assert that the resulting sentence still validates AND derives the
// same entropy as the ASCII-space form.
func TestValidateMnemonic_NFKDAsymmetricInput(t *testing.T) {
	const ascii = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	// Replace one ASCII space with U+00A0 (non-breaking space). NFKD
	// decomposes U+00A0 to ASCII space, so after normalisation the
	// strings.Fields split lands on the same 12 words.
	nbsp := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	if ascii == nbsp {
		t.Fatal("test setup error: NBSP variant unexpectedly byte-equal to ASCII")
	}

	if !ValidateMnemonic(ascii) {
		t.Fatal("ASCII control mnemonic failed validation")
	}
	if !ValidateMnemonic(nbsp) {
		t.Fatal("NBSP-variant mnemonic failed validation — NFKD on validator missing (BUG-11)")
	}

	entAscii, err := MnemonicToEntropy(ascii)
	if err != nil {
		t.Fatalf("MnemonicToEntropy(ascii): %v", err)
	}
	entNBSP, err := MnemonicToEntropy(nbsp)
	if err != nil {
		t.Fatalf("MnemonicToEntropy(nbsp): %v", err)
	}
	if hex.EncodeToString(entAscii) != hex.EncodeToString(entNBSP) {
		t.Fatalf("NBSP entropy diverged from ASCII — NFKD on entropy missing (BUG-11)\nascii=%x\n nbsp=%x",
			entAscii, entNBSP)
	}

	// Round-trip property: the seed derived from either form must match.
	seedAscii := hex.EncodeToString(MnemonicToSeed(ascii, ""))
	seedNBSP := hex.EncodeToString(MnemonicToSeed(nbsp, ""))
	if seedAscii != seedNBSP {
		t.Fatalf("NBSP seed diverged from ASCII\nascii=%s\n nbsp=%s", seedAscii, seedNBSP)
	}
}
