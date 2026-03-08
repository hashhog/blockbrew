package wallet

import (
	"encoding/hex"
	"strings"
	"testing"
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
