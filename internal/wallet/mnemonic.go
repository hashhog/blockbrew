package wallet

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

//go:embed wordlist_english.txt
var englishWordlist string

var (
	// ErrInvalidMnemonic is returned when a mnemonic is invalid.
	ErrInvalidMnemonic = errors.New("invalid mnemonic")
	// ErrInvalidEntropyLength is returned when entropy length is invalid.
	ErrInvalidEntropyLength = errors.New("invalid entropy length")
)

// wordlist is the parsed BIP39 English wordlist (2048 words).
var wordlist []string

// wordIndex maps words to their index in the wordlist for fast lookup.
var wordIndex map[string]int

func init() {
	wordlist = strings.Split(strings.TrimSpace(englishWordlist), "\n")
	if len(wordlist) != 2048 {
		panic("BIP39 wordlist must have exactly 2048 words")
	}

	wordIndex = make(map[string]int, 2048)
	for i, word := range wordlist {
		wordlist[i] = strings.TrimSpace(word)
		wordIndex[wordlist[i]] = i
	}
}

// GenerateMnemonic generates a new BIP39 mnemonic with 24 words (256 bits of entropy).
func GenerateMnemonic() (string, error) {
	// Generate 256 bits (32 bytes) of entropy
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}
	return EntropyToMnemonic(entropy)
}

// GenerateMnemonic12 generates a new BIP39 mnemonic with 12 words (128 bits of entropy).
func GenerateMnemonic12() (string, error) {
	// Generate 128 bits (16 bytes) of entropy
	entropy := make([]byte, 16)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}
	return EntropyToMnemonic(entropy)
}

// EntropyToMnemonic converts entropy bytes to a BIP39 mnemonic.
// Entropy must be 16, 20, 24, 28, or 32 bytes (128, 160, 192, 224, or 256 bits).
func EntropyToMnemonic(entropy []byte) (string, error) {
	entropyBits := len(entropy) * 8

	// Validate entropy length: must be a multiple of 32 bits, between 128 and 256
	if entropyBits < 128 || entropyBits > 256 || entropyBits%32 != 0 {
		return "", ErrInvalidEntropyLength
	}

	// Compute checksum: SHA256 of entropy, take first (entropyBits/32) bits
	checksumBits := entropyBits / 32
	hash := sha256.Sum256(entropy)

	// Combine entropy + checksum into bit stream
	// Total bits = entropyBits + checksumBits
	totalBits := entropyBits + checksumBits
	numWords := totalBits / 11 // Each word is 11 bits

	// Build words by extracting 11-bit indices
	words := make([]string, numWords)

	for i := 0; i < numWords; i++ {
		// Get 11 bits starting at bit position i*11
		idx := extract11Bits(entropy, hash[:], i*11)
		words[i] = wordlist[idx]
	}

	return strings.Join(words, " "), nil
}

// extract11Bits extracts 11 bits starting at bitPos from the combined entropy+checksum.
func extract11Bits(entropy, checksum []byte, bitPos int) int {
	entropyBits := len(entropy) * 8

	var value int
	for j := 0; j < 11; j++ {
		pos := bitPos + j
		var bit int
		if pos < entropyBits {
			// Bit is in entropy
			byteIdx := pos / 8
			bitIdx := 7 - (pos % 8)
			bit = int((entropy[byteIdx] >> bitIdx) & 1)
		} else {
			// Bit is in checksum
			checksumPos := pos - entropyBits
			byteIdx := checksumPos / 8
			bitIdx := 7 - (checksumPos % 8)
			bit = int((checksum[byteIdx] >> bitIdx) & 1)
		}
		value = (value << 1) | bit
	}
	return value
}

// ValidateMnemonic checks if a mnemonic is valid.
// It verifies word count, word validity, and checksum.
func ValidateMnemonic(mnemonic string) bool {
	words := strings.Fields(mnemonic)

	// Valid word counts: 12, 15, 18, 21, 24
	wordCount := len(words)
	if wordCount != 12 && wordCount != 15 && wordCount != 18 && wordCount != 21 && wordCount != 24 {
		return false
	}

	// Convert words to bit stream
	var bits []int
	for _, word := range words {
		idx, ok := wordIndex[word]
		if !ok {
			return false
		}
		// Add 11 bits for this word
		for j := 10; j >= 0; j-- {
			bits = append(bits, (idx>>j)&1)
		}
	}

	// Total bits = wordCount * 11
	// entropyBits = wordCount * 11 - checksumBits
	// checksumBits = entropyBits / 32
	// So: totalBits = entropyBits + entropyBits/32 = entropyBits * 33/32
	// entropyBits = totalBits * 32/33

	totalBits := wordCount * 11
	checksumBits := wordCount / 3 // This is entropyBits/32, and entropyBits = (wordCount*11 - checksumBits), solving: checksumBits = wordCount/3
	entropyBits := totalBits - checksumBits

	// Extract entropy bytes
	entropy := make([]byte, entropyBits/8)
	for i := 0; i < entropyBits; i++ {
		if bits[i] == 1 {
			entropy[i/8] |= 1 << (7 - i%8)
		}
	}

	// Compute expected checksum
	hash := sha256.Sum256(entropy)

	// Compare checksum bits
	for i := 0; i < checksumBits; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		expectedBit := int((hash[byteIdx] >> bitIdx) & 1)
		actualBit := bits[entropyBits+i]
		if expectedBit != actualBit {
			return false
		}
	}

	return true
}

// MnemonicToSeed converts a mnemonic to a 64-byte seed using PBKDF2.
// The passphrase is optional; use empty string for no passphrase.
func MnemonicToSeed(mnemonic, passphrase string) []byte {
	// Normalize mnemonic to NFKD form
	mnemonicNorm := norm.NFKD.String(mnemonic)

	// Salt = "mnemonic" + passphrase (also NFKD normalized)
	salt := "mnemonic" + norm.NFKD.String(passphrase)

	// PBKDF2 with HMAC-SHA512, 2048 iterations, 64-byte output
	return pbkdf2.Key([]byte(mnemonicNorm), []byte(salt), 2048, 64, sha512.New)
}

// MnemonicToEntropy converts a mnemonic back to entropy bytes.
func MnemonicToEntropy(mnemonic string) ([]byte, error) {
	words := strings.Fields(mnemonic)

	wordCount := len(words)
	if wordCount != 12 && wordCount != 15 && wordCount != 18 && wordCount != 21 && wordCount != 24 {
		return nil, ErrInvalidMnemonic
	}

	// Convert words to bit stream
	var bits []int
	for _, word := range words {
		idx, ok := wordIndex[word]
		if !ok {
			return nil, ErrInvalidMnemonic
		}
		for j := 10; j >= 0; j-- {
			bits = append(bits, (idx>>j)&1)
		}
	}

	totalBits := wordCount * 11
	checksumBits := wordCount / 3
	entropyBits := totalBits - checksumBits

	// Extract entropy bytes
	entropy := make([]byte, entropyBits/8)
	for i := 0; i < entropyBits; i++ {
		if bits[i] == 1 {
			entropy[i/8] |= 1 << (7 - i%8)
		}
	}

	// Verify checksum
	hash := sha256.Sum256(entropy)
	for i := 0; i < checksumBits; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		expectedBit := int((hash[byteIdx] >> bitIdx) & 1)
		actualBit := bits[entropyBits+i]
		if expectedBit != actualBit {
			return nil, ErrInvalidMnemonic
		}
	}

	return entropy, nil
}
