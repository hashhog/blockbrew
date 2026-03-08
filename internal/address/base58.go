// Package address implements Bitcoin address encoding and decoding.
package address

import (
	"errors"
	"math/big"
	"strings"

	"github.com/hashhog/blockbrew/internal/crypto"
)

// Base58 alphabet (excludes 0, O, I, l for readability).
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var (
	base58AlphabetMap [256]int
	bigZero           = big.NewInt(0)
	big58             = big.NewInt(58)
)

func init() {
	for i := range base58AlphabetMap {
		base58AlphabetMap[i] = -1
	}
	for i, c := range base58Alphabet {
		base58AlphabetMap[c] = i
	}
}

// ErrInvalidBase58Char is returned when a string contains an invalid Base58 character.
var ErrInvalidBase58Char = errors.New("invalid base58 character")

// ErrInvalidChecksum is returned when the Base58Check checksum is invalid.
var ErrInvalidChecksum = errors.New("invalid base58check checksum")

// ErrInvalidBase58Length is returned when the decoded data is too short.
var ErrInvalidBase58Length = errors.New("invalid base58check length")

// Base58Encode encodes a byte slice to Base58.
func Base58Encode(input []byte) string {
	// Count leading zeros
	var leadingZeros int
	for _, b := range input {
		if b != 0 {
			break
		}
		leadingZeros++
	}

	// Convert to big integer
	num := new(big.Int).SetBytes(input)

	// Build result string by repeatedly dividing by 58
	var result strings.Builder
	mod := new(big.Int)
	for num.Cmp(bigZero) > 0 {
		num.DivMod(num, big58, mod)
		result.WriteByte(base58Alphabet[mod.Int64()])
	}

	// Get the result and reverse it
	encoded := result.String()
	reversed := make([]byte, len(encoded))
	for i := 0; i < len(encoded); i++ {
		reversed[i] = encoded[len(encoded)-1-i]
	}

	// Prepend '1' for each leading zero byte
	return strings.Repeat("1", leadingZeros) + string(reversed)
}

// Base58Decode decodes a Base58 string to bytes.
func Base58Decode(input string) ([]byte, error) {
	if len(input) == 0 {
		return []byte{}, nil
	}

	// Count leading '1' characters (they represent leading zero bytes)
	var leadingOnes int
	for _, c := range input {
		if c != '1' {
			break
		}
		leadingOnes++
	}

	// Convert from base58 to big integer
	num := new(big.Int)
	for _, c := range input {
		idx := base58AlphabetMap[c]
		if idx == -1 {
			return nil, ErrInvalidBase58Char
		}
		num.Mul(num, big58)
		num.Add(num, big.NewInt(int64(idx)))
	}

	// Convert to bytes
	decoded := num.Bytes()

	// Prepend leading zero bytes
	result := make([]byte, leadingOnes+len(decoded))
	copy(result[leadingOnes:], decoded)

	return result, nil
}

// Base58CheckEncode encodes with a version byte and 4-byte checksum.
// Format: version_byte || payload || checksum (first 4 bytes of DoubleSHA256(version_byte || payload))
func Base58CheckEncode(version byte, payload []byte) string {
	// version_byte || payload
	data := make([]byte, 1+len(payload))
	data[0] = version
	copy(data[1:], payload)

	// Compute checksum (first 4 bytes of DoubleSHA256)
	checksum := crypto.DoubleSHA256(data)

	// Append checksum
	result := make([]byte, len(data)+4)
	copy(result, data)
	copy(result[len(data):], checksum[:4])

	return Base58Encode(result)
}

// Base58CheckDecode decodes and verifies the checksum. Returns (version, payload, error).
func Base58CheckDecode(input string) (byte, []byte, error) {
	decoded, err := Base58Decode(input)
	if err != nil {
		return 0, nil, err
	}

	// Minimum length: 1 byte version + 4 bytes checksum
	if len(decoded) < 5 {
		return 0, nil, ErrInvalidBase58Length
	}

	// Split into data and checksum
	data := decoded[:len(decoded)-4]
	providedChecksum := decoded[len(decoded)-4:]

	// Verify checksum
	computedChecksum := crypto.DoubleSHA256(data)
	if providedChecksum[0] != computedChecksum[0] ||
		providedChecksum[1] != computedChecksum[1] ||
		providedChecksum[2] != computedChecksum[2] ||
		providedChecksum[3] != computedChecksum[3] {
		return 0, nil, ErrInvalidChecksum
	}

	// Extract version and payload
	version := data[0]
	payload := data[1:]

	return version, payload, nil
}
