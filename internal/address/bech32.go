package address

import (
	"errors"
	"strings"
)

// Bech32 alphabet
const bech32Alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// Checksum constants
const (
	bech32Const  = 1
	bech32mConst = 0x2bc830a3
)

var bech32AlphabetMap [256]int

func init() {
	for i := range bech32AlphabetMap {
		bech32AlphabetMap[i] = -1
	}
	for i, c := range bech32Alphabet {
		bech32AlphabetMap[c] = i
	}
}

// Bech32 errors
var (
	ErrInvalidBech32Char     = errors.New("invalid bech32 character")
	ErrInvalidBech32Checksum = errors.New("invalid bech32 checksum")
	ErrInvalidBech32Length   = errors.New("invalid bech32 length")
	ErrInvalidBech32Format   = errors.New("invalid bech32 format")
	ErrMixedCase             = errors.New("mixed case in bech32 string")
	ErrInvalidHRP            = errors.New("invalid human-readable part")
	ErrInvalidBitConversion  = errors.New("invalid bit conversion")
)

// bech32Polymod computes the bech32 checksum polynomial.
func bech32Polymod(values []int) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i, g := range gen {
			if (b>>uint(i))&1 == 1 {
				chk ^= g
			}
		}
	}
	return chk
}

// hrpExpand splits the HRP into high and low parts with a zero separator.
func hrpExpand(hrp string) []int {
	result := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		result = append(result, int(c>>5))
	}
	result = append(result, 0)
	for _, c := range hrp {
		result = append(result, int(c&31))
	}
	return result
}

// createChecksum creates a bech32/bech32m checksum for the given HRP and data.
func createChecksum(hrp string, data []int, spec int) []int {
	values := append(hrpExpand(hrp), data...)
	values = append(values, []int{0, 0, 0, 0, 0, 0}...)
	polymod := bech32Polymod(values) ^ spec
	checksum := make([]int, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = (polymod >> uint(5*(5-i))) & 31
	}
	return checksum
}

// verifyChecksum verifies the bech32/bech32m checksum.
func verifyChecksum(hrp string, data []int) int {
	return bech32Polymod(append(hrpExpand(hrp), data...))
}

// ConvertBits converts between bit groups. Used for bech32 witness program encoding.
func ConvertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := 0
	bits := uint(0)
	maxv := (1 << toBits) - 1
	result := make([]byte, 0, len(data)*int(fromBits)/int(toBits)+1)

	for _, value := range data {
		acc = (acc << fromBits) | int(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((acc>>bits)&maxv))
		}
	}

	if pad {
		if bits > 0 {
			result = append(result, byte((acc<<(toBits-bits))&maxv))
		}
	} else {
		if bits >= fromBits {
			return nil, ErrInvalidBitConversion
		}
		if ((acc << (toBits - bits)) & maxv) != 0 {
			return nil, ErrInvalidBitConversion
		}
	}

	return result, nil
}

// bech32Encode is the internal encoder for both bech32 and bech32m.
func bech32Encode(hrp string, data []byte, spec int) (string, error) {
	// Validate HRP
	if len(hrp) < 1 || len(hrp) > 83 {
		return "", ErrInvalidHRP
	}
	for _, c := range hrp {
		if c < 33 || c > 126 {
			return "", ErrInvalidHRP
		}
	}

	// Convert data to 5-bit groups (already expected to be 5-bit values)
	data5 := make([]int, len(data))
	for i, b := range data {
		data5[i] = int(b)
	}

	// Create checksum
	checksum := createChecksum(hrp, data5, spec)

	// Build result
	var result strings.Builder
	result.WriteString(strings.ToLower(hrp))
	result.WriteByte('1')
	for _, d := range data5 {
		result.WriteByte(bech32Alphabet[d])
	}
	for _, c := range checksum {
		result.WriteByte(bech32Alphabet[c])
	}

	return result.String(), nil
}

// bech32Decode is the internal decoder for both bech32 and bech32m.
func bech32Decode(s string) (string, []byte, int, error) {
	// Check for mixed case
	hasLower := false
	hasUpper := false
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			hasLower = true
		}
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
	}
	if hasLower && hasUpper {
		return "", nil, 0, ErrMixedCase
	}

	// Convert to lowercase
	s = strings.ToLower(s)

	// Find the last '1' separator
	sepIdx := strings.LastIndex(s, "1")
	if sepIdx == -1 {
		return "", nil, 0, ErrInvalidBech32Format
	}
	if sepIdx < 1 {
		return "", nil, 0, ErrInvalidHRP
	}
	if len(s)-sepIdx-1 < 6 {
		return "", nil, 0, ErrInvalidBech32Length
	}

	hrp := s[:sepIdx]
	dataStr := s[sepIdx+1:]

	// Validate HRP
	for _, c := range hrp {
		if c < 33 || c > 126 {
			return "", nil, 0, ErrInvalidHRP
		}
	}

	// Decode data
	data := make([]int, len(dataStr))
	for i, c := range dataStr {
		idx := bech32AlphabetMap[c]
		if idx == -1 {
			return "", nil, 0, ErrInvalidBech32Char
		}
		data[i] = idx
	}

	// Verify checksum and determine type
	spec := verifyChecksum(hrp, data)

	// Remove checksum from data
	data = data[:len(data)-6]

	// Convert to bytes
	result := make([]byte, len(data))
	for i, d := range data {
		result[i] = byte(d)
	}

	return hrp, result, spec, nil
}

// Bech32Encode encodes data as bech32 (BIP173).
func Bech32Encode(hrp string, data []byte) (string, error) {
	return bech32Encode(hrp, data, bech32Const)
}

// Bech32Decode decodes a bech32 string. Returns (hrp, data, error).
func Bech32Decode(s string) (string, []byte, error) {
	hrp, data, spec, err := bech32Decode(s)
	if err != nil {
		return "", nil, err
	}
	if spec != bech32Const {
		return "", nil, ErrInvalidBech32Checksum
	}
	return hrp, data, nil
}

// Bech32mEncode encodes data as bech32m (BIP350).
func Bech32mEncode(hrp string, data []byte) (string, error) {
	return bech32Encode(hrp, data, bech32mConst)
}

// Bech32mDecode decodes a bech32m string. Returns (hrp, data, error).
func Bech32mDecode(s string) (string, []byte, error) {
	hrp, data, spec, err := bech32Decode(s)
	if err != nil {
		return "", nil, err
	}
	if spec != bech32mConst {
		return "", nil, ErrInvalidBech32Checksum
	}
	return hrp, data, nil
}
