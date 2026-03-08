package address

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestConvertBits(t *testing.T) {
	tests := []struct {
		name     string
		data     string // hex
		fromBits uint
		toBits   uint
		pad      bool
		expected string // hex
		wantErr  bool
	}{
		{
			name:     "8 to 5 with padding",
			data:     "751e76e8199196d454941c45d1b3a323f1433bd6",
			fromBits: 8,
			toBits:   5,
			pad:      true,
			expected: "0e140f070d1a001912060b0d081504140311021d030c1d03040f1814060e1e16",
		},
		{
			name:     "5 to 8 no padding",
			data:     "0e140f070d1a001912060b0d081504140311021d030c1d03040f1814060e1e16",
			fromBits: 5,
			toBits:   8,
			pad:      false,
			expected: "751e76e8199196d454941c45d1b3a323f1433bd6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := hex.DecodeString(tt.data)
			result, err := ConvertBits(data, tt.fromBits, tt.toBits, tt.pad)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ConvertBits expected error")
				}
				return
			}
			if err != nil {
				t.Errorf("ConvertBits unexpected error: %v", err)
				return
			}
			expected, _ := hex.DecodeString(tt.expected)
			if !bytes.Equal(result, expected) {
				t.Errorf("ConvertBits = %x, want %s", result, tt.expected)
			}
		})
	}
}

func TestBech32Encode(t *testing.T) {
	tests := []struct {
		name     string
		hrp      string
		data     []byte
		expected string
	}{
		{
			name:     "empty data",
			hrp:      "bc",
			data:     []byte{},
			expected: "bc1gmk9yu",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Bech32Encode(tt.hrp, tt.data)
			if err != nil {
				t.Fatalf("Bech32Encode error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Bech32Encode = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestBech32Decode(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedHRP string
		wantErr     bool
	}{
		{
			name:        "valid bech32",
			input:       "bc1gmk9yu",
			expectedHRP: "bc",
		},
		{
			name:    "mixed case",
			input:   "BC1Gmk9yu",
			wantErr: true,
		},
		{
			name:    "no separator",
			input:   "bcgmk9yu",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hrp, _, err := Bech32Decode(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Bech32Decode expected error")
				}
				return
			}
			if err != nil {
				t.Errorf("Bech32Decode unexpected error: %v", err)
				return
			}
			if hrp != tt.expectedHRP {
				t.Errorf("hrp = %s, want %s", hrp, tt.expectedHRP)
			}
		})
	}
}

func TestBech32RoundTrip(t *testing.T) {
	testCases := []struct {
		hrp  string
		data []byte
	}{
		{"bc", []byte{}},
		{"bc", []byte{0, 1, 2, 3, 4, 5}},
		{"tb", []byte{15, 20, 25, 30, 31}},
		{"bcrt", []byte{0, 0, 0, 1, 2, 3}},
	}

	for _, tc := range testCases {
		encoded, err := Bech32Encode(tc.hrp, tc.data)
		if err != nil {
			t.Errorf("encode error for %s: %v", tc.hrp, err)
			continue
		}
		hrp, data, err := Bech32Decode(encoded)
		if err != nil {
			t.Errorf("decode error for %s: %v", encoded, err)
			continue
		}
		if hrp != tc.hrp {
			t.Errorf("hrp mismatch: got %s, want %s", hrp, tc.hrp)
		}
		if !bytes.Equal(data, tc.data) {
			t.Errorf("data mismatch: got %v, want %v", data, tc.data)
		}
	}
}

func TestBech32mRoundTrip(t *testing.T) {
	testCases := []struct {
		hrp  string
		data []byte
	}{
		{"bc", []byte{1, 2, 3, 4, 5}},
		{"tb", []byte{1, 15, 20, 25, 30, 31}},
	}

	for _, tc := range testCases {
		encoded, err := Bech32mEncode(tc.hrp, tc.data)
		if err != nil {
			t.Errorf("encode error for %s: %v", tc.hrp, err)
			continue
		}
		hrp, data, err := Bech32mDecode(encoded)
		if err != nil {
			t.Errorf("decode error for %s: %v", encoded, err)
			continue
		}
		if hrp != tc.hrp {
			t.Errorf("hrp mismatch: got %s, want %s", hrp, tc.hrp)
		}
		if !bytes.Equal(data, tc.data) {
			t.Errorf("data mismatch: got %v, want %v", data, tc.data)
		}
	}
}

func TestBech32VsBech32m(t *testing.T) {
	// A bech32 encoded string should NOT decode as bech32m and vice versa
	hrp := "bc"
	data := []byte{0, 1, 2, 3, 4}

	bech32Str, _ := Bech32Encode(hrp, data)
	bech32mStr, _ := Bech32mEncode(hrp, data)

	// They should be different
	if bech32Str == bech32mStr {
		t.Errorf("bech32 and bech32m produced same string: %s", bech32Str)
	}

	// bech32 string should not decode as bech32m
	_, _, err := Bech32mDecode(bech32Str)
	if err == nil {
		t.Errorf("bech32 string decoded as bech32m: %s", bech32Str)
	}

	// bech32m string should not decode as bech32
	_, _, err = Bech32Decode(bech32mStr)
	if err == nil {
		t.Errorf("bech32m string decoded as bech32: %s", bech32mStr)
	}
}
