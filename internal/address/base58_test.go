package address

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBase58Encode(t *testing.T) {
	tests := []struct {
		name     string
		input    string // hex
		expected string
	}{
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
		{
			name:     "single zero",
			input:    "00",
			expected: "1",
		},
		{
			name:     "multiple leading zeros",
			input:    "000000",
			expected: "111",
		},
		{
			name:     "hello world",
			input:    "48656c6c6f20576f726c64",
			expected: "JxF12TrwUP45BMd",
		},
		{
			name:     "leading zero with data",
			input:    "00010966776006953D5567439E5E39F86A0D273BEED61967F6",
			expected: "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, _ := hex.DecodeString(tt.input)
			result := Base58Encode(input)
			if result != tt.expected {
				t.Errorf("Base58Encode(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBase58Decode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string // hex
		wantErr  bool
	}{
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
		{
			name:     "single 1",
			input:    "1",
			expected: "00",
		},
		{
			name:     "multiple 1s",
			input:    "111",
			expected: "000000",
		},
		{
			name:     "hello world",
			input:    "JxF12TrwUP45BMd",
			expected: "48656c6c6f20576f726c64",
		},
		{
			name:     "address with leading zero",
			input:    "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
			expected: "00010966776006953D5567439E5E39F86A0D273BEED61967F6",
		},
		{
			name:    "invalid character 0",
			input:   "0123",
			wantErr: true,
		},
		{
			name:    "invalid character O",
			input:   "ABCO",
			wantErr: true,
		},
		{
			name:    "invalid character I",
			input:   "ABCI",
			wantErr: true,
		},
		{
			name:    "invalid character l",
			input:   "abcl",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Base58Decode(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Base58Decode(%s) expected error", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("Base58Decode(%s) unexpected error: %v", tt.input, err)
				return
			}
			expected, _ := hex.DecodeString(tt.expected)
			if !bytes.Equal(result, expected) {
				t.Errorf("Base58Decode(%s) = %x, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBase58RoundTrip(t *testing.T) {
	testData := []string{
		"",
		"00",
		"0000",
		"ff",
		"00ff",
		"ff00",
		"0011223344556677889900aabbccddeeff",
		"000000112233",
	}

	for _, hexStr := range testData {
		t.Run(hexStr, func(t *testing.T) {
			original, _ := hex.DecodeString(hexStr)
			encoded := Base58Encode(original)
			decoded, err := Base58Decode(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if !bytes.Equal(original, decoded) {
				t.Errorf("round trip failed: %x -> %s -> %x", original, encoded, decoded)
			}
		})
	}
}

func TestBase58CheckEncode(t *testing.T) {
	tests := []struct {
		name     string
		version  byte
		payload  string // hex
		expected string
	}{
		{
			name:     "mainnet P2PKH - Satoshi's address",
			version:  0x00,
			payload:  "62e907b15cbf27d5425399ebf6f0fb50ebb88f18",
			expected: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, _ := hex.DecodeString(tt.payload)
			result := Base58CheckEncode(tt.version, payload)
			if result != tt.expected {
				t.Errorf("Base58CheckEncode(0x%02x, %s) = %s, want %s",
					tt.version, tt.payload, result, tt.expected)
			}
		})
	}
}

func TestBase58CheckDecode(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedVersion byte
		expectedPayload string // hex
		wantErr         bool
	}{
		{
			name:            "mainnet P2PKH - Satoshi's address",
			input:           "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			expectedVersion: 0x00,
			expectedPayload: "62e907b15cbf27d5425399ebf6f0fb50ebb88f18",
		},
		{
			name:    "invalid checksum",
			input:   "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfxx",
			wantErr: true,
		},
		{
			name:    "too short",
			input:   "1A1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, payload, err := Base58CheckDecode(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Base58CheckDecode(%s) expected error", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("Base58CheckDecode(%s) unexpected error: %v", tt.input, err)
				return
			}
			if version != tt.expectedVersion {
				t.Errorf("version = 0x%02x, want 0x%02x", version, tt.expectedVersion)
			}
			expectedPayload, _ := hex.DecodeString(tt.expectedPayload)
			if !bytes.Equal(payload, expectedPayload) {
				t.Errorf("payload = %x, want %s", payload, tt.expectedPayload)
			}
		})
	}
}

func TestBase58CheckRoundTrip(t *testing.T) {
	testCases := []struct {
		version byte
		payload string
	}{
		{0x00, "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"},
		{0x05, "89abcdefabbaabbaabbaabbaabbaabbaabbaabba"},
		{0x6F, "1234567890123456789012345678901234567890"},
		{0xC4, "abcdef0123456789abcdef0123456789abcdef01"},
	}

	for _, tc := range testCases {
		payload, _ := hex.DecodeString(tc.payload)
		encoded := Base58CheckEncode(tc.version, payload)
		decodedVer, decodedPayload, err := Base58CheckDecode(encoded)
		if err != nil {
			t.Errorf("round trip decode error for version 0x%02x: %v", tc.version, err)
			continue
		}
		if decodedVer != tc.version {
			t.Errorf("version mismatch: got 0x%02x, want 0x%02x", decodedVer, tc.version)
		}
		if !bytes.Equal(decodedPayload, payload) {
			t.Errorf("payload mismatch: got %x, want %s", decodedPayload, tc.payload)
		}
	}
}
