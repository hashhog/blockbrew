package address

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDecodeKnownAddresses(t *testing.T) {
	tests := []struct {
		name         string
		address      string
		network      Network
		expectedType AddressType
		expectedHash string // hex
	}{
		{
			name:         "mainnet P2PKH - Satoshi's address",
			address:      "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			network:      Mainnet,
			expectedType: P2PKH,
			expectedHash: "62e907b15cbf27d5425399ebf6f0fb50ebb88f18",
		},
		{
			name:         "mainnet P2WPKH",
			address:      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			network:      Mainnet,
			expectedType: P2WPKH,
			expectedHash: "751e76e8199196d454941c45d1b3a323f1433bd6",
		},
		{
			name:         "mainnet P2TR",
			address:      "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
			network:      Mainnet,
			expectedType: P2TR,
			expectedHash: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := DecodeAddress(tt.address, tt.network)
			if err != nil {
				t.Fatalf("DecodeAddress(%s) error: %v", tt.address, err)
			}

			if addr.Type != tt.expectedType {
				t.Errorf("Type = %v, want %v", addr.Type, tt.expectedType)
			}

			if addr.Network != tt.network {
				t.Errorf("Network = %v, want %v", addr.Network, tt.network)
			}

			expectedHash, _ := hex.DecodeString(tt.expectedHash)
			if !bytes.Equal(addr.Hash, expectedHash) {
				t.Errorf("Hash = %x, want %s", addr.Hash, tt.expectedHash)
			}
		})
	}
}

func TestEncodeKnownAddresses(t *testing.T) {
	tests := []struct {
		name     string
		addrType AddressType
		network  Network
		hash     string // hex
		expected string
	}{
		{
			name:     "mainnet P2PKH - Satoshi's address",
			addrType: P2PKH,
			network:  Mainnet,
			hash:     "62e907b15cbf27d5425399ebf6f0fb50ebb88f18",
			expected: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		},
		{
			name:     "mainnet P2WPKH",
			addrType: P2WPKH,
			network:  Mainnet,
			hash:     "751e76e8199196d454941c45d1b3a323f1433bd6",
			expected: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		},
		{
			name:     "mainnet P2TR",
			addrType: P2TR,
			network:  Mainnet,
			hash:     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			expected: "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, _ := hex.DecodeString(tt.hash)
			addr := &Address{
				Type:    tt.addrType,
				Network: tt.network,
				Hash:    hash,
			}

			encoded, err := addr.Encode()
			if err != nil {
				t.Fatalf("Encode() error: %v", err)
			}

			if encoded != tt.expected {
				t.Errorf("Encode() = %s, want %s", encoded, tt.expected)
			}
		})
	}
}

func TestAddressRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		address string
		network Network
	}{
		// Mainnet P2PKH
		{"mainnet P2PKH", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Mainnet},
		// Mainnet P2WPKH
		{"mainnet P2WPKH", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Mainnet},
		// Mainnet P2TR
		{"mainnet P2TR", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", Mainnet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Decode
			addr, err := DecodeAddress(tt.address, tt.network)
			if err != nil {
				t.Fatalf("DecodeAddress(%s) error: %v", tt.address, err)
			}

			// Encode
			encoded, err := addr.Encode()
			if err != nil {
				t.Fatalf("Encode() error: %v", err)
			}

			if encoded != tt.address {
				t.Errorf("round trip failed: %s -> %s", tt.address, encoded)
			}
		})
	}
}

func TestNewAddressFunctions(t *testing.T) {
	var hash20 [20]byte
	var hash32 [32]byte
	copy(hash20[:], bytes.Repeat([]byte{0xab}, 20))
	copy(hash32[:], bytes.Repeat([]byte{0xcd}, 32))

	t.Run("NewP2PKHAddress", func(t *testing.T) {
		addr := NewP2PKHAddress(hash20, Mainnet)
		if addr.Type != P2PKH {
			t.Errorf("Type = %v, want P2PKH", addr.Type)
		}
		if addr.Network != Mainnet {
			t.Errorf("Network = %v, want Mainnet", addr.Network)
		}
		if !bytes.Equal(addr.Hash, hash20[:]) {
			t.Errorf("Hash mismatch")
		}
	})

	t.Run("NewP2SHAddress", func(t *testing.T) {
		addr := NewP2SHAddress(hash20, Testnet)
		if addr.Type != P2SH {
			t.Errorf("Type = %v, want P2SH", addr.Type)
		}
		if addr.Network != Testnet {
			t.Errorf("Network = %v, want Testnet", addr.Network)
		}
	})

	t.Run("NewP2WPKHAddress", func(t *testing.T) {
		addr := NewP2WPKHAddress(hash20, Mainnet)
		if addr.Type != P2WPKH {
			t.Errorf("Type = %v, want P2WPKH", addr.Type)
		}
	})

	t.Run("NewP2WSHAddress", func(t *testing.T) {
		addr := NewP2WSHAddress(hash32, Mainnet)
		if addr.Type != P2WSH {
			t.Errorf("Type = %v, want P2WSH", addr.Type)
		}
		if !bytes.Equal(addr.Hash, hash32[:]) {
			t.Errorf("Hash mismatch")
		}
	})

	t.Run("NewP2TRAddress", func(t *testing.T) {
		addr := NewP2TRAddress(hash32, Mainnet)
		if addr.Type != P2TR {
			t.Errorf("Type = %v, want P2TR", addr.Type)
		}
	})
}

func TestScriptPubKey(t *testing.T) {
	tests := []struct {
		name     string
		addrType AddressType
		hash     string // hex
		expected string // hex
	}{
		{
			name:     "P2PKH",
			addrType: P2PKH,
			hash:     "62e907b15cbf27d5425399ebf6f0fb50ebb88f18",
			expected: "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
		},
		{
			name:     "P2SH",
			addrType: P2SH,
			hash:     "89abcdefabbaabbaabbaabbaabbaabbaabbaabba",
			expected: "a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87",
		},
		{
			name:     "P2WPKH",
			addrType: P2WPKH,
			hash:     "751e76e8199196d454941c45d1b3a323f1433bd6",
			expected: "0014751e76e8199196d454941c45d1b3a323f1433bd6",
		},
		{
			name:     "P2WSH",
			addrType: P2WSH,
			hash:     "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
			expected: "0020a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
		},
		{
			name:     "P2TR",
			addrType: P2TR,
			hash:     "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
			expected: "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, _ := hex.DecodeString(tt.hash)
			addr := &Address{
				Type:    tt.addrType,
				Network: Mainnet,
				Hash:    hash,
			}

			script := addr.ScriptPubKey()
			expected, _ := hex.DecodeString(tt.expected)

			if !bytes.Equal(script, expected) {
				t.Errorf("ScriptPubKey = %x, want %s", script, tt.expected)
			}
		})
	}
}

func TestAddressEqual(t *testing.T) {
	hash1, _ := hex.DecodeString("62e907b15cbf27d5425399ebf6f0fb50ebb88f18")
	hash2, _ := hex.DecodeString("751e76e8199196d454941c45d1b3a323f1433bd6")

	addr1 := &Address{Type: P2PKH, Network: Mainnet, Hash: hash1}
	addr2 := &Address{Type: P2PKH, Network: Mainnet, Hash: hash1}
	addr3 := &Address{Type: P2PKH, Network: Testnet, Hash: hash1}
	addr4 := &Address{Type: P2WPKH, Network: Mainnet, Hash: hash2}

	if !addr1.Equal(addr2) {
		t.Errorf("addr1 should equal addr2")
	}
	if addr1.Equal(addr3) {
		t.Errorf("addr1 should not equal addr3 (different network)")
	}
	if addr1.Equal(addr4) {
		t.Errorf("addr1 should not equal addr4 (different type and hash)")
	}
	if addr1.Equal(nil) {
		t.Errorf("addr1 should not equal nil")
	}

	var nilAddr *Address
	if !nilAddr.Equal(nil) {
		t.Errorf("nil should equal nil")
	}
}

func TestDecodeAddressErrors(t *testing.T) {
	tests := []struct {
		name    string
		address string
		network Network
	}{
		{
			name:    "mainnet address on testnet",
			address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			network: Testnet,
		},
		{
			name:    "wrong HRP for network",
			address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			network: Testnet,
		},
		{
			name:    "invalid checksum",
			address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfxx",
			network: Mainnet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeAddress(tt.address, tt.network)
			if err == nil {
				t.Errorf("DecodeAddress(%s) expected error", tt.address)
			}
		})
	}
}

func TestTestnetAddresses(t *testing.T) {
	// Test testnet P2WPKH
	t.Run("testnet P2WPKH", func(t *testing.T) {
		var hash [20]byte
		hashBytes, _ := hex.DecodeString("751e76e8199196d454941c45d1b3a323f1433bd6")
		copy(hash[:], hashBytes)

		addr := NewP2WPKHAddress(hash, Testnet)
		encoded, err := addr.Encode()
		if err != nil {
			t.Fatalf("Encode error: %v", err)
		}
		if encoded[:2] != "tb" {
			t.Errorf("testnet address should start with tb, got %s", encoded)
		}

		// Decode and verify
		decoded, err := DecodeAddress(encoded, Testnet)
		if err != nil {
			t.Fatalf("Decode error: %v", err)
		}
		if !addr.Equal(decoded) {
			t.Errorf("round trip failed")
		}
	})

	// Test regtest P2WPKH
	t.Run("regtest P2WPKH", func(t *testing.T) {
		var hash [20]byte
		hashBytes, _ := hex.DecodeString("751e76e8199196d454941c45d1b3a323f1433bd6")
		copy(hash[:], hashBytes)

		addr := NewP2WPKHAddress(hash, Regtest)
		encoded, err := addr.Encode()
		if err != nil {
			t.Fatalf("Encode error: %v", err)
		}
		if encoded[:4] != "bcrt" {
			t.Errorf("regtest address should start with bcrt, got %s", encoded)
		}

		// Decode and verify
		decoded, err := DecodeAddress(encoded, Regtest)
		if err != nil {
			t.Fatalf("Decode error: %v", err)
		}
		if !addr.Equal(decoded) {
			t.Errorf("round trip failed")
		}
	})
}

func TestP2SHAddress(t *testing.T) {
	// Test mainnet P2SH
	var hash [20]byte
	hashBytes, _ := hex.DecodeString("89abcdefabbaabbaabbaabbaabbaabbaabbaabba")
	copy(hash[:], hashBytes)

	addr := NewP2SHAddress(hash, Mainnet)
	encoded, err := addr.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	// Mainnet P2SH addresses start with '3'
	if encoded[0] != '3' {
		t.Errorf("mainnet P2SH should start with '3', got %c", encoded[0])
	}

	// Decode and verify
	decoded, err := DecodeAddress(encoded, Mainnet)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if decoded.Type != P2SH {
		t.Errorf("Type = %v, want P2SH", decoded.Type)
	}
	if !addr.Equal(decoded) {
		t.Errorf("round trip failed")
	}
}

func TestP2WSHAddress(t *testing.T) {
	var hash [32]byte
	hashBytes, _ := hex.DecodeString("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
	copy(hash[:], hashBytes)

	addr := NewP2WSHAddress(hash, Mainnet)
	encoded, err := addr.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	// P2WSH uses witness version 0, so bech32 (not bech32m)
	// Should start with bc1q
	if encoded[:4] != "bc1q" {
		t.Errorf("mainnet P2WSH should start with 'bc1q', got %s", encoded[:4])
	}

	// Decode and verify
	decoded, err := DecodeAddress(encoded, Mainnet)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if decoded.Type != P2WSH {
		t.Errorf("Type = %v, want P2WSH", decoded.Type)
	}
	if !addr.Equal(decoded) {
		t.Errorf("round trip failed")
	}
}
