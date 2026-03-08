package wallet

import (
	"encoding/hex"
	"testing"

	"github.com/hashhog/blockbrew/internal/address"
)

func TestNewMasterKey(t *testing.T) {
	// BIP32 Test Vector 1
	// Seed: 000102030405060708090a0b0c0d0e0f
	seedHex := "000102030405060708090a0b0c0d0e0f"
	seed, _ := hex.DecodeString(seedHex)

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey failed: %v", err)
	}

	// Verify master key is private
	if !masterKey.IsPrivate {
		t.Error("Master key should be private")
	}

	// Verify depth is 0
	if masterKey.Depth != 0 {
		t.Errorf("Master key depth = %d, want 0", masterKey.Depth)
	}

	// Verify parent fingerprint is zero
	if masterKey.ParentFP != [4]byte{} {
		t.Errorf("Master key parent fingerprint = %x, want 0000", masterKey.ParentFP)
	}

	// Verify index is 0
	if masterKey.Index != 0 {
		t.Errorf("Master key index = %d, want 0", masterKey.Index)
	}

	// Expected master xprv
	expectedXprv := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	xprv := masterKey.Serialize(address.Mainnet)
	if xprv != expectedXprv {
		t.Errorf("Master xprv mismatch\nGot:      %s\nExpected: %s", xprv, expectedXprv)
	}

	// Expected master xpub
	expectedXpub := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	xpub := masterKey.PublicKey().Serialize(address.Mainnet)
	if xpub != expectedXpub {
		t.Errorf("Master xpub mismatch\nGot:      %s\nExpected: %s", xpub, expectedXpub)
	}
}

func TestBIP32TestVector1(t *testing.T) {
	// BIP32 Test Vector 1
	seedHex := "000102030405060708090a0b0c0d0e0f"
	seed, _ := hex.DecodeString(seedHex)

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey failed: %v", err)
	}

	tests := []struct {
		path     string
		xprv     string
		xpub     string
	}{
		{
			path: "m",
			xprv: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
			xpub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		},
		{
			path: "m/0'",
			xprv: "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
			xpub: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
		},
		{
			path: "m/0'/1",
			xprv: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
			xpub: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
		},
		{
			path: "m/0'/1/2'",
			xprv: "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
			xpub: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
		},
		{
			path: "m/0'/1/2'/2",
			xprv: "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
			xpub: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
		},
		{
			path: "m/0'/1/2'/2/1000000000",
			xprv: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
			xpub: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			key, err := masterKey.DerivePath(tt.path)
			if err != nil {
				t.Fatalf("DerivePath(%q) failed: %v", tt.path, err)
			}

			xprv := key.Serialize(address.Mainnet)
			if xprv != tt.xprv {
				t.Errorf("xprv mismatch for path %s\nGot:      %s\nExpected: %s", tt.path, xprv, tt.xprv)
			}

			xpub := key.PublicKey().Serialize(address.Mainnet)
			if xpub != tt.xpub {
				t.Errorf("xpub mismatch for path %s\nGot:      %s\nExpected: %s", tt.path, xpub, tt.xpub)
			}
		})
	}
}

func TestBIP32TestVector2(t *testing.T) {
	// BIP32 Test Vector 2
	seedHex := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
	seed, _ := hex.DecodeString(seedHex)

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey failed: %v", err)
	}

	tests := []struct {
		path     string
		xprv     string
		xpub     string
	}{
		{
			path: "m",
			xprv: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
			xpub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
		},
		{
			path: "m/0",
			xprv: "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
			xpub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
		},
		{
			path: "m/0/2147483647'",
			xprv: "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
			xpub: "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			key, err := masterKey.DerivePath(tt.path)
			if err != nil {
				t.Fatalf("DerivePath(%q) failed: %v", tt.path, err)
			}

			xprv := key.Serialize(address.Mainnet)
			if xprv != tt.xprv {
				t.Errorf("xprv mismatch for path %s\nGot:      %s\nExpected: %s", tt.path, xprv, tt.xprv)
			}

			xpub := key.PublicKey().Serialize(address.Mainnet)
			if xpub != tt.xpub {
				t.Errorf("xpub mismatch for path %s\nGot:      %s\nExpected: %s", tt.path, xpub, tt.xpub)
			}
		})
	}
}

func TestDeriveChild(t *testing.T) {
	seedHex := "000102030405060708090a0b0c0d0e0f"
	seed, _ := hex.DecodeString(seedHex)
	masterKey, _ := NewMasterKey(seed)

	// Test normal child derivation
	child, err := masterKey.DeriveChild(0)
	if err != nil {
		t.Fatalf("DeriveChild(0) failed: %v", err)
	}
	if child.Depth != 1 {
		t.Errorf("Child depth = %d, want 1", child.Depth)
	}
	if child.Index != 0 {
		t.Errorf("Child index = %d, want 0", child.Index)
	}

	// Test hardened child derivation
	hardenedChild, err := masterKey.DeriveChild(HardenedKeyStart)
	if err != nil {
		t.Fatalf("DeriveChild(hardened) failed: %v", err)
	}
	if hardenedChild.Index != HardenedKeyStart {
		t.Errorf("Hardened child index = %d, want %d", hardenedChild.Index, HardenedKeyStart)
	}

	// Test that public key cannot derive hardened child
	pubKey := masterKey.PublicKey()
	_, err = pubKey.DeriveChild(HardenedKeyStart)
	if err != ErrDerivingHardenedPub {
		t.Errorf("Expected ErrDerivingHardenedPub, got %v", err)
	}
}

func TestDerivePath(t *testing.T) {
	seedHex := "000102030405060708090a0b0c0d0e0f"
	seed, _ := hex.DecodeString(seedHex)
	masterKey, _ := NewMasterKey(seed)

	tests := []struct {
		path        string
		expectError bool
	}{
		{"m", false},
		{"m/0", false},
		{"m/0'", false},
		{"m/0h", false},
		{"m/0H", false},
		{"m/0'/1", false},
		{"m/0'/1/2'/2/1000000000", false},
		{"", true},          // Invalid: no 'm' prefix
		{"0/1", true},       // Invalid: no 'm' prefix
		{"m/abc", true},     // Invalid: non-numeric segment
		{"m/-1", true},      // Invalid: negative index
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			_, err := masterKey.DerivePath(tt.path)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for path %q, got nil", tt.path)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for path %q: %v", tt.path, err)
			}
		})
	}
}

func TestParseExtendedKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		isPriv   bool
	}{
		{
			name:   "mainnet xprv",
			key:    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
			isPriv: true,
		},
		{
			name:   "mainnet xpub",
			key:    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			isPriv: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParseExtendedKey(tt.key)
			if err != nil {
				t.Fatalf("ParseExtendedKey failed: %v", err)
			}

			if key.IsPrivate != tt.isPriv {
				t.Errorf("IsPrivate = %v, want %v", key.IsPrivate, tt.isPriv)
			}

			// Re-serialize and compare
			serialized := key.Serialize(address.Mainnet)
			if serialized != tt.key {
				t.Errorf("Re-serialization mismatch\nGot:      %s\nExpected: %s", serialized, tt.key)
			}
		})
	}
}

func TestPublicKeyDerivation(t *testing.T) {
	seedHex := "000102030405060708090a0b0c0d0e0f"
	seed, _ := hex.DecodeString(seedHex)
	masterKey, _ := NewMasterKey(seed)

	// Derive a non-hardened path from private key
	privKey, _ := masterKey.DerivePath("m/0")

	// Derive the same path from public key of parent
	pubKey := masterKey.PublicKey()
	derivedPub, err := pubKey.DerivePath("m/0")
	if err != nil {
		t.Fatalf("Public key derivation failed: %v", err)
	}

	// The derived public key should match
	expectedPub := privKey.PublicKey().Serialize(address.Mainnet)
	actualPub := derivedPub.Serialize(address.Mainnet)
	if actualPub != expectedPub {
		t.Errorf("Public key derivation mismatch\nGot:      %s\nExpected: %s", actualPub, expectedPub)
	}
}

func TestECKeys(t *testing.T) {
	seedHex := "000102030405060708090a0b0c0d0e0f"
	seed, _ := hex.DecodeString(seedHex)
	masterKey, _ := NewMasterKey(seed)

	// Test ECPrivKey
	privKey, err := masterKey.ECPrivKey()
	if err != nil {
		t.Fatalf("ECPrivKey failed: %v", err)
	}
	if privKey == nil {
		t.Error("ECPrivKey returned nil")
	}

	// Test ECPubKey
	pubKey, err := masterKey.ECPubKey()
	if err != nil {
		t.Fatalf("ECPubKey failed: %v", err)
	}
	if pubKey == nil {
		t.Error("ECPubKey returned nil")
	}

	// Verify pub key matches
	derivedPub := privKey.PubKey()
	if hex.EncodeToString(derivedPub.SerializeCompressed()) != hex.EncodeToString(pubKey.SerializeCompressed()) {
		t.Error("Public key derived from private doesn't match ECPubKey")
	}

	// Test ECPrivKey from public key (should error)
	pubHDKey := masterKey.PublicKey()
	_, err = pubHDKey.ECPrivKey()
	if err != ErrNotPrivateKey {
		t.Errorf("Expected ErrNotPrivateKey, got %v", err)
	}
}

func TestFingerprint(t *testing.T) {
	seedHex := "000102030405060708090a0b0c0d0e0f"
	seed, _ := hex.DecodeString(seedHex)
	masterKey, _ := NewMasterKey(seed)

	fp := masterKey.Fingerprint()

	// Master key fingerprint should not be zero
	if fp == [4]byte{} {
		t.Error("Master key fingerprint is zero")
	}

	// Child key should have parent fingerprint
	child, _ := masterKey.DeriveChild(0)
	if child.ParentFP != fp {
		t.Errorf("Child parent fingerprint = %x, want %x", child.ParentFP, fp)
	}
}

func TestBIP84Path(t *testing.T) {
	expected := "m/84'/0'/0'/0/5"
	actual := BIP84Path(0, 0, 0, 5)
	if actual != expected {
		t.Errorf("BIP84Path(0, 0, 0, 5) = %q, want %q", actual, expected)
	}

	expected = "m/84'/1'/0'/1/10"
	actual = BIP84Path(1, 0, 1, 10)
	if actual != expected {
		t.Errorf("BIP84Path(1, 0, 1, 10) = %q, want %q", actual, expected)
	}
}

func TestInvalidSeed(t *testing.T) {
	// Too short
	_, err := NewMasterKey([]byte{1, 2, 3, 4, 5})
	if err != ErrInvalidSeedLength {
		t.Errorf("Expected ErrInvalidSeedLength for short seed, got %v", err)
	}

	// Too long
	longSeed := make([]byte, 100)
	_, err = NewMasterKey(longSeed)
	if err != ErrInvalidSeedLength {
		t.Errorf("Expected ErrInvalidSeedLength for long seed, got %v", err)
	}
}

func BenchmarkDerivePath(b *testing.B) {
	seedHex := "000102030405060708090a0b0c0d0e0f"
	seed, _ := hex.DecodeString(seedHex)
	masterKey, _ := NewMasterKey(seed)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		masterKey.DerivePath("m/84'/0'/0'/0/0")
	}
}
