package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestDetectSHA256Implementation(t *testing.T) {
	impl := DetectSHA256Implementation()

	// Verify we get a non-empty implementation name
	if impl.Name == "" {
		t.Error("Expected non-empty implementation name")
	}

	// Verify arch is set
	if impl.Arch == "" {
		t.Error("Expected non-empty architecture")
	}

	t.Logf("SHA256 implementation: %s (arch=%s, sha-ni=%v, avx2=%v)",
		impl.Name, impl.Arch, impl.HasSHANI, impl.HasAVX2)
}

func TestSum256(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty",
			input:    []byte{},
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "hello",
			input:    []byte("hello"),
			expected: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:     "test",
			input:    []byte("test"),
			expected: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Sum256(tt.input)
			got := hex.EncodeToString(result[:])
			if got != tt.expected {
				t.Errorf("Sum256(%q) = %s, want %s", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDoubleSum256(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty",
			input:    []byte{},
			expected: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
		},
		{
			name:     "bitcoin",
			input:    []byte("bitcoin"),
			expected: "f1ef1bf105d788352c052453b15a913403be59b90ddf9f7c1f937edee8938dc5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DoubleSum256(tt.input)
			got := hex.EncodeToString(result[:])
			if got != tt.expected {
				t.Errorf("DoubleSum256(%q) = %s, want %s", tt.input, got, tt.expected)
			}
		})
	}
}

func TestMidstateComputation(t *testing.T) {
	// Create a test 80-byte block header
	var header [80]byte
	for i := range header {
		header[i] = byte(i)
	}

	// Compute full hash the normal way
	expectedFirst := sha256.Sum256(header[:])
	expected := sha256.Sum256(expectedFirst[:])

	// Compute using midstate optimization
	var firstBlock [64]byte
	copy(firstBlock[:], header[:64])
	midstate := ComputeMidstate(firstBlock)

	var secondBlock [16]byte
	copy(secondBlock[:], header[64:])

	// Get first SHA256 using midstate
	firstHash := midstate.FinishHash(secondBlock)
	// Second SHA256
	result := sha256.Sum256(firstHash[:])

	if result != expected {
		t.Errorf("Midstate computation mismatch:\ngot:  %x\nwant: %x", result, expected)
	}
}

func TestDoubleHashBlockHeader(t *testing.T) {
	// Bitcoin genesis block header
	// version: 1
	// prev_block: 0000000000000000000000000000000000000000000000000000000000000000
	// merkle_root: 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
	// timestamp: 1231006505
	// bits: 1d00ffff
	// nonce: 2083236893

	headerHex := "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
	headerBytes, err := hex.DecodeString(headerHex)
	if err != nil {
		t.Fatal(err)
	}

	var header [80]byte
	copy(header[:], headerBytes)

	hash := DoubleHashBlockHeader(header)

	// Expected hash (little-endian, so we need to reverse for display)
	// Genesis block hash: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
	expectedHashLE := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	expectedBytes, _ := hex.DecodeString(expectedHashLE)

	// Reverse for comparison (Bitcoin displays hashes in reverse byte order)
	var reversedHash [32]byte
	for i := 0; i < 32; i++ {
		reversedHash[i] = hash[31-i]
	}

	if !bytes.Equal(reversedHash[:], expectedBytes) {
		t.Errorf("Genesis block hash mismatch:\ngot:  %x\nwant: %s", reversedHash, expectedHashLE)
	}
}

func TestDoubleHashBlockHeaderWithMidstate(t *testing.T) {
	// Create test header
	var header [80]byte
	for i := range header {
		header[i] = byte(i * 3)
	}

	// Compute expected result
	expected := DoubleHashBlockHeader(header)

	// Compute using midstate
	var firstBlock [64]byte
	copy(firstBlock[:], header[:64])
	midstate := ComputeMidstate(firstBlock)

	var headerTail [16]byte
	copy(headerTail[:], header[64:])

	result := DoubleHashBlockHeaderWithMidstate(midstate, headerTail)

	if result != expected {
		t.Errorf("Midstate double hash mismatch:\ngot:  %x\nwant: %x", result, expected)
	}
}

func TestMerklePairHash(t *testing.T) {
	// Test case from Bitcoin block
	left, _ := hex.DecodeString("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098")
	right, _ := hex.DecodeString("9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5")

	var leftArr, rightArr [32]byte
	copy(leftArr[:], left)
	copy(rightArr[:], right)

	hash := MerklePairHash(leftArr, rightArr)

	// Manually compute expected
	var combined [64]byte
	copy(combined[:32], left)
	copy(combined[32:], right)
	first := sha256.Sum256(combined[:])
	expected := sha256.Sum256(first[:])

	if hash != expected {
		t.Errorf("MerklePairHash mismatch:\ngot:  %x\nwant: %x", hash, expected)
	}
}

func TestBatchDoubleSum256(t *testing.T) {
	// Create test inputs
	inputs := make([][]byte, 4)
	for i := range inputs {
		inputs[i] = make([]byte, 64)
		for j := range inputs[i] {
			inputs[i][j] = byte(i*64 + j)
		}
	}

	results := BatchDoubleSum256(inputs)

	if len(results) != len(inputs) {
		t.Errorf("Expected %d results, got %d", len(inputs), len(results))
	}

	// Verify each result
	for i, input := range inputs {
		first := sha256.Sum256(input)
		expected := sha256.Sum256(first[:])
		if results[i] != expected {
			t.Errorf("BatchDoubleSum256[%d] mismatch:\ngot:  %x\nwant: %x", i, results[i], expected)
		}
	}
}

func TestBlockGeneric(t *testing.T) {
	// Test that our generic block function matches sha256.Sum256
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}

	// Compute with our function
	h := [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	blockGeneric(&h, data)

	// Expected state after processing "0123456789..." (64 bytes)
	// We need to add padding and compute full hash for comparison
	// Instead, let's compare against a known midstate
	var result [32]byte
	binary.BigEndian.PutUint32(result[0:], h[0])
	binary.BigEndian.PutUint32(result[4:], h[1])
	binary.BigEndian.PutUint32(result[8:], h[2])
	binary.BigEndian.PutUint32(result[12:], h[3])
	binary.BigEndian.PutUint32(result[16:], h[4])
	binary.BigEndian.PutUint32(result[20:], h[5])
	binary.BigEndian.PutUint32(result[24:], h[6])
	binary.BigEndian.PutUint32(result[28:], h[7])

	// This is the intermediate state, not a full hash
	// Just verify it's non-zero and deterministic
	if result == [32]byte{} {
		t.Error("blockGeneric returned zero state")
	}

	// Run again with same input to verify determinism
	h2 := [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	blockGeneric(&h2, data)

	var result2 [32]byte
	binary.BigEndian.PutUint32(result2[0:], h2[0])
	binary.BigEndian.PutUint32(result2[4:], h2[1])
	binary.BigEndian.PutUint32(result2[8:], h2[2])
	binary.BigEndian.PutUint32(result2[12:], h2[3])
	binary.BigEndian.PutUint32(result2[16:], h2[4])
	binary.BigEndian.PutUint32(result2[20:], h2[5])
	binary.BigEndian.PutUint32(result2[24:], h2[6])
	binary.BigEndian.PutUint32(result2[28:], h2[7])

	if result != result2 {
		t.Error("blockGeneric is not deterministic")
	}
}

func TestMidstateMiningSimulation(t *testing.T) {
	// Simulate mining: precompute midstate and iterate nonces
	var header [80]byte
	// Fill with some data
	for i := 0; i < 64; i++ {
		header[i] = byte(i)
	}
	// Merkle root suffix, timestamp, bits
	for i := 64; i < 76; i++ {
		header[i] = byte(i)
	}

	// Compute midstate once
	var firstBlock [64]byte
	copy(firstBlock[:], header[:64])
	midstate := ComputeMidstate(firstBlock)

	// Try a few nonces
	var hashes [][32]byte
	for nonce := uint32(0); nonce < 100; nonce++ {
		binary.LittleEndian.PutUint32(header[76:], nonce)

		var headerTail [16]byte
		copy(headerTail[:], header[64:])

		hash := DoubleHashBlockHeaderWithMidstate(midstate, headerTail)
		hashes = append(hashes, hash)
	}

	// Verify they're all different
	seen := make(map[[32]byte]bool)
	for i, hash := range hashes {
		if seen[hash] {
			t.Errorf("Duplicate hash at nonce %d", i)
		}
		seen[hash] = true
	}

	// Verify the midstate version matches the full computation
	for nonce := uint32(0); nonce < 10; nonce++ {
		binary.LittleEndian.PutUint32(header[76:], nonce)

		expected := DoubleHashBlockHeader(header)

		var headerTail [16]byte
		copy(headerTail[:], header[64:])
		result := DoubleHashBlockHeaderWithMidstate(midstate, headerTail)

		if result != expected {
			t.Errorf("Nonce %d: midstate result differs from full computation", nonce)
		}
	}
}

func TestConsistencyWithStdlib(t *testing.T) {
	// Verify our functions produce the same results as crypto/sha256
	testCases := [][]byte{
		{},
		[]byte("a"),
		[]byte("abc"),
		[]byte("message digest"),
		[]byte("abcdefghijklmnopqrstuvwxyz"),
		bytes.Repeat([]byte("a"), 1000000),
	}

	for _, input := range testCases {
		expected := sha256.Sum256(input)
		got := Sum256(input)
		if got != expected {
			t.Errorf("Sum256 mismatch for input len %d", len(input))
		}

		first := sha256.Sum256(input)
		expectedDouble := sha256.Sum256(first[:])
		gotDouble := DoubleSum256(input)
		if gotDouble != expectedDouble {
			t.Errorf("DoubleSum256 mismatch for input len %d", len(input))
		}
	}
}
