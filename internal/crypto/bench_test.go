package crypto

import (
	"encoding/binary"
	"testing"
)

func BenchmarkDoubleSHA256(b *testing.B) {
	// Test with 80-byte input (block header size)
	data := make([]byte, 80)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DoubleSHA256(data)
	}
}

func BenchmarkDoubleSHA256_32(b *testing.B) {
	// Test with 32-byte input (transaction hash)
	data := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DoubleSHA256(data)
	}
}

func BenchmarkDoubleSHA256_1KB(b *testing.B) {
	// Test with 1KB input
	data := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DoubleSHA256(data)
	}
}

func BenchmarkHash160(b *testing.B) {
	// Test with 33-byte input (compressed public key)
	data := make([]byte, 33)
	data[0] = 0x02
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash160(data)
	}
}

func BenchmarkSHA256Hash(b *testing.B) {
	data := make([]byte, 80)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SHA256Hash(data)
	}
}

// SHA256-specific benchmarks

func BenchmarkSum256_80(b *testing.B) {
	// 80-byte block header
	data := make([]byte, 80)
	for i := range data {
		data[i] = byte(i)
	}
	b.SetBytes(80)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum256(data)
	}
}

func BenchmarkSum256_64(b *testing.B) {
	// 64-byte merkle pair
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}
	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum256(data)
	}
}

func BenchmarkDoubleSum256_80(b *testing.B) {
	// 80-byte block header (standard Bitcoin hash)
	data := make([]byte, 80)
	for i := range data {
		data[i] = byte(i)
	}
	b.SetBytes(80)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DoubleSum256(data)
	}
}

func BenchmarkDoubleSum256_64(b *testing.B) {
	// 64-byte merkle pair
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}
	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DoubleSum256(data)
	}
}

func BenchmarkDoubleHashBlockHeader(b *testing.B) {
	var header [80]byte
	for i := range header {
		header[i] = byte(i)
	}
	b.SetBytes(80)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DoubleHashBlockHeader(header)
	}
}

func BenchmarkMidstateComputation(b *testing.B) {
	var block [64]byte
	for i := range block {
		block[i] = byte(i)
	}
	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeMidstate(block)
	}
}

func BenchmarkMidstateFinishHash(b *testing.B) {
	var block [64]byte
	for i := range block {
		block[i] = byte(i)
	}
	midstate := ComputeMidstate(block)

	var tail [16]byte
	for i := range tail {
		tail[i] = byte(i + 64)
	}

	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		midstate.FinishHash(tail)
	}
}

func BenchmarkMiningWithMidstate(b *testing.B) {
	// Simulates mining: precompute midstate and iterate nonces
	// Note: midstate uses our pure-Go blockGeneric, which is slower than
	// Go's hardware-accelerated crypto/sha256. The benefit of midstate
	// is when iterating many nonces, the first 64 bytes don't need rehashing.
	// For a fair comparison, see BenchmarkMiningAmortized.
	var header [80]byte
	for i := 0; i < 64; i++ {
		header[i] = byte(i)
	}
	for i := 64; i < 76; i++ {
		header[i] = byte(i)
	}

	var firstBlock [64]byte
	copy(firstBlock[:], header[:64])
	midstate := ComputeMidstate(firstBlock)

	b.SetBytes(80)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint32(header[76:], uint32(i))
		var tail [16]byte
		copy(tail[:], header[64:])
		DoubleHashBlockHeaderWithMidstate(midstate, tail)
	}
}

func BenchmarkMiningAmortized(b *testing.B) {
	// Realistic mining scenario: compute midstate once, iterate 1000 nonces
	// This amortizes the midstate cost over many hash operations
	var header [80]byte
	for i := 0; i < 64; i++ {
		header[i] = byte(i)
	}
	for i := 64; i < 76; i++ {
		header[i] = byte(i)
	}

	iterations := 1000
	b.SetBytes(int64(80 * iterations))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Compute midstate once per "block template"
		var firstBlock [64]byte
		copy(firstBlock[:], header[:64])
		midstate := ComputeMidstate(firstBlock)

		// Iterate nonces
		for nonce := uint32(0); nonce < uint32(iterations); nonce++ {
			binary.LittleEndian.PutUint32(header[76:], nonce)
			var tail [16]byte
			copy(tail[:], header[64:])
			DoubleHashBlockHeaderWithMidstate(midstate, tail)
		}
	}
}

func BenchmarkMiningWithoutMidstate(b *testing.B) {
	// Baseline: full hash computation each iteration
	var header [80]byte
	for i := range header {
		header[i] = byte(i)
	}

	b.SetBytes(80)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint32(header[76:], uint32(i))
		DoubleHashBlockHeader(header)
	}
}

func BenchmarkMerklePairHash(b *testing.B) {
	var left, right [32]byte
	for i := range left {
		left[i] = byte(i)
		right[i] = byte(i + 32)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MerklePairHash(left, right)
	}
}

func BenchmarkBatchDoubleSum256_8(b *testing.B) {
	// 8 merkle pairs (typical small transaction block)
	inputs := make([][]byte, 8)
	for i := range inputs {
		inputs[i] = make([]byte, 64)
		for j := range inputs[i] {
			inputs[i][j] = byte(i*64 + j)
		}
	}

	b.SetBytes(64 * 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BatchDoubleSum256(inputs)
	}
}

func BenchmarkBatchDoubleSum256_1024(b *testing.B) {
	// 1024 merkle pairs (large block)
	inputs := make([][]byte, 1024)
	for i := range inputs {
		inputs[i] = make([]byte, 64)
		for j := range inputs[i] {
			inputs[i][j] = byte((i*64 + j) & 0xff)
		}
	}

	b.SetBytes(64 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BatchDoubleSum256(inputs)
	}
}

func BenchmarkGeneratePrivateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GeneratePrivateKey()
	}
}

func BenchmarkECDSASign(b *testing.B) {
	key, _ := GeneratePrivateKey()
	hash := DoubleSHA256([]byte("benchmark message for signing"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignECDSA(key, hash)
	}
}

func BenchmarkECDSAVerify(b *testing.B) {
	key, _ := GeneratePrivateKey()
	hash := DoubleSHA256([]byte("benchmark message for verification"))
	sig, _ := SignECDSA(key, hash)
	pub := key.PubKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyECDSA(pub, hash, sig)
	}
}

func BenchmarkSchnorrSign(b *testing.B) {
	key, _ := GeneratePrivateKey()
	hash := DoubleSHA256([]byte("benchmark message for schnorr signing"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignSchnorr(key, hash)
	}
}

func BenchmarkSchnorrVerify(b *testing.B) {
	key, _ := GeneratePrivateKey()
	hash := DoubleSHA256([]byte("benchmark message for schnorr verification"))
	sig, _ := SignSchnorr(key, hash)
	pub := key.PubKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifySchnorrWithPubKey(pub, hash, sig)
	}
}

func BenchmarkPublicKeySerializeCompressed(b *testing.B) {
	key, _ := GeneratePrivateKey()
	pub := key.PubKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pub.SerializeCompressed()
	}
}

func BenchmarkPublicKeySerializeUncompressed(b *testing.B) {
	key, _ := GeneratePrivateKey()
	pub := key.PubKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pub.SerializeUncompressed()
	}
}

func BenchmarkPublicKeyFromBytes(b *testing.B) {
	key, _ := GeneratePrivateKey()
	pub := key.PubKey()
	data := pub.SerializeCompressed()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = PublicKeyFromBytes(data)
	}
}

func BenchmarkXOnlyPubKey(b *testing.B) {
	key, _ := GeneratePrivateKey()
	pub := key.PubKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pub.XOnlyPubKey()
	}
}
