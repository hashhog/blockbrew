package crypto

import (
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
