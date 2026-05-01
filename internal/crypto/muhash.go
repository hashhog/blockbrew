// Package crypto / muhash.go: MuHash3072 set hash + Num3072 modular arithmetic.
//
// MuHash is a multiset homomorphic hash function. It supports adding (Insert)
// and removing (Remove) elements in any order, and the resulting digest is
// independent of insertion order. This makes it the natural primitive for
// computing a hash over the UTXO set: the running value can be updated as
// blocks connect/disconnect without rehashing every coin every time.
//
// Spec: bitcoin-core/src/crypto/muhash.{h,cpp}.
//
// Construction:
//   - Num3072 is an unsigned integer mod p where p = 2^3072 - 1103717
//     (the largest 3072-bit safe prime).
//   - Each input is mapped to a Num3072 by:
//         seed = SHA256(input)                            (32 bytes)
//         out  = ChaCha20(key=seed, nonce=0, counter=0)   (384 bytes keystream)
//         num  = LE-decode(out) interpreted as a 3072-bit unsigned integer.
//   - Insert multiplies num into the numerator; Remove multiplies into
//     denominator.
//   - Finalize:
//         result = numerator * inverse(denominator) mod p, serialized LE 384B,
//         out    = SHA256(result)                          (single SHA256).
//     (Note: this is *not* SHA256d — Core's MuHash3072::Finalize uses
//     HashWriter::GetSHA256(), the single-SHA256 path. See muhash.cpp:560.)
//
// Performance is not a hot path here — MuHash is invoked once per UTXO snapshot
// dump/load (and incrementally on every block connect, but that path is lockstep
// with disk I/O). Correctness wins over micro-optimization, so we use
// math/big for the 3072-bit modular arithmetic.

package crypto

import (
	"crypto/sha256"
	"math/big"

	"golang.org/x/crypto/chacha20"
)

// Num3072ByteSize is the canonical Num3072 serialization length: 3072 bits = 384 bytes.
const Num3072ByteSize = 384

// muhashPrime is the modulus 2^3072 - 1103717 used by MuHash3072.
// Computed once at package init.
var muhashPrime *big.Int

// muhashOne is the multiplicative identity (1).
var muhashOne *big.Int

func init() {
	// p = 2^3072 - 1103717
	one := big.NewInt(1)
	p := new(big.Int).Lsh(one, 3072)
	p.Sub(p, big.NewInt(1103717))
	muhashPrime = p
	muhashOne = big.NewInt(1)
}

// Num3072 is a 3072-bit unsigned integer represented in little-endian byte form.
// The zero value is the integer 0; callers that need 1 should use Num3072One().
type Num3072 [Num3072ByteSize]byte

// Num3072One returns the multiplicative identity (1) in Num3072 form.
func Num3072One() Num3072 {
	var n Num3072
	n[0] = 1
	return n
}

// toBig converts the little-endian Num3072 to a big.Int.
func (n *Num3072) toBig() *big.Int {
	// Reverse bytes: math/big.SetBytes consumes big-endian.
	var be [Num3072ByteSize]byte
	for i := 0; i < Num3072ByteSize; i++ {
		be[i] = n[Num3072ByteSize-1-i]
	}
	return new(big.Int).SetBytes(be[:])
}

// fromBig fills n from a big.Int, mod p, in little-endian.
// The input MUST be in [0, p) for the canonical encoding to be unique.
func (n *Num3072) fromBig(x *big.Int) {
	// Reduce defensively — callers should already have done this.
	r := new(big.Int).Mod(x, muhashPrime)
	be := r.Bytes() // big-endian, no leading zeros
	// Zero-pad to 384 bytes and reverse to little-endian.
	*n = Num3072{}
	for i, b := range be {
		// be[i] is the (len-1-i)-th most-significant byte.
		// LE position = (len-1-i).
		lePos := len(be) - 1 - i
		n[lePos] = b
	}
}

// MuHash3072 is a homomorphic multiset hash with insert and remove.
//
// The accumulator is represented as a fraction (numerator / denominator) so
// that Insert and Remove are both single multiplications, with the (expensive)
// modular inverse deferred to Finalize.
type MuHash3072 struct {
	numerator   *big.Int
	denominator *big.Int
}

// NewMuHash3072 returns the empty-set accumulator (numerator=1, denominator=1).
func NewMuHash3072() *MuHash3072 {
	return &MuHash3072{
		numerator:   new(big.Int).Set(muhashOne),
		denominator: new(big.Int).Set(muhashOne),
	}
}

// dataToNum maps an arbitrary-length byte slice to a Num3072 via SHA256 ->
// ChaCha20 expansion. This is MuHash3072::ToNum3072 in muhash.cpp:536.
func dataToNum(in []byte) *big.Int {
	// 1. SHA256 the input to get a 32-byte ChaCha20 key.
	seed := sha256.Sum256(in)

	// 2. ChaCha20 keystream of 384 bytes (Core uses ChaCha20Aligned with the
	//    SHA256 hash as both key and nonce in IETF construction; see
	//    crypto/chacha20.cpp::ChaCha20Aligned. The IETF nonce is 12 bytes;
	//    Core's ChaCha20Aligned takes only a 32-byte key and uses a zero
	//    nonce / zero counter implicitly.).
	//
	// Cross-check: muhash.cpp:541 calls
	//     ChaCha20Aligned{MakeByteSpan(hashed_in)}.Keystream(...)
	// where ChaCha20Aligned's constructor takes a 32-byte key only, with the
	// 96-bit nonce defaulting to zero and the block counter defaulting to 0.
	// So we instantiate a stock IETF ChaCha20 with nonce=0^12 and key=seed,
	// and read 384 zero-bytes through it.
	var nonce [12]byte
	cipher, err := chacha20.NewUnauthenticatedCipher(seed[:], nonce[:])
	if err != nil {
		// Should be unreachable: NewUnauthenticatedCipher only fails on
		// wrong key/nonce length, which we control.
		panic(err)
	}
	keystream := make([]byte, Num3072ByteSize)
	cipher.XORKeyStream(keystream, keystream)

	// 3. Interpret the 384 bytes as a little-endian 3072-bit integer.
	var le [Num3072ByteSize]byte
	copy(le[:], keystream)
	// Convert to big-endian for SetBytes.
	var be [Num3072ByteSize]byte
	for i := 0; i < Num3072ByteSize; i++ {
		be[i] = le[Num3072ByteSize-1-i]
	}
	x := new(big.Int).SetBytes(be[:])

	// 4. Reduce mod p. The expanded number CAN exceed p (range is
	//    [0, 2^3072) and p = 2^3072 - 1103717), so this matters for
	//    correctness. Core does this lazily inside Multiply via the
	//    overflow / FullReduce dance; math/big.Mod just normalizes it
	//    immediately.
	x.Mod(x, muhashPrime)
	return x
}

// Insert multiplies the input's Num3072 image into the numerator.
// Returns the receiver for chaining.
func (m *MuHash3072) Insert(in []byte) *MuHash3072 {
	x := dataToNum(in)
	m.numerator.Mul(m.numerator, x)
	m.numerator.Mod(m.numerator, muhashPrime)
	return m
}

// Remove multiplies the input's Num3072 image into the denominator.
// Returns the receiver for chaining.
func (m *MuHash3072) Remove(in []byte) *MuHash3072 {
	x := dataToNum(in)
	m.denominator.Mul(m.denominator, x)
	m.denominator.Mod(m.denominator, muhashPrime)
	return m
}

// Finalize returns the 32-byte SHA256 of the canonical 384-byte little-endian
// serialization of (numerator / denominator) mod p.
//
// Calling Finalize does NOT consume the receiver; subsequent Insert/Remove
// calls continue from the same accumulator state.
func (m *MuHash3072) Finalize() [32]byte {
	// combined = numerator * inverse(denominator) mod p
	denomInv := new(big.Int).ModInverse(m.denominator, muhashPrime)
	if denomInv == nil {
		// Mathematically impossible: every nonzero residue mod a prime is
		// invertible, and our representation only ever multiplies in
		// nonzero residues (dataToNum's ChaCha20 keystream is nonzero
		// w.h.p., and 0 mod p is impossible from a 3072-bit-bounded LE
		// stream of fresh random bytes). Treat as a programming error.
		panic("muhash: denominator is zero mod p (unreachable)")
	}
	combined := new(big.Int).Mul(m.numerator, denomInv)
	combined.Mod(combined, muhashPrime)

	var canonical Num3072
	canonical.fromBig(combined)

	// Single SHA256 over the 384-byte canonical form. Note: muhash.cpp:560
	// uses HashWriter::GetSHA256() (single SHA256), NOT GetHash() (SHA256d).
	return sha256.Sum256(canonical[:])
}

// MuHashSerialize serializes the accumulator as numerator || denominator,
// each in 384-byte little-endian form (matching Core's SERIALIZE_METHODS).
// Returned slice has length 2*Num3072ByteSize = 768 bytes.
func (m *MuHash3072) MuHashSerialize() []byte {
	out := make([]byte, 2*Num3072ByteSize)
	var n Num3072
	n.fromBig(m.numerator)
	copy(out[:Num3072ByteSize], n[:])
	n.fromBig(m.denominator)
	copy(out[Num3072ByteSize:], n[:])
	return out
}

// MuHashDeserialize loads an accumulator from a 768-byte numerator||denominator
// blob.
func MuHashDeserialize(data []byte) (*MuHash3072, error) {
	if len(data) != 2*Num3072ByteSize {
		return nil, errMuHashSerSize
	}
	var n Num3072
	copy(n[:], data[:Num3072ByteSize])
	num := n.toBig()
	num.Mod(num, muhashPrime)
	copy(n[:], data[Num3072ByteSize:])
	den := n.toBig()
	den.Mod(den, muhashPrime)
	return &MuHash3072{numerator: num, denominator: den}, nil
}

// muhashSerSizeError sentinel.
var errMuHashSerSize = &muhashErr{msg: "muhash: serialized form must be 768 bytes"}

type muhashErr struct{ msg string }

func (e *muhashErr) Error() string { return e.msg }

// Combine multiplies another accumulator into this one (set union).
//
// (a*b) for the numerators, (c*d) for the denominators — equivalent to
// Core's operator*=.
func (m *MuHash3072) Combine(other *MuHash3072) *MuHash3072 {
	m.numerator.Mul(m.numerator, other.numerator)
	m.numerator.Mod(m.numerator, muhashPrime)
	m.denominator.Mul(m.denominator, other.denominator)
	m.denominator.Mod(m.denominator, muhashPrime)
	return m
}

// Difference divides another accumulator into this one (set difference).
//
// Equivalent to Core's operator/=: numerator gets multiplied by the other
// denominator, denominator by the other numerator.
func (m *MuHash3072) Difference(other *MuHash3072) *MuHash3072 {
	m.numerator.Mul(m.numerator, other.denominator)
	m.numerator.Mod(m.numerator, muhashPrime)
	m.denominator.Mul(m.denominator, other.numerator)
	m.denominator.Mod(m.denominator, muhashPrime)
	return m
}

// MuHashFromInt builds a singleton MuHash3072 from a 32-byte buffer whose first
// byte is `i` and the rest are zero — matching the FromInt helper in Core's
// crypto_tests.cpp test suite.
func MuHashFromInt(i byte) *MuHash3072 {
	var tmp [32]byte
	tmp[0] = i
	m := NewMuHash3072()
	m.Insert(tmp[:])
	return m
}

