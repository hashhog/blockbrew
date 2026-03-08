package wallet

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/hashhog/blockbrew/internal/address"
	bbcrypto "github.com/hashhog/blockbrew/internal/crypto"
)

// BIP32 constants
const (
	// HardenedKeyStart is the index at which a hardened key starts.
	HardenedKeyStart = 0x80000000

	// MinSeedBytes is the minimum number of bytes allowed for a seed.
	MinSeedBytes = 16

	// MaxSeedBytes is the maximum number of bytes allowed for a seed.
	MaxSeedBytes = 64
)

// Extended key version bytes
const (
	// Mainnet
	MainnetPrivate = 0x0488ADE4 // xprv
	MainnetPublic  = 0x0488B21E // xpub

	// Testnet
	TestnetPrivate = 0x04358394 // tprv
	TestnetPublic  = 0x043587CF // tpub
)

// Errors
var (
	ErrInvalidSeedLength    = errors.New("invalid seed length")
	ErrDerivingHardenedPub  = errors.New("cannot derive hardened child from public key")
	ErrInvalidKeyData       = errors.New("invalid key data")
	ErrInvalidPath          = errors.New("invalid derivation path")
	ErrInvalidChildIndex    = errors.New("invalid child index")
	ErrNotPrivateKey        = errors.New("cannot derive private key from public key")
	ErrInvalidExtendedKey   = errors.New("invalid extended key format")
	ErrInvalidChecksum      = errors.New("invalid extended key checksum")
	ErrUnusableSeed         = errors.New("seed produces invalid master key")
)

// HDKey represents a BIP32 extended key.
type HDKey struct {
	Key       []byte   // 32-byte private key or 33-byte compressed public key
	ChainCode []byte   // 32-byte chain code
	Depth     byte     // 0x00 for master key
	ParentFP  [4]byte  // First 4 bytes of Hash160(parent pubkey)
	Index     uint32   // Child index
	IsPrivate bool     // Whether this is a private key
}

// NewMasterKey creates a master key from a seed (BIP32).
// Seed should be 16-64 bytes (typically 64 from BIP39).
func NewMasterKey(seed []byte) (*HDKey, error) {
	if len(seed) < MinSeedBytes || len(seed) > MaxSeedBytes {
		return nil, ErrInvalidSeedLength
	}

	// HMAC-SHA512 with key "Bitcoin seed"
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	sum := mac.Sum(nil)

	// Left 32 bytes = master private key
	// Right 32 bytes = master chain code
	secretKey := sum[:32]
	chainCode := sum[32:]

	// Verify the key is valid (not zero, not >= curve order)
	if !isValidSecretKey(secretKey) {
		return nil, ErrUnusableSeed
	}

	return &HDKey{
		Key:       secretKey,
		ChainCode: chainCode,
		Depth:     0,
		ParentFP:  [4]byte{},
		Index:     0,
		IsPrivate: true,
	}, nil
}

// isValidSecretKey checks if a 32-byte key is valid for secp256k1.
func isValidSecretKey(key []byte) bool {
	if len(key) != 32 {
		return false
	}

	// Check for zero
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}

	// Parse it to verify it's less than curve order
	privKey := secp256k1.PrivKeyFromBytes(key)
	return privKey != nil
}

// DeriveChild derives a child key at the given index.
// For hardened derivation, add HardenedKeyStart to the index.
func (k *HDKey) DeriveChild(index uint32) (*HDKey, error) {
	isHardened := index >= HardenedKeyStart

	// Cannot derive hardened child from public key
	if isHardened && !k.IsPrivate {
		return nil, ErrDerivingHardenedPub
	}

	var data []byte
	if isHardened {
		// Hardened child: 0x00 || private_key || index
		data = make([]byte, 37)
		data[0] = 0x00
		copy(data[1:33], k.Key)
		binary.BigEndian.PutUint32(data[33:], index)
	} else {
		// Normal child: public_key || index
		pubKey := k.publicKeyBytes()
		data = make([]byte, 37)
		copy(data[:33], pubKey)
		binary.BigEndian.PutUint32(data[33:], index)
	}

	// HMAC-SHA512
	mac := hmac.New(sha512.New, k.ChainCode)
	mac.Write(data)
	sum := mac.Sum(nil)

	il := sum[:32]
	ir := sum[32:]

	// Child chain code
	childChainCode := make([]byte, 32)
	copy(childChainCode, ir)

	// Parent fingerprint
	parentFP := k.Fingerprint()

	if k.IsPrivate {
		// Child private key = il + parent_private_key (mod n)
		childKey, err := addPrivateKeys(k.Key, il)
		if err != nil {
			return nil, err
		}

		return &HDKey{
			Key:       childKey,
			ChainCode: childChainCode,
			Depth:     k.Depth + 1,
			ParentFP:  parentFP,
			Index:     index,
			IsPrivate: true,
		}, nil
	}

	// Child public key = point(il) + parent_public_key
	childPubKey, err := addPublicKeys(k.Key, il)
	if err != nil {
		return nil, err
	}

	return &HDKey{
		Key:       childPubKey,
		ChainCode: childChainCode,
		Depth:     k.Depth + 1,
		ParentFP:  parentFP,
		Index:     index,
		IsPrivate: false,
	}, nil
}

// addPrivateKeys adds two private keys modulo the curve order.
func addPrivateKeys(key1, key2 []byte) ([]byte, error) {
	var k1, k2 secp256k1.ModNScalar
	k1.SetByteSlice(key1)
	k2.SetByteSlice(key2)

	k1.Add(&k2)

	// Check for zero result
	if k1.IsZero() {
		return nil, ErrInvalidKeyData
	}

	result := make([]byte, 32)
	k1.PutBytesUnchecked(result)
	return result, nil
}

// addPublicKeys adds a scalar to a public key (point multiplication and addition).
func addPublicKeys(pubKeyBytes, scalar []byte) ([]byte, error) {
	// Parse the parent public key
	pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	// Convert scalar to private key to get the point
	var scalarMod secp256k1.ModNScalar
	overflow := scalarMod.SetByteSlice(scalar)
	if overflow || scalarMod.IsZero() {
		return nil, ErrInvalidKeyData
	}

	// Compute scalar * G
	var result secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&scalarMod, &result)

	// Convert parent public key to Jacobian
	var parentPoint secp256k1.JacobianPoint
	pubKey.AsJacobian(&parentPoint)

	// Add the points
	secp256k1.AddNonConst(&parentPoint, &result, &result)

	// Convert back to affine
	result.ToAffine()

	// Check for point at infinity
	if result.X.IsZero() && result.Y.IsZero() {
		return nil, ErrInvalidKeyData
	}

	// Create public key from Jacobian point
	childPubKey := secp256k1.NewPublicKey(&result.X, &result.Y)
	return childPubKey.SerializeCompressed(), nil
}

// publicKeyBytes returns the compressed public key bytes.
func (k *HDKey) publicKeyBytes() []byte {
	if !k.IsPrivate {
		return k.Key
	}
	// Derive public key from private key
	privKey := secp256k1.PrivKeyFromBytes(k.Key)
	return privKey.PubKey().SerializeCompressed()
}

// DerivePath derives a key from a path string like "m/84'/0'/0'/0/5".
func (k *HDKey) DerivePath(path string) (*HDKey, error) {
	// Parse the path
	if !strings.HasPrefix(path, "m") && !strings.HasPrefix(path, "M") {
		return nil, ErrInvalidPath
	}

	// Handle root path
	if path == "m" || path == "M" {
		return k, nil
	}

	// Remove the "m/" prefix
	path = strings.TrimPrefix(path, "m/")
	path = strings.TrimPrefix(path, "M/")

	segments := strings.Split(path, "/")
	result := k

	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}

		var index uint32
		isHardened := false

		// Check for hardened marker
		if strings.HasSuffix(segment, "'") || strings.HasSuffix(segment, "h") || strings.HasSuffix(segment, "H") {
			isHardened = true
			segment = segment[:len(segment)-1]
		}

		// Parse the index
		n, err := strconv.ParseUint(segment, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid index %q", ErrInvalidPath, segment)
		}
		index = uint32(n)

		if isHardened {
			index += HardenedKeyStart
		}

		result, err = result.DeriveChild(index)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// PublicKey returns the public key version of this extended key.
func (k *HDKey) PublicKey() *HDKey {
	if !k.IsPrivate {
		return k
	}

	return &HDKey{
		Key:       k.publicKeyBytes(),
		ChainCode: k.ChainCode,
		Depth:     k.Depth,
		ParentFP:  k.ParentFP,
		Index:     k.Index,
		IsPrivate: false,
	}
}

// ECPrivKey returns the secp256k1 private key.
func (k *HDKey) ECPrivKey() (*bbcrypto.PrivateKey, error) {
	if !k.IsPrivate {
		return nil, ErrNotPrivateKey
	}
	return bbcrypto.PrivateKeyFromBytes(k.Key), nil
}

// ECPubKey returns the secp256k1 public key.
func (k *HDKey) ECPubKey() (*bbcrypto.PublicKey, error) {
	pubKeyBytes := k.publicKeyBytes()
	return bbcrypto.PublicKeyFromBytes(pubKeyBytes)
}

// Fingerprint returns the first 4 bytes of Hash160(serialized public key).
func (k *HDKey) Fingerprint() [4]byte {
	pubKeyBytes := k.publicKeyBytes()
	hash := bbcrypto.Hash160(pubKeyBytes)
	var fp [4]byte
	copy(fp[:], hash[:4])
	return fp
}

// Serialize returns the Base58Check-encoded extended key (xprv/xpub).
func (k *HDKey) Serialize(net address.Network) string {
	var version uint32

	switch net {
	case address.Mainnet:
		if k.IsPrivate {
			version = MainnetPrivate
		} else {
			version = MainnetPublic
		}
	default:
		// Testnet, Regtest, Signet
		if k.IsPrivate {
			version = TestnetPrivate
		} else {
			version = TestnetPublic
		}
	}

	return k.serializeWithVersion(version)
}

func (k *HDKey) serializeWithVersion(version uint32) string {
	// 78 bytes before Base58Check
	data := make([]byte, 78)

	// 4 bytes: version
	binary.BigEndian.PutUint32(data[0:4], version)

	// 1 byte: depth
	data[4] = k.Depth

	// 4 bytes: parent fingerprint
	copy(data[5:9], k.ParentFP[:])

	// 4 bytes: child index (big-endian)
	binary.BigEndian.PutUint32(data[9:13], k.Index)

	// 32 bytes: chain code
	copy(data[13:45], k.ChainCode)

	// 33 bytes: key
	if k.IsPrivate {
		// 0x00 + 32-byte private key
		data[45] = 0x00
		copy(data[46:78], k.Key)
	} else {
		// 33-byte compressed public key
		copy(data[45:78], k.Key)
	}

	return address.Base58CheckEncode(data[0], data[1:])
}

// ParseExtendedKey parses a Base58Check-encoded extended key.
func ParseExtendedKey(s string) (*HDKey, error) {
	// Decode Base58Check
	version, payload, err := address.Base58CheckDecode(s)
	if err != nil {
		return nil, ErrInvalidExtendedKey
	}

	// Reconstruct the full 78-byte data
	data := make([]byte, 78)
	data[0] = version
	copy(data[1:], payload)

	if len(data) != 78 {
		return nil, ErrInvalidExtendedKey
	}

	// Parse version
	ver := binary.BigEndian.Uint32(data[0:4])
	var isPrivate bool
	switch ver {
	case MainnetPrivate, TestnetPrivate:
		isPrivate = true
	case MainnetPublic, TestnetPublic:
		isPrivate = false
	default:
		return nil, ErrInvalidExtendedKey
	}

	// Parse depth
	depth := data[4]

	// Parse parent fingerprint
	var parentFP [4]byte
	copy(parentFP[:], data[5:9])

	// Parse child index
	index := binary.BigEndian.Uint32(data[9:13])

	// Parse chain code
	chainCode := make([]byte, 32)
	copy(chainCode, data[13:45])

	// Parse key
	var key []byte
	if isPrivate {
		// Should have 0x00 prefix
		if data[45] != 0x00 {
			return nil, ErrInvalidExtendedKey
		}
		key = make([]byte, 32)
		copy(key, data[46:78])
	} else {
		key = make([]byte, 33)
		copy(key, data[45:78])
	}

	return &HDKey{
		Key:       key,
		ChainCode: chainCode,
		Depth:     depth,
		ParentFP:  parentFP,
		Index:     index,
		IsPrivate: isPrivate,
	}, nil
}

// String returns a human-readable representation of the extended key.
func (k *HDKey) String() string {
	return k.Serialize(address.Mainnet)
}

// BIP84Path returns the BIP84 derivation path for native segwit addresses.
// Format: m/84'/coin'/account'/change/index
func BIP84Path(coinType, account, change, index uint32) string {
	return fmt.Sprintf("m/84'/%d'/%d'/%d/%d", coinType, account, change, index)
}

// BIP44Path returns the BIP44 derivation path.
// Format: m/44'/coin'/account'/change/index
func BIP44Path(coinType, account, change, index uint32) string {
	return fmt.Sprintf("m/44'/%d'/%d'/%d/%d", coinType, account, change, index)
}
