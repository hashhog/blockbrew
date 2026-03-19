// Package wallet implements key management and transaction signing.
package wallet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/hashhog/blockbrew/internal/address"
	bbcrypto "github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/script"
)

// Descriptor errors
var (
	ErrInvalidDescriptor        = errors.New("invalid descriptor")
	ErrInvalidDescriptorChecksum = errors.New("invalid descriptor checksum")
	ErrInvalidKey               = errors.New("invalid key in descriptor")
	ErrInvalidDerivationPath    = errors.New("invalid derivation path")
	ErrDescriptorNotRanged      = errors.New("descriptor is not ranged")
	ErrUnsupportedDescriptor    = errors.New("unsupported descriptor type")
	ErrInvalidMultisigThreshold = errors.New("invalid multisig threshold")
	ErrPrivateKeyNotAvailable   = errors.New("private key not available")
)

// DescriptorType represents the type of output descriptor.
type DescriptorType int

const (
	DescPK         DescriptorType = iota // pk(KEY)
	DescPKH                              // pkh(KEY)
	DescWPKH                             // wpkh(KEY)
	DescWSH                              // wsh(SCRIPT)
	DescSH                               // sh(SCRIPT)
	DescMulti                            // multi(k, KEY...)
	DescSortedMulti                      // sortedmulti(k, KEY...)
	DescTR                               // tr(KEY) or tr(KEY, TREE)
	DescCombo                            // combo(KEY)
	DescRaw                              // raw(HEX)
	DescAddr                             // addr(ADDRESS)
	DescMiniscript                       // wsh(MINISCRIPT) or tr(KEY, MINISCRIPT)
)

// String returns the function name for the descriptor type.
func (t DescriptorType) String() string {
	switch t {
	case DescPK:
		return "pk"
	case DescPKH:
		return "pkh"
	case DescWPKH:
		return "wpkh"
	case DescWSH:
		return "wsh"
	case DescSH:
		return "sh"
	case DescMulti:
		return "multi"
	case DescSortedMulti:
		return "sortedmulti"
	case DescTR:
		return "tr"
	case DescCombo:
		return "combo"
	case DescRaw:
		return "raw"
	case DescAddr:
		return "addr"
	default:
		return "unknown"
	}
}

// DescriptorChecksum computes the checksum for a descriptor string.
// The checksum is an 8-character string using the character set qpzry9x8gf2tvdw0s3jn54khce6mua7l.
func DescriptorChecksum(desc string) string {
	// Character set for input
	const inputCharset = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ABCDEFGHijklmnopqrstuvwxyz "
	// Character set for checksum output
	const checksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

	// Build charset position map
	charPos := make(map[rune]int)
	for i, c := range inputCharset {
		charPos[c] = i
	}

	// Polynomial modulo operations
	polyMod := func(c uint64, val int) uint64 {
		c0 := c >> 35
		c = ((c & 0x7ffffffff) << 5) ^ uint64(val)
		if (c0 & 1) != 0 {
			c ^= 0xf5dee51989
		}
		if (c0 & 2) != 0 {
			c ^= 0xa9fdca3312
		}
		if (c0 & 4) != 0 {
			c ^= 0x1bab10e32d
		}
		if (c0 & 8) != 0 {
			c ^= 0x3706b1677a
		}
		if (c0 & 16) != 0 {
			c ^= 0x644d626ffd
		}
		return c
	}

	c := uint64(1)
	cls := 0
	clsCount := 0

	for _, ch := range desc {
		pos, ok := charPos[ch]
		if !ok {
			return "" // Invalid character
		}

		// Accumulate character groups
		c = polyMod(c, pos&31)
		cls = cls*3 + (pos >> 5)
		clsCount++

		if clsCount == 3 {
			c = polyMod(c, cls)
			cls = 0
			clsCount = 0
		}
	}

	// Finalize remaining characters
	if clsCount > 0 {
		c = polyMod(c, cls)
	}

	// Add 8 zero groups
	for i := 0; i < 8; i++ {
		c = polyMod(c, 0)
	}

	// XOR with final constant
	c ^= 1

	// Generate checksum characters
	result := make([]byte, 8)
	for i := 0; i < 8; i++ {
		result[i] = checksumCharset[(c>>(5*(7-i)))&31]
	}

	return string(result)
}

// ValidateDescriptorChecksum validates that a descriptor has a correct checksum.
// Returns the descriptor without checksum and true if valid, or empty and false if invalid.
func ValidateDescriptorChecksum(desc string) (string, bool) {
	idx := strings.LastIndex(desc, "#")
	if idx == -1 {
		// No checksum - descriptor might be valid without one
		return desc, true
	}

	body := desc[:idx]
	checksum := desc[idx+1:]

	if len(checksum) != 8 {
		return "", false
	}

	expected := DescriptorChecksum(body)
	if checksum != expected {
		return "", false
	}

	return body, true
}

// AddChecksum adds a checksum to a descriptor string.
func AddChecksum(desc string) string {
	// Remove existing checksum if present
	if idx := strings.LastIndex(desc, "#"); idx != -1 {
		desc = desc[:idx]
	}
	return desc + "#" + DescriptorChecksum(desc)
}

// PubkeyProvider generates public keys for descriptor expansion.
type PubkeyProvider interface {
	// GetPubKey derives the public key at the given position.
	// pos is used for ranged descriptors (with * wildcard).
	GetPubKey(pos uint32) (*bbcrypto.PublicKey, error)

	// GetPrivKey returns the private key if available.
	GetPrivKey(pos uint32) (*bbcrypto.PrivateKey, error)

	// IsRange returns true if this provider generates multiple keys.
	IsRange() bool

	// IsPrivate returns true if private key information is available.
	IsPrivate() bool

	// String returns the key expression as a string.
	String() string

	// PrivateString returns the key expression with private key (if available).
	PrivateString() string
}

// ConstPubkeyProvider provides a single static public key.
type ConstPubkeyProvider struct {
	PubKey  *bbcrypto.PublicKey
	PrivKey *bbcrypto.PrivateKey // Optional
	HexStr  string               // Original hex string
}

func (p *ConstPubkeyProvider) GetPubKey(pos uint32) (*bbcrypto.PublicKey, error) {
	return p.PubKey, nil
}

func (p *ConstPubkeyProvider) GetPrivKey(pos uint32) (*bbcrypto.PrivateKey, error) {
	if p.PrivKey == nil {
		return nil, ErrPrivateKeyNotAvailable
	}
	return p.PrivKey, nil
}

func (p *ConstPubkeyProvider) IsRange() bool {
	return false
}

func (p *ConstPubkeyProvider) IsPrivate() bool {
	return p.PrivKey != nil
}

func (p *ConstPubkeyProvider) String() string {
	return p.HexStr
}

func (p *ConstPubkeyProvider) PrivateString() string {
	if p.PrivKey != nil {
		// TODO: Return WIF-encoded private key
		return hex.EncodeToString(p.PrivKey.Serialize())
	}
	return p.HexStr
}

// XPubPubkeyProvider provides keys derived from an extended public/private key.
type XPubPubkeyProvider struct {
	ExtKey     *HDKey
	Path       []uint32 // Derivation path after the xpub
	Wildcard   bool     // True if path contains *
	WildcardH  bool     // True if wildcard is hardened (*')
	OriginInfo *KeyOriginInfo
	XPubStr    string // Original xpub/xprv string
}

// KeyOriginInfo stores BIP32 fingerprint and derivation path for key origin.
type KeyOriginInfo struct {
	Fingerprint [4]byte
	Path        []uint32
}

func (p *XPubPubkeyProvider) GetPubKey(pos uint32) (*bbcrypto.PublicKey, error) {
	key := p.ExtKey

	// Derive through the path
	for _, idx := range p.Path {
		var err error
		key, err = key.DeriveChild(idx)
		if err != nil {
			return nil, err
		}
	}

	// If there's a wildcard, derive the final index
	if p.Wildcard {
		idx := pos
		if p.WildcardH {
			idx += HardenedKeyStart
		}
		var err error
		key, err = key.DeriveChild(idx)
		if err != nil {
			return nil, err
		}
	}

	return key.ECPubKey()
}

func (p *XPubPubkeyProvider) GetPrivKey(pos uint32) (*bbcrypto.PrivateKey, error) {
	if !p.ExtKey.IsPrivate {
		return nil, ErrPrivateKeyNotAvailable
	}

	key := p.ExtKey

	// Derive through the path
	for _, idx := range p.Path {
		var err error
		key, err = key.DeriveChild(idx)
		if err != nil {
			return nil, err
		}
	}

	// If there's a wildcard, derive the final index
	if p.Wildcard {
		idx := pos
		if p.WildcardH {
			idx += HardenedKeyStart
		}
		var err error
		key, err = key.DeriveChild(idx)
		if err != nil {
			return nil, err
		}
	}

	return key.ECPrivKey()
}

func (p *XPubPubkeyProvider) IsRange() bool {
	return p.Wildcard
}

func (p *XPubPubkeyProvider) IsPrivate() bool {
	return p.ExtKey.IsPrivate
}

func (p *XPubPubkeyProvider) String() string {
	return p.formatKeyExpr(false)
}

func (p *XPubPubkeyProvider) PrivateString() string {
	return p.formatKeyExpr(true)
}

func (p *XPubPubkeyProvider) formatKeyExpr(includePrivate bool) string {
	var sb strings.Builder

	// Add origin info if present
	if p.OriginInfo != nil {
		sb.WriteString("[")
		sb.WriteString(hex.EncodeToString(p.OriginInfo.Fingerprint[:]))
		for _, idx := range p.OriginInfo.Path {
			sb.WriteString("/")
			if idx >= HardenedKeyStart {
				sb.WriteString(strconv.FormatUint(uint64(idx-HardenedKeyStart), 10))
				sb.WriteString("'")
			} else {
				sb.WriteString(strconv.FormatUint(uint64(idx), 10))
			}
		}
		sb.WriteString("]")
	}

	// Add the xpub/xprv
	if includePrivate && p.ExtKey.IsPrivate {
		sb.WriteString(p.ExtKey.Serialize(address.Mainnet))
	} else {
		sb.WriteString(p.ExtKey.PublicKey().Serialize(address.Mainnet))
	}

	// Add derivation path
	for _, idx := range p.Path {
		sb.WriteString("/")
		if idx >= HardenedKeyStart {
			sb.WriteString(strconv.FormatUint(uint64(idx-HardenedKeyStart), 10))
			sb.WriteString("'")
		} else {
			sb.WriteString(strconv.FormatUint(uint64(idx), 10))
		}
	}

	// Add wildcard
	if p.Wildcard {
		sb.WriteString("/*")
		if p.WildcardH {
			sb.WriteString("'")
		}
	}

	return sb.String()
}

// Descriptor represents a parsed output descriptor.
type Descriptor struct {
	Type        DescriptorType
	Keys        []PubkeyProvider   // Key arguments
	Subdesc     *Descriptor        // Sub-descriptor for sh(), wsh()
	Threshold   int                // For multi/sortedmulti
	Network     address.Network    // Network for address generation
	RawScript   []byte             // For raw() descriptor
	AddrStr     string             // For addr() descriptor
	TapTree     *TapTreeDescriptor // For tr() script tree
	Miniscript  *script.MiniscriptNode // For miniscript descriptors
	MiniscriptStr string            // Original miniscript string
}

// TapTreeDescriptor represents a taproot script tree.
type TapTreeDescriptor struct {
	Left    *TapTreeDescriptor
	Right   *TapTreeDescriptor
	Subdesc *Descriptor // Leaf script
}

// IsRange returns true if the descriptor generates multiple scripts.
func (d *Descriptor) IsRange() bool {
	for _, key := range d.Keys {
		if key.IsRange() {
			return true
		}
	}
	if d.Subdesc != nil && d.Subdesc.IsRange() {
		return true
	}
	if d.TapTree != nil && d.TapTree.isRange() {
		return true
	}
	return false
}

func (t *TapTreeDescriptor) isRange() bool {
	if t == nil {
		return false
	}
	if t.Subdesc != nil && t.Subdesc.IsRange() {
		return true
	}
	if t.Left != nil && t.Left.isRange() {
		return true
	}
	if t.Right != nil && t.Right.isRange() {
		return true
	}
	return false
}

// IsSolvable returns true if private keys are available for signing.
func (d *Descriptor) IsSolvable() bool {
	for _, key := range d.Keys {
		if key.IsPrivate() {
			return true
		}
	}
	if d.Subdesc != nil {
		return d.Subdesc.IsSolvable()
	}
	return false
}

// HasPrivateKeys returns true if all keys have private key information.
func (d *Descriptor) HasPrivateKeys() bool {
	for _, key := range d.Keys {
		if !key.IsPrivate() {
			return false
		}
	}
	if d.Subdesc != nil {
		return d.Subdesc.HasPrivateKeys()
	}
	return true
}

// Expand generates the scriptPubKey(s) at the given derivation position.
func (d *Descriptor) Expand(pos uint32) ([][]byte, error) {
	switch d.Type {
	case DescPK:
		return d.expandPK(pos)
	case DescPKH:
		return d.expandPKH(pos)
	case DescWPKH:
		return d.expandWPKH(pos)
	case DescWSH:
		return d.expandWSH(pos)
	case DescSH:
		return d.expandSH(pos)
	case DescMulti:
		return d.expandMulti(pos, false)
	case DescSortedMulti:
		return d.expandMulti(pos, true)
	case DescTR:
		return d.expandTR(pos)
	case DescCombo:
		return d.expandCombo(pos)
	case DescRaw:
		return [][]byte{d.RawScript}, nil
	case DescAddr:
		return d.expandAddr()
	case DescMiniscript:
		return d.expandMiniscript(pos)
	default:
		return nil, ErrUnsupportedDescriptor
	}
}

func (d *Descriptor) expandPK(pos uint32) ([][]byte, error) {
	if len(d.Keys) != 1 {
		return nil, ErrInvalidDescriptor
	}
	pubKey, err := d.Keys[0].GetPubKey(pos)
	if err != nil {
		return nil, err
	}

	// P2PK: <pubkey> OP_CHECKSIG
	compressed := pubKey.SerializeCompressed()
	script := make([]byte, 1+len(compressed)+1)
	script[0] = byte(len(compressed))
	copy(script[1:], compressed)
	script[len(script)-1] = 0xac // OP_CHECKSIG

	return [][]byte{script}, nil
}

func (d *Descriptor) expandPKH(pos uint32) ([][]byte, error) {
	if len(d.Keys) != 1 {
		return nil, ErrInvalidDescriptor
	}
	pubKey, err := d.Keys[0].GetPubKey(pos)
	if err != nil {
		return nil, err
	}

	// P2PKH: OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
	hash := bbcrypto.Hash160(pubKey.SerializeCompressed())
	script := make([]byte, 25)
	script[0] = 0x76 // OP_DUP
	script[1] = 0xa9 // OP_HASH160
	script[2] = 0x14 // Push 20 bytes
	copy(script[3:23], hash[:])
	script[23] = 0x88 // OP_EQUALVERIFY
	script[24] = 0xac // OP_CHECKSIG

	return [][]byte{script}, nil
}

func (d *Descriptor) expandWPKH(pos uint32) ([][]byte, error) {
	if len(d.Keys) != 1 {
		return nil, ErrInvalidDescriptor
	}
	pubKey, err := d.Keys[0].GetPubKey(pos)
	if err != nil {
		return nil, err
	}

	// P2WPKH: OP_0 <hash160>
	hash := bbcrypto.Hash160(pubKey.SerializeCompressed())
	script := make([]byte, 22)
	script[0] = 0x00 // OP_0
	script[1] = 0x14 // Push 20 bytes
	copy(script[2:], hash[:])

	return [][]byte{script}, nil
}

func (d *Descriptor) expandWSH(pos uint32) ([][]byte, error) {
	if d.Subdesc == nil {
		return nil, ErrInvalidDescriptor
	}

	// Get the witness script
	witnessScripts, err := d.Subdesc.Expand(pos)
	if err != nil {
		return nil, err
	}
	if len(witnessScripts) != 1 {
		return nil, ErrInvalidDescriptor
	}
	witnessScript := witnessScripts[0]

	// P2WSH: OP_0 <sha256(witness_script)>
	hash := bbcrypto.SHA256Hash(witnessScript)
	script := make([]byte, 34)
	script[0] = 0x00 // OP_0
	script[1] = 0x20 // Push 32 bytes
	copy(script[2:], hash[:])

	return [][]byte{script}, nil
}

func (d *Descriptor) expandSH(pos uint32) ([][]byte, error) {
	if d.Subdesc == nil {
		return nil, ErrInvalidDescriptor
	}

	// Get the redeem script
	redeemScripts, err := d.Subdesc.Expand(pos)
	if err != nil {
		return nil, err
	}
	if len(redeemScripts) != 1 {
		return nil, ErrInvalidDescriptor
	}
	redeemScript := redeemScripts[0]

	// P2SH: OP_HASH160 <hash160(redeem_script)> OP_EQUAL
	hash := bbcrypto.Hash160(redeemScript)
	script := make([]byte, 23)
	script[0] = 0xa9 // OP_HASH160
	script[1] = 0x14 // Push 20 bytes
	copy(script[2:22], hash[:])
	script[22] = 0x87 // OP_EQUAL

	return [][]byte{script}, nil
}

func (d *Descriptor) expandMulti(pos uint32, sorted bool) ([][]byte, error) {
	if d.Threshold < 1 || d.Threshold > len(d.Keys) || len(d.Keys) > 20 {
		return nil, ErrInvalidMultisigThreshold
	}

	// Collect public keys
	pubKeys := make([][]byte, len(d.Keys))
	for i, key := range d.Keys {
		pk, err := key.GetPubKey(pos)
		if err != nil {
			return nil, err
		}
		pubKeys[i] = pk.SerializeCompressed()
	}

	// Sort if sortedmulti
	if sorted {
		sort.Slice(pubKeys, func(i, j int) bool {
			return hex.EncodeToString(pubKeys[i]) < hex.EncodeToString(pubKeys[j])
		})
	}

	// Build multisig script: OP_m <pubkey1> <pubkey2> ... OP_n OP_CHECKMULTISIG
	var sb []byte
	sb = append(sb, byte(0x50+d.Threshold)) // OP_m (OP_1 = 0x51, etc.)
	for _, pk := range pubKeys {
		sb = append(sb, byte(len(pk)))
		sb = append(sb, pk...)
	}
	sb = append(sb, byte(0x50+len(pubKeys))) // OP_n
	sb = append(sb, 0xae)                    // OP_CHECKMULTISIG

	return [][]byte{sb}, nil
}

func (d *Descriptor) expandTR(pos uint32) ([][]byte, error) {
	if len(d.Keys) != 1 {
		return nil, ErrInvalidDescriptor
	}

	pubKey, err := d.Keys[0].GetPubKey(pos)
	if err != nil {
		return nil, err
	}

	// Get x-only pubkey
	compressed := pubKey.SerializeCompressed()
	xOnly := compressed[1:33]

	// Compute merkle root if there's a script tree
	var merkleRoot []byte
	if d.TapTree != nil {
		root, err := d.TapTree.computeMerkleRoot(pos)
		if err != nil {
			return nil, err
		}
		merkleRoot = root
	}

	// Tweak the pubkey
	tweakHash := script.TapTweak(xOnly, merkleRoot)

	// Compute tweaked public key
	tweakedXOnly, err := computeTweakedPubKeyFromCompressed(compressed, tweakHash)
	if err != nil {
		return nil, err
	}

	// P2TR: OP_1 <x-only-tweaked-pubkey>
	script := make([]byte, 34)
	script[0] = 0x51 // OP_1
	script[1] = 0x20 // Push 32 bytes
	copy(script[2:], tweakedXOnly)

	return [][]byte{script}, nil
}

// computeTweakedPubKeyFromCompressed is a helper that computes the tweaked x-only pubkey.
func computeTweakedPubKeyFromCompressed(compressedPubKey []byte, tweakHash [32]byte) ([]byte, error) {
	// Parse the public key
	pubKey, err := secp256k1.ParsePubKey(compressedPubKey)
	if err != nil {
		return nil, err
	}

	// Convert tweak to scalar
	var tweakScalar secp256k1.ModNScalar
	if tweakScalar.SetByteSlice(tweakHash[:]) {
		return nil, errors.New("tweak overflow")
	}

	// Compute tweak * G
	var tweakPoint secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&tweakScalar, &tweakPoint)

	// Get internal key as Jacobian point
	var internalPoint secp256k1.JacobianPoint
	pubKey.AsJacobian(&internalPoint)

	// If the internal key has odd y, negate it (BIP340 requirement)
	if compressedPubKey[0] == 0x03 { // Odd y
		internalPoint.Y.Negate(1)
		internalPoint.Y.Normalize()
	}

	// Add: tweakedPoint = internalPoint + tweakPoint
	var resultPoint secp256k1.JacobianPoint
	secp256k1.AddNonConst(&internalPoint, &tweakPoint, &resultPoint)
	resultPoint.ToAffine()

	// Create the tweaked public key
	tweakedPubKey := secp256k1.NewPublicKey(&resultPoint.X, &resultPoint.Y)

	// Return x-only (32 bytes)
	tweakedCompressed := tweakedPubKey.SerializeCompressed()
	return tweakedCompressed[1:33], nil
}

func (t *TapTreeDescriptor) computeMerkleRoot(pos uint32) ([]byte, error) {
	if t.Subdesc != nil {
		// Leaf node
		scripts, err := t.Subdesc.Expand(pos)
		if err != nil {
			return nil, err
		}
		if len(scripts) != 1 {
			return nil, ErrInvalidDescriptor
		}
		// Leaf hash = tagged_hash("TapLeaf", leaf_version || compact_size(script) || script)
		hash := script.TapLeaf(0xc0, scripts[0])
		return hash[:], nil
	}

	// Internal node
	leftHash, err := t.Left.computeMerkleRoot(pos)
	if err != nil {
		return nil, err
	}
	rightHash, err := t.Right.computeMerkleRoot(pos)
	if err != nil {
		return nil, err
	}

	// Branch hash = tagged_hash("TapBranch", min(left, right) || max(left, right))
	var left, right [32]byte
	copy(left[:], leftHash)
	copy(right[:], rightHash)
	hash := script.TapBranch(left, right)
	return hash[:], nil
}

func (d *Descriptor) expandCombo(pos uint32) ([][]byte, error) {
	if len(d.Keys) != 1 {
		return nil, ErrInvalidDescriptor
	}

	pubKey, err := d.Keys[0].GetPubKey(pos)
	if err != nil {
		return nil, err
	}

	compressed := pubKey.SerializeCompressed()
	hash := bbcrypto.Hash160(compressed)

	var results [][]byte

	// P2PK
	pk := make([]byte, 1+len(compressed)+1)
	pk[0] = byte(len(compressed))
	copy(pk[1:], compressed)
	pk[len(pk)-1] = 0xac
	results = append(results, pk)

	// P2PKH
	pkh := make([]byte, 25)
	pkh[0] = 0x76
	pkh[1] = 0xa9
	pkh[2] = 0x14
	copy(pkh[3:23], hash[:])
	pkh[23] = 0x88
	pkh[24] = 0xac
	results = append(results, pkh)

	// P2WPKH
	wpkh := make([]byte, 22)
	wpkh[0] = 0x00
	wpkh[1] = 0x14
	copy(wpkh[2:], hash[:])
	results = append(results, wpkh)

	// P2SH-P2WPKH
	witnessProgram := make([]byte, 22)
	witnessProgram[0] = 0x00
	witnessProgram[1] = 0x14
	copy(witnessProgram[2:], hash[:])
	scriptHash := bbcrypto.Hash160(witnessProgram)
	sh := make([]byte, 23)
	sh[0] = 0xa9
	sh[1] = 0x14
	copy(sh[2:22], scriptHash[:])
	sh[22] = 0x87
	results = append(results, sh)

	return results, nil
}

func (d *Descriptor) expandAddr() ([][]byte, error) {
	addr, err := address.DecodeAddress(d.AddrStr, d.Network)
	if err != nil {
		return nil, err
	}
	return [][]byte{addr.ScriptPubKey()}, nil
}

func (d *Descriptor) expandMiniscript(pos uint32) ([][]byte, error) {
	if d.Miniscript == nil {
		return nil, ErrInvalidDescriptor
	}

	// Compile miniscript to Bitcoin Script
	compiledScript, err := d.Miniscript.ToScript()
	if err != nil {
		return nil, err
	}

	return [][]byte{compiledScript}, nil
}

// ExpandToAddresses expands the descriptor and returns addresses.
func (d *Descriptor) ExpandToAddresses(pos uint32) ([]string, error) {
	scripts, err := d.Expand(pos)
	if err != nil {
		return nil, err
	}

	var addresses []string
	for _, script := range scripts {
		addr, err := scriptToAddr(script, d.Network)
		if err != nil {
			continue // Some scripts might not have standard addresses
		}
		addrStr, err := addr.Encode()
		if err != nil {
			continue
		}
		addresses = append(addresses, addrStr)
	}

	return addresses, nil
}

// scriptToAddr converts a scriptPubKey to an Address.
func scriptToAddr(pkScript []byte, net address.Network) (*address.Address, error) {
	// P2WPKH: OP_0 <20-byte-hash>
	if len(pkScript) == 22 && pkScript[0] == 0x00 && pkScript[1] == 0x14 {
		var hash [20]byte
		copy(hash[:], pkScript[2:22])
		return address.NewP2WPKHAddress(hash, net), nil
	}

	// P2WSH: OP_0 <32-byte-hash>
	if len(pkScript) == 34 && pkScript[0] == 0x00 && pkScript[1] == 0x20 {
		var hash [32]byte
		copy(hash[:], pkScript[2:34])
		return address.NewP2WSHAddress(hash, net), nil
	}

	// P2PKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
	if len(pkScript) == 25 && pkScript[0] == 0x76 && pkScript[1] == 0xa9 &&
		pkScript[2] == 0x14 && pkScript[23] == 0x88 && pkScript[24] == 0xac {
		var hash [20]byte
		copy(hash[:], pkScript[3:23])
		return address.NewP2PKHAddress(hash, net), nil
	}

	// P2SH: OP_HASH160 <20-byte-hash> OP_EQUAL
	if len(pkScript) == 23 && pkScript[0] == 0xa9 && pkScript[1] == 0x14 && pkScript[22] == 0x87 {
		var hash [20]byte
		copy(hash[:], pkScript[2:22])
		return address.NewP2SHAddress(hash, net), nil
	}

	// P2TR: OP_1 <32-byte-key>
	if len(pkScript) == 34 && pkScript[0] == 0x51 && pkScript[1] == 0x20 {
		var key [32]byte
		copy(key[:], pkScript[2:34])
		return address.NewP2TRAddress(key, net), nil
	}

	return nil, errors.New("unknown script type")
}

// String returns the descriptor as a string with checksum.
func (d *Descriptor) String() string {
	return AddChecksum(d.stringWithoutChecksum())
}

// stringWithoutChecksum returns the descriptor without checksum.
func (d *Descriptor) stringWithoutChecksum() string {
	switch d.Type {
	case DescPK:
		return fmt.Sprintf("pk(%s)", d.Keys[0].String())
	case DescPKH:
		return fmt.Sprintf("pkh(%s)", d.Keys[0].String())
	case DescWPKH:
		return fmt.Sprintf("wpkh(%s)", d.Keys[0].String())
	case DescWSH:
		return fmt.Sprintf("wsh(%s)", d.Subdesc.stringWithoutChecksum())
	case DescSH:
		return fmt.Sprintf("sh(%s)", d.Subdesc.stringWithoutChecksum())
	case DescMulti:
		return d.formatMulti("multi")
	case DescSortedMulti:
		return d.formatMulti("sortedmulti")
	case DescTR:
		if d.TapTree != nil {
			return fmt.Sprintf("tr(%s,%s)", d.Keys[0].String(), d.TapTree.String())
		}
		return fmt.Sprintf("tr(%s)", d.Keys[0].String())
	case DescCombo:
		return fmt.Sprintf("combo(%s)", d.Keys[0].String())
	case DescRaw:
		return fmt.Sprintf("raw(%s)", hex.EncodeToString(d.RawScript))
	case DescAddr:
		return fmt.Sprintf("addr(%s)", d.AddrStr)
	case DescMiniscript:
		if d.MiniscriptStr != "" {
			return fmt.Sprintf("wsh(%s)", d.MiniscriptStr)
		}
		if d.Miniscript != nil {
			return fmt.Sprintf("wsh(%s)", d.Miniscript.String())
		}
		return ""
	default:
		return ""
	}
}

func (d *Descriptor) formatMulti(fn string) string {
	var sb strings.Builder
	sb.WriteString(fn)
	sb.WriteString("(")
	sb.WriteString(strconv.Itoa(d.Threshold))
	for _, key := range d.Keys {
		sb.WriteString(",")
		sb.WriteString(key.String())
	}
	sb.WriteString(")")
	return sb.String()
}

func (t *TapTreeDescriptor) String() string {
	if t.Subdesc != nil {
		return t.Subdesc.stringWithoutChecksum()
	}
	return fmt.Sprintf("{%s,%s}", t.Left.String(), t.Right.String())
}

// ParseDescriptor parses a descriptor string into a Descriptor object.
func ParseDescriptor(desc string, net address.Network) (*Descriptor, error) {
	// Validate and strip checksum
	body, valid := ValidateDescriptorChecksum(desc)
	if !valid {
		return nil, ErrInvalidDescriptorChecksum
	}

	parser := &descriptorParser{
		input:   body,
		pos:     0,
		network: net,
	}

	return parser.parseDescriptor()
}

// descriptorParser implements recursive descent parsing for descriptors.
type descriptorParser struct {
	input   string
	pos     int
	network address.Network
}

func (p *descriptorParser) parseDescriptor() (*Descriptor, error) {
	// Parse function name
	fn := p.parseIdentifier()
	if fn == "" {
		return nil, fmt.Errorf("%w: expected function name", ErrInvalidDescriptor)
	}

	// Expect '('
	if !p.consume('(') {
		return nil, fmt.Errorf("%w: expected '(' after %s", ErrInvalidDescriptor, fn)
	}

	var d *Descriptor
	var err error

	switch fn {
	case "pk":
		d, err = p.parsePK()
	case "pkh":
		d, err = p.parsePKH()
	case "wpkh":
		d, err = p.parseWPKH()
	case "wsh":
		d, err = p.parseWSH()
	case "sh":
		d, err = p.parseSH()
	case "multi":
		d, err = p.parseMulti(false)
	case "sortedmulti":
		d, err = p.parseMulti(true)
	case "tr":
		d, err = p.parseTR()
	case "combo":
		d, err = p.parseCombo()
	case "raw":
		d, err = p.parseRaw()
	case "addr":
		d, err = p.parseAddr()
	default:
		return nil, fmt.Errorf("%w: unknown function %s", ErrUnsupportedDescriptor, fn)
	}

	if err != nil {
		return nil, err
	}

	// Expect ')'
	if !p.consume(')') {
		return nil, fmt.Errorf("%w: expected ')' after arguments", ErrInvalidDescriptor)
	}

	d.Network = p.network
	return d, nil
}

func (p *descriptorParser) parsePK() (*Descriptor, error) {
	key, err := p.parseKey()
	if err != nil {
		return nil, err
	}
	return &Descriptor{Type: DescPK, Keys: []PubkeyProvider{key}}, nil
}

func (p *descriptorParser) parsePKH() (*Descriptor, error) {
	key, err := p.parseKey()
	if err != nil {
		return nil, err
	}
	return &Descriptor{Type: DescPKH, Keys: []PubkeyProvider{key}}, nil
}

func (p *descriptorParser) parseWPKH() (*Descriptor, error) {
	key, err := p.parseKey()
	if err != nil {
		return nil, err
	}
	return &Descriptor{Type: DescWPKH, Keys: []PubkeyProvider{key}}, nil
}

func (p *descriptorParser) parseWSH() (*Descriptor, error) {
	// Try to parse as miniscript first (check if it starts with a miniscript fragment)
	savedPos := p.pos
	if p.isMiniscriptStart() {
		msStr := p.parseMiniscriptString()
		ms, err := script.ParseMiniscript(msStr, script.P2WSH)
		if err == nil {
			return &Descriptor{
				Type:          DescMiniscript,
				Miniscript:    ms,
				MiniscriptStr: msStr,
			}, nil
		}
		// Fall back to descriptor parsing
		p.pos = savedPos
	}

	subdesc, err := p.parseDescriptor()
	if err != nil {
		return nil, err
	}
	return &Descriptor{Type: DescWSH, Subdesc: subdesc}, nil
}

func (p *descriptorParser) parseSH() (*Descriptor, error) {
	subdesc, err := p.parseDescriptor()
	if err != nil {
		return nil, err
	}
	return &Descriptor{Type: DescSH, Subdesc: subdesc}, nil
}

func (p *descriptorParser) parseMulti(sorted bool) (*Descriptor, error) {
	// Parse threshold
	threshold, err := p.parseNumber()
	if err != nil {
		return nil, err
	}

	// Parse keys
	var keys []PubkeyProvider
	for p.consume(',') {
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	if threshold < 1 || threshold > len(keys) {
		return nil, ErrInvalidMultisigThreshold
	}

	descType := DescMulti
	if sorted {
		descType = DescSortedMulti
	}

	return &Descriptor{Type: descType, Keys: keys, Threshold: threshold}, nil
}

func (p *descriptorParser) parseTR() (*Descriptor, error) {
	// Parse internal key
	key, err := p.parseKey()
	if err != nil {
		return nil, err
	}

	var tree *TapTreeDescriptor
	if p.consume(',') {
		tree, err = p.parseTapTree()
		if err != nil {
			return nil, err
		}
	}

	return &Descriptor{Type: DescTR, Keys: []PubkeyProvider{key}, TapTree: tree}, nil
}

func (p *descriptorParser) parseTapTree() (*TapTreeDescriptor, error) {
	// Tree is either {left,right} or a script descriptor
	if p.consume('{') {
		left, err := p.parseTapTree()
		if err != nil {
			return nil, err
		}
		if !p.consume(',') {
			return nil, fmt.Errorf("%w: expected ',' in tap tree", ErrInvalidDescriptor)
		}
		right, err := p.parseTapTree()
		if err != nil {
			return nil, err
		}
		if !p.consume('}') {
			return nil, fmt.Errorf("%w: expected '}' in tap tree", ErrInvalidDescriptor)
		}
		return &TapTreeDescriptor{Left: left, Right: right}, nil
	}

	// Parse leaf script (a descriptor)
	subdesc, err := p.parseDescriptor()
	if err != nil {
		return nil, err
	}
	return &TapTreeDescriptor{Subdesc: subdesc}, nil
}

func (p *descriptorParser) parseCombo() (*Descriptor, error) {
	key, err := p.parseKey()
	if err != nil {
		return nil, err
	}
	return &Descriptor{Type: DescCombo, Keys: []PubkeyProvider{key}}, nil
}

func (p *descriptorParser) parseRaw() (*Descriptor, error) {
	// Parse hex string
	hexStr := p.parseUntil(')')
	script, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex in raw()", ErrInvalidDescriptor)
	}
	return &Descriptor{Type: DescRaw, RawScript: script}, nil
}

func (p *descriptorParser) parseAddr() (*Descriptor, error) {
	addrStr := p.parseUntil(')')
	// Validate the address
	_, err := address.DecodeAddress(addrStr, p.network)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid address %s", ErrInvalidDescriptor, addrStr)
	}
	return &Descriptor{Type: DescAddr, AddrStr: addrStr}, nil
}

func (p *descriptorParser) parseKey() (PubkeyProvider, error) {
	// Key can be:
	// - [origin]xpub.../path/*
	// - xpub.../path/*
	// - hex pubkey
	// - WIF private key

	// Check for origin info
	var origin *KeyOriginInfo
	if p.peek() == '[' {
		p.consume('[')
		var err error
		origin, err = p.parseOrigin()
		if err != nil {
			return nil, err
		}
		if !p.consume(']') {
			return nil, fmt.Errorf("%w: expected ']' after origin", ErrInvalidDescriptor)
		}
	}

	// Get the key part
	keyStart := p.pos
	keyStr := ""

	// Parse until we hit a delimiter
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if ch == ')' || ch == ',' || ch == '{' || ch == '}' {
			break
		}
		p.pos++
	}
	keyStr = p.input[keyStart:p.pos]

	if keyStr == "" {
		return nil, fmt.Errorf("%w: empty key", ErrInvalidKey)
	}

	// Try to parse as xpub/xprv
	if strings.HasPrefix(keyStr, "xpub") || strings.HasPrefix(keyStr, "xprv") ||
		strings.HasPrefix(keyStr, "tpub") || strings.HasPrefix(keyStr, "tprv") {
		return p.parseXPubKey(keyStr, origin)
	}

	// Try to parse as hex pubkey
	if (len(keyStr) == 66 || len(keyStr) == 130) && isHex(keyStr) {
		pubKeyBytes, err := hex.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid hex pubkey", ErrInvalidKey)
		}
		pubKey, err := bbcrypto.PublicKeyFromBytes(pubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return &ConstPubkeyProvider{PubKey: pubKey, HexStr: keyStr}, nil
	}

	// Try to parse as WIF private key
	privKey, err := decodeWIF(keyStr, p.network)
	if err == nil {
		return &ConstPubkeyProvider{
			PubKey:  privKey.PubKey(),
			PrivKey: privKey,
			HexStr:  hex.EncodeToString(privKey.PubKey().SerializeCompressed()),
		}, nil
	}

	return nil, fmt.Errorf("%w: unrecognized key format", ErrInvalidKey)
}

func (p *descriptorParser) parseXPubKey(keyStr string, origin *KeyOriginInfo) (PubkeyProvider, error) {
	// Split by '/'
	parts := strings.Split(keyStr, "/")
	xpubPart := parts[0]

	// Parse the xpub/xprv
	extKey, err := ParseExtendedKey(xpubPart)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	// Parse derivation path
	var path []uint32
	wildcard := false
	wildcardH := false

	for i := 1; i < len(parts); i++ {
		part := parts[i]
		if part == "*" {
			wildcard = true
			continue
		}
		if part == "*'" || part == "*h" || part == "*H" {
			wildcard = true
			wildcardH = true
			continue
		}

		hardened := false
		if strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") || strings.HasSuffix(part, "H") {
			hardened = true
			part = part[:len(part)-1]
		}

		idx, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid path component %s", ErrInvalidDerivationPath, part)
		}

		if hardened {
			idx += HardenedKeyStart
		}
		path = append(path, uint32(idx))
	}

	return &XPubPubkeyProvider{
		ExtKey:     extKey,
		Path:       path,
		Wildcard:   wildcard,
		WildcardH:  wildcardH,
		OriginInfo: origin,
		XPubStr:    xpubPart,
	}, nil
}

func (p *descriptorParser) parseOrigin() (*KeyOriginInfo, error) {
	// Parse fingerprint (8 hex chars)
	if p.pos+8 > len(p.input) {
		return nil, fmt.Errorf("%w: origin too short", ErrInvalidDescriptor)
	}
	fpHex := p.input[p.pos : p.pos+8]
	p.pos += 8

	fpBytes, err := hex.DecodeString(fpHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid fingerprint hex", ErrInvalidDescriptor)
	}
	var fp [4]byte
	copy(fp[:], fpBytes)

	// Parse path
	var path []uint32
	for p.peek() == '/' {
		p.consume('/')
		// Parse path component
		numStr := ""
		for p.pos < len(p.input) {
			ch := p.input[p.pos]
			if ch >= '0' && ch <= '9' {
				numStr += string(ch)
				p.pos++
			} else {
				break
			}
		}
		if numStr == "" {
			return nil, fmt.Errorf("%w: empty path component", ErrInvalidDescriptor)
		}
		idx, err := strconv.ParseUint(numStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid path number", ErrInvalidDescriptor)
		}

		// Check for hardened marker
		if p.peek() == '\'' || p.peek() == 'h' || p.peek() == 'H' {
			p.pos++
			idx += HardenedKeyStart
		}

		path = append(path, uint32(idx))
	}

	return &KeyOriginInfo{Fingerprint: fp, Path: path}, nil
}

func (p *descriptorParser) parseNumber() (int, error) {
	numStr := ""
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if ch >= '0' && ch <= '9' {
			numStr += string(ch)
			p.pos++
		} else {
			break
		}
	}
	if numStr == "" {
		return 0, fmt.Errorf("%w: expected number", ErrInvalidDescriptor)
	}
	return strconv.Atoi(numStr)
}

func (p *descriptorParser) parseIdentifier() string {
	start := p.pos
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' {
			p.pos++
		} else {
			break
		}
	}
	return p.input[start:p.pos]
}

func (p *descriptorParser) parseUntil(delim byte) string {
	start := p.pos
	for p.pos < len(p.input) && p.input[p.pos] != delim {
		p.pos++
	}
	return p.input[start:p.pos]
}

func (p *descriptorParser) peek() byte {
	if p.pos >= len(p.input) {
		return 0
	}
	return p.input[p.pos]
}

func (p *descriptorParser) consume(ch byte) bool {
	if p.pos < len(p.input) && p.input[p.pos] == ch {
		p.pos++
		return true
	}
	return false
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isMiniscriptStart checks if the current position looks like a miniscript expression.
func (p *descriptorParser) isMiniscriptStart() bool {
	if p.pos >= len(p.input) {
		return false
	}

	// Miniscript fragments and wrappers
	miniscriptPrefixes := []string{
		"pk(", "pkh(", "pk_k(", "pk_h(",
		"older(", "after(",
		"sha256(", "hash256(", "ripemd160(", "hash160(",
		"and_v(", "and_b(", "and_n(",
		"or_b(", "or_c(", "or_d(", "or_i(",
		"andor(", "thresh(", "multi(",
		"a:", "s:", "c:", "d:", "v:", "j:", "n:", "l:", "u:", "t:",
		"0", "1",
	}

	rest := p.input[p.pos:]
	for _, prefix := range miniscriptPrefixes {
		if strings.HasPrefix(rest, prefix) {
			return true
		}
	}
	return false
}

// parseMiniscriptString extracts the miniscript string from the input.
func (p *descriptorParser) parseMiniscriptString() string {
	start := p.pos
	depth := 0

	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if ch == '(' {
			depth++
		} else if ch == ')' {
			if depth == 0 {
				// End of miniscript (this is the closing paren of wsh())
				break
			}
			depth--
		}
		p.pos++
	}

	return p.input[start:p.pos]
}

// decodeWIF decodes a WIF-encoded private key.
func decodeWIF(wif string, net address.Network) (*bbcrypto.PrivateKey, error) {
	// Decode base58check
	version, payload, err := address.Base58CheckDecode(wif)
	if err != nil {
		return nil, err
	}

	// Check version byte
	var expectedVersion byte
	switch net {
	case address.Mainnet:
		expectedVersion = 0x80
	default:
		expectedVersion = 0xef
	}
	if version != expectedVersion {
		return nil, fmt.Errorf("wrong network version")
	}

	// Handle compressed flag
	var keyBytes []byte
	if len(payload) == 33 && payload[32] == 0x01 {
		// Compressed
		keyBytes = payload[:32]
	} else if len(payload) == 32 {
		// Uncompressed
		keyBytes = payload
	} else {
		return nil, fmt.Errorf("invalid WIF payload length")
	}

	return bbcrypto.PrivateKeyFromBytes(keyBytes), nil
}

// EncodeWIF encodes a private key as WIF.
func EncodeWIF(privKey *bbcrypto.PrivateKey, net address.Network, compressed bool) string {
	var version byte
	switch net {
	case address.Mainnet:
		version = 0x80
	default:
		version = 0xef
	}

	payload := privKey.Serialize()
	if compressed {
		payload = append(payload, 0x01)
	}

	return address.Base58CheckEncode(version, payload)
}

// GetDescriptorInfo returns information about a descriptor.
type DescriptorInfo struct {
	Descriptor     string `json:"descriptor"`     // Descriptor with checksum
	Checksum       string `json:"checksum"`       // Just the checksum
	IsRange        bool   `json:"isrange"`        // Whether it's a ranged descriptor
	IsSolvable     bool   `json:"issolvable"`     // Whether we can sign for it
	HasPrivateKeys bool   `json:"hasprivatekeys"` // Whether private keys are present
}

// GetDescriptorInfo analyzes a descriptor and returns information about it.
func GetDescriptorInfo(desc string, net address.Network) (*DescriptorInfo, error) {
	// Parse the descriptor
	parsed, err := ParseDescriptor(desc, net)
	if err != nil {
		return nil, err
	}

	// Get the normalized descriptor string
	normalized := parsed.stringWithoutChecksum()
	checksum := DescriptorChecksum(normalized)

	return &DescriptorInfo{
		Descriptor:     normalized + "#" + checksum,
		Checksum:       checksum,
		IsRange:        parsed.IsRange(),
		IsSolvable:     parsed.IsSolvable(),
		HasPrivateKeys: parsed.HasPrivateKeys(),
	}, nil
}

// DeriveAddresses derives addresses from a descriptor.
// For ranged descriptors, start and end specify the range (inclusive).
// For non-ranged descriptors, start and end are ignored.
func DeriveAddresses(desc string, net address.Network, start, end uint32) ([]string, error) {
	parsed, err := ParseDescriptor(desc, net)
	if err != nil {
		return nil, err
	}

	if !parsed.IsRange() {
		// Non-ranged descriptor - derive single address
		return parsed.ExpandToAddresses(0)
	}

	// Ranged descriptor
	var addresses []string
	for pos := start; pos <= end; pos++ {
		addrs, err := parsed.ExpandToAddresses(pos)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, addrs...)
	}

	return addresses, nil
}
