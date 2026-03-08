package address

import (
	"bytes"
	"errors"
)

// Network represents a Bitcoin network.
type Network int

const (
	Mainnet Network = iota
	Testnet
	Regtest
	Signet
)

// AddressType represents the type of Bitcoin address.
type AddressType int

const (
	P2PKH  AddressType = iota // Pay to Public Key Hash
	P2SH                      // Pay to Script Hash
	P2WPKH                    // Pay to Witness Public Key Hash
	P2WSH                     // Pay to Witness Script Hash
	P2TR                      // Pay to Taproot
)

// Version bytes for Base58Check
const (
	mainnetP2PKHVersion = 0x00
	mainnetP2SHVersion  = 0x05
	testnetP2PKHVersion = 0x6F
	testnetP2SHVersion  = 0xC4
)

// Bech32 Human-Readable Parts
const (
	mainnetHRP = "bc"
	testnetHRP = "tb"
	regtestHRP = "bcrt"
	signetHRP  = "tb"
)

// Address errors
var (
	ErrInvalidAddressLength = errors.New("invalid address length")
	ErrInvalidAddressType   = errors.New("invalid address type")
	ErrInvalidNetwork       = errors.New("invalid network")
	ErrInvalidWitnessVer    = errors.New("invalid witness version")
	ErrNetworkMismatch      = errors.New("address network mismatch")
	ErrUnknownAddressFormat = errors.New("unknown address format")
)

// Address represents a decoded Bitcoin address.
type Address struct {
	Type    AddressType
	Network Network
	Hash    []byte // 20 bytes for P2PKH/P2WPKH/P2SH, 32 bytes for P2WSH/P2TR
}

// getHRP returns the bech32 HRP for a network.
func getHRP(net Network) string {
	switch net {
	case Mainnet:
		return mainnetHRP
	case Testnet:
		return testnetHRP
	case Regtest:
		return regtestHRP
	case Signet:
		return signetHRP
	default:
		return ""
	}
}

// Encode returns the string representation of the address.
func (a *Address) Encode() (string, error) {
	switch a.Type {
	case P2PKH:
		if len(a.Hash) != 20 {
			return "", ErrInvalidAddressLength
		}
		var version byte
		switch a.Network {
		case Mainnet:
			version = mainnetP2PKHVersion
		case Testnet, Regtest, Signet:
			version = testnetP2PKHVersion
		default:
			return "", ErrInvalidNetwork
		}
		return Base58CheckEncode(version, a.Hash), nil

	case P2SH:
		if len(a.Hash) != 20 {
			return "", ErrInvalidAddressLength
		}
		var version byte
		switch a.Network {
		case Mainnet:
			version = mainnetP2SHVersion
		case Testnet, Regtest, Signet:
			version = testnetP2SHVersion
		default:
			return "", ErrInvalidNetwork
		}
		return Base58CheckEncode(version, a.Hash), nil

	case P2WPKH:
		if len(a.Hash) != 20 {
			return "", ErrInvalidAddressLength
		}
		hrp := getHRP(a.Network)
		if hrp == "" {
			return "", ErrInvalidNetwork
		}
		return encodeSegwit(hrp, 0, a.Hash)

	case P2WSH:
		if len(a.Hash) != 32 {
			return "", ErrInvalidAddressLength
		}
		hrp := getHRP(a.Network)
		if hrp == "" {
			return "", ErrInvalidNetwork
		}
		return encodeSegwit(hrp, 0, a.Hash)

	case P2TR:
		if len(a.Hash) != 32 {
			return "", ErrInvalidAddressLength
		}
		hrp := getHRP(a.Network)
		if hrp == "" {
			return "", ErrInvalidNetwork
		}
		return encodeSegwit(hrp, 1, a.Hash)

	default:
		return "", ErrInvalidAddressType
	}
}

// encodeSegwit encodes a segwit address with the given witness version.
func encodeSegwit(hrp string, version int, program []byte) (string, error) {
	// Convert 8-bit program to 5-bit groups
	data5, err := ConvertBits(program, 8, 5, true)
	if err != nil {
		return "", err
	}

	// Prepend witness version
	data := make([]byte, 1+len(data5))
	data[0] = byte(version)
	copy(data[1:], data5)

	// Use bech32 for v0, bech32m for v1+
	if version == 0 {
		return Bech32Encode(hrp, data)
	}
	return Bech32mEncode(hrp, data)
}

// DecodeAddress parses a Bitcoin address string and returns the Address.
func DecodeAddress(s string, net Network) (*Address, error) {
	// Try Base58Check first (P2PKH, P2SH)
	if version, payload, err := Base58CheckDecode(s); err == nil {
		return decodeBase58Address(version, payload, net)
	}

	// Try Bech32/Bech32m (SegWit)
	return decodeSegwitAddress(s, net)
}

// decodeBase58Address decodes a Base58Check address.
func decodeBase58Address(version byte, payload []byte, net Network) (*Address, error) {
	if len(payload) != 20 {
		return nil, ErrInvalidAddressLength
	}

	addr := &Address{
		Hash: payload,
	}

	switch version {
	case mainnetP2PKHVersion:
		if net != Mainnet {
			return nil, ErrNetworkMismatch
		}
		addr.Type = P2PKH
		addr.Network = Mainnet
	case mainnetP2SHVersion:
		if net != Mainnet {
			return nil, ErrNetworkMismatch
		}
		addr.Type = P2SH
		addr.Network = Mainnet
	case testnetP2PKHVersion:
		if net != Testnet && net != Regtest && net != Signet {
			return nil, ErrNetworkMismatch
		}
		addr.Type = P2PKH
		addr.Network = net
	case testnetP2SHVersion:
		if net != Testnet && net != Regtest && net != Signet {
			return nil, ErrNetworkMismatch
		}
		addr.Type = P2SH
		addr.Network = net
	default:
		return nil, ErrUnknownAddressFormat
	}

	return addr, nil
}

// decodeSegwitAddress decodes a bech32/bech32m segwit address.
func decodeSegwitAddress(s string, net Network) (*Address, error) {
	expectedHRP := getHRP(net)

	// Try bech32 first (witness version 0)
	hrp, data, err := Bech32Decode(s)
	isBech32m := false
	if err != nil {
		// Try bech32m (witness version 1+)
		hrp, data, err = Bech32mDecode(s)
		if err != nil {
			return nil, err
		}
		isBech32m = true
	}

	// Validate HRP
	if hrp != expectedHRP {
		return nil, ErrNetworkMismatch
	}

	// Need at least witness version + some data
	if len(data) < 1 {
		return nil, ErrInvalidAddressLength
	}

	witnessVersion := int(data[0])

	// Validate witness version vs encoding
	if witnessVersion == 0 && isBech32m {
		return nil, ErrInvalidWitnessVer
	}
	if witnessVersion > 0 && !isBech32m {
		return nil, ErrInvalidWitnessVer
	}

	// Convert 5-bit data back to 8-bit program
	program, err := ConvertBits(data[1:], 5, 8, false)
	if err != nil {
		return nil, err
	}

	// Validate witness program length
	if len(program) < 2 || len(program) > 40 {
		return nil, ErrInvalidAddressLength
	}

	addr := &Address{
		Network: net,
		Hash:    program,
	}

	switch witnessVersion {
	case 0:
		switch len(program) {
		case 20:
			addr.Type = P2WPKH
		case 32:
			addr.Type = P2WSH
		default:
			return nil, ErrInvalidAddressLength
		}
	case 1:
		if len(program) != 32 {
			return nil, ErrInvalidAddressLength
		}
		addr.Type = P2TR
	default:
		return nil, ErrInvalidWitnessVer
	}

	return addr, nil
}

// NewP2PKHAddress creates a P2PKH address from a 20-byte pubkey hash.
func NewP2PKHAddress(hash [20]byte, net Network) *Address {
	return &Address{
		Type:    P2PKH,
		Network: net,
		Hash:    hash[:],
	}
}

// NewP2SHAddress creates a P2SH address from a 20-byte script hash.
func NewP2SHAddress(hash [20]byte, net Network) *Address {
	return &Address{
		Type:    P2SH,
		Network: net,
		Hash:    hash[:],
	}
}

// NewP2WPKHAddress creates a P2WPKH address from a 20-byte pubkey hash.
func NewP2WPKHAddress(hash [20]byte, net Network) *Address {
	return &Address{
		Type:    P2WPKH,
		Network: net,
		Hash:    hash[:],
	}
}

// NewP2WSHAddress creates a P2WSH address from a 32-byte script hash.
func NewP2WSHAddress(hash [32]byte, net Network) *Address {
	return &Address{
		Type:    P2WSH,
		Network: net,
		Hash:    hash[:],
	}
}

// NewP2TRAddress creates a P2TR address from a 32-byte x-only pubkey.
func NewP2TRAddress(pubkey [32]byte, net Network) *Address {
	return &Address{
		Type:    P2TR,
		Network: net,
		Hash:    pubkey[:],
	}
}

// ScriptPubKey returns the scriptPubKey for this address.
func (a *Address) ScriptPubKey() []byte {
	switch a.Type {
	case P2PKH:
		// OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
		// [0x76, 0xa9, 0x14, ...hash..., 0x88, 0xac]
		script := make([]byte, 25)
		script[0] = 0x76 // OP_DUP
		script[1] = 0xa9 // OP_HASH160
		script[2] = 0x14 // Push 20 bytes
		copy(script[3:23], a.Hash)
		script[23] = 0x88 // OP_EQUALVERIFY
		script[24] = 0xac // OP_CHECKSIG
		return script

	case P2SH:
		// OP_HASH160 <20-byte-hash> OP_EQUAL
		// [0xa9, 0x14, ...hash..., 0x87]
		script := make([]byte, 23)
		script[0] = 0xa9 // OP_HASH160
		script[1] = 0x14 // Push 20 bytes
		copy(script[2:22], a.Hash)
		script[22] = 0x87 // OP_EQUAL
		return script

	case P2WPKH:
		// OP_0 <20-byte-hash>
		// [0x00, 0x14, ...hash...]
		script := make([]byte, 22)
		script[0] = 0x00 // OP_0
		script[1] = 0x14 // Push 20 bytes
		copy(script[2:], a.Hash)
		return script

	case P2WSH:
		// OP_0 <32-byte-hash>
		// [0x00, 0x20, ...hash...]
		script := make([]byte, 34)
		script[0] = 0x00 // OP_0
		script[1] = 0x20 // Push 32 bytes
		copy(script[2:], a.Hash)
		return script

	case P2TR:
		// OP_1 <32-byte-key>
		// [0x51, 0x20, ...key...]
		script := make([]byte, 34)
		script[0] = 0x51 // OP_1
		script[1] = 0x20 // Push 32 bytes
		copy(script[2:], a.Hash)
		return script

	default:
		return nil
	}
}

// Equal returns true if two addresses are equal.
func (a *Address) Equal(other *Address) bool {
	if a == nil || other == nil {
		return a == other
	}
	return a.Type == other.Type &&
		a.Network == other.Network &&
		bytes.Equal(a.Hash, other.Hash)
}
