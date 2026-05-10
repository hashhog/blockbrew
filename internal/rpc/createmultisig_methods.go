// createmultisig_methods.go — RPC handler for createmultisig
//
// Reference: Bitcoin Core src/rpc/util.cpp (createmultisig)
// Spec: createmultisig <nrequired> <pubkeys[]> [address_type]
//
// Returns {address, descriptor, redeemScript} where:
//   - redeemScript: OP_M || for each pk: 0x21||pk(33B) || OP_N || OP_CHECKMULTISIG
//   - address: P2SH (legacy/default), P2WSH (bech32), P2SH-P2WSH (p2sh-segwit)
//   - descriptor: sh(multi(...))/wsh(multi(...))/sh(wsh(multi(...))) + BIP-380 checksum
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wallet"
)

// createMultisigResult is the return value of createmultisig.
type createMultisigResult struct {
	Address      string `json:"address"`
	RedeemScript string `json:"redeemScript"`
	Descriptor   string `json:"descriptor"`
}

func (s *Server) handleCreateMultisig(params json.RawMessage) (interface{}, *RPCError) {
	// Parse positional params: [nrequired, [pubkey...], address_type?]
	var raw []json.RawMessage
	if err := json.Unmarshal(params, &raw); err != nil || len(raw) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "createmultisig requires at least 2 arguments"}
	}

	// Param 0: nrequired (integer)
	var nRequired int
	if err := json.Unmarshal(raw[0], &nRequired); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid nrequired parameter"}
	}

	// Param 1: pubkeys array
	var pubkeyStrs []string
	if err := json.Unmarshal(raw[1], &pubkeyStrs); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid pubkeys parameter"}
	}

	// Param 2 (optional): address_type
	addrType := "legacy"
	if len(raw) >= 3 {
		if err := json.Unmarshal(raw[2], &addrType); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid address_type parameter"}
		}
	}

	nKeys := len(pubkeyStrs)

	// Validate bounds.
	if nKeys < 1 || nKeys > 16 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Number of keys %d is not in range [1..16]", nKeys)}
	}
	if nRequired < 1 || nRequired > nKeys {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Multisig threshold %d is not in range [1..%d]", nRequired, nKeys)}
	}

	// Validate address_type.
	switch addrType {
	case "legacy", "bech32", "p2sh-segwit":
		// ok
	default:
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Unknown address_type '%s'", addrType)}
	}

	// Parse and validate pubkeys.
	pubkeys := make([][]byte, nKeys)
	for i, pkHex := range pubkeyStrs {
		pkBytes, err := hex.DecodeString(pkHex)
		if err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Pubkey %d is not valid hex", i)}
		}
		// Must be 33 bytes (compressed) for bech32/p2sh-segwit; Core also
		// rejects uncompressed for segwit.  For legacy we accept 33-byte
		// compressed only (Core's createmultisig accepts only compressed).
		if len(pkBytes) != 33 {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Pubkey %d is not compressed (must be 33 bytes)", i)}
		}
		// Verify the point is on the curve.
		if _, err := crypto.PublicKeyFromBytes(pkBytes); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Pubkey %d is not a valid secp256k1 public key", i)}
		}
		pubkeys[i] = pkBytes
	}

	// ── Build redeemScript ───────────────────────────────────────────────
	// Layout: OP_M || for each pk: 0x21 || pk[33] || OP_N || OP_CHECKMULTISIG
	// OP_1..OP_16 = 0x51..0x60 = 0x50 + n
	rsLen := 1 + nKeys*(1+33) + 1 + 1 // OP_M + (push+pk)*N + OP_N + OP_CHECKMULTISIG
	rs := make([]byte, 0, rsLen)
	rs = append(rs, byte(0x50+nRequired)) // OP_M
	for _, pk := range pubkeys {
		rs = append(rs, 0x21) // push 33 bytes
		rs = append(rs, pk...)
	}
	rs = append(rs, byte(0x50+nKeys)) // OP_N
	rs = append(rs, 0xae)             // OP_CHECKMULTISIG

	rsHex := hex.EncodeToString(rs)

	// ── Derive address ───────────────────────────────────────────────────
	net := s.getNetwork()

	var addrStr string
	switch addrType {
	case "legacy":
		// P2SH: HASH160(redeemScript)
		h160 := crypto.Hash160(rs)
		a := &address.Address{Type: address.P2SH, Network: net, Hash: h160[:]}
		var err error
		addrStr, err = a.Encode()
		if err != nil {
			return nil, &RPCError{Code: RPCErrMisc, Message: fmt.Sprintf("Failed to encode P2SH address: %v", err)}
		}

	case "bech32":
		// P2WSH: SHA256(redeemScript)
		sha256rs := crypto.SHA256Hash(rs)
		a := &address.Address{Type: address.P2WSH, Network: net, Hash: sha256rs[:]}
		var err error
		addrStr, err = a.Encode()
		if err != nil {
			return nil, &RPCError{Code: RPCErrMisc, Message: fmt.Sprintf("Failed to encode P2WSH address: %v", err)}
		}

	case "p2sh-segwit":
		// P2SH-P2WSH: P2SH(HASH160(OP_0 OP_PUSH32 SHA256(redeemScript)))
		// Inner witnessScript = 0x0020 || SHA256(rs)
		sha256rs := crypto.SHA256Hash(rs)
		witnessScript := make([]byte, 34)
		witnessScript[0] = 0x00 // OP_0
		witnessScript[1] = 0x20 // push 32 bytes
		copy(witnessScript[2:], sha256rs[:])
		h160ws := crypto.Hash160(witnessScript)
		a := &address.Address{Type: address.P2SH, Network: net, Hash: h160ws[:]}
		var err error
		addrStr, err = a.Encode()
		if err != nil {
			return nil, &RPCError{Code: RPCErrMisc, Message: fmt.Sprintf("Failed to encode P2SH-P2WSH address: %v", err)}
		}
	}

	// ── Build descriptor ─────────────────────────────────────────────────
	// multi(M, pk1, pk2, ...) inner expression
	var sb strings.Builder
	fmt.Fprintf(&sb, "multi(%d", nRequired)
	for _, pkHex := range pubkeyStrs {
		sb.WriteString(",")
		sb.WriteString(pkHex)
	}
	sb.WriteString(")")
	multiExpr := sb.String()

	var descBody string
	switch addrType {
	case "legacy":
		descBody = "sh(" + multiExpr + ")"
	case "bech32":
		descBody = "wsh(" + multiExpr + ")"
	case "p2sh-segwit":
		descBody = "sh(wsh(" + multiExpr + "))"
	}

	descriptor := wallet.AddChecksum(descBody)

	return &createMultisigResult{
		Address:      addrStr,
		RedeemScript: rsHex,
		Descriptor:   descriptor,
	}, nil
}
