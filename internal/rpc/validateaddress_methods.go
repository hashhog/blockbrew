// validateaddress_methods.go — RPC handler for validateaddress
//
// Reference: Bitcoin Core src/rpc/util.cpp (validateaddress)
// Spec: Core 27+ format — valid returns {address, isvalid, isscript, iswitness,
//
//	scriptPubKey, witness_version?, witness_program?}; invalid returns
//	{isvalid:false, error, error_locations:[]}
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/hashhog/blockbrew/internal/address"
)

// validateAddressResult is the result of validateaddress for a valid address.
type validateAddressResult struct {
	IsValid        bool   `json:"isvalid"`
	Address        string `json:"address"`
	ScriptPubKey   string `json:"scriptPubKey"`
	IsScript       bool   `json:"isscript"`
	IsWitness      bool   `json:"iswitness"`
	WitnessVersion *int   `json:"witness_version,omitempty"`
	WitnessProgram string `json:"witness_program,omitempty"`
}

// validateAddressInvalidResult is the result for an invalid address (Core 27+).
// Field order mirrors Core's pushKV order (rpc/output_script.cpp:67,80,81):
// isvalid, error_locations, error — NOT isvalid/error/error_locations. The
// byte-diff harness checks field-emission order.
type validateAddressInvalidResult struct {
	IsValid        bool   `json:"isvalid"`
	ErrorLocations []int  `json:"error_locations"`
	Error          string `json:"error"`
}

func (s *Server) handleValidateAddress(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid address parameter"}
	}

	net := s.getNetwork()
	addr, err := address.DecodeAddress(addrStr, net)
	if err != nil {
		return &validateAddressInvalidResult{
			IsValid:        false,
			Error:          validateAddressErrorMessage(addrStr, net),
			ErrorLocations: []int{},
		}, nil
	}

	spk := addr.ScriptPubKey()
	spkHex := hex.EncodeToString(spk)

	result := &validateAddressResult{
		IsValid:      true,
		Address:      addrStr,
		ScriptPubKey: spkHex,
	}

	switch addr.Type {
	case address.P2PKH:
		result.IsScript = false
		result.IsWitness = false

	case address.P2SH:
		result.IsScript = true
		result.IsWitness = false

	case address.P2WPKH:
		// 20-byte witness program, version 0
		result.IsScript = false
		result.IsWitness = true
		v := 0
		result.WitnessVersion = &v
		result.WitnessProgram = hex.EncodeToString(addr.Hash)

	case address.P2WSH:
		// 32-byte witness program, version 0
		result.IsScript = true
		result.IsWitness = true
		v := 0
		result.WitnessVersion = &v
		result.WitnessProgram = hex.EncodeToString(addr.Hash)

	case address.P2TR:
		// 32-byte witness program, version 1
		result.IsScript = true
		result.IsWitness = true
		v := 1
		result.WitnessVersion = &v
		result.WitnessProgram = hex.EncodeToString(addr.Hash)
	}

	return result, nil
}

// validateAddressErrorMessage mirrors Bitcoin Core DecodeDestination
// (key_io.cpp:85-128) error strings. The R5 exact-invalid probe is
// "notanaddress": not a Bech32 HRP prefix, Base58Check fails, raw Base58
// succeeds → "Invalid checksum or length of Base58 address (P2PKH or P2SH)".
func validateAddressErrorMessage(addrStr string, net address.Network) string {
	hrp := "bc"
	switch net {
	case address.Testnet, address.Signet:
		hrp = "tb"
	case address.Regtest:
		hrp = "bcrt"
	}
	lower := strings.ToLower(addrStr)
	isBech32 := len(lower) >= len(hrp) && lower[:len(hrp)] == hrp
	if isBech32 {
		return "Invalid or unsupported Segwit (Bech32) or Base58 encoding."
	}
	if _, _, err := address.Base58CheckDecode(addrStr); err == nil {
		return "Invalid or unsupported Base58-encoded address."
	}
	if _, err := address.Base58Decode(addrStr); err != nil {
		return "Invalid or unsupported Segwit (Bech32) or Base58 encoding."
	}
	return "Invalid checksum or length of Base58 address (P2PKH or P2SH)"
}
