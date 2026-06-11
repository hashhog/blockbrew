// validateaddress_methods.go — RPC handler for validateaddress
//
// Reference: Bitcoin Core src/rpc/util.cpp (validateaddress)
// Spec: Core 27+ format — valid returns {address, isvalid, isscript, iswitness,
//   scriptPubKey, witness_version?, witness_program?}; invalid returns
//   {isvalid:false, error, error_locations:[]}
package rpc

import (
	"encoding/hex"
	"encoding/json"

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
	IsValid        bool     `json:"isvalid"`
	ErrorLocations []string `json:"error_locations"`
	Error          string   `json:"error"`
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
			Error:          "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
			ErrorLocations: []string{},
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
