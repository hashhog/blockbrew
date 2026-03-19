package rpc

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// PSBT RPCs (BIP174/370)
// ============================================================================

// handleCreatePSBT creates a PSBT from raw transaction inputs and outputs.
// Inputs: [inputs, outputs, locktime, replaceable]
func (s *Server) handleCreatePSBT(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing inputs and/or outputs"}
	}

	// Parse inputs
	inputsRaw, ok := args[0].([]interface{})
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid inputs"}
	}

	// Parse outputs
	outputsRaw, ok := args[1].([]interface{})
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid outputs"}
	}

	// Parse optional locktime
	lockTime := uint32(0)
	if len(args) >= 3 {
		if lt, ok := args[2].(float64); ok {
			lockTime = uint32(lt)
		}
	}

	// Parse optional replaceable flag (BIP125)
	replaceable := false
	if len(args) >= 4 {
		if r, ok := args[3].(bool); ok {
			replaceable = r
		}
	}

	// Build the unsigned transaction
	tx := &wire.MsgTx{
		Version:  2,
		LockTime: lockTime,
	}

	// Add inputs
	for i, inp := range inputsRaw {
		inputMap, ok := inp.(map[string]interface{})
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid input %d", i)}
		}

		txidStr, ok := inputMap["txid"].(string)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Missing txid in input %d", i)}
		}

		voutFloat, ok := inputMap["vout"].(float64)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Missing vout in input %d", i)}
		}

		txid, err := wire.NewHash256FromHex(txidStr)
		if err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid txid in input %d", i)}
		}

		sequence := uint32(0xfffffffe) // Enable RBF by default
		if !replaceable {
			sequence = 0xffffffff
		}
		if seq, ok := inputMap["sequence"].(float64); ok {
			sequence = uint32(seq)
		}

		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  txid,
				Index: uint32(voutFloat),
			},
			Sequence: sequence,
		})
	}

	// Add outputs
	for i, out := range outputsRaw {
		outputMap, ok := out.(map[string]interface{})
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid output %d", i)}
		}

		for addrStr, amountRaw := range outputMap {
			amountBTC, ok := amountRaw.(float64)
			if !ok {
				return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid amount in output %d", i)}
			}

			amountSat := int64(amountBTC * satoshiPerBitcoin)

			// Check for "data" key (OP_RETURN output)
			if addrStr == "data" {
				dataStr, ok := amountRaw.(string)
				if !ok {
					return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid data output"}
				}
				dataBytes, err := hex.DecodeString(dataStr)
				if err != nil {
					return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid hex in data output"}
				}
				// Build OP_RETURN script: OP_RETURN <push data>
				pkScript := make([]byte, 0, 2+len(dataBytes))
				pkScript = append(pkScript, 0x6a) // OP_RETURN
				if len(dataBytes) < 76 {
					pkScript = append(pkScript, byte(len(dataBytes)))
				} else if len(dataBytes) < 256 {
					pkScript = append(pkScript, 0x4c, byte(len(dataBytes)))
				}
				pkScript = append(pkScript, dataBytes...)
				tx.TxOut = append(tx.TxOut, &wire.TxOut{
					Value:    0,
					PkScript: pkScript,
				})
				continue
			}

			// Decode address to scriptPubKey
			// Need to import address package for this
			pkScript, err := addressToScript(addrStr)
			if err != nil {
				return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid address: %s", addrStr)}
			}

			tx.TxOut = append(tx.TxOut, &wire.TxOut{
				Value:    amountSat,
				PkScript: pkScript,
			})
		}
	}

	// Create PSBT
	psbt, err := wallet.NewPSBT(tx)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to create PSBT: %v", err)}
	}

	// Encode to base64
	encoded, err := psbt.EncodeBase64()
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to encode PSBT: %v", err)}
	}

	return encoded, nil
}

// handleDecodePSBT decodes a PSBT and returns detailed information.
func (s *Server) handleDecodePSBT(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing PSBT parameter"}
	}

	psbtStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid PSBT string"}
	}

	// Decode PSBT
	psbt, err := wallet.DecodePSBTBase64(psbtStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Failed to decode PSBT: %v", err)}
	}

	return buildDecodePSBTResult(psbt), nil
}

// handleCombinePSBT combines multiple PSBTs.
func (s *Server) handleCombinePSBT(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing PSBTs parameter"}
	}

	psbtsRaw, ok := args[0].([]interface{})
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "PSBTs must be an array"}
	}

	if len(psbtsRaw) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "At least one PSBT required"}
	}

	// Decode all PSBTs
	psbts := make([]*wallet.PSBT, len(psbtsRaw))
	for i, raw := range psbtsRaw {
		str, ok := raw.(string)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid PSBT at index %d", i)}
		}
		psbt, err := wallet.DecodePSBTBase64(str)
		if err != nil {
			return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Failed to decode PSBT %d: %v", i, err)}
		}
		psbts[i] = psbt
	}

	// Combine
	combined, err := wallet.CombinePSBTs(psbts)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to combine PSBTs: %v", err)}
	}

	// Encode result
	encoded, err := combined.EncodeBase64()
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to encode PSBT: %v", err)}
	}

	return encoded, nil
}

// handleFinalizePSBT finalizes a PSBT.
func (s *Server) handleFinalizePSBT(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing PSBT parameter"}
	}

	psbtStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid PSBT string"}
	}

	// Optional: extract flag (default true)
	extract := true
	if len(args) >= 2 {
		if e, ok := args[1].(bool); ok {
			extract = e
		}
	}

	// Decode PSBT
	psbt, err := wallet.DecodePSBTBase64(psbtStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Failed to decode PSBT: %v", err)}
	}

	// Finalize
	complete, err := wallet.FinalizePSBT(psbt)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to finalize PSBT: %v", err)}
	}

	result := &FinalizePSBTResult{
		Complete: complete,
	}

	if complete && extract {
		// Extract and serialize transaction
		tx, err := wallet.ExtractTransaction(psbt)
		if err != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to extract transaction: %v", err)}
		}

		var buf bytes.Buffer
		if err := tx.Serialize(&buf); err != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to serialize transaction"}
		}
		result.Hex = hex.EncodeToString(buf.Bytes())
	} else {
		// Return the finalized PSBT
		encoded, err := psbt.EncodeBase64()
		if err != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to encode PSBT"}
		}
		result.PSBT = encoded
	}

	return result, nil
}

// handleConvertToPSBT converts a raw transaction to a PSBT.
func (s *Server) handleConvertToPSBT(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing hex transaction parameter"}
	}

	hexStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid hex string"}
	}

	// Decode transaction
	txBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Invalid hex encoding"}
	}

	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Failed to decode transaction: %v", err)}
	}

	// Optional: permitsigdata (default false) - if false, fail on signed inputs
	permitSigData := false
	if len(args) >= 2 {
		if p, ok := args[1].(bool); ok {
			permitSigData = p
		}
	}

	// Check for signed inputs
	if !permitSigData {
		for i, in := range tx.TxIn {
			if len(in.SignatureScript) > 0 || len(in.Witness) > 0 {
				return nil, &RPCError{
					Code:    RPCErrDeserialization,
					Message: fmt.Sprintf("Inputs must not have scriptSigs and scriptWitnesses. Input %d has one.", i),
				}
			}
		}
	}

	// Clear any signatures if permitSigData is true
	if permitSigData {
		for _, in := range tx.TxIn {
			in.SignatureScript = nil
			in.Witness = nil
		}
	}

	// Create PSBT
	psbt, err := wallet.NewPSBT(tx)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to create PSBT: %v", err)}
	}

	// Encode to base64
	encoded, err := psbt.EncodeBase64()
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to encode PSBT"}
	}

	return encoded, nil
}

// handleWalletProcessPSBT signs a PSBT using the wallet.
func (s *Server) handleWalletProcessPSBT(params json.RawMessage) (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing PSBT parameter"}
	}

	psbtStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid PSBT string"}
	}

	// Optional parameters
	sign := true
	if len(args) >= 2 {
		if s, ok := args[1].(bool); ok {
			sign = s
		}
	}

	// sighashtype (optional, default ALL)
	// bip32derivs (optional, default true)
	// finalize (optional, default true)

	// Decode PSBT
	psbt, err := wallet.DecodePSBTBase64(psbtStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Failed to decode PSBT: %v", err)}
	}

	// Sign if requested
	if sign {
		signer := wallet.NewWalletPSBTSigner(s.wallet)
		if err := wallet.SignPSBT(psbt, signer); err != nil {
			return nil, &RPCError{Code: RPCErrWalletError, Message: fmt.Sprintf("Failed to sign PSBT: %v", err)}
		}
	}

	// Check if complete
	complete := psbt.IsComplete()

	// Encode result
	encoded, err := psbt.EncodeBase64()
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to encode PSBT"}
	}

	return &ProcessPSBTResult{
		PSBT:     encoded,
		Complete: complete,
	}, nil
}

// handleAnalyzePSBT analyzes a PSBT.
func (s *Server) handleAnalyzePSBT(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing PSBT parameter"}
	}

	psbtStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid PSBT string"}
	}

	// Decode PSBT
	psbt, err := wallet.DecodePSBTBase64(psbtStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Failed to decode PSBT: %v", err)}
	}

	// Analyze each input
	inputs := make([]AnalyzePSBTInput, len(psbt.Inputs))
	allComplete := true
	totalFee := int64(0)

	for i, input := range psbt.Inputs {
		inputResult := AnalyzePSBTInput{}

		// Check if UTXO info is present
		hasUTXO := input.WitnessUTXO != nil || input.NonWitnessUTXO != nil
		inputResult.HasUTXO = hasUTXO

		// Check if finalized
		isFinalized := len(input.FinalScriptSig) > 0 || len(input.FinalScriptWitness) > 0
		inputResult.IsFinalized = isFinalized

		if !isFinalized {
			allComplete = false

			// Analyze what's missing
			missing := []string{}

			if !hasUTXO {
				missing = append(missing, "utxo")
			}

			// Check if has any partial sigs
			if len(input.PartialSigs) == 0 && len(input.TapKeySig) == 0 {
				missing = append(missing, "signature")
			}

			if len(missing) > 0 {
				inputResult.Missing = &AnalyzePSBTMissing{
					Signatures: len(input.PartialSigs) == 0,
				}
			}

			// Determine next role
			if !hasUTXO {
				inputResult.Next = "updater"
			} else if len(input.PartialSigs) == 0 && len(input.TapKeySig) == 0 {
				inputResult.Next = "signer"
			} else {
				inputResult.Next = "finalizer"
			}
		}

		// Calculate fee if we have UTXO info
		if hasUTXO {
			var utxoValue int64
			if input.WitnessUTXO != nil {
				utxoValue = input.WitnessUTXO.Value
			} else if input.NonWitnessUTXO != nil {
				prevOut := psbt.UnsignedTx.TxIn[i].PreviousOutPoint
				if int(prevOut.Index) < len(input.NonWitnessUTXO.TxOut) {
					utxoValue = input.NonWitnessUTXO.TxOut[prevOut.Index].Value
				}
			}
			totalFee += utxoValue
		}

		inputs[i] = inputResult
	}

	// Subtract outputs from total fee
	for _, out := range psbt.UnsignedTx.TxOut {
		totalFee -= out.Value
	}

	// Determine next role
	next := ""
	if !allComplete {
		// Check all inputs to determine next
		for _, inp := range inputs {
			if !inp.IsFinalized {
				next = inp.Next
				break
			}
		}
	} else {
		next = "extractor"
	}

	result := &AnalyzePSBTResult{
		Inputs:   inputs,
		Next:     next,
		Complete: allComplete,
	}

	// Only include fee if we could calculate it and it's positive
	if totalFee > 0 {
		result.Fee = float64(totalFee) / satoshiPerBitcoin
	}

	return result, nil
}

// handleJoinPSBTs joins multiple PSBTs into one (combining inputs and outputs).
func (s *Server) handleJoinPSBTs(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing PSBTs parameter"}
	}

	psbtsRaw, ok := args[0].([]interface{})
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "PSBTs must be an array"}
	}

	if len(psbtsRaw) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "At least two PSBTs required for join"}
	}

	// Decode all PSBTs
	psbts := make([]*wallet.PSBT, len(psbtsRaw))
	for i, raw := range psbtsRaw {
		str, ok := raw.(string)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid PSBT at index %d", i)}
		}
		psbt, err := wallet.DecodePSBTBase64(str)
		if err != nil {
			return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Failed to decode PSBT %d: %v", i, err)}
		}
		psbts[i] = psbt
	}

	// Create new transaction combining all inputs and outputs
	tx := &wire.MsgTx{
		Version:  2,
		LockTime: 0,
	}

	// Collect all inputs and their PSBT data
	var allInputs []wallet.PSBTInput

	for _, psbt := range psbts {
		for i, in := range psbt.UnsignedTx.TxIn {
			tx.TxIn = append(tx.TxIn, in)
			allInputs = append(allInputs, psbt.Inputs[i])
		}
		for _, out := range psbt.UnsignedTx.TxOut {
			tx.TxOut = append(tx.TxOut, out)
		}
	}

	// Create the joined PSBT
	joined, err := wallet.NewPSBT(tx)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to create joined PSBT: %v", err)}
	}

	// Copy input data
	for i, inp := range allInputs {
		joined.Inputs[i] = inp
	}

	// Encode result
	encoded, err := joined.EncodeBase64()
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to encode PSBT"}
	}

	return encoded, nil
}

// handleUTXOUpdatePSBT updates a PSBT with UTXO information.
func (s *Server) handleUTXOUpdatePSBT(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing PSBT parameter"}
	}

	psbtStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid PSBT string"}
	}

	// Decode PSBT
	psbt, err := wallet.DecodePSBTBase64(psbtStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Failed to decode PSBT: %v", err)}
	}

	// Optional: descriptors array for looking up UTXOs
	// For now, we'll look up UTXOs from the UTXO set if available

	if s.chainMgr != nil && s.chainMgr.UTXOSet() != nil {
		utxoSet := s.chainMgr.UTXOSet()

		for i, in := range psbt.UnsignedTx.TxIn {
			// Skip if already has UTXO info
			if psbt.Inputs[i].WitnessUTXO != nil || psbt.Inputs[i].NonWitnessUTXO != nil {
				continue
			}

			// Look up UTXO
			entry := utxoSet.GetUTXO(in.PreviousOutPoint)
			if entry != nil {
				psbt.Inputs[i].WitnessUTXO = &wire.TxOut{
					Value:    entry.Amount,
					PkScript: entry.PkScript,
				}
			}
		}
	}

	// Encode result
	encoded, err := psbt.EncodeBase64()
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to encode PSBT"}
	}

	return encoded, nil
}

// ============================================================================
// PSBT Result Types
// ============================================================================

// FinalizePSBTResult is the result of finalizepsbt RPC.
type FinalizePSBTResult struct {
	PSBT     string `json:"psbt,omitempty"`
	Hex      string `json:"hex,omitempty"`
	Complete bool   `json:"complete"`
}

// ProcessPSBTResult is the result of walletprocesspsbt RPC.
type ProcessPSBTResult struct {
	PSBT     string `json:"psbt"`
	Complete bool   `json:"complete"`
}

// AnalyzePSBTResult is the result of analyzepsbt RPC.
type AnalyzePSBTResult struct {
	Inputs   []AnalyzePSBTInput `json:"inputs"`
	Fee      float64            `json:"fee,omitempty"`
	Next     string             `json:"next,omitempty"`
	Complete bool               `json:"complete"`
}

// AnalyzePSBTInput is the analysis of a single PSBT input.
type AnalyzePSBTInput struct {
	HasUTXO     bool                `json:"has_utxo"`
	IsFinalized bool                `json:"is_finalized"`
	Missing     *AnalyzePSBTMissing `json:"missing,omitempty"`
	Next        string              `json:"next,omitempty"`
}

// AnalyzePSBTMissing describes what's missing for an input.
type AnalyzePSBTMissing struct {
	Pubkeys    []string `json:"pubkeys,omitempty"`
	Signatures bool     `json:"signatures,omitempty"`
}

// DecodePSBTResult is the result of decodepsbt RPC.
type DecodePSBTResult struct {
	Tx       *TxResult             `json:"tx"`
	GlobalXPubs []DecodePSBTXPub   `json:"global_xpubs,omitempty"`
	Unknown  map[string]string     `json:"unknown,omitempty"`
	Inputs   []DecodePSBTInput     `json:"inputs"`
	Outputs  []DecodePSBTOutput    `json:"outputs"`
	Fee      float64               `json:"fee,omitempty"`
}

// DecodePSBTXPub represents an extended public key in decodepsbt.
type DecodePSBTXPub struct {
	XPub       string `json:"xpub"`
	MasterFP   string `json:"master_fingerprint"`
	Path       string `json:"path"`
}

// DecodePSBTInput represents a decoded PSBT input.
type DecodePSBTInput struct {
	NonWitnessUTXO    *TxResult            `json:"non_witness_utxo,omitempty"`
	WitnessUTXO       *VoutResult          `json:"witness_utxo,omitempty"`
	PartialSignatures map[string]string    `json:"partial_signatures,omitempty"`
	SighashType       string               `json:"sighash,omitempty"`
	RedeemScript      *Script              `json:"redeem_script,omitempty"`
	WitnessScript     *Script              `json:"witness_script,omitempty"`
	BIP32Derivation   []DecodePSBTBIP32    `json:"bip32_derivs,omitempty"`
	FinalScriptSig    *Script              `json:"final_scriptSig,omitempty"`
	FinalScriptWitness []string            `json:"final_scriptwitness,omitempty"`
	TapKeySig         string               `json:"tap_key_sig,omitempty"`
	TapInternalKey    string               `json:"tap_internal_key,omitempty"`
	TapMerkleRoot     string               `json:"tap_merkle_root,omitempty"`
	Unknown           map[string]string    `json:"unknown,omitempty"`
}

// DecodePSBTOutput represents a decoded PSBT output.
type DecodePSBTOutput struct {
	RedeemScript    *Script           `json:"redeem_script,omitempty"`
	WitnessScript   *Script           `json:"witness_script,omitempty"`
	BIP32Derivation []DecodePSBTBIP32 `json:"bip32_derivs,omitempty"`
	TapInternalKey  string            `json:"tap_internal_key,omitempty"`
	Unknown         map[string]string `json:"unknown,omitempty"`
}

// DecodePSBTBIP32 represents BIP32 derivation info.
type DecodePSBTBIP32 struct {
	PubKey            string `json:"pubkey"`
	MasterFingerprint string `json:"master_fingerprint"`
	Path              string `json:"path"`
}

// ============================================================================
// Helper Functions
// ============================================================================

// addressToScript converts an address string to a scriptPubKey.
func addressToScript(addrStr string) ([]byte, error) {
	// This would need to use the address package
	// For now, return an error indicating we need the address package
	return nil, fmt.Errorf("address decoding not implemented in RPC context")
}

// buildDecodePSBTResult builds a DecodePSBTResult from a PSBT.
func buildDecodePSBTResult(psbt *wallet.PSBT) *DecodePSBTResult {
	result := &DecodePSBTResult{
		Tx:      buildTxResult(psbt.UnsignedTx, false),
		Inputs:  make([]DecodePSBTInput, len(psbt.Inputs)),
		Outputs: make([]DecodePSBTOutput, len(psbt.Outputs)),
	}

	// Build inputs
	totalInputValue := int64(0)
	for i, input := range psbt.Inputs {
		inp := DecodePSBTInput{}

		if input.WitnessUTXO != nil {
			totalInputValue += input.WitnessUTXO.Value
			inp.WitnessUTXO = &VoutResult{
				Value: float64(input.WitnessUTXO.Value) / satoshiPerBitcoin,
				N:     0,
				ScriptPubKey: ScriptPubKey{
					Hex: hex.EncodeToString(input.WitnessUTXO.PkScript),
				},
			}
		}

		if input.NonWitnessUTXO != nil {
			inp.NonWitnessUTXO = buildTxResult(input.NonWitnessUTXO, false)
			prevOut := psbt.UnsignedTx.TxIn[i].PreviousOutPoint
			if int(prevOut.Index) < len(input.NonWitnessUTXO.TxOut) {
				totalInputValue += input.NonWitnessUTXO.TxOut[prevOut.Index].Value
			}
		}

		if len(input.PartialSigs) > 0 {
			inp.PartialSignatures = make(map[string]string)
			for pk, sig := range input.PartialSigs {
				inp.PartialSignatures[hex.EncodeToString([]byte(pk))] = hex.EncodeToString(sig)
			}
		}

		if len(input.RedeemScript) > 0 {
			inp.RedeemScript = &Script{Hex: hex.EncodeToString(input.RedeemScript)}
		}

		if len(input.WitnessScript) > 0 {
			inp.WitnessScript = &Script{Hex: hex.EncodeToString(input.WitnessScript)}
		}

		if len(input.FinalScriptSig) > 0 {
			inp.FinalScriptSig = &Script{Hex: hex.EncodeToString(input.FinalScriptSig)}
		}

		if len(input.FinalScriptWitness) > 0 {
			inp.FinalScriptWitness = make([]string, len(input.FinalScriptWitness))
			for j, w := range input.FinalScriptWitness {
				inp.FinalScriptWitness[j] = hex.EncodeToString(w)
			}
		}

		if len(input.TapKeySig) > 0 {
			inp.TapKeySig = hex.EncodeToString(input.TapKeySig)
		}

		if len(input.TapInternalKey) > 0 {
			inp.TapInternalKey = hex.EncodeToString(input.TapInternalKey)
		}

		if len(input.TapMerkleRoot) > 0 {
			inp.TapMerkleRoot = hex.EncodeToString(input.TapMerkleRoot)
		}

		// BIP32 derivations
		if len(input.BIP32Derivation) > 0 {
			for pk, deriv := range input.BIP32Derivation {
				inp.BIP32Derivation = append(inp.BIP32Derivation, DecodePSBTBIP32{
					PubKey:            hex.EncodeToString([]byte(pk)),
					MasterFingerprint: hex.EncodeToString(deriv.Fingerprint[:]),
					Path:              formatBIP32Path(deriv.Path),
				})
			}
		}

		if len(input.Unknown) > 0 {
			inp.Unknown = make(map[string]string)
			for k, v := range input.Unknown {
				inp.Unknown[hex.EncodeToString([]byte(k))] = hex.EncodeToString(v)
			}
		}

		result.Inputs[i] = inp
	}

	// Build outputs
	totalOutputValue := int64(0)
	for i, output := range psbt.Outputs {
		out := DecodePSBTOutput{}

		if i < len(psbt.UnsignedTx.TxOut) {
			totalOutputValue += psbt.UnsignedTx.TxOut[i].Value
		}

		if len(output.RedeemScript) > 0 {
			out.RedeemScript = &Script{Hex: hex.EncodeToString(output.RedeemScript)}
		}

		if len(output.WitnessScript) > 0 {
			out.WitnessScript = &Script{Hex: hex.EncodeToString(output.WitnessScript)}
		}

		if len(output.TapInternalKey) > 0 {
			out.TapInternalKey = hex.EncodeToString(output.TapInternalKey)
		}

		// BIP32 derivations
		if len(output.BIP32Derivation) > 0 {
			for pk, deriv := range output.BIP32Derivation {
				out.BIP32Derivation = append(out.BIP32Derivation, DecodePSBTBIP32{
					PubKey:            hex.EncodeToString([]byte(pk)),
					MasterFingerprint: hex.EncodeToString(deriv.Fingerprint[:]),
					Path:              formatBIP32Path(deriv.Path),
				})
			}
		}

		if len(output.Unknown) > 0 {
			out.Unknown = make(map[string]string)
			for k, v := range output.Unknown {
				out.Unknown[hex.EncodeToString([]byte(k))] = hex.EncodeToString(v)
			}
		}

		result.Outputs[i] = out
	}

	// Calculate fee if we have all UTXO info
	if totalInputValue > 0 && totalOutputValue > 0 {
		fee := totalInputValue - totalOutputValue
		if fee > 0 {
			result.Fee = float64(fee) / satoshiPerBitcoin
		}
	}

	// Global unknowns
	if len(psbt.Unknown) > 0 {
		result.Unknown = make(map[string]string)
		for k, v := range psbt.Unknown {
			result.Unknown[hex.EncodeToString([]byte(k))] = hex.EncodeToString(v)
		}
	}

	return result
}

// formatBIP32Path formats a BIP32 derivation path as a string.
func formatBIP32Path(path []uint32) string {
	if len(path) == 0 {
		return "m"
	}

	result := "m"
	for _, idx := range path {
		if idx >= wallet.HardenedKeyStart {
			result += fmt.Sprintf("/%d'", idx-wallet.HardenedKeyStart)
		} else {
			result += fmt.Sprintf("/%d", idx)
		}
	}
	return result
}

// Ensure base64 is imported for encoding
var _ = base64.StdEncoding
