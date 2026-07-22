package rpc

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/hashhog/blockbrew/internal/address"
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

		// BIP-125 RBF opt-in: nSequence ≤ MAX_BIP125_RBF_SEQUENCE
		// (0xFFFFFFFD). Previously 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL,
		// anti-fee-sniping), which does NOT signal RBF. Comment claimed
		// "Enable RBF by default" but code was off-by-one. Fixed via
		// FIX-61 / W118 BUG-1 ("comment-claims-correct-code-violates-spec"
		// pattern). Reference: BIP-125; bitcoin-core/src/policy/rbf.h.
		sequence := wallet.BIP125RBFSequence
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

	return buildDecodePSBTResultWithNet(psbt, s.getNetwork()), nil
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

	// sighashtype (arg[2], optional, default ALL) — not yet plumbed
	// bip32derivs (arg[3], optional, default true) — not yet plumbed
	// finalize (arg[4], optional, default true): also finalize inputs where
	// possible so `complete` reflects a fully-signed, extractable tx — Core's
	// walletprocesspsbt default (wallet/rpc/spend.cpp:1624, FillPSBT finalize).
	finalize := true
	if len(args) >= 5 {
		if f, ok := args[4].(bool); ok {
			finalize = f
		}
	}

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

	// `complete` mirrors Core: it is true when every input is fully signed and
	// finalizable, NOT merely when the PSBT already carries final witnesses.
	// IsComplete() only reports the latter, so after a signing pass that adds
	// partial signatures it returned false even for a fully-signed single-sig
	// tx — making the caller believe signing failed. Determine finalizability
	// on a decoded COPY (a trial finalize) so `complete` is accurate without
	// mutating the returned PSBT when finalize=false.
	complete := psbt.IsComplete()
	if !complete {
		if b, eerr := psbt.EncodeBase64(); eerr == nil {
			if trial, derr := wallet.DecodePSBTBase64(b); derr == nil {
				if done, ferr := wallet.FinalizePSBT(trial); ferr == nil && done {
					complete = true
				}
			}
		}
	}

	// When finalize is requested (Core default) and the PSBT is complete, return
	// the finalized PSBT (final witnesses in place), matching Core's in-place
	// finalize so a subsequent finalizepsbt/extract sees a ready tx.
	if finalize && complete {
		if _, ferr := wallet.FinalizePSBT(psbt); ferr != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to finalize PSBT: %v", ferr)}
		}
	}

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
		// Core: rpc/rawtransaction.cpp joinpsbts throws RPC_INVALID_PARAMETER (-8).
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "At least two PSBTs are required to join PSBTs."}
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

// buildDecodePSBTResult builds the decodepsbt JSON response as a map[string]any,
// producing output byte-identical (after jq -S normalization) to Bitcoin Core
// 31.99. Uses W52 helpers (decodepsbt_helpers.go) for amount formatting,
// script ASM, descriptor inference, and the embedded tx sub-object.
//
// Key differences from the old struct-based approach:
//   - btcAmount marshals as "1.00000000" not "1" (Core's ValueFromAmount)
//   - global_xpubs always emitted as [] even when empty
//   - proprietary always emitted as []
//   - unknown always emitted as {} even when empty
//   - psbt_version always emitted
//   - tx sub-object built by buildPSBTTxJSON (no hex, proper scriptSig/SPK shape)
func buildDecodePSBTResult(psbt *wallet.PSBT) map[string]any {
	// Use mainnet for address encoding by default; the RPC server will
	// set this correctly when calling via handleDecodePSBT using s.getNetwork().
	// This function is kept network-agnostic for callers that don't have a
	// server reference; callers that do should pass net explicitly.
	return buildDecodePSBTResultWithNet(psbt, address.Mainnet)
}

// buildDecodePSBTResultWithNet is the network-aware version used by
// handleDecodePSBT. Separated so tests can pass a specific network.
func buildDecodePSBTResultWithNet(psbt *wallet.PSBT, net address.Network) map[string]any {
	// ── embedded tx ──────────────────────────────────────────────────────
	txJSON := buildPSBTTxJSON(psbt.UnsignedTx, net)

	// ── per-input PSBT extension records ─────────────────────────────────
	totalInputValue := int64(0)
	inputs := make([]map[string]any, len(psbt.Inputs))
	for i, input := range psbt.Inputs {
		inp := map[string]any{}

		if input.WitnessUTXO != nil {
			inp["witness_utxo"] = map[string]any{
				"amount":       btcAmount(input.WitnessUTXO.Value),
				"scriptPubKey": scriptPubKeyToUniv(input.WitnessUTXO.PkScript, net),
			}
		}

		if input.NonWitnessUTXO != nil {
			inp["non_witness_utxo"] = buildPSBTTxJSON(input.NonWitnessUTXO, net)
			prevOut := psbt.UnsignedTx.TxIn[i].PreviousOutPoint
			if int(prevOut.Index) < len(input.NonWitnessUTXO.TxOut) {
				totalInputValue += input.NonWitnessUTXO.TxOut[prevOut.Index].Value
			}
		} else if input.WitnessUTXO != nil {
			// Use witness_utxo for fee calculation only when non_witness_utxo
			// is absent. Mirrors Core's rawtransaction.cpp fee calculation:
			// non_witness_utxo takes precedence when both are present.
			totalInputValue += input.WitnessUTXO.Value
		}

		if len(input.PartialSigs) > 0 {
			partialSigs := map[string]any{}
			for pk, sig := range input.PartialSigs {
				partialSigs[hex.EncodeToString([]byte(pk))] = hex.EncodeToString(sig)
			}
			inp["partial_signatures"] = partialSigs
		}

		// PSBT_IN_SIGHASH_TYPE (0x03): emit as string when present (non-zero).
		// Core: SighashToStr(sighash_type) — see core_io.cpp:343 and
		// rpc/rawtransaction.cpp:1166. Unknown values emit "".
		if input.SighashType != 0 {
			inp["sighash"] = sighashToStr(input.SighashType)
		}

		if len(input.RedeemScript) > 0 {
			inp["redeem_script"] = map[string]any{
				"asm":  scriptToAsmStr(input.RedeemScript, false),
				"hex":  hex.EncodeToString(input.RedeemScript),
				"type": scriptTypeName(input.RedeemScript),
			}
		}

		if len(input.WitnessScript) > 0 {
			inp["witness_script"] = map[string]any{
				"asm":  scriptToAsmStr(input.WitnessScript, false),
				"hex":  hex.EncodeToString(input.WitnessScript),
				"type": scriptTypeName(input.WitnessScript),
			}
		}

		if len(input.BIP32Derivation) > 0 {
			bip32s := make([]map[string]any, 0, len(input.BIP32Derivation))
			for pk, deriv := range input.BIP32Derivation {
				bip32s = append(bip32s, map[string]any{
					"pubkey":             hex.EncodeToString([]byte(pk)),
					"master_fingerprint": hex.EncodeToString(deriv.Fingerprint[:]),
					"path":               formatBIP32Path(deriv.Path),
				})
			}
			inp["bip32_derivs"] = bip32s
		}

		if len(input.FinalScriptSig) > 0 {
			inp["final_scriptSig"] = map[string]any{
				"asm": scriptToAsmStr(input.FinalScriptSig, true),
				"hex": hex.EncodeToString(input.FinalScriptSig),
			}
		}

		if len(input.FinalScriptWitness) > 0 {
			witness := make([]string, len(input.FinalScriptWitness))
			for j, w := range input.FinalScriptWitness {
				witness[j] = hex.EncodeToString(w)
			}
			inp["final_scriptwitness"] = witness
		}

		// BIP-371 taproot input fields — field names must match Core's
		// rpc/rawtransaction.cpp:1251-1313 exactly.
		if len(input.TapKeySig) > 0 {
			inp["taproot_key_path_sig"] = hex.EncodeToString(input.TapKeySig)
		}

		// taproot_script_path_sigs: array of {pubkey, leaf_hash, sig}
		if len(input.TapScriptSigs) > 0 {
			scriptSigs := make([]map[string]any, 0, len(input.TapScriptSigs))
			for sigKey, sig := range input.TapScriptSigs {
				scriptSigs = append(scriptSigs, map[string]any{
					"pubkey":    hex.EncodeToString(sigKey.XOnlyPubKey[:]),
					"leaf_hash": hex.EncodeToString(sigKey.LeafHash[:]),
					"sig":       hex.EncodeToString(sig),
				})
			}
			inp["taproot_script_path_sigs"] = scriptSigs
		}

		// taproot_scripts: group TapLeafScripts by (script, leaf_ver) →
		// collecting all control_blocks for the same leaf. Mirrors Core's
		// std::map<std::pair<CScript,int>,std::set<std::vector<unsigned char>>>
		// m_tap_scripts. (rpc/rawtransaction.cpp:1271-1283)
		if len(input.TapLeafScripts) > 0 {
			type leafKey struct {
				script  string
				leafVer byte
			}
			// Use insertion order via a slice of unique keys.
			seenLeaves := make(map[leafKey]int) // key → index in tapScripts
			tapScripts := make([]map[string]any, 0)
			for _, leaf := range input.TapLeafScripts {
				k := leafKey{script: string(leaf.Script), leafVer: leaf.LeafVersion}
				if idx, found := seenLeaves[k]; found {
					// Append control block to existing entry
					existing := tapScripts[idx]["control_blocks"].([]string)
					tapScripts[idx]["control_blocks"] = append(existing, hex.EncodeToString(leaf.ControlBlock))
				} else {
					seenLeaves[k] = len(tapScripts)
					tapScripts = append(tapScripts, map[string]any{
						"script":         hex.EncodeToString(leaf.Script),
						"leaf_ver":       int(leaf.LeafVersion),
						"control_blocks": []string{hex.EncodeToString(leaf.ControlBlock)},
					})
				}
			}
			inp["taproot_scripts"] = tapScripts
		}

		// taproot_bip32_derivs: array of {pubkey, master_fingerprint, path, leaf_hashes[]}
		if len(input.TapBIP32Derivation) > 0 {
			tapBip32s := make([]map[string]any, 0, len(input.TapBIP32Derivation))
			for pk, deriv := range input.TapBIP32Derivation {
				leafHashes := make([]string, 0, len(deriv.LeafHashes))
				for _, h := range deriv.LeafHashes {
					leafHashes = append(leafHashes, hex.EncodeToString(h[:]))
				}
				tapBip32s = append(tapBip32s, map[string]any{
					"pubkey":             hex.EncodeToString([]byte(pk)),
					"master_fingerprint": hex.EncodeToString(deriv.Fingerprint[:]),
					"path":               formatBIP32Path(deriv.Path),
					"leaf_hashes":        leafHashes,
				})
			}
			inp["taproot_bip32_derivs"] = tapBip32s
		}

		if len(input.TapInternalKey) > 0 {
			inp["taproot_internal_key"] = hex.EncodeToString(input.TapInternalKey)
		}
		if len(input.TapMerkleRoot) > 0 {
			inp["taproot_merkle_root"] = hex.EncodeToString(input.TapMerkleRoot)
		}

		if len(input.Unknown) > 0 {
			unk := map[string]any{}
			for k, v := range input.Unknown {
				unk[hex.EncodeToString([]byte(k))] = hex.EncodeToString(v)
			}
			inp["unknown"] = unk
		}

		inputs[i] = inp
	}

	// ── per-output PSBT extension records ────────────────────────────────
	totalOutputValue := int64(0)
	outputs := make([]map[string]any, len(psbt.Outputs))
	for i, output := range psbt.Outputs {
		out := map[string]any{}

		if i < len(psbt.UnsignedTx.TxOut) {
			totalOutputValue += psbt.UnsignedTx.TxOut[i].Value
		}

		if len(output.RedeemScript) > 0 {
			out["redeem_script"] = map[string]any{
				"asm":  scriptToAsmStr(output.RedeemScript, false),
				"hex":  hex.EncodeToString(output.RedeemScript),
				"type": scriptTypeName(output.RedeemScript),
			}
		}

		if len(output.WitnessScript) > 0 {
			out["witness_script"] = map[string]any{
				"asm":  scriptToAsmStr(output.WitnessScript, false),
				"hex":  hex.EncodeToString(output.WitnessScript),
				"type": scriptTypeName(output.WitnessScript),
			}
		}

		if len(output.BIP32Derivation) > 0 {
			bip32s := make([]map[string]any, 0, len(output.BIP32Derivation))
			for pk, deriv := range output.BIP32Derivation {
				bip32s = append(bip32s, map[string]any{
					"pubkey":             hex.EncodeToString([]byte(pk)),
					"master_fingerprint": hex.EncodeToString(deriv.Fingerprint[:]),
					"path":               formatBIP32Path(deriv.Path),
				})
			}
			out["bip32_derivs"] = bip32s
		}

		// BIP-371 output taproot fields — field names match Core's
		// rpc/rawtransaction.cpp:1421-1453 exactly.
		if len(output.TapInternalKey) > 0 {
			out["taproot_internal_key"] = hex.EncodeToString(output.TapInternalKey)
		}

		// taproot_tree: array of {depth, leaf_ver, script}
		if len(output.TapTree) > 0 {
			tree := make([]map[string]any, 0, len(output.TapTree))
			for _, leaf := range output.TapTree {
				tree = append(tree, map[string]any{
					"depth":    int(leaf.Depth),
					"leaf_ver": int(leaf.LeafVersion),
					"script":   hex.EncodeToString(leaf.Script),
				})
			}
			out["taproot_tree"] = tree
		}

		// taproot_bip32_derivs: array of {pubkey, master_fingerprint, path, leaf_hashes[]}
		if len(output.TapBIP32Derivation) > 0 {
			tapBip32s := make([]map[string]any, 0, len(output.TapBIP32Derivation))
			for pk, deriv := range output.TapBIP32Derivation {
				leafHashes := make([]string, 0, len(deriv.LeafHashes))
				for _, h := range deriv.LeafHashes {
					leafHashes = append(leafHashes, hex.EncodeToString(h[:]))
				}
				tapBip32s = append(tapBip32s, map[string]any{
					"pubkey":             hex.EncodeToString([]byte(pk)),
					"master_fingerprint": hex.EncodeToString(deriv.Fingerprint[:]),
					"path":               formatBIP32Path(deriv.Path),
					"leaf_hashes":        leafHashes,
				})
			}
			out["taproot_bip32_derivs"] = tapBip32s
		}

		// musig2_participant_pubkeys: array of {aggregate_pubkey, participant_pubkeys[]}
		if len(output.MuSig2Participants) > 0 {
			musigArr := make([]map[string]any, 0, len(output.MuSig2Participants))
			for _, entry := range output.MuSig2Participants {
				parts := make([]string, 0, len(entry.ParticipantPubkeys))
				for _, p := range entry.ParticipantPubkeys {
					parts = append(parts, hex.EncodeToString(p))
				}
				musigArr = append(musigArr, map[string]any{
					"aggregate_pubkey":   hex.EncodeToString(entry.AggregatePubkey),
					"participant_pubkeys": parts,
				})
			}
			out["musig2_participant_pubkeys"] = musigArr
		}

		if len(output.Unknown) > 0 {
			unk := map[string]any{}
			for k, v := range output.Unknown {
				unk[hex.EncodeToString([]byte(k))] = hex.EncodeToString(v)
			}
			out["unknown"] = unk
		}

		outputs[i] = out
	}

	// ── fee ──────────────────────────────────────────────────────────────
	// Core emits "fee" only when all UTXOs are present and the fee is
	// non-negative.
	var feeVal any = nil
	if totalInputValue > 0 && totalOutputValue > 0 {
		fee := totalInputValue - totalOutputValue
		if fee >= 0 {
			feeVal = btcAmount(fee)
		}
	}

	// ── global_xpubs ─────────────────────────────────────────────────────
	// Core always emits global_xpubs as an array (empty when none). The
	// PSBT stores xpubs as XPubs map[string][]byte (raw key bytes →
	// fingerprint+path blob). The W50/W52 corpus entries contain no
	// global xpubs, so we emit [] for all of them. Full xpub decoding
	// (BIP-32 serialization, derivation-path parsing) is deferred to W53.
	globalXPubs := make([]any, 0)

	// ── global_unknown / proprietary ─────────────────────────────────────
	// Core always emits unknown as {} and proprietary as [].
	globalUnknown := map[string]any{}
	for k, v := range psbt.Unknown {
		globalUnknown[hex.EncodeToString([]byte(k))] = hex.EncodeToString(v)
	}

	result := map[string]any{
		"tx":           txJSON,
		"global_xpubs": globalXPubs,
		"psbt_version": psbt.Version,
		"proprietary":  []any{},
		"unknown":      globalUnknown,
		"inputs":       inputs,
		"outputs":      outputs,
	}
	if feeVal != nil {
		result["fee"] = feeVal
	}

	return result
}

// formatBIP32Path formats a BIP32 derivation path as a string, matching
// Bitcoin Core's WriteHDKeypath (util/bip32.cpp:61). Core defaults to 'h'
// for hardened derivation (apostrophe=false) e.g. "m/84h/1h/0h/0/0".
func formatBIP32Path(path []uint32) string {
	if len(path) == 0 {
		return "m"
	}

	result := "m"
	for _, idx := range path {
		if idx >= wallet.HardenedKeyStart {
			result += fmt.Sprintf("/%dh", idx-wallet.HardenedKeyStart)
		} else {
			result += fmt.Sprintf("/%d", idx)
		}
	}
	return result
}

// Ensure base64 is imported for encoding
var _ = base64.StdEncoding
