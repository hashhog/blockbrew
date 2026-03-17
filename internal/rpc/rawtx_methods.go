package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// createrawtransaction RPC
// ============================================================================

// CreateRawTransactionInput represents an input for createrawtransaction.
type CreateRawTransactionInput struct {
	TxID     string `json:"txid"`
	Vout     uint32 `json:"vout"`
	Sequence uint32 `json:"sequence,omitempty"`
}

func (s *Server) handleCreateRawTransaction(params json.RawMessage) (interface{}, *RPCError) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing required parameters: inputs and outputs"}
	}

	// Parse inputs array
	var inputs []CreateRawTransactionInput
	if err := json.Unmarshal(args[0], &inputs); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid inputs array"}
	}

	// Parse outputs - can be array of objects or single object
	var outputs []map[string]interface{}
	// First try parsing as array
	if err := json.Unmarshal(args[1], &outputs); err != nil {
		// Try single object format
		var singleOutput map[string]interface{}
		if err := json.Unmarshal(args[1], &singleOutput); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid outputs"}
		}
		outputs = []map[string]interface{}{singleOutput}
	}

	// Parse optional locktime
	locktime := uint32(0)
	if len(args) >= 3 {
		var lt float64
		if err := json.Unmarshal(args[2], &lt); err == nil {
			locktime = uint32(lt)
		}
	}

	// Parse optional replaceable flag
	replaceable := false
	if len(args) >= 4 {
		if err := json.Unmarshal(args[3], &replaceable); err != nil {
			// Try parsing as bool directly
			var r bool
			if err := json.Unmarshal(args[3], &r); err == nil {
				replaceable = r
			}
		}
	}

	// Get network from chain params
	net := address.Mainnet
	if s.chainParams != nil {
		switch s.chainParams.Name {
		case "testnet", "testnet3", "testnet4":
			net = address.Testnet
		case "regtest":
			net = address.Regtest
		case "signet":
			net = address.Signet
		}
	}

	// Build the transaction
	tx := &wire.MsgTx{
		Version:  2,
		LockTime: locktime,
	}

	// Add inputs
	for _, in := range inputs {
		txid, err := wire.NewHash256FromHex(in.TxID)
		if err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid txid: %s", in.TxID)}
		}

		sequence := in.Sequence
		if sequence == 0 {
			if replaceable {
				// BIP125: signal RBF with sequence < 0xFFFFFFFE
				sequence = 0xFFFFFFFD
			} else {
				sequence = 0xFFFFFFFF
			}
		}

		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  txid,
				Index: in.Vout,
			},
			Sequence: sequence,
		})
	}

	// Add outputs
	for _, out := range outputs {
		for key, val := range out {
			if key == "data" {
				// OP_RETURN output
				dataStr, ok := val.(string)
				if !ok {
					return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid data value"}
				}
				data, err := hex.DecodeString(dataStr)
				if err != nil {
					return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid data hex"}
				}
				if len(data) > 80 {
					return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Data exceeds OP_RETURN limit (80 bytes)"}
				}

				// Build OP_RETURN script: OP_RETURN <data>
				pkScript := make([]byte, 0, 2+len(data))
				pkScript = append(pkScript, 0x6a) // OP_RETURN
				if len(data) <= 75 {
					pkScript = append(pkScript, byte(len(data)))
				} else {
					pkScript = append(pkScript, 0x4c) // OP_PUSHDATA1
					pkScript = append(pkScript, byte(len(data)))
				}
				pkScript = append(pkScript, data...)

				tx.TxOut = append(tx.TxOut, &wire.TxOut{
					Value:    0,
					PkScript: pkScript,
				})
			} else {
				// Address output
				amount, ok := val.(float64)
				if !ok {
					return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid amount for address %s", key)}
				}

				satoshis := int64(math.Round(amount * satoshiPerBitcoin))
				if satoshis < 0 {
					return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Negative amount"}
				}

				addr, err := address.DecodeAddress(key, net)
				if err != nil {
					return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid address: %s", key)}
				}

				tx.TxOut = append(tx.TxOut, &wire.TxOut{
					Value:    satoshis,
					PkScript: addr.ScriptPubKey(),
				})
			}
		}
	}

	// Serialize the transaction
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to serialize transaction: %v", err)}
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

// ============================================================================
// testmempoolaccept RPC
// ============================================================================

// TestMempoolAcceptResult is the result for a single transaction.
type TestMempoolAcceptResult struct {
	TxID         string   `json:"txid"`
	WTxID        string   `json:"wtxid,omitempty"`
	Allowed      bool     `json:"allowed"`
	VSize        int64    `json:"vsize,omitempty"`
	Fees         *FeeInfo `json:"fees,omitempty"`
	RejectReason string   `json:"reject-reason,omitempty"`
}

// FeeInfo contains fee information for testmempoolaccept.
type FeeInfo struct {
	Base float64 `json:"base"`
}

func (s *Server) handleTestMempoolAccept(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing rawtxs parameter"}
	}

	// Parse raw transactions array
	rawTxsArg, ok := args[0].([]interface{})
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "rawtxs must be an array"}
	}

	// Parse optional maxfeerate (BTC/kvB)
	maxFeeRate := 0.10 // Default: 0.10 BTC/kvB
	if len(args) >= 2 {
		if mfr, ok := args[1].(float64); ok {
			maxFeeRate = mfr
		}
	}

	if s.mempool == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	results := make([]*TestMempoolAcceptResult, 0, len(rawTxsArg))

	for _, rawTxInterface := range rawTxsArg {
		rawTxHex, ok := rawTxInterface.(string)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid transaction hex"}
		}

		result := &TestMempoolAcceptResult{}

		// Decode the transaction
		txBytes, err := hex.DecodeString(rawTxHex)
		if err != nil {
			result.Allowed = false
			result.RejectReason = "invalid-hex"
			results = append(results, result)
			continue
		}

		tx := &wire.MsgTx{}
		if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
			result.Allowed = false
			result.RejectReason = "decode-error"
			results = append(results, result)
			continue
		}

		txHash := tx.TxHash()
		result.TxID = txHash.String()
		if tx.HasWitness() {
			result.WTxID = tx.WTxHash().String()
		}

		// Check if already in mempool
		if s.mempool.HasTransaction(txHash) {
			result.Allowed = false
			result.RejectReason = "txn-already-in-mempool"
			results = append(results, result)
			continue
		}

		// Basic sanity check
		if err := consensus.CheckTransactionSanity(tx); err != nil {
			result.Allowed = false
			result.RejectReason = fmt.Sprintf("bad-txns-sanity: %v", err)
			results = append(results, result)
			continue
		}

		// Reject coinbase
		if consensus.IsCoinbaseTx(tx) {
			result.Allowed = false
			result.RejectReason = "bad-txns-coinbase"
			results = append(results, result)
			continue
		}

		// Calculate vsize
		weight := consensus.CalcTxWeight(tx)
		vsize := (weight + 3) / 4

		// Check weight limit
		if weight > consensus.MaxStandardTxWeight {
			result.Allowed = false
			result.RejectReason = "tx-size"
			results = append(results, result)
			continue
		}

		// Calculate fee by looking up inputs
		var totalInputValue int64
		inputsFound := true
		for _, txIn := range tx.TxIn {
			// Check UTXO set
			if s.chainMgr != nil {
				utxo := s.chainMgr.UTXOSet().GetUTXO(txIn.PreviousOutPoint)
				if utxo != nil {
					totalInputValue += utxo.Amount
					continue
				}
			}
			// Check mempool
			mempoolUtxo := s.mempool.GetUTXO(txIn.PreviousOutPoint)
			if mempoolUtxo != nil {
				totalInputValue += mempoolUtxo.Amount
				continue
			}
			inputsFound = false
			break
		}

		if !inputsFound {
			result.Allowed = false
			result.RejectReason = "missing-inputs"
			results = append(results, result)
			continue
		}

		var totalOutputValue int64
		for _, txOut := range tx.TxOut {
			totalOutputValue += txOut.Value
		}

		fee := totalInputValue - totalOutputValue
		if fee < 0 {
			result.Allowed = false
			result.RejectReason = "bad-txns-in-belowout"
			results = append(results, result)
			continue
		}

		// Check fee rate against minimum
		feeRate := float64(fee) / float64(vsize) * 1000 // sat/kvB
		minFeeRate := s.mempool.GetMinFeeRate()
		if int64(feeRate) < minFeeRate {
			result.Allowed = false
			result.RejectReason = "min-fee-not-met"
			results = append(results, result)
			continue
		}

		// Check against maxfeerate
		feeRateBTC := float64(fee) / float64(vsize) / satoshiPerBitcoin * 1000 // BTC/kvB
		if maxFeeRate > 0 && feeRateBTC > maxFeeRate {
			result.Allowed = false
			result.RejectReason = "max-fee-exceeded"
			results = append(results, result)
			continue
		}

		// Transaction passed validation
		result.Allowed = true
		result.VSize = vsize
		result.Fees = &FeeInfo{
			Base: float64(fee) / satoshiPerBitcoin,
		}
		results = append(results, result)
	}

	return results, nil
}

// ============================================================================
// disconnectnode RPC
// ============================================================================

func (s *Server) handleDisconnectNode(params json.RawMessage) (interface{}, *RPCError) {
	if s.peerMgr == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "P2P manager not available"}
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		// Try parsing as named parameters
		var namedParams struct {
			Address string  `json:"address"`
			NodeID  float64 `json:"nodeid"`
		}
		if err := json.Unmarshal(params, &namedParams); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}

		if namedParams.Address != "" {
			return s.disconnectByAddress(namedParams.Address)
		}
		if namedParams.NodeID > 0 {
			return s.disconnectByNodeID(int(namedParams.NodeID))
		}
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Either address or nodeid must be specified"}
	}

	// Positional parameters
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing address or nodeid parameter"}
	}

	// Check if first arg is address (string) or nodeid (number)
	switch v := args[0].(type) {
	case string:
		if v == "" {
			// Check if nodeid is provided
			if len(args) >= 2 {
				if nodeID, ok := args[1].(float64); ok {
					return s.disconnectByNodeID(int(nodeID))
				}
			}
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Address is empty and no nodeid provided"}
		}
		return s.disconnectByAddress(v)
	case float64:
		return s.disconnectByNodeID(int(v))
	default:
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameter type"}
	}
}

func (s *Server) disconnectByAddress(addr string) (interface{}, *RPCError) {
	peer := s.peerMgr.GetPeer(addr)
	if peer == nil {
		return nil, &RPCError{Code: RPCErrClientNodeNotConnected, Message: fmt.Sprintf("Node not found: %s", addr)}
	}

	peer.Disconnect()
	return nil, nil
}

func (s *Server) disconnectByNodeID(nodeID int) (interface{}, *RPCError) {
	peers := s.peerMgr.ConnectedPeers()
	if nodeID < 0 || nodeID >= len(peers) {
		return nil, &RPCError{Code: RPCErrClientNodeNotConnected, Message: fmt.Sprintf("Node not found with id: %d", nodeID)}
	}

	peers[nodeID].Disconnect()
	return nil, nil
}

// ============================================================================
// signrawtransactionwithwallet RPC
// ============================================================================

// SignRawTransactionResult is the result of signrawtransactionwithwallet.
type SignRawTransactionResult struct {
	Hex      string                  `json:"hex"`
	Complete bool                    `json:"complete"`
	Errors   []SignRawTransactionErr `json:"errors,omitempty"`
}

// SignRawTransactionErr describes an error signing an input.
type SignRawTransactionErr struct {
	TxID      string `json:"txid"`
	Vout      uint32 `json:"vout"`
	ScriptSig string `json:"scriptSig"`
	Sequence  uint32 `json:"sequence"`
	Error     string `json:"error"`
}

// PrevTx describes a previous transaction output for signing.
type PrevTx struct {
	TxID          string `json:"txid"`
	Vout          uint32 `json:"vout"`
	ScriptPubKey  string `json:"scriptPubKey"`
	RedeemScript  string `json:"redeemScript,omitempty"`
	WitnessScript string `json:"witnessScript,omitempty"`
	Amount        float64 `json:"amount,omitempty"`
}

func (s *Server) handleSignRawTransactionWithWallet(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	// Get wallet
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing hexstring parameter"}
	}

	hexStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid hexstring"}
	}

	// Parse optional prevtxs
	var prevTxs []PrevTx
	if len(args) >= 2 && args[1] != nil {
		prevTxsData, err := json.Marshal(args[1])
		if err == nil {
			json.Unmarshal(prevTxsData, &prevTxs)
		}
	}

	// Parse optional sighashtype (default: "ALL")
	sighashType := "ALL"
	if len(args) >= 3 {
		if st, ok := args[2].(string); ok {
			sighashType = st
		}
	}

	// Validate sighash type
	validSighashTypes := map[string]bool{
		"ALL": true, "NONE": true, "SINGLE": true,
		"ALL|ANYONECANPAY": true, "NONE|ANYONECANPAY": true, "SINGLE|ANYONECANPAY": true,
	}
	if !validSighashTypes[sighashType] {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid sighash type: %s", sighashType)}
	}

	// Decode the transaction
	txBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Invalid transaction hex"}
	}

	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Transaction decode failed: %v", err)}
	}

	// Build a map of prevtxs for quick lookup
	prevTxMap := make(map[wire.OutPoint]PrevTx)
	for _, ptx := range prevTxs {
		hash, err := wire.NewHash256FromHex(ptx.TxID)
		if err != nil {
			continue
		}
		prevTxMap[wire.OutPoint{Hash: hash, Index: ptx.Vout}] = ptx
	}

	// Try to sign with wallet
	// Note: Current wallet.SignTransaction only handles P2WPKH
	// We'll extend the result to track partial/failed signatures
	var signErrors []SignRawTransactionErr

	err = w.SignTransaction(tx)
	complete := err == nil

	if err != nil {
		// Add errors for inputs we couldn't sign
		for i, txIn := range tx.TxIn {
			// Check if this input has witness data (signed)
			if len(txIn.Witness) == 0 && len(txIn.SignatureScript) == 0 {
				signErrors = append(signErrors, SignRawTransactionErr{
					TxID:      txIn.PreviousOutPoint.Hash.String(),
					Vout:      txIn.PreviousOutPoint.Index,
					ScriptSig: hex.EncodeToString(txIn.SignatureScript),
					Sequence:  txIn.Sequence,
					Error:     fmt.Sprintf("Unable to sign input %d: %v", i, err),
				})
			}
		}
	}

	// Serialize the result
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to serialize transaction: %v", err)}
	}

	result := &SignRawTransactionResult{
		Hex:      hex.EncodeToString(buf.Bytes()),
		Complete: complete,
	}
	if len(signErrors) > 0 {
		result.Errors = signErrors
	}

	return result, nil
}

// ============================================================================
// importdescriptors RPC
// ============================================================================

// ImportDescriptorRequest is a single descriptor import request.
type ImportDescriptorRequest struct {
	Desc      string `json:"desc"`
	Active    bool   `json:"active,omitempty"`
	Range     []int  `json:"range,omitempty"`
	NextIndex int    `json:"next_index,omitempty"`
	Timestamp interface{} `json:"timestamp"` // "now" or unix timestamp
	Internal  bool   `json:"internal,omitempty"`
	Label     string `json:"label,omitempty"`
}

// ImportDescriptorResult is the result of importing a single descriptor.
type ImportDescriptorResult struct {
	Success  bool     `json:"success"`
	Warnings []string `json:"warnings,omitempty"`
	Error    *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (s *Server) handleImportDescriptors(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	// Get wallet
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}
	_ = w // We'll need to implement descriptor import in the wallet

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing requests parameter"}
	}

	// Parse the requests array
	requestsData, err := json.Marshal(args[0])
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid requests array"}
	}

	var requests []ImportDescriptorRequest
	if err := json.Unmarshal(requestsData, &requests); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Failed to parse requests"}
	}

	// Get network
	net := address.Mainnet
	if s.chainParams != nil {
		switch s.chainParams.Name {
		case "testnet", "testnet3", "testnet4":
			net = address.Testnet
		case "regtest":
			net = address.Regtest
		case "signet":
			net = address.Signet
		}
	}

	results := make([]*ImportDescriptorResult, 0, len(requests))

	for _, req := range requests {
		result := &ImportDescriptorResult{}

		// Parse and validate the descriptor using package-level function
		desc, err := wallet.ParseDescriptor(req.Desc, net)
		if err != nil {
			result.Success = false
			result.Error = &struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}{
				Code:    RPCErrInvalidParams,
				Message: fmt.Sprintf("Invalid descriptor: %v", err),
			}
			results = append(results, result)
			continue
		}

		// Import the descriptor into the wallet
		err = w.ImportDescriptor(desc, req.Active, req.Internal, req.Label)
		if err != nil {
			result.Success = false
			result.Error = &struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}{
				Code:    RPCErrWallet,
				Message: fmt.Sprintf("Failed to import descriptor: %v", err),
			}
			results = append(results, result)
			continue
		}

		// If range is specified, expand the descriptor for those indices
		if len(req.Range) > 0 {
			start := 0
			end := 1000 // default lookahead
			if len(req.Range) >= 1 {
				end = req.Range[0]
			}
			if len(req.Range) >= 2 {
				start = req.Range[0]
				end = req.Range[1]
			}

			for i := start; i <= end; i++ {
				_, err := desc.Expand(uint32(i))
				if err != nil {
					result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to expand index %d: %v", i, err))
				}
			}
		}

		result.Success = true
		results = append(results, result)
	}

	return results, nil
}
