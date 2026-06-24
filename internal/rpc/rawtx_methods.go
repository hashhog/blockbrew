package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
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
// combinerawtransaction RPC
// ============================================================================

// handleCombineRawTransaction combines multiple partially-signed versions of
// the SAME transaction into one carrying the union of their signature data.
//
// Reference: Bitcoin Core rpc/rawtransaction.cpp combinerawtransaction (impl
// body 605-668). Each element of the (single, required) array param is a
// hex-encoded raw tx with the SAME inputs/outputs/version/locktime but
// DIFFERENT partial signatures. The first variant is the structural template;
// per input we merge the scriptSig + witness across all variants and write the
// combined result back. Returns the witness-serialized hex as a bare JSON
// string.
//
// MERGE SCOPE (single-sig parity, the dominant case — identical to the
// ouroboros reference, committed f4c98ee): for the common/realistic case where
// each variant carries a COMPLETE single-key signature for a DIFFERENT subset
// of inputs (or one variant is unsigned), we take, per input, the non-empty
// (signed) scriptSig + witness. This is BYTE-IDENTICAL to Core for single-sig
// inputs (P2PKH / P2WPKH / P2SH-P2WPKH), because Core's DataFromTransaction
// returns the variant's scriptSig + scriptWitness verbatim once VerifyScript
// marks the input complete, and MergeSignatureData adopts that complete sigdata
// wholesale.
//
// KNOWN LIMITATION (flagged, not faked): the FULL Core behavior also merges
// PARTIAL multisig signatures WITHIN a single input — two variants each holding
// one of M sigs for a bare/P2SH/P2WSH M-of-N — via SignatureData::Merge over
// the extracted (pubkey -> sig) map. That needs Solver / a VerifyScript with a
// signature-extracting checker / sighash validation, which this handler does
// NOT implement. For an input that is partially signed in BOTH variants
// (neither alone complete) we keep the longer (more-signatures) of the two
// scriptSigs rather than splicing the two sig sets together; the output for
// that input is therefore NOT guaranteed byte-identical to Core.
//
// DEVIATION (flagged): Core resolves every input's prevout from its own UTXO +
// mempool CCoinsViewCache and throws RPC_VERIFY_ERROR (-25) "Input not found or
// already spent" when a coin is missing/spent. This handler does NOT consult
// chainstate — combine is a pure function of the provided variants here — so it
// does NOT raise -25 for unresolvable prevouts. The -22 empty / -22
// decode-failure / -3 non-array error paths DO match Core byte-for-byte.
func (s *Server) handleCombineRawTransaction(params json.RawMessage) (interface{}, *RPCError) {
	// Core: UniValue txs = request.params[0].get_array(); a non-array (or a
	// missing param) is a JSON type error from get_array(). We accept the
	// positional-args envelope and require the first element to be an array.
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &RPCError{Code: RPCErrTypeError, Message: "Expected type array, got null"}
	}

	var txsRaw []interface{}
	if err := json.Unmarshal(args[0], &txsRaw); err != nil {
		// Not an array — mirror Core's get_array() type error (-3). Report the
		// actual JSON type seen, as Core's UniValue::get_array() does.
		var any interface{}
		_ = json.Unmarshal(args[0], &any)
		return nil, &RPCError{
			Code:    RPCErrTypeError,
			Message: fmt.Sprintf("Expected type array, got %s", jsonTypeName(any)),
		}
	}

	// 1. Decode every variant (witness-aware). Core: DecodeHexTx per idx; on
	//    failure -> -22 "TX decode failed for tx %d. Make sure the tx has at
	//    least one input." (0-based idx).
	variants := make([]*wire.MsgTx, 0, len(txsRaw))
	for idx, item := range txsRaw {
		// Core reads each element with .get_str() -> a non-string element is a
		// type error before the body's decode runs.
		hexStr, ok := item.(string)
		if !ok {
			return nil, &RPCError{
				Code:    RPCErrTypeError,
				Message: fmt.Sprintf("JSON value of type %s is not of expected type string", jsonTypeName(item)),
			}
		}
		tx, decErr := decodeCombineVariant(hexStr)
		if decErr != nil {
			return nil, &RPCError{
				Code:    RPCErrDeserialization,
				Message: fmt.Sprintf("TX decode failed for tx %d. Make sure the tx has at least one input.", idx),
			}
		}
		variants = append(variants, tx)
	}

	// 2. Empty array -> -22 "Missing transactions". (Core: txVariants.empty().)
	if len(variants) == 0 {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Missing transactions"}
	}

	// 3. mergedTx starts as a clone of the first variant (the template: its
	//    version / locktime / vin / vout define the result; only each input's
	//    scriptSig + witness get rebuilt below).
	template := variants[0]
	merged := &wire.MsgTx{
		Version:  template.Version,
		LockTime: template.LockTime,
		TxIn:     make([]*wire.TxIn, 0, len(template.TxIn)),
		TxOut:    make([]*wire.TxOut, len(template.TxOut)),
	}
	copy(merged.TxOut, template.TxOut)

	for i := range template.TxIn {
		base := template.TxIn[i]
		var bestScriptSig []byte
		var bestWitness [][]byte
		bestScore := -1 // rank candidates; higher = more complete

		for _, variant := range variants {
			if i >= len(variant.TxIn) {
				continue
			}
			vin := variant.TxIn[i]
			ss := vin.SignatureScript
			wit := vin.Witness

			ssNonempty := len(ss) > 0
			witNonempty := false
			for _, w := range wit {
				if len(w) > 0 {
					witNonempty = true
					break
				}
			}

			// Score the candidate so we deterministically prefer the variant
			// that actually carries signature data for this input. Tie-break by
			// total signature-data length (longer = more sigs, matching the
			// partial-multisig fallback note above). Equal length -> keep the
			// earliest variant (Core's merge is order-stable for the complete
			// single-sig case).
			var score int
			if !ssNonempty && !witNonempty {
				score = 0
			} else {
				sigLen := len(ss)
				for _, w := range wit {
					sigLen += len(w)
				}
				score = 1000000 + sigLen
			}

			if score > bestScore {
				bestScore = score
				bestScriptSig = ss
				if len(wit) > 0 {
					bestWitness = wit
				} else {
					bestWitness = nil
				}
			}
		}

		merged.TxIn = append(merged.TxIn, &wire.TxIn{
			PreviousOutPoint: base.PreviousOutPoint,
			SignatureScript:  bestScriptSig,
			Sequence:         base.Sequence,
			Witness:          bestWitness,
		})
	}

	// Core re-encodes WITH witness (TX_WITH_WITNESS) unconditionally; the
	// serializer only emits the marker/flag when the tx HasWitness (Core
	// CTransaction::HasWitness). MsgTx.Serialize already drives the marker off
	// HasWitness(), so a plain Serialize matches Core: witness-serialize iff any
	// input carries a non-empty witness stack.
	var buf bytes.Buffer
	if err := merged.Serialize(&buf); err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Failed to serialize combined transaction: %v", err)}
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

// decodeCombineVariant decodes one hex-encoded raw tx for combinerawtransaction,
// mirroring Core's DecodeHexTx default (try_no_witness=false, try_witness=true):
// witness-extended decoding is attempted first; if that fails to consume the
// whole input we fall back to legacy (no-witness) decoding. An input that
// decodes to zero inputs is rejected (Core's "at least one input" guard is the
// natural failure of the witness-marker ambiguity for a 0-input tx).
func decodeCombineVariant(hexStr string) (*wire.MsgTx, error) {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	// Witness-extended attempt (Core try_witness=true, tried first). Require it
	// to consume the entire buffer, matching Core's "ssData.empty()" check.
	txExt := &wire.MsgTx{}
	rExt := bytes.NewReader(raw)
	extErr := txExt.Deserialize(rExt)
	if extErr == nil && rExt.Len() == 0 && len(txExt.TxIn) > 0 {
		return txExt, nil
	}

	// Legacy (no-witness) fallback (Core try_no_witness path). This handles a
	// non-segwit variant whose post-version byte happens to be 0x00 etc.
	txLegacy := &wire.MsgTx{}
	rLeg := bytes.NewReader(raw)
	legErr := txLegacy.DeserializeNoWitness(rLeg)
	if legErr == nil && rLeg.Len() == 0 && len(txLegacy.TxIn) > 0 {
		return txLegacy, nil
	}

	// Prefer the extended result if it fully decoded (even past the input
	// guard) before failing the legacy path entirely.
	if extErr == nil && rExt.Len() == 0 && len(txExt.TxIn) > 0 {
		return txExt, nil
	}
	return nil, fmt.Errorf("TX decode failed")
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

// classifyRBFReject maps a checkRBFLocked error sentinel onto the Bitcoin Core
// reject-reason token that testmempoolaccept (and sendrawtransaction) would
// report for the same condition. The categories here are exactly the ones the
// RBF differential harness normalises against:
//
//   - Rule 3 (lower absolute fee) AND Rule 4 (insufficient fee bump) both
//     surface as "insufficient fee" in Core (rbf.cpp:109-123 → the
//     ReplacementChecks "insufficient fee" state in validation.cpp). blockbrew
//     folds both into ErrRBFInsufficientFee, as does the feerate-diagram gate.
//   - A non-signaling conflict with full-RBF disabled is Core
//     "txn-mempool-conflict" (validation.cpp PreChecks).
//   - Rule 2 (new unconfirmed input) → "replacement-adds-unconfirmed".
//   - Rule 5 (too many candidates) → "too many potential replacements".
//   - Spending a conflicting tx → "bad-txns-spends-conflicting-tx".
func classifyRBFReject(err error) string {
	switch {
	case errors.Is(err, mempool.ErrRBFInsufficientFee),
		errors.Is(err, mempool.ErrRBFFeerateDiagram):
		return "insufficient fee"
	case errors.Is(err, mempool.ErrRBFNotSignaled):
		return "txn-mempool-conflict"
	case errors.Is(err, mempool.ErrRBFNewUnconfirmedInput):
		return "replacement-adds-unconfirmed"
	case errors.Is(err, mempool.ErrRBFTooManyConflicts):
		return "too many potential replacements"
	case errors.Is(err, mempool.ErrRBFAncestorConflict):
		return "bad-txns-spends-conflicting-tx"
	default:
		// Any other conflict condition (e.g. unresolved inputs) — report the
		// generic conflict token rather than an opaque error string.
		return "txn-mempool-conflict"
	}
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

		// Transaction version range check (standardness). Mirrors Bitcoin
		// Core IsStandardTx (policy/policy.cpp:102-104): a version outside
		// [TX_MIN_STANDARD_VERSION, TX_MAX_STANDARD_VERSION] is non-standard
		// and rejected with reason "version". This is part of the genuine
		// relay-policy floor (rejected by default Core, not a strict-flag-only
		// gate), so the testmempoolaccept dry-run must enforce it exactly as
		// the AddTransaction submission path (mempool.go:935) already does.
		if tx.Version < mempool.TxMinStandardVersion || tx.Version > mempool.TxMaxStandardVersion {
			result.Allowed = false
			result.RejectReason = "version"
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
		dustOutput := false
		for _, txOut := range tx.TxOut {
			totalOutputValue += txOut.Value
			// Dust-output standardness check. Mirrors Bitcoin Core IsStandardTx
			// (policy/policy.cpp:74-76,159-161 -> reason "dust"): an output
			// whose value is below its dust threshold is non-standard. Reuse the
			// mempool's own IsDust so the threshold is byte-identical to the
			// AddTransaction submission path (mempool.go:3700). Part of the
			// genuine relay-policy floor — rejected by default Core, so the
			// testmempoolaccept dry-run must enforce it too.
			if s.mempool.IsDust(txOut) {
				dustOutput = true
			}
		}
		if dustOutput {
			result.Allowed = false
			result.RejectReason = "dust"
			results = append(results, result)
			continue
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

		// BIP-125 / full-RBF replacement gate (mempool conflict handling).
		//
		// Bitcoin Core's testmempoolaccept runs the FULL MemPoolAccept,
		// including ReplacementChecks (validation.cpp:1290-1380): a tx that
		// spends an outpoint already spent by a mempool tx is a "conflict",
		// and is only admissible if it qualifies as a replacement under
		// BIP-125 (signaling + Rules 3/4/5 + feerate diagram) or full-RBF.
		// Before this, blockbrew's testmempoolaccept dry-run never inspected
		// mempool conflicts, so a replacement that violates Rule 3 (lower
		// absolute fee) or Rule 4 (insufficient fee bump) was falsely reported
		// `allowed: true` — a divergence from Core that this cell closes.
		//
		// TestReplacement is the read-only twin of the AddTransaction conflict
		// branch: it reuses the identical checkRBFLocked gate without mutating
		// the mempool. We map its Core-shaped error sentinels onto the same
		// reject-reason CATEGORY tokens Core emits.
		if conflicts, rbfErr := s.mempool.TestReplacement(tx); conflicts && rbfErr != nil {
			result.Allowed = false
			result.RejectReason = classifyRBFReject(rbfErr)
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

// SignRawTransactionErr describes an error signing an input. The shape mirrors
// Bitcoin Core's per-input error object (rawtransaction.cpp::SignTransaction ->
// TxInErrorToJSON): {txid, vout, witness, scriptSig, sequence, error}. Witness
// is the input's witness stack (each item hex-encoded) and is omitted when the
// input is non-segwit so the field tracks Core's "witness": [...] entry.
type SignRawTransactionErr struct {
	TxID      string   `json:"txid"`
	Vout      uint32   `json:"vout"`
	Witness   []string `json:"witness,omitempty"`
	ScriptSig string   `json:"scriptSig"`
	Sequence  uint32   `json:"sequence"`
	Error     string   `json:"error"`
}

// PrevTx describes a previous transaction output for signing.
type PrevTx struct {
	TxID          string  `json:"txid"`
	Vout          uint32  `json:"vout"`
	ScriptPubKey  string  `json:"scriptPubKey"`
	RedeemScript  string  `json:"redeemScript,omitempty"`
	WitnessScript string  `json:"witnessScript,omitempty"`
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

	// Build a map of prevtxs for quick lookup AND a slice of decoded
	// PrevTxInfo entries for the wallet signer. The slice form is what
	// SignTransactionWithPrevs consumes; mirrors Bitcoin Core's
	// `signrawtransactionwithwallet --prevtxs` argument shape.
	prevTxMap := make(map[wire.OutPoint]PrevTx)
	walletPrevs := make([]wallet.PrevTxInfo, 0, len(prevTxs))
	for _, ptx := range prevTxs {
		hash, err := wire.NewHash256FromHex(ptx.TxID)
		if err != nil {
			continue
		}
		op := wire.OutPoint{Hash: hash, Index: ptx.Vout}
		prevTxMap[op] = ptx

		info := wallet.PrevTxInfo{OutPoint: op}
		if ptx.ScriptPubKey != "" {
			if b, err := hex.DecodeString(ptx.ScriptPubKey); err == nil {
				info.ScriptPubKey = b
			}
		}
		if ptx.RedeemScript != "" {
			if b, err := hex.DecodeString(ptx.RedeemScript); err == nil {
				info.RedeemScript = b
			}
		}
		if ptx.WitnessScript != "" {
			if b, err := hex.DecodeString(ptx.WitnessScript); err == nil {
				info.WitnessScript = b
			}
		}
		// Amount is in BTC in the RPC; convert to satoshis. The wallet
		// signer needs satoshi-amounts for BIP-143 sighash.
		info.Amount = int64(ptx.Amount * 1e8)
		walletPrevs = append(walletPrevs, info)
	}

	// Sign with wallet via the new prevtxs-aware entry-point. The W27-D
	// wave (Phases 1+2+3) closes the W19 P0 where this RPC's `prevtxs`
	// arg was parsed but never threaded into the signer.
	var signErrors []SignRawTransactionErr

	err = w.SignTransactionWithPrevs(tx, walletPrevs)
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
// signrawtransactionwithkey RPC
//
// Core-faithful port of bitcoin-core/src/rpc/rawtransaction.cpp
// signrawtransactionwithkey (672) + SignTransaction. Unlike
// signrawtransactionwithwallet, this RPC needs NO wallet: the caller supplies
// the WIF private keys directly. blockbrew builds a temporary, in-memory
// keystore from those keys (wallet.NewKeystoreFromWIFKeys — Core's
// FillableSigningProvider) and drives the SAME signer the wallet path uses
// (SignTransactionPerInput -> signInputWithScripts -> signP2WPKH / signP2PKH /
// signP2TR / signP2WSH ... -> script.CalcWitnessSignatureHash /
// script.CalcSignatureHash + bbcrypto.SignECDSA / Schnorr). The only
// difference from signrawtransactionwithwallet is the source of the keys.
//
// Signature: signrawtransactionwithkey "hexstring" ["privatekey",...]
//	( [{prevtx}...] "sighashtype" )
// Result: { "hex", "complete", "errors"? } where errors[] entries carry the
// {txid, vout, witness, scriptSig, sequence, error} shape for every input left
// unsigned, and complete is true iff EVERY input was fully signed.
// ============================================================================

func (s *Server) handleSignRawTransactionWithKey(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "signrawtransactionwithkey requires hexstring and privkeys"}
	}

	hexStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid hexstring"}
	}

	// Arg 1: array of WIF private keys.
	rawKeys, ok := args[1].([]interface{})
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "privkeys must be an array"}
	}
	wifs := make([]string, 0, len(rawKeys))
	for _, k := range rawKeys {
		ks, ok := k.(string)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: "Invalid private key"}
		}
		wifs = append(wifs, ks)
	}

	// Arg 2 (optional): prevtxs array.
	var prevTxs []PrevTx
	if len(args) >= 3 && args[2] != nil {
		prevTxsData, err := json.Marshal(args[2])
		if err == nil {
			json.Unmarshal(prevTxsData, &prevTxs)
		}
	}

	// Arg 3 (optional): sighashtype (default ALL).
	sighashType := "ALL"
	if len(args) >= 4 {
		if st, ok := args[3].(string); ok {
			sighashType = st
		}
	}
	validSighashTypes := map[string]bool{
		"ALL": true, "NONE": true, "SINGLE": true,
		"ALL|ANYONECANPAY": true, "NONE|ANYONECANPAY": true, "SINGLE|ANYONECANPAY": true,
	}
	if !validSighashTypes[sighashType] {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid sighash type: %s", sighashType)}
	}

	// Build the temporary keystore from the supplied WIF keys (Core's
	// FillableSigningProvider for this RPC).
	ks, err := wallet.NewKeystoreFromWIFKeys(wifs, s.getNetwork())
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: err.Error()}
	}

	// Decode the transaction.
	txBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Invalid transaction hex"}
	}
	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Transaction decode failed: %v", err)}
	}

	// Merge prevout info from the prevtxs array (txid/vout/scriptPubKey/amount
	// + optional redeem/witness scripts). Same decoding the wallet RPC uses.
	walletPrevs := make([]wallet.PrevTxInfo, 0, len(prevTxs))
	for _, ptx := range prevTxs {
		hash, err := wire.NewHash256FromHex(ptx.TxID)
		if err != nil {
			continue
		}
		info := wallet.PrevTxInfo{OutPoint: wire.OutPoint{Hash: hash, Index: ptx.Vout}}
		if ptx.ScriptPubKey != "" {
			if b, err := hex.DecodeString(ptx.ScriptPubKey); err == nil {
				info.ScriptPubKey = b
			}
		}
		if ptx.RedeemScript != "" {
			if b, err := hex.DecodeString(ptx.RedeemScript); err == nil {
				info.RedeemScript = b
			}
		}
		if ptx.WitnessScript != "" {
			if b, err := hex.DecodeString(ptx.WitnessScript); err == nil {
				info.WitnessScript = b
			}
		}
		// RPC amount is BTC; the BIP-143 signer needs satoshis.
		info.Amount = int64(math.Round(ptx.Amount * 1e8))
		walletPrevs = append(walletPrevs, info)
	}

	// Sign every input we can; collect per-input errors for the rest.
	inputErrs, err := ks.SignTransactionPerInput(tx, walletPrevs)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Signing failed: %v", err)}
	}

	complete := true
	var signErrors []SignRawTransactionErr
	for i, txIn := range tx.TxIn {
		if inputErrs[i] == nil {
			continue
		}
		complete = false
		witness := make([]string, 0, len(txIn.Witness))
		for _, item := range txIn.Witness {
			witness = append(witness, hex.EncodeToString(item))
		}
		signErrors = append(signErrors, SignRawTransactionErr{
			TxID:      txIn.PreviousOutPoint.Hash.String(),
			Vout:      txIn.PreviousOutPoint.Index,
			Witness:   witness,
			ScriptSig: hex.EncodeToString(txIn.SignatureScript),
			Sequence:  txIn.Sequence,
			Error:     inputErrs[i].Error(),
		})
	}

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
//
// Core-faithful implementation of bitcoin-core/src/wallet/rpc/backup.cpp:
// importdescriptors (302-462) + ProcessDescriptorImport (141-300) +
// GetImportTimestamp (127-139). Contract highlights:
//
//   - the response is an array the SAME SIZE as the request; every per-element
//     failure is embedded as {success:false, error:{code,message}} and the
//     batch continues — EXCEPT timestamp errors, which Core evaluates OUTSIDE
//     the per-element try/catch (backup.cpp:388-391) and which therefore abort
//     the whole RPC with -3;
//   - descriptors are parsed with require_checksum=true; checksum failures are
//     per-element -5 with Core's literal CheckChecksum strings;
//   - timestamp is a number or "now" (= tip MTP), clamped to >= 1; after the
//     batch, one synchronous rescan runs from 2h (TIMESTAMP_WINDOW, chain.h:37)
//     before the lowest timestamp so pre-import funds near the boundary are
//     credited (wallet.cpp:1827-1847);
//   - if the rescan stops early, previously-successful elements whose
//     timestamp wasn't fully covered are rewritten to success:false with the
//     -1 "Rescan failed..." error (backup.cpp:416-455).
// ============================================================================

// ImportDescriptorResult is one element of the importdescriptors response.
type ImportDescriptorResult struct {
	Success  bool      `json:"success"`
	Warnings []string  `json:"warnings,omitempty"`
	Error    *RPCError `json:"error,omitempty"`
}

// rescanTimestampWindow is Core's TIMESTAMP_WINDOW = MAX_FUTURE_BLOCK_TIME
// (bitcoin-core/src/chain.h:37): rescans begin this many seconds BEFORE the
// earliest import timestamp.
const rescanTimestampWindow = 7200

// importDefaultKeypoolRange is the default range end (exclusive of Core's
// half-open form; we store inclusive [0, 999]) applied when a ranged
// descriptor is imported without a range — Core uses wallet.m_keypool_size
// (DEFAULT_KEYPOOL_SIZE = 1000) at backup.cpp:180-184.
const importDefaultKeypoolRange = 1000

// addressNetwork maps the node's chain params to the address-encoding network.
func (s *Server) addressNetwork() address.Network {
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
	return net
}

// jsonTypeName names a decoded JSON value with Core's UniValue type
// vocabulary, used in the -3 timestamp type error (uvTypeName).
func jsonTypeName(v interface{}) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case float64:
		return "number"
	case string:
		return "string"
	case []interface{}:
		return "array"
	default:
		return "object"
	}
}

// getImportTimestamp mirrors Core's GetImportTimestamp (backup.cpp:127-139):
// number -> as-is; "now" -> tip MTP; missing/wrong type -> RPC_TYPE_ERROR (-3)
// which the caller surfaces as a WHOLE-RPC error (Core evaluates it outside
// ProcessDescriptorImport's try/catch).
func getImportTimestamp(req map[string]json.RawMessage, now int64) (int64, *RPCError) {
	raw, ok := req["timestamp"]
	if !ok {
		return 0, &RPCError{Code: RPCErrTypeError, Message: "Missing required timestamp field for key"}
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, &RPCError{Code: RPCErrTypeError, Message: "Expected number or \"now\" timestamp value for key. got type null"}
	}
	switch t := v.(type) {
	case float64:
		return int64(t), nil
	case string:
		if t == "now" {
			return now, nil
		}
	}
	return 0, &RPCError{Code: RPCErrTypeError,
		Message: fmt.Sprintf("Expected number or \"now\" timestamp value for key. got type %s", jsonTypeName(v))}
}

// parseImportRange mirrors Core's ParseDescriptorRange (rpc/util.cpp): a bare
// number n means [0, n]; [begin, end] is taken as-is (inclusive). All failures
// are -8 with Core's strings.
func parseImportRange(raw json.RawMessage) (int32, int32, *RPCError) {
	rangeErr := func(msg string) (int32, int32, *RPCError) {
		return 0, 0, &RPCError{Code: RPCErrInvalidParameter, Message: msg}
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return rangeErr("Range must be specified as integer or as [begin,end]")
	}
	var begin, end int64
	switch t := v.(type) {
	case float64:
		begin, end = 0, int64(t)
	case []interface{}:
		if len(t) != 2 {
			return rangeErr("Range must have exactly two elements")
		}
		b, bok := t[0].(float64)
		e, eok := t[1].(float64)
		if !bok || !eok {
			return rangeErr("Range must be specified as integer or as [begin,end]")
		}
		begin, end = int64(b), int64(e)
	default:
		return rangeErr("Range must be specified as integer or as [begin,end]")
	}
	if begin > end {
		return rangeErr("Range specified as [begin,end] must not have begin after end")
	}
	if begin < 0 {
		return rangeErr("Range should be greater or equal than 0")
	}
	if end-begin >= 10000 {
		return rangeErr("Range is too large")
	}
	if end >= 0x7fffffff {
		return rangeErr("End of range is too high")
	}
	return int32(begin), int32(end), nil
}

// processDescriptorImport is the per-element body (Core's
// ProcessDescriptorImport, backup.cpp:141-300): every failure is embedded in
// the element result; the batch continues.
func (s *Server) processDescriptorImport(w *wallet.Wallet, req map[string]json.RawMessage, timestamp int64) *ImportDescriptorResult {
	res := &ImportDescriptorResult{}
	fail := func(code int, msg string) *ImportDescriptorResult {
		res.Success = false
		res.Error = &RPCError{Code: code, Message: msg}
		return res
	}

	descRaw, ok := req["desc"]
	if !ok {
		return fail(RPCErrInvalidParameter, "Descriptor not found.")
	}
	var descStr string
	if err := json.Unmarshal(descRaw, &descStr); err != nil {
		return fail(RPCErrTypeError, "Expected type string for desc")
	}

	// require_checksum=true (Core Parse at backup.cpp:158; strings from
	// descriptor.cpp CheckChecksum). -5, NOT -32602.
	if err := wallet.RequireDescriptorChecksum(descStr); err != nil {
		return fail(RPCErrInvalidAddressOrKey, err.Error())
	}
	desc, err := wallet.ParseDescriptor(descStr, s.addressNetwork())
	if err != nil {
		return fail(RPCErrInvalidAddressOrKey, err.Error())
	}

	var active, internal bool
	if raw, ok := req["active"]; ok {
		_ = json.Unmarshal(raw, &active)
	}
	if raw, ok := req["internal"]; ok {
		_ = json.Unmarshal(raw, &internal)
	}
	label := ""
	_, hasLabel := req["label"]
	if hasLabel {
		_ = json.Unmarshal(req["label"], &label)
	}

	// Range gates (Core backup.cpp:170-195).
	isRanged := desc.IsRange()
	rangeRaw, hasRange := req["range"]
	var rangeStart, rangeEnd, nextIndex int32
	if hasRange && !isRanged {
		return fail(RPCErrInvalidParameter, "Range should not be specified for an un-ranged descriptor")
	}
	if isRanged {
		if hasRange {
			var rpcErr *RPCError
			rangeStart, rangeEnd, rpcErr = parseImportRange(rangeRaw)
			if rpcErr != nil {
				return fail(rpcErr.Code, rpcErr.Message)
			}
		} else {
			res.Warnings = append(res.Warnings, "Range not given, using default keypool range")
			rangeStart, rangeEnd = 0, importDefaultKeypoolRange-1
		}
		nextIndex = rangeStart
		if rawNext, hasNext := req["next_index"]; hasNext {
			var nf float64
			if err := json.Unmarshal(rawNext, &nf); err != nil {
				return fail(RPCErrTypeError, "Expected type number for next_index")
			}
			nextIndex = int32(nf)
			if nextIndex < rangeStart || nextIndex > rangeEnd {
				return fail(RPCErrInvalidParameter, "next_index is out of range")
			}
		}
	}

	// Activity / label gates (Core backup.cpp:197-221).
	if active && !isRanged {
		return fail(RPCErrInvalidParameter, "Active descriptors must be ranged")
	}
	if isRanged && hasLabel {
		return fail(RPCErrInvalidParameter, "Ranged descriptors should not have a label")
	}
	if internal && hasLabel {
		return fail(RPCErrInvalidParameter, "Internal addresses should not have a label")
	}
	if active && desc.Type == wallet.DescCombo {
		return fail(RPCErrWalletError, "Combo descriptors cannot be set to active")
	}

	// Wallet-side import: privkey/dpk direction gates (-4, Core backup.cpp:
	// 224-226 / 259-262), expansion, registration.
	_, warnings, err := w.ImportDescriptor(desc, wallet.DescriptorImport{
		Active:     active,
		Internal:   internal,
		Label:      label,
		RangeStart: rangeStart,
		RangeEnd:   rangeEnd,
		NextIndex:  nextIndex,
		Timestamp:  timestamp,
	})
	if err != nil {
		return fail(RPCErrWalletError, err.Error())
	}
	res.Warnings = append(res.Warnings, warnings...)
	res.Success = true
	return res
}

// rescanStartHeight maps the lowest import timestamp to the first active-chain
// height whose block time is >= ts - TIMESTAMP_WINDOW, mirroring Core's
// RescanFromTime -> CChain::FindEarliestAtLeast (wallet.cpp:1827-1847: the
// scan starts 2h BEFORE the earliest timestamp). Returns tip+1 when no block
// qualifies (nothing to scan).
func (s *Server) rescanStartHeight(lowestTs int64) int32 {
	if lowestTs <= 1 {
		return 1 // timestamp 0/1 -> scan the whole chain
	}
	tip := s.chainMgr.BestBlockNode()
	if tip == nil {
		return 1
	}
	target := lowestTs - rescanTimestampWindow
	first := tip.Height + 1
	for node := tip; node != nil && node.Height > 0; node = node.Parent {
		if int64(node.Header.Timestamp) >= target {
			first = node.Height
		}
	}
	return first
}

func (s *Server) handleImportDescriptors(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing requests parameter"}
	}

	// Raw-keyed request objects so field PRESENCE is observable (a missing
	// timestamp must abort the whole RPC; an explicit null is a type error).
	var requests []map[string]json.RawMessage
	if err := json.Unmarshal(args[0], &requests); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Failed to parse requests"}
	}

	tip := s.chainMgr.BestBlockNode()
	if tip == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}
	// Core: now = tip MTP; lowest_timestamp starts at the tip block time and
	// is lowered by every request (backup.cpp:385-396).
	now := tip.GetMedianTimePast()
	lowestTimestamp := int64(tip.Header.Timestamp)

	results := make([]*ImportDescriptorResult, 0, len(requests))
	elemTimestamps := make([]int64, len(requests))
	rescan := false
	for i, req := range requests {
		// Timestamp errors abort the ENTIRE RPC with -3 — Core calls
		// GetImportTimestamp outside the per-element try/catch
		// (backup.cpp:388-391).
		ts, tsErr := getImportTimestamp(req, now)
		if tsErr != nil {
			return nil, tsErr
		}
		if ts < 1 {
			ts = 1 // minimum_timestamp clamp (backup.cpp:376,390)
		}
		elemTimestamps[i] = ts

		res := s.processDescriptorImport(w, req, ts)
		results = append(results, res)

		if ts < lowestTimestamp {
			lowestTimestamp = ts
		}
		if res.Success {
			rescan = true
		}
	}

	// One synchronous rescan for the whole batch (Core backup.cpp:407-410):
	// the RPC blocks until pre-import funds are credited.
	if rescan {
		_, tipHeight := s.chainMgr.BestBlock()
		startHeight := s.rescanStartHeight(lowestTimestamp)
		if startHeight <= tipHeight {
			scannedTo, scanErr := w.Rescan(startHeight, tipHeight, s.blockByHeight)
			if scanErr != nil || scannedTo < tipHeight {
				// Post-rescan rewrite (Core backup.cpp:416-455): elements whose
				// timestamp range was not fully scanned become success:false
				// with the -1 "Rescan failed" error; elements that already
				// carry an error stand unmodified.
				scannedTime := now
				if node := tip.GetAncestor(scannedTo + 1); node != nil {
					scannedTime = int64(node.Header.Timestamp)
				}
				for i := range results {
					if results[i].Error != nil || scannedTime <= elemTimestamps[i] {
						continue
					}
					results[i] = &ImportDescriptorResult{
						Success: false,
						Error: &RPCError{Code: RPCErrMisc, Message: fmt.Sprintf(
							"Rescan failed for descriptor with timestamp %d. There was an error reading a "+
								"block from time %d, which is after or within %d seconds of key creation, and "+
								"could contain transactions pertaining to the desc. As a result, transactions "+
								"and coins using this desc may not appear in the wallet. This error could "+
								"potentially caused by data corruption. If the issue persists you may want to "+
								"reindex (see -reindex option).",
							elemTimestamps[i], scannedTime-rescanTimestampWindow-1, rescanTimestampWindow)},
					}
				}
			}
		}
	}

	// Persist the registry (and any rescan credits) durably before returning —
	// Core's AddWalletDescriptor writes through the wallet DB before the RPC
	// responds. No-op when nothing changed.
	_ = w.Flush()

	return results, nil
}
