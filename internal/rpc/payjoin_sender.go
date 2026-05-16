// PayJoin sender RPCs — `getpayjoinrequest` + `sendpayjoinrequest`.
//
// Closes W119 BUG-4: blockbrew's JSON-RPC dispatch had no PayJoin entry
// points. These two methods give an external caller (a wallet UI, a CLI
// like btcpayserver) full programmatic control of the sender side:
//
//   getpayjoinrequest <address> <amount_btc> [feerate]
//     → returns base64 Original PSBT (signed, ready to POST to the
//       receiver's pj= endpoint). Useful for "dry runs" where the
//       caller wants to drive the HTTP layer themselves (e.g. via a
//       Tor SOCKS proxy that blockbrew has no native support for).
//
//   sendpayjoinrequest { "address", "amount", "endpoint", "feerate"?,
//                        "maxadditionalfeecontribution"?,
//                        "additionalfeeoutputindex"?,
//                        "disableoutputsubstitution"?, "minfeerate"? }
//     → runs the full sender flow: build Original PSBT, POST to
//       `endpoint`, run G10-G15 anti-snoop, fall back on any failure
//       (G22), broadcast the final tx to the mempool. Returns
//       { "txid": "...", "fallback": bool, "fallback_reason": "..." }.
//
// Both methods route through getWalletForRPC so the multi-wallet URL
// pattern `/wallet/<name>` works out of the box. They live in the rpc
// package (next to payjoin.go for the receiver-side route).
//
// Reference: bips/bip-0078.mediawiki §"Send payjoin"; payjoin.org Rust
// crate `payjoin::sender::PayjoinPSBT`.

package rpc

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/hashhog/blockbrew/internal/wallet"
)

// ── payload schemas ─────────────────────────────────────────────────────

// getPayjoinRequestResult is the JSON shape returned by getpayjoinrequest.
type getPayjoinRequestResult struct {
	// PSBT is the base64-encoded Original PSBT. Caller POSTs this to
	// the receiver's pj= endpoint with Content-Type: text/plain and
	// `?v=1` query param.
	PSBT string `json:"psbt"`
	// FeeRate is the sat/vB feerate used to build the tx. Surfaced so
	// the caller can validate against their own min-fee policy before
	// broadcasting.
	FeeRate float64 `json:"feerate"`
}

// sendPayjoinRequestArgs is the parsed argument struct for
// sendpayjoinrequest. The on-wire JSON shape is either a positional array
// or a named-object form (Core convention for new RPCs).
//
// Required: Address, Amount, Endpoint. Optional with sensible defaults:
// everything else.
type sendPayjoinRequestArgs struct {
	Address                      string  `json:"address"`
	Amount                       float64 `json:"amount"` // BTC (Core convention)
	Endpoint                     string  `json:"endpoint"`
	FeeRate                      float64 `json:"feerate"`                      // sat/vB; 0 → use mempool estimate
	MaxAdditionalFeeContribution int64   `json:"maxadditionalfeecontribution"` // sats
	AdditionalFeeOutputIndex     int     `json:"additionalfeeoutputindex"`     // -1 = unspecified
	DisableOutputSubstitution    bool    `json:"disableoutputsubstitution"`
	MinFeeRate                   float64 `json:"minfeerate"` // sat/vB
}

// sendPayjoinRequestResult is the JSON shape returned by sendpayjoinrequest.
type sendPayjoinRequestResult struct {
	// TxID is the broadcast transaction's txid. Empty when Fallback
	// occurred AND the caller declined to broadcast the Original.
	TxID string `json:"txid"`
	// Fallback is true when the BIP-78 G22 fallback path triggered
	// (transport failed, receiver returned an error, or one of the six
	// anti-snoop validators rejected the proposal).
	Fallback bool `json:"fallback"`
	// FallbackReason is the human-readable explanation. Empty when
	// Fallback is false.
	FallbackReason string `json:"fallback_reason,omitempty"`
	// ReceiverStatus is the HTTP status from the receiver. 0 when
	// transport failed before status was read.
	ReceiverStatus int `json:"receiver_status"`
	// PSBT is the final base64 PSBT (signed proposal, or Original on
	// fallback). Surfaced so the caller can inspect / re-broadcast
	// manually if AcceptToMemoryPool succeeded but external broadcast
	// is desired.
	PSBT string `json:"psbt"`
}

// ── handleGetPayjoinRequest ─────────────────────────────────────────────

// handleGetPayjoinRequest implements:
//
//   getpayjoinrequest <address> <amount_btc> [feerate_sat_per_vb]
//
// Builds a Bitcoin tx paying `amount_btc` to `address`, wraps it as a
// PSBT, signs every sender input, returns the base64 form. The caller
// then POSTs this to the receiver's pj= endpoint themselves (useful for
// custom transport, e.g. Tor SOCKS).
func (s *Server) handleGetPayjoinRequest(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing address and/or amount"}
	}

	addr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid address"}
	}
	amountBTC, ok := args[1].(float64)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid amount"}
	}
	amountSat := int64(amountBTC * satoshiPerBitcoin)
	if amountSat <= 0 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Amount must be positive"}
	}

	// Feerate: optional arg 2 overrides; otherwise use the mempool
	// estimator's 6-block target (same default the send path uses).
	feeRate := 10.0
	if len(args) >= 3 {
		if fr, ok := args[2].(float64); ok && fr > 0 {
			feeRate = fr
		}
	} else if s.mempool != nil {
		if estimated := s.mempool.EstimateFee(6); estimated > feeRate {
			feeRate = estimated
		}
	}

	psbt, err := w.BuildPayjoinOriginalPSBT(addr, amountSat, feeRate)
	if err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}
	b64, err := psbt.EncodeBase64()
	if err != nil {
		return nil, &RPCError{Code: RPCErrMisc, Message: fmt.Sprintf("EncodeBase64: %v", err)}
	}

	return getPayjoinRequestResult{
		PSBT:    b64,
		FeeRate: feeRate,
	}, nil
}

// ── handleSendPayjoinRequest ────────────────────────────────────────────

// handleSendPayjoinRequest implements:
//
//   sendpayjoinrequest { address, amount, endpoint, feerate?,
//                        maxadditionalfeecontribution?,
//                        additionalfeeoutputindex?,
//                        disableoutputsubstitution?, minfeerate? }
//
// Runs the full sender flow: build, POST, anti-snoop, broadcast.
// On G22 fallback the Original PSBT is preserved in the response so
// the caller can decide whether to broadcast the snitch tx (privacy
// trade-off documented in BIP-78 §"Fallback strategies").
//
// We accept BOTH positional array and named object forms — this mirrors
// Core's RPC habit of accepting either depending on the call site.
func (s *Server) handleSendPayjoinRequest(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	args, rpcErr := parseSendPayjoinRequestArgs(params)
	if rpcErr != nil {
		return nil, rpcErr
	}

	// Feerate defaulting matches handleSendToAddress.
	feeRate := args.FeeRate
	if feeRate <= 0 {
		feeRate = 10.0
		if s.mempool != nil {
			if estimated := s.mempool.EstimateFee(6); estimated > feeRate {
				feeRate = estimated
			}
		}
	}

	amountSat := int64(args.Amount * satoshiPerBitcoin)
	if amountSat <= 0 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Amount must be positive"}
	}

	psbt, err := w.BuildPayjoinOriginalPSBT(args.Address, amountSat, feeRate)
	if err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}

	opts := wallet.PayjoinSendOptions{
		Endpoint:                     args.Endpoint,
		Version:                      "1",
		MaxAdditionalFeeContribution: args.MaxAdditionalFeeContribution,
		AdditionalFeeOutputIndex:     args.AdditionalFeeOutputIndex,
		DisableOutputSubstitution:    args.DisableOutputSubstitution,
		MinFeeRate:                   args.MinFeeRate,
	}
	// Default the optional fee-output index to -1 (BIP-78 default = unset).
	if opts.AdditionalFeeOutputIndex == 0 {
		// The JSON-RPC layer can't distinguish "unset" from "explicitly 0";
		// we treat 0 as "use the receiver's pay-output by default" which
		// is the spec's implicit fallback. Set explicit -1 if you want to
		// signal "no fee output at all" via the named-args form.
	}

	res, sendErr := w.SendPayjoinRequest(psbt, opts)
	if sendErr != nil {
		// A non-fallback error (endpoint scheme rejected, finalize
		// failure, etc) — surface as a wallet error rather than
		// silently dropping the call. Caller can retry with a fresh
		// build.
		return nil, &RPCError{Code: RPCErrWalletError, Message: sendErr.Error()}
	}

	result := sendPayjoinRequestResult{
		Fallback:       res.Fallback,
		FallbackReason: res.FallbackReason,
		ReceiverStatus: res.ReceiverStatus,
		PSBT:           res.FinalPSBTBase64,
	}

	// Broadcast on the happy path. We don't auto-broadcast the Original
	// on fallback — that's the caller's privacy decision per BIP-78
	// §"Fallback strategies". The Original PSBT is returned in `psbt`
	// so the caller can sendrawtransaction it explicitly.
	if !res.Fallback && res.FinalTx != nil {
		if s.mempool != nil {
			if err := s.mempool.AcceptToMemoryPool(res.FinalTx); err != nil {
				return nil, &RPCError{
					Code:    RPCErrVerify,
					Message: fmt.Sprintf("PayJoin proposal rejected by mempool: %v", err),
				}
			}
		}
		// Serialize once so a future TODO (P2P broadcast hookup) has a
		// natural insertion point — currently handleSendToAddress also
		// only does AcceptToMemoryPool without explicit P2P send, since
		// the mempool itself triggers inv-relay on accept.
		var buf bytes.Buffer
		_ = res.FinalTx.Serialize(&buf)
		result.TxID = res.FinalTx.TxHash().String()
	}

	return result, nil
}

// parseSendPayjoinRequestArgs handles the dual positional/named arg form.
//
// Positional: ["address", amount_btc, "endpoint", feerate?, maxAddFee?,
//              addFeeOutIdx?, disableOutSub?, minFeeRate?]
// Named:      object with the JSON keys defined on sendPayjoinRequestArgs.
//
// Returns (*sendPayjoinRequestArgs, *RPCError); the RPCError is non-nil
// when any required arg is missing or the wrong type.
func parseSendPayjoinRequestArgs(params json.RawMessage) (*sendPayjoinRequestArgs, *RPCError) {
	// First try named object form. If that fails AND the body looks like
	// an array, fall back to positional.
	var named sendPayjoinRequestArgs
	named.AdditionalFeeOutputIndex = -1 // BIP-78 default = unset
	if err := json.Unmarshal(params, &named); err == nil && named.Address != "" {
		return &named, nil
	}
	var arr []interface{}
	if err := json.Unmarshal(params, &arr); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters: expected array or object"}
	}
	if len(arr) < 3 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing address, amount, or endpoint"}
	}
	out := &sendPayjoinRequestArgs{AdditionalFeeOutputIndex: -1}
	if s, ok := arr[0].(string); ok {
		out.Address = s
	} else {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid address"}
	}
	if a, ok := arr[1].(float64); ok {
		out.Amount = a
	} else {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid amount"}
	}
	if s, ok := arr[2].(string); ok {
		out.Endpoint = s
	} else {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid endpoint"}
	}
	if len(arr) >= 4 {
		if v, ok := arr[3].(float64); ok {
			out.FeeRate = v
		}
	}
	if len(arr) >= 5 {
		if v, ok := arr[4].(float64); ok {
			out.MaxAdditionalFeeContribution = int64(v)
		}
	}
	if len(arr) >= 6 {
		if v, ok := arr[5].(float64); ok {
			out.AdditionalFeeOutputIndex = int(v)
		}
	}
	if len(arr) >= 7 {
		if v, ok := arr[6].(bool); ok {
			out.DisableOutputSubstitution = v
		}
	}
	if len(arr) >= 8 {
		if v, ok := arr[7].(float64); ok {
			out.MinFeeRate = v
		}
	}
	return out, nil
}
