// RPC handlers for bumpfee / psbtbumpfee — W118 BUG-2, FIX-61.
//
// These RPCs were previously absent: server.go had no dispatch arms and
// the wallet package had no BumpFee helper. With the wallet.BumpFee
// helper now in place (see internal/wallet/bumpfee.go), this file wires
// the two RPCs:
//
//   bumpfee      → build replacement, re-sign, submit to mempool, return txid+fees.
//   psbtbumpfee  → build replacement, wrap in a PSBT (BIP-174), return base64 PSBT.
//
// Reference: bitcoin-core/src/wallet/rpc/feebumper.cpp (bumpfee / psbtbumpfee).
package rpc

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// BumpFeeResult is the JSON response shape for the `bumpfee` RPC, matching
// Bitcoin Core's bumpfee result (rpc/feebumper.cpp). Errors is empty in the
// success path; we keep it nullable via omitempty so a clean response does
// not carry the field.
type BumpFeeResult struct {
	TxID       string   `json:"txid"`
	OrigFee    float64  `json:"origfee"` // BTC
	Fee        float64  `json:"fee"`     // BTC
	Errors     []string `json:"errors,omitempty"`
	NewFeeRate float64  `json:"newfeerate,omitempty"` // sat/vB
}

// PSBTBumpFeeResult is the JSON response shape for the `psbtbumpfee` RPC,
// matching Bitcoin Core's psbtbumpfee result.
type PSBTBumpFeeResult struct {
	PSBT       string   `json:"psbt"` // base64
	OrigFee    float64  `json:"origfee"`
	Fee        float64  `json:"fee"`
	Errors     []string `json:"errors,omitempty"`
	NewFeeRate float64  `json:"newfeerate,omitempty"`
}

// handleBumpFee implements the `bumpfee` RPC:
//
//	bumpfee "txid" ( options )
//
// options.fee_rate (sat/vB) is the only field we currently parse. Builds a
// replacement transaction, broadcasts it to the mempool (which performs
// the BIP-125 replacement, evicting the original), and returns the new
// txid plus old/new fees.
func (s *Server) handleBumpFee(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	req, rpcErr := parseBumpFeeParams(params)
	if rpcErr != nil {
		return nil, rpcErr
	}

	res, rpcErr := s.buildBumpedTx(w, req)
	if rpcErr != nil {
		return nil, rpcErr
	}

	// Submit the replacement to the mempool. The mempool's RBF code
	// (checkRBFLocked) will validate BIP-125 rules and evict the original.
	if s.mempool != nil {
		if err := s.mempool.AcceptToMemoryPool(res.NewTx); err != nil {
			return nil, &RPCError{
				Code:    RPCErrVerify,
				Message: fmt.Sprintf("bumpfee replacement rejected by mempool: %v", err),
			}
		}
	}

	return BumpFeeResult{
		TxID:       res.NewTx.TxHash().String(),
		OrigFee:    float64(res.OldFee) / satoshiPerBitcoin,
		Fee:        float64(res.NewFee) / satoshiPerBitcoin,
		NewFeeRate: res.NewFeeRate,
	}, nil
}

// handlePSBTBumpFee implements the `psbtbumpfee` RPC:
//
//	psbtbumpfee "txid" ( options )
//
// Same parsing as bumpfee, but the replacement is returned as a base64
// PSBT instead of being broadcast. Useful when the caller wants to
// inspect or re-sign before submitting (e.g. with a separate signer).
//
// Because the wallet has already filled in scriptSig/witness when it
// constructed res.NewTx via signTx, this RPC wraps a *fresh* unsigned
// copy (clearing scripts) in a PSBT — that's what BIP-174 requires for
// new PSBTs. The signature data is preserved as PartialSigs / FinalScript
// fields by the wallet.NewPSBT path in a fuller implementation; here we
// produce a minimal PSBT with the unsigned tx + the prev-out witness UTXOs
// so a downstream signer can finalise it.
func (s *Server) handlePSBTBumpFee(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	req, rpcErr := parseBumpFeeParams(params)
	if rpcErr != nil {
		return nil, rpcErr
	}

	res, rpcErr := s.buildBumpedTx(w, req)
	if rpcErr != nil {
		return nil, rpcErr
	}

	// Build the unsigned twin of res.NewTx (BIP-174 §"PSBT" requires the
	// global unsigned tx to have empty scriptSig and empty witness).
	unsigned := &wire.MsgTx{
		Version:  res.NewTx.Version,
		LockTime: res.NewTx.LockTime,
	}
	for _, in := range res.NewTx.TxIn {
		unsigned.TxIn = append(unsigned.TxIn, &wire.TxIn{
			PreviousOutPoint: in.PreviousOutPoint,
			Sequence:         in.Sequence,
		})
	}
	for _, out := range res.NewTx.TxOut {
		unsigned.TxOut = append(unsigned.TxOut, &wire.TxOut{
			Value:    out.Value,
			PkScript: out.PkScript,
		})
	}

	psbt, err := wallet.NewPSBT(unsigned)
	if err != nil {
		return nil, &RPCError{Code: RPCErrMisc, Message: fmt.Sprintf("psbtbumpfee: NewPSBT failed: %v", err)}
	}

	// Attach WitnessUTXO records for each input — these are mandatory for
	// segwit-input PSBTs and allow a downstream signer to verify the
	// pkScript/value pair without re-fetching the previous tx. We re-look
	// up via w.GetUTXO rather than threading the map through because the
	// wallet API is the canonical source of truth and we've already
	// validated ownership inside buildBumpedTx.
	for i, in := range res.NewTx.TxIn {
		u := w.GetUTXO(in.PreviousOutPoint)
		if u == nil {
			continue
		}
		psbt.Inputs[i].WitnessUTXO = &wire.TxOut{
			Value:    u.Amount,
			PkScript: u.PkScript,
		}
	}

	encoded, err := psbt.EncodeBase64()
	if err != nil {
		return nil, &RPCError{Code: RPCErrMisc, Message: fmt.Sprintf("psbtbumpfee: PSBT encode failed: %v", err)}
	}

	return PSBTBumpFeeResult{
		PSBT:       encoded,
		OrigFee:    float64(res.OldFee) / satoshiPerBitcoin,
		Fee:        float64(res.NewFee) / satoshiPerBitcoin,
		NewFeeRate: res.NewFeeRate,
	}, nil
}

// parseBumpFeeParams parses the shared parameter shape of bumpfee /
// psbtbumpfee:
//
//	[ "txid", { "fee_rate": <number, sat/vB> } ]
//
// txid is required, options is optional.
func parseBumpFeeParams(params json.RawMessage) (*bumpFeeArgs, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing txid parameter"}
	}
	txidStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid txid"}
	}
	txid, err := wire.NewHash256FromHex(txidStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: fmt.Sprintf("Invalid txid: %v", err)}
	}

	feeRate := 0.0
	if len(args) >= 2 && args[1] != nil {
		opts, ok := args[1].(map[string]interface{})
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid options object"}
		}
		if fr, ok := opts["fee_rate"]; ok {
			switch v := fr.(type) {
			case float64:
				feeRate = v
			case string:
				// Core also accepts a stringified number for backwards compat;
				// not implementing the full parsing path here — reject loudly.
				return nil, &RPCError{Code: RPCErrInvalidParameter, Message: fmt.Sprintf("fee_rate must be numeric, got string %q", v)}
			default:
				return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "fee_rate must be numeric"}
			}
			if feeRate <= 0 {
				return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "fee_rate must be positive"}
			}
		}
	}

	return &bumpFeeArgs{TxID: txid, FeeRate: feeRate}, nil
}

// bumpFeeArgs is the parsed user-supplied shape for bumpfee / psbtbumpfee.
type bumpFeeArgs struct {
	TxID    wire.Hash256
	FeeRate float64 // 0 means "+1 sat/vB over original"
}

// buildBumpedTx looks up the original tx from the mempool, builds the
// InputUTXOs map from the wallet's UTXO set, and calls wallet.BumpFee.
// Maps wallet-layer error sentinels to Core-compatible RPC error codes.
func (s *Server) buildBumpedTx(w *wallet.Wallet, args *bumpFeeArgs) (*wallet.BumpFeeResult, *RPCError) {
	if s.mempool == nil {
		return nil, &RPCError{Code: RPCErrMisc, Message: "mempool unavailable"}
	}
	origTx := s.mempool.GetTransaction(args.TxID)
	if origTx == nil {
		return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: "Transaction not in mempool (cannot bump confirmed or unknown tx)"}
	}

	inputUTXOs := make(map[wire.OutPoint]*wallet.WalletUTXO, len(origTx.TxIn))
	for _, in := range origTx.TxIn {
		u := w.GetUTXO(in.PreviousOutPoint)
		if u == nil {
			return nil, &RPCError{
				Code:    RPCErrWalletError,
				Message: fmt.Sprintf("Input %s:%d not owned by this wallet (cannot bump)", in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index),
			}
		}
		inputUTXOs[in.PreviousOutPoint] = u
	}

	res, err := w.BumpFee(wallet.BumpFeeRequest{
		OrigTx:     origTx,
		InputUTXOs: inputUTXOs,
		FeeRate:    args.FeeRate,
	})
	if err != nil {
		return nil, mapBumpFeeError(err)
	}
	return res, nil
}

// mapBumpFeeError translates wallet-package error sentinels into the
// Bitcoin-Core-compatible RPC error codes that the callers should see.
func mapBumpFeeError(err error) *RPCError {
	switch {
	case errors.Is(err, wallet.ErrBumpFeeTxNotInMempool):
		return &RPCError{Code: RPCErrInvalidAddressOrKey, Message: err.Error()}
	case errors.Is(err, wallet.ErrBumpFeeNoRBFSignal):
		return &RPCError{Code: RPCErrInvalidParameter, Message: err.Error()}
	case errors.Is(err, wallet.ErrBumpFeeNoChange):
		return &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	case errors.Is(err, wallet.ErrBumpFeeNotOurs):
		return &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	case errors.Is(err, wallet.ErrBumpFeeDustAfterReduce):
		return &RPCError{Code: RPCErrInvalidParameter, Message: err.Error()}
	case errors.Is(err, wallet.ErrBumpFeeRateTooLow):
		return &RPCError{Code: RPCErrInvalidParameter, Message: err.Error()}
	case errors.Is(err, wallet.ErrWalletLocked):
		return &RPCError{Code: RPCErrWallet, Message: err.Error()}
	default:
		return &RPCError{Code: RPCErrWalletError, Message: fmt.Sprintf("bumpfee: %v", err)}
	}
}

// satoshiPerBitcoin is provided by other files in the rpc package.
