package rpc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// lockunspent / listlockunspent
//
// Reference: bitcoin-core/src/wallet/rpc/coins.cpp::lockunspent (L214) and
// listlockunspent (L347). Locks are in-memory by default; persistent=true
// would write through to the wallet DB on disk. blockbrew currently honors
// the `persistent` flag in the in-memory map but does not yet flush it to
// disk — same as several other impls — see audit doc for status.
// ============================================================================

// LockedOutpoint is the JSON shape of a single entry in listlockunspent.
type LockedOutpoint struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}

// handleLockUnspent implements `lockunspent unlock ([{txid,vout},...]) (persistent)`.
//
// Semantics (matching coins.cpp::lockunspent):
//   - unlock=true with no outputs array (or null): unlock all coins, return true
//   - unlock=true with outputs: each must currently be locked or -8 INVALID_PARAMETER
//   - unlock=false with outputs: each UTXO must exist in the wallet and not be
//     spent; if already locked and persistent=false, return -8.
//
// Returns boolean true on success.
func (s *Server) handleLockUnspent(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing required parameter: unlock"}
	}

	var unlock bool
	if err := json.Unmarshal(args[0], &unlock); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid 'unlock' (expected boolean)"}
	}

	// Optional persistent flag (third arg). Ignored for unlocking, per Core.
	persistent := false
	if len(args) >= 3 {
		if err := json.Unmarshal(args[2], &persistent); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid 'persistent' (expected boolean)"}
		}
	}

	// If outputs missing or null: unlock-all (only valid for unlock=true).
	if len(args) < 2 || string(args[1]) == "null" {
		if unlock {
			w.UnlockAllCoins()
		}
		return true, nil
	}

	// Parse the outputs array.
	var outs []struct {
		TxID string `json:"txid"`
		Vout int64  `json:"vout"`
	}
	if err := json.Unmarshal(args[1], &outs); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid transactions array"}
	}

	// Validate every outpoint up-front (Core does the same: validate all,
	// then atomically apply). This way a single bad entry rejects the
	// entire call without leaving partial state.
	type validated struct {
		op       wire.OutPoint
		isLocked bool
	}
	checked := make([]validated, 0, len(outs))
	for _, o := range outs {
		if o.Vout < 0 {
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: "Invalid parameter, vout cannot be negative",
			}
		}
		txid, err := wire.NewHash256FromHex(o.TxID)
		if err != nil {
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: fmt.Sprintf("Invalid parameter, txid is not a valid hex string: %s", o.TxID),
			}
		}
		op := wire.OutPoint{Hash: txid, Index: uint32(o.Vout)}

		// Core checks the UTXO is known to the wallet. We only enforce
		// this on lock (not unlock) to keep parity with Core's
		// `mapWallet.find` lookup, which is performed on both paths but
		// throws the same -8. We mirror that here.
		if !w.HasOwnUTXO(op) {
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: "Invalid parameter, unknown transaction",
			}
		}

		isLocked := w.IsLockedCoin(op)
		if unlock && !isLocked {
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: "Invalid parameter, expected locked output",
			}
		}
		if !unlock && isLocked && !persistent {
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: "Invalid parameter, output already locked",
			}
		}
		checked = append(checked, validated{op: op, isLocked: isLocked})
	}

	for _, v := range checked {
		if unlock {
			if !w.UnlockCoin(v.op) {
				return nil, &RPCError{Code: RPCErrWalletError, Message: "Unlocking coin failed"}
			}
		} else {
			if !w.LockCoin(v.op, persistent) {
				return nil, &RPCError{Code: RPCErrWalletError, Message: "Locking coin failed"}
			}
		}
	}
	return true, nil
}

// handleListLockUnspent implements `listlockunspent`.
func (s *Server) handleListLockUnspent(walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	out := w.ListLockedCoins()
	result := make([]LockedOutpoint, 0, len(out))
	for _, op := range out {
		result = append(result, LockedOutpoint{
			TxID: op.Hash.String(),
			Vout: op.Index,
		})
	}
	return result, nil
}

// ============================================================================
// getbalances
//
// Reference: bitcoin-core/src/wallet/rpc/coins.cpp::getbalances (L401).
// Result shape:
//
//	{
//	  "mine": {
//	    "trusted": <amount>,
//	    "untrusted_pending": <amount>,
//	    "immature": <amount>
//	  },
//	  "lastprocessedblock": { "hash": ..., "height": ... }
//	}
//
// blockbrew has no watch-only support yet, so the optional "watchonly"
// object is omitted (matches Core's `IsWalletFlagSet(WALLET_FLAG_WATCH_ONLY)`
// gating).
// ============================================================================

// GetBalancesMine is the "mine" sub-object in getbalances.
type GetBalancesMine struct {
	Trusted          float64 `json:"trusted"`
	UntrustedPending float64 `json:"untrusted_pending"`
	Immature         float64 `json:"immature"`
}

// LastProcessedBlock matches Core's RESULT_LAST_PROCESSED_BLOCK shape.
type LastProcessedBlock struct {
	Hash   string `json:"hash"`
	Height int32  `json:"height"`
}

// GetBalancesResult is the JSON envelope returned by getbalances.
type GetBalancesResult struct {
	Mine               GetBalancesMine    `json:"mine"`
	LastProcessedBlock LastProcessedBlock `json:"lastprocessedblock"`
}

// handleGetBalances implements `getbalances`.
func (s *Server) handleGetBalances(walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	tipHeight := int32(0)
	tipHash := wire.Hash256{}
	if s.chainMgr != nil {
		tipHash, tipHeight = s.chainMgr.BestBlock()
	}

	bal := w.GetBalances(tipHeight)
	return &GetBalancesResult{
		Mine: GetBalancesMine{
			Trusted:          float64(bal.Trusted) / satoshiPerBitcoin,
			UntrustedPending: float64(bal.UntrustedPending) / satoshiPerBitcoin,
			Immature:         float64(bal.Immature) / satoshiPerBitcoin,
		},
		LastProcessedBlock: LastProcessedBlock{
			Hash:   tipHash.String(),
			Height: tipHeight,
		},
	}, nil
}

// ============================================================================
// walletcreatefundedpsbt
//
// Reference: bitcoin-core/src/wallet/rpc/spend.cpp::walletcreatefundedpsbt
// (L1653). blockbrew implementation:
//
//   - `inputs` may be empty: we then auto-select coins from the wallet using
//     existing SelectCoins (BnB → knapsack fallback).
//   - `outputs` is the standard {address: amount, ...} or [{addr: amt}, {data: hex}]
//     form (matching createrawtransaction parser).
//   - `options` honored:  changeAddress, lockUnspents, fee_rate (sat/vB),
//     feeRate (BTC/kvB), subtractFeeFromOutputs, replaceable.
//   - `bip32derivs` / `version` are accepted but version is currently fixed
//     at 2 (matching DEFAULT_WALLET_TX_VERSION); the field is parsed for
//     forward compatibility.
//   - `add_inputs` / `include_unsafe` / `minconf` / `maxconf` / `change_type`
//     / `changePosition` / `max_tx_weight` are accepted and validated but
//     not all are honored yet (blockbrew's coin-selector doesn't expose
//     these knobs — same gap as ouroboros / camlcoin per the audit).
// ============================================================================

// WalletCreateFundedPSBTResult is the result of walletcreatefundedpsbt.
type WalletCreateFundedPSBTResult struct {
	PSBT      string  `json:"psbt"`
	Fee       float64 `json:"fee"`
	ChangePos int     `json:"changepos"`
}

// handleWalletCreateFundedPSBT implements `walletcreatefundedpsbt`.
func (s *Server) handleWalletCreateFundedPSBT(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing required parameters: inputs and outputs"}
	}

	// 1. Parse inputs (may be empty / null = auto-select).
	var rawInputs []map[string]interface{}
	if string(args[0]) != "null" {
		if err := json.Unmarshal(args[0], &rawInputs); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid 'inputs' array"}
		}
	}

	// 2. Parse outputs (array of single-key objects, OR object).
	var outputs []map[string]interface{}
	if err := json.Unmarshal(args[1], &outputs); err != nil {
		var single map[string]interface{}
		if err2 := json.Unmarshal(args[1], &single); err2 != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid 'outputs'"}
		}
		outputs = []map[string]interface{}{single}
	}
	if len(outputs) == 0 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "At least one output required"}
	}

	// 3. Optional locktime (third arg).
	locktime := uint32(0)
	if len(args) >= 3 && string(args[2]) != "null" {
		var lt float64
		if err := json.Unmarshal(args[2], &lt); err == nil {
			locktime = uint32(lt)
		}
	}

	// 4. Optional options object (fourth arg).
	type fundOptions struct {
		AddInputs              *bool    `json:"add_inputs,omitempty"`
		IncludeUnsafe          *bool    `json:"include_unsafe,omitempty"`
		Minconf                *int     `json:"minconf,omitempty"`
		Maxconf                *int     `json:"maxconf,omitempty"`
		ChangeAddress          string   `json:"changeAddress,omitempty"`
		ChangePosition         *int     `json:"changePosition,omitempty"`
		ChangeType             string   `json:"change_type,omitempty"`
		LockUnspents           bool     `json:"lockUnspents,omitempty"`
		FeeRate                *float64 `json:"fee_rate,omitempty"` // sat/vB
		FeeRateLegacy          *float64 `json:"feeRate,omitempty"`  // BTC/kvB
		SubtractFeeFromOutputs []int    `json:"subtractFeeFromOutputs,omitempty"`
		Replaceable            *bool    `json:"replaceable,omitempty"`
	}
	var opts fundOptions
	if len(args) >= 4 && string(args[3]) != "null" {
		if err := json.Unmarshal(args[3], &opts); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid 'options' object"}
		}
	}

	// 5. bip32derivs (fifth arg, default true). Currently just accepted —
	//    blockbrew NewPSBT path doesn't auto-fill BIP32 derivs yet. Same as
	//    walletprocesspsbt's existing behaviour.
	bip32derivs := true
	if len(args) >= 5 && string(args[4]) != "null" {
		var b bool
		if err := json.Unmarshal(args[4], &b); err == nil {
			bip32derivs = b
		}
	}
	_ = bip32derivs

	// 6. tx version (sixth arg, default 2 = DEFAULT_WALLET_TX_VERSION).
	txVersion := int32(2)
	if len(args) >= 6 && string(args[5]) != "null" {
		var v float64
		if err := json.Unmarshal(args[5], &v); err == nil {
			txVersion = int32(v)
		}
	}

	// Determine RBF behavior. Default: signal RBF (BIP125) unless caller
	// explicitly disables.
	replaceable := true
	if opts.Replaceable != nil {
		replaceable = *opts.Replaceable
	}

	// Resolve the network for address decoding.
	net := w.Network()

	// 7. Build the unsigned transaction skeleton.
	tx := &wire.MsgTx{
		Version:  txVersion,
		LockTime: locktime,
	}

	// 7a. Add caller-supplied inputs first (preserving order).
	manualInputs := make([]wire.OutPoint, 0, len(rawInputs))
	for i, inp := range rawInputs {
		txidStr, _ := inp["txid"].(string)
		voutF, voutOK := inp["vout"].(float64)
		if txidStr == "" || !voutOK {
			return nil, &RPCError{
				Code:    RPCErrInvalidParams,
				Message: fmt.Sprintf("Invalid input %d: missing txid or vout", i),
			}
		}
		txid, err := wire.NewHash256FromHex(txidStr)
		if err != nil {
			return nil, &RPCError{
				Code:    RPCErrInvalidParams,
				Message: fmt.Sprintf("Invalid txid in input %d", i),
			}
		}
		seq := uint32(0xfffffffd) // BIP125 RBF signalling default
		if !replaceable {
			seq = 0xffffffff
		}
		if locktime > 0 && seq == 0xffffffff {
			// Core: any non-final sequence keeps locktime active.
			seq = 0xfffffffe
		}
		if seqRaw, ok := inp["sequence"].(float64); ok {
			seq = uint32(seqRaw)
		}
		op := wire.OutPoint{Hash: txid, Index: uint32(voutF)}
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: op,
			Sequence:         seq,
		})
		manualInputs = append(manualInputs, op)
	}

	// 7b. Add outputs and capture each output's amount + scriptPubKey for
	// later fee-from-output adjustment.
	type outputRec struct {
		amount   int64
		pkScript []byte
		isData   bool
	}
	var outRecs []outputRec
	for i, out := range outputs {
		// Core enforces single-key objects in array form. Loop here to
		// stay tolerant of {addr1: amt, addr2: amt} object form too,
		// which the audit doc mentions some impls accept.
		for key, val := range out {
			if key == "data" {
				dataStr, ok := val.(string)
				if !ok {
					return nil, &RPCError{
						Code:    RPCErrInvalidParams,
						Message: fmt.Sprintf("Invalid 'data' value in output %d", i),
					}
				}
				dataBytes, err := decodeHexLenient(dataStr)
				if err != nil {
					return nil, &RPCError{
						Code:    RPCErrInvalidParams,
						Message: "Invalid hex in data output",
					}
				}
				if len(dataBytes) > 80 {
					return nil, &RPCError{
						Code:    RPCErrInvalidParams,
						Message: "Data exceeds OP_RETURN limit (80 bytes)",
					}
				}
				pkScript := make([]byte, 0, 2+len(dataBytes))
				pkScript = append(pkScript, 0x6a)
				if len(dataBytes) <= 75 {
					pkScript = append(pkScript, byte(len(dataBytes)))
				} else {
					pkScript = append(pkScript, 0x4c, byte(len(dataBytes)))
				}
				pkScript = append(pkScript, dataBytes...)
				outRecs = append(outRecs, outputRec{amount: 0, pkScript: pkScript, isData: true})
				tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: 0, PkScript: pkScript})
				continue
			}

			amt, ok := val.(float64)
			if !ok {
				return nil, &RPCError{
					Code:    RPCErrInvalidParams,
					Message: fmt.Sprintf("Invalid amount for address %s", key),
				}
			}
			satoshis := int64(math.Round(amt * satoshiPerBitcoin))
			if satoshis < 0 {
				return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Negative amount"}
			}
			parsed, err := address.DecodeAddress(key, net)
			if err != nil {
				return nil, &RPCError{
					Code:    RPCErrInvalidAddressOrKey,
					Message: fmt.Sprintf("Invalid address: %s", key),
				}
			}
			pkScript := parsed.ScriptPubKey()
			outRecs = append(outRecs, outputRec{amount: satoshis, pkScript: pkScript})
			tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: satoshis, PkScript: pkScript})
		}
	}

	// 8. Determine fee rate. Order of precedence (matches Core):
	//    fee_rate (sat/vB) > feeRate (BTC/kvB) > wallet estimate.
	feeRate := 10.0 // sat/vB default
	if opts.FeeRate != nil {
		feeRate = *opts.FeeRate
	} else if opts.FeeRateLegacy != nil {
		// BTC/kvB → sat/vB: (BTC * 100_000_000 sat/BTC) / 1000 vB/kvB
		feeRate = (*opts.FeeRateLegacy) * satoshiPerBitcoin / 1000.0
	} else if s.mempool != nil {
		if est := s.mempool.EstimateFee(6); est > feeRate {
			feeRate = est
		}
	}
	if feeRate < 0 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Fee rate cannot be negative"}
	}

	// 9. Sum target output amount.
	var targetOut int64
	for _, r := range outRecs {
		targetOut += r.amount
	}

	// 10. Compute total amount of caller-supplied inputs (need wallet UTXOs).
	var manualTotal int64
	for _, op := range manualInputs {
		// We only know the value if we own the UTXO. Non-wallet inputs
		// require solving data per Core; blockbrew returns an error to
		// stay safe.
		u := walletUTXOByOutpoint(w, op)
		if u == nil {
			return nil, &RPCError{
				Code:    RPCErrInvalidParameter,
				Message: fmt.Sprintf("Input %s:%d not found in wallet (external inputs not supported)", op.Hash.String(), op.Index),
			}
		}
		manualTotal += u.Amount
	}

	// 11. Add wallet inputs to cover the shortfall, unless add_inputs=false.
	addInputs := opts.AddInputs == nil || *opts.AddInputs || len(manualInputs) == 0
	tipHeight := int32(0)
	if s.chainMgr != nil {
		_, tipHeight = s.chainMgr.BestBlock()
	}

	// Build the input-script slice for vsize estimation; we'll grow it as
	// we add coins.
	inputScripts := make([][]byte, 0, len(tx.TxIn))
	for _, op := range manualInputs {
		u := walletUTXOByOutpoint(w, op)
		inputScripts = append(inputScripts, u.PkScript)
	}

	var selected []*wallet.WalletUTXO
	totalIn := manualTotal
	if addInputs {
		// Estimate the cost of a change output (assume P2WPKH for change).
		changeOutputSize := 31
		costOfChange := int64(float64(changeOutputSize) * feeRate)

		// Available pool: exclude already-locked + already-used + immature.
		spendable := w.ListSpendable(tipHeight)
		var available []*wallet.WalletUTXO
		alreadyUsed := make(map[wire.OutPoint]bool, len(manualInputs))
		for _, op := range manualInputs {
			alreadyUsed[op] = true
		}
		for _, u := range spendable {
			if alreadyUsed[u.OutPoint] {
				continue
			}
			if w.IsLockedCoin(u.OutPoint) {
				continue
			}
			available = append(available, u)
		}

		// Estimate base fee for the existing skeleton.
		estimatedBaseVSize := wallet.EstimateTxVSize(len(tx.TxIn)+1, append(inputScripts, nil), len(tx.TxOut)+1, append(scriptsForTxOut(tx.TxOut), nil))
		baseFee := int64(float64(estimatedBaseVSize) * feeRate)
		needed := targetOut + baseFee - manualTotal

		if needed > 0 {
			selResult, err := wallet.SelectCoins(available, needed, feeRate, costOfChange)
			if err != nil {
				if errors.Is(err, wallet.ErrInsufficientFunds) {
					return nil, &RPCError{
						Code:    RPCErrWalletError,
						Message: "Insufficient funds",
					}
				}
				return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
			}
			selected = selResult.Coins
			for _, u := range selected {
				totalIn += u.Amount
				tx.TxIn = append(tx.TxIn, &wire.TxIn{
					PreviousOutPoint: u.OutPoint,
					Sequence:         sequenceForLocktime(locktime, replaceable),
				})
				inputScripts = append(inputScripts, u.PkScript)
			}
		}
	}

	if totalIn < targetOut {
		return nil, &RPCError{Code: RPCErrWalletError, Message: "Insufficient funds"}
	}

	// 12. Compute estimated fee + change. We assume one extra change
	// output sized to feeRate; if the resulting change is below dust we
	// drop it and let the difference bleed into fee.
	finalOutputScripts := scriptsForTxOut(tx.TxOut)
	estVSizeWithChange := wallet.EstimateTxVSize(len(tx.TxIn), inputScripts, len(tx.TxOut)+1, append(finalOutputScripts, nil))
	estFeeWithChange := int64(float64(estVSizeWithChange) * feeRate)

	// 12a. Apply subtractFeeFromOutputs (if any).
	if len(opts.SubtractFeeFromOutputs) > 0 {
		// Validate indices.
		for _, idx := range opts.SubtractFeeFromOutputs {
			if idx < 0 || idx >= len(tx.TxOut) {
				return nil, &RPCError{
					Code:    RPCErrInvalidParams,
					Message: fmt.Sprintf("subtractFeeFromOutputs index %d out of range", idx),
				}
			}
			if tx.TxOut[idx].Value == 0 {
				// data outputs have value 0 — splitting fee makes no sense.
				return nil, &RPCError{
					Code:    RPCErrInvalidParams,
					Message: fmt.Sprintf("Cannot subtract fee from data output %d", idx),
				}
			}
		}
		share := estFeeWithChange / int64(len(opts.SubtractFeeFromOutputs))
		remainder := estFeeWithChange % int64(len(opts.SubtractFeeFromOutputs))
		for i, idx := range opts.SubtractFeeFromOutputs {
			deduction := share
			if i == 0 {
				deduction += remainder
			}
			tx.TxOut[idx].Value -= deduction
			if tx.TxOut[idx].Value < 0 {
				return nil, &RPCError{
					Code:    RPCErrWalletError,
					Message: "Fee exceeds output amount in subtractFeeFromOutputs",
				}
			}
		}
		// targetOut shrinks accordingly so change calculation below is right.
		targetOut -= estFeeWithChange
	}

	change := totalIn - targetOut - estFeeWithChange
	changePos := -1
	if change > dustThresholdFor() {
		var changeScript []byte
		switch {
		case opts.ChangeAddress != "":
			parsed, err := address.DecodeAddress(opts.ChangeAddress, net)
			if err != nil {
				return nil, &RPCError{
					Code:    RPCErrInvalidAddressOrKey,
					Message: fmt.Sprintf("Invalid changeAddress: %s", opts.ChangeAddress),
				}
			}
			changeScript = parsed.ScriptPubKey()
		default:
			// Derive a fresh internal change address from the wallet.
			changeAddr, err := w.NewChangeAddress()
			if err != nil {
				return nil, &RPCError{Code: RPCErrWalletError, Message: fmt.Sprintf("Failed to derive change address: %v", err)}
			}
			parsed, err := address.DecodeAddress(changeAddr, net)
			if err != nil {
				return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to encode change address"}
			}
			changeScript = parsed.ScriptPubKey()
		}
		changeOut := &wire.TxOut{Value: change, PkScript: changeScript}

		insertPos := len(tx.TxOut) // append by default
		if opts.ChangePosition != nil {
			cp := *opts.ChangePosition
			if cp < 0 || cp > len(tx.TxOut) {
				return nil, &RPCError{
					Code:    RPCErrInvalidParams,
					Message: fmt.Sprintf("changePosition %d out of range", cp),
				}
			}
			insertPos = cp
		}
		tx.TxOut = append(tx.TxOut, nil)
		copy(tx.TxOut[insertPos+1:], tx.TxOut[insertPos:])
		tx.TxOut[insertPos] = changeOut
		changePos = insertPos
	}

	// 13. Lock the selected UTXOs if requested.
	if opts.LockUnspents {
		for _, u := range selected {
			w.LockCoin(u.OutPoint, false)
		}
	}

	// 14. Build the PSBT skeleton and populate WitnessUTXO for each input
	// we own (so it round-trips through walletprocesspsbt).
	psbt, err := wallet.NewPSBT(tx)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to create PSBT: %v", err)}
	}
	for i, in := range tx.TxIn {
		u := walletUTXOByOutpoint(w, in.PreviousOutPoint)
		if u == nil {
			continue
		}
		psbt.Inputs[i].WitnessUTXO = &wire.TxOut{Value: u.Amount, PkScript: u.PkScript}
	}

	encoded, err := psbt.EncodeBase64()
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to encode PSBT"}
	}

	// 15. Compute the actual fee = totalIn - sum(outputs) for reporting.
	var totalOut int64
	for _, o := range tx.TxOut {
		totalOut += o.Value
	}
	fee := totalIn - totalOut

	return &WalletCreateFundedPSBTResult{
		PSBT:      encoded,
		Fee:       float64(fee) / satoshiPerBitcoin,
		ChangePos: changePos,
	}, nil
}

// ============================================================================
// Helpers
// ============================================================================

// walletUTXOByOutpoint looks up a wallet-owned UTXO by outpoint. Returns nil
// if the UTXO is not in the wallet's set. Iterates the public ListUnspent
// to avoid breaking the wallet's encapsulation.
func walletUTXOByOutpoint(w *wallet.Wallet, op wire.OutPoint) *wallet.WalletUTXO {
	for _, u := range w.ListUnspent() {
		if u.OutPoint == op {
			return u
		}
	}
	return nil
}

// scriptsForTxOut maps TxOut → []pkScript for vsize estimation.
func scriptsForTxOut(outs []*wire.TxOut) [][]byte {
	scripts := make([][]byte, len(outs))
	for i, o := range outs {
		scripts[i] = o.PkScript
	}
	return scripts
}

// sequenceForLocktime returns the sequence number to use for a wallet-added
// input, mirroring Core's logic in CreateTransactionInternal.
func sequenceForLocktime(locktime uint32, replaceable bool) uint32 {
	if replaceable {
		return 0xfffffffd
	}
	if locktime > 0 {
		return 0xfffffffe
	}
	return 0xffffffff
}

// dustThresholdFor returns the dust threshold (sat) used by walletcreatefundedpsbt
// to decide whether a change output should be created. Mirrors Core's default
// of 546 sat for non-segwit; we use a single value to match the legacy
// CreateTransactionWithTip path in this file.
func dustThresholdFor() int64 { return 546 }

// decodeHexLenient is hex.DecodeString with empty-input allowance. Used by
// walletcreatefundedpsbt's `data` output handling.
func decodeHexLenient(s string) ([]byte, error) {
	if s == "" {
		return []byte{}, nil
	}
	return hex.DecodeString(s)
}

// _ keeps the consensus import from being flagged when CoinbaseMaturity is
// referenced only via wallet.GetBalances elsewhere.
var _ = consensus.CoinbaseMaturity
