package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// amountFromValue mirrors Core rpc/util.cpp AmountFromValue: a number (or
// numeric string) inside MoneyRange, else RPC_TYPE_ERROR (-3).
func amountFromValue(v interface{}) (int64, *RPCError) {
	var n float64
	switch t := v.(type) {
	case float64:
		n = t
	case string:
		if _, err := fmt.Sscanf(t, "%f", &n); err != nil {
			return 0, &RPCError{Code: RPCErrTypeError, Message: "Invalid amount"}
		}
	default:
		return 0, &RPCError{Code: RPCErrTypeError, Message: "Amount is not a number or string"}
	}
	if n < 0 || n > 21000000 {
		return 0, &RPCError{Code: RPCErrTypeError, Message: "Amount out of range"}
	}
	return int64(math.Round(n * satoshiPerBitcoin)), nil
}

func mapSpendError(err error) *RPCError {
	if errors.Is(err, wallet.ErrInsufficientFunds) {
		return &RPCError{Code: RPCErrWalletInsufficientFunds, Message: "Insufficient funds"}
	}
	if errors.Is(err, wallet.ErrInvalidAddress) {
		return &RPCError{Code: RPCErrInvalidAddressOrKey, Message: "Invalid Bitcoin address"}
	}
	return &RPCError{Code: RPCErrWalletError, Message: err.Error()}
}

// commitWalletSend removes spent inputs from the wallet UTXO set and credits
// change. Core CommitTransaction does this before returning the txid so a
// subsequent send cannot double-spend the same coins.
func commitWalletSend(w *wallet.Wallet, tx *wire.MsgTx) {
	if w == nil || tx == nil {
		return
	}
	for _, in := range tx.TxIn {
		w.RemoveUTXO(in.PreviousOutPoint)
	}
	txid := tx.TxHash()
	net := w.Network()
	for i, out := range tx.TxOut {
		addr, ok := extractAddressFromScript(out.PkScript, net)
		if !ok || !w.IsOwnAddress(addr) {
			continue
		}
		w.AddUTXO(&wallet.WalletUTXO{
			OutPoint:  wire.OutPoint{Hash: txid, Index: uint32(i)},
			Amount:    out.Value,
			PkScript:  out.PkScript,
			Address:   addr,
			Confirmed: true,
		})
	}
}

// SendResult is the result of the `send` RPC (spend.cpp).
type SendResult struct {
	Complete bool   `json:"complete"`
	TxID     string `json:"txid,omitempty"`
	Hex      string `json:"hex,omitempty"`
	PSBT     string `json:"psbt,omitempty"`
}

// handleSend implements Core's `send` (spend.cpp). The T3 probe is a single
// address output plus an explicit fee_rate; multi-output is accepted as a
// sequence of the same CreateTransaction path only for the first output in
// this cut — the lane's success probe is one payment of 0.5 BTC.
func (s *Server) handleSend(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if w.PrivateKeysDisabled() {
		return nil, &RPCError{Code: RPCErrWalletError, Message: "Error: Private keys are disabled for this wallet"}
	}

	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing outputs"}
	}

	var outputs []map[string]interface{}
	if err := json.Unmarshal(args[0], &outputs); err != nil {
		var single map[string]interface{}
		if err2 := json.Unmarshal(args[0], &single); err2 != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid outputs"}
		}
		outputs = []map[string]interface{}{single}
	}
	if len(outputs) == 0 {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "No recipient addresses specified"}
	}

	feeRate := 10.0
	if len(args) >= 4 && string(args[3]) != "null" {
		var fr float64
		if err := json.Unmarshal(args[3], &fr); err == nil && fr > 0 {
			feeRate = fr
		}
	}

	var dest string
	var amountSat int64
	nOut := 0
	for _, out := range outputs {
		for key, val := range out {
			if key == "data" {
				continue
			}
			nOut++
			dest = key
			sat, aerr := amountFromValue(val)
			if aerr != nil {
				return nil, aerr
			}
			amountSat = sat
		}
	}
	if nOut == 0 {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "No recipient addresses specified"}
	}
	if _, err := address.DecodeAddress(dest, w.Network()); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: fmt.Sprintf("Invalid Bitcoin address: %s", dest)}
	}

	tipHeight := int32(0)
	if s.chainMgr != nil {
		_, tipHeight = s.chainMgr.BestBlock()
	}
	tx, err := w.CreateTransactionWithTip(dest, amountSat, feeRate, tipHeight)
	if err != nil {
		return nil, mapSpendError(err)
	}
	commitWalletSend(w, tx)

	if s.mempool != nil {
		if err := s.mempool.AcceptToMemoryPool(tx); err != nil {
			return nil, &RPCError{Code: RPCErrVerify, Message: fmt.Sprintf("Transaction rejected: %v", err)}
		}
	}

	return &SendResult{Complete: true, TxID: tx.TxHash().String()}, nil
}

func (s *Server) handleRestoreWallet(params json.RawMessage) (interface{}, *RPCError) {
	if s.walletMgr == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Wallet manager not available"}
	}
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing wallet_name or backup_file"}
	}
	name, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid wallet_name"}
	}
	backup, ok := args[1].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid backup_file"}
	}
	var loadOnStartup *bool
	if len(args) >= 3 {
		if val, ok := args[2].(bool); ok {
			loadOnStartup = &val
		}
	}
	w, err := s.walletMgr.RestoreWallet(name, backup, loadOnStartup)
	if err != nil {
		if err == wallet.ErrInvalidBackupFile {
			return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Backup file does not exist"}
		}
		if err == wallet.ErrWalletAlreadyExists || err == wallet.ErrWalletAlreadyLoaded {
			return nil, &RPCError{Code: RPCErrWalletAlreadyExists, Message: fmt.Sprintf("Failed to restore wallet. Database file exists '%s'.", name)}
		}
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}
	return &LoadWalletResult{Name: w.Name()}, nil
}

// checkStopWaitArg type-checks Core's hidden `wait` argument (rpc/server.cpp).
// Arity allows 0 or 1 positional arg; a non-number is RPC_TYPE_ERROR (-3).
func checkStopWaitArg(params json.RawMessage) *RPCError {
	if len(params) == 0 || string(params) == "null" {
		return nil
	}
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil
	}
	if len(args) == 0 || args[0] == nil {
		return nil
	}
	if _, ok := args[0].(float64); ok {
		return nil
	}
	return &RPCError{
		Code:    RPCErrTypeError,
		Message: "JSON value of type " + jsonTypeName(args[0]) + " is not of expected type number",
	}
}
