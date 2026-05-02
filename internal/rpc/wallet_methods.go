package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashhog/blockbrew/internal/wallet"
)

// ============================================================================
// Wallet RPCs
// ============================================================================

func (s *Server) handleGetNewAddress() (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	addr, err := s.wallet.NewAddress()
	if err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}

	return addr, nil
}

func (s *Server) handleGetBalance() (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	confirmed, _ := s.wallet.GetBalance()
	return float64(confirmed) / satoshiPerBitcoin, nil
}

func (s *Server) handleListUnspent() (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	utxos := s.wallet.ListUnspent()
	_, tipHeight := int32(0), int32(0)
	if s.chainMgr != nil {
		_, tipHeight = s.chainMgr.BestBlock()
	}

	result := make([]ListUnspentResult, 0, len(utxos))
	for _, u := range utxos {
		confs := int32(0)
		if u.Confirmed && u.Height > 0 {
			confs = tipHeight - u.Height + 1
		}

		// Check if spendable (wallet unlocked AND not immature coinbase)
		spendable := !s.wallet.IsLocked() && s.wallet.IsUTXOSpendable(u, tipHeight)

		result = append(result, ListUnspentResult{
			TxID:          u.OutPoint.Hash.String(),
			Vout:          u.OutPoint.Index,
			Address:       u.Address,
			Label:         s.wallet.GetLabel(u.Address),
			Amount:        float64(u.Amount) / satoshiPerBitcoin,
			Confirmations: confs,
			Spendable:     spendable,
			Solvable:      true,
			Safe:          u.Confirmed,
		})
	}

	return result, nil
}

func (s *Server) handleSendToAddress(params json.RawMessage) (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
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

	// Default fee rate: 10 sat/vB
	feeRate := 10.0
	if len(args) >= 3 {
		// args[2] is comment (ignored), args[3] is comment_to (ignored)
		// For custom fee rate, we could add an extension
	}

	// Estimate fee rate from mempool if available
	if s.mempool != nil {
		estimated := s.mempool.EstimateFee(6)
		if estimated > feeRate {
			feeRate = estimated
		}
	}

	// Get current tip height for coinbase maturity check
	tipHeight := int32(0)
	if s.chainMgr != nil {
		_, tipHeight = s.chainMgr.BestBlock()
	}

	tx, err := s.wallet.CreateTransactionWithTip(addr, amountSat, feeRate, tipHeight)
	if err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}

	// Add to mempool
	if s.mempool != nil {
		if err := s.mempool.AcceptToMemoryPool(tx); err != nil {
			return nil, &RPCError{Code: RPCErrVerify, Message: fmt.Sprintf("Transaction rejected: %v", err)}
		}
	}

	// Broadcast to peers
	if s.peerMgr != nil {
		var buf bytes.Buffer
		if err := tx.Serialize(&buf); err == nil {
			_ = hex.EncodeToString(buf.Bytes())
			// TODO: broadcast inv to peers
		}
	}

	return tx.TxHash().String(), nil
}

// handleEncryptWallet implements `encryptwallet "passphrase"`.
//
// Encrypts the master HD key under the supplied passphrase and locks the
// wallet. Reference: bitcoin-core/src/wallet/rpc/encrypt.cpp::encryptwallet.
//
// Errors:
//   -15 RPCErrWalletWrongEncState     when the wallet is already encrypted
//   -8  RPCErrInvalidParameter        when passphrase is empty
//   -16 RPCErrWalletEncryptionFailed  when encryption fails internally
func (s *Server) handleEncryptWallet(params json.RawMessage) (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing passphrase"}
	}
	passphrase, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid passphrase"}
	}
	if passphrase == "" {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "passphrase cannot be empty"}
	}

	if err := s.wallet.EncryptWallet(passphrase); err != nil {
		return nil, mapEncryptionError(err)
	}

	return "wallet encrypted; the keypool has been flushed. The wallet is now locked; use walletpassphrase to unlock.", nil
}

// handleWalletPassphrase implements `walletpassphrase "passphrase" timeout`.
//
// Decrypts the master key for `timeout` seconds, then auto-relocks via a
// time.AfterFunc callback. If the wallet is not yet encrypted (i.e. created
// without EncryptWallet), falls back to the legacy mnemonic-unlock for
// backward compatibility with pre-encryption blockbrew callers.
//
// Reference: bitcoin-core/src/wallet/rpc/encrypt.cpp::walletpassphrase.
func (s *Server) handleWalletPassphrase(params json.RawMessage) (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing passphrase"}
	}

	passphrase, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid passphrase"}
	}
	if passphrase == "" {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "passphrase cannot be empty"}
	}

	// Bitcoin Core behavior: timeout in seconds, second positional arg.
	// If absent, fall back to a 60s default for ergonomic CLI use.
	var timeout int64 = 60
	if len(args) >= 2 {
		switch t := args[1].(type) {
		case float64:
			timeout = int64(t)
		case int64:
			timeout = t
		default:
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid timeout"}
		}
	}
	if timeout < 0 {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Timeout cannot be negative."}
	}

	if s.wallet.IsEncrypted() {
		if err := s.wallet.UnlockWithPassphrase(passphrase, timeout); err != nil {
			return nil, mapEncryptionError(err)
		}
		return nil, nil
	}

	// Backward-compatible path: pre-encryption wallets use the mnemonic.
	if err := s.wallet.Unlock(passphrase, ""); err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: fmt.Sprintf("Failed to unlock wallet: %v", err)}
	}
	return nil, nil
}

// handleWalletLock implements `walletlock`. Zeroes the in-memory master key
// and clears any pending auto-relock timer. Reference:
// bitcoin-core/src/wallet/rpc/encrypt.cpp::walletlock.
func (s *Server) handleWalletLock() (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	if !s.wallet.IsEncrypted() {
		return nil, &RPCError{
			Code:    RPCErrWalletWrongEncState,
			Message: "Error: running with an unencrypted wallet, but walletlock was called.",
		}
	}

	s.wallet.Lock()
	return nil, nil
}

// mapEncryptionError converts wallet-package errors into the canonical
// JSON-RPC error codes from bitcoin-core/src/rpc/protocol.h.
func mapEncryptionError(err error) *RPCError {
	switch {
	case errors.Is(err, wallet.ErrWalletAlreadyEncrypted):
		return &RPCError{
			Code:    RPCErrWalletWrongEncState,
			Message: "Error: running with an encrypted wallet, but encryptwallet was called.",
		}
	case errors.Is(err, wallet.ErrWalletNotEncrypted):
		return &RPCError{
			Code:    RPCErrWalletWrongEncState,
			Message: "Error: running with an unencrypted wallet, but walletpassphrase was called.",
		}
	case errors.Is(err, wallet.ErrPassphraseIncorrect):
		return &RPCError{
			Code:    RPCErrWalletPassphraseIncorrect,
			Message: "Error: The wallet passphrase entered was incorrect.",
		}
	case errors.Is(err, wallet.ErrEmptyPassphrase):
		return &RPCError{
			Code:    RPCErrInvalidParameter,
			Message: "passphrase cannot be empty",
		}
	case errors.Is(err, wallet.ErrNoMasterKey):
		return &RPCError{
			Code:    RPCErrWalletEncryptionFailed,
			Message: "Error: wallet does not contain private keys, nothing to encrypt.",
		}
	default:
		return &RPCError{Code: RPCErrWalletEncryptionFailed, Message: err.Error()}
	}
}

func (s *Server) handleListTransactions(params json.RawMessage) (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	count := 10
	if params != nil {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err == nil {
			// args[0] is label (ignored), args[1] is count
			if len(args) >= 2 {
				if c, ok := args[1].(float64); ok {
					count = int(c)
				}
			}
		}
	}

	_, tipHeight := int32(0), int32(0)
	if s.chainMgr != nil {
		_, tipHeight = s.chainMgr.BestBlock()
	}

	history := s.wallet.GetHistory()

	// Return most recent transactions (up to count)
	start := len(history) - count
	if start < 0 {
		start = 0
	}

	result := make([]ListTransactionsResult, 0, count)
	for i := len(history) - 1; i >= start; i-- {
		tx := history[i]

		category := "receive"
		if tx.Amount < 0 {
			category = "send"
		}

		confs := int32(0)
		if tx.Height > 0 {
			confs = tipHeight - tx.Height + 1
		}

		result = append(result, ListTransactionsResult{
			Address:       tx.Address,
			Category:      category,
			Amount:        float64(tx.Amount) / satoshiPerBitcoin,
			Fee:           float64(tx.Fee) / satoshiPerBitcoin,
			Confirmations: confs,
			TxID:          tx.TxHash.String(),
			Time:          tx.Timestamp,
			BlockHeight:   tx.Height,
		})
	}

	return result, nil
}

func (s *Server) handleGetWalletInfo() (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	confirmed, unconfirmed := s.wallet.GetBalance()
	history := s.wallet.GetHistory()

	return &WalletInfo{
		WalletName:         "default",
		WalletVersion:      1,
		Balance:            float64(confirmed) / satoshiPerBitcoin,
		UnconfirmedBalance: float64(unconfirmed) / satoshiPerBitcoin,
		TxCount:            len(history),
		KeypoolSize:        20,
		PayTxFee:           0,
		Locked:             s.wallet.IsLocked(),
	}, nil
}

// ============================================================================
// Address Label RPCs
// ============================================================================

func (s *Server) handleSetLabel(params json.RawMessage) (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing address and/or label"}
	}

	addr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid address"}
	}

	label, ok := args[1].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid label"}
	}

	if err := s.wallet.SetLabel(addr, label); err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}

	return nil, nil
}

func (s *Server) handleListLabels(params json.RawMessage) (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	// Optional purpose filter (receive or send), ignored for now
	labels := s.wallet.ListLabels()
	return labels, nil
}

func (s *Server) handleGetAddressesByLabel(params json.RawMessage) (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing label"}
	}

	label, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid label"}
	}

	addrs := s.wallet.GetAddressesByLabel(label)

	// Return as map of address -> purpose (Bitcoin Core format)
	result := make(map[string]AddressByLabelResult)
	for _, addr := range addrs {
		result[addr] = AddressByLabelResult{Purpose: "receive"}
	}
	return result, nil
}

func (s *Server) handleGetAddressInfo(params json.RawMessage) (interface{}, *RPCError) {
	if s.wallet == nil {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing address"}
	}

	addr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid address"}
	}

	isMine := s.wallet.IsOwnAddress(addr)
	label := s.wallet.GetLabel(addr)

	result := &AddressInfoResult{
		Address:     addr,
		IsMine:      isMine,
		IsWatchOnly: false,
		Solvable:    isMine,
		Label:       label,
	}

	if label != "" {
		result.Labels = []struct {
			Name    string `json:"name"`
			Purpose string `json:"purpose"`
		}{{Name: label, Purpose: "receive"}}
	}

	return result, nil
}
