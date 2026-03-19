package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/hashhog/blockbrew/internal/wallet"
)

// ============================================================================
// Wallet Management RPCs
// ============================================================================

// handleCreateWallet creates a new wallet.
func (s *Server) handleCreateWallet(params json.RawMessage) (interface{}, *RPCError) {
	if s.walletMgr == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Wallet manager not available"}
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing wallet name"}
	}

	name, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid wallet name"}
	}

	opts := wallet.CreateWalletOpts{}

	// Parse optional parameters
	if len(args) >= 2 {
		if val, ok := args[1].(bool); ok {
			opts.DisablePrivateKeys = val
		}
	}
	if len(args) >= 3 {
		if val, ok := args[2].(bool); ok {
			opts.Blank = val
		}
	}
	if len(args) >= 4 {
		if val, ok := args[3].(string); ok {
			opts.Passphrase = val
		}
	}
	if len(args) >= 5 {
		if val, ok := args[4].(bool); ok {
			opts.AvoidReuse = val
		}
	}
	// args[5] is descriptors (ignored, always true in blockbrew)
	if len(args) >= 7 {
		if val, ok := args[6].(bool); ok {
			opts.LoadOnStartup = &val
		}
	}

	w, err := s.walletMgr.CreateWallet(name, opts)
	if err != nil {
		if err == wallet.ErrWalletAlreadyLoaded {
			return nil, &RPCError{Code: RPCErrWalletAlreadyLoaded, Message: fmt.Sprintf("Wallet \"%s\" is already loaded", name)}
		}
		if err == wallet.ErrWalletAlreadyExists {
			return nil, &RPCError{Code: RPCErrWalletError, Message: fmt.Sprintf("Wallet \"%s\" already exists", name)}
		}
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}

	var warnings []string
	if opts.Passphrase == "" {
		warnings = append(warnings, "Empty string given as passphrase, wallet will not be encrypted.")
	}

	return &CreateWalletResult{
		Name:     w.Name(),
		Warnings: warnings,
	}, nil
}

// handleLoadWallet loads an existing wallet.
func (s *Server) handleLoadWallet(params json.RawMessage) (interface{}, *RPCError) {
	if s.walletMgr == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Wallet manager not available"}
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing wallet filename"}
	}

	name, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid wallet filename"}
	}

	var loadOnStartup *bool
	if len(args) >= 2 {
		if val, ok := args[1].(bool); ok {
			loadOnStartup = &val
		}
	}

	w, err := s.walletMgr.LoadWallet(name, loadOnStartup)
	if err != nil {
		if err == wallet.ErrWalletAlreadyLoaded {
			return nil, &RPCError{Code: RPCErrWalletAlreadyLoaded, Message: fmt.Sprintf("Wallet \"%s\" is already loaded", name)}
		}
		if err == wallet.ErrWalletNotFound {
			return nil, &RPCError{Code: RPCErrWalletNotFound, Message: fmt.Sprintf("Wallet \"%s\" not found", name)}
		}
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}

	return &LoadWalletResult{
		Name: w.Name(),
	}, nil
}

// handleUnloadWallet unloads a wallet.
func (s *Server) handleUnloadWallet(params json.RawMessage, walletNameFromURL string) (interface{}, *RPCError) {
	if s.walletMgr == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Wallet manager not available"}
	}

	// Determine wallet name: from params, or from URL, or single loaded wallet
	var walletName string

	var args []interface{}
	if params != nil {
		if err := json.Unmarshal(params, &args); err == nil && len(args) >= 1 {
			if name, ok := args[0].(string); ok && name != "" {
				walletName = name
			}
		}
	}

	if walletName == "" {
		walletName = walletNameFromURL
	}

	// If still empty, try to get the single loaded wallet
	if walletName == "" {
		w, err := s.walletMgr.GetDefaultWallet()
		if err != nil {
			if err == wallet.ErrMultipleWalletsNamed {
				return nil, &RPCError{Code: RPCErrWalletNotSpecified, Message: "Wallet file not specified (multiple wallets loaded)"}
			}
			return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "No wallet loaded"}
		}
		walletName = w.Name()
	}

	// Verify both sources match if both specified
	if walletNameFromURL != "" && len(args) >= 1 {
		if name, ok := args[0].(string); ok && name != "" && name != walletNameFromURL {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "wallet_name argument does not match wallet endpoint"}
		}
	}

	var loadOnStartup *bool
	if len(args) >= 2 {
		if val, ok := args[1].(bool); ok {
			loadOnStartup = &val
		}
	}

	err := s.walletMgr.UnloadWallet(walletName, loadOnStartup)
	if err != nil {
		if err == wallet.ErrWalletNotFound {
			return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Requested wallet does not exist or is not loaded"}
		}
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}

	return &UnloadWalletResult{}, nil
}

// handleListWallets returns names of all loaded wallets.
func (s *Server) handleListWallets() (interface{}, *RPCError) {
	if s.walletMgr == nil {
		// Legacy mode: return single wallet name if loaded
		if s.wallet != nil {
			return []string{""}, nil
		}
		return []string{}, nil
	}

	return s.walletMgr.ListWallets(), nil
}

// handleListWalletDir returns all wallets in the wallet directory.
func (s *Server) handleListWalletDir() (interface{}, *RPCError) {
	if s.walletMgr == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Wallet manager not available"}
	}

	walletInfos := s.walletMgr.ListWalletDir()
	entries := make([]WalletDirEntry, 0, len(walletInfos))
	for _, info := range walletInfos {
		entries = append(entries, WalletDirEntry{
			Name:     info.Name,
			Warnings: info.Warnings,
		})
	}

	return &ListWalletDirResult{
		Wallets: entries,
	}, nil
}

// handleBackupWallet backs up a wallet to a destination.
func (s *Server) handleBackupWallet(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing destination"}
	}

	destination, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid destination"}
	}

	if s.walletMgr != nil {
		// Determine wallet to backup
		if walletName == "" {
			w, err := s.walletMgr.GetDefaultWallet()
			if err != nil {
				if err == wallet.ErrMultipleWalletsNamed {
					return nil, &RPCError{Code: RPCErrWalletNotSpecified, Message: "Wallet file not specified (multiple wallets loaded)"}
				}
				return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "No wallet loaded"}
			}
			walletName = w.Name()
		}

		if err := s.walletMgr.BackupWallet(walletName, destination); err != nil {
			return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
		}
	} else if s.wallet != nil {
		if err := s.wallet.SaveToFile(""); err != nil {
			return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
		}
		// For legacy mode, just return success (actual backup not implemented)
	} else {
		return nil, &RPCError{Code: RPCErrWalletNotFound, Message: "Wallet not loaded"}
	}

	return nil, nil
}

// ============================================================================
// Wallet RPCs with wallet context (multi-wallet support)
// ============================================================================

func (s *Server) handleGetNewAddressWithWallet(walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	addr, err := w.NewAddress()
	if err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}

	return addr, nil
}

func (s *Server) handleGetBalanceWithWallet(walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	confirmed, _ := w.GetBalance()
	return float64(confirmed) / satoshiPerBitcoin, nil
}

func (s *Server) handleListUnspentWithWallet(walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	utxos := w.ListUnspent()
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

		spendable := !w.IsLocked() && w.IsUTXOSpendable(u, tipHeight)

		result = append(result, ListUnspentResult{
			TxID:          u.OutPoint.Hash.String(),
			Vout:          u.OutPoint.Index,
			Address:       u.Address,
			Label:         w.GetLabel(u.Address),
			Amount:        float64(u.Amount) / satoshiPerBitcoin,
			Confirmations: confs,
			Spendable:     spendable,
			Solvable:      true,
			Safe:          u.Confirmed,
		})
	}

	return result, nil
}

func (s *Server) handleSendToAddressWithWallet(params json.RawMessage, walletName string) (interface{}, *RPCError) {
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

	feeRate := 10.0
	if s.mempool != nil {
		estimated := s.mempool.EstimateFee(6)
		if estimated > feeRate {
			feeRate = estimated
		}
	}

	tipHeight := int32(0)
	if s.chainMgr != nil {
		_, tipHeight = s.chainMgr.BestBlock()
	}

	tx, err := w.CreateTransactionWithTip(addr, amountSat, feeRate, tipHeight)
	if err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}

	if s.mempool != nil {
		if err := s.mempool.AddTransaction(tx); err != nil {
			return nil, &RPCError{Code: RPCErrVerify, Message: fmt.Sprintf("Transaction rejected: %v", err)}
		}
	}

	if s.peerMgr != nil {
		var buf bytes.Buffer
		if err := tx.Serialize(&buf); err == nil {
			_ = hex.EncodeToString(buf.Bytes())
		}
	}

	return tx.TxHash().String(), nil
}

func (s *Server) handleWalletPassphraseWithWallet(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
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

	if err := w.Unlock(passphrase, ""); err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: fmt.Sprintf("Failed to unlock wallet: %v", err)}
	}

	return nil, nil
}

func (s *Server) handleWalletLockWithWallet(walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	w.Lock()
	return nil, nil
}

func (s *Server) handleListTransactionsWithWallet(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	count := 10
	if params != nil {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err == nil {
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

	history := w.GetHistory()

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

func (s *Server) handleGetWalletInfoWithWallet(walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	confirmed, unconfirmed := w.GetBalance()
	history := w.GetHistory()

	return &WalletInfo{
		WalletName:            w.Name(),
		WalletVersion:         169900, // Latest legacy wallet version for compatibility
		Format:                "sqlite",
		Balance:               float64(confirmed) / satoshiPerBitcoin,
		UnconfirmedBalance:    float64(unconfirmed) / satoshiPerBitcoin,
		TxCount:               len(history),
		KeypoolSize:           20,
		PayTxFee:              0,
		PrivateKeysEnabled:    true,
		AvoidReuse:            false,
		Scanning:              false,
		Descriptors:           true,
		ExternalSigner:        false,
		Blank:                 confirmed == 0 && unconfirmed == 0 && len(history) == 0,
		Locked:                w.IsLocked(),
	}, nil
}

func (s *Server) handleSetLabelWithWallet(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
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

	if err := w.SetLabel(addr, label); err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}

	return nil, nil
}

func (s *Server) handleListLabelsWithWallet(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	labels := w.ListLabels()
	return labels, nil
}

func (s *Server) handleGetAddressesByLabelWithWallet(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
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

	addrs := w.GetAddressesByLabel(label)

	result := make(map[string]AddressByLabelResult)
	for _, addr := range addrs {
		result[addr] = AddressByLabelResult{Purpose: "receive"}
	}
	return result, nil
}

func (s *Server) handleGetAddressInfoWithWallet(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
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

	isMine := w.IsOwnAddress(addr)
	label := w.GetLabel(addr)

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

func (s *Server) handleWalletProcessPSBTWithWallet(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	// Delegate to the existing implementation but use the resolved wallet
	// This requires temporarily setting s.wallet (hacky but maintains compatibility)
	oldWallet := s.wallet
	s.wallet = w
	defer func() { s.wallet = oldWallet }()

	return s.handleWalletProcessPSBT(params)
}
