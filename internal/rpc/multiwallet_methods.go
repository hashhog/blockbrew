package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// walletCoinbaseMaturity is the confirmation threshold below which a coinbase
// credit renders as "immature" rather than "generate" in listtransactions /
// gettransaction, matching the wallet's spendability rule
// (GetSpendableBalance) and Core's IsTxImmatureCoinBase.
const walletCoinbaseMaturity = consensus.CoinbaseMaturity

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
	// args[7] is external_signer (Core arg; not supported in blockbrew — ignored)
	// args[8] is BIP-39 seed passphrase ("25th word"). Non-Core extension
	// — distinct from args[3] which is the wallet-file encryption passphrase.
	// W161 BUG-16 fix: previously dropped before PBKDF2; now plumbed through
	// CreateWalletOpts.SeedPassphrase into MnemonicToSeed. See
	// CORE-PARITY-AUDIT/w161-bip32-bip39-bip43-bip44-hd-derivation.md.
	if len(args) >= 9 {
		if val, ok := args[8].(string); ok {
			opts.SeedPassphrase = val
		}
	}
	// args[9] is a BIP-39 mnemonic to RESTORE from. Non-Core extension
	// (Core uses createwallet(blank=true)+sethdseed); blockbrew exposes
	// seed-only recovery directly on createwallet so the same words always
	// re-derive byte-identical keys+addresses. Mirrors ouroboros's
	// createwallet `mnemonic` param. Empty/absent → fresh random wallet.
	if len(args) >= 10 {
		if val, ok := args[9].(string); ok {
			opts.Mnemonic = val
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

	// Bitcoin Core's `getbalance` returns m_mine_trusted (wallet/rpc/coins.cpp:
	// `return ValueFromAmount(bal.m_mine_trusted)`), which is the confirmed
	// balance EXCLUDING immature coinbase outputs. Use the maturity-aware
	// spendable balance at the current tip rather than Wallet.GetBalance (which
	// sums every confirmed UTXO including not-yet-mature coinbase). Without the
	// tip height the wallet cannot tell mature from immature coinbase, so a
	// freshly mined chain would report the full subsidy instead of only the
	// spendable portion.
	tipHeight := int32(0)
	if s.chainMgr != nil {
		_, tipHeight = s.chainMgr.BestBlock()
	}
	spendable, _ := w.GetSpendableBalance(tipHeight)
	return float64(spendable) / satoshiPerBitcoin, nil
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
		if err := s.mempool.AcceptToMemoryPool(tx); err != nil {
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

// handleEncryptWalletWithWallet implements `encryptwallet "passphrase"` for
// the multi-wallet routing path. See handleEncryptWallet for semantics.
func (s *Server) handleEncryptWalletWithWallet(params json.RawMessage, walletName string) (interface{}, *RPCError) {
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
	if passphrase == "" {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "passphrase cannot be empty"}
	}

	if err := w.EncryptWallet(passphrase); err != nil {
		return nil, mapEncryptionError(err)
	}

	return "wallet encrypted; the keypool has been flushed. The wallet is now locked; use walletpassphrase to unlock.", nil
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
	if passphrase == "" {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "passphrase cannot be empty"}
	}

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

	if w.IsEncrypted() {
		if err := w.UnlockWithPassphrase(passphrase, timeout); err != nil {
			return nil, mapEncryptionError(err)
		}
		return nil, nil
	}

	// Backward-compatible path for pre-encryption wallets.
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

	if !w.IsEncrypted() {
		return nil, &RPCError{
			Code:    RPCErrWalletWrongEncState,
			Message: "Error: running with an unencrypted wallet, but walletlock was called.",
		}
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

	skip := 0
	if params != nil {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err == nil {
			if len(args) >= 3 {
				if sk, ok := args[2].(float64); ok && sk > 0 {
					skip = int(sk)
				}
			}
		}
	}

	history := w.GetHistory()

	// Flatten history (oldest→newest) into per-detail entries, then apply
	// skip/count over the most-recent window, matching Core's
	// listtransactions ordering (oldest first, then the last `count` after
	// skipping `skip` from the tail). Reference:
	// bitcoin-core/src/wallet/rpc/transactions.cpp::listtransactions.
	all := make([]ListTransactionsResult, 0, len(history))
	for _, tx := range history {
		all = append(all, s.walletTxToListEntries(tx, tipHeight)...)
	}

	// Select the window: Core returns entries [nFrom, nFrom+nCount) counting
	// from the END (most recent). We keep oldest→newest order within the page.
	n := len(all)
	end := n - skip
	if end < 0 {
		end = 0
	}
	start := end - count
	if start < 0 {
		start = 0
	}
	page := all[start:end]

	result := make([]ListTransactionsResult, len(page))
	copy(result, page)
	return result, nil
}

// walletTxToListEntries renders a wallet transaction into zero or more
// listtransactions entries — one per credit/debit detail — applying Core's
// sign conventions and the coinbase generate/immature/orphan split using the
// live tip height. Reference: bitcoin-core/src/wallet/rpc/transactions.cpp::
// ListTransactions + WalletTxToJSON.
func (s *Server) walletTxToListEntries(tx *wallet.WalletTx, tipHeight int32) []ListTransactionsResult {
	confs := int32(0)
	if tx.Height > 0 {
		confs = tipHeight - tx.Height + 1
	}
	txid := tx.TxHash.String()
	blockHash := ""
	if !tx.BlockHash.IsZero() {
		blockHash = tx.BlockHash.String()
	}
	bip125 := s.bip125ReplaceableForWalletTx(tx.TxHash, confs)

	out := make([]ListTransactionsResult, 0, len(tx.Details))
	for _, d := range tx.Details {
		entry := ListTransactionsResult{
			Address:           d.Address,
			Vout:              d.Vout,
			Confirmations:     confs,
			TxID:              txid,
			Time:              tx.Timestamp,
			BlockHeight:       tx.Height,
			BlockHash:         blockHash,
			BlockTime:         tx.Timestamp,
			BIP125Replaceable: bip125,
		}
		switch d.Category {
		case "send":
			entry.Category = "send"
			entry.Amount = -float64(d.Amount) / satoshiPerBitcoin // negative
			entry.Fee = -float64(tx.Fee) / satoshiPerBitcoin       // negative
		default: // receive / generate / immature
			entry.Category = coinbaseCategory(d, confs)
			entry.Amount = float64(d.Amount) / satoshiPerBitcoin // positive
			if d.IsCoinbase {
				entry.Generated = true
			}
		}
		out = append(out, entry)
	}
	return out
}

// coinbaseCategory resolves the receive/generate/immature/orphan category for a
// detail given its confirmation count, mirroring Core's ListTransactions:
// non-coinbase → "receive"; coinbase with <1 conf → "orphan"; coinbase still
// immature (< CoinbaseMaturity confs) → "immature"; otherwise → "generate".
func coinbaseCategory(d wallet.WalletTxDetail, confs int32) string {
	if !d.IsCoinbase {
		return "receive"
	}
	if confs < 1 {
		return "orphan"
	}
	if confs < walletCoinbaseMaturity {
		return "immature"
	}
	return "generate"
}

// handleGetTransactionWithWallet implements `gettransaction <txid>`, returning
// the wallet's view of one transaction it sent or received. Shape mirrors
// Bitcoin Core's src/wallet/rpc/transactions.cpp::gettransaction: top-level
// amount = nNet - nFee (negative for a spend), fee present (negative) only for
// from-me txs, plus a per-output details[] array and the raw hex.
func (s *Server) handleGetTransactionWithWallet(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "txid required"}
	}
	txidStr, ok := args[0].(string)
	if !ok || len(txidStr) != 64 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid txid"}
	}
	txid, err := wire.NewHash256FromHex(txidStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid txid"}
	}

	tx := w.GetTransaction(txid)
	if tx == nil {
		// Match Core's error for an unknown wallet tx.
		return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: "Invalid or non-wallet transaction id"}
	}

	_, tipHeight := int32(0), int32(0)
	if s.chainMgr != nil {
		_, tipHeight = s.chainMgr.BestBlock()
	}
	confs := int32(0)
	if tx.Height > 0 {
		confs = tipHeight - tx.Height + 1
	}

	// Top-level amount mirrors Core gettransaction: amount = nNet - nFee,
	// where Core's gettransaction nFee = GetValueOut() - nDebit (i.e. the
	// NEGATIVE of the real fee). Our tx.Fee is the positive real fee
	// (Debit - ValueOut), so amount = tx.Net - (-tx.Fee) = tx.Net + tx.Fee.
	// For a 10 BTC send with change this yields exactly -10.0 (the value that
	// left the wallet, NOT including the fee, which is reported separately).
	// For a receive tx.Fee == 0 so amount == net (positive credit).
	netSats := tx.Net + tx.Fee
	res := &GetTransactionResult{
		Amount:        float64(netSats) / satoshiPerBitcoin,
		Confirmations: confs,
		TxID:          tx.TxHash.String(),
		Time:          tx.Timestamp,
		TimeReceived:  tx.Timestamp,
		BlockHeight:   tx.Height,
		Hex:           tx.RawHex,
	}
	if tx.IsFromMe {
		res.Fee = -float64(tx.Fee) / satoshiPerBitcoin // negative, Core convention
	}
	if tx.IsCoinbase {
		res.Generated = true
	}
	if !tx.BlockHash.IsZero() {
		res.BlockHash = tx.BlockHash.String()
		res.BlockTime = tx.Timestamp
	}

	// details[] is the same per-output breakdown listtransactions emits,
	// rendered with gettransaction's narrower field set (Core calls
	// ListTransactions with fLong=false).
	entries := s.walletTxToListEntries(tx, tipHeight)
	res.Details = make([]GetTransactionDetail, 0, len(entries))
	for _, e := range entries {
		res.Details = append(res.Details, GetTransactionDetail{
			Address:  e.Address,
			Category: e.Category,
			Amount:   e.Amount,
			Vout:     e.Vout,
			Fee:      e.Fee,
		})
	}

	return res, nil
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
