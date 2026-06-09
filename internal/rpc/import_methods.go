package rpc

import (
	"encoding/json"
	"fmt"

	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// blockByHeight fetches the active-chain block at the given height, returning
// (block, true) on success. It walks the in-memory active chain (tip ancestor)
// to map height -> hash exactly as getblockhash does, then loads the block body
// from the chain database. Returns (nil, false) when the height is out of range
// or the body is unavailable (pruned / missing), which a rescan treats as an
// early stop. Mirrors the height->block resolution Core's rescan uses via
// ChainstateManager::ActiveChain()[height] + ReadBlockFromDisk.
func (s *Server) blockByHeight(height int32) (*wire.MsgBlock, bool) {
	if s.chainMgr == nil || s.chainDB == nil {
		return nil, false
	}
	tip := s.chainMgr.BestBlockNode()
	if tip == nil || height < 0 || height > tip.Height {
		return nil, false
	}
	node := tip.GetAncestor(height)
	if node == nil {
		return nil, false
	}
	block, err := s.chainDB.GetBlock(node.Hash)
	if err != nil || block == nil {
		return nil, false
	}
	return block, true
}

// handleRescanBlockchain implements the rescanblockchain RPC.
//
//	rescanblockchain ( start_height stop_height )
//	-> { "start_height": n, "stop_height": n }
//
// It rescans the active chain over [start_height, stop_height] (defaulting to
// [0, tip]) for outputs paying any script the wallet owns — HD-derived within
// the gap-limit look-ahead OR imported via importprivkey — crediting them into
// the wallet's UTXO ledger + transaction history, and debiting inputs that
// spend tracked UTXOs. This is the real wallet rescan (it rebuilds wallet
// bookkeeping), as opposed to scantxoutset which only scans the chain-level
// UTXO set without touching the wallet.
//
// Reference: bitcoin-core/src/wallet/rpc/transactions.cpp::rescanblockchain
// + CWallet::ScanForWalletTransactions.
func (s *Server) handleRescanBlockchain(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	var args []interface{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
		}
	}

	_, tipHeight := s.chainMgr.BestBlock()

	startHeight := int32(0)
	if len(args) >= 1 && args[0] != nil {
		f, ok := args[0].(float64)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid start_height"}
		}
		startHeight = int32(f)
	}
	stopHeight := tipHeight
	if len(args) >= 2 && args[1] != nil {
		f, ok := args[1].(float64)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid stop_height"}
		}
		stopHeight = int32(f)
	}

	// Core: "Invalid start_height" / "Invalid stop_height" bounds checks
	// (wallet/rpc/transactions.cpp).
	if startHeight < 0 || startHeight > tipHeight {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid start_height"}
	}
	if stopHeight < startHeight || stopHeight > tipHeight {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid stop_height"}
	}

	scannedTo, err := w.Rescan(startHeight, stopHeight, s.blockByHeight)
	if err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: fmt.Sprintf("rescan failed: %v", err)}
	}

	return map[string]interface{}{
		"start_height": startHeight,
		"stop_height":  scannedTo,
	}, nil
}

// handleDumpPrivKey implements the dumpprivkey RPC.
//
//	dumpprivkey "address" -> "WIF"
//
// Returns the WIF-encoded private key for a wallet-owned address (HD-derived
// or imported). Mirrors Bitcoin Core's dumpprivkey (wallet/rpc/backup.cpp):
// it is the natural companion of importprivkey and lets a second wallet's key
// be moved into this one. Errors with -4 if the address is not owned or the
// wallet is locked.
func (s *Server) handleDumpPrivKey(params json.RawMessage, walletName string) (interface{}, *RPCError) {
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

	key, err := w.GetKeyForAddress(addr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: fmt.Sprintf("Private key for address %s is not known", addr)}
	}

	// blockbrew derives and imports compressed keys throughout.
	return wallet.EncodeWIF(key, w.Network(), true), nil
}

// handleGetMnemonic implements the getmnemonic RPC (non-Core extension; the
// companion of createwallet's mnemonic restore parameter).
//
//	getmnemonic -> "word1 word2 ... word24"
//
// Returns the wallet's BIP-39 recovery phrase, persisted in the encrypted
// wallet file at creation (W161 BUG-15/17 funds-loss fix). This is blockbrew's
// seed-export surface — the analog of Bitcoin Core's listdescriptors
// private=true (which reveals the master xprv only after
// EnsureWalletIsUnlocked, bitcoin-core/src/wallet/rpc/backup.cpp) and of
// legacy dumpwallet's 'hdseed=1' line. Like Core, the export is a separate,
// explicit, unlock-gated call and the words are never logged.
//
// Errors:
//
//	-13 RPCErrWalletUnlockNeeded  when the wallet is locked
//	 -4 RPCErrWalletError         when no mnemonic is stored (blank/watch-only
//	                              wallet, or a wallet file written before
//	                              mnemonic persistence existed)
func (s *Server) handleGetMnemonic(walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	mnemonic, err := w.Mnemonic()
	if err != nil {
		if err == wallet.ErrWalletLocked {
			return nil, &RPCError{Code: RPCErrWalletUnlockNeeded, Message: "Error: Please enter the wallet passphrase with walletpassphrase first."}
		}
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}
	return mnemonic, nil
}

// handleImportPrivKey implements the importprivkey RPC.
//
//	importprivkey "privkey" ( "label" rescan )
//
// It decodes the WIF, registers the key + its standard addresses (P2WPKH,
// P2PKH, P2SH-P2WPKH) as wallet-owned, and — when rescan is true (the default)
// — rescans the active chain to credit the key's existing funds. Returns null
// on success, matching Core (wallet/rpc/backup.cpp::importprivkey).
func (s *Server) handleImportPrivKey(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing private key (WIF)"}
	}
	wif, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid private key"}
	}

	label := ""
	if len(args) >= 2 {
		if l, ok := args[1].(string); ok {
			label = l
		}
	}
	rescan := true
	if len(args) >= 3 {
		if b, ok := args[2].(bool); ok {
			rescan = b
		}
	}

	privKey, err := wallet.DecodeWIF(wif, w.Network())
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: "Invalid private key encoding"}
	}

	if _, err := w.ImportPrivKey(privKey, label); err != nil {
		return nil, &RPCError{Code: RPCErrWalletError, Message: err.Error()}
	}

	if rescan {
		if s.chainMgr == nil {
			return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
		}
		_, tipHeight := s.chainMgr.BestBlock()
		if _, err := w.Rescan(0, tipHeight, s.blockByHeight); err != nil {
			return nil, &RPCError{Code: RPCErrWalletError, Message: fmt.Sprintf("rescan failed: %v", err)}
		}
	}

	return nil, nil
}
