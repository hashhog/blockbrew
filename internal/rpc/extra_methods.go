package rpc

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	bbcrypto "github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ============================================================================
// Additional Blockchain RPCs
// ============================================================================

func (s *Server) handleGetTxOut(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing txid and vout parameters"}
	}

	txidStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid txid"}
	}

	voutFloat, ok := args[1].(float64)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid vout"}
	}
	vout := uint32(voutFloat)

	includeMempool := true
	if len(args) >= 3 {
		if v, ok := args[2].(bool); ok {
			includeMempool = v
		}
	}

	txid, err := wire.NewHash256FromHex(txidStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid txid format"}
	}

	outpoint := wire.OutPoint{Hash: txid, Index: vout}

	// Check mempool first
	if includeMempool && s.mempool != nil {
		if spender := s.mempool.CheckSpend(outpoint); spender != nil {
			return nil, nil // Output is spent in mempool
		}
	}

	// Check UTXO set
	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	utxo := s.chainMgr.UTXOSet().GetUTXO(outpoint)
	if utxo == nil {
		return nil, nil // Output not found or already spent
	}

	bestHash, tipHeight := s.chainMgr.BestBlock()
	confs := tipHeight - utxo.Height + 1

	scriptType := "unknown"
	if consensus.IsP2PKH(utxo.PkScript) {
		scriptType = "pubkeyhash"
	} else if consensus.IsP2SH(utxo.PkScript) {
		scriptType = "scripthash"
	} else if consensus.IsP2WPKH(utxo.PkScript) {
		scriptType = "witness_v0_keyhash"
	} else if consensus.IsP2WSH(utxo.PkScript) {
		scriptType = "witness_v0_scripthash"
	} else if consensus.IsP2TR(utxo.PkScript) {
		scriptType = "witness_v1_taproot"
	}

	return &TxOutResult{
		BestBlock:     bestHash.String(),
		Confirmations: confs,
		Value:         float64(utxo.Amount) / satoshiPerBitcoin,
		ScriptPubKey: ScriptPubKey{
			Hex:  hex.EncodeToString(utxo.PkScript),
			Type: scriptType,
		},
		Coinbase: utxo.IsCoinbase,
	}, nil
}

// ============================================================================
// Mempool entry RPCs
// ============================================================================

// mempoolEntryFromTxEntry builds an RPC MempoolEntry from a mempool.TxEntry.
func (s *Server) mempoolEntryFromTxEntry(entry *mempool.TxEntry) MempoolEntry {
	depends := make([]string, len(entry.Depends))
	for i, d := range entry.Depends {
		depends[i] = d.String()
	}
	spentBy := make([]string, len(entry.SpentBy))
	for i, sb := range entry.SpentBy {
		spentBy[i] = sb.String()
	}
	return MempoolEntry{
		VSize:           entry.Size,
		Weight:          entry.Size * 4,
		Fee:             float64(entry.Fee) / satoshiPerBitcoin,
		ModifiedFee:     float64(entry.Fee) / satoshiPerBitcoin,
		Time:            entry.Time.Unix(),
		Height:          entry.Height,
		DescendantCount: len(entry.SpentBy) + 1,
		DescendantSize:  entry.DescendantSize,
		DescendantFees:  float64(entry.DescendantFee) / satoshiPerBitcoin,
		AncestorCount:   len(entry.Depends) + 1,
		AncestorSize:    entry.AncestorSize,
		AncestorFees:    float64(entry.AncestorFee) / satoshiPerBitcoin,
		WTxID:           entry.Tx.WTxHash().String(),
		Depends:         depends,
		SpentBy:         spentBy,
	}
}

func (s *Server) handleGetMempoolEntry(params json.RawMessage) (interface{}, *RPCError) {
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

	if s.mempool == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Mempool not available"}
	}

	txid, err := wire.NewHash256FromHex(txidStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid txid format"}
	}

	entry := s.mempool.GetEntry(txid)
	if entry == nil {
		return nil, &RPCError{Code: RPCErrTxNotFound, Message: fmt.Sprintf("Transaction not in mempool: %s", txidStr)}
	}

	result := s.mempoolEntryFromTxEntry(entry)
	return &result, nil
}

func (s *Server) handleGetMempoolAncestors(params json.RawMessage) (interface{}, *RPCError) {
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

	verbose := false
	if len(args) >= 2 {
		if v, ok := args[1].(bool); ok {
			verbose = v
		}
	}

	if s.mempool == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Mempool not available"}
	}

	txid, err := wire.NewHash256FromHex(txidStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid txid format"}
	}

	if !s.mempool.HasTransaction(txid) {
		return nil, &RPCError{Code: RPCErrTxNotFound, Message: fmt.Sprintf("Transaction not in mempool: %s", txidStr)}
	}

	ancestors := s.mempool.GetAncestors(txid)

	if !verbose {
		result := make([]string, len(ancestors))
		for i, h := range ancestors {
			result[i] = h.String()
		}
		return result, nil
	}

	result := make(map[string]MempoolEntry)
	for _, h := range ancestors {
		entry := s.mempool.GetEntry(h)
		if entry != nil {
			result[h.String()] = s.mempoolEntryFromTxEntry(entry)
		}
	}
	return result, nil
}

func (s *Server) handleGetMempoolDescendants(params json.RawMessage) (interface{}, *RPCError) {
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

	verbose := false
	if len(args) >= 2 {
		if v, ok := args[1].(bool); ok {
			verbose = v
		}
	}

	if s.mempool == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Mempool not available"}
	}

	txid, err := wire.NewHash256FromHex(txidStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid txid format"}
	}

	if !s.mempool.HasTransaction(txid) {
		return nil, &RPCError{Code: RPCErrTxNotFound, Message: fmt.Sprintf("Transaction not in mempool: %s", txidStr)}
	}

	descendants := s.mempool.GetDescendants(txid)

	if !verbose {
		result := make([]string, len(descendants))
		for i, h := range descendants {
			result[i] = h.String()
		}
		return result, nil
	}

	result := make(map[string]MempoolEntry)
	for _, h := range descendants {
		entry := s.mempool.GetEntry(h)
		if entry != nil {
			result[h.String()] = s.mempoolEntryFromTxEntry(entry)
		}
	}
	return result, nil
}

// handleDumpMempool implements both `dumpmempool` (Core legacy) and the
// modern `savemempool`. Writes <datadir>/mempool.dat in Core MEMPOOL_DUMP_VERSION=2
// byte-compatible format. Returns true on success.
func (s *Server) handleDumpMempool(_ json.RawMessage) (interface{}, *RPCError) {
	if s.mempool == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Mempool not available"}
	}
	if s.dataDir == "" {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Data dir not configured"}
	}
	if err := s.mempool.Dump(s.dataDir); err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("dumpmempool: %v", err)}
	}
	return true, nil
}

// handleLoadMempool reloads <datadir>/mempool.dat. Honours Core
// DEFAULT_MEMPOOL_EXPIRY = 336 hours when filtering by age. Returns a result
// summary (read/accepted/failed/expired counts) so callers can audit.
func (s *Server) handleLoadMempool(_ json.RawMessage) (interface{}, *RPCError) {
	if s.mempool == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Mempool not available"}
	}
	if s.dataDir == "" {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Data dir not configured"}
	}
	res, err := s.mempool.Load(s.dataDir, mempool.LoadOptions{MaxAge: 14 * 24 * time.Hour})
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("loadmempool: %v", err)}
	}
	if res == nil {
		// File didn't exist — return zero counts instead of an error.
		res = &mempool.LoadResult{}
	}
	return map[string]interface{}{
		"read":     res.Read,
		"accepted": res.Accepted,
		"failed":   res.Failed,
		"expired":  res.Expired,
	}, nil
}

// ============================================================================
// Script RPCs
// ============================================================================

func (s *Server) handleDecodeScript(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing hex parameter"}
	}

	hexStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid hex string"}
	}

	scriptBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Invalid hex encoding"}
	}

	// Disassemble script
	asm := disassembleScript(scriptBytes)

	// Detect script type
	scriptType := "nonstandard"
	if consensus.IsP2PKH(scriptBytes) {
		scriptType = "pubkeyhash"
	} else if consensus.IsP2SH(scriptBytes) {
		scriptType = "scripthash"
	} else if consensus.IsP2WPKH(scriptBytes) {
		scriptType = "witness_v0_keyhash"
	} else if consensus.IsP2WSH(scriptBytes) {
		scriptType = "witness_v0_scripthash"
	} else if consensus.IsP2TR(scriptBytes) {
		scriptType = "witness_v1_taproot"
	} else if len(scriptBytes) > 0 && scriptBytes[0] == 0x6a {
		scriptType = "nulldata"
	} else if isMultisig(scriptBytes) {
		scriptType = "multisig"
	}

	return &DecodeScriptResult{
		Asm:  asm,
		Type: scriptType,
	}, nil
}

// ============================================================================
// Mining RPCs
// ============================================================================

func (s *Server) handleGetMiningInfo() (interface{}, *RPCError) {
	if s.chainMgr == nil || s.headerIndex == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	_, tipHeight := s.chainMgr.BestBlock()
	// Lock-free read via chainMgr tip cache — avoids idx.mu.RLock contention.
	node := s.chainMgr.BestBlockNode()

	var difficulty float64
	var tipBitsHex, tipTargetHex string
	if node != nil {
		genesisTarget := consensus.CompactToBig(0x1d00ffff)
		currentTarget := consensus.CompactToBig(node.Header.Bits)
		if currentTarget.Sign() > 0 {
			diff := new(big.Float).SetInt(genesisTarget)
			diff.Quo(diff, new(big.Float).SetInt(currentTarget))
			difficulty, _ = diff.Float64()
		}
		tipBitsHex = fmt.Sprintf("%08x", node.Header.Bits)
		tipTargetHex = fmt.Sprintf("%064x", consensus.CompactToBig(node.Header.Bits))
	} else {
		tipBitsHex = "1d00ffff"
		tipTargetHex = fmt.Sprintf("%064x", consensus.CompactToBig(0x1d00ffff))
	}

	pooledTx := 0
	if s.mempool != nil {
		pooledTx = s.mempool.Count()
	}

	// "next" block: approximate with current bits.
	next := MiningInfoNext{
		Height:     tipHeight + 1,
		Bits:       tipBitsHex,
		Difficulty: difficulty,
		Target:     tipTargetHex,
	}

	return &MiningInfo{
		Blocks:        tipHeight,
		Bits:          tipBitsHex,
		Difficulty:    difficulty,
		Target:        tipTargetHex,
		PooledTx:      pooledTx,
		BlockMinTxFee: 0.00001,
		Chain:         s.rpcChainName(),
		Next:          next,
		Warnings:      "",
	}, nil
}

// ============================================================================
// Index RPCs
// ============================================================================

func (s *Server) handleGetIndexInfo() (interface{}, *RPCError) {
	result := make(map[string]interface{})

	if s.indexManager == nil {
		return result, nil
	}

	for _, idx := range s.indexManager.AllIndexes() {
		status := idx.Status()
		result[status.Name] = map[string]interface{}{
			"synced":      status.Synced,
			"best_height": status.BestHeight,
			"best_hash":   status.BestHash.String(),
		}
	}

	return result, nil
}

func (s *Server) handleGetBlockFilter(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing blockhash parameter"}
	}

	hashStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid blockhash"}
	}

	// Parse filtertype (default: "basic")
	filterType := "basic"
	if len(args) >= 2 {
		if ft, ok := args[1].(string); ok {
			filterType = ft
		}
	}

	if filterType != "basic" {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Unknown filtertype"}
	}

	// Get the block filter index
	if s.indexManager == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "No indexes available"}
	}

	idx := s.indexManager.GetIndex("blockfilterindex")
	if idx == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Block filter index not available. Enable with -blockfilterindex"}
	}

	bfi, ok := idx.(*storage.BlockFilterIndex)
	if !ok {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Block filter index not properly initialized"}
	}

	// Parse the block hash
	hash, err := wire.NewHash256FromHex(hashStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid blockhash format"}
	}

	// Get block height from header index
	if s.headerIndex == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	node := s.headerIndex.GetNode(hash)
	if node == nil {
		return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not found"}
	}

	// Get the filter
	filterData, err := bfi.GetFilter(node.Height)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Block filter not available for this height"}
	}

	return &BlockFilterResult{
		Filter: hex.EncodeToString(filterData.Filter),
		Header: filterData.FilterHeader.String(),
	}, nil
}

// BlockFilterResult is the result of getblockfilter RPC.
type BlockFilterResult struct {
	Filter string `json:"filter"`
	Header string `json:"header"`
}

// ============================================================================
// Help RPC
// ============================================================================

func (s *Server) handleHelp(params json.RawMessage) (interface{}, *RPCError) {
	var command string
	if params != nil {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err == nil && len(args) >= 1 {
			if c, ok := args[0].(string); ok {
				command = c
			}
		}
	}

	if command != "" {
		return getMethodHelp(command), nil
	}

	// Return list of all available methods
	methods := []string{
		"== Blockchain ==",
		"getbestblockhash",
		"getblock \"blockhash\" ( verbosity )",
		"getblockchaininfo",
		"getblockcount",
		"getblockhash height",
		"getblockheader \"blockhash\" ( verbose )",
		"getchaintips",
		"getdifficulty",
		"getsyncstate",
		"gettxout \"txid\" n ( include_mempool )",
		"",
		"== Mining ==",
		"getblocktemplate ( \"template_request\" )",
		"getmininginfo",
		"submitblock \"hexdata\"",
		"",
		"== Mempool ==",
		"dumpmempool",
		"getmempoolancestors \"txid\" ( verbose )",
		"getmempooldescendants \"txid\" ( verbose )",
		"getmempoolentry \"txid\"",
		"getmempoolinfo",
		"getrawmempool ( verbose )",
		"loadmempool",
		"savemempool",
		"testmempoolaccept [\"rawtx\",...]",
		"",
		"== Network ==",
		"addnode \"node\" \"command\"",
		"getconnectioncount",
		"getnetworkinfo",
		"getpeerinfo",
		"",
		"== Transaction ==",
		"decoderawtransaction \"hexstring\"",
		"decodescript \"hexstring\"",
		"getrawtransaction \"txid\" ( verbose )",
		"sendrawtransaction \"hexstring\"",
		"signmessage \"address\" \"message\"",
		"signmessagewithprivkey \"privkey\" \"message\"",
		"verifymessage \"address\" \"signature\" \"message\"",
		"",
		"== Fee Estimation ==",
		"estimaterawfee conf_target ( threshold )",
		"estimatesmartfee conf_target ( \"estimate_mode\" )",
		"",
		"== Wallet ==",
		"getbalance",
		"getnewaddress",
		"getwalletinfo",
		"listtransactions ( \"label\" count )",
		"listunspent",
		"sendtoaddress \"address\" amount",
		"encryptwallet \"passphrase\"",
		"walletlock",
		"walletpassphrase \"passphrase\" timeout",
		"",
		"== Control ==",
		"getinfo",
		"help ( \"command\" )",
		"stop",
		"uptime",
	}

	return strings.Join(methods, "\n"), nil
}

// handleVerifyMessage implements the `verifymessage` RPC.
// Reference: bitcoin-core/src/rpc/signmessage.cpp::verifymessage and
// src/common/signmessage.cpp::MessageVerify. Only legacy P2PKH addresses are
// supported, matching Core's behavior — segwit addresses do not commit to the
// pubkey hash in a way that lets a base64 compact-recoverable ECDSA signature
// alone identify the signer.
func (s *Server) handleVerifyMessage(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 3 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "verifymessage requires address, signature, message"}
	}
	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "address must be a string"}
	}
	sigB64, ok := args[1].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "signature must be a string"}
	}
	message, ok := args[2].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "message must be a string"}
	}

	addr, err := address.DecodeAddress(addrStr, s.getNetwork())
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: "Invalid address"}
	}
	if addr.Type != address.P2PKH {
		return nil, &RPCError{Code: RPCErrTypeError, Message: "Address does not refer to key"}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, &RPCError{Code: RPCErrTypeError, Message: "Malformed base64 encoding"}
	}

	hash := bbcrypto.MessageHash(message)
	pub, compressed, err := bbcrypto.RecoverPubKeyFromCompact(sigBytes, hash)
	if err != nil {
		return false, nil
	}

	// The recovery byte already encodes whether the signer used a compressed
	// pubkey; honor that when computing Hash160 so we hash exactly the bytes
	// the signer committed to.
	var pkBytes []byte
	if compressed {
		pkBytes = pub.SerializeCompressed()
	} else {
		pkBytes = pub.SerializeUncompressed()
	}
	gotHash := bbcrypto.Hash160(pkBytes)
	if len(addr.Hash) != 20 {
		return false, nil
	}
	for i := 0; i < 20; i++ {
		if gotHash[i] != addr.Hash[i] {
			return false, nil
		}
	}
	return true, nil
}

// handleSignMessage implements the `signmessage` RPC.
// Reference: bitcoin-core/src/wallet/rpc/signmessage.cpp. Signs `message` using
// the private key tied to `address` in the loaded wallet, returning a base64
// compact-recoverable ECDSA signature. The address must be P2PKH.
func (s *Server) handleSignMessage(params json.RawMessage, walletName string) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "signmessage requires address and message"}
	}
	addrStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "address must be a string"}
	}
	message, ok := args[1].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "message must be a string"}
	}

	w, rpcErr := s.getWalletForRPC(walletName)
	if rpcErr != nil {
		return nil, rpcErr
	}

	addr, err := address.DecodeAddress(addrStr, s.getNetwork())
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: "Invalid address"}
	}
	if addr.Type != address.P2PKH {
		return nil, &RPCError{Code: RPCErrTypeError, Message: "Address does not refer to key"}
	}

	privKey, err := w.GetKeyForAddress(addrStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: err.Error()}
	}

	hash := bbcrypto.MessageHash(message)
	// Wallet-derived keys are always compressed (BIP32 produces compressed
	// pubkeys), and the owning P2PKH address was hashed from the compressed
	// pubkey, so we must sign with isCompressedKey=true.
	sig := bbcrypto.SignMessageCompact(privKey, hash, true)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// handleSignMessageWithPrivKey implements the `signmessagewithprivkey` RPC.
// Reference: bitcoin-core/src/rpc/signmessage.cpp::signmessagewithprivkey.
// This is wallet-less: the caller passes a WIF private key directly.
func (s *Server) handleSignMessageWithPrivKey(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "signmessagewithprivkey requires privkey and message"}
	}
	wif, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "privkey must be a string"}
	}
	message, ok := args[1].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "message must be a string"}
	}

	priv, compressed, err := decodeWIFForRPC(wif, s.getNetwork())
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: "Invalid private key"}
	}
	hash := bbcrypto.MessageHash(message)
	sig := bbcrypto.SignMessageCompact(priv, hash, compressed)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// decodeWIFForRPC decodes a WIF-encoded private key and reports whether the
// associated public key should be compressed (33-byte SEC) or not. Mirrors the
// wallet package's unexported decodeWIF but is local to the RPC layer to avoid
// adding a public wallet API solely for `signmessagewithprivkey`.
func decodeWIFForRPC(wif string, net address.Network) (*bbcrypto.PrivateKey, bool, error) {
	version, payload, err := address.Base58CheckDecode(wif)
	if err != nil {
		return nil, false, err
	}
	var expectedVersion byte
	switch net {
	case address.Mainnet:
		expectedVersion = 0x80
	default:
		expectedVersion = 0xef
	}
	if version != expectedVersion {
		return nil, false, fmt.Errorf("wrong network version")
	}
	switch {
	case len(payload) == 33 && payload[32] == 0x01:
		return bbcrypto.PrivateKeyFromBytes(payload[:32]), true, nil
	case len(payload) == 32:
		return bbcrypto.PrivateKeyFromBytes(payload), false, nil
	default:
		return nil, false, fmt.Errorf("invalid WIF payload length")
	}
}

// handleEstimateRawFee implements the `estimaterawfee` RPC.
// Reference: bitcoin-core/src/rpc/fees.cpp::estimaterawfee. The result is
// keyed by horizon (`short`/`medium`/`long`); blockbrew tracks a single
// horizon, so we report it under `medium` only — Core treats omitted
// horizons as "not tracked" for this confirmation target, which is exactly
// our semantics. Output values mirror Core's per-horizon shape so that
// consensus-diff tooling and scripted callers see no schema surprises.
func (s *Server) handleEstimateRawFee(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "estimaterawfee requires conf_target"}
	}
	confTargetF, ok := args[0].(float64)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "conf_target must be a number"}
	}
	confTarget := int(confTargetF)
	threshold := 0.95
	if len(args) >= 2 {
		t, ok := args[1].(float64)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "threshold must be a number"}
		}
		threshold = t
	}
	if threshold < 0 || threshold > 1 {
		return nil, &RPCError{Code: RPCErrInvalidParameter, Message: "Invalid threshold"}
	}

	out := map[string]interface{}{}
	if s.feeEstimator == nil {
		// No estimator configured — return an empty object, matching Core's
		// behavior when no horizons track the requested target.
		return out, nil
	}

	maxTarget := s.feeEstimator.HighestTargetTracked()
	if confTarget < 1 || confTarget > maxTarget {
		// Out of range for the only horizon we track; emit empty object so
		// callers can detect "no data" without parsing an error.
		return out, nil
	}

	res := s.feeEstimator.EstimateRawFee(confTarget, threshold)
	horizon := map[string]interface{}{
		"decay": res.Decay,
		"scale": res.Scale,
	}
	bucketObj := func(b mempool.EstimationBucketStats) map[string]interface{} {
		return map[string]interface{}{
			"startrange":     b.StartRange,
			"endrange":       b.EndRange,
			"withintarget":   b.WithinTarget,
			"totalconfirmed": b.TotalConfirmed,
			"inmempool":      b.InMempool,
			"leftmempool":    b.LeftMempool,
		}
	}
	if res.FeeRate > 0 {
		// sat/vB → BTC/kvB to match estimatesmartfee.
		horizon["feerate"] = res.FeeRate / satoshiPerBitcoin * 1000
		horizon["pass"] = bucketObj(res.Pass)
		if res.Fail.StartRange != -1 {
			horizon["fail"] = bucketObj(res.Fail)
		}
	} else {
		horizon["fail"] = bucketObj(res.Fail)
		horizon["errors"] = []string{"Insufficient data or no feerate found which meets threshold"}
	}
	out["medium"] = horizon
	return out, nil
}

// ============================================================================
// Helper functions
// ============================================================================

// disassembleScript converts script bytes to a human-readable ASM representation.
func disassembleScript(scriptBytes []byte) string {
	var parts []string
	i := 0

	for i < len(scriptBytes) {
		op := scriptBytes[i]
		i++

		if op >= 0x01 && op <= 0x4b {
			// Direct push: next op bytes
			end := i + int(op)
			if end > len(scriptBytes) {
				parts = append(parts, "[error]")
				break
			}
			parts = append(parts, hex.EncodeToString(scriptBytes[i:end]))
			i = end
		} else if op == script.OP_PUSHDATA1 && i < len(scriptBytes) {
			size := int(scriptBytes[i])
			i++
			end := i + size
			if end > len(scriptBytes) {
				parts = append(parts, "[error]")
				break
			}
			parts = append(parts, hex.EncodeToString(scriptBytes[i:end]))
			i = end
		} else {
			parts = append(parts, script.OpcodeName(op))
		}
	}

	return strings.Join(parts, " ")
}

// isMultisig returns true if the script is a bare multisig script.
func isMultisig(pkScript []byte) bool {
	if len(pkScript) < 4 {
		return false
	}
	// Check: OP_N <pubkeys> OP_M OP_CHECKMULTISIG
	return pkScript[len(pkScript)-1] == script.OP_CHECKMULTISIG
}

// getMethodHelp returns help text for a specific RPC method.
func getMethodHelp(method string) string {
	switch method {
	case "getblockchaininfo":
		return "getblockchaininfo\nReturns an object containing various state info regarding blockchain processing."
	case "getblock":
		return "getblock \"blockhash\" ( verbosity )\nReturns block data. verbosity: 0=hex, 1=json with txids, 2=json with full txs."
	case "getblockhash":
		return "getblockhash height\nReturns hash of block at given height in the main chain."
	case "getblockcount":
		return "getblockcount\nReturns the height of the most-work fully-validated chain."
	case "getsyncstate":
		return "getsyncstate\nReturns the node's chain/sync state in the W70 v1 canonical shape. See spec/getsyncstate.md."
	case "gettxout":
		return "gettxout \"txid\" n ( include_mempool )\nReturns details about an unspent transaction output."
	case "sendtoaddress":
		return "sendtoaddress \"address\" amount\nSend an amount to a given address. Returns the transaction id."
	case "getnewaddress":
		return "getnewaddress\nReturns a new Bitcoin address for receiving payments."
	case "getbalance":
		return "getbalance\nReturns the total available balance."
	case "help":
		return "help ( \"command\" )\nList all commands, or get help for a specified command."
	default:
		return fmt.Sprintf("help: unknown command: %s", method)
	}
}
