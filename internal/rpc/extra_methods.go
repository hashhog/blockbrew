package rpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/script"
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

	tipHash, tipHeight := s.chainMgr.BestBlock()
	node := s.headerIndex.GetNode(tipHash)

	var difficulty float64
	if node != nil {
		genesisTarget := consensus.CompactToBig(0x1d00ffff)
		currentTarget := consensus.CompactToBig(node.Header.Bits)
		if currentTarget.Sign() > 0 {
			diff := new(big.Float).SetInt(genesisTarget)
			diff.Quo(diff, new(big.Float).SetInt(currentTarget))
			difficulty, _ = diff.Float64()
		}
	}

	pooledTx := 0
	if s.mempool != nil {
		pooledTx = s.mempool.Count()
	}

	chain := "main"
	if s.chainParams != nil {
		chain = s.chainParams.Name
	}

	return &MiningInfo{
		Blocks:     tipHeight,
		Difficulty: difficulty,
		PooledTx:   pooledTx,
		Chain:      chain,
	}, nil
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
		"gettxout \"txid\" n ( include_mempool )",
		"",
		"== Mining ==",
		"getblocktemplate ( \"template_request\" )",
		"getmininginfo",
		"submitblock \"hexdata\"",
		"",
		"== Mempool ==",
		"getmempoolinfo",
		"getrawmempool ( verbose )",
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
		"verifymessage \"address\" \"signature\" \"message\"",
		"",
		"== Fee Estimation ==",
		"estimatesmartfee conf_target ( \"estimate_mode\" )",
		"",
		"== Wallet ==",
		"getbalance",
		"getnewaddress",
		"getwalletinfo",
		"listtransactions ( \"label\" count )",
		"listunspent",
		"sendtoaddress \"address\" amount",
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

func (s *Server) handleVerifyMessage(params json.RawMessage) (interface{}, *RPCError) {
	// Placeholder - message verification requires specific address-based signing
	return nil, &RPCError{Code: RPCErrInternal, Message: "verifymessage not yet implemented"}
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
