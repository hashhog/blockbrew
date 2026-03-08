package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mining"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Satoshis per Bitcoin for conversion.
const satoshiPerBitcoin = 100_000_000

// ============================================================================
// Blockchain RPCs
// ============================================================================

func (s *Server) handleGetBlockchainInfo() (interface{}, *RPCError) {
	if s.headerIndex == nil || s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	tipHash, tipHeight := s.chainMgr.BestBlock()
	headersHeight := s.headerIndex.BestHeight()
	tipNode := s.headerIndex.GetNode(tipHash)

	// Calculate difficulty: genesis_target / current_target
	var difficulty float64
	if tipNode != nil {
		genesisTarget := consensus.CompactToBig(0x1d00ffff) // Genesis difficulty
		currentTarget := consensus.CompactToBig(tipNode.Header.Bits)
		if currentTarget.Sign() > 0 {
			// difficulty = genesis_target / current_target
			diff := new(big.Float).SetInt(genesisTarget)
			diff.Quo(diff, new(big.Float).SetInt(currentTarget))
			difficulty, _ = diff.Float64()
		}
	}

	// Calculate verification progress
	var verificationProgress float64
	if headersHeight > 0 {
		verificationProgress = float64(tipHeight) / float64(headersHeight)
		if verificationProgress > 1.0 {
			verificationProgress = 1.0
		}
	}

	// Get median time past
	var medianTime int64
	if tipNode != nil {
		medianTime = tipNode.GetMedianTimePast()
	}

	// Determine chain name
	chain := "main"
	if s.chainParams != nil {
		chain = s.chainParams.Name
	}

	// Check if IBD is active
	ibd := false
	if s.syncMgr != nil {
		ibd = s.syncMgr.IsIBDActive()
	}

	return &BlockchainInfo{
		Chain:                chain,
		Blocks:               tipHeight,
		Headers:              headersHeight,
		BestBlockHash:        tipHash.String(),
		Difficulty:           difficulty,
		MedianTime:           medianTime,
		VerificationProgress: verificationProgress,
		InitialBlockDownload: ibd,
		Pruned:               false,
	}, nil
}

func (s *Server) handleGetBlock(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters: [hash, verbosity]
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing block hash parameter"}
	}

	hashStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid block hash"}
	}

	verbosity := 1 // Default verbosity
	if len(args) >= 2 {
		if v, ok := args[1].(float64); ok {
			verbosity = int(v)
		}
	}

	// Parse hash
	hash, err := wire.NewHash256FromHex(hashStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid block hash format"}
	}

	// Get block from database
	if s.chainDB == nil {
		return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not found"}
	}

	block, err := s.chainDB.GetBlock(hash)
	if err != nil {
		return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not found"}
	}

	// Verbosity 0: return hex-encoded block
	if verbosity == 0 {
		var buf bytes.Buffer
		if err := block.Serialize(&buf); err != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to serialize block"}
		}
		return hex.EncodeToString(buf.Bytes()), nil
	}

	// Get block metadata from header index
	node := s.headerIndex.GetNode(hash)
	if node == nil {
		return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not found in header index"}
	}

	// Calculate confirmations
	_, tipHeight := s.chainMgr.BestBlock()
	confirmations := tipHeight - node.Height + 1
	if !s.chainMgr.IsInMainChain(hash) {
		confirmations = -1
	}

	// Calculate block size and weight
	var buf bytes.Buffer
	block.Serialize(&buf)
	size := buf.Len()
	weight := calcBlockWeight(block)

	// Calculate difficulty
	genesisTarget := consensus.CompactToBig(0x1d00ffff)
	currentTarget := consensus.CompactToBig(block.Header.Bits)
	var difficulty float64
	if currentTarget.Sign() > 0 {
		diff := new(big.Float).SetInt(genesisTarget)
		diff.Quo(diff, new(big.Float).SetInt(currentTarget))
		difficulty, _ = diff.Float64()
	}

	// Build transaction list
	var txList []interface{}
	for i, tx := range block.Transactions {
		if verbosity == 1 {
			// Just txids
			txList = append(txList, tx.TxHash().String())
		} else {
			// Full transaction objects (verbosity >= 2)
			txResult := buildTxResult(tx, i == 0)
			txResult.BlockHash = hash.String()
			txResult.Confirmations = confirmations
			txResult.BlockTime = block.Header.Timestamp
			txResult.Time = block.Header.Timestamp
			txList = append(txList, txResult)
		}
	}

	// Get previous and next block hashes
	var prevHash, nextHash string
	if node.Parent != nil {
		prevHash = node.Parent.Hash.String()
	}
	// Try to find next block
	if len(node.Children) > 0 {
		// Find child in main chain
		for _, child := range node.Children {
			if s.chainMgr.IsInMainChain(child.Hash) {
				nextHash = child.Hash.String()
				break
			}
		}
	}

	return &BlockResult{
		Hash:          hash.String(),
		Confirmations: confirmations,
		Size:          size,
		Weight:        weight,
		Height:        node.Height,
		Version:       block.Header.Version,
		VersionHex:    fmt.Sprintf("%08x", uint32(block.Header.Version)),
		MerkleRoot:    block.Header.MerkleRoot.String(),
		Tx:            txList,
		Time:          block.Header.Timestamp,
		MedianTime:    node.GetMedianTimePast(),
		Nonce:         block.Header.Nonce,
		Bits:          fmt.Sprintf("%08x", block.Header.Bits),
		Difficulty:    difficulty,
		NTx:           len(block.Transactions),
		PreviousHash:  prevHash,
		NextHash:      nextHash,
	}, nil
}

func (s *Server) handleGetBlockHash(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing height parameter"}
	}

	height, ok := args[0].(float64)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid height"}
	}

	if s.chainDB == nil {
		return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not found"}
	}

	hash, err := s.chainDB.GetBlockHashByHeight(int32(height))
	if err != nil {
		return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not found"}
	}

	return hash.String(), nil
}

func (s *Server) handleGetBlockCount() (interface{}, *RPCError) {
	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	_, height := s.chainMgr.BestBlock()
	return height, nil
}

func (s *Server) handleGetBestBlockHash() (interface{}, *RPCError) {
	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	hash, _ := s.chainMgr.BestBlock()
	return hash.String(), nil
}

func (s *Server) handleGetBlockHeader(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing block hash parameter"}
	}

	hashStr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid block hash"}
	}

	verbose := true
	if len(args) >= 2 {
		if v, ok := args[1].(bool); ok {
			verbose = v
		}
	}

	hash, err := wire.NewHash256FromHex(hashStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid block hash format"}
	}

	node := s.headerIndex.GetNode(hash)
	if node == nil {
		return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block header not found"}
	}

	// Non-verbose: return hex-encoded header
	if !verbose {
		var buf bytes.Buffer
		if err := node.Header.Serialize(&buf); err != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to serialize header"}
		}
		return hex.EncodeToString(buf.Bytes()), nil
	}

	// Calculate confirmations
	_, tipHeight := s.chainMgr.BestBlock()
	confirmations := tipHeight - node.Height + 1
	if !s.chainMgr.IsInMainChain(hash) {
		confirmations = -1
	}

	// Calculate difficulty
	genesisTarget := consensus.CompactToBig(0x1d00ffff)
	currentTarget := consensus.CompactToBig(node.Header.Bits)
	var difficulty float64
	if currentTarget.Sign() > 0 {
		diff := new(big.Float).SetInt(genesisTarget)
		diff.Quo(diff, new(big.Float).SetInt(currentTarget))
		difficulty, _ = diff.Float64()
	}

	var prevHash, nextHash string
	if node.Parent != nil {
		prevHash = node.Parent.Hash.String()
	}
	for _, child := range node.Children {
		if s.chainMgr.IsInMainChain(child.Hash) {
			nextHash = child.Hash.String()
			break
		}
	}

	// Count transactions if we have the full block
	nTx := 0
	if s.chainDB != nil {
		if block, err := s.chainDB.GetBlock(hash); err == nil {
			nTx = len(block.Transactions)
		}
	}

	return &BlockHeaderResult{
		Hash:          hash.String(),
		Confirmations: confirmations,
		Height:        node.Height,
		Version:       node.Header.Version,
		VersionHex:    fmt.Sprintf("%08x", uint32(node.Header.Version)),
		MerkleRoot:    node.Header.MerkleRoot.String(),
		Time:          node.Header.Timestamp,
		MedianTime:    node.GetMedianTimePast(),
		Nonce:         node.Header.Nonce,
		Bits:          fmt.Sprintf("%08x", node.Header.Bits),
		Difficulty:    difficulty,
		NTx:           nTx,
		PreviousHash:  prevHash,
		NextHash:      nextHash,
	}, nil
}

func (s *Server) handleGetDifficulty() (interface{}, *RPCError) {
	if s.chainMgr == nil || s.headerIndex == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	tipHash, _ := s.chainMgr.BestBlock()
	node := s.headerIndex.GetNode(tipHash)
	if node == nil {
		return 1.0, nil
	}

	genesisTarget := consensus.CompactToBig(0x1d00ffff)
	currentTarget := consensus.CompactToBig(node.Header.Bits)
	if currentTarget.Sign() <= 0 {
		return 1.0, nil
	}

	diff := new(big.Float).SetInt(genesisTarget)
	diff.Quo(diff, new(big.Float).SetInt(currentTarget))
	difficulty, _ := diff.Float64()
	return difficulty, nil
}

func (s *Server) handleGetChainTips() (interface{}, *RPCError) {
	if s.headerIndex == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	// Get the best tip
	bestTip := s.headerIndex.BestTip()
	if bestTip == nil {
		return []ChainTip{}, nil
	}

	tips := []ChainTip{
		{
			Height:    bestTip.Height,
			Hash:      bestTip.Hash.String(),
			BranchLen: 0,
			Status:    "active",
		},
	}

	// TODO: For a complete implementation, we would traverse the header index
	// to find all chain tips (nodes with no children that aren't on the main chain)

	return tips, nil
}

// ============================================================================
// Transaction RPCs
// ============================================================================

func (s *Server) handleGetRawTransaction(params json.RawMessage) (interface{}, *RPCError) {
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
		} else if v, ok := args[1].(float64); ok {
			verbose = v != 0
		}
	}

	txid, err := wire.NewHash256FromHex(txidStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid txid format"}
	}

	// First check mempool
	var tx *wire.MsgTx
	var blockHash wire.Hash256
	var blockTime uint32
	var confirmations int32

	if s.mempool != nil {
		tx = s.mempool.GetTransaction(txid)
	}

	if tx == nil {
		// TODO: Search in blockchain
		// This requires a transaction index which we don't have yet
		return nil, &RPCError{Code: RPCErrTxNotFound, Message: "Transaction not found"}
	}

	// Non-verbose: return hex
	if !verbose {
		var buf bytes.Buffer
		if err := tx.Serialize(&buf); err != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to serialize transaction"}
		}
		return hex.EncodeToString(buf.Bytes()), nil
	}

	// Verbose: return full transaction object
	result := buildTxResult(tx, false)
	if !blockHash.IsZero() {
		result.BlockHash = blockHash.String()
		result.Confirmations = confirmations
		result.BlockTime = blockTime
		result.Time = blockTime
	}

	return result, nil
}

func (s *Server) handleSendRawTransaction(params json.RawMessage) (interface{}, *RPCError) {
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

	// Decode hex
	txBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Invalid hex encoding"}
	}

	// Deserialize transaction
	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("TX decode failed: %v", err)}
	}

	// Add to mempool
	if s.mempool == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Mempool not available"}
	}

	if err := s.mempool.AddTransaction(tx); err != nil {
		return nil, &RPCError{Code: RPCErrVerify, Message: fmt.Sprintf("Transaction rejected: %v", err)}
	}

	txid := tx.TxHash()

	// Broadcast to peers via inv message
	if s.peerMgr != nil {
		// TODO: Broadcast inv to peers
		// This would require access to the p2p layer's inv broadcasting
	}

	return txid.String(), nil
}

func (s *Server) handleDecodeRawTransaction(params json.RawMessage) (interface{}, *RPCError) {
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

	txBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Invalid hex encoding"}
	}

	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("TX decode failed: %v", err)}
	}

	return buildTxResult(tx, false), nil
}

// ============================================================================
// Mempool RPCs
// ============================================================================

func (s *Server) handleGetMempoolInfo() (interface{}, *RPCError) {
	if s.mempool == nil {
		return &MempoolInfo{Loaded: false}, nil
	}

	return &MempoolInfo{
		Loaded:        true,
		Size:          s.mempool.Count(),
		Bytes:         s.mempool.TotalSize(),
		Usage:         s.mempool.TotalSize(), // Simplified: actual usage would include overhead
		MaxMempool:    300_000_000,            // 300 MB default
		MinRelayTxFee: 0.00001,                // 1 sat/vB in BTC/kvB
	}, nil
}

func (s *Server) handleGetRawMempool(params json.RawMessage) (interface{}, *RPCError) {
	verbose := false

	if params != nil {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err == nil && len(args) >= 1 {
			if v, ok := args[0].(bool); ok {
				verbose = v
			}
		}
	}

	if s.mempool == nil {
		if verbose {
			return map[string]interface{}{}, nil
		}
		return []string{}, nil
	}

	if !verbose {
		hashes := s.mempool.GetAllTxHashes()
		txids := make([]string, len(hashes))
		for i, h := range hashes {
			txids[i] = h.String()
		}
		return txids, nil
	}

	// Verbose mode: return detailed entries
	result := make(map[string]MempoolEntry)
	hashes := s.mempool.GetAllTxHashes()
	for _, h := range hashes {
		entry := s.mempool.GetEntry(h)
		if entry == nil {
			continue
		}

		depends := make([]string, len(entry.Depends))
		for i, d := range entry.Depends {
			depends[i] = d.String()
		}

		spentBy := make([]string, len(entry.SpentBy))
		for i, sb := range entry.SpentBy {
			spentBy[i] = sb.String()
		}

		result[h.String()] = MempoolEntry{
			VSize:           entry.Size,
			Weight:          entry.Size * 4, // Simplified
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

	return result, nil
}

// ============================================================================
// Network RPCs
// ============================================================================

func (s *Server) handleGetPeerInfo() (interface{}, *RPCError) {
	if s.peerMgr == nil {
		return []PeerInfo{}, nil
	}

	peers := s.peerMgr.ConnectedPeers()
	result := make([]PeerInfo, 0, len(peers))

	for i, p := range peers {
		result = append(result, PeerInfo{
			ID:          i,
			Addr:        p.Address(),
			Services:    fmt.Sprintf("%016x", p.Services()),
			LastSend:    p.LastSend().Unix(),
			LastRecv:    p.LastRecv().Unix(),
			BytesSent:   p.BytesSent(),
			BytesRecv:   p.BytesRecvd(),
			ConnTime:    time.Now().Add(-p.ConnTime()).Unix(),
			PingTime:    p.PingLatency().Seconds(),
			Version:     p.ProtocolVersion(),
			SubVer:      p.UserAgent(),
			Inbound:     p.Inbound(),
			StartHeight: p.StartHeight(),
		})
	}

	return result, nil
}

func (s *Server) handleGetConnectionCount() (interface{}, *RPCError) {
	if s.peerMgr == nil {
		return 0, nil
	}

	out, in := s.peerMgr.PeerCount()
	return out + in, nil
}

func (s *Server) handleGetNetworkInfo() (interface{}, *RPCError) {
	outbound, inbound := 0, 0
	if s.peerMgr != nil {
		outbound, inbound = s.peerMgr.PeerCount()
	}

	return &NetworkInfo{
		Version:         1,
		SubVersion:      "/blockbrew:0.1.0/",
		ProtocolVersion: 70016,
		LocalServices:   "0000000000000009", // NODE_NETWORK | NODE_WITNESS
		LocalRelay:      true,
		NetworkActive:   true,
		Connections:     outbound + inbound,
		ConnectionsIn:   inbound,
		ConnectionsOut:  outbound,
	}, nil
}

func (s *Server) handleAddNode(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters: [addr, command]
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing parameters"}
	}

	_, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid address"}
	}

	_, ok = args[1].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid command"}
	}

	// TODO: Implement addnode functionality
	// For now, just acknowledge the request
	return nil, nil
}

// ============================================================================
// Mining RPCs
// ============================================================================

func (s *Server) handleGetBlockTemplate(params json.RawMessage) (interface{}, *RPCError) {
	if s.templateGen == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Mining not available"}
	}

	// Generate template with default config
	config := mining.TemplateConfig{
		MinerAddress: nil, // Caller needs to set this
	}

	template, err := s.templateGen.GenerateTemplate(config)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Template generation failed: %v", err)}
	}

	// Build transaction list
	txs := make([]BlockTemplateTx, 0, len(template.Block.Transactions)-1)
	for i, tx := range template.Block.Transactions {
		if i == 0 {
			continue // Skip coinbase
		}

		var buf bytes.Buffer
		tx.Serialize(&buf)

		txs = append(txs, BlockTemplateTx{
			Data:    hex.EncodeToString(buf.Bytes()),
			TxID:    tx.TxHash().String(),
			Hash:    tx.WTxHash().String(),
			Depends: []int{}, // Simplified
			Fee:     0,       // Would need fee tracking per tx
			SigOps:  0,       // Would need sigop counting
			Weight:  int64(consensus.CalcTxWeight(tx)),
		})
	}

	// Calculate target
	target := consensus.CompactToBig(template.Block.Header.Bits)
	targetHex := fmt.Sprintf("%064x", target)

	// Build witness commitment hex if present
	var witnessCommitment string
	if template.WitnessCommitment != nil {
		witnessCommitment = hex.EncodeToString(template.WitnessCommitment)
	}

	return &BlockTemplateResult{
		Version:                  template.Block.Header.Version,
		PreviousBlockHash:        template.Block.Header.PrevBlock.String(),
		Transactions:             txs,
		CoinbaseAux:              map[string]string{},
		CoinbaseValue:            template.CoinbaseValue,
		Target:                   targetHex,
		MinTime:                  int64(template.Block.Header.Timestamp),
		Mutable:                  []string{"time", "transactions", "prevblock"},
		NonceRange:               "00000000ffffffff",
		SigOpLimit:               consensus.MaxBlockSigOpsCost,
		SizeLimit:                consensus.MaxBlockSize,
		WeightLimit:              consensus.MaxBlockWeight,
		CurTime:                  int64(template.Block.Header.Timestamp),
		Bits:                     fmt.Sprintf("%08x", template.Block.Header.Bits),
		Height:                   template.Height,
		DefaultWitnessCommitment: witnessCommitment,
	}, nil
}

func (s *Server) handleSubmitBlock(params json.RawMessage) (interface{}, *RPCError) {
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

	// Decode block
	blockBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Invalid hex encoding"}
	}

	block := &wire.MsgBlock{}
	if err := block.Deserialize(bytes.NewReader(blockBytes)); err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Block decode failed: %v", err)}
	}

	// Validate block sanity
	if s.chainParams == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Chain params not configured"}
	}

	if err := consensus.CheckBlockSanity(block, s.chainParams.PowLimit); err != nil {
		return nil, &RPCError{Code: RPCErrVerify, Message: fmt.Sprintf("Block sanity check failed: %v", err)}
	}

	// Add header to index
	hash := block.Header.BlockHash()
	if _, err := s.headerIndex.AddHeader(block.Header); err != nil {
		// If duplicate, that's OK
		if err != consensus.ErrDuplicateHeader {
			return nil, &RPCError{Code: RPCErrVerify, Message: fmt.Sprintf("Header validation failed: %v", err)}
		}
	}

	// Store block
	if s.chainDB != nil {
		if err := s.chainDB.StoreBlock(hash, block); err != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to store block: %v", err)}
		}
	}

	// Connect block to chain
	if s.chainMgr != nil {
		if err := s.chainMgr.ConnectBlock(block); err != nil {
			return nil, &RPCError{Code: RPCErrVerify, Message: fmt.Sprintf("Block connection failed: %v", err)}
		}
	}

	// Broadcast to peers
	if s.peerMgr != nil {
		// TODO: Broadcast block inv to peers
	}

	return nil, nil // Success returns null
}

// ============================================================================
// Fee Estimation RPCs
// ============================================================================

func (s *Server) handleEstimateSmartFee(params json.RawMessage) (interface{}, *RPCError) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	confTarget := 6 // Default
	if len(args) >= 1 {
		if v, ok := args[0].(float64); ok {
			confTarget = int(v)
		}
	}

	if s.mempool == nil {
		return &SmartFeeResult{
			Errors: []string{"Fee estimation unavailable"},
			Blocks: confTarget,
		}, nil
	}

	// Get fee estimate from mempool
	feeRate := s.mempool.EstimateFee(confTarget)

	// Convert from sat/vB to BTC/kvB
	feeRateBTC := feeRate / satoshiPerBitcoin * 1000

	return &SmartFeeResult{
		FeeRate: feeRateBTC,
		Blocks:  confTarget,
	}, nil
}

// ============================================================================
// Control RPCs
// ============================================================================

func (s *Server) handleStop() (interface{}, *RPCError) {
	// Signal shutdown in background to allow response to be sent
	go func() {
		time.Sleep(100 * time.Millisecond)
		s.Stop()
	}()

	return "blockbrew server stopping", nil
}

func (s *Server) handleUptime() (interface{}, *RPCError) {
	return int64(time.Since(s.startTime).Seconds()), nil
}

func (s *Server) handleGetInfo() (interface{}, *RPCError) {
	// Deprecated but included for compatibility
	var blocks int32
	if s.chainMgr != nil {
		_, blocks = s.chainMgr.BestBlock()
	}

	connections := 0
	if s.peerMgr != nil {
		out, in := s.peerMgr.PeerCount()
		connections = out + in
	}

	return map[string]interface{}{
		"version":         1,
		"protocolversion": 70016,
		"blocks":          blocks,
		"connections":     connections,
		"proxy":           "",
		"difficulty":      1.0,
		"testnet":         false,
		"relayfee":        0.00001,
	}, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// calcBlockWeight calculates the weight of a block.
func calcBlockWeight(block *wire.MsgBlock) int {
	weight := int64(0)
	for _, tx := range block.Transactions {
		weight += consensus.CalcTxWeight(tx)
	}
	// Add header weight (80 bytes * 4 = 320)
	weight += 80 * consensus.WitnessScaleFactor
	return int(weight)
}

// buildTxResult builds a TxResult from a transaction.
func buildTxResult(tx *wire.MsgTx, isCoinbase bool) *TxResult {
	// Serialize for size calculation
	var buf bytes.Buffer
	tx.Serialize(&buf)
	size := buf.Len()

	var noWitBuf bytes.Buffer
	tx.SerializeNoWitness(&noWitBuf)

	weight := int(consensus.CalcTxWeight(tx))
	vsize := (weight + 3) / 4

	// Build vin
	vin := make([]VinResult, len(tx.TxIn))
	for i, in := range tx.TxIn {
		if isCoinbase && i == 0 {
			vin[i] = VinResult{
				Coinbase: hex.EncodeToString(in.SignatureScript),
				Sequence: in.Sequence,
			}
		} else {
			var scriptSig *Script
			if len(in.SignatureScript) > 0 {
				scriptSig = &Script{
					Hex: hex.EncodeToString(in.SignatureScript),
					Asm: "", // Would need script disassembler
				}
			}

			var witness []string
			if len(in.Witness) > 0 {
				witness = make([]string, len(in.Witness))
				for j, w := range in.Witness {
					witness[j] = hex.EncodeToString(w)
				}
			}

			vin[i] = VinResult{
				TxID:        in.PreviousOutPoint.Hash.String(),
				Vout:        in.PreviousOutPoint.Index,
				ScriptSig:   scriptSig,
				TxInWitness: witness,
				Sequence:    in.Sequence,
			}
		}
	}

	// Build vout
	vout := make([]VoutResult, len(tx.TxOut))
	for i, out := range tx.TxOut {
		scriptType := "unknown"
		if consensus.IsP2PKH(out.PkScript) {
			scriptType = "pubkeyhash"
		} else if consensus.IsP2SH(out.PkScript) {
			scriptType = "scripthash"
		} else if consensus.IsP2WPKH(out.PkScript) {
			scriptType = "witness_v0_keyhash"
		} else if consensus.IsP2WSH(out.PkScript) {
			scriptType = "witness_v0_scripthash"
		} else if consensus.IsP2TR(out.PkScript) {
			scriptType = "witness_v1_taproot"
		} else if len(out.PkScript) > 0 && out.PkScript[0] == 0x6a {
			scriptType = "nulldata"
		}

		vout[i] = VoutResult{
			Value: float64(out.Value) / satoshiPerBitcoin,
			N:     i,
			ScriptPubKey: ScriptPubKey{
				Hex:  hex.EncodeToString(out.PkScript),
				Asm:  "", // Would need script disassembler
				Type: scriptType,
			},
		}
	}

	return &TxResult{
		TxID:     tx.TxHash().String(),
		Hash:     tx.WTxHash().String(),
		Version:  tx.Version,
		Size:     size,
		VSize:    vsize,
		Weight:   weight,
		LockTime: tx.LockTime,
		Vin:      vin,
		Vout:     vout,
		Hex:      hex.EncodeToString(buf.Bytes()),
	}
}
