package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"time"

	"strings"

	"github.com/hashhog/blockbrew/internal/address"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/mempool"
	"github.com/hashhog/blockbrew/internal/mining"
	"github.com/hashhog/blockbrew/internal/p2p"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wallet"
	"github.com/hashhog/blockbrew/internal/wire"
)

// createSnapshotFile creates a file for writing a UTXO snapshot.
func createSnapshotFile(path string) (*os.File, error) {
	return os.Create(path)
}

// openSnapshotFile opens a UTXO snapshot file for reading.
func openSnapshotFile(path string) (*os.File, error) {
	return os.Open(path)
}

// snapshotTempPath returns the canonical "<path>.incomplete" suffix used by
// the atomic dumptxoutset write pattern. Mirrors Bitcoin Core's
// `temppath = path + ".incomplete"` (rpc/blockchain.cpp::dumptxoutset).
func snapshotTempPath(path string) string {
	return path + ".incomplete"
}

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
	// Use the atomic tip cache instead of headerIndex.GetNode(tipHash),
	// which would block on idx.mu.RLock while AddHeader holds the write
	// lock during sync. BestBlockNode is lock-free. See chainmanager.go.
	tipNode := s.chainMgr.BestBlockNode()

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

	// Check if IBD is active
	ibd := false
	if s.syncMgr != nil {
		ibd = s.syncMgr.IsIBDActive()
	}

	// Build softforks using the same shared helper as getdeploymentinfo so both
	// RPCs always read from the same canonical data source (chainparams + chain
	// state).  tipNode may be nil only if the chain is completely uninitialized;
	// in that case we omit softforks rather than panic.
	var softforks map[string]DeploymentEntry
	if tipNode != nil && s.chainParams != nil {
		softforks = buildDeploymentMap(tipNode, s.chainParams)
	}

	// Pruning fields. Core's rpc/blockchain.cpp emits `pruned` always,
	// `pruneheight` and `automatic_pruning` only when pruning is on, and
	// `prune_target_size` only when automatic_pruning is on. We follow
	// the same shape (omitempty in BlockchainInfo). When the operator
	// passed `-prune=N` but no pass has yet freed any files,
	// pruneheight is still reported as 0 — Core does the same.
	pruned := s.pruner.IsEnabled()
	pruneHeight := int32(0)
	pruneTarget := uint64(0)
	if pruned {
		pruneHeight = s.pruner.PruneHeight()
		pruneTarget = s.pruner.TargetBytes()
	}

	return &BlockchainInfo{
		Chain:                s.rpcChainName(),
		Blocks:               tipHeight,
		Headers:              headersHeight,
		BestBlockHash:        tipHash.String(),
		Difficulty:           difficulty,
		MedianTime:           medianTime,
		VerificationProgress: verificationProgress,
		InitialBlockDownload: ibd,
		Pruned:               pruned,
		PruneHeight:          pruneHeight,
		AutomaticPruning:     pruned, // we don't expose Core's -prune=1 manual-only mode
		PruneTargetSize:      pruneTarget,
		Softforks:            softforks,
	}, nil
}

// handleGetSyncState implements the W70 getsyncstate RPC. Spec:
// spec/getsyncstate.md. Returns the node's chain/sync state in a single
// canonical shape every hashhog node honors, so fleet-rate.py and
// friends can stop special-casing each node's getblockcount +
// getbestblockhash + ad-hoc counters.
func (s *Server) handleGetSyncState() (interface{}, *RPCError) {
	if s.chainMgr == nil || s.headerIndex == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	tipHash, tipHeight := s.chainMgr.BestBlock()
	bestHeaderHeight := s.headerIndex.BestHeight()

	// BestTip acquires idx.mu.RLock; acceptable here because this RPC
	// is called infrequently (fleet-rate probes ~1/min) and the lock is
	// not held long. If this becomes a hotspot later, promote to the
	// same atomic-cache pattern used by BestHeight().
	var bestHeaderHash string
	if tip := s.headerIndex.BestTip(); tip != nil {
		bestHeaderHash = tip.Hash.String()
	} else {
		bestHeaderHash = tipHash.String()
	}

	// Default IBD to true: until the sync manager is attached and has
	// observed a recent-timestamped tip, we cannot safely claim to be
	// out of IBD. Spec (spec/getsyncstate.md): "Node's own judgment".
	ibd := true
	var blocksInFlight, blocksPendingConnect *int
	var lastBlockRecv *int64
	if s.syncMgr != nil {
		ibd = s.syncMgr.IsIBDActive()
		inflight := s.syncMgr.BlocksInFlight()
		pending := s.syncMgr.PendingConnectCount()
		blocksInFlight = &inflight
		blocksPendingConnect = &pending
		if t := s.syncMgr.LastTipUpdateTime(); t > 0 {
			lastBlockRecv = &t
		}
	}

	numPeers := 0
	if s.peerMgr != nil {
		numPeers = len(s.peerMgr.ConnectedPeers())
	}

	var vp *float64
	if bestHeaderHeight > 0 {
		v := float64(tipHeight) / float64(bestHeaderHeight)
		if v > 1.0 {
			v = 1.0
		}
		vp = &v
	}

	chain := s.rpcChainName()
	pv := int(p2p.ProtocolVersion)

	return &SyncStateResult{
		TipHeight:             tipHeight,
		TipHash:               tipHash.String(),
		BestHeaderHeight:      bestHeaderHeight,
		BestHeaderHash:        bestHeaderHash,
		InitialBlockDownload:  ibd,
		NumPeers:              numPeers,
		VerificationProgress:  vp,
		BlocksInFlight:        blocksInFlight,
		BlocksPendingConnect:  blocksPendingConnect,
		LastBlockReceivedTime: lastBlockRecv,
		Chain:                 &chain,
		ProtocolVersion:       &pv,
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

	// Headers known but body absent? Distinguish "never had it" from
	// "had it, pruned now" so callers see Core's pruned-data error
	// (RPC_MISC_ERROR / "Block not available (pruned data)") instead of
	// a generic -5 not-found that operators can't tell from a typo'd hash.
	// We report pruned only when the operator actually enabled pruning
	// AND the header is known on the active chain — the same conditions
	// Core checks (rpc/blockchain.cpp:677).
	block, err := s.chainDB.GetBlock(hash)
	if err != nil {
		// Header in index + on main chain + prune enabled implies pruned.
		if s.pruner.IsEnabled() && s.headerIndex != nil {
			if hdrNode := s.headerIndex.GetNode(hash); hdrNode != nil {
				if s.chainMgr != nil && s.chainMgr.IsInMainChain(hash) {
					return nil, &RPCError{
						Code:    RPCErrMisc,
						Message: "Block not available (pruned data)",
					}
				}
			}
		}
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

	// Lock-free read via chainMgr tip cache — avoids idx.mu.RLock contention.
	node := s.chainMgr.BestBlockNode()
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

	// Parse optional blockhash parameter
	var blockHashParam *wire.Hash256
	if len(args) >= 3 {
		if bhStr, ok := args[2].(string); ok && bhStr != "" {
			bh, err := wire.NewHash256FromHex(bhStr)
			if err != nil {
				return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid blockhash format"}
			}
			blockHashParam = &bh
		}
	}

	txid, err := wire.NewHash256FromHex(txidStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid txid format"}
	}

	var tx *wire.MsgTx
	var blockHash wire.Hash256
	var blockTime uint32
	var confirmations int32
	var isCoinbase bool

	// If blockhash is provided, look up the transaction in that specific block
	if blockHashParam != nil {
		if s.chainDB == nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: "Block storage not available"}
		}

		block, err := s.chainDB.GetBlock(*blockHashParam)
		if err != nil {
			return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not found"}
		}

		// Search for transaction in block
		for i, btx := range block.Transactions {
			if btx.TxHash() == txid {
				tx = btx
				isCoinbase = (i == 0)
				break
			}
		}

		if tx == nil {
			return nil, &RPCError{Code: RPCErrTxNotFound, Message: "No such transaction found in the provided block"}
		}

		blockHash = *blockHashParam
		blockTime = block.Header.Timestamp

		// Calculate confirmations
		if s.chainMgr != nil {
			_, tipHeight := s.chainMgr.BestBlock()
			blockNode := s.headerIndex.GetNode(blockHash)
			if blockNode != nil {
				confirmations = tipHeight - blockNode.Height + 1
			}
		}
	} else {
		// First check mempool
		if s.mempool != nil {
			tx = s.mempool.GetTransaction(txid)
		}

		// If not in mempool, check txindex
		if tx == nil && s.chainDB != nil && s.config.TxIndex {
			entry, err := s.chainDB.GetTxIndex(txid)
			if err == nil && entry != nil {
				// Found in txindex, get the block
				block, err := s.chainDB.GetBlock(entry.BlockHash)
				if err == nil {
					for i, btx := range block.Transactions {
						if btx.TxHash() == txid {
							tx = btx
							isCoinbase = (i == 0)
							blockHash = entry.BlockHash
							blockTime = block.Header.Timestamp
							break
						}
					}
				}

				// Calculate confirmations
				if tx != nil && s.chainMgr != nil {
					_, tipHeight := s.chainMgr.BestBlock()
					blockNode := s.headerIndex.GetNode(blockHash)
					if blockNode != nil {
						confirmations = tipHeight - blockNode.Height + 1
					}
				}
			}
		}

		// Transaction not found
		if tx == nil {
			if !s.config.TxIndex {
				return nil, &RPCError{
					Code:    RPCErrTxNotFound,
					Message: "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries",
				}
			}
			return nil, &RPCError{Code: RPCErrTxNotFound, Message: "No such mempool or blockchain transaction"}
		}
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
	result := buildTxResult(tx, isCoinbase)
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

	// Parse maxfeerate parameter (optional, default 0.10 BTC/kvB)
	// 0 means no limit
	maxFeeRate := 0.10 * satoshiPerBitcoin // Default: 0.10 BTC/kvB = 10,000,000 sat/kvB
	if len(args) >= 2 {
		switch v := args[1].(type) {
		case float64:
			maxFeeRate = v * satoshiPerBitcoin // Convert from BTC/kvB to sat/kvB
		case string:
			// Some clients may pass as string
			var f float64
			if _, err := fmt.Sscanf(v, "%f", &f); err == nil {
				maxFeeRate = f * satoshiPerBitcoin
			}
		}
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

	txid := tx.TxHash()

	// Check mempool availability
	if s.mempool == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Mempool not available"}
	}

	// Check if transaction is already in mempool (idempotent behavior)
	if s.mempool.HasTransaction(txid) {
		// Transaction already in mempool, return txid without error
		// Optionally relay again
		if s.peerMgr != nil {
			entry := s.mempool.GetEntry(txid)
			if entry != nil {
				s.peerMgr.RelayTransaction(txid, entry.Fee, entry.Size, "")
			}
		}
		return txid.String(), nil
	}

	// Add to mempool via AcceptToMemoryPool (canonical Bitcoin Core entry point)
	if err := s.mempool.AcceptToMemoryPool(tx); err != nil {
		return nil, &RPCError{Code: RPCErrVerify, Message: fmt.Sprintf("Transaction rejected: %v", err)}
	}

	// Check fee rate against maxfeerate limit
	if maxFeeRate > 0 {
		entry := s.mempool.GetEntry(txid)
		if entry != nil {
			// Convert entry.FeeRate from sat/vB to sat/kvB for comparison
			feeRateKvB := entry.FeeRate * 1000
			if feeRateKvB > maxFeeRate {
				// Fee rate too high, remove from mempool and return error
				s.mempool.RemoveTransaction(txid)
				return nil, &RPCError{
					Code:    RPCErrVerify,
					Message: fmt.Sprintf("Fee rate (%.8f BTC/kvB) exceeds maxfeerate (%.8f BTC/kvB)", feeRateKvB/satoshiPerBitcoin, maxFeeRate/satoshiPerBitcoin),
				}
			}
		}
	}

	// Broadcast to peers via inv message
	// Pass empty string for fromPeer since this originated locally via RPC
	if s.peerMgr != nil {
		entry := s.mempool.GetEntry(txid)
		if entry != nil {
			s.peerMgr.RelayTransaction(txid, entry.Fee, entry.Size, "")
		}
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

func (s *Server) handleSubmitPackage(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters: array of raw transaction hex strings
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing package parameter"}
	}

	// First argument is the array of raw transactions
	rawTxs, ok := args[0].([]interface{})
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Package must be an array of hex strings"}
	}

	if len(rawTxs) == 0 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Package must contain at least one transaction"}
	}

	// Parse maxfeerate (optional, default 0.10 BTC/kvB)
	maxFeeRate := 0.10 * satoshiPerBitcoin // sat/kvB
	if len(args) >= 2 {
		switch v := args[1].(type) {
		case float64:
			maxFeeRate = v * satoshiPerBitcoin
		case string:
			var f float64
			if _, err := fmt.Sscanf(v, "%f", &f); err == nil {
				maxFeeRate = f * satoshiPerBitcoin
			}
		}
	}

	// Parse maxburnamount (optional, default 0)
	maxBurnAmount := int64(0)
	if len(args) >= 3 {
		if v, ok := args[2].(float64); ok {
			maxBurnAmount = int64(v * satoshiPerBitcoin)
		}
	}

	// Decode all transactions
	txns := make([]*wire.MsgTx, 0, len(rawTxs))
	for i, rawTx := range rawTxs {
		hexStr, ok := rawTx.(string)
		if !ok {
			return nil, &RPCError{
				Code:    RPCErrInvalidParams,
				Message: fmt.Sprintf("Transaction %d must be a hex string", i),
			}
		}

		txBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, &RPCError{
				Code:    RPCErrDeserialization,
				Message: fmt.Sprintf("Transaction %d: invalid hex encoding", i),
			}
		}

		tx := &wire.MsgTx{}
		if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
			return nil, &RPCError{
				Code:    RPCErrDeserialization,
				Message: fmt.Sprintf("Transaction %d: decode failed: %v", i, err),
			}
		}

		// Check burn amount if limit is set
		if maxBurnAmount > 0 {
			for j, out := range tx.TxOut {
				if isUnspendable(out.PkScript) && out.Value > maxBurnAmount {
					return nil, &RPCError{
						Code:    RPCErrVerify,
						Message: fmt.Sprintf("Transaction %d output %d exceeds maxburnamount", i, j),
					}
				}
			}
		}

		txns = append(txns, tx)
	}

	// Check package topology for multi-tx packages
	if len(txns) > 1 {
		if !mempool.IsChildWithParentsTree(txns) {
			return nil, &RPCError{
				Code:    RPCErrVerify,
				Message: "package topology disallowed. not child-with-parents or parents depend on each other.",
			}
		}
	}

	// Check mempool availability
	if s.mempool == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Mempool not available"}
	}

	// Accept the package
	pkgResult, err := s.mempool.AcceptPackage(txns)

	// Build result
	result := &SubmitPackageResult{
		TxResults: make(map[string]*SubmitPackageTxResult),
	}

	// Set package message
	if err != nil {
		result.PackageMsg = err.Error()
	} else {
		result.PackageMsg = "success"
	}

	// Add replaced transactions
	if pkgResult != nil && len(pkgResult.ReplacedTxs) > 0 {
		result.ReplacedTransactions = make([]string, len(pkgResult.ReplacedTxs))
		for i, txid := range pkgResult.ReplacedTxs {
			result.ReplacedTransactions[i] = txid.String()
		}
	}

	// Add per-transaction results
	if pkgResult != nil {
		for wtxid, txResult := range pkgResult.TxResults {
			txResultRPC := &SubmitPackageTxResult{
				TxID:  txResult.TxID.String(),
				WTxID: wtxid.String(),
			}

			if txResult.Accepted || txResult.AlreadyInMempool {
				txResultRPC.VSize = txResult.VSize
				txResultRPC.Fees = &TxFees{
					Base: float64(txResult.Fee) / satoshiPerBitcoin,
				}
				// Effective feerate in BTC/kvB
				txResultRPC.EffectiveFeerate = txResult.EffectiveFeerate / satoshiPerBitcoin * 1000

				// List of wtxids included in feerate calculation
				txResultRPC.EffectiveIncludes = make([]string, len(txResult.EffectiveIncludes))
				for i, w := range txResult.EffectiveIncludes {
					txResultRPC.EffectiveIncludes[i] = w.String()
				}
			}

			if txResult.Error != nil {
				txResultRPC.Error = txResult.Error.Error()
			}

			result.TxResults[wtxid.String()] = txResultRPC
		}
	}

	// Check if any transaction exceeds maxfeerate
	if maxFeeRate > 0 && pkgResult != nil {
		for _, txResult := range pkgResult.TxResults {
			if txResult.Accepted && txResult.EffectiveFeerate*1000 > maxFeeRate {
				// Remove transactions that exceed the fee rate
				// Note: In a production implementation, we would prevent acceptance entirely
				// rather than accepting then removing. For now, we just warn.
				rpcResult := result.TxResults[txResult.WTxID.String()]
				if rpcResult != nil {
					rpcResult.Error = fmt.Sprintf("max-fee-exceeded: %.8f BTC/kvB",
						txResult.EffectiveFeerate/satoshiPerBitcoin*1000)
				}
			}
		}
	}

	return result, nil
}

// isUnspendable checks if a script is unspendable (OP_RETURN or invalid).
func isUnspendable(pkScript []byte) bool {
	if len(pkScript) == 0 {
		return false
	}
	// OP_RETURN
	if pkScript[0] == 0x6a {
		return true
	}
	return false
}

func (s *Server) handleGetMempoolInfo() (interface{}, *RPCError) {
	if s.mempool == nil {
		return &MempoolInfo{Loaded: false}, nil
	}

	// Calculate total fees
	totalFee := 0.0
	for _, h := range s.mempool.GetAllTxHashes() {
		if entry := s.mempool.GetEntry(h); entry != nil {
			totalFee += float64(entry.Fee) / satoshiPerBitcoin
		}
	}

	return &MempoolInfo{
		Loaded:             true,
		Size:               s.mempool.Count(),
		Bytes:              s.mempool.TotalSize(),
		Usage:              s.mempool.TotalSize(), // Simplified: actual usage would include overhead
		TotalFee:           totalFee,
		MaxMempool:         300_000_000, // 300 MB default
		MempoolMinFee:      0.00001,     // 1 sat/vB in BTC/kvB
		MinRelayTxFee:      0.00001,     // 1 sat/vB in BTC/kvB
		IncrementalRelayFee: 0.00001,
		UnbroadcastCount:   0,
		FullRBF:            true,
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

// decodeServiceNames returns human-readable names for service flags.
func decodeServiceNames(services uint64) []string {
	var names []string
	if services&1 != 0 {
		names = append(names, "NETWORK")
	}
	if services&8 != 0 {
		names = append(names, "WITNESS")
	}
	if services&1024 != 0 {
		names = append(names, "NETWORK_LIMITED")
	}
	if len(names) == 0 {
		return []string{}
	}
	return names
}

func (s *Server) handleGetPeerInfo() (interface{}, *RPCError) {
	if s.peerMgr == nil {
		return []PeerInfo{}, nil
	}

	peers := s.peerMgr.ConnectedPeers()
	result := make([]PeerInfo, 0, len(peers))

	for i, p := range peers {
		services := p.Services()
		connType := "outbound-full-relay"
		if p.Inbound() {
			connType = "inbound"
		}
		result = append(result, PeerInfo{
			ID:             i,
			Addr:           p.Address(),
			Network:        "ipv4",
			Services:       fmt.Sprintf("%016x", services),
			ServicesNames:  decodeServiceNames(services),
			RelayTxes:      p.RelayTxes(),
			LastSend:       p.LastSend().Unix(),
			LastRecv:       p.LastRecv().Unix(),
			BytesSent:      p.BytesSent(),
			BytesRecv:      p.BytesRecvd(),
			ConnTime:       time.Now().Add(-p.ConnTime()).Unix(),
			TimeOffset:     p.TimeOffset(),
			PingTime:       p.PingLatency().Seconds(),
			Version:        p.ProtocolVersion(),
			SubVer:         p.UserAgent(),
			Inbound:        p.Inbound(),
			BIP152HBTo:     false,
			BIP152HBFrom:   false,
			StartHeight:    p.StartHeight(),
			SyncedHeaders:  -1,
			SyncedBlocks:   -1,
			Inflight:       []int{},
			ConnectionType: connType,
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
		Version:            250000,
		SubVersion:         "/blockbrew:0.1.0/",
		ProtocolVersion:    70016,
		LocalServices:      "0000000000000009", // NODE_NETWORK | NODE_WITNESS
		LocalServicesNames: []string{"NETWORK", "WITNESS"},
		LocalRelay:         true,
		NetworkActive:      true,
		Connections:        outbound + inbound,
		ConnectionsIn:      inbound,
		ConnectionsOut:     outbound,
		Networks: []NetworkEntry{
			{Name: "ipv4", Limited: false, Reachable: true, Proxy: "", ProxyRandomizeCredentials: false},
			{Name: "ipv6", Limited: false, Reachable: true, Proxy: "", ProxyRandomizeCredentials: false},
			{Name: "onion", Limited: true, Reachable: false, Proxy: "", ProxyRandomizeCredentials: false},
		},
		RelayFee:       0.00001,
		IncrementalFee: 0.00001,
		LocalAddresses: []interface{}{},
		Warnings:       "",
	}, nil
}

func (s *Server) handleListBanned() (interface{}, *RPCError) {
	if s.peerMgr == nil {
		return []BannedInfo{}, nil
	}

	banList := s.peerMgr.ListBanned()
	result := make([]BannedInfo, 0, len(banList))

	for ip, info := range banList {
		result = append(result, BannedInfo{
			Address:     ip,
			BanCreated:  info.CreatedAt.Unix(),
			BannedUntil: info.Expiry.Unix(),
			BanReason:   info.Reason,
		})
	}

	return result, nil
}

func (s *Server) handleSetBan(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters: [ip, command, bantime, absolute]
	// command: "add" or "remove"
	// bantime: duration in seconds (default 86400 = 24h)
	// absolute: if true, bantime is an absolute Unix timestamp
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing parameters (ip, command)"}
	}

	ip, ok := args[0].(string)
	if !ok || ip == "" {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid IP address"}
	}

	command, ok := args[1].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid command"}
	}

	if s.peerMgr == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Peer manager not available"}
	}

	switch command {
	case "add":
		banTime := int64(86400) // Default 24 hours
		absolute := false

		if len(args) >= 3 {
			if bt, ok := args[2].(float64); ok {
				banTime = int64(bt)
			}
		}
		if len(args) >= 4 {
			if abs, ok := args[3].(bool); ok {
				absolute = abs
			}
		}

		var duration time.Duration
		if absolute {
			// banTime is an absolute Unix timestamp
			untilTime := time.Unix(banTime, 0)
			duration = time.Until(untilTime)
			if duration <= 0 {
				return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Ban time already expired"}
			}
		} else {
			duration = time.Duration(banTime) * time.Second
		}

		s.peerMgr.SetBan(ip, duration, "manually banned via RPC")
		return nil, nil

	case "remove":
		if s.peerMgr.Unban(ip) {
			return nil, nil
		}
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "IP not found in ban list"}

	default:
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid command (use 'add' or 'remove')"}
	}
}

func (s *Server) handleClearBanned() (interface{}, *RPCError) {
	if s.peerMgr == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Peer manager not available"}
	}

	s.peerMgr.ClearBanned()
	return nil, nil
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

	addr, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid address"}
	}

	command, ok := args[1].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid command"}
	}

	if s.peerMgr == nil {
		return nil, &RPCError{Code: RPCErrClientP2PDisabled, Message: "P2P networking is disabled"}
	}

	switch command {
	case "onetry", "add":
		s.peerMgr.ConnectManualPeer(addr)
	case "remove":
		// Disconnect if connected
		if peer := s.peerMgr.GetPeer(addr); peer != nil {
			peer.Disconnect()
		}
	default:
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid command (use add, remove, or onetry)"}
	}

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

	// Build transaction list. Per-tx sigops cost comes from the template's
	// TxSigOpsCost slice (parallel to non-coinbase txs); see mining.selectTransactions.
	txs := make([]BlockTemplateTx, 0, len(template.Block.Transactions)-1)
	for i, tx := range template.Block.Transactions {
		if i == 0 {
			continue // Skip coinbase
		}

		var buf bytes.Buffer
		tx.Serialize(&buf)

		var sigOps int64
		if idx := i - 1; idx >= 0 && idx < len(template.TxSigOpsCost) {
			sigOps = template.TxSigOpsCost[idx]
		}

		txs = append(txs, BlockTemplateTx{
			Data:    hex.EncodeToString(buf.Bytes()),
			TxID:    tx.TxHash().String(),
			Hash:    tx.WTxHash().String(),
			Depends: []int{}, // Simplified
			Fee:     0,       // Would need fee tracking per tx
			SigOps:  sigOps,
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

// bip22ResultString maps a submitblock rejection error to the canonical short
// ASCII string defined in BIP-22 and Bitcoin Core BIP22ValidationResult()
// (src/rpc/mining.cpp).  Returns "rejected" for unrecognised errors so callers
// never leak verbose internal messages to mining pools.
func bip22ResultString(err error) string {
	if err == nil {
		return "" // caller should return null (success)
	}
	switch {
	// Proof-of-work failure (hash above target)
	case errors.Is(err, consensus.ErrDifficultyTooLow),
		errors.Is(err, consensus.ErrNegativeTarget),
		errors.Is(err, consensus.ErrTargetTooHigh):
		return "high-hash"
	// nBits field doesn't match required difficulty
	case errors.Is(err, consensus.ErrBadDifficultyBits),
		errors.Is(err, consensus.ErrBadDifficulty):
		return "bad-diffbits"
	// Merkle root
	case errors.Is(err, consensus.ErrBadMerkleRoot):
		return "bad-txnmrklroot"
	// Witness commitment (BIP-141)
	case errors.Is(err, consensus.ErrBadWitnessCommitment),
		errors.Is(err, consensus.ErrMissingWitnessCommitment):
		return "bad-witness-merkle-match"
	// Negative output value (consensus/tx_check.cpp::CheckTransaction — Core parity)
	case errors.Is(err, consensus.ErrNegativeOutput):
		return "bad-txns-vout-negative"
	// Output value > MAX_MONEY (consensus/tx_check.cpp::CheckTransaction — Core parity)
	case errors.Is(err, consensus.ErrOutputTooLarge):
		return "bad-txns-vout-toolarge"
	// Coinbase scriptSig length (consensus/tx_check.cpp:49 — 2..100 bytes)
	case errors.Is(err, consensus.ErrCoinbaseScriptSize):
		return "bad-cb-length"
	// Coinbase value / subsidy
	case errors.Is(err, consensus.ErrBadCoinbaseValue):
		return "bad-cb-amount"
	// Sigops budget
	case errors.Is(err, consensus.ErrSigOpsCostTooHigh):
		return "bad-blk-sigops"
	// Missing or already-spent prevout (ConnectBlock input check, CVE-2012-2459 path)
	case errors.Is(err, consensus.ErrMissingInput):
		return "bad-txns-inputs-missingorspent"
	// Duplicate tx within block (BIP-30)
	case errors.Is(err, consensus.ErrDuplicateTx),
		errors.Is(err, consensus.ErrDuplicateCoinbase):
		return "bad-txns-duplicate"
	// BIP-34 coinbase height encoding
	case errors.Is(err, consensus.ErrBadBIP34Height):
		return "bad-cb-height"
	// Non-final transaction (IsFinalTx check)
	case errors.Is(err, consensus.ErrNonFinalTx):
		return "bad-txns-nonfinal"
	// Time checks
	case errors.Is(err, consensus.ErrTimestampBeforeMTP),
		errors.Is(err, consensus.ErrTimestampTooEarly):
		return "time-too-old"
	case errors.Is(err, consensus.ErrTimestampTooFar):
		return "time-too-new"
	// Script / signature verification failures (connect-block stage).
	// Core validation.cpp:2122: "block-script-verify-flag-failed (%s)".
	// Covers ErrDisabledOpcode (OP_CAT + 14 peers), ErrScriptFailed,
	// ErrScriptTooLong, ErrScriptNotClean, and any other script engine error
	// that bubbles up as a wrapped "script failed" string.
	case errors.Is(err, script.ErrDisabledOpcode),
		errors.Is(err, script.ErrScriptFailed),
		errors.Is(err, script.ErrScriptTooLong),
		errors.Is(err, script.ErrScriptNotClean):
		return "block-script-verify-flag-failed"
	// Catch-all string match for errors wrapped with fmt.Errorf("tx %d script: ...").
	// The errors.Is chain above covers sentinel errors; this catches the
	// format-wrapped variants that lose the sentinel through multiple wraps.
	default:
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "script") || strings.Contains(msg, "disabled opcode") {
			return "block-script-verify-flag-failed"
		}
		return "rejected"
	}
}

func (s *Server) handleSubmitBlock(params json.RawMessage) (result interface{}, rpcErr *RPCError) {
	// Recover from any panic during block deserialization or processing to
	// prevent a malformed submitblock from crashing the node (DoS vector).
	defer func() {
		if r := recover(); r != nil {
			log.Printf("WARN: panic in handleSubmitBlock recovered: %v", r)
			result = nil
			rpcErr = &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Block processing panic: %v", r)}
		}
	}()

	// NetworkDisable gate: refuse submissions while a `dumptxoutset
	// rollback` dance is in progress. Mirrors Core's NetworkDisable RAII
	// around TemporaryRollback in rpc/blockchain.cpp::dumptxoutset.
	if s.IsBlockSubmissionPaused() {
		return "rejected: block submission paused (dumptxoutset rollback in progress)", nil
	}

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

	// Reject obviously oversized payloads before decoding hex.
	// A 4MB block encodes to 8MB of hex characters.
	if len(hexStr) > wire.MaxBlockSerializedSize*2 {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Block hex data exceeds maximum block size"}
	}

	// Decode block
	blockBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Invalid hex encoding"}
	}

	if len(blockBytes) > wire.MaxBlockSerializedSize {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: "Block data exceeds maximum serialized size"}
	}

	block := &wire.MsgBlock{}
	if err := block.Deserialize(bytes.NewReader(blockBytes)); err != nil {
		return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Block decode failed: %v", err)}
	}

	// Validate block sanity
	if s.chainParams == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Chain params not configured"}
	}

	// CheckBlockSanity covers PoW, merkle root, weight, sigops, etc.
	// Failures are mapped to BIP-22 result strings (not RPC errors) per spec.
	if err := consensus.CheckBlockSanity(block, s.chainParams.PowLimit); err != nil {
		return bip22ResultString(err), nil
	}

	// Add header to index
	hash := block.Header.BlockHash()
	if _, err := s.headerIndex.AddHeader(block.Header); err != nil {
		// If duplicate, that's OK — return "duplicate" per BIP-22
		if errors.Is(err, consensus.ErrDuplicateHeader) {
			return "duplicate", nil
		}
		return bip22ResultString(err), nil
	}

	// Store block
	if s.chainDB != nil {
		if err := s.chainDB.StoreBlock(hash, block); err != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to store block: %v", err)}
		}
	}

	// Add header to index before connecting (ignore duplicate — headers may
	// already be present from P2P header sync).
	if s.chainMgr != nil {
		if _, err := s.chainMgr.GetHeaderIndex().AddHeader(block.Header); err != nil && !errors.Is(err, consensus.ErrDuplicateHeader) {
			return bip22ResultString(err), nil
		}
		if err := s.chainMgr.ConnectBlock(block); err != nil {
			// Map connection failures to BIP-22 result strings.
			return bip22ResultString(err), nil
		}
	}

	// Broadcast to peers
	if s.peerMgr != nil {
		// TODO: Broadcast block inv to peers
	}

	return nil, nil // null = success per BIP-22
}

// handleSubmitBlockBatch processes multiple blocks in a single RPC call.
// Params: [[hex1, hex2, ...]]  — array of hex-encoded block strings.
// Returns: [null, null, "error-string", ...] — per-block results.
func (s *Server) handleSubmitBlockBatch(params json.RawMessage) (result interface{}, rpcErr *RPCError) {
	// Recover from any panic during batch block processing.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("WARN: panic in handleSubmitBlockBatch recovered: %v", r)
			result = nil
			rpcErr = &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Batch block processing panic: %v", r)}
		}
	}()

	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}
	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing hex array parameter"}
	}

	hexArr, ok := args[0].([]interface{})
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "First parameter must be an array of hex strings"}
	}

	results := make([]interface{}, len(hexArr))
	for i, raw := range hexArr {
		hexStr, ok := raw.(string)
		if !ok {
			results[i] = "invalid hex string"
			continue
		}

		if len(hexStr) > wire.MaxBlockSerializedSize*2 {
			results[i] = "block hex data exceeds maximum block size"
			continue
		}

		blockBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			results[i] = "invalid hex encoding"
			continue
		}

		if len(blockBytes) > wire.MaxBlockSerializedSize {
			results[i] = "block data exceeds maximum serialized size"
			continue
		}

		block := &wire.MsgBlock{}
		if err := block.Deserialize(bytes.NewReader(blockBytes)); err != nil {
			results[i] = fmt.Sprintf("block decode failed: %v", err)
			continue
		}

		if s.chainParams != nil {
			if err := consensus.CheckBlockSanity(block, s.chainParams.PowLimit); err != nil {
				results[i] = fmt.Sprintf("block sanity check failed: %v", err)
				continue
			}
		}

		hash := block.Header.BlockHash()
		if _, err := s.headerIndex.AddHeader(block.Header); err != nil && err != consensus.ErrDuplicateHeader {
			results[i] = fmt.Sprintf("header validation failed: %v", err)
			continue
		}

		if s.chainDB != nil {
			if err := s.chainDB.StoreBlock(hash, block); err != nil {
				results[i] = fmt.Sprintf("failed to store block: %v", err)
				continue
			}
		}

		if s.chainMgr != nil {
			if _, err := s.chainMgr.GetHeaderIndex().AddHeader(block.Header); err != nil && err != consensus.ErrDuplicateHeader {
				results[i] = fmt.Sprintf("failed to add header: %v", err)
				continue
			}
			if err := s.chainMgr.ConnectBlock(block); err != nil {
				results[i] = fmt.Sprintf("block connection failed: %v", err)
				continue
			}
		}

		results[i] = nil // success
	}

	return results, nil
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

	// Use the bucket-based fee estimator if available, otherwise fall back to mempool heuristic
	var feeRate float64
	var actualTarget int
	if s.feeEstimator != nil {
		feeRate, actualTarget = s.feeEstimator.EstimateSmartFee(confTarget)
	} else if s.mempool != nil {
		feeRate = s.mempool.EstimateFee(confTarget)
		actualTarget = confTarget
	}

	if feeRate <= 0 {
		return &SmartFeeResult{
			Errors: []string{"Insufficient data or no feerate found"},
			Blocks: confTarget,
		}, nil
	}

	// Convert from sat/vB to BTC/kvB
	feeRateBTC := feeRate / satoshiPerBitcoin * 1000

	blocks := confTarget
	if actualTarget > 0 {
		blocks = actualTarget
	}
	return &SmartFeeResult{
		FeeRate: feeRateBTC,
		Blocks:  blocks,
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

// ============================================================================
// Descriptor RPCs
// ============================================================================

func (s *Server) handleGetDescriptorInfo(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters: [descriptor]
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing descriptor parameter"}
	}

	desc, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid descriptor"}
	}

	// Determine network from chain params
	net := s.getNetwork()

	// Get descriptor info
	info, err := wallet.GetDescriptorInfo(desc, net)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: err.Error()}
	}

	return &DescriptorInfoResult{
		Descriptor:     info.Descriptor,
		Checksum:       info.Checksum,
		IsRange:        info.IsRange,
		IsSolvable:     info.IsSolvable,
		HasPrivateKeys: info.HasPrivateKeys,
	}, nil
}

func (s *Server) handleDeriveAddresses(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters: [descriptor, [start, end]]
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing descriptor parameter"}
	}

	desc, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid descriptor"}
	}

	// Parse optional range parameter
	var start, end uint32 = 0, 0
	if len(args) >= 2 {
		// Range can be a number or [start, end] array
		switch r := args[1].(type) {
		case float64:
			// Single number means [0, n]
			end = uint32(r)
		case []interface{}:
			if len(r) == 2 {
				if s, ok := r[0].(float64); ok {
					start = uint32(s)
				}
				if e, ok := r[1].(float64); ok {
					end = uint32(e)
				}
			}
		}
	}

	// Determine network from chain params
	net := s.getNetwork()

	// Parse descriptor to check if it's ranged
	parsed, err := wallet.ParseDescriptor(desc, net)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: err.Error()}
	}

	// For non-ranged descriptors, derive a single address
	if !parsed.IsRange() {
		addresses, err := wallet.DeriveAddresses(desc, net, 0, 0)
		if err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: err.Error()}
		}
		return addresses, nil
	}

	// For ranged descriptors, a range must be specified
	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Range must be specified for ranged descriptor"}
	}

	addresses, err := wallet.DeriveAddresses(desc, net, start, end)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: err.Error()}
	}

	return addresses, nil
}

// getNetwork returns the address.Network based on chain params.
func (s *Server) getNetwork() address.Network {
	if s.chainParams == nil {
		return address.Mainnet
	}
	switch s.chainParams.Name {
	case "testnet4", "testnet":
		return address.Testnet
	case "regtest":
		return address.Regtest
	case "signet":
		return address.Signet
	default:
		return address.Mainnet
	}
}

// ============================================================================
// AssumeUTXO RPCs
// ============================================================================

// handleDumpTxOutSet implements the dumptxoutset RPC. Mirrors Bitcoin Core
// (rpc/blockchain.cpp:dumptxoutset) including the optional rollback path.
//
// Accepted parameter shapes (positional, JSON array):
//
//	[path]                              -> "latest" (existing behavior)
//	[path, "latest"]                    -> equivalent to above
//	[path, "rollback"]                  -> rollback to the highest assumeutxo
//	                                        height <= current tip
//	[path, "rollback", {"rollback": h}] -> rollback to a specific height/hash
//	[path, "",         {"rollback": h}] -> same; "type" omitted
//
// Behavior on rollback:
//  1. Resolve target node via header index (height or block-hash string).
//  2. Use ChainManager.ReorgTo(target) to disconnect the active tip back to
//     the target. Because target is on the active chain, FindFork(tip,target)
//     == target and ReorgTo just disconnects without reconnecting anything.
//  3. Write the snapshot at the rolled-back tip.
//  4. Re-apply blocks back to the original tip via ReorgTo(originalTip).
//
// If step (4) fails (block data missing on disk, etc.) the chain is left
// at the lower height and the error is returned to the caller. The dump
// itself has already been written.
func (s *Server) handleDumpTxOutSet(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters: [path, type?, options?]
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing path parameter"}
	}

	path, ok := args[0].(string)
	if !ok || path == "" {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid path"}
	}

	snapshotType := ""
	if len(args) >= 2 {
		if args[1] != nil {
			st, stOK := args[1].(string)
			if !stOK {
				return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid type parameter (must be string)"}
			}
			snapshotType = st
		}
	}

	var rollbackOpt interface{}
	rollbackSpecified := false
	if len(args) >= 3 && args[2] != nil {
		opts, optsOK := args[2].(map[string]interface{})
		if !optsOK {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid options parameter (must be object)"}
		}
		if v, present := opts["rollback"]; present {
			rollbackOpt = v
			rollbackSpecified = true
		}
	}

	// Reject contradictory inputs (Core: rpc/blockchain.cpp:3117).
	if rollbackSpecified && snapshotType != "" && snapshotType != "rollback" {
		return nil, &RPCError{
			Code:    RPCErrInvalidParams,
			Message: fmt.Sprintf("Invalid snapshot type %q specified with rollback option", snapshotType),
		}
	}

	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Chain manager not available"}
	}

	// Snapshot the current ("real") tip up front.
	originalTipHash, originalTipHeight := s.chainMgr.BestBlock()
	originalTipNode := s.chainMgr.BestBlockNode()

	// Resolve target node.
	var targetNode *consensus.BlockNode
	switch {
	case rollbackSpecified:
		var rerr *RPCError
		targetNode, rerr = s.resolveRollbackTarget(rollbackOpt)
		if rerr != nil {
			return nil, rerr
		}
	case snapshotType == "rollback":
		// Default: highest assumeutxo height <= current tip.
		if s.chainParams == nil || s.chainParams.AssumeUTXO == nil ||
			len(s.chainParams.AssumeUTXO.Data) == 0 {
			return nil, &RPCError{
				Code:    RPCErrInvalidParams,
				Message: "No assumeutxo snapshot heights available for this network",
			}
		}
		var bestHeight int32 = -1
		var bestData *consensus.AssumeUTXOData
		for i := range s.chainParams.AssumeUTXO.Data {
			d := &s.chainParams.AssumeUTXO.Data[i]
			if d.Height <= originalTipHeight && d.Height > bestHeight {
				bestHeight = d.Height
				bestData = d
			}
		}
		if bestData == nil {
			return nil, &RPCError{
				Code: RPCErrInvalidParams,
				Message: fmt.Sprintf(
					"No assumeutxo snapshot height <= current tip height %d", originalTipHeight),
			}
		}
		// Prefer header-index lookup by hash (definitive); fall back to height.
		if s.headerIndex != nil {
			if n := s.headerIndex.GetNode(bestData.BlockHash); n != nil {
				targetNode = n
			}
		}
		if targetNode == nil && originalTipNode != nil {
			targetNode = originalTipNode.GetAncestor(bestData.Height)
		}
		if targetNode == nil {
			return nil, &RPCError{
				Code: RPCErrInternal,
				Message: fmt.Sprintf(
					"Could not locate assumeutxo target block at height %d", bestData.Height),
			}
		}
	case snapshotType == "" || snapshotType == "latest":
		// Stay at the current tip — no rollback.
		targetNode = originalTipNode
	default:
		return nil, &RPCError{
			Code: RPCErrInvalidParams,
			Message: fmt.Sprintf(
				"Invalid snapshot type %q specified. Please specify \"rollback\" or \"latest\"",
				snapshotType),
		}
	}

	// Bail out cleanly if we're being asked to roll back but have no path.
	if targetNode == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Could not resolve target block"}
	}

	// If the target is above the active tip, that's a forward jump we can't do.
	if targetNode.Height > originalTipHeight {
		return nil, &RPCError{
			Code: RPCErrInvalidParams,
			Message: fmt.Sprintf(
				"Target height %d is above current tip %d", targetNode.Height, originalTipHeight),
		}
	}

	// Verify target is on the active chain (otherwise rollback is undefined).
	if originalTipNode != nil && targetNode.Height < originalTipHeight {
		ancestor := originalTipNode.GetAncestor(targetNode.Height)
		if ancestor == nil || ancestor.Hash != targetNode.Hash {
			return nil, &RPCError{
				Code: RPCErrInvalidParams,
				Message: fmt.Sprintf(
					"Target block %s is not on the active chain", targetNode.Hash.String()),
			}
		}
	}

	// Validate that we have the needed UTXO set type before we touch the chain.
	utxoSet := s.chainMgr.UTXOSet()
	if utxoSet == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "UTXO set not available"}
	}
	us, ok := utxoSet.(*consensus.UTXOSet)
	if !ok {
		return nil, &RPCError{Code: RPCErrInternal, Message: "UTXO set type not supported for snapshots"}
	}

	// Pruned-mode pre-check (Core: rpc/blockchain.cpp:dumptxoutset, the
	// `IsPruneMode() && target_index->nHeight < GetFirstBlock()->nHeight`
	// guard). Blockbrew does not implement block pruning today (Cat C audit
	// `project_storage_parity_category_c` — Pruning MISSING in blockbrew).
	// Every block from genesis is on disk, so any rollback target is reachable
	// and the check is a no-op. Documented gap: revisit once `-prune` lands.

	// Roll back if needed. ReorgTo(target) where target is an ancestor of the
	// current tip just disconnects down to target (FindFork == target, no
	// connect loop iterations).
	rolledBack := targetNode.Hash != originalTipHash
	if rolledBack {
		// NetworkDisable RAII: pause inbound block acceptance for the
		// duration of the rewind→dump→replay dance. Mirrors Core's
		// NetworkDisable wrapper around TemporaryRollback in
		// rpc/blockchain.cpp::dumptxoutset. The deferred restore fires
		// on every return path (success, error) so peers can resume
		// submitting once the original tip is back.
		restore := s.networkDisable()
		defer restore()

		log.Printf("rpc: dumptxoutset rolling back from height %d to %d (%s)",
			originalTipHeight, targetNode.Height, targetNode.Hash.String()[:16])
		if err := s.chainMgr.ReorgTo(targetNode); err != nil {
			return nil, &RPCError{
				Code:    RPCErrInternal,
				Message: fmt.Sprintf("Failed to roll back to target height %d: %v", targetNode.Height, err),
			}
		}
		// Defensive: confirm the chain actually moved to where we asked.
		gotHash, gotHeight := s.chainMgr.BestBlock()
		if gotHash != targetNode.Hash || gotHeight != targetNode.Height {
			log.Printf("rpc: dumptxoutset rolled back to %d/%s but expected %d/%s",
				gotHeight, gotHash.String()[:16],
				targetNode.Height, targetNode.Hash.String()[:16])
			// Best-effort: try to restore original tip and bail.
			if originalTipNode != nil {
				_ = s.chainMgr.ReorgTo(originalTipNode)
			}
			return nil, &RPCError{Code: RPCErrInternal, Message: "Rollback target was not reached"}
		}
	}

	// Now snapshot the UTXO set at the (possibly rolled-back) tip.
	dumpTipHash, dumpTipHeight := s.chainMgr.BestBlock()

	dumpResult, dumpErr := s.writeUtxoSnapshotFile(path, us, dumpTipHash, dumpTipHeight)

	// Re-apply blocks back to the original tip if we rolled back.
	if rolledBack && originalTipNode != nil {
		if err := s.chainMgr.ReorgTo(originalTipNode); err != nil {
			// We've already written the snapshot if dumpErr == nil. Surface
			// this as a hard error so the operator notices the chain is
			// stuck below the original tip.
			log.Printf("rpc: dumptxoutset failed to roll forward to original tip %s (height %d): %v",
				originalTipHash.String()[:16], originalTipHeight, err)
			return nil, &RPCError{
				Code: RPCErrInternal,
				Message: fmt.Sprintf(
					"Snapshot dumped at height %d but failed to restore tip to height %d: %v",
					dumpTipHeight, originalTipHeight, err),
			}
		}
	}

	if dumpErr != nil {
		return nil, dumpErr
	}
	return dumpResult, nil
}

// resolveRollbackTarget parses the `rollback` named-option value, which Core
// accepts as either a number (height) or a hex string (block hash). We accept
// JSON numbers, JSON strings of decimal digits, and 64-hex-character block
// hashes. Returns the corresponding BlockNode on the active chain, or an
// RPC error.
func (s *Server) resolveRollbackTarget(v interface{}) (*consensus.BlockNode, *RPCError) {
	if s.headerIndex == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Header index not available"}
	}

	var asHeight int32 = -1
	var asHashStr string

	switch t := v.(type) {
	case float64:
		// JSON numbers always come back as float64 from encoding/json. Reject
		// anything that isn't an integer in int32 range.
		if t < 0 || t > float64(int32(0x7fffffff)) || t != float64(int32(t)) {
			return nil, &RPCError{
				Code: RPCErrInvalidParams,
				Message: fmt.Sprintf("Invalid rollback height %v", t),
			}
		}
		asHeight = int32(t)
	case string:
		if len(t) == 64 {
			asHashStr = t
		} else if h, err := strconv.ParseInt(t, 10, 32); err == nil && h >= 0 {
			asHeight = int32(h)
		} else {
			return nil, &RPCError{
				Code:    RPCErrInvalidParams,
				Message: fmt.Sprintf("Invalid rollback target %q (expected height or 64-char block hash)", t),
			}
		}
	default:
		return nil, &RPCError{
			Code:    RPCErrInvalidParams,
			Message: "Invalid rollback option (expected number or string)",
		}
	}

	if asHashStr != "" {
		hash, err := wire.NewHash256FromHex(asHashStr)
		if err != nil {
			return nil, &RPCError{
				Code:    RPCErrInvalidParams,
				Message: fmt.Sprintf("Invalid block hash %q: %v", asHashStr, err),
			}
		}
		node := s.headerIndex.GetNode(hash)
		if node == nil {
			return nil, &RPCError{
				Code:    RPCErrInvalidParams,
				Message: fmt.Sprintf("Block %s not found", asHashStr),
			}
		}
		return node, nil
	}

	node := s.headerIndex.GetHeaderByHeight(asHeight)
	if node == nil {
		return nil, &RPCError{
			Code:    RPCErrInvalidParams,
			Message: fmt.Sprintf("Block at height %d not found", asHeight),
		}
	}
	return node, nil
}

// writeUtxoSnapshotFile writes the UTXO set to the given path and returns the
// dumptxoutset result. Factored out so the rollback path can run it after the
// chain is rewound.
//
// Atomic write protocol: writes to "<path>.incomplete", fsyncs via
// File.Sync(), then renames to <path>. Mirrors Bitcoin Core's
// `temppath = path + ".incomplete"` flow (rpc/blockchain.cpp::dumptxoutset)
// so that operators copying mid-dump never see a torn file, and a SIGKILL
// during dump leaves only the .incomplete artifact behind for cleanup. The
// caller is also expected to refuse if <path> already exists.
func (s *Server) writeUtxoSnapshotFile(
	path string,
	us *consensus.UTXOSet,
	tipHash wire.Hash256,
	tipHeight int32,
) (*DumpTxOutSetResult, *RPCError) {
	// Refuse to overwrite an existing destination — matches Core's
	// behaviour. The .incomplete temp is fine to overwrite (a previous
	// crashed dump's leftover).
	if _, statErr := os.Stat(path); statErr == nil {
		return nil, &RPCError{
			Code:    RPCErrInvalidParams,
			Message: fmt.Sprintf("%s already exists. If you are sure this is what you want, move it out of the way first.", path),
		}
	} else if !os.IsNotExist(statErr) {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to stat %s: %v", path, statErr)}
	}

	tempPath := snapshotTempPath(path)
	// Best-effort cleanup helper for any error-path return.
	cleanupTemp := func() {
		if rmErr := os.Remove(tempPath); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Printf("rpc: dumptxoutset failed to remove temp file %s: %v", tempPath, rmErr)
		}
	}

	f, err := createSnapshotFile(tempPath)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Failed to create file: %v", err)}
	}

	networkMagic := s.chainParams.NetworkMagic
	stats, err := consensus.WriteSnapshot(f, us, tipHash, networkMagic)
	if err != nil {
		_ = f.Close()
		cleanupTemp()
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to write snapshot: %v", err)}
	}
	stats.Height = tipHeight

	// fsync so durability is guaranteed before the atomic rename. Without
	// this, a power loss between rename and the OS flushing dirty pages
	// could leave <path> visible but with zero-length / torn contents.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanupTemp()
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to fsync snapshot: %v", err)}
	}
	if err := f.Close(); err != nil {
		cleanupTemp()
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to close snapshot: %v", err)}
	}

	// Compute Core-compatible HASH_SERIALIZED over the UTXO set. This is the
	// value compared against `assumeutxo` whitelist entries on the load side
	// (validation.cpp:5912-5914) and the same one Core's `dumptxoutset`
	// reports as `txoutset_hash`.
	utxoHash, coinsCount, err := consensus.ComputeHashSerialized(us)
	if err != nil {
		cleanupTemp()
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to compute UTXO hash: %v", err)}
	}

	if err := os.Rename(tempPath, path); err != nil {
		cleanupTemp()
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to rename snapshot to final path: %v", err)}
	}

	return &DumpTxOutSetResult{
		CoinsWritten: stats.CoinsWritten,
		BaseHash:     tipHash.String(),
		BaseHeight:   tipHeight,
		Path:         path,
		TxOutSetHash: utxoHash.String(),
		NChainTx:     coinsCount, // Note: this is coins count, not chain tx count
	}, nil
}

func (s *Server) handleLoadTxOutSet(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters: [path]
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 1 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing path parameter"}
	}

	path, ok := args[0].(string)
	if !ok || path == "" {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid path"}
	}

	if s.chainParams == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Chain params not available"}
	}

	// Open file for reading
	f, err := openSnapshotFile(path)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Failed to open file: %v", err)}
	}
	defer f.Close()

	// Read snapshot metadata FIRST so we can refuse early on a height
	// not in m_assumeutxo_data, matching Bitcoin Core's behavior in
	// validation.cpp:5775-5780. Loading the coins into a chainstate
	// before the whitelist check would defeat the purpose of the check.
	sr, err := consensus.NewSnapshotReader(f)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Failed to read snapshot metadata: %v", err)}
	}
	meta := sr.Metadata()

	// Verify network magic before consulting assumeutxo params.
	if meta.NetworkMagic != s.chainParams.NetworkMagic {
		return nil, &RPCError{
			Code:    RPCErrVerify,
			Message: "Snapshot network magic does not match node network",
		}
	}

	// Strict whitelist: refuse to load any snapshot whose base_blockhash
	// (and therefore height) is not in m_assumeutxo_data for this network.
	// Core spec: bitcoin-core/src/validation.cpp:5775-5780.
	if s.chainParams.AssumeUTXO == nil || len(s.chainParams.AssumeUTXO.Data) == 0 {
		// No whitelist configured for this network at all => refuse.
		// (Core's AssumeutxoForHeight returns nullopt for any height on
		// such a network, and the caller errors out the same way.)
		baseHeight := int32(-1)
		if s.headerIndex != nil {
			if node := s.headerIndex.GetNode(meta.BlockHash); node != nil {
				baseHeight = node.Height
			}
		}
		return nil, &RPCError{
			Code: RPCErrVerify,
			Message: fmt.Sprintf("Assumeutxo height in snapshot metadata not recognized "+
				"(%d) - refusing to load snapshot", baseHeight),
		}
	}

	auData := s.chainParams.AssumeUTXO.ForBlockHash(meta.BlockHash)
	if auData == nil {
		// Look up height in the header index for the error message; if
		// unknown, fall back to -1 to match the "we don't know it" intent.
		baseHeight := int32(-1)
		if s.headerIndex != nil {
			if node := s.headerIndex.GetNode(meta.BlockHash); node != nil {
				baseHeight = node.Height
			}
		}
		return nil, &RPCError{
			Code: RPCErrVerify,
			Message: fmt.Sprintf("Assumeutxo height in snapshot metadata not recognized "+
				"(%d) - refusing to load snapshot", baseHeight),
		}
	}

	// Whitelisted: now actually load the coins. We re-open the file and
	// hand it to LoadSnapshot, which re-reads the metadata. (Cheap: 51 bytes.)
	if _, seekErr := f.Seek(0, 0); seekErr != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to rewind snapshot file: %v", seekErr)}
	}

	utxoSet, stats, err := consensus.LoadSnapshot(f, s.chainDB, s.chainParams.NetworkMagic)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to load snapshot: %v", err)}
	}

	// Strict content-hash check: refuse to activate the snapshot if the
	// HASH_SERIALIZED digest of the loaded coins does not match the
	// whitelisted assumeutxo value. Mirrors Core validation.cpp:5912-5914
	// down to the error wording ("Bad snapshot content hash: expected %s,
	// got %s") so behaviour is identical from an operator's perspective.
	gotHash, _, hashErr := consensus.ComputeHashSerialized(utxoSet)
	if hashErr != nil {
		return nil, &RPCError{
			Code:    RPCErrInternal,
			Message: fmt.Sprintf("Failed to compute snapshot content hash: %v", hashErr),
		}
	}
	if gotHash != auData.HashSerialized {
		return nil, &RPCError{
			Code: RPCErrVerify,
			Message: fmt.Sprintf("Bad snapshot content hash: expected %s, got %s",
				auData.HashSerialized.String(), gotHash.String()),
		}
	}

	stats.Height = auData.Height

	// If the header index knows the block, prefer that height (matches Core
	// which uses snapshot_start_block->nHeight). Should agree with auData.Height.
	if s.headerIndex != nil {
		if node := s.headerIndex.GetNode(stats.BlockHash); node != nil {
			stats.Height = node.Height
		}
	}

	// Flush the loaded coins to chainDB. LoadSnapshot deliberately defers
	// this so the post-flush cache eviction doesn't run before
	// ComputeHashSerialized has walked the in-memory cache. After this
	// flush, the snapshot's coins are durable in the shared chainDB and
	// the cache may be trimmed.
	if flushErr := utxoSet.Flush(); flushErr != nil {
		return nil, &RPCError{
			Code:    RPCErrInternal,
			Message: fmt.Sprintf("Failed to flush snapshot UTXOs: %v", flushErr),
		}
	}

	// Store reference to the loaded UTXO set
	// In a full implementation, this would activate a snapshot chainstate
	// For now, we just return success with the stats. The coins are
	// already in chainDB via the Flush above; promotion to active
	// chainstate (SetChainState/SetBlockHeight) is handled by the
	// CLI -load-snapshot path in cmd/blockbrew/main.go::loadSnapshotFromFile.
	_ = utxoSet // Would be used to create a snapshot chainstate

	return &LoadTxOutSetResult{
		CoinsLoaded: stats.CoinsLoaded,
		TipHash:     stats.BlockHash.String(),
		BaseHeight:  stats.Height,
		Path:        path,
	}, nil
}

func (s *Server) handleGetChainStates() (interface{}, *RPCError) {
	headersHeight := int32(-1)
	if s.headerIndex != nil {
		headersHeight = s.headerIndex.BestHeight()
	}

	result := &ChainStatesResult{
		Headers:     headersHeight,
		Chainstates: make([]ChainstateInfo, 0),
	}

	// Add the main chainstate
	if s.chainMgr != nil {
		tipHash, tipHeight := s.chainMgr.BestBlock()

		var difficulty float64
		// Lock-free read via chainMgr tip cache — avoids idx.mu.RLock contention.
		tipNode := s.chainMgr.BestBlockNode()
		if tipNode != nil {
			genesisTarget := consensus.CompactToBig(0x1d00ffff)
			currentTarget := consensus.CompactToBig(tipNode.Header.Bits)
			if currentTarget.Sign() > 0 {
				diff := new(big.Float).SetInt(genesisTarget)
				diff.Quo(diff, new(big.Float).SetInt(currentTarget))
				difficulty, _ = diff.Float64()
			}
		}

		var verificationProgress float64
		if headersHeight > 0 {
			verificationProgress = float64(tipHeight) / float64(headersHeight)
			if verificationProgress > 1.0 {
				verificationProgress = 1.0
			}
		}

		info := ChainstateInfo{
			Blocks:               tipHeight,
			BestBlockHash:        tipHash.String(),
			Difficulty:           difficulty,
			VerificationProgress: verificationProgress,
			Validated:            true, // Main chainstate is always validated
		}

		if tipNode != nil {
			info.Bits = fmt.Sprintf("%08x", tipNode.Header.Bits)
			info.Target = consensus.CompactToBig(tipNode.Header.Bits).Text(16)
		}

		result.Chainstates = append(result.Chainstates, info)
	}

	return result, nil
}

// DumpTxOutSetResult is the result of the dumptxoutset RPC.
type DumpTxOutSetResult struct {
	CoinsWritten uint64 `json:"coins_written"`
	BaseHash     string `json:"base_hash"`
	BaseHeight   int32  `json:"base_height"`
	Path         string `json:"path"`
	TxOutSetHash string `json:"txoutset_hash"`
	NChainTx     uint64 `json:"nchaintx"`
}

// LoadTxOutSetResult is the result of the loadtxoutset RPC.
type LoadTxOutSetResult struct {
	CoinsLoaded uint64 `json:"coins_loaded"`
	TipHash     string `json:"tip_hash"`
	BaseHeight  int32  `json:"base_height"`
	Path        string `json:"path"`
}

// ChainStatesResult is the result of the getchainstates RPC.
type ChainStatesResult struct {
	Headers     int32            `json:"headers"`
	Chainstates []ChainstateInfo `json:"chainstates"`
}

// ChainstateInfo contains information about a single chainstate.
type ChainstateInfo struct {
	Blocks               int32   `json:"blocks"`
	BestBlockHash        string  `json:"bestblockhash"`
	Bits                 string  `json:"bits,omitempty"`
	Target               string  `json:"target,omitempty"`
	Difficulty           float64 `json:"difficulty"`
	VerificationProgress float64 `json:"verificationprogress"`
	SnapshotBlockHash    string  `json:"snapshot_blockhash,omitempty"`
	CoinsDBCacheBytes    int64   `json:"coins_db_cache_bytes,omitempty"`
	CoinsTipCacheBytes   int64   `json:"coins_tip_cache_bytes,omitempty"`
	Validated            bool    `json:"validated"`
}

// ============================================================================
// Generate RPCs (for regtest)
// ============================================================================

func (s *Server) handleGenerateToAddress(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters: [nblocks, address, maxtries]
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing required parameters (nblocks, address)"}
	}

	// Parse nblocks
	nblocks, ok := args[0].(float64)
	if !ok || nblocks < 0 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid nblocks parameter"}
	}

	// Parse address
	addrStr, ok := args[1].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid address parameter"}
	}

	// Parse optional maxtries
	maxTries := mining.DefaultMaxTries
	if len(args) >= 3 {
		if mt, ok := args[2].(float64); ok {
			maxTries = int(mt)
		}
	}

	// Validate address and get scriptPubKey
	net := s.getNetwork()
	addr, err := address.DecodeAddress(addrStr, net)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid address: %v", err)}
	}
	coinbaseScript := addr.ScriptPubKey()

	// Create the block miner
	miner := s.createBlockMiner()
	if miner == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Mining not available"}
	}

	// Generate blocks
	hashes, err := miner.GenerateBlocks(int(nblocks), coinbaseScript, maxTries)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Block generation failed: %v", err)}
	}

	// Broadcast inv(MSG_BLOCK) to all connected peers for each new block
	if s.peerMgr != nil {
		for _, h := range hashes {
			inv := &p2p.MsgInv{}
			inv.AddInvVect(&p2p.InvVect{Type: p2p.InvTypeBlock, Hash: h})
			s.peerMgr.BroadcastMessage(inv)
			log.Printf("rpc: broadcast block inv %x to peers", h[:4])
		}
	}

	// Convert hashes to strings
	result := make([]string, len(hashes))
	for i, h := range hashes {
		result[i] = h.String()
	}

	return result, nil
}

func (s *Server) handleGenerateToDescriptor(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters: [num_blocks, descriptor, maxtries]
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing required parameters (num_blocks, descriptor)"}
	}

	// Parse num_blocks
	numBlocks, ok := args[0].(float64)
	if !ok || numBlocks < 0 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid num_blocks parameter"}
	}

	// Parse descriptor
	descriptor, ok := args[1].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid descriptor parameter"}
	}

	// Parse optional maxtries
	maxTries := mining.DefaultMaxTries
	if len(args) >= 3 {
		if mt, ok := args[2].(float64); ok {
			maxTries = int(mt)
		}
	}

	// Derive address from descriptor
	net := s.getNetwork()
	addresses, err := wallet.DeriveAddresses(descriptor, net, 0, 0)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Invalid descriptor: %v", err)}
	}
	if len(addresses) == 0 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Descriptor did not produce any addresses"}
	}

	// Get scriptPubKey from the first derived address
	addr, err := address.DecodeAddress(addresses[0], net)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Failed to decode derived address: %v", err)}
	}
	coinbaseScript := addr.ScriptPubKey()

	// Create the block miner
	miner := s.createBlockMiner()
	if miner == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Mining not available"}
	}

	// Generate blocks
	hashes, err := miner.GenerateBlocks(int(numBlocks), coinbaseScript, maxTries)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Block generation failed: %v", err)}
	}

	// Broadcast inv(MSG_BLOCK) to all connected peers for each new block
	if s.peerMgr != nil {
		for _, h := range hashes {
			inv := &p2p.MsgInv{}
			inv.AddInvVect(&p2p.InvVect{Type: p2p.InvTypeBlock, Hash: h})
			s.peerMgr.BroadcastMessage(inv)
		}
	}

	// Convert hashes to strings
	result := make([]string, len(hashes))
	for i, h := range hashes {
		result[i] = h.String()
	}

	return result, nil
}

func (s *Server) handleGenerateBlock(params json.RawMessage) (interface{}, *RPCError) {
	// Parse parameters: [output, transactions, submit]
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid parameters"}
	}

	if len(args) < 2 {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Missing required parameters (output, transactions)"}
	}

	// Parse output (address or descriptor)
	output, ok := args[0].(string)
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid output parameter"}
	}

	// Parse transactions array
	txsRaw, ok := args[1].([]interface{})
	if !ok {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid transactions parameter"}
	}

	// Parse optional submit parameter (default true)
	submit := true
	if len(args) >= 3 {
		if sub, ok := args[2].(bool); ok {
			submit = sub
		}
	}

	// Get coinbase script from output (try as address first, then descriptor)
	net := s.getNetwork()
	var coinbaseScript []byte

	// Try as address first
	addr, err := address.DecodeAddress(output, net)
	if err == nil {
		coinbaseScript = addr.ScriptPubKey()
	} else {
		// Try as descriptor
		addresses, err := wallet.DeriveAddresses(output, net, 0, 0)
		if err != nil || len(addresses) == 0 {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid output: not a valid address or descriptor"}
		}
		addr, err := address.DecodeAddress(addresses[0], net)
		if err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Failed to decode derived address: %v", err)}
		}
		coinbaseScript = addr.ScriptPubKey()
	}

	// Parse transactions (can be txids from mempool or raw tx hex)
	var txs []*wire.MsgTx
	for i, txRaw := range txsRaw {
		txStr, ok := txRaw.(string)
		if !ok {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: fmt.Sprintf("Transaction %d must be a string", i)}
		}

		// Try as txid first (lookup in mempool)
		if len(txStr) == 64 {
			txid, err := wire.NewHash256FromHex(txStr)
			if err == nil && s.mempool != nil {
				if tx := s.mempool.GetTransaction(txid); tx != nil {
					txs = append(txs, tx)
					continue
				}
			}
		}

		// Try as raw transaction hex
		txBytes, err := hex.DecodeString(txStr)
		if err != nil {
			return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Transaction %d: invalid hex", i)}
		}

		tx := &wire.MsgTx{}
		if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
			return nil, &RPCError{Code: RPCErrDeserialization, Message: fmt.Sprintf("Transaction %d: decode failed: %v", i, err)}
		}
		txs = append(txs, tx)
	}

	// Generate the block template
	config := mining.TemplateConfig{
		MinerAddress: coinbaseScript,
	}

	if s.templateGen == nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Mining not available"}
	}

	template, err := s.templateGen.GenerateTemplate(config)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Template generation failed: %v", err)}
	}

	block := template.Block

	// Replace transactions with the provided ones
	coinbase := block.Transactions[0]
	block.Transactions = make([]*wire.MsgTx, 0, len(txs)+1)
	block.Transactions = append(block.Transactions, coinbase)
	block.Transactions = append(block.Transactions, txs...)

	// Recalculate merkle root
	txHashes := make([]wire.Hash256, len(block.Transactions))
	for i, tx := range block.Transactions {
		txHashes[i] = tx.TxHash()
	}
	block.Header.MerkleRoot = consensus.CalcMerkleRoot(txHashes)

	// Recalculate witness commitment if segwit is active
	if s.chainParams.SegwitHeight <= template.Height {
		wtxids := make([]wire.Hash256, len(block.Transactions))
		wtxids[0] = wire.Hash256{} // Coinbase wtxid is all zeros
		for i := 1; i < len(block.Transactions); i++ {
			wtxids[i] = block.Transactions[i].WTxHash()
		}
		witnessReserved := make([]byte, 32)
		commitment := consensus.CalcWitnessCommitment(wtxids, witnessReserved)
		mining.UpdateCoinbaseWitnessCommitment(coinbase, commitment[:])
	}

	// Mine the block
	target := consensus.CompactToBig(block.Header.Bits)
	var blockHash wire.Hash256
	found := false

	for nonce := uint32(0); nonce < uint32(mining.DefaultMaxTries); nonce++ {
		block.Header.Nonce = nonce
		hash := block.Header.BlockHash()

		hashNum := consensus.HashToBig(hash)
		if hashNum.Cmp(target) <= 0 {
			blockHash = hash
			found = true
			break
		}
	}

	if !found {
		return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to mine block (max tries exceeded)"}
	}

	result := &GenerateBlockResult{
		Hash: blockHash.String(),
	}

	// If not submitting, return the hex
	if !submit {
		var buf bytes.Buffer
		if err := block.Serialize(&buf); err != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: "Failed to serialize block"}
		}
		result.Hex = hex.EncodeToString(buf.Bytes())
		return result, nil
	}

	// Submit the block
	if s.chainDB != nil {
		if err := s.chainDB.StoreBlock(blockHash, block); err != nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: fmt.Sprintf("Failed to store block: %v", err)}
		}
	}

	if s.chainMgr != nil {
		if err := s.chainMgr.ConnectBlock(block); err != nil {
			return nil, &RPCError{Code: RPCErrVerify, Message: fmt.Sprintf("Block connection failed: %v", err)}
		}
	}

	// Broadcast inv(MSG_BLOCK) to all connected peers
	if s.peerMgr != nil {
		inv := &p2p.MsgInv{}
		inv.AddInvVect(&p2p.InvVect{Type: p2p.InvTypeBlock, Hash: blockHash})
		s.peerMgr.BroadcastMessage(inv)
	}

	return result, nil
}

func (s *Server) handleGenerate(params json.RawMessage) (interface{}, *RPCError) {
	// The 'generate' RPC is deprecated in Bitcoin Core
	// It has been replaced by 'generatetoaddress'
	return nil, &RPCError{
		Code:    RPCErrMethodNotFound,
		Message: "The 'generate' RPC has been replaced by 'generatetoaddress'. Please use 'generatetoaddress' instead.",
	}
}

// createBlockMiner creates a BlockMiner for instant block generation.
func (s *Server) createBlockMiner() *mining.BlockMiner {
	if s.templateGen == nil {
		return nil
	}

	return mining.NewBlockMiner(
		s.templateGen,
		s.chainMgr,
		s.chainDB,
		s.headerIndex,
		s.chainParams,
	)
}

// ============================================================================
// Chain Management RPCs
// ============================================================================

// handleInvalidateBlock marks a block as permanently invalid.
// If the block is in the active chain, it triggers a reorg to the best valid chain.
func (s *Server) handleInvalidateBlock(params json.RawMessage) (interface{}, *RPCError) {
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

	hash, err := wire.NewHash256FromHex(hashStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid blockhash format"}
	}

	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	// Check if block exists
	if s.headerIndex.GetNode(hash) == nil {
		return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not found"}
	}

	// Invalidate the block
	if err := s.chainMgr.InvalidateBlock(hash); err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: err.Error()}
	}

	return nil, nil
}

// handleReconsiderBlock removes the invalid status from a block and its descendants.
// This undoes the effect of invalidateblock.
func (s *Server) handleReconsiderBlock(params json.RawMessage) (interface{}, *RPCError) {
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

	hash, err := wire.NewHash256FromHex(hashStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid blockhash format"}
	}

	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	// Check if block exists
	if s.headerIndex.GetNode(hash) == nil {
		return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not found"}
	}

	// Reconsider the block
	if err := s.chainMgr.ReconsiderBlock(hash); err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: err.Error()}
	}

	return nil, nil
}

// handlePreciousBlock treats a block as if it were received before others with the same work.
// This gives the block's chain priority in chain selection when there are ties.
// The effect is ephemeral - lost on restart - and new calls override previous ones.
// handleGetDeploymentInfo implements the getdeploymentinfo RPC.
// It accepts an optional block hash parameter (default: chain tip) and returns
// deployment state for all known soft-fork deployments (buried and BIP9).
func (s *Server) handleGetDeploymentInfo(params json.RawMessage) (interface{}, *RPCError) {
	if s.headerIndex == nil || s.chainMgr == nil || s.chainParams == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	// Parse optional blockhash parameter.
	var blockNode *consensus.BlockNode
	if len(params) > 0 && string(params) != "null" && string(params) != "[]" {
		var args []interface{}
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid params"}
		}
		if len(args) > 0 && args[0] != nil {
			hashStr, ok := args[0].(string)
			if !ok {
				return nil, &RPCError{Code: RPCErrInvalidParams, Message: "blockhash must be a string"}
			}
			hash, err := wire.NewHash256FromHex(hashStr)
			if err != nil {
				return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid blockhash format"}
			}
			blockNode = s.headerIndex.GetNode(hash)
			if blockNode == nil {
				return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not found"}
			}
		}
	}
	if blockNode == nil {
		blockNode = s.headerIndex.BestTip()
		if blockNode == nil {
			return nil, &RPCError{Code: RPCErrInternal, Message: "No chain tip available"}
		}
	}

	result := &DeploymentInfoResult{
		Hash:        blockNode.Hash.String(),
		Height:      blockNode.Height,
		Deployments: buildDeploymentMap(blockNode, s.chainParams),
	}
	return result, nil
}

// buildDeploymentMap is the single shared source-of-truth for softfork deployment
// state.  Both getblockchaininfo (.softforks) and getdeploymentinfo (.deployments)
// call this helper so the two RPCs always read from the same data source:
// chainparams + active chain state via GetDeploymentState / GetStateSinceHeight.
// No hard-coded tables; every entry is derived from cp.BIP*Height / cp.Deployments.
func buildDeploymentMap(tip *consensus.BlockNode, cp *consensus.ChainParams) map[string]DeploymentEntry {
	// Pass a nil cache; GetDeploymentState accepts nil and simply skips caching.
	// A shared cache can be wired in later as an optimisation.
	var cache *consensus.VersionBitsCache

	deployments := make(map[string]DeploymentEntry)

	// ---- Buried deployments (height-activated) ----
	// BIP34: coinbase height in scriptSig
	addBuriedDeployment(deployments, "bip34", tip.Height, cp.BIP34Height)
	// BIP65: CHECKLOCKTIMEVERIFY
	addBuriedDeployment(deployments, "bip65", tip.Height, cp.BIP65Height)
	// BIP66: strict DER signatures
	addBuriedDeployment(deployments, "bip66", tip.Height, cp.BIP66Height)
	// CSV (BIP68/BIP112/BIP113)
	addBuriedDeployment(deployments, "csv", tip.Height, cp.CSVHeight)
	// Segwit (BIP141/BIP143/BIP147)
	addBuriedDeployment(deployments, "segwit", tip.Height, cp.SegwitHeight)
	// Taproot (BIP341/BIP342)
	addBuriedDeployment(deployments, "taproot", tip.Height, cp.TaprootHeight)

	// ---- BIP9 deployments ----
	for i, dep := range cp.Deployments {
		entry := buildBIP9DeploymentEntry(dep, i, tip, cp, cache)
		deployments[dep.Name] = entry
	}

	return deployments
}

// addBuriedDeployment adds a buried (height-activated) deployment entry to the map.
// active is true when the current block height is at or above the activation height.
// Following Bitcoin Core getdeploymentinfo semantics: active means "enforced for
// the mempool and next block", so we check height >= activationHeight.
func addBuriedDeployment(deployments map[string]DeploymentEntry, name string, tipHeight, activationHeight int32) {
	active := tipHeight >= activationHeight
	h := activationHeight
	entry := DeploymentEntry{
		Type:   "buried",
		Height: &h,
		Active: active,
	}
	deployments[name] = entry
}

// buildBIP9DeploymentEntry builds a DeploymentEntry for a BIP9 deployment.
func buildBIP9DeploymentEntry(
	dep *consensus.BIP9Deployment,
	depIndex int,
	tip *consensus.BlockNode,
	params *consensus.ChainParams,
	cache *consensus.VersionBitsCache,
) DeploymentEntry {
	// The state for the next block after tip is determined by passing tip as pindexPrev.
	currentState := consensus.GetDeploymentState(dep, depIndex, tip, params, cache)
	nextState := consensus.GetDeploymentState(dep, depIndex, tip, params, cache)
	// next state: state for the block after (tip+1), i.e. pass tip itself
	// currentState is state for blocks at the tip (pindexPrev = tip.Parent)
	// To match Bitcoin Core: current = GetStateFor(tip.Parent), next = GetStateFor(tip)
	var parentState consensus.DeploymentState
	if tip.Parent != nil {
		parentState = consensus.GetDeploymentState(dep, depIndex, tip.Parent, params, cache)
	} else {
		parentState = consensus.GetDeploymentState(dep, depIndex, nil, params, cache)
	}
	_ = nextState
	currentState = parentState
	nextState = consensus.GetDeploymentState(dep, depIndex, tip, params, cache)

	sinceHeight := consensus.GetStateSinceHeight(dep, depIndex, tip.Parent, params, cache)
	if tip.Parent == nil {
		sinceHeight = 0
	}

	// Determine if the bit should be shown (started or locked_in states).
	hasSignal := currentState == consensus.DeploymentStarted || currentState == consensus.DeploymentLockedIn

	var bitPtr *int
	if hasSignal {
		bit := dep.Bit
		bitPtr = &bit
	}

	bip9 := &BIP9Info{
		Bit:                 bitPtr,
		StartTime:           dep.StartTime,
		Timeout:             dep.Timeout,
		MinActivationHeight: dep.MinActivationHeight,
		Status:              currentState.String(),
		Since:               sinceHeight,
		StatusNext:          nextState.String(),
	}

	// Add statistics for started/locked_in states.
	if hasSignal {
		stats := consensus.GetDeploymentStats(dep, tip, params)
		if stats != nil {
			possible := stats.Possible
			statsResult := &BIP9StatsResult{
				Period:  stats.Period,
				Elapsed: stats.Elapsed,
				Count:   stats.Count,
			}
			if currentState == consensus.DeploymentStarted {
				statsResult.Threshold = stats.Threshold
				statsResult.Possible = &possible
			}
			bip9.Statistics = statsResult
		}
	}

	// Determine active status and height.
	// A BIP9 deployment is "active" if currentState == ACTIVE.
	// height is set to the activation height when active or becoming active next block.
	isActive := currentState == consensus.DeploymentActive
	var activationHeight *int32
	if isActive {
		// Find the height at which it became active (same as sinceHeight for active state).
		activeSince := consensus.GetStateSinceHeight(dep, depIndex, tip.Parent, params, cache)
		activationHeight = &activeSince
	} else if nextState == consensus.DeploymentActive {
		// Will become active with the next block.
		nextHeight := tip.Height + 1
		activationHeight = &nextHeight
	}

	return DeploymentEntry{
		Type:   "bip9",
		Height: activationHeight,
		Active: isActive,
		BIP9:   bip9,
	}
}

func (s *Server) handlePreciousBlock(params json.RawMessage) (interface{}, *RPCError) {
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

	hash, err := wire.NewHash256FromHex(hashStr)
	if err != nil {
		return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Invalid blockhash format"}
	}

	if s.chainMgr == nil {
		return nil, &RPCError{Code: RPCErrInWarmup, Message: "Node is warming up"}
	}

	// Check if block exists
	if s.headerIndex.GetNode(hash) == nil {
		return nil, &RPCError{Code: RPCErrBlockNotFound, Message: "Block not found"}
	}

	// Mark the block as precious
	if err := s.chainMgr.PreciousBlock(hash); err != nil {
		return nil, &RPCError{Code: RPCErrInternal, Message: err.Error()}
	}

	return nil, nil
}
