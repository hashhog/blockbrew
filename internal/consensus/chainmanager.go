package consensus

import (
	"fmt"
	"log"
	"sync"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// UndoEntry stores the UTXO that was spent by a transaction input,
// so it can be restored during DisconnectBlock.
type UndoEntry struct {
	Outpoint wire.OutPoint
	Entry    UTXOEntry
}

// BlockUndo stores all undo data needed to disconnect a block.
type BlockUndo struct {
	SpentUTXOs []UndoEntry // UTXOs spent by this block (in tx order)
}

// ChainManager maintains the active chain and processes new blocks.
type ChainManager struct {
	mu          sync.RWMutex
	params      *ChainParams
	headerIndex *HeaderIndex
	chainDB     *storage.ChainDB
	utxoSet     UpdatableUTXOView
	tipNode     *BlockNode
	tipHeight   int32

	// Undo data for recent blocks (needed for reorgs)
	undoData map[wire.Hash256]*BlockUndo

	// Flush tracking for IBD
	blocksSinceFlush int
	flushInterval    int

	// IBD optimizations
	assumeValidHash   wire.Hash256 // Skip script validation below this hash
	assumeValidHeight int32        // Height of assume-valid block
	isIBD             bool         // Initial Block Download mode
	parallelScripts   bool         // Use parallel script validation
}

// ChainManagerConfig configures the chain manager.
type ChainManagerConfig struct {
	Params        *ChainParams
	HeaderIndex   *HeaderIndex
	ChainDB       *storage.ChainDB
	UTXOSet       UpdatableUTXOView
	FlushInterval int // Blocks between UTXO flushes (default: 2000)

	// IBD optimizations
	AssumeValidHash wire.Hash256 // Hash of assume-valid block (skip scripts below this)
	ParallelScripts bool         // Use parallel script validation (default: true)
}

// NewChainManager creates a new chain manager.
func NewChainManager(config ChainManagerConfig) *ChainManager {
	flushInterval := config.FlushInterval
	if flushInterval <= 0 {
		flushInterval = 2000 // Default: flush every 2000 blocks
	}

	cm := &ChainManager{
		params:          config.Params,
		headerIndex:     config.HeaderIndex,
		chainDB:         config.ChainDB,
		utxoSet:         config.UTXOSet,
		undoData:        make(map[wire.Hash256]*BlockUndo),
		flushInterval:   flushInterval,
		assumeValidHash: config.AssumeValidHash,
		parallelScripts: config.ParallelScripts,
		isIBD:           true, // Start in IBD mode
	}

	// Default to parallel script validation
	if !config.ParallelScripts {
		// Only disable if explicitly set (zero value means not set)
		cm.parallelScripts = true
	}

	// Initialize tip from genesis if no UTXO set provided
	if cm.utxoSet == nil {
		cm.utxoSet = NewInMemoryUTXOView()
	}

	// Set initial tip to genesis
	cm.tipNode = config.HeaderIndex.Genesis()
	cm.tipHeight = 0

	// Try to load chain state from database
	if config.ChainDB != nil {
		cm.loadChainState()
	}

	// Resolve assume-valid height
	if !cm.assumeValidHash.IsZero() {
		avNode := cm.headerIndex.GetNode(cm.assumeValidHash)
		if avNode != nil {
			cm.assumeValidHeight = avNode.Height
			log.Printf("chainmgr: assume-valid block at height %d", cm.assumeValidHeight)
		}
	}

	return cm
}

// loadChainState loads the chain state from the database.
func (cm *ChainManager) loadChainState() {
	state, err := cm.chainDB.GetChainState()
	if err != nil {
		// No saved state, start from genesis
		return
	}

	node := cm.headerIndex.GetNode(state.BestHash)
	if node == nil {
		log.Printf("chainmgr: saved chain tip %s not found in header index",
			state.BestHash.String()[:16])
		return
	}

	cm.tipNode = node
	cm.tipHeight = state.BestHeight
	log.Printf("chainmgr: loaded chain state at height %d", cm.tipHeight)
}

// ConnectBlock validates and connects a block to the active chain.
func (cm *ChainManager) ConnectBlock(block *wire.MsgBlock) error {
	hash := block.Header.BlockHash()
	node := cm.headerIndex.GetNode(hash)
	if node == nil {
		return fmt.Errorf("block %s not found in header index", hash.String()[:16])
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Verify this block connects to our current tip
	if block.Header.PrevBlock != cm.tipNode.Hash {
		// This might be a fork
		if node.TotalWork.Cmp(cm.tipNode.TotalWork) > 0 {
			// New chain has more work - reorg
			cm.mu.Unlock()
			err := cm.ReorgTo(node)
			cm.mu.Lock()
			return err
		}
		return fmt.Errorf("block does not connect to tip (prev=%s, tip=%s) and has less work",
			block.Header.PrevBlock.String()[:16], cm.tipNode.Hash.String()[:16])
	}

	// Full block validation
	err := CheckBlockSanity(block, cm.params.PowLimit)
	if err != nil {
		return fmt.Errorf("block sanity check failed: %w", err)
	}

	// Collect MTP timestamps from previous 11 blocks
	var mtp uint32
	prevTimestamps := cm.collectPrevTimestamps(cm.tipNode, MedianTimeSpan)
	if len(prevTimestamps) > 0 {
		mtp = CalcMedianTimePast(prevTimestamps)
	}

	prevHeader := cm.tipNode.Header
	err = CheckBlockContext(block, &prevHeader, node.Height, cm.params, mtp)
	if err != nil {
		return fmt.Errorf("block context check failed: %w", err)
	}

	// Get script flags for this height
	flags := GetBlockScriptFlags(node.Height, cm.params)

	// Calculate expected subsidy
	subsidy := CalcBlockSubsidy(node.Height)

	// Track total fees and undo data
	var totalFees int64
	undo := &BlockUndo{}

	// First pass: validate transaction structure and inputs (not scripts)
	for i, tx := range block.Transactions {
		// Check transaction sanity
		if err := CheckTransactionSanity(tx); err != nil {
			return fmt.Errorf("tx %d sanity failed: %w", i, err)
		}

		if i == 0 {
			// Coinbase - add outputs to UTXO view
			cm.utxoSet.AddTxOutputs(tx, node.Height)
			continue
		}

		// Check transaction inputs
		fee, err := CheckTransactionInputs(tx, node.Height, cm.utxoSet)
		if err != nil {
			return fmt.Errorf("tx %d input validation failed: %w", i, err)
		}
		totalFees += fee

		// Record spent UTXOs for undo data before spending
		for _, in := range tx.TxIn {
			utxo := cm.utxoSet.GetUTXO(in.PreviousOutPoint)
			if utxo != nil {
				undo.SpentUTXOs = append(undo.SpentUTXOs, UndoEntry{
					Outpoint: in.PreviousOutPoint,
					Entry:    *utxo,
				})
			}
		}

		// Update UTXO view: spend inputs and add outputs
		cm.utxoSet.SpendTxInputs(tx)
		cm.utxoSet.AddTxOutputs(tx, node.Height)
	}

	// Second pass: validate scripts (can be skipped for assume-valid or parallelized)
	// Assume-valid optimization: skip script validation for blocks before assume-valid point
	skipScripts := cm.assumeValidHeight > 0 && node.Height <= cm.assumeValidHeight

	if !skipScripts {
		if cm.parallelScripts {
			// Use parallel script validation for better performance
			if err := ParallelScriptValidation(block, cm.utxoSet, flags); err != nil {
				return fmt.Errorf("script validation failed: %w", err)
			}
		} else {
			// Sequential script validation
			for i, tx := range block.Transactions {
				if i == 0 {
					continue // Skip coinbase
				}
				if err := ValidateTransactionScripts(tx, cm.utxoSet, flags); err != nil {
					return fmt.Errorf("tx %d script validation failed: %w", i, err)
				}
			}
		}
	}

	// Verify coinbase value doesn't exceed subsidy + fees
	coinbase := block.Transactions[0]
	var coinbaseValue int64
	for _, out := range coinbase.TxOut {
		coinbaseValue += out.Value
	}
	if coinbaseValue > subsidy+totalFees {
		return fmt.Errorf("coinbase value %d exceeds allowed %d (subsidy %d + fees %d)",
			coinbaseValue, subsidy+totalFees, subsidy, totalFees)
	}

	// Store undo data for this block
	cm.undoData[hash] = undo

	// Update chain state
	cm.tipNode = node
	cm.tipHeight = node.Height
	node.Status |= StatusFullyValid

	// Exit IBD mode when close to current time
	if cm.isIBD && cm.tipHeight == cm.assumeValidHeight {
		cm.isIBD = false
		log.Printf("chainmgr: exiting IBD mode at height %d", cm.tipHeight)
	}

	// Persist chain state
	if cm.chainDB != nil {
		cm.chainDB.SetBlockHeight(node.Height, hash)
		cm.chainDB.SetChainState(&storage.ChainState{
			BestHash:   hash,
			BestHeight: node.Height,
		})
	}

	// Periodic UTXO flush during IBD
	cm.blocksSinceFlush++
	if cm.blocksSinceFlush >= cm.flushInterval {
		cm.flushUTXOs()
		cm.blocksSinceFlush = 0
	}

	return nil
}

// IsIBD returns whether the node is in Initial Block Download mode.
func (cm *ChainManager) IsIBD() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.isIBD
}

// SetIBD sets the IBD mode flag.
func (cm *ChainManager) SetIBD(isIBD bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.isIBD = isIBD
}

// SetParallelScripts enables or disables parallel script validation.
func (cm *ChainManager) SetParallelScripts(parallel bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.parallelScripts = parallel
}

// flushUTXOs persists the UTXO set to disk.
func (cm *ChainManager) flushUTXOs() {
	// This is a placeholder - actual implementation would persist the UTXO set
	// to the database. For InMemoryUTXOView, we'd need a database-backed version.
	log.Printf("chainmgr: UTXO flush at height %d", cm.tipHeight)
}

// collectPrevTimestamps collects timestamps from the previous N blocks.
func (cm *ChainManager) collectPrevTimestamps(node *BlockNode, count int) []uint32 {
	timestamps := make([]uint32, 0, count)
	current := node
	for i := 0; i < count && current != nil; i++ {
		timestamps = append(timestamps, current.Header.Timestamp)
		current = current.Parent
	}
	return timestamps
}

// DisconnectBlock undoes the effects of a block (for reorgs).
func (cm *ChainManager) DisconnectBlock(hash wire.Hash256) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Verify this is the current tip
	if hash != cm.tipNode.Hash {
		return fmt.Errorf("cannot disconnect non-tip block")
	}

	// Get the block data
	block, err := cm.chainDB.GetBlock(hash)
	if err != nil {
		return fmt.Errorf("block %s not found for disconnect: %w", hash.String()[:16], err)
	}

	// Get undo data for this block
	undo, hasUndo := cm.undoData[hash]

	// Undo UTXO changes in reverse order
	// First, remove outputs that were created
	for i := len(block.Transactions) - 1; i >= 0; i-- {
		tx := block.Transactions[i]
		txHash := tx.TxHash()
		for idx := range tx.TxOut {
			outpoint := wire.OutPoint{Hash: txHash, Index: uint32(idx)}
			cm.utxoSet.SpendUTXO(outpoint)
		}
	}

	// Then, restore inputs that were spent using undo data
	if hasUndo {
		for _, entry := range undo.SpentUTXOs {
			restored := entry.Entry // copy
			cm.utxoSet.AddUTXO(entry.Outpoint, &restored)
		}
	}

	// Clean up undo data
	delete(cm.undoData, hash)

	// Update chain state
	parent := cm.tipNode.Parent
	if parent == nil {
		return fmt.Errorf("cannot disconnect genesis block")
	}

	cm.tipNode = parent
	cm.tipHeight = parent.Height

	// Persist
	if cm.chainDB != nil {
		cm.chainDB.SetChainState(&storage.ChainState{
			BestHash:   parent.Hash,
			BestHeight: parent.Height,
		})
	}

	return nil
}

// ReorgTo reorganizes the chain to a new tip.
func (cm *ChainManager) ReorgTo(newTip *BlockNode) error {
	cm.mu.Lock()
	currentTip := cm.tipNode
	cm.mu.Unlock()

	// Find the fork point
	fork := FindFork(currentTip, newTip)
	if fork == nil {
		return fmt.Errorf("no common ancestor found")
	}

	log.Printf("chainmgr: reorg from height %d to %d (fork at %d)",
		currentTip.Height, newTip.Height, fork.Height)

	// Disconnect blocks from current tip back to fork
	disconnectNodes := make([]*BlockNode, 0)
	for node := currentTip; node != fork; node = node.Parent {
		disconnectNodes = append(disconnectNodes, node)
	}
	for _, node := range disconnectNodes {
		if err := cm.DisconnectBlock(node.Hash); err != nil {
			return fmt.Errorf("disconnect block %s failed: %w", node.Hash.String()[:16], err)
		}
	}

	// Connect blocks from fork to new tip
	connectNodes := make([]*BlockNode, 0)
	for node := newTip; node != fork; node = node.Parent {
		connectNodes = append(connectNodes, node)
	}
	// Reverse to connect in order
	for i, j := 0, len(connectNodes)-1; i < j; i, j = i+1, j-1 {
		connectNodes[i], connectNodes[j] = connectNodes[j], connectNodes[i]
	}
	for _, node := range connectNodes {
		block, err := cm.chainDB.GetBlock(node.Hash)
		if err != nil {
			return fmt.Errorf("block %s not found for reorg: %w", node.Hash.String()[:16], err)
		}
		if err := cm.ConnectBlock(block); err != nil {
			return fmt.Errorf("connect block %s failed during reorg: %w", node.Hash.String()[:16], err)
		}
	}

	return nil
}

// BestBlock returns the current chain tip hash and height.
func (cm *ChainManager) BestBlock() (wire.Hash256, int32) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.tipNode == nil {
		return wire.Hash256{}, 0
	}
	return cm.tipNode.Hash, cm.tipHeight
}

// IsInMainChain checks if a block hash is in the active (main) chain.
func (cm *ChainManager) IsInMainChain(hash wire.Hash256) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	node := cm.headerIndex.GetNode(hash)
	if node == nil {
		return false
	}

	// Check if this node is an ancestor of our tip
	tipAtHeight := cm.tipNode.GetAncestor(node.Height)
	return tipAtHeight != nil && tipAtHeight.Hash == hash
}

// TipNode returns the current tip block node.
func (cm *ChainManager) TipNode() *BlockNode {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.tipNode
}

// UTXOSet returns the current UTXO set.
func (cm *ChainManager) UTXOSet() UpdatableUTXOView {
	return cm.utxoSet
}
