package consensus

import (
	"fmt"
	"log"
	"sync"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ChainManager maintains the active chain and processes new blocks.
type ChainManager struct {
	mu          sync.RWMutex
	params      *ChainParams
	headerIndex *HeaderIndex
	chainDB     *storage.ChainDB
	utxoSet     UpdatableUTXOView
	tipNode     *BlockNode
	tipHeight   int32

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
	// Undo data: one TxUndo per non-coinbase transaction
	blockUndo := &storage.BlockUndo{
		TxUndos: make([]storage.TxUndo, 0, len(block.Transactions)-1),
	}

	// Genesis block special case: the genesis coinbase is unspendable.
	// Bitcoin Core skips transaction connection for the genesis block.
	if node.Height == 0 {
		// Store empty undo data and update chain state
		cm.tipNode = node
		cm.tipHeight = node.Height
		node.Status |= StatusFullyValid
		if cm.chainDB != nil {
			cm.chainDB.WriteBlockUndo(hash, blockUndo)
			cm.chainDB.SetBlockHeight(node.Height, hash)
			cm.chainDB.SetChainState(&storage.ChainState{
				BestHash:   hash,
				BestHeight: node.Height,
			})
		}
		return nil
	}

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
		if totalFees > MaxMoney {
			return fmt.Errorf("accumulated fee in the block out of range: %d > %d", totalFees, MaxMoney)
		}

		// BIP68: Enforce sequence locks after CSV activation
		if node.Height >= cm.params.CSVHeight {
			prevHeights := make([]int32, len(tx.TxIn))
			for j, in := range tx.TxIn {
				utxo := cm.utxoSet.GetUTXO(in.PreviousOutPoint)
				if utxo != nil {
					prevHeights[j] = utxo.Height
				}
			}
			// Create MTP lookup function using header index
			// BIP68 time-based locks need MTP at the height of the block prior to
			// where the UTXO was confirmed
			getMTP := func(height int32) int64 {
				ancestor := node.GetAncestor(height)
				if ancestor == nil {
					return 0
				}
				return ancestor.GetMedianTimePast()
			}
			seqLock := CalculateSequenceLocks(tx, prevHeights, getMTP)
			if !EvaluateSequenceLocks(seqLock, node.Height, int64(mtp)) {
				return fmt.Errorf("tx %d: %w", i, ErrSequenceLockNotMet)
			}
		}

		// Record spent UTXOs for undo data before spending (one TxUndo per transaction)
		txUndo := storage.TxUndo{
			SpentCoins: make([]storage.SpentCoin, 0, len(tx.TxIn)),
		}
		for _, in := range tx.TxIn {
			utxo := cm.utxoSet.GetUTXO(in.PreviousOutPoint)
			if utxo != nil {
				txUndo.SpentCoins = append(txUndo.SpentCoins, storage.SpentCoin{
					TxOut: wire.TxOut{
						Value:    utxo.Amount,
						PkScript: utxo.PkScript,
					},
					Height:   utxo.Height,
					Coinbase: utxo.IsCoinbase,
				})
			}
		}
		blockUndo.TxUndos = append(blockUndo.TxUndos, txUndo)

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

	// Update chain state
	cm.tipNode = node
	cm.tipHeight = node.Height
	node.Status |= StatusFullyValid

	// Exit IBD mode when close to current time
	if cm.isIBD && cm.tipHeight == cm.assumeValidHeight {
		cm.isIBD = false
		log.Printf("chainmgr: exiting IBD mode at height %d", cm.tipHeight)
	}

	// Persist undo data and chain state
	if cm.chainDB != nil {
		// Write undo data keyed by block hash (not height, since heights can change during reorgs)
		if err := cm.chainDB.WriteBlockUndo(hash, blockUndo); err != nil {
			return fmt.Errorf("failed to write undo data: %w", err)
		}
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
// It removes outputs created by the block and restores spent UTXOs from undo data.
// Transactions must be disconnected in reverse order to correctly restore the UTXO set.
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

	// Load undo data from database
	blockUndo, err := cm.chainDB.ReadBlockUndo(hash)
	if err != nil {
		return fmt.Errorf("failed to read undo data for block %s: %w", hash.String()[:16], err)
	}

	// Verify undo data consistency
	nonCoinbaseTxCount := len(block.Transactions) - 1
	if nonCoinbaseTxCount < 0 {
		nonCoinbaseTxCount = 0
	}
	if len(blockUndo.TxUndos) != nonCoinbaseTxCount {
		return fmt.Errorf("undo data mismatch: %d TxUndos but %d non-coinbase transactions",
			len(blockUndo.TxUndos), nonCoinbaseTxCount)
	}

	// Process transactions in REVERSE order (critical for correct UTXO restoration)
	for i := len(block.Transactions) - 1; i >= 0; i-- {
		tx := block.Transactions[i]
		txHash := tx.TxHash()

		// Remove outputs created by this transaction (skip unspendable outputs
		// since they were never added to the UTXO set)
		for idx, out := range tx.TxOut {
			if IsUnspendable(out.PkScript) {
				continue
			}
			outpoint := wire.OutPoint{Hash: txHash, Index: uint32(idx)}
			cm.utxoSet.SpendUTXO(outpoint)
		}

		// For non-coinbase transactions, restore the inputs that were spent
		if i > 0 {
			// Get the TxUndo for this transaction (i-1 because index 0 is coinbase)
			txUndo := &blockUndo.TxUndos[i-1]

			// Verify input count matches
			if len(txUndo.SpentCoins) != len(tx.TxIn) {
				return fmt.Errorf("tx %d undo mismatch: %d spent coins but %d inputs",
					i, len(txUndo.SpentCoins), len(tx.TxIn))
			}

			// Restore each spent UTXO
			for j, in := range tx.TxIn {
				spentCoin := &txUndo.SpentCoins[j]
				cm.utxoSet.AddUTXO(in.PreviousOutPoint, &UTXOEntry{
					Amount:     spentCoin.TxOut.Value,
					PkScript:   spentCoin.TxOut.PkScript,
					Height:     spentCoin.Height,
					IsCoinbase: spentCoin.Coinbase,
				})
			}
		}
		// Coinbase (i == 0) has no inputs to restore - we just removed its outputs above
	}

	// Delete undo data from database
	if err := cm.chainDB.DeleteBlockUndo(hash); err != nil {
		log.Printf("chainmgr: warning: failed to delete undo data for %s: %v", hash.String()[:16], err)
	}

	// Update chain state
	parent := cm.tipNode.Parent
	if parent == nil {
		return fmt.Errorf("cannot disconnect genesis block")
	}

	cm.tipNode = parent
	cm.tipHeight = parent.Height

	// Persist updated chain state
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
