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
}

// ChainManagerConfig configures the chain manager.
type ChainManagerConfig struct {
	Params        *ChainParams
	HeaderIndex   *HeaderIndex
	ChainDB       *storage.ChainDB
	UTXOSet       UpdatableUTXOView
	FlushInterval int // Blocks between UTXO flushes (default: 2000)
}

// NewChainManager creates a new chain manager.
func NewChainManager(config ChainManagerConfig) *ChainManager {
	flushInterval := config.FlushInterval
	if flushInterval <= 0 {
		flushInterval = 2000 // Default: flush every 2000 blocks
	}

	cm := &ChainManager{
		params:        config.Params,
		headerIndex:   config.HeaderIndex,
		chainDB:       config.ChainDB,
		utxoSet:       config.UTXOSet,
		flushInterval: flushInterval,
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

	prevHeader := cm.tipNode.Header
	err = CheckBlockContext(block, &prevHeader, node.Height, cm.params)
	if err != nil {
		return fmt.Errorf("block context check failed: %w", err)
	}

	// Get script flags for this height
	flags := GetBlockScriptFlags(node.Height, cm.params)

	// Calculate expected subsidy
	subsidy := CalcBlockSubsidy(node.Height)

	// Track total fees
	var totalFees int64

	// Validate each transaction
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

		// Validate scripts
		err = ValidateTransactionScripts(tx, cm.utxoSet, flags)
		if err != nil {
			return fmt.Errorf("tx %d script validation failed: %w", i, err)
		}

		// Update UTXO view: spend inputs and add outputs
		cm.utxoSet.SpendTxInputs(tx)
		cm.utxoSet.AddTxOutputs(tx, node.Height)
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

// flushUTXOs persists the UTXO set to disk.
func (cm *ChainManager) flushUTXOs() {
	// This is a placeholder - actual implementation would persist the UTXO set
	// to the database. For InMemoryUTXOView, we'd need a database-backed version.
	log.Printf("chainmgr: UTXO flush at height %d", cm.tipHeight)
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

	// Then, restore inputs that were spent (except coinbase)
	for i := len(block.Transactions) - 1; i > 0; i-- {
		tx := block.Transactions[i]
		for _, in := range tx.TxIn {
			// We need to get the original UTXO entry from the database
			// For now, this is a simplified implementation
			// A full implementation would store undo data when connecting blocks
			_ = in // placeholder
		}
	}

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
