package consensus

import (
	"fmt"
	"log"
	"sync"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// cachedUTXOView wraps a UTXOView with a cache of entries that may have been
// spent from the underlying view. This is used during block connection so that
// script validation (second pass) can still access UTXOs that were spent in the
// first pass.
type cachedUTXOView struct {
	cache    map[wire.OutPoint]*UTXOEntry
	fallback UTXOView
}

func (c *cachedUTXOView) GetUTXO(outpoint wire.OutPoint) *UTXOEntry {
	if entry, ok := c.cache[outpoint]; ok {
		return entry
	}
	return c.fallback.GetUTXO(outpoint)
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

	// Flush tracking for IBD
	blocksSinceFlush int
	flushInterval    int

	// IBD optimizations
	assumeValidHash   wire.Hash256 // Skip script validation below this hash
	assumeValidHeight int32        // Height of assume-valid block
	isIBD             bool         // Initial Block Download mode
	parallelScripts   bool         // Use parallel script validation

	// Signature cache for faster block connection
	sigCache *SigCache
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

	// SigCacheSize is the maximum number of entries in the signature cache.
	// Default: 50,000 entries. Set to 0 to disable caching.
	SigCacheSize int
}

// NewChainManager creates a new chain manager.
func NewChainManager(config ChainManagerConfig) *ChainManager {
	flushInterval := config.FlushInterval
	if flushInterval <= 0 {
		flushInterval = 2000 // Default: flush every 2000 blocks
	}

	// Initialize signature cache
	var sigCache *SigCache
	if config.SigCacheSize >= 0 {
		// Use provided size (0 means use default, negative means disabled)
		sigCache = NewSigCache(config.SigCacheSize)
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
		sigCache:        sigCache,
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

// ReloadChainState re-resolves the chain tip from the database after the
// header index has been populated (e.g. after P2P header sync completes).
// This is needed because on startup the header index only contains the genesis
// block, so loadChainState cannot find the saved tip.
// It also resolves the assume-valid height if not yet resolved.
func (cm *ChainManager) ReloadChainState() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Resolve assume-valid height if not yet done.  This must happen even
	// when the chain tip is already known, because the assume-valid block
	// might not have been in the header index at startup.
	if cm.assumeValidHeight == 0 && !cm.assumeValidHash.IsZero() {
		avNode := cm.headerIndex.GetNode(cm.assumeValidHash)
		if avNode != nil {
			cm.assumeValidHeight = avNode.Height
			log.Printf("chainmgr: assume-valid resolved at height %d during ReloadChainState", cm.assumeValidHeight)
		}
	}

	// Only reload chain tip if currently at genesis — don't clobber a valid tip
	if cm.tipHeight > 0 {
		return
	}

	if cm.chainDB == nil {
		return
	}

	state, err := cm.chainDB.GetChainState()
	if err != nil {
		return
	}

	node := cm.headerIndex.GetNode(state.BestHash)
	if node == nil {
		log.Printf("chainmgr: ReloadChainState: saved tip %s still not in header index",
			state.BestHash.String()[:16])
		return
	}

	cm.tipNode = node
	cm.tipHeight = state.BestHeight
	log.Printf("chainmgr: reloaded chain state at height %d after header sync", cm.tipHeight)
}

// ConnectBlock validates and connects a block to the active chain.
func (cm *ChainManager) ConnectBlock(block *wire.MsgBlock) error {
	hash := block.Header.BlockHash()
	node := cm.headerIndex.GetNode(hash)
	if node == nil {
		return fmt.Errorf("block %s not found in header index", hash.String()[:16])
	}

	// Log every 5000th block and any block that might be problematic
	if node.Height%5000 == 0 || (node.Height >= 59170 && node.Height <= 59180) {
		log.Printf("chainmgr: ConnectBlock height=%d hash=%s txCount=%d tipHeight=%d",
			node.Height, hash.String()[:16], len(block.Transactions), cm.tipHeight)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Verify this block connects to our current tip
	if block.Header.PrevBlock != cm.tipNode.Hash {
		// During IBD, never attempt reorgs — blocks must arrive in order.
		// The sync pipeline ensures ordering; a mismatch here means a block
		// was skipped or failed, so just return an error.
		if cm.isIBD {
			return fmt.Errorf("block does not connect to tip during IBD (prev=%s, tip=%s, height=%d)",
				block.Header.PrevBlock.String()[:16], cm.tipNode.Hash.String()[:16], node.Height)
		}
		// Post-IBD: this might be a fork
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

	// Resolve assume-valid early so we can skip expensive work during IBD.
	if cm.assumeValidHeight == 0 && !cm.assumeValidHash.IsZero() {
		avNode := cm.headerIndex.GetNode(cm.assumeValidHash)
		if avNode != nil {
			cm.assumeValidHeight = avNode.Height
			log.Printf("chainmgr: assume-valid block resolved at height %d", cm.assumeValidHeight)
		}
	}
	skipScripts := cm.assumeValidHeight > 0 && node.Height <= cm.assumeValidHeight

	// Full block validation (skip sanity during IBD -- already done by validationWorker)
	if !cm.isIBD {
		err := CheckBlockSanity(block, cm.params.PowLimit)
		if err != nil {
			return fmt.Errorf("block sanity check failed: %w", err)
		}
	}

	// Collect MTP timestamps from previous 11 blocks
	var mtp uint32
	prevTimestamps := cm.collectPrevTimestamps(cm.tipNode, MedianTimeSpan)
	if len(prevTimestamps) > 0 {
		mtp = CalcMedianTimePast(prevTimestamps)
	}

	prevHeader := cm.tipNode.Header
	err := CheckBlockContext(block, &prevHeader, node.Height, cm.params, mtp)
	if err != nil {
		return fmt.Errorf("block context check failed: %w", err)
	}

	// Get script flags for this block (hash checked against exception map)
	flags := GetBlockScriptFlags(node.Height, cm.params, hash)

	// Calculate expected subsidy
	subsidy := CalcBlockSubsidy(node.Height)

	// Track total fees and undo data.
	// Skip undo data generation during assume-valid IBD for performance.
	var totalFees int64
	generateUndo := !skipScripts || !cm.isIBD
	var blockUndo *storage.BlockUndo
	if generateUndo {
		blockUndo = &storage.BlockUndo{
			TxUndos: make([]storage.TxUndo, 0, len(block.Transactions)-1),
		}
	}

	// Genesis block special case: the genesis coinbase is unspendable.
	// Bitcoin Core skips transaction connection for the genesis block.
	if node.Height == 0 {
		// Store empty undo data and update chain state
		cm.tipNode = node
		cm.tipHeight = node.Height
		node.Status |= StatusFullyValid
		if cm.chainDB != nil {
			emptyUndo := &storage.BlockUndo{}
			cm.chainDB.WriteBlockUndo(hash, emptyUndo)
			cm.chainDB.SetBlockHeight(node.Height, hash)
			cm.chainDB.SetChainState(&storage.ChainState{
				BestHash:   hash,
				BestHeight: node.Height,
			})
		}
		return nil
	}

	// Cache prevouts for script validation BEFORE spending them.
	// The first pass spends UTXOs, so the second pass (script validation)
	// needs a cached view of the original UTXOs.
	cachedView := &cachedUTXOView{
		cache:    make(map[wire.OutPoint]*UTXOEntry),
		fallback: cm.utxoSet,
	}

	// Track UTXO modifications so we can roll back if validation fails.
	// Each entry records a tx index and the outputs it added / inputs it spent.
	type utxoModification struct {
		txIdx       int
		addedOuts   []wire.OutPoint    // outputs added to UTXO set
		spentInputs []wire.OutPoint    // inputs spent from UTXO set
		spentCoins  []storage.SpentCoin // original UTXOs for rollback
	}
	var utxoMods []utxoModification

	// rollbackUTXOs undoes all UTXO changes made during the first pass.
	// This is critical: without rollback, a failed ConnectBlock corrupts the
	// UTXO set and causes all subsequent blocks to fail validation too.
	rollbackUTXOs := func() {
		// Undo in reverse order
		for i := len(utxoMods) - 1; i >= 0; i-- {
			mod := utxoMods[i]
			// Remove outputs that were added
			for _, op := range mod.addedOuts {
				cm.utxoSet.SpendUTXO(op)
			}
			// Restore inputs that were spent
			for _, sc := range mod.spentCoins {
				cm.utxoSet.AddUTXO(mod.spentInputs[0], &UTXOEntry{
					Amount:     sc.TxOut.Value,
					PkScript:   sc.TxOut.PkScript,
					Height:     sc.Height,
					IsCoinbase: sc.Coinbase,
				})
				mod.spentInputs = mod.spentInputs[1:]
			}
		}
	}

	// First pass: validate transaction structure and inputs (not scripts)
	for i, tx := range block.Transactions {
		// Check transaction sanity
		if err := CheckTransactionSanity(tx); err != nil {
			rollbackUTXOs()
			return fmt.Errorf("tx %d sanity failed: %w", i, err)
		}

		txHash := tx.TxHash()

		if i == 0 {
			// Coinbase - add outputs to UTXO view
			cm.utxoSet.AddTxOutputs(tx, node.Height)
			// Track coinbase outputs for rollback
			var addedOuts []wire.OutPoint
			for idx := range tx.TxOut {
				addedOuts = append(addedOuts, wire.OutPoint{Hash: txHash, Index: uint32(idx)})
			}
			utxoMods = append(utxoMods, utxoModification{txIdx: i, addedOuts: addedOuts})
			continue
		}

		// Cache all input UTXOs before they get spent
		for _, in := range tx.TxIn {
			utxo := cm.utxoSet.GetUTXO(in.PreviousOutPoint)
			if utxo != nil {
				cachedView.cache[in.PreviousOutPoint] = utxo
			}
		}

		// Check transaction inputs
		fee, err := CheckTransactionInputs(tx, node.Height, cm.utxoSet)
		if err != nil {
			rollbackUTXOs()
			return fmt.Errorf("tx %d input validation failed: %w", i, err)
		}
		totalFees += fee
		if totalFees > MaxMoney {
			rollbackUTXOs()
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
				rollbackUTXOs()
				return fmt.Errorf("tx %d: %w", i, ErrSequenceLockNotMet)
			}
		}

		// Always record spent UTXOs for in-memory rollback. Without this,
		// a validation failure mid-block leaves the UTXO set corrupted
		// because spent inputs cannot be restored.
		spentInputs := make([]wire.OutPoint, 0, len(tx.TxIn))
		spentCoins := make([]storage.SpentCoin, 0, len(tx.TxIn))
		for _, in := range tx.TxIn {
			utxo := cm.utxoSet.GetUTXO(in.PreviousOutPoint)
			if utxo != nil {
				spentCoins = append(spentCoins, storage.SpentCoin{
					TxOut: wire.TxOut{
						Value:    utxo.Amount,
						PkScript: utxo.PkScript,
					},
					Height:   utxo.Height,
					Coinbase: utxo.IsCoinbase,
				})
			}
			spentInputs = append(spentInputs, in.PreviousOutPoint)
		}

		// Persist undo data to disk only when needed (not during assume-valid IBD)
		if generateUndo {
			txUndo := storage.TxUndo{
				SpentCoins: spentCoins,
			}
			blockUndo.TxUndos = append(blockUndo.TxUndos, txUndo)
		}

		// Update UTXO view: spend inputs and add outputs
		cm.utxoSet.SpendTxInputs(tx)
		cm.utxoSet.AddTxOutputs(tx, node.Height)

		// Track modifications for rollback
		var addedOuts []wire.OutPoint
		for idx := range tx.TxOut {
			addedOuts = append(addedOuts, wire.OutPoint{Hash: txHash, Index: uint32(idx)})
		}
		utxoMods = append(utxoMods, utxoModification{
			txIdx:       i,
			addedOuts:   addedOuts,
			spentInputs: spentInputs,
			spentCoins:  spentCoins,
		})
	}

	// Second pass: validate scripts (can be skipped for assume-valid or parallelized)
	if !skipScripts {
		// Use the cached UTXO view so script validation can find spent UTXOs
		if cm.parallelScripts {
			if err := ParallelScriptValidationCached(block, cachedView, flags, cm.sigCache); err != nil {
				rollbackUTXOs()
				return fmt.Errorf("script validation failed: %w", err)
			}
		} else {
			for i, tx := range block.Transactions {
				if i == 0 {
					continue // Skip coinbase
				}
				if err := ValidateTransactionScripts(tx, cachedView, flags); err != nil {
					rollbackUTXOs()
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
		rollbackUTXOs()
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

	// Persist undo data and chain state.
	// IMPORTANT: UTXO flush MUST happen BEFORE chain state is written so
	// that a crash never leaves the chain tip ahead of the UTXO set.
	if cm.chainDB != nil {
		// Write undo data keyed by block hash (not height, since heights can change during reorgs)
		if generateUndo {
			if err := cm.chainDB.WriteBlockUndo(hash, blockUndo); err != nil {
				return fmt.Errorf("failed to write undo data: %w", err)
			}
		}
		cm.chainDB.SetBlockHeight(node.Height, hash)
	}

	// Periodic UTXO flush during IBD
	cm.blocksSinceFlush++
	if cm.blocksSinceFlush >= cm.flushInterval {
		cm.flushUTXOs()
		cm.blocksSinceFlush = 0
	}

	// Write chain state AFTER UTXO flush to ensure consistency on crash.
	// During IBD, batch writes every flushInterval blocks to reduce I/O.
	// Post-IBD, write every block for crash safety.
	if cm.chainDB != nil {
		if !cm.isIBD || cm.blocksSinceFlush == 0 {
			cm.chainDB.SetChainState(&storage.ChainState{
				BestHash:   hash,
				BestHeight: node.Height,
			})
		}
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
	// Check if the UTXO set supports flushing (database-backed UTXOSet)
	type flusher interface {
		Flush() error
	}
	if f, ok := cm.utxoSet.(flusher); ok {
		if err := f.Flush(); err != nil {
			log.Printf("chainmgr: UTXO flush error at height %d: %v", cm.tipHeight, err)
		} else {
			log.Printf("chainmgr: UTXO flush at height %d", cm.tipHeight)
		}
	}
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

	// Clear signature cache since cached entries may no longer be valid after reorg.
	// A transaction that was valid in the old chain might reference UTXOs that
	// no longer exist or have different values in the new chain.
	if cm.sigCache != nil {
		cm.sigCache.Clear()
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

// InvalidateBlock marks a block as invalid and triggers a reorg if needed.
// This implements the invalidateblock RPC behavior.
// If the block is in the active chain, it will be disconnected along with all
// blocks built on top of it, and the best valid chain will be activated.
// Descendants of the invalid block are marked with StatusInvalidChild.
func (cm *ChainManager) InvalidateBlock(hash wire.Hash256) error {
	node := cm.headerIndex.GetNode(hash)
	if node == nil {
		return fmt.Errorf("block not found")
	}

	// Genesis block can't be invalidated
	if node.Height == 0 {
		return fmt.Errorf("genesis block cannot be invalidated")
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// First, mark all descendants as invalid child (before disconnecting)
	// This way the descendants get the right flag even if they're in the active chain
	cm.markDescendantsInvalid(node)

	// Mark the target block itself as explicitly invalid
	node.Status |= StatusInvalid

	// Check if block is in the active chain
	isInActiveChain := cm.isAncestorOfTip(node)

	if isInActiveChain {
		// Disconnect blocks from tip back to the invalid block (inclusive)
		// We stop when the parent of the invalid block becomes the tip
		disconnected := 0
		for cm.tipNode != node.Parent {
			if cm.tipNode == nil || cm.tipNode.Height < node.Parent.Height {
				return fmt.Errorf("failed to disconnect to target: tip is below target parent")
			}

			tipHash := cm.tipNode.Hash

			// Unlock for the potentially long disconnect operation
			cm.mu.Unlock()
			err := cm.DisconnectBlock(tipHash)
			cm.mu.Lock()

			if err != nil {
				return fmt.Errorf("failed to disconnect block at height %d: %w",
					cm.tipNode.Height, err)
			}
			disconnected++

			// Limit transactions being readded to mempool during deep reorgs
			if disconnected > 10 {
				// For deep reorgs, mempool updates become expensive
				// In a full implementation, we'd stop adding txs back to mempool
			}
		}
	}

	// Update header index to recalculate best tip excluding invalid blocks
	cm.headerIndex.RecalculateBestTip()

	// If the new best tip has more work than current tip, reorg to it
	bestTip := cm.headerIndex.BestTip()
	if bestTip != nil && !bestTip.Status.IsInvalid() && bestTip.TotalWork.Cmp(cm.tipNode.TotalWork) > 0 {
		// Need to activate the best valid chain
		cm.mu.Unlock()
		err := cm.ReorgTo(bestTip)
		cm.mu.Lock()
		if err != nil {
			log.Printf("chainmgr: failed to reorg to best chain after invalidation: %v", err)
		}
	}

	log.Printf("chainmgr: invalidated block %s at height %d", hash.String()[:16], node.Height)
	return nil
}

// markDescendantsInvalid marks all descendants of a block as invalid.
func (cm *ChainManager) markDescendantsInvalid(node *BlockNode) {
	// Use BFS to mark all descendants
	queue := make([]*BlockNode, 0)
	for _, child := range node.Children {
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// Mark as invalid child (unless already explicitly invalid)
		if current.Status&StatusInvalid == 0 {
			current.Status |= StatusInvalidChild
		}

		// Add children to queue
		queue = append(queue, current.Children...)
	}
}

// isAncestorOfTip checks if a node is an ancestor of (or equal to) the current tip.
func (cm *ChainManager) isAncestorOfTip(node *BlockNode) bool {
	if cm.tipNode == nil || node == nil {
		return false
	}
	// Walk up from tip to see if we reach node
	current := cm.tipNode
	for current != nil && current.Height >= node.Height {
		if current.Hash == node.Hash {
			return true
		}
		current = current.Parent
	}
	return false
}

// ReconsiderBlock clears the invalid flag from a block and its ancestors/descendants,
// allowing them to be reconsidered for chain selection.
// This implements the reconsiderblock RPC behavior.
func (cm *ChainManager) ReconsiderBlock(hash wire.Hash256) error {
	node := cm.headerIndex.GetNode(hash)
	if node == nil {
		return fmt.Errorf("block not found")
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Clear invalid flags from this block and all ancestors up to genesis
	current := node
	for current != nil {
		current.Status &^= (StatusInvalid | StatusInvalidChild)
		current = current.Parent
	}

	// Clear invalid flags from all descendants
	cm.clearDescendantInvalidFlags(node)

	// Recalculate best tip
	cm.headerIndex.RecalculateBestTip()

	// If the reconsidered chain now has more work, reorg to it
	bestTip := cm.headerIndex.BestTip()
	if bestTip != nil && !bestTip.Status.IsInvalid() {
		// Only reorg if the new best has more work
		if bestTip.TotalWork.Cmp(cm.tipNode.TotalWork) > 0 {
			cm.mu.Unlock()
			err := cm.ReorgTo(bestTip)
			cm.mu.Lock()
			if err != nil {
				return fmt.Errorf("failed to reorg to reconsidered chain: %w", err)
			}
		}
	}

	log.Printf("chainmgr: reconsidered block %s at height %d", hash.String()[:16], node.Height)
	return nil
}

// clearDescendantInvalidFlags clears invalid flags from all descendants of a block.
func (cm *ChainManager) clearDescendantInvalidFlags(node *BlockNode) {
	// Use BFS to clear flags from all descendants
	queue := make([]*BlockNode, 0)
	for _, child := range node.Children {
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// Clear invalid child flag (keep explicit invalid if set)
		current.Status &^= StatusInvalidChild

		// Add children to queue
		queue = append(queue, current.Children...)
	}
}

// PreciousBlock gives a block temporary priority in chain selection.
// If there are two chains with equal work, prefer the one containing this block.
// This is ephemeral - the preference is lost on restart.
// Only the last PreciousBlock call matters (new calls override previous).
func (cm *ChainManager) PreciousBlock(hash wire.Hash256) error {
	node := cm.headerIndex.GetNode(hash)
	if node == nil {
		return fmt.Errorf("block not found")
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// If the block has less work than current tip, nothing to do
	if node.TotalWork.Cmp(cm.tipNode.TotalWork) < 0 {
		return nil
	}

	// Mark this block as precious in the header index
	cm.headerIndex.SetPreciousBlock(node)

	// If the precious block is not on our current chain and has equal or more work,
	// try to reorg to it
	if !cm.isAncestorOfTip(node) && node.TotalWork.Cmp(cm.tipNode.TotalWork) >= 0 {
		// Recalculate best tip with precious preference
		cm.headerIndex.RecalculateBestTip()

		bestTip := cm.headerIndex.BestTip()
		if bestTip != nil && bestTip.Hash != cm.tipNode.Hash {
			cm.mu.Unlock()
			err := cm.ReorgTo(bestTip)
			cm.mu.Lock()
			if err != nil {
				return fmt.Errorf("failed to reorg to precious chain: %w", err)
			}
		}
	}

	log.Printf("chainmgr: set precious block %s at height %d", hash.String()[:16], node.Height)
	return nil
}

// GetHeaderIndex returns the header index.
func (cm *ChainManager) GetHeaderIndex() *HeaderIndex {
	return cm.headerIndex
}
