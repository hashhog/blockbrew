// Package mempool implements the transaction memory pool.
package mempool

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Mempool errors.
var (
	ErrAlreadyInMempool   = errors.New("transaction already in mempool")
	ErrCoinbaseNotAllowed = errors.New("coinbase transactions not allowed in mempool")
	ErrTxTooLarge         = errors.New("transaction exceeds maximum standard weight")
	ErrDoubleSpend        = errors.New("input already spent by mempool transaction")
	ErrMissingInputs      = errors.New("transaction references missing inputs")
	ErrNegativeFee        = errors.New("transaction fee is negative")
	ErrInsufficientFee    = errors.New("fee rate below minimum relay fee")
	ErrDustOutput         = errors.New("output is dust")
	ErrScriptValidation   = errors.New("script validation failed")
	ErrMempoolFull        = errors.New("mempool is full")
	ErrOrphanPoolFull     = errors.New("orphan pool is full")
)

// Config configures the mempool.
type Config struct {
	MaxSize         int64 // Maximum mempool size in bytes (default: 300 MB)
	MinRelayFeeRate int64 // Minimum fee rate in sat/kvB (default: 1000)
	MaxOrphanTxs    int   // Maximum orphan transactions (default: 100)
	ChainParams     *consensus.ChainParams
}

// DefaultConfig returns a mempool config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxSize:         300_000_000, // 300 MB
		MinRelayFeeRate: 1000,        // 1 sat/vB
		MaxOrphanTxs:    100,
		ChainParams:     consensus.MainnetParams(),
	}
}

// TxEntry represents a transaction in the mempool.
type TxEntry struct {
	Tx             *wire.MsgTx
	TxHash         wire.Hash256
	Fee            int64         // Transaction fee in satoshis
	Size           int64         // Transaction virtual size (weight / 4)
	FeeRate        float64       // Fee rate in sat/vB
	Time           time.Time     // When the transaction was added
	Height         int32         // Chain height when added
	Depends        []wire.Hash256 // Transactions this depends on (parent txids in mempool)
	SpentBy        []wire.Hash256 // Transactions that spend this transaction's outputs
	AncestorFee    int64         // Total fee of this tx + all ancestors
	AncestorSize   int64         // Total size of this tx + all ancestors
	DescendantFee  int64         // Total fee of this tx + all descendants
	DescendantSize int64         // Total size of this tx + all descendants
}

// AncestorFeeRate returns the ancestor fee rate (sat/vB).
func (e *TxEntry) AncestorFeeRate() float64 {
	if e.AncestorSize == 0 {
		return 0
	}
	return float64(e.AncestorFee) / float64(e.AncestorSize)
}

// DescendantFeeRate returns the descendant fee rate (sat/vB).
func (e *TxEntry) DescendantFeeRate() float64 {
	if e.DescendantSize == 0 {
		return 0
	}
	return float64(e.DescendantFee) / float64(e.DescendantSize)
}

// orphanEntry represents an orphan transaction awaiting its parents.
type orphanEntry struct {
	tx         *wire.MsgTx
	txHash     wire.Hash256
	addedTime  time.Time
	missingOut []wire.OutPoint // Missing parent outpoints
}

// Mempool holds unconfirmed transactions.
type Mempool struct {
	mu          sync.RWMutex
	config      Config
	pool        map[wire.Hash256]*TxEntry     // txid -> TxEntry
	outpoints   map[wire.OutPoint]wire.Hash256 // spent outpoint -> spending txid
	orphans     map[wire.Hash256]*orphanEntry  // Orphan transactions (missing inputs)
	totalSize   int64                          // Total virtual size of all mempool txs
	utxoSet     consensus.UTXOView
	chainHeight int32
}

// New creates a new mempool.
func New(config Config, utxoSet consensus.UTXOView) *Mempool {
	// Apply defaults if not set
	if config.MaxSize == 0 {
		config.MaxSize = 300_000_000
	}
	if config.MinRelayFeeRate == 0 {
		config.MinRelayFeeRate = 1000
	}
	if config.MaxOrphanTxs == 0 {
		config.MaxOrphanTxs = 100
	}
	if config.ChainParams == nil {
		config.ChainParams = consensus.MainnetParams()
	}

	return &Mempool{
		config:    config,
		pool:      make(map[wire.Hash256]*TxEntry),
		outpoints: make(map[wire.OutPoint]wire.Hash256),
		orphans:   make(map[wire.Hash256]*orphanEntry),
		utxoSet:   utxoSet,
	}
}

// SetChainHeight updates the chain height (called when blocks are connected/disconnected).
func (mp *Mempool) SetChainHeight(height int32) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.chainHeight = height
}

// ChainHeight returns the current chain height.
func (mp *Mempool) ChainHeight() int32 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.chainHeight
}

// AddTransaction validates and adds a transaction to the mempool.
// Returns nil if accepted, error with reason if rejected.
func (mp *Mempool) AddTransaction(tx *wire.MsgTx) error {
	txHash := tx.TxHash()

	mp.mu.Lock()
	defer mp.mu.Unlock()

	// 1. Reject if already in mempool
	if _, ok := mp.pool[txHash]; ok {
		return fmt.Errorf("%w: %s", ErrAlreadyInMempool, txHash)
	}

	// 2. Basic sanity checks
	if err := consensus.CheckTransactionSanity(tx); err != nil {
		return fmt.Errorf("transaction sanity check failed: %w", err)
	}

	// 3. Reject coinbase transactions
	if consensus.IsCoinbaseTx(tx) {
		return ErrCoinbaseNotAllowed
	}

	// 4. Check transaction weight (max standard tx weight: 400,000 WU)
	weight := consensus.CalcTxWeight(tx)
	if weight > consensus.MaxStandardTxWeight {
		return fmt.Errorf("%w: weight %d exceeds maximum %d", ErrTxTooLarge, weight, consensus.MaxStandardTxWeight)
	}

	// 5. Calculate virtual size
	vsize := (weight + 3) / 4 // Round up

	// 6. Check for double spends and gather input values
	var totalInputValue int64
	var missingInputs []wire.OutPoint

	for _, in := range tx.TxIn {
		// Check mempool double-spend
		if existingTx, ok := mp.outpoints[in.PreviousOutPoint]; ok {
			return fmt.Errorf("%w: input %s:%d already spent by mempool tx %s",
				ErrDoubleSpend, in.PreviousOutPoint.Hash, in.PreviousOutPoint.Index, existingTx)
		}

		// Look up the UTXO (check mempool outputs first, then UTXO set)
		utxo := mp.lookupOutputLocked(in.PreviousOutPoint)
		if utxo == nil {
			missingInputs = append(missingInputs, in.PreviousOutPoint)
		} else {
			totalInputValue += utxo.Amount
		}
	}

	// If we have missing inputs, treat as orphan
	if len(missingInputs) > 0 {
		mp.addOrphanLocked(txHash, tx, missingInputs)
		return fmt.Errorf("%w: added as orphan with %d missing inputs", ErrMissingInputs, len(missingInputs))
	}

	// 7. Calculate fee
	var totalOutputValue int64
	for _, out := range tx.TxOut {
		totalOutputValue += out.Value
	}
	fee := totalInputValue - totalOutputValue
	if fee < 0 {
		return ErrNegativeFee
	}

	// 8. Check minimum fee rate
	feeRate := float64(fee) / float64(vsize) * 1000 // sat/kvB
	if int64(feeRate) < mp.config.MinRelayFeeRate {
		return fmt.Errorf("%w: %.1f sat/kvB below minimum %d sat/kvB",
			ErrInsufficientFee, feeRate, mp.config.MinRelayFeeRate)
	}

	// 9. Check dust outputs
	for i, out := range tx.TxOut {
		if mp.isDust(out) {
			return fmt.Errorf("%w: output %d value %d", ErrDustOutput, i, out.Value)
		}
	}

	// 10. Validate scripts
	flags := mp.getStandardScriptFlags()
	if err := mp.validateScriptsLocked(tx, flags); err != nil {
		return fmt.Errorf("%w: %v", ErrScriptValidation, err)
	}

	// 11. Create entry and add to mempool
	entry := &TxEntry{
		Tx:             tx,
		TxHash:         txHash,
		Fee:            fee,
		Size:           vsize,
		FeeRate:        float64(fee) / float64(vsize),
		Time:           time.Now(),
		Height:         mp.chainHeight,
		AncestorFee:    fee,
		AncestorSize:   vsize,
		DescendantFee:  fee,
		DescendantSize: vsize,
	}

	// Track dependencies (parent transactions in mempool)
	for _, in := range tx.TxIn {
		if parentEntry, ok := mp.pool[in.PreviousOutPoint.Hash]; ok {
			entry.Depends = append(entry.Depends, parentEntry.TxHash)
			parentEntry.SpentBy = append(parentEntry.SpentBy, txHash)
		}
	}

	// Update ancestor/descendant tracking
	mp.updateAncestorStateLocked(entry)
	mp.updateDescendantStateLocked(entry)

	// Add to pool
	mp.pool[txHash] = entry
	for _, in := range tx.TxIn {
		mp.outpoints[in.PreviousOutPoint] = txHash
	}
	mp.totalSize += vsize

	// 12. Evict if mempool too large
	mp.maybeEvictLocked()

	// 13. Check if this resolves any orphans
	mp.processOrphansLocked(txHash)

	return nil
}

// lookupOutputLocked looks up a UTXO from mempool or UTXO set.
// Must be called with mu held.
func (mp *Mempool) lookupOutputLocked(outpoint wire.OutPoint) *consensus.UTXOEntry {
	// First check if a mempool transaction creates this output
	if entry, ok := mp.pool[outpoint.Hash]; ok {
		if int(outpoint.Index) < len(entry.Tx.TxOut) {
			out := entry.Tx.TxOut[outpoint.Index]
			return &consensus.UTXOEntry{
				Amount:   out.Value,
				PkScript: out.PkScript,
				Height:   entry.Height,
			}
		}
	}
	// Fall back to the UTXO set
	if mp.utxoSet != nil {
		return mp.utxoSet.GetUTXO(outpoint)
	}
	return nil
}

// GetUTXO implements consensus.UTXOView, allowing mempool to be used as a UTXO source.
func (mp *Mempool) GetUTXO(outpoint wire.OutPoint) *consensus.UTXOEntry {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.lookupOutputLocked(outpoint)
}

// isDust checks if an output is dust (uneconomical to spend).
func (mp *Mempool) isDust(txOut *wire.TxOut) bool {
	// Dust is defined as an output whose spending cost exceeds its value.
	// Spending cost depends on the script type.
	spendingSize := int64(148) // Conservative default (P2PKH spending size)

	if consensus.IsP2WPKH(txOut.PkScript) {
		spendingSize = 68 // Witness v0 keyhash spending size
	} else if consensus.IsP2WSH(txOut.PkScript) {
		spendingSize = 68 // Conservative estimate
	} else if consensus.IsP2TR(txOut.PkScript) {
		spendingSize = 58 // Taproot key path spending size
	}

	dustThreshold := spendingSize * mp.config.MinRelayFeeRate / 1000
	return txOut.Value < dustThreshold
}

// getStandardScriptFlags returns script validation flags for mempool validation.
func (mp *Mempool) getStandardScriptFlags() script.ScriptFlags {
	return consensus.GetBlockScriptFlags(mp.chainHeight, mp.config.ChainParams)
}

// validateScriptsLocked validates transaction scripts.
// Must be called with mu held (at least for reading).
func (mp *Mempool) validateScriptsLocked(tx *wire.MsgTx, flags script.ScriptFlags) error {
	// Build prevOuts slice for the transaction
	prevOuts := make([]*wire.TxOut, len(tx.TxIn))
	for i, in := range tx.TxIn {
		utxo := mp.lookupOutputLocked(in.PreviousOutPoint)
		if utxo == nil {
			return consensus.ErrMissingInput
		}
		prevOuts[i] = &wire.TxOut{
			Value:    utxo.Amount,
			PkScript: utxo.PkScript,
		}
	}

	// Validate each input
	for i, in := range tx.TxIn {
		utxo := mp.lookupOutputLocked(in.PreviousOutPoint)
		if utxo == nil {
			return consensus.ErrMissingInput
		}

		err := script.VerifyScript(
			in.SignatureScript,
			utxo.PkScript,
			tx,
			i,
			flags,
			utxo.Amount,
			prevOuts,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// updateAncestorStateLocked updates ancestor fee/size for a new entry.
// Must be called with mu held.
func (mp *Mempool) updateAncestorStateLocked(entry *TxEntry) {
	// Collect all ancestors
	visited := make(map[wire.Hash256]bool)
	ancestors := mp.collectAncestorsLocked(entry.TxHash, visited)

	for _, ancestorHash := range ancestors {
		if ancestor, ok := mp.pool[ancestorHash]; ok {
			entry.AncestorFee += ancestor.Fee
			entry.AncestorSize += ancestor.Size
		}
	}
}

// updateDescendantStateLocked updates descendant fees for ancestors when adding a new tx.
// Must be called with mu held.
func (mp *Mempool) updateDescendantStateLocked(entry *TxEntry) {
	// Update all ancestors' descendant counts
	visited := make(map[wire.Hash256]bool)
	ancestors := mp.collectAncestorsLocked(entry.TxHash, visited)

	for _, ancestorHash := range ancestors {
		if ancestor, ok := mp.pool[ancestorHash]; ok {
			ancestor.DescendantFee += entry.Fee
			ancestor.DescendantSize += entry.Size
		}
	}
}

// collectAncestorsLocked collects all ancestor transaction hashes.
// Must be called with mu held.
func (mp *Mempool) collectAncestorsLocked(txHash wire.Hash256, visited map[wire.Hash256]bool) []wire.Hash256 {
	if visited[txHash] {
		return nil
	}
	visited[txHash] = true

	entry, ok := mp.pool[txHash]
	if !ok {
		return nil
	}

	var result []wire.Hash256
	for _, parentHash := range entry.Depends {
		result = append(result, parentHash)
		result = append(result, mp.collectAncestorsLocked(parentHash, visited)...)
	}
	return result
}

// collectDescendantsLocked collects all descendant transaction hashes.
// Must be called with mu held.
func (mp *Mempool) collectDescendantsLocked(txHash wire.Hash256, visited map[wire.Hash256]bool) []wire.Hash256 {
	if visited[txHash] {
		return nil
	}
	visited[txHash] = true

	entry, ok := mp.pool[txHash]
	if !ok {
		return nil
	}

	var result []wire.Hash256
	for _, childHash := range entry.SpentBy {
		result = append(result, childHash)
		result = append(result, mp.collectDescendantsLocked(childHash, visited)...)
	}
	return result
}

// RemoveTransaction removes a transaction and all its descendants from the mempool.
func (mp *Mempool) RemoveTransaction(txHash wire.Hash256) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.removeWithDescendantsLocked(txHash)
}

// removeWithDescendantsLocked removes a transaction and all descendants.
// Must be called with mu held.
func (mp *Mempool) removeWithDescendantsLocked(txHash wire.Hash256) {
	visited := make(map[wire.Hash256]bool)
	descendants := mp.collectDescendantsLocked(txHash, visited)

	// Remove descendants first (children before parents for proper cleanup)
	// Reverse order to remove children first
	for i := len(descendants) - 1; i >= 0; i-- {
		mp.removeSingleTxLocked(descendants[i])
	}

	// Remove the transaction itself
	mp.removeSingleTxLocked(txHash)
}

// removeSingleTxLocked removes a single transaction without touching descendants.
// Must be called with mu held.
func (mp *Mempool) removeSingleTxLocked(txHash wire.Hash256) {
	entry, ok := mp.pool[txHash]
	if !ok {
		return
	}

	// Remove from outpoints map
	for _, in := range entry.Tx.TxIn {
		delete(mp.outpoints, in.PreviousOutPoint)
	}

	// Update parent's SpentBy lists
	for _, parentHash := range entry.Depends {
		if parent, ok := mp.pool[parentHash]; ok {
			parent.SpentBy = removeHash(parent.SpentBy, txHash)
			// Update parent's descendant tracking
			parent.DescendantFee -= entry.Fee
			parent.DescendantSize -= entry.Size
		}
	}

	// Update total size
	mp.totalSize -= entry.Size

	// Remove from pool
	delete(mp.pool, txHash)
}

// removeHash removes a hash from a slice.
func removeHash(slice []wire.Hash256, hash wire.Hash256) []wire.Hash256 {
	result := make([]wire.Hash256, 0, len(slice))
	for _, h := range slice {
		if h != hash {
			result = append(result, h)
		}
	}
	return result
}

// GetTransaction returns a transaction from the mempool, or nil if not found.
func (mp *Mempool) GetTransaction(txHash wire.Hash256) *wire.MsgTx {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if entry, ok := mp.pool[txHash]; ok {
		return entry.Tx
	}
	return nil
}

// GetEntry returns a transaction entry from the mempool, or nil if not found.
func (mp *Mempool) GetEntry(txHash wire.Hash256) *TxEntry {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.pool[txHash]
}

// HasTransaction returns true if the transaction is in the mempool.
func (mp *Mempool) HasTransaction(txHash wire.Hash256) bool {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	_, ok := mp.pool[txHash]
	return ok
}

// Count returns the number of transactions in the mempool.
func (mp *Mempool) Count() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return len(mp.pool)
}

// TotalSize returns the total virtual size of mempool transactions in bytes.
func (mp *Mempool) TotalSize() int64 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.totalSize
}

// GetAllTxHashes returns all transaction hashes in the mempool.
func (mp *Mempool) GetAllTxHashes() []wire.Hash256 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	hashes := make([]wire.Hash256, 0, len(mp.pool))
	for hash := range mp.pool {
		hashes = append(hashes, hash)
	}
	return hashes
}

// GetSortedByFeeRate returns transactions sorted by fee rate (highest first).
// Used by block template construction.
func (mp *Mempool) GetSortedByFeeRate() []*TxEntry {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	entries := make([]*TxEntry, 0, len(mp.pool))
	for _, entry := range mp.pool {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].FeeRate > entries[j].FeeRate
	})

	return entries
}

// GetSortedByAncestorFeeRate returns transactions sorted by ancestor fee rate (highest first).
// This is the correct metric for CPFP-aware mining.
func (mp *Mempool) GetSortedByAncestorFeeRate() []*TxEntry {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	entries := make([]*TxEntry, 0, len(mp.pool))
	for _, entry := range mp.pool {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].AncestorFeeRate() > entries[j].AncestorFeeRate()
	})

	return entries
}

// CheckSpend checks if an outpoint is already spent by a mempool transaction.
// Returns the spending transaction hash, or nil if not spent.
func (mp *Mempool) CheckSpend(outpoint wire.OutPoint) *wire.Hash256 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if txHash, ok := mp.outpoints[outpoint]; ok {
		return &txHash
	}
	return nil
}

// maybeEvictLocked evicts transactions if the mempool is too large.
// Must be called with mu held.
func (mp *Mempool) maybeEvictLocked() {
	for mp.totalSize > mp.config.MaxSize && len(mp.pool) > 0 {
		// Find the entry with the lowest descendant fee rate
		var worst *TxEntry
		worstRate := math.MaxFloat64

		for _, entry := range mp.pool {
			rate := entry.DescendantFeeRate()
			if rate < worstRate {
				worstRate = rate
				worst = entry
			}
		}

		if worst == nil {
			break
		}

		mp.removeWithDescendantsLocked(worst.TxHash)
	}
}

// Orphan pool management

// addOrphanLocked adds a transaction to the orphan pool.
// Must be called with mu held.
func (mp *Mempool) addOrphanLocked(txHash wire.Hash256, tx *wire.MsgTx, missingOuts []wire.OutPoint) {
	// Check if already in orphan pool
	if _, ok := mp.orphans[txHash]; ok {
		return
	}

	// Evict random orphan if pool is full
	if len(mp.orphans) >= mp.config.MaxOrphanTxs {
		mp.evictRandomOrphanLocked()
	}

	mp.orphans[txHash] = &orphanEntry{
		tx:         tx,
		txHash:     txHash,
		addedTime:  time.Now(),
		missingOut: missingOuts,
	}
}

// evictRandomOrphanLocked removes a random orphan from the pool.
// Must be called with mu held.
func (mp *Mempool) evictRandomOrphanLocked() {
	if len(mp.orphans) == 0 {
		return
	}

	// First try to evict expired orphans (> 20 minutes old)
	expiry := time.Now().Add(-20 * time.Minute)
	for hash, orphan := range mp.orphans {
		if orphan.addedTime.Before(expiry) {
			delete(mp.orphans, hash)
			return
		}
	}

	// No expired orphans, pick a random one
	idx := rand.Intn(len(mp.orphans))
	i := 0
	for hash := range mp.orphans {
		if i == idx {
			delete(mp.orphans, hash)
			return
		}
		i++
	}
}

// processOrphansLocked checks if any orphans can now be promoted to the mempool.
// Must be called with mu held.
func (mp *Mempool) processOrphansLocked(newTxHash wire.Hash256) {
	entry, ok := mp.pool[newTxHash]
	if !ok {
		return
	}

	// Find orphans that depend on outputs of the new transaction
	var toProcess []*orphanEntry
	for _, orphan := range mp.orphans {
		for i, missing := range orphan.missingOut {
			if missing.Hash == newTxHash && int(missing.Index) < len(entry.Tx.TxOut) {
				// This missing output is now available
				orphan.missingOut = append(orphan.missingOut[:i], orphan.missingOut[i+1:]...)
				break
			}
		}
		if len(orphan.missingOut) == 0 {
			toProcess = append(toProcess, orphan)
		}
	}

	// Promote orphans that have all inputs now
	for _, orphan := range toProcess {
		delete(mp.orphans, orphan.txHash)

		// Unlock and relock to avoid deadlock during recursive AddTransaction
		mp.mu.Unlock()
		_ = mp.AddTransaction(orphan.tx) // Ignore errors, orphan might still be invalid
		mp.mu.Lock()
	}
}

// ExpireOrphans removes orphans older than 20 minutes.
func (mp *Mempool) ExpireOrphans() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	expiry := time.Now().Add(-20 * time.Minute)
	for hash, orphan := range mp.orphans {
		if orphan.addedTime.Before(expiry) {
			delete(mp.orphans, hash)
		}
	}
}

// OrphanCount returns the number of orphan transactions.
func (mp *Mempool) OrphanCount() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return len(mp.orphans)
}

// Block connection/disconnection

// BlockConnected removes transactions that were included in a new block.
func (mp *Mempool) BlockConnected(block *wire.MsgBlock) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	// Increment chain height
	mp.chainHeight++

	// Remove confirmed transactions
	for _, tx := range block.Transactions {
		txHash := tx.TxHash()
		mp.removeSingleTxLocked(txHash)

		// Also remove conflicting transactions (double spends)
		for _, in := range tx.TxIn {
			if spendingTx, ok := mp.outpoints[in.PreviousOutPoint]; ok {
				mp.removeWithDescendantsLocked(spendingTx)
			}
		}
	}
}

// BlockDisconnected re-adds transactions from a disconnected block
// (if they are still valid).
func (mp *Mempool) BlockDisconnected(block *wire.MsgBlock) {
	mp.mu.Lock()
	mp.chainHeight--
	mp.mu.Unlock()

	// Re-add transactions from the disconnected block (skip coinbase)
	for i, tx := range block.Transactions {
		if i == 0 {
			continue // Skip coinbase
		}
		_ = mp.AddTransaction(tx) // Ignore errors
	}
}

// Fee estimation

// EstimateFee returns the estimated fee rate (sat/vB) for confirmation within targetBlocks.
// Uses a simple heuristic based on current mempool state.
func (mp *Mempool) EstimateFee(targetBlocks int) float64 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if len(mp.pool) == 0 {
		// Empty mempool, return minimum fee rate
		return float64(mp.config.MinRelayFeeRate) / 1000
	}

	// Sort by fee rate
	entries := make([]*TxEntry, 0, len(mp.pool))
	for _, entry := range mp.pool {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].FeeRate > entries[j].FeeRate
	})

	// Estimate how many transactions can fit in targetBlocks blocks
	// Assume ~4MB of transactions per block (4,000,000 WU / 4 = 1,000,000 vB)
	targetVSize := int64(targetBlocks) * 1_000_000

	var cumSize int64
	for _, entry := range entries {
		cumSize += entry.Size
		if cumSize >= targetVSize {
			return entry.FeeRate
		}
	}

	// All mempool fits, return minimum fee rate
	return float64(mp.config.MinRelayFeeRate) / 1000
}

// Utility functions

// CalcMinFee calculates the minimum fee for a transaction of given vsize.
func (mp *Mempool) CalcMinFee(vsize int64) int64 {
	return (vsize * mp.config.MinRelayFeeRate + 999) / 1000 // Round up
}

// GetRawMempool returns a map of txid -> fee rate for all mempool transactions.
func (mp *Mempool) GetRawMempool() map[wire.Hash256]float64 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	result := make(map[wire.Hash256]float64, len(mp.pool))
	for hash, entry := range mp.pool {
		result[hash] = entry.FeeRate
	}
	return result
}

// Clear removes all transactions from the mempool.
func (mp *Mempool) Clear() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.pool = make(map[wire.Hash256]*TxEntry)
	mp.outpoints = make(map[wire.OutPoint]wire.Hash256)
	mp.orphans = make(map[wire.Hash256]*orphanEntry)
	mp.totalSize = 0
}

// Ensure Mempool implements consensus.UTXOView
var _ consensus.UTXOView = (*Mempool)(nil)

// TxSerializeSize returns the serialized size of a transaction without witness.
func txSerializeSize(tx *wire.MsgTx) int64 {
	var buf bytes.Buffer
	_ = tx.SerializeNoWitness(&buf)
	return int64(buf.Len())
}
