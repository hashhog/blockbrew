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
	ErrWitnessStuffing    = errors.New("witness stuffing: P2A input must have empty witness")
	ErrMempoolFull        = errors.New("mempool is full")
	ErrOrphanPoolFull     = errors.New("orphan pool is full")
	ErrRBFNotSignaled     = errors.New("conflicting transaction does not signal RBF")
	ErrRBFInsufficientFee = errors.New("replacement fee too low")
	ErrRBFTooManyConflicts = errors.New("replacement would evict too many transactions")

	// BIP-68 sequence-lock failure (mempool accept).
	ErrSequenceLockNotMet = errors.New("non-final transaction (BIP-68 sequence locks not met)")

	// Ancestor/descendant chain limits (Core DEFAULT_ANCESTOR_LIMIT/DEFAULT_DESCENDANT_LIMIT).
	ErrTooManyAncestors   = errors.New("too many unconfirmed ancestors")
	ErrTooManyDescendants = errors.New("too many descendants for an unconfirmed parent")

	// Package validation errors.
	ErrPackageEmpty            = errors.New("package is empty")
	ErrPackageTooManyTxs       = errors.New("package exceeds maximum transaction count")
	ErrPackageTooLarge         = errors.New("package exceeds maximum weight")
	ErrPackageDuplicateTx      = errors.New("package contains duplicate transactions")
	ErrPackageNotSorted        = errors.New("package is not topologically sorted")
	ErrPackageConflict         = errors.New("package contains conflicting transactions")
	ErrPackageNotChildWithParents = errors.New("package topology must be child-with-unconfirmed-parents")
	ErrPackageInsufficientFee  = errors.New("package feerate below minimum relay fee")
)

// RBF constants (BIP125).
const (
	// MaxRBFReplacedTxs is the maximum number of transactions that can be
	// replaced by a single RBF replacement (including descendants).
	MaxRBFReplacedTxs = 100

	// SequenceFinal is the maximum sequence number (disables RBF signaling).
	SequenceFinal = 0xFFFFFFFF
)

// Package relay constants (BIP331 / Bitcoin Core policy).
const (
	// MaxPackageCount is the maximum number of transactions in a package.
	MaxPackageCount = 25

	// MaxPackageWeight is the maximum total weight of a package in weight units.
	// This matches the default ancestor size limit (~101 kvB).
	MaxPackageWeight = 404_000
)

// Ancestor/descendant chain limits matching Bitcoin Core
// (src/policy/policy.h DEFAULT_ANCESTOR_LIMIT / DEFAULT_DESCENDANT_LIMIT).
const (
	// DefaultAncestorLimit is the maximum number of in-mempool ancestors a tx
	// may have (including itself).
	DefaultAncestorLimit = 25

	// DefaultDescendantLimit is the maximum number of in-mempool descendants
	// a tx may have (including itself).
	DefaultDescendantLimit = 25
)

// ChainState is the read-only view of the active chain that the mempool needs
// for context-sensitive checks (BIP-68 sequence-locks, lock-time evaluation).
//
// All methods must be safe for concurrent callers. The implementation in
// production is the chain manager; tests provide fakes.
type ChainState interface {
	// TipHeight returns the current best chain tip height.
	TipHeight() int32

	// TipMTP returns the median time past at the chain tip (the timestamp used
	// to evaluate BIP-68 time-based sequence locks for transactions that would
	// be included in the next block).
	TipMTP() int64

	// MTPAtHeight returns the median time past of the block at the given
	// height in the active chain. Returns 0 when the height is unknown
	// (caller treats this as "no time-based lock satisfied").
	MTPAtHeight(height int32) int64
}

// Config configures the mempool.
type Config struct {
	MaxSize             int64 // Maximum mempool size in bytes (default: 300 MB)
	MinRelayFeeRate     int64 // Minimum fee rate in sat/kvB (default: 1000)
	IncrementalRelayFee int64 // Incremental relay fee in sat/kvB (default: 1000)
	MaxOrphanTxs        int   // Maximum orphan transactions (default: 100)
	ChainParams         *consensus.ChainParams

	// ChainState is optional. When provided, mempool accept enforces BIP-68
	// sequence-locks against the chain tip's MTP. When nil (legacy/test
	// callers), the BIP-68 check is skipped.
	ChainState ChainState
}

// DefaultConfig returns a mempool config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxSize:             300_000_000, // 300 MB
		MinRelayFeeRate:     1000,        // 1 sat/vB
		IncrementalRelayFee: 1000,        // 1 sat/vB
		MaxOrphanTxs:        100,
		ChainParams:         consensus.MainnetParams(),
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

// PackageResult holds the result of a package acceptance attempt.
type PackageResult struct {
	// PackageFeerate is the aggregate feerate of the package (sat/vB).
	PackageFeerate float64

	// PackageError is a package-level error, if any.
	PackageError error

	// TxResults contains per-transaction results.
	TxResults map[wire.Hash256]*TxAcceptResult

	// ReplacedTxs lists txids that were replaced via package RBF.
	ReplacedTxs []wire.Hash256
}

// TxAcceptResult holds the result for a single transaction in a package.
type TxAcceptResult struct {
	// TxID is the transaction ID.
	TxID wire.Hash256

	// WTxID is the witness transaction ID.
	WTxID wire.Hash256

	// Accepted indicates whether the transaction was accepted.
	Accepted bool

	// AlreadyInMempool indicates the transaction was already in the mempool.
	AlreadyInMempool bool

	// Fee is the transaction fee in satoshis (if accepted).
	Fee int64

	// VSize is the virtual size in vbytes (if accepted).
	VSize int64

	// Error is the rejection reason (if not accepted).
	Error error

	// EffectiveFeerate is the feerate used for this transaction (sat/vB).
	// For package transactions, this is the package aggregate feerate.
	EffectiveFeerate float64

	// EffectiveIncludes lists wtxids included in the effective feerate calculation.
	EffectiveIncludes []wire.Hash256
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
	clusters    *ClusterManager               // Cluster-based mempool structure
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
	if config.IncrementalRelayFee == 0 {
		config.IncrementalRelayFee = 1000
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
		clusters:  NewClusterManager(),
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

// AcceptToMemoryPool validates and adds a transaction to the mempool.
// This is the canonical entry point matching Bitcoin Core's naming convention.
// Performs all policy checks including BIP125 RBF, fee-rate validation,
// script verification, and cluster mempool limits.
// Returns nil if accepted, error with reason if rejected.
func (mp *Mempool) AcceptToMemoryPool(tx *wire.MsgTx) error {
	return mp.AddTransaction(tx)
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

	// 6. Check for double spends (with RBF support) and gather input values
	var totalInputValue int64
	var missingInputs []wire.OutPoint
	var conflictingTxs map[wire.Hash256]bool // Transactions to replace via RBF

	for _, in := range tx.TxIn {
		// Check mempool double-spend
		if existingTxHash, ok := mp.outpoints[in.PreviousOutPoint]; ok {
			if conflictingTxs == nil {
				conflictingTxs = make(map[wire.Hash256]bool)
			}
			conflictingTxs[existingTxHash] = true
		}

		// Look up the UTXO (check mempool outputs first, then UTXO set)
		utxo := mp.lookupOutputLocked(in.PreviousOutPoint)
		if utxo == nil {
			missingInputs = append(missingInputs, in.PreviousOutPoint)
		} else {
			totalInputValue += utxo.Amount
		}
	}

	// If there are conflicting transactions, check RBF rules
	if len(conflictingTxs) > 0 && len(missingInputs) == 0 {
		rbfErr := mp.checkRBFLocked(tx, conflictingTxs, totalInputValue)
		if rbfErr != nil {
			return rbfErr
		}
	} else if len(conflictingTxs) > 0 {
		// Can't do RBF with missing inputs
		for txHash := range conflictingTxs {
			return fmt.Errorf("%w: input already spent by mempool tx %s",
				ErrDoubleSpend, txHash)
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

	// 8. Check minimum fee rate (dynamic, accounts for mempool fullness)
	feeRate := float64(fee) / float64(vsize) * 1000 // sat/kvB
	minFeeRate := mp.getMinFeeRateLocked()
	if int64(feeRate) < minFeeRate {
		return fmt.Errorf("%w: %.1f sat/kvB below minimum %d sat/kvB",
			ErrInsufficientFee, feeRate, minFeeRate)
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

	// 10b. BIP-68 sequence-lock check (Bitcoin Core
	//      validation.cpp::CheckSequenceLocksAtTip in PreChecks).
	//      Locks are evaluated against the *next* block (tip height + 1)
	//      and the chain tip's MTP. Skipped when no ChainState is wired.
	if err := mp.checkSequenceLocksLocked(tx); err != nil {
		return err
	}

	// 10c. Ancestor/descendant count limits (Core DEFAULT_ANCESTOR_LIMIT /
	//      DEFAULT_DESCENDANT_LIMIT, both = 25). Reject before mutating
	//      cluster/pool state so a rejection is side-effect free.
	if err := mp.checkChainLimitsLocked(tx); err != nil {
		return err
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

	// Execute RBF replacements if any
	if len(conflictingTxs) > 0 {
		for conflictHash := range conflictingTxs {
			mp.removeWithDescendantsLocked(conflictHash)
		}
	}

	// Add to pool
	mp.pool[txHash] = entry
	for _, in := range tx.TxIn {
		mp.outpoints[in.PreviousOutPoint] = txHash
	}
	mp.totalSize += vsize

	// Add to cluster manager
	parentTxids := entry.Depends
	_, clusterErr := mp.clusters.AddTransaction(txHash, fee, int32(vsize), parentTxids)
	if clusterErr != nil {
		// Cluster too large - remove the transaction we just added
		mp.removeSingleTxLocked(txHash)
		return clusterErr
	}

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

// AnchorDust is the maximum value allowed for P2A outputs (in satoshis).
// P2A outputs are exempt from the normal dust threshold but capped at this value.
const AnchorDust int64 = 240

// isDust checks if an output is dust (uneconomical to spend).
func (mp *Mempool) isDust(txOut *wire.TxOut) bool {
	// P2A (Pay-to-Anchor) outputs are exempt from normal dust rules.
	// They are meant for fee bumping via CPFP and can have value 0.
	// However, for standardness we cap them at AnchorDust satoshis.
	if consensus.IsPayToAnchor(txOut.PkScript) {
		return txOut.Value > AnchorDust // P2A is only standard if value <= AnchorDust
	}

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
	// Mempool uses current chain tip flags — no exception hash needed
	// (exceptions are only for historical blocks during IBD).
	var zeroHash wire.Hash256
	return consensus.GetBlockScriptFlags(mp.chainHeight, mp.config.ChainParams, zeroHash)
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

		// Check for P2A witness stuffing (policy check).
		// P2A outputs are anyone-can-spend and require an empty witness.
		// Having witness data attached to a P2A spend is non-standard.
		if consensus.IsPayToAnchor(utxo.PkScript) && len(in.Witness) > 0 {
			return ErrWitnessStuffing
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

// checkSequenceLocksLocked enforces BIP-68 (sequence locks) at mempool accept.
//
// Mirrors src/validation.cpp::CheckSequenceLocksAtTip: the lock is evaluated
// against the *next* block (tip height + 1) and the chain tip's MTP — i.e.,
// the values the transaction would see if mined into the next block. The
// per-input height is the height of the block that confirmed the spent UTXO
// (mempool parents are conservatively treated as confirming at tip+1, which
// matches Core's "use the next block height for not-yet-confirmed inputs").
//
// Skipped when no ChainState is wired (legacy and test callers).
// Must be called with mu held.
func (mp *Mempool) checkSequenceLocksLocked(tx *wire.MsgTx) error {
	if mp.config.ChainState == nil {
		return nil
	}
	// BIP-68 only applies to v2+ transactions; spare the work otherwise.
	if tx.Version < 2 {
		return nil
	}
	cs := mp.config.ChainState
	tipHeight := cs.TipHeight()
	if mp.config.ChainParams != nil && tipHeight < mp.config.ChainParams.CSVHeight {
		// CSV not yet active.
		return nil
	}
	nextHeight := tipHeight + 1

	prevHeights := make([]int32, len(tx.TxIn))
	for i, in := range tx.TxIn {
		// Mempool parent: would be in the same block as this tx, so use
		// nextHeight (Core uses tip+1 for unconfirmed parents).
		if _, ok := mp.pool[in.PreviousOutPoint.Hash]; ok {
			prevHeights[i] = nextHeight
			continue
		}
		utxo := mp.lookupOutputLocked(in.PreviousOutPoint)
		if utxo == nil {
			// Caller already checked missing inputs; treat as "not yet
			// confirmed" so we don't crash.
			prevHeights[i] = nextHeight
			continue
		}
		prevHeights[i] = utxo.Height
	}

	getMTP := func(h int32) int64 {
		if h < 0 {
			return 0
		}
		return cs.MTPAtHeight(h)
	}
	lock := consensus.CalculateSequenceLocks(tx, prevHeights, getMTP)
	if !consensus.EvaluateSequenceLocks(lock, nextHeight, cs.TipMTP()) {
		return ErrSequenceLockNotMet
	}
	return nil
}

// checkChainLimitsLocked enforces ancestor/descendant count limits when
// adding a new transaction. Mirrors Bitcoin Core's CalculateMemPoolAncestors
// failure path (DEFAULT_ANCESTOR_LIMIT / DEFAULT_DESCENDANT_LIMIT, both 25).
//
// Counts include the transaction itself (Core's
// "ancestor count = 1 + parent count" / "descendant count = 1 + child count"
// semantics). Must be called with mu held.
func (mp *Mempool) checkChainLimitsLocked(tx *wire.MsgTx) error {
	// Ancestor limit: candidate + union of ancestor-sets of its mempool parents.
	// Build the union by visiting each parent, then expanding via Depends.
	ancestorSet := make(map[wire.Hash256]bool)
	var addAncestors func(hash wire.Hash256)
	addAncestors = func(hash wire.Hash256) {
		if ancestorSet[hash] {
			return
		}
		entry, ok := mp.pool[hash]
		if !ok {
			return
		}
		ancestorSet[hash] = true
		for _, parent := range entry.Depends {
			addAncestors(parent)
		}
	}
	for _, in := range tx.TxIn {
		addAncestors(in.PreviousOutPoint.Hash)
	}
	// |ancestorSet| is the number of distinct in-mempool ancestors. +1 for self.
	if len(ancestorSet)+1 > DefaultAncestorLimit {
		return fmt.Errorf("%w: %d > %d", ErrTooManyAncestors,
			len(ancestorSet)+1, DefaultAncestorLimit)
	}

	// Descendant limit: for each in-mempool ancestor of the candidate, adding
	// the candidate would push that ancestor's descendant-set by one. Core
	// counts descendants-including-self; the candidate is a new descendant.
	for ancHash := range ancestorSet {
		descVisited := make(map[wire.Hash256]bool)
		descs := mp.collectDescendantsLocked(ancHash, descVisited)
		// descs excludes ancHash itself. After adding candidate, the count
		// including self becomes len(descs) + 1 (self) + 1 (new candidate).
		if len(descs)+2 > DefaultDescendantLimit {
			return fmt.Errorf("%w: ancestor %s would have %d descendants > %d",
				ErrTooManyDescendants, ancHash, len(descs)+2,
				DefaultDescendantLimit)
		}
	}
	return nil
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

	// Remove from cluster manager
	mp.clusters.RemoveTransaction(txHash)

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

// GetAncestors returns the ancestor transaction hashes for the given transaction.
// The returned list does not include txHash itself.
func (mp *Mempool) GetAncestors(txHash wire.Hash256) []wire.Hash256 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	if _, ok := mp.pool[txHash]; !ok {
		return nil
	}
	visited := make(map[wire.Hash256]bool)
	return mp.collectAncestorsLocked(txHash, visited)
}

// GetDescendants returns the descendant transaction hashes for the given transaction.
// The returned list does not include txHash itself.
func (mp *Mempool) GetDescendants(txHash wire.Hash256) []wire.Hash256 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	if _, ok := mp.pool[txHash]; !ok {
		return nil
	}
	visited := make(map[wire.Hash256]bool)
	return mp.collectDescendantsLocked(txHash, visited)
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

// GetAllTransactions returns all transactions in the mempool.
// Used by compact block reconstruction.
func (mp *Mempool) GetAllTransactions() []*wire.MsgTx {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	txs := make([]*wire.MsgTx, 0, len(mp.pool))
	for _, entry := range mp.pool {
		txs = append(txs, entry.Tx)
	}
	return txs
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
// Deprecated: Use GetChunksForMining for cluster-based optimal ordering.
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

// GetChunksForMining returns all transaction chunks sorted by feerate (highest first).
// This provides optimal ordering for block template construction using cluster mempool.
// Chunks respect transaction dependencies - including a chunk means including all its transactions.
func (mp *Mempool) GetChunksForMining() []MiningChunk {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.clusters.GetChunksForMining()
}

// GetTransactionsForMining returns transactions in optimal mining order.
// Uses cluster linearization for globally optimal transaction ordering.
func (mp *Mempool) GetTransactionsForMining() []*TxEntry {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	chunks := mp.clusters.GetChunksForMining()
	var result []*TxEntry

	for _, mchunk := range chunks {
		// Get txids for this chunk from the cluster
		idxToHash := make(map[int]wire.Hash256)
		for txHash, idx := range mchunk.Cluster.Transactions {
			idxToHash[idx] = txHash
		}

		for _, idx := range mchunk.Chunk.Txs {
			if txHash, ok := idxToHash[idx]; ok {
				if entry, ok := mp.pool[txHash]; ok {
					result = append(result, entry)
				}
			}
		}
	}

	return result
}

// GetCluster returns the cluster containing the specified transaction.
func (mp *Mempool) GetCluster(txHash wire.Hash256) *Cluster {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.clusters.GetCluster(txHash)
}

// GetAllClusters returns all transaction clusters in the mempool.
func (mp *Mempool) GetAllClusters() []*Cluster {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.clusters.GetAllClusters()
}

// CountDistinctClusters counts how many distinct clusters contain the given transactions.
// Used for RBF validation with cluster mempool.
func (mp *Mempool) CountDistinctClusters(txids []wire.Hash256) int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.clusters.CountDistinctClusters(txids)
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
// Uses cluster-based eviction: removes the lowest-feerate chunk from the worst cluster.
// Must be called with mu held.
func (mp *Mempool) maybeEvictLocked() {
	for mp.totalSize > mp.config.MaxSize && len(mp.pool) > 0 {
		// Use cluster-based eviction: find the worst chunk across all clusters
		worstCluster, worstChunk := mp.clusters.GetWorstChunkForEviction()

		if worstCluster == nil || worstChunk == nil {
			// Fallback to old behavior if no clusters
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
			continue
		}

		// Build reverse map from index to txHash for this cluster
		idxToHash := make(map[int]wire.Hash256)
		for txHash, idx := range worstCluster.Transactions {
			idxToHash[idx] = txHash
		}

		// Remove all transactions in the worst chunk
		for _, idx := range worstChunk.Txs {
			if txHash, ok := idxToHash[idx]; ok {
				mp.removeWithDescendantsLocked(txHash)
			}
		}
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

// GetMinFeeRate returns the current dynamic minimum fee rate in sat/kvB.
// This accounts for mempool fullness - when the mempool is full, the minimum
// fee rate increases to the lowest-feerate transaction plus the incremental relay fee.
// This value should be broadcast to peers via feefilter (BIP133).
func (mp *Mempool) GetMinFeeRate() int64 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.getMinFeeRateLocked()
}

// getMinFeeRateLocked returns the minimum fee rate (must hold lock).
func (mp *Mempool) getMinFeeRateLocked() int64 {
	// Start with the configured minimum
	minRate := mp.config.MinRelayFeeRate

	// If the mempool is at capacity, we need a higher fee rate
	if mp.totalSize >= mp.config.MaxSize {
		// Find the lowest fee rate in the mempool
		lowestRate := int64(math.MaxInt64)
		for _, entry := range mp.pool {
			// Convert sat/vB to sat/kvB for comparison
			feeRateKvB := int64(entry.FeeRate * 1000)
			if feeRateKvB < lowestRate {
				lowestRate = feeRateKvB
			}
		}

		if lowestRate < math.MaxInt64 {
			// Require incremental relay fee above the lowest rate
			requiredRate := lowestRate + mp.config.IncrementalRelayFee
			if requiredRate > minRate {
				minRate = requiredRate
			}
		}
	}

	return minRate
}

// GetMinFee returns the minimum fee required for a transaction of given vsize.
// This uses the dynamic minimum fee rate (accounting for mempool fullness).
func (mp *Mempool) GetMinFee(vsize int64) int64 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	minRate := mp.getMinFeeRateLocked()
	// Convert from sat/kvB to satoshis for this transaction size
	return (minRate * vsize + 999) / 1000 // Round up
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
	mp.clusters.Clear()
}

// checkRBFLocked validates whether a replacement transaction satisfies BIP125 rules.
// Must be called with mu held.
func (mp *Mempool) checkRBFLocked(newTx *wire.MsgTx, conflicting map[wire.Hash256]bool, totalInputValue int64) error {
	// BIP125 Rule 1: All conflicting transactions must signal replaceability.
	// A transaction signals RBF if any of its inputs have nSequence < 0xFFFFFFFF.
	for txHash := range conflicting {
		entry, ok := mp.pool[txHash]
		if !ok {
			continue
		}
		if !signalsRBF(entry.Tx) {
			return fmt.Errorf("%w: tx %s does not signal RBF", ErrRBFNotSignaled, txHash)
		}
	}

	// BIP125 Rule 2: The replacement must not contain any new unconfirmed inputs
	// that weren't already in the original transactions. (Relaxed in practice.)

	// BIP125 Rule 3: The replacement must pay an absolute fee higher than
	// the total fees of all conflicting transactions.
	var totalConflictingFee int64
	var totalConflictingSize int64
	var totalEvicted int

	for txHash := range conflicting {
		entry, ok := mp.pool[txHash]
		if !ok {
			continue
		}
		totalConflictingFee += entry.Fee
		totalConflictingSize += entry.Size
		totalEvicted++

		// Include descendants
		visited := make(map[wire.Hash256]bool)
		descendants := mp.collectDescendantsLocked(txHash, visited)
		for _, descHash := range descendants {
			if descEntry, ok := mp.pool[descHash]; ok {
				totalConflictingFee += descEntry.Fee
				totalEvicted++
			}
		}
	}

	// BIP125 Rule 5: The number of replaced transactions (plus descendants) must
	// not exceed MaxRBFReplacedTxs.
	if totalEvicted > MaxRBFReplacedTxs {
		return fmt.Errorf("%w: would evict %d transactions (max %d)",
			ErrRBFTooManyConflicts, totalEvicted, MaxRBFReplacedTxs)
	}

	// Calculate new transaction fee
	var totalOutputValue int64
	for _, out := range newTx.TxOut {
		totalOutputValue += out.Value
	}
	newFee := totalInputValue - totalOutputValue

	// Rule 3: New fee must be higher than all conflicting fees combined
	if newFee <= totalConflictingFee {
		return fmt.Errorf("%w: new fee %d <= conflicting fees %d",
			ErrRBFInsufficientFee, newFee, totalConflictingFee)
	}

	// BIP125 Rule 4: The replacement must pay for its own bandwidth at the
	// minimum relay fee rate (the fee increase must cover at least the
	// relay cost of the replacement).
	weight := consensus.CalcTxWeight(newTx)
	newVSize := (weight + 3) / 4
	minFeeBump := (newVSize * mp.config.MinRelayFeeRate + 999) / 1000
	if newFee-totalConflictingFee < minFeeBump {
		return fmt.Errorf("%w: fee increase %d < minimum bump %d",
			ErrRBFInsufficientFee, newFee-totalConflictingFee, minFeeBump)
	}

	return nil
}

// signalsRBF returns true if the transaction signals BIP125 replaceability.
func signalsRBF(tx *wire.MsgTx) bool {
	for _, in := range tx.TxIn {
		if in.Sequence < SequenceFinal {
			return true
		}
	}
	return false
}

// Ensure Mempool implements consensus.UTXOView
var _ consensus.UTXOView = (*Mempool)(nil)

// TxSerializeSize returns the serialized size of a transaction without witness.
func txSerializeSize(tx *wire.MsgTx) int64 {
	var buf bytes.Buffer
	_ = tx.SerializeNoWitness(&buf)
	return int64(buf.Len())
}

// ============================================================================
// Package Validation
// ============================================================================

// IsTopoSortedPackage checks if the package is topologically sorted
// (parents appear before children).
func IsTopoSortedPackage(txns []*wire.MsgTx) bool {
	// Build a set of txids that appear later in the package
	laterTxids := make(map[wire.Hash256]bool)
	for i := len(txns) - 1; i >= 0; i-- {
		txid := txns[i].TxHash()
		// Check that no input spends a transaction that appears later
		for _, in := range txns[i].TxIn {
			if laterTxids[in.PreviousOutPoint.Hash] {
				return false
			}
		}
		laterTxids[txid] = true
	}
	return true
}

// IsConsistentPackage checks that no transactions in the package conflict
// (no duplicate txids, no inputs spending the same prevout).
func IsConsistentPackage(txns []*wire.MsgTx) bool {
	txids := make(map[wire.Hash256]bool)
	spentOutpoints := make(map[wire.OutPoint]bool)

	for _, tx := range txns {
		txid := tx.TxHash()

		// Check for duplicate txids
		if txids[txid] {
			return false
		}
		txids[txid] = true

		// Check for conflicting inputs
		for _, in := range tx.TxIn {
			if spentOutpoints[in.PreviousOutPoint] {
				return false
			}
			spentOutpoints[in.PreviousOutPoint] = true
		}
	}
	return true
}

// IsChildWithParents checks if the package is a valid child-with-unconfirmed-parents
// topology: all transactions except the last (child) must be direct parents of the child.
func IsChildWithParents(txns []*wire.MsgTx) bool {
	if len(txns) < 2 {
		return false
	}

	// The last transaction is the child
	child := txns[len(txns)-1]

	// Collect all txids the child references as inputs
	childInputTxids := make(map[wire.Hash256]bool)
	for _, in := range child.TxIn {
		childInputTxids[in.PreviousOutPoint.Hash] = true
	}

	// All parent transactions must be referenced by the child
	for i := 0; i < len(txns)-1; i++ {
		parentTxid := txns[i].TxHash()
		if !childInputTxids[parentTxid] {
			return false
		}
	}

	return true
}

// IsChildWithParentsTree is a stricter check: child-with-parents where
// parents don't depend on each other (tree structure, no inter-parent deps).
func IsChildWithParentsTree(txns []*wire.MsgTx) bool {
	if !IsChildWithParents(txns) {
		return false
	}

	// Check that no parent spends another parent's output
	parentTxids := make(map[wire.Hash256]bool)
	for i := 0; i < len(txns)-1; i++ {
		parentTxids[txns[i].TxHash()] = true
	}

	for i := 0; i < len(txns)-1; i++ {
		for _, in := range txns[i].TxIn {
			if parentTxids[in.PreviousOutPoint.Hash] {
				return false
			}
		}
	}

	return true
}

// CheckPackage performs context-free package validation.
func CheckPackage(txns []*wire.MsgTx) error {
	if len(txns) == 0 {
		return ErrPackageEmpty
	}

	if len(txns) > MaxPackageCount {
		return ErrPackageTooManyTxs
	}

	// Check total weight (only for multi-tx packages)
	if len(txns) > 1 {
		var totalWeight int64
		for _, tx := range txns {
			totalWeight += consensus.CalcTxWeight(tx)
		}
		if totalWeight > MaxPackageWeight {
			return ErrPackageTooLarge
		}
	}

	// Check for duplicates (via txid set)
	txids := make(map[wire.Hash256]bool)
	for _, tx := range txns {
		txid := tx.TxHash()
		if txids[txid] {
			return ErrPackageDuplicateTx
		}
		txids[txid] = true
	}

	// Check topological sorting
	if !IsTopoSortedPackage(txns) {
		return ErrPackageNotSorted
	}

	// Check for internal conflicts
	if !IsConsistentPackage(txns) {
		return ErrPackageConflict
	}

	return nil
}

// AcceptPackage validates and accepts a package of related transactions.
// The package must be in child-with-unconfirmed-parents topology.
// Returns detailed results for each transaction.
func (mp *Mempool) AcceptPackage(txns []*wire.MsgTx) (*PackageResult, error) {
	result := &PackageResult{
		TxResults: make(map[wire.Hash256]*TxAcceptResult),
	}

	// Context-free validation
	if err := CheckPackage(txns); err != nil {
		result.PackageError = err
		return result, err
	}

	// For multi-tx packages, verify child-with-parents topology
	if len(txns) > 1 && !IsChildWithParentsTree(txns) {
		result.PackageError = ErrPackageNotChildWithParents
		return result, ErrPackageNotChildWithParents
	}

	// Single-tx package is trivially valid topology
	if len(txns) == 1 {
		return mp.acceptSingleTxPackage(txns[0], result)
	}

	return mp.acceptMultiTxPackage(txns, result)
}

// acceptSingleTxPackage handles a single-transaction "package".
func (mp *Mempool) acceptSingleTxPackage(tx *wire.MsgTx, result *PackageResult) (*PackageResult, error) {
	txid := tx.TxHash()
	wtxid := tx.WTxHash()

	txResult := &TxAcceptResult{
		TxID:  txid,
		WTxID: wtxid,
	}
	result.TxResults[wtxid] = txResult

	// Check if already in mempool
	if mp.HasTransaction(txid) {
		txResult.AlreadyInMempool = true
		txResult.Accepted = true
		entry := mp.GetEntry(txid)
		if entry != nil {
			txResult.Fee = entry.Fee
			txResult.VSize = entry.Size
			txResult.EffectiveFeerate = entry.FeeRate
		}
		txResult.EffectiveIncludes = []wire.Hash256{wtxid}
		return result, nil
	}

	// Try to add the transaction
	if err := mp.AddTransaction(tx); err != nil {
		txResult.Error = err
		result.PackageError = err
		return result, err
	}

	// Transaction accepted
	txResult.Accepted = true
	entry := mp.GetEntry(txid)
	if entry != nil {
		txResult.Fee = entry.Fee
		txResult.VSize = entry.Size
		txResult.EffectiveFeerate = entry.FeeRate
		result.PackageFeerate = entry.FeeRate
	}
	txResult.EffectiveIncludes = []wire.Hash256{wtxid}

	return result, nil
}

// acceptMultiTxPackage handles multi-transaction package acceptance.
func (mp *Mempool) acceptMultiTxPackage(txns []*wire.MsgTx, result *PackageResult) (*PackageResult, error) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	// Track transactions that need package evaluation
	var toEvaluate []*wire.MsgTx
	var totalFee int64
	var totalVSize int64
	var allWtxids []wire.Hash256

	// First pass: try each transaction individually
	for _, tx := range txns {
		txid := tx.TxHash()
		wtxid := tx.WTxHash()

		txResult := &TxAcceptResult{
			TxID:  txid,
			WTxID: wtxid,
		}
		result.TxResults[wtxid] = txResult

		// Already in mempool?
		if entry, ok := mp.pool[txid]; ok {
			txResult.AlreadyInMempool = true
			txResult.Accepted = true
			txResult.Fee = entry.Fee
			txResult.VSize = entry.Size
			txResult.EffectiveFeerate = entry.FeeRate
			txResult.EffectiveIncludes = []wire.Hash256{wtxid}
			totalFee += entry.Fee
			totalVSize += entry.Size
			allWtxids = append(allWtxids, wtxid)
			continue
		}

		// Try to validate individually (without actually adding yet)
		fee, vsize, err := mp.validateTransactionLocked(tx, false)
		if err != nil {
			// Check if this is a retryable error (missing inputs or fee issues)
			if isRetryablePackageError(err) {
				// Defer to package evaluation
				toEvaluate = append(toEvaluate, tx)
				allWtxids = append(allWtxids, wtxid)
				continue
			}
			// Non-retryable error - fail the package
			txResult.Error = err
			result.PackageError = fmt.Errorf("transaction %s failed: %w", txid, err)
			return result, result.PackageError
		}

		// Transaction would be valid individually
		txResult.Fee = fee
		txResult.VSize = vsize
		txResult.EffectiveFeerate = float64(fee) / float64(vsize)
		totalFee += fee
		totalVSize += vsize
		allWtxids = append(allWtxids, wtxid)
		toEvaluate = append(toEvaluate, tx)
	}

	// Calculate package feerate
	if totalVSize > 0 {
		result.PackageFeerate = float64(totalFee) / float64(totalVSize)
	}

	// Check package feerate against minimum
	minFeeRate := float64(mp.config.MinRelayFeeRate) / 1000 // Convert to sat/vB
	if result.PackageFeerate < minFeeRate {
		result.PackageError = fmt.Errorf("%w: package feerate %.2f sat/vB < minimum %.2f sat/vB",
			ErrPackageInsufficientFee, result.PackageFeerate, minFeeRate)
		return result, result.PackageError
	}

	// Now validate and add all transactions that need package evaluation
	// We need to add them in order, making parent outputs available for children
	for _, tx := range toEvaluate {
		txid := tx.TxHash()
		wtxid := tx.WTxHash()
		txResult := result.TxResults[wtxid]

		// Skip if already processed
		if txResult.Accepted || txResult.AlreadyInMempool {
			continue
		}

		// Validate with package context (parent outputs now available)
		fee, vsize, err := mp.validateTransactionLocked(tx, true)
		if err != nil {
			txResult.Error = err
			result.PackageError = fmt.Errorf("transaction %s failed validation: %w", txid, err)
			// Rollback: remove any transactions we added
			mp.rollbackPackageLocked(toEvaluate[:indexOf(toEvaluate, tx)])
			return result, result.PackageError
		}

		// Add to mempool
		if err := mp.addTransactionLocked(tx, fee, vsize); err != nil {
			txResult.Error = err
			result.PackageError = fmt.Errorf("failed to add %s: %w", txid, err)
			mp.rollbackPackageLocked(toEvaluate[:indexOf(toEvaluate, tx)])
			return result, result.PackageError
		}

		txResult.Accepted = true
		txResult.Fee = fee
		txResult.VSize = vsize
		txResult.EffectiveFeerate = result.PackageFeerate
		txResult.EffectiveIncludes = allWtxids
	}

	// Update effective feerate for all transactions in the package
	for _, wtxid := range allWtxids {
		if txResult, ok := result.TxResults[wtxid]; ok {
			txResult.EffectiveFeerate = result.PackageFeerate
			txResult.EffectiveIncludes = allWtxids
		}
	}

	// Evict if needed
	mp.maybeEvictLocked()

	return result, nil
}

// validateTransactionLocked validates a transaction without adding it.
// If packageMode is true, allows looking up parent outputs from earlier package txs.
// Returns fee and vsize on success.
// Must be called with mu held.
func (mp *Mempool) validateTransactionLocked(tx *wire.MsgTx, packageMode bool) (int64, int64, error) {
	txHash := tx.TxHash()

	// Reject if already in mempool
	if _, ok := mp.pool[txHash]; ok {
		return 0, 0, ErrAlreadyInMempool
	}

	// Basic sanity checks
	if err := consensus.CheckTransactionSanity(tx); err != nil {
		return 0, 0, fmt.Errorf("sanity check failed: %w", err)
	}

	// Reject coinbase
	if consensus.IsCoinbaseTx(tx) {
		return 0, 0, ErrCoinbaseNotAllowed
	}

	// Check weight
	weight := consensus.CalcTxWeight(tx)
	if weight > consensus.MaxStandardTxWeight {
		return 0, 0, ErrTxTooLarge
	}
	vsize := (weight + 3) / 4

	// Gather inputs and check for conflicts
	var totalInputValue int64
	var missingInputs []wire.OutPoint

	for _, in := range tx.TxIn {
		// Check for double-spend in mempool
		if existingTxHash, ok := mp.outpoints[in.PreviousOutPoint]; ok {
			existingEntry := mp.pool[existingTxHash]
			if existingEntry != nil && !signalsRBF(existingEntry.Tx) {
				return 0, 0, ErrRBFNotSignaled
			}
		}

		// Look up the UTXO
		utxo := mp.lookupOutputLocked(in.PreviousOutPoint)
		if utxo == nil {
			missingInputs = append(missingInputs, in.PreviousOutPoint)
		} else {
			totalInputValue += utxo.Amount
		}
	}

	if len(missingInputs) > 0 {
		return 0, 0, fmt.Errorf("%w: %d missing inputs", ErrMissingInputs, len(missingInputs))
	}

	// Calculate fee
	var totalOutputValue int64
	for _, out := range tx.TxOut {
		totalOutputValue += out.Value
	}
	fee := totalInputValue - totalOutputValue
	if fee < 0 {
		return 0, 0, ErrNegativeFee
	}

	// Note: In package mode, we don't check individual feerate here
	// because the package aggregate feerate is used instead.
	if !packageMode {
		feeRate := float64(fee) / float64(vsize) * 1000 // sat/kvB
		if int64(feeRate) < mp.config.MinRelayFeeRate {
			return 0, 0, fmt.Errorf("%w: %.1f sat/kvB below minimum %d sat/kvB",
				ErrInsufficientFee, feeRate, mp.config.MinRelayFeeRate)
		}
	}

	// Check dust
	for i, out := range tx.TxOut {
		if mp.isDust(out) {
			return 0, 0, fmt.Errorf("%w: output %d value %d", ErrDustOutput, i, out.Value)
		}
	}

	// Validate scripts
	flags := mp.getStandardScriptFlags()
	if err := mp.validateScriptsLocked(tx, flags); err != nil {
		return 0, 0, fmt.Errorf("%w: %v", ErrScriptValidation, err)
	}

	// BIP-68 sequence-lock check (mirrors AddTransaction).
	if err := mp.checkSequenceLocksLocked(tx); err != nil {
		return 0, 0, err
	}

	// Ancestor/descendant chain limits.
	if err := mp.checkChainLimitsLocked(tx); err != nil {
		return 0, 0, err
	}

	return fee, vsize, nil
}

// addTransactionLocked adds a validated transaction to the mempool.
// Must be called with mu held.
func (mp *Mempool) addTransactionLocked(tx *wire.MsgTx, fee, vsize int64) error {
	txHash := tx.TxHash()

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

	// Track dependencies
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

	return nil
}

// rollbackPackageLocked removes transactions that were added as part of a failed package.
// Must be called with mu held.
func (mp *Mempool) rollbackPackageLocked(txns []*wire.MsgTx) {
	// Remove in reverse order (children before parents)
	for i := len(txns) - 1; i >= 0; i-- {
		txHash := txns[i].TxHash()
		mp.removeSingleTxLocked(txHash)
	}
}

// isRetryablePackageError returns true if the error might be resolved
// by evaluating the transaction as part of a package.
func isRetryablePackageError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Missing inputs might be satisfied by earlier package transactions
	if errors.Is(err, ErrMissingInputs) {
		return true
	}
	if containsSubstr(errStr, "missing") {
		return true
	}
	// Insufficient fee might be covered by aggregate package feerate
	if errors.Is(err, ErrInsufficientFee) {
		return true
	}
	if containsSubstr(errStr, "fee") {
		return true
	}
	return false
}

// containsSubstr checks if s contains substr.
func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// indexOf returns the index of tx in txns, or -1 if not found.
func indexOf(txns []*wire.MsgTx, tx *wire.MsgTx) int {
	for i, t := range txns {
		if t == tx {
			return i
		}
	}
	return -1
}
