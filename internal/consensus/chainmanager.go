package consensus

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// W76: log a ConnectBlock sub-phase breakdown every N successful connects.
// Complements the [W75-CONN] outer-latency line emitted from sync.go.
// Temporarily lowered 500 → 100 while diagnosing the post-4da26c8 connector
// bottleneck: at ~60 blk/hr the old 500-window took ~8 hr to emit one rollup.
const PhaseStatsLogEvery = 100


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

	// Lock-free tip cache for RPC reads (updated atomically after tip changes).
	// This avoids RLock contention with ConnectBlock's write lock during IBD.
	// cachedTipNode holds the full BlockNode so RPCs like getblockchaininfo,
	// getmininginfo and getdifficulty can read header fields (bits, time,
	// medianTime) without taking headerIndex.mu.RLock — which contends with
	// AddHeader's write lock and causes multi-second tail latency during sync.
	cachedTipHash   atomic.Value // wire.Hash256
	cachedTipHeight atomic.Int32
	cachedTipNode   atomic.Pointer[BlockNode]

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

	// pendingRecovery is set when loadChainState read a saved tip from
	// the database but could not resolve it against the header index
	// (expected on startup, where the header index is freshly seeded with
	// only the genesis block).  While this flag is true, callers that add
	// headers should invoke ReloadChainState so the tip can be restored as
	// soon as the saved-tip header becomes available.  Lock-free so the
	// P2P header-handler can read it without contending with cm.mu.
	// (See W17 chainmgr-startup recovery fix.)
	pendingRecovery atomic.Bool

	// W76: ConnectBlock sub-phase timing accumulators.
	// Writer is ConnectBlock only, which runs under cm.mu — no extra
	// synchronization needed. Reset every PhaseStatsLogEvery successful
	// connects so operators see rolling per-window averages.
	phaseStatsN            int64 // successful connects in current window
	phaseStatsPreNs        int64 // summed prelude latency (header/MTP/context)
	phaseStatsFirstPassNs  int64 // summed first-pass latency (UTXO reads + in-memory apply)
	phaseStatsScriptNs     int64 // summed script-validation latency (zero during assume-valid IBD)
	phaseStatsPersistNs    int64 // summed persistence latency (RocksDB batch write)
	phaseStatsMaxPreNs     int64
	phaseStatsMaxFirstNs   int64
	phaseStatsMaxScriptNs  int64
	phaseStatsMaxPersistNs int64
	phaseStatsLifetime     int64 // cumulative successful connects since process start

	// W74: split of the [W76-PHASE] first phase into UTXO-read vs the rest
	// (CheckTransactionInputs, BIP68, in-memory spend/add, undo tracking).
	// Emitted as a parallel [W74-FIRST] line so operators can tell whether
	// blockbrew's ConnectBlock is UTXO-read bound (the symptom clearbit's
	// W73 Fix 1 targeted via multi-get prefetch) or compute-bound. Same
	// writer-only-under-cm.mu discipline as the W76 fields above.
	phaseStatsFirstUtxoNs    int64
	phaseStatsFirstValNs     int64
	phaseStatsMaxFirstUtxoNs int64
	phaseStatsMaxFirstValNs  int64
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
	if cm.tipNode != nil {
		cm.updateTipCache(cm.tipNode.Hash, 0)
	}

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
//
// On startup the header index contains only the genesis block, so a saved
// tip at height > 0 cannot be resolved here.  In that case we mark the
// chain manager as pendingRecovery so the P2P layer will retry via
// ReloadChainState after headers have been re-synced.  We deliberately
// emit a diagnostic log (not silent) so operators can see the startup
// recovery path fire (see W16 BLOCKBREW-DURABILITY-VERIFIED for the
// pre-fix silent-reset failure mode).
func (cm *ChainManager) loadChainState() {
	state, err := cm.chainDB.GetChainState()
	if err != nil {
		// No saved state, start from genesis
		return
	}

	log.Printf("chainmgr: loaded chain state from DB: height=%d hash=%s",
		state.BestHeight, state.BestHash.String())

	if state.BestHeight == 0 || state.BestHash == cm.params.GenesisHash {
		// Already at genesis — nothing to recover.
		return
	}

	node := cm.headerIndex.GetNode(state.BestHash)
	if node != nil {
		cm.tipNode = node
		cm.tipHeight = state.BestHeight
		cm.updateTipCache(node.Hash, state.BestHeight)
		log.Printf("chainmgr: restored chain tip at height %d hash=%s from saved state",
			cm.tipHeight, node.Hash.String())
		return
	}

	// Saved tip is not in the header index yet.  This is the normal
	// startup condition: only genesis is in the index until the P2P
	// layer has re-synced headers.  Mark the manager as pending
	// recovery and let ReloadChainState retry once headers arrive.
	cm.pendingRecovery.Store(true)
	log.Printf("chainmgr: saved chain tip %s at height %d not yet in header index; "+
		"deferring recovery until headers are re-synced",
		state.BestHash.String(), state.BestHeight)
}

// HasPendingRecovery returns true iff the chain manager loaded a saved
// chain tip from the database that has not yet been reconciled with the
// header index.  The P2P header-handler polls this (lock-free) after
// each header batch so it can invoke ReloadChainState as soon as the
// saved tip becomes reachable.
// (See W17 chainmgr-startup recovery fix.)
func (cm *ChainManager) HasPendingRecovery() bool {
	return cm.pendingRecovery.Load()
}

// ReloadChainState re-resolves the chain tip from the database after the
// header index has been populated (e.g. after P2P header sync progresses
// past the saved tip height).  On mainnet the header index starts with
// only genesis, so the initial loadChainState cannot restore a saved
// multi-hundred-thousand-height tip; this method is the retry hook.
//
// Recovery strategy (W17):
//  1. Happy path: saved tip hash is now in the header index → adopt it.
//  2. Header sync is still shallower than the saved tip height → keep
//     pendingRecovery = true and retry on the next batch.
//  3. Header sync has passed the saved tip but the saved hash is still
//     missing (the previously-active chain is a fork peers don't advertise)
//     → log loudly and leave the tip at genesis.  We deliberately do NOT
//     rewind to an ancestor because the persisted UTXO set is in the
//     post-state of the saved tip; re-pointing the tip to an ancestor
//     without replaying undo data would corrupt UTXO validation for
//     every subsequent ConnectBlock.  UTXO-consistent rewind via undo
//     replay is a W18 follow-up; for now the operator must wipe
//     chaindata/ to recover from this state.
//
// Also resolves the assume-valid height if it was not yet known.
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

	// Nothing to do if we have a non-genesis tip already.
	if cm.tipHeight > 0 {
		cm.pendingRecovery.Store(false)
		return
	}

	if cm.chainDB == nil {
		return
	}

	state, err := cm.chainDB.GetChainState()
	if err != nil {
		return
	}

	if state.BestHeight == 0 {
		// Genuinely at genesis.
		cm.pendingRecovery.Store(false)
		return
	}

	// 1. Happy path.
	if node := cm.headerIndex.GetNode(state.BestHash); node != nil {
		cm.tipNode = node
		cm.tipHeight = state.BestHeight
		cm.updateTipCache(node.Hash, state.BestHeight)
		cm.pendingRecovery.Store(false)
		log.Printf("chainmgr: reloaded chain state at height %d after header sync (saved tip %s)",
			cm.tipHeight, node.Hash.String())
		return
	}

	// 2. Recovery path is only valid AFTER header sync has passed the saved
	//    height.  If the header index is still shallower than the saved
	//    tip, the saved tip's header simply hasn't been re-fetched yet —
	//    any fallback now would discard known-good persisted work for
	//    nothing.  Wait; the next header batch will re-trigger us.
	headerHeight := cm.headerIndex.BestHeight()
	if headerHeight < state.BestHeight {
		// Keep pendingRecovery = true so we retry after more headers arrive.
		return
	}

	// 3. Header sync is at or past the saved tip height but the saved-tip
	//    hash is still not in the index.  A naive rewind to a deeper
	//    ancestor would corrupt the UTXO set: the persisted UTXOs reflect
	//    the saved tip's post-state, but the rewound tip height would
	//    have them looking "un-spent-too-early".  Proper recovery requires
	//    replaying undo data back to the ancestor, which is beyond the
	//    scope of the W17 startup-recovery patch.  For now we log loudly,
	//    clear pendingRecovery so we stop retrying every batch, and
	//    leave the tip at its current (genesis) value.  Operator must
	//    wipe chaindata/ to force a full re-sync.  See
	//    wave17-2026-04-15/BLOCKBREW-CHAINMGR-STARTUP-RECOVERY-FIX.md
	//    (W18 follow-up: UTXO-consistent rewind with undo replay).
	cm.pendingRecovery.Store(false)
	log.Printf("chainmgr: WARNING saved chain tip %s at height %d is not in the header index "+
		"even after header sync reached height %d — the previously-active chain appears to "+
		"be a fork no peers advertise.  UTXO-consistent rewind is not yet implemented; the "+
		"node will remain at genesis and will not advance.  Operator action required: wipe "+
		"chaindata/ to force a full re-sync.  See W18 follow-up.",
		state.BestHash.String(), state.BestHeight, headerHeight)
}

// ConnectBlock validates and connects a block to the active chain.
func (cm *ChainManager) ConnectBlock(block *wire.MsgBlock) error {
	hash := block.Header.BlockHash()
	node := cm.headerIndex.GetNode(hash)
	if node == nil {
		return fmt.Errorf("block %s not found in header index", hash.String())
	}

	// Log every 5000th block and any block that might be problematic
	if node.Height%5000 == 0 || (node.Height >= 59170 && node.Height <= 59180) {
		log.Printf("chainmgr: ConnectBlock height=%d hash=%s txCount=%d tipHeight=%d",
			node.Height, hash.String()[:16], len(block.Transactions), cm.tipHeight)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// W76: phase-timing stamps. Only the successful-return path at the
	// bottom of this function accumulates into the stats window, so early
	// returns (tip-mismatch, context check, validation failure, genesis
	// special-case) are naturally excluded.
	_phaseStart := time.Now()
	var _phaseFirstStart, _phaseScriptStart, _phasePersistStart time.Time

	// W74: accumulate just the UTXO-read time inside the first-pass loop
	// so we can report how much of `first` is RocksDB reads vs in-memory
	// validate/spend/add work.
	var _firstUtxoNs int64

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
		cm.updateTipCache(node.Hash, node.Height)
		node.Status |= StatusFullyValid
		if cm.chainDB != nil {
			batch := cm.chainDB.NewBatch()
			emptyUndo := &storage.BlockUndo{}
			cm.chainDB.WriteBlockUndoBatch(batch, hash, emptyUndo)
			cm.chainDB.SetBlockHeightBatch(batch, node.Height, hash)
			cm.chainDB.SetChainStateBatch(batch, &storage.ChainState{
				BestHash:   hash,
				BestHeight: node.Height,
			})
			if err := batch.Write(); err != nil {
				return fmt.Errorf("failed to write genesis block batch: %w", err)
			}
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

	_phaseFirstStart = time.Now() // W76: prelude → first-pass boundary

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

		// W69d: Fetch each input's UTXO exactly once into cachedView.cache, then
		// use that local (no-lock) map for every downstream read within this tx.
		// Before W69d, CheckTransactionInputs + BIP68 + spentCoins each made their
		// own GetUTXO calls, costing 3–4× UTXOSet.mu acquisitions per input. Post-
		// W69 profile showed connCh saturated (1024/1024) and rate stuck at
		// ~77 blk/hr; connection-step mutex thrash was the diagnosed bottleneck.
		//
		// W74: time just this inner loop so the rollup can show UTXO-read cost
		// separately from the rest of the first-pass work.
		_utxoStart := time.Now()
		for _, in := range tx.TxIn {
			utxo := cm.utxoSet.GetUTXO(in.PreviousOutPoint)
			if utxo != nil {
				cachedView.cache[in.PreviousOutPoint] = utxo
			}
		}
		_firstUtxoNs += time.Since(_utxoStart).Nanoseconds()

		// Check transaction inputs — read through cachedView so the input pass
		// hits the local map populated above instead of re-acquiring UTXOSet.mu.
		fee, err := CheckTransactionInputs(tx, node.Height, cachedView)
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
				// W69d: Direct cache read — populated above, same UTXOs.
				if utxo, ok := cachedView.cache[in.PreviousOutPoint]; ok && utxo != nil {
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
			// W69d: Direct cache read — populated above, same UTXOs.
			if utxo, ok := cachedView.cache[in.PreviousOutPoint]; ok && utxo != nil {
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

	_phaseScriptStart = time.Now() // W76: first-pass → script-validation boundary

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
	cm.updateTipCache(node.Hash, node.Height)
	node.Status |= StatusFullyValid

	// Exit IBD mode when close to current time
	if cm.isIBD && cm.tipHeight == cm.assumeValidHeight {
		cm.isIBD = false
		log.Printf("chainmgr: exiting IBD mode at height %d", cm.tipHeight)
	}

	// Periodic UTXO flush during IBD
	cm.blocksSinceFlush++
	shouldFlush := cm.blocksSinceFlush >= cm.flushInterval

	_phasePersistStart = time.Now() // W76: script-validation → persistence boundary

	// Persist block data atomically: undo data, block height, UTXO set, and
	// chain state are written in a single batch so a crash can never leave the
	// chain tip ahead of (or behind) the UTXO set.
	if cm.chainDB != nil {
		writeChainState := !cm.isIBD || shouldFlush

		if writeChainState || generateUndo {
			// Use NoSync for non-flush IBD batches — only the flush batch
			// (which persists chain state) needs durability.
			var batch storage.Batch
			if cm.isIBD && !shouldFlush {
				batch = cm.chainDB.NewBatchNoSync()
			} else {
				batch = cm.chainDB.NewBatch()
			}

			// Undo data keyed by block hash (not height, since heights can change during reorgs)
			if generateUndo {
				cm.chainDB.WriteBlockUndoBatch(batch, hash, blockUndo)
			}

			// Height -> hash mapping
			cm.chainDB.SetBlockHeightBatch(batch, node.Height, hash)

			// UTXO flush into the same batch when it's time
			if shouldFlush {
				type batchFlusher interface {
					FlushBatch(storage.Batch) error
				}
				if f, ok := cm.utxoSet.(batchFlusher); ok {
					if err := f.FlushBatch(batch); err != nil {
						return fmt.Errorf("failed to flush UTXOs to batch: %w", err)
					}
				}
			}

			// Chain state (tip hash + height) in the same atomic batch
			if writeChainState {
				cm.chainDB.SetChainStateBatch(batch, &storage.ChainState{
					BestHash:   hash,
					BestHeight: node.Height,
				})
			}

			if err := batch.Write(); err != nil {
				return fmt.Errorf("failed to write atomic block batch: %w", err)
			}

			if shouldFlush {
				log.Printf("chainmgr: UTXO flush at height %d (atomic)", cm.tipHeight)
			}
		} else {
			// During IBD between flushes, still persist height mapping
			cm.chainDB.SetBlockHeight(node.Height, hash)
			// Write undo data individually between flush intervals
			if generateUndo {
				if err := cm.chainDB.WriteBlockUndo(hash, blockUndo); err != nil {
					return fmt.Errorf("failed to write undo data: %w", err)
				}
			}
		}
	}

	if shouldFlush {
		cm.blocksSinceFlush = 0
	}

	// W76: phase accumulator. Only reached on the successful-return path,
	// so rollback + early-error paths never poison the window.
	_phaseEnd := time.Now()
	preNs := _phaseFirstStart.Sub(_phaseStart).Nanoseconds()
	firstNs := _phaseScriptStart.Sub(_phaseFirstStart).Nanoseconds()
	scriptNs := _phasePersistStart.Sub(_phaseScriptStart).Nanoseconds()
	persistNs := _phaseEnd.Sub(_phasePersistStart).Nanoseconds()

	cm.phaseStatsN++
	cm.phaseStatsPreNs += preNs
	cm.phaseStatsFirstPassNs += firstNs
	cm.phaseStatsScriptNs += scriptNs
	cm.phaseStatsPersistNs += persistNs
	if preNs > cm.phaseStatsMaxPreNs {
		cm.phaseStatsMaxPreNs = preNs
	}
	if firstNs > cm.phaseStatsMaxFirstNs {
		cm.phaseStatsMaxFirstNs = firstNs
	}
	if scriptNs > cm.phaseStatsMaxScriptNs {
		cm.phaseStatsMaxScriptNs = scriptNs
	}
	if persistNs > cm.phaseStatsMaxPersistNs {
		cm.phaseStatsMaxPersistNs = persistNs
	}

	// W74: split first into utxo-read vs the rest. Clamp the val delta at
	// zero to guard against clock skew making firstNs < _firstUtxoNs.
	firstValNs := firstNs - _firstUtxoNs
	if firstValNs < 0 {
		firstValNs = 0
	}
	cm.phaseStatsFirstUtxoNs += _firstUtxoNs
	cm.phaseStatsFirstValNs += firstValNs
	if _firstUtxoNs > cm.phaseStatsMaxFirstUtxoNs {
		cm.phaseStatsMaxFirstUtxoNs = _firstUtxoNs
	}
	if firstValNs > cm.phaseStatsMaxFirstValNs {
		cm.phaseStatsMaxFirstValNs = firstValNs
	}

	cm.phaseStatsLifetime++
	if cm.phaseStatsN >= PhaseStatsLogEvery {
		n := cm.phaseStatsN
		log.Printf(
			"[W76-PHASE] window=%d total=%d pre_avg=%.1fms first_avg=%.1fms script_avg=%.1fms persist_avg=%.1fms pre_max=%.0fms first_max=%.0fms script_max=%.0fms persist_max=%.0fms",
			n,
			cm.phaseStatsLifetime,
			float64(cm.phaseStatsPreNs/n)/1e6,
			float64(cm.phaseStatsFirstPassNs/n)/1e6,
			float64(cm.phaseStatsScriptNs/n)/1e6,
			float64(cm.phaseStatsPersistNs/n)/1e6,
			float64(cm.phaseStatsMaxPreNs)/1e6,
			float64(cm.phaseStatsMaxFirstNs)/1e6,
			float64(cm.phaseStatsMaxScriptNs)/1e6,
			float64(cm.phaseStatsMaxPersistNs)/1e6,
		)
		log.Printf(
			"[W74-FIRST] window=%d utxo_avg=%.1fms val_avg=%.1fms utxo_max=%.0fms val_max=%.0fms",
			n,
			float64(cm.phaseStatsFirstUtxoNs/n)/1e6,
			float64(cm.phaseStatsFirstValNs/n)/1e6,
			float64(cm.phaseStatsMaxFirstUtxoNs)/1e6,
			float64(cm.phaseStatsMaxFirstValNs)/1e6,
		)
		cm.phaseStatsN = 0
		cm.phaseStatsPreNs = 0
		cm.phaseStatsFirstPassNs = 0
		cm.phaseStatsScriptNs = 0
		cm.phaseStatsPersistNs = 0
		cm.phaseStatsMaxPreNs = 0
		cm.phaseStatsMaxFirstNs = 0
		cm.phaseStatsMaxScriptNs = 0
		cm.phaseStatsMaxPersistNs = 0
		cm.phaseStatsFirstUtxoNs = 0
		cm.phaseStatsFirstValNs = 0
		cm.phaseStatsMaxFirstUtxoNs = 0
		cm.phaseStatsMaxFirstValNs = 0
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
	cm.updateTipCache(parent.Hash, parent.Height)

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

// updateTipCache atomically publishes the current tip for lock-free reads.
// Must be called while cm.mu is held (or during init before any readers).
//
// Every call site assigns cm.tipNode = <node> immediately before invoking
// this, so we read cm.tipNode here and publish the pointer atomically.
// Readers using BestBlockNode() get a consistent snapshot without any lock.
func (cm *ChainManager) updateTipCache(hash wire.Hash256, height int32) {
	cm.cachedTipHash.Store(hash)
	cm.cachedTipHeight.Store(height)
	cm.cachedTipNode.Store(cm.tipNode)
}

// BestBlock returns the current chain tip hash and height.
// Uses atomic cache so it never blocks on the write lock held by ConnectBlock.
func (cm *ChainManager) BestBlock() (wire.Hash256, int32) {
	height := cm.cachedTipHeight.Load()
	hash, ok := cm.cachedTipHash.Load().(wire.Hash256)
	if !ok {
		return wire.Hash256{}, 0
	}
	return hash, height
}

// BestBlockNode returns the current chain tip BlockNode via atomic cache.
// Returns nil if the cache has not yet been populated (pre-init only).
//
// This is the lock-free alternative to headerIndex.GetNode(tipHash), which
// must take idx.mu.RLock and therefore contends with AddHeader's write lock
// during header sync. RPC handlers that only need the tip header fields
// (bits, time, medianTime) should use BestBlockNode instead.
func (cm *ChainManager) BestBlockNode() *BlockNode {
	return cm.cachedTipNode.Load()
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
