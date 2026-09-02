package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// W76: log a ConnectBlock sub-phase breakdown every N successful connects.
// Complements the [W75-CONN] outer-latency line emitted from sync.go.
// Temporarily lowered 500 → 100 while diagnosing the post-4da26c8 connector
// bottleneck: at ~60 blk/hr the old 500-window took ~8 hr to emit one rollup.
const PhaseStatsLogEvery = 100

// MaxReorgDepth bounds the disconnect+reconnect span of a single ReorgTo — but
// ONLY when the node is pruning (see ChainManager.pruningEnabled). On an ARCHIVE
// node (pruning off = the default) the cap is NOT applied: Bitcoin Core has NO
// reorg-depth cap (ActivateBestChainStep loops to the fork point unbounded;
// MIN_BLOCKS_TO_KEEP=288 governs PRUNED undo retention only), so it follows the
// most-work valid chain to ANY depth. An archive node always has every rev*.dat
// undo record on disk, so a deep reorg is physically safe; refusing it was a
// gratuitous Class-A consensus divergence (blockbrew would stay on a lower-work
// minority chain that Core would abandon). See CORE-PARITY-AUDIT/_loop-ledger.md
// "288-block reorg cap".
//
// On a PRUNED node the retained undo window is only MIN_BLOCKS_TO_KEEP=288 deep,
// so a reorg whose span exceeds it cannot be replayed (the undo is gone). There
// the cap stays as controlled protection: ReorgTo returns ErrReorgTooDeep rather
// than reorging into missing undo. 288 matches Core's MIN_BLOCKS_TO_KEEP so any
// reorg within the retained window is never refused.
const MaxReorgDepth = 288

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

	// pruningEnabled gates the MaxReorgDepth reorg cap. false (archive, the
	// default) = no cap: follow the most-work valid chain to any depth like
	// Bitcoin Core, since every undo record is on disk. true (pruned) = the
	// cap applies as protection against reorging into pruned-away undo. Set
	// once at construction from ChainManagerConfig.PruningEnabled; read under
	// no lock in ReorgTo (immutable after NewChainManager).
	pruningEnabled bool

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

	// reorgMu serializes ReorgTo against itself. The reorg batch wraps many
	// Connect+Disconnect calls; running two reorgs in parallel would mix
	// their writes into the same Pebble batch and corrupt the chain. Held
	// for the entire duration of a single ReorgTo (separate from cm.mu so
	// ConnectBlock / DisconnectBlock can take cm.mu in their normal pattern
	// without recursive-lock issues).
	reorgMu sync.Mutex

	// mutationWG counts chain-mutating operations currently in flight, and
	// quiescing latches once shutdown has begun. Together they let shutdown
	// prove the chain is at rest BEFORE it flushes chainstate and closes the
	// DB. See QuiesceForShutdown for why persisting a chainstate while a
	// mutation is running is unsafe.
	mutationWG sync.WaitGroup
	quiescing  atomic.Bool

	// reorgBatch, when non-nil, redirects all per-block persistence writes
	// inside ConnectBlock / DisconnectBlock into the named batch instead of
	// committing to disk per-block. Set by ReorgTo for the duration of a
	// multi-block reorg so the disconnects + reconnects ride a single Pebble
	// commit (Pattern D, multi-block atomicity, 2026-05-05). Always nil
	// outside ReorgTo. Read+written only while cm.mu is held; ReorgTo
	// installs / clears it under cm.mu and the per-block helpers read it
	// under cm.mu, so visibility is guaranteed by the lock.
	//
	// Crash mid-reorg semantics: with this in place a crash at ANY point in
	// ReorgTo before batch.Write() succeeds leaves the on-disk state at the
	// pre-reorg tip; success leaves it at the post-reorg tip. There is no
	// intermediate-tip state on disk where the chainstate has advanced past
	// the fork but UTXO mutations or undo deletions are partial. Cross-impl
	// reference: bitcoin-core validation.cpp's CChainState::ActivateBestChain
	// holds a single CDBBatch across all DisconnectTip / ConnectTip calls.
	reorgBatch storage.Batch

	// onBlockDisconnected, if set, is invoked once per block popped off the
	// active tip by DisconnectBlock — including each peel inside ReorgTo.
	// Wired from main.go to mp.BlockDisconnected so transactions from the
	// just-disconnected block (other than coinbase) get re-fed into the
	// mempool, mirroring Bitcoin Core's MaybeUpdateMempoolForReorg flow
	// (validation.cpp::DisconnectTip → MaybeUpdateMempoolForReorg).
	//
	// Pattern B closure for blockbrew (CORE-PARITY-AUDIT
	// _mempool-refill-on-reorg-fleet-result-2026-05-05.md). Stacks on top
	// of the Pattern Y closure 4e51e8b which made submitblock-driven
	// reorgs flow through ReorgTo at all; without B, every such reorg was
	// dropping its disconnected-tip txs on the floor.
	//
	// Invoked OUTSIDE cm.mu so the hook can take its own locks (mempool's
	// mu) without risking lock-order issues. The callback runs after the
	// chain state has been updated and the tip pointer advanced, so an
	// embedded mempool re-validation against the new tip's UTXO view sees
	// a coherent state.
	onBlockDisconnected func(block *wire.MsgBlock, height int32)

	// tipNotifier, if set, is pulsed once per active-chain tip advance via
	// updateTipCache — the single chokepoint every tip change funnels through:
	// ConnectBlock during IBD (genesis + extend), ConnectBlock post-IBD, the
	// submitblock/generate accept path (ProcessSubmittedBlock → ConnectBlock),
	// and BOTH halves of a reorg (DisconnectBlock peels + ConnectBlock replays
	// inside ReorgTo all route through updateTipCache). Wakes any
	// waitfornewblock / waitforblock / waitforblockheight RPC blocked on a tip
	// change. Mirrors Bitcoin Core's KernelNotifications::blockTip /
	// WaitTipChanged signal. Lock-free Notify (its own mutex) so calling it
	// while cm.mu is held introduces no lock-order risk. nil = no waiters wired
	// (degraded boot / unit tests); Notify on a nil receiver is a no-op.
	tipNotifier *TipNotifier

	// onBlockConnected, if set, is invoked once per block whose ConnectBlock
	// successfully extends the active tip — including each replay inside
	// ReorgTo. Wired from main.go to chainDB.WriteTxIndex so the txindex
	// (tx_id → block_hash mapping) is populated even on the submitblock /
	// reorg paths, not just the IBD-via-SyncManager path. Mirrors Bitcoin
	// Core's BaseIndex::BlockConnected fan-out (index/base.cpp), which is
	// invoked from validation.cpp::ConnectTip → MempoolNotifyEnter →
	// CValidationInterface::BlockConnected.
	//
	// Pattern C0 closure for blockbrew (CORE-PARITY-AUDIT
	// _txindex-revert-on-reorg-fleet-result-2026-05-05.md). The pre-fix
	// state had WriteTxIndex defined at internal/storage/chaindb.go:332
	// with zero non-test callers, so getrawtransaction(<txid>) returned
	// "no such tx" even for confirmed transactions on the active chain.
	// Stacks on top of today's submitblock-side-branch (4e51e8b) and
	// Pattern B disconnect (72c23be) work — both of which already exercise
	// the connect-replay path that this hook now hangs txindex writes off.
	//
	// Invoked OUTSIDE cm.mu (same locking discipline as onBlockDisconnected
	// above) so the hook can take its own locks (chainDB's RocksDB batch
	// commit) without lock-order risk against cm.mu.
	onBlockConnected func(block *wire.MsgBlock, height int32)
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

	// PruningEnabled reports whether the node is pruning block/undo data
	// (-prune=N or -prune=1). false (the default, archive mode) removes the
	// MaxReorgDepth reorg cap so ReorgTo follows the most-work valid chain to
	// any depth like Bitcoin Core — safe because archive nodes retain every
	// undo record. true keeps the cap as protection against reorging deeper
	// than the retained (MIN_BLOCKS_TO_KEEP=288) undo window. Wired from
	// main.go via storage.Pruner.IsEnabled().
	PruningEnabled bool

	// OnBlockDisconnected, if set, is invoked once per block popped off the
	// active tip by DisconnectBlock (and transitively by every peel inside
	// ReorgTo). Wired from main.go to mp.BlockDisconnected so non-coinbase
	// txs from the disconnected block get re-fed into the mempool. Mirrors
	// Bitcoin Core's MaybeUpdateMempoolForReorg.
	//
	// Pattern B closure (2026-05-05). Cross-impl reference: camlcoin
	// lib/sync.ml:2354-2363 which iterates !disconnected_txs and calls
	// Mempool.add_transaction per non-coinbase tx.
	OnBlockDisconnected func(block *wire.MsgBlock, height int32)

	// OnBlockConnected, if set, is invoked once per block successfully
	// connected to the active tip via ConnectBlock — including each replay
	// inside ReorgTo. Wired from main.go to chainDB.WriteTxIndex (gated by
	// -txindex) so submitblock + reorg paths write txindex entries, not
	// just the IBD-via-SyncManager path. Mirrors Bitcoin Core's
	// BaseIndex::BlockConnected fan-out.
	//
	// Pattern C0 closure (2026-05-05). Cross-impl reference: bitcoin-core
	// src/index/txindex.cpp::TxIndex::CustomAppend.
	OnBlockConnected func(block *wire.MsgBlock, height int32)
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
		params:              config.Params,
		headerIndex:         config.HeaderIndex,
		chainDB:             config.ChainDB,
		utxoSet:             config.UTXOSet,
		flushInterval:       flushInterval,
		assumeValidHash:     config.AssumeValidHash,
		parallelScripts:     config.ParallelScripts,
		isIBD:               true, // Start in IBD mode
		sigCache:            sigCache,
		onBlockDisconnected: config.OnBlockDisconnected,
		onBlockConnected:    config.OnBlockConnected,
		pruningEnabled:      config.PruningEnabled,
	}

	// parallelScripts is already set from config.ParallelScripts in the struct
	// literal above. No override needed.

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
		// ...and, before anything can move the tip, tell the UTXO view what
		// the ON-DISK coin set already reflects. Core's LoadChainTip
		// (validation.cpp:4546) takes the tip from the coins database's own
		// best block for exactly this reason. See seedAppliedTipFromMarker.
		cm.seedAppliedTipFromMarker()
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

// getBlockProofEquivalentTime computes the number of seconds of chain activity
// represented by the work difference between bestHeader and pindex.
//
// Mirrors Bitcoin Core chain.cpp GetBlockProofEquivalentTime, called as
// GetBlockProofEquivalentTime(*best_header, *pindex, *best_header, params):
//
//	r = (bestHeader.nChainWork - pindex.nChainWork) * nPowTargetSpacing / GetBlockProof(bestHeader)
//
// Result is clamped to [0, math.MaxInt64].  Used by shouldSkipScripts condition 5.
func getBlockProofEquivalentTime(bestHeader, pindex *BlockNode, params *ChainParams) int64 {
	// Work difference: bestHeader always has >= work in the skip-scripts call path.
	r := new(big.Int)
	if bestHeader.TotalWork.Cmp(pindex.TotalWork) >= 0 {
		r.Sub(bestHeader.TotalWork, pindex.TotalWork)
	} else {
		// Shouldn't occur on the skip path (bestHeader must have >= work than pindex),
		// but handle defensively so we never skip in an unexpected scenario.
		return 0
	}

	// Multiply by PoW target spacing.
	r.Mul(r, big.NewInt(params.TargetSpacing))

	// Divide by GetBlockProof(bestHeader) == CalcWork(bestHeader.Header.Bits).
	bestProof := CalcWork(bestHeader.Header.Bits)
	if bestProof.Sign() <= 0 {
		// Unreachable for any valid block, but be defensive — never skip.
		return 0
	}
	r.Div(r, bestProof)

	// Clamp to int64 max (mirrors Core's `r.bits() > 63` guard).
	if r.BitLen() > 63 {
		return math.MaxInt64
	}
	return r.Int64()
}

// shouldSkipScripts implements Bitcoin Core's assume-valid script-skip gate
// (validation.cpp:2346-2382). Returns true ONLY when ALL five conditions hold:
//
//  1. assumevalid is configured (assumeValidHash != zero hash).
//  2. The assumevalid block hash is present in our block index.
//     3a. node is an ANCESTOR OF (or equal to) the assumevalid block
//     (avNode.GetAncestor(node.Height) == node). A fork block at height ≤
//     av_height fails here because it is NOT on the av block's ancestry chain.
//     3b. node is on the BEST-HEADER CHAIN
//     (bestHeader.GetAncestor(node.Height) == node). Ensures avNode is
//     itself on our best-known chain.
//  4. bestHeader.TotalWork >= MinimumChainWork (eclipse-attack defense).
//  5. getBlockProofEquivalentTime(bestHeader, node) > 1209600 s (2 weeks,
//     DoS defense: blocks mined too recently are always script-verified).
//
// This gate is STRICTLY NARROWER than the old height-only check
// (assumeValidHeight > 0 && node.Height <= assumeValidHeight): it can only
// increase verification — never skip more blocks.
//
// Must be called while cm.mu is held; acquires idx.mu.RLock internally via
// GetNode/BestTip, consistent with existing ConnectBlock → GetNode calls.
func (cm *ChainManager) shouldSkipScripts(node *BlockNode) bool {
	const twoWeeksSec = int64(60 * 60 * 24 * 7 * 2) // 1 209 600 s

	// Condition 1: assumevalid must be configured.
	if cm.assumeValidHash.IsZero() {
		return false
	}

	// Condition 2: assumevalid block must be in our header index.
	avNode := cm.headerIndex.GetNode(cm.assumeValidHash)
	if avNode == nil {
		return false
	}

	// Condition 3a: node must be an ancestor of (or equal to) avNode.
	// Equivalent to Core: it->second.GetAncestor(pindex->nHeight) == pindex.
	// A fork block at the same height as a mainchain ancestor of avNode returns
	// a DIFFERENT node from GetAncestor, so the condition fails → verify scripts.
	if avNode.GetAncestor(node.Height) != node {
		return false
	}

	// Condition 3b: node must be on the best-header chain.
	// Equivalent to Core: m_best_header->GetAncestor(pindex->nHeight) == pindex.
	bestHeader := cm.headerIndex.BestTip()
	if bestHeader == nil || bestHeader.GetAncestor(node.Height) != node {
		return false
	}

	// Condition 4: best header chainwork must meet MinimumChainWork (eclipse defense).
	if bestHeader.TotalWork.Cmp(cm.params.MinimumChainWork) < 0 {
		return false
	}

	// Condition 5: equivalent time between node and bestHeader must exceed 2 weeks.
	// This prevents the DoS attack of presenting a long chain of recent blocks
	// and skipping their scripts by claiming they are under the assumevalid block.
	if getBlockProofEquivalentTime(bestHeader, node, cm.params) <= twoWeeksSec {
		return false
	}

	return true
}

// ConnectBlock validates and connects a block to the active chain.
// AdoptAppliedBlock advances the chain tip over a block whose UTXO effects
// are ALREADY in the persisted set from a prior session — the marker-lag
// case (2026-08-14 genesis-blockbrew: coins flushed through height 958,794
// while chain_tip recorded 958,000; replaying 958,001 then hit its own
// already-applied spend as "missing UTXO" and the corruption-halt advised
// deleting a VALID 10.9-day chainstate).
//
// Safety: adoption requires POSITIVE evidence that this exact block's
// connect batch committed — at least one of the block's own outputs is
// present in the UTXO set. An outpoint (txid,vout) can only enter the set
// via that block's connect, so presence is proof of application; a false
// positive is impossible. Absence proves nothing (outputs may have been
// spent by later already-applied blocks), so a fully-spent block yields
// ErrNoAdoptionEvidence and the caller falls back to the halt path —
// fail-closed, exactly like the old behavior, just with the false alarm
// removed for every provable case.
//
// The tip bookkeeping mirrors ConnectBlock's persistence (height map row +
// chain_tip batch) WITHOUT touching the UTXO set, block store, or undo
// store — those were all written by the prior session (per-block atomic
// batches; the height row rewrite is idempotent).
func (cm *ChainManager) AdoptAppliedBlock(block *wire.MsgBlock) error {
	if !cm.beginMutation() {
		return ErrShuttingDown
	}
	defer cm.endMutation()

	hash := block.Header.BlockHash()
	node := cm.headerIndex.GetNode(hash)
	if node == nil {
		return fmt.Errorf("block %s not found in header index", hash.String())
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if block.Header.PrevBlock != cm.tipNode.Hash {
		return fmt.Errorf("adopt: block %s does not connect to tip %s",
			hash.String()[:16], cm.tipNode.Hash.String()[:16])
	}

	// Positive already-applied evidence: any of this block's own outputs
	// present in the UTXO set. Coinbase first (within the 100-block
	// maturity window it cannot have been spent), then every other output.
	// ── Evidence probe: DURABLE reads only. ─────────────────────────────────
	//
	// An outpoint is unique to the block that created it (the txid commits to
	// the whole transaction, which exists only in this block), so ANY of this
	// block's own outputs found ON DISK proves the prior session committed its
	// batch. False positives are impossible — as long as the read is durable.
	//
	// It MUST NOT go through GetUTXO/HasUTXO: those consult the cache and would
	// confirm this session's own in-flight writes, including the residue of the
	// connect attempt that just failed. nimrod shipped that exact mistake and
	// it "proved" a block applied off in-memory residue.
	//
	// Outputs spent LATER WITHIN this same block are legitimately absent after a
	// full apply, so they are excluded from the probe set rather than counted as
	// missing evidence.
	dview, ok := cm.utxoSet.(durableUTXOView)
	if !ok {
		return ErrNoDurableUTXOView
	}

	spentInBlock := make(map[wire.OutPoint]struct{})
	for i, tx := range block.Transactions {
		if i == 0 {
			continue // coinbase has no real inputs
		}
		for _, in := range tx.TxIn {
			spentInBlock[in.PreviousOutPoint] = struct{}{}
		}
	}

	evidence, probed := 0, 0
	for _, tx := range block.Transactions {
		txid := tx.TxHash()
		for vout := range tx.TxOut {
			op := wire.OutPoint{Hash: txid, Index: uint32(vout)}
			if _, ok := spentInBlock[op]; ok {
				continue
			}
			probed++
			if dview.HasUTXODurable(op) {
				evidence++
			}
		}
	}
	if evidence == 0 {
		return ErrNoAdoptionEvidence
	}
	log.Printf("chainmgr: adoption evidence (durable) height=%d hash=%s evidence=%d/%d",
		node.Height, hash.String()[:16], evidence, probed)

	// ── Tolerant roll-forward (Core validation.cpp::RollforwardBlock). ──────
	//
	// The durable state may hold only a PREFIX of this block's mutations — a
	// crash can land mid-flush. Merely advancing the tip (the original
	// behaviour here) freezes that partial state under a tip claiming the block
	// is complete, and every later block spending a missing output then fails
	// forever. Worse, it is SILENT: the chain looks healthy and the UTXO set is
	// simply wrong.
	//
	// That is not hypothetical. On 2026-08-15 this function adopted its way to
	// C(958794) on the genesis rig and produced 166,180,926 coins against the
	// pinned 166,180,925 — exactly one un-applied spend — with a correct block
	// hash (receipts/T2-capture-blockbrew-20260815T125623Z.md).
	//
	// So re-apply every mutation instead. Both directions are safe to repeat:
	// SpendUTXO on an already-spent outpoint is a no-op, and AddUTXO rewrites
	// an identical value (an output is created once and never mutated before it
	// is spent). Prefix, complete, and partially-poisoned states all converge to
	// the exact post-block state.
	for i, tx := range block.Transactions {
		if i > 0 {
			for _, in := range tx.TxIn {
				cm.utxoSet.SpendUTXO(in.PreviousOutPoint)
			}
		}
		txid := tx.TxHash()
		for vout, out := range tx.TxOut {
			cm.utxoSet.AddUTXO(wire.OutPoint{Hash: txid, Index: uint32(vout)}, &UTXOEntry{
				Amount:     out.Value,
				PkScript:   bytes.Clone(out.PkScript),
				Height:     node.Height,
				IsCoinbase: i == 0,
			})
		}
	}

	cm.tipNode = node
	cm.tipHeight = node.Height
	cm.updateTipCache(node.Hash, node.Height)
	node.Status |= StatusFullyValid | StatusDataStored
	// The roll-forward above applied this block's mutations, so the coins
	// marker staged by FlushBatch below must name this block — but ADVANCE
	// only: the persisted set may already reflect blocks above this one (that
	// lag is the very condition that routed us here), and lowering the marker
	// to this height would make the next boot re-apply them.
	cm.advanceAppliedTip(hash, node.Height)

	if cm.chainDB != nil {
		batch := cm.chainDB.NewBatch()
		// Stage the rolled-forward UTXO mutations into the SAME batch as the
		// tip pointer. Adoption exists precisely because a previous crash left
		// the coins and the tip out of step; committing them atomically is what
		// stops this repair from re-creating the condition it repairs. (The old
		// code wrote only the tip, leaving the re-apply — when there was one —
		// in volatile cache.)
		if err := dview.FlushBatch(batch); err != nil {
			return fmt.Errorf("adopt: failed to stage rolled-forward UTXOs: %w", err)
		}
		cm.chainDB.SetBlockHeightBatch(batch, node.Height, hash)
		cm.chainDB.SetChainStateBatch(batch, &storage.ChainState{
			BestHash:   hash,
			BestHeight: node.Height,
		})
		if err := batch.Write(); err != nil {
			return fmt.Errorf("adopt: failed to persist tip advance: %w", err)
		}
	}

	log.Printf("chainmgr: ADOPTED already-applied block height=%d hash=%s (marker-lag repair; block re-applied by tolerant roll-forward, committed atomically with the tip)",
		node.Height, hash.String()[:16])
	return nil
}

// ErrNoAdoptionEvidence: AdoptAppliedBlock found none of the block's outputs
// in the UTXO set — cannot prove the block was already applied.
var ErrNoAdoptionEvidence = errors.New("no adoption evidence: none of the block's outputs are in the UTXO set")

// ErrNoDurableUTXOView: AdoptAppliedBlock was called against a UTXO view with
// no durable backing store. Marker-lag repair is only meaningful for the real
// DB-backed set — it must read what a PRIOR session committed to disk and must
// commit its roll-forward atomically. Fail closed so the caller keeps the
// ordinary reject path.
var ErrNoDurableUTXOView = errors.New("adoption requires a durable (DB-backed) UTXO view")

// appliedTipTracker is the optional capability a UTXO view exposes when it
// can record (and durably publish) the block through which its mutations are
// reflected. The DB-backed UTXOSet implements it; the scratch views used
// during validation do not, and for them setAppliedTip is a no-op.
type appliedTipTracker interface {
	SetAppliedTip(hash wire.Hash256, height int32)
	AdvanceAppliedTip(hash wire.Hash256, height int32) bool
}

// appliedFloorTracker is the optional capability a UTXO view exposes when it
// can hold a raise-only LOWER BOUND on what the persisted set may already
// reflect, separately from the named block. Kept apart from appliedTipTracker
// so scratch views (and third-party fakes) that only implement the marker keep
// compiling and keep working.
type appliedFloorTracker interface {
	RaiseAppliedFloor(height int32) bool
	AppliedFloor() (int32, bool)
}

// raiseAppliedFloor records that the persisted set may already reflect blocks
// up to `height`, without naming the block. No-op on views that cannot hold a
// floor.
func (cm *ChainManager) raiseAppliedFloor(height int32) {
	if t, ok := cm.utxoSet.(appliedFloorTracker); ok {
		t.RaiseAppliedFloor(height)
	}
}

// viewAppliedTip reports the IN-MEMORY applied-through marker of the UTXO view
// this manager mutates — what the connect path's own view reflects right now,
// as opposed to what disk reflects. Zero value when the view cannot track one.
func (cm *ChainManager) viewAppliedTip() (wire.Hash256, int32, bool) {
	type appliedTipReader interface {
		AppliedTip() (wire.Hash256, int32, bool)
	}
	if t, ok := cm.utxoSet.(appliedTipReader); ok {
		return t.AppliedTip()
	}
	return wire.Hash256{}, 0, false
}

// appliedFloor reports the view's raise-only lower bound, if it holds one.
func (cm *ChainManager) appliedFloor() (int32, bool) {
	if t, ok := cm.utxoSet.(appliedFloorTracker); ok {
		return t.AppliedFloor()
	}
	return 0, false
}

// setAppliedTip tells the UTXO view which block its mutations now reflect.
//
// Call it AFTER the block's mutations have been applied to the view (or, for
// a disconnect, after they have been undone), and always with the resulting
// tip. Every subsequent flush stamps this value into the same batch as the
// coins, which is what makes crash recovery able to ask "is this block's
// effect already in the persisted set?" instead of guessing from a connect
// error. Core keeps the same invariant in CCoinsViewCache::SetBestBlock →
// CCoinsViewDB::BatchWrite (txdb.cpp:158-159).
func (cm *ChainManager) setAppliedTip(hash wire.Hash256, height int32) {
	if t, ok := cm.utxoSet.(appliedTipTracker); ok {
		t.SetAppliedTip(hash, height)
	}
}

// advanceAppliedTip raises the coins marker to (hash, height) and REFUSES to
// lower it. Every forward path uses this — ConnectBlock, AdoptAppliedBlock,
// AdoptFlushedBlock — because none of them can prove the persisted set does
// not already reflect something higher.
//
// The refusal closes the hole the first version of this fix left open. Crash
// recovery walks the tip UP from the chain-state pointer, which is only a
// LOWER bound on the persisted set. Adopting block 9 out of a set that is
// durable through 121 must leave the marker at 121; stamping it down to 9
// publishes a marker BELOW its own coins, and the next boot re-applies
// 10..121 — re-adding coinbases that later blocks in that same span already
// spent. Core cannot reach this state at all: it takes the tip FROM the
// marker on boot (validation.cpp:4546 LoadChainTip) and only ever rolls
// FORWARD from it (validation.cpp:4773 ReplayBlocks).
func (cm *ChainManager) advanceAppliedTip(hash wire.Hash256, height int32) {
	if t, ok := cm.utxoSet.(appliedTipTracker); ok {
		t.AdvanceAppliedTip(hash, height)
	}
}

// seedAppliedTipFromMarker teaches the in-memory UTXO view what the ON-DISK
// coin set already reflects, before anything is allowed to move the tip.
//
// This is blockbrew's Chainstate::LoadChainTip (validation.cpp:4546), which
// takes the chainstate tip from `coins_cache.GetBestBlock()` — the coins
// database's own best block, not the chain-tip pointer. Without it the
// in-memory applied tip starts unset, the first thing that touches it (a
// recovery adopt, a connect) becomes the marker, and the next flush publishes
// that value over a set that reflects far more. Every other guarantee in this
// file is built on the view knowing what disk already holds.
//
// blockbrew differs from Core in ONE respect, deliberately: it does not move
// cm.tipNode to the marker here. The header index is not yet hydrated at
// construction time, so the marker's node usually does not exist; instead
// RecoverFromPersistedBlocks walks the tip up to the marker over the persisted
// height map, adopting (never re-applying) each block. The marker itself is
// authoritative from this moment on either way.
func (cm *ChainManager) seedAppliedTipFromMarker() {
	hash, height, ok := cm.durableCoinsTip()
	if ok {
		cm.setAppliedTip(hash, height)
		log.Printf("chainmgr: coins marker on disk: the persisted UTXO set reflects %s@%d",
			hash.String()[:16], height)
		return
	}

	// FAIL-CLOSED, NOT GUARD-OFF (2026-09-02).
	//
	// durableCoinsTip refuses the marker whenever it cannot NAME the block the
	// persisted set reflects: an interrupted multi-batch flush is recorded, the
	// marker is missing, or the height map disagrees with it. Returning here
	// used to leave UTXOSet.appliedSet false — and AdvanceAppliedTip's
	// raise-only guard is conditioned on appliedSet, so failing closed silently
	// DISABLED the monotonicity guard on exactly the boots that need it most.
	// A guard that switches itself off in its own failure case is not a guard.
	//
	// "Which block does the set reflect?" and "how much can the set already
	// reflect?" are different questions. The first is unanswerable here. The
	// second is not: the refused marker and both ends of a recorded flush
	// window are hard on-disk evidence of an upper extent, and the guard needs
	// nothing more than that bound. Install it as a floor. Adoption stays
	// refused — nothing below is allowed to skip work on a floor.
	//
	// Core reaches the same place by repairing instead of bounding: it records
	// both ends of the window in DB_HEAD_BLOCKS (txdb.cpp:128-129), erases it
	// with the new DB_BEST_BLOCK in the final batch (txdb.cpp:157-159), and
	// ReplayBlocks (validation.cpp:4773) rolls forward to hashHeads[0] before
	// LoadChainTip (validation.cpp:4546) is ever allowed to read the marker.
	// It never publishes a best block below the window. Neither may we.
	floor, ok := cm.durableCoinsFloor()
	if !ok {
		return
	}
	cm.raiseAppliedFloor(floor)
	log.Printf("chainmgr: the coins marker is unusable, but on-disk evidence says the "+
		"persisted UTXO set may already reflect blocks up to height %d; the "+
		"applied-through marker will NOT be published at or below that height "+
		"until a block above it is genuinely connected", floor)
}

// durableCoinsFloor reports a LOWER BOUND on the block height the persisted
// coin set may already reflect, and whether any on-disk evidence exists for
// one. It deliberately asks a WEAKER question than durableCoinsTip and so
// answers in cases where that one must refuse.
//
// The bound is the highest height any on-disk record mentions:
//
//   - the coins marker itself (storage.CoinsTipKey), even when it failed the
//     height-map cross-check — a marker that is not on THIS chain is still
//     proof that some flush stamped that height over this set;
//   - both ends of a recorded interrupted flush (storage.CoinsFlushKey,
//     Core's DB_HEAD_BLOCKS): the set is somewhere between them, so it may
//     contain mutations up to the higher end.
//
// Taking the maximum is the conservative direction for a FLOOR whose only use
// is to refuse marker publication. Over-estimating it can at worst withhold a
// marker that would have been legitimate (recovery then re-connects, which is
// safe); under-estimating it re-opens the resurrection.
func (cm *ChainManager) durableCoinsFloor() (int32, bool) {
	if cm.chainDB == nil {
		return 0, false
	}
	floor := int32(-1)
	if rec, err := cm.chainDB.GetCoinsFlushWindow(); err == nil && rec != nil {
		if rec.From != nil && rec.From.BestHeight > floor {
			floor = rec.From.BestHeight
		}
		if rec.To != nil && rec.To.BestHeight > floor {
			floor = rec.To.BestHeight
		}
	}
	if marker, err := cm.chainDB.GetCoinsTip(); err == nil && marker != nil && marker.BestHeight > floor {
		floor = marker.BestHeight
	}
	if floor < 0 {
		return 0, false
	}
	return floor, true
}

// durableCoinsTip reports the on-disk coins marker (Core's DB_BEST_BLOCK)
// and whether it is trustworthy for THIS chain.
//
// The marker is rejected — reported as absent — unless the persisted
// height->hash map agrees that its hash sits at its height. That guards the
// case where the map was rewritten by a reorg after the marker was stamped:
// an ancestor test built on a marker that is not on this chain would adopt
// blocks whose effects are genuinely absent. Fail closed: an unusable marker
// simply drops recovery back to the connect-first behaviour.
func (cm *ChainManager) durableCoinsTip() (wire.Hash256, int32, bool) {
	if cm.chainDB == nil {
		return wire.Hash256{}, 0, false
	}
	// An interrupted multi-batch coin flush (Core's DB_HEAD_BLOCKS,
	// txdb.cpp:128-129) means the persisted set is somewhere BETWEEN two
	// markers and neither describes it. Fail closed: refuse the marker and
	// say so loudly. blockbrew has no ReplayBlocks to repair the window, and
	// guessing is exactly the failure mode this whole mechanism removes.
	if rec, err := cm.chainDB.GetCoinsFlushWindow(); err == nil && rec != nil {
		log.Printf("[CHAINSTATE-CORRUPTION] chainmgr: an interrupted coin flush is "+
			"recorded (set is between %s@%d and %s@%d); the coins marker cannot be "+
			"trusted and no block will be adopted from it",
			rec.From.BestHash.String()[:16], rec.From.BestHeight,
			rec.To.BestHash.String()[:16], rec.To.BestHeight)
		return wire.Hash256{}, 0, false
	}

	marker, err := cm.chainDB.GetCoinsTip()
	if err != nil || marker == nil || marker.BestHeight < 0 {
		return wire.Hash256{}, 0, false
	}
	onChain, err := cm.chainDB.GetBlockHashByHeight(marker.BestHeight)
	if err != nil || onChain != marker.BestHash {
		log.Printf("chainmgr: recovery: ignoring coins marker %s@%d — the persisted "+
			"height map does not put that hash at that height",
			marker.BestHash.String()[:16], marker.BestHeight)
		return wire.Hash256{}, 0, false
	}
	return marker.BestHash, marker.BestHeight, true
}

// DurableCoinsTip reports the on-disk coins marker (Core's DB_BEST_BLOCK) and
// whether it is trustworthy for this chain. Exported so the boot paths that do
// NOT go through RecoverFromPersistedBlocks — import-blocks in particular — can
// ask the same question before they re-apply anything.
func (cm *ChainManager) DurableCoinsTip() (wire.Hash256, int32, bool) {
	return cm.durableCoinsTip()
}

// AdoptIfAlreadyFlushed advances the tip over `block` WITHOUT touching the
// UTXO set, when the durable coins marker PROVES the persisted set already
// reflects it. Reports whether it did.
//
// This is the single place the "is this block already applied?" question is
// answered, so every connect path can ask it the same way. It is a pure
// no-op — no state change, no error — whenever the answer is not provable:
// no marker, an untrustworthy marker, a block above the marker, or a block
// that is not the one the persisted height map puts at that height.
//
// The alternative every caller used before was to connect first and infer
// "already applied" from a "references missing UTXO" error. That inference is
// structurally blind to coinbase-only blocks: with no inputs they can never
// raise the error, so they were always re-applied, and AddUTXO put a coinbase
// back that a later block had already spent. Core never asks the question that
// way — it takes the tip from the coins marker (validation.cpp:4546) and rolls
// forward only above it (validation.cpp:4773).
func (cm *ChainManager) AdoptIfAlreadyFlushed(block *wire.MsgBlock) (bool, error) {
	if cm.chainDB == nil || block == nil {
		return false, nil
	}
	hash := block.Header.BlockHash()
	node := cm.headerIndex.GetNode(hash)
	if node == nil {
		return false, nil
	}
	// THE VIEW THIS CONNECT WOULD MUTATE MUST ITSELF ALREADY COVER THE BLOCK.
	//
	// The coins marker describes the PERSISTED set; the connect path mutates
	// the IN-MEMORY view, and the two are not the same statement. DisconnectBlock
	// and ReorgTo's rollback restate the view DOWNWARD (setAppliedTip) without
	// flushing, so between such a restatement and the next flush the on-disk
	// marker is stale-HIGH: it still names a block whose coins the view has
	// already undone. An invalidateblock / reconsiderblock / resubmit round trip
	// is enough — no crash required. Adopting there would advance the tip over a
	// block whose mutations the view genuinely lacks, which is the
	// silent-corruption direction.
	//
	// This is also the cheap test, and it goes first: every ordinary connect —
	// IBD, a new tip off the wire, a freshly mined block — arrives ABOVE the
	// view's applied tip and is rejected without a single database read. That
	// matters now that every block-connecting caller runs through this gate.
	_, viewHeight, viewSet := cm.viewAppliedTip()
	if !viewSet || node.Height > viewHeight {
		return false, nil
	}

	markerHash, markerHeight, ok := cm.durableCoinsTip()
	if !ok || node.Height > markerHeight {
		return false, nil
	}

	// The marker covers this HEIGHT; require that it covers this BLOCK.
	if !cm.provablyCoveredByMarker(node, hash, markerHash) {
		return false, nil
	}
	if err := cm.AdoptFlushedBlock(block); err != nil {
		return false, err
	}
	return true, nil
}

// provablyCoveredByMarker reports whether `node`/`hash` is an ancestor-or-self
// of the block the coins marker names, i.e. whether the persisted set already
// reflects it. Caller must have established node.Height <= markerHeight and
// that the marker itself is trustworthy (durableCoinsTip).
//
// Two independent proofs, in order of cost:
//
//  1. The persisted height->hash map. It is the same map durableCoinsTip
//     validated the marker against, so agreement means ancestor-or-self on the
//     persisted chain. Disagreement names a COMPETING block at that height,
//     whose mutations are emphatically not in the set — refuse.
//
//  2. When the height ROW IS MISSING, the header index's prev-hash chain.
//     This case is not exotic: a hole in the height map is precisely what makes
//     RecoverFromPersistedBlocks halt below the marker (its replay loop breaks
//     on the first GetBlockHashByHeight failure), and the halt is what leaves
//     later callers connecting blocks the set already contains. A gate whose
//     only proof is the height map therefore cannot fire in the case it exists
//     for. The marker NAMES a block; the set reflects that block's mutations,
//     which are applied on top of every ancestor's, so an ancestor of the
//     marker block at this height is covered by construction. That ancestry is
//     cryptographic — each node's Parent is resolved through the header's
//     PrevBlock — so unlike a height table it cannot be rewritten by a later
//     reorg. Core answers exactly this question exactly this way
//     (CBlockIndex::GetAncestor, src/chain.cpp), never from a height table.
//
// Anything else — a real read error, a marker block absent from the header
// index, an ancestry walk that cannot reach the height — is not evidence and
// refuses. Refusing costs a re-connect; a wrong "yes" skips work that was
// never done.
func (cm *ChainManager) provablyCoveredByMarker(node *BlockNode, hash, markerHash wire.Hash256) bool {
	onChain, err := cm.chainDB.GetBlockHashByHeight(node.Height)
	switch {
	case err == nil:
		return onChain == hash
	case errors.Is(err, storage.ErrNotFound):
		markerNode := cm.headerIndex.GetNode(markerHash)
		if markerNode == nil {
			return false
		}
		anc := markerNode.GetAncestor(node.Height)
		return anc != nil && anc.Hash == hash
	default:
		return false
	}
}

// ConnectOrAdoptBlock is the ONE entry point every block-connecting caller
// uses. It asks the durable coins marker whether the persisted UTXO set
// already reflects `block` and, if it provably does, advances the tip WITHOUT
// re-applying the block; otherwise it connects normally.
//
// The gate used to be wired into the P2P connect loop alone (p2p/sync.go).
// Every other caller — submitblock, submitblock batch, generatetoaddress, the
// miner — connected unconditionally, which is safe only while the boot walk
// leaves the tip at the marker. A halted recovery is exactly the state where
// it does not: the tip sits BELOW the marker, and the next block any of those
// callers connects is one the set already contains. Re-applying a coinbase-only
// block there re-adds a coinbase a later block already spent (the 2026-08-15
// signature), with no error raised anywhere, because a block with no inputs has
// nothing to trip over.
//
// Core has no equivalent split: every path lands in ActivateBestChain over a
// chainstate whose tip came FROM the coins marker (validation.cpp:4546).
func (cm *ChainManager) ConnectOrAdoptBlock(block *wire.MsgBlock) error {
	adopted, err := cm.AdoptIfAlreadyFlushed(block)
	if err != nil {
		return err
	}
	if adopted {
		return nil
	}
	return cm.ConnectBlock(block)
}

// AdoptFlushedBlock advances the chain tip over a block the DURABLE coins
// marker already accounts for, WITHOUT touching the UTXO set.
//
// This is the Core-shaped half of crash recovery. Core boots the chainstate
// at the coins database's own best block (validation.cpp:4546 LoadChainTip
// takes the tip from coins_cache.GetBestBlock()) and only ever rolls blocks
// ABOVE that marker forward (validation.cpp:4773 ReplayBlocks, whose
// roll-forward window starts at the fork point of the recorded interrupted
// flush). It never re-applies a block the marker says is already reflected.
//
// Re-applying such a block is not harmless. A block's outputs may have been
// spent by a LATER block that the marker also covers; AddUTXO would put the
// spent coin back. That is the whole defect this function exists to remove —
// see RecoverFromPersistedBlocks.
//
// The caller must have established that the marker covers this block. This
// function only verifies chain shape.
func (cm *ChainManager) AdoptFlushedBlock(block *wire.MsgBlock) error {
	if !cm.beginMutation() {
		return ErrShuttingDown
	}
	defer cm.endMutation()

	hash := block.Header.BlockHash()
	node := cm.headerIndex.GetNode(hash)
	if node == nil {
		return fmt.Errorf("block %s not found in header index", hash.String())
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if block.Header.PrevBlock != cm.tipNode.Hash {
		return fmt.Errorf("adopt-flushed: block %s does not connect to tip %s",
			hash.String()[:16], cm.tipNode.Hash.String()[:16])
	}

	// NEVER adopt a block the index has marked invalid, and never stamp it
	// FullyValid. The marker only says the coin set reflects this block's
	// mutations — it says nothing about whether the block is still WANTED on
	// the active chain. A standalone DisconnectBlock (invalidateblock) drops
	// the tip pointer below a block whose coins are still on disk without
	// flushing the undo, so recovery legitimately meets a marker that covers
	// a deliberately-disconnected block. Walking the tip back over it and
	// re-stamping StatusFullyValid would silently un-invalidate it. Mirrors
	// Core, which excludes invalid nodes from chain selection entirely
	// (validation.cpp InvalidChainFound / setBlockIndexCandidates).
	if node.Status.IsInvalid() {
		return fmt.Errorf("adopt-flushed: refusing to adopt block %s at height %d — "+
			"the header index marks it invalid", hash.String()[:16], node.Height)
	}

	cm.tipNode = node
	cm.tipHeight = node.Height
	cm.updateTipCache(node.Hash, node.Height)
	node.Status |= StatusFullyValid | StatusDataStored
	// ADVANCE ONLY. This block is at-or-below the marker by construction, so
	// this is normally a no-op — and that is the whole point. Stamping the
	// marker DOWN to this block, while the set on disk reflects everything up
	// to the marker, is what made the previous version of this fix publish a
	// marker of 9 over a set durable through 121 and resurrect a coin on the
	// next boot.
	cm.advanceAppliedTip(hash, node.Height)

	if cm.chainDB != nil {
		// Height row + tip pointer only. Deliberately NO UTXO write: there is
		// nothing of this block's to write, and the tip-never-leads-the-coins
		// invariant already holds because the coins marker covers this height.
		batch := cm.chainDB.NewBatch()
		cm.chainDB.SetBlockHeightBatch(batch, node.Height, hash)
		cm.chainDB.SetChainStateBatch(batch, &storage.ChainState{
			BestHash:   hash,
			BestHeight: node.Height,
		})
		if err := batch.Write(); err != nil {
			return fmt.Errorf("adopt-flushed: failed to persist tip advance: %w", err)
		}
	}
	return nil
}

// durableUTXOView is the optional capability AdoptAppliedBlock needs. It is
// deliberately NOT folded into UpdatableUTXOView: that interface is also
// implemented by intra-block scratch views used during validation, which have
// no database and could only satisfy these methods by lying.
type durableUTXOView interface {
	// HasUTXODurable reports on-disk presence, bypassing cache and pending
	// deletes.
	HasUTXODurable(outpoint wire.OutPoint) bool
	// FlushBatch stages all pending UTXO mutations into the caller's batch so
	// they commit atomically with the tip pointer.
	FlushBatch(batch storage.Batch) error
}

func (cm *ChainManager) ConnectBlock(block *wire.MsgBlock) error {
	if !cm.beginMutation() {
		return ErrShuttingDown
	}
	defer cm.endMutation()

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

	// connectedBlock + connectedHeight are captured under cm.mu only on the
	// successful-return path below (just before the lock is released by the
	// `defer cm.mu.Unlock()` immediately following). The deferred dispatcher
	// below fires the OnBlockConnected callback OUTSIDE cm.mu so the hook
	// (e.g. txindex batch commit on RocksDB) cannot deadlock against cm.mu
	// held by a contending ConnectBlock / DisconnectBlock. Mirrors the
	// post-unlock discipline used by DisconnectBlock for the symmetric
	// onBlockDisconnected hook (Pattern B closure 72c23be).
	//
	// Pattern C0 closure for blockbrew (CORE-PARITY-AUDIT
	// _txindex-revert-on-reorg-fleet-result-2026-05-05.md). For ReorgTo,
	// ConnectBlock is called recursively per replay, so each replay fires
	// its own onBlockConnected naturally.
	var (
		connectedBlock  *wire.MsgBlock
		connectedHeight int32
		connectedCB     func(*wire.MsgBlock, int32)
	)
	defer func() {
		if connectedCB != nil && connectedBlock != nil {
			connectedCB(connectedBlock, connectedHeight)
		}
	}()

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

	// Resolve assume-valid height (used for IBD-exit check further below).
	// The full skip-scripts decision is made by shouldSkipScripts (which calls
	// GetNode directly), so this early-resolution block is kept only for the
	// assumeValidHeight field used in the IBD exit gate at the bottom.
	if cm.assumeValidHeight == 0 && !cm.assumeValidHash.IsZero() {
		avNode := cm.headerIndex.GetNode(cm.assumeValidHash)
		if avNode != nil {
			cm.assumeValidHeight = avNode.Height
			log.Printf("chainmgr: assume-valid block resolved at height %d", cm.assumeValidHeight)
		}
	}

	// Apply Bitcoin Core's faithful assume-valid script-skip gate
	// (validation.cpp:2346-2382). This replaces the old HEIGHT-ONLY check
	// (node.Height <= assumeValidHeight) with the full 5-condition gate:
	// ancestor-of-avBlock, on-best-header-chain, MinimumChainWork, and
	// 2-week equivalent-time burial. See shouldSkipScripts for details.
	skipScripts := cm.shouldSkipScripts(node)

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

	// Calculate expected subsidy using the network-aware halving interval.
	// Core: GetBlockSubsidy(nHeight, consensusParams) reads
	// consensusParams.nSubsidyHalvingInterval (validation.cpp:1839).
	// Regtest uses 150; mainnet/testnet4 use 210000.  CalcBlockSubsidy
	// hardcodes 210000, which would false-reject coinbases on regtest after
	// block 150 (subsidy expected to halve but coinbase still pays 50 BTC).
	subsidy := CalcBlockSubsidyForInterval(node.Height, cm.params.SubsidyHalvingInterval)

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
	//
	// W93 fix #4 (genesis-by-hash, not height): Bitcoin Core compares the
	// block hash to params.GetConsensus().hashGenesisBlock (validation.cpp:2339)
	// rather than height==0. Height-based detection can misfire on regtest /
	// custom networks where a fork could in principle plant a non-genesis
	// block at height 0. The hash-based comparison is the canonical check
	// and matches every other Bitcoin Core reference site (chain.cpp,
	// chainparams.cpp). Fall back to height as a safety net for the
	// HeaderIndex contract that genesis is always node.Height==0 with
	// node.Hash == params.GenesisHash.
	if hash == cm.params.GenesisHash || node.Height == 0 {
		// Store empty undo data and update chain state
		cm.tipNode = node
		cm.tipHeight = node.Height
		cm.updateTipCache(node.Hash, node.Height)
		node.Status |= StatusFullyValid | StatusDataStored
		cm.advanceAppliedTip(hash, node.Height)
		if cm.chainDB != nil {
			batch := cm.chainDB.NewBatch()
			// #126 (2026-05-27): fold the block body into the genesis batch
			// so that on a brand-new datadir the genesis body + undo +
			// height map + chainstate commit atomically. Callers (genesis
			// init in testutil + main.go bootstrap) used to invoke a
			// separate chainDB.StoreBlock first; ConnectBlock now owns
			// the body persistence end-to-end via StoreBlockAtBatch. The
			// call is idempotent (HasBlock fast-path), so any caller still
			// pre-storing the genesis body sees a no-op here.
			if err := cm.chainDB.StoreBlockAtBatch(batch, hash, block, node.Height); err != nil {
				return fmt.Errorf("failed to stage genesis block body: %w", err)
			}
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
			// Mirror Core blockstorage.cpp:1029 — set BLOCK_HAVE_UNDO after
			// undo data is committed to disk.
			cm.headerIndex.MarkUndoStored(hash)
		}
		return nil
	}

	// BIP-30: Reject any block whose transactions would overwrite existing
	// (unspent) UTXOs.  Logic lives in CheckBIP30 (blockvalidation.go) so
	// tests can exercise it without a full ChainManager.
	// Mirrors Bitcoin Core validation.cpp ConnectBlock ~line 2402-2476.
	//
	// Pass the block hash (for IsBIP30Repeat height+hash check) and an
	// ancestor-hash lookup (for BIP34 short-circuit via BIP34Hash).
	if err := CheckBIP30(block, node.Height, hash, cm.params, cm.utxoSet,
		func(h int32) (wire.Hash256, bool) { return node.GetAncestorHashAtHeight(h) },
	); err != nil {
		return err
	}

	// Cache prevouts for script validation BEFORE spending them.
	// The first pass spends UTXOs, so the second pass (script validation)
	// needs a cached view of the original UTXOs.
	cachedView := &cachedUTXOView{
		cache:    make(map[wire.OutPoint]*UTXOEntry),
		fallback: cm.utxoSet,
	}
	// scriptView is a separate snapshot used exclusively by the second-pass
	// script validation.  Unlike cachedView, entries are NEVER evicted from
	// scriptView: the CVE-2012-2459 eviction that removes spent inputs from
	// cachedView.cache (so that a later duplicate tx cannot find a stale
	// "unspent" entry) would otherwise leave the second pass unable to look up
	// inputs that the first pass already spent.  scriptView is populated
	// alongside cachedView in the UTXO-fetch loop below and then used
	// (read-only) in ParallelScriptValidationCached / ValidateTransactionScripts.
	scriptView := make(map[wire.OutPoint]*UTXOEntry)

	// Accumulate block-wide sigop cost (BIP-141 §Block size limit).
	// Counted per-tx inside the first-pass loop while prevouts are still
	// available in cachedView (before SpendTxInputs evicts them).
	// Reject with bad-blk-sigops if total exceeds MaxBlockSigOpsCost (80,000).
	// Mirrors Bitcoin Core validation.cpp ConnectBlock nSigOpsCost logic (~line 2568).
	var nSigOpsCost int

	// Track UTXO modifications so we can roll back if validation fails.
	// Each entry records a tx index and the outputs it added / inputs it spent.
	type utxoModification struct {
		txIdx       int
		addedOuts   []wire.OutPoint     // outputs added to UTXO set
		spentInputs []wire.OutPoint     // inputs spent from UTXO set
		spentCoins  []storage.SpentCoin // original UTXOs for rollback
	}
	var utxoMods []utxoModification

	// rollbackUTXOs undoes all UTXO changes made during the first pass.
	// This is critical: without rollback, a failed ConnectBlock corrupts the
	// UTXO set and causes all subsequent blocks to fail validation too.
	//
	// W93 fix #1 (slice misalignment): the previous implementation walked
	// mod.spentCoins and indexed mod.spentInputs[0]/[1:], which only worked
	// when spentCoins and spentInputs had identical length. Bug 1 (below)
	// arranged for them to ALWAYS be 1:1, so this loop indexes them with the
	// same `j` and never mutates the local slice header (defensive: keeps
	// the rollback idempotent if invoked twice).
	//
	// W93 fix #6 (PkScript aliasing on restore — W82/W92 pattern): clone the
	// PkScript when constructing the restored UTXOEntry so subsequent
	// mutations of the spentCoin's backing buffer cannot corrupt the cache
	// entry. The bug surfaces when the rollback is invoked AFTER the same
	// pkScript slice has already been recorded into blockUndo (persisted on
	// the success path), or when test harnesses mutate input buffers between
	// validation passes.
	rollbackUTXOs := func() {
		// Undo in reverse order
		for i := len(utxoMods) - 1; i >= 0; i-- {
			mod := utxoMods[i]
			// Remove outputs that were added
			for _, op := range mod.addedOuts {
				cm.utxoSet.SpendUTXO(op)
			}
			// Restore inputs that were spent. spentCoins and spentInputs are
			// always parallel arrays of the same length (see Bug 1 fix below).
			if len(mod.spentCoins) != len(mod.spentInputs) {
				// Should be unreachable; log loudly so any future regression
				// is caught instead of silently misaligning the undo data.
				log.Printf("chainmgr: BUG: rollback length mismatch txIdx=%d coins=%d inputs=%d",
					mod.txIdx, len(mod.spentCoins), len(mod.spentInputs))
				continue
			}
			for j, sc := range mod.spentCoins {
				cm.utxoSet.AddUTXO(mod.spentInputs[j], &UTXOEntry{
					Amount:     sc.TxOut.Value,
					PkScript:   bytes.Clone(sc.TxOut.PkScript),
					Height:     sc.Height,
					IsCoinbase: sc.Coinbase,
				})
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
			// Count coinbase sigops (legacy only; CountP2SHSigOps + CountWitnessSigOps
			// both short-circuit to 0 for coinbase txs).
			// Use INACCURATE counting (CHECKMULTISIG=20), matching Core's
			// GetLegacySigOpCount → GetSigOpCount(fAccurate=false).
			for _, txIn := range tx.TxIn {
				nSigOpsCost += CountSigOpsInaccurate(txIn.SignatureScript) * WitnessScaleFactor
			}
			for _, txOut := range tx.TxOut {
				nSigOpsCost += CountSigOpsInaccurate(txOut.PkScript) * WitnessScaleFactor
			}
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
				// Also snapshot into scriptView for the second-pass script
				// validation; scriptView is never evicted so the second pass
				// can always find inputs that the first pass spent.
				scriptView[in.PreviousOutPoint] = utxo
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
				} else {
					// #53 (2026-08-27): a miss here means the input coin was
					// created by an earlier tx IN THIS BLOCK (intra-block
					// chain) or a bookkeeping bug. Core assigns such coins
					// the containing block's height (CalculateSequenceLocks:
					// MEMPOOL_HEIGHT coins -> tip+1). The old zero default
					// made every BIP-68 height lock on the input TRIVIALLY
					// SATISFIED — fail-open on a chain-derived value (the
					// fabrication family). The mempool caller already uses
					// the conservative height; the connect path now matches.
					prevHeights[j] = node.Height
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

		// Block-wide sigop COST cap (BIP-141 §Block size limit, MAX_BLOCK_SIGOPS_COST=80000).
		// Count BEFORE spending inputs so cachedView still holds the prevout data
		// needed by CountP2SHSigOps and CountWitnessSigOps.
		// Mirrors Core's per-tx nSigOpsCost accumulation (validation.cpp ~line 2568).
		// Use INACCURATE counting (CHECKMULTISIG=20) for legacy sigops, matching
		// Core's GetLegacySigOpCount → GetSigOpCount(fAccurate=false).
		for _, txIn := range tx.TxIn {
			nSigOpsCost += CountSigOpsInaccurate(txIn.SignatureScript) * WitnessScaleFactor
		}
		for _, txOut := range tx.TxOut {
			nSigOpsCost += CountSigOpsInaccurate(txOut.PkScript) * WitnessScaleFactor
		}
		// P2SH and witness sigops are FLAG-GATED in Core, using the same
		// GetBlockScriptFlags result computed at the top of this function — so
		// the per-block script_flag_exceptions reach sigop accounting too.
		// Core: `if (flags & SCRIPT_VERIFY_P2SH)` (consensus/tx_verify.cpp:150-152),
		// and CountWitnessSigOps returns 0 when SCRIPT_VERIFY_WITNESS is clear
		// (script/interpreter.cpp:2141-2143).
		// At the BIP-16 exception block (170060) Core's flags are
		// SCRIPT_VERIFY_NONE and it counts ZERO of both; counting them
		// unconditionally over-counts and can false-reject. These lines are not
		// under the skipScripts guard, so they run on every connect — IBD with
		// assumevalid, reorg replay and the import tool included.
		if flags&script.ScriptVerifyP2SH != 0 {
			nSigOpsCost += CountP2SHSigOps(tx, cachedView)
		}
		if flags&script.ScriptVerifyWitness != 0 {
			nSigOpsCost += CountWitnessSigOps(tx, cachedView)
		}
		if nSigOpsCost > MaxBlockSigOpsCost {
			rollbackUTXOs()
			return fmt.Errorf("%w: %d > %d", ErrSigOpsCostTooHigh, nSigOpsCost, MaxBlockSigOpsCost)
		}

		// Always record spent UTXOs for in-memory rollback. Without this,
		// a validation failure mid-block leaves the UTXO set corrupted
		// because spent inputs cannot be restored.
		//
		// W93 fix #1 (spentInputs/spentCoins must be 1:1):
		// Mirrors Bitcoin Core UpdateCoins (validation.cpp:1999-2011) which
		// reserves vprevout.size() == tx.vin.size() and asserts(is_spent) for
		// every input. Without 1:1 alignment, the persisted blockundo would
		// have fewer SpentCoins than tx.vin and DisconnectBlock's
		// "len(txUndo.SpentCoins) != len(tx.TxIn)" guard rejects the reorg
		// (chainmanager.go:1371). The block becomes silently UNDISCONNECTABLE
		// on the success path of ConnectBlock — a critical correctness bug.
		//
		// W93 fix #2 (PkScript slice aliasing — W82/W92 pattern):
		// utxo.PkScript points into the UTXOEntry held by cachedView /
		// cm.utxoSet. Recording the slice into storage.SpentCoin without a
		// bytes.Clone leaves the SpentCoin's PkScript aliased to that
		// backing array. Subsequent flushes/evictions in the same batch
		// could mutate (or, more commonly, drop) the entry while the
		// blockundo still references it. The block-replay-from-disk path
		// is unaffected (serialization copies bytes) but the in-memory
		// rollback path uses these PkScripts directly via AddUTXO, and
		// reorg dispatchers can re-flush before the rollback fires.
		// Clone defensively to mirror AddTxOutputs (utxoset.go:534) which
		// already clones on the outbound path.
		//
		// W93 fix #3 (loud failure on nil prevout): the previous code
		// silently elided a SpentCoin when utxo was nil. Reaching this loop
		// with a nil prevout is a consensus violation that CheckTransactionInputs
		// should have caught upstream. If somehow it leaks through, we now
		// rollback + return an error rather than mis-shape the undo data.
		spentInputs := make([]wire.OutPoint, 0, len(tx.TxIn))
		spentCoins := make([]storage.SpentCoin, 0, len(tx.TxIn))
		for _, in := range tx.TxIn {
			// W69d: Direct cache read — populated above, same UTXOs.
			utxo, ok := cachedView.cache[in.PreviousOutPoint]
			if !ok || utxo == nil {
				// Should have been caught by CheckTransactionInputs above
				// (which returned ErrMissingInput). Reaching here means a
				// gap between input-validation and spend-recording — most
				// likely a future refactor that re-orders the passes.
				// Mirrors Core's `assert(is_spent)` in UpdateCoins.
				rollbackUTXOs()
				return fmt.Errorf("tx %d: bad-txns-inputs-missingorspent: prevout %s:%d not in cached view",
					i, in.PreviousOutPoint.Hash.String()[:16], in.PreviousOutPoint.Index)
			}
			spentCoins = append(spentCoins, storage.SpentCoin{
				TxOut: wire.TxOut{
					Value:    utxo.Amount,
					PkScript: bytes.Clone(utxo.PkScript),
				},
				Height:   utxo.Height,
				Coinbase: utxo.IsCoinbase,
			})
			spentInputs = append(spentInputs, in.PreviousOutPoint)
		}

		// Persist undo data to disk only when needed (not during assume-valid IBD)
		if generateUndo {
			txUndo := storage.TxUndo{
				SpentCoins: spentCoins,
			}
			blockUndo.TxUndos = append(blockUndo.TxUndos, txUndo)
		}

		// Update UTXO view: spend inputs and add outputs.
		// CVE-2012-2459 / dup-txid fix: after spending inputs, evict them from
		// cachedView.cache so a later duplicate tx cannot find a stale "unspent"
		// entry there.  Without this, a block containing [coinbase, tx, tx] (same
		// non-coinbase tx twice) would be incorrectly accepted: the second copy's
		// inputs were still in cachedView.cache from the first copy's fetch loop,
		// so CheckTransactionInputs found them even though cm.utxoSet had already
		// marked them spent.  Core rejects via bad-txns-inputs-missingorspent in
		// ConnectBlock (validation.cpp) when the second tx finds its prevout absent.
		cm.utxoSet.SpendTxInputs(tx)
		for _, in := range tx.TxIn {
			delete(cachedView.cache, in.PreviousOutPoint)
		}
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
		// Build a read-only view that the second pass uses to look up prevouts.
		// We use scriptView (populated in the first-pass UTXO-fetch loop) rather
		// than cachedView because cachedView has spent inputs evicted for
		// CVE-2012-2459 protection.  scriptView is never modified, so outputs
		// created within this block (same-block spends) are found via the
		// cm.utxoSet fallback (they were added with AddTxOutputs in the first pass).
		scriptUTXOView := &cachedUTXOView{
			cache:    scriptView,
			fallback: cm.utxoSet,
		}
		if cm.parallelScripts {
			if err := ParallelScriptValidationCached(block, scriptUTXOView, flags, cm.sigCache); err != nil {
				rollbackUTXOs()
				return fmt.Errorf("script validation failed: %w", err)
			}
		} else {
			for i, tx := range block.Transactions {
				if i == 0 {
					continue // Skip coinbase
				}
				if err := ValidateTransactionScripts(tx, scriptUTXOView, flags); err != nil {
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
		return fmt.Errorf("%w: %d > %d (subsidy %d + fees %d)",
			ErrBadCoinbaseValue, coinbaseValue, subsidy+totalFees, subsidy, totalFees)
	}

	// Update chain state
	cm.tipNode = node
	cm.tipHeight = node.Height
	cm.updateTipCache(node.Hash, node.Height)
	// This block's UTXO mutations are now applied to the in-memory set, so
	// the coins marker any subsequent flush stamps must name this block.
	// Set on the success path only: every failure path above returns after
	// rollbackUTXOs(), leaving the marker where it was.
	//
	// ADVANCE only. A connect at or below the marker means we just re-applied
	// a block the persisted set already reflects — a bug upstream, not here —
	// and republishing the marker downwards would turn that into durable
	// corruption on the next boot. Hold the marker and let the set's true
	// high-water mark stand.
	cm.advanceAppliedTip(hash, node.Height)
	// G1/G3 fix (W101): set StatusFullyValid so recalculateBestTipLocked can
	// filter invalid-marked nodes. StatusDataStored is set further down,
	// AFTER batch.Write succeeds — see the persistence block below for why.
	node.Status |= StatusFullyValid
	// FIX-33 (W109 G14/G15): set StatusHaveUndo when undo data will be written
	// to disk as part of this block connection. Mirrors Bitcoin Core's
	// blockstorage.cpp:1029 (block.nStatus |= BLOCK_HAVE_UNDO after CBlockUndo
	// is written to rev*.dat). When generateUndo is false (assume-valid IBD),
	// no undo data is generated so the flag stays clear.
	//
	// #126: like StatusDataStored, this flag now sets on the post-batch.Write
	// path so the in-memory headerindex never advertises HAVE_UNDO before
	// the undo bytes are durable on disk.
	// (Set below, gated on batch.Write success.)

	// Exit IBD mode once the tip is recent — mirrors Core's
	// IsInitialBlockDownload max-tip-age check (validation.cpp). The old
	// condition (cm.tipHeight == cm.assumeValidHeight) was an exact equality
	// that any height skip — notably an assumeUTXO snapshot import — jumps
	// clean past, leaving the node stuck in IBD mode permanently. isIBD is
	// latched: once false, nothing here sets it true again.
	const maxTipAgeSecs = 24 * 60 * 60 // Core DEFAULT_MAX_TIP_AGE
	tipRecent := int64(cm.tipNode.Header.Timestamp) >= time.Now().Unix()-maxTipAgeSecs
	// G22 (W101): height-based assume-valid exit uses >= (Core semantics), not ==.
	// An exact equality is jumped clean past by any height skip (e.g. an
	// assumeUTXO snapshot import or a multi-block connect), leaving the node
	// stuck in IBD permanently. Mirrors Core's IsInitialBlockDownload, which
	// exits once the threshold is crossed (>=), never on an exact match.
	pastAssumeValid := cm.assumeValidHeight > 0 && cm.tipHeight >= cm.assumeValidHeight
	if cm.isIBD && (tipRecent || pastAssumeValid) {
		cm.isIBD = false
		log.Printf("chainmgr: exiting IBD mode at height %d (tip recent=%v, past-assume-valid=%v)", cm.tipHeight, tipRecent, pastAssumeValid)
	}

	// Periodic UTXO flush during IBD
	cm.blocksSinceFlush++
	shouldFlush := cm.blocksSinceFlush >= cm.flushInterval

	_phasePersistStart = time.Now() // W76: script-validation → persistence boundary

	// Persist block data atomically: block body, undo data, block height,
	// UTXO set, and chain state are written in a single batch so a crash
	// can never leave the chain tip ahead of (or behind) the UTXO set, and
	// can never leave the chainstate pointing at a hash whose body the
	// position-index lookup cannot resolve.
	//
	// #126 (2026-05-27): the block body (StoreBlockAtBatch) is now folded
	// into every batch below. Pre-#126 the body was written by sync.go's
	// HandleBlock arm at a separate non-batched callsite (StoreBlockAt),
	// and the flat-file position-index PUT was a separate non-batched
	// Pebble PUT (PebbleDB.Put runs with pebble.NoSync, so it was not
	// durable until a later batch.Write triggered a Sync). A crash between
	// those writes and ConnectBlock's chainstate batch could leave the
	// position-index PUT un-fsynced while the chainstate advanced — the
	// "tip advanced but chainDB.HasBlock=false" condition that #122
	// gated against. Folding the body into this batch closes that crash
	// window: body bytes hit blk*.dat (with fsync) immediately, and the
	// Pebble keys that let readers find them commit together with the
	// rest of the chainstate. StoreBlockAtBatch is idempotent (HasBlock
	// short-circuit), so the sync.go pre-store remains a no-op cost on
	// the hot path while still acting as side-branch staging for the
	// out-of-order-P2P-fork case that ReorgTo's GetBlock relies on.
	//
	// Mirrors haskoin f768a01 which folded PrefixBlockData into
	// connectBlockAt's WriteBatch. blockbrew's flat-file architecture
	// means the actual block bytes go to blk*.dat (not a Pebble key),
	// but every Pebble key that references those bytes is in this batch.
	//
	// Pattern D (multi-block reorg atomicity, 2026-05-05): when cm.reorgBatch
	// is set (we are inside ReorgTo), we APPEND every persistence write to
	// that shared batch instead of opening + committing our own per-block.
	// ReorgTo commits the union batch once, so a crash mid-reorg leaves the
	// on-disk state at the pre-reorg tip OR the post-reorg tip — never a
	// partial state where some blocks of the new chain are persisted but
	// others are not.
	if cm.chainDB != nil {
		if cm.reorgBatch != nil {
			// Reorg-batched path: append to the union batch ReorgTo opened.
			// UTXO flush is done ONCE at the end of ReorgTo (not per-block)
			// so the FRESH-bit dedup across the whole reorg span still works.
			//
			// #126: fold the body into the reorg union batch too. ReorgTo
			// resolves block bodies via cm.chainDB.GetBlock before each
			// inner ConnectBlock — those bodies are already on disk from
			// earlier sync.go pre-stores, so StoreBlockAtBatch is a no-op
			// here under normal operation. If a reorg replays an older
			// branch whose body was orphaned (HasBlock = false), the body
			// is restored as part of the union batch.
			if err := cm.chainDB.StoreBlockAtBatch(cm.reorgBatch, hash, block, node.Height); err != nil {
				return fmt.Errorf("failed to stage block body on reorg batch: %w", err)
			}
			if generateUndo {
				cm.chainDB.WriteBlockUndoBatch(cm.reorgBatch, hash, blockUndo)
			}
			cm.chainDB.SetBlockHeightBatch(cm.reorgBatch, node.Height, hash)
			cm.chainDB.SetChainStateBatch(cm.reorgBatch, &storage.ChainState{
				BestHash:   hash,
				BestHeight: node.Height,
			})
			// #126: set HAVE_DATA + HAVE_UNDO on the in-memory headerindex.
			// The actual on-disk commit happens later (ReorgTo's batch.Write),
			// but the reorg-as-a-whole is atomic — if it fails, the entire
			// in-memory chain state is rolled back via reorgInMemoryFallback
			// semantics (per-block disconnects + connects). Setting the bits
			// here keeps the reorg path symmetric with the regular path.
			node.Status |= StatusDataStored
			if generateUndo {
				node.Status |= StatusHaveUndo
			}
		} else {
			writeChainState := !cm.isIBD || shouldFlush

			// #126: open a batch for every connect, not just when there is
			// chainstate / undo work, so the body store can ride a batch
			// even between IBD flush intervals. Without this, blocks
			// reaching the "legacy non-batch" else-arm below (assume-valid
			// IBD between flushes, generateUndo = false) would skip the
			// atomic body-store guarantee — and a sync.go pre-store crash
			// could leave the body in flat-file but no Pebble key
			// referencing it until the next flush.
			//
			// Use NoSync for non-flush IBD batches — only the flush batch
			// (which persists chain state) needs durability.
			var batch storage.Batch
			if cm.isIBD && !shouldFlush {
				batch = cm.chainDB.NewBatchNoSync()
			} else {
				batch = cm.chainDB.NewBatch()
			}

			// Block body (idempotent: skipped if HasBlock(hash) already).
			if err := cm.chainDB.StoreBlockAtBatch(batch, hash, block, node.Height); err != nil {
				return fmt.Errorf("failed to stage block body: %w", err)
			}

			// Undo data keyed by block hash (not height, since heights can change during reorgs)
			if generateUndo {
				cm.chainDB.WriteBlockUndoBatch(batch, hash, blockUndo)
			}

			// Height -> hash mapping
			cm.chainDB.SetBlockHeightBatch(batch, node.Height, hash)

			// UTXO flush into the same atomic batch.
			//
			// DURABILITY (2026-06-06): flush the UTXO delta in the SAME synced
			// batch whenever we advance the on-disk tip pointer
			// (writeChainState), not only on the flushInterval (2000-block)
			// shouldFlush cadence. At tip (isIBD=false) writeChainState is true
			// every block, so the persisted ChainState tip used to run up to
			// flushInterval blocks AHEAD of the persisted UTXO set; an unclean
			// exit (OOM/SIGKILL, no final flush) then left the tip pointing past
			// coins that only existed in the in-memory cache, and the next block
			// failed "transaction input references missing UTXO" and wedged
			// (the recurring [CHAINSTATE-CORRUPTION] banner — h=952343 on
			// 2026-06-06, and 950146/950155/950304/952342 before it).
			//
			// writeChainState ⊇ shouldFlush (writeChainState = !isIBD ||
			// shouldFlush) and writeChainState ⟹ a Sync batch (the NoSync arm
			// above is gated on isIBD && !shouldFlush), so the UTXO delta always
			// rides a durable batch together with the tip. FlushBatch is
			// incremental (writes only the dirty set, then clears it), so at tip
			// this costs one block's coins per ~10 min; during IBD writeChainState
			// only fires on shouldFlush, so the 2000-block cadence is unchanged.
			// Mirrors Bitcoin Core's invariant that CoinsTip's best-block is
			// flushed atomically with the coins and never trails the active tip
			// on disk (validation.cpp FlushStateToDisk).
			if writeChainState {
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

			// #126: now that body + position index + undo + height + UTXO +
			// chainstate are atomically durable, set the in-memory
			// HAVE_DATA + HAVE_UNDO flags. Previously these were set BEFORE
			// the batch.Write, which left a window where a write failure
			// returned an error but the in-memory headerindex already
			// advertised data presence. Mirrors Bitcoin Core's
			// ReceivedBlockTransactions + blockstorage.cpp:1029 ordering:
			// the in-memory flag transition follows the durable on-disk
			// write.
			node.Status |= StatusDataStored
			if generateUndo {
				node.Status |= StatusHaveUndo
			}

			if shouldFlush {
				log.Printf("chainmgr: UTXO flush at height %d (atomic)", cm.tipHeight)
			}
		}
	} else {
		// No chainDB attached (some unit tests): the body is in memory only,
		// but downstream callers that probe StatusDataStored treat "nil
		// chainDB" as "always durable" (see the pre-#126 HasBlock guard).
		// Preserve that behavior so the test paths don't regress.
		node.Status |= StatusDataStored
		if generateUndo {
			node.Status |= StatusHaveUndo
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

	// Pattern C0 closure (2026-05-05): hand the just-connected block to the
	// onBlockConnected callback for txindex writes. Captured here, fired
	// post-unlock by the deferred dispatcher at the top of this function so
	// the hook can take its own locks (chainDB batch commit) without
	// lock-order risk against cm.mu.
	// Cross-impl reference: bitcoin-core/src/index/txindex.cpp.
	if cm.onBlockConnected != nil {
		connectedBlock = block
		connectedHeight = node.Height
		connectedCB = cm.onBlockConnected
	}

	return nil
}

// ErrSideBranchAccepted is a sentinel returned by ProcessSubmittedBlock when
// a block has been validated and stored as a side-branch (heavier ancestor
// chain has not yet overtaken the active tip). Callers should map this to
// BIP-22's "inconclusive" result string per Bitcoin Core's
// rpc/mining.cpp::submitblock convention.
//
// This is the Pattern Y closure for blockbrew — see
// CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md and
// rustoshi 68a422b for the cross-impl reference fix. Pre-fix, blockbrew
// rejected any block whose parent was not on the active chain with a
// generic "rejected" string, even if the parent was already in the header
// index. Post-fix, side-branch blocks are stored + indexed (HAVE_DATA in
// Core's CBlockIndex parlance) and a reorg fires later if a heavier branch
// arrives — mirroring `BlockManager::AcceptBlock` in validation.cpp where
// storage and best-chain selection are decoupled.
var ErrSideBranchAccepted = fmt.Errorf("block accepted as side-branch")

// ProcessSubmittedBlock handles an externally-submitted block (RPC submitblock
// path). Unlike ConnectBlock which only extends the active tip, this method
// also accepts side-branch blocks (parent in header index but not on active
// chain) and triggers a reorg when the new branch becomes heaviest.
//
// Caller contract:
//   - The block has already passed CheckBlockSanity.
//   - The header has already been added to the header index (so we can look
//     up its node and TotalWork).
//   - The full block body has already been persisted via chainDB.StoreBlock.
//
// Return values (mirrors Bitcoin Core's submitblock return convention):
//   - nil                       → block accepted, became part of active chain.
//   - ErrSideBranchAccepted     → block stored on a non-active branch
//     (caller should return BIP-22 "inconclusive").
//   - other error               → validation/connection failure; caller maps
//     via bip22ResultString.
//
// Reference: bitcoin-core/src/validation.cpp::AcceptBlock + ActivateBestChain.
// Storage and best-chain selection are decoupled in Core; this method
// brings blockbrew's submitblock path into parity.
func (cm *ChainManager) ProcessSubmittedBlock(block *wire.MsgBlock) error {
	hash := block.Header.BlockHash()
	newNode := cm.headerIndex.GetNode(hash)
	if newNode == nil {
		return fmt.Errorf("block %s not found in header index", hash.String())
	}

	// Snapshot current tip under read lock — both decision branches release
	// before re-acquiring under their own locking discipline.
	cm.mu.RLock()
	tipNode := cm.tipNode
	tipWork := cm.tipNode.TotalWork
	cm.mu.RUnlock()

	// Happy path: block extends current active tip → connect inline, THROUGH
	// THE MARKER GATE. submitblock, submitblock batch and the post-IBD P2P
	// connect loop all land here, and "extends the active tip" is not the same
	// claim as "is not already in the persisted UTXO set" whenever the tip sits
	// below the coins marker (a halted recovery). See ConnectOrAdoptBlock.
	if newNode.Parent == tipNode {
		return cm.ConnectOrAdoptBlock(block)
	}

	// Side-branch: parent is in the header index but not the active tip.
	// Two sub-cases per Core's ActivateBestChain logic:
	//
	//   (a) New branch has STRICTLY MORE work than active tip → reorg.
	//   (b) New branch has equal or less work → store as side-branch and
	//       return "inconclusive" per BIP-22; the block already has a node
	//       in the header index (with TotalWork) and its body persisted on
	//       disk, so a later submission that extends this branch and tips
	//       the work balance can trigger a reorg via this same method.
	if newNode.TotalWork.Cmp(tipWork) > 0 {
		log.Printf("chainmgr: submitblock-triggered reorg target=%s height=%d work=%s tip_work=%s",
			hash.String()[:16], newNode.Height, newNode.TotalWork.String(), tipWork.String())
		return cm.ReorgTo(newNode)
	}

	// Side-branch stored, no reorg.
	log.Printf("chainmgr: submitblock side-branch stored hash=%s height=%d (tip stays at %s height=%d)",
		hash.String()[:16], newNode.Height, tipNode.Hash.String()[:16], tipNode.Height)
	return ErrSideBranchAccepted
}

// IsIBD returns whether the node is in Initial Block Download mode.
func (cm *ChainManager) IsIBD() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.isIBD
}

// IsPruning reports whether the node is pruning block/undo data (-prune=N,
// N>0). Fixed at construction from ChainManagerConfig.PruningEnabled, so no
// lock is needed. The P2P fork-download descent (p2p/sync.go) consults this to
// decide whether the MaxReorgDepth cap applies: an ARCHIVE node retains every
// undo record and, like Bitcoin Core, follows the most-work valid chain to ANY
// depth, so its below-tip fork download must NOT be depth-capped (else it would
// strand on the minority chain — the same Class-A divergence ReorgTo's
// pruning-gated cap already avoids). A PRUNED node keeps the cap.
func (cm *ChainManager) IsPruning() bool {
	return cm.pruningEnabled
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

// IsTooFarAhead reports whether blockHeight is too far ahead of activeHeight
// for an unrequested block to be admitted. Mirrors Bitcoin Core
// validation.cpp:4325:
//
//	bool fTooFarAhead{pindex->nHeight > ActiveHeight() + int(MIN_BLOCKS_TO_KEEP)};
//	if (!fRequested) {
//	    ...
//	    if (fTooFarAhead) return true;
//	    ...
//	}
//
// MIN_BLOCKS_TO_KEEP == storage.MinBlocksToKeep == 288. The check only
// applies to unrequested (P2P-inv-driven) blocks; submitblock RPC and
// in-order IBD blocks are exempt because they are always "requested" in
// Core's terms.
func IsTooFarAhead(blockHeight, activeHeight int32) bool {
	return blockHeight > activeHeight+int32(storage.MinBlocksToKeep)
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

// RecoverFromPersistedBlocks replays block bodies that were durably written to
// the block store + height index but sit AHEAD of the flushed chain-state tip.
//
// During IBD the block body + undo + height->hash map are written every block
// (NoSync batch — survives a SIGKILL/OOM via the OS page cache), but the
// chain-state tip pointer + UTXO flush only fire on the flushInterval cadence
// (writeChainState = !isIBD || shouldFlush), because the tip pointer must never
// lead the persisted UTXO on disk (the tip-ahead-of-UTXO corruption invariant —
// see ConnectBlock lines ~1110-1131). An unclean crash between flushes therefore
// boots to the last flush even though every block up to the crash height is on
// disk; without this replay the node re-downloads that gap (up to flushInterval
// blocks) from peers — or, when the last flush was genesis, boots all the way to
// height 0 (the "comes up at 0 despite an intact datadir" failure the W16/W17
// hydration work only partially closed: HydrateFromDB walks BACKWARD from the
// flushed tip, so it never reaches blocks persisted ahead of it).
//
// This walks the height index FORWARD from the current (flushed) tip, rebuilds
// the missing header-index nodes from the persisted bodies, and re-connects each
// block through the normal ConnectBlock path (full re-validation; UTXO applied
// in memory). It then flushes the UTXO and advances the on-disk chain-state
// pointer so the recovered tip is durable. Mirrors Bitcoin Core, which on
// startup rolls the chainstate forward over block files from the last flushed
// best-block (validation.cpp LoadChainTip / RollforwardBlock).
//
// SAFE on every boot: on a fresh datadir or a clean shutdown the next height is
// absent from the index, so the loop is a no-op (0 replayed). It only ever
// replays blocks already on disk and already validated once, in order, stopping
// at the first gap/unreadable body/validation error (then the node falls back to
// normal P2P sync for the remainder). Must be called once at startup BEFORE the
// P2P/sync layer starts and before the per-block index callbacks are wired (the
// secondary indexes catch up to the recovered tip via their own startup sync).
func (cm *ChainManager) RecoverFromPersistedBlocks() (int, error) {
	if cm.chainDB == nil {
		return 0, nil
	}

	// Phase 1 — rebuild the header index from the durable height->hash map + block
	// bodies, for blocks the backward HydrateFromDB walk couldn't reach. The
	// header index is hydrated by walking the SEPARATE header store
	// (MakeBlockHeaderKey), which is written by P2P header sync — NOT by
	// ConnectBlock. So blocks accepted via submitblock/mining (or after a header-
	// store loss) leave no header-store entry, and HydrateFromDB stops short even
	// though the body + height map are durable. Rebuild from the bodies (AddHeader
	// only — no UTXO mutation), in ascending height so each connects to its parent.
	rebuilt := 0
	for {
		next := cm.headerIndex.BestHeight() + 1
		hash, err := cm.chainDB.GetBlockHashByHeight(next)
		if err != nil {
			break // no persisted block at this height
		}
		if cm.headerIndex.GetNode(hash) != nil {
			break // already present but BestHeight didn't advance — avoid a loop
		}
		block, err := cm.chainDB.GetBlock(hash)
		if err != nil || block == nil {
			break
		}
		if _, err := cm.headerIndex.AddHeader(block.Header, true); err != nil {
			log.Printf("chainmgr: recovery: AddHeader at height %d failed (%v); stopping header rebuild", next, err)
			break
		}
		rebuilt++
	}

	// Phase 2 — now that the header index reaches the persisted chainstate tip,
	// re-resolve the in-memory tip from the (UTXO-consistent) saved chain state.
	// ReloadChainState's happy path adopts the saved tip once its node is present.
	if rebuilt > 0 && cm.tipHeight == 0 {
		cm.ReloadChainState()
	}

	// Phase 3 — replay any block bodies AHEAD of the flushed chainstate tip (the
	// genuine IBD unflushed-gap case: during IBD the body + height map are written
	// every block but the chainstate pointer + UTXO flush only on the ~2000-block
	// cadence). No-op in the at-tip/submitblock case where the chainstate already
	// covers the bodies.
	//
	// WHICH BLOCKS ARE ALREADY APPLIED IS DECIDED BY THE COINS MARKER, NOT BY A
	// CONNECT ERROR (fix, 2026-09-02).
	//
	// The chain-tip pointer is only a LOWER bound on what the persisted UTXO set
	// reflects: coins are also flushed without advancing it (cache pressure,
	// scantxoutset, the IBD cadence), so blocks above the pointer may or may not
	// already be in the set. The old loop resolved that by calling ConnectBlock
	// first and routing to AdoptAppliedBlock only when ConnectBlock returned
	// "references missing UTXO" — i.e. it inferred "already applied" from a
	// block tripping over its OWN already-applied spends.
	//
	// A coinbase-only block (nTx=1) has no inputs, so it can never trip that
	// error. ConnectBlock always succeeded and re-applied it, and AddUTXO put
	// its coinbase output back — including when a later block had already spent
	// it. That is a coin conjured out of nothing, under a correct-looking tip
	// and block hash, invisible to BIP-30 (BIP-34 is active and these heights
	// are below the 1,983,702 re-enforcement limit). Observed on the 2026-08-15
	// genesis rig: 958187/958693/958762 were the three blocks of 794 that did
	// NOT log "ADOPTED already-applied", all nTx=1, and 958187's coinbase
	// f29f7086…bea0:0 (3.125 BTC) — spent well before 958,794 and absent from
	// Core's C(958794) — came back: 166,180,925 -> 166,180,926, set hash
	// 29692050…7af0 -> 24ec9202…7a5a.
	//
	// Bitcoin Core never asks the question this way. Its coins database carries
	// its own best-block marker written in the SAME batch as the coin writes
	// (txdb.cpp:158-159, DB_BEST_BLOCK in the final CDBBatch of BatchWrite), it
	// boots the chainstate AT that marker (validation.cpp:4546 LoadChainTip:
	// `m_chain.SetTip(*m_blockman.LookupBlockIndex(coins_cache.GetBestBlock()))`),
	// and ReplayBlocks (validation.cpp:4773) rolls forward only the blocks in
	// the recorded interrupted-flush window — never anything the marker already
	// covers. blockbrew now keeps the same marker (storage.CoinsTipKey, stamped
	// by UTXOSet on every flush) and asks it BEFORE attempting to connect:
	//
	//   height <= coins marker  -> already in the persisted set. Advance the
	//                              tip only (AdoptFlushedBlock). No re-apply.
	//   height >  coins marker  -> genuinely unapplied. ConnectBlock, with the
	//                              existing evidence + tolerant-roll-forward
	//                              adoption still covering a torn flush inside
	//                              that window (Core's ReplayBlocks role).
	//
	// Datadirs written before the marker existed report it absent, and fall back
	// to exactly the previous behaviour.
	replayed := 0
	coinsHash, coinsHeight, haveCoinsMarker := cm.durableCoinsTip()
	if haveCoinsMarker {
		_, tipH := cm.BestBlock()
		if coinsHeight > tipH {
			log.Printf("chainmgr: recovery: coins marker at height %d (%s) leads the "+
				"chain-tip pointer at height %d — blocks up to the marker are already "+
				"in the persisted UTXO set and will be adopted, not re-applied",
				coinsHeight, coinsHash.String()[:16], tipH)
		}
	}
	for {
		_, height := cm.BestBlock()
		next := height + 1
		hash, err := cm.chainDB.GetBlockHashByHeight(next)
		if err != nil {
			break
		}
		block, err := cm.chainDB.GetBlock(hash)
		if err != nil || block == nil {
			break
		}
		if cm.headerIndex.GetNode(hash) == nil {
			if _, err := cm.headerIndex.AddHeader(block.Header, true); err != nil {
				log.Printf("chainmgr: recovery: AddHeader (replay) at height %d failed (%v); stopping", next, err)
				break
			}
		}
		// Already reflected in the persisted set: advance the tip over it and
		// touch nothing else. `hash` came from the same height->hash map that
		// durableCoinsTip validated the marker against, so next <= coinsHeight
		// means this block is an ancestor-or-self of the marker on this chain.
		if haveCoinsMarker && next <= coinsHeight {
			adopted, err := cm.AdoptIfAlreadyFlushed(block)
			if err != nil {
				log.Printf("chainmgr: recovery: AdoptFlushedBlock at height %d failed (%v); stopping replay", next, err)
				break
			}
			if !adopted {
				log.Printf("chainmgr: recovery: coins marker covers height %d but the block "+
					"there is not provably the one it covers; stopping replay", next)
				break
			}
			replayed++
			continue
		}
		if err := cm.ConnectBlock(block); err != nil {
			// MARKER-LAG REPAIR (2026-08-15): "missing UTXO" here usually
			// means this block was ALREADY APPLIED in a prior session and
			// only the chainstate pointer lagged (the 2026-08-14 genesis
			// rig: coins flushed through 958,794, pointer at 958,000 — the
			// replay then hit its own already-applied spends and the old
			// code halted with a false corruption verdict). Adopt on
			// positive evidence (one of the block's own outputs present in
			// the set proves its batch committed); anything unprovable
			// still stops the replay exactly as before.
			if strings.Contains(err.Error(), "references missing UTXO") {
				if adoptErr := cm.AdoptAppliedBlock(block); adoptErr == nil {
					replayed++
					continue
				}
			}
			log.Printf("chainmgr: recovery: ConnectBlock at height %d failed (%v); stopping replay", next, err)
			break
		}
		replayed++
	}
	if replayed > 0 {
		// Make the replayed tip durable: flush the UTXO FIRST, then advance the
		// on-disk chainstate pointer, so a crash mid-recovery never leaves the tip
		// pointing past coins that are only in memory (the ConnectBlock invariant).
		cm.flushUTXOs()
		hash, height := cm.BestBlock()
		if err := cm.chainDB.SetChainState(&storage.ChainState{BestHash: hash, BestHeight: height}); err != nil {
			log.Printf("chainmgr: recovery: SetChainState after replay failed: %v", err)
		}
	}

	if rebuilt > 0 || replayed > 0 {
		_, height := cm.BestBlock()
		log.Printf("chainmgr: crash recovery: rebuilt %d header(s) + replayed %d block(s) from disk; tip now at height %d",
			rebuilt, replayed, height)
	}
	return rebuilt + replayed, nil
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

// SetOnBlockDisconnected installs (or replaces) the block-disconnected
// callback after construction. The callback fires once per block popped off
// the active tip in DisconnectBlock, including each peel inside ReorgTo.
// Used by main.go to wire chain manager → mempool refill (Pattern B closure).
func (cm *ChainManager) SetOnBlockDisconnected(cb func(block *wire.MsgBlock, height int32)) {
	cm.mu.Lock()
	cm.onBlockDisconnected = cb
	cm.mu.Unlock()
}

// SetOnBlockConnected installs (or replaces) the block-connected callback
// after construction. The callback fires once per block successfully
// connected to the active tip in ConnectBlock, including each replay inside
// ReorgTo. Used by main.go to wire chain manager → txindex writes
// (Pattern C0 closure for blockbrew).
//
// Reference: bitcoin-core/src/index/txindex.cpp + index/base.cpp.
// Cross-impl: stacks on top of SetOnBlockDisconnected (Pattern B, 72c23be)
// using the identical post-unlock dispatch discipline.
func (cm *ChainManager) SetOnBlockConnected(cb func(block *wire.MsgBlock, height int32)) {
	cm.mu.Lock()
	cm.onBlockConnected = cb
	cm.mu.Unlock()
}

// CurrentReorgBatch returns the per-reorg shared persistence batch when the
// chain manager is mid-reorg, or nil otherwise. Used by external secondary
// indexes (BIP-157 blockfilterindex Phase 2, future BIP-158 follow-ups)
// whose connect/disconnect hooks need to ride the same Pebble batch as the
// UTXO + chainstate + undo-data rewind so a multi-block reorg commits
// atomically.
//
// Locking discipline: the OnBlockConnected / OnBlockDisconnected hooks fire
// AFTER cm.mu is released by the dispatcher in ConnectBlock /
// DisconnectBlock, but BEFORE ReorgTo's batch.Write() lands. Read here
// under cm.mu so the hook sees a coherent (nil OR live-shared) batch
// pointer; once the hook captures the pointer, it is safe to use until
// ReorgTo's deferred dispatcher clears cm.reorgBatch (which only happens
// after the synchronous batch.Write in the success path, or after the
// error path returns to the caller).
//
// Returns nil when called outside of a ReorgTo. The hook is responsible for
// falling back to its own per-block batch in that case.
//
// Cross-impl reference: bitcoin-core/src/validation.cpp::ActivateBestChain
// holds a single CDBBatch across DisconnectTip / ConnectTip and the
// secondary-index fan-out via CValidationInterface composes into the same
// batch by Reading cm.reorgBatch's analog through the ChainstateManager.
func (cm *ChainManager) CurrentReorgBatch() storage.Batch {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.reorgBatch
}

// DisconnectBlock undoes the effects of a block (for reorgs).
// It removes outputs created by the block and restores spent UTXOs from undo data.
// Transactions must be disconnected in reverse order to correctly restore the UTXO set.
//
// On a successful disconnect, fires the OnBlockDisconnected callback (if
// configured) with the just-popped block and its pre-disconnect height. The
// callback is invoked OUTSIDE cm.mu — primary current consumer is the
// mempool refill helper (mp.BlockDisconnected) which takes its own lock and
// must not contend with cm.mu. See Pattern B closure (CORE-PARITY-AUDIT
// _mempool-refill-on-reorg-fleet-result-2026-05-05.md) and Bitcoin Core's
// MaybeUpdateMempoolForReorg in validation.cpp.
func (cm *ChainManager) DisconnectBlock(hash wire.Hash256) error {
	if !cm.beginMutation() {
		return ErrShuttingDown
	}
	defer cm.endMutation()

	// disconnectedBlock and disconnectedHeight are captured under the lock
	// and used to fire the OnBlockDisconnected callback after the lock is
	// released. Zero values mean "no callback fire" (early-return path).
	var (
		disconnectedBlock  *wire.MsgBlock
		disconnectedHeight int32
		disconnectedCB     func(*wire.MsgBlock, int32)
	)
	defer func() {
		// Fire post-unlock so the callback (e.g. mempool refill) can take
		// its own locks freely without lock-order risk against cm.mu.
		if disconnectedCB != nil && disconnectedBlock != nil {
			disconnectedCB(disconnectedBlock, disconnectedHeight)
		}
	}()

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

	// Verify undo data consistency.
	// Mirrors Core validation.cpp:2190 "vtxundo.size() + 1 != vtx.size()".
	nonCoinbaseTxCount := len(block.Transactions) - 1
	if nonCoinbaseTxCount < 0 {
		nonCoinbaseTxCount = 0
	}
	if len(blockUndo.TxUndos) != nonCoinbaseTxCount {
		return fmt.Errorf("undo data mismatch: %d TxUndos but %d non-coinbase transactions",
			len(blockUndo.TxUndos), nonCoinbaseTxCount)
	}

	// BIP-30 exception: the two historical mainnet blocks at heights 91722
	// and 91812 contained coinbase transactions that duplicated the txid of
	// an earlier (still-unspent) coinbase. When we disconnect one of these
	// blocks the output-identity check below will see the "wrong" coin
	// metadata in the UTXO set — that is expected. Skip the inconsistency
	// signal in that one case (mirrors Core validation.cpp:2201-2202).
	tipHeight := cm.tipNode.Height
	enforceBIP30 := !IsBIP30Unspendable(tipHeight, hash)

	// Track DisconnectResult-equivalent. Even if fClean goes false we still
	// finish the rollback — Core treats UNCLEAN as a successful disconnect
	// (the chain state advances; we just log the inconsistency).
	fClean := true

	// Process transactions in REVERSE order (critical for correct UTXO restoration).
	// Mirrors Core validation.cpp:2205-2242.
	for i := len(block.Transactions) - 1; i >= 0; i-- {
		tx := block.Transactions[i]
		txHash := tx.TxHash()
		isCoinbase := i == 0 // tx 0 is the coinbase by consensus
		isBIP30Exception := isCoinbase && !enforceBIP30

		// Check that all outputs are available and match the outputs in the
		// block itself exactly. Mirrors Core validation.cpp:2213-2224. We use
		// SpendUTXOWithCoin so we can compare height + coinbase + value +
		// script of the coin we're removing.
		for idx, out := range tx.TxOut {
			if IsUnspendable(out.PkScript) {
				continue
			}
			outpoint := wire.OutPoint{Hash: txHash, Index: uint32(idx)}
			coin, isSpent := cm.utxoSet.SpendUTXOWithCoin(outpoint)
			if !isSpent || coin == nil {
				if !isBIP30Exception {
					fClean = false
				}
				continue
			}
			// Identity check: value + script + height + coinbase must match.
			if coin.Amount != out.Value ||
				!bytes.Equal(coin.PkScript, out.PkScript) ||
				coin.Height != tipHeight ||
				coin.IsCoinbase != isCoinbase {
				if !isBIP30Exception {
					fClean = false
				}
			}
		}

		// For non-coinbase transactions, restore the inputs that were spent.
		if i > 0 {
			// Get the TxUndo for this transaction (i-1 because index 0 is coinbase)
			txUndo := &blockUndo.TxUndos[i-1]

			// Verify input count matches. Mirrors Core validation.cpp:2229.
			if len(txUndo.SpentCoins) != len(tx.TxIn) {
				return fmt.Errorf("tx %d undo mismatch: %d spent coins but %d inputs",
					i, len(txUndo.SpentCoins), len(tx.TxIn))
			}

			// REVERSE iteration over inputs. Mirrors Core validation.cpp:2233-2239
			// ("for (unsigned int j = tx.vin.size(); j > 0;)").
			// While the end-state UTXO set is order-independent for normal txs,
			// the reverse order matters under BIP-30 collisions and during
			// ApplyTxInUndo's overwrite detection — if a tx spends two inputs
			// that resolve to the same outpoint (degenerate), restoring in
			// reverse preserves LIFO semantics with the original spend order.
			for j := len(tx.TxIn); j > 0; j-- {
				idx := j - 1
				spentCoin := &txUndo.SpentCoins[idx]
				outpoint := tx.TxIn[idx].PreviousOutPoint
				// W93 fix #6 (PkScript aliasing on disconnect — W82/W92 pattern):
				// clone the script when handing it to the UTXOSet cache so the
				// downstream cache entry has its own backing buffer. The
				// deserialized SpentCoin slice may be freed/recycled when
				// txUndo goes out of scope (escape analysis may keep it live in
				// practice today, but the contract is fragile). Mirrors the
				// clone discipline used by AddTxOutputs (utxoset.go:534).
				undoEntry := &UTXOEntry{
					Amount:     spentCoin.TxOut.Value,
					PkScript:   bytes.Clone(spentCoin.TxOut.PkScript),
					Height:     spentCoin.Height,
					IsCoinbase: spentCoin.Coinbase,
				}
				clean, ok := cm.utxoSet.ApplyTxInUndo(undoEntry, outpoint)
				if !ok {
					// Sibling-recovery failed; mirrors Core's DISCONNECT_FAILED.
					return fmt.Errorf("disconnect failed: missing undo metadata for %s:%d (no unspent sibling)",
						outpoint.Hash.String()[:16], outpoint.Index)
				}
				if !clean {
					fClean = false
				}
			}
		}
		// Coinbase (i == 0) has no inputs to restore — we just removed its
		// outputs above.
	}

	if !fClean {
		// Log but do not error. Mirrors Core's DISCONNECT_UNCLEAN: the
		// chainstate write still lands, but the inconsistency is recorded.
		// Typically only fires for BIP-30 collision aftermath (h=91722/91812)
		// during deep reorg tests.
		log.Printf("chainmgr: DisconnectBlock unclean for %s at h=%d (BIP-30 aftermath or undo-mismatch)",
			hash.String()[:16], tipHeight)
	}

	// Delete undo data from database.
	//
	// Pattern D (multi-block reorg atomicity, 2026-05-05): when cm.reorgBatch
	// is set, the delete rides the shared batch so the multi-block reorg is
	// one atomic Pebble commit. Outside ReorgTo we still issue an individual
	// Delete (preserves the pre-existing single-disconnect API).
	if cm.reorgBatch != nil {
		cm.chainDB.DeleteBlockUndoBatch(cm.reorgBatch, hash)
	} else {
		if err := cm.chainDB.DeleteBlockUndo(hash); err != nil {
			log.Printf("chainmgr: warning: failed to delete undo data for %s: %v", hash.String()[:16], err)
		}
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

	prevHeight := cm.tipNode.Height
	cm.tipNode = parent
	cm.tipHeight = parent.Height
	cm.updateTipCache(parent.Hash, parent.Height)
	// The undo above removed this block's mutations from the set, so the
	// coins marker must come DOWN with the tip. Leaving it high would let a
	// later flush publish a marker claiming a block that has been undone is
	// still reflected — recovery would then adopt it instead of re-applying.
	cm.setAppliedTip(parent.Hash, parent.Height)

	// Persist updated chain state.
	//
	// Pattern D: under ReorgTo we append the (intermediate) chainstate write
	// to the shared batch — it will be overwritten by later DisconnectBlock
	// peels and finally by the new-tip ConnectBlock writes within the same
	// batch. Pebble's batch dedups in-key Puts, so only the final value lands
	// on disk. Outside ReorgTo we issue a direct Put as before.
	if cm.chainDB != nil {
		if cm.reorgBatch != nil {
			cm.chainDB.SetChainStateBatch(cm.reorgBatch, &storage.ChainState{
				BestHash:   parent.Hash,
				BestHeight: parent.Height,
			})
		} else {
			cm.chainDB.SetChainState(&storage.ChainState{
				BestHash:   parent.Hash,
				BestHeight: parent.Height,
			})
		}
	}

	// Pattern B closure (2026-05-05): hand the disconnected block to the
	// mempool-refill callback. Captured here, fired post-unlock by the
	// deferred dispatcher at the top of this function so the hook can
	// take its own locks (mp.mu) without lock-order risk against cm.mu.
	// Cross-impl reference: camlcoin lib/sync.ml:2354-2363.
	if cm.onBlockDisconnected != nil {
		disconnectedBlock = block
		disconnectedHeight = prevHeight
		disconnectedCB = cm.onBlockDisconnected
	}

	return nil
}

// ErrShuttingDown is returned by chain-mutating entry points once shutdown has
// begun. Callers should treat it as "the node is going away", not as a
// validation failure.
var ErrShuttingDown = errors.New("chain manager is shutting down")

// beginMutation registers an in-flight chain mutation. It returns false when
// the node is quiescing for shutdown, in which case the caller MUST return
// without touching chain state.
//
// The flag is re-checked after the Add: QuiesceForShutdown latches the flag
// before it waits, so a mutation that slipped past the first check but landed
// after Wait() returned would otherwise escape the barrier entirely.
func (cm *ChainManager) beginMutation() bool {
	if cm.quiescing.Load() {
		return false
	}
	cm.mutationWG.Add(1)
	if cm.quiescing.Load() {
		cm.mutationWG.Done()
		return false
	}
	return true
}

// endMutation retires an in-flight chain mutation.
func (cm *ChainManager) endMutation() { cm.mutationWG.Done() }

// QuiesceForShutdown latches out new chain mutations and waits for in-flight
// ones to finish. It reports whether the chain reached rest within timeout.
//
// A FALSE RETURN MEANS A MUTATION IS STILL RUNNING, AND THE CALLER MUST NOT
// FLUSH CHAINSTATE. A rollback or reorg caught mid-flight has an in-memory
// UTXO set and a tip pointer that disagree; persisting that pair produces a
// chainstate which validates against neither height.
//
// That is not a theoretical concern. On 2026-07-27 genesis-blockbrew took
// SIGTERM while an InvalidateBlock rollback was in flight. Shutdown gave up on
// the RPC ("RPC server stop error: context deadline exceeded"), flushed
// "chainstate atomically (UTXO + tip) at height 959906" anyway, and closed
// Pebble — whereupon the still-running disconnect loop hit the closed DB and
// died with `fatal error: sync: Unlock of unlocked RWMutex`. The node came
// back with an unrecoverable [CHAINSTATE-CORRUPTION] wedge and an 83-hour
// from-genesis datadir was lost.
//
// Declining to flush is always the safe branch: blockbrew recovers by
// replaying from the last atomic flush, so the cost of a false return is
// replay time, never correctness.
func (cm *ChainManager) QuiesceForShutdown(timeout time.Duration) bool {
	cm.quiescing.Store(true)

	done := make(chan struct{})
	go func() {
		cm.mutationWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// ErrReorgTooDeep is returned by ReorgTo when the requested reorg span
// (disconnect_count + connect_count) exceeds MaxReorgDepth. Splitting a
// reorg across multiple Pebble commits would forfeit the multi-block
// atomicity Pattern D was added for, so we refuse loudly instead.
var ErrReorgTooDeep = errors.New("reorg span exceeds MaxReorgDepth")

// ReorgTo reorganizes the chain to a new tip.
//
// Pattern D — multi-block reorg atomicity (2026-05-05).
// The disconnect of N old-tip blocks and the connect of M new-branch blocks
// are accumulated into a SINGLE Pebble batch and committed once at the end.
// Crash semantics: a process crash at any point before the final batch.Write()
// returns leaves on-disk state at the pre-reorg tip; success leaves it at the
// post-reorg tip. There is no on-disk state where the chainstate has advanced
// past the fork but per-block undo deletions or UTXO mutations are partial.
//
// MaxReorgDepth caps the span: a reorg that would require disconnect+connect
// of more than MaxReorgDepth blocks returns ErrReorgTooDeep rather than
// splitting the work across multiple commits (which would defeat the
// atomicity guarantee). This is an impl-specific bound; Core has no cap.
//
// Cross-impl: validation.cpp::ActivateBestChain holds a single CDBBatch
// across all DisconnectTip / ConnectTip calls inside one activation; we
// mirror that by parking the batch on cm.reorgBatch and having the per-block
// helpers read it under cm.mu.
func (cm *ChainManager) ReorgTo(newTip *BlockNode) error {
	if !cm.beginMutation() {
		return ErrShuttingDown
	}
	defer cm.endMutation()

	// Serialize against any concurrent ReorgTo. Two reorgs would otherwise
	// share cm.reorgBatch and tangle their writes; the chainstate write at
	// the end would race and one of the new-tip key chains would land
	// half-committed. cm.reorgMu is separate from cm.mu so per-block
	// helpers can take cm.mu under it without recursive-lock issues.
	cm.reorgMu.Lock()
	defer cm.reorgMu.Unlock()

	return cm.reorgToLocked(newTip)
}

// reorgToLocked is ReorgTo's body. The caller MUST already hold cm.reorgMu.
//
// This split exists so the other chain-rewinding entry points —
// InvalidateBlock and ReconsiderBlock — can hold cm.reorgMu across their
// WHOLE operation (see the incident note on InvalidateBlock) and still reorg
// internally, without deadlocking on Go's non-reentrant mutex.
func (cm *ChainManager) reorgToLocked(newTip *BlockNode) error {
	cm.mu.Lock()
	currentTip := cm.tipNode
	cm.mu.Unlock()

	// Find the fork point
	fork := FindFork(currentTip, newTip)
	if fork == nil {
		return fmt.Errorf("no common ancestor found")
	}

	// Build disconnect + connect plans before touching state. We need both
	// counts up front for the MaxReorgDepth bound check.
	disconnectNodes := make([]*BlockNode, 0)
	for node := currentTip; node != fork; node = node.Parent {
		disconnectNodes = append(disconnectNodes, node)
	}
	connectNodes := make([]*BlockNode, 0)
	for node := newTip; node != fork; node = node.Parent {
		connectNodes = append(connectNodes, node)
	}
	// Reverse to connect in order (fork+1 .. newTip).
	for i, j := 0, len(connectNodes)-1; i < j; i, j = i+1, j-1 {
		connectNodes[i], connectNodes[j] = connectNodes[j], connectNodes[i]
	}

	// The reorg-depth cap applies ONLY when pruning. On an archive node every
	// undo record is on disk, so — like Bitcoin Core, which has no reorg-depth
	// cap — we follow the most-work valid chain to any depth. On a pruned node
	// the cap protects against reorging deeper than the retained undo window.
	span := len(disconnectNodes) + len(connectNodes)
	if cm.pruningEnabled && span > MaxReorgDepth {
		log.Printf("chainmgr: refusing reorg from %d to %d: span=%d exceeds MaxReorgDepth=%d (pruned node; undo beyond the retained window is gone)",
			currentTip.Height, newTip.Height, span, MaxReorgDepth)
		return fmt.Errorf("%w: span=%d limit=%d", ErrReorgTooDeep, span, MaxReorgDepth)
	}

	log.Printf("chainmgr: reorg from height %d to %d (fork at %d, disconnect=%d connect=%d)",
		currentTip.Height, newTip.Height, fork.Height,
		len(disconnectNodes), len(connectNodes))

	// Open the union batch. Sync mode (durable) — a reorg unwinds visible
	// state, so the post-commit fsync is non-negotiable. cm.reorgBatch is
	// installed under cm.mu so per-block helpers see it consistently.
	if cm.chainDB == nil {
		// In-memory ChainDB-less paths (some tests) keep the per-call
		// behavior since there is no batch to share.
		return cm.reorgInMemoryFallback(disconnectNodes, connectNodes)
	}
	// Indexed batch: each ConnectBlock during this reorg stages its undo data
	// into this shared batch (WriteBlockUndoBatch), and the coinstatsindex
	// connect hook reads that just-staged undo back via ReadBlockUndoFromBatch
	// to subtract spent coins from its running MuHash. A plain (write-only)
	// batch's Get cannot observe pending writes, so the hook would read
	// ErrNotFound for every reconnected block and serve a stale, chain-A
	// MuHash after the reorg (the REORG-RECONNECT desync). Indexed-batch Get
	// layers the batch's pending undo over disk, so B's reconnected blocks get
	// their real undo. Mirrors Core's CoinStatsIndex CustomAppend running on
	// each connected B block during ActivateBestChain.
	batch := cm.chainDB.NewIndexedBatch()

	cm.mu.Lock()
	if cm.reorgBatch != nil {
		cm.mu.Unlock()
		// Should be impossible thanks to reorgMu, but guard against silent
		// double-install corruption if a future caller bypasses ReorgTo.
		return fmt.Errorf("reorgBatch already set — concurrent reorg in flight")
	}
	cm.reorgBatch = batch
	cm.mu.Unlock()

	// Always clear reorgBatch before returning, including on every error
	// path. If the batch was committed it is just dropped here; if it was
	// not committed (error path) it is dropped too — Pebble batches are
	// safe to abandon, no Reset/Close required for correctness.
	defer func() {
		cm.mu.Lock()
		cm.reorgBatch = nil
		cm.mu.Unlock()
	}()

	// Atomic rollback to the pre-reorg tip.
	//
	// A reorg that fails partway (e.g. the competing chain has an invalid
	// block near its tip — bad-cb-amount) must NOT leave the node on a
	// partial switch: DisconnectBlock/ConnectBlock advance the in-memory tip
	// (cm.tipNode) and mutate the in-memory UTXO cache as they run, so an
	// early `return err` here would strand the node on the losing branch
	// (tip at B2 after B3 rejected) with a polluted UTXO view — and a later
	// heavier VALID block that extends the original chain would then be
	// rejected as "less work / does not connect". Bitcoin Core never does a
	// partial switch: ActivateBestChainStep connects against a throwaway
	// CoinsViewCache and only flushes on success; a ConnectTip failure drops
	// that view and re-selects the best VALID chain, so the node stays on a
	// fully-connected tip (validation.cpp:3191-3262).
	//
	// blockbrew's union-batch design makes the rollback cheap and total: the
	// on-disk chainstate + UTXO set are untouched until batch.Write() at the
	// very end, so the on-disk state is STILL the pre-reorg tip throughout the
	// disconnect/connect loop. We therefore only have to restore the IN-MEMORY
	// state: the tip pointer and the UTXO cache. The freshly-connected tip's
	// coins live only in that cache (the per-block on-disk flush is deferred to
	// the end of the reorg), so a blind cache wipe would lose committed state;
	// instead the reorg journal (BeginReorgJournal above) recorded a pre-image
	// of every outpoint the reorg touched, and RollbackReorgJournal reverts
	// exactly those. currentTip was snapshotted above under cm.mu.
	rollbackToOriginalTip := func() {
		cm.mu.Lock()
		cm.tipNode = currentTip
		cm.tipHeight = currentTip.Height
		cm.updateTipCache(currentTip.Hash, currentTip.Height)
		cm.mu.Unlock()
		if j, ok := cm.utxoSet.(utxoReorgJournal); ok {
			j.RollbackReorgJournal()
		}
		// The journal just put the coin set back exactly as it was at
		// currentTip, so the coins marker must be restated to currentTip too —
		// the tip and the marker have to move together or the pair lies.
		//
		// Without this the marker is left wherever the failed reorg abandoned
		// it: the disconnect loop rewound it to the FORK POINT, the partial
		// connect loop may have pushed it onto branch blocks that no longer
		// exist in the set. Either way the next flush publishes it, and no
		// crash is needed — an RPC invalidateblock/reconsiderblock round trip
		// that fails partway is enough. An authoritative restatement (not an
		// advance): the correct value can be below where the partial connect
		// left it. Core has no equivalent hole because ActivateBestChainStep
		// connects against a throwaway CCoinsViewCache and only ever flushes
		// on success (validation.cpp:3191-3262).
		cm.setAppliedTip(currentTip.Hash, currentTip.Height)
	}

	// Begin recording UTXO pre-images so any failure below can be unwound
	// exactly. Committed (dropped) only on the fully-successful path.
	if j, ok := cm.utxoSet.(utxoReorgJournal); ok {
		j.BeginReorgJournal()
	}

	// Disconnect blocks from current tip back to fork.
	for _, node := range disconnectNodes {
		if err := cm.DisconnectBlock(node.Hash); err != nil {
			rollbackToOriginalTip()
			return fmt.Errorf("disconnect block %s failed: %w", node.Hash.String()[:16], err)
		}
	}

	// Connect blocks from fork to new tip.
	//
	// DELIBERATELY NOT THROUGH ConnectOrAdoptBlock. The disconnect loop above
	// has just UNDONE mutations in the in-memory view without flushing, so the
	// on-disk coins marker is stale-HIGH here by construction: it still names
	// the pre-reorg tip. Adopting on it would skip re-applying blocks the view
	// genuinely no longer contains. (AdoptIfAlreadyFlushed refuses this on its
	// own — it requires the view's applied tip to be at or above the marker —
	// but a reorg must not depend on a downstream guard to stay correct.)
	for _, node := range connectNodes {
		block, err := cm.chainDB.GetBlock(node.Hash)
		if err != nil {
			rollbackToOriginalTip()
			return fmt.Errorf("block %s not found for reorg: %w", node.Hash.String()[:16], err)
		}
		if err := cm.ConnectBlock(block); err != nil {
			// Consensus failure in the competing chain. Mark the offending
			// block invalid (and its descendants invalid-child) so it is
			// excluded from future best-chain selection and the doomed reorg
			// is not retried on every subsequent block announcement — mirrors
			// Core's InvalidBlockFound + InvalidChainFound
			// (validation.cpp:3040-3043, 3237-3243). B-prefix blocks that DID
			// connect (B1, B2) stay valid, exactly as in Core. The block can
			// be un-blacklisted later via reconsiderblock.
			cm.mu.Lock()
			node.Status |= StatusInvalid
			cm.markDescendantsInvalid(node)
			cm.mu.Unlock()
			rollbackToOriginalTip()
			return fmt.Errorf("connect block %s failed during reorg: %w", node.Hash.String()[:16], err)
		}
	}

	// Drain the in-memory UTXO mutations from every Connect/Disconnect we
	// just executed into the same batch. FlushBatch resets the dirty /
	// deleted / fresh maps so the post-commit cache is consistent with
	// disk. This is the moment that turns the per-block in-memory UTXO
	// updates into durable on-disk writes — must happen before batch.Write.
	type batchFlusher interface {
		FlushBatch(storage.Batch) error
	}
	cm.mu.Lock()
	if f, ok := cm.utxoSet.(batchFlusher); ok {
		if err := f.FlushBatch(batch); err != nil {
			cm.mu.Unlock()
			rollbackToOriginalTip()
			return fmt.Errorf("failed to flush reorg UTXO mutations to batch: %w", err)
		}
	}
	cm.mu.Unlock()

	// Commit the union batch. Up to this point a crash would leave the
	// on-disk state at the pre-reorg tip (in-memory mutations are lost on
	// restart and the chainstate key on disk still points at currentTip).
	// After this call returns nil, on-disk state is at newTip.
	//
	// A Pebble batch write is all-or-nothing: on error nothing is committed,
	// so the on-disk state is still the pre-reorg tip and we roll the
	// in-memory state back to match (FlushBatch already reset the cache's
	// dirty/deleted/fresh tracking, so DiscardCache here also drops the now
	// batch-only mutations and re-reads the pre-reorg coins from disk).
	if err := batch.Write(); err != nil {
		rollbackToOriginalTip()
		return fmt.Errorf("failed to commit multi-block reorg batch: %w", err)
	}

	// Reorg fully applied and durable — the recorded pre-images are no longer
	// needed; drop them.
	if j, ok := cm.utxoSet.(utxoReorgJournal); ok {
		j.CommitReorgJournal()
	}

	return nil
}

// utxoReorgJournal is the optional savepoint contract a UTXO view exposes so
// ReorgTo can record + roll back the in-memory UTXO mutations of a multi-block
// reorg. *UTXOSet implements it; in-memory test views may not (the reorg then
// runs without a journal, which is fine because those paths do not rely on the
// exact-restore guarantee). Kept off UpdatableUTXOView so unrelated views need
// not implement it.
type utxoReorgJournal interface {
	BeginReorgJournal()
	RollbackReorgJournal()
	CommitReorgJournal()
}

// reorgInMemoryFallback executes a reorg without the union-batch path. Only
// reachable when chainDB is nil (some unit-test configurations) — the live
// fleet always has a ChainDB so this is unreachable in production. Preserves
// the pre-Pattern-D behavior (per-block in-memory mutations) for those tests.
func (cm *ChainManager) reorgInMemoryFallback(
	disconnectNodes []*BlockNode,
	connectNodes []*BlockNode,
) error {
	for _, node := range disconnectNodes {
		if err := cm.DisconnectBlock(node.Hash); err != nil {
			return fmt.Errorf("disconnect block %s failed: %w", node.Hash.String()[:16], err)
		}
	}
	for _, node := range connectNodes {
		// Raw ConnectBlock, for the same reason as the batched reorg path:
		// the disconnect loop above has already undone these heights in the
		// view, so the coins marker cannot speak for it.
		//
		// Without chainDB we cannot resolve block bodies; this matches the
		// pre-existing behavior (such tests stash blocks elsewhere or skip
		// the connect phase entirely).
		if cm.chainDB == nil {
			return fmt.Errorf("reorg connect requires chainDB (block %s)",
				node.Hash.String()[:16])
		}
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
	// Wake any wait-family RPC blocked on a tip change. This is THE chokepoint
	// every active-chain tip advance funnels through (ConnectBlock IBD +
	// post-IBD, ProcessSubmittedBlock/generate, and both halves of a reorg via
	// DisconnectBlock peels + ConnectBlock replays inside ReorgTo). Notify is
	// a no-op on a nil notifier and takes its own lock, so it is safe to call
	// here regardless of whether cm.mu is held by the caller.
	cm.tipNotifier.Notify()
}

// SetTipNotifier wires the wait-family-RPC tip-change notifier. Called once at
// startup (main.go) after the notifier is constructed and before the RPC server
// begins serving. Pulsed by updateTipCache on every tip advance.
func (cm *ChainManager) SetTipNotifier(tn *TipNotifier) {
	cm.tipNotifier = tn
}

// TipNotifier returns the wired tip-change notifier (nil if none). The RPC
// server reads it to block the wait-family handlers on tip advances.
func (cm *ChainManager) TipNotifier() *TipNotifier {
	return cm.tipNotifier
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
	if !cm.beginMutation() {
		return ErrShuttingDown
	}
	defer cm.endMutation()

	node := cm.headerIndex.GetNode(hash)
	if node == nil {
		return fmt.Errorf("block not found")
	}

	// Genesis block can't be invalidated
	if node.Height == 0 {
		return fmt.Errorf("genesis block cannot be invalidated")
	}

	// Serialize against every other chain mutator for the WHOLE operation.
	//
	// The disconnect loop below releases cm.mu around each DisconnectBlock (it
	// must — DisconnectBlock takes cm.mu itself). Without cm.reorgMu that
	// window let the P2P/sync path run a full ReorgTo *into the middle of a
	// rollback*, because ReorgTo serialises only against other ReorgTo calls
	// and this loop was not participating.
	//
	// That is not hypothetical. genesis-blockbrew, mainnet, 2026-07-27, while
	// rolling back for a UTXO-set capture:
	//
	//   21:59:55 sync: received block height=959908 from 127.0.0.1:8333
	//   21:59:55 chainmgr: reorg from height 959898 to 959908
	//            (fork at 959898, disconnect=0 connect=10)
	//   22:00:11 chainmgr: DisconnectBlock unclean for ... at h=959908
	//            (BIP-30 aftermath or undo-mismatch)
	//
	// InvalidateBlock had walked the tip down to 959898; the sync goroutine
	// connected 10 blocks on top of the half-rolled-back state. The resulting
	// UTXO set matched NEITHER tip, the shutdown flush persisted it, and the
	// node came back with an unrecoverable [CHAINSTATE-CORRUPTION] wedge at
	// 959906 ("references missing UTXO"). It cost an 83-hour from-genesis
	// datadir. Note the reorg also connected blocks this call had just marked
	// invalid, so the invalid-flag filter did not save us either.
	//
	// Holding reorgMu here makes rollback and reorg mutually exclusive, which
	// is the invariant the disconnect loop always assumed it had.
	cm.reorgMu.Lock()
	defer cm.reorgMu.Unlock()

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
		// Need to activate the best valid chain.
		// reorgToLocked, not ReorgTo: we already hold cm.reorgMu for the whole
		// of InvalidateBlock, and Go mutexes are not reentrant.
		cm.mu.Unlock()
		err := cm.reorgToLocked(bestTip)
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
	if !cm.beginMutation() {
		return ErrShuttingDown
	}
	defer cm.endMutation()

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
	if !cm.beginMutation() {
		return ErrShuttingDown
	}
	defer cm.endMutation()

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

// ChainstateConsistencyResult summarises the outcome of a startup
// consistency probe.  Callers log it and may use the rollback fields to
// surface user-facing recovery hints.
type ChainstateConsistencyResult struct {
	// TipBefore is the tip height the probe started at (informational).
	TipBefore int32
	// TipAfter is the tip height after any auto-rollback.
	TipAfter int32
	// BlocksProbed is the number of blocks examined (1..maxDepth).
	BlocksProbed int
	// CorruptionAtHeight is the highest height where the consistency check
	// detected a missing UTXO / undo-data / block-body invariant.  Zero
	// when the chain is clean.
	CorruptionAtHeight int32
	// RolledBackBlocks is the number of blocks DisconnectBlock peeled off
	// the tip in response.  Zero when the chain is clean or rollback
	// could not run.
	RolledBackBlocks int
	// RollbackFailed is set if a corruption was detected but the rollback
	// could not complete (e.g. missing undo data).  When true the caller
	// should surface a [CHAINSTATE-CORRUPTION] notice and exit so the
	// operator can wipe chaindata/.
	RollbackFailed bool
}

// VerifyChainstateConsistency performs a startup consistency probe of the
// persisted chainstate.  Same class of recovery as lunarblock c6fd8a0 +
// nimrod 4920988: a hard crash mid-IBD can leave a state where chain_tip
// advanced past blocks whose UTXO mutations / undo data / block body
// never reached disk, producing a deterministic later wedge ("missing
// UTXO" forever; see project memory `project_lunarblock_wedge_2026_04_28`
// + the May 1 2026 blockbrew h=938360 wedge).
//
// Strategy: walk back maxDepth blocks from the current tip; for each
// block, fetch the body + first 5 non-coinbase tx inputs and verify each
// previous output resolves either to the live UTXO set or to the block's
// own undo-data records.  A miss means the persisted UTXO set lost a
// coin that the chain tip claims is spendable — the smoking-gun
// corruption pattern.
//
// On detection we DisconnectBlock back to the deepest known-good height
// (which restores UTXOs from undo data and rewrites chain_tip atomically
// via the existing reorg path).  If undo data is missing for a block we
// would need to peel, rollback aborts and the caller is expected to
// surface a clear [CHAINSTATE-CORRUPTION] error directing the operator
// to wipe chaindata/ (analogous to lunarblock's --reindex-chainstate
// hint; blockbrew currently honest-defers --reindex per
// cmd/blockbrew/main.go:258).
//
// maxDepth bounds the probe so a healthy node pays O(maxDepth) on every
// startup, not O(tip).  200 mirrors lunarblock; large enough to catch
// the typical "last few blocks of UTXO writes were lost" pattern, small
// enough to finish in well under a second on warm caches.
func (cm *ChainManager) VerifyChainstateConsistency(maxDepth int) ChainstateConsistencyResult {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	res := ChainstateConsistencyResult{}
	if cm.tipNode == nil || cm.tipHeight <= 0 {
		// Genesis-only chainstate. Nothing to verify.
		return res
	}
	if cm.chainDB == nil {
		return res
	}

	res.TipBefore = cm.tipHeight
	res.TipAfter = cm.tipHeight

	if maxDepth <= 0 {
		maxDepth = 200
	}

	// inputCheckLimit caps the per-block input probe at a small number so
	// the walk is cheap on archive nodes. Five is enough to catch the
	// typical wedge where one of the early txs in a block spends a UTXO
	// from the unflushed window — the original h=938361 symptom.
	const inputCheckLimit = 5

	// Walk back from tip up to maxDepth blocks. We stop early at the
	// first detected corruption — DisconnectBlock will peel the tip back
	// to that height (inclusive) and the next IBD pass re-applies it.
	node := cm.tipNode
	deepestBad := int32(-1)
	for i := 0; i < maxDepth && node != nil && node.Height > 0; i++ {
		res.BlocksProbed++

		// Fetch the block body. If it is missing, the on-disk state has
		// chain_tip ahead of block storage — the lunarblock
		// `block_in_storage=no` symptom. Treat as corruption.
		block, err := cm.chainDB.GetBlock(node.Hash)
		if err != nil || block == nil {
			log.Printf("chainmgr: [CONSISTENCY-PROBE] block body missing for tip-side block height=%d hash=%s err=%v",
				node.Height, node.Hash.String()[:16], err)
			deepestBad = node.Height
			node = node.Parent
			continue
		}

		// For each non-coinbase tx (capped), verify each input's prev-out
		// resolves either to a live UTXO (already-spent inputs are
		// expected to be ABSENT here, so we only consult the undo data
		// in that case) or to the block's recorded SpentCoin.
		probed := 0
		blockCorrupt := false
	txLoop:
		for txIdx, tx := range block.Transactions {
			if txIdx == 0 {
				continue // coinbase
			}
			for inIdx, in := range tx.TxIn {
				probed++
				if probed > inputCheckLimit {
					break txLoop
				}

				// Live UTXO lookup. After the block is connected, the
				// input UTXO is spent and *should* be absent. So we
				// expect the lookup to return nil — and the proof of
				// historical existence comes from undo data.
				live := cm.utxoSet.GetUTXO(in.PreviousOutPoint)
				if live != nil {
					// Live UTXO still exists. Either (a) chain tip is
					// behind, (b) this is a duplicate-coinbase artifact
					// (BIP30), or (c) the UTXO set is genuinely
					// inconsistent. Live presence is not a corruption
					// signal on its own; skip to undo-data check.
					_ = live
				}

				// Undo data records the coins this tx spent. Existence
				// proves the chainstate transition was applied and
				// the on-disk view is internally consistent.
				if cm.chainDB == nil {
					continue
				}
				undo, err := cm.chainDB.ReadBlockUndo(node.Hash)
				if err != nil || undo == nil {
					log.Printf("chainmgr: [CONSISTENCY-PROBE] undo data missing for height=%d hash=%s tx=%d in=%d err=%v",
						node.Height, node.Hash.String()[:16], txIdx, inIdx, err)
					blockCorrupt = true
					break txLoop
				}
				// We don't drill into the SpentCoin contents — presence
				// is sufficient for the lightweight probe. Deeper
				// validation is the job of -reindex-chainstate.
				break txLoop
			}
		}
		if blockCorrupt {
			deepestBad = node.Height
		}

		node = node.Parent
	}

	if deepestBad < 0 {
		// Clean chainstate.
		log.Printf("chainmgr: [CONSISTENCY-PROBE] OK tip=%d depth=%d blocks", res.TipBefore, res.BlocksProbed)
		return res
	}

	// Corruption detected. Peel the chain tip back to deepestBad-1 by
	// repeated DisconnectBlock. DisconnectBlock validates the tip
	// matches and replays undo data — if it fails (undo missing) we stop
	// and surface RollbackFailed=true.
	res.CorruptionAtHeight = deepestBad
	log.Printf("chainmgr: [CONSISTENCY-PROBE] corruption detected at height %d — rolling back", deepestBad)

	// Disconnect runs under cm.mu, but DisconnectBlock acquires it again
	// (it's a public entrypoint). Drop the lock around each call.
	for cm.tipNode != nil && cm.tipHeight >= deepestBad {
		hash := cm.tipNode.Hash
		h := cm.tipHeight

		cm.mu.Unlock()
		err := cm.DisconnectBlock(hash)
		cm.mu.Lock()

		if err != nil {
			log.Printf("chainmgr: [CONSISTENCY-PROBE] DisconnectBlock failed at height %d: %v", h, err)
			res.RollbackFailed = true
			break
		}
		res.RolledBackBlocks++
		// Safety cap: don't peel more than 2*maxDepth blocks even if
		// something pathological keeps reporting corruption.
		if res.RolledBackBlocks >= 2*maxDepth {
			log.Printf("chainmgr: [CONSISTENCY-PROBE] reached rollback safety cap (%d blocks)", res.RolledBackBlocks)
			res.RollbackFailed = true
			break
		}
	}

	res.TipAfter = cm.tipHeight
	if res.RollbackFailed {
		log.Printf("chainmgr: [CHAINSTATE-CORRUPTION] auto-rollback could not complete (tip=%d). "+
			"The on-disk chainstate appears corrupt. Operator action: stop the node and remove "+
			"the chaindata/ directory to force a full re-sync (blockbrew -reindex is honest-deferred).",
			res.TipAfter)
	} else {
		log.Printf("chainmgr: [CONSISTENCY-PROBE] rolled back %d blocks; tip=%d", res.RolledBackBlocks, res.TipAfter)
	}

	return res
}
