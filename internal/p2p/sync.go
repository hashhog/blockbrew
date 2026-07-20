package p2p

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

const (
	// MaxHeadersPerRequest is the maximum headers we can receive per request.
	MaxHeadersPerRequest = 2000

	// MaxNumUnconnectingHeadersMsgs caps how many *successive* unconnecting-
	// headers messages a peer may send before we disconnect (and ban via
	// the existing misbehavior pipeline).  Mirrors Bitcoin Core's
	// MAX_NUM_UNCONNECTING_HEADERS_MSGS in net_processing.cpp.
	//
	// Per the 2026-05-06 header-sync DoS audit (Pattern B), blockbrew used
	// to bake misbehavior(20) + Disconnect() into the very first
	// ErrOrphanHeader message — five honest unconnecting batches in a
	// row hit the +100 ban threshold and dropped the peer.  Core tolerates
	// up to 10 (>1 reorg attempt) before disconnecting.
	MaxNumUnconnectingHeadersMsgs = 10

	// HeaderSyncTimeout is the timeout for receiving headers from a peer.
	HeaderSyncTimeout = 2 * time.Minute

	// SyncRetryInterval is how long to wait before retrying sync with a new peer.
	SyncRetryInterval = 5 * time.Second

	// DefaultDownloadWindow is the max concurrent blocks in flight.
	DefaultDownloadWindow = 1024

	// MaxBlocksPerPeer is the max concurrent requests per peer.
	MaxBlocksPerPeer = 16

	// BlockRequestTimeout is the timeout for a single block request.
	BlockRequestTimeout = 2 * time.Minute

	// BaseStallTimeout is the initial stall detection timeout.
	BaseStallTimeout = 30 * time.Second

	// MaxStallTimeout is the maximum stall timeout after adaptive backoff.
	MaxStallTimeout = 120 * time.Second

	// MaxRetriesBeforeRotate is how many timeouts before we avoid a peer.
	MaxRetriesBeforeRotate = 3

	// ProgressLogInterval is how often to log IBD progress.
	ProgressLogInterval = 10 * time.Second

	// UTXOFlushInterval is how many blocks between UTXO flushes during IBD.
	UTXOFlushInterval = 2000

	// StaleTipCheckInterval is how often to check if our chain tip is stale.
	// Reference: Bitcoin Core STALE_CHECK_INTERVAL (10 minutes)
	StaleTipCheckInterval = 10 * time.Minute

	// StaleTipThreshold is how long without a new block before we consider the tip stale.
	// Reference: Bitcoin Core nPowTargetSpacing * 3 = 30 minutes
	StaleTipThreshold = 30 * time.Minute

	// PeriodicHeaderInterval is how often to send getheaders to a random peer
	// when synced, to discover new blocks missed by inv messages.
	PeriodicHeaderInterval = 5 * time.Minute

	// MaxTipAge is the maximum age of our best block tip before we consider
	// the node still in IBD.  Matches Bitcoin Core's DEFAULT_MAX_TIP_AGE (24h).
	// If the chain tip's block timestamp is older than this, IsIBDActive returns
	// true regardless of block height.
	MaxTipAge = 24 * time.Hour

	// MaxValidationWorkers caps how many concurrent validationWorker
	// goroutines Start() will spawn.  CheckBlockSanity (the main work the
	// validation worker does) is independent per block and CPU-bound, so
	// parallelising it drains validationChan faster and prevents the
	// "validation channel full, dropping unsolicited block" back-pressure
	// regime that caused the 6-minute stall cycle diagnosed in W63.
	// Reference: wave63-2026-04-18/BLOCKBREW-PROFILE.md (validation
	// state-machine stalled; validCh=1024/1024, connCh=1024/1024).
	MaxValidationWorkers = 4

	// MinValidationWorkers is the floor for validation-worker parallelism
	// so even on a 1-core VM we get at least two so the non-blocking
	// connection-channel send path keeps making forward progress under
	// transient connectionChan pressure.
	MinValidationWorkers = 2

	// ConnStatsLogEvery is how many successfully-connected blocks the
	// connectionWorker accumulates before emitting a [W75-CONN] line.
	// Matches the W72-DESER / W75-CONN cadence used in lunarblock so the
	// two logs line up visually at 500-block boundaries during a side-by-
	// side comparison between implementations.
	ConnStatsLogEvery = 500

	// OrphanExpireDriverInterval is how often the main loop fires the
	// orphan expiry sweep (mempool.ExpireOrphans).  Bitcoin Core calls
	// LimitOrphans inside every AddTx; blockbrew approximates that with a
	// once-per-minute timer in cmd/blockbrew/main.go.  This constant is
	// exported so the W103 BUG-22 test can assert the correct interval.
	OrphanExpireDriverInterval = time.Minute
)

// numValidationWorkers returns how many validationWorker goroutines to
// spawn.  The policy is runtime.NumCPU()/2, clamped to
// [MinValidationWorkers, MaxValidationWorkers].  We deliberately do NOT
// use all cores: the connectionWorker must remain the single serialisation
// point for chain extension, and over-parallelising CheckBlockSanity
// would only push back-pressure onto connectionChan sooner.
func numValidationWorkers() int {
	n := runtime.NumCPU() / 2
	if n < MinValidationWorkers {
		n = MinValidationWorkers
	}
	if n > MaxValidationWorkers {
		n = MaxValidationWorkers
	}
	return n
}

// BlockDownloadState tracks the download state of a block.
type BlockDownloadState int

const (
	BlockDownloadPending BlockDownloadState = iota
	BlockDownloadInFlight
	BlockDownloadReceived
	BlockDownloadValidated
	BlockDownloadConnected
)

// blockRequest tracks a pending block download.
type blockRequest struct {
	Hash       wire.Hash256
	Height     int32
	Peer       *Peer
	State      BlockDownloadState
	RequestAt  time.Time
	RetryCount int
	// FailedPeers records peer addresses that responded notfound for this
	// specific block hash.  Populated in HandleNotFound, consulted by
	// requestBlocks to avoid re-asking peers that have already told us they
	// don't have this block.  Without this, blockbrew round-robins back to
	// the same peer, gets the same notfound, and produces millions of log
	// lines of spam (observed haskoin flooding ~50k/min).
	FailedPeers map[string]struct{}
}

// blockWithRequest pairs a received block with its request metadata.
type blockWithRequest struct {
	block *wire.MsgBlock
	req   *blockRequest
}

// SyncManager coordinates header and block synchronization with peers.
type SyncManager struct {
	mu            sync.RWMutex
	chainParams   *consensus.ChainParams
	headerIndex   *consensus.HeaderIndex
	chainDB       *storage.ChainDB
	peerMgr       *PeerManager
	syncPeer      *Peer // Current peer we're syncing headers from
	headersSynced bool  // Whether we've caught up with headers
	quit          chan struct{}
	wg            sync.WaitGroup

	// Callbacks for external integration
	onSyncComplete   func()                                   // Called when header sync completes
	onBlockConnected func(block *wire.MsgBlock, height int32) // Called after block connected

	// Block download state
	blockQueue     []*blockRequest // Ordered list of blocks to download
	inflight       map[wire.Hash256]*blockRequest
	downloadWindow int   // Max concurrent downloads
	nextHeight     int32 // Next height to connect

	// IBD pipeline channels
	validationChan chan *blockWithRequest
	connectionChan chan *blockWithRequest

	// Peer stall tracking (adaptive timeout)
	peerStallTimeout map[string]time.Duration

	// Chain manager for block connection
	chainMgr ChainConnector

	// IBD state
	//
	// ibdActive is accessed lock-free via atomic operations so that RPC
	// readers (IsIBDActive) don't contend with sm.mu, which is held as a
	// write lock for long intervals during header/block processing. Go's
	// sync.RWMutex has writer preference, so a naive RLock-guarded read
	// starves the RPC goroutine indefinitely during IBD. See L1-7b.
	//
	// Semantics match Bitcoin Core's m_cached_is_ibd (validation.h):
	// the flag starts true and is latched to false (never back to true)
	// once the chain tip has a timestamp within MaxTipAge of wall-clock
	// time.  This means header sync is correctly reported as IBD, not
	// just block download.  See updateIBDStatus().
	ibdActive atomic.Bool // True while in IBD (header sync OR block download)
	// blockDownloadLoopRunning guards the single blockDownloadLoop goroutine.
	// StartBlockDownload can legitimately re-enter (drain/rebuild branch, peer
	// churn, periodic getheaders) and used to `go sm.blockDownloadLoop()`
	// unconditionally — but the existing loop only exits on quit or a drained
	// queue, so a rebuild spawned a SECOND loop while the first was still
	// alive. Each leaked loop carries its own request/stale/stall tickers:
	// duplicated getdata traffic, duplicated stall handling, and N× CPU.
	// Observed 2026-07-16..19 on genesis-blockbrew (GEN-BREW-665671): 207% CPU
	// and 733k identical "stall ... NOT IN QUEUE" lines logged MICROSECONDS
	// apart — the signature of many goroutines ticking together, not one loop
	// spinning. CompareAndSwap admits exactly one; the loop clears it on exit.
	blockDownloadLoopRunning atomic.Bool
	peerRoundIdx             int // Round-robin index for peer selection

	// Stale tip detection (Bitcoin Core: CheckForStaleTipAndEvictPeers)
	lastTipUpdate     time.Time // When our chain tip last advanced
	nextStaleTipCheck time.Time // When to next check for stale tip

	// lastRequeueLog holds the UnixNano timestamp of the last
	// "connection channel saturated, re-queued" message so
	// requeueForRedownload can rate-limit logging when
	// validationWorkers' non-blocking connectionChan sends fall back
	// under sustained back-pressure.  Accessed via atomic to avoid
	// contention between parallel validationWorkers.  W64 thread A.
	lastRequeueLog atomic.Int64

	// W75 instrumentation — per-block ConnectBlock latency window,
	// accumulated inside connectionWorker's goroutine.  All reads and
	// writes happen from that single goroutine (retry-ticker and
	// channel-receive branches both run inside the same for-select),
	// so no atomics or lock are needed.  Emitted as a [W75-CONN] log
	// line every connStatsLogEvery blocks.  connCh saturates at
	// 1024/1024 with observed IBD rate ≈ 290 blk/hr → per-block ceiling
	// around 12 s.  This probe attributes that to ConnectBlock wall
	// time so we can decide whether the lever is UTXO cache, RocksDB
	// batch flush, script validation, or lock contention.
	connStatsN        int64 // blocks in current window
	connStatsTotalNs  int64 // summed ConnectBlock latency (ns)
	connStatsMaxNs    int64 // max ConnectBlock latency in window (ns)
	connStatsTotalTxs int64 // summed tx count across window
	connStatsLifetime int64 // cumulative count since process start

	// chainstateCorrupted latches when connectPendingBlocks hits a
	// genuine validation failure during IBD (presumed chainstate
	// corruption per BUG-REPORT.md).  Once set, the connect loop early-
	// exits without re-running ConnectBlock, so the corruption notice is
	// printed at most once per retry tick (not 50k times/min like the
	// pre-fix skip-and-loop path).  Cleared only by process restart.
	chainstateCorrupted   atomic.Bool
	lastCorruptionWarning atomic.Int64 // unix nanos

	// pruner, when non-nil and configured with a target, is used by
	// HandleGetData to reject pre-prune-horizon block requests with a
	// `notfound` reply (BIP-159 peer-served-blocks gate).
	pruner *storage.Pruner

	// unconnectingHeaders tracks per-peer counters of consecutive
	// unconnecting-headers messages.  Protected by `mu`.  Mirrors
	// Bitcoin Core's nUnconnectingHeaders state machine.  The counter
	// is incremented on every ErrOrphanHeader from the first header
	// in a batch, reset on the first connecting batch, and triggers
	// disconnect once it would exceed MaxNumUnconnectingHeadersMsgs.
	unconnectingHeaders map[string]int

	// peerHeadersSync tracks the per-peer HeadersSyncState for the
	// PRESYNC/REDOWNLOAD pipeline (Bitcoin Core headerssync.cpp, Core 24+).
	// A state is created when we start syncing headers with a peer whose
	// chain work is below nMinimumChainWork, and destroyed when the sync
	// completes, fails, or the peer disconnects.  Protected by mu.
	peerHeadersSync map[string]*HeadersSyncState

	// mempool is the tx source the sync manager uses to participate in the
	// inv->getdata->tx relay loop: membership tests (avoid re-requesting a tx
	// we already have) on the REQUEST side, and full-tx lookup on the SERVE
	// side of HandleGetData.  nil disables both tx-relay paths (tests, or
	// nodes wired without a mempool).
	mempool MempoolTxSource

	// txInflight is the minimal request-dedup set for transactions we have
	// getdata-requested but not yet received.  Keyed by the announced hash
	// (wtxid for wtxid-relay peers, txid for legacy peers) so the same tx is
	// not re-requested from every peer that announces it.  Modelled on the
	// block `inflight` map above; entries expire after txInflightExpiry so a
	// dropped/never-served tx does not pin the slot forever (Core's
	// TxRequestTracker expiry).  Protected by mu.
	txInflight map[wire.Hash256]time.Time
}

// MempoolTxSource is the minimal mempool interface the sync manager needs to
// take part in transaction relay.  internal/mempool.Mempool satisfies it via
// HasTransaction / GetTransaction / GetTxByWTxid.  The interface is declared
// here (rather than importing mempool) to avoid an import cycle between the
// p2p and mempool packages and to keep HandleInv/HandleGetData unit-testable
// with a stub.
type MempoolTxSource interface {
	// HasTransaction reports whether a tx with the given txid is in the pool.
	HasTransaction(txid wire.Hash256) bool
	// GetTransaction returns the pool tx with the given txid, or nil.
	GetTransaction(txid wire.Hash256) *wire.MsgTx
	// GetTxByWTxid returns the pool tx with the given witness txid, or nil.
	GetTxByWTxid(wtxid wire.Hash256) *wire.MsgTx
}

// txInflightExpiry bounds how long a getdata-requested tx stays in the
// txInflight dedup set before it may be re-requested.  Mirrors the spirit of
// Bitcoin Core's TxRequestTracker per-request expiry (GETDATA_TX_INTERVAL):
// if the announcer never serves the tx, the slot is reclaimed and another
// announcer's inv can trigger a fresh request.
const txInflightExpiry = 60 * time.Second

// ChainConnector is the interface for connecting blocks to the chain.
// This allows the sync manager to work with any chain manager implementation.
type ChainConnector interface {
	// ConnectBlock validates and connects a block to the active chain.
	ConnectBlock(block *wire.MsgBlock) error
	// ProcessSubmittedBlock connects a block via the side-branch-aware path:
	// it extends the active tip (fast ConnectBlock path) when the block's
	// parent IS the tip, reorgs when the block is a heavier side branch, and
	// STORES the block returning consensus.ErrSideBranchAccepted when it is an
	// equal/less-work side branch. Used by the post-IBD competing-fork connect
	// path so fork bodies arriving bottom-up are stored (not rejected) until a
	// heavier fork tip drives ReorgTo. Caller contract: the header is already in
	// the index and the body is already persisted on disk (both guaranteed by
	// the headers-first download path before the block reaches the connect loop).
	// Mirrors the RPC submitblock path (rpc/methods.go) and Bitcoin Core's
	// AcceptBlock/ActivateBestChain split (validation.cpp).
	ProcessSubmittedBlock(block *wire.MsgBlock) error
	// BestBlock returns the current chain tip hash and height.
	BestBlock() (wire.Hash256, int32)
	// BestBlockNode returns the BlockNode for the current chain tip via
	// an atomic cache.  Used by updateIBDStatus to read the tip timestamp
	// without holding any lock.
	BestBlockNode() *consensus.BlockNode
	// ReloadChainState re-resolves the chain tip and assume-valid height
	// from the database after the header index has been populated.
	ReloadChainState()
	// HasPendingRecovery reports whether the chain manager is holding a
	// saved chain tip that hasn't yet been reconciled with the header
	// index.  Polled (lock-free) after each header batch so we can
	// invoke ReloadChainState as soon as the saved tip becomes reachable,
	// instead of waiting for OnSyncComplete which may never fire on a
	// long chain where every batch is a full MaxHeadersPerRequest.
	// (See W17 chainmgr-startup recovery fix.)
	HasPendingRecovery() bool
	// IsIBD reports whether the node is in Initial Block Download mode.
	// Sync uses this to soften misbehavior penalties during catch-up so a
	// transient header-ambiguity burst can't drain the outbound peer pool
	// (W15 root-cause fix).
	IsIBD() bool
	// IsPruning reports whether the node prunes block/undo data (-prune=N,
	// N>0). The fork-aware download descent uses it to decide whether the
	// MaxReorgDepth cap applies: an archive node follows the most-work chain
	// to any depth (Core-parity, no cap on a genuine below-tip reorg); a
	// pruned node keeps the cap (a reorg past its retained undo window is
	// un-appliable). Mirrors ChainManager.ReorgTo's pruning gate.
	IsPruning() bool
}

// SyncManagerConfig configures the sync manager.
type SyncManagerConfig struct {
	ChainParams      *consensus.ChainParams
	HeaderIndex      *consensus.HeaderIndex
	ChainDB          *storage.ChainDB
	PeerManager      *PeerManager
	ChainManager     ChainConnector
	OnSyncComplete   func()
	OnBlockConnected func(block *wire.MsgBlock, height int32) // Called after a block is connected
	DownloadWindow   int                                      // Max concurrent block downloads (default: 1024)
	// Pruner is the auto-prune subsystem.  When non-nil and the configured
	// target is non-zero, BIP-159 NODE_NETWORK_LIMITED is advertised and
	// HandleGetData rejects requests below the recent-288 keep window with
	// a `notfound` reply (Core net_processing.cpp behaviour).
	Pruner *storage.Pruner
	// Mempool is the tx source used for the inv->getdata->tx relay loop
	// (request unknown announced txs; serve requested txs).  Optional: when
	// nil both tx-relay paths are disabled.  internal/mempool.Mempool
	// satisfies MempoolTxSource.
	Mempool MempoolTxSource
}

// NewSyncManager creates a new sync manager.
func NewSyncManager(config SyncManagerConfig) *SyncManager {
	downloadWindow := config.DownloadWindow
	if downloadWindow <= 0 {
		downloadWindow = DefaultDownloadWindow
	}
	// W67d: clamp the download window to MaxPendingBlocks so the
	// connection worker's pending-map eviction never throws away blocks
	// that are still in flight. Violating this invariant produces a
	// cursor-skip stall (same shape as lunarblock's W65 bug).
	if downloadWindow > MaxPendingBlocks {
		log.Printf("sync: clamping configured DownloadWindow %d to MaxPendingBlocks %d "+
			"to preserve pending-map invariant", downloadWindow, MaxPendingBlocks)
		downloadWindow = MaxPendingBlocks
	}

	now := time.Now()
	sm := &SyncManager{
		chainParams:         config.ChainParams,
		headerIndex:         config.HeaderIndex,
		chainDB:             config.ChainDB,
		peerMgr:             config.PeerManager,
		quit:                make(chan struct{}),
		onSyncComplete:      config.OnSyncComplete,
		onBlockConnected:    config.OnBlockConnected,
		inflight:            make(map[wire.Hash256]*blockRequest),
		downloadWindow:      downloadWindow,
		validationChan:      make(chan *blockWithRequest, downloadWindow),
		connectionChan:      make(chan *blockWithRequest, downloadWindow),
		peerStallTimeout:    make(map[string]time.Duration),
		chainMgr:            config.ChainManager,
		lastTipUpdate:       now,
		nextStaleTipCheck:   now.Add(StaleTipCheckInterval),
		pruner:              config.Pruner,
		mempool:             config.Mempool,
		txInflight:          make(map[wire.Hash256]time.Time),
		unconnectingHeaders: make(map[string]int),
		peerHeadersSync:     make(map[string]*HeadersSyncState),
	}
	// IBD starts true from the moment the sync manager is created; it is
	// only latched to false by updateIBDStatus() once the chain tip is
	// recent.  This matches Bitcoin Core's m_cached_is_ibd{true} initial
	// value in validation.h.
	sm.ibdActive.Store(true)
	return sm
}

// SetPeerManager sets or updates the peer manager reference.
// This is needed to break the circular dependency between SyncManager and PeerManager
// during initialization: SyncManager needs PeerManager for block downloads, and
// PeerManager needs SyncManager's listeners for message handling.
func (sm *SyncManager) SetPeerManager(pm *PeerManager) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.peerMgr = pm
}

// Start begins the sync process.
func (sm *SyncManager) Start() {
	// Initialize nextHeight from the current chain tip so that unsolicited
	// blocks received before IBD starts are connected at the right height.
	if sm.chainMgr != nil {
		_, tipHeight := sm.chainMgr.BestBlock()
		sm.nextHeight = tipHeight + 1
	}

	sm.wg.Add(1)
	go sm.syncHandler()

	// Start IBD pipeline workers.
	//
	// W64 (thread A) — validationWorker is now parallelised: CheckBlockSanity
	// is independent per block, so running N of them drains validationChan
	// fast enough to prevent the 6-min "validation channel full, dropping
	// unsolicited block" stall cycle diagnosed in W63.  connectionWorker
	// remains a single goroutine because ConnectBlock must be ordered and
	// must own the chain-extension critical section.  Combined with the
	// non-blocking send to connectionChan inside validationWorker (which
	// falls back to re-queueing the block for re-download rather than
	// parking the goroutine), this breaks the pipeline deadlock.
	// Reference: wave63-2026-04-18/BLOCKBREW-PROFILE.md.
	nVal := numValidationWorkers()
	sm.wg.Add(2 + nVal)
	for i := 0; i < nVal; i++ {
		go sm.validationWorker()
	}
	go sm.connectionWorker()
	go sm.progressLogger()
}

// Stop halts synchronization.
func (sm *SyncManager) Stop() {
	close(sm.quit)
	sm.wg.Wait()
}

// syncHandler is the main sync loop.
func (sm *SyncManager) syncHandler() {
	defer sm.wg.Done()

	// Wait a bit for peers to connect
	select {
	case <-time.After(5 * time.Second):
	case <-sm.quit:
		return
	}

	// Start header synchronization
	sm.startHeaderSync()

	// Periodically check if we need to restart sync
	ticker := time.NewTicker(SyncRetryInterval)
	defer ticker.Stop()

	// Stale tip check timer — runs every 60s to detect stuck sync
	staleTipTicker := time.NewTicker(60 * time.Second)
	defer staleTipTicker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.mu.RLock()
			synced := sm.headersSynced
			syncPeer := sm.syncPeer
			sm.mu.RUnlock()

			if !synced && syncPeer == nil {
				// Not yet synced — try to start header sync
				sm.startHeaderSync()
			} else if synced {
				// Already synced — send periodic getheaders to discover
				// new blocks.  This catches blocks missed by inv messages.
				// Reference: Bitcoin Core SendMessages() periodic header fetch.
				sm.sendPeriodicGetHeaders()
			}

		case <-staleTipTicker.C:
			sm.checkStaleTip()

		case <-sm.quit:
			return
		}
	}
}

// startHeaderSync begins downloading headers from the best peer.
func (sm *SyncManager) startHeaderSync() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Already synced
	if sm.headersSynced {
		return
	}

	// Don't (re)start header sync while a PRESYNC/REDOWNLOAD pipeline is already
	// active. A periodic sync-ticker / retry call mid-pipeline would otherwise
	// delete the live HeadersSyncState (below, line ~503) and start a fresh
	// presync rooted at the current — and, with the addPipelineHeaders fix,
	// advancing — header-index tip, whose getheaders reply collides with the
	// in-flight redownload stream → false "non-continuous" abort + self-
	// disconnect (the genesis-IBD wedge). The active pipeline drives itself to
	// completion via HandleHeaders/NextLocator. Legitimate restarts (initial
	// sync, or after a pipeline failure) reach here with peerHeadersSync already
	// empty (the failure path deletes it first), so they are not blocked.
	if len(sm.peerHeadersSync) > 0 {
		return
	}

	// Select best peer
	syncPeer := sm.selectSyncPeer()
	if syncPeer == nil {
		log.Printf("sync: no peers available for header sync")
		return
	}

	sm.syncPeer = syncPeer
	log.Printf("sync: starting header sync with %s (height %d)", syncPeer.Address(), syncPeer.StartHeight())

	addr := syncPeer.Address()

	// Determine whether we need the PRESYNC/REDOWNLOAD pipeline.
	// We use it when our current chain tip has less work than nMinimumChainWork,
	// meaning we cannot yet trust that the peer's chain is legitimate.
	// This matches Bitcoin Core net_processing.cpp::ProcessHeadersMessage:
	// "if we're in initial headers sync and the peer's chain doesn't have enough
	//  work, start the headerssync process."
	if sm.needsHeadersSync() {
		chainStart := sm.headerIndex.BestTip()
		minWork := sm.computeMinimumRequiredWork()
		delete(sm.peerHeadersSync, addr) // clear any stale state
		sm.peerHeadersSync[addr] = NewHeadersSyncState(addr, sm.chainParams, chainStart, minWork)
		log.Printf("sync: starting PRESYNC pipeline with %s (tip_work < min_work)", addr)
	}

	// Build locator from our current best tip
	locator := sm.headerIndex.BestTip().BuildLocator()

	// Send getheaders request
	sm.sendGetHeaders(syncPeer, locator)
}

// needsHeadersSync returns true if our current chain tip has less work than
// nMinimumChainWork, meaning we should use the PRESYNC/REDOWNLOAD pipeline.
// Must be called with sm.mu held.
func (sm *SyncManager) needsHeadersSync() bool {
	minWork := sm.chainParams.MinimumChainWork
	if minWork == nil || minWork.Sign() == 0 {
		return false
	}
	tip := sm.headerIndex.BestTip()
	if tip == nil || tip.TotalWork == nil {
		return true // no tip means definitely below threshold
	}
	return tip.TotalWork.Cmp(minWork) < 0
}

// computeMinimumRequiredWork returns the minimum chain work threshold that a
// peer's chain must meet.  This is the greater of the chain tip's work and
// nMinimumChainWork, matching Bitcoin Core net_processing.cpp:2643.
func (sm *SyncManager) computeMinimumRequiredWork() *big.Int {
	chainMinWork := sm.chainParams.MinimumChainWork
	if chainMinWork == nil {
		chainMinWork = big.NewInt(0)
	}
	tip := sm.headerIndex.BestTip()
	if tip == nil || tip.TotalWork == nil {
		return new(big.Int).Set(chainMinWork)
	}
	tipWork := tip.TotalWork
	if tipWork.Cmp(chainMinWork) > 0 {
		return new(big.Int).Set(tipWork)
	}
	return new(big.Int).Set(chainMinWork)
}

// sendGetHeaders sends a getheaders message to a peer.
func (sm *SyncManager) sendGetHeaders(peer *Peer, locator []wire.Hash256) {
	msg := &MsgGetHeaders{
		ProtocolVersion: uint32(peer.ProtocolVersion()),
		BlockLocators:   locator,
		HashStop:        wire.Hash256{}, // Get as many as possible
	}
	peer.SendMessage(msg)
}

// selectSyncPeer chooses the best peer to sync from (highest start height).
func (sm *SyncManager) selectSyncPeer() *Peer {
	peers := sm.peerMgr.ConnectedPeers()
	if len(peers) == 0 {
		return nil
	}

	var bestPeer *Peer
	var bestHeight int32

	for _, p := range peers {
		height := p.StartHeight()
		if height > bestHeight {
			bestHeight = height
			bestPeer = p
		}
	}

	// Only sync if the peer is ahead of us
	if bestPeer != nil && bestHeight <= sm.headerIndex.BestHeight() {
		// We're already caught up
		sm.headersSynced = true
		if sm.onSyncComplete != nil {
			// Run callback in a goroutine to avoid deadlock
			// (caller holds sm.mu, callback may also need sm.mu)
			go sm.onSyncComplete()
		}
		return nil
	}

	return bestPeer
}

// HandleHeaders processes a received headers message.
// This should be called from the peer manager's OnHeaders callback.
//
// When our chain work is below nMinimumChainWork the PRESYNC/REDOWNLOAD
// pipeline (Bitcoin Core headerssync.cpp) is used to avoid committing low-work
// headers to permanent memory.  Headers are only passed to headerIndex.AddHeader
// once the pipeline has verified they sit on a chain with sufficient PoW.
func (sm *SyncManager) HandleHeaders(peer *Peer, msg *MsgHeaders) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check for too many headers (protocol violation)
	if len(msg.Headers) > MaxHeadersPerRequest {
		peer.Misbehaving(20, "too many headers in message")
		return
	}

	// Ignore headers from non-sync peers during initial sync
	if sm.syncPeer != nil && peer != sm.syncPeer {
		return
	}

	addr := peer.Address()

	// -----------------------------------------------------------------------
	// PRESYNC / REDOWNLOAD pipeline (Core headerssync.cpp)
	// -----------------------------------------------------------------------
	// If a HeadersSyncState exists for this peer, route the batch through it.
	// The pipeline returns either:
	//   - Success=false → disconnect/penalise the peer, abandon sync.
	//   - Success=true + RequestMore=true → send a follow-up GETHEADERS.
	//   - POWValidatedHeaders non-empty → promote these to the normal path.
	// Once the state transitions to FINAL (i.e. success=true, request_more=false)
	// we delete it and fall through to the normal completion logic.
	if hss, ok := sm.peerHeadersSync[addr]; ok {
		fullMsg := len(msg.Headers) == MaxHeadersPerRequest
		result := hss.ProcessNextHeaders(msg.Headers, fullMsg)

		if !result.Success {
			// Peer violated the protocol — penalise and restart.
			log.Printf("headerssync: pipeline failure with peer=%s, disconnecting", addr)
			delete(sm.peerHeadersSync, addr)
			peer.Misbehaving(ScoreHeadersDontConnect, "headerssync pipeline failure")
			peer.Disconnect()
			sm.syncPeer = nil
			go sm.startHeaderSync()
			return
		}

		if result.RequestMore {
			// Still in PRESYNC or REDOWNLOAD — ask for the next batch. This is
			// the ONLY getheaders allowed to this peer while the pipeline is
			// active (Core MaybeSendGetHeaders inside the headerssync path).
			locator := hss.NextLocator(func(height int32) wire.Hash256 {
				n := sm.headerIndex.BestTip().GetAncestor(height)
				if n == nil {
					return wire.Hash256{}
				}
				return n.Hash
			})
			if len(locator) == 0 {
				locator = sm.headerIndex.BestTip().BuildLocator()
			}
			sm.sendGetHeaders(peer, locator)

			// Core parity (net_processing.cpp:2751 `headers.swap(result.
			// pow_validated_headers)`): during REDOWNLOAD the state machine drains
			// its validated-lookahead buffer on EVERY batch, not just the final
			// one. Promote those to the header index now (index-only — the pipeline
			// still owns the next getheaders via NextLocator above). The previous
			// early return DROPPED result.POWValidatedHeaders, so the index stayed
			// stuck at genesis through the entire redownload; only the final batch
			// tried to promote, its parent (height base-of-buffer) was never added
			// → ErrOrphanHeader → a spurious tip-rooted re-sync that wedged the IBD
			// at h102000. See _ibd-from-genesis-campaign finding #1.
			if len(result.POWValidatedHeaders) > 0 {
				sm.addPipelineHeaders(result.POWValidatedHeaders)
			}
			return
		}

		// Pipeline complete (FINAL): promote the PoW-validated headers.
		delete(sm.peerHeadersSync, addr)
		if len(result.POWValidatedHeaders) > 0 {
			sm.addValidatedHeaders(peer, result.POWValidatedHeaders)
		}
		// After a successful PRESYNC/REDOWNLOAD cycle the pipeline produced
		// all confirmed headers; continue to the regular completion path below.
		// If addValidatedHeaders already triggered sync completion, the guard
		// at the bottom will be a no-op.
		return
	}
	// -----------------------------------------------------------------------
	// Normal path (chain already above nMinimumChainWork)
	// -----------------------------------------------------------------------
	sm.addValidatedHeaders(peer, msg.Headers)
}

// addPipelineHeaders adds PRESYNC/REDOWNLOAD-promoted headers to the header
// index ONLY. Unlike addValidatedHeaders it performs NO out-of-band side effects:
// no orphan getheaders re-request, no full-batch getheaders, no block-download
// kickoff, no headersSynced flip, no chain-recovery hook. The HeadersSyncState is
// still active and owns the next request via NextLocator (Core gates the
// "fetch more" getheaders on !have_headers_sync, net_processing.cpp:3104). The
// redownload set is pre-validated and strictly in order, so an AddHeader error
// here is unexpected — log and stop, but DO NOT send a getheaders (that ad-hoc
// re-request, rooted at a stale tip, is exactly the collision class that wedged
// the genesis IBD). Caller must hold sm.mu.
func (sm *SyncManager) addPipelineHeaders(headers []wire.BlockHeader) {
	startHeight := sm.headerIndex.BestHeight()
	added := 0
	var pending []storage.HeaderBatchEntry
	if sm.chainDB != nil {
		pending = make([]storage.HeaderBatchEntry, 0, len(headers))
	}
	for i := range headers {
		node, err := sm.headerIndex.AddHeader(headers[i], true)
		if err != nil {
			if err == consensus.ErrDuplicateHeader {
				continue
			}
			// Pre-validated, in-order redownload headers should always connect;
			// an error means a real pipeline bug. Flush what we have and stop —
			// no getheaders, no disconnect (the pipeline retries/aborts itself).
			if sm.chainDB != nil && len(pending) > 0 {
				if ferr := sm.chainDB.StoreBlockHeadersBatch(pending); ferr != nil {
					log.Printf("headerssync: failed to flush %d pipeline headers: %v", len(pending), ferr)
				}
				pending = pending[:0]
			}
			log.Printf("headerssync: unexpected error promoting redownload header at height %d: %v",
				sm.headerIndex.BestHeight()+1, err)
			break
		}
		added++
		if sm.chainDB != nil {
			pending = append(pending, storage.HeaderBatchEntry{Hash: node.Hash, Header: &headers[i]})
		}
	}
	if sm.chainDB != nil && len(pending) > 0 {
		if err := sm.chainDB.StoreBlockHeadersBatch(pending); err != nil {
			log.Printf("headerssync: failed to batch-store %d pipeline headers: %v", len(pending), err)
		}
	}
	if added > 0 {
		log.Printf("sync: added %d headers (%d -> %d)", added, startHeight, sm.headerIndex.BestHeight())
	}
}

// addValidatedHeaders inserts a batch of headers (already PoW-vetted) into the
// header index and drives the normal sync-completion / block-download logic.
// The caller must hold sm.mu.
func (sm *SyncManager) addValidatedHeaders(peer *Peer, headers []wire.BlockHeader) {
	addr := peer.Address()
	startHeight := sm.headerIndex.BestHeight()
	headersAdded := 0

	// Collect accepted headers for a single batched DB write at the end of
	// the loop.  A full headers message carries up to MaxHeadersPerRequest
	// (2000) entries; previously each triggered a separate pebble Set call
	// (one WAL record apiece), and IBD profiling showed this as the second-
	// biggest source of unnecessary WAL traffic after the now-flatfiled
	// block bodies.  Buffering into a single NewBatchNoSync collapses 2000
	// WAL records into one.
	//
	// On the early-return error path the buffered entries are flushed
	// before returning: crash recovery relies on successfully-validated
	// headers being on disk even when a later header in the same message
	// turns out to be invalid.
	var pendingHeaders []storage.HeaderBatchEntry
	if sm.chainDB != nil {
		pendingHeaders = make([]storage.HeaderBatchEntry, 0, len(headers))
	}

	for i := range headers {
		hdr := headers[i]
		// minPowChecked=true: these headers were already vetted by the
		// PRESYNC/REDOWNLOAD pipeline (or our chain is above MinimumChainWork
		// on the normal path), so no further work-threshold check is needed.
		node, err := sm.headerIndex.AddHeader(hdr, true)
		if err != nil {
			if err == consensus.ErrDuplicateHeader {
				// Skip duplicates silently
				continue
			}

			// Special case: ErrOrphanHeader on the FIRST header of a batch
			// is the Core "headers don't connect" path.  Bitcoin Core
			// tolerates up to MAX_NUM_UNCONNECTING_HEADERS_MSGS=10
			// successive unconnecting messages from a peer before
			// disconnecting (net_processing.cpp::ProcessHeadersMessage).
			// Pre-fix, blockbrew immediately Misbehaving(20)+Disconnect on
			// the first orphan, which is stricter than Core and drops
			// honest peers caught in a transient reorg.  See
			// CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
			// (Pattern B).
			if err == consensus.ErrOrphanHeader && i == 0 {
				sm.unconnectingHeaders[addr]++
				count := sm.unconnectingHeaders[addr]
				// Flush any earlier-good headers before bailing.
				if sm.chainDB != nil && len(pendingHeaders) > 0 {
					if ferr := sm.chainDB.StoreBlockHeadersBatch(pendingHeaders); ferr != nil {
						log.Printf("sync: failed to flush %d pending headers: %v",
							len(pendingHeaders), ferr)
					}
				}
				if count > MaxNumUnconnectingHeadersMsgs {
					log.Printf("sync: peer %s exceeded MAX_NUM_UNCONNECTING_HEADERS_MSGS=%d, disconnecting",
						addr, MaxNumUnconnectingHeadersMsgs)
					peer.Misbehaving(ScoreHeadersDontConnect,
						fmt.Sprintf("too many unconnecting headers (count=%d)", count))
					peer.Disconnect()
					delete(sm.unconnectingHeaders, addr)
					sm.syncPeer = nil
					go sm.startHeaderSync()
					return
				}
				// Under threshold: do NOT misbehave / disconnect.  Re-issue
				// getheaders so the peer can find a common ancestor (Core's
				// FindForkInGlobalIndex behavior).
				log.Printf("sync: orphan header from %s (unconnecting #%d/%d), re-requesting headers",
					addr, count, MaxNumUnconnectingHeadersMsgs)
				// Do NOT send a tip-rooted getheaders while a headerssync pipeline
				// is active for any peer: it would re-enter the live HeadersSyncState
				// out of order and trip the continuity check (false "non-continuous"
				// abort). The pipeline owns header requests via NextLocator. Core
				// gates unconnecting-header handling on !have_headers_sync. (With the
				// addPipelineHeaders fix the redownload index now climbs in order, so
				// this orphan should no longer fire mid-pipeline; this is the general
				// class guard.)
				if len(sm.peerHeadersSync) > 0 {
					return
				}
				locator := sm.headerIndex.BestTip().BuildLocator()
				sm.sendGetHeaders(peer, locator)
				return
			}

			// Genuinely bad header (PoW, fork-before-checkpoint, mid-batch
			// orphan, etc.).  Score depends on error type: most invalid =
			// 100 (instant ban); fork-before-checkpoint = 20 (IBD soft).
			// W15 root-cause fix (ref: wave14-2026-04-14/BLOCKBREW-DURABILITY.md):
			// during IBD catch-up we intentionally cap non-PoW header errors at a
			// small score so a transient chain-ambiguity burst from a single peer
			// (orphan window, checkpoint-fork false positive after a header-index
			// race) cannot drain the outbound peer pool in one hit.  A peer that
			// is genuinely feeding invalid PoW or a checkpoint-contradicting chain
			// still gets the full +100 — we key off error type, not peer identity.
			score := ScoreInvalidBlock
			switch err {
			case consensus.ErrOrphanHeader:
				// Mid-batch orphan: keep the legacy +20 (this should be
				// rare; the peer announced a chain that breaks part-way
				// through, which is closer to inconsistent than missing).
				score = ScoreHeadersDontConnect
			case consensus.ErrForkBeforeCheckpoint:
				// Reduced during IBD to avoid banning honest peers whose batches
				// briefly expose a cross-branch ancestor during catch-up.  Outside
				// IBD this error is unlikely and still deserves a heavier penalty.
				if sm.chainMgr != nil && sm.chainMgr.IsIBD() {
					score = ScoreHeadersDontConnectIBD
				}
			}
			log.Printf("sync: bad header from %s at height %d: %v",
				addr, sm.headerIndex.BestHeight()+1, err)
			// Flush any headers we accepted before the bad one so crash
			// recovery sees them.
			if sm.chainDB != nil && len(pendingHeaders) > 0 {
				if err := sm.chainDB.StoreBlockHeadersBatch(pendingHeaders); err != nil {
					log.Printf("sync: failed to flush %d pending headers: %v",
						len(pendingHeaders), err)
				}
			}
			peer.Misbehaving(score, fmt.Sprintf("invalid header: %v", err))
			peer.Disconnect()
			sm.syncPeer = nil
			go sm.startHeaderSync() // Try another peer
			return
		}

		headersAdded++

		// Buffer the header for the batched DB write below.
		if sm.chainDB != nil {
			pendingHeaders = append(pendingHeaders, storage.HeaderBatchEntry{
				Hash:   node.Hash,
				Header: &headers[i],
			})
		}
	}

	// Single batched write for every accepted header in this message.
	if sm.chainDB != nil && len(pendingHeaders) > 0 {
		if err := sm.chainDB.StoreBlockHeadersBatch(pendingHeaders); err != nil {
			log.Printf("sync: failed to batch-store %d headers: %v",
				len(pendingHeaders), err)
		}
	}

	newHeight := sm.headerIndex.BestHeight()
	if headersAdded > 0 {
		log.Printf("sync: added %d headers (%d -> %d)", headersAdded, startHeight, newHeight)
		// Core parity: reset the unconnecting-headers counter on any
		// successfully-connecting batch from this peer.  Mirrors
		// nUnconnectingHeaders = 0 in the success path of
		// net_processing.cpp::ProcessHeadersMessage.
		delete(sm.unconnectingHeaders, addr)
	}

	// W17 chainmgr-startup recovery: if the chain manager is still holding
	// a saved tip that wasn't yet in the header index at boot, retry the
	// reconciliation now that more headers have arrived.  Without this
	// hook the tip stays at genesis until OnSyncComplete fires — which
	// never happens on mainnet when every header batch is a full
	// MaxHeadersPerRequest (stale-tip detection re-triggers before a
	// short final batch is ever returned).  See
	// wave16-2026-04-15/BLOCKBREW-DURABILITY-VERIFIED.md.
	if headersAdded > 0 && sm.chainMgr != nil && sm.chainMgr.HasPendingRecovery() {
		sm.chainMgr.ReloadChainState()
	}

	// W17 block-download kickoff: once the chain manager has a non-genesis
	// tip AND headers have advanced past it AND no download pipeline is
	// active yet, start block download inline.  We check this every
	// header batch (not just immediately after recovery) because the
	// initial recovery may land at a height exactly equal to the current
	// bestTip height — StartBlockDownload short-circuits on
	// bestTip.Height <= startHeight, and we rely on the next header
	// batch to push bestTip above the restored tip before we can queue
	// any downloads.
	if headersAdded > 0 && sm.chainMgr != nil && len(sm.blockQueue) == 0 && !sm.headersSynced {
		if _, tipHeight := sm.chainMgr.BestBlock(); tipHeight > 0 && sm.headerIndex.BestHeight() > tipHeight {
			// Release sm.mu first because StartBlockDownload takes it.
			sm.mu.Unlock()
			log.Printf("sync: chain manager tip at height %d, headers at %d, starting block download",
				tipHeight, sm.headerIndex.BestHeight())
			sm.StartBlockDownload()
			sm.mu.Lock()
		}
	}

	// Check if we received a full batch
	if len(headers) == MaxHeadersPerRequest {
		// More headers available — request next batch
		locator := sm.headerIndex.BestTip().BuildLocator()
		sm.sendGetHeaders(peer, locator)
	} else {
		// Sync complete (received fewer than max headers).
		//
		// In the at-tip steady state the periodic getheaders broadcast
		// (sendPeriodicGetHeaders) delivers a short — usually empty — headers
		// message from every peer every few seconds.  Re-running the
		// completion side-effects (log line + onSyncComplete →
		// StartBlockDownload) on each of those is what produced the ~920k-line
		// "header sync complete" / "no blocks to download" log spam observed on
		// the mainnet node.  Only fire the completion path when this batch
		// actually advanced our header tip OR is the first transition into the
		// synced state; an empty/duplicate batch leaves nothing new to download.
		firstCompletion := !sm.headersSynced
		sm.headersSynced = true
		sm.syncPeer = nil

		if headersAdded > 0 || firstCompletion {
			log.Printf("sync: header sync complete at height %d", newHeight)

			// Persist the best header tip
			if sm.chainDB != nil {
				sm.persistHeaderTip()
			}

			if sm.onSyncComplete != nil {
				// Run callback in a goroutine to avoid deadlock:
				// HandleHeaders holds sm.mu, and StartBlockDownload
				// also needs sm.mu
				go sm.onSyncComplete()
			}
		}
	}
}

// persistHeaderTip saves the current best header to the database.
func (sm *SyncManager) persistHeaderTip() {
	tip := sm.headerIndex.BestTip()
	state := &storage.ChainState{
		BestHash:   tip.Hash,
		BestHeight: tip.Height,
	}

	// Use BestHeaderKey to distinguish from chain tip
	if err := sm.chainDB.DB().Put(storage.BestHeaderKey, state.Serialize()); err != nil {
		log.Printf("sync: failed to persist header tip: %v", err)
	}
}

// HandlePeerConnected is called when a new peer connects.
// Use this to potentially start or restart sync.
func (sm *SyncManager) HandlePeerConnected(peer *Peer) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// If we have no sync peer and aren't synced, start syncing
	if sm.syncPeer == nil && !sm.headersSynced {
		// Release lock before starting sync (it will acquire it)
		sm.mu.Unlock()
		sm.startHeaderSync()
		sm.mu.Lock()
		return
	}

	// If peer has a better height than our current sync peer, consider switching
	if sm.syncPeer != nil && peer.StartHeight() > sm.syncPeer.StartHeight() {
		// For simplicity, we don't switch mid-sync
		// In production, you might want to be more aggressive
	}
}

// HandlePeerDisconnected is called when a peer disconnects.
func (sm *SyncManager) HandlePeerDisconnected(peer *Peer) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Clean up any PRESYNC/REDOWNLOAD state for this peer.
	addr := peer.Address()
	delete(sm.peerHeadersSync, addr)

	// If our sync peer disconnected, find a new one
	if peer == sm.syncPeer {
		sm.syncPeer = nil
		if !sm.headersSynced {
			log.Printf("sync: sync peer %s disconnected, finding new peer", addr)
			// Release lock before starting sync
			sm.mu.Unlock()
			sm.startHeaderSync()
			sm.mu.Lock()
		}
	}
}

// IsSynced returns true if header sync is complete.
func (sm *SyncManager) IsSynced() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.headersSynced
}

// CurrentHeight returns the current best header height.
func (sm *SyncManager) CurrentHeight() int32 {
	return sm.headerIndex.BestHeight()
}

// SyncPeer returns the current sync peer, or nil.
func (sm *SyncManager) SyncPeer() *Peer {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.syncPeer
}

// HandleGetHeaders responds to a getheaders request from a peer.
// This allows us to serve headers to other nodes.
func (sm *SyncManager) HandleGetHeaders(peer *Peer, msg *MsgGetHeaders) {
	// Find the best starting point from the locators
	var startNode *consensus.BlockNode
	for _, hash := range msg.BlockLocators {
		node := sm.headerIndex.GetNode(hash)
		if node != nil {
			startNode = node
			break
		}
	}

	// If no locator matched, start from genesis
	if startNode == nil {
		startNode = sm.headerIndex.Genesis()
	}

	// Collect headers starting after startNode
	headers := make([]wire.BlockHeader, 0, MaxHeadersPerRequest)
	bestTip := sm.headerIndex.BestTip()

	for height := startNode.Height + 1; height <= bestTip.Height && len(headers) < MaxHeadersPerRequest; height++ {
		node := bestTip.GetAncestor(height)
		if node == nil {
			break
		}
		headers = append(headers, node.Header)

		// Stop if we hit the stop hash
		if !msg.HashStop.IsZero() && node.Hash == msg.HashStop {
			break
		}
	}

	// Send response
	response := &MsgHeaders{
		Headers: headers,
	}
	peer.SendMessage(response)
}

// CreatePeerListeners returns PeerListeners configured for sync.
// Use this to integrate with PeerManager.
func (sm *SyncManager) CreatePeerListeners() *PeerListeners {
	return &PeerListeners{
		OnHeaders: func(p *Peer, msg *MsgHeaders) {
			sm.HandleHeaders(p, msg)
		},
		OnGetHeaders: func(p *Peer, msg *MsgGetHeaders) {
			sm.HandleGetHeaders(p, msg)
		},
		OnBlock: func(p *Peer, msg *MsgBlock) {
			sm.HandleBlock(p, msg)
		},
		OnGetData: func(p *Peer, msg *MsgGetData) {
			sm.HandleGetData(p, msg)
		},
		OnNotFound: func(p *Peer, msg *MsgNotFound) {
			sm.HandleNotFound(p, msg)
		},
		OnInv: func(p *Peer, msg *MsgInv) {
			sm.HandleInv(p, msg)
		},
		// BIP152: Handle compact block relay messages
		OnSendCmpct: func(p *Peer, msg *MsgSendCmpct) {
			log.Printf("[compact] Peer %s supports compact blocks: version=%d, announce=%v",
				p.Address(), msg.CmpctBlockVersion, msg.AnnounceUsingCmpctBlock)
		},
		OnCmpctBlock: func(p *Peer, msg *MsgCmpctBlock) {
			// We don't have a mempool, so we can't reconstruct the block from
			// short IDs. Fall back to requesting the full block via getdata.
			blockHash := msg.Header.BlockHash()

			// MAX_CMPCTBLOCK_DEPTH guard (Bitcoin Core net_processing.cpp:2466):
			// If the announced block is more than MaxCmpctBlockDepth below our
			// best tip, we would not serve it as a compact block ourselves —
			// log and request full block regardless (our current fallback).
			if sm.headerIndex != nil {
				tipHeight := sm.headerIndex.BestHeight()
				if node := sm.headerIndex.GetNode(blockHash); node != nil {
					depth := tipHeight - node.Height
					if depth > MaxCmpctBlockDepth {
						log.Printf("[compact] cmpctblock from %s is %d deep (limit %d), requesting full block (hash=%s)",
							p.Address(), depth, MaxCmpctBlockDepth, blockHash)
					}
				}
			}

			log.Printf("[compact] Received cmpctblock from %s, falling back to full block request (hash=%s)",
				p.Address(), blockHash)
			inv := &MsgGetData{
				InvList: []*InvVect{
					{Type: InvTypeWitnessBlock, Hash: blockHash},
				},
			}
			p.SendMessage(inv)
		},
		OnGetBlockTxn: func(p *Peer, msg *MsgGetBlockTxn) {
			// Peer requesting missing transactions for compact block reconstruction.
			// MAX_BLOCKTXN_DEPTH guard (Bitcoin Core net_processing.cpp):
			// If the requested block is more than MaxBlocktxnDepth below our best
			// tip, fall back to sending the full block instead of serving blocktxn.
			// We don't serve compact blocks yet, so in either case we ignore, but
			// the depth check ensures correct behaviour once serving is implemented.
			if sm.headerIndex != nil {
				tipHeight := sm.headerIndex.BestHeight()
				if node := sm.headerIndex.GetNode(msg.BlockHash); node != nil {
					depth := tipHeight - node.Height
					if depth > MaxBlocktxnDepth {
						log.Printf("[compact] getblocktxn from %s for block %s is %d deep (limit %d), would fall back to full block",
							p.Address(), msg.BlockHash, depth, MaxBlocktxnDepth)
						// TODO(BUG-3): once OnGetBlockTxn serving is implemented,
						// send full block via getdata here instead of blocktxn.
						return
					}
				}
			}
			log.Printf("[compact] Received getblocktxn from %s, ignoring", p.Address())
		},
		OnBlockTxn: func(p *Peer, _ *MsgBlockTxn) {
			// Response to our getblocktxn request. Since we fall back to full
			// block download, we shouldn't receive these. Ignore.
			log.Printf("[compact] Received blocktxn from %s, ignoring", p.Address())
		},
	}
}

// HandleInv processes an inv message from a peer.
// When a peer announces new blocks via inv, request headers to learn
// about them.  This is how nodes at tip discover new blocks.
// Reference: Bitcoin Core net_processing.cpp ProcessMessage("inv").
// HandleInv processes an inv message from a peer.
// When a peer announces new blocks via inv, request headers to learn
// about them.  This is how nodes at tip discover new blocks.
// Reference: Bitcoin Core net_processing.cpp ProcessMessage("inv").
func (sm *SyncManager) HandleInv(peer *Peer, msg *MsgInv) {
	hasBlock := false
	var txReqs []*InvVect
	for _, inv := range msg.InvList {
		baseType := inv.Type &^ InvWitnessFlag
		switch baseType {
		case InvTypeBlock:
			hasBlock = true
		case InvTypeTx, InvTypeWtx:
			// Collect tx announcements to (maybe) request. Actual REQUEST
			// decision (IBD gate, block-relay-only, membership, dedup) is
			// made in maybeRequestTx below. baseType is InvTypeTx (MSG_TX=1,
			// txid) or InvTypeWtx (MSG_WTX=5, wtxid); InvTypeWitnessTx
			// (0x40000001) folds into InvTypeTx after stripping the witness
			// flag and is treated as a txid announcement.
			txReqs = append(txReqs, inv)
		}
	}

	// Block announcements → learn about the new block(s) via getheaders.
	if hasBlock {
		sm.sendGetHeadersTo(peer)
	}

	// Tx announcements → request any we don't already have. Reference:
	// Bitcoin Core net_processing.cpp ProcessMessage("inv"), which feeds
	// MSG_TX / MSG_WTX invs into the TxRequestTracker and later issues a
	// getdata for each not-already-known tx.
	if len(txReqs) > 0 {
		sm.requestAnnouncedTxs(peer, txReqs)
	}
}

// requestAnnouncedTxs issues getdata for transactions a peer announced via inv
// that we do not already have (mempool membership) and have not already
// requested (txInflight dedup). Mirrors Bitcoin Core's tx-inv handling:
//   - Skip entirely during IBD — we don't relay/accept loose txs until synced
//     (Core: `if (fInitialDownload) return;` guard around tx handling).
//   - Skip block-relay-only connections — no tx relay on those links.
//   - Skip txs already in the mempool or already in flight (dedup).
//
// The getdata reuses the exact type/hash the peer announced, which naturally
// respects the per-peer BIP-339 wtxid negotiation: a wtxid-relay peer
// announces MSG_WTX+wtxid (we request the same), a legacy peer announces
// MSG_TX+txid.
//
// NOTE: Bitcoin Core additionally suppresses re-requests of txs in its
// recently-rejected filter (m_recent_rejects). blockbrew has no such filter
// yet, so a peer can re-offer a rejected tx and we will re-request it once per
// txInflightExpiry window. Documented gap, not a correctness bug.
func (sm *SyncManager) requestAnnouncedTxs(peer *Peer, invs []*InvVect) {
	if sm.mempool == nil {
		return
	}
	// Skip during IBD: we are not participating in loose-tx relay yet.
	if sm.ibdActive.Load() {
		return
	}
	// Skip block-relay-only connections (no tx relay on those links).
	if peer != nil && peer.TxRelayDisabled() {
		return
	}

	var getData []*InvVect
	now := time.Now()

	sm.mu.Lock()
	for _, inv := range invs {
		baseType := inv.Type &^ InvWitnessFlag

		// Already in the mempool? Nothing to request. For wtxid
		// announcements we must look up by wtxid; txid announcements by txid.
		var have bool
		if baseType == InvTypeWtx {
			have = sm.mempool.GetTxByWTxid(inv.Hash) != nil
		} else {
			have = sm.mempool.HasTransaction(inv.Hash)
		}
		if have {
			continue
		}

		// Already requested (and not yet expired)? Don't re-request.
		if reqAt, ok := sm.txInflight[inv.Hash]; ok {
			if now.Sub(reqAt) < txInflightExpiry {
				continue
			}
			// Stale slot: fall through and re-request, refreshing the stamp.
		}

		sm.txInflight[inv.Hash] = now
		// Request the same type/hash the peer announced (respects BIP-339).
		getData = append(getData, &InvVect{Type: inv.Type, Hash: inv.Hash})
	}
	sm.mu.Unlock()

	if len(getData) > 0 {
		peer.SendMessage(&MsgGetData{InvList: getData})
	}
}

// NotifyTxReceived clears a transaction's entry from the request-dedup set
// once we have received (or otherwise resolved) it. Called from the tx-accept
// path so an accepted tx's in-flight slot is reclaimed immediately rather than
// waiting for txInflightExpiry. Both the txid and wtxid keys are cleared
// because either could have been the announced/in-flight hash depending on the
// announcing peer's BIP-339 negotiation.
func (sm *SyncManager) NotifyTxReceived(txid, wtxid wire.Hash256) {
	sm.mu.Lock()
	delete(sm.txInflight, txid)
	delete(sm.txInflight, wtxid)
	sm.mu.Unlock()
}

// sendPeriodicGetHeaders sends getheaders to connected peers to discover new
// blocks.  Called periodically after IBD completes.
//
// Previously this picked ONE uniformly-random peer and sent a single-hash
// locator.  On mainnet that is fragile: if the chosen peer is at-or-behind our
// tip (block-relay-only, feeler, or a laggard fleet node) it answers with an
// empty headers message and we make no progress.  When a running node falls
// behind the network tip and no fresh inv covers the gap (e.g. after an
// OOM-restart that left the chain a few dozen blocks back, or after the peers
// that were announcing churn out), the gap could persist for many minutes —
// the node only inched forward one header per freshly-mined block via the inv
// path and never bulk-recovered the gap.  Observed on the mainnet blockbrew
// node: header index pinned at 952342 while the network was at 952389,
// "no blocks to download, already at height 952342" looping every 5 s.
//
// Fix: broadcast getheaders to every connected peer using a FULL block locator
// (BuildLocator) from our best header tip.  Any peer that is ahead returns the
// gap (up to MaxHeadersPerRequest in one batch); peers that are not ahead reply
// empty and cost one cheap round-trip.  This mirrors Bitcoin Core's periodic
// header fetch in PeerManagerImpl::SendMessages, which solicits headers from
// peers rather than relying solely on inv announcements.
func (sm *SyncManager) sendPeriodicGetHeaders() {
	sm.mu.RLock()
	pm := sm.peerMgr
	// Do NOT broadcast a tip-rooted getheaders while a headerssync pipeline is
	// active for any peer — the reply would re-enter that peer's live
	// HeadersSyncState out of order (false "non-continuous" abort). The pipeline
	// owns header requests via NextLocator. Core's periodic header fetch in
	// SendMessages is likewise gated off while presync is active.
	if len(sm.peerHeadersSync) > 0 {
		sm.mu.RUnlock()
		return
	}
	// Build the locator once from the best header tip so we ask for everything
	// above our highest known header (not just above the connected chain tip).
	var locator []wire.Hash256
	if sm.headerIndex != nil {
		if tip := sm.headerIndex.BestTip(); tip != nil {
			locator = tip.BuildLocator()
		}
	}
	sm.mu.RUnlock()
	if pm == nil {
		return
	}
	if len(locator) == 0 {
		// Fall back to the chain-tip single-hash locator if the header index
		// has no usable tip yet.
		peers := pm.ConnectedPeers()
		if len(peers) > 0 {
			sm.sendGetHeadersTo(peers[0])
		}
		return
	}

	peers := pm.ConnectedPeers()
	if len(peers) == 0 {
		return
	}
	for _, peer := range peers {
		if !peer.IsConnected() {
			continue
		}
		sm.sendGetHeaders(peer, locator)
	}
}

// tipMayBeStale checks if our chain tip hasn't advanced in StaleTipThreshold.
// Reference: Bitcoin Core TipMayBeStale()
func (sm *SyncManager) tipMayBeStale() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Don't consider stale during active IBD with blocks in flight
	if len(sm.inflight) > 0 {
		return false
	}
	return time.Since(sm.lastTipUpdate) > StaleTipThreshold
}

// checkStaleTip detects when our chain tip hasn't advanced and triggers re-sync.
// Reference: Bitcoin Core CheckForStaleTipAndEvictPeers()
func (sm *SyncManager) checkStaleTip() {
	sm.mu.RLock()
	now := time.Now()
	nextCheck := sm.nextStaleTipCheck
	sm.mu.RUnlock()

	if now.Before(nextCheck) {
		return
	}

	// Schedule next check
	sm.mu.Lock()
	sm.nextStaleTipCheck = now.Add(StaleTipCheckInterval)
	sm.mu.Unlock()

	if !sm.tipMayBeStale() {
		return
	}

	// Do NOT re-issue a tip-rooted getheaders while a PRESYNC/REDOWNLOAD
	// headerssync pipeline is active. During a from-genesis IBD, presync
	// deliberately does not store low-work headers, so headerIndex.BestTip()
	// stays frozen (e.g. at 450000) and lastTipUpdate (advanced only on block
	// connect) never moves during the headers phase — so this stale-tip path
	// fires ~StaleTipThreshold (30min) in and sends a getheaders rooted at the
	// FROZEN tip to the active sync peer. That reply re-enters the live
	// HeadersSyncState whose lastHeaderReceived has already advanced, tripping
	// the continuity check → false "non-continuous at height=N (presync)" abort
	// and a self-inflicted disconnect (the genesis-IBD wedge at h452000).
	// Bitcoin Core's CheckForStaleTipAndEvictPeers never sends getheaders for
	// exactly this reason (net_processing.cpp:5372 only SetTryNewOutboundPeer);
	// legitimate presync next-batch requests flow through HeadersSyncState via
	// NextLocator in HandleHeaders. Skip while any pipeline is active.
	sm.mu.RLock()
	presyncActive := len(sm.peerHeadersSync) > 0
	sm.mu.RUnlock()
	if presyncActive {
		return
	}

	sm.mu.RLock()
	staleDuration := time.Since(sm.lastTipUpdate)
	sm.mu.RUnlock()

	log.Printf("sync: potential stale tip detected (last tip update: %v ago), requesting headers from peers",
		staleDuration.Round(time.Second))

	// Get peer manager
	sm.mu.RLock()
	pm := sm.peerMgr
	sm.mu.RUnlock()
	if pm == nil {
		return
	}

	peers := pm.ConnectedPeers()
	if len(peers) == 0 {
		return
	}

	// Find our current height
	var ourHeight int32
	if sm.chainMgr != nil {
		_, ourHeight = sm.chainMgr.BestBlock()
	}

	// Find the peer with the highest tip and disconnect the worst peer
	var bestPeer *Peer
	var bestHeight int32
	var worstPeer *Peer
	var worstHeight int32 = int32(1<<31 - 1) // MaxInt32

	for _, p := range peers {
		peerHeight := p.StartHeight()
		if peerHeight > bestHeight {
			bestHeight = peerHeight
			bestPeer = p
		}
		if peerHeight < worstHeight {
			worstHeight = peerHeight
			worstPeer = p
		}
	}

	// If any peer reports a higher tip than ours, we're behind
	if bestPeer != nil && bestHeight > ourHeight {
		// Disconnect the worst peer to make room for better ones
		if worstPeer != nil && worstPeer != bestPeer && worstHeight < ourHeight {
			log.Printf("sync: disconnecting stale peer %s (height %d, ours %d)",
				worstPeer.Address(), worstHeight, ourHeight)
			worstPeer.Disconnect()
		}

		// Request headers from the best peer
		log.Printf("sync: requesting headers from best peer %s (height %d)",
			bestPeer.Address(), bestHeight)
		sm.sendGetHeadersTo(bestPeer)
	} else {
		// No peer ahead of us — send getheaders to random peer to discover
		sm.sendPeriodicGetHeaders()
	}
}

// sendGetHeadersTo sends a getheaders message to a specific peer using a full
// exponential block locator built from our best header tip.
//
// A degenerate single-hash locator ([chainTip]) only works when the peer's
// active chain contains exactly that block; if the peer is on a slightly
// different view (transient reorg, or it indexed our tip on a stale branch) it
// cannot find a common ancestor and replies empty.  A full locator (Core's
// CBlockLocator / GetLocator) lets the peer walk back to the real fork point
// and always return the headers above it.  We anchor on the header-index tip
// (not the connected chain tip) so that, when headers are ahead of the
// connected chain, we still solicit everything above our highest known header.
func (sm *SyncManager) sendGetHeadersTo(peer *Peer) {
	var locator []wire.Hash256
	if sm.headerIndex != nil {
		if tip := sm.headerIndex.BestTip(); tip != nil {
			locator = tip.BuildLocator()
		}
	}
	if len(locator) == 0 {
		// Fall back to the connected chain tip if the header index is empty.
		if sm.chainMgr == nil {
			return
		}
		bestHash, _ := sm.chainMgr.BestBlock()
		locator = []wire.Hash256{bestHash}
	}
	sm.sendGetHeaders(peer, locator)
}

// HandleNotFound processes a notfound message from a peer.
// When a peer doesn't have a requested block, it responds with notfound.
// We need to remove the block from inflight and mark it for retry with a
// different peer, otherwise it stays in-flight until it times out.
func (sm *SyncManager) HandleNotFound(peer *Peer, msg *MsgNotFound) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, inv := range msg.InvList {
		baseType := inv.Type &^ InvWitnessFlag
		if baseType != InvTypeBlock {
			continue
		}

		req, ok := sm.inflight[inv.Hash]
		if !ok {
			continue
		}

		// Record peer as unable to serve this block.  Log only on first
		// notice per (peer, block) pair — repeat notfounds from the same
		// peer for the same block are a spam source (14M log lines in a
		// day on mainnet) and add no new information.
		addr := peer.Address()
		if req.FailedPeers == nil {
			req.FailedPeers = make(map[string]struct{})
		}
		if _, seen := req.FailedPeers[addr]; !seen {
			req.FailedPeers[addr] = struct{}{}
			log.Printf("sync: peer %s does not have block height=%d hash=%s (failed_peers=%d), will retry with different peer",
				addr, req.Height, inv.Hash.String()[:16], len(req.FailedPeers))
		}

		// Remove from inflight and mark for retry with a different peer
		delete(sm.inflight, inv.Hash)
		req.State = BlockDownloadPending
		req.RetryCount++
		// Keep req.Peer so requestBlocks can avoid this peer
	}
}

// HandleGetData responds to getdata requests by sending requested blocks and transactions.
//
// BIP-159 peer-served-blocks gate: when prune mode is on, refuse to serve
// blocks below the prune horizon (tip - MIN_BLOCKS_TO_KEEP).  Mirrors Core's
// net_processing.cpp `ProcessGetBlockData` which short-circuits and emits a
// `notfound` for any historical block the pruned node no longer has.  Without
// this gate a pruned node would attempt a disk read for a deleted block and
// either return a stale error to the peer or hang the request.
func (sm *SyncManager) HandleGetData(peer *Peer, msg *MsgGetData) {
	// Determine the prune horizon once for the whole batch.
	pruneHorizon := int32(-1) // -1 = no gate
	if sm.pruner != nil && sm.pruner.TargetBytes() > 0 && sm.chainMgr != nil {
		_, tipHeight := sm.chainMgr.BestBlock()
		if tipHeight > int32(storage.MinBlocksToKeep) {
			pruneHorizon = tipHeight - int32(storage.MinBlocksToKeep)
		}
	}

	var notFound []*InvVect
	for _, inv := range msg.InvList {
		// Strip witness flag to get base type
		baseType := inv.Type &^ InvWitnessFlag
		switch baseType {
		case InvTypeBlock:
			// Prune-mode gate: if we're a NODE_NETWORK_LIMITED node and the
			// requested block is below tip-288, decline with notfound.
			if pruneHorizon >= 0 && sm.headerIndex != nil {
				if node := sm.headerIndex.GetNode(inv.Hash); node != nil &&
					node.Height < pruneHorizon {
					notFound = append(notFound, inv)
					continue
				}
			}
			block, err := sm.chainDB.GetBlock(inv.Hash)
			if err != nil {
				// On any read error in prune mode, send a notfound so the
				// peer can re-request from a NODE_NETWORK peer instead of
				// hanging.  Outside prune mode we keep the legacy log+skip.
				if pruneHorizon >= 0 {
					notFound = append(notFound, inv)
				} else {
					log.Printf("sync: getdata block %x not found: %v", inv.Hash[:4], err)
				}
				continue
			}
			log.Printf("sync: serving block at %x to peer %s", inv.Hash[:4], peer.Address())
			peer.SendMessage(&MsgBlock{Block: block})
		case InvTypeTx, InvTypeWtx:
			// Serve a transaction from the mempool. Mirrors Bitcoin Core's
			// net_processing.cpp ProcessGetData -> FindTxForGetData: look the
			// tx up in the mempool and send it as a `tx` message, or append to
			// `notfound` on a miss so the peer can ask elsewhere. baseType is
			// InvTypeTx (MSG_TX / MSG_WITNESS_TX -> txid lookup) or InvTypeWtx
			// (MSG_WTX -> wtxid lookup, BIP-339). blockbrew always serializes
			// transactions with their witness, so both branches return the
			// full witness tx (no separate witness-stripping like Core's
			// legacy MSG_TX path).
			if sm.mempool == nil {
				notFound = append(notFound, inv)
				continue
			}
			var tx *wire.MsgTx
			if baseType == InvTypeWtx {
				tx = sm.mempool.GetTxByWTxid(inv.Hash)
			} else {
				tx = sm.mempool.GetTransaction(inv.Hash)
			}
			if tx == nil {
				notFound = append(notFound, inv)
				continue
			}
			peer.SendMessage(&MsgTx{Tx: tx})
		}
	}
	if len(notFound) > 0 {
		peer.SendMessage(&MsgNotFound{InvList: notFound})
	}
}

// ============================================================================
// IBD (Initial Block Download) Pipeline
// ============================================================================

// StartBlockDownload begins downloading blocks after headers are synced.
// This is called automatically when header sync completes.
func (sm *SyncManager) StartBlockDownload() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Guard against duplicate invocations: check whether blockQueue was
	// already populated rather than ibdActive (which is now always true
	// until the tip is recent, not just during block download).
	if len(sm.blockQueue) > 0 {
		// W13 fix: before short-circuiting, sweep the queue for entries
		// whose owning peer has been disconnected/banned. W8/W12 post-mortem
		// showed this guard firing repeatedly while the queue was populated
		// entirely with stale in-flight slots held by banned peers, which
		// prevented any progress.
		evicted := 0
		for _, req := range sm.blockQueue {
			if req.Peer != nil && (!req.Peer.IsConnected() || req.Peer.ShouldBan()) {
				if req.State == BlockDownloadInFlight {
					delete(sm.inflight, req.Hash)
				}
				req.State = BlockDownloadPending
				req.Peer = nil
				req.RetryCount = 0
				evicted++
			}
		}
		if evicted > 0 {
			log.Printf("sync: StartBlockDownload evicted %d stale slots owned by dead peers", evicted)
		}

		// #30 fix: rebuild a STALE queue instead of pinning it forever. The queue
		// is built once from chainMgr.BestBlock() as the walk floor; on a
		// -load-snapshot boot that floor is a stale genesis (the snapshot base
		// header is not yet in the index, so BestBlock()==genesis), so the walk
		// floors at genesis and enqueues heights 1.. that the snapshot UTXO set
		// already covers. Once ReloadChainState adopts the real tip the queue is
		// stale, but the old unconditional "return" pinned it forever (nextH=1).
		//
		// Detect staleness by ANCESTRY, not height: rebuild iff the LOWEST queued
		// block is now ON the active validated chain (an ancestor of the validated
		// tip = already covered). This is exactly the snapshot case (floor=block1,
		// an ancestor of validated tip 944183). It is deliberately FALSE for a
		// below-tip heavier fork: that queue's floor (F+1) is on the FORK, NOT an
		// ancestor of the active tip H, so onActiveChain is false and the GAP2
		// fork-aware queue is left fully intact (reorg-drop invariant preserved —
		// see TestConnectPendingBlocks_BelowTipHeavierForkReorgs).
		stale := false
		var floorH int32
		if sm.chainMgr != nil && sm.headerIndex != nil && len(sm.blockQueue) > 0 {
			floor := sm.blockQueue[0]
			for _, req := range sm.blockQueue {
				if req.Height < floor.Height {
					floor = req
				}
			}
			floorH = floor.Height
			if tipHash, _ := sm.chainMgr.BestBlock(); tipHash != (wire.Hash256{}) {
				if at := sm.headerIndex.GetNode(tipHash); at != nil {
					if fn := sm.headerIndex.GetNode(floor.Hash); fn != nil {
						// CChain::Contains: fn is on the active chain iff it is at/
						// below the validated tip AND the tip's ancestor at fn.Height
						// is fn itself.
						stale = fn.Height <= at.Height && at.GetAncestor(fn.Height) == fn
					}
				}
			}
		}
		if stale {
			log.Printf("sync: StartBlockDownload rebuilding stale queue (floor height %d now on the active validated chain — rebuilding from the real tip)", floorH)
			// Drop the stale queue + its in-flight bookkeeping and fall through to a
			// fresh fork-aware build below; the running blockDownloadLoop exits via
			// its drain branch and this call relaunches one.
			for _, req := range sm.blockQueue {
				delete(sm.inflight, req.Hash)
			}
			sm.blockQueue = nil
			// fall through to the build path
		} else {
			log.Printf("sync: StartBlockDownload called but block queue already populated (floor=%d)", floorH)
			return
		}
	}

	// Determine where to start downloading from
	startHeight := int32(0)
	if sm.chainMgr != nil {
		_, startHeight = sm.chainMgr.BestBlock()
	}

	// Build the block queue from headers.
	bestTip := sm.headerIndex.BestTip()
	if bestTip == nil {
		log.Printf("sync: no blocks to download, header index empty (startHeight=%d)", startHeight)
		return
	}

	// GAP2 fix (Core FindNextBlocksToDownload, net_processing.cpp; ports the
	// shipped rustoshi Unit-E E3 fork-aware download floor). We must collect
	// EVERY block whose body we still need on the path from bestTip back to the
	// fork point — NOT just the blocks strictly above the active validated tip.
	//
	// The old code floored the walk at startHeight (= chainMgr.BestBlock()),
	// so for a heavier branch that forks BELOW the active tip (active tip H,
	// fork point F < H, fork tip T > H by work) it collected only H+1..T and
	// STOPPED at the sibling whose Height == H. The bridging fork bodies at
	// F+1..H were never enqueued → never getdata-d → ConnectBlock never saw the
	// fork tip → the (already P2P-reachable) ReorgTo trigger was starved. The
	// SOLE disqualifier for blockbrew's reorg path.
	//
	// Core's rule (line 1506): a block on the walk is skipped iff we already
	// HAVE its body (BLOCK_HAVE_DATA, here StatusDataStored) OR it is on the
	// active chain (Contains — covers a pruned-but-active body). We descend by
	// ancestry from bestTip and stop at the deepest ancestor that satisfies that
	// predicate — the common ancestor / fork point. With NO active-tip height
	// floor on the walk.
	//
	// Resolve the active validated tip BlockNode (chainMgr tip hash → index
	// node) so we can test "on active chain" precisely. When it cannot be
	// resolved (pre-init, or a stub connector with no real tip hash), fall back
	// to the legacy startHeight floor so steady-state behaviour is unchanged.
	var activeTip *consensus.BlockNode
	if sm.chainMgr != nil {
		if tipHash, _ := sm.chainMgr.BestBlock(); tipHash != (wire.Hash256{}) {
			activeTip = sm.headerIndex.GetNode(tipHash)
		}
	}

	// onActiveChain reports whether n is on the active validated chain (an
	// ancestor of, or equal to, the active tip). Mirrors CChain::Contains.
	onActiveChain := func(n *consensus.BlockNode) bool {
		if activeTip != nil {
			if n.Height > activeTip.Height {
				return false
			}
			return activeTip.GetAncestor(n.Height) == n
		}
		// Legacy fallback (no resolvable active tip node): treat everything at
		// or below the connected height as already-on-chain, exactly the old
		// startHeight floor.
		return n.Height <= startHeight
	}

	// needBody reports whether we still have to download n's block body: we do
	// NOT have its data AND it is not already on the active chain. The descent
	// stops at the first ancestor for which this is false — the fork point.
	needBody := func(n *consensus.BlockNode) bool {
		if n.Status&consensus.StatusDataStored != 0 {
			return false
		}
		return !onActiveChain(n)
	}

	// If bestTip itself is already covered, there is nothing to fetch. This
	// replaces the old `bestTip.Height <= startHeight` early-return: it does NOT
	// bail when bestTip has MORE WORK than the active tip but is not strictly
	// taller (a below-tip heavier fork), because needBody(bestTip) is true there.
	if !needBody(bestTip) {
		log.Printf("sync: no blocks to download, best tip already have-data/on-chain at height %d (startHeight=%d)",
			bestTip.Height, startHeight)
		return
	}

	// Walk from bestTip back to the fork point collecting the blocks we need,
	// then reverse to ascending order. O(n) parent walk (no repeated
	// GetAncestor). Cap the descent depth defensively so a pathologically deep
	// or malformed fork cannot enqueue an unbounded set — a reorg deeper than
	// MaxReorgDepth would be refused by ReorgTo anyway. We never floor on the
	// active tip height; the floor is purely the have-data / on-chain fork
	// point (Core BLOCK_HAVE_DATA), bounded by MaxReorgDepth.
	// #30 fix: descend-from-bestTip + the MaxReorgDepth cap is correct for a REORG
	// (a fork within MaxReorgDepth of the tip), but for a large IBD / forward-sync
	// gap (bestTip far above the validated floor) it would collect the TOP
	// MaxReorgDepth blocks near the header tip while sequential validation needs
	// the BOTTOM (startHeight+1) next — wedging the connect loop (the snapshot &
	// genesis fresh-sync stalls). When the gap exceeds MaxReorgDepth, start the
	// descent from a capped height just above the floor so we collect the bottom
	// window (startHeight+1 ..) in ascending order; the drain-rebuild advances the
	// window each time it empties. This does NOT change reorg behaviour: a legit
	// below-tip fork has bestTip within MaxReorgDepth of the active tip (deeper
	// reorgs are refused by ReorgTo), so the gap is <= MaxReorgDepth and
	// descendFrom stays bestTip — the fork-aware descent below the active tip is
	// untouched (GAP2 reorg-drop invariant preserved).
	// The MaxReorgDepth cap below serves TWO distinct roles and must only apply
	// to the first:
	//
	//  (1) Forward-IBD windowing. When bestTip is a straight EXTENSION of the
	//      active chain far ahead of the validated floor (a huge IBD gap), the
	//      descent would otherwise collect the TOP window near the header tip,
	//      while sequential validation needs the BOTTOM (startHeight+1). Capping
	//      descendFrom to startHeight+MaxReorgDepth collects the bottom window;
	//      the drain-rebuild advances it. This is pure batching — correct to keep.
	//
	//  (2) Below-tip reorg refusal. For a heavier fork that forks BELOW the
	//      active tip, capping the descent stops it before it reaches the true
	//      fork point, so the bottom bridging bodies (fork_point+1 ..) are never
	//      enqueued → ReorgTo never sees the fork tip → the node strands on the
	//      minority chain. Bitcoin Core (FindNextBlocksToDownload) follows the
	//      most-work header chain to the fork point at ANY depth. The old comment
	//      "a deeper reorg would be refused by ReorgTo" is now FALSE for an
	//      ARCHIVE node: ReorgTo's cap is gated on pruning (chainmanager.go), so
	//      an archive node reorgs to any depth and its download must too.
	//
	// Distinguish the two: bestTip is a forward extension iff its ancestor at the
	// active tip height IS the active tip. A genuine below-tip reorg on an
	// archive node (not pruning) must NOT be capped; every other case (forward
	// extension, pruned node, or an unresolved active tip where we cannot prove
	// it is a below-tip reorg) keeps the cap.
	isForwardExtension := activeTip != nil && bestTip.GetAncestor(activeTip.Height) == activeTip
	belowTipReorg := activeTip != nil && !isForwardExtension
	pruning := sm.chainMgr != nil && sm.chainMgr.IsPruning()
	capDescent := !(belowTipReorg && !pruning)

	descendFrom := bestTip
	if capDescent && bestTip.Height-startHeight > consensus.MaxReorgDepth {
		if capped := bestTip.GetAncestor(startHeight + consensus.MaxReorgDepth); capped != nil {
			descendFrom = capped
		}
	}
	nodes := make([]*consensus.BlockNode, 0, 64)
	node := descendFrom
	for node != nil && needBody(node) {
		nodes = append(nodes, node)
		if capDescent && len(nodes) >= consensus.MaxReorgDepth {
			log.Printf("sync: block-download descent hit MaxReorgDepth=%d at height %d without reaching the fork point; "+
				"capping (forward-IBD window or pruned node; a below-tip reorg on an archive node descends uncapped to the fork point)", consensus.MaxReorgDepth, node.Height)
			break
		}
		node = node.Parent
	}
	// Reverse to get ascending order.
	for i, j := 0, len(nodes)-1; i < j; i, j = i+1, j-1 {
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}
	sm.blockQueue = make([]*blockRequest, 0, len(nodes))
	zeroHash := wire.Hash256{}
	for _, n := range nodes {
		if n.Hash == zeroHash {
			log.Printf("sync: WARNING: zero hash for block at height %d (parent=%v)", n.Height, n.Parent)
			continue // Skip zero-hash nodes
		}
		sm.blockQueue = append(sm.blockQueue, &blockRequest{
			Hash:   n.Hash,
			Height: n.Height,
			State:  BlockDownloadPending,
		})
	}

	// nextHeight is the height of the first block we will connect. For a normal
	// extension this is startHeight+1; for a below-tip fork it is the first
	// height above the fork point (which may be <= startHeight). Derive it from
	// the lowest node we actually enqueued rather than assuming startHeight+1,
	// so the connect/stall loop targets the right height on the fork.
	if len(nodes) > 0 {
		sm.nextHeight = nodes[0].Height
	} else {
		sm.nextHeight = startHeight + 1
	}

	log.Printf("sync: starting block download from height %d to %d (%d blocks, startHeight=%d)",
		sm.nextHeight, bestTip.Height, len(sm.blockQueue), startHeight)

	// Start requesting blocks — exactly one loop at a time (see
	// blockDownloadLoopRunning). A re-entrant StartBlockDownload whose loop is
	// still alive just feeds the rebuilt queue to that loop.
	if sm.blockDownloadLoopRunning.CompareAndSwap(false, true) {
		go sm.blockDownloadLoop()
	} else {
		log.Printf("sync: block-download loop already running — rebuilt queue handed to it (no second loop)")
	}
}

// blockDownloadLoop is the main loop for requesting blocks during IBD.
func (sm *SyncManager) blockDownloadLoop() {
	// Release the single-loop guard on EVERY exit path (quit, drained queue,
	// IBD complete, panic) so a later StartBlockDownload can legitimately
	// relaunch. Without this the first exit would wedge block download
	// permanently — a worse failure than the leak it prevents.
	defer sm.blockDownloadLoopRunning.Store(false)

	requestTicker := time.NewTicker(100 * time.Millisecond)
	defer requestTicker.Stop()

	staleTicker := time.NewTicker(time.Second)
	defer staleTicker.Stop()

	// Stall detection: if nextHeight hasn't advanced for this long,
	// re-request the block at nextHeight.
	stallCheckTicker := time.NewTicker(10 * time.Second)
	defer stallCheckTicker.Stop()
	lastNextHeight := int32(-1)
	lastAdvanceTime := time.Now()

	for {
		select {
		case <-requestTicker.C:
			sm.requestBlocks()

		case <-staleTicker.C:
			sm.checkStaleRequests()

		case <-stallCheckTicker.C:
			sm.mu.Lock()
			nh := sm.nextHeight
			inflightLen := len(sm.inflight)
			stallDuration := time.Since(lastAdvanceTime)

			if nh == lastNextHeight && stallDuration > 30*time.Second {
				// nextHeight hasn't advanced for 30s. Diagnose the stall.
				found := false
				for _, req := range sm.blockQueue {
					if req.Height == nh {
						found = true
						log.Printf("sync: stall detected at height %d: state=%d, inflight=%d, peer=%v, retries=%d, stallDuration=%v",
							nh, req.State, inflightLen, req.Peer != nil, req.RetryCount, stallDuration)

						if req.State == BlockDownloadPending {
							// Block is pending but not being downloaded.
							// This happens when all peers are busy or disconnected.
							// Force a re-request by logging and letting requestBlocks
							// pick it up on next tick. Also reset peer to allow any peer.
							log.Printf("sync: block %d is pending but not downloading, clearing peer restriction",
								nh)
							req.Peer = nil
							req.RetryCount = 0
							// W48: state invariant says Pending blocks must not be in
							// sm.inflight; otherwise requestBlocks skips them and the
							// stall never clears. Sibling branches (line ~1014, ~1034)
							// already do this; match them here. Delete is a no-op if
							// the block isn't actually in the map.
							delete(sm.inflight, req.Hash)
						} else if req.State != BlockDownloadPending {
							// Block is in some intermediate state (InFlight, Received, Validated).
							// It may be stuck in the pipeline. Reset to pending.
							log.Printf("sync: block %d stuck in state %d, resetting to pending", nh, req.State)
							req.State = BlockDownloadPending
							req.Peer = nil
							// Also remove from inflight if it's there
							delete(sm.inflight, req.Hash)
						}
						break
					}
				}
				if !found {
					// Block not in queue at all - it was removed (connected or skipped).
					// This shouldn't happen if nextH points to it. Log for debugging.
					log.Printf("sync: stall at height %d but block NOT IN QUEUE, inflight=%d queue=%d",
						nh, inflightLen, len(sm.blockQueue))
				}

				// Also reset any blocks in non-pending states near nextHeight
				// to ensure the pipeline can flow
				resetWindow := int32(16)
				for _, req := range sm.blockQueue {
					if req.Height > nh && req.Height <= nh+resetWindow {
						if req.State != BlockDownloadPending && req.State != BlockDownloadConnected {
							req.State = BlockDownloadPending
							req.Peer = nil
							delete(sm.inflight, req.Hash)
						}
					}
				}
			}
			if nh != lastNextHeight {
				lastNextHeight = nh
				lastAdvanceTime = time.Now()
			}
			sm.mu.Unlock()

		case <-sm.quit:
			return
		}

		// Check if IBD is complete
		sm.mu.RLock()
		done := len(sm.blockQueue) == 0 && len(sm.inflight) == 0
		var connectedH, headerH int32
		if done && sm.chainMgr != nil {
			_, connectedH = sm.chainMgr.BestBlock()
			headerH = sm.headerIndex.BestHeight()
		}
		sm.mu.RUnlock()

		if done {
			// The block queue is a SNAPSHOT of the header tip taken when
			// StartBlockDownload built it (line ~1456). Header sync runs
			// concurrently, so headers can advance AFTER the queue is built:
			// late header batches that arrive while this loop is still draining
			// hit StartBlockDownload's "already populated" short-circuit and are
			// dropped, and once sm.headersSynced is set the HandleHeaders
			// kickoff (gated on !headersSynced) stops firing on the periodic
			// empty batches. If we simply returned here, the loop would
			// terminate at that intermediate height and never resume — the node
			// wedges with a full header chain but blocks stuck short of the tip
			// (the 946000 stall on the 2026-06-06 blockbrew snapshot restore:
			// blocks=946000, headers=952612, queue=0, inflight=0). So when the
			// queue drains but headers still extend past the connected tip,
			// rebuild the queue from the current header tip and hand off to a
			// fresh loop instead of exiting.
			if headerH > connectedH {
				log.Printf("sync: block queue drained at height %d but headers extend to %d — rebuilding block queue",
					connectedH, headerH)
				sm.StartBlockDownload() // rebuilds queue (empty now) + launches a fresh blockDownloadLoop
				return
			}
			// Block queue drained AND the connected tip has reached the header
			// tip. Run the IBD status check (latches ibdActive to false once we
			// have a recent tip); also handles the empty-from-the-start case.
			// Steady-state tip-following past this point is driven by new header
			// announcements (HandleHeaders -> onSyncComplete -> StartBlockDownload).
			sm.updateIBDStatus()
			if sm.ibdActive.Load() {
				log.Printf("sync: block queue empty but tip is not yet recent — IBD remains active")
			} else {
				log.Printf("sync: IBD complete")
			}
			return
		}
	}
}

// requestJitter returns a random 0–500 ms offset added to each request's
// RequestAt timestamp. Without it, a batch of ~140 getdata requests all
// stamp RequestAt within the same millisecond, so their timeouts fire as
// a thundering herd 120 s later — producing the oscillating drain-refill
// pattern observed in W63's profile. Spreading the deadlines keeps the
// connection worker fed with a steady trickle of validated blocks (W69b).
func requestJitter() time.Duration {
	return time.Duration(rand.IntN(500)) * time.Millisecond
}

// requestBlocks sends block requests to peers up to the download window.
func (sm *SyncManager) requestBlocks() {
	// alreadyHave collects Pending block requests whose block bodies are
	// already persisted locally (flatfile or legacy "B"-blob). They bypass
	// the network and are pushed to the validation pipeline after the main
	// lock is released. See fastPathDispatch for the dispatch side.
	var alreadyHave []*blockRequest

	sm.mu.Lock()
	// LIFO defers: unlock runs first, THEN fast-path dispatch. Dispatch
	// reacquires the lock briefly per block; keeping it outside the main
	// critical section avoids holding mu across chainDB.GetBlock (a disk
	// read that can be slow during warmup).
	defer func() {
		for _, req := range alreadyHave {
			sm.fastPathDispatch(req)
		}
	}()
	defer sm.mu.Unlock()

	if sm.peerMgr == nil {
		return
	}

	// Count in-flight requests per peer
	peerInflight := make(map[string]int)
	for _, req := range sm.inflight {
		if req.Peer != nil {
			peerInflight[req.Peer.Address()]++
		}
	}

	// Get connected peers
	peers := sm.peerMgr.ConnectedPeers()
	if len(peers) == 0 {
		return
	}

	// Batch getdata requests per peer
	peerRequests := make(map[*Peer][]*InvVect)

	// Use round-robin peer index for better distribution (persists across calls)
	peerIdx := sm.peerRoundIdx

	for _, req := range sm.blockQueue {
		if req.State != BlockDownloadPending {
			continue
		}
		if len(sm.inflight) >= sm.downloadWindow {
			break
		}

		// Fast path: if the block body is already on disk (e.g. a prior
		// requeue already persisted it, or a restart rebuilt blockQueue
		// over indexed blocks), skip the network round-trip and queue
		// it for validation directly. Closes the gap the requeue comment
		// at requeueForRedownload has long claimed was already in place.
		if sm.chainDB != nil && sm.chainDB.HasBlock(req.Hash) {
			alreadyHave = append(alreadyHave, req)
			continue
		}

		// Find a peer that can serve this block using round-robin.
		// After a failure, skip the previously-failed peer.
		var selectedPeer *Peer
		var lastFailedAddr string
		if req.Peer != nil && req.RetryCount >= MaxRetriesBeforeRotate {
			lastFailedAddr = req.Peer.Address()
		}

		// Try all peers starting from the round-robin index
		for i := 0; i < len(peers); i++ {
			idx := (peerIdx + i) % len(peers)
			peer := peers[idx]
			if !peer.IsConnected() || peer.ShouldBan() {
				continue
			}
			addr := peer.Address()
			if peerInflight[addr] >= MaxBlocksPerPeer {
				continue
			}
			// Skip the peer that just timed out on this block
			if lastFailedAddr != "" && addr == lastFailedAddr {
				continue
			}
			// Skip any peer that has already told us (via notfound) it
			// doesn't have this block — otherwise we round-robin back to
			// haskoin / other partially-synced peers and burn CPU plus
			// produce millions of log lines for the same misses.
			if req.FailedPeers != nil {
				if _, failed := req.FailedPeers[addr]; failed {
					continue
				}
			}
			selectedPeer = peer
			peerIdx = (idx + 1) % len(peers)
			break
		}
		// If no alternative found, fall back to any available peer
		// (including FailedPeers — liveness > avoidance when all else fails).
		if selectedPeer == nil && (lastFailedAddr != "" || req.FailedPeers != nil) {
			for _, peer := range peers {
				if !peer.IsConnected() {
					continue
				}
				if peerInflight[peer.Address()] >= MaxBlocksPerPeer {
					continue
				}
				selectedPeer = peer
				break
			}
		}

		if selectedPeer == nil {
			// All peers are at max capacity
			break
		}

		// Mark request as in-flight
		req.Peer = selectedPeer
		req.State = BlockDownloadInFlight
		req.RequestAt = time.Now().Add(requestJitter())
		sm.inflight[req.Hash] = req
		peerInflight[selectedPeer.Address()]++

		// Add to batch for this peer
		peerRequests[selectedPeer] = append(peerRequests[selectedPeer], &InvVect{
			Type: InvTypeWitnessBlock,
			Hash: req.Hash,
		})
	}

	// Save round-robin index for next call
	sm.peerRoundIdx = peerIdx

	// Send batched getdata requests, capped at MaxGetDataSize=1000 items per
	// message (Bitcoin Core MAX_GETDATA_SZ, net_processing.cpp:128). Previously
	// the entire invList was sent as one message, allowing up to MaxInvVects
	// (50000) items — 50× the protocol limit.
	for peer, invList := range peerRequests {
		for start := 0; start < len(invList); start += MaxGetDataSize {
			end := start + MaxGetDataSize
			if end > len(invList) {
				end = len(invList)
			}
			peer.SendMessage(&MsgGetData{InvList: invList[start:end]})
		}
	}

}

// checkStaleRequests detects and handles timed-out block requests.
func (sm *SyncManager) checkStaleRequests() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	timedOut := 0
	evictedDead := 0
	for hash, req := range sm.inflight {
		// W13 fix: if the owning peer is gone (disconnected or flagged for
		// ban), free the slot immediately — don't wait for the adaptive
		// timeout (up to 120 s × 16 slots per dead peer = the W8/W12 wedge).
		if req.Peer == nil || !req.Peer.IsConnected() || req.Peer.ShouldBan() {
			delete(sm.inflight, hash)
			req.State = BlockDownloadPending
			req.Peer = nil
			req.RetryCount = 0
			evictedDead++
			continue
		}

		// Get the adaptive timeout for this peer
		timeout := sm.getStallTimeout(req.Peer)

		if now.Sub(req.RequestAt) > timeout {
			timedOut++

			// W35: do NOT score misbehavior for block-download timeouts.
			// Bitcoin Core's policy: BLOCK_DOWNLOAD_STALLING isn't banned;
			// only INVALID_BLOCK etc. score heavily. During IBD, peers
			// legitimately time out under load (16 parallel reqs/peer,
			// slow links, pruned nodes). +50 per timeout × threshold 100
			// caused cascade bans — observed W35 at height 194,098 where
			// 15+ peers got banned in ~5 minutes, wedging progress. Rely
			// on per-peer adaptive timeout backoff + peer rotation to
			// deprioritise slow peers without permanent bans.
			// (ScoreBlockDownloadStall/Misbehaving still used for actual
			// protocol violations elsewhere.)

			// Increase timeout for this peer (adaptive backoff)
			sm.increaseStallTimeout(req.Peer)

			// Reset request for retry — keep Peer reference so requestBlocks
			// can rotate to a different peer on the next attempt.
			delete(sm.inflight, hash)
			req.State = BlockDownloadPending
			req.RetryCount++
			// Don't nil out req.Peer — requestBlocks uses it to avoid the same peer
		}
	}
	if evictedDead > 0 {
		log.Printf("sync: evicted %d in-flight blocks from disconnected/banned peers", evictedDead)
	}
	if timedOut > 0 {
		log.Printf("sync: %d block requests timed out, will retry with peer rotation", timedOut)
	}
}

// getStallTimeout returns the current stall timeout for a peer.
func (sm *SyncManager) getStallTimeout(peer *Peer) time.Duration {
	if peer == nil {
		return BlockRequestTimeout
	}
	timeout, ok := sm.peerStallTimeout[peer.Address()]
	if !ok {
		return BaseStallTimeout
	}
	return timeout
}

// increaseStallTimeout doubles the timeout for a peer (adaptive backoff).
func (sm *SyncManager) increaseStallTimeout(peer *Peer) {
	if peer == nil {
		return
	}
	addr := peer.Address()
	current := sm.getStallTimeout(peer)
	newTimeout := current * 2
	if newTimeout > MaxStallTimeout {
		newTimeout = MaxStallTimeout
	}
	sm.peerStallTimeout[addr] = newTimeout
}

// decreaseStallTimeout reduces timeout on success (decay toward base).
func (sm *SyncManager) decreaseStallTimeout(peer *Peer) {
	if peer == nil {
		return
	}
	addr := peer.Address()
	current, ok := sm.peerStallTimeout[addr]
	if !ok || current <= BaseStallTimeout {
		return
	}
	// Decay by 25%
	newTimeout := current * 3 / 4
	if newTimeout < BaseStallTimeout {
		newTimeout = BaseStallTimeout
	}
	sm.peerStallTimeout[addr] = newTimeout
}

// HandleBlock processes a received block message.
func (sm *SyncManager) HandleBlock(peer *Peer, msg *MsgBlock) {
	hash := msg.Block.Header.BlockHash()

	sm.mu.Lock()
	nh := sm.nextHeight
	req, ok := sm.inflight[hash]
	if !ok {
		// Block not in-flight — it may have timed out but the peer sent it late.
		// Check if it's still in our queue (pending retry). If so, accept it.
		req = sm.findInQueue(hash)
		if req == nil {
			nh := sm.nextHeight
			sm.mu.Unlock()
			// Not in queue either — process as an unsolicited block
			// (e.g., announced via inv from a miner).
			// First, add its header to the header index (headers-first requirement).
			log.Printf("sync: received unsolicited block %s from %s, processing header first", hash, peer.Address())
			resolvedHeight := false
			if sm.headerIndex != nil {
				// minPowChecked=false: this is an unsolicited P2P block whose
				// header has NOT been through the PRESYNC pipeline.  AddHeader
				// will enforce the MinimumChainWork gate itself.
				node, err := sm.headerIndex.AddHeader(msg.Block.Header, false)
				if err == nil && node != nil {
					log.Printf("sync: added header for unsolicited block (height %d)", node.Height)
					nh = node.Height
					resolvedHeight = true
				} else if err == consensus.ErrDuplicateHeader {
					// Header already in the index — look up its canonical height.
					// Without this we would slot the block at pending[sm.nextHeight]
					// even though its true height differs, causing ConnectBlock
					// to reject it every retry ("prev != tip") for the lifetime
					// of the stuck slot. See W49 cascade-loop investigation.
					if existing := sm.headerIndex.GetNode(hash); existing != nil {
						nh = existing.Height
						resolvedHeight = true
					}
				} else if err != nil {
					log.Printf("sync: failed to add header for unsolicited block: %v — dropping", err)
				}
			}
			if !resolvedHeight {
				// Can't position this block in the pipeline without a known
				// height — dropping is safer than slotting at an arbitrary
				// cursor.
				return
			}
			// G19c fTooFarAhead gate (Bitcoin Core validation.cpp:4325).
			// An unrequested block more than MIN_BLOCKS_TO_KEEP (288) heights
			// ahead of our active tip is dropped without further processing.
			// Mirrors Core's `if (fTooFarAhead) return true;` on the
			// !fRequested path. Solicited (queue-driven) blocks are exempt
			// because they go through the inflight/blockQueue path above.
			if sm.chainMgr != nil {
				_, activeHeight := sm.chainMgr.BestBlock()
				if consensus.IsTooFarAhead(nh, activeHeight) {
					log.Printf("sync: dropping unsolicited block height=%d too far ahead of tip=%d (limit=%d)",
						nh, activeHeight, activeHeight+int32(storage.MinBlocksToKeep))
					return
				}
			}
			// #126 (2026-05-27): hand the block straight to validation. The
			// body persistence is folded into ConnectBlock's atomic batch
			// (chainmanager.go: every persistence arm now calls
			// chainDB.StoreBlockAtBatch in the same batch as undo data +
			// height map + UTXO set + chainstate). Pre-#126 the unsolicited
			// arm had to call StoreBlockAt + MarkDataStored ahead of the
			// channel send (the #115 fix); that pre-store is now redundant
			// for the active-tip path because ConnectBlock owns body
			// persistence end-to-end and a crash mid-write can no longer
			// leave the chainstate ahead of the body. The
			// inflight/queued arm below KEEPS its pre-store: those bodies
			// are downloaded along the headers-first projected best chain
			// and may belong to a side branch whose ancestors must be on
			// disk before ReorgTo's GetBlock can replay them. An unsolicited
			// block is by definition a single miner-announced inv whose
			// only role is to extend the active tip, so there is no
			// side-branch-ancestor that must be pre-staged.
			//
			// If ConnectBlock fails (e.g., heavier side branch triggers a
			// reorg, but the side branch's other body is missing from disk
			// because no queue download ran), the failure is loud and the
			// block can be re-requested.
			//
			// Mirrors haskoin f768a01 which removed the active-tip
			// putBlock from submitBlock once connectBlockAt's WriteBatch
			// folded in the body store.
			select {
			case sm.validationChan <- &blockWithRequest{
				block: msg.Block,
				req:   &blockRequest{Hash: hash, Height: nh, State: BlockDownloadReceived},
			}:
			default:
				log.Printf("sync: validation channel full, dropping unsolicited block")
			}
			return
		}
		// Accept the late block: remove from queue's pending state
		if req.Height == nh || req.Height == nh+1 {
			log.Printf("sync: received late block height=%d (nextH=%d) from %s",
				req.Height, nh, peer.Address())
		}
		req.State = BlockDownloadReceived
		sm.mu.Unlock()
	} else {
		if req.Height == nh || req.Height == nh+1 {
			log.Printf("sync: received block height=%d (nextH=%d) from %s, sending to validation",
				req.Height, nh, peer.Address())
		}
		delete(sm.inflight, hash)
		req.State = BlockDownloadReceived

		// Reduce stall timeout for successful peer
		sm.decreaseStallTimeout(peer)
		sm.mu.Unlock()
	}

	// Store block to database. Use StoreBlockAt so the flat-file
	// BlockFileInfo metadata records the chain height for this block.
	//
	// #126 (2026-05-27): this pre-store is RETAINED (not removed like the
	// unsolicited arm above) because the inflight/queued arm sees blocks
	// downloaded along the headers-first projected best chain — including
	// blocks that may belong to a side branch whose ancestors must be
	// resident on disk before ReorgTo's GetBlock can replay them. The
	// ConnectBlock atomic batch now ALSO stages the body via
	// StoreBlockAtBatch (chainmanager.go), so this pre-store is a no-op
	// on the hot path (HasBlock short-circuit) and acts purely as
	// side-branch staging for the out-of-order-P2P-fork case.
	//
	// MarkDataStored stays because side-branch nodes that have a body on
	// disk but have not yet been ConnectBlock'd need the in-memory flag
	// so recalculateBestTipLocked treats them as candidate tips.
	if sm.chainDB != nil {
		if err := sm.chainDB.StoreBlockAt(hash, msg.Block, req.Height); err != nil {
			log.Printf("sync: failed to store block %s: %v", hash.String()[:16], err)
		} else {
			// G1/G3 fix (W101): mark the header-index node as having block data
			// stored on disk. Mirrors Bitcoin Core's ReceivedBlockTransactions
			// (validation.cpp) which sets BLOCK_HAVE_DATA after the block body
			// lands on disk. This allows recalculateBestTipLocked to filter
			// data-absent nodes from chain selection.
			sm.headerIndex.MarkDataStored(hash)
		}
	}

	// Send to validation pipeline.
	// Use a non-blocking send to avoid blocking the peer's readHandler.
	// If the channel is full, the block is already persisted to DB, so we
	// reset its state to pending. The stall detector or next request cycle
	// will re-download it (from DB via fast path). This prevents unbounded
	// goroutine/memory growth from the old goroutine-fallback approach.
	select {
	case sm.validationChan <- &blockWithRequest{block: msg.Block, req: req}:
		// Sent immediately
	default:
		// Pipeline backed up — block is already stored to DB.
		// Reset state so it gets re-requested when pipeline drains.
		sm.mu.Lock()
		req.State = BlockDownloadPending
		req.Peer = nil
		sm.mu.Unlock()
	}
}

// validationWorker validates blocks from the validation channel.
func (sm *SyncManager) validationWorker() {
	defer sm.wg.Done()

	for {
		select {
		case bwr := <-sm.validationChan:
			if bwr == nil {
				continue
			}

			// Recover from panics to keep the pipeline alive
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("sync: PANIC in validation worker for block height=%d hash=%s: %v",
							bwr.req.Height, bwr.req.Hash.String()[:16], r)
						// Reset block to pending so stall detector can retry
						sm.mu.Lock()
						bwr.req.State = BlockDownloadPending
						bwr.req.Peer = nil
						sm.mu.Unlock()
					}
				}()

				// Basic sanity check
				err := consensus.CheckBlockSanity(bwr.block, sm.chainParams.PowLimit)
				if err != nil {
					log.Printf("sync: block %s (height %d) failed sanity check: %v",
						bwr.req.Hash.String()[:16], bwr.req.Height, err)
					// BLOCK_MUTATED defense (Bitcoin Core validation.cpp:3843-3911):
					// The following errors all map to BLOCK_MUTATED (transient) in
					// Core — the block must be rejected but the block HASH must NOT
					// be marked permanently invalid, because the same hash can arrive
					// in a legitimate (non-mutated) form from an honest peer later.
					//
					// ErrBlockMutated: CVE-2012-2459 merkle-tree mutation. Duplicate
					//   adjacent leaves produce the same root as the legitimate block;
					//   the legitimate block has the same hash and is still valid.
					//   Core ref: validation.cpp:3850-3858 ("bad-txns-duplicate",
					//   BLOCK_MUTATED).
					//
					// ErrBadMerkleRoot: wrong block body delivered for a known-good
					//   header. In headers-first sync a misbehaving peer can send wrong
					//   transaction bytes for a header we already accepted. The block
					//   hash (which commits only to the header, including the declared
					//   MerkleRoot) is still valid; another peer may deliver the correct
					//   body. Core ref: validation.cpp:3843-3848 ("bad-txnmrklroot",
					//   BLOCK_MUTATED).
					//
					// ErrBadWitnessNonceSize / ErrUnexpectedWitnessInBlock: witness
					//   malleation. Witness data is NOT committed to by the block hash;
					//   an attacker can modify witness bytes on a valid block without
					//   changing its hash. Core ref: validation.cpp:3870-3916
					//   (CheckWitnessMalleation, BLOCK_MUTATED).
					transientMutation := errors.Is(err, consensus.ErrBlockMutated) ||
						errors.Is(err, consensus.ErrBadMerkleRoot) ||
						errors.Is(err, consensus.ErrBadWitnessNonceSize) ||
						errors.Is(err, consensus.ErrUnexpectedWitnessInBlock)
					if !transientMutation {
						// Mark as invalid in header index
						node := sm.headerIndex.GetNode(bwr.req.Hash)
						if node != nil {
							node.Status |= consensus.StatusInvalid
						}
					}
					// Penalize the peer that sent the invalid block (the peer
					// is bad regardless: they shipped either an invalid block
					// or a mutated one).
					if bwr.req.Peer != nil {
						bwr.req.Peer.Misbehaving(100, fmt.Sprintf("invalid block: %v", err))
					}
					// On transient mutation, requeue for re-download from a
					// different peer instead of routing to the connection
					// pipeline (which would skip the height entirely).
					if transientMutation {
						sm.requeueForRedownload(bwr)
						return
					}
					// Still send to connection pipeline so it can skip this height
					// and continue with subsequent blocks. Mark it as failed so
					// connectionWorker knows to skip it.
					//
					// W64 (thread A): non-blocking send.  If connectionChan is
					// saturated we used to park here, which backed up
					// validationChan and caused the net handler to drop incoming
					// blocks ("validation channel full, dropping unsolicited
					// block" — see W63 profile).  Falling through to re-queue
					// lets validationChan keep draining; the block is already
					// stored to DB (handleBlock) and will be re-delivered via
					// the stall detector's re-request path once pressure eases.
					bwr.req.State = BlockDownloadValidated
					select {
					case sm.connectionChan <- bwr:
					case <-sm.quit:
						return
					default:
						sm.requeueForRedownload(bwr)
					}
					return
				}

				bwr.req.State = BlockDownloadValidated

				// Send to connection pipeline.
				//
				// W64 (thread A): non-blocking send with re-queue fallback.
				// See the comment above the failed-sanity send for context —
				// same rationale, same fallback path.  Dropping validated
				// work here is safe because the block body is persisted to
				// chainDB before this point (handleBlock line ~1365) and
				// the stall detector will re-request it once connectionChan
				// drains.
				select {
				case sm.connectionChan <- bwr:
				case <-sm.quit:
					return
				default:
					sm.requeueForRedownload(bwr)
				}
			}()

		case <-sm.quit:
			return
		}
	}
}

// requeueForRedownload resets a block's download state so the stall
// detector / next request cycle will re-download it.  Used as the
// back-pressure fallback when the validationWorker cannot push to
// connectionChan without blocking.  The block body has already been
// persisted to chainDB by handleBlock(), so re-download hits the DB
// fast path — no network round-trip is forced by the requeue.
//
// Rate-limited logging prevents a saturated pipeline from flooding the
// log; the progressLogger already reports validCh/connCh saturation
// every 10s, which is sufficient telemetry for this condition.
//
// W64 (thread A): added to break the single-validationWorker deadlock
// where a blocking send to a full connectionChan backed up validationChan
// and caused the 6-min stall cycle diagnosed in W63.
func (sm *SyncManager) requeueForRedownload(bwr *blockWithRequest) {
	if bwr == nil || bwr.req == nil {
		return
	}
	sm.mu.Lock()
	bwr.req.State = BlockDownloadPending
	bwr.req.Peer = nil
	delete(sm.inflight, bwr.req.Hash)
	sm.mu.Unlock()

	now := time.Now()
	last := sm.lastRequeueLog.Load()
	if last == 0 || now.Sub(time.Unix(0, last)) >= 30*time.Second {
		if sm.lastRequeueLog.CompareAndSwap(last, now.UnixNano()) {
			log.Printf("sync: connection channel saturated, re-queued block %d (%s) for later re-download",
				bwr.req.Height, bwr.req.Hash.String()[:16])
		}
	}
}

// fastPathDispatch reads a locally-persisted block from chainDB and queues
// it for validation, bypassing the network request cycle. Called by
// requestBlocks after the main lock is released, once per Pending block
// whose body the local chainDB already has on disk.
//
// Re-checks req.State under the lock because HandleBlock (via unsolicited
// inv or a racing arrival) may have advanced it between the outer
// collection and this call; a disk read + re-push would cause
// double-validation.
//
// On channel saturation or a surprise GetBlock miss, req stays Pending
// and the next requestBlocks tick will retry.
func (sm *SyncManager) fastPathDispatch(req *blockRequest) {
	if sm.chainDB == nil {
		return
	}
	block, err := sm.chainDB.GetBlock(req.Hash)
	if err != nil {
		return
	}

	sm.mu.Lock()
	if req.State != BlockDownloadPending {
		sm.mu.Unlock()
		return
	}
	req.State = BlockDownloadReceived
	sm.mu.Unlock()

	select {
	case sm.validationChan <- &blockWithRequest{block: block, req: req}:
		// Queued for validation; state progresses via validationWorker.
	default:
		// Pipeline full. Revert so the next requestBlocks tick retries.
		sm.mu.Lock()
		req.State = BlockDownloadPending
		sm.mu.Unlock()
	}
}

// MaxPendingBlocks bounds the connection worker's pending map. W69a
// raised it 1024 → 2048 to absorb burst-arrival pileups during IBD
// without triggering the eviction path (which forces re-download of a
// validated block body). Invariant: DownloadWindow ≤ MaxPendingBlocks,
// enforced at startup (W67d).
const MaxPendingBlocks = 2048

// evictDistantPending re-queues blocks whose heights are beyond maxKeep
// for re-download. W69c: takes sm.mu once for a single pass over
// blockQueue instead of per evicted height (the old path held the lock
// O(N) times inside an inner O(M) scan, blocking requestBlocks for the
// duration of an eviction burst). `pending` is the connectionWorker's
// goroutine-local map, so deletes here need no lock.
func (sm *SyncManager) evictDistantPending(pending map[int32]*blockWithRequest, maxKeep int32) int {
	var evict []int32
	for h := range pending {
		if h > maxKeep {
			evict = append(evict, h)
		}
	}
	if len(evict) == 0 {
		return 0
	}
	evictSet := make(map[int32]struct{}, len(evict))
	for _, h := range evict {
		evictSet[h] = struct{}{}
	}
	sm.mu.Lock()
	for _, req := range sm.blockQueue {
		if _, ok := evictSet[req.Height]; ok {
			req.State = BlockDownloadPending
			req.Peer = nil
		}
	}
	sm.mu.Unlock()
	for _, h := range evict {
		delete(pending, h)
	}
	return len(evict)
}

// connectionWorker connects validated blocks to the chain in order.
func (sm *SyncManager) connectionWorker() {
	defer sm.wg.Done()

	// Buffer for out-of-order blocks
	pending := make(map[int32]*blockWithRequest)

	// Periodic retry timer: if the block at nextHeight is in pending but
	// ConnectBlock previously failed, we retry periodically instead of
	// waiting for new blocks to arrive on connectionChan.
	retryTicker := time.NewTicker(5 * time.Second)
	defer retryTicker.Stop()

	var lastPendingWarn time.Time // rate-limit "pending map too large" warnings

	connectPending := func() {
		// Halted: skip the whole connect loop.  Once the corruption
		// flag is latched (BUG-REPORT.md fix #4), connectPendingBlocks
		// is a no-op until the operator restarts. Prevents the 50k/min
		// retry storm we saw on May 1 (h=938361 wedge log).
		if sm.chainstateCorrupted.Load() {
			return
		}

		// Evict blocks that are behind nextHeight (already connected or skipped)
		sm.mu.RLock()
		nh := sm.nextHeight
		sm.mu.RUnlock()
		for h := range pending {
			if h < nh {
				delete(pending, h)
			}
		}

		// If pending is too large, drop blocks that are far ahead
		// to prevent unbounded memory growth
		if len(pending) > MaxPendingBlocks {
			if time.Since(lastPendingWarn) >= 30*time.Second {
				log.Printf("sync: pending map too large (%d entries), evicting distant blocks", len(pending))
				lastPendingWarn = time.Now()
			}
			maxKeep := nh + int32(MaxPendingBlocks)
			sm.evictDistantPending(pending, maxKeep)
		}

		// Try to connect blocks in order, with panic recovery
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("sync: PANIC in connectionWorker while connecting blocks: %v", r)
					sm.mu.Lock()
					nh := sm.nextHeight
					for _, req := range sm.blockQueue {
						if req.Height == nh {
							req.State = BlockDownloadPending
							req.Peer = nil
							break
						}
					}
					sm.mu.Unlock()
					delete(pending, nh)
				}
			}()
			sm.connectPendingBlocks(pending)
		}()
	}

	for {
		select {
		case bwr := <-sm.connectionChan:
			if bwr == nil {
				continue
			}

			// Add to pending
			pending[bwr.req.Height] = bwr

			connectPending()

		case <-retryTicker.C:
			// Periodically retry connecting pending blocks.
			// This handles the case where ConnectBlock failed previously
			// and no new blocks are arriving on connectionChan.
			if len(pending) > 0 {
				connectPending()
			}

		case <-sm.quit:
			return
		}
	}
}

// connectPendingBlocks connects any blocks that are ready in order.
func (sm *SyncManager) connectPendingBlocks(pending map[int32]*blockWithRequest) {
	// Halt-on-corruption fast path (BUG-REPORT.md fix #4). Once
	// chainstateCorrupted is latched by an earlier ConnectBlock failure,
	// every subsequent call here is a no-op until the operator restarts
	// the node. Without this guard the retry ticker would re-enter the
	// connect loop every 5s and re-print the corruption banner.
	if sm.chainstateCorrupted.Load() {
		return
	}

	sm.mu.Lock()
	nextHeight := sm.nextHeight
	sm.mu.Unlock()

	for {
		bwr, ok := pending[nextHeight]
		if !ok {
			break
		}

		// Connect the block
		if sm.chainMgr != nil {
			// Recover from panics in ConnectBlock
			var connectErr error
			// sideBranchAccepted latches when the connect routed through the
			// side-branch-aware path and stored the block on a non-active
			// branch (reorg-drop fix part 2). It is a SUCCESS, not an error:
			// the active tip legitimately stays put, the cursor advances to
			// the next fork body, and a heavier fork tip later drives ReorgTo.
			var sideBranchAccepted bool
			// W75 instrumentation: wall-clock timing around the
			// ConnectBlock call.  Only success-path timings feed the
			// rolling window below (see post-call accumulator).
			_connStart := time.Now()
			func() {
				defer func() {
					if r := recover(); r != nil {
						connectErr = fmt.Errorf("PANIC in ConnectBlock: %v", r)
					}
				}()
				// reorg-drop fix part 2: post-IBD, route through the
				// side-branch-aware ProcessSubmittedBlock so a competing fork
				// forking BELOW the active tip is STORED (its bodies arrive
				// bottom-up, each lighter than the active chain) until the
				// fork tip's TotalWork overtakes the tip and triggers ReorgTo.
				// Raw ConnectBlock (chainmanager.go:512) rejects+discards such
				// a block ("does not connect to tip ... and has less work"),
				// which is exactly why fork bodies never accumulated (the
				// runtime-proven part-1 gap). During IBD proper we KEEP raw
				// ConnectBlock: blocks arrive in order and extend the tip, and
				// ConnectBlock intentionally refuses reorgs there (invariant 3).
				// The extension fast path is identical either way —
				// ProcessSubmittedBlock dispatches parent==tip straight to
				// ConnectBlock — so steady-state behaviour/performance is
				// unchanged (invariant 1).
				if sm.chainMgr.IsIBD() {
					connectErr = sm.chainMgr.ConnectBlock(bwr.block)
				} else {
					connectErr = sm.chainMgr.ProcessSubmittedBlock(bwr.block)
					if errors.Is(connectErr, consensus.ErrSideBranchAccepted) {
						// Side-branch store succeeded. Clear the error: this is
						// NOT a validation failure and must never reach the
						// wedge / chainstate-corruption path below (invariant 2).
						sideBranchAccepted = true
						connectErr = nil
					}
				}
			}()
			_connDurNs := time.Since(_connStart).Nanoseconds()

			if connectErr != nil {
				log.Printf("sync: failed to connect block %d (%s): %v",
					nextHeight, bwr.req.Hash.String()[:16], connectErr)

				// Check if this is a genuine validation failure vs. an ordering issue.
				// "does not connect to tip during IBD" means the previous block
				// was not connected — this is a cascading failure, NOT a bad block.
				errStr := connectErr.Error()
				isCascade := len(errStr) > 30 && errStr[:30] == "block does not connect to tip "

				if isCascade {
					// Check if a previous block was skipped, creating an
					// unrecoverable gap. If the chain tip is behind
					// nextHeight-1, the missing block was marked invalid and
					// removed from the queue. We need to re-download it.
					if sm.chainMgr != nil {
						_, tipH := sm.chainMgr.BestBlock()
						missingHeight := tipH + 1
						if missingHeight < nextHeight {
							// There is a gap: block at missingHeight was
							// skipped. Look it up in the header index and
							// re-insert it into the queue for re-download.
							sm.mu.Lock()
							alreadyQueued := false
							for _, req := range sm.blockQueue {
								if req.Height == missingHeight {
									alreadyQueued = true
									// Clear any invalid status so it gets re-downloaded
									if req.State != BlockDownloadPending {
										req.State = BlockDownloadPending
										req.Peer = nil
										delete(sm.inflight, req.Hash)
									}
									node := sm.headerIndex.GetNode(req.Hash)
									if node != nil {
										node.Status &^= consensus.StatusInvalid
									}
									break
								}
							}
							if !alreadyQueued {
								// Find the block hash from the header index
								bestTip := sm.headerIndex.BestTip()
								if bestTip != nil {
									ancestor := bestTip.GetAncestor(missingHeight)
									if ancestor != nil {
										log.Printf("sync: gap detected — re-queuing skipped block at height %d (%s)",
											missingHeight, ancestor.Hash.String()[:16])
										// Clear invalid status
										ancestor.Status &^= consensus.StatusInvalid
										// Insert at the front of the queue
										newReq := &blockRequest{
											Hash:   ancestor.Hash,
											Height: missingHeight,
											State:  BlockDownloadPending,
										}
										sm.blockQueue = append([]*blockRequest{newReq}, sm.blockQueue...)
									}
								}
							}
							// Reset nextHeight to fill the gap
							sm.nextHeight = missingHeight
							sm.mu.Unlock()
							log.Printf("sync: resetting nextHeight to %d to fill gap (tip=%d, was=%d)",
								missingHeight, tipH, nextHeight)
							break
						}
						// missingHeight >= nextHeight: tip is at or ahead of
						// this slot, so the block in pending[nextHeight] cannot
						// connect (its PrevBlock does not match current tip).
						// Treat the delivered block as stale or mis-delivered:
						// evict the pending entry and re-queue the download, so
						// the retry ticker does not infinite-loop on a slot it
						// can never make progress on.
						log.Printf("sync: evicting stuck block at height %d (hash=%s, tip=%d) — re-requesting",
							nextHeight, bwr.req.Hash.String()[:16], tipH)
						delete(pending, nextHeight)
						sm.mu.Lock()
						requeued := false
						for _, req := range sm.blockQueue {
							if req.Height == nextHeight {
								req.State = BlockDownloadPending
								req.Peer = nil
								delete(sm.inflight, req.Hash)
								requeued = true
								break
							}
						}
						if !requeued {
							if bestTip := sm.headerIndex.BestTip(); bestTip != nil {
								if ancestor := bestTip.GetAncestor(nextHeight); ancestor != nil {
									sm.blockQueue = append([]*blockRequest{{
										Hash:   ancestor.Hash,
										Height: nextHeight,
										State:  BlockDownloadPending,
									}}, sm.blockQueue...)
								}
							}
						}
						sm.mu.Unlock()
						break
					}
					// chainMgr nil — can't verify; wait for next signal.
					break
				}

				// Check if this block has a script flag exception (e.g., the
				// BIP16 exception at height 170,060).  If so, the failure is
				// almost certainly because assume-valid was not resolved and
				// the flags override alone was insufficient.  Rather than
				// permanently skipping the block, force assume-valid resolution
				// and keep it pending so it gets retried.
				if sm.chainParams != nil && sm.chainParams.ScriptFlagExceptions != nil {
					if _, isException := sm.chainParams.ScriptFlagExceptions[bwr.req.Hash]; isException {
						log.Printf("sync: block %d (%s) is a script-flag exception — will not skip; retrying",
							nextHeight, bwr.req.Hash.String()[:16])
						// Try to force assume-valid resolution in the chain manager
						if sm.chainMgr != nil {
							sm.chainMgr.ReloadChainState()
						}
						// Leave the block pending for the retry timer
						break
					}
				}

				// Genuine validation error.  Pre-2026-05-02 the handler
				// here marked the header invalid + advanced nextHeight
				// past the failed block, but left chain_tip at the
				// previous block — meaning the *next* block would
				// always fail "block does not connect to tip" + the
				// gap-detection path would re-queue the same block,
				// re-fail validation, ad infinitum (the May 1 blockbrew
				// h=938361 wedge: 14M log lines, ~50k retries/min).
				//
				// Genuine validation failures during IBD are almost
				// always a symptom of chainstate corruption — same root
				// cause as lunarblock c6fd8a0 / project memory
				// `project_lunarblock_wedge_2026_04_28`: a hard crash
				// mid-IBD lost an unflushed UTXO write window, so a
				// later block's tx now references a coin that is no
				// longer in the persisted UTXO set.  Silently skipping
				// it would either (a) wedge as above, or (b) advance
				// the chain on a known-bad state — both are worse than
				// halting.
				//
				// Halt the connection loop and surface a loud
				// [CHAINSTATE-CORRUPTION] line.  The startup
				// VerifyChainstateConsistency probe (chainmanager.go)
				// will auto-rollback on the next restart; if that
				// recovery path also fails, the operator is told to
				// wipe chaindata/.  The block is NOT marked invalid in
				// the header index, so a recovered restart can validate
				// it cleanly.
				// Latch the flag + rate-limit the warning. First print is
				// always emitted; subsequent retries print at most once
				// per minute. Both lines fire on the first hit so the
				// operator sees both the symptom and the recovery hint.
				firstHit := sm.chainstateCorrupted.CompareAndSwap(false, true)
				now := time.Now().UnixNano()
				last := sm.lastCorruptionWarning.Load()
				if firstHit || now-last >= int64(time.Minute) {
					sm.lastCorruptionWarning.Store(now)
					log.Printf("[CHAINSTATE-CORRUPTION] sync: GENUINE validation failure at height %d hash=%s: %v",
						nextHeight, bwr.req.Hash.String()[:16], connectErr)
					if firstHit {
						log.Printf("[CHAINSTATE-CORRUPTION] this is almost certainly a chainstate-corruption " +
							"wedge (UTXO writes lost in a prior crash window). The broken \"skip-and-advance\" " +
							"loop has been removed; halting block connection here. Restart the node to run " +
							"the startup consistency probe, which auto-rolls-back the tip to the last known-good " +
							"height. If the wedge recurs after restart, stop the node and remove the chaindata/ " +
							"directory to force a full re-sync (-reindex is honest-deferred).")
					}
				}

				// Drop the block from the in-memory pending map so we
				// don't busy-loop on it.  Crucially we do NOT advance
				// nextHeight and do NOT mark the header invalid — the
				// next restart's consistency probe will peel chain_tip
				// back so this block becomes connectable again.
				delete(pending, nextHeight)

				// Stop connecting further blocks. The retry ticker will
				// re-enter this loop and re-print the corruption
				// message at most once per tick (10s in the default
				// config) so operators see the wedge but the log
				// volume is bounded — vs the 50k/min loop the old
				// skip-and-advance produced.
				break
			}

			// reorg-drop fix part 2: side-branch store path. The block was
			// validated + stored on a non-active branch (parent is NOT the
			// active tip and the branch is not yet heavier). The active tip
			// LEGITIMATELY did not move — there is no connected block to notify
			// on, no real ConnectBlock latency to record, no tip advance, and
			// the tip-anchored desync check below would false-fire (it expects
			// the tip to equal nextHeight). Simply advance the cursor to the
			// next fork body and continue: when the fork tip's TotalWork finally
			// overtakes the active tip, ProcessSubmittedBlock returns nil after
			// ReorgTo and falls through to the normal connected-block path below.
			if sideBranchAccepted {
				bwr.req.State = BlockDownloadConnected
				delete(pending, nextHeight)
				sm.mu.Lock()
				sm.removeFromQueue(bwr.req.Hash)
				nextHeight++
				sm.nextHeight = nextHeight
				sm.mu.Unlock()
				continue
			}

			// W75 instrumentation: success-path ConnectBlock latency.
			// Only connectionWorker's goroutine mutates these fields
			// (connectPendingBlocks is invoked only from there), so
			// plain reads/writes are race-free.
			sm.connStatsN++
			sm.connStatsTotalNs += _connDurNs
			sm.connStatsTotalTxs += int64(len(bwr.block.Transactions))
			if _connDurNs > sm.connStatsMaxNs {
				sm.connStatsMaxNs = _connDurNs
			}
			sm.connStatsLifetime++
			if sm.connStatsN >= ConnStatsLogEvery {
				avgMs := float64(sm.connStatsTotalNs/sm.connStatsN) / 1e6
				maxMs := float64(sm.connStatsMaxNs) / 1e6
				txsAvg := float64(sm.connStatsTotalTxs) / float64(sm.connStatsN)
				log.Printf(
					"[W75-CONN] window=%d total=%d connect_avg=%.1fms connect_max=%.0fms txs_avg=%.0f",
					sm.connStatsN, sm.connStatsLifetime, avgMs, maxMs, txsAvg)
				sm.connStatsN = 0
				sm.connStatsTotalNs = 0
				sm.connStatsMaxNs = 0
				sm.connStatsTotalTxs = 0
			}
		}

		bwr.req.State = BlockDownloadConnected
		delete(pending, nextHeight)

		// Notify listeners of connected block
		if sm.onBlockConnected != nil {
			sm.onBlockConnected(bwr.block, nextHeight)
		}

		// Check whether IBD should be considered complete now that this
		// block is connected.  updateIBDStatus latches ibdActive to false
		// once the tip is recent enough; it is a no-op once already false.
		sm.updateIBDStatus()

		// Update stale tip tracker — our chain tip just advanced
		sm.mu.Lock()
		sm.lastTipUpdate = time.Now()
		sm.removeFromQueue(bwr.req.Hash)
		sm.mu.Unlock()

		// Invariant: a successful ConnectBlock advances the validated tip to
		// exactly this height. Anchor nextHeight to the real chain tip rather
		// than a blind ++ — if the two ever disagree, the connect cursor has
		// desynced from the chainstate. That desync is the layer-A assumeUTXO
		// forward-sync thrash: nextHeight runs ahead of the tip, every block
		// then fails "does not connect", and the gap-handler churns the cursor
		// back and forth for hours. Halt loudly on the anomaly instead.
		//
		// A reorg (ProcessSubmittedBlock → ReorgTo on the fork tip) lands the
		// active tip on the fork tip, whose height can EXCEED nextHeight (the
		// fork tip may be higher than the body we were connecting). tipH >=
		// nextHeight after a reorg is healthy progress, not desync; only a tip
		// BEHIND nextHeight is the pathological forward-sync thrash this guard
		// targets. Anchor nextHeight to the real tip in both cases.
		if sm.chainMgr != nil {
			_, tipH := sm.chainMgr.BestBlock()
			if tipH < nextHeight {
				log.Printf("[IBD-DESYNC] sync: ConnectBlock(%d) succeeded but the "+
					"chain tip is %d — connect cursor desynced from the chainstate; "+
					"halting the connect loop (layer-A forward-sync thrash)",
					nextHeight, tipH)
				sm.mu.Lock()
				sm.nextHeight = tipH + 1
				sm.mu.Unlock()
				break
			}
			nextHeight = tipH + 1
		} else {
			nextHeight++
		}
		sm.mu.Lock()
		sm.nextHeight = nextHeight
		sm.mu.Unlock()
	}
}

// findInQueue looks up a block request in the queue by hash.
// Must be called with sm.mu held.
func (sm *SyncManager) findInQueue(hash wire.Hash256) *blockRequest {
	for _, req := range sm.blockQueue {
		if req.Hash == hash {
			return req
		}
	}
	return nil
}

// removeFromQueue removes a block request from the queue.
func (sm *SyncManager) removeFromQueue(hash wire.Hash256) {
	for i, req := range sm.blockQueue {
		if req.Hash == hash {
			sm.blockQueue = append(sm.blockQueue[:i], sm.blockQueue[i+1:]...)
			return
		}
	}
}

// progressLogger logs IBD progress periodically.
func (sm *SyncManager) progressLogger() {
	defer sm.wg.Done()

	ticker := time.NewTicker(ProgressLogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			active := sm.ibdActive.Load()
			sm.mu.RLock()
			queueLen := len(sm.blockQueue)
			inflightLen := len(sm.inflight)
			nextHeight := sm.nextHeight
			sm.mu.RUnlock()

			if !active {
				continue
			}

			tipHeight := sm.headerIndex.BestHeight()
			if tipHeight <= 0 {
				continue
			}

			// Calculate progress
			var height int32
			if sm.chainMgr != nil {
				_, height = sm.chainMgr.BestBlock()
			} else {
				height = nextHeight - 1
			}

			pct := float64(height) / float64(tipHeight) * 100
			log.Printf("sync: IBD progress %d/%d (%.1f%%) [queue=%d, inflight=%d, validCh=%d/%d, connCh=%d/%d, nextH=%d]",
				height, tipHeight, pct, queueLen, inflightLen,
				len(sm.validationChan), cap(sm.validationChan),
				len(sm.connectionChan), cap(sm.connectionChan),
				nextHeight)

		case <-sm.quit:
			return
		}
	}
}

// IsIBDActive returns true if initial block download is in progress.
// Lock-free: the RPC handler (handleGetBlockchainInfo) calls this on every
// getblockchaininfo, and sm.mu is held as a write lock for seconds at a
// time during header/block processing. Using an atomic.Bool avoids the
// writer-preference starvation that made L1-7 also trip this path.
func (sm *SyncManager) IsIBDActive() bool {
	return sm.ibdActive.Load()
}

// RefreshIBDStatus re-evaluates the IBD latch from outside the P2P sync loop.
// Core calls ChainstateManager::UpdateIBDStatus() in ConnectTip on EVERY block
// connect, regardless of whether the block arrived via P2P or submitblock; the
// blockbrew sync loop only calls updateIBDStatus on the block-download drain
// path, so a chain advanced purely via submitblock (e.g. a miner or the
// byte-diff harness mirroring Core) would never leave IBD. This exported wrapper
// lets the submitblock handler trigger the same recheck after a successful
// connect. No-op once the latch has flipped to false (updateIBDStatus is sticky).
func (sm *SyncManager) RefreshIBDStatus() {
	sm.updateIBDStatus()
}

// updateIBDStatus checks whether IBD should be considered complete and, if so,
// latches ibdActive to false.  It is the Go equivalent of Bitcoin Core's
// ChainstateManager::UpdateIBDStatus() in validation.cpp.
//
// Rules (must ALL be true to leave IBD):
//  1. ibdActive is currently true (latch — never re-enters IBD once false).
//  2. The chain manager reports a best block (not at genesis-only state).
//  3. The best block's timestamp is within MaxTipAge (24h) of wall-clock time.
//
// This is called lock-free (no sm.mu needed) because ibdActive is an
// atomic.Bool and the chain manager's BestBlock / BestBlockNode are also
// designed to be read without the sync-manager lock.
func (sm *SyncManager) updateIBDStatus() {
	// Fast path: already left IBD — never flip back.
	if !sm.ibdActive.Load() {
		return
	}
	if sm.chainMgr == nil {
		return
	}
	_, tipHeight := sm.chainMgr.BestBlock()
	if tipHeight < 0 {
		return
	}
	tipNode := sm.chainMgr.BestBlockNode()
	if tipNode == nil {
		return
	}
	tipTime := time.Unix(int64(tipNode.Header.Timestamp), 0)
	if time.Since(tipTime) <= MaxTipAge {
		// Tip is recent enough — latch IBD to false.
		// CompareAndSwap ensures only one goroutine does the log line.
		if sm.ibdActive.CompareAndSwap(true, false) {
			log.Printf("sync: leaving InitialBlockDownload (tip age %v, height %d)",
				time.Since(tipTime).Round(time.Second), tipHeight)
		}
		return
	}

	// Regtest parity: Core's IsTipRecent reads Now<NodeSeconds>(), which honors
	// -mocktime. Regtest chains are mined under a pinned mocktime (e.g.
	// 1700000000), so Core sees the freshly-mined tip as recent and latches
	// m_cached_is_ibd=false even though the block timestamp is years behind real
	// wall-clock. blockbrew has no mock clock, so the wall-clock gate above never
	// fires on a mocktime regtest chain. We match Core's effective regtest
	// outcome WITHOUT a mock clock: a regtest node whose connected block tip has
	// caught up to its best-header tip (nothing left to download) and whose
	// chainwork meets the bar (regtest MinimumChainWork == 0) is fully synced, so
	// it is not in IBD. Scoped to regtest ONLY — mainnet/testnet keep the exact
	// Core wall-clock tip-age gate above, and their large MinimumChainWork keeps a
	// genuinely-behind node in IBD via the header-sync work check.
	if sm.chainParams != nil && sm.chainParams.Name == "regtest" &&
		sm.headerIndex != nil && tipHeight == sm.headerIndex.BestHeight() {
		if sm.ibdActive.CompareAndSwap(true, false) {
			log.Printf("sync: leaving InitialBlockDownload (regtest tip caught up to headers, height %d)",
				tipHeight)
		}
	}
}

// BlocksInFlight returns the number of blocks currently being downloaded.
func (sm *SyncManager) BlocksInFlight() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.inflight)
}

// BlockQueueLength returns the number of blocks waiting to be downloaded.
func (sm *SyncManager) BlockQueueLength() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.blockQueue)
}

// PendingConnectCount returns the number of validated blocks queued for
// connection but not yet connected to the tip. Reads the connection
// channel's current length (O(1), no lock). Used by the getsyncstate RPC
// to expose the same counter the W69 post-deploy diagnosis found
// saturated at 1024/1024.
func (sm *SyncManager) PendingConnectCount() int {
	return len(sm.connectionChan)
}

// LastTipUpdateTime returns the unix-seconds timestamp of when this node
// last advanced its best-chain tip. Returns 0 if the tip has never
// advanced (fresh datadir, pre-IBD). Used by the getsyncstate RPC.
func (sm *SyncManager) LastTipUpdateTime() int64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.lastTipUpdate.IsZero() {
		return 0
	}
	return sm.lastTipUpdate.Unix()
}
