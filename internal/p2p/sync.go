package p2p

import (
	"fmt"
	"log"
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
	syncPeer      *Peer  // Current peer we're syncing headers from
	headersSynced bool   // Whether we've caught up with headers
	quit          chan struct{}
	wg            sync.WaitGroup

	// Callbacks for external integration
	onSyncComplete   func()                                    // Called when header sync completes
	onBlockConnected func(block *wire.MsgBlock, height int32)  // Called after block connected

	// Block download state
	blockQueue     []*blockRequest              // Ordered list of blocks to download
	inflight       map[wire.Hash256]*blockRequest
	downloadWindow int                           // Max concurrent downloads
	nextHeight     int32                         // Next height to connect

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
	ibdActive    atomic.Bool // True while in IBD (header sync OR block download)
	peerRoundIdx int         // Round-robin index for peer selection

	// Stale tip detection (Bitcoin Core: CheckForStaleTipAndEvictPeers)
	lastTipUpdate      time.Time // When our chain tip last advanced
	nextStaleTipCheck  time.Time // When to next check for stale tip

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
	connStatsN        int64         // blocks in current window
	connStatsTotalNs  int64         // summed ConnectBlock latency (ns)
	connStatsMaxNs    int64         // max ConnectBlock latency in window (ns)
	connStatsTotalTxs int64         // summed tx count across window
	connStatsLifetime int64         // cumulative count since process start

	// chainstateCorrupted latches when connectPendingBlocks hits a
	// genuine validation failure during IBD (presumed chainstate
	// corruption per BUG-REPORT.md).  Once set, the connect loop early-
	// exits without re-running ConnectBlock, so the corruption notice is
	// printed at most once per retry tick (not 50k times/min like the
	// pre-fix skip-and-loop path).  Cleared only by process restart.
	chainstateCorrupted   atomic.Bool
	lastCorruptionWarning atomic.Int64 // unix nanos
}

// ChainConnector is the interface for connecting blocks to the chain.
// This allows the sync manager to work with any chain manager implementation.
type ChainConnector interface {
	// ConnectBlock validates and connects a block to the active chain.
	ConnectBlock(block *wire.MsgBlock) error
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
		chainParams:       config.ChainParams,
		headerIndex:       config.HeaderIndex,
		chainDB:           config.ChainDB,
		peerMgr:           config.PeerManager,
		quit:              make(chan struct{}),
		onSyncComplete:    config.OnSyncComplete,
		onBlockConnected:  config.OnBlockConnected,
		inflight:          make(map[wire.Hash256]*blockRequest),
		downloadWindow:    downloadWindow,
		validationChan:    make(chan *blockWithRequest, downloadWindow),
		connectionChan:    make(chan *blockWithRequest, downloadWindow),
		peerStallTimeout:  make(map[string]time.Duration),
		chainMgr:          config.ChainManager,
		lastTipUpdate:     now,
		nextStaleTipCheck: now.Add(StaleTipCheckInterval),
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

	// Select best peer
	syncPeer := sm.selectSyncPeer()
	if syncPeer == nil {
		log.Printf("sync: no peers available for header sync")
		return
	}

	sm.syncPeer = syncPeer
	log.Printf("sync: starting header sync with %s (height %d)", syncPeer.Address(), syncPeer.StartHeight())

	// Build locator from our current best tip
	locator := sm.headerIndex.BestTip().BuildLocator()

	// Send getheaders request
	sm.sendGetHeaders(syncPeer, locator)
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
		pendingHeaders = make([]storage.HeaderBatchEntry, 0, len(msg.Headers))
	}

	for i := range msg.Headers {
		hdr := msg.Headers[i]
		node, err := sm.headerIndex.AddHeader(hdr)
		if err != nil {
			if err == consensus.ErrDuplicateHeader {
				// Skip duplicates silently
				continue
			}

			// Score depends on error type: orphan/disconnected = 20, invalid PoW = 100.
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
				peer.Address(), sm.headerIndex.BestHeight()+1, err)
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
				Header: &msg.Headers[i],
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
	if len(msg.Headers) == MaxHeadersPerRequest {
		// More headers available — request next batch
		locator := sm.headerIndex.BestTip().BuildLocator()
		sm.sendGetHeaders(peer, locator)
	} else {
		// Sync complete (received fewer than max headers)
		sm.headersSynced = true
		sm.syncPeer = nil
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

	// If our sync peer disconnected, find a new one
	if peer == sm.syncPeer {
		sm.syncPeer = nil
		if !sm.headersSynced {
			log.Printf("sync: sync peer %s disconnected, finding new peer", peer.Address())
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
			log.Printf("[compact] Received cmpctblock from %s, falling back to full block request (hash=%s)",
				p.Address(), blockHash)
			inv := &MsgGetData{
				InvList: []*InvVect{
					{Type: InvTypeWitnessBlock, Hash: blockHash},
				},
			}
			p.SendMessage(inv)
		},
		OnGetBlockTxn: func(p *Peer, _ *MsgGetBlockTxn) {
			// Peer requesting missing transactions for compact block reconstruction.
			// We don't serve compact blocks yet, so ignore.
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
	for _, inv := range msg.InvList {
		baseType := inv.Type &^ InvWitnessFlag
		if baseType == InvTypeBlock {
			hasBlock = true
			break
		}
	}
	if !hasBlock {
		return
	}

	sm.sendGetHeadersTo(peer)
}

// sendPeriodicGetHeaders sends getheaders to a random peer to discover
// new blocks.  Called periodically after IBD completes.
func (sm *SyncManager) sendPeriodicGetHeaders() {
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
	// Pick a random peer
	peer := peers[time.Now().UnixNano()%int64(len(peers))]
	sm.sendGetHeadersTo(peer)
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

// sendGetHeadersTo sends a getheaders message to a specific peer using
// our current chain tip as the locator.
func (sm *SyncManager) sendGetHeadersTo(peer *Peer) {
	if sm.chainMgr == nil {
		return
	}
	bestHash, _ := sm.chainMgr.BestBlock()
	sm.sendGetHeaders(peer, []wire.Hash256{bestHash})
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
func (sm *SyncManager) HandleGetData(peer *Peer, msg *MsgGetData) {
	for _, inv := range msg.InvList {
		// Strip witness flag to get base type
		baseType := inv.Type &^ InvWitnessFlag
		switch baseType {
		case InvTypeBlock:
			block, err := sm.chainDB.GetBlock(inv.Hash)
			if err != nil {
				log.Printf("sync: getdata block %x not found: %v", inv.Hash[:4], err)
				continue
			}
			log.Printf("sync: serving block at %x to peer %s", inv.Hash[:4], peer.Address())
			peer.SendMessage(&MsgBlock{Block: block})
		case InvTypeTx:
			// TODO: look up transaction from mempool
		}
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
		log.Printf("sync: StartBlockDownload called but block queue already populated")
		return
	}

	// Determine where to start downloading from
	startHeight := int32(0)
	if sm.chainMgr != nil {
		_, startHeight = sm.chainMgr.BestBlock()
	}

	// Build the block queue from headers
	bestTip := sm.headerIndex.BestTip()
	if bestTip == nil || bestTip.Height <= startHeight {
		log.Printf("sync: no blocks to download, already at height %d (bestTip=%v)", startHeight, bestTip)
		return
	}

	// Walk from tip back to startHeight to collect all block hashes,
	// then reverse. This is O(n) instead of O(n^2) from repeated GetAncestor calls.
	count := int(bestTip.Height - startHeight)
	nodes := make([]*consensus.BlockNode, 0, count)
	node := bestTip
	for node != nil && node.Height > startHeight {
		nodes = append(nodes, node)
		node = node.Parent
	}
	// Reverse to get ascending order
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

	sm.nextHeight = startHeight + 1

	log.Printf("sync: starting block download from height %d to %d (%d blocks)",
		startHeight+1, bestTip.Height, len(sm.blockQueue))

	// Start requesting blocks
	go sm.blockDownloadLoop()
}

// blockDownloadLoop is the main loop for requesting blocks during IBD.
func (sm *SyncManager) blockDownloadLoop() {
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
		sm.mu.RUnlock()

		if done {
			// Block queue drained: run the IBD status check.  This should
			// latch ibdActive to false now that we have a recent tip, but
			// also handles the edge case where the queue was empty from the
			// start (e.g., already synced before StartBlockDownload ran).
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

	// Send batched getdata requests
	for peer, invList := range peerRequests {
		if len(invList) > 0 {
			peer.SendMessage(&MsgGetData{InvList: invList})
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
				node, err := sm.headerIndex.AddHeader(msg.Block.Header)
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
			// Now pass to validation
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
	if sm.chainDB != nil {
		if err := sm.chainDB.StoreBlockAt(hash, msg.Block, req.Height); err != nil {
			log.Printf("sync: failed to store block %s: %v", hash.String()[:16], err)
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
					// Mark as invalid in header index
					node := sm.headerIndex.GetNode(bwr.req.Hash)
					if node != nil {
						node.Status |= consensus.StatusInvalid
					}
					// Penalize the peer that sent the invalid block
					if bwr.req.Peer != nil {
						bwr.req.Peer.Misbehaving(100, fmt.Sprintf("invalid block: %v", err))
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
				connectErr = sm.chainMgr.ConnectBlock(bwr.block)
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
		sm.mu.Unlock()

		// Remove from queue and advance nextHeight
		nextHeight++
		sm.mu.Lock()
		sm.removeFromQueue(bwr.req.Hash)
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
