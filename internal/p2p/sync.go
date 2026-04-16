package p2p

import (
	"fmt"
	"log"
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
)

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

	// Start IBD pipeline workers
	sm.wg.Add(3)
	go sm.validationWorker()
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

	for _, hdr := range msg.Headers {
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
			peer.Misbehaving(score, fmt.Sprintf("invalid header: %v", err))
			peer.Disconnect()
			sm.syncPeer = nil
			go sm.startHeaderSync() // Try another peer
			return
		}

		headersAdded++

		// Persist header to DB
		if sm.chainDB != nil {
			if err := sm.chainDB.StoreBlockHeader(node.Hash, &hdr); err != nil {
				log.Printf("sync: failed to store header %s: %v", node.Hash.String(), err)
			}
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

		log.Printf("sync: peer %s does not have block height=%d hash=%s, will retry with different peer",
			peer.Address(), req.Height, inv.Hash.String()[:16])

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

// requestBlocks sends block requests to peers up to the download window.
func (sm *SyncManager) requestBlocks() {
	sm.mu.Lock()
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
			selectedPeer = peer
			peerIdx = (idx + 1) % len(peers)
			break
		}
		// If no alternative found, fall back to any available peer
		if selectedPeer == nil && lastFailedAddr != "" {
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
		req.RequestAt = time.Now()
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
			if sm.headerIndex != nil {
				node, err := sm.headerIndex.AddHeader(msg.Block.Header)
				if err == nil && node != nil {
					log.Printf("sync: added header for unsolicited block (height %d)", node.Height)
					nh = node.Height
				} else if err != nil {
					log.Printf("sync: failed to add header for unsolicited block: %v", err)
				}
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

	// Store block to database
	if sm.chainDB != nil {
		if err := sm.chainDB.StoreBlock(hash, msg.Block); err != nil {
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
					bwr.req.State = BlockDownloadValidated
					select {
					case sm.connectionChan <- bwr:
					case <-sm.quit:
						return
					}
					return
				}

				bwr.req.State = BlockDownloadValidated

				// Send to connection pipeline
				select {
				case sm.connectionChan <- bwr:
				case <-sm.quit:
					return
				}
			}()

		case <-sm.quit:
			return
		}
	}
}

// MaxPendingBlocks is the maximum number of blocks to buffer in the
// connection worker's pending map before dropping the oldest entries.
// This prevents unbounded memory growth when the chain tip is stalled.
const MaxPendingBlocks = 1024

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
			for h := range pending {
				if h > maxKeep {
					sm.mu.Lock()
					for _, req := range sm.blockQueue {
						if req.Height == h {
							req.State = BlockDownloadPending
							req.Peer = nil
							break
						}
					}
					sm.mu.Unlock()
					delete(pending, h)
				}
			}
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
			func() {
				defer func() {
					if r := recover(); r != nil {
						connectErr = fmt.Errorf("PANIC in ConnectBlock: %v", r)
					}
				}()
				connectErr = sm.chainMgr.ConnectBlock(bwr.block)
			}()

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
					}
					// No gap — the preceding block just hasn't been
					// connected yet. Wait for it.
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

				// Genuine validation error: mark as invalid and skip
				log.Printf("sync: GENUINE validation failure at height %d, skipping block: %v",
					nextHeight, connectErr)
				node := sm.headerIndex.GetNode(bwr.req.Hash)
				if node != nil {
					node.Status |= consensus.StatusInvalid
				}
				delete(pending, nextHeight)

				// Remove from queue and advance past the failed block
				nextHeight++
				sm.mu.Lock()
				sm.removeFromQueue(bwr.req.Hash)
				sm.nextHeight = nextHeight
				sm.mu.Unlock()

				// Stop connecting further blocks: the chain tip is now behind
				// nextHeight, so subsequent blocks will also fail because their
				// PrevBlock won't match the tip.
				break
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
