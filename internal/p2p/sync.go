package p2p

import (
	"fmt"
	"log"
	"sync"
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
)

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
	onSyncComplete func() // Called when header sync completes
}

// SyncManagerConfig configures the sync manager.
type SyncManagerConfig struct {
	ChainParams    *consensus.ChainParams
	HeaderIndex    *consensus.HeaderIndex
	ChainDB        *storage.ChainDB
	PeerManager    *PeerManager
	OnSyncComplete func()
}

// NewSyncManager creates a new sync manager.
func NewSyncManager(config SyncManagerConfig) *SyncManager {
	return &SyncManager{
		chainParams:    config.ChainParams,
		headerIndex:    config.HeaderIndex,
		chainDB:        config.ChainDB,
		peerMgr:        config.PeerManager,
		quit:           make(chan struct{}),
		onSyncComplete: config.OnSyncComplete,
	}
}

// Start begins the sync process.
func (sm *SyncManager) Start() {
	sm.wg.Add(1)
	go sm.syncHandler()
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

	for {
		select {
		case <-ticker.C:
			sm.mu.RLock()
			synced := sm.headersSynced
			syncPeer := sm.syncPeer
			sm.mu.RUnlock()

			// If not synced and no sync peer, try again
			if !synced && syncPeer == nil {
				sm.startHeaderSync()
			}

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
			sm.onSyncComplete()
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

			// Invalid header — ban the peer
			log.Printf("sync: bad header from %s at height %d: %v",
				peer.Address(), sm.headerIndex.BestHeight()+1, err)
			sm.peerMgr.BanPeer(peer.Address(), 24*time.Hour, fmt.Sprintf("bad header: %v", err))
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
			sm.onSyncComplete()
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
	}
}
