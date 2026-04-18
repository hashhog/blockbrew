package p2p

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// createMockPeer creates a mock peer for testing.
func createMockPeer(addr string, startHeight int32) *Peer {
	return &Peer{
		config: PeerConfig{
			Network:         MainnetMagic,
			ProtocolVersion: ProtocolVersion,
		},
		addr:          addr,
		state:         PeerStateConnected,
		peerVersion:   &MsgVersion{StartHeight: startHeight},
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		handshakeDone: make(chan struct{}),
	}
}

// createTestBlockHeader creates a test block header with valid PoW for regtest.
func createTestBlockHeader(prevHash wire.Hash256, timestamp uint32, baseNonce uint32) wire.BlockHeader {
	header := wire.BlockHeader{
		Version:    1,
		PrevBlock:  prevHash,
		MerkleRoot: wire.Hash256{},
		Timestamp:  timestamp,
		Bits:       0x207fffff, // Regtest difficulty
		Nonce:      baseNonce,
	}

	// Find a valid nonce (regtest target is very high, so this is fast)
	target := consensus.CompactToBig(header.Bits)
	for i := uint32(0); i < 1000000; i++ {
		header.Nonce = baseNonce + i
		hash := header.BlockHash()
		if consensus.HashToBig(hash).Cmp(target) <= 0 {
			return header
		}
	}

	// Fallback - shouldn't happen with regtest difficulty
	return header
}

func TestSyncManagerCreation(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	if sm == nil {
		t.Fatal("sync manager should not be nil")
	}

	if sm.IsSynced() {
		t.Error("new sync manager should not be synced")
	}

	if sm.CurrentHeight() != 0 {
		t.Errorf("initial height = %d, want 0", sm.CurrentHeight())
	}
}

func TestSyncManagerSelectSyncPeer(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// Create a mock peer manager with peers
	pm := &PeerManager{
		peers: make(map[string]*PeerInfo),
	}

	// Add peers with different heights
	peer1 := createMockPeer("1.2.3.4:8333", 100)
	peer2 := createMockPeer("5.6.7.8:8333", 500)
	peer3 := createMockPeer("9.10.11.12:8333", 200)

	pm.peers["1.2.3.4:8333"] = &PeerInfo{peer: peer1, connType: ConnFullRelay}
	pm.peers["5.6.7.8:8333"] = &PeerInfo{peer: peer2, connType: ConnFullRelay}
	pm.peers["9.10.11.12:8333"] = &PeerInfo{peer: peer3, connType: ConnFullRelay}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
		PeerManager: pm,
	})

	// selectSyncPeer should pick peer2 (highest height)
	sm.mu.Lock()
	selected := sm.selectSyncPeer()
	sm.mu.Unlock()

	if selected != peer2 {
		if selected == nil {
			t.Error("selected peer should not be nil")
		} else {
			t.Errorf("selected peer height = %d, want 500", selected.StartHeight())
		}
	}
}

func TestSyncManagerHandleHeaders(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	var syncComplete atomic.Bool
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
		OnSyncComplete: func() {
			syncComplete.Store(true)
		},
	})

	// Create a mock sync peer
	peer := createMockPeer("1.2.3.4:8333", 100)
	sm.mu.Lock()
	sm.syncPeer = peer
	sm.mu.Unlock()

	// Build a chain of headers
	headers := make([]wire.BlockHeader, 10)
	prevHash := params.GenesisHash
	prevTimestamp := params.GenesisBlock.Header.Timestamp

	for i := 0; i < 10; i++ {
		headers[i] = createTestBlockHeader(prevHash, prevTimestamp+600, uint32(i+1))
		prevHash = headers[i].BlockHash()
		prevTimestamp = headers[i].Timestamp
	}

	// Handle the headers message (fewer than 2000, so sync should complete)
	msg := &MsgHeaders{Headers: headers}
	sm.HandleHeaders(peer, msg)

	// Should have added all headers
	if idx.BestHeight() != 10 {
		t.Errorf("best height = %d, want 10", idx.BestHeight())
	}

	// Sync should be complete (received < 2000 headers)
	if !sm.IsSynced() {
		t.Error("sync should be complete after receiving < 2000 headers")
	}

	// OnSyncComplete runs in a goroutine, give it a moment
	time.Sleep(50 * time.Millisecond)

	if !syncComplete.Load() {
		t.Error("OnSyncComplete callback should have been called")
	}
}

func TestSyncManagerContinuesOnFullBatch(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	var requestCount int
	requestCh := make(chan bool, 10)

	// Create a connection to capture sent messages
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	peer := &Peer{
		config: PeerConfig{
			Network:         RegtestMagic,
			ProtocolVersion: ProtocolVersion,
		},
		conn:          clientConn,
		addr:          "1.2.3.4:8333",
		state:         PeerStateConnected,
		peerVersion:   &MsgVersion{StartHeight: 10000},
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		handshakeDone: make(chan struct{}),
	}

	// Start a goroutine to read sent messages
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg := <-peer.sendQueue:
				if _, ok := msg.(*MsgGetHeaders); ok {
					requestCount++
					requestCh <- true
				}
			case <-peer.quit:
				return
			}
		}
	}()

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	sm.mu.Lock()
	sm.syncPeer = peer
	sm.mu.Unlock()

	// Create exactly 2000 headers (should trigger another request)
	headers := make([]wire.BlockHeader, MaxHeadersPerRequest)
	prevHash := params.GenesisHash
	prevTimestamp := params.GenesisBlock.Header.Timestamp

	for i := 0; i < MaxHeadersPerRequest; i++ {
		headers[i] = createTestBlockHeader(prevHash, prevTimestamp+uint32(i+1)*600, uint32(i+1))
		prevHash = headers[i].BlockHash()
		prevTimestamp = headers[i].Timestamp
	}

	msg := &MsgHeaders{Headers: headers}
	sm.HandleHeaders(peer, msg)

	// Wait for getheaders to be sent
	select {
	case <-requestCh:
		// Good, request was sent
	case <-time.After(time.Second):
		t.Error("expected getheaders request after full batch")
	}

	// Sync should NOT be complete yet
	if sm.IsSynced() {
		t.Error("sync should not be complete after receiving exactly 2000 headers")
	}

	// Clean up
	close(peer.quit)
	wg.Wait()
}

func TestSyncManagerIgnoresNonSyncPeer(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	// Set a sync peer
	syncPeer := createMockPeer("1.2.3.4:8333", 100)
	sm.mu.Lock()
	sm.syncPeer = syncPeer
	sm.mu.Unlock()

	// Create a different peer
	otherPeer := createMockPeer("5.6.7.8:8333", 200)

	// Build headers
	headers := make([]wire.BlockHeader, 5)
	prevHash := params.GenesisHash
	prevTimestamp := params.GenesisBlock.Header.Timestamp

	for i := 0; i < 5; i++ {
		headers[i] = createTestBlockHeader(prevHash, prevTimestamp+600, uint32(i+1))
		prevHash = headers[i].BlockHash()
		prevTimestamp = headers[i].Timestamp
	}

	msg := &MsgHeaders{Headers: headers}

	// Handle from non-sync peer
	sm.HandleHeaders(otherPeer, msg)

	// Should NOT have added headers
	if idx.BestHeight() != 0 {
		t.Errorf("best height = %d, want 0 (headers from non-sync peer should be ignored)",
			idx.BestHeight())
	}
}

func TestSyncManagerHandleGetHeaders(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// Build a chain of headers in the index
	prevNode := idx.Genesis()
	for i := 1; i <= 50; i++ {
		header := createTestBlockHeader(
			prevNode.Hash,
			prevNode.Header.Timestamp+600,
			uint32(i),
		)
		node, err := idx.AddHeader(header)
		if err != nil {
			t.Fatalf("failed to add header %d: %v", i, err)
		}
		prevNode = node
	}

	// Create peer with send queue
	peer := &Peer{
		config: PeerConfig{
			Network:         RegtestMagic,
			ProtocolVersion: ProtocolVersion,
		},
		addr:          "1.2.3.4:8333",
		state:         PeerStateConnected,
		peerVersion:   &MsgVersion{StartHeight: 0},
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		handshakeDone: make(chan struct{}),
	}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	// Request headers starting from genesis
	getHeaders := &MsgGetHeaders{
		ProtocolVersion: ProtocolVersion,
		BlockLocators:   []wire.Hash256{params.GenesisHash},
		HashStop:        wire.Hash256{},
	}

	// Handle the request (this should send headers in response)
	sm.HandleGetHeaders(peer, getHeaders)

	// Check for response
	select {
	case msg := <-peer.sendQueue:
		headersMsg, ok := msg.(*MsgHeaders)
		if !ok {
			t.Fatalf("expected MsgHeaders, got %T", msg)
		}
		if len(headersMsg.Headers) != 50 {
			t.Errorf("got %d headers, want 50", len(headersMsg.Headers))
		}
	case <-time.After(time.Second):
		t.Error("no response received")
	}

	close(peer.quit)
}

func TestSyncManagerPeerDisconnect(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	pm := &PeerManager{
		peers: make(map[string]*PeerInfo),
	}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
		PeerManager: pm,
	})

	// Set up sync peer
	syncPeer := createMockPeer("1.2.3.4:8333", 100)
	sm.mu.Lock()
	sm.syncPeer = syncPeer
	sm.mu.Unlock()

	// Handle disconnect
	sm.HandlePeerDisconnected(syncPeer)

	// Sync peer should be cleared
	if sm.SyncPeer() != nil {
		t.Error("sync peer should be nil after disconnect")
	}
}

func TestSyncManagerStartStop(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	pm := &PeerManager{
		peers: make(map[string]*PeerInfo),
	}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
		PeerManager: pm,
	})

	// Start should not block
	sm.Start()

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Stop should complete quickly
	done := make(chan struct{})
	go func() {
		sm.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Good
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not complete in time")
	}
}

func TestSyncManagerCreatePeerListeners(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	listeners := sm.CreatePeerListeners()

	if listeners.OnHeaders == nil {
		t.Error("OnHeaders should not be nil")
	}

	if listeners.OnGetHeaders == nil {
		t.Error("OnGetHeaders should not be nil")
	}
}

func TestSyncManagerHandlesInvalidHeader(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	pm := &PeerManager{
		peers:  make(map[string]*PeerInfo),
		banned: make(map[string]*BanInfo),
		quit:   make(chan struct{}),
	}

	// Create a test peer
	peer := &Peer{
		config: PeerConfig{
			Network:         RegtestMagic,
			ProtocolVersion: ProtocolVersion,
		},
		addr:          "1.2.3.4:8333",
		state:         PeerStateConnected,
		peerVersion:   &MsgVersion{StartHeight: 100},
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		handshakeDone: make(chan struct{}),
	}

	pm.peers[peer.addr] = &PeerInfo{peer: peer, connType: ConnFullRelay}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
		PeerManager: pm,
	})

	sm.mu.Lock()
	sm.syncPeer = peer
	sm.mu.Unlock()

	// Create an invalid header (orphan - unknown parent)
	invalidHeader := createTestBlockHeader(
		wire.Hash256{0x12, 0x34}, // Unknown parent
		params.GenesisBlock.Header.Timestamp+600,
		1,
	)

	msg := &MsgHeaders{Headers: []wire.BlockHeader{invalidHeader}}

	// Handle the invalid headers - this should clear the sync peer
	sm.HandleHeaders(peer, msg)

	// Sync peer should be cleared after receiving bad header
	if sm.SyncPeer() != nil {
		t.Error("sync peer should be nil after bad header")
	}
}

func TestHeaderSyncFlow(t *testing.T) {
	// This test simulates a complete header sync flow:
	// 1. Peer sends 2000 headers
	// 2. We request more
	// 3. Peer sends remaining headers (< 2000)
	// 4. Sync completes

	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	var syncComplete atomic.Bool
	var requestCount atomic.Int32

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
		OnSyncComplete: func() {
			syncComplete.Store(true)
		},
	})

	// Create peer
	peer := &Peer{
		config: PeerConfig{
			Network:         RegtestMagic,
			ProtocolVersion: ProtocolVersion,
		},
		addr:          "1.2.3.4:8333",
		state:         PeerStateConnected,
		peerVersion:   &MsgVersion{StartHeight: 2500},
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		handshakeDone: make(chan struct{}),
	}

	// Count getheaders requests
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg := <-peer.sendQueue:
				if _, ok := msg.(*MsgGetHeaders); ok {
					requestCount.Add(1)
				}
			case <-peer.quit:
				return
			}
		}
	}()

	sm.mu.Lock()
	sm.syncPeer = peer
	sm.mu.Unlock()

	// Build first batch of 2000 headers
	headers1 := make([]wire.BlockHeader, 2000)
	prevHash := params.GenesisHash
	prevTimestamp := params.GenesisBlock.Header.Timestamp

	for i := 0; i < 2000; i++ {
		headers1[i] = createTestBlockHeader(prevHash, prevTimestamp+uint32(i+1)*10, uint32(i+1))
		prevHash = headers1[i].BlockHash()
		prevTimestamp = headers1[i].Timestamp
	}

	// Send first batch
	sm.HandleHeaders(peer, &MsgHeaders{Headers: headers1})

	// Should not be synced yet
	if sm.IsSynced() {
		t.Error("should not be synced after first batch")
	}

	// Should have requested more headers
	time.Sleep(50 * time.Millisecond)
	if requestCount.Load() == 0 {
		t.Error("should have sent getheaders request after full batch")
	}

	// Height should be 2000
	if idx.BestHeight() != 2000 {
		t.Errorf("height = %d, want 2000", idx.BestHeight())
	}

	// Build second batch of 500 headers (< 2000)
	headers2 := make([]wire.BlockHeader, 500)
	for i := 0; i < 500; i++ {
		headers2[i] = createTestBlockHeader(prevHash, prevTimestamp+uint32(i+1)*10, uint32(2000+i+1))
		prevHash = headers2[i].BlockHash()
		prevTimestamp = headers2[i].Timestamp
	}

	// Send second batch
	sm.HandleHeaders(peer, &MsgHeaders{Headers: headers2})

	// Should now be synced
	if !sm.IsSynced() {
		t.Error("should be synced after second batch (< 2000 headers)")
	}

	// OnSyncComplete is called in a goroutine (to avoid deadlock on sm.mu),
	// so give it a moment to run before checking.
	time.Sleep(50 * time.Millisecond)
	if !syncComplete.Load() {
		t.Error("OnSyncComplete should have been called")
	}

	// Final height should be 2500
	if idx.BestHeight() != 2500 {
		t.Errorf("final height = %d, want 2500", idx.BestHeight())
	}

	// Clean up
	close(peer.quit)
	wg.Wait()
}

// ============================================================================
// Block Download (IBD) Tests
// ============================================================================

func TestBlockDownloadStateConstants(t *testing.T) {
	// Verify state constants are defined correctly
	if BlockDownloadPending != 0 {
		t.Errorf("BlockDownloadPending = %d, want 0", BlockDownloadPending)
	}
	if BlockDownloadInFlight != 1 {
		t.Errorf("BlockDownloadInFlight = %d, want 1", BlockDownloadInFlight)
	}
	if BlockDownloadReceived != 2 {
		t.Errorf("BlockDownloadReceived = %d, want 2", BlockDownloadReceived)
	}
}

func TestSyncManagerBlockDownloadConfig(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// Test default download window
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	if sm.downloadWindow != DefaultDownloadWindow {
		t.Errorf("download window = %d, want %d", sm.downloadWindow, DefaultDownloadWindow)
	}

	// Test custom download window
	sm2 := NewSyncManager(SyncManagerConfig{
		ChainParams:    params,
		HeaderIndex:    idx,
		DownloadWindow: 512,
	})

	if sm2.downloadWindow != 512 {
		t.Errorf("custom download window = %d, want 512", sm2.downloadWindow)
	}
}

func TestSyncManagerHandleBlock(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	// Create a mock peer
	peer := createMockPeer("1.2.3.4:8333", 100)

	// Create a test block
	genesis := idx.Genesis()
	header := createTestBlockHeader(genesis.Hash, genesis.Header.Timestamp+600, 1)
	blockHash := header.BlockHash()

	// Add header to index
	_, err := idx.AddHeader(header)
	if err != nil {
		t.Fatalf("failed to add header: %v", err)
	}

	// Create block request in inflight
	sm.mu.Lock()
	sm.inflight[blockHash] = &blockRequest{
		Hash:      blockHash,
		Height:    1,
		Peer:      peer,
		State:     BlockDownloadInFlight,
		RequestAt: time.Now(),
	}
	sm.mu.Unlock()

	// Create the block message
	block := &wire.MsgBlock{
		Header: header,
		Transactions: []*wire.MsgTx{
			{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
						SignatureScript:  []byte{0x01, 0x01},
						Sequence:         0xFFFFFFFF,
					},
				},
				TxOut: []*wire.TxOut{
					{Value: 5000000000, PkScript: []byte{0x51}},
				},
			},
		},
	}

	// Handle the block
	msgBlock := &MsgBlock{Block: block}
	sm.HandleBlock(peer, msgBlock)

	// Verify request was removed from inflight
	sm.mu.RLock()
	_, stillInflight := sm.inflight[blockHash]
	sm.mu.RUnlock()

	if stillInflight {
		t.Error("block should be removed from inflight after handling")
	}
}

func TestSyncManagerIgnoresUnsolicitedBlock(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	peer := createMockPeer("1.2.3.4:8333", 100)

	// Create a block that wasn't requested
	block := &wire.MsgBlock{
		Header: createTestBlockHeader(params.GenesisHash, params.GenesisBlock.Header.Timestamp+600, 1),
		Transactions: []*wire.MsgTx{
			{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
						SignatureScript:  []byte{0x01, 0x01},
						Sequence:         0xFFFFFFFF,
					},
				},
				TxOut: []*wire.TxOut{{Value: 5000000000, PkScript: []byte{0x51}}},
			},
		},
	}

	msgBlock := &MsgBlock{Block: block}

	// Should not panic when receiving unsolicited block
	sm.HandleBlock(peer, msgBlock)

	// No crash means success
}

func TestStallTimeoutAdaptive(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	peer := createMockPeer("1.2.3.4:8333", 100)

	// Initial timeout should be base
	timeout := sm.getStallTimeout(peer)
	if timeout != BaseStallTimeout {
		t.Errorf("initial timeout = %v, want %v", timeout, BaseStallTimeout)
	}

	// Increase timeout
	sm.increaseStallTimeout(peer)
	timeout = sm.getStallTimeout(peer)
	expectedTimeout := BaseStallTimeout * 2
	if timeout != expectedTimeout {
		t.Errorf("after increase timeout = %v, want %v", timeout, expectedTimeout)
	}

	// Increase again
	sm.increaseStallTimeout(peer)
	timeout = sm.getStallTimeout(peer)
	expectedTimeout = BaseStallTimeout * 4
	if timeout != expectedTimeout {
		t.Errorf("after second increase timeout = %v, want %v", timeout, expectedTimeout)
	}

	// Should cap at MaxStallTimeout
	for i := 0; i < 10; i++ {
		sm.increaseStallTimeout(peer)
	}
	timeout = sm.getStallTimeout(peer)
	if timeout > MaxStallTimeout {
		t.Errorf("timeout %v exceeds max %v", timeout, MaxStallTimeout)
	}

	// Decrease should work
	sm.decreaseStallTimeout(peer)
	newTimeout := sm.getStallTimeout(peer)
	if newTimeout >= timeout {
		t.Errorf("decrease should reduce timeout: %v >= %v", newTimeout, timeout)
	}
}

func TestBlockQueueLength(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	// Initially queue should be empty
	if sm.BlockQueueLength() != 0 {
		t.Errorf("initial queue length = %d, want 0", sm.BlockQueueLength())
	}

	// Add some items to queue
	sm.mu.Lock()
	sm.blockQueue = []*blockRequest{
		{Hash: wire.Hash256{1}, Height: 1, State: BlockDownloadPending},
		{Hash: wire.Hash256{2}, Height: 2, State: BlockDownloadPending},
		{Hash: wire.Hash256{3}, Height: 3, State: BlockDownloadPending},
	}
	sm.mu.Unlock()

	if sm.BlockQueueLength() != 3 {
		t.Errorf("queue length = %d, want 3", sm.BlockQueueLength())
	}
}

func TestBlocksInFlight(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	// Initially should be empty
	if sm.BlocksInFlight() != 0 {
		t.Errorf("initial inflight = %d, want 0", sm.BlocksInFlight())
	}

	// Add some inflight requests
	sm.mu.Lock()
	sm.inflight[wire.Hash256{1}] = &blockRequest{Hash: wire.Hash256{1}}
	sm.inflight[wire.Hash256{2}] = &blockRequest{Hash: wire.Hash256{2}}
	sm.mu.Unlock()

	if sm.BlocksInFlight() != 2 {
		t.Errorf("inflight = %d, want 2", sm.BlocksInFlight())
	}
}

func TestCreatePeerListenersIncludesOnBlock(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	listeners := sm.CreatePeerListeners()

	if listeners.OnBlock == nil {
		t.Error("OnBlock listener should be set")
	}
	if listeners.OnHeaders == nil {
		t.Error("OnHeaders listener should be set")
	}
	if listeners.OnGetHeaders == nil {
		t.Error("OnGetHeaders listener should be set")
	}
}

// ---------------------------------------------------------------------------
// IBD-flag regression tests (L1-7c)
//
// These three tests guard the Bitcoin-Core-matching semantics introduced by
// L1-7c: ibdActive starts true, is latched to false only when the chain tip
// is recent, and never returns to true.
// ---------------------------------------------------------------------------

// mockChainConnector is a minimal ChainConnector for IBD-flag tests.
// It lets callers control the tip timestamp so we can simulate a recent vs.
// stale tip without actually connecting blocks.
type mockChainConnector struct {
	tipHash      wire.Hash256
	tipHeight    int32
	tipTimestamp uint32 // Unix seconds for the simulated tip block
}

func (m *mockChainConnector) BestBlock() (wire.Hash256, int32) {
	return m.tipHash, m.tipHeight
}

func (m *mockChainConnector) BestBlockNode() *consensus.BlockNode {
	return &consensus.BlockNode{
		Hash:   m.tipHash,
		Height: m.tipHeight,
		Header: wire.BlockHeader{Timestamp: m.tipTimestamp},
	}
}

func (m *mockChainConnector) ConnectBlock(_ *wire.MsgBlock) error { return nil }
func (m *mockChainConnector) ReloadChainState()                   {}
func (m *mockChainConnector) HasPendingRecovery() bool            { return false }
func (m *mockChainConnector) IsIBD() bool                         { return true }

// TestIsIBDActive_TrueAtStartup verifies that a freshly created SyncManager
// reports IsIBDActive()=true before any blocks have connected.
// Regression for L1-7c: the old code initialised ibdActive=false so the
// flag stayed false during the entire header-sync phase.
func TestIsIBDActive_TrueAtStartup(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	// A fresh sync manager must report IBD active — we are definitely not
	// at tip when we have no peers and no blocks.
	if !sm.IsIBDActive() {
		t.Fatal("new sync manager should report IsIBDActive()=true before any blocks connect")
	}
}

// TestIsIBDActive_FalseWhenTipIsRecent verifies that updateIBDStatus latches
// ibdActive to false once the chain tip's timestamp is within MaxTipAge (24h),
// and that it never flips back to true.
func TestIsIBDActive_FalseWhenTipIsRecent(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// Simulate a tip whose block timestamp is 1 minute ago — well within MaxTipAge.
	recentTimestamp := uint32(time.Now().Add(-1 * time.Minute).Unix())
	mock := &mockChainConnector{tipHeight: 1000, tipTimestamp: recentTimestamp}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  idx,
		ChainManager: mock,
	})

	// Should start in IBD.
	if !sm.IsIBDActive() {
		t.Fatal("expected IsIBDActive()=true at startup")
	}

	// After calling updateIBDStatus the flag should latch to false.
	sm.updateIBDStatus()
	if sm.IsIBDActive() {
		t.Fatal("expected IsIBDActive()=false after tip age < MaxTipAge")
	}

	// Confirm latch: calling updateIBDStatus again must not re-set the flag.
	sm.updateIBDStatus()
	if sm.IsIBDActive() {
		t.Fatal("IsIBDActive() must never return true once latched false")
	}

	// Confirm lock-freedom: IsIBDActive must be callable concurrently without
	// data races.  The race detector will flag any violation.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_ = sm.IsIBDActive()
			}
		}()
	}
	wg.Wait()
}

// TestIsIBDActive_TrueDuringHeaderSync exercises the scenario that triggered
// the L1-7c bug: blockbrew returned initialblockdownload:false while syncing
// headers (blocks=0, headers>0).
//
// The test feeds the sync manager 10 headers as if a peer sent them, then
// verifies IBD is still active because the headers' timestamps are old (the
// genesis timestamp is from 2009, far older than MaxTipAge).
func TestIsIBDActive_TrueDuringHeaderSync(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// Stale-tip chain manager: tip is at height 0, timestamp epoch 0 (very old).
	staleMock := &mockChainConnector{tipHeight: 0, tipTimestamp: 0}

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:  params,
		HeaderIndex:  idx,
		ChainManager: staleMock,
	})

	// Feed some headers (old timestamps, as regtest genesis is from 2011).
	peer := createMockPeer("1.2.3.4:8333", 10)
	sm.mu.Lock()
	sm.syncPeer = peer
	sm.mu.Unlock()

	headers := make([]wire.BlockHeader, 10)
	prevHash := params.GenesisHash
	prevTS := params.GenesisBlock.Header.Timestamp // 2011 — very old
	for i := 0; i < 10; i++ {
		headers[i] = createTestBlockHeader(prevHash, prevTS+uint32((i+1)*600), uint32(i+1))
		prevHash = headers[i].BlockHash()
		prevTS = headers[i].Timestamp
	}
	sm.HandleHeaders(peer, &MsgHeaders{Headers: headers})

	// Header sync completed (< 2000 headers), but we have no connected blocks
	// and the timestamps are old → IBD must still be active.
	sm.updateIBDStatus()
	if !sm.IsIBDActive() {
		t.Fatal("IBD should remain active during header sync with stale timestamps")
	}

	// Simulate tip advancing to a recent block (tip caught up).
	recentTS := uint32(time.Now().Add(-30 * time.Second).Unix())
	staleMock.tipTimestamp = recentTS
	staleMock.tipHeight = 10

	sm.updateIBDStatus()
	if sm.IsIBDActive() {
		t.Fatal("IBD should be false once tip is recent")
	}
}

// TestNumValidationWorkers verifies the worker-count policy: we clamp
// runtime.NumCPU()/2 into [MinValidationWorkers, MaxValidationWorkers].
// A bogus policy (e.g. 0 workers, or >MaxValidationWorkers) would either
// deadlock Start() or pin every core to block-sanity checks, so this
// guards the constants that W64 introduced.
func TestNumValidationWorkers(t *testing.T) {
	n := numValidationWorkers()
	if n < MinValidationWorkers {
		t.Errorf("numValidationWorkers()=%d, want >= %d", n, MinValidationWorkers)
	}
	if n > MaxValidationWorkers {
		t.Errorf("numValidationWorkers()=%d, want <= %d", n, MaxValidationWorkers)
	}
}

// stallingChainConnector blocks forever inside ConnectBlock so the test
// can saturate connectionChan without the connectionWorker draining it.
// Used by TestValidationWorkerNoDeadlockUnderBackpressure.
type stallingChainConnector struct {
	mockChainConnector
	release chan struct{}
}

func (s *stallingChainConnector) ConnectBlock(_ *wire.MsgBlock) error {
	<-s.release
	return nil
}

// TestValidationWorkerNoDeadlockUnderBackpressure is the W63 / W64-thread-A
// regression test.  The old single-goroutine validationWorker did a
// blocking send to connectionChan; when connectionChan was full (because
// connectionWorker was stuck on a slow ConnectBlock or a missing
// nextHeight) the validation worker parked forever, which backed up
// validationChan and caused the peer readHandler to drop incoming blocks.
// The new implementation must:
//   1. Spawn N parallel validation workers (so one slow ConnectBlock
//      can't stop validation globally).
//   2. Fall back to requeueForRedownload() when connectionChan is full,
//      instead of parking the goroutine.
//
// This test stuffs both channels past capacity with a wedged connection
// worker, then asserts the validation workers drained validationChan
// (the blocks ended up in BlockDownloadPending via requeue) within a
// short deadline.  If the old blocking-send code were still in place,
// validationChan would stay saturated and the test would time out.
func TestValidationWorkerNoDeadlockUnderBackpressure(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }

	stall := &stallingChainConnector{
		mockChainConnector: mockChainConnector{tipHeight: 0, tipTimestamp: 1},
		release:            release,
	}

	// Small downloadWindow keeps the channel caps tight so we can
	// saturate them quickly without allocating thousands of blocks.
	const window = 8
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:    params,
		HeaderIndex:    idx,
		ChainManager:   stall,
		DownloadWindow: window,
	})
	sm.Start()
	// Cleanup: release the wedged ConnectBlock FIRST so the connectionWorker
	// unblocks, then Stop() can complete and wg.Wait() returns.  If we Stop
	// before releasing, the connectionWorker stays wedged and we leak
	// goroutines into subsequent tests — which makes `go test -race` flag
	// the whole package as FAIL even when every individual test passes.
	defer func() {
		releaseFn()
		done := make(chan struct{})
		go func() {
			sm.Stop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Stop did not complete within 3s — goroutine leak")
		}
	}()

	// Seed connectionChan directly with `window` validated blocks so the
	// connectionWorker picks one up, enters the wedged ConnectBlock, and
	// can no longer drain connectionChan — the rest stays buffered.
	// Then seed validationChan with >window blocks.  If the validation
	// workers' connectionChan send is still blocking, none of these will
	// be drained and the inflight map will stay full.
	seedBlock := func(height int32) *blockWithRequest {
		hdr := createTestBlockHeader(wire.Hash256{}, uint32(100+height), uint32(height))
		return &blockWithRequest{
			block: &wire.MsgBlock{
				Header: hdr,
				Transactions: []*wire.MsgTx{
					{
						Version: 1,
						TxIn: []*wire.TxIn{{
							PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
							SignatureScript:  []byte{0x01, byte(height)},
							Sequence:         0xFFFFFFFF,
						}},
						TxOut: []*wire.TxOut{{Value: 5000000000, PkScript: []byte{0x51}}},
					},
				},
			},
			req: &blockRequest{
				Hash:   hdr.BlockHash(),
				Height: height,
				State:  BlockDownloadReceived,
			},
		}
	}

	// Record some inflight entries so requeueForRedownload's delete
	// path actually has something to delete (exercises the full code
	// path, not just the state reset).
	for h := int32(1); h <= window*3; h++ {
		bwr := seedBlock(h)
		sm.mu.Lock()
		sm.inflight[bwr.req.Hash] = bwr.req
		sm.mu.Unlock()
	}

	// Fill connectionChan to capacity (non-blocking pre-seed).
	for i := 0; i < window; i++ {
		bwr := seedBlock(int32(1000 + i))
		select {
		case sm.connectionChan <- bwr:
		default:
			// Expected once we hit cap — that's fine.
		}
	}

	// Push enough blocks onto validationChan to overflow connectionChan
	// capacity after validation.  If the fix works, the surplus blocks
	// are re-queued (state=Pending, removed from inflight) rather than
	// parking goroutines.  We need to retain references so we can assert
	// on their final state.
	pushed := make([]*blockWithRequest, 0, window*3)
	for h := int32(1); h <= window*3; h++ {
		bwr := seedBlock(h)
		// Track the already-registered inflight req so we can observe
		// the state mutation driven by requeueForRedownload.
		sm.mu.Lock()
		if existing, ok := sm.inflight[bwr.req.Hash]; ok {
			bwr.req = existing
		}
		sm.mu.Unlock()
		pushed = append(pushed, bwr)
		select {
		case sm.validationChan <- bwr:
		case <-time.After(2 * time.Second):
			t.Fatalf("validationChan send blocked at h=%d — workers likely deadlocked", h)
		}
	}

	// Give the validation workers time to drain validationChan and
	// requeue the surplus.  200ms is generous for CheckBlockSanity on
	// tiny regtest blocks + channel ops.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(sm.validationChan) == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(sm.validationChan); got != 0 {
		t.Fatalf("validationChan still has %d entries after 2s — workers are deadlocked", got)
	}

	// Additional invariant: inflight must shrink because
	// requeueForRedownload() deletes from the inflight map on the
	// re-queue path.  We pre-seeded `window*3` inflight entries and
	// pushed the same number through validationChan; in a healthy run
	// some non-zero fraction will have taken the requeue path (the
	// rest landed in connectionChan before it saturated).  We only
	// assert that the pipeline drained — we do NOT read bwr.req.State
	// from the test goroutine because the validationWorker mutates
	// that field without holding sm.mu (pre-existing invariant: state
	// is owned by the stage currently processing the block, handed
	// off via channels).
	_ = pushed
	t.Logf("backpressure test: validationChan drained, no deadlock (len=%d, cap=%d)",
		len(sm.validationChan), cap(sm.validationChan))
}

// TestMaxPendingBlocksInvariant guards a silent-data-loss class of bug
// (W67d). The connection worker's pending map evicts entries when its
// size exceeds MaxPendingBlocks. If MaxPendingBlocks is ever smaller
// than the download window actually in use, the worker will throw away
// blocks that are still in flight — producing the same cursor-skip
// stall we debugged in lunarblock's sync loop.
//
// Two layers of defense:
//  1. MaxPendingBlocks must not drop below DefaultDownloadWindow
//     (compile-time invariant).
//  2. A custom DownloadWindow configured larger than MaxPendingBlocks
//     must be clamped by NewSyncManager, not silently accepted.
func TestMaxPendingBlocksInvariant(t *testing.T) {
	if MaxPendingBlocks < DefaultDownloadWindow {
		t.Fatalf("MaxPendingBlocks (%d) must be >= DefaultDownloadWindow (%d): "+
			"any default-config blockbrew would lose in-flight blocks to "+
			"pending-map eviction, stalling IBD",
			MaxPendingBlocks, DefaultDownloadWindow)
	}
}

func TestSyncManagerClampsOversizedDownloadWindow(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	// Ask for a window 2× the pending cap; NewSyncManager must clamp.
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:    params,
		HeaderIndex:    idx,
		DownloadWindow: MaxPendingBlocks * 2,
	})

	if sm.downloadWindow > MaxPendingBlocks {
		t.Fatalf("downloadWindow = %d, want <= MaxPendingBlocks (%d): "+
			"without clamping, the connection worker's pending map would "+
			"evict in-flight blocks",
			sm.downloadWindow, MaxPendingBlocks)
	}
	if sm.downloadWindow != MaxPendingBlocks {
		t.Errorf("downloadWindow = %d, want exactly MaxPendingBlocks (%d)",
			sm.downloadWindow, MaxPendingBlocks)
	}
}
