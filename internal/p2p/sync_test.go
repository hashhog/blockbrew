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
		peers: make(map[string]*Peer),
	}

	// Add peers with different heights
	peer1 := createMockPeer("1.2.3.4:8333", 100)
	peer2 := createMockPeer("5.6.7.8:8333", 500)
	peer3 := createMockPeer("9.10.11.12:8333", 200)

	pm.peers["1.2.3.4:8333"] = peer1
	pm.peers["5.6.7.8:8333"] = peer2
	pm.peers["9.10.11.12:8333"] = peer3

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
		peers: make(map[string]*Peer),
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
		peers: make(map[string]*Peer),
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
		peers:  make(map[string]*Peer),
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

	pm.peers[peer.addr] = peer

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

func TestIsIBDActive(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
	})

	// Initially IBD should not be active
	if sm.IsIBDActive() {
		t.Error("IBD should not be active initially")
	}

	// Set IBD active
	sm.mu.Lock()
	sm.ibdActive = true
	sm.mu.Unlock()

	if !sm.IsIBDActive() {
		t.Error("IBD should be active after setting")
	}
}
