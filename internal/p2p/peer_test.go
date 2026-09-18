package p2p

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPeerHandshakeOutbound tests the full outbound handshake sequence.
func TestPeerHandshakeOutbound(t *testing.T) {
	// Create a net.Pipe to simulate a TCP connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	config := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork | ServiceNodeWitness,
		UserAgent:       "/blockbrew:0.1.0/",
		BestHeight:      800000,
	}

	// Create peer with the client side of the pipe
	peer := &Peer{
		config:        config,
		conn:          clientConn,
		addr:          "127.0.0.1:8333",
		state:         PeerStateConnecting,
		inbound:       false,
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		localNonce:    12345678,
		handshakeDone: make(chan struct{}),
		startTime:     time.Now(),
		lastRecv:      time.Now(),
		lastSend:      time.Now(),
		transport:     NewV1Transport(clientConn, config.Network),
	}

	// Run the mock server in a goroutine
	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr = mockServerHandshake(serverConn, config.Network)
	}()

	// Start the peer (this initiates handshake)
	errCh := make(chan error, 1)
	go func() {
		errCh <- peer.Start()
	}()

	// Wait for handshake to complete
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("peer.Start() failed: %v", err)
		}
	case <-time.After(pipeHandshakeBudget):
		t.Fatal("handshake timed out")
	}

	// Verify state
	if !peer.IsConnected() {
		t.Error("peer should be connected after handshake")
	}

	if peer.State() != PeerStateConnected {
		t.Errorf("state = %v, want %v", peer.State(), PeerStateConnected)
	}

	// Close ordering: handshakeDone is the signal; then hang up. The
	// mock treats the resulting closed-pipe as success, not a fixture
	// failure.
	peer.Disconnect()
	wg.Wait()

	if serverErr != nil {
		t.Errorf("server error: %v", serverErr)
	}
}

// TestPeerHandshakeInbound tests the inbound handshake sequence.
func TestPeerHandshakeInbound(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	config := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork,
		UserAgent:       "/blockbrew:0.1.0/",
		BestHeight:      800000,
	}

	// Create an inbound peer (server side)
	peer := NewInboundPeer(serverConn, config)

	// Run the mock client in a goroutine
	var clientErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientErr = mockClientHandshake(clientConn, config.Network)
	}()

	// Start the peer
	errCh := make(chan error, 1)
	go func() {
		errCh <- peer.Start()
	}()

	// Wait for handshake to complete
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("peer.Start() failed: %v", err)
		}
	case <-time.After(pipeHandshakeBudget):
		t.Fatal("handshake timed out")
	}

	if !peer.IsConnected() {
		t.Error("peer should be connected after handshake")
	}

	// Clean up
	peer.Disconnect()
	wg.Wait()

	if clientErr != nil {
		t.Errorf("client error: %v", clientErr)
	}
}

type mockHandshakeOpts struct {
	protocolVersion   int32
	nonce             uint64
	extraBeforeVerack []Message
}

// mockServerHandshake simulates a Bitcoin node responding to an outbound
// handshake. The pipe reader runs concurrently with our writes so net.Pipe
// cannot deadlock when the peer also writes (wtxidrelay/sendaddrv2/verack).
func mockServerHandshake(conn net.Conn, magic uint32) error {
	return mockServerHandshakeOpts(conn, magic, mockHandshakeOpts{})
}

func mockServerHandshakeOpts(conn net.Conn, magic uint32, opts mockHandshakeOpts) error {
	sess := servePipe(conn, magic)
	if _, err := sess.waitMessage(pipeHandshakeBudget, func(m Message) bool {
		_, ok := m.(*MsgVersion)
		return ok
	}); err != nil {
		return err
	}

	pv := opts.protocolVersion
	if pv == 0 {
		pv = ProtocolVersion
	}
	nonce := opts.nonce
	if nonce == 0 {
		nonce = 87654321
	}
	version := &MsgVersion{
		ProtocolVersion: pv,
		Services:        ServiceNodeNetwork | ServiceNodeWitness,
		Timestamp:       time.Now().Unix(),
		AddrRecv:        NetAddress{},
		AddrFrom:        NetAddress{},
		Nonce:           nonce,
		UserAgent:       "/mocknode:0.1.0/",
		StartHeight:     800001,
		Relay:           true,
	}
	if err := writePipeMessage(conn, magic, version); err != nil {
		return err
	}
	for _, extra := range opts.extraBeforeVerack {
		if err := writePipeMessage(conn, magic, extra); err != nil {
			return err
		}
	}
	if err := writePipeMessage(conn, magic, &MsgVerAck{}); err != nil {
		return err
	}
	return sess.waitClose(pipeHandshakeBudget)
}

// mockClientHandshake simulates an outbound client initiating handshake with us.
func mockClientHandshake(conn net.Conn, magic uint32) error {
	sess := servePipe(conn, magic)
	version := &MsgVersion{
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork,
		Timestamp:       time.Now().Unix(),
		AddrRecv:        NetAddress{},
		AddrFrom:        NetAddress{},
		Nonce:           11111111,
		UserAgent:       "/mockclient:0.1.0/",
		StartHeight:     799999,
		Relay:           true,
	}
	if err := writePipeMessage(conn, magic, version); err != nil {
		return err
	}

	gotVersion := false
	gotVerack := false
	for !gotVersion || !gotVerack {
		msg, err := sess.waitMessage(pipeHandshakeBudget, func(m Message) bool {
			switch m.(type) {
			case *MsgVersion:
				return !gotVersion
			case *MsgVerAck:
				return !gotVerack
			default:
				return false
			}
		})
		if err != nil {
			return err
		}
		switch msg.(type) {
		case *MsgVersion:
			gotVersion = true
		case *MsgVerAck:
			gotVerack = true
		}
	}

	if err := writePipeMessage(conn, magic, &MsgVerAck{}); err != nil {
		return err
	}
	return sess.waitClose(pipeHandshakeBudget)
}

// TestPeerPingPong tests ping/pong nonce matching and latency measurement.
func TestPeerPingPong(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	config := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork,
		UserAgent:       "/blockbrew:0.1.0/",
		BestHeight:      800000,
	}

	// Create peer
	peer := &Peer{
		config:        config,
		conn:          clientConn,
		addr:          "127.0.0.1:8333",
		state:         PeerStateConnected, // Skip handshake
		inbound:       false,
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		localNonce:    12345678,
		handshakeDone: make(chan struct{}),
		startTime:     time.Now(),
		lastRecv:      time.Now(),
		lastSend:      time.Now(),
		transport:     NewV1Transport(clientConn, config.Network),
	}
	close(peer.handshakeDone) // Mark handshake as done

	// Start only read/write handlers
	peer.wg.Add(2)
	go peer.readHandler()
	go peer.writeHandler()

	// Run mock server that responds to pings
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sess := servePipe(serverConn, config.Network)
		for {
			msg, err := sess.waitMessage(pipeHandshakeBudget, func(m Message) bool {
				_, ok := m.(*MsgPing)
				return ok
			})
			if err != nil {
				return
			}
			ping := msg.(*MsgPing)
			_ = writePipeMessage(serverConn, config.Network, &MsgPong{Nonce: ping.Nonce})
		}
	}()

	// Send a ping and wait for latency measurement
	testNonce := uint64(0xDEADBEEF)
	peer.mu.Lock()
	peer.lastPingNonce = testNonce
	peer.lastPingTime = time.Now()
	peer.mu.Unlock()

	peer.SendMessage(&MsgPing{Nonce: testNonce})

	waitUntil(t, pipeHandshakeBudget, func() bool { return peer.PingLatency() > 0 })
	latency := peer.PingLatency()
	if latency > time.Second {
		t.Errorf("ping latency = %v, seems too high", latency)
	}

	// Clean up
	peer.Disconnect()
	wg.Wait()
}

// TestPeerDisconnectCleanup tests that Disconnect properly cleans up goroutines.
func TestPeerDisconnectCleanup(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	config := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork,
		UserAgent:       "/blockbrew:0.1.0/",
		BestHeight:      800000,
	}

	peer := &Peer{
		config:        config,
		conn:          clientConn,
		addr:          "127.0.0.1:8333",
		state:         PeerStateConnected,
		inbound:       false,
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		localNonce:    12345678,
		handshakeDone: make(chan struct{}),
		startTime:     time.Now(),
		lastRecv:      time.Now(),
		lastSend:      time.Now(),
		transport:     NewV1Transport(clientConn, config.Network),
	}
	close(peer.handshakeDone)

	// Start handlers
	peer.wg.Add(3)
	go peer.readHandler()
	go peer.writeHandler()
	go peer.pingHandler()

	// Disconnect should wait for all goroutines
	done := make(chan struct{})
	go func() {
		peer.Disconnect()
		close(done)
	}()

	select {
	case <-done:
		// Success - all goroutines cleaned up
	case <-time.After(pipeHandshakeBudget):
		t.Fatal("Disconnect did not return in time - goroutines may be stuck")
	}

	// Verify state
	if peer.State() != PeerStateDisconnected {
		t.Errorf("state = %v, want %v", peer.State(), PeerStateDisconnected)
	}
}

// TestPeerSelfConnectionDetection tests that we detect self-connections.
func TestPeerSelfConnectionDetection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	config := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork,
		UserAgent:       "/blockbrew:0.1.0/",
		BestHeight:      800000,
	}

	ourNonce := uint64(12345678)

	peer := &Peer{
		config:        config,
		conn:          clientConn,
		addr:          "127.0.0.1:8333",
		state:         PeerStateHandshaking,
		inbound:       false,
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		localNonce:    ourNonce,
		handshakeDone: make(chan struct{}),
		startTime:     time.Now(),
		lastRecv:      time.Now(),
		lastSend:      time.Now(),
		transport:     NewV1Transport(clientConn, config.Network),
	}

	// Start handlers
	peer.wg.Add(2)
	go peer.readHandler()
	go peer.writeHandler()

	// Server sends a version with our own nonce (self-connection)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sess := servePipe(serverConn, config.Network)
		version := &MsgVersion{
			ProtocolVersion: ProtocolVersion,
			Services:        ServiceNodeNetwork,
			Timestamp:       time.Now().Unix(),
			Nonce:           ourNonce, // Same as our nonce!
			UserAgent:       "/blockbrew:0.1.0/",
			StartHeight:     800000,
			Relay:           true,
		}
		_ = writePipeMessage(serverConn, config.Network, version)
		_ = sess.waitClose(pipeHandshakeBudget)
	}()

	waitUntil(t, pipeHandshakeBudget, func() bool {
		return peer.State() == PeerStateDisconnected
	})

	peer.Disconnect() // Ensure cleanup
	wg.Wait()
}

// TestPeerProtocolVersionNegotiation tests version negotiation.
func TestPeerProtocolVersionNegotiation(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// We advertise 70016
	config := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: 70016,
		Services:        ServiceNodeNetwork,
		UserAgent:       "/blockbrew:0.1.0/",
		BestHeight:      800000,
	}

	peer := &Peer{
		config:        config,
		conn:          clientConn,
		addr:          "127.0.0.1:8333",
		state:         PeerStateConnecting,
		inbound:       false,
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		localNonce:    12345678,
		handshakeDone: make(chan struct{}),
		startTime:     time.Now(),
		lastRecv:      time.Now(),
		lastSend:      time.Now(),
		transport:     NewV1Transport(clientConn, config.Network),
	}

	// Server with older protocol version
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = mockServerHandshakeOpts(serverConn, config.Network, mockHandshakeOpts{
			protocolVersion: 70015,
		})
	}()

	// Start handshake
	errCh := make(chan error, 1)
	go func() {
		errCh <- peer.Start()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
	case <-time.After(pipeHandshakeBudget):
		t.Fatal("handshake timed out")
	}

	// Negotiated version should be min(70016, 70015) = 70015
	negotiated := peer.ProtocolVersion()
	if negotiated != 70015 {
		t.Errorf("negotiated version = %d, want 70015", negotiated)
	}

	peer.Disconnect()
	wg.Wait()
}

// TestPeerListeners tests that message listeners are called.
func TestPeerListeners(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var pingReceived atomic.Bool
	var pongReceived atomic.Bool

	config := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork,
		UserAgent:       "/blockbrew:0.1.0/",
		BestHeight:      800000,
		Listeners: &PeerListeners{
			OnPing: func(p *Peer, msg *MsgPing) {
				pingReceived.Store(true)
			},
			OnPong: func(p *Peer, msg *MsgPong) {
				pongReceived.Store(true)
			},
		},
	}

	peer := &Peer{
		config:        config,
		conn:          clientConn,
		addr:          "127.0.0.1:8333",
		state:         PeerStateConnected,
		inbound:       false,
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		localNonce:    12345678,
		handshakeDone: make(chan struct{}),
		startTime:     time.Now(),
		lastRecv:      time.Now(),
		lastSend:      time.Now(),
		transport:     NewV1Transport(clientConn, config.Network),
	}
	close(peer.handshakeDone)

	peer.wg.Add(2)
	go peer.readHandler()
	go peer.writeHandler()

	// Server sends ping and pong
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sess := servePipe(serverConn, config.Network)
		_ = writePipeMessage(serverConn, config.Network, &MsgPing{Nonce: 123})
		_, _ = sess.waitMessage(pipeHandshakeBudget, func(m Message) bool {
			_, ok := m.(*MsgPong)
			return ok
		})
		_ = writePipeMessage(serverConn, config.Network, &MsgPong{Nonce: 456})
		_ = sess.waitClose(pipeHandshakeBudget)
	}()

	waitUntil(t, pipeHandshakeBudget, func() bool {
		return pingReceived.Load() && pongReceived.Load()
	})

	peer.Disconnect()
	wg.Wait()
}

// TestPeerSendQueueBackpressure tests send queue behavior when full.
func TestPeerSendQueueBackpressure(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	config := PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork,
		UserAgent:       "/blockbrew:0.1.0/",
		BestHeight:      800000,
	}

	peer := &Peer{
		config:        config,
		conn:          clientConn,
		addr:          "127.0.0.1:8333",
		state:         PeerStateConnected,
		inbound:       false,
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		localNonce:    12345678,
		handshakeDone: make(chan struct{}),
		startTime:     time.Now(),
		lastRecv:      time.Now(),
		lastSend:      time.Now(),
	}
	close(peer.handshakeDone)

	// Don't start write handler - queue will fill up

	// Fill the queue
	for i := 0; i < SendQueueSize; i++ {
		peer.SendMessage(&MsgPing{Nonce: uint64(i)})
	}

	// Next message should be dropped (non-blocking SendMessage)
	peer.SendMessage(&MsgPing{Nonce: 999})

	// Queue should still be at capacity
	if len(peer.sendQueue) != SendQueueSize {
		t.Errorf("queue length = %d, want %d", len(peer.sendQueue), SendQueueSize)
	}

	// SendMessageWait should return error
	err := peer.SendMessageWait(&MsgPing{Nonce: 1000})
	if err != ErrSendQueueFull {
		t.Errorf("SendMessageWait error = %v, want ErrSendQueueFull", err)
	}

	peer.Disconnect()
}

// TestRandomUint64 tests the random nonce generator.
func TestRandomUint64(t *testing.T) {
	seen := make(map[uint64]bool)
	for i := 0; i < 100; i++ {
		n, err := randomUint64()
		if err != nil {
			t.Fatalf("randomUint64 failed: %v", err)
		}
		if seen[n] {
			t.Errorf("duplicate nonce: %d", n)
		}
		seen[n] = true
	}
}

// TestPeerStateString tests the PeerState String method.
func TestPeerStateString(t *testing.T) {
	tests := []struct {
		state PeerState
		want  string
	}{
		{PeerStateDisconnected, "disconnected"},
		{PeerStateConnecting, "connecting"},
		{PeerStateHandshaking, "handshaking"},
		{PeerStateConnected, "connected"},
		{PeerStateBanned, "banned"},
		{PeerState(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.want {
			t.Errorf("PeerState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

// TestFeeFilterReceived tests receiving feefilter messages from peers.
func TestFeeFilterReceived(t *testing.T) {
	tests := []struct {
		name       string
		filterRate int64
		wantStored int64
	}{
		{"zero filter", 0, 0},
		{"1 sat/vB", 1000, 1000},
		{"10 sat/vB", 10000, 10000},
		{"high fee", 1_000_000, 1_000_000},
		{"negative (invalid)", -100, 0}, // Should be ignored
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := &Peer{}
			msg := &MsgFeeFilter{MinFeeRate: tt.filterRate}
			peer.handleFeeFilter(msg)

			got := peer.FeeFilterReceived()
			if got != tt.wantStored {
				t.Errorf("FeeFilterReceived() = %d, want %d", got, tt.wantStored)
			}
		})
	}
}

// TestFeeFilterValidation tests that invalid feefilter values are rejected.
func TestFeeFilterValidation(t *testing.T) {
	peer := &Peer{}

	// Set a valid value first
	peer.handleFeeFilter(&MsgFeeFilter{MinFeeRate: 1000})
	if got := peer.FeeFilterReceived(); got != 1000 {
		t.Fatalf("initial feefilter = %d, want 1000", got)
	}

	// Try to set an invalid value (exceeds max money)
	const maxMoney = 21_000_000 * 100_000_000
	peer.handleFeeFilter(&MsgFeeFilter{MinFeeRate: maxMoney + 1})

	// Should remain unchanged
	if got := peer.FeeFilterReceived(); got != 1000 {
		t.Errorf("feefilter after invalid update = %d, want 1000 (unchanged)", got)
	}
}

// TestShouldRelayTx tests the transaction relay filtering based on feefilter.
func TestShouldRelayTx(t *testing.T) {
	tests := []struct {
		name       string
		filterRate int64 // peer's feefilter in sat/kvB
		fee        int64 // tx fee in satoshis
		vsize      int64 // tx vsize in vbytes
		wantRelay  bool
	}{
		{"no filter", 0, 1000, 100, true},            // Any tx passes with no filter
		{"no filter zero fee", 0, 0, 100, true},      // Even zero fee passes with no filter
		{"exact threshold", 1000, 100, 100, true},    // 100 sat / 100 vB = 1 sat/vB = 1000 sat/kvB
		{"above threshold", 1000, 200, 100, true},    // 200 sat / 100 vB = 2 sat/vB
		{"below threshold", 1000, 50, 100, false},    // 50 sat / 100 vB = 0.5 sat/vB < 1 sat/vB
		{"high filter", 10000, 500, 100, false},      // 500 sat / 100 vB = 5 sat/vB < 10 sat/vB
		{"high filter pass", 10000, 1000, 100, true}, // 1000 sat / 100 vB = 10 sat/vB
		{"large tx below", 1000, 100, 200, false},    // 100 sat / 200 vB = 0.5 sat/vB < 1 sat/vB
		{"large tx above", 1000, 250, 200, true},     // 250 sat / 200 vB = 1.25 sat/vB > 1 sat/vB
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := &Peer{}
			atomic.StoreInt64(&peer.feeFilterReceived, tt.filterRate)

			got := peer.ShouldRelayTx(tt.fee, tt.vsize)
			if got != tt.wantRelay {
				t.Errorf("ShouldRelayTx(fee=%d, vsize=%d) with filter=%d = %v, want %v",
					tt.fee, tt.vsize, tt.filterRate, got, tt.wantRelay)
			}
		})
	}
}

// TestFeeFilterConstants verifies the BIP133 constants.
func TestFeeFilterConstants(t *testing.T) {
	if FeeFilterVersion != 70013 {
		t.Errorf("FeeFilterVersion = %d, want 70013", FeeFilterVersion)
	}

	if FeeFilterBroadcastInterval != 10*time.Minute {
		t.Errorf("FeeFilterBroadcastInterval = %v, want 10m", FeeFilterBroadcastInterval)
	}

	if FeeFilterMaxChangeDelay != 5*time.Minute {
		t.Errorf("FeeFilterMaxChangeDelay = %v, want 5m", FeeFilterMaxChangeDelay)
	}
}

// TestPeerSyncedHeightsDefaultUnset pins Core's nSyncHeight / nCommonHeight
// sentinel: a peer that has not announced a header we have, and has not
// delivered a block body, reports -1 — including a zero-value Peer, and
// including after VERSION (startHeight is not pindexBestKnownBlock).
func TestPeerSyncedHeightsDefaultUnset(t *testing.T) {
	p := NewTestPeer("1.2.3.4:8333", 800000)
	if got := p.SyncedHeaders(); got != -1 {
		t.Errorf("SyncedHeaders() = %d, want -1 before any announcement", got)
	}
	if got := p.SyncedBlocks(); got != -1 {
		t.Errorf("SyncedBlocks() = %d, want -1 before any block body", got)
	}
	if p.StartHeight() != 800000 {
		t.Errorf("StartHeight() = %d, want 800000 (VERSION is independent of synced_*)", p.StartHeight())
	}

	var zero Peer
	if got := zero.SyncedHeaders(); got != -1 {
		t.Errorf("zero Peer SyncedHeaders() = %d, want -1", got)
	}
	if got := zero.SyncedBlocks(); got != -1 {
		t.Errorf("zero Peer SyncedBlocks() = %d, want -1", got)
	}
}

// TestPeerSyncedHeightsMonotonicAndGenesisZero: height 0 is a valid
// measurement (genesis) and must not collapse to the unset sentinel; a
// lower later announcement must not rewind the best-known height.
func TestPeerSyncedHeightsMonotonicAndGenesisZero(t *testing.T) {
	p := NewTestPeer("1.2.3.4:8333", 0)

	p.UpdateSyncedHeaders(0)
	if got := p.SyncedHeaders(); got != 0 {
		t.Errorf("SyncedHeaders after genesis announce = %d, want 0", got)
	}
	if got := p.SyncedBlocks(); got != -1 {
		t.Errorf("SyncedBlocks after header-only = %d, want -1", got)
	}

	p.UpdateSyncedHeaders(50)
	p.UpdateSyncedHeaders(20) // must not rewind
	if got := p.SyncedHeaders(); got != 50 {
		t.Errorf("SyncedHeaders after rewind attempt = %d, want 50", got)
	}

	p.UpdateSyncedBlocks(40)
	if got := p.SyncedBlocks(); got != 40 {
		t.Errorf("SyncedBlocks = %d, want 40", got)
	}
	if got := p.SyncedHeaders(); got != 50 {
		t.Errorf("SyncedHeaders after lower block body = %d, want 50 (headers stay ahead)", got)
	}

	p.UpdateSyncedBlocks(60)
	if got := p.SyncedBlocks(); got != 60 {
		t.Errorf("SyncedBlocks = %d, want 60", got)
	}
	if got := p.SyncedHeaders(); got != 60 {
		t.Errorf("SyncedHeaders after higher block body = %d, want 60 (body implies header)", got)
	}
}
