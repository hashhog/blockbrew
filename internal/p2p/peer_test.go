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
	case <-time.After(5 * time.Second):
		t.Fatal("handshake timed out")
	}

	// Verify state
	if !peer.IsConnected() {
		t.Error("peer should be connected after handshake")
	}

	if peer.State() != PeerStateConnected {
		t.Errorf("state = %v, want %v", peer.State(), PeerStateConnected)
	}

	// Clean up
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
	case <-time.After(5 * time.Second):
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

// mockServerHandshake simulates a Bitcoin node responding to our handshake.
func mockServerHandshake(conn net.Conn, magic uint32) error {
	// 1. Wait for version from client
	msg, err := ReadMessage(conn, magic)
	if err != nil {
		return err
	}
	if _, ok := msg.(*MsgVersion); !ok {
		return ErrHandshakeFailed
	}

	// 2. Send our version
	version := &MsgVersion{
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork | ServiceNodeWitness,
		Timestamp:       time.Now().Unix(),
		AddrRecv:        NetAddress{},
		AddrFrom:        NetAddress{},
		Nonce:           87654321, // Different nonce
		UserAgent:       "/mocknode:0.1.0/",
		StartHeight:     800001,
		Relay:           true,
	}
	if err := WriteMessage(conn, magic, version); err != nil {
		return err
	}

	// 3. Send verack
	if err := WriteMessage(conn, magic, &MsgVerAck{}); err != nil {
		return err
	}

	// 4. Read remaining messages (verack, sendheaders, etc.) until connection closes
	// The peer may close the connection at any time after handshake
	for {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := ReadMessage(conn, magic)
		if err != nil {
			// Expected EOF when peer disconnects
			return nil
		}
	}
}

// mockClientHandshake simulates an outbound client initiating handshake with us.
func mockClientHandshake(conn net.Conn, magic uint32) error {
	// 1. Send version (client initiates)
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
	if err := WriteMessage(conn, magic, version); err != nil {
		return err
	}

	// 2. Read messages until we get both version and verack (order may vary)
	gotVersion := false
	gotVerack := false
	for !gotVersion || !gotVerack {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		msg, err := ReadMessage(conn, magic)
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

	// 3. Send verack
	if err := WriteMessage(conn, magic, &MsgVerAck{}); err != nil {
		return err
	}

	// 4. Read any additional messages until connection closes
	for {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := ReadMessage(conn, magic)
		if err != nil {
			return nil
		}
	}
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
		for {
			serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			msg, err := ReadMessage(serverConn, config.Network)
			if err != nil {
				return
			}
			if ping, ok := msg.(*MsgPing); ok {
				// Respond with pong (same nonce)
				pong := &MsgPong{Nonce: ping.Nonce}
				WriteMessage(serverConn, config.Network, pong)
			}
		}
	}()

	// Send a ping and wait for latency measurement
	testNonce := uint64(0xDEADBEEF)
	peer.mu.Lock()
	peer.lastPingNonce = testNonce
	peer.lastPingTime = time.Now()
	peer.mu.Unlock()

	peer.SendMessage(&MsgPing{Nonce: testNonce})

	// Wait for pong to be processed
	time.Sleep(100 * time.Millisecond)

	// Check that latency was measured
	latency := peer.PingLatency()
	if latency == 0 {
		t.Error("ping latency should be measured after pong received")
	}
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
	case <-time.After(2 * time.Second):
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
	go func() {
		version := &MsgVersion{
			ProtocolVersion: ProtocolVersion,
			Services:        ServiceNodeNetwork,
			Timestamp:       time.Now().Unix(),
			Nonce:           ourNonce, // Same as our nonce!
			UserAgent:       "/blockbrew:0.1.0/",
			StartHeight:     800000,
			Relay:           true,
		}
		WriteMessage(serverConn, config.Network, version)
	}()

	// Wait a bit for the peer to detect and disconnect
	time.Sleep(200 * time.Millisecond)

	// Peer should have disconnected
	if peer.State() != PeerStateDisconnected {
		t.Errorf("peer should disconnect on self-connection, state = %v", peer.State())
	}

	peer.Disconnect() // Ensure cleanup
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
		// Read our version
		ReadMessage(serverConn, config.Network)

		// Send version with older protocol
		version := &MsgVersion{
			ProtocolVersion: 70015, // Older version
			Services:        ServiceNodeNetwork,
			Timestamp:       time.Now().Unix(),
			Nonce:           87654321,
			UserAgent:       "/oldnode:0.1.0/",
			StartHeight:     800000,
			Relay:           true,
		}
		WriteMessage(serverConn, config.Network, version)
		WriteMessage(serverConn, config.Network, &MsgVerAck{})

		// Read verack and any other messages
		for {
			serverConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, err := ReadMessage(serverConn, config.Network)
			if err != nil {
				return
			}
		}
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
	case <-time.After(5 * time.Second):
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
		// Send ping
		WriteMessage(serverConn, config.Network, &MsgPing{Nonce: 123})
		// Read the pong response
		serverConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadMessage(serverConn, config.Network)
		// Send pong
		WriteMessage(serverConn, config.Network, &MsgPong{Nonce: 456})
		// Keep reading until closed
		for {
			serverConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, err := ReadMessage(serverConn, config.Network)
			if err != nil {
				return
			}
		}
	}()

	// Wait for messages to be processed
	time.Sleep(200 * time.Millisecond)

	if !pingReceived.Load() {
		t.Error("OnPing listener was not called")
	}
	if !pongReceived.Load() {
		t.Error("OnPong listener was not called")
	}

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
		{"no filter", 0, 1000, 100, true},          // Any tx passes with no filter
		{"no filter zero fee", 0, 0, 100, true},    // Even zero fee passes with no filter
		{"exact threshold", 1000, 100, 100, true},  // 100 sat / 100 vB = 1 sat/vB = 1000 sat/kvB
		{"above threshold", 1000, 200, 100, true},  // 200 sat / 100 vB = 2 sat/vB
		{"below threshold", 1000, 50, 100, false},  // 50 sat / 100 vB = 0.5 sat/vB < 1 sat/vB
		{"high filter", 10000, 500, 100, false},    // 500 sat / 100 vB = 5 sat/vB < 10 sat/vB
		{"high filter pass", 10000, 1000, 100, true}, // 1000 sat / 100 vB = 10 sat/vB
		{"large tx below", 1000, 100, 200, false},  // 100 sat / 200 vB = 0.5 sat/vB < 1 sat/vB
		{"large tx above", 1000, 250, 200, true},   // 250 sat / 200 vB = 1.25 sat/vB > 1 sat/vB
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
