package p2p

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Connection timeouts.
const (
	ConnectTimeout   = 30 * time.Second
	HandshakeTimeout = 60 * time.Second
	IdleTimeout      = 5 * time.Minute
	PingInterval     = 2 * time.Minute
	PingTimeout      = 30 * time.Second
	SendQueueSize    = 50
)

// Errors for peer connections.
var (
	ErrPeerDisconnected = errors.New("peer disconnected")
	ErrHandshakeFailed  = errors.New("handshake failed")
	ErrSelfConnection   = errors.New("self connection detected")
	ErrSendQueueFull    = errors.New("send queue full")
)

// PeerConfig configures a new peer connection.
type PeerConfig struct {
	Network         uint32         // Network magic
	ProtocolVersion int32          // Our protocol version (70016)
	Services        uint64         // Our service flags
	UserAgent       string         // Our user agent string
	BestHeight      int32          // Our best block height
	DisableRelayTx  bool           // Whether to disable tx relay
	Listeners       *PeerListeners // Callbacks for received messages
}

// PeerListeners contains callbacks invoked when messages are received.
type PeerListeners struct {
	OnVersion     func(p *Peer, msg *MsgVersion)
	OnVerAck      func(p *Peer, msg *MsgVerAck)
	OnInv         func(p *Peer, msg *MsgInv)
	OnHeaders     func(p *Peer, msg *MsgHeaders)
	OnBlock       func(p *Peer, msg *MsgBlock)
	OnTx          func(p *Peer, msg *MsgTx)
	OnPing        func(p *Peer, msg *MsgPing)
	OnPong        func(p *Peer, msg *MsgPong)
	OnAddr        func(p *Peer, msg *MsgAddr)
	OnGetData     func(p *Peer, msg *MsgGetData)
	OnGetHeaders  func(p *Peer, msg *MsgGetHeaders)
	OnNotFound    func(p *Peer, msg *MsgNotFound)
	OnFeeFilter   func(p *Peer, msg *MsgFeeFilter)
	OnSendHeaders func(p *Peer, msg *MsgSendHeaders)
}

// PeerState represents the connection state.
type PeerState int

const (
	PeerStateDisconnected PeerState = iota
	PeerStateConnecting
	PeerStateHandshaking
	PeerStateConnected
	PeerStateBanned
)

// String returns a human-readable state name.
func (s PeerState) String() string {
	switch s {
	case PeerStateDisconnected:
		return "disconnected"
	case PeerStateConnecting:
		return "connecting"
	case PeerStateHandshaking:
		return "handshaking"
	case PeerStateConnected:
		return "connected"
	case PeerStateBanned:
		return "banned"
	default:
		return "unknown"
	}
}

// Peer represents a connection to a remote Bitcoin node.
type Peer struct {
	config        PeerConfig
	conn          net.Conn
	addr          string // "host:port"
	state         PeerState
	mu            sync.RWMutex
	inbound       bool         // Whether this is an inbound connection
	versionSent   bool
	versionRecvd  bool
	verAckRecvd   bool
	peerVersion   *MsgVersion // Received version message
	sendQueue     chan Message // Outbound message queue
	quit          chan struct{} // Signal to stop goroutines
	quitOnce      sync.Once    // Ensure quit is closed only once
	wg            sync.WaitGroup // Wait for goroutines to finish
	lastRecv      time.Time
	lastSend      time.Time
	lastPingNonce uint64
	lastPingTime  time.Time
	pingLatency   time.Duration
	startTime     time.Time
	bytesSent     uint64
	bytesRecvd    uint64

	// Our local nonce for self-connection detection
	localNonce uint64

	// Protocol negotiation results
	sendHeadersPreferred bool // Peer prefers headers announcements (BIP130)
	wtxidRelaySupported  bool // Peer supports wtxid-based relay (BIP339)

	// Handshake completion signal
	handshakeDone chan struct{}
}

// NewOutboundPeer creates a new outbound peer and initiates the TCP connection.
func NewOutboundPeer(addr string, config PeerConfig) (*Peer, error) {
	// Generate our local nonce for self-connection detection
	localNonce, err := randomUint64()
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	p := &Peer{
		config:        config,
		addr:          addr,
		state:         PeerStateConnecting,
		inbound:       false,
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		localNonce:    localNonce,
		handshakeDone: make(chan struct{}),
	}

	// Connect with timeout
	conn, err := net.DialTimeout("tcp", addr, ConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}

	p.conn = conn
	p.setupConn()

	return p, nil
}

// NewInboundPeer wraps an already-accepted TCP connection as an inbound peer.
func NewInboundPeer(conn net.Conn, config PeerConfig) *Peer {
	// Generate our local nonce for self-connection detection
	localNonce, _ := randomUint64()

	p := &Peer{
		config:        config,
		conn:          conn,
		addr:          conn.RemoteAddr().String(),
		state:         PeerStateHandshaking,
		inbound:       true,
		sendQueue:     make(chan Message, SendQueueSize),
		quit:          make(chan struct{}),
		localNonce:    localNonce,
		handshakeDone: make(chan struct{}),
	}

	p.setupConn()

	return p
}

// setupConn configures TCP keepalive on the connection.
func (p *Peer) setupConn() {
	if tcpConn, ok := p.conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	p.startTime = time.Now()
	p.lastRecv = time.Now()
	p.lastSend = time.Now()
}

// Start begins the peer's read/write goroutines and initiates the handshake.
func (p *Peer) Start() error {
	p.mu.Lock()
	p.state = PeerStateHandshaking
	p.mu.Unlock()

	// Start goroutines
	p.wg.Add(2)
	go p.readHandler()
	go p.writeHandler()

	// For outbound connections, we initiate the handshake
	if !p.inbound {
		if err := p.sendVersionMessage(); err != nil {
			p.Disconnect()
			return fmt.Errorf("send version: %w", err)
		}
	}

	// Wait for handshake with timeout
	select {
	case <-p.handshakeDone:
		// Handshake completed successfully
		return nil
	case <-time.After(HandshakeTimeout):
		p.Disconnect()
		return ErrHandshakeFailed
	case <-p.quit:
		return ErrPeerDisconnected
	}
}

// sendVersionMessage constructs and queues our version message.
func (p *Peer) sendVersionMessage() error {
	// Build the version message
	msg := &MsgVersion{
		ProtocolVersion: p.config.ProtocolVersion,
		Services:        p.config.Services,
		Timestamp:       time.Now().Unix(),
		AddrRecv:        p.remoteNetAddress(),
		AddrFrom:        p.localNetAddress(),
		Nonce:           p.localNonce,
		UserAgent:       p.config.UserAgent,
		StartHeight:     p.config.BestHeight,
		Relay:           !p.config.DisableRelayTx,
	}

	p.mu.Lock()
	p.versionSent = true
	p.mu.Unlock()

	p.SendMessage(msg)
	return nil
}

// remoteNetAddress returns the NetAddress for the remote peer.
func (p *Peer) remoteNetAddress() NetAddress {
	addr, err := net.ResolveTCPAddr("tcp", p.addr)
	if err != nil {
		return NetAddress{}
	}
	return *NewNetAddress(addr, 0)
}

// localNetAddress returns our local NetAddress (placeholder since we don't know our external IP).
func (p *Peer) localNetAddress() NetAddress {
	return NetAddress{
		Services: p.config.Services,
		IP:       net.IPv4zero.To16(),
		Port:     0,
	}
}

// readHandler reads messages from the TCP connection in a loop.
func (p *Peer) readHandler() {
	defer p.wg.Done()
	defer p.signalDisconnect()
	for {
		// Check if we should stop
		select {
		case <-p.quit:
			return
		default:
		}

		// Set read deadline to detect dead connections
		p.conn.SetReadDeadline(time.Now().Add(IdleTimeout))

		msg, err := ReadMessage(p.conn, p.config.Network)
		if err != nil {
			// Connection closed or read error
			return
		}

		p.mu.Lock()
		p.lastRecv = time.Now()
		p.mu.Unlock()

		// Track bytes received (approximate)
		atomic.AddUint64(&p.bytesRecvd, uint64(len(msg.Command())+24)) // header + command overhead

		p.handleMessage(msg)
	}
}

// writeHandler reads from the sendQueue channel and writes to TCP.
func (p *Peer) writeHandler() {
	defer p.wg.Done()
	defer p.signalDisconnect()
	for {
		select {
		case msg := <-p.sendQueue:
			// Set write deadline
			p.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

			err := WriteMessage(p.conn, p.config.Network, msg)
			if err != nil {
				return
			}

			p.mu.Lock()
			p.lastSend = time.Now()
			p.mu.Unlock()

			// Track bytes sent (approximate)
			atomic.AddUint64(&p.bytesSent, uint64(len(msg.Command())+24))

		case <-p.quit:
			return
		}
	}
}

// pingHandler sends periodic pings to keep the connection alive.
func (p *Peer) pingHandler() {
	defer p.wg.Done()
	ticker := time.NewTicker(PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			nonce, err := randomUint64()
			if err != nil {
				continue
			}

			p.mu.Lock()
			p.lastPingNonce = nonce
			p.lastPingTime = time.Now()
			p.mu.Unlock()

			p.SendMessage(&MsgPing{Nonce: nonce})

		case <-p.quit:
			return
		}
	}
}

// handleMessage dispatches received messages to the appropriate handler.
func (p *Peer) handleMessage(msg Message) {
	switch m := msg.(type) {
	case *MsgVersion:
		p.handleVersion(m)
	case *MsgVerAck:
		p.handleVerAck(m)
	case *MsgPing:
		// Respond with pong immediately
		p.SendMessage(&MsgPong{Nonce: m.Nonce})
		if p.config.Listeners != nil && p.config.Listeners.OnPing != nil {
			p.config.Listeners.OnPing(p, m)
		}
	case *MsgPong:
		p.handlePong(m)
	case *MsgSendHeaders:
		p.mu.Lock()
		p.sendHeadersPreferred = true
		p.mu.Unlock()
		if p.config.Listeners != nil && p.config.Listeners.OnSendHeaders != nil {
			p.config.Listeners.OnSendHeaders(p, m)
		}
	case *MsgInv:
		if p.config.Listeners != nil && p.config.Listeners.OnInv != nil {
			p.config.Listeners.OnInv(p, m)
		}
	case *MsgHeaders:
		if p.config.Listeners != nil && p.config.Listeners.OnHeaders != nil {
			p.config.Listeners.OnHeaders(p, m)
		}
	case *MsgBlock:
		if p.config.Listeners != nil && p.config.Listeners.OnBlock != nil {
			p.config.Listeners.OnBlock(p, m)
		}
	case *MsgTx:
		if p.config.Listeners != nil && p.config.Listeners.OnTx != nil {
			p.config.Listeners.OnTx(p, m)
		}
	case *MsgAddr:
		if p.config.Listeners != nil && p.config.Listeners.OnAddr != nil {
			p.config.Listeners.OnAddr(p, m)
		}
	case *MsgGetData:
		if p.config.Listeners != nil && p.config.Listeners.OnGetData != nil {
			p.config.Listeners.OnGetData(p, m)
		}
	case *MsgGetHeaders:
		if p.config.Listeners != nil && p.config.Listeners.OnGetHeaders != nil {
			p.config.Listeners.OnGetHeaders(p, m)
		}
	case *MsgNotFound:
		if p.config.Listeners != nil && p.config.Listeners.OnNotFound != nil {
			p.config.Listeners.OnNotFound(p, m)
		}
	case *MsgFeeFilter:
		if p.config.Listeners != nil && p.config.Listeners.OnFeeFilter != nil {
			p.config.Listeners.OnFeeFilter(p, m)
		}
	case *MsgWTxidRelay:
		p.mu.Lock()
		p.wtxidRelaySupported = true
		p.mu.Unlock()
	case *MsgSendCmpct:
		// Record compact block preferences (handled in BIP152 negotiation)
	}
}

// handleVersion processes a received version message.
func (p *Peer) handleVersion(msg *MsgVersion) {
	// Check for self-connection
	p.mu.Lock()
	if msg.Nonce == p.localNonce {
		p.mu.Unlock()
		p.signalDisconnect()
		return
	}

	// Store the peer's version info
	p.peerVersion = msg
	p.versionRecvd = true
	inbound := p.inbound
	versionSent := p.versionSent
	listeners := p.config.Listeners
	p.mu.Unlock()

	// Call listener if set
	if listeners != nil && listeners.OnVersion != nil {
		listeners.OnVersion(p, msg)
	}

	// For inbound connections, send our version after receiving theirs
	if inbound && !versionSent {
		p.sendVersionMessage()
	}

	// Send wtxidrelay (BIP339) before verack if peer supports protocol >= 70016
	if msg.ProtocolVersion >= 70016 {
		p.SendMessage(&MsgWTxidRelay{})
	}

	// Send verack
	p.SendMessage(&MsgVerAck{})

	// Check if handshake is complete
	p.checkHandshakeComplete()
}

// handleVerAck processes a received verack message.
func (p *Peer) handleVerAck(msg *MsgVerAck) {
	p.mu.Lock()
	p.verAckRecvd = true
	listeners := p.config.Listeners
	p.mu.Unlock()

	// Call listener if set
	if listeners != nil && listeners.OnVerAck != nil {
		listeners.OnVerAck(p, msg)
	}

	// Check if handshake is complete
	p.checkHandshakeComplete()
}

// checkHandshakeComplete checks if the handshake is done and transitions state.
func (p *Peer) checkHandshakeComplete() {
	p.mu.Lock()
	if !p.versionSent || !p.versionRecvd || !p.verAckRecvd || p.state != PeerStateHandshaking {
		p.mu.Unlock()
		return
	}

	p.state = PeerStateConnected
	p.mu.Unlock()

	// Signal handshake completion (only once)
	select {
	case <-p.handshakeDone:
		// Already closed
	default:
		close(p.handshakeDone)
	}

	// Start ping handler now that we're connected
	p.wg.Add(1)
	go p.pingHandler()

	// Send sendheaders (BIP130) to request header announcements
	p.SendMessage(&MsgSendHeaders{})
}

// handlePong processes a received pong message.
func (p *Peer) handlePong(msg *MsgPong) {
	p.mu.Lock()
	// Check if the nonce matches our last ping
	if msg.Nonce == p.lastPingNonce && p.lastPingNonce != 0 {
		p.pingLatency = time.Since(p.lastPingTime)
		p.lastPingNonce = 0 // Reset to avoid double-counting
	}
	listeners := p.config.Listeners
	p.mu.Unlock()

	if listeners != nil && listeners.OnPong != nil {
		listeners.OnPong(p, msg)
	}
}

// signalDisconnect is called by handlers when they exit due to errors.
// It triggers the disconnect process without waiting.
func (p *Peer) signalDisconnect() {
	p.quitOnce.Do(func() {
		p.mu.Lock()
		p.state = PeerStateDisconnected
		p.mu.Unlock()

		// Close quit channel to signal other goroutines
		close(p.quit)

		// Close the connection - this will unblock any pending reads
		if p.conn != nil {
			p.conn.Close()
		}
	})
}

// Disconnect gracefully shuts down the peer connection and waits for cleanup.
func (p *Peer) Disconnect() {
	p.signalDisconnect()
	p.wg.Wait()
}

// SendMessage queues a message for sending.
func (p *Peer) SendMessage(msg Message) {
	select {
	case p.sendQueue <- msg:
		// Message queued successfully
	case <-p.quit:
		// Peer is disconnecting
	default:
		// Queue is full - drop message (could log this)
	}
}

// SendMessageWait queues a message and waits briefly for it to be sent.
// Returns error if the queue is full.
func (p *Peer) SendMessageWait(msg Message) error {
	select {
	case p.sendQueue <- msg:
		return nil
	case <-p.quit:
		return ErrPeerDisconnected
	case <-time.After(100 * time.Millisecond):
		return ErrSendQueueFull
	}
}

// Address returns the peer's remote address.
func (p *Peer) Address() string {
	return p.addr
}

// ProtocolVersion returns the negotiated protocol version.
func (p *Peer) ProtocolVersion() int32 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.peerVersion == nil {
		return 0
	}

	// Negotiated version is the minimum of our version and peer's version
	peerVer := p.peerVersion.ProtocolVersion
	ourVer := p.config.ProtocolVersion
	if peerVer < ourVer {
		return peerVer
	}
	return ourVer
}

// Services returns the peer's advertised services.
func (p *Peer) Services() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.peerVersion == nil {
		return 0
	}
	return p.peerVersion.Services
}

// StartHeight returns the peer's advertised best height.
func (p *Peer) StartHeight() int32 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.peerVersion == nil {
		return 0
	}
	return p.peerVersion.StartHeight
}

// IsConnected returns true if the handshake is complete and the peer is live.
func (p *Peer) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state == PeerStateConnected
}

// State returns the current peer state.
func (p *Peer) State() PeerState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// PingLatency returns the measured ping latency.
func (p *Peer) PingLatency() time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.pingLatency
}

// UserAgent returns the peer's user agent string.
func (p *Peer) UserAgent() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.peerVersion == nil {
		return ""
	}
	return p.peerVersion.UserAgent
}

// Inbound returns true if this is an inbound connection.
func (p *Peer) Inbound() bool {
	return p.inbound
}

// LastRecv returns the time of the last received message.
func (p *Peer) LastRecv() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastRecv
}

// LastSend returns the time of the last sent message.
func (p *Peer) LastSend() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastSend
}

// BytesSent returns the total bytes sent.
func (p *Peer) BytesSent() uint64 {
	return atomic.LoadUint64(&p.bytesSent)
}

// BytesRecvd returns the total bytes received.
func (p *Peer) BytesRecvd() uint64 {
	return atomic.LoadUint64(&p.bytesRecvd)
}

// ConnTime returns how long the peer has been connected.
func (p *Peer) ConnTime() time.Duration {
	return time.Since(p.startTime)
}

// SendsHeaders returns true if the peer prefers header announcements (BIP130).
func (p *Peer) SendsHeaders() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sendHeadersPreferred
}

// WTxidRelay returns true if the peer supports wtxid-based relay (BIP339).
func (p *Peer) WTxidRelay() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.wtxidRelaySupported
}

// randomUint64 generates a cryptographically random uint64.
func randomUint64() (uint64, error) {
	var buf [8]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}
