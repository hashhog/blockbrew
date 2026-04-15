package p2p

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
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

// BIP133 feefilter constants.
const (
	// FeeFilterBroadcastInterval is the average interval between feefilter broadcasts.
	// Bitcoin Core uses 10 minutes on average.
	FeeFilterBroadcastInterval = 10 * time.Minute

	// FeeFilterMaxChangeDelay is the maximum delay when feefilter changes significantly.
	// If the filter changes by >33% we reschedule to within this window.
	FeeFilterMaxChangeDelay = 5 * time.Minute

	// FeeFilterVersion is the minimum protocol version for feefilter support.
	// BIP133 was activated with protocol version 70013.
	FeeFilterVersion = 70013
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
	PreferV2        bool           // Whether to prefer BIP324 v2 transport
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
	// BIP152 compact block callbacks
	OnSendCmpct   func(p *Peer, msg *MsgSendCmpct)
	OnCmpctBlock  func(p *Peer, msg *MsgCmpctBlock)
	OnGetBlockTxn func(p *Peer, msg *MsgGetBlockTxn)
	OnBlockTxn    func(p *Peer, msg *MsgBlockTxn)
	// BIP155 ADDRv2 callbacks
	OnSendAddrv2 func(p *Peer, msg *MsgSendAddrv2)
	OnAddrv2     func(p *Peer, msg *MsgAddrv2)
	// BIP330 Erlay callbacks
	OnSendTxRcncl  func(p *Peer, msg *MsgSendTxRcncl)
	OnReqReconcil  func(p *Peer, msg *MsgReqReconcil)
	OnSketch       func(p *Peer, msg *MsgSketch)
	OnReconcilDiff func(p *Peer, msg *MsgReconcilDiff)
	// BIP37 bloom filter callbacks
	OnFilterLoad  func(p *Peer, msg *MsgFilterLoad)
	OnFilterAdd   func(p *Peer, msg *MsgFilterAdd)
	OnFilterClear func(p *Peer, msg *MsgFilterClear)
	OnMerkleBlock func(p *Peer, msg *MsgMerkleBlock)
	// BIP157/158 compact block filter callbacks
	OnGetCFilters  func(p *Peer, msg *MsgGetCFilters)
	OnCFilter      func(p *Peer, msg *MsgCFilter)
	OnGetCFHeaders func(p *Peer, msg *MsgGetCFHeaders)
	OnCFHeaders    func(p *Peer, msg *MsgCFHeaders)
	OnGetCFCheckpt func(p *Peer, msg *MsgGetCFCheckpt)
	OnCFCheckpt    func(p *Peer, msg *MsgCFCheckpt)
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

// Misbehavior score threshold — at this score, peer is disconnected and banned.
const MisbehaviorThreshold = 100

// Misbehavior score values for specific infractions.
const (
	ScoreInvalidBlock          = 100 // Instant ban
	ScoreHeadersDontConnect    = 20  // Headers that don't connect to our chain
	ScoreHeadersDontConnectIBD = 10  // IBD-time soft penalty for transient header errors (W15)
	ScoreBlockDownloadStall    = 50  // Stalling block download
	ScoreUnrequestedData       = 5   // Sending unrequested data
)

// Peer represents a connection to a remote Bitcoin node.
type Peer struct {
	config        PeerConfig
	conn          net.Conn
	transport     Transport    // v1 or v2 transport layer
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
	v2Transport          bool // Whether using BIP324 v2 transport
	wantsAddrv2          bool // Peer supports BIP155 ADDRv2 messages

	// BIP152 compact block state
	compactBlockState *CompactBlockState

	// BIP330 Erlay state
	erlaySupported    bool   // Peer supports Erlay (received sendtxrcncl)
	erlaySalt         uint64 // Peer's Erlay salt from sendtxrcncl
	erlayVersion      uint32 // Peer's Erlay protocol version
	erlaySentTxRcncl  bool   // Whether we sent sendtxrcncl to peer

	// BIP133 feefilter state
	feeFilterReceived int64         // Peer's minimum fee rate (sat/kvB), atomic
	feeFilterSent     int64         // Last fee filter we sent to peer (sat/kvB)
	nextFeeFilterTime time.Time     // When to next send feefilter
	feeFilterMu       sync.Mutex    // Protects feefilter state

	// Handshake completion signal
	handshakeDone chan struct{}

	// Misbehavior tracking
	misbehaviorScore int           // Accumulated misbehavior score
	shouldBan        bool          // Set to true when threshold reached
	banCallback      func(*Peer)   // Called when peer should be banned
}

// NewOutboundPeer creates a new outbound peer and initiates the TCP connection.
func NewOutboundPeer(addr string, config PeerConfig) (*Peer, error) {
	// Generate our local nonce for self-connection detection
	localNonce, err := randomUint64()
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	p := &Peer{
		config:            config,
		addr:              addr,
		state:             PeerStateConnecting,
		inbound:           false,
		sendQueue:         make(chan Message, SendQueueSize),
		quit:              make(chan struct{}),
		localNonce:        localNonce,
		handshakeDone:     make(chan struct{}),
		compactBlockState: NewCompactBlockState(),
	}

	// Connect with timeout
	conn, err := net.DialTimeout("tcp", addr, ConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}

	p.conn = conn
	p.setupConn()

	// Negotiate transport (v1 or v2)
	if config.PreferV2 {
		transport, err := NegotiateTransport(conn, config.Network, true, true)
		if err != nil {
			// Fall back to v1 on error
			log.Printf("v2 transport negotiation failed, using v1: %v", err)
			p.transport = NewV1Transport(conn, config.Network)
		} else {
			p.transport = transport
			p.v2Transport = transport.IsEncrypted()
		}
	} else {
		p.transport = NewV1Transport(conn, config.Network)
	}

	return p, nil
}

// NewInboundPeer wraps an already-accepted TCP connection as an inbound peer.
func NewInboundPeer(conn net.Conn, config PeerConfig) *Peer {
	// Generate our local nonce for self-connection detection
	localNonce, _ := randomUint64()

	p := &Peer{
		config:            config,
		conn:              conn,
		addr:              conn.RemoteAddr().String(),
		state:             PeerStateHandshaking,
		inbound:           true,
		sendQueue:         make(chan Message, SendQueueSize),
		quit:              make(chan struct{}),
		localNonce:        localNonce,
		handshakeDone:     make(chan struct{}),
		compactBlockState: NewCompactBlockState(),
	}

	p.setupConn()

	// For inbound, we'll negotiate transport during Start() since we need to
	// detect whether the peer is using v1 or v2 based on first bytes.
	// For now, default to v1 - the actual negotiation happens in Start().
	p.transport = NewV1Transport(conn, config.Network)

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
		p.transport.SetReadDeadline(time.Now().Add(IdleTimeout))

		msg, err := p.transport.ReadMessage()
		if err != nil {
			// Non-fatal errors (e.g., failed addrv2 deserialization) should not
			// kill the connection. The payload was fully consumed and checksum-
			// verified, so the TCP stream remains valid.
			if IsNonFatalMessageError(err) {
				log.Printf("peer %s: skipping bad message: %v", p.addr, err)
				continue
			}
			// Fatal errors (IO errors, bad magic, bad checksum) kill the connection
			log.Printf("peer %s: read error: %v", p.addr, err)
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
	// Check for messages sent before handshake (except version/verack/wtxidrelay/sendcmpct/sendaddrv2/sendtxrcncl)
	switch msg.(type) {
	case *MsgVersion, *MsgVerAck, *MsgWTxidRelay, *MsgSendCmpct, *MsgSendAddrv2, *MsgSendTxRcncl:
		// These are allowed before handshake
	default:
		p.mu.RLock()
		handshaking := p.state == PeerStateHandshaking
		p.mu.RUnlock()
		if handshaking {
			p.Misbehaving(10, "message before handshake complete")
			return
		}
	}

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
		p.handleFeeFilter(m)
		if p.config.Listeners != nil && p.config.Listeners.OnFeeFilter != nil {
			p.config.Listeners.OnFeeFilter(p, m)
		}
	case *MsgWTxidRelay:
		p.mu.Lock()
		p.wtxidRelaySupported = true
		p.mu.Unlock()
	case *MsgSendAddrv2:
		p.handleSendAddrv2(m)
	case *MsgAddrv2:
		if p.config.Listeners != nil && p.config.Listeners.OnAddrv2 != nil {
			p.config.Listeners.OnAddrv2(p, m)
		}
	case *MsgSendCmpct:
		// Record compact block preferences (BIP152)
		if p.compactBlockState != nil {
			p.compactBlockState.SetSendCmpct(m.AnnounceUsingCmpctBlock, m.CmpctBlockVersion)
		}
		if p.config.Listeners != nil && p.config.Listeners.OnSendCmpct != nil {
			p.config.Listeners.OnSendCmpct(p, m)
		}
	case *MsgCmpctBlock:
		// Compact block received
		if p.config.Listeners != nil && p.config.Listeners.OnCmpctBlock != nil {
			p.config.Listeners.OnCmpctBlock(p, m)
		}
	case *MsgGetBlockTxn:
		// Peer requesting missing transactions for compact block
		if p.config.Listeners != nil && p.config.Listeners.OnGetBlockTxn != nil {
			p.config.Listeners.OnGetBlockTxn(p, m)
		}
	case *MsgBlockTxn:
		// Missing transactions received for compact block reconstruction
		if p.config.Listeners != nil && p.config.Listeners.OnBlockTxn != nil {
			p.config.Listeners.OnBlockTxn(p, m)
		}
	// BIP330 Erlay messages
	case *MsgSendTxRcncl:
		p.handleSendTxRcncl(m)
	case *MsgReqReconcil:
		if p.config.Listeners != nil && p.config.Listeners.OnReqReconcil != nil {
			p.config.Listeners.OnReqReconcil(p, m)
		}
	case *MsgSketch:
		if p.config.Listeners != nil && p.config.Listeners.OnSketch != nil {
			p.config.Listeners.OnSketch(p, m)
		}
	case *MsgReconcilDiff:
		if p.config.Listeners != nil && p.config.Listeners.OnReconcilDiff != nil {
			p.config.Listeners.OnReconcilDiff(p, m)
		}
	// BIP37 bloom filter messages — accepted but not actively served
	case *MsgFilterLoad:
		if p.config.Listeners != nil && p.config.Listeners.OnFilterLoad != nil {
			p.config.Listeners.OnFilterLoad(p, m)
		}
	case *MsgFilterAdd:
		if p.config.Listeners != nil && p.config.Listeners.OnFilterAdd != nil {
			p.config.Listeners.OnFilterAdd(p, m)
		}
	case *MsgFilterClear:
		if p.config.Listeners != nil && p.config.Listeners.OnFilterClear != nil {
			p.config.Listeners.OnFilterClear(p, m)
		}
	case *MsgMerkleBlock:
		if p.config.Listeners != nil && p.config.Listeners.OnMerkleBlock != nil {
			p.config.Listeners.OnMerkleBlock(p, m)
		}
	// BIP157/158 compact block filter messages
	case *MsgGetCFilters:
		if p.config.Listeners != nil && p.config.Listeners.OnGetCFilters != nil {
			p.config.Listeners.OnGetCFilters(p, m)
		}
	case *MsgCFilter:
		if p.config.Listeners != nil && p.config.Listeners.OnCFilter != nil {
			p.config.Listeners.OnCFilter(p, m)
		}
	case *MsgGetCFHeaders:
		if p.config.Listeners != nil && p.config.Listeners.OnGetCFHeaders != nil {
			p.config.Listeners.OnGetCFHeaders(p, m)
		}
	case *MsgCFHeaders:
		if p.config.Listeners != nil && p.config.Listeners.OnCFHeaders != nil {
			p.config.Listeners.OnCFHeaders(p, m)
		}
	case *MsgGetCFCheckpt:
		if p.config.Listeners != nil && p.config.Listeners.OnGetCFCheckpt != nil {
			p.config.Listeners.OnGetCFCheckpt(p, m)
		}
	case *MsgCFCheckpt:
		if p.config.Listeners != nil && p.config.Listeners.OnCFCheckpt != nil {
			p.config.Listeners.OnCFCheckpt(p, m)
		}
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

	// Send feature negotiation messages before verack if peer supports protocol >= 70016
	if msg.ProtocolVersion >= 70016 {
		p.SendMessage(&MsgWTxidRelay{})
		// BIP155: Signal ADDRv2 support
		p.SendMessage(&MsgSendAddrv2{})
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

// handleSendAddrv2 processes a received sendaddrv2 message (BIP155).
// This must be received before verack to enable ADDRv2 support.
func (p *Peer) handleSendAddrv2(msg *MsgSendAddrv2) {
	p.mu.Lock()
	// Only accept sendaddrv2 before handshake complete
	if p.verAckRecvd {
		p.mu.Unlock()
		// BIP155: sendaddrv2 after verack is a protocol violation
		p.Misbehaving(10, "sendaddrv2 received after verack")
		return
	}
	p.wantsAddrv2 = true
	listeners := p.config.Listeners
	p.mu.Unlock()

	// Call listener if set
	if listeners != nil && listeners.OnSendAddrv2 != nil {
		listeners.OnSendAddrv2(p, msg)
	}
}

// handleSendTxRcncl processes a received sendtxrcncl message (BIP330 Erlay).
// This must be received before verack to enable Erlay support.
func (p *Peer) handleSendTxRcncl(msg *MsgSendTxRcncl) {
	p.mu.Lock()
	// Only accept sendtxrcncl before handshake complete
	if p.verAckRecvd {
		p.mu.Unlock()
		// BIP330: sendtxrcncl after verack is a protocol violation
		p.Misbehaving(10, "sendtxrcncl received after verack")
		return
	}

	// Validate version
	if msg.Version < MinReconciliationVersion {
		p.mu.Unlock()
		p.Misbehaving(10, "invalid sendtxrcncl version")
		return
	}

	// Store peer's Erlay info
	p.erlaySupported = true
	p.erlaySalt = msg.Salt
	p.erlayVersion = msg.Version
	listeners := p.config.Listeners
	p.mu.Unlock()

	// Call listener if set
	if listeners != nil && listeners.OnSendTxRcncl != nil {
		listeners.OnSendTxRcncl(p, msg)
	}
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

	// Send sendcmpct (BIP152) to indicate we support compact blocks
	// Version 2 indicates segwit support (wtxid-based short IDs)
	// announce=false means low-bandwidth mode (we'll receive inv/headers first)
	p.SendMessage(&MsgSendCmpct{
		AnnounceUsingCmpctBlock: false,
		CmpctBlockVersion:       CmpctBlockVersion,
	})
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

// handleFeeFilter processes a received feefilter message (BIP133).
// The feefilter message tells us the minimum fee rate the peer will relay.
func (p *Peer) handleFeeFilter(msg *MsgFeeFilter) {
	// Validate the fee filter value (must be within valid money range)
	// Max satoshis is 21M BTC = 2,100,000,000,000,000 satoshis
	const maxMoney = 21_000_000 * 100_000_000
	if msg.MinFeeRate < 0 || msg.MinFeeRate > maxMoney {
		// Invalid value, ignore it
		return
	}

	// Store atomically
	atomic.StoreInt64(&p.feeFilterReceived, msg.MinFeeRate)
}

// FeeFilterReceived returns the peer's minimum fee rate in sat/kvB.
// A value of 0 means no filtering (send all transactions).
func (p *Peer) FeeFilterReceived() int64 {
	return atomic.LoadInt64(&p.feeFilterReceived)
}

// ShouldRelayTx returns true if the transaction should be relayed to this peer
// based on the peer's feefilter setting.
// fee is the transaction fee in satoshis, vsize is the virtual size in vbytes.
func (p *Peer) ShouldRelayTx(fee int64, vsize int64) bool {
	filterRate := atomic.LoadInt64(&p.feeFilterReceived)
	if filterRate == 0 {
		// No filter set, relay everything
		return true
	}

	// Calculate the minimum fee required for this transaction size
	// filterRate is in sat/kvB (satoshis per 1000 virtual bytes)
	minFee := (filterRate * vsize + 999) / 1000 // Round up

	return fee >= minFee
}

// MaybeSendFeeFilter sends a feefilter message to the peer if conditions are met.
// currentMinFee is the current minimum fee rate in sat/kvB that our node requires.
// This should be called periodically (e.g., every time the mempool state changes).
func (p *Peer) MaybeSendFeeFilter(currentMinFee int64) {
	// Don't send feefilter to peers that don't want tx relay
	if !p.WantsTxRelay() {
		return
	}

	// Check if peer supports feefilter (protocol version >= 70013)
	if p.ProtocolVersion() < FeeFilterVersion {
		return
	}

	p.feeFilterMu.Lock()
	defer p.feeFilterMu.Unlock()

	now := time.Now()

	// Check if it's time to send a feefilter
	shouldSend := false

	if now.After(p.nextFeeFilterTime) {
		// Regular broadcast interval elapsed
		shouldSend = true
	} else if currentMinFee != p.feeFilterSent {
		// Check for significant change (>33% increase or <25% decrease)
		// This triggers an early update if the fee environment changed dramatically
		if p.feeFilterSent > 0 {
			// Significant increase: currentMinFee > 4/3 * sent (>33% increase)
			if currentMinFee > (p.feeFilterSent*4)/3 {
				// Check if we're far from next scheduled send
				if now.Add(FeeFilterMaxChangeDelay).Before(p.nextFeeFilterTime) {
					// Reschedule to sooner
					p.nextFeeFilterTime = now.Add(time.Duration(rand.Int63n(int64(FeeFilterMaxChangeDelay))))
				}
			}
			// Significant decrease: currentMinFee < 3/4 * sent (<25% decrease)
			if currentMinFee < (p.feeFilterSent*3)/4 {
				if now.Add(FeeFilterMaxChangeDelay).Before(p.nextFeeFilterTime) {
					p.nextFeeFilterTime = now.Add(time.Duration(rand.Int63n(int64(FeeFilterMaxChangeDelay))))
				}
			}
		}
	}

	if !shouldSend {
		return
	}

	// Add privacy noise: ±10% randomization to prevent fingerprinting
	// (peers cannot determine exact mempool state from our feefilter)
	noisy := currentMinFee
	if currentMinFee > 0 {
		// Add noise in range [-10%, +10%]
		noise := currentMinFee / 10
		if noise > 0 {
			noisy = currentMinFee + rand.Int63n(noise*2) - noise
			if noisy < 0 {
				noisy = 0
			}
		}
	}

	// Send the feefilter message
	p.SendMessage(&MsgFeeFilter{MinFeeRate: noisy})

	// Update state
	p.feeFilterSent = currentMinFee
	// Schedule next send with exponential distribution for timing privacy
	delay := FeeFilterBroadcastInterval + time.Duration(rand.Int63n(int64(FeeFilterBroadcastInterval/2)))
	p.nextFeeFilterTime = now.Add(delay)
}

// SendFeeFilter immediately sends a feefilter message to the peer.
// This is typically called right after handshake completion.
func (p *Peer) SendFeeFilter(minFeeRate int64) {
	if !p.WantsTxRelay() {
		return
	}
	if p.ProtocolVersion() < FeeFilterVersion {
		return
	}

	p.feeFilterMu.Lock()
	defer p.feeFilterMu.Unlock()

	p.SendMessage(&MsgFeeFilter{MinFeeRate: minFeeRate})
	p.feeFilterSent = minFeeRate

	// Schedule next regular update
	delay := FeeFilterBroadcastInterval + time.Duration(rand.Int63n(int64(FeeFilterBroadcastInterval/2)))
	p.nextFeeFilterTime = time.Now().Add(delay)
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

// WantsAddrv2 returns true if the peer supports BIP155 ADDRv2 messages.
func (p *Peer) WantsAddrv2() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.wantsAddrv2
}

// SupportsErlay returns true if the peer supports BIP330 Erlay reconciliation.
func (p *Peer) SupportsErlay() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.erlaySupported
}

// ErlaySalt returns the peer's Erlay salt from sendtxrcncl.
func (p *Peer) ErlaySalt() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.erlaySalt
}

// ErlayVersion returns the peer's Erlay protocol version.
func (p *Peer) ErlayVersion() uint32 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.erlayVersion
}

// ProvidesCompactBlocks returns true if the peer supports BIP152 compact blocks.
func (p *Peer) ProvidesCompactBlocks() bool {
	if p.compactBlockState == nil {
		return false
	}
	return p.compactBlockState.ProvidesCompactBlocks()
}

// WantsHBCompactBlocks returns true if the peer wants high-bandwidth compact blocks.
func (p *Peer) WantsHBCompactBlocks() bool {
	if p.compactBlockState == nil {
		return false
	}
	return p.compactBlockState.WantsHBCompactBlocks()
}

// CompactBlockState returns the peer's compact block state.
func (p *Peer) CompactBlockState() *CompactBlockState {
	return p.compactBlockState
}

// WantsTxRelay returns true if the peer wants to receive transaction announcements.
// This is based on the fRelay flag in the version message and whether we're configured
// to disable tx relay to this peer (block-relay-only connections).
func (p *Peer) WantsTxRelay() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// If we're configured not to relay txs to this peer, respect that
	if p.config.DisableRelayTx {
		return false
	}

	// Check the peer's version message Relay flag
	if p.peerVersion == nil {
		return false
	}
	return p.peerVersion.Relay
}

// SetBanCallback sets the callback invoked when peer exceeds misbehavior threshold.
func (p *Peer) SetBanCallback(cb func(*Peer)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.banCallback = cb
}

// Misbehaving adds a misbehavior score to the peer.
// If the score reaches MisbehaviorThreshold (100), the peer is flagged for disconnect/ban.
// Returns true if the threshold was reached (on this call or a prior one).
//
// W13 fix: once shouldBan is latched, further scoring is a no-op. Previously
// a stalling peer could accumulate score +50 → 450 → 750 → 800+ (visible in
// the pre-freeze log) because checkStaleRequests kept calling Misbehaving on
// the same in-flight block slots before the async ban callback had a chance
// to disconnect. The callback also received a phantom &Peer{addr:addr} so
// handlePeerBan could not observe any per-peer state on the banned peer.
func (p *Peer) Misbehaving(score int, reason string) bool {
	p.mu.Lock()

	if p.shouldBan {
		// Already flagged for ban — stop amplifying the score and don't
		// re-fire the callback. The ban is already in flight.
		p.mu.Unlock()
		return true
	}

	p.misbehaviorScore += score
	log.Printf("peer %s misbehaving (%+d → %d): %s",
		p.addr, score, p.misbehaviorScore, reason)

	if p.misbehaviorScore >= MisbehaviorThreshold {
		p.shouldBan = true
		cb := p.banCallback
		log.Printf("peer %s: misbehavior threshold reached, flagging for ban", p.addr)
		p.mu.Unlock()

		// Call ban callback outside the lock with the real peer so
		// handlePeerBan → BanPeer can correctly match and disconnect.
		if cb != nil {
			go cb(p)
		}
		return true
	}
	p.mu.Unlock()
	return false
}

// MisbehaviorScore returns the current misbehavior score.
func (p *Peer) MisbehaviorScore() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.misbehaviorScore
}

// ShouldBan returns true if the peer has exceeded the misbehavior threshold.
func (p *Peer) ShouldBan() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.shouldBan
}

// randomUint64 generates a cryptographically random uint64.
func randomUint64() (uint64, error) {
	var buf [8]byte
	_, err := cryptorand.Read(buf[:])
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}
