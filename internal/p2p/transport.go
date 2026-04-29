package p2p

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashhog/blockbrew/internal/crypto"
)

// Transport handles reading and writing P2P messages over a connection.
// It abstracts the differences between v1 (plaintext) and v2 (encrypted) transports.
type Transport interface {
	// ReadMessage reads the next message from the transport.
	ReadMessage() (Message, error)

	// WriteMessage writes a message to the transport.
	WriteMessage(msg Message) error

	// IsEncrypted returns true if this transport uses encryption.
	IsEncrypted() bool

	// SessionID returns the v2 session ID, or nil for v1.
	SessionID() []byte

	// Close closes the underlying connection.
	Close() error

	// SetReadDeadline sets the deadline for read operations.
	SetReadDeadline(t time.Time) error

	// SetWriteDeadline sets the deadline for write operations.
	SetWriteDeadline(t time.Time) error
}

// V1Transport implements the v1 (plaintext) P2P transport.
type V1Transport struct {
	conn   net.Conn
	magic  uint32
	mu     sync.Mutex
}

// NewV1Transport creates a new v1 transport.
func NewV1Transport(conn net.Conn, magic uint32) *V1Transport {
	return &V1Transport{
		conn:  conn,
		magic: magic,
	}
}

// ReadMessage reads a v1 message from the connection.
func (t *V1Transport) ReadMessage() (Message, error) {
	return ReadMessage(t.conn, t.magic)
}

// WriteMessage writes a v1 message to the connection.
func (t *V1Transport) WriteMessage(msg Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return WriteMessage(t.conn, t.magic, msg)
}

// IsEncrypted returns false for v1 transport.
func (t *V1Transport) IsEncrypted() bool {
	return false
}

// SessionID returns nil for v1 transport.
func (t *V1Transport) SessionID() []byte {
	return nil
}

// Close closes the connection.
func (t *V1Transport) Close() error {
	return t.conn.Close()
}

// SetReadDeadline sets the read deadline.
func (t *V1Transport) SetReadDeadline(deadline time.Time) error {
	return t.conn.SetReadDeadline(deadline)
}

// SetWriteDeadline sets the write deadline.
func (t *V1Transport) SetWriteDeadline(deadline time.Time) error {
	return t.conn.SetWriteDeadline(deadline)
}

// V2TransportState represents the state of a v2 transport during handshake.
type V2TransportState int

const (
	// V2StateKeyExchange is the initial state where we're exchanging keys.
	V2StateKeyExchange V2TransportState = iota
	// V2StateGarbageTerminator is where we're waiting for the garbage terminator.
	V2StateGarbageTerminator
	// V2StateVersion is where we're waiting for the version packet.
	V2StateVersion
	// V2StateReady is when the transport is ready for application messages.
	V2StateReady
)

// V2Transport implements the v2 (encrypted) P2P transport per BIP324.
type V2Transport struct {
	conn        net.Conn
	magic       uint32
	cipher      *BIP324Cipher
	initiator   bool
	state       V2TransportState
	mu          sync.Mutex

	// Handshake data
	ourGarbage   []byte
	theirGarbage []byte

	// Buffer for partial reads
	recvBuffer []byte
}

// NewV2Transport creates a new v2 transport.
func NewV2Transport(conn net.Conn, magic uint32, initiator bool) (*V2Transport, error) {
	cipher, err := NewBIP324Cipher()
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	return &V2Transport{
		conn:      conn,
		magic:     magic,
		cipher:    cipher,
		initiator: initiator,
		state:     V2StateKeyExchange,
		ourGarbage: GenerateGarbage(),
	}, nil
}

// NewV2TransportWithKey creates a v2 transport with a specific key (for testing).
func NewV2TransportWithKey(conn net.Conn, magic uint32, initiator bool, privKey, entropy []byte) (*V2Transport, error) {
	cipher, err := NewBIP324CipherWithKey(privKey, entropy)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	return &V2Transport{
		conn:      conn,
		magic:     magic,
		cipher:    cipher,
		initiator: initiator,
		state:     V2StateKeyExchange,
		ourGarbage: GenerateGarbage(),
	}, nil
}

// Handshake performs the v2 handshake.
// Returns an error if the handshake fails, or if the peer only supports v1.
func (t *V2Transport) Handshake() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.initiator {
		return t.initiatorHandshake()
	}
	return t.responderHandshake()
}

// initiatorHandshake performs the initiator's side of the v2 handshake.
//
// The wire-level interleaving is delicate because both sides start by sending
// pubkey+garbage and then need each other's pubkey to derive the cipher
// keys.  We use one goroutine for all sends (which can include arbitrarily
// large garbage) so reads on the main goroutine cannot deadlock on pipe
// back-pressure.  This matches the event-driven approach in
// bitcoin-core/src/net.cpp::V2Transport (clearbit/peer.zig:performV2Handshake
// uses the same pattern).
//
// Wire shape:
//
//	->  pubkey || garbage
//	<-  pubkey || garbage || garbage_terminator || version_packet
//	->  garbage_terminator || version_packet
func (t *V2Transport) initiatorHandshake() error {
	ourPubKey := t.cipher.GetOurPubKey()

	// Drive our outbound bytes from a goroutine.  The first chunk
	// (pubkey + garbage) is queued before we know the peer's pubkey;
	// the second chunk (terminator + version_packet) is computed only
	// after we receive the peer's pubkey, then signaled via a channel.
	type sendStage struct {
		data []byte
	}
	stage := make(chan sendStage, 2)
	sendErrCh := make(chan error, 1)

	go func() {
		for chunk := range stage {
			if _, err := t.conn.Write(chunk.data); err != nil {
				sendErrCh <- err
				return
			}
		}
		sendErrCh <- nil
	}()

	// Step 1: queue pubkey + garbage immediately.
	first := make([]byte, EllSwiftPubKeySize+len(t.ourGarbage))
	copy(first[0:EllSwiftPubKeySize], ourPubKey[:])
	copy(first[EllSwiftPubKeySize:], t.ourGarbage)
	stage <- sendStage{first}

	// Step 2: read their pubkey (64 bytes).
	theirPubKeyBytes := make([]byte, EllSwiftPubKeySize)
	if _, err := io.ReadFull(t.conn, theirPubKeyBytes); err != nil {
		close(stage)
		return fmt.Errorf("read pubkey: %w", err)
	}
	var theirPubKey crypto.EllSwiftPubKey
	copy(theirPubKey[:], theirPubKeyBytes)

	// Step 3: derive cipher state.
	if err := t.cipher.InitializeWithMagic(theirPubKey, true, t.magic); err != nil {
		close(stage)
		return fmt.Errorf("init cipher: %w", err)
	}

	// Step 4: queue our terminator + version_packet now that the cipher is
	// ready.  Per BIP-324 the version packet's AAD is our sent garbage.
	versionPacket, err := t.cipher.Encrypt(nil, t.ourGarbage, false)
	if err != nil {
		close(stage)
		return fmt.Errorf("encrypt version: %w", err)
	}
	ourGarbageTerminator := t.cipher.GetSendGarbageTerminator()
	second := make([]byte, GarbageTerminatorLen+len(versionPacket))
	copy(second[0:GarbageTerminatorLen], ourGarbageTerminator[:])
	copy(second[GarbageTerminatorLen:], versionPacket)
	stage <- sendStage{second}
	close(stage)

	// Step 5: scan for their garbage terminator.
	theirGarbageTerminator := t.cipher.GetRecvGarbageTerminator()
	if err := t.readGarbageAndTerminator(theirGarbageTerminator[:]); err != nil {
		return fmt.Errorf("read garbage: %w", err)
	}

	// Step 6: read & decrypt their version packet (AAD = their garbage).
	if err := t.readVersionPacket(); err != nil {
		return fmt.Errorf("read version packet: %w", err)
	}

	// Make sure all of our writes flushed before we declare success.
	if err := <-sendErrCh; err != nil {
		return fmt.Errorf("send: %w", err)
	}

	t.state = V2StateReady
	return nil
}

// responderHandshake performs the responder's side of the v2 handshake.
func (t *V2Transport) responderHandshake() error {
	// Step 1: Read their ElligatorSwift public key, detect v1
	firstBytes := make([]byte, EllSwiftPubKeySize)
	if _, err := io.ReadFull(t.conn, firstBytes); err != nil {
		return fmt.Errorf("read pubkey: %w", err)
	}

	// Check if this looks like a v1 message
	if CheckV1Magic(firstBytes, t.magic) {
		return errors.New("detected v1 protocol, fallback required")
	}

	var theirPubKey crypto.EllSwiftPubKey
	copy(theirPubKey[:], firstBytes)

	// Step 2: Initialize cipher
	if err := t.cipher.InitializeWithMagic(theirPubKey, false, t.magic); err != nil {
		return fmt.Errorf("init cipher: %w", err)
	}

	// Step 3: Read their garbage + garbage terminator
	theirGarbageTerminator := t.cipher.GetRecvGarbageTerminator()
	if err := t.readGarbageAndTerminator(theirGarbageTerminator[:]); err != nil {
		return fmt.Errorf("read garbage: %w", err)
	}

	// Step 4: Send our pubkey + garbage + garbage terminator + version packet
	ourPubKey := t.cipher.GetOurPubKey()
	ourGarbageTerminator := t.cipher.GetSendGarbageTerminator()

	// Encrypt version packet with our garbage as AAD
	versionPacket, err := t.cipher.Encrypt(nil, t.ourGarbage, false)
	if err != nil {
		return fmt.Errorf("encrypt version: %w", err)
	}

	sendData := make([]byte, EllSwiftPubKeySize+len(t.ourGarbage)+GarbageTerminatorLen+len(versionPacket))
	offset := 0
	copy(sendData[offset:], ourPubKey[:])
	offset += EllSwiftPubKeySize
	copy(sendData[offset:], t.ourGarbage)
	offset += len(t.ourGarbage)
	copy(sendData[offset:], ourGarbageTerminator[:])
	offset += GarbageTerminatorLen
	copy(sendData[offset:], versionPacket)

	if _, err := t.conn.Write(sendData); err != nil {
		return fmt.Errorf("send response: %w", err)
	}

	// Step 5: Read and decrypt their version packet
	if err := t.readVersionPacket(); err != nil {
		return fmt.Errorf("read version packet: %w", err)
	}

	t.state = V2StateReady
	return nil
}

// readGarbageAndTerminator reads garbage data until the garbage terminator
// is found, scanning the trailing 16-byte window after each new byte.
//
// We must read at least 16 bytes before checking — peers MAY send 0-byte
// garbage, in which case the terminator arrives in the first 16 bytes.
// Reading byte-by-byte after the initial bulk read keeps us aligned with
// the wire shape Bitcoin Core / ouroboros / clearbit use.
func (t *V2Transport) readGarbageAndTerminator(terminator []byte) error {
	maxRead := MaxGarbageLen + GarbageTerminatorLen

	// Bulk-read the first GarbageTerminatorLen (16) bytes; the smallest
	// case (zero-length garbage) puts the terminator entirely inside this
	// initial window.
	buffer := make([]byte, GarbageTerminatorLen, maxRead)
	if _, err := io.ReadFull(t.conn, buffer); err != nil {
		return err
	}

	for {
		if bytes.Equal(buffer[len(buffer)-GarbageTerminatorLen:], terminator) {
			t.theirGarbage = buffer[:len(buffer)-GarbageTerminatorLen]
			return nil
		}
		if len(buffer) >= maxRead {
			return errors.New("garbage terminator not found within MaxGarbageLen window")
		}
		var b [1]byte
		if _, err := io.ReadFull(t.conn, b[:]); err != nil {
			return err
		}
		buffer = append(buffer, b[0])
	}
}

// readVersionPacket reads and decrypts the version packet.
func (t *V2Transport) readVersionPacket() error {
	// Read encrypted length (3 bytes)
	encLen := make([]byte, LengthLen)
	if _, err := io.ReadFull(t.conn, encLen); err != nil {
		return fmt.Errorf("read length: %w", err)
	}

	length, err := t.cipher.DecryptLength(encLen)
	if err != nil {
		return fmt.Errorf("decrypt length: %w", err)
	}

	// Read encrypted payload (length + 1 header + 16 tag)
	payloadLen := int(length) + HeaderLen + crypto.Expansion
	encPayload := make([]byte, payloadLen)
	if _, err := io.ReadFull(t.conn, encPayload); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	// Decrypt with their garbage as AAD
	_, _, err = t.cipher.Decrypt(encPayload, t.theirGarbage)
	if err != nil {
		return fmt.Errorf("decrypt version: %w", err)
	}

	// Version packet is accepted (contents are ignored for now)
	return nil
}

// ReadMessage reads an encrypted message from the v2 transport.
func (t *V2Transport) ReadMessage() (Message, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state != V2StateReady {
		return nil, errors.New("transport not ready")
	}

	for {
		// Read encrypted length
		encLen := make([]byte, LengthLen)
		if _, err := io.ReadFull(t.conn, encLen); err != nil {
			return nil, fmt.Errorf("read length: %w", err)
		}

		length, err := t.cipher.DecryptLength(encLen)
		if err != nil {
			return nil, fmt.Errorf("decrypt length: %w", err)
		}

		// Validate length
		if length > MaxPayloadSize {
			return nil, ErrPayloadTooLarge
		}

		// Read encrypted payload
		payloadLen := int(length) + HeaderLen + crypto.Expansion
		encPayload := make([]byte, payloadLen)
		if _, err := io.ReadFull(t.conn, encPayload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}

		// Decrypt
		content, ignore, err := t.cipher.Decrypt(encPayload, nil)
		if err != nil {
			return nil, fmt.Errorf("decrypt: %w", err)
		}

		// Skip decoy messages
		if ignore {
			continue
		}

		// Decode v2 message format
		command, payload, err := DecodeV2Message(content)
		if err != nil {
			return nil, fmt.Errorf("decode message: %w", err)
		}

		// Create message object
		msg, err := makeMessage(command)
		if err != nil {
			return nil, err
		}

		// Deserialize payload
		if err := msg.Deserialize(bytes.NewReader(payload)); err != nil {
			return nil, fmt.Errorf("deserialize %s: %w", command, err)
		}

		return msg, nil
	}
}

// WriteMessage writes an encrypted message to the v2 transport.
func (t *V2Transport) WriteMessage(msg Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state != V2StateReady {
		return errors.New("transport not ready")
	}

	// Serialize payload
	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Encode for v2 format
	content := EncodeV2Message(msg.Command(), buf.Bytes())

	// Encrypt
	encrypted, err := t.cipher.Encrypt(content, nil, false)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Write to connection
	if _, err := t.conn.Write(encrypted); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

// SendDecoy sends a decoy message for traffic analysis resistance.
func (t *V2Transport) SendDecoy(length int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state != V2StateReady {
		return errors.New("transport not ready")
	}

	content := make([]byte, length)
	encrypted, err := t.cipher.Encrypt(content, nil, true)
	if err != nil {
		return fmt.Errorf("encrypt decoy: %w", err)
	}

	if _, err := t.conn.Write(encrypted); err != nil {
		return fmt.Errorf("write decoy: %w", err)
	}

	return nil
}

// IsEncrypted returns true for v2 transport.
func (t *V2Transport) IsEncrypted() bool {
	return true
}

// SessionID returns the v2 session ID.
func (t *V2Transport) SessionID() []byte {
	id := t.cipher.GetSessionID()
	return id[:]
}

// Close closes the connection.
func (t *V2Transport) Close() error {
	return t.conn.Close()
}

// SetReadDeadline sets the read deadline.
func (t *V2Transport) SetReadDeadline(deadline time.Time) error {
	return t.conn.SetReadDeadline(deadline)
}

// SetWriteDeadline sets the write deadline.
func (t *V2Transport) SetWriteDeadline(deadline time.Time) error {
	return t.conn.SetWriteDeadline(deadline)
}

// NegotiateTransport attempts to establish a v2 connection, falling back to
// v1 if needed.
//
// For outbound connections this drives the v2 initiator handshake.  For
// inbound connections it peeks the first 64 bytes to classify v1 vs v2:
//
//   - v1: bytes 0..15 match `magic || "version\0\0\0\0\0"`.  The peeked
//     bytes are preserved on a `prefixedConn` and a V1Transport is
//     returned, so the caller can continue reading the v1 frame normally.
//   - v2: those 64 bytes are treated as the peer's ElligatorSwift public
//     key; we initialise the responder cipher and drive the rest of the
//     BIP-324 handshake.
//
// The responder send/receive path uses a goroutine for the outbound bytes
// because both sides queue up to ~4 KB of garbage during the handshake and
// net.Pipe / kernel pipe buffers can stall a synchronous Write/Read order.
// This mirrors the event-driven I/O Bitcoin Core uses in V2Transport
// (src/net.cpp).
func NegotiateTransport(conn net.Conn, magic uint32, initiator, preferV2 bool) (Transport, error) {
	if !preferV2 {
		return NewV1Transport(conn, magic), nil
	}

	if initiator {
		// Try v2 handshake
		v2, err := NewV2Transport(conn, magic, true)
		if err != nil {
			return nil, err
		}

		if err := v2.Handshake(); err != nil {
			// Handshake failed, could try v1 fallback here
			return nil, fmt.Errorf("v2 handshake failed: %w", err)
		}

		return v2, nil
	}

	// Inbound: peek the first 64 bytes (ElligatorSwift pubkey size) and
	// classify v1 vs v2.
	firstBytes := make([]byte, EllSwiftPubKeySize)
	if _, err := io.ReadFull(conn, firstBytes); err != nil {
		return nil, fmt.Errorf("read first bytes: %w", err)
	}

	// v1 fast path: prefix the already-read bytes back onto the conn so
	// the v1 reader sees an intact frame.
	if CheckV1Magic(firstBytes, magic) {
		prefixedConn := &prefixedConn{
			prefix: firstBytes,
			conn:   conn,
		}
		return NewV1Transport(prefixedConn, magic), nil
	}

	// v2 path: those 64 bytes are the peer's pubkey.  Drive the responder
	// handshake, with all sends going through a goroutine so we don't
	// deadlock on synchronous pipe back-pressure (the peer can't send its
	// terminator until it sees our pubkey, but our pubkey send may need
	// kernel buffer space its garbage hasn't yet vacated).
	v2, err := NewV2Transport(conn, magic, false)
	if err != nil {
		return nil, err
	}

	var theirPubKey crypto.EllSwiftPubKey
	copy(theirPubKey[:], firstBytes)

	if err := v2.cipher.InitializeWithMagic(theirPubKey, false, magic); err != nil {
		return nil, fmt.Errorf("init cipher: %w", err)
	}

	// Build the full responder reply: pubkey || garbage || terminator || version_packet.
	ourPubKey := v2.cipher.GetOurPubKey()
	ourGarbageTerminator := v2.cipher.GetSendGarbageTerminator()
	versionPacket, err := v2.cipher.Encrypt(nil, v2.ourGarbage, false)
	if err != nil {
		return nil, fmt.Errorf("encrypt version: %w", err)
	}

	sendData := make([]byte, EllSwiftPubKeySize+len(v2.ourGarbage)+GarbageTerminatorLen+len(versionPacket))
	offset := 0
	copy(sendData[offset:], ourPubKey[:])
	offset += EllSwiftPubKeySize
	copy(sendData[offset:], v2.ourGarbage)
	offset += len(v2.ourGarbage)
	copy(sendData[offset:], ourGarbageTerminator[:])
	offset += GarbageTerminatorLen
	copy(sendData[offset:], versionPacket)

	// Drive the write from a goroutine so the upcoming
	// readGarbageAndTerminator (which scans byte-by-byte through the
	// peer's garbage) isn't blocked behind our Write completing.
	sendErrCh := make(chan error, 1)
	go func() {
		_, werr := conn.Write(sendData)
		sendErrCh <- werr
	}()

	// Now read the peer's garbage + terminator.  This consumes from the
	// initiator's first send (pubkey+garbage); the initiator queues
	// terminator+version_packet only AFTER it observes our pubkey, which
	// reaches the wire above.
	theirGarbageTerminator := v2.cipher.GetRecvGarbageTerminator()
	if err := v2.readGarbageAndTerminator(theirGarbageTerminator[:]); err != nil {
		return nil, fmt.Errorf("read garbage: %w", err)
	}

	// Read their version packet (AAD = their garbage).
	if err := v2.readVersionPacket(); err != nil {
		return nil, fmt.Errorf("read version packet: %w", err)
	}

	// Make sure our send goroutine flushed everything before we report
	// success — otherwise application messages could race in front of
	// the version packet on the wire.
	if werr := <-sendErrCh; werr != nil {
		return nil, fmt.Errorf("send response: %w", werr)
	}

	v2.state = V2StateReady
	return v2, nil
}

// prefixedConn wraps a connection with a prefix that is read first.
type prefixedConn struct {
	prefix []byte
	offset int
	conn   net.Conn
}

func (c *prefixedConn) Read(b []byte) (int, error) {
	if c.offset < len(c.prefix) {
		n := copy(b, c.prefix[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.conn.Read(b)
}

func (c *prefixedConn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *prefixedConn) Close() error {
	return c.conn.Close()
}

func (c *prefixedConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *prefixedConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *prefixedConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *prefixedConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *prefixedConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// ServiceFlags for v2 support.
const (
	// ServiceNodeP2PV2 indicates support for BIP324 v2 P2P protocol.
	ServiceNodeP2PV2 uint64 = 1 << 11
)

// SupportsV2 checks if the given service flags indicate v2 support.
func SupportsV2(services uint64) bool {
	return (services & ServiceNodeP2PV2) != 0
}
