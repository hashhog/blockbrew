package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-zeromq/zmq4"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ZMQ topic strings, matching Bitcoin Core
// `bitcoin-core/src/zmq/zmqpublishnotifier.cpp:33-37`.
const (
	zmqTopicHashBlock = "hashblock"
	zmqTopicHashTx    = "hashtx"
	zmqTopicRawBlock  = "rawblock"
	zmqTopicRawTx     = "rawtx"
	zmqTopicSequence  = "sequence"
)

// Sequence-message labels from
// `bitcoin-core/src/zmq/zmqpublishnotifier.cpp:NotifyBlockConnect/Disconnect/...`.
const (
	zmqSeqLabelBlockConnect    byte = 'C'
	zmqSeqLabelBlockDisconnect byte = 'D'
	zmqSeqLabelTxAccept        byte = 'A'
	zmqSeqLabelTxRemove        byte = 'R'
)

// zmqPublisherConfig captures all five `-zmqpub*` endpoints. Each is the
// ZMQ bind address (e.g. "tcp://127.0.0.1:28332") or empty to disable.
type zmqPublisherConfig struct {
	HashBlock string
	HashTx    string
	RawBlock  string
	RawTx     string
	Sequence  string
}

// hasAny reports whether at least one publisher is enabled.
func (c zmqPublisherConfig) hasAny() bool {
	return c.HashBlock != "" || c.HashTx != "" || c.RawBlock != "" || c.RawTx != "" || c.Sequence != ""
}

// zmqEndpoint groups one PUB socket with its per-topic monotonic counter.
// We open one socket per `-zmqpub*` URI so two topics on the same address
// (the common case in Core) share a socket via the addr→endpoint dedup.
type zmqEndpoint struct {
	addr   string
	socket zmq4.Socket
	// per-topic counters used in the third frame of each PUB message
	// (matches Core: <topic> | <body> | <LE u32 sequence>).
	counters map[string]*uint32
	mu       sync.Mutex
}

// zmqPublisher fans block / tx events out to the configured PUB sockets.
// One zmqPublisher serves the whole node lifetime; Stop() closes every
// socket. Send is goroutine-safe but each socket is internally serialised
// because zmq4 sockets are NOT safe for concurrent Send calls.
type zmqPublisher struct {
	cfg zmqPublisherConfig
	// addr → endpoint. Map insertion happens once during Start; reads
	// during Send are unsynchronised after Start returns.
	endpoints map[string]*zmqEndpoint
	// global mempool sequence (mirrors Core's m_mempool_sequence).
	mempoolSeq uint64
	// stopped flag so Send is a no-op after Close.
	stopped atomic.Bool

	ctx    context.Context
	cancel context.CancelFunc
}

// newZMQPublisher returns a stopped publisher; the caller must invoke
// Start() to bind the sockets.
func newZMQPublisher(cfg zmqPublisherConfig) *zmqPublisher {
	ctx, cancel := context.WithCancel(context.Background())
	return &zmqPublisher{
		cfg:       cfg,
		endpoints: map[string]*zmqEndpoint{},
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start binds a PUB socket per unique endpoint URI. Multiple topics on
// the same URI share a socket, matching Core's behaviour. Returns the
// first error encountered; partially-bound sockets are closed before
// returning so callers don't leak fds on error.
func (p *zmqPublisher) Start() error {
	if !p.cfg.hasAny() {
		return nil
	}
	addrs := []struct {
		topic string
		addr  string
	}{
		{zmqTopicHashBlock, p.cfg.HashBlock},
		{zmqTopicHashTx, p.cfg.HashTx},
		{zmqTopicRawBlock, p.cfg.RawBlock},
		{zmqTopicRawTx, p.cfg.RawTx},
		{zmqTopicSequence, p.cfg.Sequence},
	}
	for _, a := range addrs {
		if a.addr == "" {
			continue
		}
		ep, ok := p.endpoints[a.addr]
		if !ok {
			sock := zmq4.NewPub(p.ctx)
			normAddr, err := normalizeZMQAddr(a.addr)
			if err != nil {
				p.shutdownAll()
				return fmt.Errorf("zmq publisher: invalid address %q: %w", a.addr, err)
			}
			if err := sock.Listen(normAddr); err != nil {
				_ = sock.Close()
				p.shutdownAll()
				return fmt.Errorf("zmq publisher: bind %q: %w", normAddr, err)
			}
			ep = &zmqEndpoint{
				addr:     normAddr,
				socket:   sock,
				counters: map[string]*uint32{},
			}
			p.endpoints[a.addr] = ep
			log.Printf("[zmq] publisher listening on %s", normAddr)
		}
		// Pre-allocate a counter for this topic so Send() never has to.
		var c uint32
		ep.counters[a.topic] = &c
	}
	return nil
}

// shutdownAll closes every endpoint, used on Start failure to avoid
// leaking partially-bound sockets.
func (p *zmqPublisher) shutdownAll() {
	for addr, ep := range p.endpoints {
		_ = ep.socket.Close()
		delete(p.endpoints, addr)
	}
}

// Stop closes all PUB sockets. Safe to call multiple times. Subsequent
// Send calls become no-ops.
func (p *zmqPublisher) Stop() {
	if p.stopped.Swap(true) {
		return
	}
	p.cancel()
	for _, ep := range p.endpoints {
		_ = ep.socket.Close()
	}
}

// sendTopic publishes a three-frame message to the endpoint serving
// `topic`: [topic] [body] [LE u32 sequence]. Mirrors Core's
// CZMQAbstractPublishNotifier::SendZmqMessage.  Returns nil if the
// topic was not configured (Core does the same — silent drop).
func (p *zmqPublisher) sendTopic(topic, addr string, body []byte) error {
	if p.stopped.Load() {
		return nil
	}
	if addr == "" {
		return nil
	}
	ep, ok := p.endpoints[addr]
	if !ok {
		return nil // not configured; should not happen post-Start
	}
	c, ok := ep.counters[topic]
	if !ok {
		// First time we send this topic on this socket: allocate.
		ep.mu.Lock()
		if ep.counters == nil {
			ep.counters = map[string]*uint32{}
		}
		c, ok = ep.counters[topic]
		if !ok {
			var nc uint32
			c = &nc
			ep.counters[topic] = c
		}
		ep.mu.Unlock()
	}
	seq := atomic.AddUint32(c, 1) - 1
	seqBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBuf, seq)

	msg := zmq4.NewMsgFrom([]byte(topic), body, seqBuf)
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if err := ep.socket.Send(msg); err != nil {
		return err
	}
	return nil
}

// PublishBlockConnected is the hook fired by main.go's onBlockConnected
// callback. It serialises the block once (if rawblock is enabled) and
// fans the payload out to hashblock / rawblock / sequence as applicable.
//
// If serialisation fails the block-connect path is *not* aborted — we
// log and skip just the rawblock topic, since ZMQ failures must never
// stall consensus progression.
func (p *zmqPublisher) PublishBlockConnected(block *wire.MsgBlock, height int32) {
	if p == nil || p.stopped.Load() {
		return
	}
	hash := block.Header.BlockHash()
	if p.cfg.HashBlock != "" {
		if err := p.sendTopic(zmqTopicHashBlock, p.cfg.HashBlock, hash[:]); err != nil {
			log.Printf("[zmq] hashblock send failed: %v", err)
		}
	}
	if p.cfg.RawBlock != "" {
		var buf bytes.Buffer
		if err := block.Serialize(&buf); err != nil {
			log.Printf("[zmq] rawblock serialize failed: %v", err)
		} else if err := p.sendTopic(zmqTopicRawBlock, p.cfg.RawBlock, buf.Bytes()); err != nil {
			log.Printf("[zmq] rawblock send failed: %v", err)
		}
	}
	if p.cfg.Sequence != "" {
		seqBody := make([]byte, 32+1)
		copy(seqBody[:32], hash[:])
		seqBody[32] = zmqSeqLabelBlockConnect
		if err := p.sendTopic(zmqTopicSequence, p.cfg.Sequence, seqBody); err != nil {
			log.Printf("[zmq] sequence(C) send failed: %v", err)
		}
	}
	// height is currently informational only; Core's sequence/rawblock
	// frames don't carry height. Keeping the parameter in the signature
	// matches the OnBlockConnected callback shape so we can extend later.
	_ = height
}

// PublishTxAccepted is the hook for new txs entering the mempool. Serialises
// the tx once, fans out to hashtx / rawtx / sequence(A).
func (p *zmqPublisher) PublishTxAccepted(tx *wire.MsgTx) {
	if p == nil || p.stopped.Load() {
		return
	}
	hash := tx.TxHash()
	if p.cfg.HashTx != "" {
		if err := p.sendTopic(zmqTopicHashTx, p.cfg.HashTx, hash[:]); err != nil {
			log.Printf("[zmq] hashtx send failed: %v", err)
		}
	}
	if p.cfg.RawTx != "" {
		var buf bytes.Buffer
		if err := tx.Serialize(&buf); err != nil {
			log.Printf("[zmq] rawtx serialize failed: %v", err)
		} else if err := p.sendTopic(zmqTopicRawTx, p.cfg.RawTx, buf.Bytes()); err != nil {
			log.Printf("[zmq] rawtx send failed: %v", err)
		}
	}
	if p.cfg.Sequence != "" {
		mseq := atomic.AddUint64(&p.mempoolSeq, 1) - 1
		body := make([]byte, 32+1+8)
		copy(body[:32], hash[:])
		body[32] = zmqSeqLabelTxAccept
		binary.LittleEndian.PutUint64(body[33:], mseq)
		if err := p.sendTopic(zmqTopicSequence, p.cfg.Sequence, body); err != nil {
			log.Printf("[zmq] sequence(A) send failed: %v", err)
		}
	}
}

// normalizeZMQAddr canonicalises a `-zmqpub*` value the user supplied.
//
// Bitcoin Core's notifier accepts:
//   - tcp://host:port
//   - ipc:///abs/path
//
// We accept the same and also tolerate a bare "host:port" form (mapped
// to tcp://). Returns an error for anything we don't recognise so
// operators see a clear "invalid -zmqpub..." rather than a confusing
// ZMQ-internal failure.
func normalizeZMQAddr(addr string) (string, error) {
	if addr == "" {
		return "", fmt.Errorf("empty address")
	}
	if strings.HasPrefix(addr, "tcp://") || strings.HasPrefix(addr, "ipc://") {
		return addr, nil
	}
	// Bare host:port?
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return "tcp://" + addr, nil
	}
	return "", fmt.Errorf("expected tcp://host:port or ipc:///path, got %q", addr)
}
