package p2p

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/crypto"
)

// Tests for how fast a lost full-relay outbound slot is refilled, and for the
// per-disconnect log line that says who closed an outbound connection.
//
// Mainnet evidence (2026-11-12): a full-relay peer hung up at 13:06:41 and the
// slot was refilled at 13:13:59. Every dial to an unreachable address held the
// slot's reservation for ConnectTimeout (30 s), where Core gives up after
// DEFAULT_CONNECT_TIMEOUT = 5 s (netbase.h).

// coreConnectTimeout is Core's DEFAULT_CONNECT_TIMEOUT (netbase.h:27).
const coreConnectTimeout = 5 * time.Second

// fullRig returns a refill rig with every full-relay and block-relay-only slot
// connected.
func fullRig(t *testing.T) *refillRig {
	t.Helper()
	r := newRefillRig(t, 60, 0, 0)
	r.pm.openConnectionsTick()
	r.settle(t)
	if f, b := r.counts(); f != DefaultMaxOutbound || b != DefaultMaxBlockRelayOnly {
		t.Fatalf("setup: full-relay=%d block-relay-only=%d, want %d and %d",
			f, b, DefaultMaxOutbound, DefaultMaxBlockRelayOnly)
	}
	return r
}

// peersOfType lists the connected peers of one connection type.
func (r *refillRig) peersOfType(ct ConnType) []*Peer {
	r.pm.mu.RLock()
	defer r.pm.mu.RUnlock()
	var out []*Peer
	for _, info := range r.pm.peers {
		if info.connType == ct {
			out = append(out, info.peer)
		}
	}
	return out
}

// dropOneFullRelay disconnects one full-relay peer and waits for its slot to
// open.
func (r *refillRig) dropOneFullRelay(t *testing.T) *Peer {
	t.Helper()
	peers := r.peersOfType(ConnFullRelay)
	if len(peers) == 0 {
		t.Fatal("no full-relay peer to drop")
	}
	p := peers[0]
	p.Disconnect()
	waitUntil(t, 5*time.Second, func() bool {
		f, _ := r.counts()
		return f == DefaultMaxOutbound-1
	})
	return p
}

// dialLog records the type of every dial, in order, while passing dials on
// to the rig's dialer. The first blackholed full-relay dials behave like a
// SYN sent to an address that never answers: they block for the dial timeout
// the real dialer uses (net.DialTimeout(addr, ConnectTimeout)) and then fail.
type dialLog struct {
	mu         sync.Mutex
	types      []ConnType
	blackholed int
}

func (r *refillRig) wrapDial(blackholeFull int) *dialLog {
	dl := &dialLog{blackholed: blackholeFull}
	inner := r.pm.dialFn
	r.pm.dialFn = func(addr string, cfg PeerConfig) (*Peer, error) {
		ct := ConnFullRelay
		if cfg.DisableRelayTx {
			ct = ConnBlockRelayOnly
		}
		dl.mu.Lock()
		dl.types = append(dl.types, ct)
		hole := ct == ConnFullRelay && dl.blackholed > 0
		if hole {
			dl.blackholed--
		}
		dl.mu.Unlock()
		if hole {
			time.Sleep(ConnectTimeout)
			return nil, fmt.Errorf("dial %s: i/o timeout", addr)
		}
		return inner(addr, cfg)
	}
	return dl
}

func (dl *dialLog) snapshot() []ConnType {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	return append([]ConnType(nil), dl.types...)
}

// The dial timeout is Core's 5 s, not 30 s.
func TestDefaultConnectTimeoutMatchesCore(t *testing.T) {
	if ConnectTimeout != coreConnectTimeout {
		t.Fatalf("ConnectTimeout = %s, want Core's DEFAULT_CONNECT_TIMEOUT %s", ConnectTimeout, coreConnectTimeout)
	}
}

// One full-relay slot open and the next K addresses picked for it blackholed:
// the slot must be filled within K dial timeouts of Core's length plus a
// margin. With a 30 s dial timeout the slot stays open for K*30 s.
func TestOutboundRefillBlackholedAddressesFillSlotWithinConnectTimeout(t *testing.T) {
	const K = 3
	r := fullRig(t)
	r.dropOneFullRelay(t)
	r.wrapDial(K)

	// Refill passes as the connection loop runs them, only more often, so the
	// pass interval cannot be what makes this slow.
	budget := K*coreConnectTimeout + 5*time.Second
	start := time.Now()
	for time.Since(start) < budget {
		if f, _ := r.counts(); f == DefaultMaxOutbound {
			t.Logf("slot refilled after %s (%d blackholed dials, ConnectTimeout %s)",
				time.Since(start).Round(time.Millisecond), K, ConnectTimeout)
			return
		}
		r.pm.openConnectionsTick()
		time.Sleep(100 * time.Millisecond)
	}
	f, _ := r.counts()
	t.Fatalf("full-relay=%d after %s with %d blackholed addresses, want %d: each failed dial held the slot for ConnectTimeout=%s",
		f, budget, K, DefaultMaxOutbound, ConnectTimeout)
}

// A full-relay slot that opens while a block-relay-only rotation is due is
// dialed first, and the rotation does not drop a block-relay peer while
// full-relay is short (Core ThreadOpenConnections only makes the extra
// block-relay connection once every full-relay slot is filled).
func TestBlockRelayRotationYieldsToOpenFullRelaySlot(t *testing.T) {
	r := fullRig(t)
	before := r.peersOfType(ConnBlockRelayOnly)
	r.dropOneFullRelay(t)
	dl := r.wrapDial(0)

	// The rotation timer fires, then the next refill pass runs.
	r.pm.maybeRotateBlockRelayPeer()
	time.Sleep(50 * time.Millisecond)
	r.pm.openConnectionsTick()
	r.settle(t)

	types := dl.snapshot()
	if len(types) == 0 || types[0] != ConnFullRelay {
		t.Fatalf("dials after the rotation: %v, want the first one full-relay", types)
	}
	after := r.peersOfType(ConnBlockRelayOnly)
	still := 0
	for _, a := range after {
		for _, b := range before {
			if a == b {
				still++
			}
		}
	}
	if still != len(before) {
		t.Fatalf("rotation dropped %d of %d block-relay-only peers while a full-relay slot was open",
			len(before)-still, len(before))
	}
	if f, _ := r.counts(); f != DefaultMaxOutbound {
		t.Fatalf("full-relay=%d, want %d", f, DefaultMaxOutbound)
	}
}

// Guard: with every full-relay slot filled the rotation still runs.
func TestBlockRelayRotationRunsWhenFullRelayIsFull(t *testing.T) {
	r := fullRig(t)
	r.pm.maybeRotateBlockRelayPeer()
	waitUntil(t, 5*time.Second, func() bool {
		_, b := r.counts()
		return b == DefaultMaxBlockRelayOnly-1
	})
}

// captureLog sends the package logger to a buffer for the test.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLog(t *testing.T) *syncBuf {
	t.Helper()
	buf := &syncBuf{}
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return buf
}

// waitLogLine waits for a log line that contains every one of parts.
func waitLogLine(t *testing.T, buf *syncBuf, parts ...string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(buf.String(), "\n") {
			ok := true
			for _, p := range parts {
				if !strings.Contains(line, p) {
					ok = false
					break
				}
			}
			if ok {
				return line
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no log line containing %q; log:\n%s", parts, buf.String())
	return ""
}

// serverSide finds the far end of a rig peer's pipe.
func (r *refillRig) serverSide(t *testing.T, p *Peer) net.Conn {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i+1 < len(r.conns); i += 2 {
		if r.conns[i] == p.conn {
			return r.conns[i+1]
		}
	}
	t.Fatalf("no server side for %s", p.Address())
	return nil
}

// An outbound peer that hangs up is logged at info as closed by the remote,
// with the read error, so the remote-hangup share can be counted.
func TestOutboundDisconnectLogsRemoteHangup(t *testing.T) {
	r := fullRig(t)
	buf := captureLog(t)
	p := r.peersOfType(ConnFullRelay)[0]
	r.serverSide(t, p).Close()
	line := waitLogLine(t, buf, "outbound disconnect", p.Address(), "by=remote")
	if !strings.Contains(line, "type=full-relay") || !strings.Contains(line, "EOF") {
		t.Fatalf("disconnect line %q: want type=full-relay and the EOF read error", line)
	}
}

// An outbound peer we drop is logged as closed by us, with our reason.
func TestOutboundDisconnectLogsOurReason(t *testing.T) {
	r := fullRig(t)
	buf := captureLog(t)
	r.pm.maybeRotateBlockRelayPeer()
	line := waitLogLine(t, buf, "outbound disconnect", "by=local")
	if !strings.Contains(line, "type=block-relay-only") || !strings.Contains(line, "block-relay rotation") {
		t.Fatalf("disconnect line %q: want type=block-relay-only and reason block-relay rotation", line)
	}
}

// Disconnect() with no stated reason still names who asked for it.
func TestPeerDisconnectReasonNamesCaller(t *testing.T) {
	r := fullRig(t)
	p := r.peersOfType(ConnFullRelay)[0]
	p.Disconnect()
	dr, ok := any(p).(interface{ DisconnectReason() (string, string) })
	if !ok {
		t.Fatal("Peer has no DisconnectReason()")
	}
	by, reason := dr.DisconnectReason()
	if by != "local" || !strings.Contains(reason, "TestPeerDisconnectReasonNamesCaller") {
		t.Fatalf("DisconnectReason() = %q, %q; want local and the calling function", by, reason)
	}
}

// rawV1Frame builds a v1 message frame with a correct checksum.
func rawV1Frame(magic uint32, cmd string, payload []byte) []byte {
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], magic)
	copy(hdr[4:16], cmd)
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(payload)))
	sum := crypto.DoubleSHA256(payload)
	copy(hdr[20:24], sum[:4])
	return append(hdr[:], payload...)
}

// A peer that sends a checksum-valid but truncated headers message is dropped
// by us for a malformed message. Its parser runs out of payload with io.EOF,
// which must not be counted as the remote hanging up.
func TestOutboundDisconnectTruncatedMessageIsLocal(t *testing.T) {
	r := fullRig(t)
	buf := captureLog(t)
	p := r.peersOfType(ConnFullRelay)[0]
	srv := r.serverSide(t, p)
	// headers: count 1, then no header bytes.
	frame := rawV1Frame(MainnetMagic, "headers", []byte{0x01})
	go func() { _, _ = srv.Write(frame) }()
	line := waitLogLine(t, buf, "outbound disconnect", p.Address())
	if !strings.Contains(line, "by=local") || !strings.Contains(line, "malformed headers") {
		t.Fatalf("disconnect line %q: want by=local and reason malformed headers", line)
	}
}
