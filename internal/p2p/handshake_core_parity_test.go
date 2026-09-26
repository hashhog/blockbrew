package p2p

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Handshake Core-parity tests (Bitcoin Core net_processing.cpp VERSION /
// VERACK handling):
//   - MIN_PEER_PROTO_VERSION (31800) is the only version floor; an inbound
//     VERSION(70002) completes the handshake and is never sent a feature
//     message its version cannot parse.
//   - Between VERSION and VERACK, sendheaders is PROCESSED; everything else
//     unsupported (ping, inv, feefilter, ...) is logged and ignored — no
//     disconnect, no misbehaviour.

// handshakeClient drives the remote side of an inbound handshake over a
// net.Pipe and records every message the peer sends us.
type handshakeClient struct {
	t     *testing.T
	conn  net.Conn
	sess  *pipeSession
	magic uint32
	seen  []Message
}

func newHandshakeClient(t *testing.T, conn net.Conn, magic uint32) *handshakeClient {
	return &handshakeClient{t: t, conn: conn, sess: servePipe(conn, magic), magic: magic}
}

func (c *handshakeClient) send(m Message) {
	c.t.Helper()
	if err := writePipeMessage(c.conn, c.magic, m); err != nil {
		c.t.Fatalf("write %s: %v", m.Command(), err)
	}
}

// waitFor records messages until one with command cmd arrives.
func (c *handshakeClient) waitFor(cmd string) bool {
	m, err := c.sess.waitMessage(pipeHandshakeBudget, func(m Message) bool {
		c.seen = append(c.seen, m)
		return m.Command() == cmd
	})
	return err == nil && m != nil
}

// drain records everything that arrives within d.
func (c *handshakeClient) drain(d time.Duration) {
	_, _ = c.sess.waitMessage(d, func(m Message) bool {
		c.seen = append(c.seen, m)
		return false
	})
}

func (c *handshakeClient) commands() []string {
	var out []string
	for _, m := range c.seen {
		out = append(out, m.Command())
	}
	return out
}

func handshakeTestConfig() PeerConfig {
	return PeerConfig{
		Network:         MainnetMagic,
		ProtocolVersion: ProtocolVersion,
		Services:        ServiceNodeNetwork | ServiceNodeWitness,
		UserAgent:       "/blockbrew:test/",
		BestHeight:      0,
	}
}

func clientVersion(pv int32, services uint64) *MsgVersion {
	return &MsgVersion{
		ProtocolVersion: pv,
		Services:        services,
		Timestamp:       time.Now().Unix(),
		Nonce:           424242,
		UserAgent:       "/hs-test/",
		StartHeight:     0,
		Relay:           true,
	}
}

// startInbound starts an inbound peer and returns a channel with Start()'s result.
func startInbound(t *testing.T) (*Peer, *handshakeClient, chan error, func()) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	peer := NewInboundPeer(serverConn, handshakeTestConfig())
	client := newHandshakeClient(t, clientConn, MainnetMagic)
	errCh := make(chan error, 1)
	go func() { errCh <- peer.Start() }()
	cleanup := func() {
		peer.Disconnect()
		clientConn.Close()
		serverConn.Close()
	}
	return peer, client, errCh, cleanup
}

func waitStart(t *testing.T, errCh chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(pipeHandshakeBudget):
		t.Fatal("handshake timed out")
		return nil
	}
}

// TestInboundVersion70002CompletesHandshake: a 70002 (pre-segwit, NODE_NETWORK
// only) inbound peer is above MIN_PEER_PROTO_VERSION, so Core keeps it. It
// must complete the handshake and must NOT be sent sendheaders (>=70012),
// sendcmpct (>=70014), feefilter (>=70013), wtxidrelay or sendaddrv2
// (>=70016). Master sent it sendheaders + sendcmpct.
func TestInboundVersion70002CompletesHandshake(t *testing.T) {
	peer, client, errCh, cleanup := startInbound(t)
	defer cleanup()

	client.send(clientVersion(70002, ServiceNodeNetwork))
	if !client.waitFor("verack") {
		t.Fatalf("no verack from peer; got %v", client.commands())
	}
	client.send(&MsgVerAck{})
	if err := waitStart(t, errCh); err != nil {
		t.Fatalf("Start() = %v, want handshake to complete for a 70002 peer", err)
	}
	if !peer.IsConnected() {
		t.Fatal("70002 peer must be connected after the handshake")
	}
	if peer.ShouldBan() {
		t.Fatal("70002 peer must not be discouraged")
	}
	if peer.CanServeWitnesses() {
		t.Fatal("a NODE_NETWORK-only peer must not be a witness block source")
	}

	client.drain(500 * time.Millisecond)
	forbidden := map[string]int32{
		"sendheaders": SendHeadersVersion,
		"feefilter":   FeeFilterVersion,
		"sendcmpct":   ShortIDsBlocksVersion,
		"wtxidrelay":  WTxidRelayVersion,
		"sendaddrv2":  70016,
	}
	for _, cmd := range client.commands() {
		if gate, bad := forbidden[cmd]; bad {
			t.Errorf("sent %q (needs version >= %d) to a 70002 peer; all sent: %v",
				cmd, gate, client.commands())
		}
	}
}

// TestVersionBelowMinPeerProtoDisconnects: Core disconnects a peer whose
// version is below MIN_PEER_PROTO_VERSION (31800). Master had no floor.
func TestVersionBelowMinPeerProtoDisconnects(t *testing.T) {
	peer, client, errCh, cleanup := startInbound(t)
	defer cleanup()

	client.send(clientVersion(MinPeerProtoVersion-1, ServiceNodeNetwork))
	if err := waitStart(t, errCh); err == nil {
		t.Fatal("Start() succeeded for a version-31799 peer; Core disconnects below 31800")
	}
	if peer.IsConnected() {
		t.Fatal("version-31799 peer must not be connected")
	}
	if peer.ShouldBan() {
		t.Fatal("an obsolete version is a plain disconnect, not misbehaviour")
	}
	for _, cmd := range client.commands() {
		if cmd == "verack" {
			t.Fatal("must not verack an obsolete-version peer")
		}
	}
}

// TestVersionAtMinPeerProtoKept: exactly 31800 is accepted.
func TestVersionAtMinPeerProtoKept(t *testing.T) {
	peer, client, errCh, cleanup := startInbound(t)
	defer cleanup()

	client.send(clientVersion(MinPeerProtoVersion, 0))
	if !client.waitFor("verack") {
		t.Fatalf("no verack; got %v", client.commands())
	}
	client.send(&MsgVerAck{})
	if err := waitStart(t, errCh); err != nil {
		t.Fatalf("Start() = %v, want a version-31800 peer kept", err)
	}
	if !peer.IsConnected() {
		t.Fatal("version-31800 peer must be connected")
	}
}

// TestPreVerackSendHeadersRecorded: Core processes sendheaders before verack
// (peer.m_prefers_headers = true). Master discouraged the peer.
func TestPreVerackSendHeadersRecorded(t *testing.T) {
	peer, client, errCh, cleanup := startInbound(t)
	defer cleanup()

	client.send(clientVersion(ProtocolVersion, ServiceNodeNetwork|ServiceNodeWitness))
	if !client.waitFor("verack") {
		t.Fatalf("no verack; got %v", client.commands())
	}
	client.send(&MsgSendHeaders{})
	client.send(&MsgVerAck{})
	if err := waitStart(t, errCh); err != nil {
		t.Fatalf("Start() = %v after pre-verack sendheaders", err)
	}
	client.drain(300 * time.Millisecond)
	if peer.ShouldBan() {
		t.Fatal("pre-verack sendheaders must not discourage the peer")
	}
	if !peer.IsConnected() {
		t.Fatal("pre-verack sendheaders must not disconnect the peer")
	}
	if !peer.SendsHeaders() {
		t.Fatal("pre-verack sendheaders must be recorded (Core m_prefers_headers)")
	}
}

// TestPreVerackUnsupportedIgnored: ping / inv / feefilter / getheaders between
// VERSION and VERACK are logged and ignored by Core ("Unsupported message
// prior to verack") — no disconnect, no misbehaviour, no reply. Master
// discouraged on the first one.
func TestPreVerackUnsupportedIgnored(t *testing.T) {
	peer, client, errCh, cleanup := startInbound(t)
	defer cleanup()

	client.send(clientVersion(ProtocolVersion, ServiceNodeNetwork|ServiceNodeWitness))
	if !client.waitFor("verack") {
		t.Fatalf("no verack; got %v", client.commands())
	}
	for i := 0; i < 5; i++ {
		client.send(&MsgPing{Nonce: 77})
		client.send(&MsgInv{InvList: []*InvVect{{Type: InvTypeTx, Hash: wire.Hash256{1}}}})
		client.send(&MsgFeeFilter{MinFeeRate: 1000})
	}
	client.drain(300 * time.Millisecond)
	if peer.ShouldBan() {
		t.Fatal("pre-verack ping/inv/feefilter must not discourage the peer")
	}
	if peer.FeeFilterReceived() != 0 {
		t.Fatal("pre-verack feefilter must be ignored, not applied")
	}
	for _, cmd := range client.commands() {
		if cmd == "pong" {
			t.Fatal("pre-verack ping must be ignored, not answered")
		}
	}

	client.send(&MsgVerAck{})
	if err := waitStart(t, errCh); err != nil {
		t.Fatalf("Start() = %v; the handshake must still complete", err)
	}
	if !peer.IsConnected() || peer.ShouldBan() {
		t.Fatal("peer must be connected and not discouraged after ignored pre-verack messages")
	}
}

// TestPreVersionMessageIgnored: before VERSION, Core ignores every other
// message ("non-version message before version handshake"), with no penalty.
func TestPreVersionMessageIgnored(t *testing.T) {
	peer, client, errCh, cleanup := startInbound(t)
	defer cleanup()

	client.send(&MsgPing{Nonce: 5})
	client.send(clientVersion(ProtocolVersion, ServiceNodeNetwork|ServiceNodeWitness))
	if !client.waitFor("verack") {
		t.Fatalf("no verack; got %v", client.commands())
	}
	client.send(&MsgVerAck{})
	if err := waitStart(t, errCh); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	if peer.ShouldBan() {
		t.Fatal("a pre-version ping must not discourage the peer")
	}
}

// TestRequestBlocksSkipsNonWitnessPeer: blocks are requested only from
// NODE_WITNESS peers (Core CanServeWitnesses), though non-witness peers stay
// connected.
func TestRequestBlocksSkipsNonWitnessPeer(t *testing.T) {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	pm := &PeerManager{}
	legacy := createMockPeer("legacy.example:8333", 10)
	legacy.peerVersion.Services = ServiceNodeNetwork
	witness := createMockPeer("witness.example:8333", 10)
	pm.InsertConnectedPeer(legacy)

	sm := NewSyncManager(SyncManagerConfig{
		ChainParams:    params,
		HeaderIndex:    idx,
		PeerManager:    pm,
		ChainManager:   &mockChainConnector{},
		DownloadWindow: 8,
	})
	req := &blockRequest{Hash: wire.Hash256{0xab}, Height: 1, State: BlockDownloadPending}
	sm.mu.Lock()
	sm.blockQueue = []*blockRequest{req}
	sm.mu.Unlock()

	sm.requestBlocks()
	if got := drainGetData(legacy); len(got) != 0 {
		t.Fatalf("requested %v from a non-witness peer", got)
	}
	if req.State != BlockDownloadPending {
		t.Fatalf("with only a non-witness peer the request must stay pending, state=%d", req.State)
	}

	pm.InsertConnectedPeer(witness)
	sm.requestBlocks()
	if got := drainGetData(witness); len(got) != 1 || got[0] != req.Hash {
		t.Fatalf("witness peer getdata = %v, want [%x]", got, req.Hash[:4])
	}
	if got := drainGetData(legacy); len(got) != 0 {
		t.Fatalf("requested %v from a non-witness peer", got)
	}
}

// TestGetDataNoWitnessSerialization: MSG_BLOCK / MSG_TX are answered without
// witness data, MSG_WITNESS_* with it (Core ProcessGetData).
func TestGetDataNoWitnessSerialization(t *testing.T) {
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0xffffffff},
			SignatureScript:  []byte{0x01, 0x01},
			Witness:          [][]byte{bytes.Repeat([]byte{0x00}, 32)},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
	}
	var want, gotNW, gotW bytes.Buffer
	if err := tx.SerializeNoWitness(&want); err != nil {
		t.Fatal(err)
	}
	if err := (&MsgTx{Tx: tx, NoWitness: true}).Serialize(&gotNW); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotNW.Bytes(), want.Bytes()) {
		t.Fatal("MsgTx NoWitness must serialize without witness")
	}
	if err := (&MsgTx{Tx: tx}).Serialize(&gotW); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(gotW.Bytes(), want.Bytes()) {
		t.Fatal("default MsgTx must keep the witness")
	}

	blk := &wire.MsgBlock{Transactions: []*wire.MsgTx{tx}}
	var bNW bytes.Buffer
	if err := (&MsgBlock{Block: blk, NoWitness: true}).Serialize(&bNW); err != nil {
		t.Fatal(err)
	}
	var decoded wire.MsgBlock
	if err := decoded.Deserialize(bytes.NewReader(bNW.Bytes())); err != nil {
		t.Fatalf("no-witness block must parse: %v", err)
	}
	if len(decoded.Transactions) != 1 || len(decoded.Transactions[0].TxIn[0].Witness) != 0 {
		t.Fatal("no-witness block must carry the tx without witness")
	}
}
