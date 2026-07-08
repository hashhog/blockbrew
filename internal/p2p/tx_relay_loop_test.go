// Tests for the inv->getdata->tx relay loop wiring added to HandleInv
// (REQUEST side) and HandleGetData (SERVE side).
//
// Reference: Bitcoin Core net_processing.cpp — inv handling feeds tx
// announcements into the TxRequestTracker and issues a getdata for each
// not-already-known tx; getdata handling (ProcessGetData -> FindTxForGetData)
// serves the tx from the mempool or replies notfound.
package p2p

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// stubMempool is a minimal MempoolTxSource for message-level relay tests.
type stubMempool struct {
	byTxid  map[wire.Hash256]*wire.MsgTx
	byWtxid map[wire.Hash256]*wire.MsgTx
}

func newStubMempool() *stubMempool {
	return &stubMempool{
		byTxid:  make(map[wire.Hash256]*wire.MsgTx),
		byWtxid: make(map[wire.Hash256]*wire.MsgTx),
	}
}

func (s *stubMempool) add(tx *wire.MsgTx) {
	s.byTxid[tx.TxHash()] = tx
	s.byWtxid[tx.WTxHash()] = tx
}

func (s *stubMempool) HasTransaction(txid wire.Hash256) bool {
	_, ok := s.byTxid[txid]
	return ok
}
func (s *stubMempool) GetTransaction(txid wire.Hash256) *wire.MsgTx { return s.byTxid[txid] }
func (s *stubMempool) GetTxByWTxid(wtxid wire.Hash256) *wire.MsgTx  { return s.byWtxid[wtxid] }

// Compile-time assurance the stub satisfies the interface.
var _ MempoolTxSource = (*stubMempool)(nil)

// simpleTestTx returns a minimal, deterministic transaction. `n` seeds the
// input's sequence so distinct calls produce distinct txids.
func simpleTestTx(n uint32) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: n},
				SignatureScript:  []byte{0x01, byte(n)},
				Sequence:         0xFFFFFFFF,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 1000, PkScript: []byte{0x51}},
		},
	}
}

// drainSent non-blockingly collects all messages currently queued on the peer.
func drainSent(peer *Peer) []Message {
	var out []Message
	for {
		select {
		case msg := <-peer.sendQueue:
			out = append(out, msg)
		default:
			return out
		}
	}
}

func newRelayTestSyncManager(mp MempoolTxSource) *SyncManager {
	params := consensus.RegtestParams()
	idx := consensus.NewHeaderIndex(params)
	sm := NewSyncManager(SyncManagerConfig{
		ChainParams: params,
		HeaderIndex: idx,
		Mempool:     mp,
	})
	// Simulate a synced node: the tx-request path is IBD-gated.
	sm.ibdActive.Store(false)
	return sm
}

// TestHandleInv_RequestsUnknownTx: a tx-inv for a tx we don't have emits a
// getdata for exactly that tx.
func TestHandleInv_RequestsUnknownTx(t *testing.T) {
	mp := newStubMempool()
	sm := newRelayTestSyncManager(mp)
	peer := createMockPeer("1.2.3.4:8333", 100)

	tx := simpleTestTx(1)
	txid := tx.TxHash()

	sm.HandleInv(peer, &MsgInv{InvList: []*InvVect{
		{Type: InvTypeTx, Hash: txid},
	}})

	sent := drainSent(peer)
	var gd *MsgGetData
	for _, m := range sent {
		if g, ok := m.(*MsgGetData); ok {
			gd = g
		}
	}
	if gd == nil {
		t.Fatalf("expected a getdata for the unknown tx, got %d messages: %#v", len(sent), sent)
	}
	if len(gd.InvList) != 1 {
		t.Fatalf("getdata InvList len = %d, want 1", len(gd.InvList))
	}
	if gd.InvList[0].Type != InvTypeTx || gd.InvList[0].Hash != txid {
		t.Errorf("getdata inv = {type 0x%x, hash %x}, want {InvTypeTx, %x}",
			gd.InvList[0].Type, gd.InvList[0].Hash[:4], txid[:4])
	}

	// The tx must now be recorded in-flight for dedup.
	sm.mu.RLock()
	_, inflight := sm.txInflight[txid]
	sm.mu.RUnlock()
	if !inflight {
		t.Error("expected requested tx to be marked in-flight")
	}
}

// TestHandleInv_WtxRelayRequestsWtxid: a wtxid-relay peer's MSG_WTX inv is
// requested as MSG_WTX + wtxid (BIP-339).
func TestHandleInv_WtxRelayRequestsWtxid(t *testing.T) {
	mp := newStubMempool()
	sm := newRelayTestSyncManager(mp)
	peer := createMockPeer("1.2.3.4:8333", 100)
	peer.wtxidRelaySupported = true

	tx := simpleTestTx(7)
	wtxid := tx.WTxHash()

	sm.HandleInv(peer, &MsgInv{InvList: []*InvVect{
		{Type: InvTypeWtx, Hash: wtxid},
	}})

	var gd *MsgGetData
	for _, m := range drainSent(peer) {
		if g, ok := m.(*MsgGetData); ok {
			gd = g
		}
	}
	if gd == nil || len(gd.InvList) != 1 {
		t.Fatalf("expected one getdata inv for the wtxid announcement, got %#v", gd)
	}
	if gd.InvList[0].Type != InvTypeWtx || gd.InvList[0].Hash != wtxid {
		t.Errorf("getdata inv = {type 0x%x, hash %x}, want {InvTypeWtx, %x}",
			gd.InvList[0].Type, gd.InvList[0].Hash[:4], wtxid[:4])
	}
}

// TestHandleInv_SkipsTxAlreadyInMempool: no getdata for a tx we already have.
func TestHandleInv_SkipsTxAlreadyInMempool(t *testing.T) {
	mp := newStubMempool()
	tx := simpleTestTx(2)
	mp.add(tx)

	sm := newRelayTestSyncManager(mp)
	peer := createMockPeer("1.2.3.4:8333", 100)

	sm.HandleInv(peer, &MsgInv{InvList: []*InvVect{
		{Type: InvTypeTx, Hash: tx.TxHash()},
	}})

	for _, m := range drainSent(peer) {
		if _, ok := m.(*MsgGetData); ok {
			t.Fatalf("must NOT request a tx already in the mempool")
		}
	}
}

// TestHandleInv_SkipsTxAlreadyInFlight: a second announcement of the same tx
// (already in-flight) must not re-request it.
func TestHandleInv_SkipsTxAlreadyInFlight(t *testing.T) {
	mp := newStubMempool()
	sm := newRelayTestSyncManager(mp)
	peerA := createMockPeer("1.1.1.1:8333", 100)
	peerB := createMockPeer("2.2.2.2:8333", 100)

	tx := simpleTestTx(3)
	inv := &MsgInv{InvList: []*InvVect{{Type: InvTypeTx, Hash: tx.TxHash()}}}

	// First announcer → one getdata.
	sm.HandleInv(peerA, inv)
	gotA := 0
	for _, m := range drainSent(peerA) {
		if _, ok := m.(*MsgGetData); ok {
			gotA++
		}
	}
	if gotA != 1 {
		t.Fatalf("first announcer: want 1 getdata, got %d", gotA)
	}

	// Second announcer for the same (still in-flight) tx → no getdata.
	sm.HandleInv(peerB, inv)
	for _, m := range drainSent(peerB) {
		if _, ok := m.(*MsgGetData); ok {
			t.Fatalf("second announcer must NOT re-request an in-flight tx")
		}
	}
}

// TestHandleInv_SkipsDuringIBD: the tx-request path is disabled during IBD.
func TestHandleInv_SkipsDuringIBD(t *testing.T) {
	mp := newStubMempool()
	sm := newRelayTestSyncManager(mp)
	sm.ibdActive.Store(true) // still in IBD
	peer := createMockPeer("1.2.3.4:8333", 100)

	tx := simpleTestTx(4)
	sm.HandleInv(peer, &MsgInv{InvList: []*InvVect{
		{Type: InvTypeTx, Hash: tx.TxHash()},
	}})

	for _, m := range drainSent(peer) {
		if _, ok := m.(*MsgGetData); ok {
			t.Fatalf("must NOT request txs during IBD")
		}
	}
}

// TestHandleInv_SkipsBlockRelayOnlyPeer: no tx requests on block-relay-only links.
func TestHandleInv_SkipsBlockRelayOnlyPeer(t *testing.T) {
	mp := newStubMempool()
	sm := newRelayTestSyncManager(mp)
	peer := createMockPeer("1.2.3.4:8333", 100)
	peer.config.DisableRelayTx = true // block-relay-only

	tx := simpleTestTx(5)
	sm.HandleInv(peer, &MsgInv{InvList: []*InvVect{
		{Type: InvTypeTx, Hash: tx.TxHash()},
	}})

	for _, m := range drainSent(peer) {
		if _, ok := m.(*MsgGetData); ok {
			t.Fatalf("must NOT request txs from a block-relay-only peer")
		}
	}
}

// TestHandleInv_ExpiredInFlightReRequested: an in-flight slot older than
// txInflightExpiry may be re-requested.
func TestHandleInv_ExpiredInFlightReRequested(t *testing.T) {
	mp := newStubMempool()
	sm := newRelayTestSyncManager(mp)
	peer := createMockPeer("1.2.3.4:8333", 100)

	tx := simpleTestTx(6)
	txid := tx.TxHash()

	// Pre-seed an expired in-flight entry.
	sm.mu.Lock()
	sm.txInflight[txid] = time.Now().Add(-2 * txInflightExpiry)
	sm.mu.Unlock()

	sm.HandleInv(peer, &MsgInv{InvList: []*InvVect{{Type: InvTypeTx, Hash: txid}}})

	got := 0
	for _, m := range drainSent(peer) {
		if _, ok := m.(*MsgGetData); ok {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("expired in-flight tx should be re-requested once, got %d getdata", got)
	}
}

// TestHandleGetData_ServesTxFromMempool: getdata for a tx in the mempool is
// answered with a MsgTx.
func TestHandleGetData_ServesTxFromMempool(t *testing.T) {
	mp := newStubMempool()
	tx := simpleTestTx(11)
	mp.add(tx)

	sm := newRelayTestSyncManager(mp)
	peer := createMockPeer("1.2.3.4:8333", 100)

	sm.HandleGetData(peer, &MsgGetData{InvList: []*InvVect{
		{Type: InvTypeTx, Hash: tx.TxHash()},
	}})

	var served *MsgTx
	for _, m := range drainSent(peer) {
		if mt, ok := m.(*MsgTx); ok {
			served = mt
		}
		if _, ok := m.(*MsgNotFound); ok {
			t.Fatalf("must not send notfound for a tx we have")
		}
	}
	if served == nil {
		t.Fatalf("expected a MsgTx serving the mempool tx")
	}
	if served.Tx.TxHash() != tx.TxHash() {
		t.Errorf("served tx %x, want %x", func() []byte { h := served.Tx.TxHash(); return h[:4] }(), tx.TxHash())
	}
}

// TestHandleGetData_ServesWtxidFromMempool: getdata MSG_WTX resolves via wtxid.
func TestHandleGetData_ServesWtxidFromMempool(t *testing.T) {
	mp := newStubMempool()
	tx := simpleTestTx(12)
	mp.add(tx)

	sm := newRelayTestSyncManager(mp)
	peer := createMockPeer("1.2.3.4:8333", 100)

	sm.HandleGetData(peer, &MsgGetData{InvList: []*InvVect{
		{Type: InvTypeWtx, Hash: tx.WTxHash()},
	}})

	var served *MsgTx
	for _, m := range drainSent(peer) {
		if mt, ok := m.(*MsgTx); ok {
			served = mt
		}
	}
	if served == nil || served.Tx.WTxHash() != tx.WTxHash() {
		t.Fatalf("expected MsgTx matching wtxid %x", tx.WTxHash())
	}
}

// TestHandleGetData_NotFoundOnMiss: getdata for an unknown tx yields notfound.
func TestHandleGetData_NotFoundOnMiss(t *testing.T) {
	mp := newStubMempool()
	sm := newRelayTestSyncManager(mp)
	peer := createMockPeer("1.2.3.4:8333", 100)

	tx := simpleTestTx(13) // never added
	sm.HandleGetData(peer, &MsgGetData{InvList: []*InvVect{
		{Type: InvTypeTx, Hash: tx.TxHash()},
	}})

	var nf *MsgNotFound
	for _, m := range drainSent(peer) {
		if n, ok := m.(*MsgNotFound); ok {
			nf = n
		}
		if _, ok := m.(*MsgTx); ok {
			t.Fatalf("must not serve a tx we do not have")
		}
	}
	if nf == nil || len(nf.InvList) != 1 || nf.InvList[0].Hash != tx.TxHash() {
		t.Fatalf("expected notfound listing the missing tx, got %#v", nf)
	}
}

// TestNotifyTxReceived_ClearsInFlight: receiving a tx clears its dedup slot.
func TestNotifyTxReceived_ClearsInFlight(t *testing.T) {
	mp := newStubMempool()
	sm := newRelayTestSyncManager(mp)
	tx := simpleTestTx(14)
	txid, wtxid := tx.TxHash(), tx.WTxHash()

	sm.mu.Lock()
	sm.txInflight[txid] = time.Now()
	sm.mu.Unlock()

	sm.NotifyTxReceived(txid, wtxid)

	sm.mu.RLock()
	_, still := sm.txInflight[txid]
	sm.mu.RUnlock()
	if still {
		t.Error("NotifyTxReceived should clear the in-flight slot")
	}
}
