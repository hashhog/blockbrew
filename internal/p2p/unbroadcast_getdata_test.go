package p2p

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

type unbroadcastStub struct {
	*stubMempool
	cleared int
}

func (u *unbroadcastStub) RemoveUnbroadcastTx(txid wire.Hash256) { u.cleared++ }

// A served tx getdata clears the unbroadcast mark; a notfound does not.
func TestHandleGetData_ServedTxClearsUnbroadcast(t *testing.T) {
	stub := &unbroadcastStub{stubMempool: newStubMempool()}
	tx := simpleTestTx(3)
	stub.add(tx)
	sm := newRelayTestSyncManager(stub)
	peer := createMockPeer("1.2.3.4:8333", 100)

	sm.HandleGetData(peer, &MsgGetData{InvList: []*InvVect{{Type: InvTypeTx, Hash: simpleTestTx(99).TxHash()}}})
	if stub.cleared != 0 {
		t.Fatalf("notfound getdata cleared the mark (%d)", stub.cleared)
	}
	sm.HandleGetData(peer, &MsgGetData{InvList: []*InvVect{{Type: InvTypeTx, Hash: tx.TxHash()}}})
	if stub.cleared != 1 {
		t.Fatalf("served getdata cleared %d times, want 1", stub.cleared)
	}
}
