package rpc

import "testing"

// Core's testmempoolaccept emits "reject-details" = state.ToString() for every
// non-missing-inputs rejection (rpc/mempool.cpp:402-403). For the PreChecks
// states "txn-already-in-mempool" and "txn-already-known" there is no debug
// message, so ToString() is the reject reason itself.

func TestTestMempoolAcceptRejectDetails_InMempool(t *testing.T) {
	s, mp, op := pkgServer(t, 0xe1)
	tx := pkgSpend(op, pkgFunding-1_000)
	if err := mp.AcceptToMemoryPool(tx); err != nil {
		t.Fatalf("seed mempool: %v", err)
	}
	r := runTMA(t, s, pkgHex(t, tx))
	if r.Allowed || r.RejectReason != "txn-already-in-mempool" {
		t.Fatalf("allowed=%v reject-reason=%q, want false txn-already-in-mempool", r.Allowed, r.RejectReason)
	}
	if r.RejectDetails != "txn-already-in-mempool" {
		t.Errorf("reject-details = %q, want %q", r.RejectDetails, "txn-already-in-mempool")
	}
}

func TestTestMempoolAcceptRejectDetails_Confirmed(t *testing.T) {
	var parent [32]byte
	parent[0] = 0xc7
	tx, txHex := srtxTx(parent)
	view := unbroadcastUTXOView{{Hash: tx.TxHash(), Index: 0}: {Amount: 990_000, PkScript: tx.TxOut[0].PkScript, Height: 5}}
	server, _ := srtxServer(view)
	r := runTMA(t, server, txHex)
	if r.Allowed || r.RejectReason != "txn-already-known" {
		t.Fatalf("allowed=%v reject-reason=%q, want false txn-already-known", r.Allowed, r.RejectReason)
	}
	if r.RejectDetails != "txn-already-known" {
		t.Errorf("reject-details = %q, want %q", r.RejectDetails, "txn-already-known")
	}
}
