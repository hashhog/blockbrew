package mempool

// AcceptPackage must not mutate the shared OnTxEvicted subscriber.
//
// Before this fix acceptSingleTxPackage saved mp.OnTxEvicted, installed a
// wrapper that collected REPLACED evictions into its own result, and restored
// the saved value on return, all without holding mp.mu. Two overlapping calls
// (two peers' unsolicited pkgtxns, or a peer and submitpackage) restore out of
// order: the later restore reinstates the other call's wrapper, which then
// stays installed for good, routes every future eviction through a finished
// call's result, and grows a chain of wrappers. Each call's
// replaced-transactions list could also miss its own replacement or pick up
// another call's.
//
// Core (validation.cpp MemPoolAccept::AcceptPackage / AcceptSingleTransaction)
// collects m_replaced_transactions in per-call state (Workspace / ATMPArgs)
// and never touches a shared callback; TransactionRemovedFromMempool is
// signalled once per removal to the registered subscribers.

import (
	"reflect"
	"sync"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// raceFundedMempool is spendableMempool with n confirmed anyone-can-spend
// UTXOs, one per goroutine.
func raceFundedMempool(n int, amount int64) (*Mempool, []wire.OutPoint) {
	utxoSet := newTestUTXOSet()
	ops := make([]wire.OutPoint, n)
	for i := range ops {
		var h wire.Hash256
		h[0] = 0xe7
		h[1] = byte(i)
		ops[i] = wire.OutPoint{Hash: h, Index: 0}
		utxoSet.AddUTXO(ops[i], &consensus.UTXOEntry{
			Amount:   amount,
			PkScript: p2shAnyoneCanSpendScript(),
			Height:   1,
		})
	}
	mp := New(Config{
		MaxSize:                10_000_000,
		MinRelayFeeRate:        1000,
		MaxOrphanTxs:           100,
		ChainParams:            consensus.RegtestParams(),
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, utxoSet)
	mp.SetChainHeight(800_000)
	return mp, ops
}

func TestAcceptPackageDoesNotMutateOnTxEvicted(t *testing.T) {
	const (
		goroutines = 8
		rounds     = 40
		amount     = 1_000_000
		feeStep    = 1_000
	)
	mp, ops := raceFundedMempool(goroutines, amount)

	var cbMu sync.Mutex
	evicted := make(map[wire.Hash256]int)
	reasons := make(map[wire.Hash256]MemPoolRemovalReason)
	original := func(h wire.Hash256, r MemPoolRemovalReason) {
		cbMu.Lock()
		evicted[h]++
		reasons[h] = r
		cbMu.Unlock()
	}
	mp.OnTxEvicted = original
	origPtr := reflect.ValueOf(mp.OnTxEvicted).Pointer()

	type failure struct {
		g, r int
		msg  string
		got  []wire.Hash256
		want wire.Hash256
	}
	failures := make(chan failure, goroutines*rounds)
	replacedIDs := make(chan wire.Hash256, goroutines*rounds)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			var prev wire.Hash256
			for r := 0; r < rounds; r++ {
				// Each round replaces the previous round's tx (same input,
				// higher fee, full-RBF).
				tx := spendableTx(ops[g], amount-int64(feeStep*(r+1)), 1)
				res, err := mp.AcceptPackage([]*wire.MsgTx{tx})
				if err != nil {
					failures <- failure{g: g, r: r, msg: "AcceptPackage: " + err.Error()}
					return
				}
				if r == 0 {
					if len(res.ReplacedTxs) != 0 {
						failures <- failure{g: g, r: r, msg: "first tx reports replacements", got: res.ReplacedTxs}
					}
				} else {
					replacedIDs <- prev
					if len(res.ReplacedTxs) != 1 || res.ReplacedTxs[0] != prev {
						failures <- failure{g: g, r: r, msg: "replaced-transactions is not exactly this call's victim", got: res.ReplacedTxs, want: prev}
					}
				}
				prev = tx.TxHash()
			}
		}(g)
	}
	wg.Wait()
	close(failures)
	close(replacedIDs)

	n := 0
	for f := range failures {
		if n < 10 {
			t.Errorf("goroutine %d round %d: %s (got %v, want [%v])", f.g, f.r, f.msg, f.got, f.want)
		}
		n++
	}
	if n > 10 {
		t.Errorf("... %d failures in total", n)
	}

	if got := reflect.ValueOf(mp.OnTxEvicted).Pointer(); got != origPtr {
		t.Errorf("OnTxEvicted was left replaced by a wrapper after AcceptPackage returned (ptr %#x, want %#x)", got, origPtr)
	}

	cbMu.Lock()
	for h := range replacedIDs {
		if c := evicted[h]; c != 1 {
			t.Errorf("original OnTxEvicted saw replaced tx %v %d times, want exactly 1", h, c)
		} else if reasons[h] != MempoolRemovalReasonReplaced {
			t.Errorf("replaced tx %v reported with reason %v, want REPLACED", h, reasons[h])
		}
	}
	cbMu.Unlock()

	// A removal after the packages reaches the original subscriber exactly
	// once, and no finished call's wrapper sees it.
	survivor := spendableTx(ops[0], amount-int64(feeStep*rounds), 1).TxHash()
	if !mp.HasTransaction(survivor) {
		t.Fatalf("fixture: last-round tx %v not in the mempool", survivor)
	}
	mp.RemoveTransactionWithReason(survivor, MempoolRemovalReasonReplaced)
	cbMu.Lock()
	if c := evicted[survivor]; c != 1 {
		t.Errorf("post-package removal reached the original callback %d times, want 1", c)
	}
	cbMu.Unlock()
}

// TestAcceptMultiTxPackageReportsReplaced pins the multi-transaction path's
// replaced-transactions list after the per-call collector replaced the
// OnTxEvicted swap there too: a parent that is valid alone and replaces an
// in-mempool tx (single-transaction RBF inside the package's individual
// pass) is reported, the subscriber is called once, and left unchanged.
func TestAcceptMultiTxPackageReportsReplaced(t *testing.T) {
	const amount = 1_000_000
	mp, ops := raceFundedMempool(1, amount)

	calls := 0
	mp.OnTxEvicted = func(wire.Hash256, MemPoolRemovalReason) { calls++ }
	origPtr := reflect.ValueOf(mp.OnTxEvicted).Pointer()

	victim := spendableTx(ops[0], amount-1_000, 1)
	if err := mp.AddTransaction(victim); err != nil {
		t.Fatalf("fixture: victim: %v", err)
	}
	parent, child := cpfpPair(ops[0], amount, 5_000, 5_000)
	res, err := mp.AcceptPackage([]*wire.MsgTx{parent, child})
	if err != nil {
		t.Fatalf("AcceptPackage: %v", err)
	}
	if len(res.ReplacedTxs) != 1 || res.ReplacedTxs[0] != victim.TxHash() {
		t.Fatalf("ReplacedTxs = %v, want [%v]", res.ReplacedTxs, victim.TxHash())
	}
	if calls != 1 {
		t.Fatalf("OnTxEvicted called %d times, want 1", calls)
	}
	if got := reflect.ValueOf(mp.OnTxEvicted).Pointer(); got != origPtr {
		t.Fatalf("OnTxEvicted left replaced after AcceptPackage")
	}
}
