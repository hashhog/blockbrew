package consensus

// F0 — coin-cache RESURRECTION race (receipts/arch-f6-f7-design-2026-10-05.md
// §0 and invariant I5).
//
// GetUTXOChecked drops u.mu for its database read. Readers that do not hold
// the chain lock (gettxout via rpc extra_methods.go, the mempool's UTXO view,
// any RPC that calls UTXOSet.GetUTXO) can therefore interleave with block
// connection like this:
//
//	reader: cache miss for coin C, reads C (unspent) from the coins DB
//	chain : a block spends C (u.deleted[C] = true)
//	chain : the flush that carries the delete commits and CLEARS u.deleted
//	reader: re-checks u.deleted (now empty) and u.cache (no entry) and
//	        installs its pre-delete copy of C as a CLEAN, unspent entry
//	chain : a later block spending C again finds it in the cache -> ACCEPTED
//
// Core cannot do this: CCoinsViewCache::FetchCoin runs under cs_main, which
// also serialises ConnectBlock and FlushStateToDisk (coins.cpp:69-82,
// validation.cpp), so a base read and its insertion are atomic with respect to
// every spend and flush.
//
// The interleaving is injected deterministically with a storage.DB wrapper
// that, for one armed key, performs the real read and then parks the reader
// (holding the pre-delete bytes) until the test releases it. Nothing in the
// production code is hooked.

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// pauseReadDB parks the first Get of an armed key AFTER the inner read
// returned, so the caller holds the value as it was at read time.
type pauseReadDB struct {
	storage.DB
	mu       sync.Mutex
	key      []byte
	readDone chan struct{} // closed once the armed read has its bytes
	release  chan struct{} // the parked read returns when this is closed
}

func (p *pauseReadDB) arm(key []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key = append([]byte(nil), key...)
	p.readDone = make(chan struct{})
	p.release = make(chan struct{})
}

func (p *pauseReadDB) Get(key []byte) ([]byte, error) {
	data, err := p.DB.Get(key)
	p.mu.Lock()
	hit := p.key != nil && bytes.Equal(key, p.key)
	var done, rel chan struct{}
	if hit {
		p.key = nil // one-shot: every later read of the key is unparked
		done, rel = p.readDone, p.release
	}
	p.mu.Unlock()
	if hit {
		close(done)
		<-rel
	}
	return data, err
}

func waitOrFail(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// newF0Rig is newGate6Rig over a pauseReadDB. maxCache 0 evicts every clean
// entry at each flush, so the planted coin is cold and the reader's lookup is
// a real database read.
func newF0Rig(t *testing.T) (*gate6Rig, *pauseReadDB) {
	t.Helper()
	ResetAbortForTesting()
	t.Cleanup(ResetAbortForTesting)
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	pdb := &pauseReadDB{DB: storage.NewMemDB()}
	fdb := storage.NewFaultDB(pdb)
	chainDB := storage.NewChainDB(fdb)
	utxo := NewUTXOSetWithMaxCache(chainDB, 0)
	cm := NewChainManager(ChainManagerConfig{Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxo})
	cm.SetIBD(false)
	r := &gate6Rig{t: t, params: params, idx: idx, fdb: fdb, chainDB: chainDB, utxo: utxo, cm: cm, tip: idx.Genesis()}
	r.tip = r.connect(r.block(r.tip, nil))
	return r, pdb
}

func (r *gate6Rig) cached(op wire.OutPoint) bool {
	r.utxo.mu.RLock()
	defer r.utxo.mu.RUnlock()
	_, ok := r.utxo.cache[op]
	return ok
}

// I5, end to end through ChainManager.ConnectBlock (the at-tip path whose
// per-block StagedFlush.Commit clears u.deleted). A gettxout-style reader that
// read coin C before block b2 spent it and committed the delete must not put C
// back; block b3 spending C again must be rejected.
func TestF0_ReaderRaceDoesNotResurrectCoinAcrossBlockCommit(t *testing.T) {
	r, pdb := newF0Rig(t)
	c := r.plant(0xf0, 50_000, nil)
	if r.cached(c) {
		t.Fatal("precondition: planted coin should be cold (maxCache 0)")
	}

	// Reader: exactly what gettxout does (rpc/extra_methods.go: chainMgr.UTXOSet().GetUTXO).
	pdb.arm(storage.MakeUTXOKey(c))
	readerDone := make(chan *UTXOEntry, 1)
	go func() { readerDone <- r.utxo.GetUTXO(c) }()
	waitOrFail(t, pdb.readDone, "reader to read the unspent coin from disk")

	// Chain: b2 spends C; its atomic batch carries the delete and Commit
	// forgets the tombstone.
	b2 := r.block(r.tip, []*wire.MsgTx{spendTx(c, 40_000, 1)})
	n2 := r.connect(b2)
	if r.utxo.HasUTXODurable(c) {
		t.Fatal("precondition: b2's delete of C is not durable")
	}

	// Reader resumes with its pre-delete copy.
	close(pdb.release)
	select {
	case <-readerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("reader never returned")
	}

	resurrected := r.cached(c) || r.utxo.GetUTXO(c) != nil
	if resurrected {
		t.Errorf("RESURRECTED: coin %s:%d spent by b2 (delete durable) is unspent in the cache again",
			c.Hash.String(), c.Index)
	}

	// The consequence: a block spending C a second time.
	b3 := r.block(n2, []*wire.MsgTx{spendTx(c, 30_000, 2)})
	if err := r.cm.ConnectBlock(b3); err == nil {
		t.Fatalf("DOUBLE-SPEND ACCEPTED: block b3 (h=%d) re-spent coin %s:%d already spent by b2 (h=%d)",
			r.node(b3).Height, c.Hash.String(), c.Index, n2.Height)
	}
	if got := r.tipHash(); got == r.node(b3).Hash {
		t.Fatal("tip advanced onto a double-spend")
	}
}

// I5 on the bare UTXOSet through Flush() — the IBD MaybeFlush / scantxoutset /
// gettxoutsetinfo flush path (flushLockedDiscard), which clears u.deleted the
// same way Commit does.
func TestF0_ReaderRaceDoesNotResurrectCoinAcrossFlush(t *testing.T) {
	ResetAbortForTesting()
	t.Cleanup(ResetAbortForTesting)
	pdb := &pauseReadDB{DB: storage.NewMemDB()}
	u := NewUTXOSetWithMaxCache(storage.NewChainDB(pdb), 0)
	c := wire.OutPoint{Hash: wire.Hash256{0xf0, 0x0f}, Index: 3}
	u.AddUTXO(c, &UTXOEntry{Amount: 7, PkScript: []byte{0x51}, Height: 1})
	if err := u.Flush(); err != nil {
		t.Fatal(err)
	}

	pdb.arm(storage.MakeUTXOKey(c))
	done := make(chan *UTXOEntry, 1)
	go func() { done <- u.GetUTXO(c) }()
	waitOrFail(t, pdb.readDone, "reader read")

	if err := u.SpendUTXOChecked(c); err != nil {
		t.Fatalf("spend: %v", err)
	}
	if err := u.Flush(); err != nil {
		t.Fatal(err)
	}
	close(pdb.release)
	<-done

	if e := u.GetUTXO(c); e != nil {
		t.Errorf("RESURRECTED after flush: spent coin readable as unspent (amount %d)", e.Amount)
	}
	if err := u.SpendUTXOChecked(c); err == nil {
		t.Error("DOUBLE SPEND: SpendUTXOChecked accepted a second spend of a flushed-spent coin")
	}
}

// Control (passes on the deployed code too): the spend lands while the read
// is parked but is NOT yet flushed — the existing u.deleted re-check catches it.
func TestF0_Control_UnflushedSpendDuringReadIsCaught(t *testing.T) {
	ResetAbortForTesting()
	t.Cleanup(ResetAbortForTesting)
	pdb := &pauseReadDB{DB: storage.NewMemDB()}
	u := NewUTXOSetWithMaxCache(storage.NewChainDB(pdb), 0)
	c := wire.OutPoint{Hash: wire.Hash256{0xf0, 0x0c}, Index: 0}
	u.AddUTXO(c, &UTXOEntry{Amount: 7, PkScript: []byte{0x51}, Height: 1})
	if err := u.Flush(); err != nil {
		t.Fatal(err)
	}
	pdb.arm(storage.MakeUTXOKey(c))
	done := make(chan *UTXOEntry, 1)
	go func() { done <- u.GetUTXO(c) }()
	waitOrFail(t, pdb.readDone, "reader read")
	if err := u.SpendUTXOChecked(c); err != nil {
		t.Fatalf("spend: %v", err)
	}
	close(pdb.release)
	<-done
	if e := u.GetUTXO(c); e != nil {
		t.Error("unflushed spend during a parked read resurrected the coin")
	}
}

// Control: a reader that races nothing still warms the cache (the fix must
// not turn read-through into read-around).
func TestF0_Control_QuietReadStillCaches(t *testing.T) {
	ResetAbortForTesting()
	t.Cleanup(ResetAbortForTesting)
	u := NewUTXOSetWithMaxCache(storage.NewChainDB(storage.NewMemDB()), 0)
	c := wire.OutPoint{Hash: wire.Hash256{0xf0, 0x0d}, Index: 1}
	u.AddUTXO(c, &UTXOEntry{Amount: 9, PkScript: []byte{0x51}, Height: 1})
	if err := u.Flush(); err != nil {
		t.Fatal(err)
	}
	u.mu.RLock()
	_, pre := u.cache[c]
	u.mu.RUnlock()
	if pre {
		t.Fatal("precondition: coin should be cold")
	}
	if e := u.GetUTXO(c); e == nil || e.Amount != 9 {
		t.Fatalf("read: got %+v", e)
	}
	u.mu.RLock()
	_, post := u.cache[c]
	u.mu.RUnlock()
	if !post {
		t.Error("an uncontended read no longer populates the cache")
	}
}
