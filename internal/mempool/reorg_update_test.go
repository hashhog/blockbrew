package mempool

import (
	"sort"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Regression tests for the mempool across invalidateblock and a reorg, the
// unit-level twin of tools/mempool-reorg-sweep.py (same vectors). They drive
// the mempool in the order the chain manager does — the tip moves first, then
// the block's hook fires — and assert the pool Bitcoin Core ends with
// (validation.cpp MaybeUpdateMempoolForReorg, txmempool.cpp removeForReorg /
// removeForBlock / removeRecursive / UpdateTransactionsFromBlock).
//
// The reorg update is reached through an interface assertion so the tests
// build against a tree without it; there they fail on the pool contents, which
// is the bug (audit 2026-10-07 BB-6): transactions re-added one block at a
// time against intermediate tips, no removeForReorg, and re-added parents never
// linked to their in-mempool children.

type reorgUpdater interface {
	UpdateForReorg(addToMempool bool) (int, int)
}

func runReorgUpdate(mp *Mempool, add bool) {
	if u, ok := any(mp).(reorgUpdater); ok {
		u.UpdateForReorg(add)
	}
}

// reorgChain is a tiny chain over a testUTXOSet: blocks apply and undo their
// coins and move the mock tip, the way ChainManager does before it calls the
// mempool hook.
type reorgChain struct {
	t     *testing.T
	utxos *testUTXOSet
	cs    *mockChainState
	undo  map[*wire.MsgBlock]map[wire.OutPoint]*consensus.UTXOEntry
}

const reorgFee = 10_000

func newReorgChain(t *testing.T) *reorgChain {
	c := &reorgChain{
		t:     t,
		utxos: newTestUTXOSet(),
		cs:    &mockChainState{height: 0, mtp: 1_700_000_000},
		undo:  make(map[*wire.MsgBlock]map[wire.OutPoint]*consensus.UTXOEntry),
	}
	return c
}

func reorgCoinbaseOutpoint(h int32) wire.OutPoint {
	var hash wire.Hash256
	hash[0] = 0xC0
	hash[1] = byte(h)
	hash[2] = byte(h >> 8)
	return wire.OutPoint{Hash: hash, Index: 0}
}

func reorgCoinbase(tag byte, h int32) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0xFFFFFFFF},
			SignatureScript:  []byte{0x03, tag, byte(h), byte(h >> 8)},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 50_0000_0000, PkScript: p2shAnyoneCanSpendScript()}},
	}
}

// spend1 mirrors the sweep's spend1: one input, one P2SH(OP_TRUE) output,
// fee 10k sat.
func spend1(prev wire.OutPoint, value int64, seq uint32, lockTime uint32) *wire.MsgTx {
	return &wire.MsgTx{
		Version:  2,
		LockTime: lockTime,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: prev,
			SignatureScript:  []byte{0x01, 0x51},
			Sequence:         seq,
		}},
		TxOut: []*wire.TxOut{{Value: value - reorgFee, PkScript: p2shAnyoneCanSpendScript()}},
	}
}

func (c *reorgChain) block(tag byte, h int32, txs ...*wire.MsgTx) *wire.MsgBlock {
	return &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 0x20000000},
		Transactions: append([]*wire.MsgTx{reorgCoinbase(tag, h)}, txs...),
	}
}

func (c *reorgChain) apply(b *wire.MsgBlock, h int32) {
	undo := make(map[wire.OutPoint]*consensus.UTXOEntry)
	for i, tx := range b.Transactions {
		if i > 0 {
			for _, in := range tx.TxIn {
				coin := c.utxos.utxos[in.PreviousOutPoint]
				if coin == nil {
					c.t.Fatalf("block at %d spends missing coin %v", h, in.PreviousOutPoint)
				}
				undo[in.PreviousOutPoint] = coin
				delete(c.utxos.utxos, in.PreviousOutPoint)
			}
		}
		txid := tx.TxHash()
		for j, out := range tx.TxOut {
			c.utxos.utxos[wire.OutPoint{Hash: txid, Index: uint32(j)}] = &consensus.UTXOEntry{
				Amount: out.Value, PkScript: out.PkScript, Height: h, IsCoinbase: i == 0,
			}
		}
	}
	c.undo[b] = undo
	c.cs.height = h
	c.cs.mtp += 600
}

func (c *reorgChain) unapply(b *wire.MsgBlock, h int32) {
	for _, tx := range b.Transactions {
		txid := tx.TxHash()
		for j := range tx.TxOut {
			delete(c.utxos.utxos, wire.OutPoint{Hash: txid, Index: uint32(j)})
		}
	}
	for op, coin := range c.undo[b] {
		c.utxos.utxos[op] = coin
	}
	c.cs.height = h - 1
	c.cs.mtp -= 600
}

type reorgFixture struct {
	chain      *reorgChain
	mp         *Mempool
	b111, b112 *wire.MsgBlock
	names      map[wire.Hash256]string
	cbs        map[int32]wire.OutPoint
	cbValue    int64
	tx         map[string]*wire.MsgTx
}

// newReorgFixture builds the sweep's chain to tip 112 and its mempool
// {M1, M2, M3}:
//
//	111: [cb, A1 <- cb1, P <- cb2]
//	112: [cb, A2 <- cb3, C <- P:0, IMM <- cb12, LT <- cb4 (nLockTime 111),
//	      B68 <- cb5 (nSequence 107), D <- B68:0]
//	mempool: M1 <- A2:0, M2 <- A1:0, M3 <- cb6
func newReorgFixture(t *testing.T) *reorgFixture {
	c := newReorgChain(t)
	f := &reorgFixture{
		chain:   c,
		names:   make(map[wire.Hash256]string),
		cbs:     make(map[int32]wire.OutPoint),
		cbValue: 50_0000_0000,
		tx:      make(map[string]*wire.MsgTx),
	}
	// Coinbase coins for heights 1..110 (the chain below the fork).
	for h := int32(1); h <= 110; h++ {
		op := reorgCoinbaseOutpoint(h)
		f.cbs[h] = op
		c.utxos.utxos[op] = &consensus.UTXOEntry{
			Amount: f.cbValue, PkScript: p2shAnyoneCanSpendScript(), Height: h, IsCoinbase: true,
		}
	}
	c.cs.height = 110
	name := func(n string, tx *wire.MsgTx) *wire.MsgTx {
		f.tx[n] = tx
		f.names[tx.TxHash()] = n
		return tx
	}
	out0 := func(tx *wire.MsgTx) wire.OutPoint { return wire.OutPoint{Hash: tx.TxHash(), Index: 0} }
	v := f.cbValue

	a1 := name("A1", spend1(f.cbs[1], v, 0xfffffffe, 0))
	p := name("P", spend1(f.cbs[2], v, 0xfffffffe, 0))
	f.b111 = c.block('m', 111, a1, p)
	c.apply(f.b111, 111)

	a2 := name("A2", spend1(f.cbs[3], v, 0xfffffffe, 0))
	cc := name("C", spend1(out0(p), v-reorgFee, 0xfffffffe, 0))
	imm := name("IMM", spend1(f.cbs[12], v, 0xfffffffe, 0))
	lt := name("LT", spend1(f.cbs[4], v, 0xfffffffe, 111))
	b68 := name("B68", spend1(f.cbs[5], v, 107, 0))
	d := name("D", spend1(out0(b68), v-reorgFee, 0xfffffffe, 0))
	f.b112 = c.block('m', 112, a2, cc, imm, lt, b68, d)
	c.apply(f.b112, 112)

	f.mp = New(Config{
		MaxSize:                300_000_000,
		MinRelayFeeRate:        1000,
		IncrementalRelayFee:    1000,
		MaxOrphanTxs:           10,
		ChainParams:            consensus.RegtestParams(),
		ChainState:             c.cs,
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, c.utxos)
	for _, n := range []string{"M1", "M2", "M3"} {
		var tx *wire.MsgTx
		switch n {
		case "M1":
			tx = spend1(out0(a2), v-reorgFee, 0xfffffffe, 0)
		case "M2":
			tx = spend1(out0(a1), v-reorgFee, 0xfffffffe, 0)
		case "M3":
			tx = spend1(f.cbs[6], v, 0xfffffffe, 0)
		}
		name(n, tx)
		if err := f.mp.AddTransaction(tx); err != nil {
			t.Fatalf("admit %s at tip 112: %v", n, err)
		}
	}
	return f
}

func (f *reorgFixture) pool() []string {
	var out []string
	for _, h := range f.mp.GetAllTxHashes() {
		n, ok := f.names[h]
		if !ok {
			n = h.String()[:12]
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func assertPool(t *testing.T, label string, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("%s: mempool = %v, want %v (Core)", label, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s: mempool = %v, want %v (Core)", label, got, want)
		}
	}
}

func hasHash(hs []wire.Hash256, h wire.Hash256) bool {
	for _, x := range hs {
		if x == h {
			return true
		}
	}
	return false
}

// TestReorgUpdate_InvalidateDropsTxsInvalidAtNewTip is sweep row (a):
// invalidateblock 111 from tip 112. Core re-accepts the disconnected txs and
// then removeForReorg drops IMM (cb12 immature at 111), LT (nLockTime 111 is
// non-final at 111), B68 (BIP68: 111-5 < 107) and D (descendant of B68).
// Re-added A1 / A2 / P adopt their in-mempool children M2 / M1 / C.
func TestReorgUpdate_InvalidateDropsTxsInvalidAtNewTip(t *testing.T) {
	f := newReorgFixture(t)

	// InvalidateBlock: tip 112 -> 111 -> 110, update after EACH block.
	f.chain.unapply(f.b112, 112)
	f.mp.BlockDisconnected(f.b112)
	runReorgUpdate(f.mp, true)
	f.chain.unapply(f.b111, 111)
	f.mp.BlockDisconnected(f.b111)
	runReorgUpdate(f.mp, true)

	assertPool(t, "after invalidateblock 111", f.pool(), "A1", "P", "A2", "C", "M1", "M2", "M3")

	// UpdateTransactionsFromBlock: the re-added parents own their children.
	if !hasHash(f.mp.GetDescendants(f.tx["A1"].TxHash()), f.tx["M2"].TxHash()) {
		t.Error("M2 is not a descendant of re-added A1")
	}
	if !hasHash(f.mp.GetAncestors(f.tx["M1"].TxHash()), f.tx["A2"].TxHash()) {
		t.Error("A2 is not an ancestor of M1")
	}
	if !hasHash(f.mp.GetAncestors(f.tx["C"].TxHash()), f.tx["P"].TxHash()) {
		t.Error("P is not an ancestor of C")
	}
	e := f.mp.GetEntry(f.tx["A1"].TxHash())
	m2 := f.mp.GetEntry(f.tx["M2"].TxHash())
	if e == nil || m2 == nil || e.DescendantFee != e.Fee+m2.Fee || m2.AncestorFee != e.Fee+m2.Fee {
		t.Errorf("package fees not updated: A1 desc=%v M2 anc=%v", e, m2)
	}
	if c := f.mp.GetCluster(f.tx["A1"].TxHash()); c == nil || c != f.mp.GetCluster(f.tx["M2"].TxHash()) {
		t.Error("A1 and M2 are not in one cluster")
	}

	// reconsiderblock 111: both blocks come back; their txs leave the pool,
	// the in-mempool children stay (sweep row (b)).
	f.chain.apply(f.b111, 111)
	f.mp.BlockConnected(f.b111)
	f.chain.apply(f.b112, 112)
	f.mp.BlockConnected(f.b112)
	runReorgUpdate(f.mp, true)
	assertPool(t, "after reconsiderblock 111", f.pool(), "M1", "M2", "M3")
}

// TestReorgUpdate_BranchConflictsDropChildren is sweep row (c): a P2P reorg
// from 112 to 113b, where 111b's X spends A1's input and 113b's Z spends M3's.
// A1 cannot be re-accepted, so Core's removeRecursive takes its in-mempool
// child M2; M3 goes as a conflict of Z; P is confirmed again in 112b.
func TestReorgUpdate_BranchConflictsDropChildren(t *testing.T) {
	f := newReorgFixture(t)
	v := f.cbValue

	x := spend1(f.cbs[1], v-1, 0xfffffffe, 0)
	f.names[x.TxHash()] = "X"
	z := spend1(f.cbs[6], v-1, 0xfffffffe, 0)
	f.names[z.TxHash()] = "Z"
	b111b := f.chain.block('b', 111, x)
	b112b := f.chain.block('b', 112, f.tx["P"])
	b113b := f.chain.block('b', 113, z)

	// ReorgTo: disconnect 112, 111; connect 111b, 112b, 113b; update once.
	f.chain.unapply(f.b112, 112)
	f.mp.BlockDisconnected(f.b112)
	f.chain.unapply(f.b111, 111)
	f.mp.BlockDisconnected(f.b111)
	f.chain.apply(b111b, 111)
	f.mp.BlockConnected(b111b)
	f.chain.apply(b112b, 112)
	f.mp.BlockConnected(b112b)
	f.chain.apply(b113b, 113)
	f.mp.BlockConnected(b113b)
	runReorgUpdate(f.mp, true)

	assertPool(t, "after reorg to 113b", f.pool(), "A2", "C", "IMM", "LT", "B68", "D", "M1")

	// Nothing left in the pool may spend a coin that is gone.
	for _, h := range f.mp.GetAllTxHashes() {
		tx := f.mp.GetTransaction(h)
		for _, in := range tx.TxIn {
			if f.chain.utxos.GetUTXO(in.PreviousOutPoint) == nil && !f.mp.HasTransaction(in.PreviousOutPoint.Hash) {
				t.Errorf("%s spends missing input %v", f.names[h], in.PreviousOutPoint)
			}
		}
	}
}

// TestReorgUpdate_DeepInvalidateDropsDescendants: past 10 disconnected blocks
// Core stops re-accepting (InvalidateBlock passes fAddToMempool=false) and
// removeRecursive takes the in-mempool spenders of the dropped txs.
func TestReorgUpdate_DeepInvalidateDropsDescendants(t *testing.T) {
	f := newReorgFixture(t)
	if _, ok := any(f.mp).(reorgUpdater); !ok {
		t.Fatal("mempool has no reorg update (UpdateForReorg)")
	}
	f.chain.unapply(f.b112, 112)
	f.mp.BlockDisconnected(f.b112)
	runReorgUpdate(f.mp, false)
	// A2 dropped -> its child M1 goes; M2 / M3 do not spend block-112 txs.
	assertPool(t, "after a no-add disconnect of 112", f.pool(), "M2", "M3")
	if d, ok := any(f.mp).(interface{ DisconnectPoolSize() int }); !ok || d.DisconnectPoolSize() != 0 {
		t.Fatal("disconnect pool not drained")
	}
}
