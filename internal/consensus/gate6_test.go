package consensus

// Gate 6 fault-injection tests (receipts/gate6-resource-limit-audit-2026-10-04.md,
// blockbrew section): a resource / system failure during block connection must
// lead to retry or halt, never to a reject verdict or an accept.
//
// Every test here injects a REAL storage fault through storage.FaultDB (the
// production code path reads and writes through the storage.DB interface) or a
// panic on a chosen key read. Each is paired with a control showing that a
// genuinely invalid block still gets its verdict.

import (
	"errors"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

type gate6Rig struct {
	t       *testing.T
	params  *ChainParams
	idx     *HeaderIndex
	fdb     *storage.FaultDB
	chainDB *storage.ChainDB
	utxo    *UTXOSet
	cm      *ChainManager
	tip     *BlockNode
}

// newGate6Rig builds genesis + one coinbase-only block on a FaultDB-backed
// chain, post-IBD. maxCache 0 keeps the coin cache empty after every flush so
// every coin read is a real database read (the cold-prevout case the audit
// names: reorg-time reads of old coins).
func newGate6Rig(t *testing.T, maxCache int64) *gate6Rig {
	t.Helper()
	ResetAbortForTesting()
	t.Cleanup(ResetAbortForTesting)
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	fdb := storage.NewFaultDB(storage.NewMemDB())
	chainDB := storage.NewChainDB(fdb)
	utxo := NewUTXOSetWithMaxCache(chainDB, maxCache)
	cm := NewChainManager(ChainManagerConfig{Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxo})
	cm.SetIBD(false)
	r := &gate6Rig{t: t, params: params, idx: idx, fdb: fdb, chainDB: chainDB, utxo: utxo, cm: cm, tip: idx.Genesis()}
	r.tip = r.connect(r.block(r.tip, nil))
	return r
}

func (r *gate6Rig) subsidy(h int32) int64 {
	return CalcBlockSubsidyForInterval(h, r.params.SubsidyHalvingInterval)
}

// block builds a block on prev with the given non-coinbase txs and registers
// its header. Coinbase pays exactly the subsidy (fees are left unclaimed).
func (r *gate6Rig) block(prev *BlockNode, txs []*wire.MsgTx) *wire.MsgBlock {
	r.t.Helper()
	b := createTestBlockWithSpendsAndCoinbaseValue(r.t, r.params, prev, txs, r.subsidy(prev.Height+1))
	if _, err := r.idx.AddHeader(b.Header, true); err != nil && !errors.Is(err, ErrDuplicateHeader) {
		r.t.Fatalf("AddHeader: %v", err)
	}
	return b
}

func (r *gate6Rig) node(b *wire.MsgBlock) *BlockNode { return r.idx.GetNode(b.Header.BlockHash()) }

func (r *gate6Rig) connect(b *wire.MsgBlock) *BlockNode {
	r.t.Helper()
	if err := r.cm.ConnectBlock(b); err != nil {
		r.t.Fatalf("ConnectBlock(h=%d): %v", r.node(b).Height, err)
	}
	return r.node(b)
}

// plant creates a durable, cold, non-coinbase coin (OP_TRUE unless pk given).
func (r *gate6Rig) plant(tag byte, value int64, pk []byte) wire.OutPoint {
	r.t.Helper()
	if pk == nil {
		pk = []byte{0x51}
	}
	op := wire.OutPoint{Hash: wire.Hash256{0x6a, 0x7e, tag}, Index: 0}
	r.utxo.AddUTXO(op, &UTXOEntry{Amount: value, PkScript: pk, Height: 1})
	if err := r.utxo.Flush(); err != nil {
		r.t.Fatalf("plant flush: %v", err)
	}
	if !r.utxo.HasUTXODurable(op) {
		r.t.Fatalf("plant: coin not durable")
	}
	return op
}

func spendTx(op wire.OutPoint, value int64, tag byte) *wire.MsgTx {
	return &wire.MsgTx{
		Version:  1,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: op, Sequence: 0xFFFFFFFF}},
		TxOut:    []*wire.TxOut{{Value: value, PkScript: []byte{0x51, tag}}},
		LockTime: 0,
	}
}

func (r *gate6Rig) tipHash() wire.Hash256 { h, _ := r.cm.BestBlock(); return h }

func (r *gate6Rig) durableTip() *storage.ChainState {
	r.t.Helper()
	st, err := r.chainDB.GetChainState()
	if err != nil {
		r.t.Fatalf("GetChainState: %v", err)
	}
	return st
}

// P0 (audit F3/C1). A block's atomic batch fails to write, twice. Pre-fix the
// in-memory tip had already moved to the block and FlushBatch had already
// forgotten its spend, so the coin it spent was read back from disk as UNSPENT
// and a second block spending the same coin was ACCEPTED (double-spend).
func TestGate6_FailedBlockWriteDoesNotResurrectSpentCoin(t *testing.T) {
	r := newGate6Rig(t, DefaultCacheMaxBytes)
	c := r.plant(1, 50_000, nil)
	b1 := r.tip

	b2 := r.block(b1, []*wire.MsgTx{spendTx(c, 40_000, 1)})
	r.fdb.FailNextWrites(2, nil)
	err := r.cm.ConnectBlock(b2)
	if err == nil {
		t.Fatal("ConnectBlock succeeded although every write of its batch failed")
	}
	if _, verdict := AsBlockInvalid(err); verdict {
		t.Fatalf("a failed write was reported as a consensus verdict: %v", err)
	}
	if !IsSystemFault(err) {
		t.Errorf("write failure not typed as a system fault: %v", err)
	}
	if !IsAborted() {
		t.Error("a write that failed twice did not latch AbortNode")
	}
	if got := r.tipHash(); got != b1.Hash {
		t.Errorf("in-memory tip moved to a block whose batch never landed (tip=%s, want %s)",
			got.String()[:16], b1.Hash.String()[:16])
	}
	if st := r.durableTip(); st.BestHash != b1.Hash {
		t.Errorf("durable tip = %s, want %s", st.BestHash.String()[:16], b1.Hash.String()[:16])
	}
	if r.node(b2).Status.IsInvalid() {
		t.Error("block marked invalid for a local write failure")
	}

	// The double-spend: a block on top of b2 spending c AGAIN. Pre-fix the
	// node believed b2 was its tip and c was unspent, and accepted this.
	r.fdb.ClearFaults()
	b3 := r.block(r.node(b2), []*wire.MsgTx{spendTx(c, 30_000, 2)})
	if err := r.cm.ConnectBlock(b3); err == nil {
		t.Fatal("DOUBLE-SPEND ACCEPTED: a second block spending the same coin connected after a failed write")
	}
	if got := r.tipHash(); got == r.node(b3).Hash {
		t.Fatal("tip advanced onto a double-spend")
	}
}

// Retry once: a single transient write failure must not halt the node.
func TestGate6_SingleWriteFailureIsRetried(t *testing.T) {
	r := newGate6Rig(t, DefaultCacheMaxBytes)
	c := r.plant(2, 50_000, nil)
	b2 := r.block(r.tip, []*wire.MsgTx{spendTx(c, 40_000, 1)})
	r.fdb.FailNextWrites(1, nil)
	if err := r.cm.ConnectBlock(b2); err != nil {
		t.Fatalf("one transient write failure was not retried: %v", err)
	}
	if IsAborted() {
		t.Error("node aborted on a write that succeeded on retry")
	}
	if r.tipHash() != r.node(b2).Hash || r.durableTip().BestHash != r.node(b2).Hash {
		t.Error("block not connected/durable after the retry")
	}
	if r.utxo.HasUTXODurable(c) {
		t.Error("the spend did not land on disk after the retry")
	}
	if r.fdb.WritesFailed() != 1 {
		t.Errorf("injection fired %d times, want 1 (instrument check)", r.fdb.WritesFailed())
	}
}

// W100-B5 / G19 at the unit level: staging a flush must not forget anything;
// only Commit (after a successful write) does.
func TestGate6_StageFlushForgetsNothingUntilCommit(t *testing.T) {
	ResetAbortForTesting()
	t.Cleanup(ResetAbortForTesting)
	fdb := storage.NewFaultDB(storage.NewMemDB())
	chainDB := storage.NewChainDB(fdb)
	u := NewUTXOSet(chainDB)
	durable := createTestOutpoint(0xD0, 0)
	u.AddUTXO(durable, createTestEntry(1000, 1, false, []byte{0x51}))
	if err := u.Flush(); err != nil {
		t.Fatal(err)
	}
	created := createTestOutpoint(0xD1, 0)
	u.AddUTXO(created, createTestEntry(2000, 2, false, []byte{0x51}))
	u.SpendUTXO(durable)

	fdb.FailNextWrites(1, nil)
	b := chainDB.NewBatch()
	st, err := u.StageFlush(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Write(); err == nil {
		t.Fatal("instrument: injected write failure did not fire")
	}
	// The write failed: nothing may have been forgotten. A fresh read of the
	// SAME set must still see the spend and the create.
	if u.GetUTXO(durable) != nil {
		t.Error("spent coin resurrected after a failed batch write (pending delete was forgotten)")
	}
	if u.GetUTXO(created) == nil {
		t.Error("created coin lost after a failed batch write (pending put was forgotten)")
	}
	// Retry the same staging and commit: both now durable.
	b2 := chainDB.NewBatch()
	st2, err := u.StageFlush(b2)
	if err != nil {
		t.Fatal(err)
	}
	if err := b2.Write(); err != nil {
		t.Fatal(err)
	}
	st2.Commit()
	_ = st
	if u.HasUTXODurable(durable) || !u.HasUTXODurable(created) {
		t.Errorf("after retry: durable(spent)=%v durable(created)=%v, want false/true",
			u.HasUTXODurable(durable), u.HasUTXODurable(created))
	}
}

// After AbortNode no UTXO state may reach disk — this is what makes the
// graceful-shutdown flush (cmd/blockbrew) a no-op after a fatal error.
func TestGate6_NoUTXOFlushAfterAbort(t *testing.T) {
	ResetAbortForTesting()
	t.Cleanup(ResetAbortForTesting)
	chainDB := storage.NewChainDB(storage.NewMemDB())
	u := NewUTXOSet(chainDB)
	op := createTestOutpoint(0xD2, 0)
	u.AddUTXO(op, createTestEntry(1000, 1, false, []byte{0x51}))
	AbortNode(errors.New("test: injected fatal error"))

	b := chainDB.NewBatch()
	if _, err := u.StageFlush(b); !errors.Is(err, ErrNodeAborted) {
		t.Errorf("StageFlush after AbortNode: err=%v, want ErrNodeAborted", err)
	}
	if b.Len() != 0 {
		t.Errorf("StageFlush staged %d writes after AbortNode", b.Len())
	}
	if err := u.Flush(); !errors.Is(err, ErrNodeAborted) {
		t.Errorf("Flush after AbortNode: err=%v, want ErrNodeAborted", err)
	}
	if u.HasUTXODurable(op) {
		t.Error("a UTXO reached disk after AbortNode")
	}
}

// P0 (audit F3/C2). A panic during validation (here: on reading the second
// spend's prevout) after part of the block was applied. Pre-fix the outer
// recover let the node run on, the shutdown flush persisted the half-applied
// block, and on reboot the marker-lag repair found the block's coinbase on disk
// and ADOPTED it as fully valid — although its first spend has an invalid
// script that was never checked.
func TestGate6_PanicMidConnectNeverPersistsOrAdoptsUncheckedBlock(t *testing.T) {
	r := newGate6Rig(t, 0)
	bad := r.plant(3, 50_000, []byte{0x00}) // OP_0: any spend of it fails script
	ok := r.plant(4, 50_000, nil)
	b2 := r.block(r.tip, []*wire.MsgTx{spendTx(bad, 40_000, 1), spendTx(ok, 40_000, 2)})

	r.fdb.PanicOnGet(storage.MakeUTXOKey(ok), "gate6 test: injected panic mid-connect")
	func() {
		defer func() { _ = recover() }() // what the P2P loop / RPC handler do
		_ = r.cm.ConnectBlock(b2)
		t.Fatal("instrument: injected panic did not fire")
	}()
	r.fdb.ClearFaults()
	if !IsAborted() {
		t.Error("a panic mid-connect did not latch AbortNode")
	}

	// The graceful shutdown flush, exactly as cmd/blockbrew does it.
	{
		b := r.chainDB.NewBatch()
		if st, err := r.utxo.StageFlush(b); err == nil {
			hash, height := r.cm.BestBlock()
			r.chainDB.SetChainStateBatch(b, &storage.ChainState{BestHash: hash, BestHeight: height})
			if b.Write() == nil {
				st.Commit()
			}
			t.Error("the shutdown flush was allowed after a panic mid-connect")
		}
	}

	// "Restart": new process state on the same database.
	ResetAbortForTesting()
	utxo2 := NewUTXOSetWithMaxCache(r.chainDB, 0)
	cm2 := NewChainManager(ChainManagerConfig{Params: r.params, HeaderIndex: r.idx, ChainDB: r.chainDB, UTXOSet: utxo2})
	cm2.SetIBD(false)
	if h, _ := cm2.BestBlock(); h != r.tip.Hash {
		t.Fatalf("restart tip = %s, want b1", h.String()[:16])
	}
	if err := cm2.AdoptAppliedBlock(b2); err == nil {
		t.Fatal("FAIL-OPEN: after restart the half-applied block was ADOPTED as fully valid without its scripts ever running")
	}
	err := cm2.ConnectBlock(b2)
	if _, verdict := AsBlockInvalid(err); !verdict {
		t.Fatalf("after restart the block with an invalid script got %v, want a script verdict", err)
	}
}

// Control for the test above: the same block, no panic, gets its verdict.
func TestGate6_Control_InvalidScriptStillRejected(t *testing.T) {
	r := newGate6Rig(t, 0)
	bad := r.plant(5, 50_000, []byte{0x00})
	ok := r.plant(6, 50_000, nil)
	b2 := r.block(r.tip, []*wire.MsgTx{spendTx(bad, 40_000, 1), spendTx(ok, 40_000, 2)})
	err := r.cm.ConnectBlock(b2)
	if _, verdict := AsBlockInvalid(err); !verdict {
		t.Fatalf("invalid-script block: err=%v, want a verdict", err)
	}
	if IsAborted() {
		t.Error("a genuine consensus failure latched AbortNode")
	}
}

// buildReorg: active chain b1 - a2 - a3; competing branch b1 - x2 - x3 - x4
// (heavier) whose x2 spends coin c.
func (r *gate6Rig) buildReorg(c wire.OutPoint) (a3, x2, x4 *BlockNode) {
	r.t.Helper()
	b1 := r.tip
	a2 := r.connect(r.block(b1, nil))
	a3 = r.connect(r.block(a2, nil))
	store := func(b *wire.MsgBlock) *BlockNode {
		if err := r.chainDB.StoreBlock(b.Header.BlockHash(), b); err != nil {
			r.t.Fatalf("StoreBlock: %v", err)
		}
		r.idx.MarkDataStored(b.Header.BlockHash())
		return r.node(b)
	}
	x2 = store(r.block(b1, []*wire.MsgTx{spendTx(c, 40_000, 9)}))
	x3 := store(r.block(x2, nil))
	x4 = store(r.block(x3, nil))
	return a3, x2, x4
}

// reseal recomputes the merkle root + PoW after a test tweak and re-adds the header.
func (r *gate6Rig) reseal(b *wire.MsgBlock) *wire.MsgBlock {
	hashes := make([]wire.Hash256, len(b.Transactions))
	for i, tx := range b.Transactions {
		hashes[i] = tx.TxHash()
	}
	b.Header.MerkleRoot = CalcMerkleRoot(hashes)
	target := CompactToBig(b.Header.Bits)
	for i := uint32(0); ; i++ {
		b.Header.Nonce = i
		if HashToBig(b.Header.BlockHash()).Cmp(target) <= 0 {
			break
		}
	}
	if _, err := r.idx.AddHeader(b.Header, true); err != nil && !errors.Is(err, ErrDuplicateHeader) {
		r.t.Fatalf("AddHeader: %v", err)
	}
	return b
}

// P2 (audit F9). On the reorg path a prevout absent from the view is a
// verdict (mark + ban) — correct for a coin that does not exist on the branch,
// wrong for a coin the database failed to READ. Cold prevouts at reorg time
// are real disk reads (EIO, EMFILE, ErrDBClosed).
func TestGate6_CoinReadErrorOnReorgIsNotAVerdict(t *testing.T) {
	r := newGate6Rig(t, 0)
	c := r.plant(7, 50_000, nil)
	a3, x2, x4 := r.buildReorg(c)

	r.fdb.FailGet(storage.MakeUTXOKey(c), nil)
	err := r.cm.ReorgTo(x4)
	if err == nil {
		t.Fatal("instrument: reorg succeeded although the branch's prevout was unreadable")
	}
	if _, verdict := AsBlockInvalid(err); verdict {
		t.Fatalf("coins-DB read error became a verdict on the branch: %v", err)
	}
	if x2.Status.IsInvalid() || x4.Status.IsInvalid() {
		t.Fatal("branch marked invalid because the coins DB could not be read")
	}
	if fails, _ := r.chainDB.ReadBlockFailures(); len(fails) != 0 {
		t.Fatalf("a failure flag was persisted for a read error: %v", fails)
	}
	if !IsAborted() {
		t.Error("coins-DB read error did not latch AbortNode")
	}
	if r.tipHash() != a3.Hash {
		t.Error("reorg did not roll back to the original tip")
	}
	if r.fdb.ReadsFailed() == 0 {
		t.Error("instrument: the read fault never fired")
	}
}

// Control: the same reorg with the coin GENUINELY absent is still a verdict.
func TestGate6_Control_ReorgMissingCoinStillAVerdict(t *testing.T) {
	r := newGate6Rig(t, 0)
	ghost := wire.OutPoint{Hash: wire.Hash256{0x6a, 0x7e, 0xFF}, Index: 0}
	_, x2, x4 := r.buildReorg(ghost)
	err := r.cm.ReorgTo(x4)
	if _, verdict := AsBlockInvalid(err); !verdict {
		t.Fatalf("missing-coin branch: err=%v, want a verdict", err)
	}
	if !x2.Status.IsInvalid() {
		t.Error("branch with a genuinely missing coin was not marked")
	}
	if IsAborted() {
		t.Error("a genuine consensus failure latched AbortNode")
	}
}

// Audit F7b: the BIP30 lookup read a failed coin read as "no conflict" and let
// a block overwrite a live, unspent coin (fail-OPEN).
func TestGate6_BIP30ReadErrorIsNotFailOpen(t *testing.T) {
	for _, inject := range []bool{false, true} {
		name := "control"
		if inject {
			name = "read-error"
		}
		t.Run(name, func(t *testing.T) {
			r := newGate6Rig(t, 0)
			c := r.plant(8, 50_000, nil)
			tx := spendTx(c, 40_000, 3)
			dup := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
			// A live coin already sits at tx's first output (BIP30 conflict).
			r.utxo.AddUTXO(dup, &UTXOEntry{Amount: 1, PkScript: []byte{0x51}, Height: 1})
			if err := r.utxo.Flush(); err != nil {
				t.Fatal(err)
			}
			b2 := r.block(r.tip, []*wire.MsgTx{tx})
			if inject {
				r.fdb.FailGet(storage.MakeUTXOKey(dup), nil)
			}
			err := r.cm.ConnectBlock(b2)
			if err == nil {
				t.Fatal("FAIL-OPEN: a block overwriting a live coin (BIP30) was connected")
			}
			_, verdict := AsBlockInvalid(err)
			if !inject {
				if !verdict || !errors.Is(err, ErrDuplicateTx) {
					t.Fatalf("control: err=%v, want a bad-txns-BIP30 verdict", err)
				}
				return
			}
			if verdict {
				t.Fatalf("read error became a verdict: %v", err)
			}
			if !IsAborted() {
				t.Error("BIP30 read error did not latch AbortNode")
			}
			if r.node(b2).Status.IsInvalid() {
				t.Error("block marked invalid for a read error")
			}
		})
	}
}

// Coin read error on the active-tip connect path: never a verdict, latched,
// and a transient (single) read error is retried.
func TestGate6_CoinReadErrorOnTipConnect(t *testing.T) {
	r := newGate6Rig(t, 0)
	c := r.plant(9, 50_000, nil)
	b2 := r.block(r.tip, []*wire.MsgTx{spendTx(c, 40_000, 1)})

	// One transient failure: retried, block connects.
	r.fdb.FailNextGets(1, nil)
	if err := r.cm.ConnectBlock(b2); err != nil {
		t.Fatalf("a single transient read error was not retried: %v", err)
	}
	if IsAborted() {
		t.Fatal("aborted on a read that succeeded on retry")
	}

	c2 := r.plant(10, 50_000, nil)
	b3 := r.block(r.node(b2), []*wire.MsgTx{spendTx(c2, 40_000, 2)})
	r.fdb.FailGet(storage.MakeUTXOKey(c2), nil)
	err := r.cm.ConnectBlock(b3)
	if _, verdict := AsBlockInvalid(err); verdict || err == nil {
		t.Fatalf("persistent read error: err=%v, want a non-verdict error", err)
	}
	if !IsSystemFault(err) {
		t.Errorf("read error not typed as a system fault (would read as missing-inputs): %v", err)
	}
	if !IsAborted() {
		t.Error("persistent coins-DB read error did not latch AbortNode")
	}
}

// Audit B2: wall-clock time-too-new is Core's BLOCK_TIME_FUTURE — never a
// verdict, never marked (it was a persisted mark + ban).
func TestGate6_TimeTooNewIsNotAVerdict(t *testing.T) {
	r := newGate6Rig(t, DefaultCacheMaxBytes)
	saved := headerNowUnix
	headerNowUnix = func() int64 { return time.Now().Unix() + 10*3600 }
	defer func() { headerNowUnix = saved }()

	b := createTestBlockWithSpendsAndCoinbaseValue(t, r.params, r.tip, nil, r.subsidy(r.tip.Height+1))
	b.Header.Timestamp = uint32(time.Now().Unix() + 3*3600)
	b = r.reseal(b)
	err := r.cm.ConnectBlock(b)
	if err == nil || !errors.Is(err, ErrTimestampTooFar) {
		t.Fatalf("instrument: err=%v, want time-too-new", err)
	}
	if _, verdict := AsBlockInvalid(err); verdict {
		t.Fatalf("time-too-new reported as a verdict (would be marked + punished): %v", err)
	}
	if IsAborted() {
		t.Error("time-too-new latched AbortNode")
	}
}
