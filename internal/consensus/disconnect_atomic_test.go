package consensus

import (
	"strings"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ─── The defect these tests pin (security audit H4) ─────────────────────────
//
// Outside a multi-block reorg, disconnectBlock undid the block's coins only in
// the in-memory UTXO cache, but wrote the tip pointer, the height-row delete
// and the undo delete to disk at once, each on its own. The coin delta (and
// the coins marker) reached disk only at the next ConnectBlock batch or Flush.
// invalidateblock flushes only when it reorgs onto a better branch, and the
// boot consistency probe's peel never flushes. A crash in that window left:
//
//   tip = parent, height row and undo gone, coins = post-block state,
//   coins marker = the disconnected block.
//
// On boot the marker no longer matches the height map, so recovery had nothing
// to replay: the node ran at the parent over a set that still held the block's
// outputs and lacked the coins it spent. A block spending the phantom outputs
// would be accepted (Core rejects it); the valid block, reconsidered, failed
// BIP30 against its own leftover outputs and was persisted invalid.
//
// Core: DisconnectTip flushes the view into CoinsTip(), whose best block moves
// with it; CCoinsViewDB::BatchWrite writes the coins and DB_BEST_BLOCK in one
// batch (validation.cpp DisconnectTip, txdb.cpp BatchWrite). Rev data is never
// erased on disconnect.
//
// "Crash" below means: drop the ChainManager and its UTXO cache without the
// shutdown flush, close and reopen the Pebble directory, and reboot over it
// (reboot, recovery_marker_test.go). Pebble, not MemDB: MemDB's batch applies
// every Put before every Delete, so a reorg batch that deletes and then re-puts
// the same height row loses it — a fake-backend artefact Pebble does not have.

// spendFixture connects genesis..101 (block 1's coinbase is the victim) and
// returns everything a test needs to build block 102 on top. The set at 101 is
// durable (not IBD: every connect at the tip flushes atomically).
type spendFixture struct {
	dir     string
	db      *storage.PebbleDB
	params  *ChainParams
	idx     *HeaderIndex
	chainDB *storage.ChainDB
	utxoSet *UTXOSet
	cm      *ChainManager
	tip     *BlockNode // height 101
	victim  wire.OutPoint
	// The set at height 101, the state every disconnect of 102 must restore.
	parentHash  wire.Hash256
	parentCoins uint64
}

func newSpendFixture(t *testing.T) *spendFixture {
	t.Helper()
	f := &spendFixture{params: RegtestParams(), dir: t.TempDir()}
	f.idx = NewHeaderIndex(f.params)
	db, err := storage.NewPebbleDB(f.dir)
	if err != nil {
		t.Fatalf("NewPebbleDB: %v", err)
	}
	f.db = db
	t.Cleanup(func() { f.db.Close() })
	f.chainDB = storage.NewChainDB(f.db)
	f.utxoSet = NewUTXOSet(f.chainDB)
	f.cm = NewChainManager(ChainManagerConfig{
		Params: f.params, HeaderIndex: f.idx, ChainDB: f.chainDB, UTXOSet: f.utxoSet,
	})
	f.cm.SetIBD(false)

	prev := f.idx.Genesis()
	for h := 1; h <= CoinbaseMaturity+1; h++ {
		b := createTestBlock(t, f.params, prev, nil)
		prev = f.connect(t, f.cm, b)
		if h == 1 {
			f.victim = wire.OutPoint{Hash: b.Transactions[0].TxHash(), Index: 0}
		}
	}
	f.tip = prev

	f.parentHash, f.parentCoins, err = ComputeHashSerialized(f.utxoSet)
	if err != nil {
		t.Fatalf("ComputeHashSerialized at 101: %v", err)
	}
	return f
}

// crash abandons the running ChainManager without the shutdown flush, reopens
// the datadir and boots over it, as a restart after SIGKILL would.
func (f *spendFixture) crash(t *testing.T) (*ChainManager, *UTXOSet) {
	t.Helper()
	if err := f.db.Close(); err != nil {
		t.Fatalf("close pebble: %v", err)
	}
	db, err := storage.NewPebbleDB(f.dir)
	if err != nil {
		t.Fatalf("reopen pebble: %v", err)
	}
	f.db = db
	f.chainDB = storage.NewChainDB(db)
	return reboot(t, f.params, f.chainDB)
}

// taggedBlock is createTestBlock with a distinct coinbase (tag in its
// scriptSig), so it does not collide with a sibling's coinbase under BIP30.
func taggedBlock(t *testing.T, params *ChainParams, prev *BlockNode, tag byte, txs []*wire.MsgTx) *wire.MsgBlock {
	t.Helper()
	b := createTestBlock(t, params, prev, txs)
	cb := b.Transactions[0]
	cb.TxIn[0].SignatureScript = append(append([]byte{}, cb.TxIn[0].SignatureScript...), 0x00, tag)
	hashes := make([]wire.Hash256, len(b.Transactions))
	for i, tx := range b.Transactions {
		hashes[i] = tx.TxHash()
	}
	b.Header.MerkleRoot = CalcMerkleRoot(hashes)
	target := CompactToBig(b.Header.Bits)
	for n := uint32(0); ; n++ {
		b.Header.Nonce = n
		if HashToBig(b.Header.BlockHash()).Cmp(target) <= 0 {
			break
		}
	}
	return b
}

func (f *spendFixture) connect(t *testing.T, cm *ChainManager, b *wire.MsgBlock) *BlockNode {
	t.Helper()
	if _, err := cm.GetHeaderIndex().AddHeader(b.Header, true); err != nil {
		t.Fatalf("AddHeader: %v", err)
	}
	if err := cm.ConnectBlock(b); err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}
	return cm.GetHeaderIndex().GetNode(b.Header.BlockHash())
}

// h4SpendTx spends `in` to a single OP_TRUE output.
func h4SpendTx(in wire.OutPoint, value int64) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: in, Sequence: 0xFFFFFFFF}},
		TxOut:   []*wire.TxOut{{Value: value, PkScript: []byte{0x51}}},
	}
}

// assertParentSet checks, on DISK, that the set is exactly the set at 101: the
// victim unspent again and none of block 102's outputs left behind.
func assertParentSet(t *testing.T, f *spendFixture, utxoSet *UTXOSet, d *wire.MsgBlock) {
	t.Helper()
	if !utxoSet.HasUTXODurable(f.victim) {
		t.Errorf("spent coin %v is still spent on disk after block 102 was disconnected", f.victim)
	}
	for i, tx := range d.Transactions {
		op := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
		if utxoSet.HasUTXODurable(op) {
			t.Errorf("phantom coin: output %v of disconnected block 102 (tx %d) is on disk", op, i)
		}
	}
	gotHash, gotCoins, err := ComputeHashSerialized(utxoSet)
	if err != nil {
		t.Fatalf("ComputeHashSerialized: %v", err)
	}
	if gotHash != f.parentHash || gotCoins != f.parentCoins {
		t.Errorf("UTXO set after disconnect + crash = %d coins %s, want the parent's %d coins %s",
			gotCoins, gotHash.String()[:16], f.parentCoins, f.parentHash.String()[:16])
	}
}

// TestInvalidateBlockCrashKeepsCoinsWithTip is the H4 repro: spend a coin in
// block 102, invalidateblock 102, crash, reboot.
func TestInvalidateBlockCrashKeepsCoinsWithTip(t *testing.T) {
	f := newSpendFixture(t)
	spend := h4SpendTx(f.victim, 1000)
	d := createTestBlock(t, f.params, f.tip, []*wire.MsgTx{spend})
	dNode := f.connect(t, f.cm, d)
	if f.utxoSet.HasUTXODurable(f.victim) {
		t.Fatalf("precondition: victim must be spent on disk at 102")
	}

	if err := f.cm.InvalidateBlock(dNode.Hash); err != nil {
		t.Fatalf("InvalidateBlock(102): %v", err)
	}
	if got, h := f.cm.BestBlock(); got != f.tip.Hash || h != f.tip.Height {
		t.Fatalf("after invalidateblock: tip height %d, want 101", h)
	}

	cm2, utxo2 := f.crash(t)
	if got, h := cm2.BestBlock(); got != f.tip.Hash || h != f.tip.Height {
		t.Fatalf("after crash: tip %s@%d, want 101", got.String()[:16], h)
	}
	assertParentSet(t, f, utxo2, d)

	// An invalid block must stay invalid: spending the disconnected block's
	// output at 102 has no such coin to spend (Core: bad-txns-inputs-missingorspent).
	phantom := wire.OutPoint{Hash: spend.TxHash(), Index: 0}
	e := taggedBlock(t, f.params, cm2.GetHeaderIndex().GetNode(f.tip.Hash), 0xE1,
		[]*wire.MsgTx{h4SpendTx(phantom, 500)})
	if _, err := cm2.GetHeaderIndex().AddHeader(e.Header, true); err != nil {
		t.Fatalf("AddHeader(E): %v", err)
	}
	if err := cm2.ConnectBlock(e); err == nil {
		t.Errorf("a block spending phantom output %v of the disconnected block was ACCEPTED", phantom)
	} else if !strings.Contains(err.Error(), "missing") {
		t.Errorf("block spending phantom output %v rejected for the wrong reason: %v", phantom, err)
	}

	// A valid block must stay valid: reconsiderblock reconnects 102.
	if err := cm2.ReconsiderBlock(dNode.Hash); err != nil {
		t.Fatalf("ReconsiderBlock(102) after crash: %v", err)
	}
	if got, h := cm2.BestBlock(); got != dNode.Hash {
		t.Fatalf("after reconsiderblock: tip height %d, want 102", h)
	}
	if utxo2.HasUTXODurable(f.victim) {
		t.Errorf("after reconsiderblock: victim %v unspent on disk, want spent by 102", f.victim)
	}
	if !utxo2.HasUTXODurable(phantom) {
		t.Errorf("after reconsiderblock: block 102's output %v missing on disk", phantom)
	}
}

// TestReorgCrashKeepsCoinsWithTip is the regression pin for the multi-block
// reorg path, which already commits disconnects and connects in one union
// batch: disconnect A102 (which spent the victim), connect B102..B103, crash.
func TestReorgCrashKeepsCoinsWithTip(t *testing.T) {
	f := newSpendFixture(t)
	spend := h4SpendTx(f.victim, 1000)
	a := createTestBlock(t, f.params, f.tip, []*wire.MsgTx{spend})
	aNode := f.connect(t, f.cm, a)

	var bBlocks []*wire.MsgBlock
	prev := f.tip
	for i := 0; i < 2; i++ {
		b := createSiblingBlock(t, f.params, prev, byte(0xB0+i))
		node, err := f.idx.AddHeader(b.Header, true)
		if err != nil {
			t.Fatalf("B%d AddHeader: %v", i+1, err)
		}
		if err := f.chainDB.StoreBlock(b.Header.BlockHash(), b); err != nil {
			t.Fatalf("B%d StoreBlock: %v", i+1, err)
		}
		bBlocks = append(bBlocks, b)
		prev = node
	}
	if err := f.cm.ReorgTo(prev); err != nil {
		t.Fatalf("ReorgTo(B103): %v", err)
	}

	cm2, utxo2 := f.crash(t)
	if got, h := cm2.BestBlock(); got != prev.Hash || h != 103 {
		t.Fatalf("after crash: tip %s@%d, want B103", got.String()[:16], h)
	}
	if !utxo2.HasUTXODurable(f.victim) {
		t.Errorf("victim %v still spent on disk after A102 was reorged out", f.victim)
	}
	for i, tx := range a.Transactions {
		if op := (wire.OutPoint{Hash: tx.TxHash(), Index: 0}); utxo2.HasUTXODurable(op) {
			t.Errorf("phantom coin: output %v of reorged-out A102 (tx %d) is on disk", op, i)
		}
	}
	for i, b := range bBlocks {
		if op := (wire.OutPoint{Hash: b.Transactions[0].TxHash(), Index: 0}); !utxo2.HasUTXODurable(op) {
			t.Errorf("B%d coinbase %v missing on disk after the reorg", i+1, op)
		}
	}
	// Rev data is kept (Core never erases it on disconnect): A102 can be
	// disconnected again later, so its undo must still be readable.
	if _, err := cm2.chainDB.ReadBlockUndo(aNode.Hash); err != nil {
		t.Errorf("undo of reorged-out A102 was erased: %v", err)
	}
}

// TestDisconnectBlockIsOneAtomicBatch: outside a reorg, a disconnect must not
// issue any direct Put/Delete — the coin delta, coins marker, height delete and
// tip pointer go to disk in one batch, or a crash between them tears the pair.
func TestDisconnectBlockIsOneAtomicBatch(t *testing.T) {
	params := RegtestParams()
	idx := NewHeaderIndex(params)
	memdb := storage.NewMemDB()
	counter := newCountingDB(memdb)
	chainDB := storage.NewChainDB(counter)
	utxoSet := NewUTXOSet(chainDB)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: utxoSet,
	})
	cm.SetIBD(false)
	prev := idx.Genesis()
	for h := 1; h <= 3; h++ {
		b := createTestBlock(t, params, prev, nil)
		if _, err := idx.AddHeader(b.Header, true); err != nil {
			t.Fatal(err)
		}
		if err := cm.ConnectBlock(b); err != nil {
			t.Fatal(err)
		}
		prev = idx.GetNode(b.Header.BlockHash())
	}

	counter.mu.Lock()
	counter.directPuts, counter.directDels, counter.batchWrites = 0, 0, 0
	counter.mu.Unlock()
	if err := cm.DisconnectBlock(prev.Hash); err != nil {
		t.Fatalf("DisconnectBlock: %v", err)
	}
	counter.mu.Lock()
	puts, dels, writes := counter.directPuts, counter.directDels, counter.batchWrites
	counter.mu.Unlock()
	if puts != 0 || dels != 0 {
		t.Errorf("disconnect issued %d direct Puts and %d direct Deletes; all must ride one batch", puts, dels)
	}
	if writes != 1 {
		t.Errorf("disconnect wrote %d batches, want exactly 1", writes)
	}
	marker, err := memdb.Get(storage.CoinsTipKey)
	if err != nil {
		t.Fatalf("coins marker missing after disconnect: %v", err)
	}
	ms, err := storage.DeserializeChainState(marker)
	if err != nil {
		t.Fatalf("decode coins marker: %v", err)
	}
	if ms.BestHash != prev.Parent.Hash || ms.BestHeight != prev.Parent.Height {
		t.Errorf("on-disk coins marker = height %d, want the parent (%d)", ms.BestHeight, prev.Parent.Height)
	}
}
