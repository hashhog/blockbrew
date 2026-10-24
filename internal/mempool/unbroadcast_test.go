package mempool

import (
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

func injectUnbroadcastTestTx(mp *Mempool, n byte) wire.Hash256 {
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xAA, n}, Index: 0},
			SignatureScript:  []byte{0x51},
			Sequence:         0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{Value: 1234, PkScript: []byte{0x00, 0x14, n}}},
	}
	InjectTestEntry(mp, &TxEntry{Tx: tx, TxHash: tx.TxHash(), Time: time.Unix(1_700_000_000, 0), Fee: 1000, Size: 200})
	return tx.TxHash()
}

func TestUnbroadcast_SetLifecycle(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())
	a := injectUnbroadcastTestTx(mp, 1)
	b := injectUnbroadcastTestTx(mp, 2)

	mp.AddUnbroadcastTx(a)
	mp.AddUnbroadcastTx(wire.Hash256{0xEE}) // not in pool: ignored
	if !mp.IsUnbroadcastTx(a) || mp.IsUnbroadcastTx(b) || mp.UnbroadcastCount() != 1 {
		t.Fatalf("after add: a=%v b=%v count=%d", mp.IsUnbroadcastTx(a), mp.IsUnbroadcastTx(b), mp.UnbroadcastCount())
	}
	mp.RemoveUnbroadcastTx(a)
	if mp.IsUnbroadcastTx(a) {
		t.Fatal("RemoveUnbroadcastTx did not clear")
	}
	// Eviction from the pool drops the mark (Core removeUnchecked).
	mp.AddUnbroadcastTx(b)
	mp.RemoveTransaction(b)
	if mp.UnbroadcastCount() != 0 {
		t.Fatalf("evicted tx still unbroadcast: %d", mp.UnbroadcastCount())
	}
}

func TestUnbroadcast_PersistedInMempoolDat(t *testing.T) {
	dir := t.TempDir()
	mp := newTestMempool(newTestUTXOSet())
	a := injectUnbroadcastTestTx(mp, 1)
	b := injectUnbroadcastTestTx(mp, 2)
	mp.AddUnbroadcastTx(a)
	if err := mp.Dump(dir); err != nil {
		t.Fatal(err)
	}
	_ = b

	// importmempool default: set not applied.
	if got := reloadForUnbroadcast(t, dir, false); got != 0 {
		t.Fatalf("apply=false: unbroadcast count = %d, want 0", got)
	}
	// Startup load: set applied.
	if got := reloadForUnbroadcast(t, dir, true); got != 1 {
		t.Fatalf("apply=true: unbroadcast count = %d, want 1", got)
	}
}

// reloadForUnbroadcast loads dir/mempool.dat into a fresh mempool whose
// ATMP is bypassed by pre-seeding the entries, so only the unbroadcast tail
// is exercised.
func reloadForUnbroadcast(t *testing.T, dir string, apply bool) int {
	t.Helper()
	mp := newTestMempool(newTestUTXOSet())
	injectUnbroadcastTestTx(mp, 1)
	injectUnbroadcastTestTx(mp, 2)
	if _, err := mp.Load(dir, LoadOptions{ApplyUnbroadcastSet: apply}); err != nil {
		t.Fatal(err)
	}
	return mp.UnbroadcastCount()
}
