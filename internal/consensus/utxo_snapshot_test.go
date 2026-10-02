package consensus

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

func snapTestCoin(b byte) (wire.OutPoint, *UTXOEntry) {
	var op wire.OutPoint
	op.Hash[0] = b
	return op, &UTXOEntry{Amount: int64(b) * 1000, PkScript: []byte{0x51}, Height: int32(b)}
}

// TestUTXOSnapshotIsIsolatedAndSelfLabelled runs on the real Pebble backend:
// a snapshot opened at "block 1" keeps reporting block 1's coins AND block 1's
// label after block 2's coins and marker have been flushed to the same DB.
func TestUTXOSnapshotIsIsolatedAndSelfLabelled(t *testing.T) {
	pdb, err := storage.NewPebbleDB(t.TempDir())
	if err != nil {
		t.Fatalf("open pebble: %v", err)
	}
	defer pdb.Close()
	u := NewUTXOSet(storage.NewChainDB(pdb))

	h1 := wire.Hash256{0x01}
	h2 := wire.Hash256{0x02}
	op1, c1 := snapTestCoin(1)
	u.AddUTXO(op1, c1)
	u.SetAppliedTip(h1, 1)

	snap, err := u.OpenSnapshot()
	if err != nil {
		t.Fatalf("OpenSnapshot: %v", err)
	}
	defer snap.Close()
	if !snap.HasMarker || snap.BestHash != h1 || snap.BestHeight != 1 {
		t.Fatalf("snapshot label = %v/%d (marker %v), want block 1", snap.BestHash, snap.BestHeight, snap.HasMarker)
	}

	// "Block 2" lands and is flushed while the walk has not started yet.
	op2, c2 := snapTestCoin(2)
	u.AddUTXO(op2, c2)
	u.AdvanceAppliedTip(h2, 2)
	if err := u.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	info, err := ComputeUTXOSetInfoFromSnapshot(snap, nil)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if info.TxOuts != 1 || info.TotalAmount != 1000 {
		t.Fatalf("old snapshot saw %d coins / %d sat after block 2 flushed; want 1 / 1000", info.TxOuts, info.TotalAmount)
	}

	fresh, err := u.OpenSnapshot()
	if err != nil {
		t.Fatalf("OpenSnapshot (fresh): %v", err)
	}
	defer fresh.Close()
	finfo, err := ComputeUTXOSetInfoFromSnapshot(fresh, nil)
	if err != nil {
		t.Fatalf("fresh walk: %v", err)
	}
	if fresh.BestHeight != 2 || fresh.BestHash != h2 || finfo.TxOuts != 2 {
		t.Fatalf("fresh snapshot: label %d, %d coins; want 2 / 2", fresh.BestHeight, finfo.TxOuts)
	}
	if finfo.HashSerialized3 == info.HashSerialized3 {
		t.Fatal("hash_serialized_3 identical for 1 and 2 coins — the hash is not measuring the set")
	}

	// The snapshot walk and the legacy flush-then-iterate walk agree on the
	// same set (same accumulator, same cursor order).
	legacy, err := ComputeUTXOSetInfo(u)
	if err != nil {
		t.Fatalf("legacy walk: %v", err)
	}
	if legacy != finfo {
		t.Fatalf("legacy walk %+v != snapshot walk %+v", legacy, finfo)
	}
}

// TestUTXOSnapshotScanStops: a closed stop channel ends the walk with
// ErrScanAborted.
func TestUTXOSnapshotScanStops(t *testing.T) {
	u := NewUTXOSet(storage.NewChainDB(storage.NewMemDB()))
	for b := byte(1); b <= 5; b++ {
		op, c := snapTestCoin(b)
		u.AddUTXO(op, c)
	}
	u.SetAppliedTip(wire.Hash256{0x05}, 5)
	snap, err := u.OpenSnapshot()
	if err != nil {
		t.Fatalf("OpenSnapshot: %v", err)
	}
	defer snap.Close()
	stop := make(chan struct{})
	close(stop)
	if _, err := ComputeUTXOSetInfoFromSnapshot(snap, stop); !errors.Is(err, ErrScanAborted) {
		t.Fatalf("walk with stop closed: err %v, want ErrScanAborted", err)
	}
	info, err := ComputeUTXOSetInfoFromSnapshot(snap, make(chan struct{}))
	if err != nil || info.TxOuts != 5 {
		t.Fatalf("walk with stop open: %d coins, err %v; want 5", info.TxOuts, err)
	}
}

// TestUTXOSnapshotRefusesInterruptedFlush: a recorded interrupted flush means
// the persisted set has no honest label; the snapshot must fail closed.
func TestUTXOSnapshotRefusesInterruptedFlush(t *testing.T) {
	mdb := storage.NewMemDB()
	u := NewUTXOSet(storage.NewChainDB(mdb))
	op, c := snapTestCoin(1)
	u.AddUTXO(op, c)
	u.SetAppliedTip(wire.Hash256{0x01}, 1)
	if err := mdb.Put(storage.CoinsFlushKey, make([]byte, 72)); err != nil {
		t.Fatal(err)
	}
	if snap, err := u.OpenSnapshot(); err == nil {
		snap.Close()
		t.Fatal("OpenSnapshot labelled a coin DB that records an interrupted flush")
	}
}
