package consensus

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// A coin flush that spans more than one batch can tear. Which tears are
// survivable is not a matter of taste — it decides whether "the marker lags the
// set" is safe or is itself corruption:
//
//   - A torn ADD phase is repairable. No delete has landed, so the set is the
//     old set plus a prefix of the new entries; the marker is still low,
//     recovery re-connects that span, every AddUTXO rewrites the same bytes and
//     every SpendUTXO still finds its coin.
//   - A landed DELETE under a low marker is NOT repairable. Recovery
//     re-connects the span and a coinbase-only block in it re-adds an output
//     whose spend is already durable — the 166,180,925 -> 166,180,926 signature.
//
// So flushLocked must keep every delete in the SAME batch as the marker. Core
// reaches the same guarantee the other way round: it lets BatchWrite span
// CDBBatches but records the window in DB_HEAD_BLOCKS first
// (bitcoin-core/src/txdb.cpp:128-129) and erases it in the last batch
// (txdb.cpp:157-159), so the tear is detected on boot and repaired by
// ReplayBlocks (validation.cpp:4773).

type recordedBatch struct {
	deletes     int
	markerPut   bool
	flushRecPut bool
	flushRecDel bool
}

type recordingDB struct {
	storage.DB
	written *[]recordedBatch
}

func (d *recordingDB) NewBatch() storage.Batch {
	return &recordingBatch{Batch: d.DB.NewBatch(), owner: d}
}

type recordingBatch struct {
	storage.Batch
	owner *recordingDB
	rec   recordedBatch
}

func (b *recordingBatch) Put(k, v []byte) {
	switch {
	case bytes.Equal(k, storage.CoinsTipKey):
		b.rec.markerPut = true
	case bytes.Equal(k, storage.CoinsFlushKey):
		b.rec.flushRecPut = true
	}
	b.Batch.Put(k, v)
}

func (b *recordingBatch) Delete(k []byte) {
	if bytes.Equal(k, storage.CoinsFlushKey) {
		b.rec.flushRecDel = true
	} else {
		b.rec.deletes++
	}
	b.Batch.Delete(k)
}

func (b *recordingBatch) Write() error {
	err := b.Batch.Write()
	if err == nil {
		*b.owner.written = append(*b.owner.written, b.rec)
	}
	return err
}

// flushOrderingFixture seeds `n` coins on disk, then stages `n` spends plus `n`
// fresh adds and flushes under a per-batch cap that forces the flush to span
// batches.
//
// cap == 0 means "compute the TIGHT cap": just above the delete phase's total
// cost, so the deletes fit one batch on their own but do NOT fit alongside the
// add phase's leftovers. That is precisely the cap at which the pre-fix single
// stream (adds and deletes chunked together) tears in the middle of the
// deletes, and the fixed two-phase flush does not.
func flushOrderingFixture(t *testing.T, n int, cap int) []recordedBatch {
	t.Helper()
	var written []recordedBatch
	rdb := &recordingDB{DB: storage.NewMemDB(), written: &written}
	u := NewUTXOSet(storage.NewChainDB(rdb))

	mk := func(i int, tag byte) wire.OutPoint {
		var h wire.Hash256
		h[0] = tag
		h[1] = byte(i)
		h[2] = byte(i >> 8)
		return wire.OutPoint{Hash: h, Index: 0}
	}
	entry := func() *UTXOEntry {
		return &UTXOEntry{Amount: 5000, PkScript: bytes.Repeat([]byte{0x51}, 24), Height: 1}
	}

	// Round 1: make `n` coins durable (single batch, default cap).
	for i := 0; i < n; i++ {
		u.AddUTXO(mk(i, 'o'), entry())
	}
	u.SetAppliedTip(wire.Hash256{0x01}, 100)
	if err := u.Flush(); err != nil {
		t.Fatalf("seed flush: %v", err)
	}
	written = written[:0]

	// Round 2: spend all of them and add `n` new ones, under a tiny cap.
	for i := 0; i < n; i++ {
		u.SpendUTXO(mk(i, 'o'))
		u.AddUTXO(mk(i, 'n'), entry())
	}
	u.SetAppliedTip(wire.Hash256{0x02}, 101)

	if cap == 0 {
		var probe wire.OutPoint
		probe.Hash[0] = 'o'
		delCost := len(storage.MakeUTXOKey(probe)) + 16
		addCost := delCost + len(SerializeUTXOEntry(entry()))
		cap = n*delCost + 2*addCost
		t.Logf("tight cap = %d (delete phase %d bytes, add phase %d bytes)",
			cap, n*delCost, n*addCost)
	}

	saved := flushMaxBatchBytes
	flushMaxBatchBytes = cap
	defer func() { flushMaxBatchBytes = saved }()
	if err := u.Flush(); err != nil {
		t.Fatalf("chunked flush: %v", err)
	}
	return written
}

// TestFlush_DeletesRideTheMarkerBatch pins the ordering guarantee: however many
// batches the add phase needs, no committed batch may carry a coin DELETE
// unless that same batch also carries the marker.
func TestFlush_DeletesRideTheMarkerBatch(t *testing.T) {
	written := flushOrderingFixture(t, 400, 0)

	if len(written) < 2 {
		t.Fatalf("precondition: the flush did not chunk (%d batch(es)); the ordering "+
			"guarantee is untested", len(written))
	}
	totalDeletes := 0
	for i, b := range written {
		totalDeletes += b.deletes
		if b.deletes > 0 && !b.markerPut {
			t.Errorf("batch %d/%d committed %d coin delete(s) WITHOUT the coins marker: "+
				"a crash here leaves durable spends under a marker that still names a "+
				"lower block, and recovery re-applies that span",
				i+1, len(written), b.deletes)
		}
	}
	if totalDeletes != 400 {
		t.Fatalf("precondition: %d deletes reached the DB, want 400", totalDeletes)
	}
	// The marker must be published exactly once, in the last batch.
	if !written[len(written)-1].markerPut {
		t.Errorf("the final batch did not carry the coins marker")
	}
	for i, b := range written[:len(written)-1] {
		if b.markerPut {
			t.Errorf("batch %d published the coins marker before the flush finished", i+1)
		}
	}
}

// TestFlush_RecordsInterruptedWindowWhenDeletesMustSpanBatches pins the escape
// hatch: when the deletes ALONE cannot fit one batch the tear is unavoidable,
// so it must be made DETECTABLE — Core's DB_HEAD_BLOCKS, written before the
// first delete lands and erased in the same batch as the final marker.
func TestFlush_RecordsInterruptedWindowWhenDeletesMustSpanBatches(t *testing.T) {
	// A cap below the total delete cost of 400 keys forces the torn-window path.
	written := flushOrderingFixture(t, 400, 512)

	var openedAt, closedAt = -1, -1
	for i, b := range written {
		if b.flushRecPut {
			openedAt = i
		}
		if b.flushRecDel {
			closedAt = i
		}
	}
	if openedAt < 0 {
		t.Fatalf("deletes had to span batches but NO interrupted-flush record was "+
			"written: a crash mid-delete would leave durable spends under a stale "+
			"marker with nothing on disk to say so (%d batches)", len(written))
	}
	if closedAt != len(written)-1 {
		t.Errorf("interrupted-flush record erased in batch %d of %d; it must be erased "+
			"in the LAST batch, together with the marker", closedAt+1, len(written))
	}
	if !written[len(written)-1].markerPut {
		t.Errorf("the final batch did not carry the coins marker")
	}
	for _, b := range written[openedAt+1 : closedAt] {
		if b.markerPut {
			t.Errorf("the marker was published while the interrupted-flush window was open")
		}
	}
}

// TestDurableCoinsTip_FailsClosedOnInterruptedFlush pins the read side: while
// an interrupted-flush record exists the persisted set is somewhere between two
// markers and NEITHER describes it, so the marker must be refused outright and
// nothing may be adopted from it.
func TestDurableCoinsTip_FailsClosedOnInterruptedFlush(t *testing.T) {
	const victimH, total = 20, 121
	chainDB, _, _, _, _ := markerProbeChain(t, victimH, total)

	params := RegtestParams()
	idx := NewHeaderIndex(params)
	cm := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: idx, ChainDB: chainDB, UTXOSet: NewUTXOSet(chainDB),
	})
	if _, _, ok := cm.DurableCoinsTip(); !ok {
		t.Fatalf("precondition: the marker should be usable before the record is written")
	}

	rec := append(
		(&storage.ChainState{BestHash: wire.Hash256{0x11}, BestHeight: 30}).Serialize(),
		(&storage.ChainState{BestHash: wire.Hash256{0x22}, BestHeight: 40}).Serialize()...)
	if err := chainDB.DB().Put(storage.CoinsFlushKey, rec); err != nil {
		t.Fatalf("write interrupted-flush record: %v", err)
	}

	cm2 := NewChainManager(ChainManagerConfig{
		Params: params, HeaderIndex: NewHeaderIndex(params), ChainDB: chainDB, UTXOSet: NewUTXOSet(chainDB),
	})
	if hash, height, ok := cm2.DurableCoinsTip(); ok {
		t.Errorf("the coins marker %s@%d was accepted while an interrupted coin flush "+
			"is recorded — the persisted set is between two markers and neither "+
			"describes it", hash.String()[:16], height)
	}
}
