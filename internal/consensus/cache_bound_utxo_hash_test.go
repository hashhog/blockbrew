package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/storage"
	"github.com/hashhog/blockbrew/internal/wire"
)

// The node now shrinks its coins cache bound to fit a cgroup memory limit
// (cmd/blockbrew membudget.go), so the same chain is connected with far more
// evictions and flushes than before. The cache bound may change WHEN coins
// leave memory, never WHICH coins exist: the same block sequence must give
// the same hash_serialized_3 under the old mainnet bound (6553 MiB, never
// evicts here) and under a bound small enough to evict on every block.
func TestUTXOHashIdenticalUnderClampedCacheBound(t *testing.T) {
	run := func(maxCacheBytes int64, corrupt bool) (wire.Hash256, uint64) {
		u := NewUTXOSetWithMaxCache(storage.NewChainDB(storage.NewMemDB()), maxCacheBytes)
		var added []wire.OutPoint
		rng := uint64(0x9E3779B97F4A7C15)
		for blk := 1; blk <= 120; blk++ {
			for i := 0; i < 200; i++ {
				op := createTestOutpoint(byte(blk), uint32(blk*1000+i))
				u.AddUTXO(op, createTestEntry(int64(blk*1000+i), int32(blk), i == 0, []byte{0x51, byte(i)}))
				added = append(added, op)
			}
			for i := 0; i < 120; i++ { // spends reach back into evicted coins
				rng ^= rng << 13
				rng ^= rng >> 7
				rng ^= rng << 17
				op := added[rng%uint64(len(added))]
				if u.GetUTXO(op) != nil {
					u.SpendUTXO(op)
				}
			}
			if err := u.MaybeFlush(1); err != nil {
				t.Fatalf("flush at block %d: %v", blk, err)
			}
		}
		if corrupt { // negative control: one coin's amount differs
			op := added[len(added)-1]
			e := u.GetUTXO(op)
			if e == nil {
				t.Fatal("control coin missing")
			}
			u.SpendUTXO(op)
			u.AddUTXO(op, createTestEntry(e.Amount+1, e.Height, e.IsCoinbase, e.PkScript))
		}
		h, n, err := ComputeHashSerialized(u)
		if err != nil {
			t.Fatal(err)
		}
		return h, n
	}

	oldBound := int64(8192<<20) * 8 / 10
	wantHash, wantN := run(oldBound, false)
	gotHash, gotN := run(2048, false) // ~10 coins: evicts on every flush
	if gotHash != wantHash || gotN != wantN {
		t.Fatalf("clamped cache bound changed the coins set: %s (%d coins) vs %s (%d coins)",
			gotHash, gotN, wantHash, wantN)
	}
	if ctl, _ := run(2048, true); ctl == wantHash {
		t.Fatal("control: a changed coin did not change the hash; the comparison sees nothing")
	}
}
