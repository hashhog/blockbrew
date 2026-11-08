package mempool

import (
	"math"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/clock"
	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Core limits the mempool by CTxMemPool::DynamicMemoryUsage, not by the
// transactions' vsize: TrimToSize (txmempool.cpp:868) evicts while
// DynamicMemoryUsage() > sizelimit, and GetMinFee (txmempool.cpp:836-840)
// picks the rolling-fee halflife from DynamicMemoryUsage() against the same
// limit. In the Core regtest pressure step (-maxmempool=5, fourteen
// 800-input transactions) Core keeps 14 with usage 4,773,160 while
// blockbrew kept 16 with a vsize sum of 927,648 and never evicted.

// trimTestTx is a 1-in/1-out spend with a 107-byte scriptSig: about 190 vB,
// but a little over 1 KB of Core memory once in the pool.
func trimTestTx(tag byte) *wire.MsgTx {
	var prev wire.Hash256
	prev[0] = 0x7e
	prev[1] = tag
	return createTestTransaction([]wire.OutPoint{{Hash: prev, Index: 0}}, 90_000, 1)
}

func newTrimTestMempool(maxSize int64) *Mempool {
	return New(Config{
		MaxSize:                maxSize,
		MinRelayFeeRate:        1000,
		IncrementalRelayFee:    1000,
		MaxOrphanTxs:           100,
		ChainParams:            consensus.RegtestParams(),
		MempoolFullRBF:         true,
		MempoolFullRBFExplicit: true,
	}, newTestUTXOSet())
}

func TestTrimToSizeLimitsDynamicMemoryUsage(t *testing.T) {
	// Three ~190 vB transactions: 570 vB, far below the limit, but about
	// 3.2 KB of Core memory, above it. Core evicts the lowest-feerate one.
	mp := newTrimTestMempool(2500)
	fees := []int64{1000, 2000, 3000}
	var hashes []wire.Hash256
	var sizes []int64
	for i, fee := range fees {
		tx := trimTestTx(byte(i))
		h := tx.TxHash()
		hashes = append(hashes, h)
		size := int64(consensus.CalcTxWeight(tx)+3) / 4
		sizes = append(sizes, size)
		InjectTestEntry(mp, &TxEntry{Tx: tx, TxHash: h, Fee: fee, Size: size,
			FeeRate: float64(fee) / float64(size), Time: time.Now(),
			DescendantFee: fee, DescendantSize: size, AncestorFee: fee, AncestorSize: size})
	}
	mp.mu.Lock()
	if mp.totalSize >= mp.config.MaxSize {
		mp.mu.Unlock()
		t.Fatalf("test setup: vsize sum %d must stay below the limit %d", mp.totalSize, mp.config.MaxSize)
	}
	mp.maybeEvictLocked()
	mp.mu.Unlock()

	if got := mp.Count(); got != 2 {
		t.Fatalf("after trim: %d transactions in the pool, want 2 (Core evicts until DynamicMemoryUsage <= -maxmempool)", got)
	}
	if mp.HasTransaction(hashes[0]) {
		t.Fatalf("the lowest-feerate transaction %s was kept", hashes[0])
	}
	if !mp.HasTransaction(hashes[1]) || !mp.HasTransaction(hashes[2]) {
		t.Fatal("a higher-feerate transaction was evicted")
	}
	// TrimToSize bumps the floor to CFeeRate{fee, vsize} + incremental, both
	// whole sat/kvB: the evicted feerate rounds down before the addition.
	wantRolling := float64(fees[0]*1000/sizes[0] + mp.config.IncrementalRelayFee)
	mp.mu.RLock()
	rolling := mp.rollingMinimumFeeRate
	mp.mu.RUnlock()
	if rolling != wantRolling {
		t.Fatalf("rolling minimum fee after eviction = %v sat/kvB, want %v (whole sat/kvB, as Core's CFeeRate)", rolling, wantRolling)
	}
	if floor := mp.GetMinFeeRate(); floor <= mp.config.MinRelayFeeRate {
		t.Fatalf("mempoolminfee %d sat/kvB not bumped above minrelay after an eviction", floor)
	}
}

func TestRollingFeeHalflifeUsesDynamicMemoryUsage(t *testing.T) {
	// Pool memory is at least half the limit (full 12h halflife in Core)
	// while the vsize sum is under a quarter of it (3h halflife if fullness
	// were measured by vsize). After 12h Core's rolling floor halves once.
	defer clock.SetMock(0)
	const start = int64(1_800_000_000)
	clock.SetMock(start)

	mp := newTrimTestMempool(4000)
	for i := 0; i < 2; i++ {
		tx := trimTestTx(byte(0x10 + i))
		size := int64(consensus.CalcTxWeight(tx)+3) / 4
		InjectTestEntry(mp, &TxEntry{Tx: tx, TxHash: tx.TxHash(), Fee: 5000, Size: size, Time: time.Now()})
	}
	mp.mu.Lock()
	if mp.totalSize*4 >= mp.config.MaxSize {
		mp.mu.Unlock()
		t.Fatalf("test setup: vsize sum %d must be under a quarter of %d", mp.totalSize, mp.config.MaxSize)
	}
	mp.rollingMinimumFeeRate = 8000
	mp.blockSinceLastRollingFeeBump = true
	mp.lastRollingFeeUpdate = start
	mp.mu.Unlock()

	clock.SetMock(start + 12*60*60)
	got := mp.GetMinFeeRate()
	if want := int64(4000); got != want {
		t.Fatalf("rolling floor after 12h = %d sat/kvB, want %d (one halving: DynamicMemoryUsage >= -maxmempool/2)", got, want)
	}
	if math.Abs(mp.rollingMinimumFeeRate-4000) > 1e-6 {
		t.Fatalf("rolling rate %.3f, want 4000", mp.rollingMinimumFeeRate)
	}
}
