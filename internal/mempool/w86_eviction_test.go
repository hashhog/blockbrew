// Package mempool — W86 eviction audit tests.
//
// Tests all ~22 gates across 5 functions:
//   Expire (6 gates), TrimToSize/maybeEvictLocked (7 gates),
//   GetMinFee/getMinFeeRateLocked (6 gates),
//   trackPackageRemovedLocked (2 gates),
//   RemoveForReorg (3 gates).
//
// Reference: Bitcoin Core txmempool.cpp:811-915 (GetMinFee, Expire,
// trackPackageRemoved, TrimToSize) and txmempool.cpp:360-386 (removeForReorg).
package mempool

import (
	"math"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newW86Pool(maxSize int64) *Mempool {
	return New(Config{
		MaxSize:             maxSize,
		MinRelayFeeRate:     1000, // 1 sat/vB = 1 sat/kvB*1000
		IncrementalRelayFee: 1000,
		MaxOrphanTxs:        10,
		ChainParams:         consensus.RegtestParams(),
	}, newTestUTXOSet())
}

// injectEntry bypasses all policy checks and injects a TxEntry directly.
// A minimal MsgTx with no inputs is included so that removeSingleTxLocked
// can safely range over entry.Tx.TxIn without panicking.
func injectEntry(mp *Mempool, h wire.Hash256, fee, size int64, addedAt time.Time) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.pool[h] = &TxEntry{
		Tx:             &wire.MsgTx{Version: 1},
		TxHash:         h,
		Fee:            fee,
		Size:           size,
		FeeRate:        float64(fee) / float64(size),
		Time:           addedAt,
		AncestorFee:    fee,
		AncestorSize:   size,
		DescendantFee:  fee,
		DescendantSize: size,
	}
	mp.totalSize += size
}

// injectCoinbaseUTXO puts a coinbase UTXO into the test UTXO set.
func injectCoinbaseUTXO(utxos *testUTXOSet, op wire.OutPoint, amount int64, height int32) {
	utxos.utxos[op] = &consensus.UTXOEntry{
		Amount:     amount,
		PkScript:   []byte{0x51}, // OP_1 (non-dust)
		Height:     height,
		IsCoinbase: true,
	}
}

// ---------------------------------------------------------------------------
// trackPackageRemovedLocked gates
// ---------------------------------------------------------------------------

// Gate P1 — rate is bumped when the new rate exceeds the current floor.
// Core: txmempool.cpp:855 (rate.GetFeePerK() > rollingMinimumFeeRate).
func TestTrackPackageRemoved_BumpsWhenHigher(t *testing.T) {
	mp := newW86Pool(300_000_000)

	mp.mu.Lock()
	mp.trackPackageRemovedLocked(5000)
	rate := mp.rollingMinimumFeeRate
	bump := mp.blockSinceLastRollingFeeBump
	mp.mu.Unlock()

	if rate != 5000 {
		t.Errorf("rollingMinimumFeeRate = %.0f, want 5000", rate)
	}
	if bump {
		t.Error("blockSinceLastRollingFeeBump should be cleared after eviction")
	}
}

// Gate P2 — rate is NOT lowered when the new rate is below the current floor.
// Core: txmempool.cpp:855 (if rate.GetFeePerK() > rollingMinimumFeeRate).
func TestTrackPackageRemoved_NoLowerWhenBelow(t *testing.T) {
	mp := newW86Pool(300_000_000)

	mp.mu.Lock()
	mp.trackPackageRemovedLocked(8000)
	mp.trackPackageRemovedLocked(3000) // below current floor — must not lower
	rate := mp.rollingMinimumFeeRate
	mp.mu.Unlock()

	if rate != 8000 {
		t.Errorf("rollingMinimumFeeRate = %.0f, want 8000 (must not be lowered)", rate)
	}
}

// ---------------------------------------------------------------------------
// maybeEvictLocked (TrimToSize) gates
// ---------------------------------------------------------------------------

// Gate T1 — pool stays within MaxSize after eviction.
// Core: txmempool.cpp:868 (while DynamicMemoryUsage() > sizelimit).
func TestTrimToSize_PoolWithinLimit(t *testing.T) {
	mp := newW86Pool(500)

	now := time.Now()
	injectEntry(mp, wire.Hash256{1}, 300, 300, now) // 300 sat / 300 vB = 1000 sat/kvB
	injectEntry(mp, wire.Hash256{2}, 100, 100, now) // lower feerate
	// total = 400 — still within 500, no eviction yet

	mp.mu.Lock()
	mp.maybeEvictLocked()
	total := mp.totalSize
	mp.mu.Unlock()

	if total > mp.config.MaxSize {
		t.Errorf("totalSize = %d after eviction, want <= %d", total, mp.config.MaxSize)
	}
}

// Gate T2 — lower-feerate transaction is evicted before higher-feerate one.
// Core: TrimToSize evicts the worst chunk (lowest feerate).
func TestTrimToSize_EvictsLowerFeeFirst(t *testing.T) {
	mp := newW86Pool(300)

	now := time.Now()
	// High-fee tx: 500 sat / 150 vB ≈ 3.33 sat/vB
	injectEntry(mp, wire.Hash256{0xAA}, 500, 150, now)
	// Low-fee tx:  50 sat / 200 vB = 0.25 sat/vB
	injectEntry(mp, wire.Hash256{0xBB}, 50, 200, now)
	// total = 350 > 300 → eviction fires

	mp.mu.Lock()
	mp.maybeEvictLocked()
	_, highFeePresent := mp.pool[wire.Hash256{0xAA}]
	_, lowFeePresent := mp.pool[wire.Hash256{0xBB}]
	mp.mu.Unlock()

	if lowFeePresent {
		t.Error("low-fee tx should have been evicted")
	}
	if !highFeePresent {
		t.Error("high-fee tx should have been retained")
	}
}

// Gate T3 — rollingMinimumFeeRate is bumped after TrimToSize eviction.
// Core: txmempool.cpp:876-878 (trackPackageRemoved(removed)).
func TestTrimToSize_BumpsRollingMinFee(t *testing.T) {
	mp := newW86Pool(300)

	now := time.Now()
	// tx at 1 sat/vB = 1000 sat/kvB
	injectEntry(mp, wire.Hash256{0xCC}, 100, 100, now) // within limit
	injectEntry(mp, wire.Hash256{0xDD}, 100, 250, now) // over limit → eviction

	mp.mu.Lock()
	before := mp.rollingMinimumFeeRate
	mp.maybeEvictLocked()
	after := mp.rollingMinimumFeeRate
	mp.mu.Unlock()

	if after <= before {
		t.Errorf("rollingMinimumFeeRate should be bumped after eviction: before=%.0f after=%.0f", before, after)
	}
}

// Gate T4 — blockSinceLastRollingFeeBump is cleared after TrimToSize.
// Core: txmempool.cpp:857 (blockSinceLastRollingFeeBump = false).
func TestTrimToSize_ClearsBlockSinceFlag(t *testing.T) {
	mp := newW86Pool(100)

	// Arm the flag as if a block just came in.
	mp.mu.Lock()
	mp.blockSinceLastRollingFeeBump = true
	mp.mu.Unlock()

	injectEntry(mp, wire.Hash256{0xEE}, 10, 200, time.Now()) // exceeds MaxSize=100

	mp.mu.Lock()
	mp.maybeEvictLocked()
	flag := mp.blockSinceLastRollingFeeBump
	mp.mu.Unlock()

	if flag {
		t.Error("blockSinceLastRollingFeeBump should be cleared after eviction")
	}
}

// Gate T5 — empty pool: eviction loop terminates without panic.
func TestTrimToSize_EmptyPool(t *testing.T) {
	mp := newW86Pool(100)
	mp.mu.Lock()
	mp.totalSize = 200 // force the condition
	mp.maybeEvictLocked()
	mp.mu.Unlock()
	// must not panic
}

// Gate T6 — pool exactly at limit: no eviction occurs.
func TestTrimToSize_ExactlyAtLimit(t *testing.T) {
	mp := newW86Pool(100)
	injectEntry(mp, wire.Hash256{0xFF}, 100, 100, time.Now())

	mp.mu.Lock()
	sizeBefore := mp.totalSize
	mp.maybeEvictLocked()
	sizeAfter := mp.totalSize
	mp.mu.Unlock()

	if sizeBefore != sizeAfter {
		t.Errorf("pool exactly at limit: size changed from %d to %d", sizeBefore, sizeAfter)
	}
}

// Gate T7 — rollingMinimumFeeRate >= evicted_chunk_feerate + incremental.
// Specifically: the bumped rate equals chunk_rate_sat_kvb + IncrementalRelayFee.
// Core: txmempool.cpp:877 (removed += m_opts.incremental_relay_feerate).
func TestTrimToSize_BumpIncludesIncrementalFee(t *testing.T) {
	mp := newW86Pool(150)
	// 200 sat / 200 vB = 1 sat/vB = 1000 sat/kvB; pool size 200 > limit 150.
	injectEntry(mp, wire.Hash256{0x01}, 200, 200, time.Now())

	mp.mu.Lock()
	mp.maybeEvictLocked()
	rate := mp.rollingMinimumFeeRate
	mp.mu.Unlock()

	// chunk rate = 1000 sat/kvB; incremental = 1000 sat/kvB; expected = 2000.
	if rate < 1999 || rate > 2001 {
		t.Errorf("rollingMinimumFeeRate = %.0f, want ~2000 (chunk 1000 + incr 1000)", rate)
	}
}

// ---------------------------------------------------------------------------
// Expire gates
// ---------------------------------------------------------------------------

// Gate E1 — transactions older than the cutoff are removed.
// Core: txmempool.cpp:817 (entry.GetTime() < time).
func TestExpire_RemovesOldTxs(t *testing.T) {
	mp := newW86Pool(300_000_000)

	old := time.Now().Add(-400 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)

	injectEntry(mp, wire.Hash256{0x01}, 100, 100, old)
	injectEntry(mp, wire.Hash256{0x02}, 100, 100, recent)

	cutoff := time.Now().Add(-336 * time.Hour) // 14 days
	removed := mp.Expire(cutoff)

	mp.mu.RLock()
	_, oldPresent := mp.pool[wire.Hash256{0x01}]
	_, recentPresent := mp.pool[wire.Hash256{0x02}]
	mp.mu.RUnlock()

	if removed != 1 {
		t.Errorf("Expire removed %d txs, want 1", removed)
	}
	if oldPresent {
		t.Error("old tx should have been expired")
	}
	if !recentPresent {
		t.Error("recent tx should have been kept")
	}
}

// Gate E2 — descendants of expired transactions are also removed.
// Core: txmempool.cpp:822-824 (CalculateDescendants → stage).
func TestExpire_RemovesDescendants(t *testing.T) {
	mp := newW86Pool(300_000_000)

	old := time.Now().Add(-400 * time.Hour)

	// parent (old) and child (recent, but depends on old parent)
	parentHash := wire.Hash256{0x01}
	childHash := wire.Hash256{0x02}

	minimalTx := func() *wire.MsgTx { return &wire.MsgTx{Version: 1} }

	mp.mu.Lock()
	mp.pool[parentHash] = &TxEntry{
		Tx: minimalTx(), TxHash: parentHash, Fee: 100, Size: 100, Time: old,
		FeeRate: 1.0, AncestorFee: 100, AncestorSize: 100,
		DescendantFee: 200, DescendantSize: 200,
	}
	mp.pool[childHash] = &TxEntry{
		Tx: minimalTx(), TxHash: childHash, Fee: 100, Size: 100,
		Time:    time.Now().Add(-1 * time.Hour), // recent
		FeeRate: 1.0, AncestorFee: 200, AncestorSize: 200,
		DescendantFee: 100, DescendantSize: 100,
		Depends: []wire.Hash256{parentHash},
	}
	mp.pool[parentHash].SpentBy = []wire.Hash256{childHash}
	mp.totalSize = 200
	mp.mu.Unlock()

	cutoff := time.Now().Add(-336 * time.Hour)
	removed := mp.Expire(cutoff)

	mp.mu.RLock()
	_, parentPresent := mp.pool[parentHash]
	_, childPresent := mp.pool[childHash]
	mp.mu.RUnlock()

	if parentPresent {
		t.Error("expired parent should have been removed")
	}
	if childPresent {
		t.Error("child of expired parent should also have been removed")
	}
	if removed != 2 {
		t.Errorf("Expire removed %d txs, want 2 (parent + child)", removed)
	}
}

// Gate E3 — time-equal to cutoff: tx at exactly cutoff is NOT removed.
// Core: txmempool.cpp:817 (strict < not <=).
func TestExpire_TimeEqualCutoffNotRemoved(t *testing.T) {
	mp := newW86Pool(300_000_000)

	cutoff := time.Now().Add(-336 * time.Hour)
	injectEntry(mp, wire.Hash256{0x10}, 100, 100, cutoff)

	removed := mp.Expire(cutoff)
	if removed != 0 {
		t.Errorf("Expire removed %d txs for tx added exactly at cutoff, want 0", removed)
	}
}

// Gate E4 — empty mempool: Expire returns 0 without panic.
func TestExpire_EmptyMempool(t *testing.T) {
	mp := newW86Pool(300_000_000)
	removed := mp.Expire(time.Now())
	if removed != 0 {
		t.Errorf("Expire on empty mempool returned %d, want 0", removed)
	}
}

// Gate E5 — nothing expired: all transactions are younger than cutoff.
func TestExpire_NoneExpired(t *testing.T) {
	mp := newW86Pool(300_000_000)
	injectEntry(mp, wire.Hash256{0x20}, 100, 100, time.Now())
	injectEntry(mp, wire.Hash256{0x21}, 100, 100, time.Now().Add(-1*time.Hour))

	cutoff := time.Now().Add(-336 * time.Hour)
	removed := mp.Expire(cutoff)
	if removed != 0 {
		t.Errorf("Expire removed %d txs, want 0 (none old enough)", removed)
	}
	mp.mu.RLock()
	poolSize := len(mp.pool)
	mp.mu.RUnlock()
	if poolSize != 2 {
		t.Errorf("pool has %d entries, want 2", poolSize)
	}
}

// Gate E6 — all transactions expired: pool is empty afterwards.
func TestExpire_AllExpired(t *testing.T) {
	mp := newW86Pool(300_000_000)
	old := time.Now().Add(-500 * time.Hour)
	injectEntry(mp, wire.Hash256{0x30}, 100, 100, old)
	injectEntry(mp, wire.Hash256{0x31}, 200, 200, old)

	cutoff := time.Now().Add(-336 * time.Hour)
	removed := mp.Expire(cutoff)

	mp.mu.RLock()
	remaining := len(mp.pool)
	mp.mu.RUnlock()

	if removed != 2 {
		t.Errorf("Expire removed %d txs, want 2", removed)
	}
	if remaining != 0 {
		t.Errorf("pool has %d entries after full expire, want 0", remaining)
	}
}

// ---------------------------------------------------------------------------
// getMinFeeRateLocked / GetMinFee gates
// ---------------------------------------------------------------------------

// Gate F1 — initial state: returns MinRelayFeeRate when no eviction occurred.
// Core: rollingMinimumFeeRate starts at 0; GetMinFee returns incremental_relay_feerate.
func TestGetMinFeeRateLocked_InitialState(t *testing.T) {
	mp := newW86Pool(300_000_000)
	rate := mp.GetMinFeeRate()
	if rate != 1000 {
		t.Errorf("initial GetMinFeeRate() = %d, want 1000", rate)
	}
}

// Gate F2 — blockSinceLastRollingFeeBump = false: no decay applied.
// Core: txmempool.cpp:831 (if (!blockSinceLastRollingFeeBump || …) return …).
func TestGetMinFeeRateLocked_NoDecayWithoutBlock(t *testing.T) {
	mp := newW86Pool(300_000_000)

	mp.mu.Lock()
	mp.rollingMinimumFeeRate = 5000
	mp.blockSinceLastRollingFeeBump = false
	// Push update time far in the past to ensure no time-gating
	mp.lastRollingFeeUpdate = time.Now().Unix() - 86400
	mp.mu.Unlock()

	rate := mp.GetMinFeeRate()
	if rate != 5000 {
		t.Errorf("GetMinFeeRate() = %d, want 5000 (no decay without block)", rate)
	}
}

// Gate F3 — halflife /4 when totalSize < sizelimit/4.
// Core: txmempool.cpp:837-838 (halflife /= 4 when < sizelimit/4).
func TestGetMinFeeRateLocked_HalflifeQuarterWhenQuarterFull(t *testing.T) {
	mp := newW86Pool(300_000_000)

	// Use a rate high enough to survive a quarter-halflife decay.
	// halflife = 3h (12h/4).  After 6h (= 2 halflives): rate / 4.
	const initialRate = 4096.0 // power-of-two for exact arithmetic

	mp.mu.Lock()
	mp.rollingMinimumFeeRate = initialRate
	mp.blockSinceLastRollingFeeBump = true
	// elapsed = 6h exactly = 21600s; halflife = 3h = 10800s → pow(2,2) = 4
	mp.lastRollingFeeUpdate = time.Now().Unix() - 2*3*60*60
	mp.totalSize = 0 // < sizelimit/4
	mp.mu.Unlock()

	rate := mp.GetMinFeeRate()
	expected := int64(initialRate / 4)
	tolerance := int64(10)
	if math.Abs(float64(rate-expected)) > float64(tolerance) {
		t.Errorf("GetMinFeeRate() = %d, want ~%d (6h at 3h-halflife)", rate, expected)
	}
}

// Gate F4 — halflife /2 when sizelimit/4 <= totalSize < sizelimit/2.
// Core: txmempool.cpp:839-840.
func TestGetMinFeeRateLocked_HalflifeHalfWhenHalfFull(t *testing.T) {
	const maxSize = int64(1_000_000)
	mp := newW86Pool(maxSize)

	const initialRate = 4096.0

	mp.mu.Lock()
	mp.rollingMinimumFeeRate = initialRate
	mp.blockSinceLastRollingFeeBump = true
	// elapsed = 6h = 21600s; halflife = 6h = 21600s → pow(2,1) = 2
	mp.lastRollingFeeUpdate = time.Now().Unix() - 6*60*60
	// Between 1/4 and 1/2 of maxSize
	mp.totalSize = maxSize / 3
	mp.mu.Unlock()

	rate := mp.GetMinFeeRate()
	expected := int64(initialRate / 2)
	tolerance := int64(10)
	if math.Abs(float64(rate-expected)) > float64(tolerance) {
		t.Errorf("GetMinFeeRate() = %d, want ~%d (6h at 6h-halflife)", rate, expected)
	}
}

// Gate F5 — rate zeroed when it decays below incremental_relay_feerate / 2.
// Core: txmempool.cpp:845-848.
func TestGetMinFeeRateLocked_ZeroedBelowHalfIncremental(t *testing.T) {
	mp := newW86Pool(300_000_000)

	// Set a rate that is above incremental/2 = 500 before decay, but will
	// definitely decay below 500 after a long elapsed time.
	// halflife = 3h (totalSize = 0 → /4 divisor).
	// Use elapsed = 48h = 16 halflives → 800 / 65536 ≈ 0.01 << 500 → zeroed.
	mp.mu.Lock()
	mp.rollingMinimumFeeRate = 800
	mp.blockSinceLastRollingFeeBump = true
	mp.lastRollingFeeUpdate = time.Now().Unix() - 48*60*60 // 48h ago
	mp.totalSize = 0                                        // use /4 halflife (aggressive)
	mp.mu.Unlock()

	rate := mp.GetMinFeeRate()
	// After decay, rate < 500 → zeroed → return MinRelayFeeRate = 1000
	if rate != 1000 {
		t.Errorf("GetMinFeeRate() = %d, want 1000 (zeroed + MinRelayFeeRate floor)", rate)
	}

	// Confirm rollingMinimumFeeRate is now 0.
	mp.mu.RLock()
	rolling := mp.rollingMinimumFeeRate
	mp.mu.RUnlock()
	if rolling != 0 {
		t.Errorf("rollingMinimumFeeRate = %.0f after zero-out, want 0", rolling)
	}
}

// Gate F6 — result is max(rolling, incremental, MinRelayFeeRate).
// Core: txmempool.cpp:850 (max(CFeeRate(llround(rollingMinimumFeeRate)),
// m_opts.incremental_relay_feerate)).
func TestGetMinFeeRateLocked_MaxFloor(t *testing.T) {
	mp := newW86Pool(300_000_000)

	// rolling = 1500, incremental = 1000, minRelay = 1000 → expect 1500
	mp.mu.Lock()
	mp.rollingMinimumFeeRate = 1500
	mp.blockSinceLastRollingFeeBump = false
	mp.mu.Unlock()

	rate := mp.GetMinFeeRate()
	if rate != 1500 {
		t.Errorf("GetMinFeeRate() = %d, want 1500 (rolling > incremental)", rate)
	}
}

// ---------------------------------------------------------------------------
// RemoveForReorg gates
// ---------------------------------------------------------------------------

// mockChainState implements ChainState for testing.
type mockChainState struct {
	height int32
	mtp    int64
}

func (m *mockChainState) TipHeight() int32 { return m.height }
func (m *mockChainState) TipMTP() int64    { return m.mtp }
func (m *mockChainState) MTPAtHeight(height int32) int64 {
	if height == m.height {
		return m.mtp
	}
	return m.mtp - int64(m.height-height)*600
}

// Gate R1 — non-final transaction is removed after reorg.
// A tx with nLockTime = tip+2 is non-final at the new tip.
// Core: txmempool.cpp:369 (check_final_and_mature — IsFinalTx check).
func TestRemoveForReorg_NonFinalTxRemoved(t *testing.T) {
	utxos := newTestUTXOSet()
	op := wire.OutPoint{Hash: wire.Hash256{0xAA}, Index: 0}
	utxos.utxos[op] = &consensus.UTXOEntry{
		Amount:     1_000_000,
		PkScript:   []byte{0x51},
		Height:     100,
		IsCoinbase: false,
	}

	chainState := &mockChainState{height: 200, mtp: 1_700_000_000}
	mp := New(Config{
		MaxSize:             300_000_000,
		MinRelayFeeRate:     1000,
		IncrementalRelayFee: 1000,
		MaxOrphanTxs:        10,
		ChainParams:         consensus.RegtestParams(),
		ChainState:          chainState,
	}, utxos)

	// nLockTime = 210 means the tx is final only when height >= 210.
	// At tip+1 = 201, it is non-final.
	// Sequence must be < 0xffffffff so IsFinalTx cannot short-circuit via
	// the "all-inputs finalized" path.  Core: consensus/tx_verify.cpp IsFinalTx.
	nonFinalTx := &wire.MsgTx{
		Version:  1,
		LockTime: 210, // non-final at height 201
		TxIn:     []*wire.TxIn{{PreviousOutPoint: op, Sequence: 0xfffffffe}},
		TxOut:    []*wire.TxOut{{Value: 900_000, PkScript: []byte{0x51}}},
	}
	txHash := nonFinalTx.TxHash()

	mp.mu.Lock()
	mp.pool[txHash] = &TxEntry{
		Tx: nonFinalTx, TxHash: txHash,
		Fee: 100_000, Size: 200, Time: time.Now(),
		AncestorFee: 100_000, AncestorSize: 200,
		DescendantFee: 100_000, DescendantSize: 200,
	}
	mp.totalSize = 200
	mp.mu.Unlock()

	removed := mp.RemoveForReorg()

	mp.mu.RLock()
	_, present := mp.pool[txHash]
	mp.mu.RUnlock()

	if removed != 1 {
		t.Errorf("RemoveForReorg removed %d txs, want 1", removed)
	}
	if present {
		t.Error("non-final tx should have been removed by RemoveForReorg")
	}
}

// Gate R2 — tx spending an immature coinbase output is removed.
// Core: txmempool.cpp:369 (check_final_and_mature — coinbase maturity check).
func TestRemoveForReorg_ImmatureCoinbaseSpendRemoved(t *testing.T) {
	utxos := newTestUTXOSet()

	// Coinbase output at height 150; tip = 200; confirmations = 51 < 100 = immature.
	coinbaseOut := wire.OutPoint{Hash: wire.Hash256{0xCB}, Index: 0}
	injectCoinbaseUTXO(utxos, coinbaseOut, 5_000_000_000, 150)

	chainState := &mockChainState{height: 200, mtp: 1_700_000_000}
	mp := New(Config{
		MaxSize:             300_000_000,
		MinRelayFeeRate:     1000,
		IncrementalRelayFee: 1000,
		MaxOrphanTxs:        10,
		ChainParams:         consensus.RegtestParams(),
		ChainState:          chainState,
	}, utxos)

	// Final tx but spends immature coinbase.
	spendTx := &wire.MsgTx{
		Version:  1,
		LockTime: 0, // final
		TxIn:     []*wire.TxIn{{PreviousOutPoint: coinbaseOut, Sequence: 0xffffffff}},
		TxOut:    []*wire.TxOut{{Value: 4_999_000_000, PkScript: []byte{0x51}}},
	}
	txHash := spendTx.TxHash()

	mp.mu.Lock()
	mp.pool[txHash] = &TxEntry{
		Tx: spendTx, TxHash: txHash,
		Fee: 1_000_000, Size: 200, Time: time.Now(),
		AncestorFee: 1_000_000, AncestorSize: 200,
		DescendantFee: 1_000_000, DescendantSize: 200,
	}
	mp.totalSize = 200
	mp.mu.Unlock()

	removed := mp.RemoveForReorg()

	mp.mu.RLock()
	_, present := mp.pool[txHash]
	mp.mu.RUnlock()

	if removed != 1 {
		t.Errorf("RemoveForReorg removed %d txs, want 1", removed)
	}
	if present {
		t.Error("tx spending immature coinbase should have been removed")
	}
}

// Gate R3 — mature coinbase spend (>= 100 confirmations) is kept.
// Core: consensus.CoinbaseMaturity = 100.
func TestRemoveForReorg_MatureCoinbaseSpendKept(t *testing.T) {
	utxos := newTestUTXOSet()

	// Coinbase output at height 50; tip = 200; confirmations = 151 >= 100 = mature.
	coinbaseOut := wire.OutPoint{Hash: wire.Hash256{0xCB}, Index: 1}
	injectCoinbaseUTXO(utxos, coinbaseOut, 5_000_000_000, 50)

	chainState := &mockChainState{height: 200, mtp: 1_700_000_000}
	mp := New(Config{
		MaxSize:             300_000_000,
		MinRelayFeeRate:     1000,
		IncrementalRelayFee: 1000,
		MaxOrphanTxs:        10,
		ChainParams:         consensus.RegtestParams(),
		ChainState:          chainState,
	}, utxos)

	spendTx := &wire.MsgTx{
		Version:  1,
		LockTime: 0,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: coinbaseOut, Sequence: 0xffffffff}},
		TxOut:    []*wire.TxOut{{Value: 4_999_000_000, PkScript: []byte{0x51}}},
	}
	txHash := spendTx.TxHash()

	mp.mu.Lock()
	mp.pool[txHash] = &TxEntry{
		Tx: spendTx, TxHash: txHash,
		Fee: 1_000_000, Size: 200, Time: time.Now(),
		AncestorFee: 1_000_000, AncestorSize: 200,
		DescendantFee: 1_000_000, DescendantSize: 200,
	}
	mp.totalSize = 200
	mp.mu.Unlock()

	removed := mp.RemoveForReorg()

	if removed != 0 {
		t.Errorf("RemoveForReorg removed %d txs, want 0 (mature coinbase spend)", removed)
	}
}

// ---------------------------------------------------------------------------
// BlockConnected rolling-fee integration
// ---------------------------------------------------------------------------

// TestBlockConnected_ArmsRollingFeeDecay verifies that BlockConnected sets
// blockSinceLastRollingFeeBump = true and resets lastRollingFeeUpdate.
// Core: txmempool.cpp:426-427.
func TestBlockConnected_ArmsRollingFeeDecay(t *testing.T) {
	mp := newW86Pool(300_000_000)

	// Simulate a prior eviction that bumped the rolling rate and cleared the flag.
	mp.mu.Lock()
	mp.trackPackageRemovedLocked(5000)
	mp.mu.Unlock()

	flagBefore := mp.blockSinceLastRollingFeeBump // should be false after eviction
	if flagBefore {
		t.Error("precondition: blockSinceLastRollingFeeBump should be false after eviction")
	}

	beforeTime := time.Now().Unix()
	block := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{
			{Version: 1, TxIn: []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{}, Sequence: 0xffffffff}},
				TxOut: []*wire.TxOut{{Value: 50_000_000_000, PkScript: []byte{0x51}}}},
		},
	}
	mp.BlockConnected(block)

	mp.mu.RLock()
	flagAfter := mp.blockSinceLastRollingFeeBump
	updateTime := mp.lastRollingFeeUpdate
	mp.mu.RUnlock()

	if !flagAfter {
		t.Error("blockSinceLastRollingFeeBump should be true after BlockConnected")
	}
	if updateTime < beforeTime {
		t.Errorf("lastRollingFeeUpdate = %d, want >= %d", updateTime, beforeTime)
	}
}

// ---------------------------------------------------------------------------
// DefaultMempoolExpiryHours constant
// ---------------------------------------------------------------------------

// TestDefaultMempoolExpiryHours ensures the constant matches Core's 336 hours.
// Core: kernel/mempool_options.h:23.
func TestDefaultMempoolExpiryHours(t *testing.T) {
	if DefaultMempoolExpiryHours != 336 {
		t.Errorf("DefaultMempoolExpiryHours = %d, want 336", DefaultMempoolExpiryHours)
	}
}

// TestRollingFeeHalflife ensures the constant matches Core's 12-hour halflife.
// Core: txmempool.h:212.
func TestRollingFeeHalflife(t *testing.T) {
	want := float64(12 * 60 * 60)
	if rollingFeeHalflife != want {
		t.Errorf("rollingFeeHalflife = %v, want %v", rollingFeeHalflife, want)
	}
}
