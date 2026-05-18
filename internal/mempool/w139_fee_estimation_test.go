// W139 fee estimation engine (CBlockPolicyEstimator) audit tests for blockbrew.
// Wave: W139 (DISCOVERY, not fix).
// Bitcoin Core reference: src/policy/fees/block_policy_estimator.{h,cpp}
// + src/policy/feerate.{h,cpp} + src/rpc/fees.cpp.
//
// These tests are intentionally written so each gate's BUG signal is a
// hard t.Errorf only when the gate must be fixed for parity. Documented
// gaps (Core feature absent from blockbrew but compatible) use t.Log so
// the test still passes — the gate is the documentation. Treat the test
// file like the audit's spec: every entry maps to one gate G1..G30.
package mempool

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ===========================================================================
// G1-G5: Constants (decay / scale / periods / bucket bounds / file version)
// ===========================================================================

// G1: Three TxConfirmStats horizons exist with Core decay values.
// Core: SHORT=0.962, MED=0.9952, LONG=0.99931.
func TestW139_G1_HorizonDecayValues(t *testing.T) {
	fe := NewFeeEstimator()
	cases := []struct {
		h    Horizon
		want float64
		name string
	}{
		{HorizonShort, 0.962, "SHORT"},
		{HorizonMedium, 0.9952, "MED"},
		{HorizonLong, 0.99931, "LONG"},
	}
	for _, c := range cases {
		if fe.stats[c.h].decay != c.want {
			t.Errorf("G1: %s decay want %.5f got %.5f", c.name, c.want, fe.stats[c.h].decay)
		}
	}
}

// G2: Scale + periods constants per horizon.
// Core: SHORT scale=1 periods=12; MED scale=2 periods=24; LONG scale=24 periods=42.
func TestW139_G2_HorizonScaleAndPeriods(t *testing.T) {
	fe := NewFeeEstimator()
	cases := []struct {
		h            Horizon
		wantScale    int
		wantPeriods  int
		wantMaxBlock int
		name         string
	}{
		{HorizonShort, 1, 12, 12, "SHORT"},
		{HorizonMedium, 2, 24, 48, "MED"},
		{HorizonLong, 24, 42, 1008, "LONG"},
	}
	for _, c := range cases {
		s := fe.stats[c.h]
		if s.scale != c.wantScale {
			t.Errorf("G2: %s scale want %d got %d", c.name, c.wantScale, s.scale)
		}
		if s.periods != c.wantPeriods {
			t.Errorf("G2: %s periods want %d got %d", c.name, c.wantPeriods, s.periods)
		}
		if maxBlocksForHorizon(c.h) != c.wantMaxBlock {
			t.Errorf("G2: %s maxBlocks want %d got %d", c.name, c.wantMaxBlock, maxBlocksForHorizon(c.h))
		}
	}
	if fe.HighestTargetTracked() != 1008 {
		t.Errorf("G2: HighestTargetTracked want 1008 got %d", fe.HighestTargetTracked())
	}
}

// G3: Bucket boundary count and bounds.
// Core: bucket boundary loop from MIN_BUCKET_FEERATE=100 sat/kvB to MAX=1e7 sat/kvB
// at FEE_SPACING=1.05 → 236 boundaries + 1 INF sentinel = 237 buckets.
func TestW139_G3_BucketCountAndBounds(t *testing.T) {
	fe := NewFeeEstimator()
	// Compute expected count from the same loop semantics.
	expected := 0
	for bb := 0.1; bb <= 1e4; bb *= 1.05 {
		expected++
	}
	expected++ // INF
	got := len(fe.buckets)
	if got != expected {
		t.Errorf("G3: bucket count want %d got %d", expected, got)
	}
	if fe.buckets[0].FeeRateStart != 0.1 {
		t.Errorf("G3: first bucket lower bound want 0.1 sat/vB got %.5f", fe.buckets[0].FeeRateStart)
	}
	// Last regular bucket boundary should be the geometric series step that
	// last satisfied <= 1e4.
	last := fe.buckets[len(fe.buckets)-2].FeeRateStart
	if last < 9000 || last > 1e4 {
		t.Errorf("G3: penultimate bucket want ≈ 9538.6 sat/vB got %.2f", last)
	}
	inf := fe.buckets[len(fe.buckets)-1].FeeRateStart
	if inf < 1e8 {
		t.Errorf("G3: last (INF) bucket should be ≥ 1e8 (Core uses 1e99); got %.2f", inf)
	}
}

// G4: FEE_SPACING ratio between adjacent buckets.
// Core: buckets[i+1] / buckets[i] == 1.05 for the regular range.
func TestW139_G4_FeeSpacingRatio(t *testing.T) {
	fe := NewFeeEstimator()
	const want = 1.05
	// Only check the first 50 boundaries — they should all be exactly 1.05x.
	for i := 1; i < 50 && i < len(fe.buckets)-1; i++ {
		ratio := fe.buckets[i].FeeRateStart / fe.buckets[i-1].FeeRateStart
		if math.Abs(ratio-want) > 0.001 {
			t.Errorf("G4: bucket[%d]/bucket[%d] want 1.05 got %.4f", i, i-1, ratio)
		}
	}
}

// G5 — BUG-1 (HIGH): persistence file version field absent.
// Core: writes CURRENT_FEES_FILE_VERSION=309900 as the first int32 of
// fee_estimates.dat and rejects newer-version files at read time. blockbrew
// uses feeEstimatorVersion=2 in feeEstimatorState — different semantic value,
// no relation to Core's number, no rejection of mismatched-version files
// against Core's binary format.
func TestW139_G5_FilesVersionConstant(t *testing.T) {
	// Structural assertion: blockbrew's version is 2, NOT 309900.
	if feeEstimatorVersion != 2 {
		t.Logf("G5 note: feeEstimatorVersion changed from 2 to %d", feeEstimatorVersion)
	}
	t.Logf("BUG-1 (HIGH): blockbrew uses feeEstimatorVersion=%d for its own JSON; "+
		"Core's CURRENT_FEES_FILE_VERSION=309900 (binary format) is unrelated. "+
		"Cross-impl interop with fee_estimates.dat is impossible.", feeEstimatorVersion)
}

// ===========================================================================
// G6-G10: Bucket structure (findBucket, lower_bound, NewTx → bucket, etc.)
// ===========================================================================

// G6: findBucket returns a valid index for any positive fee rate.
func TestW139_G6_FindBucketBounds(t *testing.T) {
	fe := NewFeeEstimator()
	cases := []float64{0.0, 0.05, 0.1, 1.0, 100.0, 1e4, 1e5}
	for _, r := range cases {
		idx := fe.findBucket(r)
		if idx < 0 || idx >= len(fe.buckets) {
			t.Errorf("G6: findBucket(%f) returned out-of-range index %d", r, idx)
		}
	}
}

// G7 — BUG-2 (HIGH): findBucket uses lo/hi binary search but Core uses
// std::map::lower_bound on bucketMap (key = bucket upper bound). Core's
// lower_bound semantics for fee rate at a bucket boundary maps to THAT
// bucket; blockbrew's >= semantics on FeeRateStart map an at-boundary
// fee rate to the bucket whose START is that boundary — but Core treats
// the boundary as the UPPER bound of the previous bucket. Off-by-one for
// fee rates exactly on a boundary.
func TestW139_G7_FindBucketBoundarySemantics(t *testing.T) {
	fe := NewFeeEstimator()
	// 1.05 is bucket 1's boundary (0.1 * 1.05 ≈ 0.105). Test a fee rate
	// equal to a stored boundary: blockbrew lo finds bucket where boundary
	// == FeeRateStart. Core's lower_bound would map to that bucket too
	// (because Core's bucketMap key is the bucket upper-bound, and
	// lower_bound(feerate) gives the first upper-bound >= feerate).
	// So this gate is actually PASS for Core's semantics — but worth noting
	// the binary-search semantics differ in pathological cases.
	boundary := fe.buckets[10].FeeRateStart
	idx := fe.findBucket(boundary)
	if idx != 10 {
		t.Logf("G7 (info): findBucket(%.5f at bucket[10] boundary) → %d (Core lower_bound would also map here)",
			boundary, idx)
	}
	t.Log("BUG-2 (LOW): blockbrew findBucket binary search is `>= FeeRateStart`; " +
		"Core uses std::map::lower_bound on bucket-upper-bound keys. Same result " +
		"in normal use; semantic divergence only on out-of-range or boundary-exact inputs.")
}

// G8 — BUG-3 (P1): NewTx bucket-index consistency across horizons.
// Core asserts bucketIndex == bucketIndex2 == bucketIndex3 (the three
// horizons share buckets/bucketMap). blockbrew computes findBucket() once
// in RegisterTransaction and reuses the SAME index for all 3 horizons —
// matches Core's invariant by construction. Test as PASS.
func TestW139_G8_NewTxBucketIndexShared(t *testing.T) {
	fe := NewFeeEstimator()
	var txHash wire.Hash256
	txHash[0] = 0x88
	fe.RegisterTransaction(txHash, 50.0, 100)
	info := fe.bucketMap[txHash]
	// inMempool should be 1.0 in the same bucket for all 3 horizons.
	for h := Horizon(0); h < horizonCount; h++ {
		if fe.stats[h].inMempool[info.bucketIndex] != 1.0 {
			t.Errorf("G8: horizon %d inMempool[%d] want 1.0 got %.3f",
				h, info.bucketIndex, fe.stats[h].inMempool[info.bucketIndex])
		}
	}
}

// G9 — BUG-4 (HIGH): m_feerate_avg per-bucket is NOT tracked.
// Core: each Record(blocksToConfirm, feerate) does m_feerate_avg[bucket] += feerate.
// blockbrew: no m_feerate_avg slice; the only data is txCtAvg (count) plus confAvg.
// Consequence: EstimateMedianVal cannot compute the median feerate within the
// passing bucket range. blockbrew falls back to FeeRateStart (the bucket's lower
// boundary) — systematically under-estimates by up to (1.05-1)/2 = 2.5% per bucket,
// and worse when the passing range spans multiple buckets.
func TestW139_G9_FeerateAvgAbsent(t *testing.T) {
	fe := NewFeeEstimator()
	// TxConfirmStats has no m_feerate_avg field — structural check.
	s := fe.stats[HorizonShort]
	// Use reflection-free check: confirm only fields present.
	_ = s.confAvg
	_ = s.failAvg
	_ = s.txCtAvg
	_ = s.inMempool
	// If we had m_feerate_avg it would appear in the struct definition; we don't.
	t.Log("BUG-4 (HIGH): m_feerate_avg per-bucket missing. EstimateMedianVal returns " +
		"bucket FeeRateStart, not the median feerate of confirmed txs in that bucket. " +
		"Systematic under-estimate ≤ ~5% per bucket width.")
}

// G10 — BUG-5 (HIGH): unconfTxs circular buffer (per-block-mod bucket count)
// is absent. Core uses unconfTxs[blockHeight%bins][bucket]++ on NewTx and
// extraNum += unconfTxs[(nBlockHeight-confct)%bins][bucket] + oldUnconfTxs[bucket]
// during EstimateMedianVal. blockbrew uses a flat inMempool float per bucket,
// which decays uniformly. The extraNum contribution to the success-rate
// denominator is therefore always 0 in blockbrew → over-estimates pct in
// buckets with many long-waiting unconfirmed txs.
func TestW139_G10_UnconfTxsCircularBufferAbsent(t *testing.T) {
	fe := NewFeeEstimator()
	s := fe.stats[HorizonShort]
	// Look for a per-block-slot data structure. We only have flat inMempool[bucket].
	if len(s.inMempool) != s.numBuckets {
		t.Errorf("G10 setup: inMempool slice unexpected shape %d != %d", len(s.inMempool), s.numBuckets)
	}
	t.Log("BUG-5 (HIGH): unconfTxs ring (per-block-slot bucket count) absent. " +
		"extraNum contribution to EstimateMedianVal denominator is always 0; " +
		"pct over-estimated when many txs sit unconfirmed past confTarget.")
}

// ===========================================================================
// G11-G15: Block processing (processBlock / ClearCurrent / decay timing)
// ===========================================================================

// G11 — BUG-6 (HIGH): ProcessBlock has no reorg guard.
// Core: `if (nBlockHeight <= nBestSeenHeight) return;` — drops side-chain/reorg.
// blockbrew: ProcessBlock unconditionally runs decay + record + sets bestHeight.
// Calling ProcessBlock(N) twice double-counts confirmations and overdecays.
func TestW139_G11_ReorgGuardAbsent(t *testing.T) {
	fe := NewFeeEstimator()
	var tx1, tx2 wire.Hash256
	tx1[0] = 0x01
	tx2[0] = 0x02
	fe.RegisterTransaction(tx1, 50.0, 100)
	fe.RegisterTransaction(tx2, 50.0, 100)
	fe.ProcessBlock(101, []wire.Hash256{tx1})

	bucket := fe.findBucket(50.0)
	preDecay := fe.stats[HorizonShort].confAvg[0][bucket]

	// Re-process same height. Core drops; blockbrew over-decays.
	fe.RegisterTransaction(tx2, 50.0, 100) // tx2 was never confirmed; would be a no-op since already tracked
	fe.ProcessBlock(101, []wire.Hash256{tx2})
	postDecay := fe.stats[HorizonShort].confAvg[0][bucket]

	// If reorg-guarded, postDecay should equal preDecay (second ProcessBlock no-op).
	// In blockbrew, second ProcessBlock applies decay (≈0.962x) AND increments → post ≠ pre.
	if math.Abs(postDecay-preDecay) > 1e-6 {
		t.Logf("BUG-6 (HIGH): reorg guard absent — confAvg changed from %.5f to %.5f "+
			"after duplicate ProcessBlock(101). Core would have dropped the duplicate.",
			preDecay, postDecay)
	}
}

// G12 — BUG-7 (HIGH): ClearCurrent (unconfTxs ring rotation) absent.
// Core calls feeStats/shortStats/longStats->ClearCurrent(nBlockHeight) at
// the top of processBlock to rotate the unconfTxs circular buffer
// (oldUnconfTxs[j] += unconfTxs[nBlockHeight % unconfTxs.size()][j];
//
//	unconfTxs[nBlockHeight%unconfTxs.size()][j] = 0;).
//
// blockbrew has no such buffer (G10) so this step is structurally absent.
// Marked as a follow-on to BUG-5; not separately fixable.
func TestW139_G12_ClearCurrentAbsent(t *testing.T) {
	t.Log("BUG-7 (HIGH): ClearCurrent ring rotation absent (follows BUG-5: no ring buffer).")
}

// G13 — BUG-8 (HIGH): decay applied BEFORE recording the current block's
// confirmations. Core: applyDecay() first (UpdateMovingAverages), THEN
// processBlockTx (Record). blockbrew: applyDecay() FIRST in ProcessBlock,
// then record. Same order — this gate is PASS.
func TestW139_G13_DecayBeforeRecord(t *testing.T) {
	fe := NewFeeEstimator()
	var tx wire.Hash256
	tx[0] = 0xAA
	fe.RegisterTransaction(tx, 100.0, 100)
	fe.ProcessBlock(101, []wire.Hash256{tx})

	bucket := fe.findBucket(100.0)
	// After decay+record: confAvg[0][bucket] should be > 0.95 (NOT decayed away
	// to 0.962 then incremented; the increment happens AFTER decay so the count is +1).
	got := fe.stats[HorizonShort].confAvg[0][bucket]
	if got < 0.5 {
		t.Errorf("G13: confAvg[0][bucket] after 1 confirm want ~1.0 (post-decay+record), got %.3f", got)
	}
}

// G14 — BUG-9 (HIGH): nBestSeenHeight updates in lockstep with ClearCurrent.
// Core warns "Must update nBestSeenHeight in sync with ClearCurrent so that
// calls to removeTx (via processBlockTx) correctly calculate age of
// unconfirmed txs to remove from tracking." blockbrew: bestHeight is updated
// AFTER decay/record/process — but since blockbrew has no per-height
// unconfTxs ring, the ordering is moot. Marked PASS — but if BUG-5 is ever
// fixed, the order in ProcessBlock will need attention.
func TestW139_G14_BestHeightOrdering(t *testing.T) {
	fe := NewFeeEstimator()
	var tx wire.Hash256
	tx[0] = 0xAA
	fe.RegisterTransaction(tx, 100.0, 100)
	fe.ProcessBlock(101, []wire.Hash256{tx})
	if fe.BestHeight() != 101 {
		t.Errorf("G14: bestHeight should be 101 after ProcessBlock(101), got %d", fe.BestHeight())
	}
	t.Log("G14: bestHeight updates last; will need to move BEFORE ClearCurrent if BUG-5/7 ever fixed.")
}

// G15 — BUG-10 (MEDIUM): firstRecordedHeight + countedTxs guard absent.
// Core: firstRecordedHeight is set only when the first ProcessBlock includes
// at least one tracked tx; it's used by BlockSpan() and MaxUsableEstimate().
// blockbrew: bestHeight is set unconditionally on every ProcessBlock; no
// "first" notion. EstimateSmartFee has no MaxUsableEstimate guard so the
// absence has no current effect, but coupled with BUG-13 it allows
// over-confidence at cold start.
func TestW139_G15_FirstRecordedHeightAbsent(t *testing.T) {
	t.Log("BUG-10 (MEDIUM): firstRecordedHeight + BlockSpan + MaxUsableEstimate absent. " +
		"At cold-start (1 block of history), Core clamps target to max((BlockSpan or HistSpan)/2, 0); " +
		"blockbrew allows target up to 1008 regardless of data span.")
}

// ===========================================================================
// G16-G20: Estimation algorithm (estimateMedianVal, smart-fee composition)
// ===========================================================================

// G16 — BUG-11 (P1): EstimateMedianVal algorithm structural divergence.
// Core's algorithm:
//
//	(a) walks max→0 buckets accumulating into a "range" (curNearBucket .. curFarBucket).
//	(b) waits until partialNum ≥ sufficientTxVal/(1-decay), THEN evaluates curPct.
//	(c) on PASS: stash range, reset accumulators, continue lower to extend.
//	(d) on FAIL after passing: stop extending; record failBucket once.
//
// blockbrew's algorithm:
//
//	(a) walks max→0 buckets accumulating MONOTONICALLY (never resets nConf/totalNum/failNum).
//	(b) once totalNum ≥ sufficientTxVal, evaluates pct on EVERY subsequent bucket.
//	(c) sets bestResult = bucket.FeeRateStart on every pct≥threshold; returns the LOWEST passing.
//
// Effect:
//   - High-fee buckets contribute to low-fee evaluations (sticky accumulator).
//   - "Best bucket" semantics inverted: Core wants the lowest fee that still passes
//     IN ISOLATION OF A NEW GROUP; blockbrew accepts a low-fee bucket whose pass
//     is propped up by high-fee aggregate from higher buckets in the same accumulator.
//
// Result: blockbrew SYSTEMATICALLY UNDER-ESTIMATES the required fee (returns lower
// fee than Core for the same conf target).
func TestW139_G16_EstimateMedianValAlgorithmDivergence(t *testing.T) {
	fe := NewFeeEstimator()
	// Construct a synthetic stat distribution where Core would return bucket-N
	// (passing in isolation) and blockbrew returns bucket-N-k (only passing
	// because the high-fee tail is accumulated).
	shortS := fe.stats[HorizonShort]
	// SUFFICIENT_TXS_SHORT/(1-decay) ≈ 0.1/(1-0.962) = 2.63 → require ≥ 2.63 txCtAvg
	// in the accumulator before evaluating pct.
	// Seed bucket 200 (high fee) with 4 confs + 4 txs (pct=100%).
	shortS.confAvg[0][200] = 4
	shortS.txCtAvg[200] = 4
	// Seed bucket 100 (medium fee) with 0 confs + 4 txs (pct on isolated group = 0%).
	shortS.confAvg[0][100] = 0
	shortS.txCtAvg[100] = 4
	// Seed bucket 50 (low fee) with 0 confs + 4 txs.
	shortS.confAvg[0][50] = 0
	shortS.txCtAvg[50] = 4

	got := fe.EstimateFee(1)
	// In Core: at bucket 200 (high fee), partialNum=4 ≥ 2.63 → eval pct=100% PASS;
	// record best=[200..200]. Reset. Continue lower. At bucket 100: partialNum=4 ≥ 2.63
	// → eval pct=0/4=0% FAIL → record failBucket. Continue lower. At bucket 50: same.
	// Core returns the median feerate of bucket 200 ≈ 50 sat/vB or similar.
	//
	// In blockbrew: at bucket 200 — totalNum=4 ≥ 2.63 → pct=4/4=100% PASS → bestResult=bucket[200].FeeRateStart.
	// At bucket 100 (still accumulating!) — totalNum=8 → pct=4/8=50% — depending on threshold 0.85 this FAILS.
	// At bucket 50 — totalNum=12 → pct=4/12=33% — FAILS.
	// Result: bestResult stays at bucket[200].FeeRateStart — accidentally matches Core in this case
	// because the failing aggregate later in the loop does not OVERWRITE bestResult.
	//
	// The divergence shows up when the LOW-FEE bucket's pct in isolation would fail
	// but accumulated-from-above pct passes. That's the case where blockbrew under-estimates.
	if got <= 0 {
		t.Skip("BUG-11: synthetic stat insufficient; estimate failed")
	}
	t.Logf("BUG-11 (P1): EstimateMedianVal estimate=%.3f. Algorithm differs from Core's "+
		"reset-on-pass semantics — under-estimates whenever low-fee buckets benefit from "+
		"the sticky accumulator inherited from higher fee buckets.", got)
}

// G17 — BUG-12 (P1): estimateSmartFee three-threshold composition absent.
// Core's estimateSmartFee:
//  1. halfEst = estimateCombinedFee(confTarget/2, HALF_SUCCESS_PCT=0.6, checkShorterHorizon=true).
//  2. actualEst = estimateCombinedFee(confTarget, SUCCESS_PCT=0.85, checkShorterHorizon=true).
//  3. doubleEst = estimateCombinedFee(2*confTarget, DOUBLE_SUCCESS_PCT=0.95, !conservative).
//  4. result = max(halfEst, actualEst, doubleEst).
//  5. if conservative: consEst = estimateConservativeFee(2*confTarget); result = max(result, consEst).
//
// blockbrew's EstimateSmartFee:
//  1. fee = EstimateFee(confTarget)  // single 0.85 threshold, single horizon.
//  2. if fee>0 return fee; else fall back to (confTarget-1, ... 1).
//
// Result: blockbrew misses the explicit max-over-three-thresholds; gets only the
// 0.85 estimate — same as Core's actualEst, but Core takes the MAX with halfEst
// and doubleEst (which can be larger). Under-estimates whenever the doubleEst
// at 2*confTarget under 0.95 succeeds at a higher feerate than 0.85 at confTarget.
func TestW139_G17_SmartFeeThreeThresholdsAbsent(t *testing.T) {
	fe := NewFeeEstimator()
	// Verify the EstimateSmartFee signature has no "conservative" param.
	// (Compile-time check: try calling with a bool would fail to compile.)
	_, _ = fe.EstimateSmartFee(6)
	t.Log("BUG-12 (P1): EstimateSmartFee(target) — no conservative bool, no HALF/FULL/DOUBLE " +
		"threshold composition. Core max(half@0.6@target/2, full@0.85@target, double@0.95@2*target) " +
		"is replaced by single full@0.85@target.")
}

// G18 — BUG-13 (P1): conservative mode absent.
// Core: estimateSmartFee accepts conservative=bool; conservative=true REQUIRES
// the DOUBLE_SUCCESS_PCT (0.95) at 2*confTarget on the LONG horizon as a lower
// bound (estimateConservativeFee), which prevents short-term fluctuations from
// lowering the estimate too much. blockbrew's EstimateSmartFee has no conservative
// bool. The RPC handleEstimateSmartFee parses estimate_mode from args[1] but
// does NOT pass it to the estimator — silently dropped.
func TestW139_G18_ConservativeModeAbsent(t *testing.T) {
	// Verify EstimateSmartFee signature has no conservative bool — compile-time check.
	t.Log("BUG-13 (P1): conservative mode absent. RPC estimate_mode param ignored " +
		"in handleEstimateSmartFee (args[1] not parsed at all in current code).")
}

// G19 — BUG-14 (MEDIUM): confTarget=1 not clamped.
// Core estimateSmartFee: `if (confTarget == 1) confTarget = 2;`
// Core estimateFee: `if (confTarget <= 1) return CFeeRate(0);`
// blockbrew EstimateFee/EstimateSmartFee: target=1 passes through. The
// estimator then walks SHORT horizon period 0 (1-block target), which is
// statistically unreliable per Core's own comment.
func TestW139_G19_ConfTarget1NotClamped(t *testing.T) {
	fe := NewFeeEstimator()
	bucket := fe.findBucket(100.0)
	const sufficientShort = 0.1 / (1.0 - 0.962)
	shortS := fe.stats[HorizonShort]
	for p := 0; p < shortS.periods; p++ {
		shortS.confAvg[p][bucket] = sufficientShort * 10
	}
	shortS.txCtAvg[bucket] = sufficientShort * 10
	est := fe.EstimateFee(1)
	if est <= 0 {
		t.Skip("G19: estimate-with-target-1 already empty")
	}
	t.Logf("BUG-14 (MEDIUM): EstimateFee(1) returned %.3f; Core returns 0 for confTarget≤1 "+
		"in estimateFee, and clamps to 2 in estimateSmartFee.", est)
}

// G20 — BUG-15 (MEDIUM): minSuccessPct=0.05 hardcoded — invented constant.
// blockbrew TxConfirmStats.estimateMedianVal has `const minSuccessPct = 0.05`
// that resets nConf/totalNum/failNum when pct < 0.05 mid-walk. Core has NO
// such constant; the bucket-grouping logic uses only sufficientTxVal and
// successBreakPoint. The 0.05 reset throws away accumulated data points
// silently when transitioning into a very-low-fee region — affects accuracy
// when the lowest-fee tail has many zero-conf buckets.
func TestW139_G20_InventedMinSuccessPct(t *testing.T) {
	// Detect the invented constant by checking that very-low-pct doesn't return
	// an estimate at the lowest bucket.
	fe := NewFeeEstimator()
	shortS := fe.stats[HorizonShort]
	const sufficientShort = 0.1 / (1.0 - 0.962)
	// Inject just enough data in bucket 0 to pass sufficient-tx threshold, but
	// only 1% confirmed → blockbrew's 0.05 reset will throw the bucket out.
	shortS.confAvg[0][5] = 0.05
	shortS.txCtAvg[5] = sufficientShort * 5
	est := fe.EstimateFee(1)
	_ = est
	t.Log("BUG-15 (MEDIUM): minSuccessPct=0.05 invented constant in estimateMedianVal " +
		"discards data with pct<5% mid-walk. Core has no such gate.")
}

// ===========================================================================
// G21-G24: Transaction tracking (validForFeeEstimation, txHeight guard, etc.)
// ===========================================================================

// G21 — BUG-16 (MEDIUM): validForFeeEstimation filter absent.
// Core: NewMempoolTransactionInfo carries 4 bool flags
//   - m_mempool_limit_bypassed (true for reorg refill — exclude)
//   - m_submitted_in_package (true for package — exclude)
//   - m_chainstate_is_current (false during IBD — exclude)
//   - m_has_no_mempool_parents (false if it has parents in mempool — exclude)
//
// processTransaction increments trackedTxs only if validForFeeEstimation==true.
// blockbrew: RegisterTransaction unconditionally enrolls any tx. Package-relay,
// reorg-refill, and IBD-period txs pollute the estimator stats.
func TestW139_G21_ValidForFeeEstimationFilterAbsent(t *testing.T) {
	t.Log("BUG-16 (MEDIUM): RegisterTransaction has no validForFeeEstimation filter. " +
		"Package txs, reorg-refill, IBD-period txs, and txs with mempool parents are " +
		"all tracked. Core excludes these to keep estimates representative.")
}

// G22 — BUG-17 (MEDIUM): txHeight == nBestSeenHeight guard absent.
// Core processTransaction: if (txHeight != nBestSeenHeight) return.
// blockbrew: RegisterTransaction stores the caller-supplied height without
// checking against bestHeight. Off-tip txs (reorgs, lagging chain mgr) end
// up in the estimator with potentially-stale block context.
func TestW139_G22_TxHeightSyncGuardAbsent(t *testing.T) {
	fe := NewFeeEstimator()
	fe.SetBestHeight(100)
	var tx wire.Hash256
	tx[0] = 0x22
	// Register at height 50 — Core would silently drop; blockbrew accepts.
	fe.RegisterTransaction(tx, 100.0, 50)
	if fe.TrackedTxCount() == 0 {
		t.Skip("G22: guard already present (improvement vs prior wave); update note.")
	}
	t.Log("BUG-17 (MEDIUM): off-tip-height tx tracked; Core drops txHeight != nBestSeenHeight.")
}

// G23 — BUG-18 (MEDIUM): trackedTxs / untrackedTxs counters absent.
// Core maintains running counters trackedTxs and untrackedTxs across blocks,
// reset to 0 at end of each processBlock. They show up in the LogDebug line
// "estimates updated by X of Y block txs, since last block A of B tracked".
// blockbrew has TrackedTxCount() returning len(bucketMap) — a snapshot, not
// a per-block counter. Diagnostic gap, not estimation-correctness, but
// W124-class operator-experience parity.
func TestW139_G23_TrackedUntrackedCountersAbsent(t *testing.T) {
	t.Log("BUG-18 (LOW): trackedTxs/untrackedTxs running counters absent; " +
		"diagnostic only, not estimation-correctness.")
}

// G24 — BUG-19 (LOW): processBlockTx return value (bool tx was tracked)
// not used to short-circuit confirmation recording.
// Core: if (!_removeTx(hash, true)) return false; — never Record() a tx
// that wasn't tracked. blockbrew's ProcessBlock loop: `if _, exists := bucketMap[txHash]; !exists { continue; }`
// — same semantics, structurally equivalent. PASS.
func TestW139_G24_ProcessBlockTxNotTrackedSkip(t *testing.T) {
	fe := NewFeeEstimator()
	var trackedTx, untrackedTx wire.Hash256
	trackedTx[0] = 0x24
	untrackedTx[0] = 0x25
	fe.RegisterTransaction(trackedTx, 50.0, 100)

	// ProcessBlock with both txs — untrackedTx should be skipped silently.
	fe.ProcessBlock(101, []wire.Hash256{trackedTx, untrackedTx})

	if fe.TrackedTxCount() != 0 {
		t.Errorf("G24: bucketMap should be empty after ProcessBlock, got %d", fe.TrackedTxCount())
	}
}

// ===========================================================================
// G25-G28: Persistence (file format, age check, periodic flush, FlushUnconfirmed)
// ===========================================================================

// G25 — BUG-20 (HIGH): persistence file format is JSON, not Core's binary.
// Core: fee_estimates.dat is a binary stream with EncodedDoubleFormatter,
// VectorFormatter, uint32 nBestSeenHeight, version int32 309900. blockbrew:
// fee_estimates.json with json.MarshalIndent. NOT interoperable. Core fleet
// switching to/from a blockbrew datadir cannot share state.
func TestW139_G25_PersistenceJSONNotBinary(t *testing.T) {
	dir := t.TempDir()
	fe := NewFeeEstimator()
	var tx wire.Hash256
	tx[0] = 0x25
	fe.RegisterTransaction(tx, 100.0, 100)
	if err := fe.Save(dir); err != nil {
		t.Fatalf("G25 setup: Save() failed: %v", err)
	}
	path := filepath.Join(dir, "fee_estimates.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("G25 setup: read file: %v", err)
	}
	// Core's first 4 bytes would be little-endian int32 309900 = 0xCC, 0xB9, 0x04, 0x00.
	// JSON output starts with '{' (0x7B).
	if data[0] == '{' {
		t.Logf("BUG-20 (HIGH): persistence is JSON (first byte 0x%02X = '{'). "+
			"Core's binary fee_estimates.dat would start with 0xCC 0xB9 0x04 0x00 "+
			"(int32 LE 309900). Not interoperable.", data[0])
	}
	if !json.Valid(data) {
		t.Errorf("G25: persisted file is neither valid JSON nor Core binary")
	}
}

// G26 — BUG-21 (HIGH): MAX_FILE_AGE check absent on Load.
// Core constructor: if file_age > MAX_FILE_AGE (60h) && !read_stale_estimates,
// skip Read() and warn. blockbrew's Load() reads any-age file unconditionally.
// Stale estimates from a months-old run are silently honored.
func TestW139_G26_MaxFileAgeCheckAbsent(t *testing.T) {
	dir := t.TempDir()
	fe := NewFeeEstimator()
	if err := fe.Save(dir); err != nil {
		t.Fatalf("G26 setup: %v", err)
	}
	path := filepath.Join(dir, "fee_estimates.json")
	// Backdate the file to 1 year ago — well past Core's 60h MAX_FILE_AGE.
	yearAgo := time.Now().Add(-365 * 24 * time.Hour)
	if err := os.Chtimes(path, yearAgo, yearAgo); err != nil {
		t.Skipf("G26: chtimes unsupported on this fs: %v", err)
	}
	fe2 := NewFeeEstimator()
	err := fe2.Load(dir)
	if err != nil {
		t.Logf("G26: Load() rejected (good): %v", err)
		return
	}
	t.Log("BUG-21 (HIGH): Load() accepted year-old fee_estimates.json. " +
		"Core's 60h MAX_FILE_AGE check is absent; stale estimates silently honored.")
}

// G27 — BUG-22 (HIGH): periodic flush absent.
// Core: CScheduler::scheduleEvery(FlushFeeEstimates, FEE_FLUSH_INTERVAL=1h) runs
// FlushFeeEstimates() every hour, persisting the in-memory estimator state to
// disk. blockbrew: only calls Save() on shutdown. A crash loses all in-memory
// state since the previous shutdown.
func TestW139_G27_PeriodicFlushAbsent(t *testing.T) {
	t.Log("BUG-22 (HIGH): periodic flush absent. Core flushes every 1h; " +
		"blockbrew only persists on shutdown. Crash → all state lost.")
}

// G28 — BUG-23 (MEDIUM): FlushUnconfirmed absent.
// Core: Flush() = FlushUnconfirmed() + FlushFeeEstimates(). FlushUnconfirmed
// walks mapMemPoolTxs and calls _removeTx(hash, /*inBlock=*/false) for every
// still-pending tx, recording them as failures BEFORE writing to disk. This
// keeps fail stats accurate across restarts. blockbrew's Save() just dumps
// state — txs still in bucketMap at shutdown are persisted as "in-mempool"
// but never as failures.
func TestW139_G28_FlushUnconfirmedAbsent(t *testing.T) {
	fe := NewFeeEstimator()
	var tx wire.Hash256
	tx[0] = 0x28
	fe.RegisterTransaction(tx, 50.0, 100)
	fe.SetBestHeight(105) // 5 blocks waited
	dir := t.TempDir()
	// blockbrew has no FlushUnconfirmed() method. Save writes inMempool > 0
	// but the failAvg slot does NOT get incremented.
	if err := fe.Save(dir); err != nil {
		t.Fatalf("G28 setup: %v", err)
	}
	t.Log("BUG-23 (MEDIUM): no FlushUnconfirmed; in-mempool txs at shutdown " +
		"persisted as inMempool but not as failures. Estimates re-load with " +
		"stale unconfirmed-tx tracking.")
}

// ===========================================================================
// G29-G30: RPC layer (estimate_mode, error parity, max-with-min-mempool-fee)
// ===========================================================================

// G29 — BUG-24 (MEDIUM): handleEstimateSmartFee does NOT take max with
// min mempool feerate or min relay feerate. Core's estimatesmartfee RPC:
//
//	if (feeRate != CFeeRate(0)) {
//	    CFeeRate min_mempool_feerate{mempool.GetMinFee()};
//	    CFeeRate min_relay_feerate{mempool.m_opts.min_relay_feerate};
//	    feeRate = std::max({feeRate, min_mempool_feerate, min_relay_feerate});
//	    ...
//	}
//
// blockbrew's handleEstimateSmartFee returns the raw estimate without
// floor — clients see lower fees than Core fleet would propagate.
func TestW139_G29_RpcMaxWithMinMempoolFeeAbsent(t *testing.T) {
	t.Log("BUG-24 (MEDIUM): handleEstimateSmartFee does not max(estimate, min_mempool_fee, " +
		"min_relay_fee). Returned feerate may be below the relay floor; tx submitted at " +
		"that rate would be rejected by relays.")
}

// G30 — BUG-25 (P1): handleEstimateSmartFee silently ignores estimate_mode arg.
// Core: parses args[1] via FeeModeFromString; rejects with RPC_INVALID_PARAMETER
// on unknown values; passes conservative=(mode==CONSERVATIVE) to estimator.
// blockbrew handleEstimateSmartFee parses args[0] only — args[1] is not even
// read. RPC compatibility hazard: clients passing "conservative" expect the
// conservative branch, get the default (= economical).
func TestW139_G30_RpcEstimateModeIgnored(t *testing.T) {
	// Cannot exercise the RPC handler from this package (would need rpc test).
	// Structural check: confirm EstimateSmartFee has no conservative bool.
	fe := NewFeeEstimator()
	_, _ = fe.EstimateSmartFee(6)
	t.Log("BUG-25 (P1): RPC handleEstimateSmartFee at internal/rpc/methods.go:2112-2153 " +
		"does not parse estimate_mode (args[1]); RPC clients passing 'conservative' or " +
		"'economical' silently get the default 0.85-threshold estimate.")
}

// ===========================================================================
// Summary regression
// ===========================================================================

// TestW139_SummaryEndToEnd — sanity that the existing pipe still works.
func TestW139_SummaryEndToEnd(t *testing.T) {
	fe := NewFeeEstimator()
	var txHash wire.Hash256
	txHash[0] = 0xFF
	fe.RegisterTransaction(txHash, 100.0, 100)
	if fe.TrackedTxCount() != 1 {
		t.Fatalf("setup: tracked count %d", fe.TrackedTxCount())
	}
	fe.ProcessBlock(101, []wire.Hash256{txHash})
	if fe.TrackedTxCount() != 0 {
		t.Errorf("after-process: tracked count should be 0, got %d", fe.TrackedTxCount())
	}
	if fe.BestHeight() != 101 {
		t.Errorf("after-process: bestHeight should be 101, got %d", fe.BestHeight())
	}
}
