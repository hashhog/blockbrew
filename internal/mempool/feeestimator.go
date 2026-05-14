// Package mempool implements the transaction memory pool.
package mempool

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/hashhog/blockbrew/internal/wire"
)

// Horizon identifies one of the three confirmation-time horizons used by
// Bitcoin Core's CBlockPolicyEstimator (src/policy/fees.cpp).
type Horizon int

const (
	HorizonShort  Horizon = 0
	HorizonMedium Horizon = 1
	HorizonLong   Horizon = 2
)

// horizonCount is the number of horizons tracked.
const horizonCount = 3

// horizonDecay are the per-horizon decay factors from Bitcoin Core.
// SHORT: ~50% weight after 18 blocks; MED: after 144; LONG: after 1000.
var horizonDecay = [horizonCount]float64{
	0.962,   // SHORT
	0.9952,  // MED
	0.99931, // LONG
}

// horizonScale is the period scale (blocks per period) for each horizon.
// LONG groups 24 blocks per period so the 1008-block range needs only 42 bins.
var horizonScale = [horizonCount]int{
	1,  // SHORT — 1 block per period
	2,  // MED   — 2 blocks per period
	24, // LONG  — 24 blocks per period
}

// horizonPeriods is the number of periods (bins) for each horizon.
// SHORT: 12 periods → 12 block max; MED: 24 → 48 blocks; LONG: 42 → 1008 blocks.
var horizonPeriods = [horizonCount]int{
	12, // SHORT
	24, // MED
	42, // LONG
}

// maxBlocksForHorizon is horizonScale × horizonPeriods.
func maxBlocksForHorizon(h Horizon) int {
	return horizonScale[h] * horizonPeriods[h]
}

// FEE_SPACING is the exponential bucket multiplier from Bitcoin Core.
const feeSpacing = 1.05

// minBucketFeeRate is Bitcoin Core's MIN_BUCKET_FEERATE expressed in sat/vB
// (Core stores sat/kvB = 100, so sat/vB = 0.1).
const minBucketFeeRate = 0.1 // sat/vB

// maxBucketFeeRate is Bitcoin Core's MAX_BUCKET_FEERATE in sat/vB (1e7 sat/kvB = 1e4 sat/vB).
const maxBucketFeeRate = 1e4 // sat/vB

// buildExponentialBuckets builds bucket lower boundaries spaced at feeSpacing
// from minBucketFeeRate up to and including maxBucketFeeRate, exactly matching
// Core's bucket-init loop in block_policy_estimator.cpp:
//
//	for (bucketBoundary = MIN_BUCKET_FEERATE; bucketBoundary <= MAX_BUCKET_FEERATE; bucketBoundary *= FEE_SPACING)
//	    buckets.push_back(bucketBoundary);
//	buckets.push_back(INF_FEERATE);
//
// Core stores sat/kvB; we store sat/vB (divide by 1000), but the bucket
// count and ratios are identical.
func buildExponentialBuckets() []float64 {
	var bounds []float64
	rate := minBucketFeeRate
	for rate <= maxBucketFeeRate {
		bounds = append(bounds, rate)
		rate *= feeSpacing
	}
	// Add an INF bucket at the end (Core's push_back(INF_FEERATE)).
	bounds = append(bounds, 1e9)
	return bounds
}

// defaultBucketBoundaries is computed once at package init.
var defaultBucketBoundaries = buildExponentialBuckets()

// TxConfirmStats tracks confirmation statistics for one estimation horizon.
// It mirrors Core's TxConfirmStats struct (src/policy/fees.cpp).
type TxConfirmStats struct {
	decay   float64
	scale   int
	periods int

	// confAvg[period][bucket]: decayed count of txs that confirmed within
	// `period+1` periods.  Cumulative: a tx confirming in period p increments
	// ALL slots from p to periods-1 (Core's Record() semantics).
	confAvg [][]float64

	// failAvg[period][bucket]: decayed count of txs that left the mempool
	// unconfirmed within `period+1` periods (evicted, RBF'd, etc.).
	failAvg [][]float64

	// txCtAvg[bucket]: decayed count of all txs seen in each bucket.
	// Used for the "sufficient data" check.
	txCtAvg []float64

	// inMempool[bucket]: current (decayed) count of tracked in-mempool txs.
	inMempool []float64

	numBuckets int
}

// newTxConfirmStats creates a TxConfirmStats for the given horizon parameters.
func newTxConfirmStats(decay float64, scale, periods, numBuckets int) *TxConfirmStats {
	s := &TxConfirmStats{
		decay:      decay,
		scale:      scale,
		periods:    periods,
		numBuckets: numBuckets,
		txCtAvg:    make([]float64, numBuckets),
		inMempool:  make([]float64, numBuckets),
	}
	s.confAvg = make([][]float64, periods)
	s.failAvg = make([][]float64, periods)
	for p := 0; p < periods; p++ {
		s.confAvg[p] = make([]float64, numBuckets)
		s.failAvg[p] = make([]float64, numBuckets)
	}
	return s
}

// applyDecay multiplies all decayed accumulators by the horizon decay factor.
func (s *TxConfirmStats) applyDecay() {
	for p := 0; p < s.periods; p++ {
		for b := 0; b < s.numBuckets; b++ {
			s.confAvg[p][b] *= s.decay
			s.failAvg[p][b] *= s.decay
		}
	}
	for b := 0; b < s.numBuckets; b++ {
		s.txCtAvg[b] *= s.decay
		s.inMempool[b] *= s.decay
	}
}

// record registers a transaction confirmation.
// blocksToConfirm is the raw block delta (≥1).
// It is converted to a period index, then incremented cumulatively for all
// periods from periodsToConfirm to s.periods-1 (Core's Record() semantics).
func (s *TxConfirmStats) record(blocksToConfirm, bucketIdx int) {
	// Convert to periods (ceiling division, clamped to [0, periods-1]).
	period := (blocksToConfirm + s.scale - 1) / s.scale
	if period < 1 {
		period = 1
	}
	periodIdx := period - 1 // zero-based
	if periodIdx >= s.periods {
		periodIdx = s.periods - 1
	}

	// Cumulative increment: contribute to all targets ≥ periodIdx.
	for p := periodIdx; p < s.periods; p++ {
		s.confAvg[p][bucketIdx]++
	}
	s.txCtAvg[bucketIdx]++
}

// recordFail registers an eviction (tx left mempool unconfirmed).
// blocksInMempool is how long the tx had been waiting.
func (s *TxConfirmStats) recordFail(blocksInMempool, bucketIdx int) {
	period := (blocksInMempool + s.scale - 1) / s.scale
	if period < 1 {
		period = 1
	}
	periodIdx := period - 1
	if periodIdx >= s.periods {
		periodIdx = s.periods - 1
	}
	for p := periodIdx; p < s.periods; p++ {
		s.failAvg[p][bucketIdx]++
	}
}

// estimateMedianVal returns the estimated fee rate (sat/vB) required for
// confirmation within targetBlocks, or -1 if insufficient data.
// threshold is the required success fraction (e.g. 0.85 or 0.95).
//
// Algorithm mirrors Core's TxConfirmStats::EstimateMedianVal():
//   - Walk buckets from high fee rate down, accumulating counts into groups
//     until the group meets the "sufficient data" threshold.
//   - The last group whose success rate meets threshold is the estimate.
func (s *TxConfirmStats) estimateMedianVal(targetBlocks int, threshold float64) float64 {
	if targetBlocks < 1 {
		targetBlocks = 1
	}

	// Convert targetBlocks to a period index.
	period := (targetBlocks + s.scale - 1) / s.scale
	if period < 1 {
		period = 1
	}
	periodIdx := period - 1
	if periodIdx >= s.periods {
		periodIdx = s.periods - 1
	}

	// SUFFICIENT_FEETXS / (1 - decay) — the threshold for "enough data".
	const sufficientFeetxs = 0.1
	sufficientTxVal := sufficientFeetxs / (1.0 - s.decay)
	const minSuccessPct = 0.05 // Core's MIN_SUCCESS_PCT — discard buckets too sparse

	var nConf, totalNum, failNum float64
	bestResult := -1.0

	for b := s.numBuckets - 1; b >= 0; b-- {
		nConf += s.confAvg[periodIdx][b]
		totalNum += s.txCtAvg[b]
		failNum += s.failAvg[periodIdx][b]

		if totalNum < sufficientTxVal {
			// Not enough data in this accumulated group yet.
			continue
		}

		// extraNum = txs that have been in mempool ≥ targetBlocks without confirming
		// blockbrew tracks a flat inMempool float, not per-slot; use 0 as a
		// conservative approximation (same as omitting extraNum — slightly
		// optimistic but consistent with current tracking granularity).
		denominator := totalNum + failNum
		if denominator <= 0 {
			nConf = 0
			totalNum = 0
			failNum = 0
			continue
		}
		pct := nConf / denominator
		if pct < minSuccessPct {
			// Too sparse — reset and keep looking lower.
			nConf = 0
			totalNum = 0
			failNum = 0
			continue
		}
		if pct >= threshold {
			// This group meets the threshold; record the bucket's lower boundary.
			bestResult = defaultBucketBoundaries[b]
		}
		// In Core this accumulates across all buckets before returning the
		// last-passing bucket. We continue iterating to find the lowest fee
		// that still meets threshold.
	}

	return bestResult
}

// FeeBucket holds the lower bound for a single fee-rate range (for legacy
// GetBucketStats and JSON persistence compatibility).
type FeeBucket struct {
	FeeRateStart float64 `json:"fee_rate_start"`
	FeeRateEnd   float64 `json:"fee_rate_end"`
	// ConfirmedAt is kept for JSON persistence backwards compatibility.
	// After the 3-horizon refactor these fields are not used for estimation;
	// estimation goes through TxConfirmStats directly.
	ConfirmedAt []BucketStats `json:"confirmed_at,omitempty"`
	InMempool   float64       `json:"in_mempool"`
}

// BucketStats tracks statistics for confirmations at a specific target.
type BucketStats struct {
	TxCount   float64 `json:"tx_count"`
	TotalFees float64 `json:"total_fees,omitempty"`
}

// txInfo stores information about a transaction when it enters the mempool.
type txInfo struct {
	bucketIndex int
	height      int32
}

// FeeEstimator tracks transaction fee rates and estimates required fees
// for target confirmation times.  It mirrors Bitcoin Core's
// CBlockPolicyEstimator (src/policy/fees.cpp) with three TxConfirmStats
// horizons: SHORT (decay=0.962, scale=1, 12 bins), MED (decay=0.9952,
// scale=2, 24 bins), LONG (decay=0.99931, scale=24, 42 bins).
type FeeEstimator struct {
	mu         sync.RWMutex
	bestHeight int32

	// buckets holds the fee-rate boundaries (indexed by bucket index).
	buckets []FeeBucket

	// bucketMap tracks in-flight transactions: txid → bucket index + entry height.
	bucketMap map[wire.Hash256]txInfo

	// stats holds the three TxConfirmStats instances indexed by Horizon.
	stats [horizonCount]*TxConfirmStats
}

// NewFeeEstimator creates a new fee estimator with Core-compatible defaults.
func NewFeeEstimator() *FeeEstimator {
	return newFeeEstimatorInternal(defaultBucketBoundaries)
}

// NewFeeEstimatorWithConfig creates a fee estimator with custom settings.
// maxTargetBlocks and decay are accepted for backwards compatibility with
// existing callers (tests); however the internal structure always uses the
// three Core horizons.  maxTargetBlocks and decay are silently ignored — the
// caller should migrate to NewFeeEstimator().
//
// Deprecated: use NewFeeEstimator() for production code.
func NewFeeEstimatorWithConfig(maxTargetBlocks int, decay float64) *FeeEstimator {
	_ = maxTargetBlocks
	_ = decay
	return newFeeEstimatorInternal(defaultBucketBoundaries)
}

func newFeeEstimatorInternal(bounds []float64) *FeeEstimator {
	nBuckets := len(bounds)
	fe := &FeeEstimator{
		bucketMap: make(map[wire.Hash256]txInfo),
		buckets:   make([]FeeBucket, nBuckets),
	}

	for i, b := range bounds {
		fe.buckets[i].FeeRateStart = b
		if i+1 < nBuckets {
			fe.buckets[i].FeeRateEnd = bounds[i+1]
		} else {
			fe.buckets[i].FeeRateEnd = 1e9
		}
	}

	for h := Horizon(0); h < horizonCount; h++ {
		fe.stats[h] = newTxConfirmStats(
			horizonDecay[h],
			horizonScale[h],
			horizonPeriods[h],
			nBuckets,
		)
	}

	return fe
}

// findBucket returns the bucket index for a given fee rate via binary search.
func (fe *FeeEstimator) findBucket(feeRate float64) int {
	lo, hi := 0, len(fe.buckets)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if feeRate >= fe.buckets[mid].FeeRateStart {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// RegisterTransaction records a new transaction entering the mempool.
func (fe *FeeEstimator) RegisterTransaction(txHash wire.Hash256, feeRate float64, height int32) {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	if _, exists := fe.bucketMap[txHash]; exists {
		return
	}

	bucketIdx := fe.findBucket(feeRate)
	fe.bucketMap[txHash] = txInfo{
		bucketIndex: bucketIdx,
		height:      height,
	}
	for h := Horizon(0); h < horizonCount; h++ {
		fe.stats[h].inMempool[bucketIdx]++
	}
}

// UnregisterTransaction removes a transaction from tracking without confirmation.
func (fe *FeeEstimator) UnregisterTransaction(txHash wire.Hash256) {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	info, exists := fe.bucketMap[txHash]
	if !exists {
		return
	}

	b := info.bucketIndex
	for h := Horizon(0); h < horizonCount; h++ {
		s := fe.stats[h]
		s.inMempool[b]--
		if s.inMempool[b] < 0 {
			s.inMempool[b] = 0
		}
		// Record as a failure (evicted without confirming) in each horizon.
		blocksWaited := int(fe.bestHeight) - int(info.height)
		if blocksWaited < 1 {
			blocksWaited = 1
		}
		s.recordFail(blocksWaited, b)
	}
	delete(fe.bucketMap, txHash)
}

// ProcessBlock updates the estimator when a new block is connected.
func (fe *FeeEstimator) ProcessBlock(height int32, txHashes []wire.Hash256) {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	// Apply decay to all horizons.
	for h := Horizon(0); h < horizonCount; h++ {
		fe.stats[h].applyDecay()
	}

	for _, txHash := range txHashes {
		info, exists := fe.bucketMap[txHash]
		if !exists {
			continue
		}

		blocksToConfirm := int(height - info.height)
		if blocksToConfirm < 1 {
			blocksToConfirm = 1
		}

		b := info.bucketIndex
		for h := Horizon(0); h < horizonCount; h++ {
			s := fe.stats[h]
			s.inMempool[b]--
			if s.inMempool[b] < 0 {
				s.inMempool[b] = 0
			}
			s.record(blocksToConfirm, b)
		}

		delete(fe.bucketMap, txHash)
	}

	fe.bestHeight = height
}

// selectHorizon returns the best horizon for a given confirmation target.
// Core's estimateSmartFee: target≤12 use SHORT, target≤48 use MED, else LONG.
func selectHorizon(targetBlocks int) Horizon {
	switch {
	case targetBlocks <= maxBlocksForHorizon(HorizonShort):
		return HorizonShort
	case targetBlocks <= maxBlocksForHorizon(HorizonMedium):
		return HorizonMedium
	default:
		return HorizonLong
	}
}

// horizonName returns the string name used in RPC output.
func horizonName(h Horizon) string {
	switch h {
	case HorizonShort:
		return "short"
	case HorizonMedium:
		return "medium"
	default:
		return "long"
	}
}

// EstimateFee returns the estimated fee rate (sat/vB) for confirmation
// within targetBlocks blocks, using the appropriate horizon.
// Returns -1 if insufficient data.
func (fe *FeeEstimator) EstimateFee(targetBlocks int) float64 {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	if targetBlocks < 1 {
		targetBlocks = 1
	}

	h := selectHorizon(targetBlocks)
	return fe.stats[h].estimateMedianVal(targetBlocks, 0.85)
}

// EstimateSmartFee returns the fee estimate and actual target used.
// It selects the horizon based on confTarget (≤12 short, ≤48 medium, else long)
// and falls back to shorter targets if insufficient data.
func (fe *FeeEstimator) EstimateSmartFee(targetBlocks int) (float64, int) {
	if targetBlocks < 1 {
		targetBlocks = 1
	}

	fee := fe.EstimateFee(targetBlocks)
	if fee > 0 {
		return fee, targetBlocks
	}

	// Fall back to shorter targets.
	for t := targetBlocks - 1; t >= 1; t-- {
		fee = fe.EstimateFee(t)
		if fee > 0 {
			return fee, t
		}
	}

	return -1, 0
}

// EstimationBucketStats summarizes a contiguous fee-rate range.
type EstimationBucketStats struct {
	StartRange     float64
	EndRange       float64
	WithinTarget   float64
	TotalConfirmed float64
	InMempool      float64
	LeftMempool    float64
}

// EstimationResult is the Core-shaped raw-fee scan result for one horizon.
type EstimationResult struct {
	FeeRate float64
	Decay   float64
	Scale   float64
	Pass    EstimationBucketStats
	Fail    EstimationBucketStats
}

// EstimateRawFee scans the buckets for the requested horizon and returns
// pass/fail bucket boundaries matching Bitcoin Core's `estimaterawfee` output.
func (fe *FeeEstimator) EstimateRawFeeForHorizon(h Horizon, targetBlocks int, threshold float64) EstimationResult {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	if targetBlocks < 1 {
		targetBlocks = 1
	}
	maxBlocks := maxBlocksForHorizon(h)
	if targetBlocks > maxBlocks {
		targetBlocks = maxBlocks
	}
	if threshold <= 0 || threshold > 1 {
		threshold = 0.95
	}

	s := fe.stats[h]
	period := (targetBlocks + s.scale - 1) / s.scale
	if period < 1 {
		period = 1
	}
	periodIdx := period - 1
	if periodIdx >= s.periods {
		periodIdx = s.periods - 1
	}

	const sufficientFeetxs = 0.1
	sufficientTxVal := sufficientFeetxs / (1.0 - s.decay)

	result := EstimationResult{
		FeeRate: -1,
		Decay:   s.decay,
		Scale:   float64(s.scale),
	}

	bestBucket := -1
	failBucket := -1
	var nConf, totalNum, failNum float64

	for b := s.numBuckets - 1; b >= 0; b-- {
		nConf += s.confAvg[periodIdx][b]
		totalNum += s.txCtAvg[b]
		failNum += s.failAvg[periodIdx][b]

		if totalNum < sufficientTxVal {
			continue
		}
		denominator := totalNum + failNum
		if denominator <= 0 {
			nConf = 0
			totalNum = 0
			failNum = 0
			continue
		}
		pct := nConf / denominator
		if pct >= threshold {
			bestBucket = b
		} else {
			failBucket = b
			break
		}
	}

	bucketToStats := func(idx int) EstimationBucketStats {
		if idx < 0 {
			return EstimationBucketStats{StartRange: -1, EndRange: -1}
		}
		return EstimationBucketStats{
			StartRange:     fe.buckets[idx].FeeRateStart,
			EndRange:       fe.buckets[idx].FeeRateEnd,
			WithinTarget:   s.confAvg[periodIdx][idx],
			TotalConfirmed: s.txCtAvg[idx],
			InMempool:      s.inMempool[idx],
			LeftMempool:    s.failAvg[periodIdx][idx],
		}
	}

	if bestBucket >= 0 {
		result.FeeRate = fe.buckets[bestBucket].FeeRateStart
		result.Pass = bucketToStats(bestBucket)
	} else {
		result.Pass = EstimationBucketStats{StartRange: -1, EndRange: -1}
	}
	if failBucket >= 0 {
		result.Fail = bucketToStats(failBucket)
	} else {
		result.Fail = EstimationBucketStats{StartRange: -1, EndRange: -1}
	}

	return result
}

// EstimateRawFee returns the result for the appropriate single horizon
// (selected by targetBlocks). The RPC layer (handleEstimateRawFee) calls
// EstimateRawFeeAllHorizons to return all three.
func (fe *FeeEstimator) EstimateRawFee(targetBlocks int, threshold float64) EstimationResult {
	h := selectHorizon(targetBlocks)
	return fe.EstimateRawFeeForHorizon(h, targetBlocks, threshold)
}

// EstimateRawFeeAllHorizons returns results for all three horizons, keyed by
// horizon name. This is used by the estimaterawfee RPC to return all horizons
// that cover the requested target, matching Core's ALL_FEE_ESTIMATE_HORIZONS loop.
func (fe *FeeEstimator) EstimateRawFeeAllHorizons(targetBlocks int, threshold float64) map[string]EstimationResult {
	out := make(map[string]EstimationResult, horizonCount)
	for h := Horizon(0); h < horizonCount; h++ {
		maxBlocks := maxBlocksForHorizon(h)
		if targetBlocks <= maxBlocks {
			out[horizonName(h)] = fe.EstimateRawFeeForHorizon(h, targetBlocks, threshold)
		}
	}
	return out
}

// HighestTargetTracked returns the maximum confirmation target supported by
// the long horizon (1008 blocks).
func (fe *FeeEstimator) HighestTargetTracked() int {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return maxBlocksForHorizon(HorizonLong)
}

// BestHeight returns the current best height known to the estimator.
func (fe *FeeEstimator) BestHeight() int32 {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return fe.bestHeight
}

// SetBestHeight sets the current best height.
func (fe *FeeEstimator) SetBestHeight(height int32) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.bestHeight = height
}

// TrackedTxCount returns the number of transactions currently tracked.
func (fe *FeeEstimator) TrackedTxCount() int {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return len(fe.bucketMap)
}

// ============================================================================
// Persistence
// ============================================================================

type feeEstimatorHorizonState struct {
	ConfAvg   [][]float64 `json:"conf_avg"`
	FailAvg   [][]float64 `json:"fail_avg"`
	TxCtAvg   []float64   `json:"tx_ct_avg"`
	InMempool []float64   `json:"in_mempool"`
}

// feeEstimatorState is the serialisable form written to fee_estimates.json.
type feeEstimatorState struct {
	// Version is bumped when the schema changes in an incompatible way.
	Version    int                          `json:"version"`
	BestHeight int32                        `json:"best_height"`
	Buckets    []float64                    `json:"buckets"`
	Horizons   [horizonCount]feeEstimatorHorizonState `json:"horizons"`
}

const feeEstimatorVersion = 2

// Save persists the fee estimator state to disk.
func (fe *FeeEstimator) Save(dataDir string) error {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	bounds := make([]float64, len(fe.buckets))
	for i, b := range fe.buckets {
		bounds[i] = b.FeeRateStart
	}

	var horizons [horizonCount]feeEstimatorHorizonState
	for h := Horizon(0); h < horizonCount; h++ {
		s := fe.stats[h]
		hs := feeEstimatorHorizonState{
			ConfAvg:   s.confAvg,
			FailAvg:   s.failAvg,
			TxCtAvg:   s.txCtAvg,
			InMempool: s.inMempool,
		}
		horizons[h] = hs
	}

	state := feeEstimatorState{
		Version:    feeEstimatorVersion,
		BestHeight: fe.bestHeight,
		Buckets:    bounds,
		Horizons:   horizons,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(dataDir, "fee_estimates.json")
	return os.WriteFile(path, data, 0644)
}

// Load restores the fee estimator state from disk.
func (fe *FeeEstimator) Load(dataDir string) error {
	path := filepath.Join(dataDir, "fee_estimates.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var state feeEstimatorState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	// Only load if version and bucket count are compatible.
	if state.Version != feeEstimatorVersion {
		return nil // stale/incompatible format — start fresh
	}
	if len(state.Buckets) != len(fe.buckets) {
		return nil // bucket count changed — start fresh
	}

	fe.mu.Lock()
	defer fe.mu.Unlock()

	fe.bestHeight = state.BestHeight
	for h := Horizon(0); h < horizonCount; h++ {
		s := fe.stats[h]
		hs := state.Horizons[h]
		if len(hs.TxCtAvg) == s.numBuckets &&
			len(hs.ConfAvg) == s.periods &&
			len(hs.FailAvg) == s.periods {
			s.txCtAvg = hs.TxCtAvg
			s.inMempool = hs.InMempool
			s.confAvg = hs.ConfAvg
			s.failAvg = hs.FailAvg
		}
	}

	return nil
}

// GetBucketStats returns statistics for debugging/monitoring.
func (fe *FeeEstimator) GetBucketStats() []struct {
	FeeRateStart float64
	FeeRateEnd   float64
	InMempool    float64
	Confirmed1   float64
	Confirmed6   float64
	Confirmed24  float64
} {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	nBuckets := len(fe.buckets)
	stats := make([]struct {
		FeeRateStart float64
		FeeRateEnd   float64
		InMempool    float64
		Confirmed1   float64
		Confirmed6   float64
		Confirmed24  float64
	}, nBuckets)

	// Use the MED horizon for stats display (reasonable middle ground).
	s := fe.stats[HorizonMedium]

	for i := 0; i < nBuckets; i++ {
		stats[i].FeeRateStart = fe.buckets[i].FeeRateStart
		stats[i].FeeRateEnd = fe.buckets[i].FeeRateEnd
		stats[i].InMempool = s.inMempool[i]

		// Confirmed1: period index 0 of MED (scale=2) covers blocks 1-2.
		if len(s.confAvg) > 0 {
			stats[i].Confirmed1 = s.confAvg[0][i]
		}
		// Confirmed6: use period index 2 (covers ≤6 blocks at scale=2).
		if len(s.confAvg) > 2 {
			stats[i].Confirmed6 = s.confAvg[2][i]
		}
		// Confirmed24: use period index 11 (covers ≤24 blocks at scale=2).
		if len(s.confAvg) > 11 {
			stats[i].Confirmed24 = s.confAvg[11][i]
		}
	}

	return stats
}

