// Package mempool implements the transaction memory pool.
package mempool

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/hashhog/blockbrew/internal/wire"
)

// FeeEstimator tracks transaction fee rates and estimates required fees
// for target confirmation times.
type FeeEstimator struct {
	mu              sync.RWMutex
	maxTargetBlocks int                      // Maximum blocks to estimate (default: 1008, ~1 week)
	buckets         []FeeBucket              // Fee rate buckets
	bucketMap       map[wire.Hash256]txInfo  // txid -> bucket index and height when tx entered mempool
	bestHeight      int32
	// Decay factor: older data is weighted less. After each block, multiply
	// counts by this factor. 0.998 means 50% weight after ~346 blocks.
	decay float64
}

// txInfo stores information about a transaction when it enters the mempool.
type txInfo struct {
	bucketIndex int
	height      int32
}

// FeeBucket represents a range of fee rates.
type FeeBucket struct {
	FeeRateStart float64       // Lower bound of this bucket (sat/vB)
	FeeRateEnd   float64       // Upper bound
	// For each target (1..maxTargetBlocks), track:
	// - TxCount: number of transactions that confirmed within this many blocks
	ConfirmedAt []BucketStats // Indexed by confirmation target (0 = confirmed in 1 block)
	InMempool   float64       // Currently in mempool (decayed count)
}

// BucketStats tracks statistics for confirmations at a specific target.
type BucketStats struct {
	TxCount   float64 // Decayed count of txs that confirmed at this target
	TotalFees float64 // Sum of fees for confirmed txs (not currently used but useful for avg)
}

// defaultBucketBoundaries defines exponentially-spaced fee rate buckets
// covering the range 1 sat/vB to 10,000 sat/vB.
var defaultBucketBoundaries = []float64{
	1, 2, 3, 4, 5, 6, 7, 8, 10,
	12, 14, 17, 20, 25, 30, 40, 50, 60, 70, 80, 100,
	120, 140, 170, 200, 250, 300, 400, 500, 600, 700, 800, 1000,
	1200, 1400, 1700, 2000, 2500, 3000, 4000, 5000, 6000, 7000, 8000, 10000,
}

// NewFeeEstimator creates a new fee estimator with default settings.
func NewFeeEstimator() *FeeEstimator {
	return NewFeeEstimatorWithConfig(1008, 0.998)
}

// NewFeeEstimatorWithConfig creates a fee estimator with custom settings.
func NewFeeEstimatorWithConfig(maxTargetBlocks int, decay float64) *FeeEstimator {
	fe := &FeeEstimator{
		maxTargetBlocks: maxTargetBlocks,
		decay:           decay,
		bucketMap:       make(map[wire.Hash256]txInfo),
	}

	// Initialize buckets from boundaries
	fe.buckets = make([]FeeBucket, len(defaultBucketBoundaries))
	for i := 0; i < len(defaultBucketBoundaries); i++ {
		fe.buckets[i] = FeeBucket{
			FeeRateStart: defaultBucketBoundaries[i],
			ConfirmedAt:  make([]BucketStats, maxTargetBlocks),
		}
		if i < len(defaultBucketBoundaries)-1 {
			fe.buckets[i].FeeRateEnd = defaultBucketBoundaries[i+1]
		} else {
			fe.buckets[i].FeeRateEnd = 1e9 // Effectively unlimited
		}
	}

	return fe
}

// findBucket returns the bucket index for a given fee rate.
func (fe *FeeEstimator) findBucket(feeRate float64) int {
	// Binary search for the appropriate bucket
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
// Called when a transaction is accepted to the mempool.
func (fe *FeeEstimator) RegisterTransaction(txHash wire.Hash256, feeRate float64, height int32) {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	// Don't re-register
	if _, exists := fe.bucketMap[txHash]; exists {
		return
	}

	bucketIdx := fe.findBucket(feeRate)
	fe.bucketMap[txHash] = txInfo{
		bucketIndex: bucketIdx,
		height:      height,
	}
	fe.buckets[bucketIdx].InMempool++
}

// UnregisterTransaction removes a transaction from tracking without it being confirmed.
// Called when a transaction is removed from the mempool for reasons other than confirmation.
func (fe *FeeEstimator) UnregisterTransaction(txHash wire.Hash256) {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	info, exists := fe.bucketMap[txHash]
	if !exists {
		return
	}

	if info.bucketIndex >= 0 && info.bucketIndex < len(fe.buckets) {
		fe.buckets[info.bucketIndex].InMempool--
		if fe.buckets[info.bucketIndex].InMempool < 0 {
			fe.buckets[info.bucketIndex].InMempool = 0
		}
	}
	delete(fe.bucketMap, txHash)
}

// ProcessBlock updates the estimator when a new block is connected.
// For each transaction in the block that was previously registered,
// record how many blocks it took to confirm.
func (fe *FeeEstimator) ProcessBlock(height int32, txHashes []wire.Hash256) {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	// Apply decay to all buckets first
	fe.applyDecay()

	// Process each confirmed transaction
	for _, txHash := range txHashes {
		info, exists := fe.bucketMap[txHash]
		if !exists {
			continue
		}

		// Calculate how many blocks it took to confirm
		blocksToConfirm := int(height - info.height)
		if blocksToConfirm < 1 {
			blocksToConfirm = 1
		}

		// Record the confirmation
		bucketIdx := info.bucketIndex
		if bucketIdx >= 0 && bucketIdx < len(fe.buckets) {
			// Decrement mempool count
			fe.buckets[bucketIdx].InMempool--
			if fe.buckets[bucketIdx].InMempool < 0 {
				fe.buckets[bucketIdx].InMempool = 0
			}

			// Record confirmation at this target (capped at maxTargetBlocks)
			targetIdx := blocksToConfirm - 1
			if targetIdx >= fe.maxTargetBlocks {
				targetIdx = fe.maxTargetBlocks - 1
			}
			fe.buckets[bucketIdx].ConfirmedAt[targetIdx].TxCount++
		}

		// Remove from tracking
		delete(fe.bucketMap, txHash)
	}

	fe.bestHeight = height
}

// applyDecay multiplies all bucket counts by the decay factor.
// Must be called with mu held.
func (fe *FeeEstimator) applyDecay() {
	for i := range fe.buckets {
		for j := range fe.buckets[i].ConfirmedAt {
			fe.buckets[i].ConfirmedAt[j].TxCount *= fe.decay
		}
		fe.buckets[i].InMempool *= fe.decay
	}
}

// EstimateFee returns the estimated fee rate (sat/vB) for confirmation
// within targetBlocks blocks. Returns -1 if insufficient data.
func (fe *FeeEstimator) EstimateFee(targetBlocks int) float64 {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	if targetBlocks < 1 {
		targetBlocks = 1
	}
	if targetBlocks > fe.maxTargetBlocks {
		targetBlocks = fe.maxTargetBlocks
	}

	// Find the lowest fee rate bucket where >= 85% of transactions
	// confirmed within targetBlocks.
	requiredSuccessRate := 0.85
	minDataPoints := 2.0 // Need at least this many (decayed) data points

	// Scan buckets from highest fee rate to lowest
	bestBucket := -1
	for i := len(fe.buckets) - 1; i >= 0; i-- {
		bucket := fe.buckets[i]
		// Count transactions in this bucket that confirmed within targetBlocks
		var confirmed float64
		for t := 0; t < targetBlocks && t < len(bucket.ConfirmedAt); t++ {
			confirmed += bucket.ConfirmedAt[t].TxCount
		}
		total := confirmed + bucket.InMempool
		if total < minDataPoints {
			continue
		}
		successRate := confirmed / total
		if successRate >= requiredSuccessRate {
			bestBucket = i
		}
	}

	if bestBucket == -1 {
		return -1 // Insufficient data
	}
	return fe.buckets[bestBucket].FeeRateStart
}

// EstimateSmartFee returns the fee estimate, also searching shorter
// targets if the requested target has insufficient data.
// Returns the fee rate and the actual target used.
func (fe *FeeEstimator) EstimateSmartFee(targetBlocks int) (float64, int) {
	if targetBlocks < 1 {
		targetBlocks = 1
	}

	// Try the requested target first
	fee := fe.EstimateFee(targetBlocks)
	if fee > 0 {
		return fee, targetBlocks
	}

	// Fall back to shorter targets
	for t := targetBlocks - 1; t >= 1; t-- {
		fee = fe.EstimateFee(t)
		if fee > 0 {
			return fee, t
		}
	}

	// No valid estimate available
	return -1, 0
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

// TrackedTxCount returns the number of transactions currently being tracked.
func (fe *FeeEstimator) TrackedTxCount() int {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return len(fe.bucketMap)
}

// feeEstimatorState is the serializable state of the fee estimator.
type feeEstimatorState struct {
	MaxTargetBlocks int         `json:"max_target_blocks"`
	Decay           float64     `json:"decay"`
	BestHeight      int32       `json:"best_height"`
	Buckets         []FeeBucket `json:"buckets"`
}

// Save persists the fee estimator state to disk.
func (fe *FeeEstimator) Save(dataDir string) error {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	state := feeEstimatorState{
		MaxTargetBlocks: fe.maxTargetBlocks,
		Decay:           fe.decay,
		BestHeight:      fe.bestHeight,
		Buckets:         fe.buckets,
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
			return nil // No saved state, use defaults
		}
		return err
	}

	var state feeEstimatorState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	fe.mu.Lock()
	defer fe.mu.Unlock()

	// Validate and apply loaded state
	if state.MaxTargetBlocks > 0 && len(state.Buckets) == len(fe.buckets) {
		fe.maxTargetBlocks = state.MaxTargetBlocks
		fe.decay = state.Decay
		fe.bestHeight = state.BestHeight
		fe.buckets = state.Buckets
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

	stats := make([]struct {
		FeeRateStart float64
		FeeRateEnd   float64
		InMempool    float64
		Confirmed1   float64
		Confirmed6   float64
		Confirmed24  float64
	}, len(fe.buckets))

	for i, bucket := range fe.buckets {
		stats[i].FeeRateStart = bucket.FeeRateStart
		stats[i].FeeRateEnd = bucket.FeeRateEnd
		stats[i].InMempool = bucket.InMempool

		// Sum confirmations for common targets
		if len(bucket.ConfirmedAt) > 0 {
			stats[i].Confirmed1 = bucket.ConfirmedAt[0].TxCount
		}
		for j := 0; j < 6 && j < len(bucket.ConfirmedAt); j++ {
			stats[i].Confirmed6 += bucket.ConfirmedAt[j].TxCount
		}
		for j := 0; j < 24 && j < len(bucket.ConfirmedAt); j++ {
			stats[i].Confirmed24 += bucket.ConfirmedAt[j].TxCount
		}
	}

	return stats
}
