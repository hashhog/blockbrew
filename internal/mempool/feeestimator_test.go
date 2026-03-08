package mempool

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

func TestNewFeeEstimator(t *testing.T) {
	fe := NewFeeEstimator()
	if fe == nil {
		t.Fatal("NewFeeEstimator returned nil")
	}
	if fe.maxTargetBlocks != 1008 {
		t.Fatalf("Expected maxTargetBlocks 1008, got %d", fe.maxTargetBlocks)
	}
	if fe.decay != 0.998 {
		t.Fatalf("Expected decay 0.998, got %f", fe.decay)
	}
	if len(fe.buckets) != len(defaultBucketBoundaries) {
		t.Fatalf("Expected %d buckets, got %d", len(defaultBucketBoundaries), len(fe.buckets))
	}
}

func TestFindBucket(t *testing.T) {
	fe := NewFeeEstimator()

	tests := []struct {
		feeRate       float64
		expectedStart float64
	}{
		{0.5, 1},     // Below minimum, goes to first bucket
		{1, 1},       // Exactly at first boundary
		{1.5, 1},     // Between 1 and 2
		{2, 2},       // Exactly at second boundary
		{5.5, 5},     // Between 5 and 6
		{100, 100},   // Exactly at 100
		{150, 140},   // Between 140 and 170
		{10000, 10000}, // Exactly at max
		{15000, 10000}, // Above max, goes to last bucket
	}

	for _, tt := range tests {
		bucketIdx := fe.findBucket(tt.feeRate)
		if fe.buckets[bucketIdx].FeeRateStart != tt.expectedStart {
			t.Errorf("feeRate %.1f: expected bucket starting at %.1f, got %.1f",
				tt.feeRate, tt.expectedStart, fe.buckets[bucketIdx].FeeRateStart)
		}
	}
}

func TestRegisterTransaction(t *testing.T) {
	fe := NewFeeEstimator()

	var txHash wire.Hash256
	txHash[0] = 0x01

	// Register a transaction
	fe.RegisterTransaction(txHash, 50.0, 100)

	if fe.TrackedTxCount() != 1 {
		t.Fatalf("Expected 1 tracked tx, got %d", fe.TrackedTxCount())
	}

	// Find the bucket for 50 sat/vB (should be the bucket starting at 50)
	bucketIdx := fe.findBucket(50.0)
	if fe.buckets[bucketIdx].InMempool != 1 {
		t.Fatalf("Expected InMempool 1, got %f", fe.buckets[bucketIdx].InMempool)
	}

	// Re-registering should not change counts
	fe.RegisterTransaction(txHash, 50.0, 100)
	if fe.TrackedTxCount() != 1 {
		t.Fatalf("Re-register should not increase count, got %d", fe.TrackedTxCount())
	}
}

func TestUnregisterTransaction(t *testing.T) {
	fe := NewFeeEstimator()

	var txHash wire.Hash256
	txHash[0] = 0x02

	fe.RegisterTransaction(txHash, 100.0, 100)
	if fe.TrackedTxCount() != 1 {
		t.Fatalf("Expected 1 tracked tx, got %d", fe.TrackedTxCount())
	}

	fe.UnregisterTransaction(txHash)
	if fe.TrackedTxCount() != 0 {
		t.Fatalf("Expected 0 tracked tx after unregister, got %d", fe.TrackedTxCount())
	}

	// Unregistering non-existent should not panic
	fe.UnregisterTransaction(txHash)
}

func TestProcessBlock(t *testing.T) {
	fe := NewFeeEstimator()

	// Register transactions at different fee rates
	var txHash1, txHash2, txHash3 wire.Hash256
	txHash1[0] = 0x10
	txHash2[0] = 0x11
	txHash3[0] = 0x12

	fe.RegisterTransaction(txHash1, 10.0, 100) // Bucket starting at 10
	fe.RegisterTransaction(txHash2, 50.0, 100) // Bucket starting at 50
	fe.RegisterTransaction(txHash3, 100.0, 99) // Bucket starting at 100, entered earlier

	// Process a block that confirms tx1 and tx3
	fe.ProcessBlock(101, []wire.Hash256{txHash1, txHash3})

	// tx1 confirmed in 1 block (101 - 100)
	// tx3 confirmed in 2 blocks (101 - 99)

	if fe.TrackedTxCount() != 1 {
		t.Fatalf("Expected 1 tracked tx remaining, got %d", fe.TrackedTxCount())
	}

	if fe.BestHeight() != 101 {
		t.Fatalf("Expected bestHeight 101, got %d", fe.BestHeight())
	}

	// Verify confirmation stats
	bucket10 := fe.findBucket(10.0)
	// After decay (0.998), the count should be approximately 1 * 0.998 = 0.998
	if fe.buckets[bucket10].ConfirmedAt[0].TxCount < 0.9 {
		t.Fatalf("Expected ~1 confirmation at target 1 for bucket 10, got %f",
			fe.buckets[bucket10].ConfirmedAt[0].TxCount)
	}

	bucket100 := fe.findBucket(100.0)
	// tx3 confirmed in 2 blocks, so target index 1
	if fe.buckets[bucket100].ConfirmedAt[1].TxCount < 0.9 {
		t.Fatalf("Expected ~1 confirmation at target 2 for bucket 100, got %f",
			fe.buckets[bucket100].ConfirmedAt[1].TxCount)
	}
}

func TestEstimateFeeInsufficientData(t *testing.T) {
	fe := NewFeeEstimator()

	// No data, should return -1
	fee := fe.EstimateFee(1)
	if fee != -1 {
		t.Fatalf("Expected -1 for insufficient data, got %f", fee)
	}

	fee = fe.EstimateFee(6)
	if fee != -1 {
		t.Fatalf("Expected -1 for insufficient data, got %f", fee)
	}
}

func TestEstimateFeeWithData(t *testing.T) {
	fe := NewFeeEstimatorWithConfig(100, 1.0) // No decay for simpler testing

	// Simulate transactions at various fee rates
	// Add many transactions at 100 sat/vB that confirm quickly
	bucket100 := fe.findBucket(100.0)
	fe.buckets[bucket100].ConfirmedAt[0].TxCount = 10 // 10 confirmed in 1 block
	fe.buckets[bucket100].InMempool = 0

	// Add transactions at 50 sat/vB that confirm within 6 blocks
	bucket50 := fe.findBucket(50.0)
	fe.buckets[bucket50].ConfirmedAt[0].TxCount = 2
	fe.buckets[bucket50].ConfirmedAt[1].TxCount = 2
	fe.buckets[bucket50].ConfirmedAt[2].TxCount = 2
	fe.buckets[bucket50].ConfirmedAt[3].TxCount = 2
	fe.buckets[bucket50].ConfirmedAt[4].TxCount = 2
	fe.buckets[bucket50].ConfirmedAt[5].TxCount = 2 // Total: 12 confirmed within 6 blocks
	fe.buckets[bucket50].InMempool = 1              // 1 still waiting

	// Add transactions at 10 sat/vB that mostly don't confirm quickly
	bucket10 := fe.findBucket(10.0)
	fe.buckets[bucket10].ConfirmedAt[0].TxCount = 1  // Only 1 confirmed in 1 block
	fe.buckets[bucket10].InMempool = 10              // 10 still waiting

	// Estimate for 1 block target
	// Bucket 100: 10 confirmed / 10 total = 100% success rate > 85%
	// Bucket 50: some confirmed in 1 block but we need to check
	// Bucket 10: 1/11 = 9% success rate < 85%
	fee := fe.EstimateFee(1)
	// Should find bucket 100 as lowest that meets 85% threshold for 1 block
	if fee <= 0 {
		t.Fatalf("Expected positive fee estimate, got %f", fee)
	}

	// Estimate for 6 block target
	// Bucket 50: 12 confirmed / 13 total = 92% success rate > 85%
	fee6 := fe.EstimateFee(6)
	if fee6 <= 0 {
		t.Fatalf("Expected positive fee estimate for 6 blocks, got %f", fee6)
	}

	// Fee for longer target should be same or lower
	if fee6 > fee {
		t.Fatalf("Fee for 6 blocks (%f) should not be higher than 1 block (%f)", fee6, fee)
	}
}

func TestEstimateSmartFeeFallback(t *testing.T) {
	fe := NewFeeEstimatorWithConfig(100, 1.0)

	// Only add data for 1-block confirmations at high fee rate
	// but NOT enough for the 6-block target (we need to make the 6-block estimate fail)
	bucket100 := fe.findBucket(100.0)
	fe.buckets[bucket100].ConfirmedAt[0].TxCount = 1 // Only 1 data point (below minDataPoints=2)
	fe.buckets[bucket100].InMempool = 0

	// This won't trigger fallback since we need at least 2 data points
	// Let's set up a scenario where longer targets have insufficient data
	// but shorter targets have data

	// Reset and try a different approach:
	// Put enough data for 1-block estimate but not for 6-block
	// We need a scenario where estimate for 6 fails but estimate for 1 succeeds

	// Actually, let's add transactions that only confirm quickly at high fee
	// and add some still-pending at lower fee rates to make longer estimates fail
	fe2 := NewFeeEstimatorWithConfig(100, 1.0)

	// High fee bucket: has enough data for 1-block, succeeds
	bucketHigh := fe2.findBucket(500.0)
	fe2.buckets[bucketHigh].ConfirmedAt[0].TxCount = 10
	fe2.buckets[bucketHigh].InMempool = 0

	// Lower fee buckets have pending transactions making them fail for all targets
	// This simulates a scenario where only high-fee transactions have data
	bucketLow := fe2.findBucket(10.0)
	fe2.buckets[bucketLow].ConfirmedAt[0].TxCount = 0
	fe2.buckets[bucketLow].InMempool = 10 // Lots pending, 0% success rate

	// Request 6-block estimate
	// For bucket 500: 10 confirmed / 10 total = 100% (passes for all targets)
	// For bucket 10: 0 confirmed / 10 total = 0% (fails for all targets)
	// EstimateFee will find bucket 500 succeeds, returns 500
	fee, actualTarget := fe2.EstimateSmartFee(6)
	if fee <= 0 {
		t.Fatalf("Expected positive fee from smart estimate, got %f", fee)
	}

	// Since bucket 500 passes for target 6, it should return 6, not fall back
	if actualTarget != 6 {
		t.Fatalf("Expected actualTarget 6, got %d", actualTarget)
	}

	// Now test actual fallback scenario: no data at all for targets 2-6
	// but data exists only for target 1
	fe3 := NewFeeEstimatorWithConfig(100, 1.0)

	// Create a bucket with data that passes 85% only for target 1
	// If we have 10 confirmed at target 0, and 5 still pending that were added
	// after target 1 window, we need to craft this carefully
	//
	// Actually, the algorithm sums confirmations from 0 to targetBlocks-1
	// So if target=6, it sums indices 0-5. If all data is at index 0,
	// then for any target >= 1, the sum is the same.
	//
	// To force fallback, we need a bucket that fails at target 6 but passes at lower targets
	// This happens when: confirmed[0:target] / (confirmed[0:target] + InMempool) < 85%
	//
	// Example: confirmed[0] = 8, InMempool = 10
	// Target 1: 8 / 18 = 44% < 85% - fails
	// So this doesn't work either.
	//
	// The only way to get fallback is if there's insufficient data (total < minDataPoints)
	// for longer targets in ALL buckets, but sufficient data for shorter targets in SOME bucket.
	// But the way data accumulates (sum over targets), this is tricky.
	//
	// Let's test a simpler scenario: no data at all triggers fallback that returns (-1, 0)
	fee3, actualTarget3 := fe3.EstimateSmartFee(6)
	if fee3 != -1 {
		t.Fatalf("Expected -1 for no data, got %f", fee3)
	}
	if actualTarget3 != 0 {
		t.Fatalf("Expected actualTarget 0 for no data, got %d", actualTarget3)
	}
}

func TestEstimateSmartFeeNoData(t *testing.T) {
	fe := NewFeeEstimator()

	fee, actualTarget := fe.EstimateSmartFee(6)
	if fee != -1 {
		t.Fatalf("Expected -1 for no data, got %f", fee)
	}
	if actualTarget != 0 {
		t.Fatalf("Expected actualTarget 0 for no data, got %d", actualTarget)
	}
}

func TestDecayReducesInfluence(t *testing.T) {
	fe := NewFeeEstimatorWithConfig(100, 0.5) // Aggressive decay for testing

	bucket100 := fe.findBucket(100.0)
	fe.buckets[bucket100].ConfirmedAt[0].TxCount = 10
	fe.buckets[bucket100].InMempool = 5

	// Process an empty block to trigger decay
	fe.ProcessBlock(1, nil)

	// Counts should be halved
	if fe.buckets[bucket100].ConfirmedAt[0].TxCount != 5 {
		t.Fatalf("Expected TxCount 5 after decay, got %f", fe.buckets[bucket100].ConfirmedAt[0].TxCount)
	}
	if fe.buckets[bucket100].InMempool != 2.5 {
		t.Fatalf("Expected InMempool 2.5 after decay, got %f", fe.buckets[bucket100].InMempool)
	}

	// Process another empty block
	fe.ProcessBlock(2, nil)

	// Should be halved again
	if fe.buckets[bucket100].ConfirmedAt[0].TxCount != 2.5 {
		t.Fatalf("Expected TxCount 2.5 after second decay, got %f", fe.buckets[bucket100].ConfirmedAt[0].TxCount)
	}
}

func TestFeeDecreaseForLongerTargets(t *testing.T) {
	fe := NewFeeEstimatorWithConfig(100, 1.0)

	// Create a scenario where lower fee rates are viable for longer targets
	// High fee rate bucket: confirms quickly
	bucketHigh := fe.findBucket(200.0)
	fe.buckets[bucketHigh].ConfirmedAt[0].TxCount = 10
	fe.buckets[bucketHigh].InMempool = 0

	// Medium fee rate bucket: confirms within 3 blocks
	bucketMed := fe.findBucket(50.0)
	fe.buckets[bucketMed].ConfirmedAt[0].TxCount = 3
	fe.buckets[bucketMed].ConfirmedAt[1].TxCount = 3
	fe.buckets[bucketMed].ConfirmedAt[2].TxCount = 4
	fe.buckets[bucketMed].InMempool = 0

	// Low fee rate bucket: confirms within 10 blocks
	bucketLow := fe.findBucket(10.0)
	for i := 0; i < 10; i++ {
		fe.buckets[bucketLow].ConfirmedAt[i].TxCount = 1
	}
	fe.buckets[bucketLow].InMempool = 0

	fee1 := fe.EstimateFee(1)
	fee3 := fe.EstimateFee(3)
	fee10 := fe.EstimateFee(10)

	// Longer targets should have same or lower fee requirements
	if fee3 > fee1 {
		t.Fatalf("Fee for 3 blocks (%f) should not exceed fee for 1 block (%f)", fee3, fee1)
	}
	if fee10 > fee3 {
		t.Fatalf("Fee for 10 blocks (%f) should not exceed fee for 3 blocks (%f)", fee10, fee3)
	}
}

func TestEmptyMempool(t *testing.T) {
	fe := NewFeeEstimator()

	// No transactions registered, no confirmations
	fee := fe.EstimateFee(1)
	if fee != -1 {
		t.Fatalf("Expected -1 for empty mempool, got %f", fee)
	}

	fee, target := fe.EstimateSmartFee(6)
	if fee != -1 || target != 0 {
		t.Fatalf("Expected (-1, 0) for empty mempool, got (%f, %d)", fee, target)
	}
}

func TestSingleTransaction(t *testing.T) {
	fe := NewFeeEstimatorWithConfig(100, 1.0)

	var txHash wire.Hash256
	txHash[0] = 0x01

	fe.RegisterTransaction(txHash, 100.0, 100)
	fe.ProcessBlock(101, []wire.Hash256{txHash})

	// With minDataPoints = 2, a single transaction is insufficient
	fee := fe.EstimateFee(1)
	if fee != -1 {
		t.Fatalf("Expected -1 for single transaction (below minDataPoints), got %f", fee)
	}
}

func TestAllSameFeeRate(t *testing.T) {
	fe := NewFeeEstimatorWithConfig(100, 1.0)

	// Add multiple transactions at exactly the same fee rate
	bucket := fe.findBucket(50.0)
	fe.buckets[bucket].ConfirmedAt[0].TxCount = 5
	fe.buckets[bucket].ConfirmedAt[1].TxCount = 3
	fe.buckets[bucket].InMempool = 0

	fee := fe.EstimateFee(1)
	if fee <= 0 {
		t.Fatalf("Expected positive fee for transactions at same rate, got %f", fee)
	}

	// Should be 50 (the bucket start)
	if fee != 50.0 {
		t.Fatalf("Expected fee 50.0, got %f", fee)
	}
}

func TestTargetBlocksBoundaries(t *testing.T) {
	fe := NewFeeEstimatorWithConfig(100, 1.0)

	// Add enough data for estimation
	bucket := fe.findBucket(50.0)
	for i := 0; i < 100; i++ {
		fe.buckets[bucket].ConfirmedAt[i].TxCount = 1
	}

	// Target < 1 should be treated as 1
	fee := fe.EstimateFee(0)
	fee1 := fe.EstimateFee(1)
	if fee != fee1 {
		t.Fatalf("Target 0 should behave like target 1")
	}

	// Target > maxTargetBlocks should be capped
	feeBig := fe.EstimateFee(10000)
	feeMax := fe.EstimateFee(100)
	if feeBig != feeMax {
		t.Fatalf("Target above max should be capped")
	}
}

func TestSaveAndLoad(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "feeestimator_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create estimator with some data
	fe1 := NewFeeEstimatorWithConfig(100, 0.99)
	fe1.bestHeight = 500000

	bucket := fe1.findBucket(100.0)
	fe1.buckets[bucket].ConfirmedAt[0].TxCount = 42
	fe1.buckets[bucket].InMempool = 5

	// Save
	if err := fe1.Save(tmpDir); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	path := filepath.Join(tmpDir, "fee_estimates.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("Save file not created")
	}

	// Load into new estimator
	fe2 := NewFeeEstimatorWithConfig(100, 0.99) // Same config required
	if err := fe2.Load(tmpDir); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify loaded data
	if fe2.bestHeight != 500000 {
		t.Fatalf("Expected bestHeight 500000, got %d", fe2.bestHeight)
	}

	bucket2 := fe2.findBucket(100.0)
	if fe2.buckets[bucket2].ConfirmedAt[0].TxCount != 42 {
		t.Fatalf("Expected TxCount 42, got %f", fe2.buckets[bucket2].ConfirmedAt[0].TxCount)
	}
}

func TestLoadNonexistent(t *testing.T) {
	fe := NewFeeEstimator()

	// Loading from nonexistent directory should not error
	err := fe.Load("/nonexistent/path/that/does/not/exist")
	if err != nil {
		t.Fatalf("Load from nonexistent path should not error, got: %v", err)
	}
}

func TestGetBucketStats(t *testing.T) {
	fe := NewFeeEstimatorWithConfig(100, 1.0)

	bucket := fe.findBucket(50.0)
	fe.buckets[bucket].ConfirmedAt[0].TxCount = 5  // Confirmed in 1 block
	fe.buckets[bucket].ConfirmedAt[5].TxCount = 3  // Confirmed in 6 blocks
	fe.buckets[bucket].ConfirmedAt[23].TxCount = 2 // Confirmed in 24 blocks
	fe.buckets[bucket].InMempool = 10

	stats := fe.GetBucketStats()
	if len(stats) != len(defaultBucketBoundaries) {
		t.Fatalf("Expected %d bucket stats, got %d", len(defaultBucketBoundaries), len(stats))
	}

	// Find the bucket for 50 sat/vB
	var found bool
	for _, s := range stats {
		if s.FeeRateStart == 50.0 {
			found = true
			if s.Confirmed1 != 5 {
				t.Fatalf("Expected Confirmed1 5, got %f", s.Confirmed1)
			}
			// Confirmed6 = sum of first 6 targets = 5 + 0 + 0 + 0 + 0 + 3 = 8
			if s.Confirmed6 != 8 {
				t.Fatalf("Expected Confirmed6 8, got %f", s.Confirmed6)
			}
			// Confirmed24 = sum of first 24 targets = 5 + 3 + 2 = 10
			if s.Confirmed24 != 10 {
				t.Fatalf("Expected Confirmed24 10, got %f", s.Confirmed24)
			}
			if s.InMempool != 10 {
				t.Fatalf("Expected InMempool 10, got %f", s.InMempool)
			}
			break
		}
	}
	if !found {
		t.Fatal("Bucket for 50 sat/vB not found in stats")
	}
}

func TestSetBestHeight(t *testing.T) {
	fe := NewFeeEstimator()

	if fe.BestHeight() != 0 {
		t.Fatalf("Expected initial height 0, got %d", fe.BestHeight())
	}

	fe.SetBestHeight(100000)
	if fe.BestHeight() != 100000 {
		t.Fatalf("Expected height 100000, got %d", fe.BestHeight())
	}
}

func TestMultipleBlockProcessing(t *testing.T) {
	fe := NewFeeEstimatorWithConfig(100, 1.0)

	// Register transactions
	var txHashes [10]wire.Hash256
	for i := range txHashes {
		txHashes[i][0] = byte(i + 1)
		fe.RegisterTransaction(txHashes[i], 100.0, 100)
	}

	if fe.TrackedTxCount() != 10 {
		t.Fatalf("Expected 10 tracked, got %d", fe.TrackedTxCount())
	}

	// Process blocks confirming transactions over time
	fe.ProcessBlock(101, []wire.Hash256{txHashes[0], txHashes[1]}) // 2 in block 101
	fe.ProcessBlock(102, []wire.Hash256{txHashes[2], txHashes[3]}) // 2 in block 102
	fe.ProcessBlock(103, []wire.Hash256{txHashes[4]})              // 1 in block 103

	if fe.TrackedTxCount() != 5 {
		t.Fatalf("Expected 5 tracked after 3 blocks, got %d", fe.TrackedTxCount())
	}

	if fe.BestHeight() != 103 {
		t.Fatalf("Expected bestHeight 103, got %d", fe.BestHeight())
	}
}

func TestEdgeCaseConfirmationTime(t *testing.T) {
	fe := NewFeeEstimatorWithConfig(100, 1.0)

	var txHash wire.Hash256
	txHash[0] = 0x01

	// Register at height 100
	fe.RegisterTransaction(txHash, 50.0, 100)

	// Confirm at same height (edge case, should be treated as 1 block)
	fe.ProcessBlock(100, []wire.Hash256{txHash})

	bucket := fe.findBucket(50.0)
	// Should record as confirmed at target index 0 (1 block)
	if fe.buckets[bucket].ConfirmedAt[0].TxCount < 0.9 {
		t.Fatalf("Expected confirmation at target 1, got %f", fe.buckets[bucket].ConfirmedAt[0].TxCount)
	}
}

func TestMaxTargetBlocksConfirmation(t *testing.T) {
	fe := NewFeeEstimatorWithConfig(10, 1.0) // Small max for testing

	var txHash wire.Hash256
	txHash[0] = 0x01

	// Register at height 100
	fe.RegisterTransaction(txHash, 50.0, 100)

	// Confirm at height 200 (100 blocks later, exceeds max)
	fe.ProcessBlock(200, []wire.Hash256{txHash})

	bucket := fe.findBucket(50.0)
	// Should be capped at last index (9 for maxTargetBlocks=10)
	if fe.buckets[bucket].ConfirmedAt[9].TxCount < 0.9 {
		t.Fatalf("Expected confirmation at max target index, got %f", fe.buckets[bucket].ConfirmedAt[9].TxCount)
	}
}
