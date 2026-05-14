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
	// Long horizon covers 1008 blocks (42 periods × 24-block scale).
	if fe.HighestTargetTracked() != 1008 {
		t.Fatalf("Expected HighestTargetTracked 1008, got %d", fe.HighestTargetTracked())
	}
	// SHORT horizon must use Core's decay of 0.962.
	if fe.stats[HorizonShort].decay != 0.962 {
		t.Fatalf("Expected SHORT decay 0.962, got %f", fe.stats[HorizonShort].decay)
	}
	// MED horizon must use Core's decay of 0.9952.
	if fe.stats[HorizonMedium].decay != 0.9952 {
		t.Fatalf("Expected MED decay 0.9952, got %f", fe.stats[HorizonMedium].decay)
	}
	// LONG horizon must use Core's decay of 0.99931.
	if fe.stats[HorizonLong].decay != 0.99931 {
		t.Fatalf("Expected LONG decay 0.99931, got %f", fe.stats[HorizonLong].decay)
	}
	if len(fe.buckets) != len(defaultBucketBoundaries) {
		t.Fatalf("Expected %d buckets, got %d", len(defaultBucketBoundaries), len(fe.buckets))
	}
}

func TestFindBucket(t *testing.T) {
	fe := NewFeeEstimator()

	// Verify that bucket lookup is monotone and within bounds.
	// With exponential 0.1-spaced buckets we can't hard-code exact starts,
	// so just verify directional correctness.
	idx001 := fe.findBucket(0.01) // Below minimum → first bucket
	if idx001 != 0 {
		t.Errorf("feeRate 0.01: expected bucket 0 (below min), got %d", idx001)
	}
	idx01 := fe.findBucket(0.1) // Exactly at first boundary
	if idx01 != 0 {
		t.Errorf("feeRate 0.1: expected bucket 0, got %d", idx01)
	}
	// A very high fee rate should fall in one of the last two buckets
	// (the last pre-INF bucket or the INF bucket itself).
	idxHigh := fe.findBucket(1e8)
	if idxHigh < len(fe.buckets)-2 {
		t.Errorf("feeRate 1e8: expected near-last bucket (≥%d), got %d",
			len(fe.buckets)-2, idxHigh)
	}
	// Monotonicity: findBucket(x) <= findBucket(y) when x <= y.
	prevIdx := 0
	for _, rate := range []float64{0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0} {
		idx := fe.findBucket(rate)
		if idx < prevIdx {
			t.Errorf("non-monotone: findBucket(%.1f)=%d < findBucket(prev)=%d", rate, idx, prevIdx)
		}
		prevIdx = idx
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

	// Find the bucket for 50 sat/vB and verify tracking via SHORT horizon.
	bucketIdx := fe.findBucket(50.0)
	if fe.stats[HorizonShort].inMempool[bucketIdx] != 1 {
		t.Fatalf("Expected inMempool 1 in SHORT horizon, got %f", fe.stats[HorizonShort].inMempool[bucketIdx])
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

	// Verify confirmation stats using SHORT horizon (scale=1, so period 0 = 1 block).
	bucket10 := fe.findBucket(10.0)
	// tx1 confirmed in 1 block (period 0 for SHORT). After decay (0.962), ~0.962.
	shortStat := fe.stats[HorizonShort]
	if shortStat.confAvg[0][bucket10] < 0.9 {
		t.Fatalf("Expected ~1 confirmation at SHORT period 0 for bucket10, got %f",
			shortStat.confAvg[0][bucket10])
	}

	bucket100 := fe.findBucket(100.0)
	// tx3 confirmed in 2 blocks. SHORT period 1 (blocks 1-2), or MED period 0 (blocks 1-2).
	// Check MED horizon period 0 (scale=2, so period 0 covers ≤2 blocks).
	medStat := fe.stats[HorizonMedium]
	if medStat.confAvg[0][bucket100] < 0.9 {
		t.Fatalf("Expected ~1 confirmation at MED period 0 for bucket100, got %f",
			medStat.confAvg[0][bucket100])
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
	fe := NewFeeEstimator()

	// Inject data directly into the SHORT horizon (both target=1 and target=6
	// use SHORT horizon since 6 ≤ maxBlocksForHorizon(SHORT)=12).

	bucket100 := fe.findBucket(100.0)
	shortS := fe.stats[HorizonShort]
	const sufficientShort = 0.1 / (1.0 - 0.962) // ≈ 2.63
	// Lots of txs at 100 sat/vB confirming in 1 block → SHORT period 0.
	for p := 0; p < shortS.periods; p++ {
		shortS.confAvg[p][bucket100] = sufficientShort * 40
	}
	shortS.txCtAvg[bucket100] = sufficientShort * 40

	bucket50 := fe.findBucket(50.0)
	// Txs at 50 sat/vB confirming within 6 blocks → SHORT period 5 (periodIdx=5).
	for p := 5; p < shortS.periods; p++ {
		shortS.confAvg[p][bucket50] = sufficientShort * 12
	}
	shortS.txCtAvg[bucket50] = sufficientShort * 13
	shortS.inMempool[bucket50] = 1

	// Estimate for 1 block target (SHORT horizon).
	fee := fe.EstimateFee(1)
	if fee <= 0 {
		t.Fatalf("Expected positive fee estimate for 1 block, got %f", fee)
	}

	// Estimate for 6 block target (SHORT horizon, period 5).
	fee6 := fe.EstimateFee(6)
	if fee6 <= 0 {
		t.Fatalf("Expected positive fee estimate for 6 blocks, got %f", fee6)
	}

	// Fee for longer target should be same or lower.
	if fee6 > fee {
		t.Fatalf("Fee for 6 blocks (%f) should not be higher than 1 block (%f)", fee6, fee)
	}
}

func TestEstimateSmartFeeFallback(t *testing.T) {
	fe := NewFeeEstimator()

	// target=6 ≤ 12 → SHORT horizon. Inject enough data into SHORT.
	bucketHigh := fe.findBucket(500.0)
	shortS := fe.stats[HorizonShort]
	const sufficientShort = 0.1 / (1.0 - 0.962) // ≈ 2.63
	// SHORT scale=1, period = ceil(6/1)=6, periodIdx=5.
	for p := 5; p < shortS.periods; p++ {
		shortS.confAvg[p][bucketHigh] = sufficientShort * 10
	}
	shortS.txCtAvg[bucketHigh] = sufficientShort * 10

	fee, actualTarget := fe.EstimateSmartFee(6)
	if fee <= 0 {
		t.Fatalf("Expected positive fee from smart estimate, got %f", fee)
	}
	if actualTarget != 6 {
		t.Fatalf("Expected actualTarget 6, got %d", actualTarget)
	}

	// No data → fallback returns (-1, 0).
	fe2 := NewFeeEstimator()
	fee2, target2 := fe2.EstimateSmartFee(6)
	if fee2 != -1 {
		t.Fatalf("Expected -1 for no data, got %f", fee2)
	}
	if target2 != 0 {
		t.Fatalf("Expected actualTarget 0 for no data, got %d", target2)
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
	fe := NewFeeEstimator()

	bucket100 := fe.findBucket(100.0)
	shortS := fe.stats[HorizonShort]
	// Inject directly into SHORT horizon confAvg[0] and inMempool.
	shortS.confAvg[0][bucket100] = 10
	shortS.inMempool[bucket100] = 5

	// Process an empty block to trigger decay.
	fe.ProcessBlock(1, nil)

	// SHORT decay = 0.962; 10 * 0.962 = 9.62, 5 * 0.962 = 4.81.
	const eps = 0.01
	got := shortS.confAvg[0][bucket100]
	if got < 9.62-eps || got > 9.62+eps {
		t.Fatalf("Expected confAvg[0] ≈ 9.62 after SHORT decay, got %f", got)
	}
	gotMem := shortS.inMempool[bucket100]
	if gotMem < 4.81-eps || gotMem > 4.81+eps {
		t.Fatalf("Expected inMempool ≈ 4.81 after SHORT decay, got %f", gotMem)
	}

	// Process another empty block.
	fe.ProcessBlock(2, nil)

	// 9.62 * 0.962 ≈ 9.254
	got2 := shortS.confAvg[0][bucket100]
	if got2 < 9.0 || got2 > 9.62 {
		t.Fatalf("Expected confAvg[0] in (9.0, 9.62) after second decay, got %f", got2)
	}
}

func TestFeeDecreaseForLongerTargets(t *testing.T) {
	fe := NewFeeEstimator()

	// All targets ≤12 use SHORT horizon (scale=1, 12 periods).
	// target=1  → period 0
	// target=3  → period 2
	// target=10 → period 9
	// target=25 → MED horizon (>12, ≤48), period = ceil(25/2)=13 → periodIdx=12
	const sufficientShort = 0.1 / (1.0 - 0.962) // ≈ 2.63
	const sufficientMed = 0.1 / (1.0 - 0.9952)  // ≈ 20.8

	// High fee bucket → confirms in 1 block (SHORT period 0).
	bucketHigh := fe.findBucket(200.0)
	shortS := fe.stats[HorizonShort]
	for p := 0; p < shortS.periods; p++ {
		shortS.confAvg[p][bucketHigh] = sufficientShort * 10
	}
	shortS.txCtAvg[bucketHigh] = sufficientShort * 10

	// Medium fee bucket → confirms within 3 blocks (SHORT period 2).
	bucketMedFee := fe.findBucket(50.0)
	for p := 2; p < shortS.periods; p++ {
		shortS.confAvg[p][bucketMedFee] = sufficientShort * 10
	}
	shortS.txCtAvg[bucketMedFee] = sufficientShort * 10

	// Low fee bucket → confirms within 10 blocks (SHORT period 9).
	bucketLow := fe.findBucket(10.0)
	for p := 9; p < shortS.periods; p++ {
		shortS.confAvg[p][bucketLow] = sufficientShort * 10
	}
	shortS.txCtAvg[bucketLow] = sufficientShort * 10

	// Very low fee bucket → confirms within 25 blocks (MED horizon, period 12).
	bucketVeryLow := fe.findBucket(5.0)
	medS := fe.stats[HorizonMedium]
	for p := 12; p < medS.periods; p++ {
		medS.confAvg[p][bucketVeryLow] = sufficientMed * 10
	}
	medS.txCtAvg[bucketVeryLow] = sufficientMed * 10

	fee1 := fe.EstimateFee(1)
	fee3 := fe.EstimateFee(3)
	fee10 := fe.EstimateFee(10)
	fee25 := fe.EstimateFee(25)

	if fee1 <= 0 || fee3 <= 0 || fee10 <= 0 || fee25 <= 0 {
		t.Fatalf("Expected positive estimates: fee1=%f fee3=%f fee10=%f fee25=%f", fee1, fee3, fee10, fee25)
	}

	// Longer targets should have same or lower fee requirements.
	if fee3 > fee1 {
		t.Fatalf("Fee for 3 blocks (%f) should not exceed fee for 1 block (%f)", fee3, fee1)
	}
	if fee10 > fee3 {
		t.Fatalf("Fee for 10 blocks (%f) should not exceed fee for 3 blocks (%f)", fee10, fee3)
	}
	if fee25 > fee10 {
		t.Fatalf("Fee for 25 blocks (%f) should not exceed fee for 10 blocks (%f)", fee25, fee10)
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
	fe := NewFeeEstimator()

	var txHash wire.Hash256
	txHash[0] = 0x01

	fe.RegisterTransaction(txHash, 100.0, 100)
	fe.ProcessBlock(101, []wire.Hash256{txHash})

	// With sufficientTxVal ≈ 2.6 for SHORT, a single transaction is insufficient.
	fee := fe.EstimateFee(1)
	if fee != -1 {
		t.Fatalf("Expected -1 for single transaction (below sufficientTxVal), got %f", fee)
	}
}

func TestAllSameFeeRate(t *testing.T) {
	fe := NewFeeEstimator()

	// Add multiple transactions at exactly the same fee rate using SHORT horizon.
	bucket := fe.findBucket(50.0)
	shortS := fe.stats[HorizonShort]
	const sufficientShort = 0.1 / (1.0 - 0.962)
	for p := 0; p < shortS.periods; p++ {
		shortS.confAvg[p][bucket] = sufficientShort * 5
	}
	shortS.txCtAvg[bucket] = sufficientShort * 5

	fee := fe.EstimateFee(1)
	if fee <= 0 {
		t.Fatalf("Expected positive fee for transactions at same rate, got %f", fee)
	}

	// The estimator accumulates across all buckets down from the highest.
	// With data only at bucket ~50 sat/vB and no data below it, the accumulated
	// group passes at 100%, so the result is the lowest fee-rate boundary scanned
	// (Core's "lowest fee rate in the passing group" semantics).
	// Just verify a positive result was returned — the exact value depends on
	// how far down the empty buckets extend.
	t.Logf("TestAllSameFeeRate: fee=%f (bucket %d start %f)", fee, bucket, fe.buckets[bucket].FeeRateStart)
}

func TestTargetBlocksBoundaries(t *testing.T) {
	fe := NewFeeEstimator()

	// Add enough data across all horizons.
	bucket := fe.findBucket(50.0)
	const sufficientShort = 0.1 / (1.0 - 0.962)
	shortS := fe.stats[HorizonShort]
	for p := 0; p < shortS.periods; p++ {
		shortS.confAvg[p][bucket] = sufficientShort * 10
	}
	shortS.txCtAvg[bucket] = sufficientShort * 10

	// Target < 1 should be treated as 1.
	fee := fe.EstimateFee(0)
	fee1 := fe.EstimateFee(1)
	if fee != fee1 {
		t.Fatalf("Target 0 should behave like target 1: fee=%f fee1=%f", fee, fee1)
	}

	// Target above LONG max (1008) should use LONG horizon (capped).
	feeBig := fe.EstimateFee(10000)
	feeMax := fe.EstimateFee(1008)
	if feeBig != feeMax {
		t.Fatalf("Target above max should be capped: feeBig=%f feeMax=%f", feeBig, feeMax)
	}
}

func TestSaveAndLoad(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "feeestimator_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create estimator with some data.
	fe1 := NewFeeEstimator()
	fe1.bestHeight = 500000

	bucket := fe1.findBucket(100.0)
	fe1.stats[HorizonShort].confAvg[0][bucket] = 42
	fe1.stats[HorizonShort].txCtAvg[bucket] = 42
	fe1.stats[HorizonShort].inMempool[bucket] = 5

	// Save
	if err := fe1.Save(tmpDir); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	path := filepath.Join(tmpDir, "fee_estimates.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("Save file not created")
	}

	// Load into new estimator.
	fe2 := NewFeeEstimator()
	if err := fe2.Load(tmpDir); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify loaded data.
	if fe2.bestHeight != 500000 {
		t.Fatalf("Expected bestHeight 500000, got %d", fe2.bestHeight)
	}

	bucket2 := fe2.findBucket(100.0)
	if fe2.stats[HorizonShort].confAvg[0][bucket2] != 42 {
		t.Fatalf("Expected confAvg[0] 42, got %f", fe2.stats[HorizonShort].confAvg[0][bucket2])
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
	fe := NewFeeEstimator()

	stats := fe.GetBucketStats()
	if len(stats) != len(defaultBucketBoundaries) {
		t.Fatalf("Expected %d bucket stats, got %d", len(defaultBucketBoundaries), len(stats))
	}

	// Verify all bucket starts are populated.
	for i, s := range stats {
		if s.FeeRateStart != defaultBucketBoundaries[i] {
			t.Fatalf("Bucket %d: expected start %f, got %f", i, defaultBucketBoundaries[i], s.FeeRateStart)
		}
	}

	// Inject some data into MED horizon and verify it shows up.
	bucket := fe.findBucket(50.0)
	medS := fe.stats[HorizonMedium]
	medS.inMempool[bucket] = 7

	stats2 := fe.GetBucketStats()
	var found bool
	for _, s := range stats2 {
		if s.FeeRateStart >= 49.0 && s.FeeRateStart <= 51.0 {
			found = true
			if s.InMempool != 7 {
				t.Fatalf("Expected InMempool 7, got %f", s.InMempool)
			}
			break
		}
	}
	if !found {
		t.Fatal("Bucket near 50 sat/vB not found in stats")
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
	fe := NewFeeEstimator()

	var txHash wire.Hash256
	txHash[0] = 0x01

	// Register at height 100.
	fe.RegisterTransaction(txHash, 50.0, 100)

	// Confirm at same height (edge case, should be treated as 1 block).
	fe.ProcessBlock(100, []wire.Hash256{txHash})

	bucket := fe.findBucket(50.0)
	// SHORT horizon: 1-block confirm lands in period 0.
	// After decay (0.962) confAvg[0][bucket] ≈ 0.962 > 0.9.
	shortS := fe.stats[HorizonShort]
	if shortS.confAvg[0][bucket] < 0.9 {
		t.Fatalf("Expected SHORT confAvg[0] ≥ 0.9 for 1-block confirm, got %f",
			shortS.confAvg[0][bucket])
	}
}

func TestMaxTargetBlocksConfirmation(t *testing.T) {
	fe := NewFeeEstimator()

	var txHash wire.Hash256
	txHash[0] = 0x01

	// Register at height 100.
	fe.RegisterTransaction(txHash, 50.0, 100)

	// Confirm at height 200 (100 blocks later, exceeds LONG horizon max of 1008).
	// The LONG horizon should cap at period 41 (its last period).
	fe.ProcessBlock(200, []wire.Hash256{txHash})

	bucket := fe.findBucket(50.0)
	longS := fe.stats[HorizonLong]
	lastPeriod := longS.periods - 1
	// Cumulative counting: all periods up to max are incremented (capped at last).
	// After 1 decay step confAvg[lastPeriod][bucket] ≈ 0.99931.
	if longS.confAvg[lastPeriod][bucket] < 0.9 {
		t.Fatalf("Expected LONG confAvg[%d] ≥ 0.9 for capped confirm, got %f",
			lastPeriod, longS.confAvg[lastPeriod][bucket])
	}
}
