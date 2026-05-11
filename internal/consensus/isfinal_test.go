package consensus

// IsFinalTx + BIP-113 comprehensive test suite.
//
// Bitcoin Core reference: consensus/tx_verify.cpp:17-37 (IsFinalTx)
//                         validation.cpp:4133-4146 (BIP-113 nLockTimeCutoff)
//
// Gates tested:
//   IsFinalTx:
//     F1.  tx.LockTime == 0 → always final
//     F2.  tx.LockTime < LOCKTIME_THRESHOLD → compare with blockHeight (height path)
//     F3.  tx.LockTime >= LOCKTIME_THRESHOLD → compare with blockTime (timestamp path)
//     F4.  tx.LockTime < cutoff (strict less-than) → final
//     F5.  tx.LockTime == cutoff → NOT final (no <=, only <)
//     F6.  ALL inputs nSequence == 0xFFFFFFFF → final regardless of locktime
//     F7.  ANY input nSequence != 0xFFFFFFFF → NOT final by SEQUENCE_FINAL bypass
//   BIP-113 wiring (CheckBlockContext):
//     B1.  Pre-CSV activation: blockTime = block header timestamp
//     B2.  Post-CSV activation: blockTime = MTP (medianTimePast)

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// makeFinalTestTx builds a transaction with the given locktime and per-input sequences.
func makeFinalTestTx(lockTime uint32, sequences ...uint32) *wire.MsgTx {
	tx := &wire.MsgTx{
		Version:  1,
		LockTime: lockTime,
	}
	for _, seq := range sequences {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Sequence:         seq,
		})
	}
	if len(tx.TxIn) == 0 {
		tx.TxIn = []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}},
			Sequence:         0xFFFFFFFE,
		}}
	}
	tx.TxOut = []*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}}
	return tx
}

// testMainnetParams returns a copy of the mainnet chain params for tests.
func testMainnetParams() *ChainParams {
	p := *MainnetParams()
	return &p
}

// ─── F1: LockTime == 0 → always final ────────────────────────────────────────

// TestIsFinalTx_F1_LockTimeZeroAlwaysFinal verifies that a transaction with
// nLockTime==0 is always considered final regardless of height/time.
// Core: tx_verify.cpp:19.
func TestIsFinalTx_F1_LockTimeZeroAlwaysFinal(t *testing.T) {
	tx := makeFinalTestTx(0, 0xFFFFFFFE)
	if !IsFinalTx(tx, 0, 0) {
		t.Fatal("LockTime=0 must be final at height=0, time=0")
	}
	if !IsFinalTx(tx, 1_000_000, 4_294_967_295) { // max uint32
		t.Fatal("LockTime=0 must be final at any height/time")
	}
	// SEQUENCE_FINAL inputs also final
	tx2 := makeFinalTestTx(0, 0xFFFFFFFF)
	if !IsFinalTx(tx2, 0, 0) {
		t.Fatal("LockTime=0 + SEQUENCE_FINAL must be final")
	}
}

// ─── F2: Block-height comparison ─────────────────────────────────────────────

// TestIsFinalTx_F2_HeightBased_FinalWhenSatisfied checks that a height-based
// locktime (< LOCKTIME_THRESHOLD) is final when locktime < blockHeight.
// Core: tx_verify.cpp:21.
func TestIsFinalTx_F2_HeightBased_FinalWhenSatisfied(t *testing.T) {
	tx := makeFinalTestTx(100, 0xFFFFFFFE)
	if !IsFinalTx(tx, 101, 0) {
		t.Fatal("height-based: lockTime(100) < blockHeight(101) → should be final")
	}
}

// TestIsFinalTx_F2_HeightBased_NotFinalAtBoundary checks the boundary: locktime
// equal to blockHeight is NOT final (strict less-than). Core:21.
func TestIsFinalTx_F2_HeightBased_NotFinalAtBoundary(t *testing.T) {
	tx := makeFinalTestTx(100, 0xFFFFFFFE)
	if IsFinalTx(tx, 100, 0) {
		t.Fatal("height-based: lockTime(100) == blockHeight(100) → must NOT be final (strict <)")
	}
}

// TestIsFinalTx_F2_HeightBased_NotFinalWhenExceedsHeight checks that when
// locktime > blockHeight the tx is not final.
func TestIsFinalTx_F2_HeightBased_NotFinalWhenExceedsHeight(t *testing.T) {
	tx := makeFinalTestTx(500, 0xFFFFFFFE)
	if IsFinalTx(tx, 100, 0) {
		t.Fatal("height-based: lockTime(500) > blockHeight(100) → must NOT be final")
	}
}

// ─── F3: Timestamp comparison ─────────────────────────────────────────────────

// TestIsFinalTx_F3_TimestampBased_FinalWhenSatisfied checks a timestamp-based
// locktime (>= LOCKTIME_THRESHOLD=500_000_000). Core: tx_verify.cpp:21.
func TestIsFinalTx_F3_TimestampBased_FinalWhenSatisfied(t *testing.T) {
	tx := makeFinalTestTx(500_000_000, 0xFFFFFFFE)
	if !IsFinalTx(tx, 0, 500_000_001) {
		t.Fatal("timestamp-based: lockTime(500_000_000) < blockTime(500_000_001) → should be final")
	}
}

// TestIsFinalTx_F3_TimestampBased_NotFinalAtBoundary checks locktime ==
// blockTime is not final (strict less-than).
func TestIsFinalTx_F3_TimestampBased_NotFinalAtBoundary(t *testing.T) {
	tx := makeFinalTestTx(500_000_000, 0xFFFFFFFE)
	if IsFinalTx(tx, 0, 500_000_000) {
		t.Fatal("timestamp-based: lockTime == blockTime → must NOT be final (strict <)")
	}
}

// TestIsFinalTx_F3_ThresholdBoundary verifies LOCKTIME_THRESHOLD (500_000_000)
// routes to the timestamp path, not the height path. Core: tx_verify.cpp:21.
// Setting blockHeight large (would satisfy height path) but blockTime=0 (does
// not satisfy timestamp path) ensures the timestamp path is tested.
func TestIsFinalTx_F3_ThresholdBoundary(t *testing.T) {
	// tx.LockTime=500_000_000 → timestamp path.
	// blockHeight=999_999_999 (would satisfy height path: 500_000_000 < 999_999_999)
	// blockTime=0 (does NOT satisfy timestamp path: 500_000_000 < 0 is false)
	// Sequence is not FINAL → no bypass.
	// Expected: NOT final (timestamp path used).
	tx := makeFinalTestTx(500_000_000, 0xFFFFFFFE)
	if IsFinalTx(tx, 999_999_999, 0) {
		t.Fatal("lockTime=500_000_000 must route to timestamp path, not height path")
	}
}

// TestIsFinalTx_F3_OneBelowThreshold verifies LOCKTIME_THRESHOLD-1
// (499_999_999) routes to the height path. Core: tx_verify.cpp:21.
func TestIsFinalTx_F3_OneBelowThreshold(t *testing.T) {
	// tx.LockTime=499_999_999 → height path.
	// blockHeight=0 (does NOT satisfy height path: 499_999_999 < 0 is false)
	// blockTime=999_999_999 (would satisfy timestamp path)
	// Sequence is not FINAL → no bypass.
	// Expected: NOT final (height path used).
	tx := makeFinalTestTx(499_999_999, 0xFFFFFFFE)
	if IsFinalTx(tx, 0, 999_999_999) {
		t.Fatal("lockTime=499_999_999 must route to height path (< LOCKTIME_THRESHOLD)")
	}
}

// ─── F6: SEQUENCE_FINAL bypass — all inputs must be FINAL ─────────────────────

// TestIsFinalTx_F6_AllSequenceFinalBypassesLocktime verifies that when ALL
// inputs have nSequence == 0xFFFFFFFF, the transaction is final even if
// locktime is not satisfied. Core: tx_verify.cpp:32-35.
func TestIsFinalTx_F6_AllSequenceFinalBypassesLocktime(t *testing.T) {
	// Unsatisfied locktime (lockTime=1000 >= blockHeight=500) but all inputs FINAL.
	tx := makeFinalTestTx(1000, 0xFFFFFFFF, 0xFFFFFFFF)
	if !IsFinalTx(tx, 500, 0) {
		t.Fatal("all inputs SEQUENCE_FINAL must bypass locktime → should be final")
	}
}

// TestIsFinalTx_F6_SingleInputSequenceFinalBypasses single-input bypass.
func TestIsFinalTx_F6_SingleInputSequenceFinalBypasses(t *testing.T) {
	tx := makeFinalTestTx(9999, 0xFFFFFFFF)
	if !IsFinalTx(tx, 100, 0) {
		t.Fatal("single input SEQUENCE_FINAL must bypass locktime")
	}
}

// ─── F7: ANY input not FINAL → no bypass ─────────────────────────────────────

// TestIsFinalTx_F7_OneNonFinalInputBlocksFinalness checks that even one input
// with nSequence != 0xFFFFFFFF prevents the SEQUENCE_FINAL bypass. Core:32-35.
func TestIsFinalTx_F7_OneNonFinalInputBlocksFinalness(t *testing.T) {
	// Two inputs: one FINAL, one not. Locktime unsatisfied.
	tx := makeFinalTestTx(9999, 0xFFFFFFFF, 0xFFFFFFFE)
	if IsFinalTx(tx, 100, 0) {
		t.Fatal("one non-FINAL input: SEQUENCE_FINAL bypass must not apply → not final")
	}
}

// TestIsFinalTx_F7_AllMustBeFinal_ThreeInputs confirms all inputs need FINAL.
func TestIsFinalTx_F7_AllMustBeFinal_ThreeInputs(t *testing.T) {
	// 3 inputs: 2 FINAL, 1 not.
	tx := makeFinalTestTx(9999, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE)
	if IsFinalTx(tx, 100, 0) {
		t.Fatal("2/3 SEQUENCE_FINAL is not enough: must NOT be final")
	}
}

// ─── B1+B2: BIP-113 wiring in CheckBlockContext ──────────────────────────────

// TestBIP113_PreCSV_UsesBlockHeaderTimestamp verifies that before CSV activation,
// CheckBlockContext uses the block header timestamp as nLockTimeCutoff.
// Proof strategy: pass no MTP argument (CheckBlockContext variadic: 0 args =
// uses header timestamp). A tx that is non-final at the header timestamp must
// be rejected. Core: validation.cpp:4133-4146.
func TestBIP113_PreCSV_UsesBlockHeaderTimestamp(t *testing.T) {
	params := testMainnetParams()
	params.CSVHeight = 1000 // CSV not active at height 500

	// tx.LockTime = 500_000_000 (timestamp).
	// Block header timestamp = 500_000_000.
	// Pre-CSV: compare tx.LockTime to header time → 500_000_000 < 500_000_000 → false
	// → not final by locktime. Sequence is not FINAL → tx is non-final → reject.
	txNonFinal := makeFinalTestTx(500_000_000, 0xFFFFFFFE)
	header := wire.BlockHeader{
		Version:   1,
		Timestamp: 500_000_000,
		Bits:      0x207fffff, // regtest-style easy target
	}
	block := &wire.MsgBlock{
		Header:       header,
		Transactions: []*wire.MsgTx{makeTestCoinbaseTx(500), txNonFinal},
	}
	prevHeader := wire.BlockHeader{Version: 1}

	// Call without MTP argument: height 500 < CSVHeight 1000 → header path.
	// (But even if we pass MTP=0, CSVHeight=1000 > height=500 so header path is still used.)
	err := CheckBlockContext(block, &prevHeader, 500, params)
	if err == nil {
		t.Fatal("pre-CSV: tx locked to header time must be non-final → CheckBlockContext must reject it")
	}
}

// TestBIP113_PostCSV_UsesMTP verifies that after CSV activation, CheckBlockContext
// uses the MTP as nLockTimeCutoff rather than the block header timestamp.
// Proof strategy: provide a tx that is non-final at the MTP but would be final
// at the block header timestamp. Post-CSV the node must use MTP and reject it.
// Core: validation.cpp:4133-4146 (enforce_locktime_median_time_past).
func TestBIP113_PostCSV_UsesMTP(t *testing.T) {
	params := testMainnetParams()
	params.CSVHeight = 100 // CSV active at height 500

	// tx.LockTime = 500_000_005 (timestamp).
	// MTP = 500_000_005 → 500_000_005 < 500_000_005 → false → non-final at MTP.
	// Header timestamp = 500_000_100 (> tx.LockTime → would be final at header time).
	// Post-CSV: uses MTP → tx is non-final → must be rejected.
	// CheckBlockTimestamp guard: header(500_000_100) > MTP(500_000_005) → passes.
	txNonFinalAtMTP := makeFinalTestTx(500_000_005, 0xFFFFFFFE)
	header := wire.BlockHeader{
		Version:   4,
		Timestamp: 500_000_100,
		Bits:      0x207fffff,
	}
	block := &wire.MsgBlock{
		Header:       header,
		Transactions: []*wire.MsgTx{makeTestCoinbaseTx(500), txNonFinalAtMTP},
	}
	prevHeader := wire.BlockHeader{Version: 4}

	// Pass MTP = 500_000_005: post-CSV blockTime = MTP → locktime check uses MTP.
	err := CheckBlockContext(block, &prevHeader, 500, params, 500_000_005)
	if err == nil {
		t.Fatal("post-CSV: tx non-final at MTP must be rejected even if it would pass at header time")
	}
}

// TestBIP113_PostCSV_FinalAtMTP verifies that a tx final at the MTP is accepted
// post-CSV.
func TestBIP113_PostCSV_FinalAtMTP(t *testing.T) {
	params := testMainnetParams()
	params.CSVHeight = 100 // CSV active at height 500

	// tx.LockTime = 500_000_000 → final when MTP > 500_000_000.
	txFinal := makeFinalTestTx(500_000_000, 0xFFFFFFFE)
	header := wire.BlockHeader{
		Version:   4,
		Timestamp: 500_000_100,
		Bits:      0x207fffff,
	}
	block := &wire.MsgBlock{
		Header:       header,
		Transactions: []*wire.MsgTx{makeTestCoinbaseTx(500), txFinal},
	}
	prevHeader := wire.BlockHeader{Version: 4}

	// MTP = 500_000_001 (> locktime=500_000_000) → tx is final at MTP.
	err := CheckBlockContext(block, &prevHeader, 500, params, 500_000_001)
	if err != nil {
		t.Fatalf("post-CSV: tx final at MTP (MTP=500_000_001 > locktime=500_000_000) must be accepted, got: %v", err)
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// makeTestCoinbaseTx creates a minimal coinbase transaction for use in test blocks.
// It uses a trivial scriptSig that satisfies BIP-34 at any height below BIP34Height.
func makeTestCoinbaseTx(height int32) *wire.MsgTx {
	// For heights before BIP34 activation we just need any scriptSig.
	// At height < BIP34Height the BIP-34 check is skipped.
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.Hash256{},
				Index: 0xFFFFFFFF,
			},
			SignatureScript: []byte{0x03, 0x01, 0x00, 0x00}, // pushdata3 height=1 (placeholder)
			Sequence:        0xFFFFFFFF,
		}},
		TxOut: []*wire.TxOut{{
			Value:    5_000_000_000,
			PkScript: []byte{0x51},
		}},
		LockTime: 0,
	}
}
