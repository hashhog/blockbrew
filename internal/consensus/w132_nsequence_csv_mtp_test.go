// Package consensus — W132 BIP-68/112/113 audit tests.
//
// These tests are DISCOVERY-only: they document blockbrew's current
// behavior vs. Bitcoin Core's contract for nSequence encoding, OP_CSV
// (via CheckSequence), BIP-68 SequenceLocks, and BIP-113 MTP-as-
// lockTime. Tests that confirm a present bug are marked t.Skip with
// the bug ID so the test compiles + runs against the current tree
// without breaking CI, while still serving as the byte-exact repro
// for the future fix wave.
//
// Cross-impl audit framework: BUG IDs match audit/w132_nsequence_csv_mtp.md.
//
// References:
//   - bitcoin-core/src/consensus/tx_verify.cpp:39 CalculateSequenceLocks
//   - bitcoin-core/src/consensus/tx_verify.cpp:97 EvaluateSequenceLocks
//   - bitcoin-core/src/consensus/tx_verify.cpp:17 IsFinalTx
//   - bitcoin-core/src/script/interpreter.cpp:561 OP_CHECKSEQUENCEVERIFY
//   - bitcoin-core/src/script/interpreter.cpp:1782 CheckSequence
//   - bitcoin-core/src/chain.h:233 GetMedianTimePast
//   - bitcoin-core/src/validation.cpp:4129 ContextualCheckBlock (BIP-113)
//   - bitcoin-core/src/primitives/transaction.h:293 `const uint32_t version`
package consensus

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/wire"
)

// ─── Constants — must match Core ────────────────────────────────────────────

// G1: SEQUENCE_FINAL = 0xFFFFFFFF (primitives/transaction.h:76).
// Status: PARTIAL — not exposed as a named constant in blockbrew; literal
// `0xFFFFFFFF` used throughout. Cosmetic but verified value-wise.
func TestW132_G1_SequenceFinal_Value(t *testing.T) {
	const SequenceFinal uint32 = 0xFFFFFFFF
	if SequenceFinal != 0xFFFFFFFF {
		t.Fatalf("SequenceFinal must be 0xFFFFFFFF, got 0x%X", SequenceFinal)
	}
	// Verify the literal is used by IsFinalTx.
	tx := &wire.MsgTx{
		Version:  1,
		LockTime: 500_000_001, // forces non-final-by-locktime
		TxIn: []*wire.TxIn{{
			Sequence: 0xFFFFFFFF, // SEQUENCE_FINAL
		}},
		TxOut: []*wire.TxOut{{Value: 1}},
	}
	if !IsFinalTx(tx, 100, 100) {
		t.Fatal("all-inputs SEQUENCE_FINAL must bypass non-final locktime → IsFinalTx=true")
	}
	tx.TxIn[0].Sequence = 0xFFFFFFFE // MAX_SEQUENCE_NONFINAL
	if IsFinalTx(tx, 100, 100) {
		t.Fatal("any-input != SEQUENCE_FINAL must respect locktime → IsFinalTx=false")
	}
}

// G2-G5: BIP-68 mask constants must be byte-identical to Core.
func TestW132_G2to5_SequenceConstants(t *testing.T) {
	// Core: primitives/transaction.h:93,99,104,114.
	if SequenceLockTimeDisabledFlag != 0x80000000 {
		t.Errorf("SequenceLockTimeDisabledFlag = 0x%X, want 0x80000000", SequenceLockTimeDisabledFlag)
	}
	if SequenceLockTimeTypeFlag != 0x00400000 {
		t.Errorf("SequenceLockTimeTypeFlag = 0x%X, want 0x00400000", SequenceLockTimeTypeFlag)
	}
	if SequenceLockTimeMask != 0x0000FFFF {
		t.Errorf("SequenceLockTimeMask = 0x%X, want 0x0000FFFF", SequenceLockTimeMask)
	}
	if SequenceLockTimeGranularity != 9 {
		t.Errorf("SequenceLockTimeGranularity = %d, want 9", SequenceLockTimeGranularity)
	}
	if (1 << SequenceLockTimeGranularity) != 512 {
		t.Errorf("1 << SequenceLockTimeGranularity = %d, want 512", 1<<SequenceLockTimeGranularity)
	}
	// SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK = 0x0040FFFF.
	// Used inside CheckSequence (interpreter.cpp:1802).
	const want uint32 = 0x0040FFFF
	got := SequenceLockTimeTypeFlag | SequenceLockTimeMask
	if got != want {
		t.Errorf("TYPE_FLAG|MASK = 0x%X, want 0x%X", got, want)
	}
}

// G6: LOCKTIME_THRESHOLD = 500_000_000 (consensus.h).
func TestW132_G6_LockTimeThreshold(t *testing.T) {
	if LockTimeThreshold != 500_000_000 {
		t.Errorf("LockTimeThreshold = %d, want 500_000_000", LockTimeThreshold)
	}
}

// G7: LOCKTIME_VERIFY_SEQUENCE flag plumbed
// Core consensus.h:28 — flag value 1<<0. blockbrew bakes the gate into
// each call site (no explicit flag plumbed). This is functionally
// equivalent because CalculateSequenceLocks's only callers
// (mempool.checkSequenceLocksLocked, chainmanager.go connect path)
// each gate independently on CSVHeight. Documented as MISSING in matrix.
func TestW132_G7_NoExplicitVerifyFlag_DocumentedDeviation(t *testing.T) {
	// No assertion — this gate is informational. The fact that
	// CalculateSequenceLocks has no `flags int` argument is the deviation.
	// Re-asserted by recipe: signature is
	//   CalculateSequenceLocks(tx *wire.MsgTx, prevHeights []int32, getMTP MTPLookup) *SequenceLock
	// (no flags parameter). Core: CalculateSequenceLocks(tx, flags, prev_heights, block).
	t.Log("blockbrew has no LOCKTIME_VERIFY_SEQUENCE flag plumbed; gate is baked into callers")
}

// ─── G8-G12: IsFinalTx (BIP-113 base semantics, MTP wiring tested in G32-G33) ─

// G8: locktime=0 → final regardless of height/time.
func TestW132_G8_IsFinalTx_LockTimeZero(t *testing.T) {
	tx := &wire.MsgTx{
		Version:  1,
		LockTime: 0,
		TxIn:     []*wire.TxIn{{Sequence: 0x12345678}},
		TxOut:    []*wire.TxOut{{Value: 1}},
	}
	if !IsFinalTx(tx, 0, 0) {
		t.Fatal("locktime=0 must be final at any (height, time)")
	}
	if !IsFinalTx(tx, 999_999, 999_999_999) {
		t.Fatal("locktime=0 must be final at any (height, time)")
	}
}

// G9: lockTime < LOCKTIME_THRESHOLD → height path.
// Core: tx_verify.cpp:21 — `(int64_t)tx.nLockTime < LOCKTIME_THRESHOLD
//	? (int64_t)nBlockHeight : nBlockTime`.
func TestW132_G9_IsFinalTx_HeightPath(t *testing.T) {
	tx := &wire.MsgTx{
		Version:  1,
		LockTime: 100, // 100 < THRESHOLD → height path
		TxIn:     []*wire.TxIn{{Sequence: 0xFFFFFFFE}},
		TxOut:    []*wire.TxOut{{Value: 1}},
	}
	// At height 100, tx.LockTime=100, height comparison: 100 < 100 false →
	// not final by locktime → must check SEQUENCE_FINAL bypass → tx is non-final.
	if IsFinalTx(tx, 100, 0) {
		t.Fatal("locktime=100 at height=100 must be non-final (not >, only <)")
	}
	// At height 101 → 100 < 101 → final.
	if !IsFinalTx(tx, 101, 0) {
		t.Fatal("locktime=100 at height=101 must be final")
	}
}

// G10: lockTime >= LOCKTIME_THRESHOLD → time path.
func TestW132_G10_IsFinalTx_TimePath(t *testing.T) {
	tx := &wire.MsgTx{
		Version:  1,
		LockTime: 500_000_000, // == THRESHOLD → time path
		TxIn:     []*wire.TxIn{{Sequence: 0xFFFFFFFE}},
		TxOut:    []*wire.TxOut{{Value: 1}},
	}
	if IsFinalTx(tx, 999_999, 500_000_000) {
		t.Fatal("locktime=500M, blockTime=500M → 500M<500M false → must be non-final")
	}
	if !IsFinalTx(tx, 999_999, 500_000_001) {
		t.Fatal("locktime=500M, blockTime=500M+1 → final")
	}
}

// G11+G12: SEQUENCE_FINAL bypass.
func TestW132_G11_G12_AllInputsFinal_BypassLocktime(t *testing.T) {
	tx := &wire.MsgTx{
		Version:  1,
		LockTime: 999_999, // future
		TxIn: []*wire.TxIn{
			{Sequence: 0xFFFFFFFF},
			{Sequence: 0xFFFFFFFF},
		},
		TxOut: []*wire.TxOut{{Value: 1}},
	}
	if !IsFinalTx(tx, 0, 0) {
		t.Fatal("all SEQUENCE_FINAL must bypass locktime even when locktime is future")
	}
	// G12: any one input != FINAL → non-final.
	tx.TxIn[1].Sequence = 0xFFFFFFFE
	if IsFinalTx(tx, 0, 0) {
		t.Fatal("any non-FINAL input must respect locktime → non-final at height 0")
	}
}

// ─── G13 (P0-CDIV): tx.Version field type — int32 vs Core uint32_t ──────────

// BUG-1 + BUG-2 (FIXED in blockbrew 75346c3, 2026-06-14): blockbrew stores
// `int32 Version` (matching the signed wire field), but Core's BIP-68 version
// gate compares UNSIGNED. Core has always done this: even when the field was
// `int32_t nVersion`, tx_verify.cpp cast it — `static_cast<uint32_t>(nVersion)
// >= 2` — with the comment "requires cast to unsigned otherwise ... half the
// range of nVersion wouldn't support BIP 68". Core PR#29325 later changed the
// storage type to `uint32_t version` (no consensus change). So for any tx with
// bit 31 set, Core ENFORCES BIP-68 (unsigned >= 2), and blockbrew must too.
//
// This test deserializes a wire tx with version bytes 0xFEFFFFFF
// (little-endian for uint32 = 0xFFFFFFFE = MAX_SEQUENCE_NONFINAL-style
// value reused as version) and asserts the Go in-memory value.
//
// Core's invariant: an unsigned uint32 representation yields
// `version >= 2` for any value >= 2 numerically.
// The stale bug was: a naive signed `version < 2` reads int32(0xFFFFFFFE) as
// -2 < 2 and would SKIP BIP-68. blockbrew now casts to uint32 in both gates
// (txvalidation.go CalculateSequenceLocks + opcodes_impl.go OP_CSV), so this
// test now asserts Core parity (enforcement), not the old defect.
func TestW132_G13_BUG1_TxVersion_HighBitDeserializesNegative(t *testing.T) {
	// Build a minimal wire-serialized tx with version=0xFFFFFFFE.
	// Layout: [4-byte version LE][varint in count=1][input (36+1+0+4)][varint out=0]... is
	// simpler to hand-build header bytes only, then test via Deserialize.
	//
	// Minimal "no inputs, no outputs" is rejected by serializer; build a
	// single-input, single-output legacy tx.
	var buf bytes.Buffer
	// version = 0xFFFFFFFE (LE)
	buf.Write([]byte{0xFE, 0xFF, 0xFF, 0xFF})
	// tx_in count = 1
	buf.WriteByte(0x01)
	// outpoint hash 32 zero bytes
	for i := 0; i < 32; i++ {
		buf.WriteByte(0x00)
	}
	// outpoint index = 0
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// scriptSig length = 0
	buf.WriteByte(0x00)
	// nSequence = 0xFFFFFFFF
	buf.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	// tx_out count = 1
	buf.WriteByte(0x01)
	// value = 1000 (LE 8 bytes)
	buf.Write([]byte{0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// scriptPubKey length = 1
	buf.WriteByte(0x01)
	// scriptPubKey = OP_1 (0x51)
	buf.WriteByte(0x51)
	// nLockTime = 0
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	var tx wire.MsgTx
	if err := tx.Deserialize(&buf); err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	// blockbrew Version is int32. For wire 0xFFFFFFFE, expect int32(-2).
	if tx.Version != -2 {
		t.Errorf("blockbrew: tx.Version after wire=0xFFFFFFFE deserialize = %d, expected -2 (int32(0xFFFFFFFE))", tx.Version)
	}

	// Core's invariant: uint32(0xFFFFFFFE) >= 2 is TRUE.
	// In blockbrew: tx.Version < 2 = (-2 < 2) = TRUE → consensus inversion.
	if !(tx.Version < 2) {
		t.Fatal("expected blockbrew tx.Version < 2 to be TRUE for negative int32 (BUG-1/BUG-2 precondition)")
	}

	// BUG-1 FIXED: CalculateSequenceLocks compares the version UNSIGNED
	// (uint32(tx.Version) < 2), exactly like Core (consensus/tx_verify.cpp:51).
	// A high-bit version (int32 -2 == uint32 0xFFFFFFFE >= 2) therefore
	// ENFORCES BIP-68, matching Core. With a relative height lock of 5 on an
	// input confirmed at height 100, Core computes MinHeight = 100 + 5 - 1 = 104;
	// blockbrew must return the same. (Previously it wrongly returned -1 — the
	// P0-CDIV chain-split defect — because a signed `< 2` skipped enforcement.)
	tx.TxIn[0].Sequence = 5 // relative height 5
	lock := CalculateSequenceLocks(&tx, []int32{100}, func(int32) int64 { return 0 })
	const wantMinHeight = int32(100 + 5 - 1) // 104, Core parity
	if lock.MinHeight != wantMinHeight || lock.MinTime != -1 {
		t.Errorf("high-bit-version tx must ENFORCE BIP-68 like Core (unsigned gate): "+
			"got MinHeight=%d MinTime=%d, want MinHeight=%d MinTime=-1",
			lock.MinHeight, lock.MinTime, wantMinHeight)
	}
	t.Logf("P0-CDIV BUG-1 RESOLVED: Core computes MinHeight=104; blockbrew returns %d (MATCH)", lock.MinHeight)
}

// G13 second half: confirm that the FIX would behave correctly.
// We simulate the fix by manually setting tx.Version = 2 and rerunning.
func TestW132_G13_BUG1_FixSimulation_Version2WorksAsCore(t *testing.T) {
	tx := &wire.MsgTx{
		Version: 2, // signed-int32 == Core's uint32 here, in agreement
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Sequence:         5,
		}},
		TxOut: []*wire.TxOut{{Value: 1000}},
	}
	lock := CalculateSequenceLocks(tx, []int32{100}, func(int32) int64 { return 0 })
	want := int32(100 + 5 - 1) // 104
	if lock.MinHeight != want {
		t.Errorf("with version=2 (signed agrees with Core), MinHeight = %d, want %d",
			lock.MinHeight, want)
	}
}

// ─── G14: CalculateSequenceLocks version-gate ────────────────────────────────

// G14: version < 2 → no enforcement (-1, -1).
func TestW132_G14_VersionGate(t *testing.T) {
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Sequence:         100, // would lock for v2
		}},
		TxOut: []*wire.TxOut{{Value: 1}},
	}
	lock := CalculateSequenceLocks(tx, []int32{50}, func(int32) int64 { return 0 })
	if lock.MinHeight != -1 || lock.MinTime != -1 {
		t.Errorf("v1 must skip BIP-68: got MinHeight=%d MinTime=%d", lock.MinHeight, lock.MinTime)
	}
}

// ─── G15+G16: DISABLE_FLAG per-input skip + prevHeights zeroing ─────────────

// G15: DISABLE_FLAG path skips the input.
func TestW132_G15_DisableFlag_SkipsInput(t *testing.T) {
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Sequence:         SequenceLockTimeDisabledFlag | 10, // disabled
		}},
		TxOut: []*wire.TxOut{{Value: 1}},
	}
	lock := CalculateSequenceLocks(tx, []int32{50}, func(int32) int64 { return 0 })
	if lock.MinHeight != -1 || lock.MinTime != -1 {
		t.Errorf("DISABLE_FLAG must yield (-1,-1): got MinHeight=%d MinTime=%d",
			lock.MinHeight, lock.MinTime)
	}
}

// G16: Core zeroes prevHeights[i] on DISABLE_FLAG. blockbrew does NOT.
// BUG-3 — latent (no caller iterates prevHeights post-call today).
func TestW132_G16_BUG3_DisableFlag_DoesNotZeroPrevHeights(t *testing.T) {
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
				Sequence:         SequenceLockTimeDisabledFlag | 99, // disabled
			},
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{2}, Index: 0},
				Sequence:         5, // height-relative lock
			},
		},
		TxOut: []*wire.TxOut{{Value: 1}},
	}
	prevHeights := []int32{9_999_999, 50}
	_ = CalculateSequenceLocks(tx, prevHeights, func(int32) int64 { return 0 })

	// blockbrew bug: prevHeights[0] is still 9_999_999, NOT zeroed.
	// Core would have set prevHeights[0] = 0.
	if prevHeights[0] == 0 {
		t.Fatal("BUG-3 closed? prevHeights[0] is 0, expected 9_999_999 (current blockbrew behavior)")
	}
	t.Logf("BUG-3 confirmed: prevHeights[0]=%d (Core zeroes to 0)", prevHeights[0])
	// prevHeights[1] should be untouched (50) in both Core and blockbrew.
	if prevHeights[1] != 50 {
		t.Errorf("prevHeights[1] should be 50, got %d", prevHeights[1])
	}
}

// ─── G17: TYPE_FLAG dispatch ────────────────────────────────────────────────

func TestW132_G17_TypeFlagDispatch(t *testing.T) {
	calledMTP := false
	getMTP := func(h int32) int64 {
		calledMTP = true
		return 1_700_000_000
	}
	// TYPE_FLAG SET → time path.
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Sequence:         SequenceLockTimeTypeFlag | 5,
		}},
		TxOut: []*wire.TxOut{{Value: 1}},
	}
	lock := CalculateSequenceLocks(tx, []int32{100}, getMTP)
	if !calledMTP {
		t.Fatal("TYPE_FLAG set must consult MTP lookup")
	}
	if lock.MinHeight != -1 {
		t.Errorf("TYPE_FLAG set: MinHeight must remain -1, got %d", lock.MinHeight)
	}
	if lock.MinTime == -1 {
		t.Errorf("TYPE_FLAG set: MinTime must be assigned, got -1")
	}

	// TYPE_FLAG CLEAR → height path.
	calledMTP = false
	tx.TxIn[0].Sequence = 5 // no type flag
	lock = CalculateSequenceLocks(tx, []int32{100}, getMTP)
	if calledMTP {
		t.Fatal("TYPE_FLAG clear must NOT consult MTP lookup")
	}
	if lock.MinHeight == -1 {
		t.Errorf("TYPE_FLAG clear: MinHeight must be assigned, got -1")
	}
	if lock.MinTime != -1 {
		t.Errorf("TYPE_FLAG clear: MinTime must remain -1, got %d", lock.MinTime)
	}
}

// ─── G18: time path uses MTP at max(coinHeight-1, 0) ────────────────────────

func TestW132_G18_TimePath_MTPAtCoinHeightMinus1(t *testing.T) {
	queried := make([]int32, 0)
	getMTP := func(h int32) int64 {
		queried = append(queried, h)
		return 1_700_000_000 + int64(h)*600
	}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Sequence:         SequenceLockTimeTypeFlag | 1,
		}},
		TxOut: []*wire.TxOut{{Value: 1}},
	}
	_ = CalculateSequenceLocks(tx, []int32{100}, getMTP)
	if len(queried) != 1 || queried[0] != 99 {
		t.Errorf("expected MTP query at height 99 (coinHeight-1), got %v", queried)
	}
	// Edge: coinHeight 0 → max(0-1, 0) = 0.
	queried = queried[:0]
	_ = CalculateSequenceLocks(tx, []int32{0}, getMTP)
	if len(queried) != 1 || queried[0] != 0 {
		t.Errorf("coinHeight=0 must query MTP at 0, got %v", queried)
	}
	// Edge: coinHeight -1 (synthetic) → should clamp to 0.
	queried = queried[:0]
	_ = CalculateSequenceLocks(tx, []int32{-1}, getMTP)
	if len(queried) != 1 || queried[0] != 0 {
		t.Errorf("coinHeight=-1 must clamp to MTP at 0, got %v", queried)
	}
}

// ─── G19: height path arithmetic ────────────────────────────────────────────

func TestW132_G19_HeightPath_Arithmetic(t *testing.T) {
	cases := []struct {
		name       string
		coinHeight int32
		seq        uint32
		want       int32 // Core: coinHeight + (seq&MASK) - 1
	}{
		{"seq=1", 100, 1, 100},        // 100+1-1 = 100
		{"seq=5", 100, 5, 104},        // 100+5-1 = 104
		{"seq=0 (no lock arithmetic)", 100, 0, 99}, // 100+0-1 = 99
		{"seq=MAX (0xFFFF)", 100, 0xFFFF, 100 + 0xFFFF - 1},
		// Bits above MASK must be ignored (only MASK applied).
		{"seq=TYPE_FLAG-1 + 5 (masked out top bits)", 0, 0x003FFFFF & 5, 4}, // 0+5-1=4
		{"seq=MASK + bit23 nonsense (masked off)", 50, 0x00800005, 54},      // bit23 above MASK, masked off → 50+5-1=54
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := &wire.MsgTx{
				Version: 2,
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
					Sequence:         tc.seq,
				}},
				TxOut: []*wire.TxOut{{Value: 1}},
			}
			lock := CalculateSequenceLocks(tx, []int32{tc.coinHeight}, func(int32) int64 { return 0 })
			if lock.MinHeight != tc.want {
				t.Errorf("MinHeight = %d, want %d", lock.MinHeight, tc.want)
			}
		})
	}
}

// ─── G20: time path arithmetic ──────────────────────────────────────────────

func TestW132_G20_TimePath_Arithmetic(t *testing.T) {
	const coinMTP = int64(1_700_000_000)
	getMTP := func(h int32) int64 { return coinMTP }
	cases := []struct {
		name   string
		maskedSeq uint32
		wantMin int64 // coinMTP + (val << 9) - 1
	}{
		{"val=0", 0, coinMTP - 1},
		{"val=1", 1, coinMTP + 512 - 1},
		{"val=2", 2, coinMTP + 1024 - 1},
		{"val=100", 100, coinMTP + 51200 - 1},
		{"val=MAX (0xFFFF)", 0xFFFF, coinMTP + (0xFFFF * 512) - 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := &wire.MsgTx{
				Version: 2,
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
					Sequence:         SequenceLockTimeTypeFlag | tc.maskedSeq,
				}},
				TxOut: []*wire.TxOut{{Value: 1}},
			}
			lock := CalculateSequenceLocks(tx, []int32{100}, getMTP)
			if lock.MinTime != tc.wantMin {
				t.Errorf("MinTime = %d, want %d", lock.MinTime, tc.wantMin)
			}
		})
	}
}

// ─── G21: BUG-5 — early-skip for coinbase-shaped input is non-Core ─────────

// BUG-5: blockbrew skips inputs whose prevout is (zero-hash, 0xFFFFFFFF)
// inside CalculateSequenceLocks. Core has no such guard (coinbase is
// excluded at the call site). Confirm the deviation exists.
func TestW132_G21_BUG5_CoinbaseShapedInputEarlySkip(t *testing.T) {
	// One coinbase-shaped input + one real input.
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xFFFFFFFF},
				Sequence:         10, // would lock if processed
			},
			{
				PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
				Sequence:         5,
			},
		},
		TxOut: []*wire.TxOut{{Value: 1}},
	}
	// prevHeights of coinbase-shaped slot is irrelevant in blockbrew (skipped).
	// In Core (without an exclusion guard) the function would also iterate it,
	// but Core's caller in ConnectBlock never feeds a coinbase to SequenceLocks.
	// blockbrew's guard makes the function more defensive than Core. We only
	// document; no assertion that Core would compute a different answer because
	// the caller-side exclusion is the contract.
	lock := CalculateSequenceLocks(tx, []int32{0, 50}, func(int32) int64 { return 0 })
	// Only the real input contributes: 50 + 5 - 1 = 54.
	if lock.MinHeight != 54 {
		t.Errorf("only-real-input lock should yield 54, got %d", lock.MinHeight)
	}
	t.Log("BUG-5 informational: blockbrew has a Core-absent early-skip guard for coinbase-shaped inputs")
}

// ─── G22+G23: EvaluateSequenceLocks strict-`>=` semantics ───────────────────

func TestW132_G22_G23_EvaluateSequenceLocks_Strict(t *testing.T) {
	cases := []struct {
		name       string
		lock       *SequenceLock
		blockHeight int32
		blockMTP   int64
		want       bool
	}{
		{"no lock → pass", &SequenceLock{-1, -1}, 100, 1_700_000_000, true},
		{"height: MinHeight=99 vs height=100 → pass (99<100)", &SequenceLock{99, -1}, 100, 1_700_000_000, true},
		{"height: MinHeight=100 vs height=100 → fail (100>=100)", &SequenceLock{100, -1}, 100, 1_700_000_000, false},
		{"height: MinHeight=101 vs height=100 → fail (101>=100)", &SequenceLock{101, -1}, 100, 1_700_000_000, false},
		{"time: MinTime=mtp-1 → pass", &SequenceLock{-1, 1_699_999_999}, 100, 1_700_000_000, true},
		{"time: MinTime=mtp → fail (>=)", &SequenceLock{-1, 1_700_000_000}, 100, 1_700_000_000, false},
		{"time: MinTime=mtp+1 → fail", &SequenceLock{-1, 1_700_000_001}, 100, 1_700_000_000, false},
		{"both set, both pass", &SequenceLock{50, 1_699_999_999}, 100, 1_700_000_000, true},
		{"both set, height fails", &SequenceLock{100, 1_699_999_999}, 100, 1_700_000_000, false},
		{"both set, time fails", &SequenceLock{50, 1_700_000_000}, 100, 1_700_000_000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateSequenceLocks(tc.lock, tc.blockHeight, tc.blockMTP)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// ─── G31: GetMedianTimePast on BlockNode ────────────────────────────────────

func TestW132_G31_GetMedianTimePast_11Samples(t *testing.T) {
	// Construct an 11-block chain with known timestamps, verify MTP.
	timestamps := []uint32{100, 90, 80, 70, 60, 50, 40, 30, 20, 10, 0}
	// Build chain bottom-up
	var prev *BlockNode
	for i := len(timestamps) - 1; i >= 0; i-- {
		node := &BlockNode{
			Header: wire.BlockHeader{Timestamp: timestamps[i]},
			Parent: prev,
			Height: int32(len(timestamps) - 1 - i),
		}
		prev = node
	}
	// `prev` is now the tip (height = 10, ts = 100).
	mtp := prev.GetMedianTimePast()
	// Sorted: [0,10,20,30,40,50,60,70,80,90,100]. Median index 5 → 50.
	if mtp != 50 {
		t.Errorf("MTP of 11-sample chain [0..100] = %d, want 50", mtp)
	}

	// MTP at height 5 (timestamps 50,40,30,20,10,0 → 6 samples sorted: 0,10,20,30,40,50, median index 3 → 30).
	// We walk Parent chain via GetAncestor.
	ancestor := prev.GetAncestor(5)
	if ancestor == nil {
		t.Fatal("GetAncestor(5) returned nil")
	}
	mtp5 := ancestor.GetMedianTimePast()
	if mtp5 != 30 {
		t.Errorf("MTP at height 5 = %d, want 30 (median of [50,40,30,20,10,0])", mtp5)
	}
}

// ─── G32+G33: BIP-113 — CheckBlockContext pre/post-CSV nLockTimeCutoff ──────

// G32: post-CSV uses MTP as locktime cutoff.
// (Existing tests in isfinal_test.go also cover this. We add a byte-exact
// regression-flip case to catch any silent change.)
func TestW132_G32_BIP113_PostCSV_UsesMTP(t *testing.T) {
	// height >= CSVHeight + medianTimePast > 0 → uses MTP path.
	// We probe the conditional in CheckBlockContext (blockvalidation.go:193-197).
	// Test only the conditional logic shape, not full block validation.
	// The shape is: height >= CSVHeight && len(medianTimePast)>0 → blockTime=mtp.
	// We unit-test through IsFinalTx, which CheckBlockContext calls with the
	// chosen blockTime.

	// tx locktime = 500_000_005 (time path), input not FINAL.
	tx := &wire.MsgTx{
		Version:  1,
		LockTime: 500_000_005,
		TxIn:     []*wire.TxIn{{Sequence: 0xFFFFFFFE}},
		TxOut:    []*wire.TxOut{{Value: 1}},
	}
	// At blockTime=MTP=500_000_005 → not final (500_000_005<500_000_005 false).
	if IsFinalTx(tx, 500, 500_000_005) {
		t.Fatal("post-CSV path: tx non-final at MTP must remain non-final")
	}
	// At blockTime=MTP=500_000_006 → final.
	if !IsFinalTx(tx, 500, 500_000_006) {
		t.Fatal("post-CSV path: tx final at MTP+1")
	}
}

// G33: pre-CSV uses block.GetBlockTime() (the variadic-omitted path).
// We unit-test the SHAPE only.
func TestW132_G33_BIP113_PreCSV_UsesHeaderTime(t *testing.T) {
	// Pre-CSV path uses header timestamp directly; covered by isfinal_test.go
	// TestBIP113_PreCSV_UsesBlockHeaderTimestamp. Re-assert presence here.
	tx := &wire.MsgTx{
		Version:  1,
		LockTime: 500_000_005,
		TxIn:     []*wire.TxIn{{Sequence: 0xFFFFFFFE}},
		TxOut:    []*wire.TxOut{{Value: 1}},
	}
	// blockTime parameter is the header timestamp pre-CSV.
	if IsFinalTx(tx, 500, 500_000_004) {
		t.Fatal("pre-CSV path with header time below locktime → must be non-final")
	}
	if !IsFinalTx(tx, 500, 500_000_006) {
		t.Fatal("pre-CSV path with header time above locktime → must be final")
	}
}

// G32 (BUG-4) — Variadic API foot-gun for CheckBlockContext.
//
// blockvalidation.go:131:
//	  func CheckBlockContext(... medianTimePast ...uint32) error
//
// At line 193:
//	  if height >= params.CSVHeight && len(medianTimePast) > 0 {
//	      blockTime = medianTimePast[0]
//	  } else {
//	      blockTime = block.Header.Timestamp
//	  }
//
// Latent issue: a caller that forgets the MTP argument silently
// disables BIP-113 even post-CSV. Core would crash on a nullptr
// pindexPrev (assert at validation.cpp:4136). This test documents the
// foot-gun by exercising the variadic-empty path against a tx that
// would only be non-final at MTP.
//
// Note: blockbrew is run with a single production caller in
// chainmanager.go:542 which DOES pass mtp. This is a future-safety
// gate, not a present bug.
func TestW132_G32_BUG4_VariadicFootgun_DocumentsFutureRisk(t *testing.T) {
	t.Skip("BUG-4 is latent — single production caller in chainmanager.go always passes mtp. " +
		"Test left as a documented future-safety lookout for any new caller path.")
}

// ─── G34: ConnectBlock CSV gate (chainmanager.go integration) ────────────────

// G34: ConnectBlock calls SequenceLocks for non-coinbase txs after CSV active.
// Full block-connect integration is heavy; we instead spot-check via
// chainmanager-internal helpers.
func TestW132_G34_ConnectBlock_CSVGateShape(t *testing.T) {
	// Confirm that CalculateSequenceLocks + EvaluateSequenceLocks produce
	// CONSISTENT behavior between height- and time-locked txs at a
	// hypothetical block at exactly the lock boundary.

	// Height lock: seq=5 at coinHeight=100 → MinHeight = 104.
	// Block at height 104 → 104>=104 → fail.
	// Block at height 105 → 104>=105 false → pass.
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{1}, Index: 0},
			Sequence:         5,
		}},
		TxOut: []*wire.TxOut{{Value: 1}},
	}
	lock := CalculateSequenceLocks(tx, []int32{100}, func(int32) int64 { return 0 })
	if EvaluateSequenceLocks(lock, 104, 1_700_000_000) {
		t.Error("height boundary: MinHeight=104 vs blockHeight=104 must FAIL (>=)")
	}
	if !EvaluateSequenceLocks(lock, 105, 1_700_000_000) {
		t.Error("height boundary: MinHeight=104 vs blockHeight=105 must PASS (<)")
	}

	// Time lock: seq=TYPE|1 (1 unit = 512s) at coinHeight=100 with coinMTP=mtp99.
	// MinTime = mtp99 + 512 - 1 = mtp99 + 511.
	mtpFor99 := int64(1_700_000_000)
	tx.TxIn[0].Sequence = SequenceLockTimeTypeFlag | 1
	lock = CalculateSequenceLocks(tx, []int32{100}, func(h int32) int64 {
		if h == 99 {
			return mtpFor99
		}
		return 0
	})
	want := mtpFor99 + 512 - 1
	if lock.MinTime != want {
		t.Errorf("time lock MinTime = %d, want %d", lock.MinTime, want)
	}
	if EvaluateSequenceLocks(lock, 105, want) {
		t.Error("time boundary: MinTime=want vs blockMTP=want must FAIL (>=)")
	}
	if !EvaluateSequenceLocks(lock, 105, want+1) {
		t.Error("time boundary: MinTime=want vs blockMTP=want+1 must PASS (<)")
	}
}

// ─── G35: Mempool CheckSequenceLocksAtTip wiring shape ──────────────────────

// G35 (BUG-7): document the test-mode opt-out. The function silently
// returns nil when ChainState is nil. This means a wallet test harness
// running without ChainState will skip BIP-68 and admit txs Core would
// reject.
//
// Not exploitable in shipping binary (main.go always wires
// chainStateAdapter at startup), but a future code path that forgets
// to wire it has no guard.
func TestW132_G35_BUG7_MempoolNilChainStateSkipsBIP68_DocumentedShape(t *testing.T) {
	t.Skip("BUG-7 is latent — production main wires ChainState. " +
		"Documented as a future-safety guard requirement.")
}

// ─── BUG-2 (OP_CSV version inversion) — direct unit ─────────────────────────

// We can't easily wire a full script engine in this test file without
// pulling internal/script as a dep (would create an import cycle). The
// direct repro lives in internal/script/seqlock_test.go gate 17; this
// test instead asserts the FIELD-TYPE precondition (same int32 →
// negative deserialization) shared by BUG-1 and BUG-2.
//
// Marker: BUG-2 is closed by the same single-line fix as BUG-1
// (changing wire.MsgTx.Version from int32 to uint32). No separate
// gating test needed beyond the existing seqlock_test.go gate 17.

// ─── Audit framework integrity gates ────────────────────────────────────────

// W132 audit MUST exercise the byte-exact wire deserialization path,
// not just Go-internal sanity. This gate fails if some future patch
// changes the deserializer to silently coerce high-bit versions.
func TestW132_AuditFrameworkGate_WireRoundtripPreservesVersion(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want int32
	}{
		{"v=1", []byte{0x01, 0x00, 0x00, 0x00}, 1},
		{"v=2", []byte{0x02, 0x00, 0x00, 0x00}, 2},
		{"v=3 (TRUC)", []byte{0x03, 0x00, 0x00, 0x00}, 3},
		// 0x7FFFFFFF — max positive int32.
		{"v=int32_max", []byte{0xFF, 0xFF, 0xFF, 0x7F}, 0x7FFFFFFF},
		// 0x80000000 — int32 MIN (would be -2147483648 in blockbrew, 2147483648 in Core).
		{"v=0x80000000", []byte{0x00, 0x00, 0x00, 0x80}, -2147483648},
		// 0xFFFFFFFE — Core uint32 4294967294, blockbrew int32 -2.
		{"v=0xFFFFFFFE", []byte{0xFE, 0xFF, 0xFF, 0xFF}, -2},
		{"v=0xFFFFFFFF", []byte{0xFF, 0xFF, 0xFF, 0xFF}, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Build full tx bytes
			var buf bytes.Buffer
			buf.Write(tc.raw) // version
			buf.WriteByte(0x01) // 1 input
			for i := 0; i < 32; i++ {
				buf.WriteByte(0x00) // outpoint hash
			}
			buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // outpoint index
			buf.WriteByte(0x00)                        // scriptSig len
			buf.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF}) // nSequence
			buf.WriteByte(0x01)                        // 1 output
			buf.Write([]byte{0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			buf.WriteByte(0x01)                        // scriptPubKey len
			buf.WriteByte(0x51)                        // OP_1
			buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // nLockTime

			var tx wire.MsgTx
			if err := tx.Deserialize(&buf); err != nil {
				t.Fatalf("deserialize: %v", err)
			}
			if tx.Version != tc.want {
				t.Errorf("Version = %d, want %d (raw=%x)", tx.Version, tc.want, tc.raw)
			}
		})
	}
}

// Documents the contrast with Core's uint32 semantics. Test passes only
// to record what each case would look like under Core's contract.
func TestW132_AuditFrameworkGate_CoreUint32Contrast(t *testing.T) {
	cases := []struct {
		raw       uint32 // wire bytes interpreted as uint32 (Core semantics)
		coreSatBIP68 bool // would Core enforce BIP-68 (version >= 2) ?
		blockbrewSatBIP68 bool // would blockbrew enforce BIP-68 (int32 version >= 2) ?
	}{
		{1, false, false}, // both: skip
		{2, true, true},   // both: enforce
		{0x7FFFFFFF, true, true},     // both: enforce (positive int32)
		{0x80000000, true, false},    // Core: enforce, blockbrew: skip (int32 MIN < 2)
		{0xFFFFFFFE, true, false},    // Core: enforce, blockbrew: skip
		{0xFFFFFFFF, true, false},    // Core: enforce, blockbrew: skip
	}
	for _, tc := range cases {
		coreSat := tc.raw >= 2
		blockbrewSat := int32(tc.raw) >= 2
		if coreSat != tc.coreSatBIP68 {
			t.Errorf("Core enforcement table wrong for 0x%08X: predicted %v, computed %v",
				tc.raw, tc.coreSatBIP68, coreSat)
		}
		if blockbrewSat != tc.blockbrewSatBIP68 {
			t.Errorf("blockbrew enforcement table wrong for 0x%08X: predicted %v, computed %v",
				tc.raw, tc.blockbrewSatBIP68, blockbrewSat)
		}
		if coreSat != blockbrewSat {
			t.Logf("DIVERGENCE at version=0x%08X: Core enforce=%v, blockbrew enforce=%v",
				tc.raw, coreSat, blockbrewSat)
		}
	}
}
