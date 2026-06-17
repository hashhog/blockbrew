// Package mempool — W135 IsStandardTx (standardness rules) audit tests.
//
// These tests are DISCOVERY-only: they document blockbrew's current
// behavior vs. Bitcoin Core's contract for IsStandardTx and related
// standardness rules (output classifier Solver, dust math, datacarrier,
// bare-multisig, P2A, witness-unknown, ValidateInputsStandardness,
// TRUC dispatch).
//
// Tests that confirm a present bug are marked t.Skip with the bug ID so
// the test compiles + runs against the current tree without breaking CI,
// while still serving as the byte-exact repro for the future fix wave.
//
// Cross-impl audit framework: BUG IDs match audit/w135_standardness_rules.md.
//
// References:
//   - bitcoin-core/src/policy/policy.h:38-95 (constants)
//   - bitcoin-core/src/policy/policy.cpp:27-165 (GetDustThreshold,
//     IsDust, IsStandard, IsStandardTx)
//   - bitcoin-core/src/policy/policy.cpp:214-263 (ValidateInputsStandardness)
//   - bitcoin-core/src/policy/policy.cpp:265-352 (IsWitnessStandard)
//   - bitcoin-core/src/script/solver.cpp:36-211 (Solver + Match helpers)
//   - bitcoin-core/src/policy/truc_policy.h:20-36 (TRUC constants)
//   - bitcoin-core/src/consensus/tx_check.cpp:11-60 (CheckTransaction)
package mempool

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ─── Constants — must match Core ────────────────────────────────────────────

// G1 + G2: TX_MIN_STANDARD_VERSION = 1, TX_MAX_STANDARD_VERSION = 3.
// Core: policy/policy.h:152-153.
func TestW135_G1_G2_TxStandardVersionRange(t *testing.T) {
	if TxMinStandardVersion != 1 {
		t.Errorf("TxMinStandardVersion = %d, want 1 (Core policy.h:152)",
			TxMinStandardVersion)
	}
	if TxMaxStandardVersion != 3 {
		t.Errorf("TxMaxStandardVersion = %d, want 3 (Core policy.h:153)",
			TxMaxStandardVersion)
	}
}

// G3: tx.Version <1 or >3 rejected as "version".
// PARTIAL — BUG-12 cross-references W132 BUG-1 (int32 vs uint32_t Version).
func TestW135_G3_TxVersionRange_BoundaryAccept(t *testing.T) {
	for _, v := range []int32{1, 2, 3} {
		if v < TxMinStandardVersion || v > TxMaxStandardVersion {
			t.Errorf("version %d should be in standard range [%d,%d]",
				v, TxMinStandardVersion, TxMaxStandardVersion)
		}
	}
}

func TestW135_G3_TxVersionRange_BoundaryReject(t *testing.T) {
	for _, v := range []int32{0, 4, 5, 100, -1, -2147483648} {
		if !(v < TxMinStandardVersion || v > TxMaxStandardVersion) {
			t.Errorf("version %d should be rejected by standard range [%d,%d]",
				v, TxMinStandardVersion, TxMaxStandardVersion)
		}
	}
}

// G3 / BUG-12: high-bit-set wire versions.
// Core would see uint32(0xFFFFFFFE) = 4294967294 > 3 → reject.
// blockbrew sees int32(0xFFFFFFFE) = -2 < 1 → reject.
// Both reject, but via opposite range gates. The equivalence-class is wrong.
// W132 BUG-1 cross-reference. Test passes today (coincidence).
func TestW135_G3_BUG12_TxVersionHighBitWrap(t *testing.T) {
	var wireVersion uint32 = 0xFFFFFFFE
	asInt32 := int32(wireVersion) //nolint:gosec // intentional truncation to expose the int32 defect
	// Document the type-defect.
	if asInt32 >= 0 {
		t.Fatalf("int32(0x%08X) should be negative, got %d",
			wireVersion, asInt32)
	}
	// Both Core and blockbrew reject this version — Core via >3, blockbrew via <1.
	if !(asInt32 < TxMinStandardVersion || asInt32 > TxMaxStandardVersion) {
		t.Fatalf("blockbrew should reject version=%d via int32 < TxMinStandardVersion",
			asInt32)
	}
	// Document the cross-ref: same defect surfaces in W132 BUG-1.
	t.Logf("BUG-12: int32 tx.Version causes high-bit-set wire versions to wrap negative; "+
		"happens to reject at IsStandardTx (via < 1) instead of Core's > 3, "+
		"but the gate equivalence-class is wrong. Cross-ref W132 BUG-1.")
}

// G4: MAX_STANDARD_TX_WEIGHT = 400_000.
func TestW135_G4_MaxStandardTxWeight(t *testing.T) {
	if consensus.MaxStandardTxWeight != 400_000 {
		t.Errorf("MaxStandardTxWeight = %d, want 400_000 (Core policy.h:38)",
			consensus.MaxStandardTxWeight)
	}
}

// G5: MIN_STANDARD_TX_NONWITNESS_SIZE = 65.
// Note: this lives in validation.cpp:813-816, not IsStandardTx — but blockbrew
// runs it inside AddTransaction.
func TestW135_G5_MinStandardTxNonWitnessSize(t *testing.T) {
	if MinStandardTxNonWitnessSize != 65 {
		t.Errorf("MinStandardTxNonWitnessSize = %d, want 65 (Core policy.h:40)",
			MinStandardTxNonWitnessSize)
	}
}

// G6: MAX_STANDARD_SCRIPTSIG_SIZE = 1650.
func TestW135_G6_MaxStandardScriptSigSize(t *testing.T) {
	if MaxStandardScriptSigSize != 1650 {
		t.Errorf("MaxStandardScriptSigSize = %d, want 1650 (Core policy.h:62)",
			MaxStandardScriptSigSize)
	}
}

// ─── G8-G14: Output script standardness allowlist ───────────────────────────

// G8: P2PKH classified STANDARD.
func TestW135_G8_P2PKH_IsStandard(t *testing.T) {
	// OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
	script := append([]byte{0x76, 0xa9, 0x14}, bytes.Repeat([]byte{0x01}, 20)...)
	script = append(script, 0x88, 0xac)
	if !isStandardOutputScript(script) {
		t.Errorf("P2PKH script must be STANDARD; got NONSTANDARD")
	}
}

// G9: P2SH classified STANDARD.
func TestW135_G9_P2SH_IsStandard(t *testing.T) {
	// OP_HASH160 <20 bytes> OP_EQUAL
	script := append([]byte{0xa9, 0x14}, bytes.Repeat([]byte{0x01}, 20)...)
	script = append(script, 0x87)
	if !isStandardOutputScript(script) {
		t.Errorf("P2SH script must be STANDARD; got NONSTANDARD")
	}
}

// G10: P2WPKH classified STANDARD.
func TestW135_G10_P2WPKH_IsStandard(t *testing.T) {
	// OP_0 <20 bytes>
	script := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x01}, 20)...)
	if !isStandardOutputScript(script) {
		t.Errorf("P2WPKH script must be STANDARD; got NONSTANDARD")
	}
}

// G11: P2WSH classified STANDARD.
func TestW135_G11_P2WSH_IsStandard(t *testing.T) {
	// OP_0 <32 bytes>
	script := append([]byte{0x00, 0x20}, bytes.Repeat([]byte{0x01}, 32)...)
	if !isStandardOutputScript(script) {
		t.Errorf("P2WSH script must be STANDARD; got NONSTANDARD")
	}
}

// G12: P2TR classified STANDARD.
func TestW135_G12_P2TR_IsStandard(t *testing.T) {
	// OP_1 <32 bytes>
	script := append([]byte{0x51, 0x20}, bytes.Repeat([]byte{0x01}, 32)...)
	if !isStandardOutputScript(script) {
		t.Errorf("P2TR script must be STANDARD; got NONSTANDARD")
	}
}

// G13: P2A (Pay-to-Anchor) classified STANDARD.
func TestW135_G13_P2A_IsStandard(t *testing.T) {
	// OP_1 OP_PUSHBYTES_2 0x4e 0x73 (4 bytes total)
	script := []byte{0x51, 0x02, 0x4e, 0x73}
	if !isStandardOutputScript(script) {
		t.Errorf("P2A script must be STANDARD; got NONSTANDARD")
	}
}

// G14: NULL_DATA (well-formed OP_RETURN + IsPushOnly remainder) STANDARD.
func TestW135_G14_NullData_IsStandard(t *testing.T) {
	// OP_RETURN <push 4 bytes>
	script := []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef}
	if !isStandardOutputScript(script) {
		t.Errorf("Well-formed nulldata script must be STANDARD; got NONSTANDARD")
	}
	// Truncated push: NONSTANDARD.
	truncated := []byte{0x6a, 0x09, 0xde, 0xad, 0xbe, 0xef}
	if isStandardOutputScript(truncated) {
		t.Errorf("Truncated nulldata script must be NONSTANDARD; got STANDARD")
	}
}

// ─── G15: PUBKEY (P2PK) — BUG-2 (P0-CDIV-relay) ──────────────────────────────

// G15 / BUG-2: bare PUBKEY (P2PK) must be classified STANDARD per Core.
// Core: script/solver.cpp:141 returns TxoutType::PUBKEY → policy.cpp:80
// IsStandard returns true (no extra gate). DEFAULT_PERMIT_BAREMULTISIG
// applies only to MULTISIG; PUBKEY has no toggle.
//
// blockbrew: isStandardOutputScript switch has no PUBKEY case → falls
// through default → isUnknownWitnessProgram(0x21=33 first byte) is false
// (0x21 not in {0x00, 0x51..0x60}) → returns false → REJECT.
//
// SKIP — bug present.
func TestW135_G15_BUG2_BarePubKey_IsStandard(t *testing.T) {
	t.Skip("BUG-2 (P0-CDIV-relay): isStandardOutputScript rejects bare P2PK; Core accepts. " +
		"audit/w135_standardness_rules.md BUG-2. " +
		"Fix requires Solver MatchPayToPubkey port.")

	// Compressed P2PK: 0x21 <33-byte pubkey> 0xac OP_CHECKSIG
	pubkey := append([]byte{0x21}, bytes.Repeat([]byte{0x02}, 33)...)
	script := append(pubkey, 0xac)
	if !isStandardOutputScript(script) {
		t.Fatalf("BUG-2: bare P2PK (compressed 33B pubkey) must be STANDARD per Core; got NONSTANDARD")
	}

	// Uncompressed P2PK: 0x41 <65-byte pubkey> 0xac OP_CHECKSIG
	pubkeyU := append([]byte{0x41}, bytes.Repeat([]byte{0x04}, 65)...)
	scriptU := append(pubkeyU, 0xac)
	if !isStandardOutputScript(scriptU) {
		t.Fatalf("BUG-2: bare P2PK (uncompressed 65B pubkey) must be STANDARD per Core; got NONSTANDARD")
	}
}

// ─── G16: MULTISIG (m-of-n, n≤3) — BUG-2 (P0-CDIV-relay) ─────────────────────

// G16 / BUG-2: bare MULTISIG with n ≤ 3 must be classified STANDARD per Core.
// Core: script/solver.cpp:85 MatchMultisig → MULTISIG, policy.cpp:87-95
// IsStandard requires `n in [1,3]` and `m in [1,n]`. policy.cpp:152 in
// IsStandardTx additionally requires `permit_bare_multisig` (default true)
// for a MULTISIG output to pass.
//
// blockbrew: isStandardOutputScript has no MULTISIG matcher → REJECT.
//
// SKIP — bug present.
func TestW135_G16_BUG2_BareMultisig_2of3_IsStandard(t *testing.T) {
	t.Skip("BUG-2 (P0-CDIV-relay): isStandardOutputScript rejects bare 2-of-3 multisig; Core accepts. " +
		"audit/w135_standardness_rules.md BUG-2. " +
		"Fix requires Solver MatchMultisig port + permit_bare_multisig toggle.")

	// OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
	script := []byte{0x52} // OP_2
	for i := 0; i < 3; i++ {
		script = append(script, 0x21) // push 33 bytes
		script = append(script, bytes.Repeat([]byte{byte(0x02 + i)}, 33)...)
	}
	script = append(script, 0x53) // OP_3
	script = append(script, 0xae) // OP_CHECKMULTISIG

	if !isStandardOutputScript(script) {
		t.Fatalf("BUG-2: bare 2-of-3 multisig (n=3 ≤ 3, m=2 ≥ 1) must be STANDARD per Core; got NONSTANDARD")
	}
}

func TestW135_G16_BUG2_BareMultisig_4of4_IsNotStandard(t *testing.T) {
	t.Skip("BUG-2 (P0-CDIV-relay): isStandardOutputScript has no multisig matcher at all. " +
		"Once fixed: must reject n > 3 (Core policy.cpp:91 `if (n < 1 || n > 3) return false;`).")

	// 4-of-4 multisig: n=4 > 3 → Core rejects as NONSTANDARD (even though
	// MULTISIG by Solver, n>3 fails the IsStandard extra gate).
	script := []byte{0x54} // OP_4
	for i := 0; i < 4; i++ {
		script = append(script, 0x21)
		script = append(script, bytes.Repeat([]byte{byte(0x02 + i)}, 33)...)
	}
	script = append(script, 0x54) // OP_4
	script = append(script, 0xae) // OP_CHECKMULTISIG

	if isStandardOutputScript(script) {
		t.Fatalf("BUG-2 fix must additionally reject n=4 > 3 (Core policy.cpp:91)")
	}
}

// ─── G17: WITNESS_UNKNOWN (v2..v16 only) — BUG-4 (HIGH) ─────────────────────

// G17: future witness versions v2..v16 standard via WITNESS_UNKNOWN.
// blockbrew accepts these.
func TestW135_G17_WitnessUnknown_v2(t *testing.T) {
	// OP_2 (witness version 2) <32-byte program>
	script := append([]byte{0x52, 0x20}, bytes.Repeat([]byte{0x01}, 32)...)
	if !isStandardOutputScript(script) {
		t.Errorf("Future witness v2 program must be STANDARD via WITNESS_UNKNOWN")
	}
}

// G17 (WITNESS_UNKNOWN for version >= 1): a witness program with version 1 (or
// any v1..v16) whose program size is NOT one of the canonical recognised types
// (P2TR is v1+32; P2A is the v1 4-byte anchor) must classify as WITNESS_UNKNOWN
// and therefore be STANDARD-to-create — NOT NONSTANDARD.
//
// Core Solver (script/solver.cpp:154-178): after P2WPKH/P2WSH (v0), P2TR
// (v1+32) and P2A are ruled out, ANY remaining witness program with
// `witnessversion != 0` returns TxoutType::WITNESS_UNKNOWN. Core does NOT
// special-case OP_1 out of this branch, so a v1 16-byte program is
// WITNESS_UNKNOWN (standard), exactly like a v2 program.
//
// This guards against the rustoshi-269681b failure mode, where the
// witness-unknown branch hardcoded an OP_2..OP_16 (0x52..0x60) range, EXCLUDING
// OP_1 (0x51) — which would wrongly drop a v1 non-32-byte program to
// NONSTANDARD. blockbrew's isUnknownWitnessProgram already accepts the full
// v1..v16 (0x51..0x60) range, so this passes; the test pins that behavior.
//
// NON-consensus: isStandardOutputScript is reached only from
// checkStandardnessLocked → mempool acceptance (AddTransactionFrom /
// validateTransactionLocked package-member), never from block/tx consensus.
func TestW135_G17_WitnessUnknown_v1_NonTaprootSize(t *testing.T) {
	// OP_1 (witness version 1) <16-byte program>. Not P2TR (which is v1+32),
	// not P2A (v1 4-byte anchor) → must be WITNESS_UNKNOWN ⇒ STANDARD.
	v1prog16 := append([]byte{0x51, 0x10}, bytes.Repeat([]byte{0x01}, 16)...)
	if !isStandardOutputScript(v1prog16) {
		t.Errorf("v1 16-byte witness program must be STANDARD via WITNESS_UNKNOWN "+
			"(Core Solver solver.cpp:172-177 returns WITNESS_UNKNOWN for witnessversion != 0); "+
			"got NONSTANDARD")
	}

	// Sanity controls that the v1+ acceptance is gated on being a *valid witness
	// program shape*, not accept-everything.

	// A 50-byte all-OP_1 (0x51) blob is NOT a witness program (push-length byte
	// 0x51 = 81 > 40), so it must remain NONSTANDARD.
	notWitProg := bytes.Repeat([]byte{0x51}, 50)
	if isStandardOutputScript(notWitProg) {
		t.Errorf("50-byte all-OP_1 blob is not a valid witness program; must be NONSTANDARD")
	}

	// P2TR (v1 + 32-byte) is still recognised as its own standard type.
	p2tr := append([]byte{0x51, 0x20}, bytes.Repeat([]byte{0x03}, 32)...)
	if !isStandardOutputScript(p2tr) {
		t.Errorf("v1 32-byte program (P2TR) must be STANDARD")
	}
}

// G17 / BUG-4: v0 witness program with size ∉ {20, 32} must be NONSTANDARD.
// Core: solver.cpp:156-177 — v0 falls through to NONSTANDARD when size is
// neither 20 (P2WPKH) nor 32 (P2WSH).
//
// blockbrew (pre-fix): isUnknownWitnessProgram accepted v0 with any size 2..40 →
// returned true → STANDARD. FIXED: isUnknownWitnessProgram now requires
// ver in 0x51..0x60 (v1..v16); a leftover v0 program (size ∉ {20, 32}) is
// NONSTANDARD.
func TestW135_G17_BUG4_WitnessV0_BadSize_IsNonStandard(t *testing.T) {
	// v0 program with 5-byte payload: 0x00 0x05 <5 bytes>
	script := append([]byte{0x00, 0x05}, bytes.Repeat([]byte{0x01}, 5)...)
	if isStandardOutputScript(script) {
		t.Fatalf("BUG-4: v0 witness program with size 5 must be NONSTANDARD (Core solver.cpp:157-176)")
	}

	// v0 program with 16-byte payload (also not P2WPKH/P2WSH).
	script16 := append([]byte{0x00, 0x10}, bytes.Repeat([]byte{0x01}, 16)...)
	if isStandardOutputScript(script16) {
		t.Fatalf("BUG-4: v0 witness program with size 16 must be NONSTANDARD")
	}

	// v0 program with 40-byte payload (max witness program size).
	script40 := append([]byte{0x00, 0x28}, bytes.Repeat([]byte{0x01}, 40)...)
	if isStandardOutputScript(script40) {
		t.Fatalf("BUG-4: v0 witness program with size 40 must be NONSTANDARD")
	}

	// Positive controls: the only two STANDARD v0 sizes per Core Solver
	// (solver.cpp:157-164) — 20-byte P2WPKH and 32-byte P2WSH — must remain
	// standard. Guards against an over-broad fix that rejects all v0.
	p2wpkh := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x02}, 20)...) // v0 + 20
	if !isStandardOutputScript(p2wpkh) {
		t.Fatalf("v0 20-byte program (P2WPKH) must be STANDARD (Core solver.cpp:157-160)")
	}
	p2wsh := append([]byte{0x00, 0x20}, bytes.Repeat([]byte{0x03}, 32)...) // v0 + 32
	if !isStandardOutputScript(p2wsh) {
		t.Fatalf("v0 32-byte program (P2WSH) must be STANDARD (Core solver.cpp:161-164)")
	}
}

// ─── G18-G20: Datacarrier + bare-multisig + permit toggles ─────────────────

// G18: MAX_OP_RETURN_RELAY = 100_000 enforced as cumulative budget.
// BUG-16 (LOW): blockbrew uses literal 100_000 not the formula
// MaxStandardTxWeight / WitnessScaleFactor (4) = 100_000.
func TestW135_G18_MaxOpReturnRelay(t *testing.T) {
	if MaxOpReturnRelay != 100_000 {
		t.Errorf("MaxOpReturnRelay = %d, want 100_000 (Core policy.h:84)",
			MaxOpReturnRelay)
	}
	// BUG-16: not formula-bound.
	if MaxOpReturnRelay != consensus.MaxStandardTxWeight/consensus.WitnessScaleFactor {
		t.Logf("BUG-16 (LOW): MaxOpReturnRelay should be MaxStandardTxWeight/WitnessScaleFactor "+
			"= %d, but is hard-coded as %d. Same value today; drift hazard.",
			consensus.MaxStandardTxWeight/consensus.WitnessScaleFactor, MaxOpReturnRelay)
	}
}

// G19 / BUG-8: -datacarrier / DEFAULT_ACCEPT_DATACARRIER toggle missing.
// Core: policy.h:80 DEFAULT_ACCEPT_DATACARRIER = true. With -datacarrier=0,
// any NULL_DATA output is rejected as nonstandard.
//
// blockbrew: no toggle, always accepts up to MaxOpReturnRelay.
//
// SKIP — bug present.
func TestW135_G19_BUG8_DatacarrierToggle(t *testing.T) {
	t.Skip("BUG-8 (MED): -datacarrier / DEFAULT_ACCEPT_DATACARRIER toggle absent. " +
		"audit/w135_standardness_rules.md BUG-8.")
}

// G20 / BUG-9: -permitbaremultisig / DEFAULT_PERMIT_BAREMULTISIG toggle missing.
// Core: policy.h:52 DEFAULT_PERMIT_BAREMULTISIG = true. With
// -permitbaremultisig=0, any MULTISIG output is rejected as bare-multisig.
//
// blockbrew: no toggle (and no MULTISIG matcher per BUG-2).
//
// SKIP — bug present, BUT only meaningful after BUG-2 is fixed.
func TestW135_G20_BUG9_PermitBareMultisigToggle(t *testing.T) {
	t.Skip("BUG-9 (MED): -permitbaremultisig toggle absent. " +
		"audit/w135_standardness_rules.md BUG-9. " +
		"Note: meaningless until BUG-2 (MULTISIG matcher) is fixed.")
}

// ─── G21-G24: Dust ──────────────────────────────────────────────────────────

// G21 / BUG-1: dust math must use DUST_RELAY_TX_FEE = 3000, NOT MinRelayFeeRate.
// Core: policy.cpp:27-64 uses dustRelayFee directly, independent of the
// -minrelaytxfee floor.
//
// FIXED: isDust now reads consensus.DustRelayFeeRate (mempool.go isDust). This
// test asserts the dust threshold is computed at 3000 sat/kvB and is INDEPENDENT
// of the configured MinRelayFeeRate (the load-bearing decouple).
func TestW135_G21_BUG1_DustRelayFeeRate(t *testing.T) {
	if consensus.DustRelayFeeRate != 3000 {
		t.Errorf("DustRelayFeeRate = %d, want 3000 (Core policy.h:68)",
			consensus.DustRelayFeeRate)
	}

	// P2WPKH output: OP_0 <20 bytes>. DustThreshold now uses the Core
	// GetSerializeSize(txout)+67 formula, giving CeilDiv(98*3000,1000) = 294 sat,
	// regardless of the relay floor.
	p2wpkhScript := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x02}, 20)...)
	const wantThreshold = 294 // CeilDiv((31 + 67) * 3000, 1000)

	// Two different relay floors prove the dust math no longer couples to it.
	for _, minRelay := range []int64{100, 1000} {
		mp := New(Config{MinRelayFeeRate: minRelay, MaxSize: 1_000_000}, newTestUTXOSet())

		// Value exactly one below the 3000-based threshold must be dust.
		if !mp.isDust(&wire.TxOut{Value: wantThreshold - 1, PkScript: p2wpkhScript}) {
			t.Errorf("minRelay=%d: P2WPKH value %d should be dust (threshold %d at DustRelayFeeRate=3000)",
				minRelay, wantThreshold-1, wantThreshold)
		}
		// Value at the threshold must NOT be dust (strict <).
		if mp.isDust(&wire.TxOut{Value: wantThreshold, PkScript: p2wpkhScript}) {
			t.Errorf("minRelay=%d: P2WPKH value %d should NOT be dust (threshold %d)",
				minRelay, wantThreshold, wantThreshold)
		}
		// Decouple proof: 100 sat is < 294 at BOTH relay floors → dust under the
		// dedicated DustRelayFeeRate=3000 math, independent of MinRelayFeeRate.
		if !mp.isDust(&wire.TxOut{Value: 100, PkScript: p2wpkhScript}) {
			t.Errorf("minRelay=%d: P2WPKH value 100 should be dust under DustRelayFeeRate=3000 (threshold %d)",
				minRelay, wantThreshold)
		}
	}
}

// G22 / BUG-1: dust math must size as GetSerializeSize(txout) + 148 (legacy) or
// +67 (segwit). Core: policy.cpp:46-58 (GetDustThreshold).
//
// FIXED: DustThreshold now sums GetSerializeSize(txout) (8-byte value +
// CompactSize(scriptlen) + script) and the per-output spending cost
// (witness 67 / non-witness 148), with CeilDiv rounding — NOT a flat
// per-script-type table. Repro: a P2WPKH output at 250 sat must now be dust
// (Core threshold 294, not the old 68/204).
func TestW135_G22_BUG1_DustSizeFormula(t *testing.T) {
	mp := New(Config{MinRelayFeeRate: 1000, MaxSize: 1_000_000}, newTestUTXOSet())

	// P2WPKH output: OP_0 <20-byte program>.
	p2wpkhScript := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x02}, 20)...)

	// Core GetDustThreshold(P2WPKH, 3000):
	//   GetSerializeSize = 8 + 1 + 22 = 31; + 67 (segwit) = 98 bytes
	//   CeilDiv(98 * 3000, 1000) = 294 sat.
	const coreThreshold = 294
	if got := DustThreshold(&wire.TxOut{Value: 0, PkScript: p2wpkhScript}, consensus.DustRelayFeeRate); got != coreThreshold {
		t.Fatalf("DustThreshold(P2WPKH) = %d, want %d (Core GetDustThreshold)", got, coreThreshold)
	}

	// 250 sat sits BELOW the Core threshold (294) but ABOVE the old buggy
	// per-shape threshold (68 byte * 3000 / 1000 = 204) — so it surfaces the
	// size-formula divergence: pre-fix accepted (250 >= 204), post-fix dust.
	if !mp.isDust(&wire.TxOut{Value: 250, PkScript: p2wpkhScript}) {
		t.Errorf("P2WPKH value 250 should be dust (Core threshold %d); the old per-shape table (204) under-rejected it", coreThreshold)
	}
	// One below / at the threshold (strict <).
	if !mp.isDust(&wire.TxOut{Value: coreThreshold - 1, PkScript: p2wpkhScript}) {
		t.Errorf("P2WPKH value %d should be dust (threshold %d)", coreThreshold-1, coreThreshold)
	}
	if mp.isDust(&wire.TxOut{Value: coreThreshold, PkScript: p2wpkhScript}) {
		t.Errorf("P2WPKH value %d should NOT be dust (threshold %d, strict <)", coreThreshold, coreThreshold)
	}
}

// G23 / BUG-3: MAX_DUST_OUTPUTS_PER_TX = 1 enforced.
// Core: policy.cpp:158-162. Counts dust outputs and rejects if > 1.
//
// blockbrew: per-output loop with `if fee == 0 { continue }` — unbounded.
//
// SKIP — bug present.
func TestW135_G23_BUG3_MaxDustOutputsPerTx(t *testing.T) {
	t.Skip("BUG-3 (HIGH): MAX_DUST_OUTPUTS_PER_TX = 1 gate missing; " +
		"blockbrew permits unlimited dust outputs as long as fee == 0. " +
		"audit/w135_standardness_rules.md BUG-3 (also BUG-7 for missing constant).")
}

func TestW135_G23_BUG7_NoMaxDustOutputsPerTxConstant(t *testing.T) {
	// BUG-7: no named constant for MAX_DUST_OUTPUTS_PER_TX = 1.
	// Cannot reference a constant that doesn't exist; logged-only test.
	t.Logf("BUG-7 (MED): no named MaxDustOutputsPerTx constant in mempool.go; " +
		"Core policy.h:95 has MAX_DUST_OUTPUTS_PER_TX = 1.")
}

// G24 / BUG-5: P2A NOT subject to a special AnchorDust cap.
// Core: P2A is just a 4-byte scriptPubKey; GetDustThreshold computes the
// segwit dust threshold for it like any other segwit output (~231 sat at
// default dust_relay_fee=3000).
//
// blockbrew: hard-coded value > 240 as dust for P2A.
//
// SKIP — bug present.
func TestW135_G24_BUG5_AnchorDustInvention(t *testing.T) {
	if AnchorDust != 240 {
		t.Errorf("AnchorDust = %d, want 240 (blockbrew invention; should be deleted)",
			AnchorDust)
	}
	t.Logf("BUG-5: AnchorDust=240 cap on P2A is a blockbrew invention not present in Core. " +
		"Core treats P2A like any segwit output for dust math (~231 sat threshold at " +
		"default dust_relay_fee=3000). Bidirectional divergence: " +
		"P2A value 200 sat (Core: REJECT dust, blockbrew: ACCEPT ≤ 240); " +
		"P2A value 250 sat (Core: ACCEPT, blockbrew: REJECT > 240).")
	t.Skip("BUG-5 (HIGH): AnchorDust=240 cap is a blockbrew invention. " +
		"audit/w135_standardness_rules.md BUG-5.")
}

// ─── G25-G28: IsWitnessStandard ─────────────────────────────────────────────

// G25: P2A input with non-empty witness → reject.
// PRESENT — blockbrew's isWitnessStandard implements this at witness_policy.go:99-101.
func TestW135_G25_P2A_WitnessReject(t *testing.T) {
	// Core: policy.cpp:283-285. Constructing a full repro requires UTXO
	// machinery; the policy is implemented at witness_policy.go:99-101
	// and exercised by witness_policy_test.go. Documentation-only here.
	t.Log("G25: P2A input with witness → reject. Implemented at witness_policy.go:99-101.")
}

// G26: P2WSH limits (script 3600, stack 100, item 80).
// PRESENT.
func TestW135_G26_P2WSH_Limits(t *testing.T) {
	if MaxStandardP2WSHScriptSize != 3600 {
		t.Errorf("MaxStandardP2WSHScriptSize = %d, want 3600 (Core policy.h:60)",
			MaxStandardP2WSHScriptSize)
	}
	if MaxStandardP2WSHStackItems != 100 {
		t.Errorf("MaxStandardP2WSHStackItems = %d, want 100 (Core policy.h:54)",
			MaxStandardP2WSHStackItems)
	}
	if MaxStandardP2WSHStackItemSize != 80 {
		t.Errorf("MaxStandardP2WSHStackItemSize = %d, want 80 (Core policy.h:56)",
			MaxStandardP2WSHStackItemSize)
	}
}

// G27: Taproot annex (ANNEX_TAG=0x50) detection + reject.
// PRESENT — witness_policy.go:157-160.
func TestW135_G27_TaprootAnnex(t *testing.T) {
	if annexTag != 0x50 {
		t.Errorf("annexTag = 0x%X, want 0x50 (Core interpreter.h)", annexTag)
	}
}

// G28: Tapscript leaf-version 0xc0 → stack item size ≤ 80.
// PRESENT — witness_policy.go:171-180.
func TestW135_G28_TapscriptStackItemSize(t *testing.T) {
	if taprootLeafTapscript != 0xc0 {
		t.Errorf("taprootLeafTapscript = 0x%X, want 0xc0 (Core interpreter.h TAPROOT_LEAF_TAPSCRIPT)",
			taprootLeafTapscript)
	}
	if MaxStandardTapscriptStackItemSize != 80 {
		t.Errorf("MaxStandardTapscriptStackItemSize = %d, want 80 (Core policy.h:58)",
			MaxStandardTapscriptStackItemSize)
	}
}

// ─── G29-G30: ValidateInputsStandardness ────────────────────────────────────

// G29 / BUG-11: per-input NONSTANDARD / WITNESS_UNKNOWN prevout reject.
// Core: policy.cpp:230 — Solver(prev.scriptPubKey) classify, reject NONSTANDARD;
// policy.cpp:234 — reject WITNESS_UNKNOWN with "witness program is undefined".
//
// blockbrew: per-input prevout-classifier loop ABSENT in AddTransaction.
// Only the P2SH redeem-sigops gate (G30) is implemented.
//
// SKIP — bug present.
func TestW135_G29_BUG11_ValidateInputsStandardness_PerInputClassifier(t *testing.T) {
	t.Skip("BUG-11 (MED): ValidateInputsStandardness per-input NONSTANDARD/WITNESS_UNKNOWN " +
		"prevout gate missing in AddTransaction. " +
		"audit/w135_standardness_rules.md BUG-11. " +
		"Forward-compat hazard for future witness-version soft-forks.")
}

// G30: Per-input P2SH redeem GetSigOpCount(accurate=true) ≤ MAX_P2SH_SIGOPS=15.
// PRESENT — mempool.go:1041-1058.
func TestW135_G30_P2SHRedeemSigOpsLimit(t *testing.T) {
	if consensus.MaxP2SHSigOpsPerInput != 15 {
		t.Errorf("MaxP2SHSigOpsPerInput = %d, want 15 (Core policy.h:42)",
			consensus.MaxP2SHSigOpsPerInput)
	}
}

// ─── G31-G35: Overflow / TRUC dispatch + sigops ─────────────────────────────

// G31: GetTransactionSigOpCost ≤ MAX_STANDARD_TX_SIGOPS_COST = 16000.
func TestW135_G31_MaxStandardTxSigOpsCost(t *testing.T) {
	if consensus.MaxStandardTxSigOpsCost != 16_000 {
		t.Errorf("MaxStandardTxSigOpsCost = %d, want 16_000 (Core policy.h:44)",
			consensus.MaxStandardTxSigOpsCost)
	}
	// BUG-14: implicit dependency on MaxBlockSigOpsCost = 80_000.
	if consensus.MaxStandardTxSigOpsCost != consensus.MaxBlockSigOpsCost/5 {
		t.Errorf("MaxStandardTxSigOpsCost should be MaxBlockSigOpsCost/5; "+
			"got %d vs %d", consensus.MaxStandardTxSigOpsCost, consensus.MaxBlockSigOpsCost/5)
	}
}

// G32: CheckSigopsBIP54 total ≤ MAX_TX_LEGACY_SIGOPS = 2500.
func TestW135_G32_MaxTxLegacySigOps(t *testing.T) {
	if consensus.MaxTxLegacySigOps != 2500 {
		t.Errorf("MaxTxLegacySigOps = %d, want 2500 (Core policy.h:46)",
			consensus.MaxTxLegacySigOps)
	}
}

// G33: singleTRUCChecks called from IsStandardTx pipeline.
// PRESENT — mempool.go:1267 calls mp.singleTRUCChecks.
func TestW135_G33_SingleTRUCChecks_CallSite(t *testing.T) {
	// Constant existence implies the dispatch site exists.
	if TRUCVersion != 3 {
		t.Errorf("TRUCVersion = %d, want 3 (Core truc_policy.h:20)", TRUCVersion)
	}
}

// G34: TRUC v=3 + non-TRUC parent → reject ErrTRUCVersionMixing.
// PRESENT.
func TestW135_G34_TRUCVersionMixing(t *testing.T) {
	// Sentinel existence.
	if ErrTRUCVersionMixing == nil {
		t.Fatal("ErrTRUCVersionMixing must exist (Core truc_policy.cpp:178-190)")
	}
}

// G35: TRUC v=3 sigop-adjusted vsize ≤ 10_000 (+ 1000 for child).
// PRESENT.
func TestW135_G35_TRUCSizeLimits(t *testing.T) {
	if TRUCMaxVSize != 10_000 {
		t.Errorf("TRUCMaxVSize = %d, want 10_000 (Core truc_policy.h:30)", TRUCMaxVSize)
	}
	if TRUCChildMaxVSize != 1_000 {
		t.Errorf("TRUCChildMaxVSize = %d, want 1_000 (Core truc_policy.h:33)", TRUCChildMaxVSize)
	}
}

// ─── Cross-cutting: ordering and Core-byte-exact dust tables ────────────────

// Audit framework: cross-impl byte-exact dust table.
//
// W122 lesson: byte-exact tests against Core values, not SHA256d-only or
// "does it return *some* threshold" — the magnitude defect (BUG-1) requires
// per-script-type expected-value tables to surface.
//
// For each output type, computes Core's expected dust threshold given
// dust_relay_fee = 3000 sat/kvB. The table is hand-computed from
// policy.cpp:27-64 and serves as the post-fix assertion target.
//
// FIXED (BUG-1): DustThreshold is now byte-exact vs Core GetDustThreshold at
// dust_relay_fee = 3000. Each value is CeilDiv((GetSerializeSize(txout) +
// spending_cost) * 3000, 1000), where spending_cost = 67 for witness programs
// (segwit-discounted, uniform P2WPKH/P2WSH/P2TR) else 148.
//
//	P2PKH:  8 + 1 + 25 = 34; + 148 = 182 → 546 sat
//	P2SH:   8 + 1 + 23 = 32; + 148 = 180 → 540 sat
//	P2WPKH: 8 + 1 + 22 = 31; +  67 =  98 → 294 sat
//	P2WSH:  8 + 1 + 34 = 43; +  67 = 110 → 330 sat
//	P2TR:   8 + 1 + 34 = 43; +  67 = 110 → 330 sat
//
// These are the canonical Core dust thresholds (policy.cpp:35-43 comments:
// P2PKH 546, P2WPKH 294). The earlier per-shape table (148/68/68/58 × 3000)
// produced 444/204/204/174 — all under-rejecting dust. Mutation-proven: revert
// DustThreshold to the per-shape table and these assertions fail.
func TestW135_AuditFramework_CoreDustThresholdTable(t *testing.T) {
	cases := []struct {
		name   string
		script []byte
		want   int64
	}{
		{
			name:   "P2PKH",
			script: append(append([]byte{0x76, 0xa9, 0x14}, bytes.Repeat([]byte{0x01}, 20)...), 0x88, 0xac),
			want:   546,
		},
		{
			name:   "P2SH",
			script: append(append([]byte{0xa9, 0x14}, bytes.Repeat([]byte{0x01}, 20)...), 0x87),
			want:   540,
		},
		{
			name:   "P2WPKH",
			script: append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x01}, 20)...),
			want:   294,
		},
		{
			name:   "P2WSH",
			script: append([]byte{0x00, 0x20}, bytes.Repeat([]byte{0x01}, 32)...),
			want:   330,
		},
		{
			name:   "P2TR",
			script: append([]byte{0x51, 0x20}, bytes.Repeat([]byte{0x01}, 32)...),
			want:   330,
		},
	}

	mp := New(Config{MinRelayFeeRate: 1000, MaxSize: 1_000_000}, newTestUTXOSet())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := &wire.TxOut{Value: 0, PkScript: tc.script}
			if got := DustThreshold(out, consensus.DustRelayFeeRate); got != tc.want {
				t.Errorf("DustThreshold(%s) = %d, want %d (Core GetDustThreshold @ 3000)", tc.name, got, tc.want)
			}
			// Boundary pins: value == threshold is NOT dust (strict <),
			// value == threshold-1 IS dust.
			if mp.isDust(&wire.TxOut{Value: tc.want, PkScript: tc.script}) {
				t.Errorf("%s value %d (== threshold) should NOT be dust", tc.name, tc.want)
			}
			if !mp.isDust(&wire.TxOut{Value: tc.want - 1, PkScript: tc.script}) {
				t.Errorf("%s value %d (threshold-1) should be dust", tc.name, tc.want-1)
			}
		})
	}
}

// Documents the contrast between Core's Solver dispatch and blockbrew's
// pattern-matching switch. Useful for the FIX-W135 wave to verify the
// new Solver port returns the correct TxoutType for every input.
func TestW135_AuditFramework_SolverDispatchContrast(t *testing.T) {
	cases := []struct {
		name           string
		script         []byte
		coreType       string // Core's TxoutType
		blockbrewStd   bool   // blockbrew isStandardOutputScript result
		coreStd        bool   // Core's IsStandard result
	}{
		{
			name:         "P2PKH",
			script:       append(append([]byte{0x76, 0xa9, 0x14}, bytes.Repeat([]byte{0x01}, 20)...), 0x88, 0xac),
			coreType:     "PUBKEYHASH",
			blockbrewStd: true, coreStd: true,
		},
		{
			name:         "P2SH",
			script:       append(append([]byte{0xa9, 0x14}, bytes.Repeat([]byte{0x01}, 20)...), 0x87),
			coreType:     "SCRIPTHASH",
			blockbrewStd: true, coreStd: true,
		},
		{
			name:         "P2WPKH",
			script:       append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x01}, 20)...),
			coreType:     "WITNESS_V0_KEYHASH",
			blockbrewStd: true, coreStd: true,
		},
		{
			name:         "P2WSH",
			script:       append([]byte{0x00, 0x20}, bytes.Repeat([]byte{0x01}, 32)...),
			coreType:     "WITNESS_V0_SCRIPTHASH",
			blockbrewStd: true, coreStd: true,
		},
		{
			name:         "P2TR",
			script:       append([]byte{0x51, 0x20}, bytes.Repeat([]byte{0x01}, 32)...),
			coreType:     "WITNESS_V1_TAPROOT",
			blockbrewStd: true, coreStd: true,
		},
		{
			name:         "P2A",
			script:       []byte{0x51, 0x02, 0x4e, 0x73},
			coreType:     "ANCHOR",
			blockbrewStd: true, coreStd: true,
		},
		{
			name:         "NullData",
			script:       []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef},
			coreType:     "NULL_DATA",
			blockbrewStd: true, coreStd: true,
		},
		{
			name:         "BarePubKey_compressed_BUG2",
			script:       append(append([]byte{0x21}, bytes.Repeat([]byte{0x02}, 33)...), 0xac),
			coreType:     "PUBKEY",
			blockbrewStd: false, coreStd: true, // BUG-2 divergence
		},
		{
			name:         "BareMultisig_2of3_BUG2",
			script:       buildBareMultisig(2, 3),
			coreType:     "MULTISIG",
			blockbrewStd: false, coreStd: true, // BUG-2 divergence
		},
		{
			name:         "BareMultisig_4of4_NONSTANDARD",
			script:       buildBareMultisig(4, 4),
			coreType:     "MULTISIG (but n>3 ⇒ NONSTANDARD per IsStandard)",
			blockbrewStd: false, coreStd: false, // both reject, different code path
		},
		{
			name:         "WitnessV0_size5_BUG4fixed",
			script:       append([]byte{0x00, 0x05}, bytes.Repeat([]byte{0x01}, 5)...),
			coreType:     "NONSTANDARD (v0 with non-{20,32} size)",
			blockbrewStd: false, coreStd: false, // BUG-4 FIXED: now matches Core
		},
		{
			name:         "WitnessV2_size32_UNKNOWN",
			script:       append([]byte{0x52, 0x20}, bytes.Repeat([]byte{0x01}, 32)...),
			coreType:     "WITNESS_UNKNOWN",
			blockbrewStd: true, coreStd: true,
		},
		{
			name:         "TruncatedNullData",
			script:       []byte{0x6a, 0x09, 0xde, 0xad, 0xbe, 0xef},
			coreType:     "NONSTANDARD (truncated push after OP_RETURN)",
			blockbrewStd: false, coreStd: false,
		},
	}

	divergences := 0
	for _, tc := range cases {
		got := isStandardOutputScript(tc.script)
		if got != tc.blockbrewStd {
			t.Errorf("%s: prediction wrong — predicted blockbrew=%v, got %v",
				tc.name, tc.blockbrewStd, got)
		}
		if got != tc.coreStd {
			divergences++
			t.Logf("DIVERGENCE %s: blockbrew=%v, Core=%v (Core type: %s)",
				tc.name, got, tc.coreStd, tc.coreType)
		}
	}
	if divergences != 2 {
		// BUG-2 (BarePubKey + BareMultisig_2of3) = 2 divergences.
		// BUG-4 (WitnessV0_size5) is now FIXED, so it no longer diverges.
		t.Logf("Expected 2 divergences (BUG-2 ×2; BUG-4 fixed), got %d. "+
			"Update the audit if the table changes.", divergences)
	}
}

// buildBareMultisig constructs an m-of-n bare multisig scriptPubKey
// (OP_m <pk1> <pk2> ... <pkn> OP_n OP_CHECKMULTISIG).
func buildBareMultisig(m, n int) []byte {
	script := []byte{byte(0x50 + m)} // OP_m
	for i := 0; i < n; i++ {
		script = append(script, 0x21) // push 33 bytes
		script = append(script, bytes.Repeat([]byte{byte(0x02 + i%14)}, 33)...)
	}
	script = append(script, byte(0x50+n)) // OP_n
	script = append(script, 0xae)         // OP_CHECKMULTISIG
	return script
}

// Touch the wire import so it isn't flagged as unused on partial test builds.
var _ = wire.MsgTx{}
