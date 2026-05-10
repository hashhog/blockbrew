package consensus

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// TestCountWitnessSigOpsForInputTaprootZero verifies that taproot (witness
// version 1) inputs contribute 0 sigops to the block-level
// MaxBlockSigOpsCost budget, mirroring Bitcoin Core's WitnessSigOps
// (interpreter.cpp:2123-2137).
//
// Per BIP-342, taproot enforces its own per-input validation-weight
// budget (VALIDATION_WEIGHT_PER_SIGOP_PASSED), separate from the block
// sigop budget. Counting tapscript CHECKSIG/CHECKSIGADD ops against the
// 80,000 block budget would reject blocks Core accepts (this is
// blockbrew P0-2 from CORE-PARITY-AUDIT/blockbrew-P0-FOUND.md).
func TestCountWitnessSigOpsForInputTaprootZero(t *testing.T) {
	// Build a tapscript with many CHECKSIG ops. CountTaprootSigOps would
	// return ~1000 for this; the BUDGET function must still return 0.
	bigTapscript := make([]byte, 1000)
	for i := range bigTapscript {
		bigTapscript[i] = script.OP_CHECKSIG
	}
	if got := CountTaprootSigOps(bigTapscript); got != 1000 {
		t.Fatalf("test setup invariant: expected CountTaprootSigOps=1000 for "+
			"1000-byte all-CHECKSIG tapscript, got %d", got)
	}

	// 32-byte witness program (taproot output)
	program := make([]byte, 32)
	for i := range program {
		program[i] = byte(i)
	}

	// Script-path spend: witness = [..., tapscript, controlBlock]
	// (controlBlock is the last item, tapscript is second-to-last.)
	controlBlock := make([]byte, 33) // 33-byte minimal control block
	witness := [][]byte{
		{0x01}, // dummy stack item
		bigTapscript,
		controlBlock,
	}

	t.Run("v1 script-path with 1000 tapscript CHECKSIGs returns 0", func(t *testing.T) {
		got := countWitnessSigOpsForInput(1, program, witness, 0)
		if got != 0 {
			t.Errorf("countWitnessSigOpsForInput(v1 script-path) = %d, want 0 "+
				"(Core's WitnessSigOps: future versions return 0)", got)
		}
	})

	t.Run("v1 key-path spend returns 0", func(t *testing.T) {
		// Key-path: single 64-byte (or 65-byte) signature on the stack.
		keyPathWitness := [][]byte{make([]byte, 64)}
		got := countWitnessSigOpsForInput(1, program, keyPathWitness, 0)
		if got != 0 {
			t.Errorf("countWitnessSigOpsForInput(v1 key-path) = %d, want 0", got)
		}
	})

	t.Run("v1 with annex returns 0", func(t *testing.T) {
		// Annex prefix is 0x50; per BIP-341 the annex is stripped before
		// taproot semantics. The block-budget contribution is still 0.
		withAnnex := append(witness, []byte{0x50, 0xab, 0xcd})
		got := countWitnessSigOpsForInput(1, program, withAnnex, 0)
		if got != 0 {
			t.Errorf("countWitnessSigOpsForInput(v1 with annex) = %d, want 0", got)
		}
	})

	t.Run("v0 P2WPKH still counts 1", func(t *testing.T) {
		// Regression: the v0 path must not be broken by the v1 fix.
		v0Program := make([]byte, 20)
		got := countWitnessSigOpsForInput(0, v0Program, [][]byte{{0x00}, {0x01}}, 0)
		if got != 1 {
			t.Errorf("countWitnessSigOpsForInput(v0 P2WPKH) = %d, want 1", got)
		}
	})

	t.Run("v0 P2WSH still counts script sigops", func(t *testing.T) {
		// Regression: P2WSH must still count CHECKSIG ops in the
		// witness script (last witness item).
		v0Program := make([]byte, 32)
		witnessScript := []byte{
			script.OP_CHECKSIG,
			script.OP_CHECKSIG,
			script.OP_CHECKSIG,
		}
		got := countWitnessSigOpsForInput(0, v0Program, [][]byte{witnessScript}, 0)
		if got != 3 {
			t.Errorf("countWitnessSigOpsForInput(v0 P2WSH 3xCHECKSIG) = %d, want 3", got)
		}
	})

	t.Run("future witness version 2 returns 0", func(t *testing.T) {
		// Core: "Future flags may be implemented here. return 0;"
		got := countWitnessSigOpsForInput(2, program, witness, 0)
		if got != 0 {
			t.Errorf("countWitnessSigOpsForInput(v2) = %d, want 0", got)
		}
	})
}

// TestCountBlockSigOpsCostTaprootBudget is the block-level regression for
// blockbrew P0-2: a block with 10 inputs × 10,000 tapscript CHECKSIGs each
// (100,000 raw tapscript ops, well above the 80,000 block budget) must
// have its CountBlockSigOpsCost stay below MaxBlockSigOpsCost. Tapscript
// ops contribute 0; only the legacy + segwit-v0 paths count.
func TestCountBlockSigOpsCostTaprootBudget(t *testing.T) {
	// Build a 10-input tx where each input spends a P2TR output via
	// script-path, with 10,000 CHECKSIGs in the tapscript.
	const numInputs = 10
	const checkSigsPerInput = 10_000

	tapscript := make([]byte, checkSigsPerInput)
	for i := range tapscript {
		tapscript[i] = script.OP_CHECKSIG
	}
	if got := CountTaprootSigOps(tapscript); got != checkSigsPerInput {
		t.Fatalf("setup invariant: tapscript should have %d CHECKSIGs, got %d",
			checkSigsPerInput, got)
	}

	controlBlock := make([]byte, 33)

	// Coinbase tx
	coinbaseTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
			SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 5000000000, PkScript: []byte{0x76, 0xa9}}},
	}

	// Build the spending tx with N taproot inputs.
	prevTxHash := wire.Hash256{0xab, 0xcd, 0xef}
	prevTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0xff}, Index: 0},
			SignatureScript:  []byte{0x00},
			Sequence:         0xffffffff,
		}},
	}
	// Build P2TR output script: OP_1 + 0x20 + 32-byte program
	tapProgram := make([]byte, 32)
	for i := range tapProgram {
		tapProgram[i] = byte(i + 1)
	}
	p2trScript := make([]byte, 0, 34)
	p2trScript = append(p2trScript, script.OP_1, 0x20)
	p2trScript = append(p2trScript, tapProgram...)

	// Generate enough outputs in prevTx to spend
	for i := 0; i < numInputs; i++ {
		prevTx.TxOut = append(prevTx.TxOut, &wire.TxOut{
			Value:    100_000,
			PkScript: p2trScript,
		})
	}

	// Build the spending tx
	spendingTx := &wire.MsgTx{
		Version:  2,
		TxIn:     make([]*wire.TxIn, numInputs),
		TxOut:    []*wire.TxOut{{Value: 50_000, PkScript: []byte{0x76, 0xa9}}},
		LockTime: 0,
	}
	for i := 0; i < numInputs; i++ {
		spendingTx.TxIn[i] = &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: prevTxHash, Index: uint32(i)},
			SignatureScript:  nil,
			Sequence:         0xffffffff,
			Witness: [][]byte{
				{0x01},        // dummy stack item
				tapscript,     // 10,000 CHECKSIGs
				controlBlock,  // taproot control block
			},
		}
	}

	// Build the UTXO view with the prevTx outputs
	utxoView := NewInMemoryUTXOView()
	for i := 0; i < numInputs; i++ {
		utxoView.AddUTXO(
			wire.OutPoint{Hash: prevTxHash, Index: uint32(i)},
			&UTXOEntry{
				Amount:   100_000,
				PkScript: p2trScript,
				Height:   1,
			},
		)
	}

	// Construct the block
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{},
		Transactions: []*wire.MsgTx{coinbaseTx, spendingTx},
	}

	// CountBlockSigOpsCost MUST treat tapscript ops as 0. The only
	// contributions in this block should be:
	//  - coinbase scriptSig sigops (none, just pushes)
	//  - coinbase pkScript sigops (none, dummy 0x76 0xa9)
	//  - spendingTx scriptSigs are nil (no sigops)
	//  - spendingTx pkScript sigops (none, dummy 0x76 0xa9)
	//  - P2SH sigops: prevout is P2TR, not P2SH → 0
	//  - witness sigops: v1 → 0 each (THE FIX)
	cost := CountBlockSigOpsCost(block, utxoView)

	if cost >= MaxBlockSigOpsCost {
		t.Fatalf("CountBlockSigOpsCost = %d, must be < MaxBlockSigOpsCost (%d). "+
			"Tapscript CHECKSIG ops are being incorrectly attributed to the "+
			"block sigop budget. Bitcoin Core's WitnessSigOps returns 0 for "+
			"witness version >= 1; tapscript uses its own per-input "+
			"VALIDATION_WEIGHT_PER_SIGOP_PASSED budget per BIP-342, not the "+
			"block-level MaxBlockSigOpsCost.", cost, MaxBlockSigOpsCost)
	}

	// Strong assertion: with this constructed block, cost must be exactly 0
	// (no legacy sigops, no P2SH sigops, taproot witness contributes 0).
	if cost != 0 {
		t.Errorf("CountBlockSigOpsCost = %d, want 0 (block has only "+
			"taproot witness sigops, which must NOT count toward the "+
			"block budget per Core's WitnessSigOps)", cost)
	}

	// Sanity: ValidateBlockWithOptions's sigop check should pass.
	// (We can't call ValidateBlock directly here because that needs a
	// full chain context — but the sigops check itself is what gates
	// the block, and the cost being below the budget is the invariant.)
	if cost > MaxBlockSigOpsCost {
		t.Errorf("Block would be rejected by sigops gate: %d > %d",
			cost, MaxBlockSigOpsCost)
	}
}

// TestCountTaprootSigOpsStandalonePreserved verifies that the
// CountTaprootSigOps helper (which is used outside the block-budget path,
// e.g. for mempool policy or future per-input budget enforcement) is
// preserved and still returns the actual count.
func TestCountTaprootSigOpsStandalonePreserved(t *testing.T) {
	// Single CHECKSIG
	if got := CountTaprootSigOps([]byte{script.OP_CHECKSIG}); got != 1 {
		t.Errorf("OP_CHECKSIG: got %d, want 1", got)
	}
	// CHECKSIGVERIFY
	if got := CountTaprootSigOps([]byte{script.OP_CHECKSIGVERIFY}); got != 1 {
		t.Errorf("OP_CHECKSIGVERIFY: got %d, want 1", got)
	}
	// CHECKSIGADD
	if got := CountTaprootSigOps([]byte{script.OP_CHECKSIGADD}); got != 1 {
		t.Errorf("OP_CHECKSIGADD: got %d, want 1", got)
	}
	// CHECKMULTISIG is NOT counted in tapscript (BIP-342 disables it)
	if got := CountTaprootSigOps([]byte{script.OP_CHECKMULTISIG}); got != 0 {
		t.Errorf("OP_CHECKMULTISIG in tapscript should not count: got %d, want 0", got)
	}
}

// --- W74: Comprehensive sigops-counting audit tests ---
//
// These tests cover all 12 gates from the W74 audit specification against
// Bitcoin Core's script.cpp:158-204, consensus/tx_verify.cpp:112-162, and
// interpreter.cpp:2123-2166.

// TestW74Gate1And2AccurateVsInaccurate verifies Gate 1 (fAccurate=false) and
// Gate 2 (fAccurate=true) for CHECKMULTISIG counting.
//
// Gate 1: GetSigOpCount(false) — CHECKMULTISIG always = MaxPubKeysPerMultisig (20)
// Gate 2: GetSigOpCount(true)  — CHECKMULTISIG uses lastOpcode if OP_1..OP_16
//
// Bitcoin Core reference: script.cpp:158-180, lines 172-175.
func TestW74Gate1And2AccurateVsInaccurate(t *testing.T) {
	// Build a 2-of-3 bare multisig scriptPubKey:
	// OP_2 <33-byte pubkey> OP_3 OP_CHECKMULTISIG
	pubKey := make([]byte, 33)
	multisig := []byte{
		script.OP_2,
		0x21, // push 33 bytes
	}
	multisig = append(multisig, pubKey...)
	multisig = append(multisig, script.OP_3, script.OP_CHECKMULTISIG)

	// Gate 2 (accurate): lastOp=OP_3 → 3 sigops.
	if got := CountSigOps(multisig); got != 3 {
		t.Errorf("Gate2 accurate 2-of-3: got %d, want 3", got)
	}

	// Gate 1 (inaccurate): CHECKMULTISIG → 20 regardless of OP_3.
	if got := CountSigOpsInaccurate(multisig); got != MaxPubKeysPerMultisig {
		t.Errorf("Gate1 inaccurate 2-of-3: got %d, want %d (MaxPubKeysPerMultisig)",
			got, MaxPubKeysPerMultisig)
	}

	// CHECKSIG is 1 in both modes.
	checksig := []byte{script.OP_CHECKSIG}
	if got := CountSigOps(checksig); got != 1 {
		t.Errorf("Gate2 CHECKSIG accurate: got %d, want 1", got)
	}
	if got := CountSigOpsInaccurate(checksig); got != 1 {
		t.Errorf("Gate1 CHECKSIG inaccurate: got %d, want 1", got)
	}

	// CHECKMULTISIGVERIFY without preceding OP_N → 20 in both modes.
	noKeyCount := []byte{script.OP_CHECKMULTISIGVERIFY}
	if got := CountSigOps(noKeyCount); got != MaxPubKeysPerMultisig {
		t.Errorf("Gate2 CHECKMULTISIGVERIFY no prior OP_N accurate: got %d, want %d",
			got, MaxPubKeysPerMultisig)
	}
	if got := CountSigOpsInaccurate(noKeyCount); got != MaxPubKeysPerMultisig {
		t.Errorf("Gate1 CHECKMULTISIGVERIFY no prior OP_N inaccurate: got %d, want %d",
			got, MaxPubKeysPerMultisig)
	}

	// 1-of-1 multisig: accurate=1, inaccurate=20.
	oneOfOne := []byte{script.OP_1, script.OP_CHECKMULTISIG}
	if got := CountSigOps(oneOfOne); got != 1 {
		t.Errorf("Gate2 OP_1 CHECKMULTISIG accurate: got %d, want 1", got)
	}
	if got := CountSigOpsInaccurate(oneOfOne); got != MaxPubKeysPerMultisig {
		t.Errorf("Gate1 OP_1 CHECKMULTISIG inaccurate: got %d, want %d",
			got, MaxPubKeysPerMultisig)
	}

	// 16-of-16 multisig: accurate=16, inaccurate=20.
	sixteenOfSixteen := []byte{script.OP_16, script.OP_CHECKMULTISIG}
	if got := CountSigOps(sixteenOfSixteen); got != 16 {
		t.Errorf("Gate2 OP_16 CHECKMULTISIG accurate: got %d, want 16", got)
	}
	if got := CountSigOpsInaccurate(sixteenOfSixteen); got != MaxPubKeysPerMultisig {
		t.Errorf("Gate1 OP_16 CHECKMULTISIG inaccurate: got %d, want %d",
			got, MaxPubKeysPerMultisig)
	}
}

// TestW74Gate3LastOpcodeTracking verifies Gate 3: lastOpcode tracking.
// Pushdata opcodes MUST update lastOpcode (they are counted in Core's
// lastOpcode = opcode at script.cpp:177). A PUSHDATA1 of a 17-byte payload
// between OP_3 and OP_CHECKMULTISIG resets lastOp → result is 20, not 3.
//
// Bitcoin Core reference: script.cpp:177 "lastOpcode = opcode" unconditionally.
func TestW74Gate3LastOpcodeTracking(t *testing.T) {
	// Script: OP_3  PUSHDATA1(17 bytes)  OP_CHECKMULTISIG
	// lastOp after PUSHDATA1 = OP_PUSHDATA1 (0x4c), which is NOT in OP_1..OP_16.
	// So accurate counting should use 20 (not 3).
	payload := make([]byte, 17) // 17-byte push via PUSHDATA1
	s := []byte{script.OP_3, script.OP_PUSHDATA1, 17}
	s = append(s, payload...)
	s = append(s, script.OP_CHECKMULTISIG)

	// After PUSHDATA1, lastOp = OP_PUSHDATA1 → not in OP_1..OP_16 → use 20.
	if got := CountSigOps(s); got != MaxPubKeysPerMultisig {
		t.Errorf("Gate3 lastOp reset by PUSHDATA1: got %d, want %d (lastOp=PUSHDATA1, not OP_3)",
			got, MaxPubKeysPerMultisig)
	}

	// Inaccurate also gives 20.
	if got := CountSigOpsInaccurate(s); got != MaxPubKeysPerMultisig {
		t.Errorf("Gate3 inaccurate with PUSHDATA1: got %d, want %d", got, MaxPubKeysPerMultisig)
	}

	// Contrast: OP_3 directly before OP_CHECKMULTISIG → lastOp=OP_3 → 3.
	direct := []byte{script.OP_3, script.OP_CHECKMULTISIG}
	if got := CountSigOps(direct); got != 3 {
		t.Errorf("Gate3 OP_3 direct before CHECKMULTISIG accurate: got %d, want 3", got)
	}
}

// TestW74Gate4P2SHScriptSigPushOnly verifies Gate 4: CountScriptSigOps
// returns 0 when scriptSig contains a non-push opcode (> OP_16).
//
// Bitcoin Core reference: script.cpp:197
//   "if (opcode > OP_16) return 0;"
func TestW74Gate4P2SHScriptSigPushOnly(t *testing.T) {
	// Build a redeemScript with 3 CHECKSIG ops (accurate count = 3).
	// Prefixed by OP_NOP (0x61, > OP_16) in the scriptSig → must return 0.
	redeemScript := []byte{script.OP_CHECKSIG, script.OP_CHECKSIG, script.OP_CHECKSIG}

	// scriptSig that is push-only (just the redeemScript as a data push).
	pushLen := len(redeemScript)
	validScriptSig := append([]byte{byte(pushLen)}, redeemScript...)
	if got := CountScriptSigOps(validScriptSig); got != 3 {
		t.Errorf("Gate4 valid push-only scriptSig: got %d, want 3", got)
	}

	// scriptSig with OP_NOP (0x61 > OP_16) before the redeem push → return 0.
	opNOP := byte(0x61) // OP_NOP
	invalidScriptSig := append([]byte{opNOP, byte(pushLen)}, redeemScript...)
	if got := CountScriptSigOps(invalidScriptSig); got != 0 {
		t.Errorf("Gate4 non-push opcode in scriptSig: got %d, want 0 (Core returns 0 for non-push opcodes)", got)
	}
}

// TestW74Gate5GetLegacySigOpCount verifies Gate 5: GetLegacySigOpCount sums
// scriptSig(false) + scriptPubKey(false) for ALL transactions including coinbase.
// Uses INACCURATE counting (CHECKMULTISIG = 20).
//
// Bitcoin Core reference: consensus/tx_verify.cpp:112-124.
func TestW74Gate5GetLegacySigOpCount(t *testing.T) {
	// A transaction with:
	//   - 1 input: scriptSig = [OP_2 OP_CHECKMULTISIG] → inaccurate=20, accurate=2
	//   - 1 output: scriptPubKey = [OP_CHECKSIG] → 1
	//
	// Legacy (inaccurate): 20 + 1 = 21.
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
			SignatureScript:  []byte{script.OP_2, script.OP_CHECKMULTISIG},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:    1000,
			PkScript: []byte{script.OP_CHECKSIG},
		}},
	}

	var legacyInaccurate int
	for _, in := range tx.TxIn {
		legacyInaccurate += CountSigOpsInaccurate(in.SignatureScript)
	}
	for _, out := range tx.TxOut {
		legacyInaccurate += CountSigOpsInaccurate(out.PkScript)
	}
	if legacyInaccurate != 21 {
		t.Errorf("Gate5 inaccurate legacy: got %d, want 21 (20 for CHECKMULTISIG + 1 for CHECKSIG)", legacyInaccurate)
	}

	var legacyAccurate int
	for _, in := range tx.TxIn {
		legacyAccurate += CountSigOps(in.SignatureScript)
	}
	for _, out := range tx.TxOut {
		legacyAccurate += CountSigOps(out.PkScript)
	}
	// Accurate: OP_2 before OP_CHECKMULTISIG → 2 + 1 = 3.
	if legacyAccurate != 3 {
		t.Errorf("Gate5 accurate legacy: got %d, want 3 (2 for OP_2 CHECKMULTISIG + 1 CHECKSIG)", legacyAccurate)
	}
}

// TestW74Gate6P2SHSigOpCountCoinbaseSkip verifies Gate 6: GetP2SHSigOpCount
// returns 0 for coinbase transactions (IsCoinBase short-circuit).
//
// Bitcoin Core reference: consensus/tx_verify.cpp:128-129.
func TestW74Gate6P2SHSigOpCountCoinbaseSkip(t *testing.T) {
	// Coinbase transaction: first input has null outpoint (hash=0, index=0xffffffff).
	coinbaseTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
			SignatureScript:  []byte{script.OP_CHECKSIG, script.OP_CHECKSIG, script.OP_CHECKSIG},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 5_000_000_000, PkScript: []byte{script.OP_CHECKSIG}}},
	}

	utxoView := NewInMemoryUTXOView()
	if got := CountP2SHSigOps(coinbaseTx, utxoView); got != 0 {
		t.Errorf("Gate6 coinbase P2SH sigops: got %d, want 0 (coinbase short-circuit)", got)
	}
}

// TestW74Gate7And8WitnessSigOps verifies Gates 7 and 8: CountWitnessSigOps
// and WitnessSigOps for P2WPKH (=1), P2WSH (accurate script count),
// P2SH-wrapped witness, and no witness (=0).
//
// Bitcoin Core reference: interpreter.cpp:2123-2166.
func TestW74Gate7And8WitnessSigOps(t *testing.T) {
	// Gate 8a: v0 P2WPKH (20-byte program) → 1.
	t.Run("P2WPKH returns 1", func(t *testing.T) {
		program := make([]byte, 20)
		got := countWitnessSigOpsForInput(0, program, [][]byte{{0x01}, {0x02}}, 0)
		if got != 1 {
			t.Errorf("P2WPKH: got %d, want 1", got)
		}
	})

	// Gate 8b: v0 P2WSH (32-byte program), witness script has 3 CHECKSIGs → 3.
	t.Run("P2WSH 3 CHECKSIGs returns 3", func(t *testing.T) {
		program := make([]byte, 32)
		witnessScript := []byte{script.OP_CHECKSIG, script.OP_CHECKSIG, script.OP_CHECKSIG}
		got := countWitnessSigOpsForInput(0, program, [][]byte{witnessScript}, 0)
		if got != 3 {
			t.Errorf("P2WSH 3xCHECKSIG: got %d, want 3", got)
		}
	})

	// Gate 8b: v0 P2WSH with 2-of-3 CHECKMULTISIG in witness script → accurate=3.
	t.Run("P2WSH 2-of-3 CHECKMULTISIG accurate", func(t *testing.T) {
		program := make([]byte, 32)
		// OP_2 OP_CHECKMULTISIG → lastOp=OP_2, so accurate count = 2.
		witnessScript := []byte{script.OP_2, script.OP_CHECKMULTISIG}
		got := countWitnessSigOpsForInput(0, program, [][]byte{witnessScript}, 0)
		if got != 2 {
			t.Errorf("P2WSH 2-of-3 accurate: got %d, want 2", got)
		}
	})

	// Gate 8b: v0 P2WSH with empty witness stack → 0 (Core: stack.size() > 0 check).
	t.Run("P2WSH empty witness stack returns 0", func(t *testing.T) {
		program := make([]byte, 32)
		got := countWitnessSigOpsForInput(0, program, [][]byte{}, 0)
		if got != 0 {
			t.Errorf("P2WSH empty stack: got %d, want 0", got)
		}
	})

	// Gate 7: P2SH-wrapped P2WPKH → 1 witness sigop (not P2SH sigop).
	t.Run("P2SH-wrapped P2WPKH via CountWitnessSigOps", func(t *testing.T) {
		// P2SH output: OP_HASH160 <20-byte hash> OP_EQUAL
		p2shScript := []byte{0xa9, 0x14}
		p2shScript = append(p2shScript, make([]byte, 20)...)
		p2shScript = append(p2shScript, 0x87)

		// P2WPKH redeemScript: OP_0 <20-byte hash>
		p2wpkhHash := make([]byte, 20)
		redeemScript := append([]byte{0x00, 0x14}, p2wpkhHash...) // OP_0 push20 hash

		// scriptSig: push(redeemScript)
		scriptSig := append([]byte{byte(len(redeemScript))}, redeemScript...)

		prevTxHash := wire.Hash256{0xde, 0xad, 0xbe, 0xef}
		utxoView := NewInMemoryUTXOView()
		utxoView.AddUTXO(
			wire.OutPoint{Hash: prevTxHash, Index: 0},
			&UTXOEntry{Amount: 1000, PkScript: p2shScript, Height: 1},
		)

		tx := &wire.MsgTx{
			Version: 1,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: prevTxHash, Index: 0},
				SignatureScript:  scriptSig,
				Sequence:         0xffffffff,
				Witness:          [][]byte{{0x01}, {0x02}}, // signature + pubkey
			}},
			TxOut: []*wire.TxOut{{Value: 900, PkScript: []byte{script.OP_CHECKSIG}}},
		}

		got := CountWitnessSigOps(tx, utxoView)
		if got != 1 {
			t.Errorf("P2SH-P2WPKH witness sigops: got %d, want 1", got)
		}
	})
}

// TestW74Gate9GetTransactionSigOpCost verifies Gate 9: GetTransactionSigOpCost
// sums legacy×4 + P2SH×4 + witness×1, with coinbase short-circuit.
//
// Bitcoin Core reference: consensus/tx_verify.cpp:143-162.
func TestW74Gate9GetTransactionSigOpCost(t *testing.T) {
	// Simple non-coinbase tx:
	// vin[0]: scriptSig = [OP_CHECKSIG] → 1 inaccurate → 1×4 = 4
	// vout[0]: scriptPubKey = [OP_CHECKSIG] → 1 inaccurate → 1×4 = 4
	// Total legacy cost: 8
	prevHash := wire.Hash256{0x01}
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0},
			SignatureScript:  []byte{script.OP_CHECKSIG},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 900, PkScript: []byte{script.OP_CHECKSIG}}},
	}
	utxoView := NewInMemoryUTXOView()
	utxoView.AddUTXO(
		wire.OutPoint{Hash: prevHash, Index: 0},
		&UTXOEntry{Amount: 1000, PkScript: []byte{script.OP_CHECKSIG}, Height: 1},
	)

	cost := GetTransactionSigOpCost(tx, utxoView)
	// legacy: (1 CHECKSIG in scriptSig + 1 CHECKSIG in vout) × 4 = 8
	// P2SH: prevout is not P2SH → 0
	// witness: no witness → 0
	if cost != 8 {
		t.Errorf("Gate9 basic tx: got %d, want 8 (1 scriptSig + 1 vout CHECKSIG, both ×4)", cost)
	}

	// Gate 12: coinbase short-circuit — P2SH/witness skipped.
	coinbaseTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
			SignatureScript:  []byte{script.OP_CHECKSIG},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 5_000_000_000, PkScript: []byte{script.OP_CHECKSIG}}},
	}
	cbCost := GetTransactionSigOpCost(coinbaseTx, utxoView)
	// Coinbase: legacy = (1 + 1) × 4 = 8; P2SH/witness skipped.
	if cbCost != 8 {
		t.Errorf("Gate12 coinbase cost: got %d, want 8 (legacy only, P2SH+witness skipped)", cbCost)
	}

	// CHECKMULTISIG inaccurate: OP_3 CHECKMULTISIG in scriptSig → 20 (not 3) for legacy.
	txMultisig := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0},
			SignatureScript:  []byte{script.OP_3, script.OP_CHECKMULTISIG},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 900, PkScript: []byte{0x51 /* OP_1 */, script.OP_CHECKSIG}}},
	}
	multisigCost := GetTransactionSigOpCost(txMultisig, utxoView)
	// inaccurate: scriptSig=20, vout=1 → legacy=(20+1)×4=84
	if multisigCost != 84 {
		t.Errorf("Gate9 inaccurate CHECKMULTISIG: got %d, want 84 (20 inaccurate × 4 + 1 × 4)", multisigCost)
	}
}

// TestW74Gate10BlockSigOpsCostCap verifies Gate 10: CountBlockSigOpsCost and
// the MaxBlockSigOpsCost=80000 cap enforcement.
//
// Bitcoin Core reference: consensus/consensus.h:17.
func TestW74Gate10BlockSigOpsCostCap(t *testing.T) {
	if MaxBlockSigOpsCost != 80_000 {
		t.Fatalf("MaxBlockSigOpsCost constant wrong: got %d, want 80000", MaxBlockSigOpsCost)
	}

	// Build a block where each non-coinbase tx contributes exactly 4 legacy
	// sigops cost (1 CHECKSIG in vout × 4). With 20000 such txs the total
	// would be 80000, which is AT the limit — CheckBlockSigOpsCost should
	// accept it (≤ not <). Using 4 txs here for speed; just verify arithmetic.
	const numTxs = 4
	var txs []*wire.MsgTx

	coinbaseTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{}, Index: 0xffffffff},
			SignatureScript:  []byte{0x03, 0x01, 0x00, 0x00},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 5_000_000_000, PkScript: []byte{0x51, script.OP_CHECKSIG}}},
	}
	txs = append(txs, coinbaseTx)

	utxoView := NewInMemoryUTXOView()
	prevHash := wire.Hash256{0xab}

	for i := 0; i < numTxs; i++ {
		utxoView.AddUTXO(
			wire.OutPoint{Hash: prevHash, Index: uint32(i)},
			&UTXOEntry{Amount: 1000, PkScript: []byte{0x76, 0xa9}, Height: 1},
		)
		tx := &wire.MsgTx{
			Version: 1,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: uint32(i)},
				Sequence:         0xffffffff,
			}},
			TxOut: []*wire.TxOut{{Value: 900, PkScript: []byte{script.OP_CHECKSIG}}},
		}
		txs = append(txs, tx)
	}

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{},
		Transactions: txs,
	}

	cost := CountBlockSigOpsCost(block, utxoView)
	// coinbase: vout=OP_1+OP_CHECKSIG → CHECKSIG=1 → 1×4=4 (OP_1 is not a sig opcode)
	// coinbase scriptSig: no sigops
	// each non-cb tx: vout=CHECKSIG=1×4=4; vin scriptSig=nil=0
	// total: 4 (coinbase vout) + numTxs×4
	expected := 4 + numTxs*4
	if cost != expected {
		t.Errorf("Gate10 block sigops cost: got %d, want %d", cost, expected)
	}
	if cost > MaxBlockSigOpsCost {
		t.Errorf("Gate10: cost %d exceeds MaxBlockSigOpsCost %d", cost, MaxBlockSigOpsCost)
	}
}

// TestW74Gate11MaxStandardTxSigOpsCost verifies Gate 11: the policy constant
// MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST / 5 = 16000.
//
// Bitcoin Core reference: policy/policy.h:44.
func TestW74Gate11MaxStandardTxSigOpsCost(t *testing.T) {
	if MaxStandardTxSigOpsCost != MaxBlockSigOpsCost/5 {
		t.Fatalf("MaxStandardTxSigOpsCost wrong: got %d, want %d (=MaxBlockSigOpsCost/5)",
			MaxStandardTxSigOpsCost, MaxBlockSigOpsCost/5)
	}
	if MaxStandardTxSigOpsCost != 16_000 {
		t.Fatalf("MaxStandardTxSigOpsCost should be 16000, got %d", MaxStandardTxSigOpsCost)
	}
}

// TestW74Gate11MaxP2SHSigOpsPerInput verifies Gate 11b: the per-input policy
// constant MAX_P2SH_SIGOPS = 15.
//
// Bitcoin Core reference: policy/policy.h:42.
func TestW74Gate11MaxP2SHSigOpsPerInput(t *testing.T) {
	if MaxP2SHSigOpsPerInput != 15 {
		t.Fatalf("MaxP2SHSigOpsPerInput wrong: got %d, want 15", MaxP2SHSigOpsPerInput)
	}
}

// TestW74Gate11MaxTxLegacySigOps verifies Gate 11c: the BIP54 per-tx legacy
// sigops constant MAX_TX_LEGACY_SIGOPS = 2500.
//
// Bitcoin Core reference: policy/policy.h:46.
func TestW74Gate11MaxTxLegacySigOps(t *testing.T) {
	if MaxTxLegacySigOps != 2_500 {
		t.Fatalf("MaxTxLegacySigOps wrong: got %d, want 2500", MaxTxLegacySigOps)
	}
}

// TestW74CountScriptPubKeySigOps verifies CountScriptPubKeySigOps:
// - For non-P2SH prevout: uses CountSigOps(scriptPubKey) accurate.
// - For P2SH prevout: uses CountScriptSigOps(scriptSig) (accurate redeemScript count).
//
// Bitcoin Core reference: script.cpp:182-204 GetSigOpCount(scriptSig).
func TestW74CountScriptPubKeySigOps(t *testing.T) {
	// Non-P2SH prevout with CHECKSIG → 1.
	nonP2SH := []byte{script.OP_CHECKSIG}
	if got := CountScriptPubKeySigOps(nonP2SH, nil); got != 1 {
		t.Errorf("non-P2SH CHECKSIG: got %d, want 1", got)
	}

	// Non-P2SH prevout with OP_2 CHECKMULTISIG → accurate = 2.
	nonP2SHMulti := []byte{script.OP_2, script.OP_CHECKMULTISIG}
	if got := CountScriptPubKeySigOps(nonP2SHMulti, nil); got != 2 {
		t.Errorf("non-P2SH OP_2 CHECKMULTISIG accurate: got %d, want 2", got)
	}

	// P2SH prevout: OP_HASH160 <20 bytes> OP_EQUAL
	p2shPubKey := []byte{0xa9, 0x14}
	p2shPubKey = append(p2shPubKey, make([]byte, 20)...)
	p2shPubKey = append(p2shPubKey, 0x87)

	// RedeemScript with 3 CHECKSIGs.
	redeemScript := []byte{script.OP_CHECKSIG, script.OP_CHECKSIG, script.OP_CHECKSIG}
	scriptSig := append([]byte{byte(len(redeemScript))}, redeemScript...)

	if got := CountScriptPubKeySigOps(p2shPubKey, scriptSig); got != 3 {
		t.Errorf("P2SH redeemScript 3×CHECKSIG: got %d, want 3", got)
	}

	// P2SH prevout with non-push-only scriptSig → 0.
	badScriptSig := append([]byte{0x61 /* OP_NOP > OP_16 */, byte(len(redeemScript))}, redeemScript...)
	if got := CountScriptPubKeySigOps(p2shPubKey, badScriptSig); got != 0 {
		t.Errorf("P2SH non-push-only scriptSig: got %d, want 0", got)
	}
}
