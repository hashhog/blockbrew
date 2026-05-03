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
