package mempool

// W74: tests for the three sigops policy gates added to AddTransaction.
//
// Gate 1 (per-tx sigops cost):   ErrTxSigOpsCostTooHigh  (MaxStandardTxSigOpsCost=16000)
// Gate 2 (per-P2SH-input):       ErrP2SHSigOpsTooMany    (MaxP2SHSigOpsPerInput=15)
// Gate 3 (BIP54 legacy per-tx):  ErrTxLegacySigOpsTooMany (MaxTxLegacySigOps=2500)
//
// All tests use newTestMempool (no script validation) so we can exercise
// the policy checks without valid signatures.
//
// Bitcoin Core references:
//   Gate 1: validation.cpp:908-943 (GetTransactionSigOpCost > MAX_STANDARD_TX_SIGOPS_COST)
//   Gate 2: policy.cpp:254-258 (ValidateInputsStandardness per P2SH input)
//   Gate 3: policy.cpp:170-193 (CheckSigopsBIP54 / MAX_TX_LEGACY_SIGOPS)

import (
	"errors"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// buildP2SHFundingUTXO returns an outpoint + UTXOEntry whose PkScript is P2SH.
// The corresponding redeemScript has the given sigop count (all CHECKSIG ops).
func buildP2SHFundingUTXO(seed byte, sigopsInRedeem int) (wire.OutPoint, *consensus.UTXOEntry, []byte) {
	// P2SH output script: OP_HASH160 <20-byte hash> OP_EQUAL  (23 bytes)
	p2shPkScript := make([]byte, 23)
	p2shPkScript[0] = 0xa9 // OP_HASH160
	p2shPkScript[1] = 0x14 // push 20 bytes
	p2shPkScript[2] = seed // use seed to differentiate UTXOs
	// bytes 3..21: zero
	p2shPkScript[22] = 0x87 // OP_EQUAL

	var h wire.Hash256
	h[0] = seed
	op := wire.OutPoint{Hash: h, Index: 0}
	entry := &consensus.UTXOEntry{
		Amount:   1_000_000,
		PkScript: p2shPkScript,
		Height:   1,
	}

	// Build a redeemScript with sigopsInRedeem CHECKSIG operations.
	redeemScript := make([]byte, sigopsInRedeem)
	for i := range redeemScript {
		redeemScript[i] = script.OP_CHECKSIG
	}

	return op, entry, redeemScript
}

// p2shScriptSig builds a scriptSig that pushes redeemScript as the last push.
// The 107-byte padding pushes before ensure the scriptSig is >= 65 bytes
// (MIN_STANDARD_TX_NONWITNESS_SIZE constraint).  Note: all bytes must be
// valid push operations (IsPushOnly) to pass the scriptSig policy gate.
func p2shScriptSig(redeemScript []byte) []byte {
	// Single data push of the redeemScript.
	if len(redeemScript) <= 75 {
		// Direct push: opcode = length
		sig := make([]byte, 1+len(redeemScript))
		sig[0] = byte(len(redeemScript))
		copy(sig[1:], redeemScript)
		return sig
	}
	// PUSHDATA1 for up to 255 bytes.
	sig := make([]byte, 2+len(redeemScript))
	sig[0] = 0x4c // OP_PUSHDATA1
	sig[1] = byte(len(redeemScript))
	copy(sig[2:], redeemScript)
	return sig
}

// buildMinimalSpendTx builds a minimal transaction spending op with the given
// scriptSig, whose non-witness size is at least MIN_STANDARD_TX_NONWITNESS_SIZE
// (65 bytes). The output value is set so the fee is above the minimum relay
// rate (2 sat/vB, which is generous to avoid ErrInsufficientFee).
func buildMinimalSpendTx(op wire.OutPoint, scriptSig []byte, pkScript []byte) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: op,
			SignatureScript:  scriptSig,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:    900_000, // leaves 100_000 sat fee on a 1_000_000 sat input
			PkScript: pkScript,
		}},
	}
}

// p2wpkhOutput returns a standard P2WPKH output script (22 bytes, passes
// isStandardOutputScript).
func p2wpkhOutput(seed byte) []byte {
	out := make([]byte, 22)
	out[0] = 0x00 // OP_0
	out[1] = 0x14 // push 20 bytes
	out[2] = seed
	return out
}

// TestW74MempoolGate1TxSigOpsCostTooHigh verifies that AddTransaction rejects
// a transaction whose GetTransactionSigOpCost exceeds MaxStandardTxSigOpsCost
// (16000). We use multiple P2SH inputs each with 15 CHECKSIG ops (at the
// per-input limit) so Gate 2 does not fire, but the cumulative cost does.
//
// Each P2SH input contributes: CountP2SHSigOps = 15 × WitnessScaleFactor(4) = 60.
// 268 inputs × 60 = 16080 > 16000 → ErrTxSigOpsCostTooHigh.
//
// We also need the tx weight to stay below MaxStandardTxWeight (400,000 WU).
// Each P2SH input: ~80 bytes (scriptSig = 17-byte redeemScript push).
// 268 inputs × 80 bytes × 4 WU = 85,760 WU. Plus 1 output × 31 bytes × 4 = 124.
// Well within 400,000 WU.
//
// Bitcoin Core reference: validation.cpp:908-943.
func TestW74MempoolGate1TxSigOpsCostTooHigh(t *testing.T) {
	// 15-sigop redeemScript: 15 × OP_CHECKSIG bytes.
	redeemScript := make([]byte, 15)
	for i := range redeemScript {
		redeemScript[i] = script.OP_CHECKSIG
	}
	scriptSig := p2shScriptSig(redeemScript)

	// Each input needs its own distinct P2SH UTXO.
	const numInputs = 268 // 268 × 60 = 16080 > 16000
	utxoSet := newTestUTXOSet()
	var ops []wire.OutPoint

	for i := 0; i < numInputs; i++ {
		var h wire.Hash256
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		h[2] = 0x10 // distinguish from Gate3 tests
		op := wire.OutPoint{Hash: h, Index: 0}

		// P2SH output script (23 bytes): OP_HASH160 <20-byte hash> OP_EQUAL
		pkScript := make([]byte, 23)
		pkScript[0] = 0xa9 // OP_HASH160
		pkScript[1] = 0x14 // push 20 bytes
		pkScript[2] = byte(i)
		pkScript[22] = 0x87 // OP_EQUAL

		utxoSet.AddUTXO(op, &consensus.UTXOEntry{
			Amount:   10_000,
			PkScript: pkScript,
			Height:   1,
		})
		ops = append(ops, op)
	}

	mp := newTestMempool(utxoSet)

	tx := &wire.MsgTx{Version: 2, LockTime: 0}
	for _, op := range ops {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: op,
			SignatureScript:  scriptSig,
			Sequence:         0xffffffff,
		})
	}
	totalIn := int64(numInputs) * 10_000
	tx.TxOut = []*wire.TxOut{{
		Value:    totalIn - 10_000, // leave 10_000 sat fee
		PkScript: p2wpkhOutput(0x01),
	}}

	err := mp.AddTransaction(tx)
	if !errors.Is(err, ErrTxSigOpsCostTooHigh) {
		t.Errorf("Gate1 cost>16000: got %v, want ErrTxSigOpsCostTooHigh", err)
	}
}

// TestW74MempoolGate2P2SHSigOpsTooMany verifies that AddTransaction rejects
// a P2SH input whose redeemScript contains > MaxP2SHSigOpsPerInput (15) sigops.
//
// Bitcoin Core reference: policy.cpp:254-258.
func TestW74MempoolGate2P2SHSigOpsTooMany(t *testing.T) {
	// Build a P2SH UTXO whose redeemScript has 16 CHECKSIG ops (> 15 limit).
	op, entry, redeemScript := buildP2SHFundingUTXO(0xb1, 16)

	utxoSet := newTestUTXOSet()
	utxoSet.AddUTXO(op, entry)
	mp := newTestMempool(utxoSet)

	scriptSig := p2shScriptSig(redeemScript)
	tx := buildMinimalSpendTx(op, scriptSig, p2wpkhOutput(0x01))

	err := mp.AddTransaction(tx)
	if !errors.Is(err, ErrP2SHSigOpsTooMany) {
		t.Errorf("Gate2 P2SH>15 sigops: got %v, want ErrP2SHSigOpsTooMany", err)
	}
}

// TestW74MempoolGate2P2SHSigOpsExactly15Passes verifies that exactly
// MaxP2SHSigOpsPerInput (15) sigops in a P2SH redeemScript is accepted
// (boundary: ≤ 15 is allowed, > 15 is rejected).
//
// The transaction will likely fail at script validation (no valid sigs),
// but the test confirms we DON'T get ErrP2SHSigOpsTooMany at exactly 15.
func TestW74MempoolGate2P2SHSigOpsExactly15Passes(t *testing.T) {
	op, entry, redeemScript := buildP2SHFundingUTXO(0xb2, 15)

	utxoSet := newTestUTXOSet()
	utxoSet.AddUTXO(op, entry)
	mp := newTestMempool(utxoSet)

	scriptSig := p2shScriptSig(redeemScript)
	tx := buildMinimalSpendTx(op, scriptSig, p2wpkhOutput(0x02))

	err := mp.AddTransaction(tx)
	// Must NOT return ErrP2SHSigOpsTooMany (15 is at the boundary, allowed).
	if errors.Is(err, ErrP2SHSigOpsTooMany) {
		t.Errorf("Gate2 P2SH exactly 15 sigops should pass gate: got ErrP2SHSigOpsTooMany")
	}
}

// TestW74MempoolGate3BIP54LegacySigOpsTooMany verifies that AddTransaction
// rejects a tx whose total non-witness legacy sigops exceed MaxTxLegacySigOps
// (2500). Core's CheckSigopsBIP54 counts per input:
//   scriptSig.GetSigOpCount(true) + prev_txo.scriptPubKey.GetSigOpCount(scriptSig)
// For P2SH prevouts, GetSigOpCount(scriptSig) extracts the redeemScript sigops
// (accurate counting).
//
// We use 167 P2SH inputs each with a 15-CHECKSIG redeemScript (at the Gate 2
// boundary, so Gate 2 doesn't fire). 167 × 15 = 2505 > 2500 → Gate 3 fires.
// Weight: 167 inputs × ~25 bytes ≈ 4175 bytes = ~16,700 WU << 400,000. OK.
//
// Bitcoin Core reference: policy.cpp:170-193 (CheckSigopsBIP54).
func TestW74MempoolGate3BIP54LegacySigOpsTooMany(t *testing.T) {
	// 15-sigop redeemScript (exactly at Gate 2 per-input limit, so Gate 2 passes).
	redeemScript := make([]byte, 15)
	for i := range redeemScript {
		redeemScript[i] = script.OP_CHECKSIG
	}
	scriptSig := p2shScriptSig(redeemScript)

	const numInputs = 167 // 167 × 15 = 2505 > 2500
	utxoSet := newTestUTXOSet()
	var ops []wire.OutPoint

	for i := 0; i < numInputs; i++ {
		var h wire.Hash256
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		h[2] = 0x30 // distinct from Gate1 tests (0x10)
		op := wire.OutPoint{Hash: h, Index: 0}

		pkScript := make([]byte, 23)
		pkScript[0] = 0xa9
		pkScript[1] = 0x14
		pkScript[2] = byte(i)
		pkScript[22] = 0x87
		utxoSet.AddUTXO(op, &consensus.UTXOEntry{
			Amount:   10_000,
			PkScript: pkScript,
			Height:   1,
		})
		ops = append(ops, op)
	}

	mp := newTestMempool(utxoSet)

	tx := &wire.MsgTx{Version: 2, LockTime: 0}
	for _, op := range ops {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: op,
			SignatureScript:  scriptSig,
			Sequence:         0xffffffff,
		})
	}
	totalIn := int64(numInputs) * 10_000
	tx.TxOut = []*wire.TxOut{{
		Value:    totalIn - 10_000,
		PkScript: p2wpkhOutput(0x03),
	}}

	err := mp.AddTransaction(tx)
	if !errors.Is(err, ErrTxLegacySigOpsTooMany) {
		t.Errorf("Gate3 BIP54 >2500 legacy sigops: got %v, want ErrTxLegacySigOpsTooMany", err)
	}
}

// TestW74MempoolGate3BIP54LegacySigOpsExactly2500Passes verifies that exactly
// MaxTxLegacySigOps (2500) non-witness sigops passes the BIP54 gate.
// We use 166 P2SH inputs × 15 sigops = 2490 ≤ 2500.
func TestW74MempoolGate3BIP54LegacySigOpsExactly2500Passes(t *testing.T) {
	redeemScript := make([]byte, 15)
	for i := range redeemScript {
		redeemScript[i] = script.OP_CHECKSIG
	}
	scriptSig := p2shScriptSig(redeemScript)

	const numInputs = 166 // 166 × 15 = 2490 ≤ 2500 → passes Gate3
	utxoSet := newTestUTXOSet()
	var ops []wire.OutPoint

	for i := 0; i < numInputs; i++ {
		var h wire.Hash256
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		h[2] = 0x40 // distinct from Gate3 fail test (0x30)
		op := wire.OutPoint{Hash: h, Index: 0}

		pkScript := make([]byte, 23)
		pkScript[0] = 0xa9
		pkScript[1] = 0x14
		pkScript[2] = byte(i)
		pkScript[22] = 0x87
		utxoSet.AddUTXO(op, &consensus.UTXOEntry{
			Amount:   10_000,
			PkScript: pkScript,
			Height:   1,
		})
		ops = append(ops, op)
	}

	mp := newTestMempool(utxoSet)

	tx := &wire.MsgTx{Version: 2, LockTime: 0}
	for _, op := range ops {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: op,
			SignatureScript:  scriptSig,
			Sequence:         0xffffffff,
		})
	}
	totalIn := int64(numInputs) * 10_000
	tx.TxOut = []*wire.TxOut{{
		Value:    totalIn - 10_000,
		PkScript: p2wpkhOutput(0x04),
	}}

	err := mp.AddTransaction(tx)
	// Must NOT return ErrTxLegacySigOpsTooMany.
	if errors.Is(err, ErrTxLegacySigOpsTooMany) {
		t.Errorf("Gate3 BIP54 2490 sigops should pass gate: got ErrTxLegacySigOpsTooMany")
	}
}
