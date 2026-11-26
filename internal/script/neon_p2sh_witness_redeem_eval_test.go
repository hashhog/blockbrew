package script

// verify-neon-blockbrew-findings, audit findings 1 and 7.
//
// Core VerifyScript (script/interpreter.cpp:2065-2092) evaluates a P2SH
// redeemScript with EvalScript and requires CastToBool(stack.back()) BEFORE it
// checks whether the redeemScript is a witness program. A witness redeemScript
// is `OP_n <program>`, so the program bytes are the top element: an all-zero or
// negative-zero program is SCRIPT_ERR_EVAL_FALSE under block (consensus) flags.
// blockbrew used to branch into the witness path first and accept such a spend
// (for v1+ the wrapped program is anyone-can-spend), an invalid-accepted split.
//
// Finding 7: Core VerifyWitnessProgram(is_p2sh=true) sends every wrapped v1+
// program to the upgradable branch (interpreter.cpp:1992-1996), which fails
// under DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Block-consensus flags of a post-taproot block (Core GetBlockScriptFlags).
const neonBlockFlags = ScriptVerifyP2SH | ScriptVerifyWitness | ScriptVerifyTaproot |
	ScriptVerifyDERSig | ScriptVerifyCLTV | ScriptVerifyCSV | ScriptVerifyNullDummy

func neonP2SHSpend(t *testing.T, redeem []byte, witness [][]byte, flags ScriptFlags) error {
	t.Helper()
	h := crypto.Hash160(redeem)
	spk := append([]byte{OP_HASH160, 20}, h[:]...)
	spk = append(spk, OP_EQUAL)
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0},
			SignatureScript:  canonicalPushScript(redeem),
			Witness:          witness,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: []byte{OP_TRUE}}},
	}
	prev := []*wire.TxOut{{Value: 2000, PkScript: spk}}
	e, err := NewEngine(spk, tx, 0, flags, 2000, prev)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e.Execute()
}

func neonScriptErrCode(err error) ErrorCode {
	if c, ok := ErrorCodeOf(err); ok {
		return c
	}
	return ErrCodeUnknownError
}

// Core: SCRIPT_ERR_EVAL_FALSE for every case (the top element is the program,
// which is false). blockbrew master accepted the v1+ cases.
func TestNeonP2SHWitnessFalseProgramIsEvalFalse(t *testing.T) {
	cases := []struct {
		name   string
		redeem []byte
	}{
		{"v1-2byte-zero", []byte{OP_1, 0x02, 0x00, 0x00}},
		{"v1-2byte-negzero", []byte{OP_1, 0x02, 0x00, 0x80}},
		{"v1-32byte-zero", append([]byte{OP_1, 0x20}, make([]byte, 32)...)},
		{"v16-40byte-zero", append([]byte{OP_16, 0x28}, make([]byte, 40)...)},
		{"v0-20byte-zero", append([]byte{OP_0, 0x14}, make([]byte, 20)...)},
		{"v0-32byte-zero", append([]byte{OP_0, 0x20}, make([]byte, 32)...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := neonP2SHSpend(t, c.redeem, nil, neonBlockFlags)
			if err == nil {
				t.Fatalf("redeemScript %x with empty witness accepted under block flags; Core rejects SCRIPT_ERR_EVAL_FALSE", c.redeem)
			}
			if got := neonScriptErrCode(err); got != ErrCodeEvalFalse {
				t.Fatalf("redeemScript %x: got %v (%v), Core SCRIPT_ERR_EVAL_FALSE", c.redeem, got, err)
			}
		})
	}
}

// Controls: a true program still takes the witness path exactly as before.
func TestNeonP2SHWitnessTrueProgramControls(t *testing.T) {
	// Wrapped v1 / v2 with a non-zero program: Core succeeds (upgradable,
	// not discouraged under consensus flags).
	for _, redeem := range [][]byte{
		{OP_1, 0x02, 0x00, 0x01},
		{OP_1, 0x02, 0x4e, 0x73}, // P2A bytes, but P2A is native-only
		{OP_2, 0x02, 0x01, 0x02},
		append([]byte{OP_1, 0x20}, append(make([]byte, 31), 0x01)...), // 32-byte: not taproot when wrapped
	} {
		if err := neonP2SHSpend(t, redeem, nil, neonBlockFlags); err != nil {
			t.Fatalf("wrapped upgradable program %x rejected under block flags: %v (Core accepts)", redeem, err)
		}
	}
	// Wrapped v0 with a non-zero 20-byte program and an empty witness: Core
	// WITNESS_PROGRAM_MISMATCH (the program is evaluated, the witness is wrong).
	redeem := append([]byte{OP_0, 0x14}, append(make([]byte, 19), 0x01)...)
	if err := neonP2SHSpend(t, redeem, nil, neonBlockFlags); err == nil {
		t.Fatalf("P2SH-P2WPKH with empty witness accepted")
	}
	// Non-witness P2SH with a false result: still EVAL_FALSE.
	if err := neonP2SHSpend(t, []byte{OP_0}, nil, neonBlockFlags); neonScriptErrCode(err) != ErrCodeEvalFalse {
		t.Fatalf("plain P2SH redeemScript OP_0: got %v, want EVAL_FALSE", err)
	}
	// Witness flag off: the all-zero v1 program is plain P2SH and still false.
	if err := neonP2SHSpend(t, []byte{OP_1, 0x02, 0x00, 0x00}, nil, ScriptVerifyP2SH); neonScriptErrCode(err) != ErrCodeEvalFalse {
		t.Fatalf("P2SH-only flags, redeemScript 51020000: got %v, want EVAL_FALSE", err)
	}
}

// A real P2SH-P2WPKH spend still verifies (the redeemScript evaluation leaves
// the 20-byte key hash on top, which is true).
func TestNeonP2SHWitnessP2WPKHStillSpends(t *testing.T) {
	priv := crypto.PrivateKeyFromBytes(append(make([]byte, 31), 0x07))
	pub := priv.PubKey().SerializeCompressed()
	kh := crypto.Hash160(pub)
	redeem := append([]byte{OP_0, 0x14}, kh[:]...)
	sh := crypto.Hash160(redeem)
	spk := append([]byte{OP_HASH160, 20}, sh[:]...)
	spk = append(spk, OP_EQUAL)
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			SignatureScript: canonicalPushScript(redeem),
			Sequence:        0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: []byte{OP_TRUE}}},
	}
	scriptCode := append([]byte{OP_DUP, OP_HASH160, 20}, kh[:]...)
	scriptCode = append(scriptCode, OP_EQUALVERIFY, OP_CHECKSIG)
	sighash, err := CalcWitnessSignatureHash(scriptCode, SigHashAll, tx, 0, 2000)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.SignECDSA(priv, sighash)
	if err != nil {
		t.Fatal(err)
	}
	tx.TxIn[0].Witness = [][]byte{append(sig, byte(SigHashAll)), pub}
	prev := []*wire.TxOut{{Value: 2000, PkScript: spk}}
	e, err := NewEngine(spk, tx, 0, neonBlockFlags|ScriptVerifyNullFail|ScriptVerifyLowS|ScriptVerifyStrictEncoding|ScriptVerifyWitnessPubKeyType|ScriptVerifyCleanStack, 2000, prev)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Execute(); err != nil {
		t.Fatalf("valid P2SH-P2WPKH spend rejected: %v", err)
	}
}

// Finding 7: wrapped v1+ under DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.
func TestNeonP2SHWitnessV1PlusDiscouraged(t *testing.T) {
	flags := neonBlockFlags | ScriptVerifyDiscourageUpgradableWitnessProgram
	for _, redeem := range [][]byte{
		{OP_1, 0x02, 0x4e, 0x73},
		{OP_2, 0x02, 0x01, 0x02},
		append([]byte{OP_1, 0x20}, append(make([]byte, 31), 0x01)...),
	} {
		if err := neonP2SHSpend(t, redeem, nil, flags); err == nil {
			t.Fatalf("wrapped v1+ program %x accepted under DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM; Core rejects", redeem)
		}
	}
}
