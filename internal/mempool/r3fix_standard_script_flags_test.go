// Package mempool — r3fix-blockbrew-mempool-standard-script-flags.
//
// The mempool's policy script flags must be Bitcoin Core's
// STANDARD_SCRIPT_VERIFY_FLAGS (policy/policy.h: MANDATORY plus 13
// standard-only flags), used for PolicyScriptChecks in validation.cpp.
// blockbrew set only STRICTENC, NULLFAIL and WITNESS_PUBKEYTYPE, so the other
// ten standard-only checks never fired in the mempool and the R3 differential
// fuzzer (night 1, seed 739943) saw 101 transactions accepted that Core
// refuses: OP_SUCCESSx leaves, unknown leaf versions, upgradable NOPs, unknown
// tapscript pubkey types, non-minimal pushes / IF arguments, unclean P2SH
// stacks and OP_CODESEPARATOR in legacy scripts.
//
// Every reject case below is consensus-valid (the block flags accept it); a
// positive control of the same shape is accepted, so the reject is the policy
// flag and not some other gate.
package mempool

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/hashhog/blockbrew/internal/consensus"
	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

// Minimised night-1 case `mempool/verdict/script-policy/DISCOURAGE_OP_SUCCESS|accept`:
// tapscript leaf [OP_SUCCESS80] (0x50), internal key G, no merkle path.
const r3fixOpSuccessHex = "02000000000101af1a052307e29fa79bfee6d53465b5369002692a23a3c27cea919fc908362c150000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326002015021c079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000"

const r3fixPrevAmount = int64(100_000)

// r3fixP2TRForLeaf returns the P2TR scriptPubKey committing to a single leaf
// (leafVersion, leafScript) under internalKey, and the matching control block.
func r3fixP2TRForLeaf(t *testing.T, internalKey []byte, leafVersion byte, leafScript []byte) ([]byte, []byte) {
	t.Helper()
	leafHash := script.TapLeaf(leafVersion, leafScript)
	tweak := script.TapTweak(internalKey, leafHash[:])
	outputKey, parity := crypto.ComputeTaprootOutputKey(internalKey, tweak)
	if outputKey == nil {
		t.Fatal("ComputeTaprootOutputKey returned nil")
	}
	pk := append([]byte{0x51, 0x20}, outputKey...)
	control := append([]byte{leafVersion | parity}, internalKey...)
	return pk, control
}

func r3fixInternalKey() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0x22
	}
	return crypto.PrivateKeyFromBytes(b).PubKey().XOnlyPubKey()
}

// r3fixSpend builds a one-in one-out spend of op paying a P2WSH output.
func r3fixSpend(op wire.OutPoint, scriptSig []byte, witness [][]byte) *wire.MsgTx {
	out := make([]byte, 34)
	out[0], out[1] = 0x00, 0x20
	for i := 2; i < 34; i++ {
		out[i] = byte(i)
	}
	return &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: op,
			SignatureScript:  scriptSig,
			Witness:          witness,
			Sequence:         0xfffffffe,
		}},
		TxOut:    []*wire.TxOut{{Value: r3fixPrevAmount - 2_000, PkScript: out}},
		LockTime: 0,
	}
}

func r3fixOutPoint(seed byte) wire.OutPoint {
	var h wire.Hash256
	h[0], h[1], h[2] = 0x3f, 0xf1, seed // distinct funding txid per case
	return wire.OutPoint{Hash: h, Index: 0}
}

func r3fixMempoolWith(op wire.OutPoint, pk []byte) *Mempool {
	u := newTestUTXOSet()
	u.AddUTXO(op, &consensus.UTXOEntry{Amount: r3fixPrevAmount, PkScript: pk, Height: 1})
	mp := newTestMempool(u)
	mp.SetChainHeight(200)
	return mp
}

// r3fixCheck asserts the mempool verdict and, for rejects, the script error
// code produced at the mempool's own standard flags.
func r3fixCheck(t *testing.T, mp *Mempool, tx *wire.MsgTx, pk []byte, wantCode script.ErrorCode, wantReject bool) {
	t.Helper()
	err := mp.AddTransaction(tx)
	if !wantReject {
		if err != nil {
			t.Fatalf("control tx rejected (must be accepted, as Core does): %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("tx accepted; Core v31.1 rejects it at STANDARD_SCRIPT_VERIFY_FLAGS (%s)",
			script.CoreErrorString(wantCode))
	}
	if !errors.Is(err, ErrScriptValidation) {
		t.Fatalf("tx rejected for the wrong reason (want script policy %s): %v",
			script.CoreErrorString(wantCode), err)
	}
	prev := []*wire.TxOut{{Value: r3fixPrevAmount, PkScript: pk}}
	verr := script.VerifyScript(tx.TxIn[0].SignatureScript, pk, tx, 0, mp.getStandardScriptFlags(), r3fixPrevAmount, prev)
	var se *script.Error
	if !errors.As(verr, &se) || se.Code != wantCode {
		t.Fatalf("script error at standard flags = %v, want code %d (%s)", verr, wantCode, script.CoreErrorString(wantCode))
	}
	// Consensus-valid: the block flags must accept it, so this is policy only.
	cerr := script.VerifyScript(tx.TxIn[0].SignatureScript, pk, tx, 0, mp.getConsensusScriptFlags(), r3fixPrevAmount, prev)
	if cerr != nil {
		t.Fatalf("case is not consensus-valid (block flags reject it: %v); the test would not isolate the policy flag", cerr)
	}
}

// TestR3Fix_StandardScriptFlagsEqualCore pins the flag set to Core's
// STANDARD_SCRIPT_VERIFY_FLAGS (policy/policy.h:118-131).
func TestR3Fix_StandardScriptFlagsEqualCore(t *testing.T) {
	mp := newTestMempool(newTestUTXOSet())
	mp.SetChainHeight(200)
	mandatory := script.ScriptVerifyP2SH | script.ScriptVerifyDERSig | script.ScriptVerifyNullDummy |
		script.ScriptVerifyCLTV | script.ScriptVerifyCSV | script.ScriptVerifyWitness | script.ScriptVerifyTaproot
	want := mandatory |
		script.ScriptVerifyStrictEncoding |
		script.ScriptVerifyMinimalData |
		script.ScriptVerifyDiscourageUpgradableNops |
		script.ScriptVerifyCleanStack |
		script.ScriptVerifyMinimalIf |
		script.ScriptVerifyNullFail |
		script.ScriptVerifyLowS |
		script.ScriptVerifyDiscourageUpgradableWitnessProgram |
		script.ScriptVerifyWitnessPubKeyType |
		script.ScriptVerifyConstScriptCode |
		script.ScriptVerifyDiscourageUpgradableTaprootVersion |
		script.ScriptVerifyDiscourageOpSuccess |
		script.ScriptVerifyDiscourageUpgradablePubKeyType
	got := mp.getStandardScriptFlags()
	if got != want {
		t.Fatalf("standard script flags = %#x, Core STANDARD_SCRIPT_VERIFY_FLAGS = %#x (missing %#x, extra %#x)",
			uint32(got), uint32(want), uint32(want&^got), uint32(got&^want))
	}
	if cns := mp.getConsensusScriptFlags(); cns&^mandatory != 0 {
		t.Fatalf("consensus flags carry policy bits %#x", uint32(cns&^mandatory))
	}
}

// TestR3Fix_MinimisedOpSuccessRejected is the night-1 minimised case, byte for byte.
func TestR3Fix_MinimisedOpSuccessRejected(t *testing.T) {
	raw, err := hex.DecodeString(r3fixOpSuccessHex)
	if err != nil {
		t.Fatal(err)
	}
	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	w := tx.TxIn[0].Witness
	if len(w) != 2 || !bytes.Equal(w[0], []byte{0x50}) || len(w[1]) != 33 {
		t.Fatalf("unexpected witness shape %x", w)
	}
	pk, control := r3fixP2TRForLeaf(t, w[1][1:], w[1][0]&0xfe, w[0])
	if !bytes.Equal(control, w[1]) {
		t.Fatalf("recomputed control block %x != case control block %x", control, w[1])
	}
	mp := r3fixMempoolWith(tx.TxIn[0].PreviousOutPoint, pk)
	r3fixCheck(t, mp, tx, pk, script.ErrCodeDiscourageOpSuccess, true)
}

func TestR3Fix_TapscriptPolicyFlags(t *testing.T) {
	ik := r3fixInternalKey()
	cases := []struct {
		name    string
		leafVer byte
		leaf    []byte
		code    script.ErrorCode
		reject  bool
	}{
		{"control_OP_TRUE", 0xc0, []byte{0x51}, 0, false},
		{"DISCOURAGE_OP_SUCCESS_OP_SUCCESS80", 0xc0, []byte{0x50}, script.ErrCodeDiscourageOpSuccess, true},
		{"DISCOURAGE_UPGRADABLE_TAPROOT_VERSION_leaf_c2", 0xc2, []byte{0x51}, script.ErrCodeDiscourageUpgradableTaprootVersion, true},
		{"DISCOURAGE_UPGRADABLE_NOPS_OP_NOP4", 0xc0, []byte{0xb3, 0x51}, script.ErrCodeDiscourageUpgradableNops, true},
		// <empty sig> <1-byte pubkey> CHECKSIG NOT: unknown pubkey type.
		{"DISCOURAGE_UPGRADABLE_PUBKEYTYPE_1byte_key", 0xc0, []byte{0x00, 0x01, 0xaa, 0xac, 0x91}, script.ErrCodeDiscourageUpgradablePubKeyType, true},
		// PUSHBYTES_1 0x01 instead of OP_1.
		{"MINIMALDATA_pushbytes_1", 0xc0, []byte{0x01, 0x01}, script.ErrCodeMinimalData, true},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pk, control := r3fixP2TRForLeaf(t, ik, c.leafVer, c.leaf)
			op := r3fixOutPoint(byte(0x10 + i))
			mp := r3fixMempoolWith(op, pk)
			tx := r3fixSpend(op, nil, [][]byte{c.leaf, control})
			r3fixCheck(t, mp, tx, pk, c.code, c.reject)
		})
	}
}

func r3fixP2SH(redeem []byte) []byte {
	h := crypto.Hash160(redeem)
	return append(append([]byte{0xa9, 0x14}, h[:]...), 0x87)
}

func r3fixP2WSH(ws []byte) []byte {
	h := crypto.SHA256Hash(ws)
	return append([]byte{0x00, 0x20}, h[:]...)
}

func TestR3Fix_LegacyAndWitnessV0PolicyFlags(t *testing.T) {
	redeemTrue := []byte{0x51}
	redeemCodesep := []byte{0xab, 0x51}
	ifScript := []byte{0x63, 0x51, 0x67, 0x51, 0x68} // IF 1 ELSE 1 ENDIF
	v2 := append([]byte{0x52, 0x20}, bytes.Repeat([]byte{0x07}, 32)...)
	cases := []struct {
		name    string
		pk      []byte
		sig     []byte
		witness [][]byte
		code    script.ErrorCode
		reject  bool
	}{
		{"control_P2SH_OP_TRUE", r3fixP2SH(redeemTrue), []byte{0x01, 0x51}, nil, 0, false},
		// OP_1 <redeem>: leaves two items after the redeemScript runs.
		{"CLEANSTACK_P2SH_extra_item", r3fixP2SH(redeemTrue), []byte{0x51, 0x01, 0x51}, nil, script.ErrCodeCleanStack, true},
		{"CONST_SCRIPTCODE_P2SH_codesep", r3fixP2SH(redeemCodesep), []byte{0x02, 0xab, 0x51}, nil, script.ErrCodeOpCodeSeparator, true},
		{"control_P2WSH_minimal_if", r3fixP2WSH(ifScript), nil, [][]byte{{0x01}, ifScript}, 0, false},
		{"MINIMALIF_P2WSH_if_arg_02", r3fixP2WSH(ifScript), nil, [][]byte{{0x02}, ifScript}, script.ErrCodeMinimalIf, true},
		{"DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM_v2", v2, nil, nil, script.ErrCodeDiscourageUpgradableWitnessProgram, true},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			op := r3fixOutPoint(byte(0x40 + i))
			mp := r3fixMempoolWith(op, c.pk)
			tx := r3fixSpend(op, c.sig, c.witness)
			r3fixCheck(t, mp, tx, c.pk, c.code, c.reject)
		})
	}
}

// TestR3Fix_LowS signs a P2WPKH spend, then replaces S with n-S. Core's
// LOW_S rejects the high-S form; the low-S original is the control.
func TestR3Fix_LowS(t *testing.T) {
	kb := make([]byte, 32)
	for i := range kb {
		kb[i] = 0x33
	}
	priv := crypto.PrivateKeyFromBytes(kb)
	pub := priv.PubKey().SerializeCompressed()
	h := crypto.Hash160(pub)
	pk := append([]byte{0x00, 0x14}, h[:]...)
	scriptCode := append(append([]byte{0x76, 0xa9, 0x14}, h[:]...), 0x88, 0xac)

	for i, high := range []bool{false, true} {
		name := "control_low_S"
		if high {
			name = "LOW_S_high_S_sig"
		}
		t.Run(name, func(t *testing.T) {
			op := r3fixOutPoint(byte(0x70 + i))
			mp := r3fixMempoolWith(op, pk)
			tx := r3fixSpend(op, nil, nil)
			sh, err := script.CalcWitnessSignatureHash(scriptCode, script.SigHashAll, tx, 0, r3fixPrevAmount)
			if err != nil {
				t.Fatal(err)
			}
			der, err := crypto.SignECDSA(priv, sh)
			if err != nil {
				t.Fatal(err)
			}
			if high {
				der = r3fixFlipS(t, der)
			}
			tx.TxIn[0].Witness = [][]byte{append(der, byte(script.SigHashAll)), pub}
			r3fixCheck(t, mp, tx, pk, script.ErrCodeSigHighS, high)
		})
	}
}

// r3fixFlipS re-encodes a DER signature (R, S) as (R, n-S).
func r3fixFlipS(t *testing.T, der []byte) []byte {
	t.Helper()
	if len(der) < 8 || der[0] != 0x30 || der[2] != 0x02 {
		t.Fatalf("unexpected DER %x", der)
	}
	rLen := int(der[3])
	r := der[4 : 4+rLen]
	if der[4+rLen] != 0x02 {
		t.Fatalf("unexpected DER %x", der)
	}
	sLen := int(der[5+rLen])
	s := new(big.Int).SetBytes(der[6+rLen : 6+rLen+sLen])
	n, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	hs := new(big.Int).Sub(n, s).Bytes()
	if hs[0]&0x80 != 0 {
		hs = append([]byte{0x00}, hs...)
	}
	body := append(append([]byte{0x02, byte(len(r))}, r...), append([]byte{0x02, byte(len(hs))}, hs...)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}
