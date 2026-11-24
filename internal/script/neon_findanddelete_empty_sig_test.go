package script

// verify-neon-blockbrew-findings, audit finding 2 (CHECKMULTISIG half).
//
// Core OP_CHECKMULTISIG (script/interpreter.cpp:1142-1149) runs, for every
// signature in a BASE (legacy / P2SH) script,
//     FindAndDelete(scriptCode, CScript() << vchSig)
// and CScript() << <empty> is the single byte 0x00 (OP_0). So an empty
// signature deletes every opcode-aligned OP_0 from the scriptCode that the
// OTHER signatures of the same CHECKMULTISIG are verified against.
// blockbrew's FindAndDeleteCount returned early for an empty signature and
// left OP_0 in the scriptCode, so the sighash of the remaining signatures
// differed from Core's. Because CHECKMULTISIG exits early once the remaining
// keys cannot cover the remaining signatures, that changes whether a later
// malformed signature is ever reached, which under DERSIG (a block flag) is
// the difference between success and SCRIPT_ERR_SIG_DER — in both directions.

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

const neonFADBlockFlags = ScriptVerifyP2SH | ScriptVerifyWitness | ScriptVerifyTaproot |
	ScriptVerifyDERSig | ScriptVerifyCLTV | ScriptVerifyCSV | ScriptVerifyNullDummy

func neonFADKey(b byte) *crypto.PrivateKey {
	return crypto.PrivateKeyFromBytes(append(make([]byte, 31), b))
}

func neonFADPush(data []byte) []byte { return canonicalPushScript(data) }

// spk = OP_0 OP_DROP OP_3 <pk3> <pk2> <pk1> OP_3 OP_CHECKMULTISIG OP_NOT
func neonFADScript(pk1, pk2, pk3 []byte) []byte {
	s := []byte{OP_0, OP_DROP, OP_3}
	s = append(s, neonFADPush(pk3)...)
	s = append(s, neonFADPush(pk2)...)
	s = append(s, neonFADPush(pk1)...)
	return append(s, OP_3, OP_CHECKMULTISIG, OP_NOT)
}

func neonFADTx() *wire.MsgTx {
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 0},
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 1000, PkScript: []byte{OP_TRUE}}},
	}
}

// run builds scriptSig = OP_0 OP_0 <bad DER> <sig1>, so the signatures popped
// from the top are [sig1, bad, ""] against keys [pk1, pk2, pk3]. sig1 is a
// valid signature by pk1 over signedCode.
func neonFADRun(t *testing.T, deleteOP0 bool) error {
	t.Helper()
	k1, k2, k3 := neonFADKey(1), neonFADKey(2), neonFADKey(3)
	pk1 := k1.PubKey().SerializeCompressed()
	pk2 := k2.PubKey().SerializeCompressed()
	pk3 := k3.PubKey().SerializeCompressed()
	spk := neonFADScript(pk1, pk2, pk3)

	signedCode := spk
	if deleteOP0 {
		// Core's scriptCode after FindAndDelete(OP_0): the only
		// opcode-aligned 0x00 is the leading OP_0.
		if spk[0] != OP_0 || bytes.Count(spk, []byte{0x00}) < 1 {
			t.Fatalf("fixture: unexpected script layout")
		}
		signedCode = spk[1:]
	}
	tx := neonFADTx()
	sighash, err := CalcSignatureHash(signedCode, SigHashAll, tx, 0)
	if err != nil {
		t.Fatal(err)
	}
	der, err := crypto.SignECDSA(k1, sighash)
	if err != nil {
		t.Fatal(err)
	}
	sig1 := append(der, byte(SigHashAll))
	bad := []byte{0x01} // not DER: SCRIPT_ERR_SIG_DER under DERSIG if reached

	ss := []byte{OP_0, OP_0}
	ss = append(ss, neonFADPush(bad)...)
	ss = append(ss, neonFADPush(sig1)...)
	tx.TxIn[0].SignatureScript = ss

	prev := []*wire.TxOut{{Value: 2000, PkScript: spk}}
	e, err := NewEngine(spk, tx, 0, neonFADBlockFlags, 2000, prev)
	if err != nil {
		t.Fatal(err)
	}
	return e.Execute()
}

// sig1 signed over the OP_0-deleted scriptCode (what Core verifies against):
// Core matches sig1/pk1, reaches the malformed signature and fails with
// SCRIPT_ERR_SIG_DER. blockbrew master accepted (invalid block accepted).
func TestNeonFindAndDeleteEmptySigMultisigRejectsLikeCore(t *testing.T) {
	err := neonFADRun(t, true)
	if err == nil {
		t.Fatalf("CHECKMULTISIG with an empty sig accepted; Core deletes OP_0 from scriptCode, matches sig1 and fails SCRIPT_ERR_SIG_DER")
	}
	if c, _ := ErrorCodeOf(err); c != ErrCodeSigDER {
		t.Fatalf("got %v, Core SCRIPT_ERR_SIG_DER", err)
	}
}

// sig1 signed over the full scriptCode: Core's sighash differs (OP_0 deleted),
// sig1 fails, CHECKMULTISIG exits early before the malformed signature, OP_NOT
// makes the script succeed. blockbrew master rejected (valid block rejected).
func TestNeonFindAndDeleteEmptySigMultisigAcceptsLikeCore(t *testing.T) {
	if err := neonFADRun(t, false); err != nil {
		t.Fatalf("CHECKMULTISIG with an empty sig rejected: %v; Core accepts (sig1 does not match the OP_0-deleted scriptCode, early exit)", err)
	}
}

// The helper itself: an empty signature is FindAndDelete of the single byte
// OP_0, opcode-aligned only.
func TestNeonFindAndDeleteCountEmptySigDeletesOP0(t *testing.T) {
	// OP_0 <push 0x00> OP_0 : the 0x00 inside the push payload is not at an
	// opcode boundary and stays.
	in := []byte{OP_0, 0x01, 0x00, OP_0, OP_CHECKSIG}
	out, n := FindAndDeleteCount(in, nil)
	if n != 2 || !bytes.Equal(out, []byte{0x01, 0x00, OP_CHECKSIG}) {
		t.Fatalf("FindAndDeleteCount(%x, empty) = %x, %d; Core removes the 2 opcode-aligned OP_0 -> 0100ac, 2", in, out, n)
	}
	// No OP_0 at a boundary: unchanged.
	in2 := []byte{OP_1, 0x01, 0x00, OP_CHECKSIG}
	if out, n := FindAndDeleteCount(in2, []byte{}); n != 0 || !bytes.Equal(out, in2) {
		t.Fatalf("FindAndDeleteCount(%x, empty) = %x, %d; want unchanged, 0", in2, out, n)
	}
}

// CONST_SCRIPTCODE (policy): an empty multisig signature that deletes an OP_0
// is SCRIPT_ERR_SIG_FINDANDDELETE in Core.
func TestNeonFindAndDeleteEmptySigConstScriptCode(t *testing.T) {
	k1 := neonFADKey(1)
	pk1 := k1.PubKey().SerializeCompressed()
	spk := []byte{OP_0, OP_DROP, OP_1}
	spk = append(spk, neonFADPush(pk1)...)
	spk = append(spk, OP_1, OP_CHECKMULTISIG, OP_NOT)
	tx := neonFADTx()
	tx.TxIn[0].SignatureScript = []byte{OP_0, OP_0}
	prev := []*wire.TxOut{{Value: 2000, PkScript: spk}}
	e, err := NewEngine(spk, tx, 0, neonFADBlockFlags|ScriptVerifyConstScriptCode, 2000, prev)
	if err != nil {
		t.Fatal(err)
	}
	err = e.Execute()
	if c, _ := ErrorCodeOf(err); c != ErrCodeSigFindAndDelete {
		t.Fatalf("got %v, Core SCRIPT_ERR_SIG_FINDANDDELETE", err)
	}
	// Control: without CONST_SCRIPTCODE the same spend succeeds (empty sig
	// fails, OP_NOT).
	e, _ = NewEngine(spk, tx, 0, neonFADBlockFlags, 2000, prev)
	if err := e.Execute(); err != nil {
		t.Fatalf("control without CONST_SCRIPTCODE rejected: %v", err)
	}
}

// Control: an ordinary 1-of-1 multisig with a valid signature and no empty
// signature is unaffected even with an OP_0 in the scriptCode.
func TestNeonFindAndDeleteNoEmptySigControl(t *testing.T) {
	k1 := neonFADKey(1)
	pk1 := k1.PubKey().SerializeCompressed()
	spk := []byte{OP_0, OP_DROP, OP_1}
	spk = append(spk, neonFADPush(pk1)...)
	spk = append(spk, OP_1, OP_CHECKMULTISIG)
	tx := neonFADTx()
	sighash, err := CalcSignatureHash(spk, SigHashAll, tx, 0)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := crypto.SignECDSA(k1, sighash)
	tx.TxIn[0].SignatureScript = append([]byte{OP_0}, neonFADPush(append(der, byte(SigHashAll)))...)
	prev := []*wire.TxOut{{Value: 2000, PkScript: spk}}
	e, _ := NewEngine(spk, tx, 0, neonFADBlockFlags|ScriptVerifyNullFail|ScriptVerifyStrictEncoding|ScriptVerifyLowS, 2000, prev)
	if err := e.Execute(); err != nil {
		t.Fatalf("valid 1-of-1 multisig rejected: %v", err)
	}
}
