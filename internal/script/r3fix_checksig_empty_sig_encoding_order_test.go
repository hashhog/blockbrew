package script

// r3fix-blockbrew-checksig-empty-sig-encoding-order (R3 night 1, seed 739943,
// triage group G3).
//
// Core EvalChecksigPreTapscript (script/interpreter.cpp:321-345) runs, for
// legacy and witness-v0 OP_CHECKSIG(VERIFY), in this order:
//
//  1. FindAndDelete(scriptCode, CScript() << sig) in BASE scripts; a hit is
//     SCRIPT_ERR_SIG_FINDANDDELETE under CONST_SCRIPTCODE. An empty sig is
//     pushed as OP_0, so it deletes (and with CONST_SCRIPTCODE trips on) an
//     opcode-aligned OP_0.
//  2. CheckSignatureEncoding (an empty sig passes).
//  3. CheckPubKeyEncoding: STRICTENC rejects anything that is not a compressed
//     or uncompressed key, the EMPTY key included (PUBKEYTYPE);
//     WITNESS_PUBKEYTYPE rejects a non-compressed key in witness v0.
//  4. CheckECDSASignature (false for an empty sig), then NULLFAIL for a
//     non-empty sig.
//
// blockbrew pushed false at once on an empty sig (skipping 1 and 3), skipped
// the STRICTENC key check for an empty key even with a non-empty sig, and ran
// FindAndDelete after the encoding checks. Every case below is also run at
// block (consensus) flags, where the verdict must not change: STRICTENC,
// WITNESS_PUBKEYTYPE and CONST_SCRIPTCODE are policy-only.

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

const r3csBlockFlags = ScriptVerifyP2SH | ScriptVerifyWitness | ScriptVerifyTaproot |
	ScriptVerifyDERSig | ScriptVerifyCLTV | ScriptVerifyCSV | ScriptVerifyNullDummy

// The policy flags blockbrew's mempool used on origin/master 0e94887.
const r3csPolicyFlags = r3csBlockFlags | ScriptVerifyStrictEncoding |
	ScriptVerifyNullFail | ScriptVerifyWitnessPubKeyType

func r3csPush(b []byte) []byte { return canonicalPushScript(b) }

func r3csTx() *wire.MsgTx {
	return &wire.MsgTx{
		Version:  2,
		TxIn:     []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Index: 0}, Sequence: 0xfffffffe}},
		TxOut:    []*wire.TxOut{{Value: 1000, PkScript: []byte{OP_TRUE}}},
		LockTime: 0,
	}
}

// runBare executes scriptSig/scriptPubKey as a bare (BASE) spend.
func r3csRunBare(scriptSig, spk []byte, flags ScriptFlags) error {
	tx := r3csTx()
	tx.TxIn[0].SignatureScript = scriptSig
	prev := []*wire.TxOut{{Value: 2000, PkScript: spk}}
	return VerifyScript(scriptSig, spk, tx, 0, flags, 2000, prev)
}

// runP2WSH executes witnessScript as a native P2WSH (witness v0) spend with
// the given stack items below the script.
func r3csRunP2WSH(items [][]byte, ws []byte, flags ScriptFlags) error {
	tx := r3csTx()
	h := crypto.SHA256Hash(ws)
	spk := append([]byte{OP_0, 0x20}, h[:]...)
	tx.TxIn[0].Witness = append(append([][]byte{}, items...), ws)
	prev := []*wire.TxOut{{Value: 2000, PkScript: spk}}
	return VerifyScript(nil, spk, tx, 0, flags, 2000, prev)
}

func r3csWant(t *testing.T, label string, err error, want ErrorCode) {
	t.Helper()
	got, ok := ErrorCodeOf(err)
	if err == nil || !ok || got != want {
		t.Fatalf("%s: got %v, want Core's %s", label, err, want)
	}
}

func r3csWantOK(t *testing.T, label string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: got %v, want success (Core accepts)", label, err)
	}
}

func r3csKey() *crypto.PrivateKey {
	return crypto.PrivateKeyFromBytes(append(make([]byte, 31), 7))
}

// A well-formed, low-S DER signature with SIGHASH_ALL over an unrelated hash:
// passes every encoding check, never verifies.
func r3csWellFormedSig(t *testing.T) []byte {
	t.Helper()
	var h [32]byte
	h[0] = 1
	der, err := crypto.SignECDSA(r3csKey(), h)
	if err != nil {
		t.Fatal(err)
	}
	return append(der, byte(SigHashAll))
}

// `0 0 CHECKSIG DROP 1` (the night-1 R113/R114 shape): empty sig, empty key.
func TestR3FixChecksigEmptySigEmptyPubKeyStrictEnc(t *testing.T) {
	spk := []byte{OP_0, OP_0, OP_CHECKSIG, OP_DROP, OP_1}
	r3csWant(t, "bare 0 0 CHECKSIG at STRICTENC", r3csRunBare(nil, spk, r3csPolicyFlags), ErrCodePubKeyType)
	r3csWantOK(t, "bare 0 0 CHECKSIG at block flags", r3csRunBare(nil, spk, r3csBlockFlags))

	ws := []byte{OP_0, OP_0, OP_CHECKSIG, OP_DROP, OP_1}
	r3csWant(t, "P2WSH 0 0 CHECKSIG at STRICTENC", r3csRunP2WSH(nil, ws, r3csPolicyFlags), ErrCodePubKeyType)
	r3csWantOK(t, "P2WSH 0 0 CHECKSIG at block flags", r3csRunP2WSH(nil, ws, r3csBlockFlags))

	// CHECKSIGVERIFY shares the path.
	spkV := []byte{OP_0, OP_0, OP_CHECKSIGVERIFY}
	r3csWant(t, "bare 0 0 CHECKSIGVERIFY at STRICTENC", r3csRunBare(nil, spkV, r3csPolicyFlags), ErrCodePubKeyType)
	// At block flags the verify fails (the verdict is what this item pins;
	// blockbrew labels it SCRIPT_ERR_VERIFY where Core says
	// SCRIPT_ERR_CHECKSIGVERIFY, a separate pre-existing difference).
	if err := r3csRunBare(nil, spkV, r3csBlockFlags); err == nil {
		t.Fatalf("bare 0 0 CHECKSIGVERIFY at block flags: accepted, Core fails the verify")
	}
}

// Empty sig with a hybrid (0x06) key: PUBKEYTYPE under STRICTENC.
func TestR3FixChecksigEmptySigHybridPubKeyStrictEnc(t *testing.T) {
	pk := r3csKey().PubKey().SerializeUncompressed()
	hybrid := append([]byte{0x06 | (pk[64] & 1)}, pk[1:]...)
	spk := append(append([]byte{OP_0}, r3csPush(hybrid)...), OP_CHECKSIG, OP_NOT)
	r3csWant(t, "empty sig + hybrid key at STRICTENC", r3csRunBare(nil, spk, r3csPolicyFlags), ErrCodePubKeyType)
	r3csWantOK(t, "empty sig + hybrid key at block flags", r3csRunBare(nil, spk, r3csBlockFlags))
}

// Empty sig with an uncompressed key in witness v0: WITNESS_PUBKEYTYPE.
func TestR3FixChecksigEmptySigUncompressedWitnessV0(t *testing.T) {
	pk := r3csKey().PubKey().SerializeUncompressed()
	ws := append(append([]byte{OP_0}, r3csPush(pk)...), OP_CHECKSIG, OP_NOT)
	r3csWant(t, "P2WSH empty sig + uncompressed key", r3csRunP2WSH(nil, ws, r3csPolicyFlags), ErrCodeWitnessPubKeyType)
	r3csWantOK(t, "P2WSH empty sig + uncompressed key at block flags", r3csRunP2WSH(nil, ws, r3csBlockFlags))
}

// Non-empty sig with an EMPTY key: Core's STRICTENC key check fires before
// verification (PUBKEYTYPE). blockbrew skipped it for an empty key and
// reported NULLFAIL.
func TestR3FixChecksigNonEmptySigEmptyPubKeyStrictEnc(t *testing.T) {
	sig := r3csWellFormedSig(t)
	spk := append(r3csPush(sig), OP_0, OP_CHECKSIG, OP_NOT)
	r3csWant(t, "sig + empty key at STRICTENC|NULLFAIL", r3csRunBare(nil, spk, r3csPolicyFlags), ErrCodePubKeyType)
	r3csWantOK(t, "sig + empty key at block flags", r3csRunBare(nil, spk, r3csBlockFlags))
}

// CONST_SCRIPTCODE: FindAndDelete runs FIRST, for an empty sig too.
func TestR3FixChecksigFindAndDeleteBeforeEncodingChecks(t *testing.T) {
	cs := r3csPolicyFlags | ScriptVerifyConstScriptCode

	// Empty sig + empty key in a script holding OP_0: Core says
	// SIG_FINDANDDELETE (not PUBKEYTYPE, not success).
	spk := []byte{OP_0, OP_0, OP_CHECKSIG, OP_DROP, OP_1}
	r3csWant(t, "0 0 CHECKSIG at CONST_SCRIPTCODE", r3csRunBare(nil, spk, cs), ErrCodeSigFindAndDelete)

	// Non-DER sig that appears in the scriptCode: SIG_FINDANDDELETE before
	// SIG_DER.
	bad := []byte{0x30, 0x01, 0x01}
	pk := r3csKey().PubKey().SerializeCompressed()
	spk2 := append(append(append(r3csPush(bad), OP_DROP), r3csPush(pk)...), OP_CHECKSIG, OP_NOT)
	r3csWant(t, "bad-DER sig in scriptCode at CONST_SCRIPTCODE", r3csRunBare(r3csPush(bad), spk2, cs), ErrCodeSigFindAndDelete)
	r3csWant(t, "bad-DER sig in scriptCode without CONST_SCRIPTCODE", r3csRunBare(r3csPush(bad), spk2, r3csPolicyFlags), ErrCodeSigDER)

	// Well-formed sig in the scriptCode with a hybrid (0x06/0x07) key:
	// SIG_FINDANDDELETE before PUBKEYTYPE.
	sig := r3csWellFormedSig(t)
	unc := r3csKey().PubKey().SerializeUncompressed()
	hybrid := append([]byte{0x06 | (unc[64] & 1)}, unc[1:]...)
	spk3 := append(append(append(r3csPush(sig), OP_DROP), r3csPush(hybrid)...), OP_CHECKSIG, OP_NOT)
	r3csWant(t, "sig in scriptCode + hybrid key at CONST_SCRIPTCODE", r3csRunBare(r3csPush(sig), spk3, cs), ErrCodeSigFindAndDelete)
	r3csWant(t, "sig in scriptCode + hybrid key without CONST_SCRIPTCODE", r3csRunBare(r3csPush(sig), spk3, r3csPolicyFlags), ErrCodePubKeyType)

	// Witness v0 has no FindAndDelete: the same OP_0-bearing script gives
	// PUBKEYTYPE, not SIG_FINDANDDELETE.
	ws := []byte{OP_0, OP_0, OP_CHECKSIG, OP_DROP, OP_1}
	r3csWant(t, "P2WSH 0 0 CHECKSIG at CONST_SCRIPTCODE", r3csRunP2WSH(nil, ws, cs), ErrCodePubKeyType)
}

// Controls: an empty sig with a valid compressed key is just a failed check
// (no NULLFAIL); a real signature still verifies at full policy flags.
func TestR3FixChecksigControls(t *testing.T) {
	k := r3csKey()
	pk := k.PubKey().SerializeCompressed()
	spk := append(append([]byte{OP_0}, r3csPush(pk)...), OP_CHECKSIG, OP_NOT)
	r3csWantOK(t, "empty sig + compressed key at policy flags", r3csRunBare(nil, spk, r3csPolicyFlags))
	r3csWantOK(t, "empty sig + compressed key at block flags", r3csRunBare(nil, spk, r3csBlockFlags))
	ws := append(append([]byte{OP_0}, r3csPush(pk)...), OP_CHECKSIG, OP_NOT)
	r3csWantOK(t, "P2WSH empty sig + compressed key at policy flags", r3csRunP2WSH(nil, ws, r3csPolicyFlags))

	// Valid P2PK spend at policy flags + CONST_SCRIPTCODE.
	p2pk := append(r3csPush(pk), OP_CHECKSIG)
	tx := r3csTx()
	h, err := CalcSignatureHash(p2pk, SigHashAll, tx, 0)
	if err != nil {
		t.Fatal(err)
	}
	der, err := crypto.SignECDSA(k, h)
	if err != nil {
		t.Fatal(err)
	}
	ss := r3csPush(append(der, byte(SigHashAll)))
	tx.TxIn[0].SignatureScript = ss
	prev := []*wire.TxOut{{Value: 2000, PkScript: p2pk}}
	flags := r3csPolicyFlags | ScriptVerifyConstScriptCode | ScriptVerifyLowS
	if err := VerifyScript(ss, p2pk, tx, 0, flags, 2000, prev); err != nil {
		t.Fatalf("valid P2PK spend rejected: %v", err)
	}
	// And a wrong-key signature is NULLFAIL, as before.
	other := crypto.PrivateKeyFromBytes(append(make([]byte, 31), 9)).PubKey().SerializeCompressed()
	p2pk2 := append(r3csPush(other), OP_CHECKSIG)
	prev2 := []*wire.TxOut{{Value: 2000, PkScript: p2pk2}}
	if c, _ := ErrorCodeOf(VerifyScript(ss, p2pk2, tx, 0, flags, 2000, prev2)); c != ErrCodeSigNullFail {
		t.Fatalf("wrong-key signature: want NULLFAIL, got %v", c)
	}
}
