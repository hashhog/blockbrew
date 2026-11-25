package script

// verify-neon-blockbrew-findings, audit findings 5 and 8 (policy flags).
//
// Finding 5: Core EvalChecksigPreTapscript (script/interpreter.cpp:321-344)
// treats a public key that does not parse as a failed signature check and
// then applies NULLFAIL to the non-empty signature. blockbrew returned early
// with "false" when PublicKeyFromBytes failed (a 0x02-prefixed x that is not
// on the curve passes the STRICTENC shape check), skipping NULLFAIL, so its
// mempool admitted `<sig> <off-curve key> CHECKSIG NOT` that Core refuses
// (shown on regtest against Core 31.1: mempool-script-verify-flag-failed
// "Signature must be zero for failed CHECK(MULTI)SIG operation").
//
// Finding 8: Core IsLowDERSignature -> CPubKey::CheckLowS parses with
// ecdsa_signature_parse_der_lax, which zeroes the signature when R or S is
// >= the group order N; normalize then reports "not high", so LOW_S passes.
// blockbrew compared the raw S against N/2 and answered SIG_HIGH_S.

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

var neonCurveN = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
	0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
	0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
}

// Core STANDARD_SCRIPT_VERIFY_FLAGS subset relevant to CHECKSIG.
const neonCSPolicyFlags = ScriptVerifyP2SH | ScriptVerifyWitness | ScriptVerifyTaproot |
	ScriptVerifyDERSig | ScriptVerifyCLTV | ScriptVerifyCSV | ScriptVerifyNullDummy |
	ScriptVerifyStrictEncoding | ScriptVerifyLowS | ScriptVerifyNullFail | ScriptVerifyWitnessPubKeyType

func neonSub1(b []byte) []byte {
	out := append([]byte(nil), b...)
	for i := len(out) - 1; i >= 0; i-- {
		if out[i] > 0 {
			out[i]--
			break
		}
		out[i] = 0xff
	}
	return out
}

// neonDERInt is the strict-DER integer body of a big-endian value.
func neonDERInt(v []byte) []byte {
	for len(v) > 1 && v[0] == 0 && v[1] < 0x80 {
		v = v[1:]
	}
	if v[0]&0x80 != 0 {
		v = append([]byte{0}, v...)
	}
	return append([]byte{0x02, byte(len(v))}, v...)
}

func neonSig(r, s []byte, hashType byte) []byte {
	body := append(neonDERInt(r), neonDERInt(s)...)
	return append(append([]byte{0x30, byte(len(body))}, body...), hashType)
}

func neonCSRun(t *testing.T, sig, pub []byte, flags ScriptFlags) error {
	t.Helper()
	spk := append(canonicalPushScript(pub), OP_CHECKSIG, OP_NOT)
	tx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{SignatureScript: canonicalPushScript(sig), Sequence: 0xffffffff}},
		TxOut:   []*wire.TxOut{{Value: 1000, PkScript: []byte{OP_TRUE}}},
	}
	e, err := NewEngine(spk, tx, 0, flags, 2000, []*wire.TxOut{{Value: 2000, PkScript: spk}})
	if err != nil {
		t.Fatal(err)
	}
	return e.Execute()
}

// A strict-DER, low-S, SIGHASH_ALL signature (it does not verify anything).
func neonSomeSig(t *testing.T) []byte {
	t.Helper()
	priv := crypto.PrivateKeyFromBytes(append(make([]byte, 31), 0x21))
	der, err := crypto.SignECDSA(priv, [32]byte{0x11})
	if err != nil {
		t.Fatal(err)
	}
	return append(der, byte(SigHashAll))
}

func neonOffCurveKey() []byte {
	// x = p (the field prime): not a valid x coordinate.
	p := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
	}
	return append([]byte{0x02}, p...)
}

func TestNeonCheckSigOffCurveKeyNullFail(t *testing.T) {
	sig, key := neonSomeSig(t), neonOffCurveKey()
	if !IsCompressedOrUncompressedPubKey(key) {
		t.Fatalf("fixture: key must pass the STRICTENC shape check")
	}
	if _, err := crypto.PublicKeyFromBytes(key); err == nil {
		t.Fatalf("fixture: key must not parse")
	}
	err := neonCSRun(t, sig, key, neonCSPolicyFlags)
	if c, _ := ErrorCodeOf(err); c != ErrCodeSigNullFail {
		t.Fatalf("<sig> <off-curve key> CHECKSIG NOT under policy flags: got %v, Core SCRIPT_ERR_SIG_NULLFAIL", err)
	}
}

func TestNeonCheckSigOffCurveKeyControls(t *testing.T) {
	sig, key := neonSomeSig(t), neonOffCurveKey()
	// Without NULLFAIL (block flags) the check just fails and OP_NOT succeeds.
	if err := neonCSRun(t, sig, key, neonCSPolicyFlags&^ScriptVerifyNullFail); err != nil {
		t.Fatalf("off-curve key without NULLFAIL: %v, Core accepts", err)
	}
	// An empty signature with the off-curve key is not NULLFAIL.
	if err := neonCSRun(t, nil, key, neonCSPolicyFlags); err != nil {
		t.Fatalf("empty sig, off-curve key: %v, Core accepts", err)
	}
	// A valid key with a non-verifying signature: NULLFAIL as before.
	pub := crypto.PrivateKeyFromBytes(append(make([]byte, 31), 0x22)).PubKey().SerializeCompressed()
	if c, _ := ErrorCodeOf(neonCSRun(t, sig, pub, neonCSPolicyFlags)); c != ErrCodeSigNullFail {
		t.Fatalf("valid key, wrong sig: got %v, want NULLFAIL", c)
	}
}

func TestNeonIsLowSOverflowingRSPasses(t *testing.T) {
	one := []byte{0x01}
	cases := []struct {
		name string
		r, s []byte
		want bool
	}{
		{"R=1,S=N (S overflows)", one, neonCurveN, true},
		{"R=N,S=N-1 (R overflows, S high)", neonCurveN, neonSub1(neonCurveN), true},
		{"R=1,S=0xff..ff (S overflows)", one, bytes.Repeat([]byte{0xff}, 32), true},
		{"R=1,S=N-1 (high, in range)", one, neonSub1(neonCurveN), false},
		{"R=1,S=1 (low)", one, one, true},
	}
	for _, c := range cases {
		if got := IsLowSSignature(neonSig(c.r, c.s, byte(SigHashAll))); got != c.want {
			t.Errorf("IsLowSSignature(%s) = %v, Core CheckLowS = %v", c.name, got, c.want)
		}
	}
}

// Script level: LOW_S without NULLFAIL accepts (the zeroed signature fails
// verification, OP_NOT); with NULLFAIL Core fails NULLFAIL, not HIGH_S.
func TestNeonCheckSigLowSOverflowScript(t *testing.T) {
	pub := crypto.PrivateKeyFromBytes(append(make([]byte, 31), 0x23)).PubKey().SerializeCompressed()
	sig := neonSig([]byte{0x01}, neonCurveN, byte(SigHashAll))
	if err := neonCSRun(t, sig, pub, neonCSPolicyFlags&^ScriptVerifyNullFail); err != nil {
		t.Fatalf("LOW_S without NULLFAIL, S=N: got %v, Core accepts", err)
	}
	if c, _ := ErrorCodeOf(neonCSRun(t, sig, pub, neonCSPolicyFlags)); c != ErrCodeSigNullFail {
		t.Fatalf("LOW_S+NULLFAIL, S=N: got %v, Core SCRIPT_ERR_SIG_NULLFAIL", c)
	}
	// Control: a genuinely high S in range is still SIG_HIGH_S.
	high := neonSig([]byte{0x01}, neonSub1(neonCurveN), byte(SigHashAll))
	if c, _ := ErrorCodeOf(neonCSRun(t, high, pub, neonCSPolicyFlags)); c != ErrCodeSigHighS {
		t.Fatalf("S=N-1: got %v, want SIG_HIGH_S", c)
	}
}
