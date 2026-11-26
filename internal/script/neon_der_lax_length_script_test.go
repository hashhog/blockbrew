package script

// verify-neon-blockbrew-findings, audit finding 3, at the script level: a
// pre-BIP66 CHECKSIG (no DERSIG/LOW_S/STRICTENC) verifies through Core's lax
// DER parser, which accepts a long-form R length written with leading zero
// length bytes (0x85 00 00 00 00 20). With DERSIG the same signature is
// SCRIPT_ERR_SIG_DER in Core and blockbrew alike.

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

func neonLaxDERScriptCase(t *testing.T) (spk []byte, tx *wire.MsgTx, prev []*wire.TxOut) {
	t.Helper()
	priv := crypto.PrivateKeyFromBytes(append(make([]byte, 31), 0x0b))
	pub := priv.PubKey().SerializeCompressed()
	spk = append(canonicalPushScript(pub), OP_CHECKSIG)
	tx = &wire.MsgTx{
		Version:  1,
		TxIn:     []*wire.TxIn{{Sequence: 0xffffffff}},
		TxOut:    []*wire.TxOut{{Value: 1000, PkScript: []byte{OP_TRUE}}},
		LockTime: 0,
	}
	h, err := CalcSignatureHash(spk, SigHashAll, tx, 0)
	if err != nil {
		t.Fatal(err)
	}
	der, err := crypto.SignECDSA(priv, h)
	if err != nil {
		t.Fatal(err)
	}
	lr := int(der[3])
	r := der[4 : 4+lr]
	rest := der[4+lr:] // 0x02 <slen> S
	body := append([]byte{0x02, 0x85, 0, 0, 0, 0, byte(lr)}, r...)
	body = append(body, rest...)
	lax := append([]byte{0x30, byte(len(body))}, body...)
	lax = append(lax, byte(SigHashAll))
	tx.TxIn[0].SignatureScript = canonicalPushScript(lax)
	prev = []*wire.TxOut{{Value: 2000, PkScript: spk}}
	return spk, tx, prev
}

func TestNeonDERLaxLengthPreBIP66CheckSig(t *testing.T) {
	spk, tx, prev := neonLaxDERScriptCase(t)
	e, err := NewEngine(spk, tx, 0, ScriptVerifyP2SH, 2000, prev)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Execute(); err != nil {
		t.Fatalf("pre-BIP66 CHECKSIG with long-form zero-padded R length rejected: %v; Core's lax DER parser accepts", err)
	}
}

func TestNeonDERLaxLengthDERSigStillRejects(t *testing.T) {
	spk, tx, prev := neonLaxDERScriptCase(t)
	e, err := NewEngine(spk, tx, 0, ScriptVerifyP2SH|ScriptVerifyDERSig, 2000, prev)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := ErrorCodeOf(e.Execute()); c != ErrCodeSigDER {
		t.Fatalf("DERSIG: got %v, want SCRIPT_ERR_SIG_DER", c)
	}
}
