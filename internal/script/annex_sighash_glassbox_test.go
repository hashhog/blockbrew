package script

// Glass-box wave 3 (2026-07-01) — HIGH consensus split:
// Tapscript (script-path) sighash omitted the annex commitment.
//
// Root cause: executeTaprootScriptPath received the annex but only used it for
// the BIP-342 weight budget; it never threaded the annex hash into the sighash.
// OP_CHECKSIG/VERIFY and OP_CHECKSIGADD built TaprootSigHashOptions with
// AnnexHash=nil, so spend_type stayed 2 and sha_annex was omitted — diverging
// from Bitcoin Core (interpreter.cpp:1533-1545: spend_type=(ext_flag<<1)+have_annex,
// with execdata.m_annex_hash committed on BOTH key and script paths).
//
// EFFECTIVE test: a real P2TR script-path spend whose witness carries a
// 0x50-tagged annex, with a Schnorr signature that commits to the annex per
// BIP-341, must VERIFY (accept). Pre-fix the engine computes the sighash with
// spend_type=2 and no sha_annex -> a different message -> VerifySchnorr fails ->
// ErrTaprootSigVerify (REJECT). Post-fix it accepts, matching Core.
//
// The no-annex sub-case is a control: it must keep verifying (unchanged).

import (
	"bytes"
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// buildTapscriptSpend constructs a P2TR script-path spend of a single-leaf tree
// whose leaf is `<32-byte xonly> OP_CHECKSIG`. It returns the spending tx, the
// prevOuts, the witness (sig, script, control [, annex]) and the flags.
//
// The Schnorr signature is computed over the BIP-341 SigMsg using `withAnnex`
// to decide whether the annex is committed (spend_type bit0 + sha_annex).
func buildTapscriptAnnexSpend(t *testing.T, withAnnex bool) (*wire.MsgTx, []*wire.TxOut, [][]byte) {
	t.Helper()

	// CHECKSIG key inside the tapscript leaf.
	sigPrivBytes := make([]byte, 32)
	for i := range sigPrivBytes {
		sigPrivBytes[i] = 0x11
	}
	sigPriv := crypto.PrivateKeyFromBytes(sigPrivBytes)
	sigXOnly := sigPriv.PubKey().XOnlyPubKey() // 32 bytes

	// Tapscript leaf: push 32-byte xonly pubkey, then OP_CHECKSIG.
	leafScript := make([]byte, 0, 34)
	leafScript = append(leafScript, 0x20) // push 32 bytes
	leafScript = append(leafScript, sigXOnly...)
	leafScript = append(leafScript, OP_CHECKSIG)

	leafHash := TapLeaf(TaprootLeafTapscript, leafScript)

	// Internal (taproot) key for the output commitment — distinct from the
	// CHECKSIG key. Single-leaf tree, so merkle root == leaf hash.
	intPrivBytes := make([]byte, 32)
	for i := range intPrivBytes {
		intPrivBytes[i] = 0x22
	}
	intPriv := crypto.PrivateKeyFromBytes(intPrivBytes)
	internalKey := intPriv.PubKey().XOnlyPubKey()

	tweak := TapTweak(internalKey, leafHash[:])
	outputKey, parity := crypto.ComputeTaprootOutputKey(internalKey, tweak)
	if outputKey == nil {
		t.Fatal("ComputeTaprootOutputKey returned nil")
	}

	// Control block: [leafVersion | parity] [internalKey], no path nodes.
	control := make([]byte, 0, TaprootControlBaseSize)
	control = append(control, TaprootLeafTapscript|parity)
	control = append(control, internalKey...)

	// prevOut scriptPubKey = OP_1 <32-byte output key>.
	pkScript := append([]byte{OP_1, 0x20}, outputKey...)
	prevOuts := []*wire.TxOut{{Value: 100_000, PkScript: pkScript}}

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: wire.Hash256{0x01}, Index: 0},
			SignatureScript:  nil,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:    90_000,
			PkScript: []byte{OP_TRUE},
		}},
		LockTime: 0,
	}

	// Compute the BIP-341 SigMsg exactly as the engine will (codesepPos is reset
	// to 0xFFFFFFFF at the top of the script-path execution).
	opts := &TaprootSigHashOptions{
		TapLeafHash: &leafHash,
		KeyVersion:  0,
		CodeSepPos:  0xFFFFFFFF,
	}
	var annex []byte
	if withAnnex {
		annex = []byte{AnnexTag, 0xDE, 0xAD, 0xBE, 0xEF}
		var annexBuf bytes.Buffer
		wire.WriteVarBytes(&annexBuf, annex)
		annexHash := crypto.SHA256Hash(annexBuf.Bytes())
		opts.AnnexHash = &annexHash
	}

	sighash, err := CalcTaprootSignatureHash(SigHashDefault, tx, 0, prevOuts, opts)
	if err != nil {
		t.Fatalf("CalcTaprootSignatureHash: %v", err)
	}
	sig, err := crypto.SignSchnorr(sigPriv, sighash)
	if err != nil {
		t.Fatalf("SignSchnorr: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("expected 64-byte SIGHASH_DEFAULT sig, got %d", len(sig))
	}

	// Witness = [sig, leafScript, control (, annex)].
	witness := [][]byte{sig, leafScript, control}
	if withAnnex {
		witness = append(witness, annex)
	}
	return tx, prevOuts, witness
}

func TestGlassboxW3_TapscriptAnnexCommitment_AnnexSpendVerifies(t *testing.T) {
	// The signer committed to the annex (spend_type=3, sha_annex present).
	// Post-fix the engine threads the annex hash into the CHECKSIG sighash and
	// this spend VERIFIES. Pre-fix the engine built the sighash with
	// AnnexHash=nil (spend_type=2, no sha_annex), producing a different message
	// and ErrTaprootSigVerify.
	tx, prevOuts, witness := buildTapscriptAnnexSpend(t, true)

	program := prevOuts[0].PkScript[2:] // strip OP_1 0x20
	eng, err := NewEngine(prevOuts[0].PkScript, tx, 0, ScriptVerifyWitness|ScriptVerifyTaproot, prevOuts[0].Value, prevOuts)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := eng.executeTaproot(program, witness); err != nil {
		t.Fatalf("annex-committing tapscript spend must VERIFY (Core accepts); got %v", err)
	}
}

func TestGlassboxW3_TapscriptAnnexCommitment_NoAnnexUnchanged(t *testing.T) {
	// Control: a spend with no annex signs spend_type=2 (no sha_annex) and must
	// keep verifying, unchanged by the fix.
	tx, prevOuts, witness := buildTapscriptAnnexSpend(t, false)

	program := prevOuts[0].PkScript[2:]
	eng, err := NewEngine(prevOuts[0].PkScript, tx, 0, ScriptVerifyWitness|ScriptVerifyTaproot, prevOuts[0].Value, prevOuts)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := eng.executeTaproot(program, witness); err != nil {
		t.Fatalf("no-annex tapscript spend must VERIFY; got %v", err)
	}
}

func TestGlassboxW3_TapscriptAnnexCommitment_MismatchStillRejects(t *testing.T) {
	// Negative control: sign committing to the annex, but strip the annex from
	// the witness at verification time. The engine then computes spend_type=2
	// (no sha_annex) while the signature committed to spend_type=3 -> the
	// messages differ -> the spend MUST be rejected. Guards against a fix that
	// unconditionally forces the annex path.
	tx, prevOuts, witness := buildTapscriptAnnexSpend(t, true)
	witness = witness[:len(witness)-1] // drop the annex element

	program := prevOuts[0].PkScript[2:]
	eng, err := NewEngine(prevOuts[0].PkScript, tx, 0, ScriptVerifyWitness|ScriptVerifyTaproot, prevOuts[0].Value, prevOuts)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := eng.executeTaproot(program, witness); err == nil {
		t.Fatal("annex-committing sig verified WITHOUT the annex in the witness; must reject")
	}
}
