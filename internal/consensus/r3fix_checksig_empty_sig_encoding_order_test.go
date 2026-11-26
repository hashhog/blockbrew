package consensus

// r3fix-blockbrew-checksig-empty-sig-encoding-order: the R3 night-1
// (seed 739943) minimised cases, byte for byte, checked at the flags the
// mempool uses (GetStandardScriptFlags) and at block flags.
//
//   R113 mempool/verdict/script-policy/PUBKEYTYPE|accept
//        P2WSH witnessScript = (0 0 CHECKSIG DROP) x5, 1
//   R114 mempool/verdict/script-policy/SIG_FINDANDDELETE|accept
//        P2SH redeemScript = 0 0 CHECKSIG DROP, scriptSig = 1 <redeem>
//
// Core v31.1 rejects both at STANDARD_SCRIPT_VERIFY_FLAGS: R113 with
// PUBKEYTYPE (CheckPubKeyEncoding of the empty key, interpreter.cpp:218-221),
// R114 with SIG_FINDANDDELETE (the empty sig is pushed as OP_0 and found in
// the scriptCode, interpreter.cpp:328-332). R114's SIG_FINDANDDELETE needs
// CONST_SCRIPTCODE in the mempool flags (sibling item
// r3fix-blockbrew-mempool-standard-script-flags); without it Core's
// interpreter reaches PUBKEYTYPE, so the expected code follows the flags.
// Both are consensus-valid: at block flags an empty signature only pushes
// false.

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/script"
	"github.com/hashhog/blockbrew/internal/wire"
)

const (
	r3csR113Hex = "020000000001013aab3bf46ea593fbf59d1afefdf56f28abd38556f72389055f10a9e84d6519b90000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326001150000ac750000ac750000ac750000ac750000ac755100000000"
	r3csR114Hex = "0200000001afa93e064abbb7d0d774cc8358c60c84689b23297a57c7e0826ce16a1a500d9b000000000651040000ac75feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"
)

func r3csDecode(t *testing.T, h string) *wire.MsgTx {
	t.Helper()
	raw, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	return tx
}

func r3csFlags() (policy, block script.ScriptFlags) {
	p := RegtestParams()
	var zero wire.Hash256
	return GetStandardScriptFlags(200, p, zero), GetBlockScriptFlags(200, p, zero)
}

func r3csVerify(tx *wire.MsgTx, spk []byte, flags script.ScriptFlags) error {
	prev := []*wire.TxOut{{Value: 100000, PkScript: spk}}
	return script.VerifyScript(tx.TxIn[0].SignatureScript, spk, tx, 0, flags, 100000, prev)
}

func TestR3FixChecksigMinimisedR113P2WSHPubKeyType(t *testing.T) {
	tx := r3csDecode(t, r3csR113Hex)
	wit := tx.TxIn[0].Witness
	if len(tx.TxIn) != 1 || len(wit) != 1 || len(tx.TxIn[0].SignatureScript) != 0 {
		t.Fatalf("fixture: unexpected shape")
	}
	ws := wit[0]
	want := []byte{0x00, 0x00, 0xac, 0x75}
	if len(ws) != 21 || !bytes.Equal(ws[:4], want) || ws[20] != 0x51 {
		t.Fatalf("fixture: witnessScript %x", ws)
	}
	h := crypto.SHA256Hash(ws)
	spk := append([]byte{0x00, 0x20}, h[:]...)

	policy, block := r3csFlags()
	err := r3csVerify(tx, spk, policy)
	if c, ok := script.ErrorCodeOf(err); err == nil || !ok || c != script.ErrCodePubKeyType {
		t.Fatalf("R113 at mempool flags: got %v; Core v31.1 rejects with SCRIPT_ERR_PUBKEYTYPE (Public key is neither compressed or uncompressed)", err)
	}
	if err := r3csVerify(tx, spk, block); err != nil {
		t.Fatalf("R113 at block flags: %v; consensus-valid in Core", err)
	}
}

func TestR3FixChecksigMinimisedR114P2SHEmptySig(t *testing.T) {
	tx := r3csDecode(t, r3csR114Hex)
	ss := tx.TxIn[0].SignatureScript
	redeem := []byte{0x00, 0x00, 0xac, 0x75}
	if !bytes.Equal(ss, append([]byte{0x51, 0x04}, redeem...)) {
		t.Fatalf("fixture: scriptSig %x", ss)
	}
	h := crypto.Hash160(redeem)
	spk := append(append([]byte{0xa9, 0x14}, h[:]...), 0x87)

	policy, block := r3csFlags()
	want := script.ErrCodePubKeyType
	if policy&script.ScriptVerifyConstScriptCode != 0 {
		want = script.ErrCodeSigFindAndDelete
	}
	err := r3csVerify(tx, spk, policy)
	if c, ok := script.ErrorCodeOf(err); err == nil || !ok || c != want {
		t.Fatalf("R114 at mempool flags: got %v; Core's interpreter at these flags: %s", err, want)
	}
	// At Core's full STANDARD_SCRIPT_VERIFY_FLAGS (CONST_SCRIPTCODE on) the
	// answer is SIG_FINDANDDELETE, whatever the mempool flags are today.
	err = r3csVerify(tx, spk, policy|script.ScriptVerifyConstScriptCode)
	if c, ok := script.ErrorCodeOf(err); err == nil || !ok || c != script.ErrCodeSigFindAndDelete {
		t.Fatalf("R114 with CONST_SCRIPTCODE: got %v; Core SCRIPT_ERR_SIG_FINDANDDELETE", err)
	}
	if err := r3csVerify(tx, spk, block); err != nil {
		t.Fatalf("R114 at block flags: %v; consensus-valid in Core", err)
	}
}
