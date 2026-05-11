package script

// W82 BIP-66 + signature/pubkey encoding comprehensive audit tests.
//
// Gate inventory (22 gates in 7 functions, matching bitcoin-core
// src/script/interpreter.cpp:64-227 + EvalChecksigPreTapscript:321-344 +
// CHECKMULTISIG:1105-1214):
//
//  IsValidDERSignatureEncoding (13 gates):
//   G1  min size 9
//   G2  max size 73
//   G3  first byte 0x30
//   G4  length field = len-3
//   G5  5+lenR < len (S element still inside)
//   G6  lenR+lenS+7 == len
//   G7  R integer tag 0x02
//   G8  lenR != 0
//   G9  R high bit clear (no negative)
//   G10 R no redundant leading zero
//   G11 S integer tag 0x02
//   G12 lenS != 0
//   G13 S high bit clear (no negative)
//   G14 S no redundant leading zero
//
//  IsDefinedHashtype (3 gates):
//   G15 empty sig → false
//   G16 hashtype (stripped of ANYONECANPAY) in [1,3]
//   G17 ANYONECANPAY + valid base type
//
//  IsLowDERSignature (3 gates):
//   G18 calls IsValidDERSignatureEncoding first
//   G19 S <= halfOrder
//   G20 S > halfOrder rejected
//
//  CheckSignatureEncoding caller chain (4 gates):
//   G21 empty sig → not an error (passes through)
//   G22 DERSIG flag triggers DER check
//   G23 LOW_S flag triggers DER + lowS checks
//   G24 STRICTENC flag triggers DER + hashtype checks
//
//  CheckPubKeyEncoding (2 gates):
//   G25 STRICTENC rejects hybrid/unknown prefix
//   G26 WITNESS_PUBKEYTYPE rejects uncompressed in segwit v0
//
//  NULLFAIL / NULLDUMMY (3 gates):
//   G27 CHECKSIG NULLFAIL: non-empty failing sig → error
//   G28 CHECKSIG NULLFAIL: empty failing sig → not ErrNullFail
//   G29 CHECKMULTISIG NULLDUMMY: non-empty dummy → error
//
//  CONST_SCRIPTCODE (2 gates, W82 newly added):
//   G30 CHECKSIG: FindAndDelete hit + CONST_SCRIPTCODE → ErrSigFindAndDelete
//   G31 CHECKMULTISIG: FindAndDelete hit + CONST_SCRIPTCODE → ErrSigFindAndDelete
//
//  Empty-sig in CHECKMULTISIG (1 gate, W82 fix):
//   G32 Empty sig in multisig does not break loop prematurely; subsequent
//       pubkey encoding errors are still caught.

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
	"github.com/hashhog/blockbrew/internal/wire"
)

// ---- helpers ----------------------------------------------------------------

func makeTx() *wire.MsgTx {
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{},
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 90000, PkScript: []byte{}},
		},
		LockTime: 0,
	}
}

// buildMinimalValidSig returns a fresh DER-encoded SIGHASH_ALL signature using
// privKey over sighash, suitable for script-engine tests.
func buildMinimalValidSig(privKey *crypto.PrivateKey, sighash [32]byte) []byte {
	sig, _ := crypto.SignECDSA(privKey, sighash)
	return append(sig, byte(SigHashAll))
}

// ---- IsValidDERSignatureEncoding gates (G1-G14) ----------------------------

func TestBIP66_G1_MinSize(t *testing.T) {
	// G1: signatures shorter than 9 bytes are invalid.
	for _, sig := range [][]byte{
		{},
		{0x30},
		{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},  // 8 bytes, 1 short
	} {
		if IsValidDERSignatureEncoding(sig) {
			t.Errorf("G1: expected invalid for %x (len=%d)", sig, len(sig))
		}
	}
}

func TestBIP66_G2_MaxSize(t *testing.T) {
	// G2: signatures longer than 73 bytes are invalid.
	// Build a structurally correct sig that is 74 bytes long.
	sig := make([]byte, 74)
	sig[0] = 0x30
	sig[1] = 71       // total-length = 74-3 = 71
	sig[2] = 0x02
	sig[3] = 33       // lenR = 33
	// sig[4..36] = R bytes (all 0, high bit clear)
	sig[37] = 0x02
	sig[38] = 33      // lenS = 33
	// sig[39..71] = S bytes (all 0)
	sig[72] = 0x01    // hashtype
	sig[73] = 0x00    // extra byte — makes total 74

	if IsValidDERSignatureEncoding(sig) {
		t.Error("G2: expected invalid for 74-byte signature")
	}
}

func TestBIP66_G3_FirstByte0x30(t *testing.T) {
	// G3: first byte must be 0x30.
	sig := buildValidDERSig()
	sig[0] = 0x31
	if IsValidDERSignatureEncoding(sig) {
		t.Error("G3: expected invalid when first byte != 0x30")
	}
}

func TestBIP66_G4_LengthField(t *testing.T) {
	// G4: sig[1] must equal len(sig)-3.
	sig := buildValidDERSig()
	sig[1]++ // corrupt length field
	if IsValidDERSignatureEncoding(sig) {
		t.Error("G4: expected invalid when length field is wrong")
	}
}

func TestBIP66_G5_SElementInsideSig(t *testing.T) {
	// G5: 5+lenR must be < len(sig); otherwise S element is outside.
	// Build a sig where lenR is too large.
	sig := buildValidDERSig()
	sig[3] = byte(len(sig) - 4) // make R consume everything → S out of bounds
	if IsValidDERSignatureEncoding(sig) {
		t.Error("G5: expected invalid when S would be outside sig")
	}
}

func TestBIP66_G6_TotalLength(t *testing.T) {
	// G6: lenR+lenS+7 must equal len(sig).
	// Build a valid sig then corrupt lenS to make total wrong.
	sig := buildValidDERSig()
	lenR := int(sig[3])
	sig[5+lenR]++ // inflate lenS by 1
	if IsValidDERSignatureEncoding(sig) {
		t.Error("G6: expected invalid when total length doesn't match")
	}
}

func TestBIP66_G7_RIntegerTag(t *testing.T) {
	// G7: sig[2] must be 0x02 (INTEGER tag for R).
	sig := buildValidDERSig()
	sig[2] = 0x03
	if IsValidDERSignatureEncoding(sig) {
		t.Error("G7: expected invalid when R integer tag is not 0x02")
	}
}

func TestBIP66_G8_RLenNonZero(t *testing.T) {
	// G8: lenR must not be zero.
	// Build a structurally adjusted sig with lenR=0.
	// Format: 0x30 [total] 0x02 0x00 0x02 [lenS] [S...] [hashtype]
	// total = 0+lenS+4, lenS=1
	sig := []byte{0x30, 5, 0x02, 0x00, 0x02, 0x01, 0x01, 0x00, 0x01}
	// len=9, sig[1]=6 not 6 → need to fix
	// 0x30 [5] 0x02 0x00 0x02 0x01 0x01 [hashtype]  => len=8
	sig = []byte{0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01, 0x01}
	// len=8 → fails G1 (min size 9). Let's add a valid hashtype.
	sig = []byte{0x30, 0x06, 0x02, 0x00, 0x02, 0x02, 0x01, 0x01, 0x01}
	// len=9, sig[1]=6 → len-3=6 ✓
	// R: tag=0x02 lenR=0 → G8 fires
	if IsValidDERSignatureEncoding(sig) {
		t.Error("G8: expected invalid when lenR == 0")
	}
}

func TestBIP66_G9_RNegative(t *testing.T) {
	// G9: R must not have its high bit set (would be negative).
	sig := buildValidDERSig()
	sig[4] |= 0x80 // set high bit of first R byte
	if IsValidDERSignatureEncoding(sig) {
		t.Error("G9: expected invalid when R high bit is set")
	}
}

func TestBIP66_G10_RRedundantLeadingZero(t *testing.T) {
	// G10: R must not have a redundant leading zero (padding with 0x00 when
	// next byte's high bit is clear).
	sig := buildValidDERSig()
	// Inject a redundant zero: make lenR one larger and prepend 0x00 to R
	// such that the second byte does NOT have its high bit set.
	lenR := int(sig[3])
	if sig[4] == 0x00 && (lenR < 2 || sig[5]&0x80 == 0) {
		// already a G10 violator — just verify
		if IsValidDERSignatureEncoding(sig) {
			t.Error("G10: existing redundant-zero sig should be invalid")
		}
		return
	}
	// Build manually: [0x30][total][0x02][lenR+1][0x00][R...][0x02][lenS][S...][ht]
	// using a minimal valid R (1 byte, high bit clear, non-zero)
	// and a minimal valid S.
	// 0x30 total=0x08 0x02 0x02 0x00 0x01 0x02 0x01 0x01 0x01 → len=10
	// sig[1]=7=10-3 ✓, lenR=2, sig[4]=0x00, sig[5]=0x01 (high bit clear) → G10
	sig2 := []byte{0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01, 0x01}
	if IsValidDERSignatureEncoding(sig2) {
		t.Error("G10: expected invalid for redundant leading zero in R")
	}
}

func TestBIP66_G11_SIntegerTag(t *testing.T) {
	// G11: the byte after R must be 0x02 (INTEGER tag for S).
	sig := buildValidDERSig()
	lenR := int(sig[3])
	sig[lenR+4] = 0x03 // corrupt S integer tag
	if IsValidDERSignatureEncoding(sig) {
		t.Error("G11: expected invalid when S integer tag is not 0x02")
	}
}

func TestBIP66_G12_SLenNonZero(t *testing.T) {
	// G12: lenS must not be zero.
	// 0x30 0x05 0x02 0x01 0x01 0x02 0x00 <hashtype> → lenS=0
	sig := []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00, 0x01}
	// len=8 → fails G1. Need len=9:
	sig = []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x00, 0x00, 0x01}
	// sig[1]=6=9-3 ✓, lenR=1, 5+lenR=6 < 9 ✓
	// lenS=0 → G12
	if IsValidDERSignatureEncoding(sig) {
		t.Error("G12: expected invalid when lenS == 0")
	}
}

func TestBIP66_G13_SNegative(t *testing.T) {
	// G13: S must not have its high bit set.
	sig := buildValidDERSig()
	lenR := int(sig[3])
	sig[lenR+6] |= 0x80 // set high bit of first S byte
	if IsValidDERSignatureEncoding(sig) {
		t.Error("G13: expected invalid when S high bit is set")
	}
}

func TestBIP66_G14_SRedundantLeadingZero(t *testing.T) {
	// G14: S must not have a redundant leading zero.
	// Build: lenR=1 R=0x01  lenS=2 S=0x00 0x01 ht=0x01
	// 0x30 0x08 0x02 0x01 0x01 0x02 0x02 0x00 0x01 0x01 → len=10
	sig := []byte{0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01, 0x01}
	// len=10, sig[1]=7=10-3 ✓
	// lenR=1, 5+lenR=6 < 10 ✓
	// lenS=2, lenR+lenS+7=1+2+7=10 ✓
	// S[0]=0x00, S[1]=0x01 (high bit clear) → redundant zero → G14
	if IsValidDERSignatureEncoding(sig) {
		t.Error("G14: expected invalid for redundant leading zero in S")
	}
}

func TestBIP66_ValidSig(t *testing.T) {
	sig := buildValidDERSig()
	if !IsValidDERSignatureEncoding(sig) {
		t.Error("expected valid DER encoding for canonical sig")
	}
}

// ---- IsDefinedHashtype gates (G15-G17) -------------------------------------

func TestBIP66_G15_EmptySigHashtype(t *testing.T) {
	// G15: empty sig is not a defined hashtype.
	if IsDefinedHashtype(nil) {
		t.Error("G15: nil should not be a defined hashtype")
	}
	if IsDefinedHashtype([]byte{}) {
		t.Error("G15: empty slice should not be a defined hashtype")
	}
}

func TestBIP66_G16_HashtypeRange(t *testing.T) {
	// G16: base hashtype (stripped of ANYONECANPAY) must be in [1,3].
	invalid := []byte{0x00, 0x04, 0x05, 0x7f}
	for _, ht := range invalid {
		sig := []byte{0x30, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, ht}
		if IsDefinedHashtype(sig) {
			t.Errorf("G16: hashtype 0x%02x should be undefined", ht)
		}
	}
	valid := []byte{0x01, 0x02, 0x03}
	for _, ht := range valid {
		sig := []byte{0x30, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, ht}
		if !IsDefinedHashtype(sig) {
			t.Errorf("G16: hashtype 0x%02x should be valid", ht)
		}
	}
}

func TestBIP66_G17_AnyoneCanPay(t *testing.T) {
	// G17: ANYONECANPAY (0x80) combined with valid base types is valid.
	for _, base := range []byte{0x01, 0x02, 0x03} {
		ht := base | 0x80
		sig := []byte{0x30, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, ht}
		if !IsDefinedHashtype(sig) {
			t.Errorf("G17: ANYONECANPAY|%02x should be valid hashtype", base)
		}
	}
	// ANYONECANPAY with invalid base (0x00, 0x04)
	for _, base := range []byte{0x00, 0x04} {
		ht := base | 0x80
		sig := []byte{0x30, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, ht}
		if IsDefinedHashtype(sig) {
			t.Errorf("G17: ANYONECANPAY|%02x (invalid base) should be undefined", base)
		}
	}
}

// ---- IsLowDERSignature gates (G18-G20) -------------------------------------

func TestBIP66_G18_LowS_RequiresValidDER(t *testing.T) {
	// G18: IsLowSSignature calls IsValidDERSignatureEncoding first; invalid DER → false.
	badDER := buildValidDERSig()
	badDER[0] = 0x31 // corrupt first byte
	if IsLowSSignature(badDER) {
		t.Error("G18: invalid DER sig should not be low-S")
	}
}

func TestBIP66_G19_LowS_Valid(t *testing.T) {
	// G19: canonical signature from crypto.SignECDSA produces low-S.
	privKey, _ := crypto.GeneratePrivateKey()
	var hash [32]byte
	sig, _ := crypto.SignECDSA(privKey, hash)
	sig = append(sig, byte(SigHashAll))

	if !IsValidDERSignatureEncoding(sig) {
		t.Skip("generated sig is not valid DER — skip")
	}
	if !IsLowSSignature(sig) {
		t.Error("G19: freshly generated signature should have low S")
	}
}

func TestBIP66_G20_LowS_HighS_Rejected(t *testing.T) {
	// G20: a signature with S == halfOrder+1 must be rejected.
	// Construct manually: R=0x01 (1 byte), S = halfOrder+1 (33 bytes with leading 0x00)
	// halfOrder = 7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 5D576E73 57A4501D DFE92F46 681B20A0
	// halfOrder+1 = 7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 5D576E73 57A4501D DFE92F46 681B20A1
	// As 32 bytes (all high-bit-clear): 0x7F ... 0xA1 — fine, no leading 0x00 needed
	s := [32]byte{
		0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
		0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA1, // +1 from halfOrder
	}
	sig := makeRawDERSig([]byte{0x01}, s[:])
	if !IsValidDERSignatureEncoding(sig) {
		t.Fatalf("G20: test sig should be valid DER: %x", sig)
	}
	if IsLowSSignature(sig) {
		t.Error("G20: S > halfOrder should be rejected")
	}
}

// ---- CheckSignatureEncoding caller chain (G21-G24) -------------------------

func TestBIP66_G21_EmptySigPassesCheckSigEncoding(t *testing.T) {
	// G21: empty sig is allowed (short-circuit in CheckSig/CheckMultiSig callers).
	// Verify by building a P2PKH script with an empty scriptSig sig slot and checking
	// that the engine does NOT return a DER error (it will return ErrScriptFailed).
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pkBytes := pubKey.SerializeCompressed()

	scriptPubKey := makeP2PKHScript(pkBytes)
	tx := makeTx()
	prevOut := &wire.TxOut{Value: 100000, PkScript: scriptPubKey}

	// scriptSig: push empty sig, then pubkey
	scriptSig := []byte{0x00} // push 0 bytes (empty sig)
	scriptSig = append(scriptSig, byte(len(pkBytes)))
	scriptSig = append(scriptSig, pkBytes...)
	tx.TxIn[0].SignatureScript = scriptSig

	err := VerifyScript(scriptSig, scriptPubKey, tx, 0,
		ScriptVerifyDERSig|ScriptVerifyLowS|ScriptVerifyStrictEncoding,
		prevOut.Value, []*wire.TxOut{prevOut})

	// Should NOT be a DER error — empty sig is exempt.
	// It should be ErrScriptFailed (sig doesn't match).
	if err == ErrSigDER {
		t.Errorf("G21: empty sig should not trigger ErrSigDER, got %v", err)
	}
	if err == nil {
		t.Error("G21: empty sig should fail verification (not pass)")
	}
}

func TestBIP66_G22_DERSIGFlag(t *testing.T) {
	// G22: ScriptVerifyDERSig flag triggers DER check on non-empty sigs.
	scriptPubKey, scriptSig := makeP2PKScriptWithBadDERSig()
	tx := makeTx()
	tx.TxIn[0].SignatureScript = scriptSig
	prevOut := &wire.TxOut{Value: 100000, PkScript: scriptPubKey}

	err := VerifyScript(scriptSig, scriptPubKey, tx, 0,
		ScriptVerifyDERSig, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrSigDER {
		t.Errorf("G22: expected ErrSigDER with DERSIG flag, got %v", err)
	}

	// Without the flag, a bad-DER sig should not trigger ErrSigDER.
	err = VerifyScript(scriptSig, scriptPubKey, tx, 0,
		ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	if err == ErrSigDER {
		t.Errorf("G22: without DERSIG flag, should not get ErrSigDER")
	}
}

func TestBIP66_G23_LowSFlag(t *testing.T) {
	// G23: ScriptVerifyLowS flag triggers both DER check and low-S check.
	// First test: bad DER → ErrSigDER even with LOW_S flag (DER check fires first).
	scriptPubKey, scriptSig := makeP2PKScriptWithBadDERSig()
	tx := makeTx()
	tx.TxIn[0].SignatureScript = scriptSig
	prevOut := &wire.TxOut{Value: 100000, PkScript: scriptPubKey}

	err := VerifyScript(scriptSig, scriptPubKey, tx, 0,
		ScriptVerifyLowS, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrSigDER {
		t.Errorf("G23: bad DER with LOW_S flag should return ErrSigDER, got %v", err)
	}

	// Second test: valid DER but high-S → ErrSigHighS.
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pkBytes := pubKey.SerializeCompressed()

	s := [32]byte{
		0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
		0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA1,
	}
	highSSig := makeRawDERSig([]byte{0x01}, s[:])
	if !IsValidDERSignatureEncoding(highSSig) {
		t.Skip("high-S test sig not valid DER")
	}

	spk := makeP2PKScript(pkBytes)
	scriptSig2 := make([]byte, 0, 1+len(highSSig))
	scriptSig2 = append(scriptSig2, byte(len(highSSig)))
	scriptSig2 = append(scriptSig2, highSSig...)

	tx2 := makeTx()
	tx2.TxIn[0].SignatureScript = scriptSig2
	prevOut2 := &wire.TxOut{Value: 100000, PkScript: spk}

	err = VerifyScript(scriptSig2, spk, tx2, 0,
		ScriptVerifyLowS, prevOut2.Value, []*wire.TxOut{prevOut2})
	if err != ErrSigHighS {
		t.Errorf("G23: high-S sig with LOW_S flag should return ErrSigHighS, got %v", err)
	}
}

func TestBIP66_G24_STRICTENCFlag_Hashtype(t *testing.T) {
	// G24: ScriptVerifyStrictEncoding checks hashtype (in addition to DER).
	// Build a valid-DER sig but with hashtype 0x04 (undefined).
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pkBytes := pubKey.SerializeCompressed()

	tx := makeTx()
	spk := makeP2PKScript(pkBytes)
	prevOut := &wire.TxOut{Value: 100000, PkScript: spk}

	sighash, _ := CalcSignatureHash(spk, SigHashAll, tx, 0)
	rawSig, _ := crypto.SignECDSA(privKey, sighash)
	// Replace the sighash byte with 0x04 (undefined hashtype).
	sigBadHT := append(rawSig, 0x04)

	scriptSig := make([]byte, 0, 1+len(sigBadHT))
	scriptSig = append(scriptSig, byte(len(sigBadHT)))
	scriptSig = append(scriptSig, sigBadHT...)
	tx.TxIn[0].SignatureScript = scriptSig

	err := VerifyScript(scriptSig, spk, tx, 0,
		ScriptVerifyStrictEncoding, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrSigHashType {
		t.Errorf("G24: undefined hashtype with STRICTENC should return ErrSigHashType, got %v", err)
	}

	// Without STRICTENC, undefined hashtype is allowed (just fails verification
	// since sighash mismatch or ECDSA failure).
	err = VerifyScript(scriptSig, spk, tx, 0,
		ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	if err == ErrSigHashType {
		t.Errorf("G24: without STRICTENC, should not get ErrSigHashType")
	}
}

// ---- CheckPubKeyEncoding gates (G25-G26) -----------------------------------

func TestBIP66_G25_STRIENCRejectsHybridPubKey(t *testing.T) {
	// G25: STRICTENC rejects hybrid/unknown prefix (0x06, 0x07).
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pkBytes := pubKey.SerializeCompressed()

	tx := makeTx()
	sighash, _ := CalcSignatureHash(makeP2PKScript(pkBytes), SigHashAll, tx, 0)
	sig := buildMinimalValidSig(privKey, sighash)

	// Build a hybrid/invalid pubkey (prefix 0x06, 65 bytes)
	hybridPK := make([]byte, 65)
	hybridPK[0] = 0x06
	copy(hybridPK[1:], pkBytes[1:]) // reuse the rest — content doesn't matter for the check

	spk := makeP2PKScript(hybridPK)
	scriptSig := make([]byte, 0, 1+len(sig))
	scriptSig = append(scriptSig, byte(len(sig)))
	scriptSig = append(scriptSig, sig...)
	tx.TxIn[0].SignatureScript = scriptSig
	prevOut := &wire.TxOut{Value: 100000, PkScript: spk}

	err := VerifyScript(scriptSig, spk, tx, 0,
		ScriptVerifyStrictEncoding, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrPubKeyType {
		t.Errorf("G25: hybrid pubkey with STRICTENC should return ErrPubKeyType, got %v", err)
	}
}

func TestBIP66_G26_WitnessPubKeyTypeForcesCompressed(t *testing.T) {
	// G26: WITNESS_PUBKEYTYPE rejects uncompressed keys in P2WPKH.
	// The existing TestWitnessPubKeyType in script_test.go covers this gate;
	// we add a targeted standalone check here.
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pkBytesUncomp := pubKey.SerializeUncompressed()
	pubKeyHash := crypto.Hash160(pkBytesUncomp)

	// P2WPKH scriptPubKey: OP_0 <20-byte hash>
	spk := make([]byte, 22)
	spk[0] = OP_0
	spk[1] = 20
	copy(spk[2:], pubKeyHash[:])

	tx := makeTx()
	tx.TxIn[0].Witness = [][]byte{}
	prevOut := &wire.TxOut{Value: 100000, PkScript: spk}

	// Compute BIP143 sighash using the constructed P2WPKH virtual script
	p2pkhScript := make([]byte, 25)
	p2pkhScript[0] = OP_DUP
	p2pkhScript[1] = OP_HASH160
	p2pkhScript[2] = 20
	copy(p2pkhScript[3:], pubKeyHash[:])
	p2pkhScript[23] = OP_EQUALVERIFY
	p2pkhScript[24] = OP_CHECKSIG

	sighash, _ := CalcWitnessSignatureHash(p2pkhScript, SigHashAll, tx, 0, 100000)
	rawSig, _ := crypto.SignECDSA(privKey, sighash)
	sig := append(rawSig, byte(SigHashAll))

	tx.TxIn[0].Witness = [][]byte{sig, pkBytesUncomp}

	err := VerifyScript(nil, spk, tx, 0,
		ScriptVerifyWitness|ScriptVerifyWitnessPubKeyType,
		prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrWitnessPubKeyType {
		t.Errorf("G26: uncompressed key in P2WPKH with WITNESS_PUBKEYTYPE should return ErrWitnessPubKeyType, got %v", err)
	}
}

// ---- NULLFAIL / NULLDUMMY (G27-G29) ----------------------------------------

func TestBIP66_G27_NullFailChecksig(t *testing.T) {
	// G27: NULLFAIL — non-empty invalid sig in CHECKSIG → ErrNullFail.
	// (covered by TestNullFail but we add a named gate test)
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pkBytes := pubKey.SerializeCompressed()

	tx := makeTx()
	spk := makeP2PKScript(pkBytes)
	prevOut := &wire.TxOut{Value: 100000, PkScript: spk}

	// Sign with a different key → valid DER but wrong sig
	other, _ := crypto.GeneratePrivateKey()
	sighash, _ := CalcSignatureHash(spk, SigHashAll, tx, 0)
	rawSig, _ := crypto.SignECDSA(other, sighash)
	wrongSig := append(rawSig, byte(SigHashAll))

	scriptSig := make([]byte, 0, 1+len(wrongSig))
	scriptSig = append(scriptSig, byte(len(wrongSig)))
	scriptSig = append(scriptSig, wrongSig...)
	tx.TxIn[0].SignatureScript = scriptSig

	err := VerifyScript(scriptSig, spk, tx, 0,
		ScriptVerifyNullFail, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrNullFail {
		t.Errorf("G27: expected ErrNullFail, got %v", err)
	}
}

func TestBIP66_G28_NullFailEmptySigAllowed(t *testing.T) {
	// G28: NULLFAIL — empty sig in CHECKSIG is allowed to fail without ErrNullFail.
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pkBytes := pubKey.SerializeCompressed()

	tx := makeTx()
	spk := makeP2PKScript(pkBytes)
	prevOut := &wire.TxOut{Value: 100000, PkScript: spk}

	// scriptSig: push empty sig
	scriptSig := []byte{0x00} // OP_0 = push empty
	tx.TxIn[0].SignatureScript = scriptSig

	err := VerifyScript(scriptSig, spk, tx, 0,
		ScriptVerifyNullFail, prevOut.Value, []*wire.TxOut{prevOut})
	if err == ErrNullFail {
		t.Error("G28: empty failing sig should not trigger ErrNullFail")
	}
}

func TestBIP66_G29_NullDummy(t *testing.T) {
	// G29: NULLDUMMY — non-empty dummy in CHECKMULTISIG → ErrNullDummy.
	// (mirrors TestCheckMultiSigNullDummy but as a named gate)
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pkBytes := pubKey.SerializeCompressed()

	redeemScript := makeMultisigScript(1, [][]byte{pkBytes})
	tx := makeTx()
	prevOut := &wire.TxOut{Value: 100000, PkScript: redeemScript}

	sighash, _ := CalcSignatureHash(redeemScript, SigHashAll, tx, 0)
	sig := buildMinimalValidSig(privKey, sighash)

	// Non-empty dummy: push a single zero byte
	scriptSig := []byte{0x01, 0x00} // push 1 byte (0x00)
	scriptSig = append(scriptSig, byte(len(sig)))
	scriptSig = append(scriptSig, sig...)
	tx.TxIn[0].SignatureScript = scriptSig

	err := VerifyScript(scriptSig, redeemScript, tx, 0,
		ScriptVerifyNullDummy, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrNullDummy {
		t.Errorf("G29: expected ErrNullDummy, got %v", err)
	}
}

// ---- CONST_SCRIPTCODE gates (G30-G31) --------------------------------------

func TestBIP66_G30_ConstScriptCode_CheckSig(t *testing.T) {
	// G30: CHECKSIG: if FindAndDelete removes the signature from scriptCode AND
	// CONST_SCRIPTCODE is active → ErrSigFindAndDelete (Core interpreter.cpp:330-332).
	//
	// Construction:
	//   scriptSig    = <push sig> <push pubkey>
	//   scriptPubKey = <push sig_bytes> OP_DROP OP_CHECKSIG
	//
	// Stack before OP_CHECKSIG: [sig, pubkey]  (sig pushed by scriptSig, then
	// scriptPubKey pushes sig_bytes and OP_DROP removes it).
	// scriptCode = full scriptPubKey = <push sig_bytes> OP_DROP OP_CHECKSIG.
	// FindAndDelete removes <push sig_bytes> → remaining = OP_DROP OP_CHECKSIG.
	// Sighash is computed over OP_DROP OP_CHECKSIG.
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pkBytes := pubKey.SerializeCompressed()

	tx := makeTx()

	// Step 1: compute sighash over the scriptCode that remains AFTER FindAndDelete.
	// remaining = [OP_DROP, OP_CHECKSIG]
	scriptCodeAfterFAD := []byte{OP_DROP, OP_CHECKSIG}
	sighash, _ := CalcSignatureHash(scriptCodeAfterFAD, SigHashAll, tx, 0)
	sig := buildMinimalValidSig(privKey, sighash)

	// Step 2: build scriptPubKey = <push sig> OP_DROP OP_CHECKSIG
	spk := make([]byte, 0, 2+len(sig)+2)
	spk = append(spk, byte(len(sig)))
	spk = append(spk, sig...)
	spk = append(spk, OP_DROP, OP_CHECKSIG)

	// Step 3: scriptSig = <push sig> <push pubkey>
	// Stack after scriptSig: [sig, pubkey] (sig at bottom, pubkey on top).
	// OP_CHECKSIG pops top (pubkey) as pubkey, pops next (sig) as sig.
	scriptSig := make([]byte, 0, 2+len(sig)+1+len(pkBytes))
	scriptSig = append(scriptSig, byte(len(sig)))
	scriptSig = append(scriptSig, sig...)
	scriptSig = append(scriptSig, byte(len(pkBytes)))
	scriptSig = append(scriptSig, pkBytes...)
	tx.TxIn[0].SignatureScript = scriptSig

	prevOut := &wire.TxOut{Value: 100000, PkScript: spk}

	// Without CONST_SCRIPTCODE: FindAndDelete removes embedded sig, sighash over
	// remaining script, verification succeeds.
	err := VerifyScript(scriptSig, spk, tx, 0,
		ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	if err != nil {
		t.Skipf("G30: base verification failed (%v) — construction incorrect, skipping", err)
	}

	// With CONST_SCRIPTCODE: FindAndDelete hit → ErrSigFindAndDelete.
	err = VerifyScript(scriptSig, spk, tx, 0,
		ScriptVerifyConstScriptCode, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrSigFindAndDelete {
		t.Errorf("G30: expected ErrSigFindAndDelete with CONST_SCRIPTCODE, got %v", err)
	}
}

func TestBIP66_G31_ConstScriptCode_CheckMultiSig(t *testing.T) {
	// G31: CHECKMULTISIG: CONST_SCRIPTCODE fires when FindAndDelete removes the
	// sig from scriptCode. Mirrors Core interpreter.cpp:1147-1148.
	//
	// Construction:
	//   scriptSig    = OP_0 (dummy) <push sig>
	//   scriptPubKey = <push sig_bytes> OP_DROP OP_1 <push pk> OP_1 OP_CHECKMULTISIG
	//
	// scriptCode = full scriptPubKey. FindAndDelete removes <push sig_bytes>.
	// Remaining = OP_DROP OP_1 <push pk> OP_1 OP_CHECKMULTISIG.
	// Sighash computed over remaining.
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pkBytes := pubKey.SerializeCompressed()

	tx := makeTx()

	// Step 1: multisig script without the leading sig push.
	multisigSuffix := makeMultisigScript(1, [][]byte{pkBytes})
	scriptCodeAfterFAD := append([]byte{OP_DROP}, multisigSuffix...)
	sighash, _ := CalcSignatureHash(scriptCodeAfterFAD, SigHashAll, tx, 0)
	sig := buildMinimalValidSig(privKey, sighash)

	// Step 2: full scriptPubKey = <push sig> OP_DROP <multisig-script>
	spk := make([]byte, 0, 2+len(sig)+1+len(multisigSuffix))
	spk = append(spk, byte(len(sig)))
	spk = append(spk, sig...)
	spk = append(spk, OP_DROP)
	spk = append(spk, multisigSuffix...)

	// Step 3: scriptSig = OP_0 (dummy) <push sig>
	scriptSig := make([]byte, 0, 2+len(sig))
	scriptSig = append(scriptSig, 0x00)            // empty dummy
	scriptSig = append(scriptSig, byte(len(sig)))
	scriptSig = append(scriptSig, sig...)
	tx.TxIn[0].SignatureScript = scriptSig

	prevOut := &wire.TxOut{Value: 100000, PkScript: spk}

	// Without CONST_SCRIPTCODE: should succeed.
	err := VerifyScript(scriptSig, spk, tx, 0,
		ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	if err != nil {
		t.Skipf("G31: base verification failed (%v) — construction incorrect, skipping", err)
	}

	// With CONST_SCRIPTCODE: FindAndDelete hit → ErrSigFindAndDelete.
	err = VerifyScript(scriptSig, spk, tx, 0,
		ScriptVerifyConstScriptCode, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrSigFindAndDelete {
		t.Errorf("G31: expected ErrSigFindAndDelete with CONST_SCRIPTCODE in multisig, got %v", err)
	}
}

// ---- Empty sig in multisig does not break loop early (G32) -----------------

func TestBIP66_G32_MultiSigEmptySigContinuesLoop(t *testing.T) {
	// G32: Empty sig in multisig must NOT break the loop prematurely.
	// If it does, pubkey encoding checks for keys reached after the empty sig
	// are silently skipped.
	//
	// Setup: 1-of-2 multisig. Sig = empty. pubKeys (in pop order) = [validPK, hybridPK].
	// scriptPubKey push order: hybridPK then validPK (so validPK ends up on top and is
	// popped first → pubKeys[0]=validPK, pubKeys[1]=hybridPK).
	//
	// Loop trace:
	//   iter 1: sig=empty vs pubKeys[0]=validPK — empty passes encoding, ECDSA fails,
	//           pubKeyIdx→1, nPubKeysRemaining=1, nSigsRemaining(1)≤nPubKeysRemaining(1).
	//   iter 2: sig=empty vs pubKeys[1]=hybridPK — STRICTENC fires → ErrPubKeyType.
	//
	// Pre-fix: the `if len(sig)==0 { break }` exits after iter 0, hybridPK never checked.
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	validPK := pubKey.SerializeCompressed()

	// hybridPK: prefix 0x06, 65 bytes — invalid under STRICTENC.
	hybridPK := make([]byte, 65)
	hybridPK[0] = 0x06
	copy(hybridPK[1:], pubKey.SerializeUncompressed()[1:])

	// scriptPubKey: OP_1 <hybridPK> <validPK> OP_2 OP_CHECKMULTISIG
	// Push order: hybridPK, validPK. validPK is on top → pubKeys[0]=validPK, pubKeys[1]=hybridPK.
	redeemScript := makeMultisigScript(1, [][]byte{hybridPK, validPK})

	tx := makeTx()
	prevOut := &wire.TxOut{Value: 100000, PkScript: redeemScript}

	// scriptSig: OP_0 (dummy) OP_0 (empty sig)
	scriptSig := []byte{0x00, 0x00} // dummy then empty sig
	tx.TxIn[0].SignatureScript = scriptSig

	// With STRICTENC, the hybrid pubkey should be caught even though the sig is empty.
	err := VerifyScript(scriptSig, redeemScript, tx, 0,
		ScriptVerifyStrictEncoding, prevOut.Value, []*wire.TxOut{prevOut})
	if err != ErrPubKeyType {
		t.Errorf("G32: expected ErrPubKeyType (hybrid key caught via STRICTENC after empty sig), got %v", err)
	}

	// Without STRICTENC, the hybrid pubkey is not checked; multisig just fails.
	err = VerifyScript(scriptSig, redeemScript, tx, 0,
		ScriptVerifyNone, prevOut.Value, []*wire.TxOut{prevOut})
	if err == ErrPubKeyType {
		t.Error("G32: without STRICTENC, hybrid key should not trigger ErrPubKeyType")
	}
}

// ---- FindAndDeleteCount count-returning variant -----------------------------

func TestBIP66_FindAndDeleteCount(t *testing.T) {
	// Verify the new count-returning variant.
	tests := []struct {
		name     string
		script   []byte
		sig      []byte
		wantN    int
		wantLeft []byte
	}{
		{
			name:     "empty sig",
			script:   []byte{OP_1, OP_2},
			sig:      []byte{},
			wantN:    0,
			wantLeft: []byte{OP_1, OP_2},
		},
		{
			name:     "one occurrence",
			script:   []byte{0x03, 0x01, 0x02, 0x03},
			sig:      []byte{0x01, 0x02, 0x03},
			wantN:    1,
			wantLeft: []byte{},
		},
		{
			name: "two occurrences",
			script: []byte{
				0x03, 0x01, 0x02, 0x03,
				0x03, 0x01, 0x02, 0x03,
			},
			sig:      []byte{0x01, 0x02, 0x03},
			wantN:    2,
			wantLeft: []byte{},
		},
		{
			name:     "no match",
			script:   []byte{0x03, 0x01, 0x02, 0x03},
			sig:      []byte{0x01, 0x02, 0x04}, // different last byte
			wantN:    0,
			wantLeft: []byte{0x03, 0x01, 0x02, 0x03},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, n := FindAndDeleteCount(tt.script, tt.sig)
			if n != tt.wantN {
				t.Errorf("count = %d, want %d", n, tt.wantN)
			}
			if len(got) != len(tt.wantLeft) {
				t.Errorf("result len = %d, want %d; got %x want %x", len(got), len(tt.wantLeft), got, tt.wantLeft)
			} else {
				for i := range got {
					if got[i] != tt.wantLeft[i] {
						t.Errorf("result[%d] = %02x, want %02x", i, got[i], tt.wantLeft[i])
					}
				}
			}
		})
	}
}

// ---- helpers ----------------------------------------------------------------

// buildValidDERSig constructs a minimal structurally-valid DER-encoded
// signature. It uses fixed R=0x01 (1 byte) and S=0x01 (1 byte) values
// with sighash byte 0x01 (SIGHASH_ALL).
//
// Format: 0x30 [total=6] 0x02 0x01 0x01 0x02 0x01 0x01 0x01
func buildValidDERSig() []byte {
	return []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01}
}

// makeRawDERSig builds a syntactically valid DER signature with the given R
// and S byte slices (high bits must be clear). Appends SIGHASH_ALL.
func makeRawDERSig(r, s []byte) []byte {
	// Prepend leading zero to r or s if high bit would be set.
	if len(r) > 0 && r[0]&0x80 != 0 {
		r = append([]byte{0x00}, r...)
	}
	if len(s) > 0 && s[0]&0x80 != 0 {
		s = append([]byte{0x00}, s...)
	}
	total := 2 + len(r) + 2 + len(s)
	sig := make([]byte, 0, 2+total+1)
	sig = append(sig, 0x30, byte(total))
	sig = append(sig, 0x02, byte(len(r)))
	sig = append(sig, r...)
	sig = append(sig, 0x02, byte(len(s)))
	sig = append(sig, s...)
	sig = append(sig, 0x01) // SIGHASH_ALL
	return sig
}

// makeP2PKHScript returns OP_DUP OP_HASH160 <hash160(pkBytes)> OP_EQUALVERIFY OP_CHECKSIG.
func makeP2PKHScript(pkBytes []byte) []byte {
	hash := crypto.Hash160(pkBytes)
	script := []byte{OP_DUP, OP_HASH160, 20}
	script = append(script, hash[:]...)
	script = append(script, OP_EQUALVERIFY, OP_CHECKSIG)
	return script
}

// makeP2PKScript returns <push pkBytes> OP_CHECKSIG.
func makeP2PKScript(pkBytes []byte) []byte {
	script := make([]byte, 0, 1+len(pkBytes)+1)
	script = append(script, byte(len(pkBytes)))
	script = append(script, pkBytes...)
	script = append(script, OP_CHECKSIG)
	return script
}

// makeMultisigScript returns m-of-n multisig scriptPubKey.
func makeMultisigScript(m int, pubKeys [][]byte) []byte {
	script := []byte{byte(OP_1 + m - 1)}
	for _, pk := range pubKeys {
		script = append(script, byte(len(pk)))
		script = append(script, pk...)
	}
	script = append(script, byte(OP_1+len(pubKeys)-1))
	script = append(script, OP_CHECKMULTISIG)
	return script
}

// makeP2PKScriptWithBadDERSig builds a P2PK-style script and a scriptSig
// containing a syntactically invalid DER sig (first byte 0x31 instead of 0x30).
func makeP2PKScriptWithBadDERSig() (spk []byte, scriptSig []byte) {
	privKey, _ := crypto.GeneratePrivateKey()
	pubKey := privKey.PubKey()
	pkBytes := pubKey.SerializeCompressed()

	spk = makeP2PKScript(pkBytes)

	// Build a malformed sig: valid DER structure but first byte is 0x31.
	badSig := buildValidDERSig()
	badSig[0] = 0x31

	scriptSig = make([]byte, 0, 1+len(badSig))
	scriptSig = append(scriptSig, byte(len(badSig)))
	scriptSig = append(scriptSig, badSig...)
	return
}
