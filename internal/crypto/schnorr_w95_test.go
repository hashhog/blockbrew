package crypto

// W95 — BIP-340 Schnorr + tagged-hash comprehensive audit.
//
// Test plan, by gate (see schnorr.go for the gate->code mapping):
//
//   G1  sig length 64                  -> TestW95_Gate1_SigLen
//   G2  rx < p                          -> TestW95_Gate2_RxRange
//   G3  s  < n                          -> TestW95_Gate3_SOverflow
//   G4  pubkey lift_x even-Y + on-curve -> TestW95_Gate4_PubkeyLift
//   G5  tagged-hash construction        -> TestW95_Gate5_TaggedHash
//   G6  challenge tagged hash byte-id   -> TestW95_Gate6_ChallengeByteIdentity
//   G7  R = sG - eP                     -> covered by BIP-340 vectors
//   G8  reject R == infinity            -> TestBIP340OfficialVectors (vec 9, 10)
//   G9  reject R.y odd                  -> TestBIP340OfficialVectors (vec 6)
//   G10 require R.x == rx               -> TestBIP340OfficialVectors (vec 7, 8)
//   G11 sig length 65 stripped to 64    -> not in this package (script engine)
//   G12 hashtype range                  -> not in this package (sighash.go)
//
// Plus end-to-end byte-identity against libsecp256k1's
// secp256k1_schnorrsig_sign32(..., aux_rand=NULL) — TestW95_SignByteIdentity.

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// ---------------------------------------------------------------------------
// BIP-340 official 32-byte-message verify vectors.
//
// Source: bitcoin-core/test/functional/test_framework/bip340_test_vectors.csv
// (indices 0-14).  Vectors 15-18 use variable-length messages and are
// covered separately by TestW95_BIP340VariableLength.

func TestW95_BIP340OfficialVectors_32byteMsg(t *testing.T) {
	type vec struct {
		idx     int
		pubHex  string
		msgHex  string
		sigHex  string
		want    bool
		comment string
	}
	vecs := []vec{
		{0, "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
			true, "key=3"},
		{1, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
			true, ""},
		{2, "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
			"7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
			"5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
			true, ""},
		{3, "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			"7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
			true, "msg=all-ones"},
		{4, "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
			"4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
			"00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
			true, "small rx"},
		{5, "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			false, "G4: pubkey x not on curve"},
		{6, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
			false, "G9: has_even_y(R) false"},
		{7, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
			false, "G10: negated message → R.x != rx"},
		{8, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
			false, "G10: negated s → R.x != rx"},
		{9, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
			false, "G8: sG-eP infinite with rx=0"},
		{10, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
			false, "G8: sG-eP infinite with rx=1"},
		{11, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			false, "G10: rx not on curve as x-coord → R.x != rx (different lift)"},
		{12, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			false, "G2: sig[0:32] == p"},
		{13, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
			false, "G3: sig[32:64] == n"},
		{14, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			false, "G4: pubkey x >= p"},
	}

	for _, v := range vecs {
		pub, _ := hex.DecodeString(v.pubHex)
		msg, _ := hex.DecodeString(v.msgHex)
		sig, _ := hex.DecodeString(v.sigHex)
		var msg32 [32]byte
		copy(msg32[:], msg)
		got := VerifySchnorr(pub, msg32, sig)
		if got != v.want {
			t.Errorf("BIP-340 vector %d (%s): got=%v want=%v", v.idx, v.comment, got, v.want)
		}
	}
}

// ---------------------------------------------------------------------------
// BIP-340 official variable-length vectors (added 2022-12).  These probe
// the variable-mlen path supported by libsecp256k1 — Bitcoin's sighash is
// always 32 bytes, but BIP-340 itself is mlen-agnostic.

func TestW95_BIP340VariableLength(t *testing.T) {
	type vec struct {
		idx    int
		pubHex string
		msgHex string
		sigHex string
		want   bool
	}
	vecs := []vec{
		// Vector 15 — msg of size 0.
		{15, "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
			"",
			"71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
			true},
		// Vector 16 — msg of size 1.
		{16, "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
			"11",
			"08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
			true},
		// Vector 17 — msg of size 17.
		{17, "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
			"0102030405060708090A0B0C0D0E0F1011",
			"5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
			true},
		// Vector 18 — msg of size 100.
		{18, "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
			"99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
			"403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
			true},
	}

	for _, v := range vecs {
		pub, _ := hex.DecodeString(v.pubHex)
		msg, _ := hex.DecodeString(v.msgHex)
		sig, _ := hex.DecodeString(v.sigHex)
		got := VerifySchnorrMsg(pub, msg, sig)
		if got != v.want {
			t.Errorf("BIP-340 vector %d (mlen=%d): got=%v want=%v",
				v.idx, len(msg), got, v.want)
		}
	}
}

// ---------------------------------------------------------------------------
// G1 — sig length must be exactly 64 (callers that handle a 65-byte
// sighash form strip the trailing byte before reaching this function).

func TestW95_Gate1_SigLen(t *testing.T) {
	pub, _ := hex.DecodeString(
		"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	var hash [32]byte

	for _, l := range []int{0, 1, 32, 63, 65, 66, 128} {
		sig := make([]byte, l)
		if VerifySchnorr(pub, hash, sig) {
			t.Errorf("VerifySchnorr should reject sig len=%d", l)
		}
	}
	// 64-byte all-zero sig is well-formed but won't verify any real
	// pubkey/msg pair; it must return false, not panic.
	sig64 := make([]byte, 64)
	if VerifySchnorr(pub, hash, sig64) {
		t.Errorf("VerifySchnorr should reject 64-byte zero sig under random hash")
	}
}

// G2 — rx must be < p (field prime).

func TestW95_Gate2_RxRange(t *testing.T) {
	pub, _ := hex.DecodeString(
		"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	var hash [32]byte

	// rx = p (field prime).  s = arbitrary valid scalar (1).
	rxEqP, _ := hex.DecodeString(
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	sig := make([]byte, 64)
	copy(sig[:32], rxEqP)
	sig[63] = 0x01

	if VerifySchnorr(pub, hash, sig) {
		t.Errorf("G2: VerifySchnorr accepted rx == p")
	}

	// rx = 2^256 - 1 (well above p).
	for i := 0; i < 32; i++ {
		sig[i] = 0xff
	}
	if VerifySchnorr(pub, hash, sig) {
		t.Errorf("G2: VerifySchnorr accepted rx = 2^256-1")
	}
}

// G3 — s must be < n (curve order).

func TestW95_Gate3_SOverflow(t *testing.T) {
	pub, _ := hex.DecodeString(
		"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	var hash [32]byte

	// s = n (curve order).  rx = some valid x-coord (use 1).
	sEqN, _ := hex.DecodeString(
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	sig := make([]byte, 64)
	sig[31] = 0x01 // rx = 1
	copy(sig[32:], sEqN)
	if VerifySchnorr(pub, hash, sig) {
		t.Errorf("G3: VerifySchnorr accepted s == n")
	}

	// s = 2^256 - 1.
	for i := 32; i < 64; i++ {
		sig[i] = 0xff
	}
	if VerifySchnorr(pub, hash, sig) {
		t.Errorf("G3: VerifySchnorr accepted s = 2^256-1")
	}
}

// G4 — pubkey lift_x: rejects (a) x >= p, (b) x not yielding any
// y on-curve.

func TestW95_Gate4_PubkeyLift(t *testing.T) {
	var hash [32]byte
	sig := make([]byte, 64)

	// (a) x >= p — vector 14 from BIP-340: x = p+1 (FFF...FC30).  All
	// other inputs irrelevant, the parse must fail.
	pubAboveP, _ := hex.DecodeString(
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30")
	if VerifySchnorr(pubAboveP, hash, sig) {
		t.Errorf("G4(a): VerifySchnorr accepted pubkey x >= p")
	}

	// (b) x not on curve — vector 5 uses x = EEFDEA4C... which has no
	// y^2 = x^3+7 solution mod p.
	pubNotOnCurve, _ := hex.DecodeString(
		"EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
	if VerifySchnorr(pubNotOnCurve, hash, sig) {
		t.Errorf("G4(b): VerifySchnorr accepted pubkey with off-curve x")
	}

	// Sanity: a known good x DOES decode (the lift to even-y succeeds).
	pubGood, _ := hex.DecodeString(
		"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	// Any valid 64-byte sig will trigger the parse path; with random
	// hash/sig the verify will fail at a later gate, but the parse must
	// have succeeded.  We can't directly observe that, but the absence
	// of panic is the smoke check.
	_ = VerifySchnorr(pubGood, hash, sig)
}

// G5 — tagged-hash construction is SHA256(SHA256(tag) || SHA256(tag) || data).
// The precomputed prefixes must be byte-identical to the on-the-fly
// SHA256(tag)||SHA256(tag).

func TestW95_Gate5_TaggedHashPrefixes(t *testing.T) {
	cases := []struct {
		tag      string
		prefix   []byte
		tagWords string
	}{
		{"BIP0340/challenge", tagPrefixBIP0340Challenge, "schnorr challenge"},
		{"BIP0340/nonce", tagPrefixBIP0340Nonce, "schnorr nonce"},
		{"BIP0340/aux", tagPrefixBIP0340Aux, "schnorr aux"},
	}
	for _, c := range cases {
		h := sha256.Sum256([]byte(c.tag))
		want := append(append([]byte(nil), h[:]...), h[:]...)
		if !equalBytes(want, c.prefix) {
			t.Errorf("G5 (%s): precomputed prefix mismatch\nwant=%x\ngot=%x",
				c.tag, want, c.prefix)
		}
		// Also: the convenience taggedHash(tag, data) and the optimized
		// taggedHashWithPrefix(prefix, data) must agree.
		for _, data := range [][]byte{nil, {}, {0}, {0xff}, {0x00, 0x01, 0x02}} {
			a := taggedHash(c.tag, data)
			b := taggedHashWithPrefix(c.prefix, data)
			if a != b {
				t.Errorf("G5 (%s): taggedHash vs prefix variant diverge for data=%x",
					c.tag, data)
			}
		}
	}
}

// G6 — Challenge hash byte identity vs Core.  Core computes
//
//	e = int(tagged_hash("BIP0340/challenge", r || P || m)) mod n
//
// and we test against an externally-known reference value.

func TestW95_Gate6_ChallengeByteIdentity(t *testing.T) {
	// Use BIP-340 vector 1: rx, P, m are all known, so we can derive e
	// from the sig and pubkey and check we get the same e Core would
	// compute.  Specifically, for a verifying sig we need
	// R.x == rx where R = sG - eP.  Re-deriving e here is the only
	// non-self-referential way to check the challenge tagged hash.
	r, _ := hex.DecodeString(
		"6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341")
	p, _ := hex.DecodeString(
		"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	m, _ := hex.DecodeString(
		"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")

	input := append(append(append([]byte{}, r...), p...), m...)
	// Compute both ways and ensure equivalence.
	viaTag := taggedHash("BIP0340/challenge", input)
	viaPre := taggedHashWithPrefix(tagPrefixBIP0340Challenge, input)
	if viaTag != viaPre {
		t.Errorf("G6: taggedHash vs prefix differ for canonical input")
	}
	// (We cannot test the *value* against a third-party reference without
	// an external Schnorr reference oracle in this package's test set;
	// the BIP-340 verify pass above is the byte-identity test, since a
	// wrong challenge would fail all 5 of the positive vectors.)
}

// ---------------------------------------------------------------------------
// G_AUX — TestSchnorrZeroAuxMask asserts that zeroAuxMask is what
// libsecp256k1 calls ZERO_MASK (main_impl.h:70-74).

func TestW95_ZeroAuxMask(t *testing.T) {
	// libsecp256k1 main_impl.h:70-74 hard-codes:
	//   54 f1 69 cf c9 e2 e5 72  74 80 44 1f 90 ba 25 c4
	//   88 f4 61 c7 0b 5e a5 dc  aa f7 af 69 27 0a a5 14
	want := []byte{
		0x54, 0xf1, 0x69, 0xcf, 0xc9, 0xe2, 0xe5, 0x72,
		0x74, 0x80, 0x44, 0x1f, 0x90, 0xba, 0x25, 0xc4,
		0x88, 0xf4, 0x61, 0xc7, 0x0b, 0x5e, 0xa5, 0xdc,
		0xaa, 0xf7, 0xaf, 0x69, 0x27, 0x0a, 0xa5, 0x14,
	}
	if !equalBytes(zeroAuxMask[:], want) {
		t.Errorf("zeroAuxMask divergence from libsecp256k1 ZERO_MASK:\nwant=%x\ngot=%x",
			want, zeroAuxMask)
	}
}

// ---------------------------------------------------------------------------
// Signing — byte-identity vs libsecp256k1.
//
// BIP-340 vector 0: sec=3, msg=zeros32, aux_rand=zeros32 ->
//   sig = E907831F...310536C0
//
// blockbrew's SignSchnorr does not take aux_rand; with the W95 fix it
// matches libsecp256k1's "aux_rand=NULL" path which masks with the
// zeroAuxMask.  That ZERO_MASK XOR is what libsecp256k1 does when
// aux_rand is NULL OR when aux_rand is zeros32 (the two yield identical
// nonces by construction).

func TestW95_SignByteIdentity_Vec0(t *testing.T) {
	sec, _ := hex.DecodeString(
		"0000000000000000000000000000000000000000000000000000000000000003")
	pk := PrivateKeyFromBytes(sec)
	var msg [32]byte // all zeros

	sig, err := SignSchnorr(pk, msg)
	if err != nil {
		t.Fatalf("SignSchnorr: %v", err)
	}

	want, _ := hex.DecodeString(
		"E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
	if !equalBytes(sig, want) {
		t.Errorf("SignSchnorr byte-identity: got=%x\n                          want=%x",
			sig, want)
	}
	// And the resulting sig must, of course, verify.
	if !VerifySchnorr(pk.PubKey().XOnlyPubKey(), msg, sig) {
		t.Errorf("self-verify failed after byte-identical sign")
	}
}

// Helper: equalBytes is intentionally local to the W95 test set — the
// package has plenty of byte-compare helpers but their semantics differ
// and we want a tight loop here for clear failure output.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
