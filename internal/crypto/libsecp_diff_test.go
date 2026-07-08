package crypto

// Differential-equivalence tests for the libsecp256k1 cgo verification path.
//
// The consensus verifiers VerifyECDSALax (ecdsa.go) and VerifySchnorrMsg
// (schnorr.go) were switched from the pure-Go dcrec backend to libsecp256k1.
// These tests run a corpus of vectors through BOTH backends and assert the
// bool results are IDENTICAL — accept AND reject — because any divergence in
// the accept set is a consensus fork.
//
//   ECDSA : VerifyECDSALax (libsecp) vs verifyECDSALaxDcrec (dcrec reference)
//   Schnorr: VerifySchnorrMsg (libsecp) vs verifySchnorrMsgDcrec (dcrec ref)
//
// The corpora deliberately over-weight reject edge cases: high-S,
// non-canonical / malleated DER, wrong pubkey/hash, empty sig, all-zero sig,
// r/s out of range, Schnorr x-only parity/edge, point-at-infinity, and a
// randomized fuzz sweep.

import (
	"encoding/hex"
	"math/big"
	"math/rand"
	"testing"
)

// encodeDERCanonical builds a canonical DER ECDSA signature from r and s
// (minimal length, leading 0x00 only when the high bit would otherwise be set).
func encodeDERCanonical(r, s *big.Int) []byte {
	encInt := func(v *big.Int) []byte {
		b := v.Bytes()
		if len(b) == 0 {
			b = []byte{0x00}
		}
		if b[0]&0x80 != 0 {
			b = append([]byte{0x00}, b...)
		}
		return append([]byte{0x02, byte(len(b))}, b...)
	}
	body := append(encInt(r), encInt(s)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// encodeDERPadded builds a DER signature with `extra` superfluous leading
// zero bytes prepended to the R integer — a non-canonical encoding the lax
// parser accepts (Core's ecdsa_signature_parse_der_lax strips them).
func encodeDERPadded(r, s *big.Int, extra int) []byte {
	encIntPadded := func(v *big.Int, pad int) []byte {
		b := v.Bytes()
		if len(b) == 0 {
			b = []byte{0x00}
		}
		if b[0]&0x80 != 0 {
			b = append([]byte{0x00}, b...)
		}
		for i := 0; i < pad; i++ {
			b = append([]byte{0x00}, b...)
		}
		return append([]byte{0x02, byte(len(b))}, b...)
	}
	body := append(encIntPadded(r, extra), encIntPadded(s, 0)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

func TestDiff_ECDSA_LibsecpVsDcrec(t *testing.T) {
	// Deterministic keys for reproducibility.
	mkKey := func(scalarLastByte byte) *PrivateKey {
		var kb [32]byte
		kb[31] = scalarLastByte
		kb[0] = 0x01 // ensure well within [1, n)
		return PrivateKeyFromBytes(kb[:])
	}
	keyA := mkKey(0x11)
	keyB := mkKey(0x22)
	pubA := keyA.PubKey()
	pubB := keyB.PubKey()

	type tc struct {
		name string
		pub  *PublicKey
		hash [32]byte
		sig  []byte
	}
	var cases []tc

	// 1. Valid low-S signatures (SignECDSA already normalizes to low-S).
	for i := 0; i < 6; i++ {
		hash := DoubleSHA256([]byte{byte(i), 0xAA, 0xBB})
		sig, err := SignECDSA(keyA, hash)
		if err != nil {
			t.Fatalf("SignECDSA: %v", err)
		}
		cases = append(cases, tc{name: "valid-lowS", pub: pubA, hash: hash, sig: sig})

		// 2. High-S malleation: both backends must normalize and accept.
		r, s, perr := ParseDERSignature(sig)
		if perr != nil {
			t.Fatalf("ParseDERSignature: %v", perr)
		}
		rInt := new(big.Int).SetBytes(scalarBytes(r))
		sInt := new(big.Int).SetBytes(scalarBytes(s))
		highS := new(big.Int).Sub(curveN, sInt)
		cases = append(cases, tc{name: "valid-highS-malleated", pub: pubA, hash: hash, sig: encodeDERCanonical(rInt, highS)})

		// 3. Non-canonical DER (extra leading zeros on R) — lax-accepted.
		cases = append(cases, tc{name: "noncanonical-padded-R", pub: pubA, hash: hash, sig: encodeDERPadded(rInt, sInt, 2)})

		// 4. Wrong pubkey → reject.
		cases = append(cases, tc{name: "wrong-pubkey", pub: pubB, hash: hash, sig: sig})

		// 5. Wrong hash → reject.
		wrong := DoubleSHA256([]byte{byte(i), 0xCC})
		cases = append(cases, tc{name: "wrong-hash", pub: pubA, hash: wrong, sig: sig})
	}

	// 6. Structural reject edge cases.
	var h0 [32]byte
	rejects := map[string][]byte{
		"empty":                 {},
		"one-byte":              {0x30},
		"junk-3":                {0x01, 0x02, 0x03},
		"der-r0-s0":             {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}, // r=0,s=0
		"der-truncated":         {0x30, 0x06, 0x02, 0x01},
		"all-zero-8":            make([]byte, 8),
		"all-zero-72":           make([]byte, 72),
		"r-equals-N":            encodeDERCanonical(curveN, big.NewInt(1)),
		"s-equals-N":            encodeDERCanonical(big.NewInt(1), curveN),
		"r-zero-s-one":          encodeDERCanonical(big.NewInt(0), big.NewInt(1)),
		"r-one-s-zero":          encodeDERCanonical(big.NewInt(1), big.NewInt(0)),
		"r-gt-N":                encodeDERCanonical(new(big.Int).Add(curveN, big.NewInt(5)), big.NewInt(1)),
	}
	for name, sig := range rejects {
		cases = append(cases, tc{name: "reject-" + name, pub: pubA, hash: h0, sig: sig})
	}

	// 7. Randomized fuzz: random buffers as signatures + occasionally
	//    structurally-valid-but-wrong sigs, over random valid pubkeys.
	rng := rand.New(rand.NewSource(0xB10CB2E4))
	for i := 0; i < 4000; i++ {
		var hb [32]byte
		rng.Read(hb[:])
		n := rng.Intn(80)
		sig := make([]byte, n)
		rng.Read(sig)
		// Bias ~1/4 toward DER-shaped buffers to exercise the parser deeper.
		if n >= 8 && rng.Intn(4) == 0 {
			sig[0] = 0x30
			sig[2] = 0x02
		}
		pub := pubA
		if rng.Intn(2) == 0 {
			pub = pubB
		}
		cases = append(cases, tc{name: "fuzz", pub: pub, hash: hb, sig: sig})
	}

	nValidTrue := 0
	for i, c := range cases {
		got := VerifyECDSALax(c.pub, c.hash, c.sig)
		want := verifyECDSALaxDcrec(c.pub, c.hash, c.sig)
		if got != want {
			t.Fatalf("ECDSA divergence [case %d %q]: libsecp=%v dcrec=%v sig=%x",
				i, c.name, got, want, c.sig)
		}
		if got {
			nValidTrue++
		}
	}
	// Sanity: the valid + malleated + noncanonical cases must actually accept,
	// otherwise the test would trivially pass by rejecting everything.
	if nValidTrue < 12 {
		t.Fatalf("expected many accepted ECDSA sigs, only %d accepted — corpus broken", nValidTrue)
	}
}

// scalarBytes extracts the 32-byte big-endian representation of a
// dcrec ModNScalar via its Bytes() array.
func scalarBytes(s interface{ Bytes() [32]byte }) []byte {
	b := s.Bytes()
	return b[:]
}

func TestDiff_Schnorr_LibsecpVsDcrec(t *testing.T) {
	type tc struct {
		name string
		pub  []byte
		msg  []byte
		sig  []byte
	}
	var cases []tc

	hx := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("hex: %v", err)
		}
		return b
	}

	// BIP-340 official vectors 0-18 (accept AND reject), from
	// bitcoin-core/test/functional/test_framework/bip340_test_vectors.csv,
	// mirrored in schnorr_w95_test.go.
	type v struct{ pub, msg, sig string }
	bip340 := []v{
		{"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "0000000000000000000000000000000000000000000000000000000000000000", "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"},
		{"DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8", "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C", "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"},
		{"25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"},
		{"D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9", "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703", "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4"},
		{"EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"},
		{"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"},
		// Variable-length message vectors 15-18.
		{"778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "", "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63"},
		{"778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "11", "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF"},
		{"778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "0102030405060708090A0B0C0D0E0F1011", "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5"},
		{"778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999", "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367"},
	}
	for i, e := range bip340 {
		cases = append(cases, tc{name: "bip340-" + string(rune('0'+i%10)), pub: hx(e.pub), msg: hx(e.msg), sig: hx(e.sig)})
	}

	// Reject edge cases.
	validPub := hx("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	var msg32 [32]byte
	cases = append(cases,
		tc{name: "all-zero-sig", pub: validPub, msg: msg32[:], sig: make([]byte, 64)},
		tc{name: "empty-sig", pub: validPub, msg: msg32[:], sig: []byte{}},
		tc{name: "short-sig-63", pub: validPub, msg: msg32[:], sig: make([]byte, 63)},
		tc{name: "long-sig-65", pub: validPub, msg: msg32[:], sig: make([]byte, 65)},
		// x-only pubkey with x == p (not a valid field element).
		tc{name: "pub-x-eq-p", pub: hx("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"), msg: msg32[:], sig: make([]byte, 64)},
		// x-only pubkey that is not liftable (no even-y point).
		tc{name: "pub-not-liftable", pub: hx("0000000000000000000000000000000000000000000000000000000000000005"), msg: msg32[:], sig: make([]byte, 64)},
		tc{name: "pub-short", pub: hx("DFF1D77F"), msg: msg32[:], sig: make([]byte, 64)},
	)

	// Valid signatures produced by our own signer, verified through both
	// backends (must both accept).
	nValidTrue := 0
	for i := 1; i <= 6; i++ {
		var kb [32]byte
		kb[31] = byte(i)
		kb[0] = 0x02
		key := PrivateKeyFromBytes(kb[:])
		hash := DoubleSHA256([]byte{byte(i), 0x5A})
		sig, err := SignSchnorr(key, hash)
		if err != nil {
			t.Fatalf("SignSchnorr: %v", err)
		}
		xonly := SerializePubKeyXOnly(key.PubKey().key)
		cases = append(cases, tc{name: "self-valid", pub: xonly, msg: hash[:], sig: sig})
		// Same sig, wrong message → reject.
		wrong := DoubleSHA256([]byte{byte(i), 0x6B})
		cases = append(cases, tc{name: "self-wrong-msg", pub: xonly, msg: wrong[:], sig: sig})
	}

	// Randomized fuzz sweep.
	rng := rand.New(rand.NewSource(0x5C4A0011))
	for i := 0; i < 4000; i++ {
		pub := make([]byte, 32)
		rng.Read(pub)
		sig := make([]byte, 64)
		rng.Read(sig)
		mlen := rng.Intn(40)
		msg := make([]byte, mlen)
		rng.Read(msg)
		cases = append(cases, tc{name: "fuzz", pub: pub, msg: msg, sig: sig})
	}

	for i, c := range cases {
		got := VerifySchnorrMsg(c.pub, c.msg, c.sig)
		want := verifySchnorrMsgDcrec(c.pub, c.msg, c.sig)
		if got != want {
			t.Fatalf("Schnorr divergence [case %d %q]: libsecp=%v dcrec=%v pub=%x msg=%x sig=%x",
				i, c.name, got, want, c.pub, c.msg, c.sig)
		}
		if got {
			nValidTrue++
		}
	}
	if nValidTrue < 14 {
		t.Fatalf("expected many accepted Schnorr sigs, only %d accepted — corpus broken", nValidTrue)
	}
}
