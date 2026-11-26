package crypto

// verify-neon-blockbrew-findings, audit finding 3.
//
// Core's ecdsa_signature_parse_der_lax (pubkey.cpp) reads a long-form integer
// length by first skipping leading 0x00 length bytes and only then requiring
// fewer than 4 significant ones. blockbrew rejected any long form with more
// than 4 length bytes before skipping zeros, so a signature whose R or S
// length is written 0x85 00 00 00 00 20 failed to verify. Without DERSIG
// (blocks below BIP66) Core accepts such a signature.

import (
	"bytes"
	"testing"
)

// neonDERParts splits a strict DER signature into its R and S integer bodies.
func neonDERParts(t *testing.T, der []byte) (r, s []byte) {
	t.Helper()
	if der[0] != 0x30 || der[2] != 0x02 {
		t.Fatalf("fixture: not strict DER: %x", der)
	}
	lr := int(der[3])
	r = der[4 : 4+lr]
	if der[4+lr] != 0x02 {
		t.Fatalf("fixture: no S tag: %x", der)
	}
	ls := int(der[5+lr])
	s = der[6+lr : 6+lr+ls]
	return r, s
}

// neonLaxSig builds 0x30 <seqlen> 0x02 <rlen-encoding> R 0x02 <slen-encoding> S.
func neonLaxSig(rLen, r, sLen, s []byte) []byte {
	body := append([]byte{0x02}, rLen...)
	body = append(body, r...)
	body = append(body, 0x02)
	body = append(body, sLen...)
	body = append(body, s...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

func neonSigned(t *testing.T) (*PublicKey, [32]byte, []byte, []byte) {
	t.Helper()
	priv := PrivateKeyFromBytes(append(make([]byte, 31), 0x09))
	var h [32]byte
	copy(h[:], bytes.Repeat([]byte{0x5a}, 32))
	der, err := SignECDSA(priv, h)
	if err != nil {
		t.Fatal(err)
	}
	r, s := neonDERParts(t, der)
	return priv.PubKey(), h, r, s
}

func TestNeonDERLaxLongFormLengthWithLeadingZeros(t *testing.T) {
	pub, h, r, s := neonSigned(t)
	short := func(b []byte) []byte { return []byte{byte(len(b))} }
	cases := []struct {
		name       string
		rLen, sLen []byte
	}{
		// 5 length bytes, 4 of them leading zeros: Core skips them -> 1 byte.
		{"R-0x85-00000000-len", []byte{0x85, 0, 0, 0, 0, byte(len(r))}, short(s)},
		{"S-0x85-00000000-len", short(r), []byte{0x85, 0, 0, 0, 0, byte(len(s))}},
		// 8 length bytes, 7 zeros.
		{"R-0x88-zeros-len", []byte{0x88, 0, 0, 0, 0, 0, 0, 0, byte(len(r))}, short(s)},
		// 6 length bytes, 5 of them leading zeros.
		{"S-0x86-5zeros", short(r), []byte{0x86, 0, 0, 0, 0, 0, byte(len(s))}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sig := neonLaxSig(c.rLen, r, c.sLen, s)
			if !VerifyECDSALax(pub, h, sig) {
				t.Fatalf("lax signature %x rejected; Core ecdsa_signature_parse_der_lax skips leading zero length bytes and accepts", sig)
			}
		})
	}
}

// Controls that Core rejects too.
func TestNeonDERLaxLongFormLengthControls(t *testing.T) {
	pub, h, r, s := neonSigned(t)
	short := []byte{byte(len(s))}
	// 4 significant length bytes after the zeros: Core `lenbyte >= 4` -> fail.
	if VerifyECDSALax(pub, h, neonLaxSig([]byte{0x84, 0x01, 0, 0, byte(len(r))}, r, short, s)) {
		t.Fatalf("4 significant length bytes accepted; Core rejects")
	}
	// Length bytes run past the end of the signature.
	trunc := neonLaxSig([]byte{0x85, 0, 0, 0, 0, byte(len(r))}, r, short, s)
	if VerifyECDSALax(pub, h, trunc[:7]) {
		t.Fatalf("truncated long-form length accepted")
	}
	// Zero-padded length that is too long for the data.
	if VerifyECDSALax(pub, h, neonLaxSig([]byte{0x82, 0x00, byte(len(r) + 1)}, r, short, s)) {
		t.Fatalf("length one past R accepted")
	}
	// Plain short-form still verifies.
	if !VerifyECDSALax(pub, h, neonLaxSig([]byte{byte(len(r))}, r, short, s)) {
		t.Fatalf("plain DER signature rejected")
	}
}
