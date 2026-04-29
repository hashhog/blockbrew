package p2p

import (
	"testing"

	"github.com/hashhog/blockbrew/internal/crypto"
)

// TestEllSwiftRoundTripSanity is the correctness gate for the underlying
// ElligatorSwift codec.  Any working BIP-324 implementation MUST satisfy:
// for any two key-pairs (a, A) and (b, B), the ECDH secrets computed by
// ComputeBIP324ECDHSecret(B, true) on side a and ComputeBIP324ECDHSecret(A,
// false) on side b are byte-equal.
//
// Backed by libsecp256k1 secp256k1_ellswift_xdh (the BIP-324 reference
// codec) since the cgo rewrite of internal/crypto/ellswift.go.  Prior to
// that rewrite this test failed every iteration because the hand-rolled
// codec picked an incorrect candidate x-coordinate during decode, wedging
// every BIP-324 handshake at the garbage-terminator scan.
func TestEllSwiftRoundTripSanity(t *testing.T) {
	for i := 0; i < 4; i++ {
		initKey, err := crypto.GenerateEllSwiftPrivKey()
		if err != nil {
			t.Fatalf("init keygen %d: %v", i, err)
		}
		respKey, err := crypto.GenerateEllSwiftPrivKey()
		if err != nil {
			t.Fatalf("resp keygen %d: %v", i, err)
		}
		initShared := initKey.ComputeBIP324ECDHSecret(respKey.EllSwiftPubKey, true)
		respShared := respKey.ComputeBIP324ECDHSecret(initKey.EllSwiftPubKey, false)
		if initShared != respShared {
			t.Errorf("iteration %d: ECDH secrets diverge\n"+
				"  init: %x\n  resp: %x", i, initShared, respShared)
		}
	}
}
