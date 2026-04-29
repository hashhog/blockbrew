package crypto

// #cgo pkg-config: libsecp256k1
// #include <stdlib.h>
// #include <string.h>
// #include <secp256k1.h>
// #include <secp256k1_ellswift.h>
//
// /*
//  * Lazily-allocated context with VERIFY|SIGN flags.  ellswift_create
//  * performs an internal pubkey derivation that needs SIGN; ellswift_xdh
//  * only needs VERIFY but is fine with both.  Mirrors haskoin's
//  * cbits/secp256k1_compat.c::get_ellswift_ctx and ouroboros's reuse
//  * of coincurve._libsecp256k1.lib.secp256k1_context_no_precomp.
//  */
// static secp256k1_context *bb_ellswift_ctx = NULL;
//
// static secp256k1_context *bb_get_ctx(void) {
//     if (bb_ellswift_ctx == NULL) {
//         bb_ellswift_ctx = secp256k1_context_create(
//             SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
//     }
//     return bb_ellswift_ctx;
// }
//
// /* secp256k1_ellswift_create wrapper: 32-byte seckey + 32-byte aux -> 64-byte ell. */
// static int bb_ellswift_create(
//     const unsigned char *seckey32,
//     const unsigned char *auxrnd32,
//     unsigned char *ell64
// ) {
//     secp256k1_context *ctx = bb_get_ctx();
//     if (!ctx) return 0;
//     return secp256k1_ellswift_create(ctx, ell64, seckey32, auxrnd32);
// }
//
// /* secp256k1_ellswift_decode wrapper: 64-byte ell -> 64-byte serialized x||y. */
// static int bb_ellswift_decode(
//     const unsigned char *ell64,
//     unsigned char *xy64
// ) {
//     secp256k1_context *ctx = bb_get_ctx();
//     if (!ctx) return 0;
//     secp256k1_pubkey pk;
//     if (!secp256k1_ellswift_decode(ctx, &pk, ell64)) {
//         return 0;
//     }
//     unsigned char out65[65];
//     size_t outlen = 65;
//     if (!secp256k1_ec_pubkey_serialize(ctx, out65, &outlen, &pk,
//                                        SECP256K1_EC_UNCOMPRESSED)) {
//         return 0;
//     }
//     /* out65[0] is 0x04 prefix; copy x||y into xy64. */
//     memcpy(xy64, out65 + 1, 64);
//     return 1;
// }
//
// /* secp256k1_ellswift_xdh wrapper using the BIP-324 hash function. */
// static int bb_ellswift_xdh_bip324(
//     const unsigned char *ell_a64,
//     const unsigned char *ell_b64,
//     const unsigned char *seckey32,
//     int party,
//     unsigned char *output32
// ) {
//     secp256k1_context *ctx = bb_get_ctx();
//     if (!ctx) return 0;
//     return secp256k1_ellswift_xdh(
//         ctx,
//         output32,
//         ell_a64,
//         ell_b64,
//         seckey32,
//         party,
//         secp256k1_ellswift_xdh_hash_function_bip324,
//         NULL
//     );
// }
import "C"

import (
	"crypto/rand"
	"errors"
	"unsafe"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ErrEllSwiftCreate is returned when libsecp256k1 fails to encode a public
// key with ElligatorSwift.  In practice this only happens for an invalid
// secret scalar (zero or >= n); the caller should regenerate.
var ErrEllSwiftCreate = errors.New("ellswift: secp256k1_ellswift_create failed (invalid seckey)")

// ErrEllSwiftDecode is returned when libsecp256k1 fails to decode the 64-byte
// ElligatorSwift encoding into a curve point.  The library guarantees that
// `ellswift_decode` always returns 1, but we keep this error for completeness
// and for the (impossible) case where serialization fails.
var ErrEllSwiftDecode = errors.New("ellswift: secp256k1_ellswift_decode failed")

// ErrEllSwiftXDH is returned when libsecp256k1 fails the XDH computation,
// e.g. the secret key is invalid for the given encoding.
var ErrEllSwiftXDH = errors.New("ellswift: secp256k1_ellswift_xdh failed")

// EllSwiftPubKey represents a 64-byte ElligatorSwift-encoded public key.
// ElligatorSwift encodes secp256k1 public keys as random-looking 64-byte
// strings indistinguishable from uniform.  See BIP-324 §"ElligatorSwift" and
// Bitcoin Core's doc/ellswift.md.
type EllSwiftPubKey [64]byte

// EllSwiftPrivKey holds a private key and its ElligatorSwift-encoded public key.
type EllSwiftPrivKey struct {
	PrivKey        *PrivateKey
	EllSwiftPubKey EllSwiftPubKey
}

// GenerateEllSwiftPrivKey generates a new private key with ElligatorSwift encoding.
//
// Backend: libsecp256k1 secp256k1_ellswift_create (BIP-324 reference codec).
func GenerateEllSwiftPrivKey() (*EllSwiftPrivKey, error) {
	for {
		privKey, err := GeneratePrivateKey()
		if err != nil {
			return nil, err
		}

		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, err
		}

		ell, err := ellswiftCreate(privKey.Serialize(), entropy[:])
		if err != nil {
			// Vanishingly unlikely: regenerate the secret and retry.
			continue
		}
		return &EllSwiftPrivKey{
			PrivKey:        privKey,
			EllSwiftPubKey: ell,
		}, nil
	}
}

// EllSwiftPrivKeyFromBytes creates an EllSwiftPrivKey from a 32-byte private
// key scalar, with random encoding entropy.
func EllSwiftPrivKeyFromBytes(keyBytes []byte) (*EllSwiftPrivKey, error) {
	privKey := PrivateKeyFromBytes(keyBytes)
	if privKey == nil {
		return nil, ErrInvalidPrivateKey
	}

	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, err
	}

	ell, err := ellswiftCreate(privKey.Serialize(), entropy[:])
	if err != nil {
		return nil, err
	}
	return &EllSwiftPrivKey{
		PrivKey:        privKey,
		EllSwiftPubKey: ell,
	}, nil
}

// EllSwiftPrivKeyFromBytesWithEntropy creates an EllSwiftPrivKey with
// caller-supplied 32-byte encoding entropy.  Useful for deterministic tests.
func EllSwiftPrivKeyFromBytesWithEntropy(keyBytes, entropy []byte) (*EllSwiftPrivKey, error) {
	privKey := PrivateKeyFromBytes(keyBytes)
	if privKey == nil {
		return nil, ErrInvalidPrivateKey
	}
	if len(entropy) != 32 {
		return nil, errors.New("ellswift: entropy must be 32 bytes")
	}

	ell, err := ellswiftCreate(privKey.Serialize(), entropy)
	if err != nil {
		return nil, err
	}
	return &EllSwiftPrivKey{
		PrivKey:        privKey,
		EllSwiftPubKey: ell,
	}, nil
}

// ellswiftCreate calls libsecp256k1 secp256k1_ellswift_create.  Both inputs
// must be 32 bytes; entropy may be all-zero (the encoding is still
// indistinguishable from uniform per BIP-324) but conventionally is random.
func ellswiftCreate(seckey32, entropy32 []byte) (EllSwiftPubKey, error) {
	var out EllSwiftPubKey
	if len(seckey32) != 32 || len(entropy32) != 32 {
		return out, errors.New("ellswift: seckey and entropy must be 32 bytes")
	}
	rc := C.bb_ellswift_create(
		(*C.uchar)(unsafe.Pointer(&seckey32[0])),
		(*C.uchar)(unsafe.Pointer(&entropy32[0])),
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)
	if rc != 1 {
		return out, ErrEllSwiftCreate
	}
	return out, nil
}

// DecodeToPubKey decodes a 64-byte ElligatorSwift encoding to a secp256k1
// public key.  Backend: libsecp256k1 secp256k1_ellswift_decode +
// secp256k1_ec_pubkey_serialize (uncompressed).
func DecodeToPubKey(encoded EllSwiftPubKey) (*PublicKey, error) {
	var xy [64]byte
	rc := C.bb_ellswift_decode(
		(*C.uchar)(unsafe.Pointer(&encoded[0])),
		(*C.uchar)(unsafe.Pointer(&xy[0])),
	)
	if rc != 1 {
		return nil, ErrEllSwiftDecode
	}

	var xField, yField secp256k1.FieldVal
	xField.SetBytes((*[32]byte)(xy[0:32]))
	yField.SetBytes((*[32]byte)(xy[32:64]))
	pubKey := secp256k1.NewPublicKey(&xField, &yField)
	return &PublicKey{key: pubKey}, nil
}

// ComputeBIP324ECDHSecret computes the BIP-324 shared secret given the peer's
// ElligatorSwift-encoded public key and our role in the handshake.
//
// Backend: libsecp256k1 secp256k1_ellswift_xdh with the BIP-324 hash function
// (tagged hash "bip324_ellswift_xonly_ecdh" || ell_a || ell_b || x).
//
// initiator=true => we are party A whose ell_a is our pubkey, ell_b is theirs.
// initiator=false => party B; ell_a is the peer's, ell_b is ours.  Both sides
// see identical ell_a64 / ell_b64 input but flip the seckey + party flag, so
// the returned 32-byte secret matches.
func (k *EllSwiftPrivKey) ComputeBIP324ECDHSecret(theirEllSwift EllSwiftPubKey, initiator bool) [32]byte {
	var ellA, ellB EllSwiftPubKey
	var party C.int
	if initiator {
		ellA = k.EllSwiftPubKey
		ellB = theirEllSwift
		party = 0
	} else {
		ellA = theirEllSwift
		ellB = k.EllSwiftPubKey
		party = 1
	}

	seckey := k.PrivKey.Serialize()
	var out [32]byte

	rc := C.bb_ellswift_xdh_bip324(
		(*C.uchar)(unsafe.Pointer(&ellA[0])),
		(*C.uchar)(unsafe.Pointer(&ellB[0])),
		(*C.uchar)(unsafe.Pointer(&seckey[0])),
		party,
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)
	if rc != 1 {
		// Constant-time-ish failure: returning zeros causes the BIP-324
		// handshake to fail downstream at the version-packet AEAD step,
		// which is the desired behaviour for an invalid input.
		var zero [32]byte
		return zero
	}
	return out
}
