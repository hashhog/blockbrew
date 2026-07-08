package crypto

// #cgo pkg-config: libsecp256k1
// #include <stdlib.h>
// #include <string.h>
// #include <secp256k1.h>
// #include <secp256k1_ellswift.h>
// #include <secp256k1_extrakeys.h>
// #include <secp256k1_schnorrsig.h>
//
// /*
//  * Lazily-allocated, process-wide libsecp256k1 context with VERIFY|SIGN
//  * flags.  Originally introduced for ElligatorSwift; generalized to also
//  * back consensus ECDSA + Schnorr signature verification (see
//  * bb_ecdsa_verify_compact / bb_schnorr_verify below).  ellswift_create
//  * performs an internal pubkey derivation that needs SIGN; ellswift_xdh
//  * and both verify paths only need VERIFY but are fine with both.  Mirrors
//  * haskoin's cbits/secp256k1_compat.c::get_ellswift_ctx and ouroboros's
//  * reuse of coincurve._libsecp256k1.lib.secp256k1_context_no_precomp.
//  *
//  * The context is seeded with 32 bytes of caller-supplied entropy via
//  * secp256k1_context_randomize at initialisation.  Per
//  * secp256k1.h:820-841 + Core key.cpp:572-587, this provides
//  * side-channel-blinding for the secret-scalar / base-point
//  * multiplication that backs secp256k1_ellswift_create.  See W159
//  * BUG-3 ("side-channel-blinding-disabled" fleet pattern).
//  */
// static secp256k1_context *bb_secp_ctx = NULL;
//
// /* Create the context and seed it with 32 bytes of entropy.  Returns 1
//  * on success, 0 on failure (context_create or context_randomize
//  * failed).  Must be called exactly once before bb_get_ctx().  Idempotent:
//  * subsequent calls re-randomize the existing context (defence in depth). */
// static int bb_init_ctx(const unsigned char *seed32) {
//     if (bb_secp_ctx == NULL) {
//         bb_secp_ctx = secp256k1_context_create(
//             SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
//         if (bb_secp_ctx == NULL) return 0;
//     }
//     return secp256k1_context_randomize(bb_secp_ctx, seed32);
// }
//
// static secp256k1_context *bb_get_ctx(void) {
//     return bb_secp_ctx;
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
//
// /*
//  * Consensus ECDSA verify.  The caller (Go VerifyECDSALax) has already run
//  * the lax-DER parser + low-S normalization and hands us a 64-byte compact
//  * (r||s, big-endian, both in [1,n) and low-S) signature, a 32-byte message
//  * hash, and a serialized public key (33-byte compressed or 65-byte
//  * uncompressed).  We do NOT do lax-DER parsing in-library — libsecp256k1
//  * has no lax parser and using its strict parser here would change the
//  * accept set (consensus hazard).  Returns 1 on valid, 0 on invalid/reject.
//  */
// static int bb_ecdsa_verify_compact(
//     const unsigned char *sig64,
//     const unsigned char *msg32,
//     const unsigned char *pubkey_ser,
//     size_t pubkey_len
// ) {
//     secp256k1_context *ctx = bb_get_ctx();
//     if (!ctx) return 0;
//     secp256k1_ecdsa_signature sig;
//     /* parse_compact only fails if r or s >= n; the Go side already
//      * rejects that range, so this is belt-and-suspenders. */
//     if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sig64)) {
//         return 0;
//     }
//     secp256k1_pubkey pubkey;
//     if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey_ser, pubkey_len)) {
//         return 0;
//     }
//     /* secp256k1_ecdsa_verify enforces low-S (rejects high-S); the Go side
//      * already normalized to low-S, matching Core's post-BIP66/BIP146
//      * consensus behaviour where the engine normalizes before verify. */
//     return secp256k1_ecdsa_verify(ctx, &sig, msg32, &pubkey);
// }
//
// /*
//  * Consensus BIP-340 Schnorr verify.  32-byte x-only pubkey, 64-byte sig,
//  * variable-length message (Bitcoin always passes 32 bytes, but BIP-340 is
//  * mlen-agnostic and the test vectors exercise 0/1/17/100-byte messages).
//  * Direct drop-in for secp256k1_schnorrsig_verify.  Returns 1 valid, 0 reject.
//  */
// static int bb_schnorr_verify(
//     const unsigned char *sig64,
//     const unsigned char *msg,
//     size_t msglen,
//     const unsigned char *xonly32
// ) {
//     secp256k1_context *ctx = bb_get_ctx();
//     if (!ctx) return 0;
//     secp256k1_xonly_pubkey pubkey;
//     if (!secp256k1_xonly_pubkey_parse(ctx, &pubkey, xonly32)) {
//         return 0;
//     }
//     return secp256k1_schnorrsig_verify(ctx, sig64, msg, msglen, &pubkey);
// }
import "C"

import (
	"crypto/rand"
	"errors"
	"sync"
	"unsafe"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ErrEllSwiftCtxInit is returned when libsecp256k1 fails to initialise
// the ellswift context — either secp256k1_context_create returned NULL
// or secp256k1_context_randomize returned 0.  Both are vanishingly rare
// (the randomize seed comes from crypto/rand and is non-NULL); a
// non-nil error here typically means OOM or a libsecp256k1 ABI break.
var ErrEllSwiftCtxInit = errors.New("ellswift: libsecp256k1 context init / randomize failed")

// ctxInitOnce + ctxInitErr lazily initialise the cgo ellswift context
// exactly once per process with 32 bytes of fresh entropy from
// crypto/rand, then call secp256k1_context_randomize to enable
// side-channel-blinding on the secret-scalar / base-point multiplication
// (Core key.cpp:572-587 ; W159 BUG-3).
var (
	ctxInitOnce sync.Once
	ctxInitErr  error
)

// ensureCtx initialises (once) the lazily-allocated ellswift context
// and seeds it with secp256k1_context_randomize.  Returns the cached
// init error on subsequent calls.  Cheap on the hot path (one
// sync.Once.Do indirection after the first call).
func ensureCtx() error {
	ctxInitOnce.Do(func() {
		var seed [32]byte
		if _, err := rand.Read(seed[:]); err != nil {
			ctxInitErr = err
			return
		}
		rc := C.bb_init_ctx((*C.uchar)(unsafe.Pointer(&seed[0])))
		if rc != 1 {
			ctxInitErr = ErrEllSwiftCtxInit
		}
	})
	return ctxInitErr
}

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
	if err := ensureCtx(); err != nil {
		return out, err
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
	if err := ensureCtx(); err != nil {
		return nil, err
	}
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
	if err := ensureCtx(); err != nil {
		// Same constant-time-ish sentinel as the rc != 1 path below:
		// returning zeros causes the BIP-324 handshake to fail at the
		// version-packet AEAD step, the desired behaviour for any
		// context-init failure (OOM / libsecp256k1 ABI break).
		var zero [32]byte
		return zero
	}
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

// ---------------------------------------------------------------------------
// libsecp256k1-backed signature verification (consensus hot path).
//
// These two functions are the cgo half of VerifyECDSALax (ecdsa.go) and
// VerifySchnorrMsg (schnorr.go).  They reuse the same lazily-initialised,
// randomized secp256k1 context as the ellswift codec above.  The pure-Go
// dcrec implementations remain in-tree (verifyECDSALaxDcrec /
// verifySchnorrMsgDcrec) as a reference oracle for the differential-
// equivalence tests (libsecp_diff_test.go).

// ecdsaVerifyCompactLibsecp verifies a low-S-normalized 64-byte compact
// signature (r||s, big-endian) against msgHash32 and a serialized public
// key (33-byte compressed or 65-byte uncompressed) via libsecp256k1's
// secp256k1_ecdsa_verify.  The DER (lax) parsing and low-S normalization
// are performed by the Go caller before this point — libsecp256k1 has no
// lax-DER parser, so doing it in-library would change the accept set.
// Returns false on any parse failure or invalid signature.
func ecdsaVerifyCompactLibsecp(pubKeySer, msgHash32, compactSig64 []byte) bool {
	if len(compactSig64) != 64 || len(msgHash32) != 32 || len(pubKeySer) == 0 {
		return false
	}
	if err := ensureCtx(); err != nil {
		return false
	}
	rc := C.bb_ecdsa_verify_compact(
		(*C.uchar)(unsafe.Pointer(&compactSig64[0])),
		(*C.uchar)(unsafe.Pointer(&msgHash32[0])),
		(*C.uchar)(unsafe.Pointer(&pubKeySer[0])),
		C.size_t(len(pubKeySer)),
	)
	return rc == 1
}

// schnorrVerifyLibsecp verifies a 64-byte BIP-340 Schnorr signature over
// msg (variable length) against a 32-byte x-only public key via
// libsecp256k1's secp256k1_schnorrsig_verify.  Returns false on any parse
// failure or invalid signature.
func schnorrVerifyLibsecp(pubKeyXOnly32, msg, sig64 []byte) bool {
	if len(pubKeyXOnly32) != 32 || len(sig64) != 64 {
		return false
	}
	if err := ensureCtx(); err != nil {
		return false
	}
	// An empty message is valid under BIP-340 (test vector 15, mlen=0).
	// cgo requires a non-nil pointer even when msglen==0, so back it with a
	// 1-byte stack array that libsecp256k1 will not read past msglen=0.
	var dummy [1]byte
	msgPtr := (*C.uchar)(unsafe.Pointer(&dummy[0]))
	if len(msg) > 0 {
		msgPtr = (*C.uchar)(unsafe.Pointer(&msg[0]))
	}
	rc := C.bb_schnorr_verify(
		(*C.uchar)(unsafe.Pointer(&sig64[0])),
		msgPtr,
		C.size_t(len(msg)),
		(*C.uchar)(unsafe.Pointer(&pubKeyXOnly32[0])),
	)
	return rc == 1
}
