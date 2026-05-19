# W158 — BIP-322 message signing (blockbrew)

**Wave:** W158 — `signmessage` / `verifymessage` / `signmessagewithprivkey`
RPCs, `MessageSign` / `MessageVerify` / `MessageHash` library, BIP-137
(legacy P2PKH) magic-prefix framing, **BIP-322 Simple mode** (segwit /
taproot virtual-witness sigs), **BIP-322 Full mode** (full virtual
`to_spend` + `to_sign` transactions), BIP-141/143 sighashing inside
BIP-322 Full, BIP-341 key/script-path sighashing for Taproot BIP-322,
low-S enforcement, NUMS-point fallback for script-path Taproot.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/common/signmessage.cpp` — `MessageSign` (compact
  ECDSA over `MessageHash(message)` → base64), `MessageVerify` (decode
  base64 → `RecoverCompact` → `PKHash(pubkey) == dest` PKH-only),
  `MessageHash` (`HashWriter << MESSAGE_MAGIC << message` → SHA256d),
  `MESSAGE_MAGIC = "Bitcoin Signed Message:\n"` (24 chars,
  serialised through `HashWriter::operator<<` which prefixes a
  CompactSize length).
- `bitcoin-core/src/common/signmessage.h` — `MessageVerificationResult`
  enum (`OK`, `ERR_INVALID_ADDRESS`, `ERR_ADDRESS_NO_KEY`,
  `ERR_MALFORMED_SIGNATURE`, `ERR_PUBKEY_NOT_RECOVERED`,
  `ERR_NOT_SIGNED`); `SigningResult` enum (`OK`,
  `PRIVATE_KEY_NOT_AVAILABLE`, `SIGNING_FAILED`).
- `bitcoin-core/src/rpc/signmessage.cpp` — RPC handlers (`verifymessage`,
  `signmessagewithprivkey`); `verifymessage` returns BOOLEAN on `OK` /
  `ERR_PUBKEY_NOT_RECOVERED` / `ERR_NOT_SIGNED`, but throws RPC errors
  for the three "invalid input" cases. `signmessagewithprivkey` decodes
  via `DecodeSecret` (per-chain WIF), enforces `key.IsValid()`, throws
  `RPC_INVALID_ADDRESS_OR_KEY` for invalid privkey or sign failure.
- `bitcoin-core/src/wallet/rpc/signmessage.cpp` — `signmessage` wallet
  RPC, resolves `address` via `DecodeDestination`, type-checks
  `std::get_if<PKHash>(&dest)` (P2PKH only), calls `EnsureWalletIsUnlocked`,
  invokes `pwallet->SignMessage(...)`; maps `SigningResult::PRIVATE_KEY_
  NOT_AVAILABLE` to `RPC_WALLET_ERROR` (-4), `SIGNING_FAILED` to
  `RPC_INVALID_ADDRESS_OR_KEY` (-5).
- `bitcoin-core/src/key.cpp:250-279` — `CKey::SignCompact`:
  `secp256k1_ecdsa_sign_recoverable` (RFC6979 nonce, canonical low-S
  by the library), serialises to 65 bytes with recovery byte =
  `27 + rec + (fCompressed ? 4 : 0)`. Includes a **post-sign
  verification step** (recover pubkey from signature, compare to
  derived pubkey) to detect bit-flip corruption — Bitcoin Core's
  defense-in-depth pattern.
- BIP-322 §"Simple Signature" — base64 of `to_sign.witness`
  serialisation, where `to_sign` is a virtual transaction spending
  `to_spend.txid:0`:
  - `to_spend = { version: 0, locktime: 0, vin: [{ prev_out: null
    (32-byte zero hash + 0xFFFFFFFF index), seq: 0, scriptSig:
    "OP_0 PUSH(sha256_tag('BIP0322-signed-message', message))" }],
    vout: [{ value: 0, scriptPubKey: address.scriptPubKey }] }`
  - `to_sign = { version: 0, locktime: 0, vin: [{ prev_out:
    to_spend.txid:0, seq: 0, scriptSig: "" (or witness for segwit),
    witness: [signature, ...] }], vout: [{ value: 0, scriptPubKey:
    OP_RETURN }] }`
- BIP-322 §"Full Signature" — base64 of the **entire serialised**
  `to_sign` transaction, allowing multi-input proofs and complex
  scriptSig/witness commitments.
- BIP-322 §"Verification" — signer is a valid signature for the
  challenge iff full script execution of `to_sign.vin[0].scriptSig +
  to_spend.vout[0].scriptPubKey` + witness yields TRUE under
  BIP-143/BIP-341 sighashing of `to_sign`.
- BIP-322 §"Taproot" — for Taproot key-spend, use BIP-341 sighash
  with `SIGHASH_DEFAULT`. For script-path, use the unspendable NUMS
  point `H = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`
  as internal key.

**Files audited**
- `internal/crypto/signmessage.go` — `MessageMagic` constant,
  `writeCompactSize` (local CompactSize encoder), `MessageHash`
  (compactsize-len(magic) || magic || compactsize-len(msg) || msg →
  DoubleSHA256), `SignMessageCompact` (delegates to
  `decred/dcrd/dcrec/secp256k1/v4/ecdsa.SignCompact`),
  `RecoverPubKeyFromCompact`. Lines 1-86.
- `internal/crypto/signmessage_test.go` — `TestMessageHashKnownVector`
  pins the framing to the byte sequence `0x18 ... 0x05 "hello"` and
  hash `cf04...84f4`. Lines 1-128.
- `internal/rpc/extra_methods.go:875-877` — help-string registrations
  for `signmessage`, `signmessagewithprivkey`, `verifymessage` (no
  BIP-322 mode argument).
- `internal/rpc/extra_methods.go:910-969` — `handleVerifyMessage`
  (P2PKH-only gate at line 935; base64 decode; `RecoverPubKeyFromCompact`;
  Hash160 of recovered pubkey via compressed-or-uncompressed flag from
  recovery byte; equality check vs decoded address.Hash).
- `internal/rpc/extra_methods.go:971-1016` — `handleSignMessage`
  (P2PKH-only gate at line 1001; `getWalletForRPC` → `GetKeyForAddress` →
  `SignMessageCompact` → base64).
- `internal/rpc/extra_methods.go:1018-1045` — `handleSignMessageWithPrivKey`
  (`decodeWIFForRPC` → `SignMessageCompact` → base64).
- `internal/rpc/extra_methods.go:1047-1074` — `decodeWIFForRPC` (mainnet
  `0x80` / testnet/regtest/signet `0xef`; compressed flag bit 0x01;
  payload length 32 or 33).
- `internal/rpc/server.go:732-737` — RPC dispatch table:
  `verifymessage`, `signmessage`, `signmessagewithprivkey`.
- `internal/wallet/wallet.go:861-885` — `GetKeyForAddress` (returns
  `ErrInvalidAddress`, `ErrWalletLocked`, `ErrNoMasterKey`, or a
  BIP32-derived `*PrivateKey`).
- `internal/address/address.go` — `DecodeAddress`, address types
  (`P2PKH`, `P2SH`, `P2WPKH`, `P2WSH`, `P2TR`), `Hash` field carries
  20-byte PKH/SH or 20/32-byte witness program.
- `internal/rpc/methods.go:2409-2424` — `getNetwork()` switch (cross-cite
  for BUG-7).
- `internal/wire/types.go:221` — `MsgTx.Version int32` (W132 carry-forward
  cross-cite).
- `internal/rpc/signmessage_test.go` — `TestSignAndVerifyMessageRoundTrip`,
  `TestSignMessageRejectsSegwit`, `TestVerifyMessageInvalidAddress`,
  `TestSignMessageWithPrivKeyRoundTrip`.

---

## Gate matrix (28 sub-gates / 7 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Legacy BIP-137 MessageHash | G1: magic = "Bitcoin Signed Message:\n" (no leading 0x18) | PASS (`signmessage.go:14`) |
| 1 | … | G2: CompactSize prefix for both magic AND message length | PASS (`signmessage.go:51-55`) |
| 1 | … | G3: double-SHA256 of the prefixed buffer | PASS (`signmessage.go:56`) |
| 1 | … | G4: matches Core's HashWriter `<<` framing on a known vector | PASS (`signmessage_test.go:15-28`, hash `cf04...84f4`) |
| 2 | signmessage RPC (wallet) | G5: P2PKH-only gate | PASS (`extra_methods.go:1001`) |
| 2 | … | G6: HELP_REQUIRING_PASSPHRASE / EnsureWalletIsUnlocked equivalent | **BUG-1 (P1)** — no explicit `EnsureWalletIsUnlocked` precheck; reliance on `GetKeyForAddress`'s `ErrWalletLocked` return, which is then mapped to **wrong error code** (BUG-2) |
| 2 | … | G7: locked-wallet error mapped to RPC_WALLET_UNLOCK_NEEDED (-13) | **BUG-2 (P1)** — `extra_methods.go:1005-1008` maps any `GetKeyForAddress` error (including `ErrWalletLocked` AND `ErrInvalidAddress` AND `ErrNoMasterKey`) to `RPCErrInvalidAddressOrKey` (-5). Core distinguishes between -4 (RPC_WALLET_ERROR, "Private key not available") and -13 (RPC_WALLET_UNLOCK_NEEDED) |
| 2 | … | G8: returns base64-encoded 65-byte sig | PASS (`extra_methods.go:1014-1015`) |
| 3 | verifymessage RPC | G9: P2PKH-only gate (segwit → RPC_TYPE_ERROR) | PASS (`extra_methods.go:935`) |
| 3 | … | G10: invalid base64 → RPC_TYPE_ERROR -3 "Malformed base64 encoding" | PASS (`extra_methods.go:939-942`) |
| 3 | … | G11: pubkey recovery failure → BOOLEAN false (not RPC error) | PASS (`extra_methods.go:945-948`) |
| 3 | … | G12: Hash160 mismatch → BOOLEAN false | PASS (`extra_methods.go:963-967`) |
| 3 | … | G13: handles compressed AND uncompressed via recovery byte bit 0x04 (≥31) | PASS (`extra_methods.go:950-958`) |
| 3 | … | G14: invalid address → RPC_INVALID_ADDRESS_OR_KEY -5 | PASS (`extra_methods.go:931-934`) |
| 4 | signmessagewithprivkey RPC | G15: WIF decode | PASS (`extra_methods.go:1038-1041`) |
| 4 | … | G16: compressed flag propagated from WIF payload[32]=0x01 | PASS (`extra_methods.go:1043, 1067`) |
| 4 | … | G17: same MessageHash + SignCompact path as wallet signmessage | PASS (shared call to `bbcrypto.SignMessageCompact`) |
| 4 | … | G18: per-chain WIF prefix (0x80 mainnet, 0xef test/regtest/signet) | PARTIAL (`extra_methods.go:1056-1062`); see BUG-7 — `getNetwork()` mis-routes testnet3 chainparams to mainnet, so a testnet3 WIF will be rejected with "wrong network version" |
| 5 | Post-sign verification | G19: re-derive pubkey from signature; assert equality (Core key.cpp:262-269) | **BUG-3 (P1)** — `SignMessageCompact` (`signmessage.go:68-70`) is a one-liner that returns immediately. No re-derivation / equality check. A bit-flip in the secp256k1 nonce buffer between signing and serialisation would be silently propagated to base64. Core treats this as a fatal defense-in-depth assertion |
| 6 | BIP-322 Simple mode | G20: detect & dispatch Simple-mode signatures (witness-only base64) for segwit addresses | **BUG-4 (P0-CDIV)** — entire BIP-322 implementation absent. `signmessage`/`verifymessage` hard-reject ALL non-P2PKH addresses (segwit, taproot, P2SH) with RPC_TYPE_ERROR |
| 6 | … | G21: construct `to_spend` virtual tx (null prev_out, sequence=0, message-tagged scriptSig with `sha256_tag("BIP0322-signed-message", msg)`) | **BUG-5 (P0-CDIV)** — no `to_spend` constructor exists. Grep returns zero hits for `to_spend`, `to_sign`, `BIP0322`, `BIP322`, `virtual_tx` |
| 6 | … | G22: construct `to_sign` virtual tx (txid pointer to to_spend.vout[0], OP_RETURN output) | **BUG-5 cross-cite** |
| 6 | … | G23: BIP-143 sighash for P2WPKH/P2WSH | partial — BIP-143 sighashing exists in `internal/script/`, but no BIP-322 wiring uses it |
| 6 | … | G24: BIP-341 sighash for P2TR key-spend | partial — BIP-341 sighashing exists, but no BIP-322 wiring |
| 7 | BIP-322 Full mode | G25: parse `to_sign` from base64 → full transaction (multi-input) | **BUG-6 (P0-CDIV)** — no Full-mode decoder; no caller routes a base64-encoded transaction through wire deserialisation as a "BIP-322 verification" path |
| 7 | … | G26: execute full script on input[0] under BIP-143/BIP-341 sighash | **BUG-6 cross-cite** |
| 7 | … | G27: NUMS-point fallback for script-path Taproot (BIP-322 §"Taproot") | **BUG-6 cross-cite** |
| 7 | … | G28: low-S enforcement on BIP-322 ECDSA witness sigs | **BUG-6 cross-cite** (BIP-322 ECDSA verification path absent) |

---

## BUG-1 (P1) — `signmessage` lacks explicit `EnsureWalletIsUnlocked` precheck

**Severity:** P1. Bitcoin Core's wallet `signmessage` calls
`EnsureWalletIsUnlocked(*pwallet)` BEFORE attempting any address decode
or signing. This produces a uniform, early `RPC_WALLET_UNLOCK_NEEDED`
error (-13) with the canonical message "Error: Please enter the wallet
passphrase with walletpassphrase first." Tools that script against the
RPC rely on the -13 error code to prompt the user.

blockbrew's `handleSignMessage` (`internal/rpc/extra_methods.go:975-1016`)
has no equivalent gate. It runs:

```
getWalletForRPC → DecodeAddress → type-check P2PKH → GetKeyForAddress
```

`GetKeyForAddress` (`internal/wallet/wallet.go:861-885`) is the FIRST
operation that observes `w.locked`, and it returns `ErrWalletLocked`.
That error is wrapped at line 1007:

```go
privKey, err := w.GetKeyForAddress(addrStr)
if err != nil {
    return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: err.Error()}
}
```

— see BUG-2 for the error-code mismapping. The structural issue is
that the locked-wallet check happens AFTER address parsing and type
checks, so an operator on a locked wallet who passes a malformed
address receives `RPC_INVALID_ADDRESS_OR_KEY` for the address error
INSTEAD of `RPC_WALLET_UNLOCK_NEEDED` for the locked-wallet error.
The error order leaks the wallet-lock state through input-validation
ordering.

**File:** `internal/rpc/extra_methods.go:992-1008`.

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:44`
(`EnsureWalletIsUnlocked(*pwallet);` at the very top of the handler).

**Impact:** error-code parity gap for tools that scrape RPC errors;
information-disclosure through error ordering (operator can probe
whether a wallet is unlocked by passing valid vs invalid addresses).

---

## BUG-2 (P1) — Locked-wallet path returns `-5 (RPC_INVALID_ADDRESS_OR_KEY)` instead of `-13 (RPC_WALLET_UNLOCK_NEEDED)`

**Severity:** P1. Core's `signmessage` wallet handler maps
`SigningResult::PRIVATE_KEY_NOT_AVAILABLE` (which is what happens when
the wallet is locked) through `SigningResultString` and throws
`RPC_WALLET_ERROR` (-4) with the message
"Private key not available". For an actively-locked wallet, the
upstream `EnsureWalletIsUnlocked` path emits the canonical
`RPC_WALLET_UNLOCK_NEEDED` (-13) earlier.

blockbrew's `handleSignMessage` collapses every `GetKeyForAddress`
failure mode to `RPCErrInvalidAddressOrKey` (-5):

```go
privKey, err := w.GetKeyForAddress(addrStr)
if err != nil {
    return nil, &RPCError{Code: RPCErrInvalidAddressOrKey, Message: err.Error()}
}
```

`GetKeyForAddress` distinguishes three errors:
- `ErrInvalidAddress` (address not in this wallet) → should map to
  RPC_WALLET_ERROR (-4) "Address does not belong to wallet" per Core
  convention (Core throws this from `LegacyScriptPubKeyMan::GetKey`).
- `ErrWalletLocked` → should map to RPC_WALLET_UNLOCK_NEEDED (-13).
- `ErrNoMasterKey` → should map to RPC_WALLET_ERROR (-4) "Wallet has
  no master key".

All three collapse to -5 in blockbrew. The error code -5 also doubles
as "invalid address" (the SAME code path returns -5 for
`DecodeAddress` failure at line 999) — so callers cannot distinguish
"the address you supplied was malformed" from "the address is valid
but I don't have its key" from "the wallet is locked".

Additionally, the RPC error type code table (`internal/rpc/types.go:33`)
defines `RPCErrWalletPassphraseIncorrect = -14`, but there is NO
constant for `RPC_WALLET_UNLOCK_NEEDED = -13` at all — blockbrew
appears never to emit this code anywhere.

**File:** `internal/rpc/extra_methods.go:1005-1008`; missing constant
in `internal/rpc/types.go:33`.

**Core ref:**
`bitcoin-core/src/wallet/rpc/signmessage.cpp:60-64`
(SigningResult error mapping);
`bitcoin-core/src/wallet/rpc/util.cpp::EnsureWalletIsUnlocked`
(emits -13).

**Impact:** RPC-error contract divergence. Cross-impl test suites that
assert on `error.code == -13` for locked wallets fail on blockbrew.
Programmable wallet-prompt tools that branch on -13 to surface a
passphrase dialog won't trigger.

---

## BUG-3 (P1) — `SignMessageCompact` skips Core's post-sign verification step

**Severity:** P1 (defense-in-depth). Bitcoin Core's `CKey::SignCompact`
(`bitcoin-core/src/key.cpp:262-269`) runs an explicit post-sign
verification:

```cpp
// Additional verification step to prevent using a potentially
// corrupted signature
secp256k1_pubkey epk, rpk;
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &epk, ...);
assert(ret);
ret = secp256k1_ecdsa_recover(secp256k1_context_static, &rpk, &rsig,
                                hash.begin());
assert(ret);
ret = secp256k1_ec_pubkey_cmp(secp256k1_context_static, &epk, &rpk);
assert(ret == 0);
```

The comment is explicit: "to prevent using a potentially corrupted
signature". This catches bit-flips in the secp256k1 ECC engine, bad
RAM, faulty CPU multiplication units, or buggy library updates.

blockbrew's `SignMessageCompact` is a one-liner:

```go
func SignMessageCompact(privKey *PrivateKey, hash [32]byte,
                        compressed bool) []byte {
    return ecdsa.SignCompact(privKey.key, hash[:], compressed)
}
```

No recovery, no comparison. A bit-flip during the sign or
serialisation phase silently propagates into the base64-encoded
signature, where it might verify correctly under a recovered wrong
pubkey, OR it might fail under recovery; the operator has no way to
distinguish the case.

The `decred/dcrd` library does run an internal verification inside
`signRFC6979` (rejecting nonces that fail to produce a valid signature
and retrying with a new RFC6979 step), but it does not re-derive the
public key from the produced signature and compare it to the signer's
pubkey. That second-layer check is exactly what Core's post-sign
verification adds.

**File:** `internal/crypto/signmessage.go:68-70`.

**Core ref:** `bitcoin-core/src/key.cpp:262-269` (post-sign
verification with explicit defensive intent comment).

**Impact:** defense-in-depth gap. On healthy hardware no observable
divergence; on degraded hardware (ECC RAM error, faulty CPU silicon,
bad library) a corrupted signature is exported. Cross-impl: blockbrew
trusts the library; Core does not.

---

## BUG-4 (P0-CDIV) — BIP-322 Simple-mode verification entirely absent

**Severity:** P0-CDIV. BIP-322 (specified 2018, draft-active in 2019,
ratified by widespread wallet implementation 2022-2024) defines a
canonical "sign-with-segwit-and-taproot-addresses" message protocol.
The user-facing contract is that **any** valid Bitcoin address type
(P2PKH, P2SH, P2WPKH, P2WSH, P2TR) can sign and verify a message via
`signmessage`/`verifymessage`.

blockbrew's `handleVerifyMessage` (`internal/rpc/extra_methods.go:935-937`)
hard-rejects every non-P2PKH address:

```go
if addr.Type != address.P2PKH {
    return nil, &RPCError{Code: RPCErrTypeError,
                          Message: "Address does not refer to key"}
}
```

The test `TestSignMessageRejectsSegwit`
(`internal/rpc/signmessage_test.go:106-134`) **pins this behavior as
intentional** with the comment "the Core-compatible behavior that
segwit addresses cannot be used with signmessage / verifymessage."

This was Core-compatible when Core itself rejected segwit, but the
modern Core (and every modern wallet — Sparrow, Specter, BlueWallet,
Electrum, Wasabi, Trezor, Coldcard, Foundation, etc.) implements
BIP-322 and accepts segwit/taproot signatures for both signing and
verification. Users with bc1q/bc1p addresses who try to prove
ownership to a service that uses blockbrew get a hard "Address does
not refer to key" rejection.

The full BIP-322 Simple-mode verification path involves:

1. Parse the base64-encoded signature as the **witness stack** of a
   virtual `to_sign` transaction.
2. Compute `to_spend` from the address and message:
   - vin[0].prev_out = `(0x00..00, 0xFFFFFFFF)` (null)
   - vin[0].sequence = 0
   - vin[0].scriptSig = `OP_0 PUSH(sha256_tag("BIP0322-signed-message", msg))`
     (using BIP-340 tagged-hash framing)
   - vout[0].value = 0
   - vout[0].scriptPubKey = `address.ScriptPubKey()`
3. Construct `to_sign`:
   - vin[0].prev_out = `(to_spend.txid, 0)`
   - vin[0].sequence = 0
   - vin[0].witness = decoded witness stack from base64
   - vout[0].value = 0
   - vout[0].scriptPubKey = `OP_RETURN`
4. Execute `to_sign.vin[0].scriptSig + to_spend.vout[0].scriptPubKey`
   with the witness stack under BIP-143 (segwit v0) or BIP-341
   (taproot v1) sighashing, verifying the resulting signature
   commits to `to_sign`'s sighash.

None of this exists. Grep for `BIP322`, `BIP-322`, `bip322`, `to_spend`,
`to_sign`, `BIP0322` against the whole tree returns zero hits.

**File:** `internal/rpc/extra_methods.go:935-937` (hard-reject);
test pins the bug as a feature at `signmessage_test.go:106-134`.

**Core ref:** BIP-322 §"Simple Signature"; Bitcoin Core does NOT yet
ship BIP-322 in its `signmessage` RPC as of master (see
`src/wallet/rpc/signmessage.cpp` still PKHash-only), so blockbrew's
behaviour matches Core's RPC surface — but Core's wallet-level
`SignMessage` interface in `src/wallet/wallet.h` accepts `PKHash`
only, and Core's policy is that BIP-322 lives in the wallet ecosystem
(Sparrow / Specter / hardware) rather than at the RPC layer.

**However,** blockbrew advertises the modern address types
(P2WPKH/P2WSH/P2TR) in `AddressType` enum and as wallet default
(`AddressTypeP2WPKH` is iota=0, the zero-value default), so a user
creating a fresh wallet ends up with bc1q… addresses that cannot
sign any message. The user-facing UX is:

```
$ bitcoin-cli getnewaddress
bc1q...
$ bitcoin-cli signmessage bc1q... "I own this"
error code: -3
error message: Address does not refer to key
```

— there is no migration path from this hard-reject to a working
signature.

**Impact:**
- Modern wallet UX broken: default wallet creates segwit/taproot
  addresses; default address cannot be signed against.
- Interop break: tools that verify BIP-322 signatures against blockbrew
  RPC report all segwit/taproot signatures as "Address does not refer
  to key", even when they're cryptographically valid.
- Cross-fleet first instance — this is the first time a hashhog impl's
  BIP-322 surface has been audited; the absence is a fleet pattern
  candidate (likely 8-10 of 10 impls).

---

## BUG-5 (P0-CDIV) — BIP-322 virtual-tx (`to_spend` / `to_sign`) construction absent

**Severity:** P0-CDIV. Even if BUG-4 were fixed by routing segwit
addresses to a non-BIP-322 fallback (e.g., trial-recover compact ECDSA
sigs against the witness program), the canonical mechanism is BIP-322
Simple-mode, which REQUIRES the two virtual transactions described in
BUG-4. Without `to_spend` / `to_sign`, there is no way to produce or
verify BIP-322 sigs.

Grep over the entire tree:

```
$ grep -rn "to_spend\|to_sign\|BIP322\|BIP-322\|bip322\|BIP0322" internal/ cmd/
(no output)
```

Specifically missing:
1. A `BIP322ToSpend(address, message) → *MsgTx` constructor.
2. A `BIP322ToSign(toSpend, witness) → *MsgTx` constructor.
3. A `BIP322MessageHash(message) → [32]byte` using
   `sha256_tag("BIP0322-signed-message", message)` (per
   BIP-340 §"Tagged Hashes": `sha256(sha256("BIP0322-signed-message") ||
   sha256("BIP0322-signed-message") || message)`).
4. The constants for the BIP-322 tag.

There is no BIP-340 tagged-hash helper in `internal/crypto/` for
arbitrary tags, only `MessageHash` (BIP-137 magic-prefix). The script
package has `taprootSighash` but that's BIP-341 not BIP-322.

**File:** `internal/crypto/signmessage.go` (no BIP-322 surface);
`internal/wire/types.go` (no virtual-tx helpers); `internal/rpc/extra_methods.go`
(no BIP-322 dispatch).

**Core ref:** BIP-322 §"Construction"; absent from Core RPC layer as
well (Core defers BIP-322 to wallet ecosystem), but the **library
primitives** would have to exist for any future wiring.

**Impact:** even as a library, blockbrew cannot produce or consume
BIP-322 sigs. Any tool that wants to integrate (e.g., a maintenance
script that asks for proof-of-ownership of cold-storage segwit
addresses) hits a wall.

---

## BUG-6 (P0-CDIV) — BIP-322 Full mode (multi-input virtual transactions) entirely absent

**Severity:** P0-CDIV. BIP-322 Full mode encodes the **entire**
serialised `to_sign` transaction (not just the witness stack) as base64
and is the only way to commit to:
- Multi-input proofs (proving you own the keys behind a list of
  inputs in a hypothetical transaction).
- Complex scriptSig commitments (e.g., proving ownership of a P2SH
  redeemScript that requires non-witness data).
- Script-path Taproot proofs that use the BIP-322 NUMS-point fallback
  `H = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`
  as the unspendable internal key.

blockbrew has no Full-mode decoder. Verification would require:

1. Decode base64 → byte stream.
2. Deserialise as a wire transaction (`MsgTx.Deserialize`).
3. Reconstruct `to_spend` from the address + message.
4. Validate `to_sign.vin[0].prev_out == (to_spend.txid, 0)`.
5. Validate `to_sign.vin[0].sequence == 0`.
6. Validate `to_sign.vout[0] == (0, OP_RETURN)`.
7. Validate `to_sign.version == 0`.
8. Validate `to_sign.locktime == 0`.
9. Execute the script (per address type) with BIP-143/BIP-341 sighash
   bound to `to_sign`.
10. **For Taproot script-path:** verify the internal key is either the
    actual taproot internal key (key-spend) or the NUMS-point
    constant H (script-path fallback).

None of steps 3-10 exist. The MsgTx deserialiser in
`internal/wire/types.go` works for ordinary transactions but the
BIP-322 wrapper validation (steps 4-8) and the BIP-322-specific NUMS
constant (step 10) are absent.

The W132 carry-forward observation here: `MsgTx.Version int32`
(`internal/wire/types.go:221`) — BIP-322 explicitly requires
`to_sign.version == 0`. With `int32`, the wire-decoded value can carry
a sign-extended negative when bit 31 is set, which would fail an
`== 0` check on inputs that should have failed earlier. Net effect on
BIP-322: if/when implemented, a `version = 0x80000000` input
(decoded as a negative `int32`) would not match `to_sign.version == 0`
even though both bit patterns encode the same on-wire value as a
4-byte little-endian unsigned integer. This is the same bit-31
inversion as W132 BUG-1 (rated P0-CDIV in W132 with the comment
"closes 2 P0-CDIVs").

**File:** absent across `internal/`.

**Core ref:** BIP-322 §"Full Signature".

**Impact:**
- Hardware wallet integration broken: Coldcard/Ledger/Trezor produce
  Full-mode sigs for multi-input proofs; blockbrew cannot consume them.
- Compliance / proof-of-reserves use cases broken: a custodian who
  signs a single Full-mode message committing to a list of addresses
  cannot have that proof verified by a blockbrew-based auditor.
- Taproot script-path BIP-322 entirely unverifiable.

---

## BUG-7 (P1) — `getNetwork()` mis-routes `testnet3` to mainnet, breaking signmessage on testnet3 wallets

**Severity:** P1. `internal/rpc/methods.go:2410-2424`:

```go
func (s *Server) getNetwork() address.Network {
    if s.chainParams == nil {
        return address.Mainnet
    }
    switch s.chainParams.Name {
    case "testnet4", "testnet":
        return address.Testnet
    case "regtest":
        return address.Regtest
    case "signet":
        return address.Signet
    default:
        return address.Mainnet
    }
}
```

The chainparams `Name` for testnet3 is `"testnet3"` (`internal/consensus/chaincfg.go:223`),
NOT `"testnet"`. There is no `"testnet"` case. So a node started with
`-network=testnet3` chainparams falls through to the `default` branch
and returns `address.Mainnet`.

This is not BIP-322-specific — it's a cross-cutting bug — but it
manifests for signmessage/verifymessage as:

- `handleVerifyMessage` calls `address.DecodeAddress(addrStr, s.getNetwork())`
  with the wrong network → testnet3 P2PKH addresses (version `0x6F`,
  starting with `m`/`n`) fail with `ErrNetworkMismatch`, returning
  RPC_INVALID_ADDRESS_OR_KEY -5 "Invalid address".
- `handleSignMessage` same issue.
- `handleSignMessageWithPrivKey` calls `decodeWIFForRPC(wif, s.getNetwork())`,
  which checks `expectedVersion == 0x80` (mainnet) for `network ==
  Mainnet`. A testnet3 WIF (prefix `0xef`) fails with "wrong network
  version".

Net effect on a testnet3 node: signmessage and verifymessage cannot
process testnet3 addresses or WIFs at all.

**File:** `internal/rpc/methods.go:2410-2424`.

**Impact:** signmessage/verifymessage fully broken on testnet3.
Cross-cut bug — also affects other RPCs that call `getNetwork()`
(decoderawtransaction, validateaddress, etc.). Reported here because
it manifests for BIP-137 signmessage as a hard failure.

---

## BUG-8 (P1) — Wallet test pins segwit-rejection as a feature, blocking BIP-322 future fix

**Severity:** P1 (process / test-as-policy). The test
`TestSignMessageRejectsSegwit` in
`internal/rpc/signmessage_test.go:106-134` explicitly asserts that
segwit addresses MUST be rejected:

```go
// TestSignMessageRejectsSegwit pins the Core-compatible behavior that
// segwit addresses cannot be used with signmessage / verifymessage. A
// regression here (silently allowing P2WPKH) would diverge from Core
// and break interop with Electrum / hardware wallets that expect the
// P2PKH-only contract.
```

The comment is wrong: every modern wallet (Electrum included)
implements BIP-322 and signs against segwit/taproot. The test as
written makes a future BIP-322 fix BACKWARD-INCOMPATIBLE with the
existing test suite — any contributor adding BIP-322 support will
have to delete this test, and the test's docstring will mislead them
into thinking the change is a "regression".

This is the "comment-as-confession" + "test-pins-bug" pattern — the
test asserts the bug is the intended behavior, locking the bug in.

**File:** `internal/rpc/signmessage_test.go:102-134`.

**Impact:** future-proofing gap; the existing tests would have to be
rewritten (and the docstring comment retracted) when BIP-322 is added.
Process risk: contributors may see the green test and think the
behavior is correct.

---

## BUG-9 (P1) — `help` output and `extra_methods.go` registration omit any mention of message-mode

**Severity:** P1. `internal/rpc/extra_methods.go:875-877` registers
help text:

```
"signmessage \"address\" \"message\"",
"signmessagewithprivkey \"privkey\" \"message\"",
"verifymessage \"address\" \"signature\" \"message\"",
```

A future BIP-322 implementation would need to add a `mode` argument
(`"legacy"` / `"simple"` / `"full"`) per the de-facto BIP-322 RPC
convention used by other wallet daemons. The help registration
doesn't preserve room for this evolution.

Additionally, no help registration mentions that the RPCs are
PKH-only — operators read the help and reasonably assume any address
works, then receive a confusing "Address does not refer to key" error.

**File:** `internal/rpc/extra_methods.go:875-877`.

**Impact:** operator UX gap; future-feature placement gap.

---

## BUG-10 (P1) — Test `TestSignMessageWithPrivKeyRoundTrip` constructs the address path **outside** the wallet, hiding a sign-vs-verify symmetry assumption

**Severity:** P1 (test-coverage gap). The test derives the P2PKH
address EXTERNALLY (`internal/rpc/signmessage_test.go:161-169`):

```go
pkh := bbcrypto.Hash160(priv.PubKey().SerializeCompressed())
var pkhArr [20]byte
copy(pkhArr[:], pkh[:])
addrObj := address.NewP2PKHAddress(pkhArr, address.Mainnet)
```

— and uses `compressed=true` because `decodeWIFForRPC` returns the
compressed flag from the WIF payload. But `handleSignMessage`
hardcodes `compressed=true` at line 1014:

```go
// Wallet-derived keys are always compressed (BIP32 produces compressed
// pubkeys), and the owning P2PKH address was hashed from the
// compressed pubkey, so we must sign with isCompressedKey=true.
sig := bbcrypto.SignMessageCompact(privKey, hash, true)
```

This works for the wallet path (BIP32 always produces compressed
pubkeys, agreed). But it means `handleSignMessage` (wallet path)
**cannot sign with an uncompressed key**, even if the imported address
was hashed from the uncompressed form. blockbrew's wallet doesn't
support importing arbitrary uncompressed keys (BIP32-only), so this
is currently unreachable — but `handleSignMessageWithPrivKey` (which
DOES support uncompressed WIFs, payload length == 32 path at
`extra_methods.go:1069-1070`) signs with `compressed=false`, which
means a verify call against an address derived from the SAME private
key but its compressed pubkey will fail (Hash160 of compressed pubkey
≠ Hash160 of uncompressed pubkey).

Net effect: an operator who has a legacy uncompressed-key wallet (rare
but exists in pre-2014 deployments) and uses
`signmessagewithprivkey` with the uncompressed WIF expects to verify
against the legacy "uncompressed" 1... address. If they accidentally
verify against the compressed 1... address derived from the same key,
verification fails silently with no diagnostic — the same private key,
different addresses.

This is correct behaviour, but the contract is invisible: there's no
log/help message saying "this signature commits to the
compressed/uncompressed form".

**File:** `internal/rpc/extra_methods.go:1043` (`compressed` from WIF
threaded into `SignMessageCompact`); test at
`signmessage_test.go:153-194` only exercises the compressed path.

**Impact:** uncompressed-key path is functionally correct but
undertested; operators have no in-band signal about which pubkey form
they signed against.

---

## BUG-11 (P1) — `MessageHash` doesn't validate message length; Core implicitly bounded by `std::string`/`MAX_SCRIPT_ELEMENT_SIZE` consumers

**Severity:** P1. Both blockbrew and Core's `MessageHash` accept an
arbitrarily long message and CompactSize-prefix it. Core's
`HashWriter::operator<<` for a `std::string` writes
`WriteCompactSize(len)` then the bytes — same encoding.

However, blockbrew's `writeCompactSize` accepts any `uint64` up to
`0xFFFFFFFFFFFFFFFF`. Core's `WriteCompactSize` (`serialize.h`)
likewise accepts any `uint64`. There's no inherent bound — but Core
limits the practical RPC entry point because `std::string` is bounded
by the JSON parser's input size limit
(`HTTP_DEFAULT_REQUEST_SIZE_LIMIT = 32 MiB` per Core init defaults).

blockbrew's HTTP body-size limit was checked at the JSON-RPC layer in
W140 — different topic, but the message-hash function itself has no
length validation. An attacker who can submit large requests can
trigger SHA256 of arbitrary size; not a DoS at small scale (SHA256 is
fast) but worth noting.

**File:** `internal/crypto/signmessage.go:50-57`.

**Impact:** no inherent bound on `MessageHash` input. Minor; gated by
HTTP body-size limit at a higher layer.

---

## BUG-12 (P1) — `decodeWIFForRPC` does NOT validate the secp256k1 scalar is in `[1, n-1]`

**Severity:** P1. `internal/rpc/extra_methods.go:1051-1074`:

```go
func decodeWIFForRPC(wif string, net address.Network) (*bbcrypto.PrivateKey, bool, error) {
    version, payload, err := address.Base58CheckDecode(wif)
    ...
    switch {
    case len(payload) == 33 && payload[32] == 0x01:
        return bbcrypto.PrivateKeyFromBytes(payload[:32]), true, nil
    case len(payload) == 32:
        return bbcrypto.PrivateKeyFromBytes(payload), false, nil
    default:
        return nil, false, fmt.Errorf("invalid WIF payload length")
    }
}
```

`PrivateKeyFromBytes` accepts any 32 bytes including:
- All zeros (scalar = 0).
- Bytes ≥ secp256k1 group order N.

Core's `DecodeSecret` calls `key.Set(payload, payload+32, fCompressed)`,
which calls `secp256k1_ec_seckey_verify` and refuses to construct an
invalid `CKey`. blockbrew's `decodeWIFForRPC` then calls
`SignMessageCompact` with the invalid key; the dcrec ECDSA library
will either crash on `mul_nonconst` of a zero scalar or produce a
mathematically meaningless signature.

Verify with a direct test: a WIF whose payload is 32 zeros decodes to
a privkey of 0. Signing with that should either error (Core) or
produce garbage (blockbrew).

**File:** `internal/rpc/extra_methods.go:1067-1073` and the
unguarded `PrivateKeyFromBytes` in `internal/crypto/`.

**Core ref:** `bitcoin-core/src/key_io.cpp::DecodeSecret` →
`CKey::Set` → `secp256k1_ec_seckey_verify`.

**Impact:** malformed-key error contract divergence; potential
crash-or-garbage on edge-case WIFs. Operator who passes a junk WIF
("Lpc1d..." with zeros) sees either a panic or a successful but
verifiable-against-nothing signature.

---

## BUG-13 (P1) — `MessageMagic` is `string`; CompactSize encoder treats it as `len(magic) = 24`, but Core uses `serialize` traits which prefix `WriteCompactSize` for strings

**Severity:** P1 (parity-by-coincidence). Core's `MessageHash` writes
the magic via `HashWriter& operator<<(const std::string&)`, which
delegates to `Serialize(s, m)` → `WriteCompactSize(s, m.size());
s.write(MakeUCharSpan(m));`. blockbrew's `MessageHash`:

```go
writeCompactSize(&buf, uint64(len(MessageMagic)))
buf.WriteString(MessageMagic)
writeCompactSize(&buf, uint64(len(message)))
buf.WriteString(message)
```

The behaviours match BY COINCIDENCE because `MessageMagic = "Bitcoin
Signed Message:\n"` has length 24, and CompactSize(24) = `0x18` (the
24 itself encoded as a single byte). The framing is correct.

The test `TestMessageHashKnownVector` pins the hash to
`cf04...84f4`, derived from `0x18 + magic + 0x05 + "hello"` → SHA256d.

The fragility is in `len(MessageMagic)` being silently dependent on
Go's `string` length being equal to the byte length of the magic
(which is true for the current ASCII-only magic). If anyone ever
changed the magic to include multi-byte UTF-8 characters,
`len(string)` would still return byte count (Go's `len` on strings is
bytes, not runes), so this stays correct — but it's an implicit
contract worth documenting.

A subtler issue: Core's `HashWriter::operator<<` is a TEMPLATE
specialised on `std::string` which calls `Serialize`. The same
template applied to a `const char[]` would NOT prefix with CompactSize
— it would just write the bytes. If Core's `MessageHash` ever
accidentally passed `MESSAGE_MAGIC` as a C-string literal instead of
a `std::string`, the framing would change. blockbrew has no equivalent
type-trait pitfall because the local `writeCompactSize` is called
explicitly.

**File:** `internal/crypto/signmessage.go:50-56`.

**Impact:** by-coincidence parity; no current divergence, fragile
contract documentation gap.

---

## BUG-14 (P1) — `RecoverPubKeyFromCompact` doesn't validate the recovery byte's compressed bit against the address-type contract

**Severity:** P1. `handleVerifyMessage` derives `compressed` from the
sig recovery byte (sig[0] ∈ [31..34] → compressed = true; sig[0] ∈
[27..30] → compressed = false). It then computes Hash160 of the
recovered pubkey in compressed-or-uncompressed form and compares to
the address's PKH.

The contract gap: a forger who has the SAME private key but uses the
WRONG compressed-bit can claim to sign against the OPPOSITE-form
address. Specifically:
- Alice signs a message with her uncompressed pubkey, producing sig
  with recovery byte ∈ [27..30].
- Mallory takes the same sig, flips the recovery byte to ∈ [31..34]
  (adds 4 to it).
- The recovered pubkey is the same secp256k1 point.
- `Hash160(SerializeCompressed(point))` != `Hash160(SerializeUncompressed(point))`,
  so the verification still correctly fails when checked against the
  ORIGINAL uncompressed address — but it would succeed against the
  alternate (compressed) form of the SAME pubkey.

This isn't a forgery attack (Mallory needs Alice to have signed the
same message in the first place), but it does mean a signature that
was intended to commit to one specific address form can be replayed
against the alternate form. Core has the same property — it's
documented behaviour of compact-recoverable sigs.

The blockbrew-specific issue: the verifier doesn't surface this
in the error path. A signature that was created with `compressed=true`
and a signer-intended `m...` (testnet uncompressed) address would
silently appear "valid" against the corresponding compressed-form
address from the same key, even though the signer's pubkey was
intended for the uncompressed address.

**File:** `internal/rpc/extra_methods.go:950-958`.

**Impact:** replay between compressed/uncompressed address forms of
the same pubkey. Documented Core behaviour; flagged for fleet
consistency.

---

## BUG-15 (P1) — `signmessagewithprivkey` doesn't enforce low-S on the produced signature

**Severity:** P1. The dcrec library's `signRFC6979` produces canonical
(low-S) signatures by construction — it rejects nonces that produce
high-S and retries. So the produced signature IS low-S.

However, `RecoverPubKeyFromCompact` (`internal/crypto/signmessage.go:76-85`)
does NOT enforce low-S on incoming signatures. A signature with S
in the upper half of the group order would still recover to the
correct pubkey (ECDSA recovery is well-defined over both halves).

This matters for BIP-322 (cross-cite BUG-4): BIP-322 explicitly
requires low-S enforcement on the ECDSA signature in the witness for
P2WPKH/P2WSH (per BIP-146 mandatory script flags). Without
low-S, an attacker who has a high-S signature for the same hash
could substitute it for the low-S original, producing a different
base64 string that nonetheless "verifies" — defeating
signature-uniqueness assumptions in higher-layer protocols (e.g.,
proof-of-reserves audit replay).

For BIP-137 (legacy signmessage), Core does NOT enforce low-S on
verify either, so this is a parity match. But the LIBRARY primitive
that BIP-322 would need is also low-S-blind, so a future BIP-322
wiring would have to add its own low-S gate at the call site rather
than relying on `RecoverPubKeyFromCompact`.

**File:** `internal/crypto/signmessage.go:76-85`.

**Impact:** no current divergence (parity with Core's BIP-137);
future-feature gap for BIP-322 implementation.

---

## BUG-16 (P1) — Help text for `signmessage` doesn't surface the "wallet must be unlocked" precondition

**Severity:** P1. Core's RPC help for `signmessage` includes the
example "Unlock the wallet for 30 seconds" with the exact
`walletpassphrase` command. blockbrew's help (`internal/rpc/extra_methods.go:875`)
is a bare:

```
"signmessage \"address\" \"message\"",
```

— no mention of the passphrase requirement, no example, no parameter
descriptions. Combined with BUG-2 (locked-wallet error mapped to
the wrong code), the operator has no in-band path to "ah, I need to
unlock the wallet."

**File:** `internal/rpc/extra_methods.go:875` (also lines 876-877
for `signmessagewithprivkey` and `verifymessage`).

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:27-35`
(RPCExamples block with explicit walletpassphrase example).

**Impact:** operator UX; cross-cite BUG-2 (the actual error code is
also wrong, so the operator gets misleading info from both the help
text AND the error response).

---

## BUG-17 (P1) — `verifymessage` accepts base64 with non-standard padding (Go's `base64.StdEncoding.DecodeString` requires exact padding; Core uses `DecodeBase64` which is also strict — but blockbrew doesn't try `RawStdEncoding`)

**Severity:** P1 (interop). Different ecosystems produce BIP-137
signatures with different padding conventions:
- Core / Electrum / Sparrow: 65-byte sig → ceil(65/3)*4 = 88 characters
  base64, with one `=` pad character (length 88, last char `=`).
- Some legacy tools strip the `=` padding (RFC 4648 §3.2 calls this
  optional in some contexts).

blockbrew (`internal/rpc/extra_methods.go:939`) uses
`base64.StdEncoding.DecodeString`, which requires the `=` padding.
A signature submitted without padding fails with a `base64.CorruptInputError`,
which maps to RPC_TYPE_ERROR -3 "Malformed base64 encoding".

Core's `DecodeBase64` (`src/util/strencodings.cpp`) is also strict, so
this is parity behavior. But blockbrew has the choice to be lenient
via `RawStdEncoding` and isn't — flagged for fleet consistency.

Worse, blockbrew's encoder (`base64.StdEncoding.EncodeToString` at
line 1015) ALWAYS emits padding. A blockbrew-produced sig is 88 chars
ending in `=`. A blockbrew-consumed verify cannot accept an 87-char
sig from a tool that strips the padding. This breaks round-trip with
any tool that uses `RawStdEncoding`.

**File:** `internal/rpc/extra_methods.go:939, 1015, 1044`.

**Impact:** interop with non-Core tools that emit unpadded base64.
Minor; users can re-pad manually.

---

## BUG-18 (P1) — Error message "Address does not refer to key" misleads for P2SH (which CAN refer to a key via redeemScript)

**Severity:** P1. Core's wallet `signmessage` returns "Address does
not refer to key" only for non-`PKHash` destinations. P2SH (Script
Hash) is non-`PKHash`, so the error fires. But a P2SH-wrapped P2PKH
or a P2SH-wrapped P2WPKH technically DOES refer to a key (via the
redeemScript). Core's error message is correct from a strict typing
standpoint but is misleading for users.

blockbrew (`internal/rpc/extra_methods.go:935-937`) inherits the
exact Core error wording. Fleet pattern — every impl has this issue.

**File:** `internal/rpc/extra_methods.go:935-937, 1001-1003`.

**Impact:** error UX (inherited from Core); no functional divergence.
Flagged for fleet awareness.

---

## BUG-19 (P1) — No round-trip with `signmessagewithprivkey` for testnet WIFs when `chainParams.Name == "testnet3"` (BUG-7 compound)

**Severity:** P1. Combining BUG-7 (`getNetwork()` returns mainnet for
"testnet3") with `decodeWIFForRPC` (which checks `0x80` for mainnet
and `0xef` otherwise), a testnet3 WIF is rejected with "wrong network
version" when `signmessagewithprivkey` is invoked on a testnet3 node.

This is a derived bug from BUG-7 but recorded separately because it
manifests specifically as a signmessage-flow failure that the operator
will diagnose as a signmessage bug rather than a getNetwork bug.

**File:** `internal/rpc/methods.go:2415` (missing "testnet3" case)
× `internal/rpc/extra_methods.go:1057-1062`.

**Impact:** signmessagewithprivkey broken on testnet3.

---

## BUG-20 (P1) — `handleSignMessage` doesn't check that `addr.Hash` is 20 bytes before calling `GetKeyForAddress` — a malformed P2PKH (e.g., empty Hash) would silently produce a wrong-address result

**Severity:** P1 (defensive). `address.DecodeAddress` constructs an
`Address{Hash: payload}` where `payload` is the Base58Check payload
(supposed to be 20 bytes). The decoder validates `len(payload) == 20`
at `internal/address/address.go:179-181`, so under normal flow this
is enforced.

However, `handleSignMessage` doesn't double-check, and the cross-
contract assumption (decoder ALWAYS returns 20-byte Hash for P2PKH)
could be broken by a future decoder refactor. The 20-byte assumption
is also exploited by the test (`signmessage_test.go:160-165`) that
hand-constructs an `Address` with `pkhArr[:]`.

`handleVerifyMessage` DOES double-check at line 960-961:
```go
if len(addr.Hash) != 20 {
    return false, nil
}
```

— but the sign path doesn't, and they're asymmetric.

**File:** `internal/rpc/extra_methods.go:997-1014` (no length guard).

**Impact:** defensive gap; no current crash because decoder enforces.
Symmetric to the verify path which does check.

---

## BUG-21 (P1) — `bbcrypto.MessageHash` returns `[32]byte` but the verify path passes it to `RecoverPubKeyFromCompact` which expects a 32-byte hash; subtle type-API mismatch

**Severity:** P1 (cosmetic / type-tightness). `MessageHash` returns
`[32]byte`; `RecoverPubKeyFromCompact` takes a `[32]byte`. The types
match. But the underlying `ecdsa.RecoverCompact` (dcrec) takes a
`[]byte`. The conversion at `signmessage.go:80` (`hash[:]`) is fine,
but the API doesn't enforce 32 bytes at the dcrec boundary — a
future refactor that passes a different-sized slice would silently
produce wrong recovery results.

`SignMessageCompact` (`signmessage.go:68`) similarly takes a `[32]byte`
hash but passes `hash[:]` to `ecdsa.SignCompact`, which doesn't
length-check.

**File:** `internal/crypto/signmessage.go:68-70, 76-85`.

**Impact:** cosmetic; cross-impl type-discipline note.

---

## BUG-22 (P0-CDIV) — No `MessageVerificationResult` enum: error mapping collapses ERR_PUBKEY_NOT_RECOVERED, ERR_NOT_SIGNED, and Hash160-mismatch into one BOOLEAN false

**Severity:** P0-CDIV. Bitcoin Core's `MessageVerificationResult`
enum distinguishes six states:

```cpp
enum class MessageVerificationResult {
    ERR_INVALID_ADDRESS,
    ERR_ADDRESS_NO_KEY,
    ERR_MALFORMED_SIGNATURE,
    ERR_PUBKEY_NOT_RECOVERED,
    ERR_NOT_SIGNED,
    OK
};
```

The first three are RPC errors; the last three (including PUBKEY_NOT_
RECOVERED and NOT_SIGNED) are BOOLEAN false. This is significant
because the RPC layer's BOOLEAN false IS a meaningful response — the
operator knows the signature MUST be either malformed (different
error) or not from the claimed signer (false).

blockbrew's `handleVerifyMessage` collapses TWO distinct
"recovery-time" failure modes:
1. `bbcrypto.RecoverPubKeyFromCompact` returns an error (sig is
   structurally wrong: bad length, bad recovery byte, R or S out of
   range). This is `ERR_PUBKEY_NOT_RECOVERED` in Core.
2. Hash160 of recovered pubkey doesn't match address. This is
   `ERR_NOT_SIGNED` in Core.

Both map to `return false, nil` (lines 947, 961-967). Core also
returns `false` for both, so the BOOLEAN output is parity-correct.

The divergence is in the **library-level** primitive. `MessageVerify`
in Core returns the enum value; callers can branch on it (the wallet
GUI shows different status messages, the RPC handler converts to
JSON-RPC errors selectively). blockbrew's `handleVerifyMessage` is
the ONLY caller of the verify path, and it discards the distinction.

This becomes critical for a future BIP-322 wiring: BIP-322 spec
distinguishes "the sig didn't recover to any valid point" (impossible
in BIP-322 because witness sigs are not recoverable — they're verified
under a known pubkey) from "the sig doesn't commit to the
to_sign sighash" (script-eval failure). A future implementor will
copy the BIP-137 verify path's collapsed shape and lose the
distinction.

Also: there is no LIBRARY-level `MessageVerify` function in
blockbrew. `bbcrypto` exposes `SignMessageCompact` and
`RecoverPubKeyFromCompact`, but no `MessageVerify(address, sig, msg)
→ enum`. Any non-RPC caller that wants to verify a BIP-137 signature
has to reimplement the address-decode + Hash160 + compare flow.

**File:** `internal/rpc/extra_methods.go:910-969` (collapsed shape);
`internal/crypto/signmessage.go` (no library-level MessageVerify).

**Core ref:** `bitcoin-core/src/common/signmessage.h:23-41`
(MessageVerificationResult enum); `bitcoin-core/src/common/signmessage.cpp:26-55`
(MessageVerify returning the enum).

**Impact:**
- Library API gap: no reusable `MessageVerify`.
- Cross-impl error-distinction gap: callers that scrape RPC errors see
  the same BOOLEAN false for two semantically distinct failure modes.
- Future BIP-322 wiring will inherit the collapsed shape.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CDIV:** 4 (BUG-4, BUG-5, BUG-6, BUG-22)
- **P1:** 18 (BUG-1, BUG-2, BUG-3, BUG-7, BUG-8, BUG-9, BUG-10,
  BUG-11, BUG-12, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-18,
  BUG-19, BUG-20, BUG-21)

**Fleet patterns confirmed / extended:**
- "Wiring-look-but-no-wire" (BUG-4/5/6) — RPC handlers exist for
  `signmessage` / `verifymessage`, address types parsed, but the
  BIP-322 protocol surface is entirely absent. The handlers gate
  on P2PKH-only and the help text omits any mention of segwit/taproot.
- "Test-pins-bug" / "test-as-policy" (BUG-8) — a docstring comment in
  `TestSignMessageRejectsSegwit` justifies the gap, locking it in.
- "Comment-as-confession" (BUG-8 docstring on signmessage_test.go:106-114
  "the Core-compatible behavior that segwit addresses cannot be used"
  is wrong about Core's wallet ecosystem support for BIP-322).
- "W132 carry-forward" (BUG-6 cross-cite) — `MsgTx.Version int32` would
  break BIP-322 Full mode's `to_sign.version == 0` check on a forged
  `0x80000000` version field. ~3 weeks open since W123.
- "W144 echo — STANDARD-flags incomplete" (BUG-15 cross-cite) — a
  future BIP-322 Full-mode implementation would need to enforce
  STANDARD_SCRIPT_VERIFY_FLAGS on the witness verification, and BUG-15
  (W144 BUG-5 fleet pattern) notes that blockbrew's
  `GetStandardScriptFlags` is missing 9 of 13 STANDARD bits — BIP-322
  Full would inherit those gaps.
- "Cross-cut bug surfaces in BIP-322" (BUG-7, BUG-19) — `getNetwork()`
  mis-routes "testnet3"; the bug manifests across many RPCs but is
  particularly visible here because signmessage has BOTH address-parse
  and WIF-parse paths.
- "Error-code parity gap" (BUG-2) — RPC_WALLET_UNLOCK_NEEDED (-13)
  is not defined as a constant in `internal/rpc/types.go`; blockbrew
  collapses three distinct `GetKeyForAddress` failure modes into
  -5 RPC_INVALID_ADDRESS_OR_KEY.
- "Library-level enum collapsed at RPC boundary" (BUG-22) — no
  `MessageVerify` library function; the RPC handler does the work
  inline and discards the `MessageVerificationResult` distinction.

**Top three findings:**
1. **BUG-4 + BUG-5 + BUG-6 cluster (P0-CDIV) — BIP-322 entirely
   absent.** No Simple-mode dispatch, no `to_spend`/`to_sign`
   constructors, no Full-mode multi-input verification, no NUMS
   fallback for script-path Taproot, no tagged-hash primitive for the
   "BIP0322-signed-message" tag. The default-newly-created wallet
   address (`AddressTypeP2WPKH`, iota=0) cannot be signed for at all.
   Cross-fleet first instance — this is the first BIP-322-specific
   audit; expect 8-10 of 10 impls fleet-wide to be in the same shape.

2. **BUG-22 (P0-CDIV) — MessageVerificationResult enum absent; library-
   level verify primitive missing.** Core distinguishes 6 verify
   states; blockbrew collapses to BOOLEAN + 3 RPC errors at the
   handler boundary, with no reusable library-level `MessageVerify`
   function. Future BIP-322 wiring would inherit the collapsed shape
   and lose the script-eval-vs-recovery-vs-mismatch distinction.

3. **BUG-2 (P1) — locked-wallet error mapped to -5 instead of -13.**
   `RPC_WALLET_UNLOCK_NEEDED` constant doesn't even exist in
   `internal/rpc/types.go`. Tools that branch on -13 to surface a
   walletpassphrase prompt won't trigger on blockbrew. Compound with
   BUG-1 (no `EnsureWalletIsUnlocked` precheck — the check happens
   AFTER address-decode and type-check), so an operator probing a
   locked wallet leaks lock state through error ordering.

**Cross-cuts to other waves:**
- W132 BUG-1 `MsgTx.Version int32→uint32` carry-forward (BUG-6).
- W144 BUG-5 STANDARD-flags missing 9 of 13 (BUG-15 future BIP-322
  Full mode).
- W140-class "RPC_WALLET_UNLOCK_NEEDED constant absent" (BUG-2).
- W149-class "operator-knob absent / wiring-look-but-no-wire" (BUG-4/5/6).
- Cross-cut `getNetwork()` mis-routing testnet3 (BUG-7, BUG-19) —
  affects ALL RPCs, not just signmessage.
