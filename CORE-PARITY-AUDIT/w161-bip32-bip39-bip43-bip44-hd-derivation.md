# W161 — BIP-32 / BIP-39 / BIP-43 / BIP-44 / BIP-49 / BIP-84 / BIP-86 HD wallet derivation + seed mnemonic (blockbrew)

**Wave:** W161 — `CExtKey::SetSeed`, `CExtKey::Derive`, `CExtKey::Neuter`,
`CKey::Derive` (BIP-32 priv CKD via `secp256k1_ec_seckey_tweak_add`),
`CPubKey::Derive` (BIP-32 pub CKD via `secp256k1_ec_pubkey_tweak_add`),
`CExtPubKey::Derive`, `CExtKey::Encode/Decode` (78-byte serialisation),
`BIP32Hash` (HMAC-SHA512 of chain code), `nDepth==255` overflow guard,
BIP-39 entropy → mnemonic → seed (PBKDF2-HMAC-SHA512, iter=2048,
salt = "mnemonic"||passphrase, output 64 bytes), BIP-39 English
wordlist (2048 words, canonical SHA-256
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`),
NFKD normalisation of mnemonic + passphrase, BIP-43 purpose registry,
BIP-44 / BIP-49 / BIP-84 / BIP-86 derivation paths
(`m/44'/coin'/account'/change/i`, `m/49'/…`, `m/84'/…`, `m/86'/…`),
BIP-86 `TapTweak(P, nil)` empty-merkle-root key-path-only commitment,
extended-key version bytes per network (`0488ADE4`/`0488B21E` mainnet,
`04358394`/`043587CF` testnet/signet/regtest), parent fingerprint =
`HASH160(parent_pubkey)[0:4]`, descriptor key origin / xpub / xprv
expansion, gap-limit, seed entropy validation, memory hygiene
(`memory_cleanse`).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/key.cpp:293-310` — `CKey::Derive` calls
  `BIP32Hash` and then `secp256k1_ec_seckey_tweak_add(secp256k1_context_static, …)`;
  returns false (=BIP-32 "invalid, proceed to next index") when the
  tweak yields a scalar ≥ n or = 0. Caller's `CExtKey::Derive` propagates
  that boolean — never silently reduces mod n.
- `bitcoin-core/src/key.cpp:482-489` — `CExtKey::Derive`:
  `if (nDepth == std::numeric_limits<unsigned char>::max()) return false;`
  (refuses to wrap depth past 255). `CKeyID id = key.GetPubKey().GetID();`
  (parent fingerprint = `HASH160(parent_pubkey)[0:4]`).
- `bitcoin-core/src/key.cpp:491-501` — `CExtKey::SetSeed`:
  HMAC-SHA512 key = literal byte string `"Bitcoin seed"` (no null
  terminator, 12 bytes); writes left-32 to key, right-32 to chaincode;
  `secure_allocator<unsigned char>` zeroizes the 64-byte vout on scope exit.
- `bitcoin-core/src/key.cpp:503-510` — `CExtKey::Neuter` (xprv → xpub).
- `bitcoin-core/src/key.cpp:513-530` — `CExtKey::Encode/Decode`
  (78-byte fixed layout: depth/fp/idx-BE/chaincode/0x00||key);
  Decode invariant: `if ((nDepth == 0 && (nChild != 0 || ReadLE32(vchFingerprint) != 0)) || code[41] != 0) key = CKey();`
  (master MUST have child==0 AND fp==0 AND key-prefix==0x00, else INVALID).
- `bitcoin-core/src/pubkey.cpp:341-363` — `CPubKey::Derive` uses
  `secp256k1_ec_pubkey_tweak_add`; returns false on overflow (BIP-32
  retry semantic preserved on pub-side too).
- `bitcoin-core/src/pubkey.cpp:415-422` — `CExtPubKey::Derive`:
  `if (nDepth == std::numeric_limits<unsigned char>::max()) return false;`
- `bitcoin-core/src/pubkey.cpp:246-255` — `XOnlyPubKey::ComputeTapTweakHash`:
  `merkle_root==nullptr` ⇒ tag-hash with **only the internal x-only key**
  (BIP-86 key-path-only); otherwise hash also commits to the merkle root
  (BIP-341 script-path).
- `bitcoin-core/src/secp256k1/include/secp256k1.h:745-790` —
  `secp256k1_ec_seckey_tweak_add`/`secp256k1_ec_pubkey_tweak_add`:
  "Returns: 0 if the arguments are invalid or the resulting key would be
  invalid (only when the tweak is the negation of the corresponding
  secret key). 1 otherwise."
- `bitcoin-core/src/secp256k1/include/secp256k1.h:810-841` —
  `secp256k1_context_randomize`: "highly recommended … defense-in-depth
  measure"; blinds base-point multiplications.
- `bitcoin-core/src/kernel/chainparams.cpp:148-149, 261-262, 366-367,
  507-508, 639-640` — per-network `EXT_PUBLIC_KEY`/`EXT_SECRET_KEY`
  prefix bytes (mainnet `0488B21E`/`0488ADE4`; testnet3/signet/
  testnet4/regtest all `043587CF`/`04358394`).
- BIP-32 §"Private parent key → private child key" — "In case
  parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one
  should proceed with the next value of i."
- BIP-32 §"Serialization format" — 78-byte fixed layout; master key
  MUST have `depth=0`, `child=0`, `parent_fingerprint=00000000`.
- BIP-39 §"Generating the mnemonic" — entropy `ENT ∈
  {128,160,192,224,256}`, checksum bits = `ENT/32`, 11-bit indices.
- BIP-39 §"From mnemonic to seed" — `PBKDF2(password = NFKD(mnemonic),
  salt = "mnemonic" || NFKD(passphrase), c = 2048, dkLen = 64,
  PRF = HMAC-SHA512)`.
- BIP-39 §"Wordlist" — canonical English wordlist SHA-256
  `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
- BIP-43 §"Purpose" — `m / purpose' / *`. Purpose values reserved:
  44=BIP-44, 49=BIP-49, 84=BIP-84, 86=BIP-86. Per-purpose registries:
  SLIP-0044 (coin types), SLIP-0132 (alt version bytes ypub/zpub).
- BIP-44/49/84/86 — `m / purpose' / coin_type' / account' / change /
  address_index`; `coin_type` from SLIP-0044 (0=BTC mainnet, 1=BTC
  testnet/signet/regtest).
- BIP-86 §"Address derivation" — taproot key-path-only: tweak with
  `t = hashTapTweak(P)` (no merkle root). x-only output key.

**Files audited**
- `internal/wallet/hdkey.go:1-500` — `HDKey`, `NewMasterKey`,
  `DeriveChild`, `addPrivateKeys`, `addPublicKeys`, `DerivePath`,
  `PublicKey`, `ECPrivKey`, `ECPubKey`, `Fingerprint`, `Serialize`,
  `serializeWithVersion`, `ParseExtendedKey`, `BIP44Path`,
  `BIP49Path`, `BIP84Path`, `BIP86Path`, `isValidSecretKey`.
- `internal/wallet/mnemonic.go:1-239` — `GenerateMnemonic`,
  `GenerateMnemonic12`, `EntropyToMnemonic`, `extract11Bits`,
  `ValidateMnemonic`, `MnemonicToSeed`, `MnemonicToEntropy`,
  English wordlist embed.
- `internal/wallet/wordlist_english.txt` — 2048 lines, canonical
  SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
- `internal/wallet/wallet.go:186-241` — `CreateFromMnemonic`,
  `CreateFromSeed`, `initAccount`.
- `internal/wallet/wallet.go:243-280` — `initAccount` (BIP-84 path
  hardcoded), `coinType`.
- `internal/wallet/wallet.go:286-400` — `NewAddressOfType`,
  `newAddressOfTypeLocked` (BIP-44/49/84/86 path dispatch).
- `internal/wallet/wallet.go:2090-2150` — `Lock`, `Unlock`.
- `internal/wallet/wallet.go:2280-2305` — `GetExtendedPublicKey`
  (hardcoded BIP-84 path even when wallet uses non-BIP-84 addresses).
- `internal/wallet/wallet.go:2330-2338` — `ImportDescriptor`
  (stub returning `not yet implemented`).
- `internal/wallet/manager.go:156-227` — `CreateWallet` (generates
  mnemonic + immediately discards it without surfacing to caller).
- `internal/wallet/storage.go:32-180` — `walletData`, `SaveToFile`,
  `LoadFromFile` (stores 64-byte master `Key||ChainCode` as "seed";
  `Mnemonic` field declared but never populated).
- `internal/wallet/descriptor.go:254-340` — `XPubPubkeyProvider`,
  `KeyOriginInfo`, `GetPubKey`, `GetPrivKey`, `formatKeyExpr`.
- `internal/wallet/descriptor.go:1354-1407` — `parseXPubKey`
  (descriptor side of xpub/xprv parsing).
- `internal/rpc/multiwallet_methods.go:16-86` — `handleCreateWallet`
  RPC (returns only `{Name, Warnings}`; never returns the mnemonic).
- `internal/crypto/keys.go:51-58` — `PrivateKeyFromBytes` (no
  scalar < n check; delegates to dcrd's `PrivKeyFromBytes` which
  silently reduces mod n).
- `internal/address/base58.go:108-156` — `Base58CheckEncode`,
  `Base58CheckDecode` (returns variable-length payload — extended-key
  caller does not length-check).
- `bitcoin-core/src/key.cpp:293-501`, `pubkey.cpp:341-422`,
  `pubkey.cpp:246-255` — Core authoritative references.

---

## Gate matrix (32 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | BIP-32 master seed (`Bitcoin seed` HMAC-SHA512) | G1: HMAC key = literal `Bitcoin seed` (12 bytes, no NUL) | PASS (`hdkey.go:71` `[]byte("Bitcoin seed")` → Go converts the string literal to bytes, no NUL appended) |
| 1 | … | G2: master left-32 = key, right-32 = chain code | PASS (`hdkey.go:77-78`) |
| 1 | … | G3: seed length validated 16–64 bytes | PASS (`hdkey.go:66-68`) |
| 1 | … | G4: invalid master key (zero or ≥ n) → error | PARTIAL — `isValidSecretKey` (`hdkey.go:96-116`) checks zero, then calls `secp256k1.PrivKeyFromBytes(key)`. **BUG-1 below**: dcrd's `PrivKeyFromBytes` silently reduces mod n and never returns nil for any 32-byte input ≥ n; so the ≥ n half of the BIP-32 spec is never enforced at master gen. |
| 2 | BIP-32 CKD priv (private child key derivation) | G5: tweak via libsecp `seckey_tweak_add` (constant-time + blinded) | **BUG-2 (P0-SEC) re-statement of W159 BUG-15** — `addPrivateKeys` (`hdkey.go:192-207`) uses decred-pure-Go `ModNScalar.Add` instead of libsecp's `secp256k1_ec_seckey_tweak_add`. Library is pure-Go and **not constant-time** (`ModNScalar.Add` operates on big-int limbs; per the decred docs, `NonConst` operations exist throughout); also no `context_randomize` base-point blinding. |
| 2 | … | G6: reject `parse256(IL) ≥ n` on private-side derivation | **BUG-2 carry-forward of W159 BUG-15** — `addPrivateKeys` calls `k2.SetByteSlice(key2)` and ignores the overflow boolean; W159 has the full write-up. Re-confirmed at master (`fcdcb19c…HEAD`) — patch from W159 has NOT landed. **Carry-forward 2-wave open**. |
| 2 | … | G7: reject `(IL + k_par) == 0` on private-side derivation | PASS (`hdkey.go:200-202`) but caller does not retry on next index per BIP-32 |
| 2 | … | G8: BIP-32 retry-on-IL≥n semantic at `DeriveChild` caller | **BUG-3 (P1)** — neither `DeriveChild` nor `DerivePath` retries with `index+1` on invalid-key error; error is propagated. A wallet importing a Core-derived xpriv that crossed an `IL ≥ n` index would silently diverge. (Note: probability ~2^-128 per index, so impact is theoretical for honest seeds; for adversarial / fuzz-test path it is a cross-impl reject-vs-accept divergence.) |
| 3 | BIP-32 CKD pub (public child key derivation, neuter) | G9: tweak via libsecp `pubkey_tweak_add` | **BUG-4 (P1)** — `addPublicKeys` (`hdkey.go:210-246`) uses pure-Go `secp256k1.AddNonConst` + `ScalarBaseMultNonConst`. Not constant-time (the `NonConst` suffix is explicit). For pub-side derivation timing is less catastrophic (the secret is the chain code, not the tweak scalar), but Core uses libsecp exclusively. **Two-curve-library variant** (W159 fleet pattern). |
| 3 | … | G10: reject `parse256(IL) ≥ n` on public-side derivation | PASS (`hdkey.go:219-222` checks `overflow` AND `IsZero`) — and W159 BUG-15 already documented this as the named origin of the **asymmetric-fix WITHIN ONE FILE / two-pipeline guard 22nd extension** pattern: pub-side checked, priv-side silently reduced. |
| 4 | BIP-32 hardened derivation + depth invariant | G11: hardened format = `0x00 \|\| ser256(seckey) \|\| ser32(i)` | PASS (`hdkey.go:130-134`) |
| 4 | … | G12: hardened path on public extended key → reject | PASS (`hdkey.go:122-126`) |
| 4 | … | G13: `nDepth == 255` overflow check (refuse to wrap to depth 0) | **BUG-5 (P0-CDIV)** — Core `key.cpp:483` AND `pubkey.cpp:416`: `if (nDepth == std::numeric_limits<unsigned char>::max()) return false;`. blockbrew `DeriveChild` (`hdkey.go:158-188`) computes `Depth: k.Depth + 1` with `Depth` of Go type `byte`; at depth 255 the increment **silently wraps to 0**, producing a "depth-0 master-like" child key with the wrong parent fingerprint and non-zero index/parent-fp violating the master-key invariant. Encoded xprv/xpub at depth-after-255 would deserialize on Core as INVALID per `CExtKey::Decode`'s master-invariant check. **First fleet instance** of "byte-overflow on BIP-32 depth" found this wave. |
| 5 | BIP-32 78-byte serialisation + parse | G14: 4-byte version, 1-byte depth, 4-byte parent fp, 4-byte child idx (BE), 32-byte chain code, 33-byte key (with 0x00 prefix for priv) | PASS (`hdkey.go:374-404`) |
| 5 | … | G15: parent fingerprint = `HASH160(parent_pubkey)[0:4]` | PASS (`hdkey.go:343-348`, uses `bbcrypto.Hash160`) |
| 5 | … | G16: round-trip `Serialize` → `ParseExtendedKey` invariant | **BUG-6 (P0-CDIV)** — `ParseExtendedKey` (`hdkey.go:407-471`) does NOT enforce Core's master-key invariant: if `depth == 0` then `child == 0` AND `parent_fp == [4]byte{0,0,0,0}` AND (for private) `data[45] == 0x00`. blockbrew checks only the 0x00 prefix for private keys. An xprv with depth=0 but nonzero parent_fp or nonzero child decodes successfully and is treated as a "master key" — Core would zero the key (`CExtKey::Decode` final clause). Cross-impl divergence on malformed-on-purpose xprvs. |
| 5 | … | G17: parsed private key validated < n | **BUG-7 (P1)** — `ParseExtendedKey` populates `Key: key` (32-byte slice) and skips ALL `isValidSecretKey` checks. A crafted xprv with `seckey == 0` or `seckey >= n` parses successfully and produces a key that will fail at first use rather than at parse. |
| 5 | … | G18: parsed public key validated as point on curve | **BUG-8 (P1)** — `ParseExtendedKey` does NOT call `secp256k1.ParsePubKey` on the 33-byte key for public xpubs. Invalid-point xpubs decode silently and only fail at first use (`addPublicKeys` calls `ParsePubKey` later). |
| 5 | … | G19: input length strictly == 78 bytes (else reject) | **BUG-9 (P0-CDIV)** — `ParseExtendedKey` calls `Base58CheckDecode` which returns variable-length payload, then does `data := make([]byte, 78); data[0] = version; copy(data[1:], payload);` followed by `if len(data) != 78 { return nil }` (impossible — `data` is allocated as 78). A too-short input **silently zero-pads** the remaining bytes (depth/chaincode/key all become 0); a too-long input has trailing bytes silently truncated. The validate path is dead. Core's `Decode` takes a fixed-size `code[BIP32_EXTKEY_SIZE]` (= 74 bytes payload after the 4-byte version), so length divergence is impossible there. |
| 5 | … | G20: SLIP-132 alt prefix support (ypub/zpub/Ypub/Zpub/Mpub) | **BUG-10 (P2)** — `ParseExtendedKey` (`hdkey.go:407-471`) accepts ONLY 4 version bytes (`0488ADE4`/`0488B21E` mainnet, `04358394`/`043587CF` testnet). SLIP-132 alt-prefix xpubs commonly exported by hardware wallets (ypub = `049d7878`, zpub = `04b24746`, Ypub = `0295b43f`, Zpub = `02aa7ed3`, etc.) are rejected with `ErrInvalidExtendedKey`. Core does NOT support SLIP-132 either (deliberate), so this is not a divergence — but blockbrew's `wpkh(zpub.../*)` descriptors imported from Sparrow/Electrum/Trezor will fail with no clear error. P2 because Core also rejects, but interop pain for hardware-wallet users is significant. |
| 6 | BIP-39 mnemonic encode + decode | G21: 12/15/18/21/24 word counts accepted | PASS (`mnemonic.go:127`) |
| 6 | … | G22: 11-bit index extraction; checksum = SHA256(entropy)[N/32 bits] | PASS (`mnemonic.go:64-118`) |
| 6 | … | G23: English wordlist matches canonical SHA-256 | PASS — `sha256sum wordlist_english.txt` = `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` (matches canonical BIP-39 English file). |
| 6 | … | G24: NFKD normalisation of mnemonic + passphrase during seed gen | PARTIAL — `MnemonicToSeed` (`mnemonic.go:181-189`) NFKD-normalises both. **BUG-11 below**: `ValidateMnemonic` and `MnemonicToEntropy` do NOT NFKD-normalise before word lookup; a NFC-encoded Spanish/French/CJK mnemonic (or any unicode-variant input) is rejected. **Two-pipeline guard 23rd extension** — same-file asymmetric normalisation. |
| 6 | … | G25: passphrase support (BIP-39 §"From mnemonic to seed") | PASS (`mnemonic.go:181-189`) at the primitive level; **BUG-12 below**: caller never passes a passphrase. |
| 6 | … | G26: non-English wordlists (Japanese, Spanish, etc.) | OUT-OF-SCOPE — Core does not ship them either; English-only is the de-facto interop wordlist. No bug. |
| 7 | BIP-43/44/49/84/86 derivation paths | G27: BIP-44 `m/44'/coin'/account'/change/i` path helper | PASS (`hdkey.go:486-488`) |
| 7 | … | G28: BIP-49 nested-segwit path | PASS (`hdkey.go:492-494`) |
| 7 | … | G29: BIP-84 native-segwit path | PASS (`hdkey.go:480-482`) |
| 7 | … | G30: BIP-86 taproot key-path-only path | PASS (`hdkey.go:498-500`) |
| 7 | … | G31: BIP-44 coin type per network (mainnet=0, testnet/regtest/signet=1) | PASS (`wallet.go:269-279` reads `ChainParams.HDCoinType`, all 4 non-mainnet networks correctly set to 1 in `consensus/chaincfg.go`) |
| 7 | … | G32: account-xpub derivation per address type (one BIP-44 account, one BIP-84 account, etc.) | **BUG-13 (P1) carry-forward of W111 BUG-2** — `initAccount` (`wallet.go:243-266`) ONLY derives the BIP-84 account key (`m/84'/coin'/account'`) and stores it as `accounts[0].ExtPubKey`. When the wallet later produces a P2PKH (BIP-44) or P2TR (BIP-86) address via `newAddressOfTypeLocked`, the per-call derivation IS correct, but `accounts[0].ExtPubKey` is wrong for any non-BIP-84 path. `GetExtendedPublicKey` (`wallet.go:2287-2305`) hardcodes `m/84'/coin'/account'` regardless of the wallet's `AddressType`. **5+ months open since W111**. |
| 8 | BIP-86 TapTweak (key-path-only) | G33: descriptor `tr(KEY)` uses `TapTweak(internal, nil)` (no merkle root) | PASS (`descriptor.go:680-690` — `merkleRoot` is `nil` when `d.TapTree == nil`, then `script.TapTweak(xOnly, merkleRoot)`) |
| 8 | … | G34: descriptor `tr(KEY, TREE)` correctly commits to merkle root | PASS (`descriptor.go:681-686` — invokes `t.computeMerkleRoot(pos)`; cross-cited as the GOOD path that exposes the W160 BUG-16 wallet-side bug) |
| 8 | … | G35: wallet signing path uses correct TapTweak commitment | **BUG-14 (P0-CDIV) cross-cite of W160 BUG-16** — `wallet.go:1292` (`signP2TR`) hardcodes `merkleRoot=nil` regardless of whether the output was script-path-committed. W160 BUG-16 named-origin (camlcoin + blockbrew + beamchain 3 fleet instances). **Carry-forward 2-wave open**. |
| 9 | BIP-39 mnemonic surfacing to operator | G36: `createwallet` RPC returns the generated mnemonic | **BUG-15 (P0-FUNDS) "generate-and-discard"** — `Manager.CreateWallet` (`manager.go:205-211`) generates a mnemonic via `GenerateMnemonic()` and **immediately discards it** by passing into `CreateFromMnemonic(mnemonic, "")` and never returning to caller. `handleCreateWallet` (`multiwallet_methods.go:82-86`) returns only `{Name, Warnings}`. **The user has zero recovery path: the mnemonic is generated, used to derive the master key, then garbage-collected. The wallet.dat stores `Key||ChainCode` (the master xprv layer), not the seed — so even decrypting the wallet.dat with the passphrase does NOT recover the BIP-39 seed words. This is a permanent funds-loss path on disk-loss.** |
| 9 | … | G37: passphrase-vs-passphrase distinction (BIP-39 vs wallet encryption) | **BUG-16 (P1) "passphrase-confusion"** — `CreateWallet` plumbs `opts.Passphrase` to `SaveToFile(opts.Passphrase)` (wallet-file AES-256-GCM key derivation) BUT passes the empty string to `CreateFromMnemonic(mnemonic, "")` (BIP-39 PBKDF2 passphrase). The two are semantically distinct (BIP-39 passphrase is the "25th word", changes the derived seed; wallet passphrase encrypts the master xprv on disk). A user expecting Core's `createwallet` semantics where the passphrase is the WALLET passphrase will silently get **no BIP-39 passphrase** ("plausible deniability" feature dead by design). No warning is logged. |
| 9 | … | G38: `dumpwallet` / `listdescriptors` RPC surfaces seed for backup | **BUG-17 (P0-FUNDS)** — no `dumpwallet`, no `listdescriptors`, no `sethdseed`, no `importmnemonic`, no `importseed`, no `getmasterxpriv` RPC anywhere. The user cannot extract their seed for paper-backup; the only "recovery" is to retain the wallet.dat file and remember the passphrase. **Compounds BUG-15**: even if the user reads source and finds out `Manager.CreateWallet` discards the mnemonic, there is no programmatic path to retrieve it later. The `Mnemonic` field exists in the serialised `walletData` JSON shape (`storage.go:35`) **but is never populated** by any code path. **Comment-as-confession** at `storage.go:113-114`: `"We can't actually recover the seed from the master key, so in a real implementation we'd store the mnemonic."` — admits the gap, never closed. |

---

## BUG-1 (P1) — `isValidSecretKey` does not reject `seckey >= n` at master-key gen

**Severity:** P1. BIP-32 §"Master key generation": "In case `IL` is 0 or
`IL ≥ n`, the master key is invalid." blockbrew's `NewMasterKey`
(`hdkey.go:65-93`) calls `isValidSecretKey(secretKey)` which:

```go
func isValidSecretKey(key []byte) bool {
    if len(key) != 32 { return false }
    // Check for zero
    allZero := true
    for _, b := range key { if b != 0 { allZero = false; break } }
    if allZero { return false }
    // Parse it to verify it's less than curve order
    privKey := secp256k1.PrivKeyFromBytes(key)
    return privKey != nil
}
```

The zero check is fine, but the "less than curve order" check is wrong:
`decred/dcrd/dcrec/secp256k1/v4.PrivKeyFromBytes` **silently reduces
mod n** and returns a non-nil pointer for ANY 32-byte input. The function
NEVER returns nil for any non-zero 32-byte slice. Probe its `modnscalar`
source (`modnscalar.go:360-368`): `SetByteSlice` returns `overflow bool`
but `PrivKeyFromBytes` ignores it.

**File:** `internal/wallet/hdkey.go:96-116`.

**Core ref:** `bitcoin-core/src/key.cpp::CExtKey::SetSeed` writes the
left-32 directly into the `CKey`, then any subsequent
`secp256k1_ec_seckey_tweak_add` rejects with `ret=0`; BUT the BIP-32
spec requires REJECTION at master gen, with caller advancing seed.

**Impact:** probability is ~2^-128 per seed (essentially never for honest
input), but a malicious / fuzz-test seed crafted to put master-IL above n
silently produces a master key that is `IL mod n` rather than the
correct BIP-32 "advance and retry" behaviour. Cross-impl divergence on
adversarial test vectors.

**Fleet pattern:** **same root cause as W159 BUG-15** ("BIP-32
private-GMP asymmetry") — blockbrew uses dcrd's pure-Go scalar
arithmetic which silently reduces mod n; Core uses libsecp's
`secp256k1_ec_seckey_tweak_add` which is fail-closed on overflow.

---

## BUG-2 (P0-SEC, re-statement of W159 BUG-15) — `addPrivateKeys` silently reduces `IL mod n`; pure-Go path is NOT constant-time

**Severity:** P0-SEC + P0-CDIV (chain-split candidate on adversarial
input). Originally reported as W159 BUG-15 and named-origin for the
fleet pattern **"BIP-32 private-GMP asymmetry"**.

```go
// hdkey.go:192-207
func addPrivateKeys(key1, key2 []byte) ([]byte, error) {
    var k1, k2 secp256k1.ModNScalar
    k1.SetByteSlice(key1)
    k2.SetByteSlice(key2)   // <-- IGNORES overflow return — silently reduces IL mod n
    k1.Add(&k2)
    if k1.IsZero() { return nil, ErrInvalidKeyData }
    result := make([]byte, 32)
    k1.PutBytesUnchecked(result)
    return result, nil
}
```

Re-confirmed at master (`fcdcb19c…HEAD`, 2026-05-19): the W159 fix has
NOT landed. **Carry-forward 2-wave open**.

Beyond the silent-divergence concern, the pure-Go `ModNScalar.Add` is
**not constant-time** (the `NonConst` suffix is consistently used in
the dcrd codebase for scalar-mult operations; the field ops underneath
are radix-26 limb arithmetic with conditional carries). Combined with
W158 BUG-3 / W159 BUG-3 (`context_randomize` never called) and W159
BUG-11 (`ScalarBaseMultNonConst` on sign), the **entire blockbrew
private-key surface** lacks both side-channel-blinding mitigations.

**File:** `internal/wallet/hdkey.go:192-207`.

**Core ref:** `bitcoin-core/src/key.cpp:307` —
`secp256k1_ec_seckey_tweak_add(secp256k1_context_static, …)` rejects
overflow with `ret=0` and constant-time path inside libsecp.

**Impact:**
- **Chain-split candidate**: a wallet importing a Core-derived xpriv
  whose subtree crosses an `IL ≥ n` index returns a child key that
  differs from Core's by `IL - n` in the scalar. Subsequent addresses
  derive from a different root and FAIL to detect funds.
- **Side-channel** (timing): the scalar add over secret material can
  leak the parent key bits on a co-located VM/cloud measurement
  attack (Hertzbleed / "platypus" class).
- **Asymmetric-fix WITHIN ONE FILE**: `addPublicKeys` at
  `hdkey.go:219-222` DOES check overflow + zero; `addPrivateKeys`
  three lines earlier does not. The fix is one line:
  `if overflow := k2.SetByteSlice(key2); overflow { return nil, ErrInvalidKeyData }`.

**Cross-cite:** W159 BUG-15 (named-origin), W158 BUG-3 / W159 BUG-3
(`context_randomize` UNIVERSAL), W159 BUG-11 (`ScalarBaseMultNonConst`).

---

## BUG-3 (P1) — `DeriveChild` does not retry on invalid-key error per BIP-32 spec

**Severity:** P1. BIP-32 §"Private parent key → private child key":
"In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid,
and one should proceed with the next value for i."

blockbrew's `DeriveChild` (`hdkey.go:158-188`) returns the error from
`addPrivateKeys` directly:

```go
if k.IsPrivate {
    childKey, err := addPrivateKeys(k.Key, il)
    if err != nil { return nil, err }   // <-- no retry with index+1
    ...
}
```

Likewise `addPublicKeys` and `DerivePath` propagate the error.

**File:** `internal/wallet/hdkey.go:158-188, 259-310`.

**Core ref:** BIP-32 spec; Core's `CKey::Derive` returns false and the
WALLET caller decides whether to advance (e.g., `wallet/scriptpubkeyman.cpp::DeriveExtKey`
advances the index for `m/0/...` BIP-44 chains).

**Impact:** probability is ~2^-128 per index — essentially never for
honest input. Adversarial / fuzz-test xpriv crossing an `IL >= n`
index makes blockbrew reject where Core retries. Cross-impl divergence
on the same xpriv.

---

## BUG-4 (P1) — `addPublicKeys` uses pure-Go `ScalarBaseMultNonConst` instead of libsecp `pubkey_tweak_add`

**Severity:** P1. blockbrew's `addPublicKeys` (`hdkey.go:210-246`):

```go
// Compute scalar * G
var result secp256k1.JacobianPoint
secp256k1.ScalarBaseMultNonConst(&scalarMod, &result)

// Convert parent public key to Jacobian
var parentPoint secp256k1.JacobianPoint
pubKey.AsJacobian(&parentPoint)

// Add the points
secp256k1.AddNonConst(&parentPoint, &result, &result)
```

Both `ScalarBaseMultNonConst` and `AddNonConst` are explicitly
not-constant-time (the `NonConst` suffix is the decred convention for
"do not use with secrets"). For pub-side derivation the secret is the
chain code (used to compute IL); a timing leak of IL leaks the chain
code, which combined with the public xpub recovers the BIP-32 subtree.

Core uses `secp256k1_ec_pubkey_tweak_add` exclusively, which:
1. operates inside a libsecp context (constant-time path),
2. is blinded by `context_randomize`,
3. validates the tweak < n internally.

**File:** `internal/wallet/hdkey.go:210-246`.

**Core ref:** `bitcoin-core/src/pubkey.cpp:355` —
`secp256k1_ec_pubkey_tweak_add(secp256k1_context_static, &pubkey, out)`.

**Impact:** timing-side-channel exposure on the chain-code-bearing pub
derivation path (CKD pub). Cross-cite: W159 BUG-15 (private side); this
is the pub-side variant. **Two-curve-library** fleet pattern (W159).

---

## BUG-5 (P0-CDIV) — `nDepth + 1` silently wraps from 255 to 0 (no `nDepth == 0xFF` check)

**Severity:** P0-CDIV. Bitcoin Core's `CExtKey::Derive` and
`CExtPubKey::Derive` BOTH start with:

```cpp
if (nDepth == std::numeric_limits<unsigned char>::max()) return false;
out.nDepth = nDepth + 1;
```

blockbrew's `DeriveChild` (`hdkey.go:158-188`) computes
`Depth: k.Depth + 1` with no guard, where `Depth` is Go type `byte`.
At depth 255 the increment **silently wraps to 0**, producing:

- An extended key with `Depth=0` (master),
- but `Index != 0` (the just-derived child index),
- and `ParentFP != [4]byte{}` (the parent's fingerprint),
- and (for private) a `0x00`-prefixed seckey.

`ParseExtendedKey` on the resulting `Serialize` output would
deserialize successfully on blockbrew (BUG-6 below — no master
invariant check), but **on Core it would zero the key** per
`CExtKey::Decode`'s final clause:

```cpp
if ((nDepth == 0 && (nChild != 0 || ReadLE32(vchFingerprint) != 0)) || code[41] != 0)
    key = CKey();
```

So a blockbrew-emitted "depth-0-after-wrap" xprv is silently rejected
as `key.IsValid() == false` by Core. Cross-impl divergence — Core sees
master-key garbage, blockbrew treats it as a normal child key.

**File:** `internal/wallet/hdkey.go:168 (private), 184 (public), 322 (PublicKey)`.

**Core ref:** `bitcoin-core/src/key.cpp:483`, `bitcoin-core/src/pubkey.cpp:416`.

**Impact:**
- A wallet that does `m/0'/0/...` 255 levels deep (deliberately or via
  a fuzzer / adversarial descriptor) produces an unparseable xprv on
  Core but a "master xprv" on blockbrew. Funds derived past depth 255
  are unrecoverable on the other side.
- Cross-impl divergence is observable today via descriptor expansion
  with absurd derivation paths.
- **First fleet instance of "byte-overflow on BIP-32 depth"** found
  this wave.

---

## BUG-6 (P0-CDIV) — `ParseExtendedKey` does not enforce Core's master-key invariant

**Severity:** P0-CDIV. Bitcoin Core's `CExtKey::Decode`
(`bitcoin-core/src/key.cpp:523-530`) finishes with:

```cpp
if ((nDepth == 0 && (nChild != 0 || ReadLE32(vchFingerprint) != 0)) || code[41] != 0)
    key = CKey();
```

That is: if depth=0, parent_fp MUST be all-zero AND child_idx MUST be
zero AND the seckey-prefix byte MUST be 0x00 — else the key is zeroed
(rejected at the next `IsValid()` check).

blockbrew's `ParseExtendedKey` (`hdkey.go:407-471`) checks ONLY the
0x00-prefix on private keys; it does NOT enforce the master invariants
on depth/child/fingerprint. A crafted xprv with `depth=0, fp=AABBCCDD,
child=5` parses successfully and the resulting `HDKey` is treated as a
master key by every consumer.

**File:** `internal/wallet/hdkey.go:407-471` (no master-invariant clause).

**Core ref:** `bitcoin-core/src/key.cpp:523-530`,
`bitcoin-core/src/pubkey.cpp:394-400` (`CExtPubKey::Decode` has same
clause but `!pubkey.IsFullyValid()` instead of `code[41] != 0`).

**Impact:** cross-impl reject-vs-accept divergence on hand-crafted xprvs.
A test vector "garbage master xprv" makes blockbrew derive children,
Core treats as invalid. Less critical than BUG-5 but bookended pair.

---

## BUG-7 (P1) — `ParseExtendedKey` does not validate parsed secret key < n

**Severity:** P1. `ParseExtendedKey` populates
`Key: key` (the 32-byte slice from `data[46:78]`) without calling
`isValidSecretKey` or any scalar validation. A crafted xprv encoding
a private key value ≥ n decodes successfully; the bogus key only fails
at first use (via `addPrivateKeys` overflow or `PrivKeyFromBytes`
returning silently-reduced scalar).

**File:** `internal/wallet/hdkey.go:451-457`.

**Core ref:** Core's `CExtKey::Decode` calls `key.Set(code+42, code+74, true)`
which validates the seckey via `secp256k1_ec_seckey_verify` (called by
`CKey::Check`); failure makes the key invalid.

**Impact:** corrupt-xprv handling diverges. P1 because honest users
do not hit this; fuzz-tests + adversarial inputs do.

---

## BUG-8 (P1) — `ParseExtendedKey` does not validate parsed public key is a valid point

**Severity:** P1. `ParseExtendedKey` populates
`Key: key` (33 bytes) for xpubs without calling
`secp256k1.ParsePubKey`. An xpub encoding 33 bytes that do not
decode to a valid secp256k1 point parses successfully; the failure
surfaces only when a descriptor expander or signer tries to use it.

**File:** `internal/wallet/hdkey.go:458-461`.

**Core ref:** Core's `CExtPubKey::Decode` calls
`pubkey.Set(code+41, code+74)` then the final clause
`if (... || !pubkey.IsFullyValid()) pubkey = CPubKey();` enforces validity.

**Impact:** corrupt-xpub handling diverges from Core.

---

## BUG-9 (P0-CDIV) — `ParseExtendedKey` silently zero-pads short input / truncates long input

**Severity:** P0-CDIV. The decode path:

```go
// hdkey.go:407-421
version, payload, err := address.Base58CheckDecode(s)
if err != nil { return nil, ErrInvalidExtendedKey }

// Reconstruct the full 78-byte data
data := make([]byte, 78)
data[0] = version
copy(data[1:], payload)

if len(data) != 78 {           // <-- IMPOSSIBLE: data is `make([]byte, 78)`
    return nil, ErrInvalidExtendedKey
}
```

`Base58CheckDecode` returns a variable-length `payload`. If
`len(payload) < 77`, the trailing `data` bytes (depth/chaincode/key)
stay zero — the xprv decodes as `Depth=0, ParentFP=0, Index=0,
ChainCode=[0...0], Key=[0...0]`. blockbrew then treats this as a valid
master key (BUG-6 cross-cite: no master-invariant check; BUG-1 cross-cite:
the zero key would trip `isValidSecretKey` for private xprv but
`ParseExtendedKey` never calls `isValidSecretKey`). For too-long
payloads, the extra bytes are silently truncated.

The `len(data) != 78` "validate" line is **DEAD CODE**: `data` is
allocated as exactly 78 bytes immediately above, so the check is
always false.

**File:** `internal/wallet/hdkey.go:413-421`.

**Core ref:** `bitcoin-core/src/key.cpp:523` —
`void CExtKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE])`
takes a fixed-size `code[74]` array; the caller (e.g.
`DecodeExtKey` in `key_io.cpp`) validates payload length before
calling `Decode`. Length divergence is impossible.

**Impact:**
- Truncated xprv → silently decoded as "all-zero master xprv" →
  derivation from it produces predictable child keys (`HMAC-SHA512(0, …)`).
  Any funds sent to addresses derived from such a "wallet" are spendable
  by anyone who reproduces the truncation.
- Overlong xprv (e.g., a 79-byte payload because of a hand-written test
  vector) decodes with bytes silently dropped.
- "Dead code" fleet pattern + "silent truncation" pattern combined.

---

## BUG-10 (P2) — SLIP-132 alt-prefix support (ypub/zpub/Ypub/Zpub) absent

**Severity:** P2 (Core also rejects; interop-only). blockbrew's
`ParseExtendedKey` (`hdkey.go:426-433`) accepts only four version-byte
constants: `MainnetPrivate=0x0488ADE4`, `MainnetPublic=0x0488B21E`,
`TestnetPrivate=0x04358394`, `TestnetPublic=0x043587CF`. The SLIP-132
alt-prefix space (`ypub=0x049d7878`, `zpub=0x04b24746`, `Ypub=0x0295b43f`,
`Zpub=0x02aa7ed3`, `Mpub=0x04b24746` …) is rejected with
`ErrInvalidExtendedKey`. Sparrow / Electrum / Trezor / Ledger / Coldcard
exports use these prefixes by default for BIP-49/84/86 descriptors.

The descriptor parser at `descriptor.go:1322-1325` only checks for
`xpub`/`xprv`/`tpub`/`tprv` prefixes; a `zpub` string falls through
to the hex-pubkey or WIF-key branches and is rejected.

**File:** `internal/wallet/hdkey.go:426-433`,
`internal/wallet/descriptor.go:1322-1326`.

**Core ref:** Core deliberately uses descriptor format
`wpkh([fp/path]xpub.../*)` rather than SLIP-132; output format is
canonical xpub. Reject is intentional.

**Impact:** users importing a BIP-84 hardware wallet export get
`unrecognized key format` rather than an actionable error message.
**P2** because Core does the same, but UX divergence + missing
"convert SLIP-132 to xpub" helper is felt by hardware-wallet users.

---

## BUG-11 (P0-CDIV) — `ValidateMnemonic` does not NFKD-normalise before word lookup

**Severity:** P0-CDIV. BIP-39 §"Generating the mnemonic": "the
mnemonic sentence and passphrase MUST be encoded in UTF-8 NFKD".

blockbrew's `MnemonicToSeed` (`mnemonic.go:181-189`) DOES NFKD-normalise
the mnemonic + passphrase:

```go
mnemonicNorm := norm.NFKD.String(mnemonic)
salt := "mnemonic" + norm.NFKD.String(passphrase)
return pbkdf2.Key([]byte(mnemonicNorm), []byte(salt), 2048, 64, sha512.New)
```

But `ValidateMnemonic` (`mnemonic.go:122-177`) and `MnemonicToEntropy`
(`mnemonic.go:193-238`) BOTH skip the normalisation:

```go
words := strings.Fields(mnemonic)             // no NFKD
for _, word := range words {
    idx, ok := wordIndex[word]                 // direct lookup, no NFKD
    if !ok { return false }
    ...
}
```

For the English-only wordlist this is mostly a non-issue (no Latin
characters in the 2048 English words decompose under NFKD). BUT
multi-byte / canonical-equivalent inputs reject inconsistently:
- A Spanish/French wallet that NFC-encodes accents would (a) fail
  validation but (b) succeed at `MnemonicToSeed` — different code paths
  give different verdicts on the same input.
- An attacker can probe whether a string is a valid mnemonic without
  using `MnemonicToSeed` (which is slow due to PBKDF2 2048 rounds).

Asymmetric-normalisation **within one file** — **two-pipeline guard
23rd extension** (fleet pattern; cross-cite W159 BUG-15
"asymmetric-fix WITHIN ONE FILE" 22nd extension; this is the 23rd).

**File:** `internal/wallet/mnemonic.go:122-177, 193-238`.

**Core ref:** Core's wallet does not ship BIP-39 (uses raw seeds /
descriptors); the BIP-39 spec is the authoritative reference. Reference
implementations (BlueWallet/iancoleman/python-mnemonic) all NFKD-normalise
on validate AND on seed-gen.

**Impact:**
- Spanish/French/Japanese wordlist (if blockbrew ever adds one) → silent
  validate-vs-seed-gen divergence.
- Even for English: a user pasting a mnemonic copied from a HTML form
  that converted spaces to non-breaking spaces (` ` → NFKD
  decomposes to `   `?) might validate differently than the
  seed-gen result.
- Two-pipeline guard 23rd extension.

---

## BUG-12 (P1) — `CreateFromMnemonic` is called with empty BIP-39 passphrase by the manager

**Severity:** P1 (combined with BUG-15/16 it becomes a UX disaster).
`Manager.CreateWallet` (`manager.go:202-211`):

```go
if !opts.Blank && !opts.DisablePrivateKeys {
    mnemonic, err := GenerateMnemonic()       // ignored! see BUG-15
    if err != nil { return nil, err }
    if err := w.CreateFromMnemonic(mnemonic, ""); err != nil {
        //                                  ^^^ empty BIP-39 passphrase
        return nil, err
    }
}
```

Then:

```go
if err := w.SaveToFile(opts.Passphrase); err != nil {    // wallet-encryption passphrase
    return nil, err
}
```

The wallet-encryption passphrase (`opts.Passphrase`) is plumbed to the
DISK ENCRYPTION layer (scrypt → AES-256-GCM) but NOT to the BIP-39
seed derivation. So:
- Passing `passphrase="hunter2"` to createwallet encrypts wallet.dat
  but produces the SAME seed as `passphrase=""`.
- A user expecting BIP-39 "25th word" plausible-deniability gets
  none — the seed words alone are enough to recover the wallet, with
  no BIP-39 passphrase required.

The two passphrases are semantically distinct in BIP-39 / Core:
- BIP-39 passphrase modifies the derived seed (different master xprv).
- Wallet-encryption passphrase encrypts the on-disk master xprv.

**File:** `internal/wallet/manager.go:209` (hardcoded `""`),
`internal/rpc/multiwallet_methods.go:49-53` (parses `args[3]` as
`opts.Passphrase` — wallet-encryption only).

**Core ref:** Core's `createwallet` RPC argument
`passphrase` encrypts the wallet (Core does not natively use BIP-39).
The BIP-39 passphrase is a separate concept handled by hardware wallets
and BIP-39-aware software wallets.

**Impact:**
- No "plausible deniability" feature: anyone who learns the seed
  words owns the funds (no 25th word).
- A user with multiple wallets created from the same mnemonic +
  different BIP-39 passphrases (a common HW-wallet pattern) cannot
  reproduce them in blockbrew — they all collapse to one wallet.
- Combined with BUG-15 (mnemonic discarded) and BUG-17 (no recovery
  RPC), this is the **"passphrase-confusion compound funds-loss"**
  trifecta.

---

## BUG-13 (P1) — `initAccount` hardcodes BIP-84 path; `GetExtendedPublicKey` likewise (carry-forward W111 BUG-2)

**Severity:** P1. `initAccount` (`wallet.go:243-266`):

```go
// Derive account key: m/84'/coin'/account'
coinType := w.coinType()
path := fmt.Sprintf("m/84'/%d'/%d'", coinType, accountIndex)
accountKey, err := w.masterKey.DerivePath(path)
...
account := &Account{
    Index:     accountIndex,
    ExtPubKey: accountKey.PublicKey(),
    Addresses: make([]string, 0),
}
```

This always uses BIP-84 (`m/84'/...`) regardless of `w.config.AddressType`.
When the wallet's default `AddressType` is `AddressTypeP2PKH` (BIP-44),
`AddressTypeP2SH_P2WPKH` (BIP-49), or `AddressTypeP2TR` (BIP-86), the
per-call derivation in `newAddressOfTypeLocked` is correct (uses the
right path), BUT `accounts[0].ExtPubKey` is the BIP-84 xpub and is
returned by `GetExtendedPublicKey`.

`GetExtendedPublicKey` (`wallet.go:2287-2305`) has the same hardcoded
path:

```go
path := fmt.Sprintf("m/84'/%d'/%d'", coinType, account)
```

So an operator running `getmasterxpub` (when that RPC is wired) gets
the BIP-84 xpub on a P2PKH/P2SH/P2TR-default wallet. **First-class
divergence from the operator's selected `AddressType`.**

**File:** `internal/wallet/wallet.go:249-266, 2287-2305`.

**Core ref:** Core's wallet uses one descriptor per output type (the
"descriptor wallet" model from `wallet/scriptpubkeyman.cpp`), where
each descriptor has its own derivation chain — there is no single
"account xpub" concept.

**Impact:** carry-forward of W111 BUG-2 (~5+ months open). A wallet
with `AddressType=AddressTypeP2TR` and `account=0` reports BIP-84
xpub in `accounts[0].ExtPubKey`. Any downstream code that uses that
xpub for "watch-only" address generation derives wrong (P2WPKH instead
of P2TR) addresses.

---

## BUG-14 (P0-CDIV, carry-forward of W160 BUG-16) — wallet `signP2TR` hardcodes `merkleRoot=nil`; cannot sign script-path-committed taproot

**Severity:** P0-CDIV. W160 BUG-16 named-origin. Cross-cite (camlcoin
+ blockbrew + beamchain — 3 fleet instances at W160).

`internal/wallet/wallet.go:1292`:

```go
tweakHash := script.TapTweak(xOnlyPubKey, nil)   // <-- hardcoded nil
```

The wallet can only sign BIP-86 (key-path-only) outputs. For
script-path-committed outputs (BIP-341 with non-empty tap tree), the
signed sig is `(d + TapTweak(P, nil))·G` but the on-chain output key
is `(d + TapTweak(P, merkleRoot))·G` — verify FAILS.

The descriptor expander at `descriptor.go:680-690` correctly handles
both paths (passing the computed merkle root when `d.TapTree != nil`).
The bug is that the wallet's signing pipeline does NOT propagate the
merkle root from the descriptor through to the sign call.

**File:** `internal/wallet/wallet.go:1292`.

**Core ref:** `bitcoin-core/src/key.cpp:532-547` — `KeyPair` constructor
takes `merkle_root` and conditionally applies
`secp256k1_keypair_xonly_tweak_add`.

**Impact:** carry-forward 2-wave open (since W160). Any wallet
descriptor with a tap tree (`tr(KEY, TREE)`) produces unsignable funds
in blockbrew.

---

## BUG-15 (P0-FUNDS) — `createwallet` generates a mnemonic and immediately discards it (no recovery)

**Severity:** P0-FUNDS. THIS IS THE BIGGEST FINDING THIS AUDIT.

`Manager.CreateWallet` (`manager.go:202-227`):

```go
if !opts.Blank && !opts.DisablePrivateKeys {
    // Generate new mnemonic and initialize wallet
    mnemonic, err := GenerateMnemonic()
    if err != nil { return nil, err }
    if err := w.CreateFromMnemonic(mnemonic, ""); err != nil {
        return nil, err
    }
    // <<< mnemonic falls out of scope HERE — garbage collected >>>
}
...
return w, nil   // <-- returns only the wallet handle; mnemonic discarded
```

`handleCreateWallet` (`multiwallet_methods.go:82-86`):

```go
return &CreateWalletResult{
    Name:     w.Name(),
    Warnings: warnings,
}, nil   // <-- no mnemonic field on CreateWalletResult
```

`CreateWalletResult` (`types.go:555`) — no mnemonic field.

So the flow is:
1. RPC client calls `createwallet "mywallet" false false "hunter2"`.
2. Server generates 24-word mnemonic.
3. Server uses mnemonic to derive seed → master xprv.
4. Server saves master xprv (encrypted under "hunter2") to wallet.dat.
5. **Mnemonic is garbage-collected. Never returned to client. Never
   stored to disk.**

`storage.go:32-43` declares a `Mnemonic` field on the on-disk JSON
shape:

```go
type walletData struct {
    Seed       []byte            `json:"seed,omitempty"`
    Mnemonic   string            `json:"mnemonic,omitempty"`
    ...
}
```

But **no code path populates it**:

```bash
$ grep -rn "\.Mnemonic\s*=" internal/wallet/
# (empty output — never assigned)
```

The on-disk "seed" is the 64-byte `Key||ChainCode` (master xprv layer),
NOT the BIP-39 seed. Even decrypting wallet.dat with the right
passphrase does NOT recover the BIP-39 seed words.

**Result:** the user has zero recovery path. On disk-loss, the funds
are unrecoverable. The user is locked into this blockbrew installation
forever — they cannot import the mnemonic into another wallet (because
they were never given the mnemonic), and they cannot reconstruct the
master xprv from any external backup.

**File:** `internal/wallet/manager.go:205-211`,
`internal/rpc/multiwallet_methods.go:82-86`,
`internal/rpc/types.go:555` (no mnemonic field on result type),
`internal/wallet/storage.go:35` (dead `Mnemonic` field),
`internal/wallet/storage.go:113-114` (**comment-as-confession**:
`"We can't actually recover the seed from the master key, so in a real
implementation we'd store the mnemonic."`).

**Core ref:** Core's `createwallet` historically returned the seed
phrase in test mode; modern Core uses `listdescriptors` to dump the
master xpub/xpriv. blockbrew has **neither**.

**Impact:**
- **PERMANENT FUNDS LOSS on disk failure**: any wallet ever created
  via blockbrew's `createwallet` is recoverable ONLY from the
  wallet.dat + passphrase combo. Disk failure → funds gone forever.
- Operator cannot move funds to another node (no export path).
- Operator cannot back up to paper/metal seed plate (no mnemonic to
  back up).
- Operator cannot use a HW wallet derived from the same seed (no
  mnemonic to import into the HW wallet).
- The presence of the `Mnemonic` field on the disk shape suggests the
  author KNEW this was needed and never finished. **Comment-as-confession
  fleet pattern, fleet-wide saturating** (per recent quad-audit memory).

**Fix:** thread `mnemonic` out of `CreateWallet` to the RPC handler,
add a `mnemonic string` field to `CreateWalletResult`, and document
that the user MUST write it down before closing the RPC connection.
(Optionally: persist the mnemonic into wallet.dat encrypted under the
same passphrase so it can be recovered via a future `dumpwallet` /
`getmnemonic` RPC.)

---

## BUG-16 (P1) — passphrase-confusion: `opts.Passphrase` encrypts wallet.dat but is NOT the BIP-39 passphrase

**Severity:** P1 (compounded with BUG-15 + BUG-17 into BUG-12's funds-loss
risk). The `createwallet` RPC accepts a 4th positional argument
`passphrase` (Core-compatible). blockbrew's handler:

- Parses it as `opts.Passphrase` (`multiwallet_methods.go:49-53`).
- Plumbs it to `w.SaveToFile(opts.Passphrase)` → AES-256-GCM wallet-file
  encryption (correct).
- Does **NOT** plumb it to `w.CreateFromMnemonic(mnemonic, "")` →
  BIP-39 passphrase is always empty (incorrect).

The two passphrases serve different cryptographic purposes:
- BIP-39 passphrase ("25th word") changes the derived BIP-32 seed,
  producing a completely different wallet for the same mnemonic +
  different passphrase combinations. This is the "plausible
  deniability" feature.
- Wallet-encryption passphrase decrypts wallet.dat on-disk.

blockbrew collapses them into the wallet-encryption role only.

**File:** `internal/wallet/manager.go:209` (hardcoded `""`),
`internal/rpc/multiwallet_methods.go:49-53`.

**Core ref:** Core does not natively support BIP-39 (uses its own
descriptor-wallet mechanism). The conflation is therefore not a
direct Core-divergence; but for a wallet THAT CHOSE TO IMPLEMENT BIP-39
(blockbrew did), the two-passphrase semantic should be honoured.

**Impact:**
- No "25th word" plausible-deniability feature available.
- Users coming from Trezor / Ledger / Sparrow with a BIP-39 passphrase
  cannot reproduce their wallet in blockbrew.
- Combined with BUG-15: even if blockbrew added mnemonic export, the
  exported mnemonic + the user's BIP-39 passphrase would NOT reproduce
  the wallet — because blockbrew never honoured the BIP-39 passphrase
  in the first place.

---

## BUG-17 (P0-FUNDS, compounds BUG-15) — no `dumpwallet` / `listdescriptors` / `sethdseed` / `importmnemonic` RPC

**Severity:** P0-FUNDS. blockbrew exposes ZERO mnemonic-recovery RPCs:

```bash
$ grep -rn 'createwallet\|importmulti\|listdescriptors\|importdescriptors\|dumpwallet\|importwallet\|sethdseed\|importmnemonic' internal/rpc/
internal/rpc/server.go:637:		case "createwallet":
internal/rpc/types.go:555:// CreateWalletResult represents the result of createwallet.
internal/rpc/rawtx_methods.go:616:// importdescriptors RPC
```

Only `createwallet` exists in the dispatch table. `importdescriptors`
is mentioned in a comment but not wired (`grep` shows it only as a
comment line). There is no:
- `dumpwallet` — exports private keys to disk.
- `listdescriptors` (modern) — lists descriptors with their xprv/xpub.
- `sethdseed` (legacy) — set HD seed from a WIF private key.
- `importmnemonic` (non-Core extension some impls offer) — restore
  from BIP-39 mnemonic.
- `getmasterxpriv` / `getbackupinfo` — any read-side recovery.

**File:** `internal/rpc/server.go:516-746` (dispatch table — none of
the recovery RPCs present).

**Core ref:** `bitcoin-core/src/wallet/rpc/backup.cpp::dumpwallet`,
`bitcoin-core/src/wallet/rpc/wallet.cpp::listdescriptors`,
historical `sethdseed` (removed in v0.21+ in favour of descriptors).

**Impact:** compounds BUG-15 — even if the operator reads the source
code and learns that `Manager.CreateWallet` discarded the mnemonic,
there is no programmatic path to retrieve it later. The wallet is
permanently sealed inside the wallet.dat file. **Same architectural
shape as the fleet pattern "wiring-look-but-no-wire" (W138 origin):
the `Mnemonic` JSON field exists, the `MnemonicToEntropy` primitive
exists, but no RPC ever invokes them.**

---

## Bug Severity Summary

| Severity | Count | IDs |
|----------|-------|-----|
| P0-FUNDS | **2** | BUG-15 (createwallet discards mnemonic), BUG-17 (no recovery RPC) |
| P0-CDIV  | **5** | BUG-5 (depth wrap), BUG-6 (master invariant), BUG-9 (silent zero-pad), BUG-11 (NFKD asymmetric), BUG-14 (TapTweak no merkle root — carry-forward W160) |
| P0-SEC   | **1** | BUG-2 (BIP-32 priv side silent reduce + not-constant-time — carry-forward W159 BUG-15) |
| P1       | **7** | BUG-1 (master-gen `>= n` check dead), BUG-3 (no retry on invalid), BUG-4 (pub-side `NonConst`), BUG-7 (parsed seckey not validated), BUG-8 (parsed pubkey not validated), BUG-12 (CreateFromMnemonic empty passphrase), BUG-13 (initAccount hardcoded BIP-84 — carry-forward W111), BUG-16 (passphrase confusion) |
| P2       | **1** | BUG-10 (SLIP-132 absent) |
| **TOTAL** | **17 (with overlap)** | |

Note: BUG-12 and BUG-16 are listed once in the summary count.

Counting distinct bug numbers: 17 BUGs.

---

## Cross-cites & fleet patterns observed this wave

- **W159 BUG-15 "BIP-32 private-GMP asymmetry"** — re-confirmed unfixed
  at master (BUG-2 above). **Carry-forward 2-wave open.** Same root
  cause spawns the BUG-1 (master gen `>= n` not enforced) and BUG-4
  (pub-side `NonConst`) issues. **blockbrew is named-origin** of this
  pattern.
- **W160 BUG-16 "TapTweak no-merkle-root"** — re-confirmed unfixed at
  master (BUG-14 above). **Carry-forward 2-wave open.** Cross-cite:
  camlcoin + blockbrew + beamchain (3 fleet instances).
- **W158 BUG-3 + W159 BUG-3 "context_randomize UNIVERSAL"** — cross-cite:
  the pure-Go scalar arithmetic in BUG-2 and BUG-4 inherits the same
  no-blinding posture as W158/W159 because blockbrew never enters a
  libsecp context for any private-key operation outside BIP-324
  ellswift.
- **"two-pipeline guard"** — extended to **23rd distinct fleet
  instance** by BUG-11 (`ValidateMnemonic` vs `MnemonicToSeed` NFKD
  asymmetric in same file). W159 BUG-15 was 22nd; W161 BUG-11 is 23rd.
- **"comment-as-confession"** — extended by BUG-15 / BUG-17 / BUG-12
  cluster. The `storage.go:113-114` comment "*We can't actually recover
  the seed from the master key, so in a real implementation we'd store
  the mnemonic*" is the most direct fleet instance to date — admits the
  on-disk shape is incomplete and the wallet is permanently sealed.
- **"wiring-look-but-no-wire"** (W138 origin) — BUG-17 (`Mnemonic`
  JSON field + `MnemonicToEntropy` primitive + zero RPC consumer) is
  the same architectural shape: the parts exist, the wiring does not.
- **"asymmetric-fix WITHIN ONE FILE"** — extended by BUG-11
  (`ValidateMnemonic` vs `MnemonicToSeed`). W159 BUG-15 was the named
  origin (priv vs pub).
- **"silent-truncation"** — BUG-9 (`Base58CheckDecode` returns
  variable-length, copy silently zero-pads). Similar shape to ouroboros
  W157 "hash-length silent-truncation".
- **"dead-code-but-called" / "dead validator"** — BUG-9
  (`if len(data) != 78` is logically dead because `data` is allocated
  78 bytes 5 lines earlier).
- **"defense-in-depth missing at the producer"** (hotbuns W157 origin)
  — BUG-15 + BUG-17 are the producer-side defense gap: at wallet
  creation time the mnemonic IS available and could be persisted; at
  later recovery time it CANNOT be reconstructed.
- **"feature-half-finished-parser-vs-signer"** — BUG-14 (descriptor
  CAN compute merkle root, wallet signer CANNOT propagate it). Similar
  to W160 BUG-16's analysis.
- **"generate-and-discard"** — **NEW PATTERN proposed this wave**:
  the implementation generates secret material in one execution scope
  and discards it before returning control to the caller, with no
  persistence layer to recover from. The user has no way to ever see
  the secret. Distinct from "wiring-look-but-no-wire" (where the
  secret is reachable in principle but no caller invokes the
  reach-path) — here the secret is unreachable BY DESIGN. **First
  fleet instance: blockbrew W161 BUG-15.**
- **"depth-byte-overflow"** — **NEW PATTERN proposed this wave**:
  BIP-32 depth field is 1 byte; deriving past depth 255 silently
  wraps to a depth=0 master-shape key with non-zero parent_fp/idx.
  Core guards with `nDepth == 0xFF → return false`. **First fleet
  instance: blockbrew W161 BUG-5.**
- **"passphrase-confusion"** — **NEW PATTERN proposed this wave**:
  an RPC argument named "passphrase" is plumbed to the wrong layer
  (wallet-file encryption instead of BIP-39 seed derivation, or
  vice versa). **First fleet instance: blockbrew W161 BUG-16.**

## Carry-forward summary (cross-quad)

- **W111 BUG-2** (initAccount hardcoded BIP-84) — re-confirmed open
  in BUG-13. **5+ months open**.
- **W111 BUG-1** (SaveToFile stores Key||ChainCode as "seed") — root
  cause for BUG-15's "even decrypting wallet.dat does not recover the
  BIP-39 seed".
- **W159 BUG-15** (BIP-32 priv-side silent reduce) — 2-wave open.
- **W160 BUG-16** (TapTweak no merkle root) — 2-wave open.

## "Fleet-wide" candidate calls

- **CKD priv via pure-Go big-int instead of libsecp** — pattern
  candidate for next quad-audit's "BIP-32-private-GMP-asymmetry"
  fleet sweep. blockbrew is named-origin. Likely shared with at least
  Go-based impls (none other in the hashhog fleet) but the
  `secp256k1_ec_seckey_tweak_add`-vs-impl-scalar-add **shape** likely
  applies to camlcoin (cryptokit), nimrod, lunarblock, hotbuns — all
  worth checking.
- **No `dumpwallet` / `listdescriptors` / mnemonic recovery RPC** —
  candidate fleet sweep. If any other impl exposes `createwallet`
  without exposing mnemonic recovery, same funds-loss applies.
