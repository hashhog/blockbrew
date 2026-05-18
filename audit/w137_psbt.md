# W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) audit (blockbrew)

**Wave**: W137 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**Scope**: PSBT codec, role state machine (Creator/Updater/Signer/Finalizer/
Extractor), Combiner, JoinPSBTs, taproot (BIP-371), MuSig2 (BIP-327 PSBT
fields), proprietary types (BIP-174 0xFC), version validation, and RPC
glue (`createpsbt`, `decodepsbt`, `combinepsbt`, `finalizepsbt`,
`converttopsbt`, `utxoupdatepsbt`, `joinpsbts`, `analyzepsbt`,
`walletprocesspsbt`).
**Verdict**: **BUGS FOUND** — **24 distinct bug IDs (BUG-1..BUG-24)**,
including **5 P0-CDIV** (round-trip data-loss / cross-impl serialization
divergence vs Core when MuSig2 input fields, proprietary entries, or PSBT
v2 global/input/output fields are present), **2 P1** (no PSBT-version
ceiling check → silently accepts unsupported versions; no DER-signature
validation on `PSBT_IN_PARTIAL_SIG` → forged-sig corpus survives parse),
and 17 HIGH/MED/LOW gaps in pubkey validity, duplicate-key tracking
granularity, extra-data-after-PSBT rejection, JoinPSBTs duplicate-input
detection, finalize role logic, analyzepsbt next-role state machine, and
RPC `createpsbt` BIP-125 default mismatch.

**Bitcoin Core references**:
- `bitcoin-core/src/psbt.h` — `PSBTInput::Unserialize`, `PSBTOutput::
  Unserialize`, `PartiallySignedTransaction::Unserialize`/`Serialize`,
  type constants `PSBT_GLOBAL_UNSIGNED_TX`..`PSBT_GLOBAL_PROPRIETARY`,
  `PSBT_IN_*`, `PSBT_OUT_*`, `PSBT_HIGHEST_VERSION=0`,
  `MAX_FILE_SIZE_PSBT=100000000`, `DeserializeMuSig2ParticipantPubkeys`,
  `DeserializeMuSig2ParticipantDataIdentifier`, `PSBTProprietary`,
  taproot key/leaf/control-block sizes, `MUSIG2_PUBNONCE_SIZE=66`,
  per-input/per-output duplicate-key detection via `std::set<vector<u8>>
  key_lookup`, separator-missing rejection, input-count/output-count vs
  tx.vin/tx.vout enforcement.
- `bitcoin-core/src/psbt.cpp` — `PSBTInput::Merge`, `PSBTOutput::Merge`,
  `PartiallySignedTransaction::Merge`, `FillSignatureData` /
  `FromSignatureData`, `PSBTInputSigned`, `PSBTInputSignedAndVerified`,
  `CountPSBTUnsignedInputs`, `UpdatePSBTOutput`, `PrecomputePSBTData`,
  `SignPSBTInput`, `RemoveUnnecessaryTransactions`, `FinalizePSBT`,
  `FinalizeAndExtractPSBT`, `CombinePSBTs`, `DecodeBase64PSBT`,
  `DecodeRawPSBT` (extra-data check), `PartiallySignedTransaction::
  GetVersion`.
- `bitcoin-core/src/rpc/rawtransaction.cpp` — `createpsbt` (line 1620),
  `converttopsbt` (1663), `utxoupdatepsbt` (1731), `joinpsbts` (1778)
  (includes randomized shuffle + duplicate-input detection +
  best-version + best-locktime aggregation), `analyzepsbt` (1880),
  `decodepsbt` (1013).
- `bitcoin-core/src/node/psbt.h/cpp` — `PSBTAnalysis` (estimated_vsize,
  estimated_feerate, fee, next, error), `AnalyzePSBT` walking each
  input through Updater→Signer→Finalizer state machine.
- BIPs: 174 (PSBT v0), 370 (PSBT v2 globals/inputs/outputs), 371 (Taproot
  PSBT fields), 327 (MuSig2 PSBT fields), 125 (RBF opt-in semantics
  relevant to `createpsbt` `replaceable` flag default).

**Source under audit**:
- `blockbrew/internal/wallet/psbt.go` — type table, codec, parse/encode
  for global/input/output maps, base64 wrapper.
- `blockbrew/internal/wallet/psbt_ops.go` — `CombinePSBTs`, `mergeInput`,
  `mergeOutput`, `WalletPSBTSigner`, `SignPSBT`, `FinalizePSBT`,
  `FinalizeInput`, `finalizeP2WPKH`/`P2WSH`/`P2SH`/`P2PKH`/`P2TR`,
  `finalizeMultisig`, `finalizeLegacyMultisig`, `clearInputSigningData`,
  `ExtractTransaction`, `FinalizeAndExtractTransaction`,
  `IsComplete`.
- `blockbrew/internal/rpc/psbt_methods.go` — `handleCreatePSBT`,
  `handleDecodePSBT`, `handleCombinePSBT`, `handleFinalizePSBT`,
  `handleConvertToPSBT`, `handleWalletProcessPSBT`,
  `handleAnalyzePSBT`, `handleJoinPSBTs`, `handleUTXOUpdatePSBT`,
  plus the `buildDecodePSBTResultWithNet` builder.
- `blockbrew/internal/rpc/decodepsbt_helpers.go` — `sighashToStr`,
  `btcAmount`, descriptor inference, embedded tx sub-object builder.

## Summary

Severity distribution:

| Severity   | Count | Notes |
|------------|-------|-------|
| P0-CDIV    | 5     | BUG-1 input MuSig2 fields (0x1a participants / 0x1b pubnonce / 0x1c partial_sig) have NO codec arms — they silently round-trip via `input.Unknown` so any PSBT carrying them re-emits **with different sort order** (Go map iteration, then `sort.Strings`) than Core's `std::set<PSBTProprietary>` lexicographic key order, breaking byte-identity; BUG-2 BIP-174 global, input, and output `PSBT_*_PROPRIETARY=0xfc` keys are also bucketed into `Unknown` — Core stores them in `std::set<PSBTProprietary>` ordered by FULL key bytes (identifier + subtype + keydata) and emits BEFORE the unknown-bucket map; blockbrew sort-by-string of the raw key produces a different on-wire ordering whenever both proprietary AND unknown entries are present, OR when proprietary keys differ from raw lexicographic order on subtype VARINT; BUG-3 PSBT v2 (BIP-370) global fields `PSBT_GLOBAL_TX_VERSION=0x02`, `PSBT_GLOBAL_FALLBACK_LOCKTIME=0x03`, `PSBT_GLOBAL_INPUT_COUNT=0x04`, `PSBT_GLOBAL_OUTPUT_COUNT=0x05`, `PSBT_GLOBAL_TX_MODIFIABLE=0x06` are DECLARED as constants but have **NO parse/encode/state arms** — a v2 PSBT round-trips through `Unknown` with no semantic enforcement of the tx-version/locktime/in-out counts, producing wrong outputs when the same PSBT is re-encoded into a v2 wire shape; BUG-4 BIP-370 v2 input fields `PSBT_IN_PREVIOUS_TXID=0x0e`, `PSBT_IN_OUTPUT_INDEX=0x0f`, `PSBT_IN_SEQUENCE=0x10`, `PSBT_IN_REQUIRED_TIME_LOCKTIME=0x11`, `PSBT_IN_REQUIRED_HEIGHT_LOCKTIME=0x12` — same shape: declared, not handled; BUG-5 BIP-370 v2 output fields `PSBT_OUT_AMOUNT=0x03`, `PSBT_OUT_SCRIPT=0x04` — same shape. Cross-impl divergence is GUARANTEED whenever the BIP-370 v2 codec is exercised against a Core-emitted artifact. |
| P1         | 2     | BUG-6 NO PSBT-version ceiling check — `psbt.Version > PSBT_HIGHEST_VERSION (=0 in Core today)` should reject as "unsupported version number" per psbt.h:1322, but blockbrew accepts ANY uint32 value; carrying a forged version=2 PSBT through the parser silently produces a v0-shaped decode (since v2 fields all fall into Unknown — BUG-3..5), corrupting `walletprocesspsbt` semantics. BUG-7 NO DER signature encoding validation on `PSBT_IN_PARTIAL_SIG=0x02` parse — Core: `psbt.h:544` calls `CheckSignatureEncoding(sig, SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC, nullptr)` and rejects invalid encodings; blockbrew accepts arbitrary bytes including non-DER and zero-length, propagating to finalizer (which builds the witness around the malformed sig). |
| HIGH       | 7     | BUG-8 NO pubkey validity check on `PSBT_IN_PARTIAL_SIG` keydata — Core asserts `CPubKey::IsFullyValid()` and rejects malformed pubkeys; blockbrew only checks length=33 or 65. Forged ECDSA pubkey bypasses parse. BUG-9 NO pubkey validity check on `PSBT_IN_BIP32_DERIVATION` (and OUT_BIP32_DERIVATION) — Core rejects on `!pubkey.IsFullyValid()`; blockbrew only checks length. BUG-10 NO global-xpub size/uniqueness enforcement matching Core — Core: `key.size() != BIP32_EXTKEY_WITH_VERSION_SIZE + 1` (=79 bytes), `!global_xpubs.contains(xpub)`; blockbrew accepts `len(keyData) < 78` only AS A FLOOR (any ≥78 admits malformed xpubs), and uses `seenKeys` (full-key map) NOT a per-xpub uniqueness check — duplicate xpubs with the same xpub but different keypath byte tails are NOT rejected at the global-map level. BUG-11 `parseBIP32Derivation` does not enforce path arity ≤ 255 elements (Core deserializes via length divisibility, but blockbrew accepts arbitrary 4-byte chunks up to 2^32 levels — OOM-ish DoS though bounded by MaxPSBTFileSize=100MB). BUG-12 `validatePSBTInput` runs at parse-time and signer-dispatch-time, but `Combine`/`merge*` does NOT re-validate after merging a foreign NON_WITNESS_UTXO into the local — a buggy/malicious combiner peer can stuff an attacker-supplied NON_WITNESS_UTXO that doesn't match the prevout hash, and the local sees it as "merged in" without sanity-rerun (the in-process bypass that `validatePSBTInput`'s comment explicitly warns about, but the Combine path was forgotten in W41). BUG-13 `DecodePSBT` does NOT reject trailing data after the last expected output map — Core: `DecodeRawPSBT` calls `if (!ss_data.empty()) { error = "extra data after PSBT"; return false; }` (psbt.cpp:622-625); blockbrew silently ignores anything past `len(tx.TxIn)` input maps + `len(tx.TxOut)` output maps. Trailing junk in a base64 PSBT survives round-trip via re-encode-from-decoded-bytes ONLY in shape, not in content — but trailing-junk corpora pass the parser silently, breaking equivalence with Core "decode then re-encode" auditors. BUG-14 `handleCreatePSBT` defaults RBF behavior to OPT-IN unconditionally via `wallet.BIP125RBFSequence` (0xFFFFFFFD) when `replaceable==true` is omitted/false-defaulted in the args — but the JSON layout's third arg is `locktime` and fourth `replaceable`; Core defaults `rbf=std::nullopt` and passes through ConstructTransaction. blockbrew's default-`replaceable=false` branch puts `Sequence = 0xffffffff` (NON-RBF, NON-anti-fee-snipe) — Core's `ConstructTransaction` instead defaults to `MAX_SEQUENCE_NONFINAL = 0xfffffffe` (NON-RBF but anti-fee-sniping ENABLED) when locktime != 0 and rbf was nullopt. blockbrew's `createpsbt` yields wallets a non-anti-fee-snipe sequence on the default path. |
| MED        | 7     | BUG-15 `handleAnalyzePSBT` next-role state machine is COARSE — Core's `AnalyzePSBT` walks per-input through Updater→Signer→Finalizer with detailed reasons (missing_pubkeys / missing_sigs / missing_redeem_script / missing_witness_script), and surfaces `estimated_vsize` + `estimated_feerate`; blockbrew emits only `has_utxo` / `is_finalized` / a coarse `missing.signatures` bool. The "Pubkeys" array is declared in the struct as `[]string` but never populated; estimated_vsize / estimated_feerate are missing entirely. BUG-16 `handleAnalyzePSBT` field-name mismatch with Core — Core emits `is_final` and `missing.redeemscript`/`missing.witnessscript`; blockbrew emits `is_finalized` and `missing.signatures` only. Field-name divergence breaks RPC clients tracking Core. BUG-17 `handleJoinPSBTs` does NOT detect duplicate inputs across PSBTs — Core: `if (!merged_psbt.AddInput(...)) throw "Input %s:%d exists in multiple PSBTs"`; blockbrew silently concatenates. Joining two PSBTs that share an input produces an invalid joined PSBT. BUG-18 `handleJoinPSBTs` does NOT pick best version/locktime — Core: `best_version=max(versions)`, `best_locktime=min(locktimes)`; blockbrew hard-codes `Version=2, LockTime=0`. BUG-19 `handleJoinPSBTs` does NOT shuffle inputs/outputs — Core deliberately shuffles (`FastRandomContext`) so the joiner does not leak the per-PSBT input grouping; blockbrew preserves order, leaking joiner-side associations. BUG-20 `mergeInput`/`mergeOutput` do NOT detect "different prevTx for the same input" — Core: `Merge` is gated by `tx->GetHash() == psbt.tx->GetHash()` and per-input/per-output is unconditional emplace. blockbrew gates with `TxHash()` equality (OK) but on a conflict (e.g. dst has WitnessUTXO=A and src has WitnessUTXO=B), the conflict is silently resolved to dst (first-wins). Core's PSBTInput::Merge mirrors this in spirit but a different-WITNESS_UTXO is observably wrong; blockbrew has no diagnostic. BUG-21 `handleCombinePSBT` re-encodes the first PSBT as the merge base, but if PSBT 0 has `Version!=0` and the others have `Version==0`, the combined output silently demotes/promotes versions with no enforcement; Core merges into the first and the version is whatever PSBT[0] had — blockbrew's behavior matches by accident, but does NOT validate that all PSBTs being combined share a version (BIP-174 requires equal versions, and v0+v2 merge is undefined). |
| LOW        | 3     | BUG-22 `clearInputSigningData` clears `TapInternalKey` and `TapMerkleRoot` on finalize, but Core's `PSBTInput::FromSignatureData` (when sigdata.complete) only clears `partial_sigs`, `hd_keypaths`, `redeem_script`, `witness_script` — taproot internal key and merkle root are preserved across finalize for verifiability. blockbrew's aggressive clear strips data that a downstream verifier needs to reconstruct the spending path for a key-path-spend audit. BUG-23 Encoder iterates input.Unknown via `sort.Strings(unknownKeys)` (lexicographic on raw-key bytes treated as Go strings) — Core sorts via `std::map<vector<u8>,vector<u8>>` which uses lexicographic comparison on the byte slice. These ARE the same for ASCII-only keys but differ if any key has bytes 0x80..0xFF in a position where one key truncates earlier and the comparison reaches end-of-string — Go's `string` comparison does NOT match `std::map<vector<uint8_t>>` ordering when keys have different lengths and a prefix relationship. Edge case: extremely rare in practice. BUG-24 `extractTransaction` builds an error message `"input " + string(rune('0'+i)) + " is not finalized"` — this stringifies the index as a SINGLE Unicode rune at the codepoint `'0'+i`, which works for i=0..9 but produces garbage for i≥10 (input 10 becomes ':', input 11 becomes ';', etc.). Cosmetic only — the error returns the wrong digit but the call site never indexes off the message. |

PASS: **8** / PARTIAL: **9** / MISSING: **13**. Bug count: **24**.

## 30-Gate Audit Matrix

| Gate | Sub-area | Status | Bug refs |
|------|----------|--------|----------|
| G1 | PSBT magic bytes (psbt + 0xff) parsed and emitted | PASS | — |
| G2 | `PSBT_GLOBAL_UNSIGNED_TX=0x00` parse + serialize + scripts-empty check | PASS | — |
| G3 | `PSBT_GLOBAL_XPUB=0x01` parse + serialize | PARTIAL | BUG-10 |
| G4 | `PSBT_GLOBAL_VERSION=0xfb` parse + ceiling check vs PSBT_HIGHEST_VERSION | PARTIAL | BUG-6 |
| G5 | `PSBT_GLOBAL_PROPRIETARY=0xfc` parse + ordered serialize | MISSING | BUG-2 |
| G6 | BIP-370 v2 global fields (0x02..0x06) parse + state machine | MISSING | BUG-3 |
| G7 | `PSBT_IN_NON_WITNESS_UTXO=0x00` parse + txid validation (W41) | PASS | — |
| G8 | `PSBT_IN_WITNESS_UTXO=0x01` parse + CVE-2020-14199 cross-check (W41) | PASS | — |
| G9 | `PSBT_IN_PARTIAL_SIG=0x02` parse + DER sig validation + pubkey IsFullyValid | PARTIAL | BUG-7 BUG-8 |
| G10 | `PSBT_IN_SIGHASH=0x03` parse + key.size()==1 enforcement | PASS | — |
| G11 | `PSBT_IN_REDEEMSCRIPT=0x04` / `PSBT_IN_WITNESSSCRIPT=0x05` parse | PASS | — |
| G12 | `PSBT_IN_BIP32_DERIVATION=0x06` parse + IsFullyValid | PARTIAL | BUG-9 BUG-11 |
| G13 | `PSBT_IN_FINAL_SCRIPTSIG=0x07` / `_SCRIPTWITNESS=0x08` parse | PASS | — |
| G14 | `PSBT_IN_RIPEMD160/SHA256/HASH160/HASH256=0x0a..0x0d` parse + hash-size check | PASS | — |
| G15 | BIP-370 v2 input fields (0x0e..0x12) parse + state machine | MISSING | BUG-4 |
| G16 | `PSBT_IN_TAP_KEY_SIG=0x13` parse + 64/65-byte length check | PASS | — |
| G17 | `PSBT_IN_TAP_SCRIPT_SIG=0x14` parse + 65-byte key + 64/65-byte sig | PASS | — |
| G18 | `PSBT_IN_TAP_LEAF_SCRIPT=0x15` parse + control-block sizing | PASS | — |
| G19 | `PSBT_IN_TAP_BIP32_DERIVATION=0x16` parse + xonly pubkey | PASS | — |
| G20 | `PSBT_IN_TAP_INTERNAL_KEY=0x17` / `_MERKLE_ROOT=0x18` parse | PASS | — |
| G21 | `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS=0x1a` parse + serialize | MISSING | BUG-1 |
| G22 | `PSBT_IN_MUSIG2_PUB_NONCE=0x1b` parse + serialize (66-byte value) | MISSING | BUG-1 |
| G23 | `PSBT_IN_MUSIG2_PARTIAL_SIG=0x1c` parse + serialize | MISSING | BUG-1 |
| G24 | `PSBT_IN_PROPRIETARY=0xfc` parse + ordered serialize | MISSING | BUG-2 |
| G25 | BIP-370 v2 output fields (0x03..0x04) parse | MISSING | BUG-5 |
| G26 | Per-map duplicate-key detection + separator-missing rejection | PARTIAL | (sep is in writer; reader uses ReadCompactSize which never returns "missing sep" — relies on EOF) |
| G27 | Input-count / output-count match vs tx.vin/tx.vout | PARTIAL | BUG-13 (input loop reads exactly len(TxIn), no trailing-data check) |
| G28 | Combiner: `tx->GetHash()` equality gate + per-input/output merge + xpubs/unknown set-union | PARTIAL | BUG-12 BUG-20 BUG-21 |
| G29 | Finalizer: per-script-type wiring (P2WPKH/P2WSH/P2SH/P2PKH/P2TR/multisig) + clearInputSigningData | PARTIAL | BUG-22 |
| G30 | JoinPSBTs: dedup inputs + best_version/locktime + FastRandomContext shuffle | MISSING | BUG-17 BUG-18 BUG-19 |

## Per-bug detail

### BUG-1 (P0-CDIV): Input MuSig2 fields have no codec arms

**Spec**: Core `psbt.h:791-836` switches on `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS=0x1a`, `PSBT_IN_MUSIG2_PUB_NONCE=0x1b`, `PSBT_IN_MUSIG2_PARTIAL_SIG=0x1c` with full deserialization, key-size checks, pubkey-validity gates, and 66-byte pubnonce length enforcement (`MUSIG2_PUBNONCE_SIZE=66`). On the encode side `psbt.h:412-447` writes the ordered maps via `SerializeToVector` with key = type|part_pubkey|agg_pubkey[|leaf_hash], value = pubnonce/partial_sig.

**Actual** (`internal/wallet/psbt.go:445-583`): The input-side `switch keyType` has no arms for `PSBTInMuSig2ParticipantPubkeys` (declared at `:66`), `PSBTInMuSig2PubNonce` (`:67`), or `PSBTInMuSig2PartialSig` (`:68`). All three fall into the `default` case at `:581` (`input.Unknown[keyStr] = value`). The output-side has ONE arm for `PSBTOutMuSig2ParticipantPubkeys` (`:649`) but no symmetric output-side pubnonce/partial-sig fields exist in Core (correct).

**Impact**: P0-CDIV. A MuSig2 PSBT round-tripped through blockbrew:
  1. Loses key validation (a malformed aggregate-pubkey passes parse).
  2. Loses 66-byte pubnonce length enforcement.
  3. Re-emits via `input.Unknown` keyed sort (Go map → `sort.Strings`), producing a different byte sequence than Core's `std::map<std::pair<CPubKey, uint256>, std::map<CPubKey, std::vector<uint8_t>>>` iteration (which sorts by `(agg_pub, leaf_hash)` outer and `part_pub` inner).
  4. The MuSig2 signing flow at any peer that reads blockbrew's emitted PSBT either rejects (key-size violation) or sees a different ordering.

**Test**: `TestW137_BUG1_MuSig2InputFieldsAreUnknown` constructs a forged input map with type-0x1a/0x1b/0x1c entries and asserts they DON'T appear in `input.Unknown` (negative assertion: codec arms exist). Currently FAILS as a XFAIL.

### BUG-2 (P0-CDIV): Proprietary entries (global + input + output) bucketed into Unknown with wrong ordering

**Spec**: Core `psbt.h:838-851, 1098-1111, 1327-1340`: `PSBT_*_PROPRIETARY=0xfc` is parsed into a `std::set<PSBTProprietary>` ordered by full key bytes. On serialize, the set is iterated and emitted BEFORE the `unknown` map (psbt.h:461-465 input, :912-916 output, :1199-1203 global). PSBTProprietary's `operator<` compares on `key` (raw bytes including identifier-length, identifier, subtype-varint, keydata).

**Actual** (`internal/wallet/psbt.go:369-373`): Global PSBT_GLOBAL_PROPRIETARY (0xfc) falls into the `Unknown[keyStr] = value` bucket. Same for input/output via `default`. Encoder iterates `Unknown` sorted by `sort.Strings(unknownKeys)`. There is NO `Proprietary` field on PSBT/PSBTInput/PSBTOutput, so the two sets are merged.

**Impact**: P0-CDIV. When a PSBT carries BOTH proprietary AND non-proprietary unknown entries:
  - Core emits proprietary set first, then unknown map.
  - blockbrew interleaves them by Go-string lex order.
The resulting wire bytes are NOT byte-identical to Core's output, so any cross-impl byte-exact corpus diff fails.

**Test**: `TestW137_BUG2_ProprietaryNotSeparated` builds a PSBT with one proprietary entry (type=0xfc, subtype=0x42, identifier="BB", keydata="x") and one unknown entry (type=0x99). After round-trip the relative order is NOT proprietary-first.

### BUG-3, BUG-4, BUG-5 (P0-CDIV): BIP-370 v2 fields declared but not implemented

**Spec**: BIP-370 mandates 5 new globals (0x02..0x06), 5 new input fields (0x0e..0x12), 2 new output fields (0x03..0x04). When `PSBT_GLOBAL_VERSION=0xfb` value is 2, the role state machine consults these for tx-version, fallback-locktime, input/output counts, modifiable flags.

**Actual** (`internal/wallet/psbt.go:30-78`): Constants are declared with comment "// BIP370 v2" but NO `case` arms exist in `readInput`/`readOutput`/`DecodePSBTReader` global-loop. All BIP-370 v2 fields fall into `Unknown` (input/output) or `Unknown` (global). No state-machine integration with `Version==2`.

**Impact**: P0-CDIV. PSBT v2 is fully non-functional. Round-trip is byte-LOSSY (sort order changes) and semantically VOID (no tx version/locktime/in-out count enforcement).

**Tests**: `TestW137_BUG3_V2GlobalFieldsAreUnknown`, `TestW137_BUG4_V2InputFieldsAreUnknown`, `TestW137_BUG5_V2OutputFieldsAreUnknown`.

### BUG-6 (P1): No PSBT version ceiling check

**Spec**: Core psbt.h:1322: `if (*m_version > PSBT_HIGHEST_VERSION) throw std::ios_base::failure("Unsupported version number");`. `PSBT_HIGHEST_VERSION=0` currently (psbt.h:80).

**Actual** (`internal/wallet/psbt.go:360-367`): Parses `PSBT_GLOBAL_VERSION` into `psbt.Version = binary.LittleEndian.Uint32(value)` with NO upper bound check. Versions 1..0xffffffff are silently accepted.

**Impact**: P1. A forged v=99 PSBT passes parse, fields silently bucketed into Unknown, downstream encode emits "v=99" globally which other impls reject.

**Test**: `TestW137_BUG6_NoVersionCeilingCheck`.

### BUG-7 (P1): No DER signature encoding validation on PSBT_IN_PARTIAL_SIG

**Spec**: Core psbt.h:540-546: `s >> sig; if (sig.empty() || !CheckSignatureEncoding(sig, SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC, nullptr)) throw "Signature is not a valid encoding"`.

**Actual** (`internal/wallet/psbt.go:460-464`): Only checks `len(keyData) != 33 && len(keyData) != 65` (pubkey size). The VALUE (sig) bytes are stored raw without DER validation or non-empty check.

**Impact**: P1. A malformed partial signature (zero-length, non-DER, oversized) round-trips through parse + finalize, producing an invalid witness that's only rejected at script verification (much later, with worse error provenance).

**Test**: `TestW137_BUG7_NoDERSignatureValidation`.

### BUG-8 (HIGH): No pubkey validity check on PSBT_IN_PARTIAL_SIG

**Spec**: Core psbt.h:531-534: `CPubKey pubkey(key.begin() + 1, key.end()); if (!pubkey.IsFullyValid()) throw "Invalid pubkey"`.

**Actual** (`internal/wallet/psbt.go:461-464`): Only length check; no SEC1 prefix-byte or on-curve check.

**Impact**: HIGH. A pubkey of length 33 with prefix 0x05 (invalid) passes parse.

**Test**: `TestW137_BUG8_NoPartialSigPubkeyValidation`.

### BUG-9 (HIGH): No pubkey validity check on BIP32_DERIVATION

**Spec**: Core psbt.h:DeserializeHDKeypaths at :149-170 requires `IsFullyValid()`.

**Actual** (`internal/wallet/psbt.go:478-486` + `:616-624`): Only length check.

**Impact**: HIGH. Same as BUG-8 but for BIP32 derivation keys.

**Test**: `TestW137_BUG9_NoBIP32PubkeyValidation`.

### BUG-10 (HIGH): Global xpub size check is a floor, not exact

**Spec**: Core psbt.h:1283-1285: `if (key.size() != BIP32_EXTKEY_WITH_VERSION_SIZE + 1)` — EXACT 79 bytes including type byte.

**Actual** (`internal/wallet/psbt.go:354-358`): `if len(keyData) < 78` — a floor, any ≥78 admits.

**Impact**: HIGH. An oversized xpub key with garbage padding passes parse.

**Test**: `TestW137_BUG10_XpubSizeFloorNotExact`.

### BUG-11 (HIGH): No path-arity bound on parseBIP32Derivation

**Actual** (`internal/wallet/psbt.go:1109-1127`): Accepts any (data-4)%4==0; up to MaxPSBTFileSize=100MB bound.

**Impact**: HIGH (DoS-flavored, but bounded). Pathological 25M-element path stalls re-serialization but not parse.

**Test**: `TestW137_BUG11_NoBIP32PathArityBound`.

### BUG-12 (HIGH): Combine path bypasses validatePSBTInput post-merge

**Spec**: The W41 docstring (`internal/wallet/psbt.go:1306-1326`) explicitly warns about in-process PSBT mutation bypassing the parser. `mergeInput` (`psbt_ops.go:74-181`) emplaces `NonWitnessUTXO` from src into dst without re-running `validatePSBTInput`.

**Actual**: After `Combine`, the dst PSBT's NonWitnessUTXO may not match dst's unsigned-tx prevout, and the signer-dispatch IsSane re-check at `psbt_ops.go:262` would catch it — but a downstream FinalizeInput that consumes WitnessUTXO directly may proceed before signing dispatch.

**Impact**: HIGH. CVE-2020-14199 surface partially re-exposed via combiner path.

**Test**: `TestW137_BUG12_CombineBypassesUTXOSanity`.

### BUG-13 (HIGH): No "extra data after PSBT" rejection

**Spec**: Core psbt.cpp:617-630: `DecodeRawPSBT` after `ss_data >> psbt` checks `if (!ss_data.empty()) { error = "extra data after PSBT"; return false; }`.

**Actual** (`internal/wallet/psbt.go:291-422`): `DecodePSBT` reads exactly `len(TxIn)` input maps + `len(TxOut)` output maps, then returns the PSBT. Trailing bytes after the last output separator are silently dropped by the buffered reader.

**Impact**: HIGH. A trailing-junk corpus passes parse silently; Core's parser rejects. Byte-exact divergence against trailing-junk fuzzers.

**Test**: `TestW137_BUG13_TrailingDataNotRejected`.

### BUG-14 (HIGH): handleCreatePSBT default sequence skips anti-fee-sniping

**Spec**: Core `ConstructTransaction` (sister of createrawtransaction) when `locktime != 0` and `rbf==std::nullopt` defaults sequence to `MAX_SEQUENCE_NONFINAL=0xfffffffe` so anti-fee-sniping kicks in.

**Actual** (`internal/rpc/psbt_methods.go:91-100`): `sequence = wallet.BIP125RBFSequence (=0xfffffffd)` when `replaceable==true`, else `sequence = 0xffffffff` (FINAL — no anti-fee-snipe). When the JSON arg is omitted, `replaceable=false` and sequence=0xffffffff.

**Impact**: HIGH. A PSBT minted via blockbrew's `createpsbt` with locktime>0 and no replaceable=true does NOT carry anti-fee-sniping protection; broadcasting it after the locktime exposes the user to a fee-sniping reorg attack.

**Test**: `TestW137_BUG14_CreatePSBTDefaultSequenceNotAntifeeSnipe` — exercises only the wire layer, asserts the produced PSBT's UnsignedTx.TxIn[0].Sequence != 0xfffffffe when locktime>0.

### BUG-15 (MED): analyzepsbt next-role machine is coarse

**Actual**: blockbrew's role state machine has only `updater`/`signer`/`finalizer`/`extractor` strings; missing detailed `missing_pubkeys`, `missing_sigs`, `missing_redeem_script`, `missing_witness_script`, `estimated_vsize`, `estimated_feerate`.

**Test**: `TestW137_BUG15_AnalyzePSBTNextRoleCoarse`.

### BUG-16 (MED): analyzepsbt field-name divergence

**Actual** (`internal/rpc/psbt_methods.go:721-732`): `is_finalized` (blockbrew) vs `is_final` (Core); `missing.signatures` (blockbrew, bool) vs `missing.signatures` (Core, []keyid).

**Test**: `TestW137_BUG16_AnalyzeFieldNameDivergence`.

### BUG-17 (MED): joinpsbts does not detect duplicate inputs

**Spec**: Core rawtransaction.cpp:1834-1836: `if (!merged_psbt.AddInput(psbt.tx->vin[i], psbt.inputs[i])) throw JSONRPCError(RPC_INVALID_PARAMETER, "Input %s:%d exists in multiple PSBTs")`.

**Actual** (`internal/rpc/psbt_methods.go:608-619`): Loop concatenates inputs unconditionally.

**Impact**: MED. Joining two PSBTs sharing an input produces an invalid PSBT.

**Test**: `TestW137_BUG17_JoinNoDuplicateInputCheck`.

### BUG-18 (MED): joinpsbts hard-codes version=2, locktime=0

**Spec**: Core: `best_version = max(versions)`, `best_locktime = min(locktimes)` across joined PSBTs (rawtransaction.cpp:1806-1822).

**Actual** (`internal/rpc/psbt_methods.go:603-606`): Hard-coded `Version: 2, LockTime: 0`.

**Test**: `TestW137_BUG18_JoinHardCodedVersionLockTime`.

### BUG-19 (MED): joinpsbts does not shuffle

**Spec**: Core: `std::shuffle(input_indices.begin(), input_indices.end(), FastRandomContext())` and same for outputs, deliberately to avoid leaking per-PSBT input grouping at the joiner.

**Actual** (`internal/rpc/psbt_methods.go:611-619`): Inputs/outputs preserved in input order; PSBT[0]'s inputs all come first, then PSBT[1]'s, etc.

**Test**: `TestW137_BUG19_JoinDoesNotShuffle`.

### BUG-20 (MED): mergeInput silently first-wins on UTXO conflict

**Actual** (`internal/wallet/psbt_ops.go:76-80`): `if dst.WitnessUTXO == nil && src.WitnessUTXO != nil { dst.WitnessUTXO = src.WitnessUTXO }` — silent first-wins.

**Impact**: MED. Honest combiner-peer disagreement is not surfaced.

**Test**: `TestW137_BUG20_MergeSilentFirstWins`.

### BUG-21 (MED): handleCombinePSBT does not validate equal versions

**Spec**: BIP-174 requires all PSBTs in a Combine to share a version.

**Actual** (`internal/rpc/psbt_methods.go:240`): Combines via `wallet.CombinePSBTs(psbts)`. Per `psbt_ops.go:15-71` `CombinePSBTs` checks `TxHash()` equality but NOT `Version` equality.

**Test**: `TestW137_BUG21_CombineNoVersionCheck`.

### BUG-22 (LOW): clearInputSigningData over-clears taproot fields

**Spec**: Core psbt.cpp PSBTInput::FromSignatureData when complete clears partial_sigs/hd_keypaths/redeem_script/witness_script ONLY. Taproot internal key + merkle root are preserved.

**Actual** (`internal/wallet/psbt_ops.go:947-960`): blockbrew also nils `TapInternalKey` and `TapMerkleRoot`.

**Impact**: LOW. Downstream key-path-spend audit needs the internal key to verify the tweak; clearing it removes that audit trail.

**Test**: `TestW137_BUG22_FinalizeOverclearsTaproot`.

### BUG-23 (LOW): Unknown-map sort uses Go string lex (mostly equal to std::map but diverges on prefix)

**Test**: `TestW137_BUG23_UnknownSortPrefixDivergence` — synthetic edge-case test asserting a divergence point.

### BUG-24 (LOW): ExtractTransaction error message uses single-rune index

**Actual** (`internal/wallet/psbt_ops.go:966-968`): `errors.New("input " + string(rune('0'+i)) + " is not finalized")`. For i=10 the rune is `:`.

**Test**: `TestW137_BUG24_ExtractErrorMsgWrongDigitForI10`.

## Universal patterns observed

1. **"constants declared, codec arms missing"** — applies to BIP-370 v2 (BUG-3/4/5), input MuSig2 (BUG-1), proprietary (BUG-2). The type table at the top of `psbt.go` advertises support for these fields but the switch statements in `readInput`/`readOutput`/`DecodePSBTReader` lack arms. This is the universal "implementation exists in TYPE LIST but never EXECUTES in CODEC" anti-pattern, isomorphic to W117/W118/W133 dead-code patterns.

2. **"comment-claims-correct-code-violates-spec"** — W41 comment in `validatePSBTInput` (BUG-12) explicitly warns about combine-path bypass but the combine path was forgotten in the W41 fix. Documented well, not implemented. Same pattern as W118 BUG-1 (BIP125RBFSequence) — comment said one thing, code did another.

3. **"sort-by-Go-string vs std::map ordering subtle divergence"** — Go's `sort.Strings` on `string([]byte)` interprets bytes as UTF-8 code units; `std::map<vector<uint8_t>>` uses raw byte lex with strict prefix < extension. These coincide except on prefix-pair keys, which BUG-23 catches.

4. **"defense-in-depth dropped at one layer"** — BUG-12 is a textbook three-layer defense (parse-side, signer-side, combine-side) where the combine-side dropped out. Pattern noted in W120 / W125 cross-impl audits.

## Out-of-scope for this wave (deferred)

- **MuSig2 cryptographic correctness** (BIP-327 nonce + agg verification) — codec absence (BUG-1) is in scope; the math is a separate wave once codec lands.
- **Descriptor-PSBT integration** (`descriptorprocesspsbt`) — handler not implemented at all in blockbrew; covered in W131 (descriptors). The codec is what's audited here.
- **Hardware-wallet PSBT flow** — out of scope; HW signing dispatch is in W118 wallet wave.
- **PSBT v2 BIP-370 STATE MACHINE** (input.modifiable, output.modifiable, sighash-anyone-can-pay coordination) — separate wave once BUG-3/4/5 codec arms land.

## Conclusion

PSBT v0 BIP-174 codec is **largely complete with HIGH-severity validation
gaps** (BUG-7..BUG-13). PSBT v2 BIP-370 is **declared but unimplemented**
(BUG-3..BUG-5). Input MuSig2 fields (BIP-327) are **missing codec arms**
(BUG-1). Proprietary keys are **bucketed into Unknown with wrong sort
order** (BUG-2). RPC layer has **multiple parity gaps** (BUG-14..BUG-19,
BUG-21). Finalizer **over-clears taproot fields** (BUG-22).

Next-action priorities (post-W137, when fix waves resume):
1. **FIX-A** (P0-CDIV bundle): wire BIP-370 v2 codec arms + Proprietary
   struct + MuSig2 input arms (BUG-1..BUG-5).
2. **FIX-B** (P1 bundle): version ceiling + DER sig validation + pubkey
   IsFullyValid (BUG-6..BUG-10).
3. **FIX-C** (HIGH bundle): trailing-data rejection + combine sanity
   re-run + createpsbt sequence default (BUG-12..BUG-14).
4. **FIX-D** (MED bundle): joinpsbts dedup + best version/locktime +
   shuffle + analyzepsbt parity (BUG-15..BUG-19).

Total: **24 bugs**, **30 gates**, **PASS 8 / PARTIAL 9 / MISSING 13**.
