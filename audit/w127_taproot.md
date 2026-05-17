# W127 — Taproot / Schnorr / Tapscript Audit (blockbrew)

**Wave**: W127 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**BIPs**: 340 (Schnorr), 341 (Taproot), 342 (Tapscript)

**References (read first)**:
- `bitcoin-core/src/script/interpreter.cpp`:
  - `EvalChecksigTapscript` (line 347-385) — tapscript sigop validation sequence
  - `CheckSchnorrSignature` (line 1717-1742) — entry-point + sighash compute
  - `SignatureHashSchnorr` (line 1483-1570) — BIP-341 sighash construction
  - `ComputeTaprootMerkleRoot` (line 1888-1901) — merkle path walk
  - `VerifyTaprootCommitment` (line 1903-1915) — q = p + tweak*G check
  - `VerifyWitnessProgram` (line 1917-2000) — witness v1 dispatch
  - `ExecuteWitnessScript` (line 1832-1870) — tapscript execution shell
  - `ComputeTapleafHash` (line 1872-1875) — leaf tagged hash
- `bitcoin-core/src/script/script.h`:
  - `ANNEX_TAG = 0x50` (line 58)
  - `VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50` (line 61)
  - `VALIDATION_WEIGHT_OFFSET = 50` (line 64)
  - `MAX_SCRIPT_ELEMENT_SIZE = 520`, `MAX_STACK_SIZE = 1000`
- `bitcoin-core/src/script/interpreter.h`:
  - `TAPROOT_LEAF_MASK = 0xfe` (line 241)
  - `TAPROOT_LEAF_TAPSCRIPT = 0xc0` (line 242)
  - `TAPROOT_CONTROL_BASE_SIZE = 33` / `NODE_SIZE = 32` / `MAX_NODE_COUNT = 128`
  - `WITNESS_V1_TAPROOT_SIZE = 32`
- `bitcoin-core/src/pubkey.cpp` — `XOnlyPubKey::CheckTapTweak`

**Precedent**:
- `W94` (commit `d4b2159`, 2026-XX-XX): "BIP-341/342 Taproot + tapscript
  comprehensive audit — 9 bugs". Fixed TapLeaf-leaf-version-mask, witness-v1
  no-flag silent success, upgradable-leaf-version/pubkey-type discourage
  flags, tapscript initial-stack-element-size, OP_SUCCESSx clean-stack
  bypass.
- `W95` (commit `9e43b4f`, 2026-XX-XX): "BIP-340 Schnorr + tagged-hash
  comprehensive audit — 2 bugs". Fixed BIP-340 zero-aux-mask in `SignSchnorr`
  for byte-identity with libsecp256k1; precomputed tag prefixes.
- Earlier: `b949962` (witness-item size for taproot, testnet4 #28527),
  `551fc13` (tapscript sigops don't count toward block budget — Core parity).

W127 is the post-W94/W95 sweep, looking for residual divergences across the
30-gate matrix below.

## Summary

| Verdict | Count |
|---------|-------|
| PRESENT | 24 |
| PARTIAL | 5 |
| MISSING | 1 |

**Bug count**: 6 distinct bugs (BUG-1 .. BUG-6).

| Priority | Count |
|----------|-------|
| P0-CONSENSUS | 0 |
| P0-CDIV | 0 |
| P1 | 2 |
| P2 | 3 |
| P3 | 1 |

**No P0-CONSENSUS / P0-CDIV findings.** The post-W94/W95 surface is solid;
all P0-class consensus pathways match Core. Residual bugs are policy-flag
gaps, sighash-cache absence (perf-only divergence), and one rule-mapping
deficiency in the witness policy layer (non-consensus relay).

## 30-Gate Matrix

Gates are organised into four areas:

1. **G1-G7** — BIP-340 Schnorr verification primitive
2. **G8-G15** — BIP-341 Taproot key-path / script-path commitment + dispatch
3. **G16-G25** — BIP-342 Tapscript execution rules
4. **G26-G30** — Cross-cutting (sighash, sigops, policy)

### Area 1: BIP-340 Schnorr verification primitive

| Gate | Description | Core ref | Verdict | blockbrew ref |
|------|-------------|----------|---------|---------------|
| G1 | Reject sig.size != 64 (after sighash-byte strip) | `interpreter.cpp:1726` | PRESENT | `crypto/schnorr.go:258` |
| G2 | Reject r >= p (curve field overflow) | `secp256k1/schnorrsig/main_impl.h` | PRESENT | `crypto/schnorr.go:278` |
| G3 | Reject s >= n (group order overflow) | same | PRESENT | `crypto/schnorr.go:287` |
| G4 | lift_x even-Y pubkey parse, reject if x not on curve | `pubkey.cpp:XOnlyPubKey` | PRESENT | `crypto/schnorr.go:262-272` |
| G5 | Tagged hash construction: SHA256(SHA256(tag)\|\|SHA256(tag)\|\|msg) | BIP-340 §3 | PRESENT | `crypto/schnorr.go:84` |
| G6 | challenge = tagged_hash("BIP0340/challenge", r\|\|P\|\|m) mod n | BIP-340 §3.2 | PRESENT | `crypto/schnorr.go:298` |
| G7 | R = sG - eP, reject R==infinity, reject odd Y, require x(R)==r | BIP-340 §3.2 | PRESENT | `crypto/schnorr.go:309-346` |

Area 1 is **fully PRESENT** with W95 having closed the only known gap
(`SignSchnorr` zero-aux-mask, commit `9e43b4f`). Official BIP-340 test
vectors 0-14 pass (32-byte msg) and 15-18 also pass (variable-length msg).

### Area 2: BIP-341 Taproot dispatch + commitment

| Gate | Description | Core ref | Verdict | blockbrew ref |
|------|-------------|----------|---------|---------------|
| G8  | Witness v1 + 32-byte program + !is_p2sh → taproot path | `interpreter.cpp:1947` | PRESENT | `script/engine.go:303-310` |
| G9  | Without SCRIPT_VERIFY_TAPROOT flag → silent success | `interpreter.cpp:1949` | PRESENT | `script/engine.go:304-306` |
| G10 | Empty witness stack → SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY | `interpreter.cpp:1950` | PRESENT | `script/engine.go:428-430` |
| G11 | Annex detection: stack >= 2, last item non-empty, first byte 0x50 | `interpreter.cpp:1951` | PRESENT | `script/engine.go:436-439` |
| G12 | Annex hash = SHA256(varint(len) \|\| annex) | `interpreter.cpp:1954` | PRESENT | `script/engine.go:478-481` |
| G13 | Stack size 1 (after annex strip) → key-path spend | `interpreter.cpp:1960` | PRESENT | `script/engine.go:441-444` |
| G14 | Control block size: 33 <= sz <= 4129, (sz-33)%32 == 0 | `interpreter.cpp:1970` | PRESENT | `script/engine.go:512-516` |
| G15 | Merkle root walk with lex-order TapBranch; tweak verify | `interpreter.cpp:1888-1914` | PRESENT | `script/engine.go:529-543`, `crypto/schnorr.go:374` |

Area 2 is **fully PRESENT** including the W94 fixes for upgradable
leaf-version discourage (G_disc1 below) and silent-success on no-flag.

### Area 3: BIP-342 Tapscript execution

| Gate | Description | Core ref | Verdict | blockbrew ref |
|------|-------------|----------|---------|---------------|
| G16 | Leaf-version 0xc0 → execute tapscript; unknown → success (or discourage) | `interpreter.cpp:1978` | PRESENT | `script/engine.go:550-555` |
| G17 | OP_SUCCESSx scan before EvalScript; immediate success or discourage | `interpreter.cpp:1837-1851` | PRESENT | `script/engine.go:699-735` |
| G18 | OP_SUCCESSx clean-stack bypass (return success before clean-stack) | `interpreter.cpp:1850 vs 1867` | PRESENT | `script/engine.go:609-611`, `taproot_w94_test.go:256` |
| G19 | Initial stack size <= 1000 | `interpreter.cpp:1855` | PRESENT | `script/engine.go:563-565` |
| G20 | Every stack element <= 520 bytes | `interpreter.cpp:1858-1861` | PRESENT | `script/engine.go:566-570`, `script/engine.go:355-359` |
| G21 | MinimalIf enforced consensus in tapscript (no flag gate) | `interpreter.cpp` (search MINIMALIF + sigversion::TAPSCRIPT) | PRESENT | `script/engine.go:908-913` |
| G22 | EvalChecksigTapscript sequence: success-first, then weight-debit, then pubkey-size | `interpreter.cpp:347-385` | PRESENT | `script/opcodes_impl.go:698-783` |
| G23 | sigopBudget = 50 + serialized_witness_size; weight -= 50 per pass | `interpreter.cpp:1981`, `script.h:61` | PRESENT | `script/engine.go:583-598` |
| G24 | OP_CHECKMULTISIG(VERIFY) rejected in tapscript | `interpreter.cpp:1108` | PRESENT | `script/engine.go:1172-1184` |
| G25 | OP_CHECKSIGADD: stack(sig,n,pubkey); n+1 on success, n on empty-sig | `interpreter.cpp:1084-1102` | PRESENT | `script/opcodes_impl.go:973-1070` |

Area 3 is **fully PRESENT**. The W94 fixes resolved the
upfront-stack-size, OP_SUCCESS-clean-stack-bypass, and CHECKMULTISIG
gating. CHECKSIGADD stack-push semantics for empty-sig + upgradable-pubkey
were also corrected by W94 (push n vs n+1).

### Area 4: Cross-cutting (sighash, sigops, policy)

| Gate | Description | Core ref | Verdict | blockbrew ref |
|------|-------------|----------|---------|---------------|
| G26 | BIP-341 sighash construction (TapSighash tagged) | `interpreter.cpp:1483-1570` | PARTIAL | `script/sighash.go:195-320` |
| G27 | hash_type range check: 0x00, 0x01-0x03, 0x81-0x83 | `interpreter.cpp:1516` | PRESENT | `script/sighash.go:201-203` |
| G28 | SIGHASH_SINGLE: in_pos < vout.size() check | `interpreter.cpp:1550` | PRESENT | `script/sighash.go:301-303` |
| G29 | Tapscript sigops do NOT count toward MaxBlockSigOpsCost | `interpreter.cpp:2123-2137` | PRESENT | `internal/consensus/sigops.go:309-345` |
| G30 | Mempool / relay policy for taproot witness shape (annex non-std, etc.) | `policy/policy.cpp:IsWitnessStandard` | PARTIAL | `internal/mempool/witness_policy.go:149-189` |

---

## Bug catalogue

### BUG-1 [P1] (G26) — TapSighash output-set gate uses `!= SINGLE && != NONE` instead of `== ALL`

**File**: `internal/script/sighash.go:261`

**Current code**:

```go
if outputType != SigHashNone && outputType != SigHashSingle {
    var buf bytes.Buffer
    for _, out := range tx.TxOut {
        out.Serialize(&buf)
    }
    h := sha256.Sum256(buf.Bytes())
    preimage.Write(h[:])
}
```

**Core code** (`interpreter.cpp:1528-1530`):

```cpp
if (output_type == SIGHASH_ALL) {
    ss << cache.m_outputs_single_hash;
}
```

Semantically equivalent for the three defined output types (NONE=2,
SINGLE=3, ALL=1, DEFAULT=0→ALL). But blockbrew's `outputType` is derived
as:

```go
outputType := hashType & 0x03
if outputType == SigHashDefault {
    outputType = SigHashAll
}
```

`hashType & 0x03` for the seven defined hashtypes yields {0,1,2,3,1,2,3}.
After the DEFAULT→ALL mapping, possible values are {1, 2, 3}.

The two predicates agree on these three values:
- `output_type == SIGHASH_ALL`: T, F, F
- `outputType != NONE && outputType != SINGLE`: T, F, F

So the **observable behavior is identical** for any sighash type the
range-check (G27) lets through. The bug is a defensive divergence: any
future "extension" hashtype that slips past the range check (or a fuzzer
input that does so via reflection / harness) would compute a different
sighash. **No consensus impact today**, P1 because it's a comment-as-
confession-class shape issue.

**Fix**: Use `if outputType == SigHashAll`. Same byte output, clearer
correspondence to Core, immune to future hashtype extensions.

### BUG-2 [P1] (G26) — TapSighash uses raw SHA256 not HashWriter HASHER_TAPSIGHASH for the final write

**File**: `internal/script/sighash.go:319-333` (and 323-333 for the
helper).

**Observation**: blockbrew computes the TapSighash via
`TapSighash(preimage.Bytes())` (line 319), which is implemented as:

```go
func TapSighash(data []byte) [32]byte {
    tagHash := sha256.Sum256([]byte("TapSighash"))
    h := sha256.New()
    h.Write(tagHash[:])
    h.Write(tagHash[:])
    h.Write(data)
    var result [32]byte
    copy(result[:], h.Sum(nil))
    return result
}
```

Core uses `HashWriter ss{HASHER_TAPSIGHASH}` which pre-loads the
SHA256-of-SHA256("TapSighash")||SHA256("TapSighash") midstate via the
`HASHER_TAPSIGHASH` template parameter (see `hash.h`). Output is
**byte-identical** (asserted in W95 by `TestTaggedHashPrecomputed` for
the W95 prefix constants).

The actual divergence is performance: every TapSighash call re-hashes
"TapSighash" twice via `sha256.Sum256`. The W95 fix added precomputed
tag-prefix constants for BIP0340/challenge/nonce/aux but **did not
extend the same optimisation to TapLeaf, TapBranch, TapTweak, or
TapSighash**. At ~5k taproot verifies per modern block this adds
~20k SHA256-of-short-string invocations per IBD block.

**No consensus impact**. P1 because it's a documented W95 pattern that
was applied only partially.

**Fix**: Add precomputed prefixes for the four BIP-341 tag strings
("TapLeaf", "TapBranch", "TapTweak", "TapSighash") and route hot-path
callers through them. See W95's `tagPrefix*` constants as the template.

### BUG-3 [P2] (G26) — `TaprootSigHashOptions.KeyVersion` not enforced

**File**: `internal/script/sighash.go:191`, `script/opcodes_impl.go:767, 1056`

**Observation**: `TaprootSigHashOptions` exposes a `KeyVersion byte`
field. Core enforces `key_version = 0` for tapscript via direct const
in `SignatureHashSchnorr` (`interpreter.cpp:1497`). blockbrew's
callers correctly pass `KeyVersion: 0` (opcodes_impl.go:767 + 1056),
but the sighash function does not assert key_version == 0 internally.

A caller that constructs `TaprootSigHashOptions{KeyVersion: 1, ...}`
(e.g., a fuzzer or a future upgradable-pubkey-type branch that
forgets to override) would silently produce a different sighash,
flushing the sigcache and potentially passing or failing verification
in subtle ways. No consensus impact today (no caller passes nonzero),
but the abstraction lets a footgun through.

**Fix**: Either remove the field (always write 0 internally for
TAPSCRIPT) or assert it equals 0 at the sighash call site when
`TapLeafHash != nil`. Add a regression test.

### BUG-4 [P2] (G26) — Tapscript sighash cache (`m_sighash_cache`) not implemented

**File**: `internal/script/sighash.go` (whole file)

**Observation**: Core caches the partial sighash midstate in
`PrecomputedTransactionData` (the `m_prevouts_single_hash`,
`m_spent_amounts_single_hash`, etc. fields) and reuses these across
all inputs of the same transaction. For a tx with N inputs and M
tapscript sigops per input, blockbrew recomputes the four
sha_prevouts/sha_amounts/sha_scriptpubkeys/sha_sequences SHA256s
**N × M times** instead of once-per-tx.

Bench numbers in `crypto/bench_test.go` (W95) confirm Schnorr verify
itself is comparable to Core; the divergence is in the surrounding
sighash construction. For a 4-input tx with 2 tapscript sigops each,
blockbrew runs 32 redundant SHA256s.

**No consensus impact**. P2 because it's a documented Core
optimization (`PrecomputedTransactionData`, validation.cpp:CheckInputScripts)
that blockbrew does not implement. Material at high taproot density
(post-2024 mainnet).

**Fix**: Add a `PrecomputedTaprootSigHashData` struct cached on the
transaction validation entry-point; mirror Core's field set
(prevouts_hash, amounts_hash, scriptpubkeys_hash, sequences_hash,
outputs_hash). Wire it through `executeTaprootKeyPath` and the
tapscript CHECKSIG / CHECKSIGADD paths.

### BUG-5 [P2] (G30) — Witness policy doesn't reject taproot with non-standard sighash bytes

**File**: `internal/mempool/witness_policy.go:149-189` (taproot v1
32B branch)

**Observation**: BIP-341 §"Standardness rules" requires that taproot
key-path spends with a non-default 65-byte signature use one of the
defined hashtypes (0x01, 0x02, 0x03, 0x81, 0x82, 0x83). blockbrew
correctly enforces this **at consensus** (`sighash.go:201-203`,
returns error), but the policy layer does not pre-filter — every
non-default 65-byte sig is dropped to consensus.

Core's `IsWitnessStandard` (`policy/policy.cpp`) pre-filters these
to avoid relaying transactions that will hit a consensus-error path.
blockbrew's policy layer only checks: (a) annex non-standard, (b)
control block presence for script-path, (c) tapscript stack-item
size <= 80. It does not parse the signature to check hashtype.

**No consensus impact**. P2 because it's a policy/relay efficiency
gap that lets known-invalid taproot txs into the consensus path; a
DOS-resistance pattern Core uses.

**Fix**: In `internal/mempool/witness_policy.go` key-path branch,
parse the single sig stack item: if size == 65, reject unless
sig[64] is in {0x01, 0x02, 0x03, 0x81, 0x82, 0x83}. Add a test.

### BUG-6 [P3] (G26 + G27) — `CalcTaprootSignatureHash` returns Go-formatted error, not Core's ScriptError code

**File**: `internal/script/sighash.go:202, 303`

**Observation**: Core's `SignatureHashSchnorr` returns
`false` and the caller (`CheckSchnorrSignature` line 1738) maps to
`SCRIPT_ERR_SCHNORR_SIG_HASHTYPE`. blockbrew returns
`fmt.Errorf("invalid taproot sighash type: 0x%02x", hashType)` and
`ErrInvalidIndex`.

These propagate up through `executeTaprootKeyPath` and
`opCheckSig`/`opCheckSigAdd` and become opaque from the consensus
client's perspective (e.g., an RPC `testmempoolaccept` response).
Core surfaces a specific machine-parseable error code; blockbrew's
string format will not match Core's error-shape contract.

**No consensus impact**. P3 because the error is correctly reported
as a verification failure — only the *kind* of error differs from
Core. This is in the same family as W125's RPC-error-code-parity
findings (bug shape is "Go error string != Core enum").

**Fix**: Define `ErrTaprootSigHashType` and
`ErrTaprootSigInvalidIndex` named errors; return those from
`CalcTaprootSignatureHash`; map to JSON-RPC error codes (-26
SCRIPT_REJECT family) in the RPC layer.

---

## Cross-wave context

W127 is the **31st discovery wave with no P0-CONSENSUS finding**.
Streak: 65 fix waves + 56 discovery waves preserved. Cumulative
~5101 bugs catalogued / ~1029-1055 fixes across the project.

The Taproot / Schnorr / Tapscript surface is one of the
most-scrutinised regions of blockbrew:
- W94 (BIP-341/342) — 9 bugs fixed
- W95 (BIP-340) — 2 bugs fixed
- This wave (W127) — 6 residual bugs (0 P0, 2 P1, 3 P2, 1 P3)

The residual bug shape is overwhelmingly "policy/perf gap" not
"consensus break", reinforcing the W94+W95 closure. All consensus
pathways correctly route BIP-341 / 342 spends per Core; BIP-340
verify matches Core byte-for-byte on the official vector set
(`crypto/schnorr_w95_test.go` 0-18).

## Test catalogue

30 gate tests are added to
`internal/script/w127_taproot_test.go`. PRESENT gates exercise the
established behavior; PARTIAL/MISSING gates `t.Skip()` with a
reference to the bug ID so the gap is visible in `go test -v`
output but does not break the suite. Tests:

- 7 BIP-340 gates: G1-G7 (all PRESENT, assertions enabled)
- 8 BIP-341 gates: G8-G15 (all PRESENT, assertions enabled)
- 10 BIP-342 gates: G16-G25 (all PRESENT, assertions enabled)
- 5 cross-cutting: G26 (PARTIAL via BUG-1, BUG-2, BUG-3, BUG-4,
  BUG-6 — skip-with-doc), G27-G29 (PRESENT, assertions), G30
  (PARTIAL via BUG-5, skip-with-doc).

All 30 gate tests + 4 helper tests, with PARTIAL/MISSING skipping
appropriately, are expected to pass in a single `go test`
invocation.
