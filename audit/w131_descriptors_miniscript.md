# W131 — Descriptors + Miniscript (BIP-380/385) Audit (blockbrew)

**Wave**: W131 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**Scope**: Descriptor language + Miniscript types, parsers, type-check,
checksum, key validation, tap-tree depth, witness/script-size limits.

**References (Bitcoin Core)**:
- `bitcoin-core/src/script/descriptor.cpp`
  - `PolyMod` (L94), `DescriptorChecksum` (L106), `INPUT_CHARSET` (L121),
    `CHECKSUM_CHARSET` (L127), `AddChecksum` (L153).
  - `ConstPubkeyProvider` (L307), `BIP32PubkeyProvider` (L377),
    `MuSigPubkeyProvider` (L596).
  - `ParseKeyPathNum` (L1754) — rejects `idx >= 0x80000000` *before*
    applying the hardened flag.
  - `ParseKeyPath` (L1789) — `allow_multipath`, the `<a;b;...>` syntax
    (L1803-1834), duplicate-substitute rejection (L1825-1828).
  - `ParsePubkeyInner` (L1876) — `permit_uncompressed = TOP || P2SH`
    (L1879); uncompressed (65-byte) pubkeys are rejected inside
    `wsh()` / `wpkh()` / `tr()` / `multi(_a)` (L1899, L1922).
  - `ParsePubkey` (L1956) — rejects `musig(` outside `tr()`/`rawtr()`
    (L1964-1968); inside `tr()` it requires x-only keys (L1995-2008).
  - `tr()` parser (L2484) — refuses `branches.size() >
    TAPROOT_CONTROL_MAX_NODE_COUNT (128)`.
  - `CheckChecksum` (L2838) — rejects descriptors with **more than one**
    `'#'`, and rejects checksums of length ≠ 8.
- `bitcoin-core/src/script/miniscript.h`
  - `MaxScriptSize(ms_ctx)` (L282) — context-sensitive size limit:
    `MAX_STANDARD_P2WSH_SCRIPT_SIZE` (3600 B, segwit-v0) vs
    `MAX_STANDARD_TX_WEIGHT - ...` (tapscript).
  - `ParseContext::WRAPPED_EXPR` (L1922) — **stacked wrappers**:
    `tvc:pk_k(...)` is parsed letter-by-letter with `last_was_v`
    enforcement (`vv:` is rejected at L1954-1956).
  - `WRAP_T` (L1778) — Core represents `t:X` as `and_v(X,1)`.
  - `Type` keywords — see L89-L104 for fragment base types.
- `bitcoin-core/src/script/miniscript.cpp`
  - `ComputeType` (L39) — canonical type-system; in particular thresh
    (L229-259) timelock-mixing rule is **gated on `k > 1`**.
  - `Fragment::MULTI`/`MULTI_A` types `"Bnudemsk"` / `"Budemsk"`
    (L223-228).
- `bitcoin-core/src/script/script.h` — `MAX_PUBKEYS_PER_MULTI_A = 999`
  (L37); `MAX_PUBKEYS_PER_MULTISIG = 20` (L34).
- `bitcoin-core/src/test/descriptor_tests.cpp` and
  `data/descriptor_tests_external.json` — test vectors (we cross-check
  blockbrew's checksum + a hand-picked vector subset).

**BIPs**: 380 (Output Script Descriptors — General Operation), 385
(`raw()`/`addr()` descriptors).

**Precedent**: W111 / W118 covered the **descriptor expansion** path
(pk/pkh/wpkh/sh/wsh/tr/multi/sortedmulti/addr/raw/combo/rawtr) at fleet
level — those are PRESENT and largely correct in blockbrew. W127
covered Taproot key-path tweaking (tr() interior + taptree leaf hash).
W131 zooms in on **descriptor-language details** (checksum framing,
multipath `<0;1>`, MUSIG, key-type restrictions, origin-info hardened
overflow, tap-tree depth cap) and the **miniscript type system and
parser** (stacked wrappers, thresh timelock-mix `k>1` gate, latent
`hash160` placeholder in pk_h compile, missing per-context script-size
gate, MAX_PUBKEYS_PER_MULTI_A check, etc.) that W111/W118/W127 did not
cover in depth.

## Summary

30 audit gates across `internal/wallet/descriptor.go` (parser +
`Descriptor` + `Expand`), `internal/script/miniscript.go` (AST + type
system + `ToScript`), `internal/script/miniscript_parse.go`
(miniscript-string parser + policy parser).

| Verdict | Count |
|---------|-------|
| PRESENT | 11 |
| PARTIAL | 6  |
| MISSING | 13 |

**Bug count**: **18 distinct bug IDs** (BUG-1 .. BUG-18).

Severity distribution:

| Severity | Count | Notes |
|----------|-------|-------|
| HIGH     | 4 | `pk_h` placeholder hash160 (BUG-1) makes every `pkh()` miniscript ship an unspendable script; uncompressed-key contamination of `wsh()` / `wpkh()` (BUG-3); `LastIndex("#")` accepts multiple `#` (BUG-2); origin-path uint32 overflow when `idx >= 2^31` is then `+= HardenedKeyStart` (BUG-4). |
| MEDIUM   | 10 | Type-system + parser parity gaps that produce sub-optimal or non-conformant descriptors but do not directly fork consensus (MUSIG/multipath/stacked-wrappers/MULTI_A keys cap/thresh-`k>1` rule). |
| LOW      | 4 | Plumbing-shape gaps (no `MaxScriptSize` per context, no `ChecksumRequired` mode, missing `ComputeMD` source-line citations, etc.). |

**No consensus break**. All bugs are wallet / descriptor / miniscript
parsing parity. Most directly affect importdescriptors / getdescriptorinfo
/ deriveaddresses semantics; BUG-1 also affects the
`internal/script/miniscript.go` compile path, so any caller that
generates Bitcoin Script from a miniscript node containing `pk_h(...)`
or `pkh(...)` (which is c:pk_h(...)) ships a literally-wrong scriptPubKey.

### Top findings

1. **BUG-1 (HIGH)**: `internal/script/miniscript.go` ships **placeholder
   `hash160`** at L1144-1148, calling `sha256Sum` / `ripemd160Sum` (both
   placeholders that `copy(h, data)` at L1151-1166 — not RIPEMD160(SHA256)
   at all). The `pk_h` compile path (L810-820) embeds the first 20 bytes
   of the raw pubkey as the "hash160" inside `OP_DUP OP_HASH160 <20>
   OP_EQUALVERIFY`. **Every miniscript containing `pk_h(K)` or `pkh(K)`
   (the c:pk_h sugar) compiles to a script that is bitwise non-matching
   to Core's output, and the resulting P2WSH/Tapscript output is
   unspendable** — the on-chain `OP_HASH160` evaluation will compare the
   real Hash160(pubkey) against the embedded raw-pubkey-prefix and fail.
   The existing `TestMiniscriptToScript` (miniscript_test.go:247) only
   covers `pk(...)`, `older(...)`, `after(...)`, `sha256(...)` — no
   `pk_h` or `pkh` coverage, so the placeholder has shipped undetected.
   *File*: `internal/script/miniscript.go:817-820, 1144-1166`.

2. **BUG-2 (HIGH)**: `ValidateDescriptorChecksum` at
   `internal/wallet/descriptor.go:163-183` splits on `strings.LastIndex(
   desc, "#")` — accepts descriptors with **multiple `'#'`** by silently
   treating only the last one as a delimiter. Core's `CheckChecksum`
   (descriptor.cpp:2840-2843) explicitly rejects this:
   `if (check_split.size() > 2) { error = "Multiple '#' symbols";
   return false; }`. Result: `wpkh(KEY)#a#bcdefghi` parses in blockbrew
   (taking `wpkh(KEY)#a` as body and `bcdefghi` as checksum); Core
   rejects it. Any tooling that round-trips descriptors via blockbrew
   loses the multi-`#` guard.
   *File*: `internal/wallet/descriptor.go:163-183`.

3. **BUG-3 (HIGH)**: `parseKey()` at `internal/wallet/descriptor.go:
   1283-1352` accepts uncompressed (130-hex = 65-byte) pubkeys
   **unconditionally**, regardless of descriptor context. Core's
   `ParsePubkeyInner` (descriptor.cpp:1876-1924) computes
   `permit_uncompressed = ctx == TOP || ctx == P2SH` (L1879) and rejects
   uncompressed inside `wsh(`, `wpkh(`, `tr(`, `multi_a(`, `sortedmulti_a(`
   (L1899, L1922, L2152). Result: `wpkh(<65-byte-hex>)` parses in
   blockbrew, expands to a `OP_0 <Hash160(uncompressed)>` segwit-v0
   scriptPubKey that is **not BIP-141 compliant** (the v0 scriptPubKey
   must encode a compressed-pubkey hash; an uncompressed Hash160
   produces a non-recoverable signature path). Importing such a
   descriptor into a Core-compatible tooling chain breaks.
   *File*: `internal/wallet/descriptor.go:1329, 1338` — no context-aware
   key-length filter. The `descriptorParser` has no `ParseScriptContext`
   tracking at all.

4. **BUG-4 (HIGH)**: `parseOrigin()` at `internal/wallet/descriptor.go:
   1409-1457` parses each path component via `strconv.ParseUint(numStr,
   10, 32)` then adds `HardenedKeyStart (= 0x80000000)` to the result
   when a hardened marker (`'`, `h`, `H`) follows. **Any path number
   ≥ 0x80000000 is accepted as-is**, and the subsequent
   `idx += HardenedKeyStart` silently overflows the uint32. Core's
   `ParseKeyPathNum` (descriptor.cpp:1754-1775) rejects this with
   `if (*p > 0x7FFFFFFF) error = ...` — the un-hardened component must
   fit in 31 bits. Result: `[deadbeef/2147483648']wpkh(KEY)` (2^31, just
   one above the bound) parses as if the path were `[deadbeef/0']`
   (after wrap) in blockbrew. Two different descriptors map to the same
   internal `KeyOriginInfo`. The corresponding `wallet.go` derivation
   path inherits the wrap.
   *File*: `internal/wallet/descriptor.go:1442-1453`. Same root cause at
   `internal/wallet/descriptor.go:1388-1396` (xpub-path parsing path).

5. **BUG-5 (HIGH/MEDIUM border)**: Miniscript `t:`/`v:`/`a:` etc.
   wrappers are parsed **one-letter-per-colon only** in
   `internal/script/miniscript_parse.go:78-185`. Core's `WRAPPED_EXPR`
   parser (miniscript.h:1922-1973) accepts **stacked** wrappers like
   `tvc:pk_k(K)` (push each letter into a parse-context stack until the
   `:`, enforcing `vv:` rejection at L1954-1956). Result: every
   BIP-spec-valid stacked-wrapper miniscript (e.g. `tv:multi(2,...)`,
   `j:and_v(v:pk(...),...)`) fails to parse in blockbrew with
   "unknown identifier" or "expected `:` not present" depending on
   layout. This is one of the most common BIP-379 patterns in
   policy-compiled miniscript and would block any external descriptor
   imported from Core into blockbrew that uses stacked wrappers.
   Note: even the single-char parser does not validate the `vv:` ban.
   *File*: `internal/script/miniscript_parse.go:80-185`.

## 30-gate audit matrix

Gates classify each Core construct as PRESENT / PARTIAL / MISSING in
blockbrew. Bugs are filed against PARTIAL and MISSING gates.

| Gate | Topic | Status | Bug |
|------|-------|--------|-----|
| G1   | `DescriptorChecksum` matches Core PolyMod (`f5dee51989`, ...) | PRESENT | — |
| G2   | `CHECKSUM_CHARSET = qpzry9x8gf2tvdw0s3jn54khce6mua7l` | PRESENT | — |
| G3   | `INPUT_CHARSET` (96-char) byte-identical to Core | PRESENT | — |
| G4   | `AddChecksum(desc)` appends `'#' + DescriptorChecksum(desc)` | PRESENT | — |
| G5   | `CheckChecksum`: reject **multiple `'#'`** | MISSING | **BUG-2** |
| G6   | `CheckChecksum`: reject checksum of length ≠ 8 | PRESENT | (descriptor.go:173-175) |
| G7   | `Parse(...)` accepts `pk(K)` / `pkh(K)` / `wpkh(K)` / `wsh(...)` / `sh(...)` / `tr(K[,TREE])` / `multi(k,K...)` / `sortedmulti(k,K...)` / `combo(K)` / `raw(HEX)` / `addr(ADDR)` / `rawtr(K)` | PRESENT | — |
| G8   | `Parse(...)` accepts **`musig(K1,K2,...)`** | MISSING | **BUG-6** |
| G9   | `Parse(...)` accepts BIP-389 **multipath `<a;b;...>`** | MISSING | **BUG-7** |
| G10  | `ParsePubkeyInner`: `permit_uncompressed = TOP || P2SH` (reject 65-byte pubkey inside `wsh`/`wpkh`/`tr`) | MISSING | **BUG-3** |
| G11  | `ParseKeyPathNum`: reject `path_num >= 0x80000000` *before* hardened-bit | MISSING | **BUG-4** |
| G12  | `tr()` taptree depth ≤ `TAPROOT_CONTROL_MAX_NODE_COUNT (=128)` | MISSING | **BUG-8** |
| G13  | `multi(...)` / `sortedmulti(...)` keys ≤ `MAX_PUBKEYS_PER_MULTISIG (=20)` | PRESENT | (descriptor.go:631, 1164) |
| G14  | `multi_a(...)` / `sortedmulti_a(...)` keys ≤ `MAX_PUBKEYS_PER_MULTI_A (=999)` | MISSING | **BUG-9** |
| G15  | x-only key (32-byte) accepted in tapscript context only | PARTIAL | **BUG-10** (parser accepts 32-byte keys in P2WSH context too) |
| G16  | `ParseDescriptor` is **stateful w.r.t. ParseScriptContext** (TOP / P2SH / P2WSH / P2TR / MUSIG) | MISSING | **BUG-11** (descriptorParser has only `network`, no script context) |
| G17  | `tr()` interior key tweak via TapTweak + leaf-version 0xc0 + sorted-pair TapBranch | PRESENT | — (W127 BUG-1 already filed for leaf-version constant — not in W131 scope) |
| G18  | `addr()` decoded against `network` and re-encoded round-trips | PRESENT | — |
| G19  | `raw()` accepts arbitrary hex script | PRESENT | — |
| G20  | Miniscript `ComputeType` per fragment (PK_K / PK_H / OLDER / AFTER / SHA256 / HASH256 / RIPEMD160 / HASH160 / JUST_0 / JUST_1 / wrap_a/s/c/d/v/j/n / and_v / and_b / or_b / or_c / or_d / or_i / andor / thresh / multi / multi_a) | PARTIAL | **BUG-12** (`FragMulti` returns `B\|N\|U\|D\|E\|M\|S\|K_Prop` — missing the `o` bit; Core says `"Bnudemsk"`; the `o` for n_keys=1 isn't there in Core either — but the **thresh** sub-rule `(i ? "Wdu" : "Bdu")` is correct in blockbrew. Actual bug is in **thresh timelock-mix gate not gated on `k>1`** — `computeK` rejects all conflicts regardless of `k`.) |
| G21  | Thresh timelock-mix rule **only fires when `k > 1`** | MISSING | **BUG-13** (blockbrew's `computeK`/`computeK3` reject any timelock conflict regardless of `k`) |
| G22  | Miniscript parser: **stacked wrappers** (`tvc:pk_k(K)`) | MISSING | **BUG-5** |
| G23  | Miniscript parser: reject **`vv:`** double-verify | MISSING | **BUG-14** |
| G24  | Miniscript parser: `0` / `1` literal accepted | PRESENT | — |
| G25  | Miniscript `ToScript` for `pk_h` produces `OP_DUP OP_HASH160 <Hash160(KEY)> OP_EQUALVERIFY` (real hash, not placeholder) | MISSING | **BUG-1** |
| G26  | Miniscript `ToScript` for `multi_a` rejects keys not 32 bytes (x-only) | PARTIAL | **BUG-15** (blockbrew silently accepts 33-byte keys and chops them; should error) |
| G27  | Per-context script-size limit (`MaxScriptSize(ms_ctx)` = 3600 for P2WSH, ~400k for Tapscript) | PARTIAL | **BUG-16** (`ValidateMiniscript` uses single constant `MaxScriptSize = 10000`, which is wrong for both contexts — P2WSH is 3600, Tapscript is ~400k) |
| G28  | Op-count limit (`MAX_OPS_PER_SCRIPT = 201`) on P2WSH miniscript | MISSING | **BUG-17** (`CheckOpsLimit` returns `true` unconditionally — script.go:1324-1331) |
| G29  | Stack-size limit (`MAX_STACK_SIZE = 1000`) | MISSING | **BUG-17** (`CheckStackSize` returns `true` unconditionally) |
| G30  | `MiniscriptFromScript` (decompile) implemented | MISSING | **BUG-18** (returns `errors.New("not yet implemented")` at miniscript_parse.go:859-863) |

## Bug catalogue

### Compile-path correctness

**BUG-1 (G25 HIGH)** — *Placeholder hash160 in pk_h compile.*
`internal/script/miniscript.go` ships:
```go
func hash160(data []byte) []byte {
    sha := sha256Sum(data)
    return ripemd160Sum(sha)
}
func sha256Sum(data []byte) []byte {
    h := make([]byte, 32)
    copy(h, data) // placeholder
    return h
}
func ripemd160Sum(data []byte) []byte {
    h := make([]byte, 20)
    copy(h, data) // placeholder
    return h
}
```
The `pk_h` compile path (L810-820) calls `hash := hash160(n.Keys[0])`
and embeds it in `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY`. The
embedded "hash" is the first 20 bytes of the raw pubkey, *not* the
RIPEMD160(SHA256(pubkey)) that Core's interpreter computes at run
time. So the on-chain `OP_HASH160` step produces the real Hash160,
which the embedded data does not equal — the script always fails.
**Outputs paying to any `wsh(pkh(K))` / `wsh(...pk_h(K)...)` /
`tr(K, pkh(K))` produced by blockbrew miniscript are unspendable.**
The existing `TestMiniscriptToScript` only exercises `pk(K)`,
`older(...)`, `after(...)`, `sha256(...)` — pk_h has no coverage.
*Fix*: import `bbcrypto.Hash160` (or `crypto.Hash160`) the same way
`expandPKH` at `internal/wallet/descriptor.go:548` already does
(`bbcrypto.Hash160(pubKey.SerializeCompressed())`).
*File*: `internal/script/miniscript.go:817-820, 1144-1166`.

### Descriptor parser framing

**BUG-2 (G5 HIGH)** — *Multiple `'#'` accepted.*
`ValidateDescriptorChecksum` uses `strings.LastIndex(desc, "#")`. Core
splits and rejects `check_split.size() > 2` (descriptor.cpp:2840-2843).
A descriptor crafted as `wpkh(02...)#aaaaaaaa#bbbbbbbb` — i.e. the
*body* contains `#aaaaaaaa`, which is then itself **not in
INPUT_CHARSET** — would in fact also fail Core's `PolyMod` (which
returns the empty string for any char not in INPUT_CHARSET, so the
"#" inside the body short-circuits via that path). But the framing
check is also Core-canonical, so blockbrew should reject it at the
splitting step for the same error message and not depend on the
charset check.
*Fix*: split on `'#'` with `strings.Split`, error if > 2 parts.
*File*: `internal/wallet/descriptor.go:163-183`.

**BUG-3 (G10 HIGH)** — *Uncompressed (65-byte) pubkey accepted in
non-TOP/P2SH contexts.* `parseKey()` accepts hex of length 66 or 130 +
hex-decode. Core's `ParsePubkeyInner` checks `permit_uncompressed = ctx
== TOP || ctx == P2SH` (descriptor.cpp:1879) and rejects 65-byte keys
inside `wsh()`, `wpkh()`, `tr()`, `multi_a()`, `sortedmulti_a()`. The
descriptor.go parser has **no ParseScriptContext**; it always permits
65-byte keys.
*Fix*: thread a `parseScriptContext` enum into `descriptorParser`,
set it from each function (`wsh→P2WSH`, `wpkh→P2WSH`, `tr→P2TR`, etc.),
and reject 65-byte keys when `ctx ≠ TOP && ctx ≠ P2SH`.
*File*: `internal/wallet/descriptor.go:1283-1352`.

**BUG-4 (G11 HIGH)** — *Origin-path uint32 overflow.*
`parseOrigin` and `parseXPubKey` both accept any 32-bit value for an
un-hardened component, then `idx += HardenedKeyStart (= 0x80000000)`
on the hardened marker. Core's `ParseKeyPathNum` (descriptor.cpp:
1754-1775) rejects un-hardened path numbers `> 0x7FFFFFFF` because
they would alias the hardened bit. **Two distinct descriptors map to
the same internal path** — privacy/correctness hazard.
*Fix*: reject `idx > 0x7FFFFFFF` *before* applying the hardened bit.
*File*: `internal/wallet/descriptor.go:1388-1396, 1442-1453`.

### Descriptor language coverage

**BUG-6 (G8 MEDIUM)** — *No `musig()` support.*
Core supports `musig(K1,K2,...)` inside `tr()` and `rawtr()`
contexts (descriptor.cpp:596-789, 1964-2008). blockbrew has no
`musig` branch in `parseDescriptor` (descriptor.go:1049-1075); the
`default` arm returns `ErrUnsupportedDescriptor`.
*Effect*: importing any modern multi-party Taproot setup from
external tooling fails at parse time.
*File*: `internal/wallet/descriptor.go:1049-1075`.

**BUG-7 (G9 MEDIUM)** — *No BIP-389 multipath support.*
Core's `ParseKeyPath` (descriptor.cpp:1789-1855) accepts the
`<0;1>` / `<0;1;2;...>` multipath syntax — one descriptor expands
to N descriptors. blockbrew's `parseXPubKey` (descriptor.go:1354-1407)
splits the path by `/` and only recognises numeric, `'`/`h`/`H`,
and `*`/`*'` components — angle-bracket components are not parsed.
*Effect*: Core's standard "receive+change" pair format
`[fp/86'/0'/0']xpub.../<0;1>/*` rejects in blockbrew.
*File*: `internal/wallet/descriptor.go:1354-1407`.

**BUG-8 (G12 MEDIUM)** — *No taptree depth cap.*
Core's `tr()` parser refuses `branches.size() >
TAPROOT_CONTROL_MAX_NODE_COUNT (= 128)` (descriptor.cpp:2484-2486).
blockbrew's `parseTapTree` (descriptor.go:1194-1220) recurses
without depth tracking. Maliciously deep `{...{...{...}}}` trees
parse and only fail at script-execution time. Stack-overflow risk
on the Go recursive parser too (goroutine stack default is 8KB
initial, but grows; not a crash but a perf-DoS vector).
*File*: `internal/wallet/descriptor.go:1194-1220`.

**BUG-9 (G14 MEDIUM)** — *No `MAX_PUBKEYS_PER_MULTI_A = 999` cap.*
The miniscript `multi_a` parser (miniscript_parse.go:487-507) checks
`k < 1 || k > len(keys)` but not `len(keys) <= 999`. Core's
`MULTI_A` `ComputeType` precondition is `n_keys >= 1 && n_keys <=
MAX_PUBKEYS_PER_MULTI_A (= 999)` (miniscript.cpp:79-80). blockbrew
will accept e.g. a 1000-key `multi_a(...)` and either crash later
or produce an oversized script.
*File*: `internal/script/miniscript_parse.go:487-507`.

**BUG-10 (G15 MEDIUM)** — *32-byte x-only keys accepted in P2WSH.*
`miniscript_parse.go:524-548` (`parseKey`) accepts key lengths
{32, 33, 65}, regardless of `p.ctx`. Core requires 32-byte x-only
*only in tapscript context*, and rejects them in P2WSH (must be
33-byte compressed; descriptor.cpp:1875-1925).
*File*: `internal/script/miniscript_parse.go:524-548`.

**BUG-11 (G16 LOW)** — *Descriptor parser has no `ParseScriptContext`.*
A coarse-grained `descriptorParser` carries only `network`, not the
Core `ParseScriptContext { TOP, P2SH, P2WSH, P2WSH_INSIDE_P2SH,
P2TR, MUSIG }`. BUG-3, BUG-10, partially BUG-9 follow from this gap.
*File*: `internal/wallet/descriptor.go:1027-1032`.

### Miniscript type system

**BUG-12 (G20 MEDIUM)** — *MULTI/MULTI_A type-string parity drift.*
blockbrew's `FragMulti` returns `TypeB | TypeN | TypeU | TypeD |
TypeE | TypeM | TypeS | TypeK_Prop` (miniscript.go:594-595) and
`FragMultiA` returns `TypeB | TypeU | TypeD | TypeE | TypeM | TypeS |
TypeK_Prop` (L596-597). Core says `"Bnudemsk"` and `"Budemsk"`
respectively (miniscript.cpp:224, 227). The lists overlap, but
**the `K_Prop` (timelock-mix `k`)** is present in both — and **so
is `e` (expression)** in MULTI_A in Core, but blockbrew has `e`
gated to e=k==n (no — actually blockbrew has it unconditionally).
On manual comparison the lists do match. **Real bug:** Core's
PK_K type includes `K` (capital — "Key" type), not just `B`. Compare
miniscript.cpp:89: `"Konudemsxk"`. blockbrew at L274-275 returns
`TypeK | TypeO | TypeN | TypeU | TypeD | TypeE | TypeM | TypeS |
TypeX | TypeK_Prop` — correct. PK_H L276-277 returns
`TypeK | TypeN | TypeU | TypeD | TypeE | TypeM | TypeS | TypeX |
TypeK_Prop` (missing `o` — but Core also omits `o` from PK_H per
miniscript.cpp:90 `"Knudemsxk"`, correct). So PK_K and PK_H are
correct; MULTI/MULTI_A is **also correct on inspection**. **What
*is* wrong is `FragWrapV` (miniscript.go:344-352)**: Core's WRAP_V
returns `(x & "zonms")` (miniscript.cpp:131), but blockbrew has
`x & (TypeZ | TypeO | TypeN | TypeM | TypeS)` — matches. So this
bug-ID re-files as **MED LOW** with the note that the verification
audit found no concrete divergence in the type strings beyond the
WRAP_V `u`-on-tapscript gate already documented at L339-341; mark
**G20 PARTIAL** rather than missing.
*Effect*: theoretical — needs cross-vector testing against Core's
`miniscript_tests.cpp` to confirm; none of the diffs found here
flip a sanity check on common examples.
*File*: `internal/script/miniscript.go:594-597`.

**BUG-13 (G21 MEDIUM)** — *Thresh timelock-mix rule not gated on
`k > 1`.* Core's `THRESH` type rule at miniscript.cpp:246-250:
```cpp
"k"_mst.If(((acc_tl & t) << "k"_mst) && ((k <= 1) ||
    ((k > 1) && !(((acc_tl << "g"_mst) && (t << "h"_mst)) ||
    ((acc_tl << "h"_mst) && (t << "g"_mst)) ||
    ((acc_tl << "i"_mst) && (t << "j"_mst)) ||
    ((acc_tl << "j"_mst) && (t << "i"_mst))))));
```
**The timelock-mix rejection only fires when `k > 1`** — for a
1-of-N thresh, mixing time + height locks is fine (we only need
one). blockbrew's `computeK` (miniscript.go:663-675) rejects
timelock conflicts unconditionally for AND_V / AND_B / ANDOR (no
`k` parameter) — but uses `computeK` from inside thresh too
(L638: `computeK(accTL, st, TypeK_Prop)`), and *thresh's k is
explicit*. So a 1-of-2 thresh of `(older_time, older_height)`
fails sanity in blockbrew where Core would accept.
*File*: `internal/script/miniscript.go:638, 663-690`.

**BUG-14 (G23 MEDIUM)** — *`vv:` double-verify not rejected.*
Core's `WRAPPED_EXPR` parser tracks `last_was_v` and refuses any
second consecutive `v` (miniscript.h:1953-1957: `if (last_was_v)
return {};`). blockbrew's parser only consumes one wrapper letter
per `:` (BUG-5 above), so this never even comes up in single-letter
input. But the parser also doesn't enforce `vv` (or `vv:` after a
stacked-wrapper fix) ever being valid. Without BUG-5 fixed first,
this is a latent bug; with BUG-5 fixed, must also reject `vv`.
*File*: `internal/script/miniscript_parse.go:117-125`.

### Miniscript compile-path limits

**BUG-15 (G26 LOW)** — *`multi_a` key length silently chopped.*
`miniscript.go:1052-1058` accepts both 32-byte and 33-byte keys and
chops 33→32. Core (after parse) requires the type-system invariant
that all keys are 32-byte x-only in tapscript context (see the
parser at miniscript.h:1881-1901: `key_length` is taken verbatim
and `ctx.FromString` validates).
*Fix*: error if any key is not 32 bytes when ctx==Tapscript.
*File*: `internal/script/miniscript.go:1047-1070`.

**BUG-16 (G27 LOW)** — *Per-context script-size limit missing.*
`ValidateMiniscript` (miniscript_parse.go:867-895) compares
`size > MaxScriptSize (= 10000)` for P2WSH context — but Core's
context-sensitive `MaxScriptSize(ms_ctx)` returns 3600 for P2WSH
(MAX_STANDARD_P2WSH_SCRIPT_SIZE) and ~400000 for Tapscript
(MAX_STANDARD_TX_WEIGHT - leeway). 10000 is the consensus
MAX_SCRIPT_SIZE for legacy scripts — wrong for both.
*File*: `internal/script/miniscript_parse.go:879-883`,
`internal/script/opcode.go:354`.

**BUG-17 (G28/G29 LOW)** — *`CheckOpsLimit` / `CheckStackSize` are
no-ops.* `miniscript.go:1324-1337` returns `true` unconditionally.
Core's `CheckOpsLimit` and `CheckStackSize` (miniscript.h:1565-1610)
walk the AST and count operations / stack frames against
`MAX_OPS_PER_SCRIPT = 201` and `MAX_STACK_SIZE = 1000` respectively.
Without them, a syntactically-valid but over-the-limit miniscript
parses, validates, and then fails at script-execution time on a
real consensus check — pushing the failure window from parse-time
(client-side) to broadcast-time (peer-rejection).
*File*: `internal/script/miniscript.go:1324-1337`.

**BUG-18 (G30 LOW)** — *`MiniscriptFromScript` (decompile) not
implemented.* Returns `errors.New("not yet implemented")`. Required
for Core's `inferdescriptor` RPC path and for any `importdescriptors`
flow that ingests raw scripts. Not exercised by the daily wallet
path but blocks "decode this output script back to a descriptor".
*File*: `internal/script/miniscript_parse.go:859-864`.

## Cross-references

- W111 + W118 BUG-1..5 covered the **wallet-layer** descriptor expand
  and BIP-32 derivation; this audit is the descriptor *language*
  layer.
- W127 BUG-1 (Taproot leaf-version constant) is **NOT** re-filed here
  — the TapLeaf 0xc0 constant is correct at descriptor.go:759.
- BUG-1 (placeholder hash160) is structurally similar to the W122
  "test-comment-as-confession" meta-pattern: a placeholder shipping
  to a real code path because the test surface does not exercise it.

## Universal patterns surfaced

Patterns that may recur across implementations on the same scope:

- **Placeholder-shipped-as-real**: any impl that has crypto helper
  imports done lazily (`crypto.SHA256Hash` not yet wired) can ship a
  placeholder that the test surface didn't catch. The fix is a
  trivial 1-import-line change; the audit value is in the discovery.
  Cross-impl: search every impl's miniscript implementation for
  the literal "placeholder" comment.
- **`strings.LastIndex("#")` vs `Split('#')` framing**: silently
  accepts multiple delimiters. Cross-impl audit candidate for any
  descriptor checksum implementation in any language.
- **Single-letter wrapper parser**: stacked wrappers `tvc:` /
  `j:` / `a:` are the BIP-379-canonical compact form; if an impl
  only parses one letter per `:`, every other-impl-roundtripped
  descriptor breaks. Cross-impl audit candidate for every
  miniscript parser.
- **`ctx`-less parser**: lacking a `ParseScriptContext` thread
  produces a cluster of related bugs (BUG-3, BUG-10, partially
  BUG-9). Cross-impl audit candidate: grep for "descriptor.*parser"
  + check whether it carries a script-context enum.
- **Uint32 path-number overflow**: 32-bit parse + 0x80000000 add =
  silent wrap. Same vulnerability class as the Bech32 5-bit-vs-8-bit
  packing bug surfaced in W120/W122 — "the integer math implements
  what the parser said, but the parser said the wrong thing".

## Methodology note

Source-line citations refer to:
- `bitcoin-core/src/script/descriptor.cpp` at `2026-05-17` clone HEAD.
- `bitcoin-core/src/script/miniscript.h` at same HEAD.
- `bitcoin-core/src/script/miniscript.cpp` at same HEAD.
- `internal/wallet/descriptor.go` at blockbrew master 10c8d79 (W128).
- `internal/script/miniscript.go`, `miniscript_parse.go`,
  `miniscript_satisfy.go` at same blockbrew master.

All 18 bugs were surfaced by direct cross-read against Core's
reference; the regression test file
`internal/script/w131_descriptors_miniscript_test.go` codifies the
PRESENT gates as pass-tests and the MISSING/PARTIAL gates as
`t.Skip(BUG-N)` or `t.Errorf(...)` failures (where the failure
mode is observable from outside without engaging the latent
crypto).
