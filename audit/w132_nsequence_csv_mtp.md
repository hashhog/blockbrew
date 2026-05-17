# W132 — BIP-68 / BIP-112 / BIP-113 nSequence + OP_CSV + MTP Audit (blockbrew)

**Wave**: W132 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**Scope**: nSequence encoding, OP_CHECKSEQUENCEVERIFY (BIP-112), BIP-68
relative locktime (`CalculateSequenceLocks`/`EvaluateSequenceLocks`),
BIP-113 (MTP-as-lockTime in `IsFinalTx` for both block-connect and
mempool-accept), and `GetMedianTimePast` semantics.

**References (Bitcoin Core)**:
- `bitcoin-core/src/primitives/transaction.h`
  - L76 `SEQUENCE_FINAL = 0xffffffff`
  - L82 `MAX_SEQUENCE_NONFINAL = SEQUENCE_FINAL - 1`
  - L93 `SEQUENCE_LOCKTIME_DISABLE_FLAG = (1U << 31)`
  - L99 `SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22)`
  - L104 `SEQUENCE_LOCKTIME_MASK = 0x0000ffff`
  - L114 `SEQUENCE_LOCKTIME_GRANULARITY = 9`
  - L293 `const uint32_t version;` — **wire field is unsigned 32-bit**
- `bitcoin-core/src/consensus/consensus.h`
  - L28 `LOCKTIME_VERIFY_SEQUENCE = (1 << 0)`
  - `LOCKTIME_THRESHOLD = 500000000`
- `bitcoin-core/src/consensus/tx_verify.cpp`
  - L17 `IsFinalTx` — locktime semantics, SEQUENCE_FINAL bypass.
  - L39 `CalculateSequenceLocks` — version≥2 + LOCKTIME_VERIFY_SEQUENCE
    gate; per-input DISABLE_FLAG skip (and **zeroes** `prevHeights[i]`,
    line 67); TYPE_FLAG path; MTP-at-`max(coinHeight-1,0)`; subtract-1
    "last invalid" semantics; max across inputs.
  - L97 `EvaluateSequenceLocks` — strict `>=` rejection (lockPair vs
    `block.nHeight` and `block.pprev->GetMedianTimePast()`).
  - L107 `SequenceLocks` — wraps Calculate + Evaluate.
- `bitcoin-core/src/script/interpreter.cpp`
  - L561 `OP_CHECKSEQUENCEVERIFY` — gates on
    `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` else `break` (NOP); 5-byte
    `CScriptNum`; `nSequence < 0` → `SCRIPT_ERR_NEGATIVE_LOCKTIME`;
    operand DISABLE_FLAG → forward-compat NOP; `CheckSequence`.
  - L1782 `CheckSequence` — `txTo->version < 2` fails; tx-side
    DISABLE_FLAG fails; mask both with
    `(SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK) =
    0x0040ffff`; apples-to-apples type-flag pairing; final masked
    operand `>` masked tx → fail.
- `bitcoin-core/src/chain.h`
  - L233 `GetMedianTimePast` — median of `this` + 10 ancestors (11
    samples), `nMedianTimeSpan = 11`, `pbegin[(pend - pbegin) / 2]`.
- `bitcoin-core/src/validation.cpp`
  - L164 `CheckFinalTxAtTip` — uses `active_chain_tip.GetMedianTimePast()`.
  - L201 `CalculateLockPointsAtTip` — `STANDARD_LOCKTIME_VERIFY_FLAGS`,
    `prev_heights` derived from coins (mempool inputs = tip+1).
  - L246 `CheckSequenceLocksAtTip` — simulated `index.nHeight = tip+1`,
    `EvaluateSequenceLocks(index, …)` (which uses `index.pprev->MTP`).
  - L2478 ConnectBlock — `nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE`
    when `DeploymentActiveAt(*pindex, …, DEPLOYMENT_CSV)`; per-tx
    `SequenceLocks(tx, nLockTimeFlags, prevheights, *pindex)`.
  - L4129 `ContextualCheckBlock` — BIP-113: post-CSV uses
    `pindexPrev->GetMedianTimePast()` as `nLockTimeCutoff`, else
    `block.GetBlockTime()`.
- `bitcoin-core/src/policy/policy.h`
  - L138 `STANDARD_LOCKTIME_VERIFY_FLAGS = LOCKTIME_VERIFY_SEQUENCE`.

**BIPs**: 68 (Relative lock-time using consensus-enforced sequence
numbers), 112 (CHECKSEQUENCEVERIFY), 113 (Median time-past as
endpoint for lock-time calculations).

## Summary

30 audit gates across:

- `internal/consensus/txvalidation.go` (BIP-68 `CalculateSequenceLocks`
  + `EvaluateSequenceLocks` + `IsFinalTx`, constants in
  `internal/consensus/params.go`).
- `internal/consensus/headerindex.go` (`BlockNode.GetMedianTimePast`).
- `internal/consensus/blockvalidation.go` (`CheckBlockContext` MTP-vs-
  header dispatch, `CalcMedianTimePast`).
- `internal/consensus/chainmanager.go` (ConnectBlock-side `SequenceLocks`
  call site + CSV gate; `collectPrevTimestamps`).
- `internal/script/opcodes_impl.go` (`opCheckSequenceVerify`).
- `internal/script/engine.go` (`ScriptVerifyCSV` flag, NOP gate).
- `internal/mempool/mempool.go` (`checkSequenceLocksLocked`,
  `IsFinalTx` mempool-side call, CSV gate at line 1686).

| Verdict | Count |
|---------|-------|
| PRESENT | 21 |
| PARTIAL | 6  |
| MISSING | 3  |

**Bug count**: **9 distinct bug IDs** (BUG-1 .. BUG-9).

Severity distribution:

| Severity | Count | Notes |
|----------|-------|-------|
| **P0-CDIV** | 2 | BUG-1 (tx.Version is `int32` not `uint32_t` → BIP-68 inversion + CSV version-gate inversion for versions ≥ 2^31; consensus-divergent for any tx with high version bit set); BUG-2 (CSV opcode's `tx.Version < 2` shares the same int32 type defect → diverges from Core for high-version tx, in the **opposite direction** of BUG-1 inside `CalculateSequenceLocks` since OP_CSV is a per-input script check, not a per-tx fEnforceBIP68 gate). |
| HIGH | 2 | BUG-3 (CalculateSequenceLocks DOES NOT zero `prevHeights[i]` on DISABLE_FLAG skip — Core sets it to 0 at tx_verify.cpp:67; latent but not exploited today because blockbrew has no LockPoints/maxInputBlock surface). BUG-4 (`CheckBlockContext` MTP wiring uses a variadic `medianTimePast ...uint32` with a `medianTimePast[0] > 0` guard that silently degrades to header timestamp if any caller passes literal `0` — even when CSV is active; the `> 0` guard is unfounded vs. Core which unconditionally substitutes MTP post-CSV). |
| MEDIUM | 3 | BUG-5 (per-input early-skip for coinbase-shaped inputs inside `CalculateSequenceLocks` — Core has no such guard; defensive but unauthorized deviation). BUG-6 (OP_CSV uses single `ErrCSVFailed` for all four failure modes — Core uses `SCRIPT_ERR_NEGATIVE_LOCKTIME` vs `SCRIPT_ERR_UNSATISFIED_LOCKTIME`; error-string parity gap, no consensus impact). BUG-7 (mempool `checkSequenceLocksLocked` skips when `mp.config.ChainState == nil` — silent test-mode opt-out with no guard against running production without a wired ChainState). |
| LOW | 2 | BUG-8 (no named constant `SequenceFinal = 0xFFFFFFFF` — literal `0xFFFFFFFF` is used at txvalidation.go:453; cosmetic). BUG-9 (potential int32 overflow in `prevHeights[i] + int32(seq&MASK) - 1` when prevHeights approaches int32 max — practically unreachable, but matches Core's `int` overflow surface; only worth a comment). |

**Consensus impact**: BUG-1 and BUG-2 are P0-CDIV. For any tx with
`version & 0x80000000` set (e.g. version `0xFFFFFFFE` or `0x80000002`),
blockbrew's signed `int32 Version` field deserializes to a **negative**
number; `tx.Version < 2` is then **TRUE** which:
- In `CalculateSequenceLocks` (BUG-1): **silently disables BIP-68**.
  blockbrew accepts a block with a sequence-locked v=0xFFFFFFFE tx
  whose lock is not satisfied; Core (uint32 version) **enforces**
  BIP-68 and rejects. → **fork**.
- In `opCheckSequenceVerify` (BUG-2): **fails OP_CSV** with
  `ErrCSVFailed`. Core (uint32 version) version-check passes → falls
  through to `CheckSequence` → either passes or fails on the real
  comparison. For a tx whose CSV operand matches the txin sequence,
  Core accepts; blockbrew rejects. → **fork**.

The two directions are **opposite** (one is "blockbrew under-enforces,"
the other is "blockbrew over-rejects") because `CalculateSequenceLocks`
uses `version < 2` to *gate* enforcement, while `opCheckSequenceVerify`
uses `version < 2` to *fail* enforcement.

Standardness rules in Core constrain mempool-accepted tx versions to
`{1, 2, 3}` (TRUC), so the bug is not currently reachable via mempool
relay. But:
- A miner can include any version in a mined block.
- An attacker could craft such a tx privately and submit it via
  `submitblock` / mining template attack.
- Future BIPs may allocate `version` bits that overlap with bit 31.

Verdict: **2 × P0-CDIV** filed as BUG-1, BUG-2. **Recommend fix** as
single-impl wave FIX-W132-blockbrew: change
`internal/wire/types.go:221 Version int32` → `Version uint32` and
update `MsgTx.Deserialize` (`ReadInt32LE` → `ReadUint32LE`),
`MsgTx.Serialize` (`WriteInt32LE` → `WriteUint32LE`), and the two
`< 2` guards (`txvalidation.go:492`, `opcodes_impl.go:1143`).

### Top findings

1. **BUG-1 / BUG-2 (P0-CDIV)**: `wire.MsgTx.Version` is declared
   `int32`, deserialized via `ReadInt32LE`. Core uses `uint32_t version`
   (transaction.h:293). The two `tx.Version < 2` guards (BIP-68 gate at
   txvalidation.go:492 and OP_CSV version check at opcodes_impl.go:1143)
   invert their truth value for any tx with bit 31 of `version` set
   relative to Core. See "Consensus impact" above.
   *Files*: `internal/wire/types.go:221, 307, 249`,
   `internal/consensus/txvalidation.go:492`,
   `internal/script/opcodes_impl.go:1143`.

2. **BUG-3 (HIGH, latent)**: `CalculateSequenceLocks` per-input
   DISABLE_FLAG path at `internal/consensus/txvalidation.go:504-507`:
   ```go
   if seq&SequenceLockTimeDisabledFlag != 0 {
       continue
   }
   ```
   Core at `tx_verify.cpp:65-69`:
   ```cpp
   if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
       prevHeights[txinIndex] = 0;   // <-- mutates input
       continue;
   }
   ```
   blockbrew does NOT zero `prevHeights[i]`. The Core mutation is
   consumed by `CalculateLockPointsAtTip` at `validation.cpp:230-236`
   when computing `max_input_height` for `LockPoints.maxInputBlock`.
   blockbrew has no `LockPoints` / `maxInputBlock` plumbing today, so
   this is **latent**. Will become a P0-CDIV if/when blockbrew adds
   lock-point caching for mempool persistence.

3. **BUG-4 (HIGH)**: `CheckBlockContext` MTP wiring at
   `internal/consensus/blockvalidation.go:131, 193-197`:
   ```go
   func CheckBlockContext(block, prevHeader, height, params, medianTimePast ...uint32) error
   …
   if height >= params.CSVHeight && len(medianTimePast) > 0 {
       blockTime = medianTimePast[0]
   } else {
       blockTime = block.Header.Timestamp
   }
   ```
   Core unconditionally substitutes `pindexPrev->GetMedianTimePast()`
   when CSV is active (validation.cpp:4133-4146). Two latent foot-guns:

   - Variadic-with-zero-length: a caller forgetting the MTP argument
     (or test passing only the 4 positional args) silently falls back
     to the header timestamp even when `height >= CSVHeight`. Core
     would crash on `assert(pindexPrev != nullptr)` — blockbrew silently
     downgrades to BIP-113-disabled. The single production caller in
     `chainmanager.go:542` does pass `mtp`, but the type signature
     permits the bug.
   - `medianTimePast[0] > 0` guard at line 147 (for the timestamp
     check) is technically dead today (block 1's MTP is genesis time
     which is non-zero on every network), but it documents a wrong
     assumption — a 0-valued MTP is legal in principle (e.g. a
     regtest-style network with a genesis at unix time 0).

   *File*: `internal/consensus/blockvalidation.go:131-204`.

4. **BUG-5 (MEDIUM)**: `CalculateSequenceLocks` early-skips coinbase
   inputs at `internal/consensus/txvalidation.go:497-500`:
   ```go
   if in.PreviousOutPoint.Hash.IsZero() && in.PreviousOutPoint.Index == 0xFFFFFFFF {
       continue
   }
   ```
   Core has **no** such guard. Coinbase exclusion is done at the
   *caller* (`ConnectBlock` at `validation.cpp:2531` only calls
   `SequenceLocks` on non-coinbase txs). The blockbrew guard is
   defensive in practice (CalculateSequenceLocks is not called on
   coinbase in any current path) but is an unauthorized deviation
   from Core's contract. If a future caller path passes a coinbase
   tx, blockbrew silently skips inputs that Core would still try to
   process (and would assert or compute lock against the dummy
   coinbase prevout).

5. **BUG-6 (MEDIUM)**: `opCheckSequenceVerify` uses a single
   `ErrCSVFailed` for all four reject modes
   (`internal/script/opcodes_impl.go:1116-1166`). Core distinguishes:
   - `SCRIPT_ERR_INVALID_STACK_OPERATION` (stack underflow,
     interpreter.cpp:569).
   - `SCRIPT_ERR_NEGATIVE_LOCKTIME` (negative operand,
     interpreter.cpp:580).
   - `SCRIPT_ERR_UNSATISFIED_LOCKTIME` (CheckSequence false path,
     interpreter.cpp:590).
   blockbrew also conflates with `ErrStackUnderflow` for the first
   case but emits `ErrCSVFailed` for the latter three. This means:
   - RPC error strings for `verifyscript` / `decodescript` will not
     match Core verbatim.
   - Any future cross-impl test that pins error parity (post-W125
     pattern) will fail.
   No consensus impact (both paths reject), but a parity wart.

## 30-gate audit matrix

| Gate | Topic | Status | Bug |
|------|-------|--------|-----|
| G1   | `SEQUENCE_FINAL = 0xFFFFFFFF` named in code | PARTIAL | BUG-8 |
| G2   | `SequenceLockTimeDisabledFlag = 1<<31` (uint32 0x80000000) | PRESENT | — |
| G3   | `SequenceLockTimeTypeFlag = 1<<22` (0x00400000) | PRESENT | — |
| G4   | `SequenceLockTimeMask = 0x0000ffff` | PRESENT | — |
| G5   | `SequenceLockTimeGranularity = 9` (`1<<9 == 512`) | PRESENT | — |
| G6   | `LOCKTIME_THRESHOLD = 500_000_000` | PRESENT | — |
| G7   | `LOCKTIME_VERIFY_SEQUENCE` flag plumbed (Core-style int flag) | MISSING | — (blockbrew bakes the gate into each call site; functionally equivalent because only CSV-enforced contexts call into BIP-68) |
| G8   | `IsFinalTx` locktime=0 → final | PRESENT | — |
| G9   | `IsFinalTx` lockTime < THRESHOLD → height path | PRESENT | — |
| G10  | `IsFinalTx` lockTime ≥ THRESHOLD → time path | PRESENT | — |
| G11  | `IsFinalTx` all-inputs SEQUENCE_FINAL → bypass locktime | PRESENT | — |
| G12  | `IsFinalTx` any-input non-FINAL → respect locktime | PRESENT | — |
| G13  | `tx.Version` field width matches Core `uint32_t` | **MISSING** | **BUG-1, BUG-2** (P0-CDIV) |
| G14  | `CalculateSequenceLocks` version-gate (`tx.version >= 2`) | PARTIAL | BUG-1 |
| G15  | `CalculateSequenceLocks` per-input DISABLE_FLAG skip | PARTIAL | BUG-3 |
| G16  | `CalculateSequenceLocks` zeroes `prevHeights[i]` on DISABLE | **MISSING** | BUG-3 |
| G17  | `CalculateSequenceLocks` TYPE_FLAG dispatch (time vs height) | PRESENT | — |
| G18  | `CalculateSequenceLocks` time path uses MTP at `max(coinHeight-1, 0)` | PRESENT | — |
| G19  | `CalculateSequenceLocks` height: `coinHeight + (seq&MASK) - 1` | PRESENT | — |
| G20  | `CalculateSequenceLocks` time: `coinMTP + ((seq&MASK)<<9) - 1` | PRESENT | — |
| G21  | `CalculateSequenceLocks` no early-skip for coinbase (delegated to caller) | PARTIAL | BUG-5 |
| G22  | `EvaluateSequenceLocks` strict `>=` for height (`MinHeight >= blockHeight`) | PRESENT | — |
| G23  | `EvaluateSequenceLocks` strict `>=` for time (`MinTime >= blockMTP`) | PRESENT | — |
| G24  | `OP_CHECKSEQUENCEVERIFY` gated on `ScriptVerifyCSV` (else NOP) | PRESENT | — |
| G25  | `OP_CHECKSEQUENCEVERIFY` 5-byte ScriptNum with minimal | PRESENT | — |
| G26  | `OP_CHECKSEQUENCEVERIFY` negative operand → error (typed) | PARTIAL | BUG-6 |
| G27  | `OP_CHECKSEQUENCEVERIFY` operand DISABLE_FLAG → NOP (softfork-compat) | PRESENT | — |
| G28  | `CheckSequence` tx.version < 2 → fail | PARTIAL | BUG-2 |
| G29  | `CheckSequence` tx-side DISABLE_FLAG → fail | PRESENT | — |
| G30  | `CheckSequence` type-flag pairing + masked operand `<=` masked tx | PRESENT | — |

Plus 5 wiring/MTP gates (overflow gates for the 30-cell table):

| Gate | Topic | Status | Bug |
|------|-------|--------|-----|
| G31  | `GetMedianTimePast` median of 11 (self + 10 ancestors) | PRESENT | — |
| G32  | `ContextualCheckBlock` BIP-113: post-CSV uses parent MTP | PARTIAL | BUG-4 |
| G33  | `ContextualCheckBlock` pre-CSV uses block.GetBlockTime() | PRESENT | — |
| G34  | ConnectBlock per-tx `SequenceLocks` call (CSV-gated) | PRESENT | — |
| G35  | Mempool `CheckSequenceLocksAtTip` (next-height + tip MTP) | PARTIAL | BUG-7 |

Note: G31–G35 are required for full BIP-68/112/113 wiring coverage;
the matrix has 35 entries to keep G13 (tx.Version width) visible.

## Repro vectors (P0-CDIV)

### BUG-1 — BIP-68 inversion via signed tx.Version

```
Build:    tx with version = 0xFFFFFFFE on wire (BIP-431-style "TRUC"
          high-bit), one input with relative-height lock seq = 5,
          prevHeight = 100.
Core:     uint32(version) = 0xFFFFFFFE → version >= 2 → BIP-68 active.
          CalculateSequenceLocks → nMinHeight = 100 + 5 - 1 = 104.
          EvaluateSequenceLocks(block at height 101) → 104 >= 101 → fail.
          Block containing the tx → REJECTED.
blockbrew: int32(version) = -2 → tx.Version < 2 → BIP-68 SKIPPED.
          lock returned with nMinHeight = -1 → EvaluateSequenceLocks
          → -1 >= 101 → false → PASS.
          Block containing the tx → ACCEPTED.

Fork: blockbrew connects, Core rejects.
```

### BUG-2 — OP_CSV inversion via signed tx.Version

```
Build:    tx with version = 0xFFFFFFFE on wire; spends a P2WSH output
          whose witness script is `<5> OP_CHECKSEQUENCEVERIFY`. Tx
          input nSequence = 5.
Core:     uint32(version) = 0xFFFFFFFE >= 2 → CheckSequence passes
          version gate. Masked comparison: 5 <= 5 → PASS. Script
          evaluates true. Tx → VALID.
blockbrew: int32(version) = -2 → opCheckSequenceVerify line 1143
          `tx.Version < 2` is TRUE → returns ErrCSVFailed. Tx →
          INVALID.

Fork: Core accepts, blockbrew rejects (and bans the peer relaying it).
```

### BUG-3 — DISABLE_FLAG skip without prevHeights zero (latent)

```
Build:    tx v2 with two inputs:
          - input[0]: DISABLE_FLAG set, sequence = 0x80000064.
          - input[1]: height-relative lock, sequence = 1, prevHeight=50.
          prevHeights passed in: [9_999_999, 50].
Core:     tx_verify.cpp:67 zeroes prevHeights[0] = 0 before continue.
          Caller (CalculateLockPointsAtTip) iterates prev_heights to
          compute max_input_height = max(0, 50) = 50.
blockbrew: continues without zeroing. If a caller iterates
          prevHeights afterwards (no such caller today), max would be
          9_999_999.

Latent fork: triggers iff blockbrew gains a LockPoints / max-input
caching path. Filed for record before such a path lands.
```

## Audit framework note

Per the W122 lesson — "audit framework requires byte-exact not
SHA256d-only" — this audit explicitly:

1. Computes Core's `CalculateSequenceLocks` outputs by hand for each
   stress case (10+ stress vectors in the test file).
2. Cross-checks against the blockbrew implementation **byte-/value-
   exactly** (not just "does it return some non-zero value").
3. Tests the version-field type defect with synthetic txs whose wire
   bytes encode `version = 0xFFFFFFFE` — the test deserializes through
   the real `MsgTx.Deserialize` path and asserts the resulting
   in-memory Go value matches Core's `uint32_t` semantics under the
   `< 2` comparison.

This is the same methodology that surfaced W122 BUG-1/BUG-2 in
blockbrew (LSB-first packing + Word64-boundary) where SHA256d
round-trip tests had hidden the bug.

## Out of scope

- BIP-431 TRUC (version=3) policy gating (covered separately in
  `internal/mempool/truc_*` and audited in a prior wave).
- nLockTime BIP-65 OP_CHECKLOCKTIMEVERIFY (audited in W117 / earlier
  CLTV audits).
- Mempool persistence / RBF interaction with sequence locks (W120).
- BIP-9 / BIP-8 CSV deployment activation logic (W117).
- Witness/Taproot CSV semantics (covered in W127 Taproot audit; CSV
  inside Tapscript inherits the same `CheckSequence` semantics).
- `BLOCK_FINAL` / `bad-txns-nonfinal` reject-reason string parity
  (covered in W125 RPC-error-parity audit).
