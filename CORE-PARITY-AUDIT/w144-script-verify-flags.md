# W144 — Script-verify flag mux (blockbrew)

**Wave:** W144 — `SCRIPT_VERIFY_*` application + softfork activation.
The bitmask Bitcoin Core assembles per block in `GetBlockScriptFlags`,
the policy-only mempool flags in `STANDARD_SCRIPT_VERIFY_FLAGS`, and
the buried vs. versionbits split.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/script/interpreter.h:47-159` — `SCRIPT_VERIFY_*`
  enum (24 distinct bits, `SCRIPT_VERIFY_NONE` … `SCRIPT_VERIFY_END_MARKER`).
- `bitcoin-core/src/validation.cpp:2250-2289` — `GetBlockScriptFlags`:
  always-on `{P2SH | WITNESS | TAPROOT}`, then `script_flag_exceptions`
  REPLACES that set, then DERSIG / CLTV / CSV / NULLDUMMY are OR-ed on
  via buried deployments.
- `bitcoin-core/src/kernel/chainparams.cpp:85-94, 210-217, 311-316,
  455-460, 538-541` — buried activation heights + `script_flag_exceptions`
  population for mainnet (BIP-16 @ 170,060 + Taproot @ 692,124),
  testnet3 (BIP-16 only).
- `bitcoin-core/src/policy/policy.h:97-135` — `MANDATORY_SCRIPT_VERIFY_FLAGS`
  (consensus subset) and `STANDARD_SCRIPT_VERIFY_FLAGS` (mempool /
  relay; 7 mandatory + 13 policy-only additions).
- `bitcoin-core/src/script/interpreter.cpp:471-602, 1199-1202,
  1917-1998, 605-635` — flag readback sites inside `EvalScript` and
  `VerifyWitnessProgram` (where each bit actually does or does not
  fire).
- `bitcoin-core/src/consensus/tx_verify.cpp:143-162` — sigops-cost
  is **flag-gated** on `SCRIPT_VERIFY_P2SH` and `SCRIPT_VERIFY_WITNESS`.
- `bitcoin-core/src/deploymentstatus.h` — `DeploymentActiveAt`,
  `DeploymentActiveAfter`.

**BIPs:** BIP-16 (P2SH), BIP-65 (CLTV), BIP-66 (DERSIG), BIP-112 (CSV),
BIP-141 (WITNESS / weight), BIP-143 (witness sighash), BIP-147
(NULLDUMMY), BIP-341 / BIP-342 (Taproot / Tapscript).

**Files audited:**
- `internal/consensus/scriptflags.go` — `GetBlockScriptFlags` (consensus,
  block path), `GetStandardScriptFlags` (mempool), `ValidateTransactionScripts`.
- `internal/consensus/chaincfg.go` — `BIP34Height / BIP65Height /
  BIP66Height / CSVHeight / SegwitHeight / TaprootHeight /
  ScriptFlagExceptions` per network.
- `internal/consensus/chainmanager.go:548, 911-930` — flag derivation
  + script-validation pass during `ConnectBlock`.
- `internal/consensus/sigops.go:203-242` — `GetTransactionSigOpCost`
  (no flag parameter).
- `internal/consensus/versionbits.go:155-499` — `GetDeploymentState`,
  `ComputeBlockVersion` (only used by miner; not by `GetBlockScriptFlags`).
- `internal/script/engine.go` — `ScriptFlags` enum and every flag
  readback site (NULLDUMMY, P2SH, WITNESS, CLEANSTACK, DERSIG, LOW_S,
  MINIMALDATA, NULLFAIL, STRICTENC, TAPROOT, CLTV, CSV,
  WITNESSPUBKEYTYPE, DISCOURAGE_UPGRADABLE_NOPS, CONST_SCRIPTCODE,
  DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
  MINIMALIF, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
  DISCOURAGE_UPGRADABLE_PUBKEYTYPE).
- `internal/script/opcodes_impl.go:790-870, 619-730, 850-1020` —
  NULLDUMMY / NULLFAIL / DERSIG / LOW_S / STRICTENC / CONST_SCRIPTCODE /
  WITNESSPUBKEYTYPE / DUPK readbacks inside `opCheckMultiSig`,
  `opCheckSig`, `opCheckSigAdd`.
- `internal/mempool/mempool.go:1528-1551` — `getStandardScriptFlags` /
  `getConsensusScriptFlags`.

---

## Gate matrix (24 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Flag derivation per height | G1: always-on `{P2SH \| WITNESS \| TAPROOT}` seed | **BUG-1** (P0-CDIV): height-gated, no always-on seed |
| 1 | … | G2: exception map REPLACES seed | PASS |
| 1 | … | G3: DERSIG / CLTV / CSV / NULLDUMMY OR-ed back on after exception | **BUG-2** (P0-CDIV): exception short-circuits return |
| 1 | … | G4: buried activations match Core heights | PASS (`chaincfg.go:144-148`) |
| 1 | … | G5: BIP9/versionbits state consulted | **BUG-3** (P3-DEAD): VersionBitsCache used only by miner |
| 2 | P2SH (BIP-16) | G6: flag ON for non-exception blocks | PASS |
| 2 | … | G7: P2SH eval branches in `engine.go:177, 216` | PASS |
| 2 | … | G8: sigops-cost gated on `SCRIPT_VERIFY_P2SH` | **BUG-4** (P3): `GetTransactionSigOpCost` has no flags param |
| 3 | DERSIG (BIP-66) | G9: flag set at `height >= BIP66Height` | PASS |
| 3 | … | G10: strict DER reject inside `opCheckSig` | PASS (`opcodes_impl.go:623-627`) |
| 4 | CLTV (BIP-65) | G11: flag set at `height >= BIP65Height` | PASS |
| 4 | … | G12: `OP_NOP2` → CLTV when flag set, NOP when not | PASS (`engine.go:1187-1191`) |
| 5 | CSV (BIP-112) | G13: flag set at `height >= CSVHeight` | PASS |
| 5 | … | G14: `OP_NOP3` → CSV when flag set, NOP when not | PASS (`engine.go:1193-1197`) |
| 6 | WITNESS (BIP-141) | G15: flag set at `height >= SegwitHeight` | PASS w/ caveat (Core sets always-on; see BUG-1) |
| 6 | … | G16: witness eval branches gated on flag | PASS |
| 6 | … | G17: `CountWitnessSigOps` gated on flag | **BUG-4** (cross-ref) |
| 7 | NULLDUMMY (BIP-147) | G18: flag set with WITNESS at SegwitHeight | PASS (`scriptflags.go:54`) |
| 7 | … | G19: `opCheckMultiSig` reject non-empty dummy | PASS (`opcodes_impl.go:839-842`) |
| 8 | TAPROOT (BIP-341/342) | G20: flag set at `height >= TaprootHeight` | PASS w/ caveat (see BUG-1) |
| 8 | … | G21: v1+32B program → taproot eval | PASS |
| 8 | … | G22: tapscript MINIMALIF consensus | PASS (`engine.go:908-913`) |
| meta | Policy / standard set | G23: `STANDARD_SCRIPT_VERIFY_FLAGS` parity | **BUG-5** (P1): 9 of 13 policy bits missing |
| meta | Policy / standard set | G24: `MANDATORY_SCRIPT_VERIFY_FLAGS` constant | **BUG-6** (P2): not defined, recomputed per call |

---

## BUG-1 (P0-CDIV) — `GetBlockScriptFlags` does NOT seed `{P2SH | WITNESS | TAPROOT}` always-on

**Severity:** P0-CDIV — consensus divergence at the taproot exception
block.

**File:** `internal/consensus/scriptflags.go:15-62`

**Core ref:** `bitcoin-core/src/validation.cpp:2262`

```cpp
script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
const auto it{consensusparams.script_flag_exceptions.find(*Assert(block_index.phashBlock))};
if (it != consensusparams.script_flag_exceptions.end()) {
    flags = it->second;
}
// Then DERSIG / CLTV / CSV / NULLDUMMY are OR-ed on if active.
```

**Description:** Core seeds the flag set with `{P2SH | WITNESS | TAPROOT}`
unconditionally — every block is verified against P2SH, WITNESS, and
TAPROOT rules from the genesis block onward, except for the two
historical violating blocks that are listed in `script_flag_exceptions`.
Modern Core (post commit `d92a8a4`, 2024-Q1) discarded `BIP16Height /
SegwitHeight / TaprootHeight` as flag-gates entirely: those heights
remain in the consensus params for bookkeeping (`MinBIP9WarningHeight`,
deployment-info RPC, version-byte gating) but `GetBlockScriptFlags` no
longer consults them. The two violating blocks (170,060 and 692,124 on
mainnet) are the only places where P2SH or TAPROOT is turned off.

blockbrew, in contrast, treats `SegwitHeight` and `TaprootHeight` as
live gates inside `GetBlockScriptFlags`:

```go
if height >= params.SegwitHeight {
    flags |= script.ScriptVerifyWitness
    flags |= script.ScriptVerifyNullDummy
}
// ...
if height >= params.TaprootHeight {
    flags |= script.ScriptVerifyTaproot
}
```

The practical consequence is small for fully-synced replay (the height
boundary coincides with the buried activation), but the seed is no
longer Core-shaped. The divergence becomes visible on the **taproot
exception block** (mainnet `0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad`,
≈ height 692,124 — post-Taproot-activation height for the
`script_flag_exceptions` to make sense, but actually pre-Taproot
activation since Taproot activated at 709,632). See BUG-2.

**Impact:** Compounding with BUG-2 — the always-on seed is the prerequisite
for the Core invariant "exception map only neuters specific bits, then
DERSIG / CLTV / CSV / NULLDUMMY come back on". Without the seed,
blockbrew's exception-map handling can never reproduce Core's flag set
on the taproot exception block. Also: forward-compat — when Core adds
a hypothetical future "always-on softfork", blockbrew's pattern would
need a 3-line `chaincfg.go` edit per network, while Core gets it for
free via the one-line `flags{...}` literal.

---

## BUG-2 (P0-CDIV) — `script_flag_exceptions` short-circuits the return; DERSIG / CLTV / CSV / NULLDUMMY never OR-ed on

**Severity:** P0-CDIV — direct consensus divergence on the taproot
exception block when replayed from IBD.

**File:** `internal/consensus/scriptflags.go:19-23`

**Core ref:** `bitcoin-core/src/validation.cpp:2263-2289`

```go
if params.ScriptFlagExceptions != nil {
    if overrideFlags, ok := params.ScriptFlagExceptions[blockHash]; ok {
        return overrideFlags
    }
}
```

vs Core:

```cpp
flags = it->second;
// FALL THROUGH — flags get DERSIG / CLTV / CSV / NULLDUMMY OR-ed on below.
if (DeploymentActiveAt(block_index, chainman, Consensus::DEPLOYMENT_DERSIG)) {
    flags |= SCRIPT_VERIFY_DERSIG;
}
// ... CLTV, CSV, NULLDUMMY
return flags;
```

**Description:** When a block hash matches the exception map, Core
*replaces* the always-on seed with the exception's flag set, then
**continues** the function — OR-ing on DERSIG / CLTV / CSV / NULLDUMMY
via the buried-deployment checks. blockbrew **returns immediately**,
producing a strictly smaller flag set than Core.

This affects exactly two mainnet blocks today:

- **BIP-16 exception block 170,060.** Core: seed = NONE → exception
  applies → flags = NONE → no buried deployment yet active (BIP66
  activates at 363,725) → final = NONE. blockbrew: returns NONE
  directly. **Match.**
- **Taproot exception block (hash
  `0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad`).**
  This block sits ABOVE BIP66Height, BIP65Height, CSVHeight,
  SegwitHeight on mainnet. Core: seed = `P2SH|WITNESS|TAPROOT` →
  exception applies → flags = `P2SH|WITNESS` → DERSIG / CLTV / CSV /
  NULLDUMMY OR-ed on → final = `P2SH|WITNESS|DERSIG|CLTV|CSV|NULLDUMMY`.
  blockbrew: returns `P2SH|WITNESS` directly. **DIVERGENCE.**

**Excerpt of mainnet chain params (`chaincfg.go:161-170`):**

```go
ScriptFlagExceptions: func() map[wire.Hash256]script.ScriptFlags {
    m := make(map[wire.Hash256]script.ScriptFlags)
    bip16Ex, _ := wire.NewHash256FromHex("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22")
    m[bip16Ex] = script.ScriptFlags(0) // SCRIPT_VERIFY_NONE
    taprootEx, _ := wire.NewHash256FromHex("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad")
    m[taprootEx] = script.ScriptVerifyP2SH | script.ScriptVerifyWitness
    return m
}(),
```

**Impact:** On replay of the mainnet taproot-exception block,
blockbrew evaluates inputs with **DERSIG / CLTV / CSV / NULLDUMMY off**
where Core evaluates them ON. Any transaction in that block whose
acceptance hinges on DERSIG-laxity (e.g. a non-strict-DER signature)
or NULLDUMMY-laxity would pass blockbrew but fail Core's stricter
gate, producing a chain split at that block. The block was selected
into Core's exception list precisely because of a taproot-specific
violation, so the DERSIG/etc. delta is unlikely to bite in practice —
but the divergence is a strict superset of "exception block flag set"
on Core's side, so any future exception would amplify the gap.

Fix: drop the early `return` and continue into the buried-deployment
OR-on path, matching Core's fall-through.

---

## BUG-3 (P3-DEAD) — `VersionBitsCache` never consulted by `GetBlockScriptFlags`

**Severity:** P3 — fleet-pattern dead-class; harmless today but
encodes the wrong invariant.

**File:** `internal/consensus/versionbits.go:115-149, 155-280`

**Core ref:** `bitcoin-core/src/validation.cpp:2269-2286`
(`DeploymentActiveAt`).

**Description:** blockbrew defines a fully-functioning `VersionBitsCache`
struct with `GetDeploymentState`, `ComputeBlockVersion`,
`getStateStatistics` — 500 LOC of BIP-9 machinery. The only production
use is **`internal/mining/mining.go:157`** (`ComputeBlockVersion` for
the miner's signaling bits). `GetBlockScriptFlags` never calls into
this cache; it uses raw buried-height comparisons.

This is partially correct: post-2018 Core also moved DERSIG / CLTV /
CSV / SEGWIT to **buried** deployments and likewise stopped consulting
the versionbits cache for those four. Taproot, however, is technically
still a versionbits deployment in Core's deployment table, even though
`DeploymentActiveAt` for `DEPLOYMENT_TAPROOT` resolves to the buried
height (`Consensus::DEPLOYMENT_TAPROOT` in `deploymentstatus.h`
short-circuits to `block_index.nHeight >= params.TaprootHeight`).
blockbrew's height-comparison reaches the same answer, so this is
**not a consensus bug** — but the cache is a dead class for
flag-derivation purposes.

**Excerpt (versionbits.go:115-128):**

```go
type VersionBitsCache struct {
    mu    sync.RWMutex
    cache map[cacheKey]DeploymentState
}

func NewVersionBitsCache() *VersionBitsCache {
    return &VersionBitsCache{
        cache: make(map[cacheKey]DeploymentState),
    }
}
```

`grep -rn 'VersionBitsCache\|GetDeploymentState' internal/ | grep -v _test.go`
returns 7 hits, all inside `versionbits.go` itself or the miner.

**Impact:** Bit-rot risk — same fleet pattern as W138's
`DualChainstateManager`. A future audit could naïvely wire `GetDeploymentState`
into `GetBlockScriptFlags` without realising the buried path is the
real one, introducing accidental divergence. Recommended: either keep
the cache as miner-only and rename to `MinerBlockVersionCache`, or
delete the unused `GetDeploymentState`/`getStateStatistics` exports.

---

## BUG-4 (P3) — `GetTransactionSigOpCost` takes no `flags` parameter; counts P2SH + witness sigops unconditionally

**Severity:** P3 — pre-segwit / pre-BIP16 IBD only; current-tip
verification matches Core.

**File:** `internal/consensus/sigops.go:203-242`

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:143-162`

```cpp
int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, script_verify_flags flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;
    if (tx.IsCoinBase()) return nSigOps;
    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        // ...
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, tx.vin[i].scriptWitness, flags);
    }
}
```

vs blockbrew (`sigops.go:214-242`):

```go
func GetTransactionSigOpCost(tx *wire.MsgTx, utxoView UTXOView) int64 {
    // ...
    cost += int64(CountP2SHSigOps(tx, utxoView))    // unconditional
    cost += int64(CountWitnessSigOps(tx, utxoView)) // unconditional
    return cost
}
```

**Description:** Core's sigops-cost function takes the flag set and
**skips** P2SH-redeem-script sigops when `SCRIPT_VERIFY_P2SH` is off,
and skips witness sigops when `SCRIPT_VERIFY_WITNESS` is off.
blockbrew always counts both. Same divergence inside
`chainmanager.go:801-802` in `ConnectBlock`'s per-tx sigops loop —
both `CountP2SHSigOps` and `CountWitnessSigOps` fire regardless of
flags.

**Impact:** Pre-BIP16-activation blocks: nobody minted P2SH outputs,
so `IsP2SH(utxo.PkScript)` returns false in `CountP2SHSigOps:260`,
and the loop counts zero anyway. Pre-segwit: nobody minted witness
outputs, ditto. The divergence is detectable only on a synthetic
chain where some operator builds a pre-segwit block containing a
P2SH-shaped output (which Core would treat as anyone-can-spend and
not as a redeem-script container). On real Bitcoin history, this is
unreachable.

Mempool path: `validateScriptsLocked` calls `VerifyScript` per input
(not `GetTransactionSigOpCost`), but `GetSigOpCountForTx` /
`txAcceptCheck` (sigop policy gate) also call `GetTransactionSigOpCost`
without flags. At current tip (segwit + BIP16 both active for years),
this is a no-op.

Fix: thread `flags` through `GetTransactionSigOpCost` and gate
`CountP2SHSigOps` / `CountWitnessSigOps` accordingly. Mirrors Core
behaviour and is forward-compatible with any future "consensus
sigops-cost rule" softfork.

---

## BUG-5 (P1) — `GetStandardScriptFlags` is missing 9 of 13 Core `STANDARD_SCRIPT_VERIFY_FLAGS` policy bits

**Severity:** P1 — mempool/relay policy divergence; relayed txns that
Core would reject as non-standard pass blockbrew's mempool.

**File:** `internal/consensus/scriptflags.go:71-84`

**Core ref:** `bitcoin-core/src/policy/policy.h:119-132`

```cpp
static constexpr script_verify_flags STANDARD_SCRIPT_VERIFY_FLAGS{
    MANDATORY_SCRIPT_VERIFY_FLAGS |
    SCRIPT_VERIFY_STRICTENC |
    SCRIPT_VERIFY_MINIMALDATA |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
    SCRIPT_VERIFY_CLEANSTACK |
    SCRIPT_VERIFY_MINIMALIF |
    SCRIPT_VERIFY_NULLFAIL |
    SCRIPT_VERIFY_LOW_S |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
    SCRIPT_VERIFY_CONST_SCRIPTCODE |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE};
```

vs blockbrew (`scriptflags.go:71-84`):

```go
func GetStandardScriptFlags(height int32, params *ChainParams, blockHash wire.Hash256) script.ScriptFlags {
    flags := GetBlockScriptFlags(height, params, blockHash)
    if height >= params.BIP66Height {
        flags |= script.ScriptVerifyStrictEncoding
    }
    if height >= params.SegwitHeight {
        flags |= script.ScriptVerifyNullFail
        flags |= script.ScriptVerifyWitnessPubKeyType
    }
    return flags
}
```

**Description:** Core's `STANDARD_SCRIPT_VERIFY_FLAGS` is a compile-time
constant — every bit is **unconditionally** added on top of the
mandatory consensus set, regardless of block height. blockbrew adds
only 3 of the 13 policy bits, and gates two of them on height
(STRICTENC at BIP66Height, NULLFAIL + WITNESS_PUBKEYTYPE at
SegwitHeight). The 10 bits missing or mis-gated are:

| Core flag | blockbrew status |
|-----------|------------------|
| `MINIMALDATA` | **missing** in mempool path |
| `DISCOURAGE_UPGRADABLE_NOPS` | **missing** |
| `CLEANSTACK` | **missing** |
| `MINIMALIF` (witness v0 policy) | **missing** |
| `LOW_S` | **missing** |
| `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` | **missing** |
| `CONST_SCRIPTCODE` | **missing** |
| `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` | **missing** |
| `DISCOURAGE_OP_SUCCESS` | **missing** |
| `DISCOURAGE_UPGRADABLE_PUBKEYTYPE` | **missing** |
| `STRICTENC` | gated on `>= BIP66Height` (Core: always) |
| `NULLFAIL` | gated on `>= SegwitHeight` (Core: always) |
| `WITNESS_PUBKEYTYPE` | gated on `>= SegwitHeight` (Core: always) |

Each individual flag IS defined in the engine (`engine.go:64-88`) and
has a readback site somewhere in `opcodes_impl.go` / `engine.go`. So
the engine WOULD enforce these rules if the mempool composed them
into the flag set — but the mempool never does.

**Excerpt of engine flag bits (`script/engine.go:64-88`):**

```go
ScriptVerifyMinimalData    ScriptFlags = 1 << 5  // Minimal push encodings
ScriptVerifyDiscourageUpgradableNops ScriptFlags = 1 << 14
ScriptVerifyConstScriptCode          ScriptFlags = 1 << 15
ScriptVerifyDiscourageOpSuccess                ScriptFlags = 1 << 16
ScriptVerifyDiscourageUpgradableWitnessProgram ScriptFlags = 1 << 17
ScriptVerifyMinimalIf                          ScriptFlags = 1 << 18
ScriptVerifyDiscourageUpgradableTaprootVersion ScriptFlags = 1 << 19
ScriptVerifyDiscourageUpgradablePubKeyType     ScriptFlags = 1 << 20
```

`grep -rn 'ScriptVerifyMinimalData\|ScriptVerifyCleanStack\|ScriptVerifyLowS\|ScriptVerifyMinimalIf\|ScriptVerifyDiscourageUpgradableNops\|ScriptVerifyDiscourageOpSuccess\|ScriptVerifyDiscourageUpgradablePubKeyType\|ScriptVerifyConstScriptCode\|ScriptVerifyDiscourageUpgradableTaprootVersion\|ScriptVerifyDiscourageUpgradableWitnessProgram\|ScriptVerifySigPushOnly' internal/ | grep -v _test.go`
returns **zero** production sites that compose these into a flag set.
The engine readbacks fire only when a test sets the flag manually.

**Impact:** A peer connected to blockbrew can relay txns that violate
any of these 10 standard rules — non-minimal push encodings, dirty
stack after eval, high-S signatures, non-minimal IF arguments,
`OP_CODESEPARATOR` in legacy script, OP_SUCCESSx in tapscript,
unknown taproot leaf versions, unknown witness program versions — and
blockbrew accepts them into its mempool, fee-bumps them, mines them
into its template. Core nodes downstream drop the same txn at the
mempool gate as non-standard, so the relay graph fragments. Mining-
wise blockbrew's templates would carry txns that Core miners refuse;
no miner-money-loss because the txns ARE consensus-valid, but the
relay-failure makes blockbrew's mempool less aligned with the rest
of the network.

This is the classic **fleet "advertise-without-honour" pattern**: the
engine fully implements the rule, the flag bit is defined and
exported, but the rule never enters the policy mask. Compare W134
fRelay-parsed-but-ignored, W136 feefilter-never-sends, W137
duplicate-key-detector-defined-but-not-called.

Fix: define a `StandardScriptVerifyFlags` constant in
`scriptflags.go` mirroring Core's `STANDARD_SCRIPT_VERIFY_FLAGS`, OR
each bit on at line 84, and audit-trail the policy fork against
`policy.h` going forward.

---

## BUG-6 (P2) — No `MANDATORY_SCRIPT_VERIFY_FLAGS` / `STANDARD_SCRIPT_VERIFY_FLAGS` constants; mask recomputed per call

**Severity:** P2 — maintainability / drift hazard.

**File:** `internal/consensus/scriptflags.go` (whole file)

**Core ref:** `bitcoin-core/src/policy/policy.h:105-135`

**Description:** Core defines `MANDATORY_SCRIPT_VERIFY_FLAGS` and
`STANDARD_SCRIPT_VERIFY_FLAGS` as `static constexpr` masks. Any
mempool or block-acceptance code path can refer to the constant
directly — there is exactly one definition site, one source of
truth for "what's mandatory vs. policy". blockbrew recomputes the
mask inside `GetBlockScriptFlags` and `GetStandardScriptFlags`
on every call; there is no compile-time mask.

The recompute is necessary in `GetBlockScriptFlags` because of the
exception map + buried-deployment merging. But `GetStandardScriptFlags`
adds a small, fixed set of policy bits — Core captures that delta
as `STANDARD_NOT_MANDATORY_VERIFY_FLAGS`
(`policy.h:135 = STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS`).
blockbrew has no equivalent.

**Impact:** Audit fatigue. Every new policy bit Core adds requires
two manual edits in blockbrew (one in `engine.go`, one in
`scriptflags.go`); a missed edit is the BUG-5 failure mode.
Compile-time constants would make the drift visible in a single
file diff.

Fix: introduce package-level `MandatoryScriptVerifyFlags` /
`StandardScriptVerifyFlags` constants; have the height-gated
`GetStandardScriptFlags` OR them on top of `GetBlockScriptFlags`.

---

## BUG-7 (P2) — `ScriptFlagExceptions` lookup uses incomplete map; testnet4 / signet / regtest get `nil` instead of empty-map sentinel

**Severity:** P2 — defensive / consistency.

**File:** `internal/consensus/chaincfg.go:308-355` (regtest),
`:360-425` (signet), `:436-503` (testnet4)

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:301-510`
(testnet4 / signet have no `script_flag_exceptions.emplace`; map is
default-constructed empty).

**Description:** Core uses a `std::map` which is empty by default —
`.find()` on it always returns `.end()`. blockbrew uses
`map[wire.Hash256]script.ScriptFlags`, which is **nil** when not
explicitly initialised. `scriptflags.go:19` guards with
`if params.ScriptFlagExceptions != nil`, so this is functionally
correct, but the three networks (regtest, signet, testnet4) have
ZERO sentinel for "explicitly empty exception map".

`grep 'ScriptFlagExceptions' chaincfg.go` confirms only mainnet (line
161) and testnet3 (line 262) initialise the map. The other three
networks leave the field nil.

**Impact:** Defensive footgun — a future refactor that does
`params.ScriptFlagExceptions[hash]` (panic on nil read is safe in
Go but `nil != make(map, 0)` for serialisation-style comparisons)
would surface here. Mirror Core: always initialise to empty map.

---

## BUG-8 (P3) — `executeWitnessProgram` rejects `version > 16` inside the `default` case, but `ExtractWitnessProgram` already bounds version to 0-16

**Severity:** P3 — dead defensive branch.

**File:** `internal/script/engine.go:317-326`

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1992-1997`

```go
default:
    // Future witness versions are anyone-can-spend (for forward compatibility)
    if e.flags&ScriptVerifyWitness != 0 && version > 16 {
        return ErrWitnessProgram
    }
    if e.flags&ScriptVerifyDiscourageUpgradableWitnessProgram != 0 {
        return ErrWitnessProgram
    }
    return nil
```

**Description:** `ExtractWitnessProgram` (`engine.go:1281-1310`)
returns version in `{0, 1, …, 16}` (via `OP_0` or `OP_1`…`OP_16`),
or `-1` for non-witness. The caller switches on `case 0`, `case 1`,
`default`. The `default` arm therefore handles versions 2-16
exclusively. The `version > 16` reject inside that arm is **unreachable**.

Compare Core (`interpreter.cpp:1992-1997`): no such version-bound
reject; the discourage-policy reject is the only gate. Core trusts
its `ExtractWitnessProgram` analogue (`script.cpp:IsWitnessProgram`)
to bound the version.

**Impact:** Dead defensive code; no consensus effect. Latent
maintenance hazard if `ExtractWitnessProgram` is ever loosened to
accept versions > 16 (e.g. for an exotic test fixture) — the
dead branch would silently become active.

---

## BUG-9 (P3) — `ValidateTransactionScripts` does not pass `prevOuts` to single-input verifies for taproot context

**Severity:** P3 — implementation; not a flag-mux bug per se but
surfaces during flag composition.

**File:** `internal/consensus/scriptflags.go:107-127`

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:VerifyScript`
+ `bitcoin-core/src/consensus/tx_verify.cpp`

**Description:** The `ValidateTransactionScripts` helper (which is
called from the block-validation path) DOES pass `prevOuts`
correctly. But `mempool.go:1576-1580` calls `script.VerifyScript`
with `prevOuts` built from the **mempool's lookup view** rather than
threading the same `prevOuts` slice into all inputs. Inputs from a
parent in the same package may not have a UTXO entry yet (pending
mempool acceptance) — the per-input lookup returns `nil` and the tx
is rejected as missing-input. Core's `CheckInputScripts` has the same
shape, so this is **not** a divergence at the API level — but the
mempool path doesn't compose flags from a single source-of-truth, so
the gap is wider than at first glance.

**Impact:** Minor — flagged for clarity around how flags flow from
`GetStandardScriptFlags` into per-input verifies.

---

## BUG-10 (P3-DEAD) — `ScriptVerifySigPushOnly` defined and readback wired, never composed into any flag set

**Severity:** P3 — dead flag bit.

**File:** `internal/script/engine.go:77, 172-174`,
`internal/consensus/scriptflags.go` (not referenced)

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:2012-2014`
(VerifyScript prelude), `bitcoin-core/src/policy/policy.h`
(SIGPUSHONLY is **not** in `STANDARD_SCRIPT_VERIFY_FLAGS`).

**Description:** `ScriptVerifySigPushOnly` is defined at bit 12 and
read back at `engine.go:172-174`. Core also defines
`SCRIPT_VERIFY_SIGPUSHONLY` but does NOT include it in either
`MANDATORY` or `STANDARD` flag sets — the bit is used internally for
P2SH (which has its own implicit push-only check). blockbrew has the
flag bit but never sets it anywhere in `consensus/` or `mempool/`,
matching Core's STANDARD set. The readback at line 172-174 is
therefore dead for production traffic; it exists only to allow tests
to manually toggle the bit.

**Impact:** No bug. Documented here for completeness — this is the
ONE flag bit in blockbrew's engine that matches Core's "defined but
deliberately unused in default sets" pattern.

---

## BUG-11 (P3) — `OP_NOP1, OP_NOP4..OP_NOP10` discourage-upgradable-NOPs path does NOT cover OP_NOP2 / OP_NOP3 when CLTV / CSV flag is off

**Severity:** P3 — policy edge; aligned with Core.

**File:** `internal/script/engine.go:1002-1007, 1187-1197`

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:522-527, 561-566, 595-601`

**Description:** When the CLTV (resp. CSV) flag is off, Core treats
`OP_NOP2` (resp. `OP_NOP3`) as a plain NOP — falls through to the
NOP path. The `OP_NOP1, OP_NOP4..OP_NOP10` `case` block at line 595
then fires `DISCOURAGE_UPGRADABLE_NOPS` only for those opcodes that
fall through — i.e., when CLTV/CSV is off, OP_NOP2/3 do NOT fire
the discourage. blockbrew structures the dispatch identically:
`OP_CHECKLOCKTIMEVERIFY` (line 1187-1191) returns `nil` when the
flag is off (treating it as a NOP), and OP_NOP2 never reaches the
`OP_NOP1, OP_NOP4..OP_NOP10` `case` (line 1002-1007). Behaviourally
**matches Core**.

**Impact:** No bug. Documented because the W144 brief calls out
this exact corner. Both Core and blockbrew silently NOP without
firing the discourage when the corresponding consensus flag is
disabled — meaning a hypothetical post-activation block carrying
`OP_NOP2` in a tx where `SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY` is set
will be evaluated as CLTV; but if a policy node has the flag off
locally for some reason, both nodes will treat it as a plain NOP
without raising the discourage error.

---

## BUG-12 (P3) — `consensusparams.script_flag_exceptions` typed `map` lookup is O(1) in Go but doesn't fingerprint missing entries

**Severity:** P3 — observability.

**File:** `internal/consensus/scriptflags.go:19-23`

**Description:** Core's `find()` on `std::map<uint256, …>` returns
an iterator end-of-map sentinel; blockbrew uses the comma-ok form
on `map[...]…`. Same correctness. But Core logs (via debug.log) any
unexpected exception map miss / hit via deployment-info RPC;
blockbrew has no equivalent. Adding a per-block trace would surface
silent BUG-2-style divergences (e.g., a hash mismatch between mainnet
chain params and the actual replayed history).

**Impact:** Low — observability only.

---

## BUG-13 (P3) — `ScriptVerifyStrictEncoding` is gated on `>= BIP66Height` in `GetStandardScriptFlags`, but Core's `STRICTENC` is a policy bit always-on

**Severity:** P3 — policy gating mis-aligned with Core (BUG-5 sub-case).

**File:** `internal/consensus/scriptflags.go:75-77`

**Core ref:** `bitcoin-core/src/policy/policy.h:119-132`

**Description:** Core's `STANDARD_SCRIPT_VERIFY_FLAGS` includes
`SCRIPT_VERIFY_STRICTENC` unconditionally. blockbrew gates it on
`height >= BIP66Height`. For chain tips at any current network this
is always true (mainnet > 363,725 since 2015). For regtest at height
0 (or testnet at very early genesis), Core enforces STRICTENC in
mempool relay, blockbrew does not. Same shape as the NULLFAIL /
WITNESS_PUBKEYTYPE gates immediately below it.

**Impact:** Regtest mempool standardness differs from Core's on the
first ~few blocks; vanishes once `tip.Height >= BIP66Height` (1 on
regtest, 1 on signet, etc.). Subsumed by BUG-5.

---

## BUG-14 (P3) — `engine.go:1002-1007` `DISCOURAGE_UPGRADABLE_NOPS` reject branches on a fresh error allocation instead of a sentinel

**Severity:** P3 — error-shape (matches Core's behaviour but
emits a non-`Err…` package error which is harder for callers to
distinguish from `ErrScriptFailed`).

**File:** `internal/script/engine.go:1004-1006`

**Excerpt:**

```go
case OP_NOP1, OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10:
    if e.flags&ScriptVerifyDiscourageUpgradableNops != 0 {
        return errors.New("discouraged upgradable NOP")
    }
    return nil
```

**Description:** Every other engine reject in `engine.go` /
`opcodes_impl.go` uses a package-level sentinel (`ErrNullFail`,
`ErrNullDummy`, `ErrSigFindAndDelete`, `ErrDiscourageUpgradablePubKeyType`,
`ErrDiscourageUpgradableTaprootVersion`, etc.). The NOP-discourage
arm bare-allocates a string error — RPC `validateblock` callers
cannot match against `errors.Is(err, ErrDiscourageUpgradableNops)`
because the sentinel doesn't exist.

**Impact:** Negligible runtime — this flag is mempool-policy only,
and BUG-5 means it's never set in production blockbrew anyway. Once
BUG-5 is fixed, this will become a P2 ergonomics issue.

---

## BUG-15 (P3) — `executeTaproot` path enforces `MaxStackSize` BEFORE the leaf-version dispatch, so non-tapscript leaves that exceed the limit reject instead of forward-compat-succeeding

**Severity:** P3 — subtle order-of-checks divergence.

**File:** `internal/script/engine.go:546-555` (leaf-version gate),
`:563-569` (stack-size check)

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1981-1989`

**Description:** Core executes the tapleaf-hash + commitment
verification, then `if (control[0] & TAPROOT_LEAF_MASK) ==
TAPROOT_LEAF_TAPSCRIPT)` runs `ExecuteWitnessScript` (which is
where `MAX_STACK_SIZE` would be checked); for an unknown leaf
version, Core returns either `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`
or `set_success(serror)` immediately — it never touches the stack-
size or per-element-size guards for unknown leaf versions.

blockbrew checks the leaf version at line 550 (and short-circuits
correctly), so the stack-size check at line 563-569 only runs for
tapscript. **No bug.** Documented because the W144 brief calls
this out as a common dead-code site. Mirrors Core.

**Impact:** No bug.

---

## Cross-cuts with prior waves

- **W127 (Taproot):** the leaf-version dispatch and tapscript
  MINIMALIF rules cross-reference here; BUG-15 documents the alignment.
- **W137 (PSBT):** PSBT signs rely on `STANDARD_SCRIPT_VERIFY_FLAGS`
  for mempool acceptance previews; BUG-5 compounds with PSBT signers
  that exit without warning on policy-rejected outputs.
- **W138 (assumeUTXO):** background validator re-applies the script
  flags via `GetBlockScriptFlags`; BUG-2 compounds with the assumeUTXO
  replay path on mainnet when the taproot exception block is in
  the replay window.
- **W143 (block validation):** the sigops-cost path in `ConnectBlock`
  is the only consumer of `GetTransactionSigOpCost`; BUG-4 lives
  on that boundary.

---

## Fleet-pattern smell

1. **"Defined-exported-readback-but-never-composed" (W134 / W136
   fleet pattern):** BUG-5 is the cleanest instance to date — 9 of
   13 policy bits have the bit defined in `script/engine.go`, the
   readback site wired in `script/opcodes_impl.go`, and zero
   production composition site. The engine fully implements
   MINIMALDATA / CLEANSTACK / LOW_S / MINIMALIF / etc., but the
   mempool never sets any of them. Same shape as W134's fRelay
   parsed-but-ignored and W136's feefilter never-sends-in-production.
   blockbrew accumulates this pattern at every flag boundary.

2. **"Exception map short-circuit elides Core's fall-through" (NEW —
   W144-specific):** BUG-2 — blockbrew's exception map RETURNs the
   override flag set immediately, where Core's exception map
   REPLACEs the seed but then OR-s on buried-deployment bits.
   Subtle: the override is **subtractive** from the always-on seed
   in Core's mental model, **terminal** in blockbrew's. A two-line
   `// FALL THROUGH` could close the divergence; the fact that nobody
   has noticed suggests testing doesn't replay the taproot-exception
   block at all (regtest doesn't have one; mainnet replay from
   genesis is too slow to be in CI).

3. **"Buried + always-on hybrid encoded as height-gating" (NEW —
   W144-specific):** BUG-1 — Core seeds `{P2SH | WITNESS | TAPROOT}`
   always-on and uses the exception map for the two violating
   blocks. blockbrew uses pure height-gating, which is **almost**
   isomorphic on real Bitcoin history but loses the always-on seed
   semantics. Compare W132 OP_CSV-no-op-for-62k-blocks (haskoin) —
   same class of "rule-application differs by a small height window"
   bug, but here the gap is the two specific exception blocks rather
   than a height window.

4. **"Versionbits cache as miner-only dead-class" (W138 / W139
   fleet pattern extension):** BUG-3 — `VersionBitsCache` is 500
   LOC of BIP-9 machinery used by the miner only. The flag-derivation
   path bypasses it entirely. Compare W138's `DualChainstateManager`
   and W139's `unconfTxs` buffers — defined, plumbed, never read on
   the production consensus path.

5. **"Mandatory + Standard not constants" (NEW — W144 architectural):**
   BUG-6 — Core has compile-time mask constants; blockbrew recomputes
   per call. The structural absence is the root cause of BUG-5's
   drift: there's no diff-able "source of truth" for what's in the
   standard set, so policy bits added to Core in 2022+ never made
   it into blockbrew.

6. **Three "defined-but-unread" instances cross-checked with the
   W138 / W141 audits:** BUG-3 (`VersionBitsCache`), BUG-8
   (`version > 16` dead reject), BUG-10 (`ScriptVerifySigPushOnly`
   never composed) — all the same shape. The fleet has been
   accumulating this pattern at every flag-boundary for 5+ waves
   now. A simple linter that flags every `ScriptVerify…` bit not
   appearing in `scriptflags.go` would have surfaced BUG-5 + BUG-10
   immediately.
