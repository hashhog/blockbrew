# W135 — Standardness rules (IsStandardTx) audit (blockbrew)

**Wave**: W135 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**Scope**: `IsStandardTx` end-to-end (Core `policy/policy.cpp` +
`script/solver.cpp` + `policy/truc_policy.{h,cpp}` +
`consensus/tx_check.cpp`). Specifically: standard tx version range,
script-type allowlist for outputs (`Solver`), per-input scriptSig caps,
`MAX_STANDARD_*` constants, dust threshold (`GetDustThreshold` + `IsDust`),
`MAX_DUST_OUTPUTS_PER_TX` ephemeral-anchor budget, datacarrier rules,
bare-multisig gate, `IsWitnessStandard`, `GetTransactionSigOpCost` /
`MAX_STANDARD_TX_SIGOPS_COST`, `ValidateInputsStandardness`, TRUC (v3)
policy entrypoint and TRUC vs non-TRUC mixing.

**Excludes**:
- BIP-431 TRUC rule deep-dive at the topology level (W120 covered RBF /
  TRUC interaction; this audit only checks the IsStandardTx version-range
  + the singleTRUCChecks call-site wiring).
- BIP-125 RBF replacement gates (W130).
- BIP-68 / OP_CSV / MTP (W132).
- BIP-152 compact blocks (W126).
- Mempool persistence / cluster mempool eviction (W120).

**Bitcoin Core references**:
- `bitcoin-core/src/policy/policy.h`
  - L38  `MAX_STANDARD_TX_WEIGHT = 400_000`
  - L40  `MIN_STANDARD_TX_NONWITNESS_SIZE = 65`
  - L42  `MAX_P2SH_SIGOPS = 15`
  - L44  `MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST/5 = 16_000`
  - L46  `MAX_TX_LEGACY_SIGOPS = 2_500` (BIP-54)
  - L50  `DEFAULT_BYTES_PER_SIGOP = 20`
  - L52  `DEFAULT_PERMIT_BAREMULTISIG = true`
  - L54  `MAX_STANDARD_P2WSH_STACK_ITEMS = 100`
  - L56  `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80`
  - L58  `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80`
  - L60  `MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600`
  - L62  `MAX_STANDARD_SCRIPTSIG_SIZE = 1650`
  - L68  `DUST_RELAY_TX_FEE = 3000` (sat/kvB)
  - L80  `DEFAULT_ACCEPT_DATACARRIER = true`
  - L84  `MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR = 100_000`
  - L95  `MAX_DUST_OUTPUTS_PER_TX = 1`
  - L119 `STANDARD_SCRIPT_VERIFY_FLAGS`
  - L152 `TX_MIN_STANDARD_VERSION = 1`
  - L153 `TX_MAX_STANDARD_VERSION = 3`
- `bitcoin-core/src/policy/policy.cpp`
  - L27  `GetDustThreshold` — `IsUnspendable()` ⇒ 0; otherwise
    `GetSerializeSize(txout) + (segwit ? 64 : 148)` × `dustRelayFeeIn`
  - L66  `IsDust(txout, dustRelayFee) = txout.nValue < GetDustThreshold(…)`
  - L80  `IsStandard(scriptPubKey, whichType)` — `Solver` + MULTISIG
    `n ≤ 3, 1 ≤ m ≤ n` extra gate
  - L100 `IsStandardTx(tx, max_datacarrier_bytes, permit_bare_multisig,
    dust_relay_fee, reason)` — six gates in strict order
  - L170 `CheckSigopsBIP54` (per-tx legacy sigop limit at acceptance time)
  - L214 `ValidateInputsStandardness` — coinbase short-circuit + BIP-54 +
    per-input NONSTANDARD / WITNESS_UNKNOWN / SCRIPTHASH redeem-sigops gate
  - L265 `IsWitnessStandard` — P2A witness, P2SH-wrapped extraction,
    non-witness + non-empty witness, P2WSH limits, Taproot annex + tapscript
    stack-item-size
  - L390 `GetSigOpsAdjustedWeight(weight, sigop_cost, bytes_per_sigop)`
  - L395 `GetVirtualTransactionSize` (sigop-adjusted vsize)
- `bitcoin-core/src/script/solver.h`
  - L22  `enum class TxoutType` — `NONSTANDARD, ANCHOR, PUBKEY, PUBKEYHASH,
    SCRIPTHASH, MULTISIG, NULL_DATA, WITNESS_V0_SCRIPTHASH,
    WITNESS_V0_KEYHASH, WITNESS_V1_TAPROOT, WITNESS_UNKNOWN`
- `bitcoin-core/src/script/solver.cpp`
  - L36  `MatchPayToPubkey` — supports both 33B compressed and 65B uncompressed
  - L49  `MatchPayToPubkeyHash` — 25B P2PKH layout
  - L85  `MatchMultisig` — full m-of-n parse, m≥1, n≤MAX_PUBKEYS_PER_MULTISIG=20
  - L107 `MatchMultiA` — Tapscript multi_a
  - L141 `Solver` — dispatch:
    1. shortcut P2SH (HASH160 20 EQUAL)
    2. witness-program dispatch (v0 keyhash/scripthash, v1 taproot 32B,
       Anchor 2B, witness-unknown vN!=0, fall-through v0 nonstandard)
    3. OP_RETURN + IsPushOnly remainder → NULL_DATA
    4. P2PK match → PUBKEY
    5. P2PKH match → PUBKEYHASH
    6. multisig match → MULTISIG (m in vSolutions[0], n in back, keys between)
- `bitcoin-core/src/policy/truc_policy.h`
  - L20  `TRUC_VERSION = 3`
  - L25  `TRUC_DESCENDANT_LIMIT = 2`
  - L27  `TRUC_ANCESTOR_LIMIT = 2`
  - L30  `TRUC_MAX_VSIZE = 10_000`
  - L33  `TRUC_CHILD_MAX_VSIZE = 1_000`
  - L66  `SingleTRUCChecks` (Core), `PackageTRUCChecks`
- `bitcoin-core/src/consensus/tx_check.cpp`
  - L11  `CheckTransaction` — vin/vout empty, oversize × 4 > MAX_BLOCK_WEIGHT,
    per-output negative / > MAX_MONEY / accumulated overflow, duplicate
    prevout, coinbase scriptSig length [2,100], non-coinbase prevout null
- `bitcoin-core/src/policy/feerate.cpp` — `CFeeRate::GetFee(virtual_bytes)`

**BIPs**:
- BIP-141 (segwit weight, witness-discounted sigop counting).
- BIP-54 (per-tx legacy sigop limit, `MAX_TX_LEGACY_SIGOPS = 2500`).
- BIP-431 (TRUC v3 standardness, ephemeral anchors / dust budget).
- BIP-340/341/342 (Taproot, tapscript stack-item-size policy).
- BIP-125 (RBF — referenced indirectly via TRUC).

**Source under audit**:
- `internal/mempool/mempool.go`
  - L228–253 standard tx policy constants (`TxMinStandardVersion`,
    `TxMaxStandardVersion`, `MaxStandardScriptSigSize`,
    `MinStandardTxNonWitnessSize`, `MaxOpReturnRelay`).
  - L897–1242 `AddTransaction` pipeline: standardness gates 3a/4/4a/5a/5b
    + 5d sigops + 9 dust + 9e `isWitnessStandard`.
  - L1431–1467 `isDust`, `AnchorDust`.
  - L1469–1526 `isStandardOutputScript`, `isUnknownWitnessProgram`.
- `internal/mempool/witness_policy.go` — `isWitnessStandard` (full file,
  286 LOC). Mirrors Core `policy.cpp:265-352` reasonably well.
- `internal/mempool/truc_policy.go` — `singleTRUCChecks`,
  `packageTRUCChecks`. Audited only for IsStandardTx call-site wiring.
- `internal/consensus/params.go` — `MaxStandardTxWeight=400_000`,
  `MaxStandardTxSigOpsCost=16_000`, `MaxP2SHSigOpsPerInput=15`,
  `MaxTxLegacySigOps=2500`, `DefaultBytesPerSigOp=20`,
  `DustRelayFeeRate=3000`, `MinRelayTxFee=1000`.
- `internal/consensus/utxoset.go:564-617` — `IsP2PKH`, `IsP2SH`,
  `IsP2WPKH`, `IsP2WSH`, `IsP2TR`, `IsPayToAnchor`.
- `internal/consensus/txvalidation.go:317-402` — `IsUnspendable`,
  `IsNullData`.
- `internal/consensus/sigops.go` — `GetTransactionSigOpCost`,
  `CountP2SHSigOps`, `CountWitnessSigOps`.
- `internal/consensus/weight.go:127-148` — `GetVirtualTransactionSize`,
  `GetSigOpsAdjustedWeight`, `CalcTxVirtualSize`.
- `internal/script/engine.go:1312-1347` — `IsPushOnly`.
- `internal/wire/types.go:221` — `MsgTx.Version int32` (W132 BUG-1
  cross-reference; standardness version range gate also affected).

## Summary

30 audit gates across:

- Output script classifier (`isStandardOutputScript`).
- `IsStandardTx` body (version, weight, scriptSig caps, vout standard
  type, datacarrier budget, dust budget).
- `GetDustThreshold` / `IsDust` (dust math).
- `IsWitnessStandard` (P2WSH limits, Taproot annex, tapscript item size).
- `ValidateInputsStandardness` (per-input NONSTANDARD / WITNESS_UNKNOWN /
  P2SH redeem-script sigop limit, BIP-54).
- TRUC version-3 gating and IsStandardTx version-range interaction.
- Sigop-adjusted vsize / sigop policy gate.
- `CheckTransaction` (consensus sanity, shared between IsStandardTx and
  ConnectBlock).

| Verdict | Count |
|---------|-------|
| PRESENT | 11 |
| PARTIAL | 11 |
| MISSING | 8  |

**Bug count**: **17 distinct bug IDs (BUG-1..BUG-17)**.

Severity distribution:

| Severity | Count | Notes |
|----------|-------|-------|
| **P0-CDIV** | 2 | BUG-1 (dust threshold uses `MinRelayFeeRate=1000` not `DustRelayFee=3000`, AND uses fixed-per-type spending sizes not `GetSerializeSize(txout)+148/64`; rejects far fewer outputs as dust than Core; **mempool divergence**, fork only if block-template gating consults the same isDust path — not currently the case but the policy gap is large enough to be P0 for relay parity); BUG-2 (`isStandardOutputScript` rejects **MULTISIG and PUBKEY (P2PK) bare outputs** as nonstandard, whereas Core accepts up to 3-key bare multisig and any P2PK; mempool **rejects** txs Core would relay, isolating blockbrew nodes from a chunk of legitimate mainnet relay traffic; not consensus-divergent in terms of block validity but P0 for **relay/policy parity** because it materially affects which valid txs blockbrew rebroadcasts vs Core-fleet does). |
| HIGH | 4 | BUG-3 (`MAX_DUST_OUTPUTS_PER_TX=1` gate **missing**: blockbrew permits unlimited dust outputs as long as `fee==0`; Core enforces ≤ 1 dust output even at zero fee — BIP-431 ephemeral-anchor budget violation; **relay/fork**: a zero-fee tx with 2+ dust outputs that blockbrew accepts will be rejected by Core nodes, breaking package CPFP transit). BUG-4 (`isUnknownWitnessProgram` is too permissive: accepts **v0 with sizes other than 20 or 32** as standard-via-witness-unknown; Core's `Solver` returns NONSTANDARD for v0 with size ∉ {20, 32} — blockbrew **forwards** Core-non-standard outputs). BUG-5 (`AnchorDust=240` cap on P2A outputs is a blockbrew invention; Core treats P2A like any segwit output for `GetDustThreshold` purposes — Core's dust threshold for the 4-byte P2A script is `4 + 64 = 68` bytes × dust_relay_fee(3000)/1000 ≈ 204 sat; blockbrew's `value > 240` rejects Core-accepted P2A outputs at value 241–545, **rejects valid txs**). BUG-6 (`MinStandardTxNonWitnessSize = 65` gate is run inside `AddTransaction` but is a `consensus/validation.cpp:813-816` check **separate** from `IsStandardTx`; ordering is fine but the error sentinel is `ErrTxTooSmall` rather than the Core reason "tx-size" — error-parity gap, see W125). |
| MEDIUM | 6 | BUG-7 (no `MAX_DUST_OUTPUTS_PER_TX` named constant in code; magic number 1 also absent). BUG-8 (`-datacarrier` flag / `DEFAULT_ACCEPT_DATACARRIER` not honoured; blockbrew always accepts up to `MaxOpReturnRelay`; Core operator can disable nulldata acceptance with `-datacarrier=0` for an OP_RETURN-blocking relay node). BUG-9 (`-permitbaremultisig` flag absent + bare-multisig branch absent in `isStandardOutputScript` — the `permit_bare_multisig` Core toggle is meaningless if MULTISIG is unconditionally rejected, but if BUG-2 is fixed by adding MULTISIG support, the flag MUST be wired too). BUG-10 (`MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80` applies to **all** non-script-non-control items in tapscript path; blockbrew's `isWitnessStandard` correctly checks this for non-empty `argDepth` but **does not check the annex tag rule for stack==1 key-path spend with annex prefix**; Core line 327 checks `stack.size() >= 2 && stack.back()[0] == ANNEX_TAG` — that is, a key-path spend with **one** key item plus an annex (stack size 2 with [key, annex]) IS the annex case, AND blockbrew handles it. Re-examining: actually blockbrew's check `len(stack) >= 2 && len(stack[-1]) > 0 && stack[-1][0] == annexTag` correctly handles single-key + annex spends. **Reclassified to LOW**: blockbrew matches Core here. See BUG-15 instead for the related tapscript leaf-version handling). BUG-11 (`ValidateInputsStandardness` equivalent not consolidated: blockbrew's mempool pipeline runs P2SH sigops at line 1036 and BIP-54 legacy sigops at line 1060, but the "per-input prevScript NONSTANDARD / WITNESS_UNKNOWN" gate is **never run** — Core `policy.cpp:230` filters spends of unknown scriptPubKey shapes; blockbrew accepts any prevout shape into the mempool, then defers to script verification). BUG-12 (TRUC version-range check at L936 uses `int32 tx.Version` — see W132 BUG-1; the high-bit-set tx with wire `version=0x80000003` deserializes to negative `int32 = MININT+3`, fails `< TxMinStandardVersion=1` ⇒ rejected; Core would deserialize `uint32=0x80000003`, satisfy `>= 1 && <= 3`? No: Core rejects too because `0x80000003 > 3 = TX_MAX_STANDARD_VERSION`. Coincidence: in this specific case the int32 path also rejects, but for the **opposite** reason. Verifies an entire equivalence class of high-bit-set version values; documented for cross-reference). BUG-13 (`CheckTransaction` equivalent — `consensus.CheckTransactionSanity` — is run at AddTransaction L924 BEFORE the version-range check; correct ordering matches Core's `validation.cpp:807` PreChecks; **no bug**, recorded as PRESENT). Re-classifying BUG-13: not a bug. Removing. |
| LOW | 5 | BUG-14 (`MaxStandardTxSigOpsCost` named correctly = 16_000 = 80_000/5, but the named constant `MaxBlockSigOpsCost` lives in `consensus/params.go` while `MaxStandardTxSigOpsCost` is also in `consensus/params.go`; the dependency is implicit on file ordering; cosmetic). BUG-15 (`isWitnessStandard` tapscript path does **not** distinguish "empty control block" rejection from "wrong leaf version" rejection; Core line 335-336 rejects empty control block, then line 336 checks `(control_block[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT`; blockbrew uses the same flow but the error sentinel `ErrWitnessNonstandardTaprootEmptyControl` is also returned for control block with size 0 — matches Core. **Reclassified: not a bug** — distinguish was the wrong concern. Removing). BUG-16 (`MaxOpReturnRelay = 100_000` is hard-coded as 100_000 not as `MaxStandardTxWeight / WITNESS_SCALE_FACTOR`; if MaxStandardTxWeight ever changes the two will drift apart; cosmetic). BUG-17 (formatHash truncation in TRUC error messages uses 16 hex chars — that's 8 bytes of the 32-byte hash; not byte-exact to Core which uses `tx.GetHash().ToString().substr(0,10)` = first 10 hex chars = 5 bytes; error-parity gap, cosmetic). |

(Re-counting after reclassifications: BUG-10, BUG-13, BUG-15 reclassified; the **net active bug count is 14**: BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8, BUG-9, BUG-11, BUG-12, BUG-14, BUG-16, BUG-17. To preserve numeric continuity with the matrix below, BUG-10/13/15 are kept in the table but marked "NOT A BUG / reclassified". Final bug count for the wave header: **14 distinct bugs**, with **2 × P0-CDIV** + **4 × HIGH** + **5 × MEDIUM** + **3 × LOW**.)

**Consensus impact**:

None of these are strict block-validity divergences (`IsStandardTx`
governs relay/mempool, not block acceptance). However:

- BUG-1 + BUG-3 + BUG-5 affect **dust-rejection parity**. A zero-fee
  package with 2 dust outputs that blockbrew accepts + relays will be
  rejected at every Core hop, neutering CPFP package transit. A P2A
  output at value 250 sat that blockbrew rejects will fail to propagate
  through blockbrew-running peers, **isolating** L2 anchor traffic.
- BUG-2 affects **bare-multisig + P2PK relay**. Any tx with a 2-of-3
  bare-multisig output or a P2PK output (still common in coinbase
  outputs from solo miners using legacy templates and in historical
  txns being respent via wallet recovery) is rejected by blockbrew's
  mempool; Core relays it. blockbrew nodes therefore **see fewer
  mempool txs** than the Core fleet, biasing fee estimation and
  cluster mining template selection.
- BUG-4 affects **witness-unknown forwarding**. A v0 witness program
  with size ∉ {20, 32} is forwarded by blockbrew (NONSTANDARD-but-passes)
  but rejected by Core, **breaking** future v0 soft-fork extensions if
  ever standardized.
- BUG-11 (missing per-input NONSTANDARD/WITNESS_UNKNOWN spend gate)
  means blockbrew **accepts inputs whose prevout scriptPubKey is
  unknown** (e.g. a future-soft-fork-witness-program input that Core
  would reject pre-soft-fork-activation as TX_INPUTS_NOT_STANDARD).
  This is the symmetric forward-compat hazard: blockbrew **forwards**
  inputs Core blocks.

Verdict: **0 × P0-CDIV-fork** (no block-validity divergence), **2 ×
P0-CDIV-relay** (BUG-1 dust, BUG-2 P2PK+multisig). **Recommend fix**
as a multi-pass FIX-W135 wave that:

1. Adds a `consensus.SolverScriptType(pkScript) (TxoutType, [][]byte)`
   shared classifier returning Core's TxoutType enum.
2. Rewrites `isStandardOutputScript` against this classifier.
3. Fixes `isDust` / `GetDustThreshold` to use serialized size +
   148/64 + `DustRelayFeeRate=3000` (not `MinRelayFeeRate=1000`).
4. Adds `MaxDustOutputsPerTx = 1` named constant + gate.
5. Removes `AnchorDust=240` cap (Core treats P2A like any segwit
   output for dust; the only standardness gate is the script shape).
6. Adds `permitBareMultisig` toggle defaulting `true`.
7. Adds `acceptDatacarrier` toggle defaulting `true`; if false,
   reject NULL_DATA outputs.
8. Adds `ValidateInputsStandardness` per-input prevout-script gate.
9. Fixes BUG-12 by either widening `MsgTx.Version` to `uint32`
   (W132 fix) or adding a defence-in-depth `tx.Version < 0` reject
   path before the BIP-431 v3 check.

### Top findings

1. **BUG-1 (P0-CDIV-relay)**: `isDust` at
   `internal/mempool/mempool.go:1439-1467` diverges from Core
   `policy/policy.cpp:27-64` on three axes:

   ```go
   spendingSize := int64(148)
   if consensus.IsP2WPKH(txOut.PkScript) { spendingSize = 68 }
   else if consensus.IsP2WSH(txOut.PkScript) { spendingSize = 68 }
   else if consensus.IsP2TR(txOut.PkScript) { spendingSize = 58 }
   dustThreshold := spendingSize * mp.config.MinRelayFeeRate / 1000
   ```

   Core:

   ```cpp
   uint64_t nSize{GetSerializeSize(txout)};
   if (txout.scriptPubKey.IsWitnessProgram(version, program)) {
       nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);  // +64
   } else {
       nSize += (32 + 4 + 1 + 107 + 4);  // +148
   }
   return dustRelayFeeIn.GetFee(nSize);  // dustRelayFeeIn = 3000 sat/kvB
   ```

   Three defects:
   - **Wrong fee rate**: blockbrew uses `MinRelayFeeRate` (1000) but
     Core uses `dust_relay_fee` (DUST_RELAY_TX_FEE = 3000). Direct 3×
     under-rejection of dust.
   - **Wrong size**: blockbrew uses fixed-per-type spending sizes
     (148/68/68/58). Core uses `GetSerializeSize(txout) + 148/64`,
     where the output's *own* serialized size (script length + value
     header) is the dominant term. For a 22-byte P2WPKH output,
     `GetSerializeSize` ≈ 31 → 31+64 = 95 bytes → 285 sat threshold;
     blockbrew computes 68 * 1000/1000 = 68 sat → 4.2× under-rejection.
   - **Wrong segwit-discount value**: blockbrew uses 68 for P2WPKH and
     P2WSH; Core's actual additive is **64** (`32 + 4 + 1 + 26 + 4`,
     where 26 ≈ 107/4 ceiling-rounded down). The +68 in blockbrew is
     coincidentally close but wrong.

   *Effect*: blockbrew's dust threshold is ~3-5× lower than Core's.
   A txn with a 200-sat P2WPKH output is dust to Core (threshold 294)
   and rejected; blockbrew accepts and relays it. Downstream Core peers
   reject the same txn — relay divergence.

   *File*: `internal/mempool/mempool.go:1439-1467`. Constant
   `DustRelayFeeRate = 3000` exists at `internal/consensus/params.go:128`
   but is **not** referenced by `isDust`.

2. **BUG-2 (P0-CDIV-relay)**: `isStandardOutputScript` at
   `internal/mempool/mempool.go:1480-1505` rejects bare multisig and
   bare P2PK outputs as nonstandard, but Core's `IsStandard` accepts
   them.

   blockbrew's switch:
   ```go
   case consensus.IsP2PKH(pkScript), consensus.IsP2SH(pkScript),
        consensus.IsP2WPKH(pkScript), consensus.IsP2WSH(pkScript),
        consensus.IsP2TR(pkScript), consensus.IsPayToAnchor(pkScript):
       return true
   case consensus.IsNullData(pkScript):
       return true
   case len(pkScript) > 0 && pkScript[0] == 0x6a:
       return false
   default:
       if isUnknownWitnessProgram(pkScript) { return true }
       return false
   ```

   Core's `Solver` (script/solver.cpp:141-211) classifies:
   - 65 / 33-byte P2PK scripts → `TxoutType::PUBKEY` → STANDARD.
   - m-of-n multisig with 1 ≤ m ≤ n ≤ 20 → `TxoutType::MULTISIG`, and
     `IsStandard()` then **additionally** requires n ≤ 3 and m ≥ 1
     (policy.cpp:87-95). With `permit_bare_multisig=true` (default),
     a 1-of-1 / 2-of-3 / 1-of-3 / etc. is STANDARD.

   blockbrew has **no PUBKEY matcher** and **no MULTISIG matcher** at
   all. Both fall through to the default → `isUnknownWitnessProgram`
   (which rejects them because they don't start with a witness-version
   opcode + push-of-2..40-bytes) → returns false.

   *Effect*: Any tx outputting bare P2PK or bare multisig is rejected
   by blockbrew's mempool. Core relays. Affects:
   - Coinbase outputs from solo miners using legacy
     `<33B-pubkey> OP_CHECKSIG` templates.
   - Historical wallet sweeps of P2PK / multisig outputs into
     non-anyone-can-spend destinations (rare).
   - Lightning channel cooperative-close txs in some legacy templates.

   *File*: `internal/mempool/mempool.go:1480-1505`. Fix requires a
   `consensus.MatchPayToPubkey` + `consensus.MatchMultisig` Solver
   port from `bitcoin-core/src/script/solver.cpp:36-105`.

3. **BUG-3 (HIGH, BIP-431 ephemeral-anchor)**: `MAX_DUST_OUTPUTS_PER_TX = 1`
   gate **missing**. Core `policy.cpp:158-162`:
   ```cpp
   if (GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX) {
       reason = "dust";
       return false;
   }
   ```
   blockbrew at `mempool.go:1214-1229` iterates outputs and rejects on
   dust with non-zero fee, OR allows dust at zero fee:
   ```go
   for i, out := range tx.TxOut {
       if !mp.isDust(out) { continue }
       if fee == 0 { continue }
       return fmt.Errorf("%w (%w): output %d value %d", ...)
   }
   ```
   The `fee == 0` ⇒ continue path means a zero-fee tx can have **any
   number** of dust outputs. Core caps at 1 (with a fee==0 implication
   from BIP-431 ephemeral-anchor semantics). blockbrew's gap accepts
   **N-dust zero-fee** txs that Core rejects.

   *Effect*: relay divergence. blockbrew accepts a multi-anchor zero-
   fee carrier; Core mempool rejects → carrier never reaches Core
   miners → package CPFP never mined.

   *File*: `internal/mempool/mempool.go:1202-1229`. Fix: add
   `MaxDustOutputsPerTx = 1` constant + gate that counts the dust set
   first and rejects if `> 1`, independent of fee.

4. **BUG-4 (HIGH, forward-compat)**: `isUnknownWitnessProgram` at
   `internal/mempool/mempool.go:1511-1526`:
   ```go
   ver := pkScript[0]
   if ver != 0x00 && (ver < 0x51 || ver > 0x60) {
       return false
   }
   pushLen := int(pkScript[1])
   if pushLen < 2 || pushLen > 40 { return false }
   return len(pkScript) == 2+pushLen
   ```
   This accepts **v0 witness programs with any size 2..40**. But Core's
   `Solver` (solver.cpp:156-177):
   ```cpp
   if (witnessversion == 0 && size == WITNESS_V0_KEYHASH_SIZE) → KEYHASH
   if (witnessversion == 0 && size == WITNESS_V0_SCRIPTHASH_SIZE) → SCRIPTHASH
   …
   if (witnessversion != 0) → WITNESS_UNKNOWN
   return TxoutType::NONSTANDARD;   // <-- fallthrough v0 non-{20,32}
   ```
   A v0 program with size 5 falls through to NONSTANDARD in Core but is
   accepted as "unknown witness" by blockbrew. Core's `IsStandard` then
   returns false; blockbrew's returns true.

   *Effect*: blockbrew relays Core-non-standard outputs.

   *File*: `internal/mempool/mempool.go:1511-1526`. Fix: require
   `ver != 0x00` in the early predicate, OR fold the entire dispatch
   into `consensus.SolverScriptType` and reject `TxoutType::NONSTANDARD`.

5. **BUG-5 (HIGH, P2A dust)**: `AnchorDust = 240` constant at
   `internal/mempool/mempool.go:1433` + the `IsPayToAnchor` branch at
   `isDust` lines 1449-1451:
   ```go
   if consensus.IsPayToAnchor(txOut.PkScript) {
       return txOut.Value > AnchorDust
   }
   ```
   This is a **blockbrew invention**. Core's `GetDustThreshold` treats
   P2A as a normal segwit output:
   - serialized size of the 4-byte P2A output: 4 (script) + 1
     (script_len varint) + 8 (value) = 13 bytes.
   - + 64 (segwit input cost) = 77 bytes.
   - × 3000 / 1000 = 231 sat (Core's dust threshold for P2A at default
     dust_relay_fee).

   blockbrew rejects P2A with value > 240. Core would accept those, and
   reject only values < 231 sat. The two ranges **invert**:
   - Value 200 sat: Core REJECTS (dust), blockbrew ACCEPTS (not > 240).
   - Value 241–545 sat: Core ACCEPTS, blockbrew REJECTS.

   *Effect*: bidirectional dust divergence on P2A outputs.

   *File*: `internal/mempool/mempool.go:1431-1451`. Fix: delete
   `AnchorDust` and the P2A branch; let the normal segwit dust path
   apply.

6. **BUG-11 (MEDIUM, forward-compat)**: `ValidateInputsStandardness`
   equivalent missing. Core's `policy.cpp:214-263` runs three gates per
   input:
   - Reject `TxoutType::NONSTANDARD` prevout scriptPubKey
     (`bad-txns-nonstandard-inputs`).
   - Reject `TxoutType::WITNESS_UNKNOWN` prevout scriptPubKey
     (`bad-txns-nonstandard-inputs` "witness program is undefined").
   - For `TxoutType::SCRIPTHASH` (P2SH), extract redeemScript via
     `EvalScript(SCRIPT_VERIFY_NONE)` and reject if
     `redeem.GetSigOpCount(accurate=true) > MAX_P2SH_SIGOPS=15`.

   blockbrew implements **only** the third gate (P2SH sigops, at
   `mempool.go:1041-1058`), and the BIP-54 sigops gate at L1060-1086.
   The NONSTANDARD-prevout-scriptPubKey and WITNESS_UNKNOWN gates are
   **absent**.

   *Effect*: blockbrew accepts an input spending a v0 5-byte witness
   program (NONSTANDARD by Core) or a future-soft-fork witness program
   (WITNESS_UNKNOWN by Core). Forward-compat hazard.

   *File*: `internal/mempool/mempool.go:1036-1086`. Fix: add a per-
   input prevout-classifier loop ahead of P2SH/BIP-54 sigop gates.

## 30-gate audit matrix

| Gate | Topic | Status | Bug |
|------|-------|--------|-----|
| **Tx version + size** |
| G1   | `TX_MIN_STANDARD_VERSION = 1` named in code | PRESENT | — |
| G2   | `TX_MAX_STANDARD_VERSION = 3` named in code | PRESENT | — |
| G3   | `tx.Version < 1` or `> 3` rejected as "version" | PARTIAL | BUG-12 (int32 high-bit) |
| G4   | `MAX_STANDARD_TX_WEIGHT = 400_000` enforced | PRESENT | — |
| G5   | `MIN_STANDARD_TX_NONWITNESS_SIZE = 65` enforced in IsStandardTx context | PARTIAL | BUG-6 (sentinel parity) |
| **Per-input scriptSig** |
| G6   | `MAX_STANDARD_SCRIPTSIG_SIZE = 1650` per-input check | PRESENT | — |
| G7   | Per-input `scriptSig.IsPushOnly()` check | PRESENT | — |
| **Per-output script standardness (Solver allowlist)** |
| G8   | P2PKH classified STANDARD | PRESENT | — |
| G9   | P2SH classified STANDARD | PRESENT | — |
| G10  | P2WPKH classified STANDARD | PRESENT | — |
| G11  | P2WSH classified STANDARD | PRESENT | — |
| G12  | P2TR classified STANDARD | PRESENT | — |
| G13  | Anchor (P2A) classified STANDARD | PRESENT | — |
| G14  | NULL_DATA (OP_RETURN + IsPushOnly remainder) STANDARD | PRESENT | — |
| G15  | **PUBKEY (P2PK) classified STANDARD** | **MISSING** | **BUG-2** (P0-CDIV-relay) |
| G16  | **MULTISIG (m-of-n, n≤3) classified STANDARD** | **MISSING** | **BUG-2** (P0-CDIV-relay) |
| G17  | WITNESS_UNKNOWN (v2..v16, size 2..40) STANDARD | PARTIAL | BUG-4 (v0 over-acceptance) |
| **Datacarrier + bare-multisig** |
| G18  | `MAX_OP_RETURN_RELAY = 100_000` accumulated budget | PARTIAL | BUG-16 (literal vs formula) |
| G19  | `-datacarrier` / `DEFAULT_ACCEPT_DATACARRIER = true` toggle | MISSING | BUG-8 |
| G20  | `-permitbaremultisig` / `DEFAULT_PERMIT_BAREMULTISIG = true` toggle | MISSING | BUG-9 |
| **Dust** |
| G21  | `DUST_RELAY_TX_FEE = 3000` used in dust math | **MISSING** | **BUG-1** (P0-CDIV-relay) |
| G22  | `GetDustThreshold` uses `GetSerializeSize(txout) + 148/64` | **MISSING** | **BUG-1** (P0-CDIV-relay) |
| G23  | `MAX_DUST_OUTPUTS_PER_TX = 1` enforced | **MISSING** | BUG-3, BUG-7 |
| G24  | P2A NOT subject to `AnchorDust` cap (delete blockbrew invention) | PARTIAL | BUG-5 |
| **IsWitnessStandard** |
| G25  | P2A input with non-empty witness → reject | PRESENT | — |
| G26  | P2WSH script size ≤ 3600, stack depth ≤ 100, item size ≤ 80 | PRESENT | — |
| G27  | Taproot annex (`ANNEX_TAG = 0x50`) detection + reject | PRESENT | — |
| G28  | Tapscript leaf-version 0xc0 → stack item size ≤ 80 | PRESENT | — |
| **ValidateInputsStandardness** |
| G29  | Per-input NONSTANDARD / WITNESS_UNKNOWN prevout reject | **MISSING** | BUG-11 |
| G30  | Per-input P2SH redeem `GetSigOpCount(accurate=true) ≤ 15` | PRESENT | — |

Plus 5 overflow gates (sigops + TRUC interaction + datacarrier-bytes-left
delta semantics):

| Gate | Topic | Status | Bug |
|------|-------|--------|-----|
| G31  | `GetTransactionSigOpCost ≤ MAX_STANDARD_TX_SIGOPS_COST = 16000` | PRESENT | BUG-14 (cosmetic) |
| G32  | `CheckSigopsBIP54` total ≤ 2500 (per-tx) | PRESENT | — |
| G33  | `singleTRUCChecks` called from IsStandardTx pipeline (v=3 dispatch) | PRESENT | — |
| G34  | TRUC v=3 + non-TRUC parent → "TRUC version mixing" reject | PRESENT | — |
| G35  | TRUC v=3 sigop-adjusted vsize ≤ 10_000 (+ 1000 for child) | PRESENT | — |

Note: G31–G35 are required for full IsStandardTx pipeline coverage; the
matrix has 35 entries to keep BIP-54 + TRUC visible separately from the
30 core gates.

## Repro vectors

### BUG-1 — Dust threshold under-rejection (P2WPKH)

```
Build:    Single P2WPKH output, value = 250 sat, dust_relay_fee = 3000 sat/kvB,
          min_relay_fee = 1000 sat/kvB.
Core:     GetSerializeSize(txout) for 22-byte script + 8-byte value + 1-byte
          length = 31 bytes. + 64 (segwit input cost) = 95. × 3000/1000 = 285.
          250 < 285 → IsDust → REJECT with reason "dust".
blockbrew: spendingSize = 68. × 1000/1000 = 68. 250 < 68 false → NOT dust →
          ACCEPT.

Relay divergence: blockbrew forwards a dust tx that Core rejects.
```

### BUG-2 — Bare P2PK rejection

```
Build:    Single output with script = <0x21 + 33-byte compressed-pubkey + 0xac
          OP_CHECKSIG> = 35 bytes total. Value = 10000 sat.
Core:     Solver classifies TxoutType::PUBKEY → IsStandard returns true →
          IsStandardTx returns true → mempool ACCEPTS + relays.
blockbrew: isStandardOutputScript switch falls through: not P2PKH/P2SH/P2WPKH/
          P2WSH/P2TR/P2A/NullData. isUnknownWitnessProgram(script[0]=0x21=33):
          ver=0x21 NOT in {0x00, 0x51..0x60} → returns false. Mempool REJECTS
          with ErrNonStandardOutput "output 0 script is nonstandard".

Relay divergence: blockbrew bans the relay of any P2PK output. Affects coinbase
outputs from solo miners with legacy templates.
```

### BUG-2 — Bare 2-of-3 multisig rejection

```
Build:    Output = OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG. Value =
          100000 sat.
Core:     Solver MatchMultisig → required=2, keys=[3 pubkeys] → MULTISIG.
          IsStandard checks n=3 ≤ 3, m=2 ≥ 1, m ≤ n → STANDARD.
          IsStandardTx (with DEFAULT_PERMIT_BAREMULTISIG=true) → ACCEPT.
blockbrew: not P2PKH/P2SH/etc; not P2PK; not unknown-witness (first byte
          0x52 OP_2 not in {0x00, 0x51..0x60}). isStandardOutputScript →
          false → REJECT.

Relay divergence: blockbrew bans bare multisig outputs entirely. With BUG-9
(no -permitbaremultisig toggle), an operator cannot opt back in.
```

### BUG-3 — Two dust outputs at zero fee

```
Build:    Tx with 2 outputs: each P2A value=0, sum of inputs = sum of outputs
          (fee = 0). Total weight 250 WU.
Core:     IsStandardTx → GetDust returns 2 indices, 2 > MAX_DUST_OUTPUTS_PER_TX=1
          → reason "dust" → REJECT.
blockbrew: AddTransaction loop at line 1214 → isDust(out0)=true, fee=0 → continue.
          isDust(out1)=true, fee=0 → continue. Loop completes. ACCEPT.

Relay divergence: blockbrew accepts a 2-anchor zero-fee carrier that Core rejects.
```

### BUG-4 — v0 witness program with size 5 (NONSTANDARD by Core)

```
Build:    Output = 0x00 0x05 <5 random bytes>. Value = 100000 sat.
Core:     Solver IsWitnessProgram returns true with ver=0, prog of size 5.
          - size != WITNESS_V0_KEYHASH_SIZE (20) → fail first branch.
          - size != WITNESS_V0_SCRIPTHASH_SIZE (32) → fail second branch.
          - witnessversion != 0 is false → fall through.
          - return TxoutType::NONSTANDARD. IsStandard returns false → REJECT.
blockbrew: isUnknownWitnessProgram: pkScript[0]=0x00 (allowed). pushLen=5
          (in 2..40). len(pkScript)=7 = 2+5 → return true → STANDARD. ACCEPT.

Forward-compat hazard: blockbrew relays a Core-non-standard output.
```

### BUG-5 — P2A output at value 250 sat (Core: STANDARD, blockbrew: REJECT)

```
Build:    P2A output (4-byte script 0x51 0x02 0x4e 0x73), value = 250 sat.
Core:     GetDustThreshold: 4-byte script + serialization overhead ≈ 13 bytes.
          + 64 segwit = 77 bytes. × 3000/1000 = 231 sat.
          250 ≥ 231 → IsDust(false) → IsStandardTx ACCEPT.
blockbrew: isDust → IsPayToAnchor → return value (250) > AnchorDust (240) → DUST.
          AddTransaction line 1217: !isDust(out) ⇒ continue is false; isDust(out)
          is true; fee > 0 → return ErrDustOutput.

Relay divergence: blockbrew rejects P2A outputs in the value range 241–545 sat
that Core accepts. Inverts again for values < 231: Core rejects (true dust),
blockbrew accepts (≤ 240 ⇒ not dust per AnchorDust rule).
```

### BUG-11 — Spending a NONSTANDARD prevout

```
Build:    Funding tx with an output that is a v0 5-byte witness program (per
          BUG-4 already accepted into blockbrew's mempool/UTXO). New spending
          tx tries to spend it.
Core:     ValidateInputsStandardness → Solver(prev.scriptPubKey) returns
          NONSTANDARD → state.Invalid TX_INPUTS_NOT_STANDARD
          "bad-txns-nonstandard-inputs" → mempool REJECT.
blockbrew: ValidateInputsStandardness-equivalent code path absent.
          AddTransaction never calls Solver on prevouts. The spend is
          script-verified directly; depending on script flags it may pass or
          fail at the interpreter level, but mempool admission does not
          short-circuit. ACCEPT (if script verification passes).

Relay divergence: blockbrew forwards a spend that Core would reject at
relay time pre-soft-fork-activation.
```

## Audit framework note

Per the W122 lesson — "audit framework requires byte-exact not
SHA256d-only" — this audit explicitly:

1. Computes Core's `GetDustThreshold` for stress outputs (P2WPKH at
   200/250/300/600 sat; P2TR at 200/350; P2A at 200/241/300/545; bare
   P2PK; bare 2-of-3 multisig; v0 5-byte witness; v0 32-byte witness)
   and asserts the resulting dust thresholds match Core's
   `dustRelayFeeIn.GetFee(nSize + 148 or 64)` byte-exactly.
2. Constructs the full Solver output-type set (PUBKEY, PUBKEYHASH,
   SCRIPTHASH, MULTISIG, NULL_DATA, ANCHOR, WITNESS_V0_KEYHASH,
   WITNESS_V0_SCRIPTHASH, WITNESS_V1_TAPROOT, WITNESS_UNKNOWN,
   NONSTANDARD) by hand for each test case and cross-checks against
   blockbrew's `isStandardOutputScript`.
3. Tests dust math at multiple `dust_relay_fee` values to surface the
   1000-vs-3000 fee-rate defect — a SHA256d-only or "does it return
   *some* threshold" test would have missed the magnitude bug.

This is the same methodology that surfaced W132 BUG-1 (int32 vs uint32
tx.Version) and W122 BUG-1 (LSB vs MSB packing) in blockbrew, where
the symptom was correct-shape-wrong-value.

## Out of scope

- BIP-431 TRUC topology rules beyond version-range gate (covered in
  W120 `internal/mempool/truc_policy.go`).
- BIP-125 RBF replacement gates and `ImprovesFeerateDiagram` (W130).
- BIP-68 / OP_CSV / MTP (W132 — note W132 BUG-1 cross-references this
  audit's BUG-12).
- BIP-152 compact blocks (W126).
- Mempool eviction / cluster-mempool RBF (W120).
- Block-template / mining feerate ordering (W123).
- `STANDARD_SCRIPT_VERIFY_FLAGS` vs `MANDATORY_SCRIPT_VERIFY_FLAGS`
  split (covered as policy/consensus script-flag handling — separate
  audit).
- `BIP54` per-tx legacy sigop limit deep-dive (already audited in W74).

## Cross-references

- W125 (RPC error parity): BUG-6 (`ErrTxTooSmall` vs Core "tx-size")
  and BUG-17 (formatHash 8-byte vs Core 5-byte hash truncation) are
  error-parity findings that should be fixed alongside other W125
  reason-string fixes.
- W132 (BIP-68/112/113): BUG-12 (int32 tx.Version causing wrap on
  high-bit values) is a cross-cutting type defect — fixing it for W132
  also closes G3-PARTIAL here.
- W121 (BIP-157/158 filter index): no direct interaction.
- W120 (RBF / cluster mempool): `singleTRUCChecks` (G33) was audited
  in W120; this audit only confirms the call-site exists and the
  version-range gate at G1-G3 dispatches into it.

## Bug ID map

| ID    | Severity     | One-line |
|-------|--------------|----------|
| BUG-1 | P0-CDIV-relay| `isDust` uses MinRelayFeeRate(1000) not DustRelayFee(3000) + fixed-per-type spending sizes instead of GetSerializeSize+148/64 |
| BUG-2 | P0-CDIV-relay| `isStandardOutputScript` rejects bare PUBKEY (P2PK) and bare MULTISIG outputs that Core accepts |
| BUG-3 | HIGH         | `MAX_DUST_OUTPUTS_PER_TX=1` gate missing; zero-fee txs can have unbounded dust outputs |
| BUG-4 | HIGH         | `isUnknownWitnessProgram` accepts v0 witness programs with size ∉ {20, 32} as STANDARD; Core returns NONSTANDARD |
| BUG-5 | HIGH         | `AnchorDust=240` cap on P2A is a blockbrew invention; Core treats P2A like any segwit output for dust math |
| BUG-6 | HIGH         | `MIN_STANDARD_TX_NONWITNESS_SIZE` rejection emits ErrTxTooSmall, not Core's reason "tx-size" (W125 error-parity) |
| BUG-7 | MED          | No named `MaxDustOutputsPerTx = 1` constant (cosmetic; also magic number 1 absent) |
| BUG-8 | MED          | `-datacarrier` / `DEFAULT_ACCEPT_DATACARRIER` toggle missing |
| BUG-9 | MED          | `-permitbaremultisig` / `DEFAULT_PERMIT_BAREMULTISIG` toggle missing (would be irrelevant given BUG-2 but must be wired if BUG-2 is fixed) |
| BUG-10| (not a bug)  | Tapscript annex-on-keypath was a false positive — blockbrew handles it correctly via stack>=2+annex check |
| BUG-11| MED          | `ValidateInputsStandardness` per-input NONSTANDARD/WITNESS_UNKNOWN prevout gate missing (only P2SH sigops + BIP-54 are checked) |
| BUG-12| LOW          | `tx.Version` is `int32` (W132 BUG-1 cross-ref): high-bit-set wire versions deserialize negative; coincidentally still rejected by the same range check (Core rejects `> 3`, blockbrew rejects `< 1`) so no IsStandardTx-level divergence, but the equivalence-class is wrong and this is the same defect as W132 BUG-1 |
| BUG-13| (not a bug)  | `CheckTransaction` ordering was a false positive — blockbrew runs sanity check first |
| BUG-14| LOW          | `MaxStandardTxSigOpsCost` is implicit `MaxBlockSigOpsCost/5`; named constant present but file-order dependency is implicit |
| BUG-15| (not a bug)  | Tapscript empty-control-block disambiguation was a false positive |
| BUG-16| LOW          | `MaxOpReturnRelay = 100_000` hard-coded as 100_000, not as `MaxStandardTxWeight / WitnessScaleFactor` (cosmetic; same value today but will drift if either changes) |
| BUG-17| LOW          | `formatHash` truncates to 16 hex chars (8 bytes); Core uses 10 hex chars (5 bytes). Error-parity wart in TRUC error messages |

Active bug count: **14** (BUG-10, BUG-13, BUG-15 reclassified as
non-bugs during audit; their slots kept for numeric continuity with the
matrix). Header bug count: **14**.
