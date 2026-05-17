# W130 — BIP-125 RBF feebumper Rule 3 audit (blockbrew)

filed BUG-1 .. BUG-13 (incrementalRelayFee.GetFee(maxTxSize) missing,
WALLET_INCREMENTAL_RELAY_FEE missing, PreconditionChecks largely missing,
MarkReplaced missing, max_tx_fee cap missing, Rule 2 m_min_depth absent,
combined_bump_fee missing, mempool_min_fee check missing, two RBF gates
duplicated in Rule 3 enforcement path, naming/string drift, and a fee-rate
float-comparison sharp edge inherited from W129 BUG-3).

## Summary

**Bug count**: **13 distinct bug IDs** (BUG-1 .. BUG-13).

| Severity   | Count | Notes |
|------------|-------|-------|
| P0-CDIV    | 0     | (No standalone *consensus* divergence — feebumper is wallet/relay policy only, but multiple Rule 3 violations would allow a wallet to construct replacements that Core mempool would reject.) |
| HIGH       | 5     | BUG-1 minTotalFee formula missing entirely (no `old_fee + incrementalRelayFee.GetFee(vsize)` check); BUG-2 WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB floor missing — auto-bump uses fixed +1 sat/vB (1000 sat/kvB) which is below Core's wallet floor; BUG-4 PreconditionChecks (5 sub-checks) absent; BUG-5 max_tx_fee cap absent — bumper can spend unlimited fee; BUG-13 mempool_min_fee gate absent — bumper can produce a tx the local mempool will reject. |
| MED        | 4     | BUG-3 strictly-greater `req.FeeRate <= origFeeRate` rejection ignores the Core "+1 sat increment to origFeeRate" baseline; BUG-6 MarkReplaced + replaces_txid / replaced_by_txid wallet bookkeeping absent; BUG-7 combined_bump_fee for unconfirmed parent inputs absent; BUG-8 Rule 2 "no new unconfirmed inputs" not enforced at wallet layer (bumper can't add inputs at all, but the helper has no input-add code and no `m_min_depth` guard for a future extension). |
| LOW        | 4     | BUG-9 `t.Errorf` vs `t.Fatalf` inconsistency in existing BumpFee tests masks cascading failures; BUG-10 RPC `bumpfee` error message string drift vs Core; BUG-11 `signTx` re-signs from scratch — wallet sets witness afresh but never clears the original witness on the supplied `req.OrigTx` (forensic only; not a bug today); BUG-12 the BumpFee `+1 sat/vB` default-bump comment claims it matches Core's "+1 sat" feerate increment but the implementation rounds up via `ceil(vsize)` which is fee-amount, not feerate. |

## 30-gate audit matrix

| Gate | What the gate asserts | Status | Bug |
|------|----------------------|--------|-----|
| G1 | `BIP125RBFSequence == 0xFFFFFFFD` constant present | PASS | — |
| G2 | `signalsRBF(tx)` exists in mempool layer | PASS | — |
| G3 | BumpFee rejects tx with no RBF-signaling inputs (`ErrBumpFeeNoRBFSignal`) | PASS | — |
| G4 | BumpFee preserves nSequence ≤ MAX_BIP125_RBF_SEQUENCE in replacement | PASS | — |
| G5 | Rule 3: replacement_fees ≥ original_fees enforced (mempool path) | PASS | — (mempool: `checkRBFLocked` gate 6a — newFee < totalConflictingFee) |
| G6 | Rule 3 precise: feebumper layer enforces `new_fee ≥ old_fee + incrementalRelayFee.GetFee(maxTxSize)` | **MISSING** | BUG-1 |
| G7 | WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB constant used (wallet floor higher than node) | **MISSING** | BUG-2 |
| G8 | BumpFee auto-mode uses `max(node_incremental_relay_fee, wallet_incremental_relay_fee)` not a hard-coded +1 sat/vB | **MISSING** | BUG-2 |
| G9 | `req.FeeRate <= origFeeRate` is rejected with Rule-4-aware message (must beat origFeeRate + incrementalRelayFee/kvB) | PARTIAL | BUG-3 |
| G10 | Rule 4: additional_fees ≥ incrementalRelayFee × replacement_vsize (mempool path) | PASS | — (mempool: gate 6b) |
| G11 | PreconditionChecks: descendants in wallet rejected | **MISSING** | BUG-4 |
| G12 | PreconditionChecks: descendants in mempool rejected | **MISSING** | BUG-4 |
| G13 | PreconditionChecks: already-mined tx rejected (`GetTxDepthInMainChain ≠ 0`) | **MISSING** | BUG-4 |
| G14 | PreconditionChecks: already-bumped tx rejected (`replaced_by_txid` flag) | **MISSING** | BUG-4 |
| G15 | PreconditionChecks: foreign-input tx rejected (AllInputsMine) | PASS | — (BumpFee rejects via `ErrBumpFeeNotOurs`) |
| G16 | max_tx_fee cap: `new_total_fee > max_tx_fee` rejected | **MISSING** | BUG-5 |
| G17 | DEFAULT_TRANSACTION_MAXFEE constant present (COIN/10 = 0.1 BTC) | **MISSING** | BUG-5 |
| G18 | MarkReplaced bookkeeping (after broadcast) — `replaces_txid` mapValue | **MISSING** | BUG-6 |
| G19 | MarkReplaced bookkeeping — `replaced_by_txid` on the bumped tx | **MISSING** | BUG-6 |
| G20 | calculateCombinedBumpFee for ancestor-cluster fee inflation | **MISSING** | BUG-7 |
| G21 | Rule 2 "no new unconfirmed inputs" — wallet layer (`m_min_depth = 1`) | **MISSING** | BUG-8 |
| G22 | Rule 2 "no new unconfirmed inputs" — mempool layer (`checkRBFNoNewUnconfirmedInputsLocked`) | PASS | — |
| G23 | `mempoolMinFee` gate — refuse bumps below local mempool floor | **MISSING** | BUG-13 |
| G24 | GetRequiredFee gate — refuse bumps below wallet `minRelayFee` | **MISSING** | BUG-5 |
| G25 | Wallet auto-mode picks `max(feerate, min_feerate, +incrementalRelayFee)` like Core's EstimateFeeRate | PARTIAL | BUG-12 (uses fixed +1 sat/vB) |
| G26 | RPC bumpfee surfaces Core-compatible error code mapping | PASS | — |
| G27 | RPC bumpfee error message text matches Core "Insufficient total fee … (oldFee X + incrementalFee Y)" | **MISSING** | BUG-10 |
| G28 | BumpFee re-signs every input (witness present on result) | PASS | — |
| G29 | BumpFee preserves output ordering | PASS | — |
| G30 | BumpFee `+1 sat/vB` minimum-bump implementation rounds **fee amount** up (ceil) — primitive matches Rule 3 invariant direction | PARTIAL | BUG-12 |

PASS: **13** / PARTIAL: **3** / MISSING: **14**.

## Bug catalogue

### BUG-1 (HIGH) — Rule 3 precise minTotalFee formula missing

Core's `CheckFeeRate` enforces:

```cpp
CAmount minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize);
if (new_total_fee < minTotalFee) { … reject … }
```

blockbrew's `BumpFee` (internal/wallet/bumpfee.go) computes
`newFee = ceil(vsize * feeRate)` and only requires `newFee > oldFee`.
There is **no `minTotalFee` formula**; specifically `incrementalRelayFee.GetFee(vsize)`
is never computed at the wallet layer. The mempool path enforces Rule 4
(additional_fees ≥ incrementalRelayFee × vsize) via `checkRBFLocked`
gate 6b, but the wallet's bumper does not pre-validate against that
formula — so a perfectly legal-looking bump can be built that the local
mempool then rejects. This is the precise W130 brief invariant.

**Reference**: `bitcoin-core/src/wallet/feebumper.cpp:93`.
**Site**: `internal/wallet/bumpfee.go:210-225`.

### BUG-2 (HIGH) — WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB missing

Core's `EstimateFeeRate` (bitcoin-core/src/wallet/feebumper.cpp:135-137):

```cpp
CFeeRate node_incremental_relay_fee = wallet.chain().relayIncrementalFee();
CFeeRate wallet_incremental_relay_fee = CFeeRate(WALLET_INCREMENTAL_RELAY_FEE);
feerate += std::max(node_incremental_relay_fee, wallet_incremental_relay_fee);
```

`WALLET_INCREMENTAL_RELAY_FEE = 5000` sat/kvB (= 5 sat/vB) per
`bitcoin-core/src/wallet/wallet.h:124`. Core deliberately uses **5× the
default node incremental relay fee** to future-proof against fee-rate
increases the node has not yet picked up. blockbrew's bumper hard-codes
**1 sat/vB** (line 217: `ceil(1.0 * float64(vsize))`) which is the bare
floor and below Core's wallet floor. A bumped tx that satisfies blockbrew's
`+1 sat/vB` floor may still be rejected by a peer running Core with the
default wallet-incremental-relay-fee policy.

**Reference**: `bitcoin-core/src/wallet/wallet.h:124`,
`bitcoin-core/src/wallet/feebumper.cpp:128-137`.
**Site**: `internal/wallet/bumpfee.go:216-222`.

### BUG-3 (MED) — `req.FeeRate <= origFeeRate` rejection drops floor

```go
if req.FeeRate <= origFeeRate {
    return nil, ErrBumpFeeRateTooLow
}
```

The user-supplied feerate path requires `feerate > origFeeRate` (in
sat/vB float). That is a necessary but not sufficient condition. Per
Rule 3 (precise form) the new total fee must beat `old_fee +
incrementalRelayFee.GetFee(vsize)`. blockbrew's check only rules out
the trivially-low rate; a caller can specify
`origFeeRate + 0.0001 sat/vB` and the bumper will accept it even though
the implied fee delta is fractional sats (rounded up to 1 sat),
below the per-replacement incremental floor. Mempool will reject
downstream, but the wallet-layer error is misleading
(`ErrBumpFeeRateTooLow` will never fire; mempool returns a different
error string).

**Reference**: `bitcoin-core/src/wallet/feebumper.cpp:93-99`.
**Site**: `internal/wallet/bumpfee.go:211-213`.

### BUG-4 (HIGH) — PreconditionChecks (5 sub-checks) absent

Core gates fee-bumping with a `PreconditionChecks` function
(`bitcoin-core/src/wallet/feebumper.cpp:23-57`) which rejects:

  1. tx has descendants in the wallet (HasWalletSpend)
  2. tx has descendants in the mempool (hasDescendantsInMempool)
  3. tx is confirmed or conflicts with a mined tx (GetTxDepthInMainChain ≠ 0)
  4. tx was already bumped (`wtx.mapValue.contains("replaced_by_txid")`)
  5. tx contains foreign inputs (AllInputsMine — `require_mine`)

blockbrew's BumpFee handles (5) (returns `ErrBumpFeeNotOurs`) but **none
of (1)-(4)**. A caller can repeatedly bump the same tx, or attempt to
bump a tx with descendants, or even bump a confirmed tx — the bumper
will happily construct a replacement (which the mempool will then
reject for unrelated reasons, e.g. double-spend of an already-confirmed
output). The error messaging is confusing and the bookkeeping is wrong.

**Reference**: `bitcoin-core/src/wallet/feebumper.cpp:23-57`.
**Site**: `internal/wallet/bumpfee.go:116-180` (entire BumpFee head).

### BUG-5 (HIGH) — max_tx_fee cap absent

Core's `CheckFeeRate` enforces (`bitcoin-core/src/wallet/feebumper.cpp:109-114`):

```cpp
const CAmount max_tx_fee = wallet.m_default_max_tx_fee;  // DEFAULT_TRANSACTION_MAXFEE = COIN/10 = 0.1 BTC
if (new_total_fee > max_tx_fee) { … reject … }
```

blockbrew never bounds the new fee. A misconfigured `fee_rate` argument
(e.g. 100,000 sat/vB through a typo) will produce a multi-BTC-fee
replacement that the bumper silently constructs and signs. The mempool
will likely still accept it (it satisfies all relay rules).
Also `GetRequiredFee(maxTxSize)` (Core line 101-106) — the wallet's own
`minRelayFee` floor — is not checked.

**Reference**: `bitcoin-core/src/wallet/feebumper.cpp:101-114`,
`bitcoin-core/src/wallet/wallet.h:DEFAULT_TRANSACTION_MAXFEE`.
**Site**: `internal/wallet/bumpfee.go:210-225`.

### BUG-6 (MED) — MarkReplaced bookkeeping absent

Core's `CommitTransaction` (`bitcoin-core/src/wallet/feebumper.cpp:350-381`):

```cpp
mapValue["replaces_txid"] = oldWtx.GetHash().ToString();
wallet.CommitTransaction(tx, std::move(mapValue), oldWtx.vOrderForm);
bumped_txid = tx->GetHash();
if (!wallet.MarkReplaced(oldWtx.GetHash(), bumped_txid)) { … warn … }
```

This populates `replaced_by_txid` on the original wallet tx (read by
PreconditionChecks above as gate 4) and `replaces_txid` on the
replacement. blockbrew's `handleBumpFee` (`internal/rpc/bumpfee_methods.go:71-78`)
calls `AcceptToMemoryPool` and returns the new txid — but never marks
the original as replaced. The wallet has no `MarkReplaced` API at all.

**Reference**: `bitcoin-core/src/wallet/feebumper.cpp:370-381`.
**Site**: `internal/wallet/bumpfee.go`, `internal/rpc/bumpfee_methods.go:71-78`.

### BUG-7 (MED) — calculateCombinedBumpFee for ancestor cluster absent

Core's `CheckFeeRate` (`bitcoin-core/src/wallet/feebumper.cpp:83-88`):

```cpp
const std::optional<CAmount> combined_bump_fee =
    wallet.chain().calculateCombinedBumpFee(reused_inputs, newFeerate);
CAmount new_total_fee = newFeerate.GetFee(maxTxSize) + combined_bump_fee.value();
```

When the tx being bumped spends an unconfirmed parent that itself needs
to be bumped (CPFP cluster), Core adds the parent's bump cost to the
new_total_fee before the Rule 3 minTotalFee comparison. blockbrew has no
analogue; the bumper treats the input cluster as if it were all
confirmed. If the parent's effective feerate is below the new target,
the replacement will fail to relay even though blockbrew approved it.

**Reference**: `bitcoin-core/src/wallet/feebumper.cpp:83-88`.
**Site**: `internal/wallet/bumpfee.go:182-225`.

### BUG-8 (MED) — Rule 2 wallet-layer `m_min_depth = 1` not enforced

Core's `CreateRateBumpTransaction` (`bitcoin-core/src/wallet/feebumper.cpp:309-312`):

```cpp
new_coin_control.m_allow_other_inputs = true;
// We cannot source new unconfirmed inputs (bip125 rule 2)
new_coin_control.m_min_depth = 1;
```

blockbrew's bumper never adds new inputs (it reuses every original
input and only mutates the change output), so the live correctness is
preserved by accident. But there is no defensive `m_min_depth` analog
or guard for a future fee-increase-via-add-input extension. Mempool
gate `checkRBFNoNewUnconfirmedInputsLocked` catches this if the
replacement is submitted, but the wallet layer is silent. Forensic-only
today, hazardous if anyone extends BumpFee to add inputs.

**Reference**: `bitcoin-core/src/wallet/feebumper.cpp:309-312`,
`bitcoin-core/src/validation.cpp` (Rule 2 enforcement).
**Site**: `internal/wallet/bumpfee.go:233-258`.

### BUG-9 (LOW) — `t.Errorf` vs `t.Fatalf` in existing BumpFee tests

Cosmetic. `TestBumpFee_RoundTrip` (`internal/wallet/bumpfee_test.go:109-171`)
uses `t.Errorf` for every assertion. If the input count check fails
the subsequent `Witness` check is meaningless but still runs and
generates noise. Pattern to consider: `t.Fatalf` on structural pre-
conditions, `t.Errorf` on the precise invariant. Forensic only.

### BUG-10 (LOW) — RPC error message drift vs Core

Core's CheckFeeRate emits (`bitcoin-core/src/wallet/feebumper.cpp:96-97`):

```
"Insufficient total fee %s, must be at least %s (oldFee %s + incrementalFee %s)"
```

blockbrew's `mapBumpFeeError` (`internal/rpc/bumpfee_methods.go:265-284`)
produces opaque sentinels — `"change output would become dust after fee
increase"` etc. — that bear no resemblance to Core's text. Callers
matching on Core's strings (which is poor practice but happens) will
not recover the precise failure mode.

### BUG-11 (LOW) — original tx witness state forensic note

`BumpFee` calls `signTx(newTx, utxos)` on the **fresh** replacement tx
which has no scriptSig/witness. Core's signing path clears
scriptSig/scriptWitness on a temporary mutable before re-signing
(`bitcoin-core/src/wallet/feebumper.cpp:283-287`). blockbrew doesn't
need to clear because the replacement is allocated empty (line 239-258),
but **if a future refactor reuses `req.OrigTx` in place** the historical
witness would leak into the replacement.

### BUG-12 (LOW) — "+1 sat/vB" comment vs ceil(vsize) implementation

Comment (line 207): `newFee = oldFee + ceil(vsize * 1 sat/vB)` —
the implementation matches the comment numerically (`int64(math.Ceil(1.0 * float64(vsize)))`)
but **Core's EstimateFeeRate adds +1 sat/kvB to the feerate** (line 126:
`feerate += CFeeRate(1)`), not +1 sat/vB to the fee amount. The semantic
gap: Core's "+1" is 1 sat per 1000 vbytes, blockbrew's "+1" is 1 sat per
1 vbyte. blockbrew's bump is 1000× more aggressive than Core's. Not
strictly a bug (still satisfies Rule 4) but misleading comment.

**Reference**: `bitcoin-core/src/wallet/feebumper.cpp:124-126`.

### BUG-13 (HIGH) — mempool_min_fee gate absent

Core's `CheckFeeRate` (`bitcoin-core/src/wallet/feebumper.cpp:67-75`):

```cpp
CFeeRate minMempoolFeeRate = wallet.chain().mempoolMinFee();
if (newFeerate.GetFeePerK() < minMempoolFeeRate.GetFeePerK()) { … reject … }
```

If the local mempool's dynamic minfee has risen since the original was
broadcast, the bumper must refuse rather than producing a tx that the
local node itself will discard. blockbrew has no such check — the
mempool's `getMinFeeRateLocked` exists (`internal/mempool/mempool.go:2700`)
but is never consulted by the bumper.

**Reference**: `bitcoin-core/src/wallet/feebumper.cpp:67-75`.
**Site**: `internal/wallet/bumpfee.go:210-225`.

## Cross-wave references

* **W129 BUG-3** (blockbrew): `estimateInputFee` rounds with float truncation
  (`int64(float64(vsize) * feeRate)`) where Core's `CFeeRate::GetFee` rounds
  UP (`EvaluateFeeUp`). This affects fee-bumping too but only indirectly:
  the wallet's BumpFee uses `math.Ceil` directly at the call site, which is
  correct. The primitive in `coinselection.go:421` remains broken — any
  future caller that uses `estimateInputFee` for Rule 3 enforcement would
  inherit the truncation bug. Cross-reference, not duplicate.
* **W120 RBF audit** (blockbrew, mempool layer): documents the
  `checkRBFLocked` mempool-side gates 1-7. W130 is the **wallet-layer**
  complement and finds the precise feebumper Rule 3 formula
  `old_fee + incrementalRelayFee.GetFee(maxTxSize)` is **not enforced**
  at the wallet layer at all — mempool catches it downstream but the
  wallet-layer error is missing.
* **FIX-61 / W118 BUG-2**: the BumpFee helper itself was introduced in
  FIX-61 to close a wholly-absent feature. W130 grades the resulting
  minimum-viable shape against Core's full feebumper.cpp surface.

## Out of scope

* psbtbumpfee return-shape parity with Core (PSBT fields, signer round-trip).
  W130 only asserts that the bumper computes the right fee delta.
* RPC documentation strings.
* Test-suite regtest fixtures (would require a live node).
* Auto-mode "add inputs" extension (currently no inputs can be added to a
  blockbrew bump; if added, BUG-8 becomes load-bearing).

## Severity rollup

* HIGH: 5 (BUG-1, BUG-2, BUG-4, BUG-5, BUG-13)
* MED: 4 (BUG-3, BUG-6, BUG-7, BUG-8)
* LOW: 4 (BUG-9, BUG-10, BUG-11, BUG-12)

Total: **13 BUGS / 30 gates** (PASS 13, PARTIAL 3, MISSING 14).
