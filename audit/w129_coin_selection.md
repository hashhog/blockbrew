# W129 — Coin Selection (BnB / Knapsack / SRD / CG) Audit (blockbrew)

**Wave**: W129 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**Scope**: BnB, Knapsack, SRD, CG, effective_value, longterm feerate,
cost-of-change, SFFO, change avoidance, dust threshold, change-target
generation, max_tx_weight, RecalculateWaste.

**References (Bitcoin Core)**:
- `bitcoin-core/src/wallet/coinselection.h` — algorithm signatures,
  `CoinSelectionParams`, `CoinEligibilityFilter`, `OutputGroup`,
  `SelectionResult`, `CHANGE_LOWER=50000`, `CHANGE_UPPER=1000000`,
  `GenerateChangeTarget`.
- `bitcoin-core/src/wallet/coinselection.cpp` — `SelectCoinsBnB`,
  `CoinGrinder`, `SelectCoinsSRD`, `KnapsackSolver`,
  `ApproximateBestSubset`, `RecalculateWaste`, descending comparators,
  `TOTAL_TRIES=100000`.
- `bitcoin-core/src/wallet/spend.cpp` — `CreateTransactionInternal`
  (L1063), `ChooseSelectionResult` (L729), `AttemptSelection` (L702),
  `GroupOutputs` (L572,690), parameter wiring (L1077-1188),
  `m_cost_of_change` formula (L1175), `min_viable_change` formula
  (L1182-1184), `GenerateChangeTarget` call (L1177), SFFO skip-BnB
  (L751), 3×LTFRE CG gate (L769), `OUTPUT_GROUP_MAX_ENTRIES` check
  (L889), random change insert (L1255).
- `bitcoin-core/src/wallet/feebumper.cpp` — bump-fee path; reuses the
  same `CoinSelectionParams` plumbing.

**Precedent**: W113 already catalogued BnB/Knapsack at fleet level and
filed BUG-1..BUG-11 (SRD missing, OutputGroup missing, avoid-partial-spends
missing, OUTPUT_GROUP_MAX_ENTRIES missing, long-term-feerate missing,
Knapsack-rng now fixed by FIX-45, change-position-not-random,
nLockTime=0 anti-fee-sniping, missing backdate, incomplete waste metric,
Knapsack second-pass-target mismatch). W129 zooms in on the algorithm
internals and selection-parameter plumbing that W113 did not cover in
depth.

## Summary

30 audit gates across `internal/wallet/coinselection.go` (selection
algorithms), `internal/wallet/wallet.go` (`CreateTransactionWithTip`),
`internal/rpc/wallet_wave_methods.go` (`walletcreatefundedpsbt`), and
`internal/wallet/bumpfee.go` (rate-bump).

| Verdict | Count |
|---------|-------|
| PRESENT | 9 |
| PARTIAL | 6 |
| MISSING | 15 |

**Bug count**: **22 distinct bug IDs** (BUG-1 .. BUG-22).

Severity distribution:

| Severity   | Count | Notes |
|------------|-------|-------|
| HIGH       | 4     | Effective-value rounding direction wrong (BUG-3), max_tx_weight cap missing (BUG-8), tx fees/change_fee not bounded by Core min-relay formula (BUG-12), no multi-algorithm waste-comparison (BUG-9). |
| MEDIUM     | 11    | Algorithm-internal correctness gaps that produce sub-optimal selections or break Core parity tests. |
| LOW        | 7     | Plumbing-shape gaps (param wiring, struct fields) that don't change selection results on default inputs but break alignment with Core's `CoinSelectionParams`. |

No consensus break. All bugs are wallet-policy / privacy / parity. The
selection-output is functionally fundable but is not byte-/algorithm-
identical to Core for any non-trivial input.

### Top findings

1. **BUG-3 (HIGH)**: `estimateInputFee` rounds the per-input fee using
   `int64(float64(vsize) * feeRate)` — Go's float-to-int conversion is
   **truncation toward zero**, not Core's `CFeeRate::GetFee` which uses
   integer ceiling (`(nFeePaid + 999) / 1000`). For any non-integer
   sat/vB feerate (e.g. 1.5 sat/vB on a 68-vbyte P2WPKH = 102.0 → 102
   correctly; but 1.7 × 68 = 115.6 → 115 truncates whereas Core's
   integer math returns 116). This means blockbrew's `effective_value`
   is **systematically 0-1 sat too high** vs Core, breaking BnB's
   cost-of-change window comparisons on adversarial inputs.

2. **BUG-8 (HIGH)**: No `max_selection_weight` cap inside BnB or
   Knapsack. Core's BnB rejects branches when `curr_selection_weight >
   max_selection_weight` (coinselection.cpp:131) and reports
   `ErrorMaxWeightExceeded`. blockbrew's BnB has no `m_weight` field on
   `utxoWithEffValue`, no weight accumulation, no per-branch weight
   check, and no `MaxWeightExceeded` error. A pathological UTXO set of
   ~50000 tiny inputs could be returned as a valid selection but would
   fail mempool acceptance at the 400k-weight standard limit.

3. **BUG-12 (HIGH)**: The `costOfChange` parameter passed to
   `SelectCoins` is computed as `changeOutputSize * feeRate` (just the
   creation cost). Core's `m_cost_of_change` is `discard_feerate ×
   change_spend_size + effective_feerate × change_output_size`
   (spend.cpp:1175) — the **future cost of spending the change UTXO at
   discard feerate** is the second term. blockbrew omits it entirely,
   so BnB's cost-of-change window is **31× too narrow** at 1 sat/vB
   (31 vs ~31+68=99 sat). This systematically makes BnB reject
   changeless solutions that Core would accept.

4. **BUG-9 (HIGH)**: Multi-algorithm waste-comparison is missing.
   Core's `ChooseSelectionResult` runs BnB, Knapsack, CG, and SRD,
   then picks the one with **lowest waste** via
   `std::min_element(results.begin(), results.end())` using
   `SelectionResult::operator<` (coinselection.cpp:948 — compares by
   waste, breaks ties by larger input count). blockbrew runs BnB
   **first** and returns immediately if it succeeds, never comparing
   to Knapsack. On any input where Knapsack would beat BnB on waste
   (e.g. low feerate + consolidation opportunity), blockbrew leaves
   waste on the table.

5. **BUG-13 (HIGH)** *(cross-references W113 BUG-10)*: `RecalculateWaste`
   is missing entirely. There is no per-result waste recomputation, no
   `change_cost` accounting, no `bump_fee_group_discount`, no
   `m_use_effective` distinction. Without `RecalculateWaste` no
   comparison across algorithms is possible (see BUG-9), and the
   `Algorithm` field on `SelectionResult` is the only signal that BnB
   was chosen — there's no waste number to compare.

## 30-gate audit matrix

Gates classify each Core construct as PRESENT / PARTIAL / MISSING in
blockbrew. Bugs are filed against PARTIAL and MISSING gates.

| Gate | Topic | Status | Bug |
|------|-------|--------|-----|
| G1   | BnB algorithm present (`SelectCoinsBnB`) | PRESENT | — |
| G2   | Knapsack algorithm present (`KnapsackSolver`) | PRESENT | — |
| G3   | SRD algorithm present (`SelectCoinsSRD`) | MISSING | BUG-1 (W113 BUG-1) |
| G4   | CoinGrinder algorithm present (`CoinGrinder`) | MISSING | BUG-2 |
| G5   | `effective_value = nValue - input_fee` per UTXO | PARTIAL | BUG-3 (rounding) |
| G6   | Effective-value filter (drop ≤0) before BnB | PRESENT | — |
| G7   | Long-term feerate (`m_long_term_feerate`) tracked per OutputGroup | MISSING | BUG-4 (W113 BUG-5) |
| G8   | Cost-of-change = `discard×change_spend + eff×change_out` | PARTIAL | BUG-12 (only the eff×change_out term is present) |
| G9   | `m_change_fee` (creation fee only) tracked | PARTIAL | BUG-5 (no struct, only inline calc at wallet.go:931) |
| G10  | `min_viable_change = max(change_spend_fee+1, dust)` | MISSING | BUG-6 (hardcoded 546 sat dust everywhere) |
| G11  | `m_min_change_target` via `GenerateChangeTarget(payment/n, change_fee, rng)` | MISSING | BUG-7 (constant `target+changeTarget` use) |
| G12  | `CHANGE_LOWER=50000`, `CHANGE_UPPER=1000000` constants | MISSING | BUG-7 (covered by same fix) |
| G13  | BnB iteration cap = `TOTAL_TRIES=100000` | PRESENT | — |
| G14  | BnB sorts by descending effective value | PRESENT | — |
| G15  | BnB sort comparator: tie-break by `fee - long_term_fee` (`descending` struct, coinselection.cpp:29-38) | MISSING | BUG-11 (long-term-fee absent, so tie-break is arbitrary Go sort.Slice — unstable) |
| G16  | BnB lookahead via `curr_available_value` | PRESENT | — |
| G17  | BnB equivalence-shortcut: skip inclusion when prior excluded sibling has same `effective_value` AND `fee` | PARTIAL | BUG-10 (skips on `effValue` only; ignores `fee` since `long_term_fee` absent) |
| G18  | BnB `is_feerate_high` waste-grows pruning (`curr_waste > best_waste && is_feerate_high` — coinselection.cpp:129) | MISSING | BUG-13 (no waste tracked; pruning impossible) |
| G19  | `max_selection_weight` cap enforced per branch | MISSING | BUG-8 |
| G20  | `ErrorMaxWeightExceeded` returned when limit exceeded | MISSING | BUG-8 (same fix) |
| G21  | Knapsack 2-pass random + fill-in (`ApproximateBestSubset`) | PRESENT | — |
| G22  | Knapsack CSPRNG randomness | PRESENT | (FIX-45 closed W113 BUG-6) |
| G23  | Knapsack iteration cap = 1000 | PRESENT | — |
| G24  | Knapsack second-pass at `target + min_change_target` | PARTIAL | BUG-14 (W113 BUG-11 — uses `target+changeTarget`, see analysis) |
| G25  | SFFO (`m_subtract_fee_outputs`): skip BnB when true (spend.cpp:751) | MISSING | BUG-15 (SFFO is honored at the RPC layer but coin-selection does NOT receive the flag — BnB always runs) |
| G26  | 3×LTFRE CG gate: run CoinGrinder when `effective_feerate > 3×long_term_feerate` | MISSING | BUG-2 (same fix as G4) |
| G27  | `OUTPUT_GROUP_MAX_ENTRIES=100` cap (spend.cpp:889) | MISSING | BUG-16 (W113 BUG-4) |
| G28  | `AttemptSelection` mixed/positive group split + per-type loop (spend.cpp:702) | MISSING | BUG-17 |
| G29  | `RecalculateWaste` formula | MISSING | BUG-13 |
| G30  | Multi-algorithm waste comparison via `std::min_element` (spend.cpp:716,811) | MISSING | BUG-9 |

## Bug catalogue

### Algorithm-presence gaps

**BUG-1 (G3 MEDIUM)** — *SRD missing entirely.*
Core's `ChooseSelectionResult` runs four algorithms (BnB, Knapsack, CG,
SRD) and picks the one with lowest waste. blockbrew has BnB + Knapsack
only. SRD (`SelectCoinsSRD` in coinselection.cpp:536) does a shuffled
greedy fill until the running total meets `target + CHANGE_LOWER +
change_fee`, evicting the lowest-value selected coin when weight is
exceeded. Missing.
*File*: `internal/wallet/coinselection.go` — no `SelectCoinsSRD`
function. (Same as W113 BUG-1, but tracked here as the W129 audit
re-confirms it.)

**BUG-2 (G4/G26 MEDIUM)** — *CoinGrinder missing entirely.*
Core's `CoinGrinder` (coinselection.cpp:325) is a DFS over the
power-set of UTXOs, optimising for **minimum input weight** rather than
waste. It is gated on `effective_feerate > 3 × long_term_feerate`
(spend.cpp:769) — the "high-feerate input-minimisation" regime. blockbrew
has no `CoinGrinder` function and no 3×LTFRE branch. Missing.
*File*: `internal/wallet/coinselection.go`.

### Per-input plumbing gaps

**BUG-3 (G5 HIGH)** — *Effective-value fee rounding wrong direction.*
`estimateInputFee` returns `int64(float64(vsize) * feeRate)` —
truncation toward zero. Core's `CFeeRate::GetFee` rounds **up** via
`(nSize * nSatoshisPerK + 999) / 1000` (policy/feerate.cpp:23-27).
At 1.7 sat/vB × 68 vbytes Core returns 116 sat (ceil(115.6)); blockbrew
returns 115 (truncates). The 1-sat under-estimate flows through to
`effective_value`, so blockbrew thinks every UTXO is worth 1 sat more
than Core does. On BnB's cost-of-change window
(`curr_value > target + cost_of_change`), this is enough to flip
"changeless solution found" vs "fall through to knapsack" on inputs
near the window boundary. Fix: round up like `CFeeRate::GetFee`:
`(vsize*satPerKvB + 999) / 1000`.
*File*: `internal/wallet/coinselection.go:419-422`.

**BUG-4 (G7 MEDIUM)** — *No `long_term_feerate` / `long_term_fee` field.*
`utxoWithEffValue` has `effValue` and `inputFee` only. Core's `COutput`
carries `long_term_fee` (coinselection.h:70), populated from
`OutputGroup::m_long_term_feerate` at `Insert` time
(coinselection.cpp:761). The waste metric uses
`coin.GetFee() - coin.long_term_fee` per coin (coinselection.cpp:836).
Without this field, every BnB branch's waste is wrong (see BUG-13) and
the BnB sort tie-break (G15) cannot prefer "lower waste" on ties.
*File*: `internal/wallet/coinselection.go:108-113`.
*Same root cause as W113 BUG-5.*

### `CoinSelectionParams` plumbing gaps

**BUG-5 (G9 LOW)** — *No `CoinSelectionParams` struct.*
Selection parameters are passed inline as four positional arguments
(`target`, `feeRate`, `costOfChange`) into `SelectCoins`. Core bundles
14 parameters into `CoinSelectionParams` (coinselection.h:134-196):
`m_min_change_target`, `min_viable_change`, `m_change_fee`,
`m_cost_of_change`, `m_effective_feerate`, `m_long_term_feerate`,
`m_discard_feerate`, `tx_noinputs_size`, `m_subtract_fee_outputs`,
`m_avoid_partial_spends`, `m_include_unsafe_inputs`, `m_version`,
`m_max_tx_weight`, `change_output_size`, `change_spend_size`. blockbrew
has none of these as a coherent struct. Selection algorithms cannot
reach the discard feerate, long-term feerate, max-tx-weight, or SFFO
flag.
*File*: `internal/wallet/coinselection.go`.

**BUG-6 (G10 MEDIUM)** — *`min_viable_change` missing.*
Core computes `min_viable_change = max(change_spend_fee + 1, dust)`
where `change_spend_fee` is `discard_feerate × change_spend_size`
(spend.cpp:1183-1184). This is the threshold below which `GetChange`
returns 0 (i.e. change is dropped to fees, coinselection.cpp:986).
blockbrew uses a hardcoded `dustThreshold = 546` (coinselection.go:56)
for the same purpose, which is correct for default policy at 3 sat/vB
discard but **wrong at any other discard feerate** — at 10 sat/vB
discard with a 68-vbyte change-spend, `change_spend_fee = 680` and
`min_viable_change` should be 681, not 546. Result: blockbrew creates
change outputs at low values that Core would have dropped to fees,
producing future-unspendable UTXOs.
*File*: `internal/wallet/coinselection.go:56`, `internal/wallet/wallet.go:992`,
`internal/rpc/wallet_wave_methods.go:630` (via `dustThresholdFor()`).

**BUG-7 (G11/G12 MEDIUM)** — *No randomised `m_min_change_target` /
`GenerateChangeTarget`.*
Core's `GenerateChangeTarget` (coinselection.cpp:809) returns
`change_fee + rng.randrange(min(payment×2, 1000000) - 50000) + 50000`
when payment > 25000, else `change_fee + 50000`. This randomises the
change target to disguise the "this is change" heuristic in
chain-analysis. blockbrew passes `costOfChange` as the change-target
unchanged (which is just the creation fee), so Knapsack's second pass
seeks the smallest viable change rather than a randomised one.
Privacy-leak. Constants `CHANGE_LOWER=50000` and `CHANGE_UPPER=1000000`
are absent.
*File*: `internal/wallet/coinselection.go` — no `GenerateChangeTarget`
function; `internal/wallet/wallet.go:931` — uses fixed `costOfChange`.

### Algorithm-internal correctness gaps

**BUG-8 (G19/G20 HIGH)** — *`max_selection_weight` cap not enforced.*
Core's BnB tracks `curr_selection_weight` per branch and backtracks
when it exceeds `max_selection_weight` (coinselection.cpp:131); when
no solution is found and the limit was tripped, returns
`ErrorMaxWeightExceeded` (the user-visible "inputs exceed max weight"
error). blockbrew's BnB has no `m_weight` field, no per-branch sum, no
check, and no error type. A pathological 50000-input UTXO set could be
returned as "valid" but rejected as oversized by mempool.
*File*: `internal/wallet/coinselection.go` — `selectCoinsBnB`
(lines 118-244) tracks no weight; `selectCoinsKnapsack` (lines 248-352)
also tracks no weight.

**BUG-9 (G30 HIGH)** — *No multi-algorithm waste comparison.*
`SelectCoins` runs BnB first, returns its result if it succeeded, falls
through to Knapsack only on BnB failure (coinselection.go:94-104). Core
runs **all** algorithms (BnB unless SFFO, Knapsack always, CG when
feerate-high, SRD always), pushes each result into a vector, and picks
the **minimum by waste** via `std::min_element` (coinselection.cpp:716,
:811). Result: if BnB succeeds with high overshoot but Knapsack would
succeed with zero overshoot, blockbrew returns the worse one.
*File*: `internal/wallet/coinselection.go:64-106`.

**BUG-10 (G17 MEDIUM)** — *BnB equivalence-shortcut incomplete.*
Core skips an inclusion branch when the prior UTXO with the same index
has the same effective value **AND** same fee
(coinselection.cpp:175-177): "Since the ratio of fee to long term fee
is the same, we only need to check if one of those values match in
order to know that the waste is the same." blockbrew checks effective
value only (coinselection.go:207): `for utxoIdx < len(sorted) &&
sorted[utxoIdx].effValue == sorted[lastIdx].effValue` — does not check
fee equality. With different input fees (e.g. mixed P2WPKH 68 vbyte
and P2TR 57 vbyte UTXOs at the same effective value), Core would
explore both branches because waste differs, but blockbrew would skip
the P2TR clone after exploring the P2WPKH one — producing a
sub-optimal result with the wrong waste metric.
*File*: `internal/wallet/coinselection.go:206-210`.

**BUG-11 (G15 LOW)** — *BnB descending-sort tie-break not by waste.*
Core's `descending` comparator (coinselection.cpp:29-38) breaks ties
on equal effective value by **lower waste first** (`a.fee -
a.long_term_fee < b.fee - b.long_term_fee`). blockbrew uses
`sort.Slice` with `sorted[i].effValue > sorted[j].effValue`
(coinselection.go:126-128) — no tie-break. Go's `sort.Slice` is
**unstable**, so on ties the order is non-deterministic across runs.
This makes the BnB result non-reproducible when several UTXOs share an
effective value (common for change outputs at the same address type
and same value, or for output groups).
*File*: `internal/wallet/coinselection.go:126-128`.

**BUG-12 (G8 HIGH)** — *`cost_of_change` formula incomplete.*
Core computes `m_cost_of_change = discard_feerate × change_spend_size
+ effective_feerate × change_output_size` (spend.cpp:1175) — the
**future spending cost** of the change UTXO at discard feerate plus the
creation cost at effective feerate. blockbrew computes only
`changeOutputSize × feeRate` (creation cost only;
wallet.go:931, wallet_wave_methods.go:533). At 1 sat/vB effective and
3 sat/vB discard with 31 vbyte change + 68 vbyte change-spend:
- Core's `m_cost_of_change`: `3 × 68 + 1 × 31 = 235 sat`
- blockbrew's `costOfChange`: `1 × 31 = 31 sat`

Result: BnB's acceptance window is **7.5× too narrow**. Many
changeless solutions that Core would accept are rejected by blockbrew,
forcing fall-through to Knapsack (which creates change). The wallet
emits more change outputs than Core would on identical inputs.
*File*: `internal/wallet/wallet.go:931`,
`internal/rpc/wallet_wave_methods.go:533`.

**BUG-13 (G18/G29 HIGH)** — *`RecalculateWaste` missing entirely.*
Core's `RecalculateWaste` (coinselection.cpp:827) is the
**authoritative waste calculator** invoked after every algorithm run.
The formula:
```
For each coin: waste += coin.GetFee() - coin.long_term_fee
waste -= bump_fee_group_discount
If change exists:    waste += change_cost
Else (no change):    waste += selected_effective_value - target
```
blockbrew tracks only `currValue - target` inline in BnB
(coinselection.go:168). This loses the **opportunity-cost** term
`inputs × (effective_feerate - long_term_feerate)` and the
**change-cost** term. Without `RecalculateWaste`:
- BnB's `is_feerate_high` pruning (`curr_waste > best_waste &&
  is_feerate_high`, coinselection.cpp:129) cannot fire (G18 also MISSING).
- The cross-algorithm `min_element` comparison (BUG-9 / G30) has nothing
  to compare on.

*File*: `internal/wallet/coinselection.go` — no `RecalculateWaste` /
`GetWaste` API on `SelectionResult`. `SelectionResult` struct has no
`Waste` field at all (coinselection.go:40-44).

**BUG-14 (G24 MEDIUM)** — *Knapsack second-pass uses
`target+changeTarget` instead of `target+min_change_target`.*
Cross-reference W113 BUG-11. Core's `KnapsackSolver`
(coinselection.cpp:709-710) calls `ApproximateBestSubset` first at
`nTargetValue`, then at `nTargetValue + change_target` where
`change_target = m_min_change_target` (the randomised change target
from `GenerateChangeTarget`). blockbrew passes `costOfChange` as the
change-target (coinselection.go:248,313), which equals the
creation-cost only — almost always **smaller** than Core's
`m_min_change_target`. Result: Knapsack's second pass converges on a
too-tight upper bound and creates change outputs Core would have
viewed as dust.
*File*: `internal/wallet/coinselection.go:248,312-318`.

### Selection-policy gaps

**BUG-15 (G25 MEDIUM)** — *SFFO skip-BnB rule not implemented.*
Core's `ChooseSelectionResult` skips BnB when SFFO is active
(spend.cpp:751: `if (!coin_selection_params.m_subtract_fee_outputs)`).
The rationale (Core's own comment): "SFFO frequently causes issues in
the context of changeless input sets: skip BnB when SFFO is active."
blockbrew's `SelectCoins` always runs BnB first, regardless of
`subtractFeeFromOutputs`. The RPC layer (`wallet_wave_methods.go:592`)
applies SFFO **after** selection has finished — too late to influence
algorithm choice. Result: on SFFO requests, BnB sometimes returns
changeless solutions that don't have enough headroom for the
output-amount reduction, causing late-stage errors that Core would
have avoided by routing to Knapsack/SRD up front.
*File*: `internal/wallet/coinselection.go:64-106` (no SFFO param),
`internal/rpc/wallet_wave_methods.go:592` (applied post-selection).

**BUG-16 (G27 LOW)** — *`OUTPUT_GROUP_MAX_ENTRIES=100` cap missing.*
Cross-reference W113 BUG-4. Core caps each OutputGroup at 100 UTXOs
(spend.cpp:889) when avoid-partial-spends is active. Since OutputGroups
don't exist at all in blockbrew (W113 BUG-2), the cap is also absent.
*File*: `internal/wallet/coinselection.go`.

**BUG-17 (G28 MEDIUM)** — *Per-OutputType `AttemptSelection` split
missing.*
Core's `AttemptSelection` (spend.cpp:702) runs `ChooseSelectionResult`
once **per output type** (`P2PKH`, `P2SH`, `P2WPKH`, `P2WSH`, `P2TR`,
`UNKNOWN`) on the type-specific OutputGroups, then picks the
minimum-waste result across types. Falls back to "all types mixed"
only if no per-type solution exists. This privacy-preserving choice
keeps the input set within a single address type when possible.
blockbrew has no output-type partitioning — every UTXO is in one
global pool. Mixed-type input sets are produced whenever Knapsack
selects them, regardless of whether a single-type solution exists.
*File*: `internal/wallet/coinselection.go` — no
`groupOutputsByType` / `OutputGroupTypeMap` analog.

### Result-shape gaps

**BUG-18 (related to G29 LOW)** — *`SelectionResult` has no `Target`
field.*
Core's `SelectionResult` stores `m_target` (coinselection.h:336),
`m_use_effective`, `m_weight`, `m_algo_completed`,
`m_selections_evaluated`, `bump_fee_group_discount`, and `m_waste`.
blockbrew's `SelectionResult` has only `Coins`, `Total`, `Algorithm`
(coinselection.go:40-44). Downstream code (`CreateTransactionWithTip`,
`walletcreatefundedpsbt`) recomputes target/fee on its own without
ever calling back into a `GetWaste` or `GetTarget` accessor.
*File*: `internal/wallet/coinselection.go:40-44`.

**BUG-19 (related to G19 LOW)** — *No `m_algo_completed` /
`m_selections_evaluated`.*
Core tracks whether BnB / CG hit the iteration cap before exhausting
the search (`SetAlgoCompleted(false)`, coinselection.cpp:468) and
exposes the count of selections evaluated via `GetSelectionsEvaluated`
(used by the `coin_selection` tracepoint). blockbrew silently breaks
out of BnB at 100000 iterations with no completion flag — the caller
cannot tell whether the result is optimal or capped-and-best-so-far.
*File*: `internal/wallet/coinselection.go:150-226`.

### Bump-fee-specific gaps

**BUG-20 (related to G11 MEDIUM)** — *`BumpFee` doesn't use coin
selection at all.*
Core's `feebumper.cpp::CreateRateBumpTransaction` reuses the full
`CoinSelectionParams` plumbing (long-term feerate, discard feerate,
cost-of-change, min-viable-change, randomised change target) and runs
the same `SelectCoins` path with `m_avoid_partial_spends` and other
controls inherited from `CCoinControl`. blockbrew's `BumpFee`
(`internal/wallet/bumpfee.go:116`) bypasses coin selection entirely: it
deducts the fee delta from the existing change output and re-signs.
Result: when the change output is below the post-bump dust threshold,
blockbrew returns `ErrBumpFeeDustAfterReduce` rather than adding
inputs (which Core can do). This is the documented blockbrew scope
(`bumpfee.go:39-45`: "blockbrew's minimal bumpfee deducts the fee
increase from change; without one we'd have to either add inputs (not
yet supported)…"), but it's a divergence from Core's behavior, so
tracked here.
*File*: `internal/wallet/bumpfee.go:116-274`.

**BUG-21 (related to G8 LOW)** — *`BumpFee` uses fixed +1 sat/vB
"incremental relay fee" floor.*
Core's `feebumper.cpp` uses `walletIncrementalRelayFee` (defaults to
`DEFAULT_INCREMENTAL_RELAY_FEE = 1000 sat/kB = 1 sat/vB`) but allows
override via `-incrementalrelayfee` and reads the policy from
`mempool.incremental_relay_feerate()`. blockbrew hardcodes `1.0 *
vsize` (`bumpfee.go:217`). The error sentinel and rate-too-low check
do match Core shape (`ErrBumpFeeRateTooLow`), but the floor is not
configurable.
*File*: `internal/wallet/bumpfee.go:216-222`.

### Cross-cutting

**BUG-22 (related to G5/G8 LOW)** — *Per-output-script size table
diverges from Core.*
`estimateOutputVSize` returns 31 for P2WPKH and 43 for P2WSH/P2TR
(coinselection.go:464-491). Core's actual sizes (`CScript` +
serialised txout): P2WPKH = 31, P2WSH = 43, P2TR = 43 — these match
on the common output types. However, blockbrew has no `DUMMY_*` size
constants (Core's `DUMMY_NESTED_P2WPKH_INPUT_SIZE`,
`DUMMY_P2WPKH_INPUT_SIZE`, used as fallbacks when the actual signing
size is unknown — see spend.cpp:1147-1148). For external inputs the
size hierarchy is missing.
*File*: `internal/wallet/coinselection.go:464-491`.

## Audit boundary / Out of scope

- **BIP-69 input/output ordering** — separate audit (W127 candidate).
- **PSBT input-finalization & signing** — covered in W118 wallet audit.
- **`-walletrejectlongchains` enforcement** — covered in W123 mempool
  audit.
- **`avoid_reuse` / `m_avoid_reuse`** — covered in W113 (BUG-3) — same
  gap, not re-filed here.
- **Manual coin control / `setLockedCoins`** — `LockCoin` / `IsLockedCoin`
  exist (W113 G29 PASS); not re-audited.
- **Change-output random insertion (BUG-7 in W113)** — separate issue,
  not re-filed.

## Universal patterns

Two universal patterns observed during this audit:

1. **"Selection-parameter struct flatness"** — blockbrew's
   `SelectCoins(utxos, target, feeRate, costOfChange)` collapses Core's
   14-field `CoinSelectionParams` into 4 positional parameters. This
   shows up across the fleet: every implementation that lacks a coherent
   `CoinSelectionParams` struct also ends up missing `long_term_feerate`,
   `min_viable_change`, `m_subtract_fee_outputs`, and the multi-algorithm
   waste comparator (BUG-4, BUG-6, BUG-15, BUG-9). Fix order would be:
   introduce the struct first, then plumb each missing field.

2. **"Waste comparator as the cross-algorithm orchestration glue"** —
   the fact that `RecalculateWaste` is missing (BUG-13) is the
   keystone bug: it gates BnB's intra-branch pruning (BUG-13 / G18),
   the multi-algorithm result comparison (BUG-9 / G30), the BnB sort
   tie-break (BUG-11 / G15), and the BnB equivalence shortcut (BUG-10
   / G17). All four downstream bugs would close on a single
   `RecalculateWaste` implementation that walks the inputs computing
   `fee - long_term_fee`. This is a candidate single-impl bundle for
   blockbrew if a fix wave is dispatched.

## Test coverage

`internal/wallet/w129_coin_selection_test.go` ships 30 tests aligned
with the gates above. Tests are categorised:

- **PRESENT gates** (9): run end-to-end, assert structural shape.
- **PARTIAL gates** (6): assert what works, then `t.Skip(...)` with a
  BUG ID for what doesn't.
- **MISSING gates** (15): `t.Skip(...)` with the BUG ID. These are
  forward-regression markers — when a fix lands they should be
  un-skipped.

Suite is expected to pass 9 / skip 21 / fail 0 on master. After fixes
land, the skip count drops 1-for-1 with bug closures.
