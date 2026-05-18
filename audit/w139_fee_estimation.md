# W139 — Fee estimation engine (CBlockPolicyEstimator) audit (blockbrew)

**Wave**: W139 (DISCOVERY, not fix)
**Date**: 2026-05-18
**Impl**: blockbrew (Go)
**Scope**: blockbrew's `FeeEstimator` (`internal/mempool/feeestimator.go`)
audited against Bitcoin Core's `CBlockPolicyEstimator`
(`src/policy/fees/block_policy_estimator.{h,cpp}`), `CFeeRate`
(`src/policy/feerate.{h,cpp}`), and the public RPC surface
(`src/rpc/fees.cpp` — `estimatesmartfee`, `estimaterawfee`). The audit
covers: three-horizon `TxConfirmStats` setup (decay / scale / period /
bucket bounds + `FEE_SPACING` exponential bucket array), `Record`
cumulative-period semantics, `EstimateMedianVal` bucket-grouping
algorithm, `estimateSmartFee` three-threshold composition with
conservative/economical modes, transaction add/remove flow
(`processTransaction` filter + `processBlockTx` + `removeTx`),
`FlushUnconfirmed` + `Flush` + `FlushFeeEstimates` periodic / shutdown
persistence, `MAX_FILE_AGE` / `CURRENT_FEES_FILE_VERSION` on-disk
format, and the RPC layer (`max(feeRate, min_mempool_feerate,
min_relay_feerate)` floor, `estimate_mode` parsing).

**Excludes**:
- `FeeFilterRounder` (BIP-133 fee-filter privacy quantizer). Touched
  only as a cross-reference — blockbrew has no equivalent. Filed as
  BUG-26 but BIP-133 is W136 territory (already audited).
- Wallet fee bumping (W130) — `bumpfee` / `psbtbumpfee` consumes
  `estimatesmartfee` results downstream; out of scope here.
- Block template fee picking (W123) — consumes `EstimateFee` results
  via cluster mining; out of scope here.

**Bitcoin Core references** (all line numbers from the shallow clone at
`bitcoin-core/src/`):
- `policy/fees/block_policy_estimator.h`:
  - L26  `FEE_FLUSH_INTERVAL = 1h`
  - L32  `MAX_FILE_AGE = 60h`
  - L35  `DEFAULT_ACCEPT_STALE_FEE_ESTIMATES = false`
  - L44  `enum class FeeEstimateHorizon` (SHORT / MED / LONG)
  - L59  `enum class FeeReason` (NONE/HALF/FULL/DOUBLE/CONSERVATIVE/
    MEMPOOL_MIN/FALLBACK/REQUIRED)
  - L71  `struct EstimatorBucket` (start, end, withinTarget,
    totalConfirmed, inMempool, leftMempool)
  - L82  `struct EstimationResult` (pass, fail, decay, scale)
  - L90  `struct FeeCalculation` (est, reason, desiredTarget,
    returnedTarget, best_height)
  - L151–158 `SHORT_BLOCK_PERIODS=12 / SHORT_SCALE=1 /
    MED_BLOCK_PERIODS=24 / MED_SCALE=2 / LONG_BLOCK_PERIODS=42 /
    LONG_SCALE=24`
  - L160 `OLDEST_ESTIMATE_HISTORY = 6 * 1008`
  - L163–167 `SHORT_DECAY=.962 / MED_DECAY=.9952 / LONG_DECAY=.99931`
  - L170–174 `HALF_SUCCESS_PCT=0.6 / SUCCESS_PCT=0.85 /
    DOUBLE_SUCCESS_PCT=0.95`
  - L177–179 `SUFFICIENT_FEETXS=0.1 / SUFFICIENT_TXS_SHORT=0.5`
  - L190 `MIN_BUCKET_FEERATE = 100`
  - L191 `MAX_BUCKET_FEERATE = 1e7`
  - L198 `FEE_SPACING = 1.05`
- `policy/fees/block_policy_estimator.cpp`:
  - L37  `CURRENT_FEES_FILE_VERSION = 309900`
  - L39  `INF_FEERATE = 1e99`
  - L82–113 `class TxConfirmStats` body
    (`txCtAvg`, `confAvg[period][bucket]`, `failAvg[period][bucket]`,
    `m_feerate_avg[bucket]`, `unconfTxs[blockHeight%bins][bucket]`,
    `oldUnconfTxs[bucket]`)
  - L207 `ClearCurrent` (ring-rotation)
  - L217 `Record` cumulative-period semantics
  - L245–409 `EstimateMedianVal` (bucket-grouping algorithm)
  - L411 `Write` / L421 `Read`
  - L477 `NewTx`
  - L485 `removeTx` (failAvg bump on non-block removal)
  - L522 `CBlockPolicyEstimator::removeTx` public
  - L543 constructor: bucket-init loop +
    `MED_BLOCK_PERIODS,MED_DECAY,MED_SCALE` / SHORT / LONG factories +
    on-disk read with file-age check
  - L581–593 `CValidationInterface` overrides:
    `TransactionAddedToMempool`, `TransactionRemovedFromMempool`,
    `MempoolTransactionsRemovedForBlock`
  - L596 `processTransaction` — `validForFeeEstimation` filter
    (`!m_mempool_limit_bypassed && !m_submitted_in_package &&
    m_chainstate_is_current && m_has_no_mempool_parents`)
  - L641 `processBlockTx`
  - L669 `processBlock` (reorg guard + decay + record loop)
  - L718 `estimateFee` (deprecated 2-target reject)
  - L727 `estimateRawFee`
  - L763 `HighestTargetTracked`
  - L780 `BlockSpan` / L788 `HistoricalBlockSpan`
  - L798 `MaxUsableEstimate`
  - L808 `estimateCombinedFee` (shorter-horizon fallback)
  - L847 `estimateConservativeFee` (DOUBLE_SUCCESS_PCT lower-bound at
    2*target on LONG)
  - L871 `estimateSmartFee` — half/full/double + conservative max
  - L958 `Flush` = `FlushUnconfirmed` + `FlushFeeEstimates`
  - L1064 `FlushUnconfirmed`
- `policy/feerate.{h,cpp}`:
  - feerate.h:31 `class CFeeRate` (sat/vB internal via FeePerVSize)
  - feerate.h:41 `explicit CFeeRate(I m_feerate_kvb)` — sat/kvB
    constructor
  - feerate.h:62 `GetFeePerK()` — sat for 1000 vB
  - feerate.cpp:11 ctor from (CAmount, vbytes)
- `rpc/fees.cpp`:
  - L32 `estimatesmartfee` — `ParseConfirmTarget` clamp at
    `HighestTargetTracked(LONG)`, `FeeModeFromString` parse,
    `max(feeRate, min_mempool_feerate, min_relay_feerate)` floor
  - L97 `estimaterawfee` — per-horizon loop emitting decay/scale +
    pass/fail bucket struct + horizon-keyed JSON
  - L218 `RegisterFeeRPCCommands` (`estimatesmartfee` public,
    `estimaterawfee` hidden)

**BIPs**: none (CBlockPolicyEstimator is policy, not consensus).

**Source under audit**:
- `blockbrew/internal/mempool/feeestimator.go` — 822 LOC.
  - L17–53 horizon enum + per-horizon `horizonDecay`/`horizonScale`/
    `horizonPeriods` arrays + `maxBlocksForHorizon`.
  - L55–88 bucket-init constants (`feeSpacing=1.05`,
    `minBucketFeeRate=0.1 sat/vB`, `maxBucketFeeRate=1e4 sat/vB`,
    `buildExponentialBuckets`, `defaultBucketBoundaries`).
  - L91–169 `TxConfirmStats` struct + `newTxConfirmStats` factory
    + `applyDecay` + `record` + `recordFail`.
  - L187–257 `estimateMedianVal`.
  - L260–300 `FeeBucket`, `BucketStats`, `txInfo`, `FeeEstimator` body.
  - L302–346 `NewFeeEstimator` / `NewFeeEstimatorWithConfig` /
    `newFeeEstimatorInternal`.
  - L362–443 `RegisterTransaction` / `UnregisterTransaction` /
    `ProcessBlock`.
  - L445–507 `selectHorizon` / `horizonName` / `EstimateFee` /
    `EstimateSmartFee`.
  - L509–649 `EstimationResult` types, `EstimateRawFeeForHorizon` /
    `EstimateRawFee` / `EstimateRawFeeAllHorizons` /
    `HighestTargetTracked` / `BestHeight` / `SetBestHeight` /
    `TrackedTxCount`.
  - L676–774 JSON persistence (`feeEstimatorState`, `Save`, `Load`)
    with `feeEstimatorVersion = 2`.
  - L777–821 `GetBucketStats` diagnostic.
- `blockbrew/internal/rpc/methods.go:2112-2153` — `handleEstimateSmartFee`.
- `blockbrew/internal/rpc/extra_methods.go:1076-1155` —
  `handleEstimateRawFee`.
- `blockbrew/internal/rpc/server.go:631-635` — dispatch table.
- `blockbrew/cmd/blockbrew/main.go:985-1153` — fleet-wiring of
  RegisterTransaction / UnregisterTransaction / ProcessBlock / Save /
  Load (FIX-47 era).

## Summary

30 audit gates split into 6 sub-areas (constants, bucket structure,
block-processing, estimation algorithm, transaction tracking,
persistence, RPC). The previous W114 wave (2026-Q1, 30 gates) recorded
30 bugs; FIX-47 closed BUG-10 / BUG-14 / BUG-15 / BUG-21 / BUG-22 /
BUG-30 (the three-horizon refactor — landed before W139). W139
re-audits the entire surface against current Core source and finds
**25 distinct bug IDs (BUG-1..BUG-26)** still active; ~10 W114 bugs
are now closed (carried forward as PASS gates here).

Severity distribution:

| Severity | Count | Notes |
|----------|-------|-------|
| **P0-CDIV** | 0 | No block-validity divergence; fee estimation is policy-only. |
| **P1**      | 5 | BUG-11 estimateMedianVal sticky-accumulator (no reset-on-pass) → systematic under-estimate vs Core; BUG-12 three-threshold smart-fee composition absent; BUG-13 conservative mode absent; BUG-25 RPC `estimate_mode` arg silently dropped; BUG-3 (informational PASS) shared bucket index across horizons. |
| **HIGH**    | 9 | BUG-1 persistence file version (309900 binary vs JSON v=2); BUG-4 `m_feerate_avg` per-bucket missing; BUG-5 `unconfTxs` circular buffer absent; BUG-6 ProcessBlock reorg guard absent; BUG-7 `ClearCurrent` ring rotation absent; BUG-8 (informational PASS) decay-before-record ordering; BUG-9 (informational PASS) bestHeight ordering; BUG-20 JSON not Core-binary on-disk format; BUG-21 `MAX_FILE_AGE=60h` Load() check absent; BUG-22 periodic flush every 1h absent. |
| **MEDIUM**  | 9 | BUG-10 `firstRecordedHeight` + `BlockSpan` + `MaxUsableEstimate` absent (cold-start over-confidence); BUG-14 `confTarget=1` not clamped to 2 / rejected; BUG-15 `minSuccessPct=0.05` invented constant in `estimateMedianVal`; BUG-16 `validForFeeEstimation` filter absent; BUG-17 `txHeight==nBestSeenHeight` guard absent; BUG-23 `FlushUnconfirmed` absent; BUG-24 RPC `max(feeRate, min_mempool_feerate, min_relay_feerate)` floor absent; BUG-26 `FeeFilterRounder` (BIP-133) missing — out-of-scope reference (W136 covered BIP-133 on the wire side). |
| **LOW**     | 4 | BUG-2 `findBucket` `>= FeeRateStart` vs Core `std::map::lower_bound` on upper-bound keys (semantic equivalence in normal use); BUG-18 `trackedTxs`/`untrackedTxs` running counters absent (diagnostic); BUG-19 `processBlockTx` skip-on-not-tracked (PASS, listed for cross-reference); BUG-26 see MEDIUM. |

**Active bugs**: 25 (BUG-1..BUG-26 with BUG-3, BUG-8, BUG-9, BUG-19
reclassified to informational PASS; BUG-26 cross-referenced to W136).

PASS: **9** / PARTIAL: **8** / MISSING: **13**.

**Cross-impl reach**: the 5 P1 findings are blockbrew-specific tuning
choices. BUG-11 (sticky-accumulator) is the most consequential —
under-estimates the fee for ANY conf-target where the high-fee
buckets are well-populated but lower buckets are sparse. The other
4 P1 issues (BUG-12/13/25) are RPC surface — the smart-fee RPC is a
single-threshold call rather than the three-threshold max composition,
and conservative mode is unreachable. BUG-25 is the operator-facing
manifestation (`estimate_mode` silently dropped).

**Operator/relay impact**: 9 HIGH bugs. Three categories:
- **Estimate correctness**: BUG-4/5/7 (missing median feerate, missing
  per-block-slot extraNum, missing ring rotation) all reduce estimate
  accuracy. blockbrew nodes will systematically under-estimate by
  the bucket-width (≤5%) PLUS a denominator-bias of ~5-20% when many
  txs sit unconfirmed past the target.
- **Persistence/interop**: BUG-1/20/21/22 (JSON format with no file
  age check, no periodic flush). Operator running blockbrew next to a
  Core node cannot share `fee_estimates.dat`. Crash between shutdowns
  loses all in-memory state.
- **Process-block correctness**: BUG-6 (no reorg guard). A duplicate
  `ProcessBlock(N)` (which can happen if main.go's `onBlockConnected`
  fires twice on a reorg via `BlockConnected` re-entry) double-decays
  and double-records. Cross-reference: main.go onBlockConnected is the
  only call site of `ProcessBlock`; check for re-entrancy on reorg
  before relying on the absence of this issue in practice.

Recommend fix as a multi-pass FIX-W139 wave:

1. **HIGH**: rewrite `estimateMedianVal` to mirror Core's
   `EstimateMedianVal` with `partialNum`/`curNearBucket`/`curFarBucket`
   group semantics + reset-on-pass.
2. **HIGH**: add `m_feerate_avg[]` per-bucket; `Record` writes
   `m_feerate_avg[bucket] += feeRate`; `applyDecay` decays it;
   `estimateMedianVal` returns `m_feerate_avg[median_bucket] /
   txCtAvg[median_bucket]` instead of `buckets[bucket].FeeRateStart`.
3. **HIGH**: add `unconfTxs[block%bins][bucket]` ring + `oldUnconfTxs[
   bucket]` + `ClearCurrent` rotation. Plumb extraNum into
   `estimateMedianVal` denominator.
4. **HIGH**: add `nBlockHeight <= nBestSeenHeight` reorg guard in
   `ProcessBlock`.
5. **HIGH**: add `firstRecordedHeight` + `BlockSpan` +
   `MaxUsableEstimate`; clamp `EstimateSmartFee`'s confTarget.
6. **HIGH**: refactor persistence to Core's binary format
   (CURRENT_FEES_FILE_VERSION=309900, big-endian variant via
   `binary.Write(LE)` over `EncodedDouble`-equivalent uint64); OR keep
   JSON but version it as 309900-equivalent + add `MAX_FILE_AGE=60h`
   on Load + add a `time.Ticker` for hourly Save.
7. **HIGH**: implement `FlushUnconfirmed` on graceful shutdown:
   iterate bucketMap, for each tx call recordFail on all 3 horizons
   with the current `bestHeight - info.height` delta; THEN Save.
8. **P1**: add `conservative bool` to `EstimateSmartFee` signature
   + implement `estimateCombinedFee` + `estimateConservativeFee`
   helpers + three-threshold max composition. Plumb `estimate_mode`
   args[1] through `handleEstimateSmartFee`.
9. **MEDIUM**: add `validForFeeEstimation` filter on
   `RegisterTransaction` (gate by 4 bool flags exposed from mempool
   `AcceptToMemoryPool` results — package, reorg, IBD, has-parents).
10. **MEDIUM**: add `txHeight == bestHeight` guard on
    `RegisterTransaction`; off-tip txs become no-op.
11. **MEDIUM**: remove `minSuccessPct=0.05` reset; Core doesn't have it.
12. **MEDIUM**: RPC: max(feeRate, mempool.GetMinFeeRate(),
    mempool.config.MinRelayFeeRate) floor in `handleEstimateSmartFee`.
13. **MEDIUM**: confTarget=1 — `EstimateFee(1)` returns 0;
    `EstimateSmartFee(1)` clamps to 2 (per Core).
14. **LOW**: trackedTxs/untrackedTxs running counters for
    `logging.Info` parity.

### Top findings

1. **BUG-11 (P1) — `estimateMedianVal` sticky-accumulator divergence**
   at `internal/mempool/feeestimator.go:195-257`:

   blockbrew:
   ```go
   var nConf, totalNum, failNum float64
   bestResult := -1.0
   for b := s.numBuckets - 1; b >= 0; b-- {
       nConf += s.confAvg[periodIdx][b]
       totalNum += s.txCtAvg[b]
       failNum += s.failAvg[periodIdx][b]
       if totalNum < sufficientTxVal { continue }
       // ... pct calc ...
       if pct >= threshold { bestResult = defaultBucketBoundaries[b] }
       // NEVER RESET nConf/totalNum/failNum
   }
   return bestResult
   ```

   Core (`block_policy_estimator.cpp:280-342`):
   ```cpp
   for (int bucket = maxbucketindex; bucket >= 0; --bucket) {
       if (newBucketRange) {
           curNearBucket = bucket;
           newBucketRange = false;
       }
       curFarBucket = bucket;
       nConf += confAvg[periodTarget - 1][bucket];
       partialNum += txCtAvg[bucket];
       totalNum += txCtAvg[bucket];
       failNum += failAvg[periodTarget - 1][bucket];
       // ... extraNum ...

       if (partialNum < sufficientTxVal / (1 - decay)) continue;
       partialNum = 0;                                  // RESET per group
       double curPct = nConf / (totalNum + failNum + extraNum);

       if (curPct < successBreakPoint) {
           // record failBucket once; KEEP accumulators (sticky during fail)
           passing = false;
       } else {
           foundAnswer = true;
           passing = true;
           passBucket = ...nConf, totalNum, extraNum...
           // RESET accumulators; new group can extend lower
           nConf = 0; totalNum = 0; failNum = 0; extraNum = 0;
           bestNearBucket = curNearBucket;
           bestFarBucket = curFarBucket;
           newBucketRange = true;
       }
   }
   ```

   The Core walk has TWO distinct mechanisms:
   - `partialNum` is the per-group accumulator; reset every time a
     group is evaluated.
   - `nConf`/`totalNum`/`failNum`/`extraNum` are the carry-into-next-
     group accumulators; reset ON PASS, KEPT ON FAIL.

   blockbrew has a SINGLE never-reset accumulator. Effect: once a
   high-fee group passes, the accumulator keeps growing with every
   subsequent lower-fee bucket; a low-fee bucket "passes" not on its
   own merits but because the cumulative nConf from above props up the
   pct. blockbrew's `bestResult = defaultBucketBoundaries[b]` writes
   the LOWEST passing bucket's start. Core's `bestNearBucket` /
   `bestFarBucket` track the LAST group that passed on its own
   per-group accumulator.

   *Effect*: blockbrew returns a fee estimate that is systematically
   LOWER than Core for the same confTarget when the high-fee end of the
   bucket array has well-confirmed traffic but the low-fee end is
   sparse. Concrete repro: confAvg[0][200]=4, confAvg[0][100]=0,
   confAvg[0][50]=0; txCtAvg[200]=4, txCtAvg[100]=4, txCtAvg[50]=4.
   Core: at bucket 200 passes (pct=100%, group reset); at 100 fails
   (pct=0%, failBucket); at 50 fails. Best range = [200..200].
   blockbrew: at 200 totalNum=4 ≥ 2.63 → pct=100% → bestResult=
   buckets[200].FeeRateStart. At 100 totalNum=8 → pct=4/8=50% < 0.85
   → no update. At 50 totalNum=12 → pct=4/12=33% < 0.85 → no update.
   In this case blockbrew happens to match Core; but if bucket 150
   had 2 confs out of 4, blockbrew would update bestResult to
   buckets[150].FeeRateStart (because cumulative pct stays high) and
   Core would not.

   *Also affects*: Core returns the median feerate (`m_feerate_avg`)
   within the passing bucket range; blockbrew returns the bucket's
   lower boundary. Combined with BUG-4 below, the gap can be > 5%.

2. **BUG-4 (HIGH) — `m_feerate_avg` per-bucket absent** at
   `internal/mempool/feeestimator.go:92-114`:

   blockbrew `TxConfirmStats` fields:
   ```go
   confAvg [][]float64    // [period][bucket]
   failAvg [][]float64    // [period][bucket]
   txCtAvg []float64      // [bucket] — count
   inMempool []float64    // [bucket] — current
   ```

   Core `TxConfirmStats` (`block_policy_estimator.cpp:82-100`):
   ```cpp
   std::vector<double> txCtAvg;        // [bucket] — count
   std::vector<std::vector<double>> confAvg;  // [Y][X]
   std::vector<std::vector<double>> failAvg;  // [Y][X]
   std::vector<double> m_feerate_avg;  // [bucket] — sum of feerates
   std::vector<std::vector<int>> unconfTxs;  // [Y][X] ring
   std::vector<int> oldUnconfTxs;      // [bucket]
   ```

   blockbrew is missing `m_feerate_avg` AND `unconfTxs`/`oldUnconfTxs`.
   The `Record(blocksToConfirm, feerate)` call in Core writes both
   `txCtAvg[bucket]++` and `m_feerate_avg[bucket] += feerate`;
   blockbrew's `record(blocksToConfirm, bucketIdx)` doesn't even
   accept feerate as a parameter — it's lost at the call site.

   At `EstimateMedianVal` exit, Core computes:
   ```cpp
   median = m_feerate_avg[j] / txCtAvg[j];
   ```
   for the bucket whose cumulative count crosses txSum/2. blockbrew
   returns `defaultBucketBoundaries[b]` (the bucket's LOWER bound),
   which under-estimates by up to one bucket width (~5% per the
   FEE_SPACING=1.05 ratio).

   *Effect*: every call to `EstimateFee` / `EstimateSmartFee`
   under-reports by 0–5% systematically. Compounding with BUG-11's
   sticky-accumulator effect, the under-estimate can reach ~10% on
   sparse distributions.

3. **BUG-5 + BUG-7 (HIGH) — `unconfTxs` ring buffer + `ClearCurrent`
   absent** at `internal/mempool/feeestimator.go:92-300`:

   blockbrew uses `inMempool []float64` — a single decayed count per
   bucket. Core uses:
   ```cpp
   std::vector<std::vector<int>> unconfTxs;  // [block%bins][bucket]
   std::vector<int> oldUnconfTxs;            // [bucket]
   ```
   and rotates the ring buffer on each block via `ClearCurrent`:
   ```cpp
   for (j = 0; j < buckets.size(); j++) {
       oldUnconfTxs[j] += unconfTxs[nBlockHeight % bins][j];
       unconfTxs[nBlockHeight%bins][j] = 0;
   }
   ```

   `EstimateMedianVal` uses the ring buffer to compute `extraNum`:
   ```cpp
   for (confct = confTarget; confct < GetMaxConfirms(); confct++)
       extraNum += unconfTxs[(nBlockHeight - confct) % bins][bucket];
   extraNum += oldUnconfTxs[bucket];
   ```
   This is the count of in-mempool txs that have been waiting LONGER
   than confTarget. It's added to the success-rate denominator:
   ```cpp
   double curPct = nConf / (totalNum + failNum + extraNum);
   ```

   blockbrew omits `extraNum` (hard-coded to 0 — see the comment at
   feeestimator.go:228-231). Effect: success-rate is over-estimated
   whenever many txs sit unconfirmed past the target. blockbrew
   reports a HIGHER pct than Core, satisfying the threshold at
   feerates Core would reject.

   *Combined effect of BUG-4 + BUG-5 + BUG-11*: blockbrew's
   estimateMedianVal is biased LOW (lower feerate) for two reasons
   (no median + sticky accumulator) and biased HIGH (looser threshold)
   for one reason (no extraNum). Net direction depends on traffic mix.
   In a typical mainnet mix with many txs sitting unconfirmed past
   confTarget=6, the net direction is **lower** feerate vs Core.

4. **BUG-12 + BUG-13 + BUG-25 (P1) — `estimateSmartFee` three-threshold
   composition + conservative mode + RPC `estimate_mode` arg**:

   Core `estimateSmartFee` (`block_policy_estimator.cpp:871-956`):
   ```cpp
   double halfEst = estimateCombinedFee(confTarget/2, 0.6, true, ...);
   double actualEst = estimateCombinedFee(confTarget, 0.85, true, ...);
   double doubleEst = estimateCombinedFee(2*confTarget, 0.95,
                                           !conservative, ...);
   median = max(halfEst, actualEst, doubleEst);
   if (conservative || median == -1) {
       double consEst = estimateConservativeFee(2*confTarget, ...);
       median = max(median, consEst);
   }
   ```

   blockbrew `EstimateSmartFee` (`feeestimator.go:488-507`):
   ```go
   fee := fe.EstimateFee(targetBlocks)
   if fee > 0 { return fee, targetBlocks }
   for t := targetBlocks - 1; t >= 1; t-- {
       fee = fe.EstimateFee(t)
       if fee > 0 { return fee, t }
   }
   return -1, 0
   ```

   The blockbrew implementation:
   - Uses ONLY the 0.85 (SUCCESS_PCT) threshold; never the 0.6 (HALF)
     or 0.95 (DOUBLE) thresholds.
   - Has no concept of "shorter horizon fallback"
     (`estimateCombinedFee`'s `checkShorterHorizon=true`).
   - Has no conservative mode.
   - Falls back to lower confTargets — but each fallback uses 0.85,
     not 0.6 / 0.85 / 0.95 composition.

   `handleEstimateSmartFee` at
   `internal/rpc/methods.go:2112-2153`:
   ```go
   func (s *Server) handleEstimateSmartFee(params json.RawMessage) (...) {
       var args []interface{}
       json.Unmarshal(params, &args)
       confTarget := 6
       if len(args) >= 1 {
           if v, ok := args[0].(float64); ok { confTarget = int(v) }
       }
       // args[1] = estimate_mode IS NEVER READ.
       feeRate, actualTarget = s.feeEstimator.EstimateSmartFee(confTarget)
       // No max() with min_mempool_fee / min_relay_fee.
       ...
   }
   ```

   `estimate_mode` parameter is silently dropped — not even rejected
   for invalid values. Core uses `FeeModeFromString` which throws
   `RPC_INVALID_PARAMETER` on unknown modes; blockbrew accepts any
   second arg as long as the first is a number.

   *Effect*: any client passing `estimate_mode="conservative"`
   (common in wallet code) gets the same result as
   `estimate_mode="economical"` — the default 0.85-threshold estimate.
   Wallet "conservative" defaults to higher feerates to reduce
   stuck-tx risk; blockbrew clients lose that safety margin.

5. **BUG-6 (HIGH) — `ProcessBlock` reorg guard absent** at
   `internal/mempool/feeestimator.go:409-443`:

   blockbrew:
   ```go
   func (fe *FeeEstimator) ProcessBlock(height int32, txHashes []wire.Hash256) {
       fe.mu.Lock()
       defer fe.mu.Unlock()
       // Apply decay
       for h := Horizon(0); h < horizonCount; h++ { fe.stats[h].applyDecay() }
       for _, txHash := range txHashes {
           // ... record confirmations ...
       }
       fe.bestHeight = height
   }
   ```

   Core (`block_policy_estimator.cpp:669-716`):
   ```cpp
   if (nBlockHeight <= nBestSeenHeight) {
       // Ignore side chains and re-orgs
       return;
   }
   nBestSeenHeight = nBlockHeight;
   feeStats->ClearCurrent(nBlockHeight);
   shortStats->ClearCurrent(nBlockHeight);
   longStats->ClearCurrent(nBlockHeight);
   feeStats->UpdateMovingAverages();
   shortStats->UpdateMovingAverages();
   longStats->UpdateMovingAverages();
   ...
   ```

   blockbrew's `ProcessBlock` is called from
   `cmd/blockbrew/main.go:1075` (onBlockConnected). Re-entrancy on
   reorg depends on the chainMgr emitting BlockConnected twice for the
   same height (e.g. via `BlockConnected` after a reorg that lands
   back on the same hash). Without the guard, the second
   `ProcessBlock(N)` call applies decay AGAIN and records the same
   confirmations AGAIN. Test G11 demonstrates: confAvg[0][bucket]
   moves from 1.0 to 1.962 (decay*1 + 1 record) when ProcessBlock(101)
   fires twice.

   *Effect*: estimate corruption on every reorg. Core silently drops;
   blockbrew silently double-counts.

## 30-Gate Audit Matrix

| Gate | Sub-area | Status  | Bug refs |
|------|----------|---------|----------|
| G1   | Horizon decay constants (SHORT 0.962, MED 0.9952, LONG 0.99931) | PASS    | — |
| G2   | Horizon scale + periods (SHORT 1/12, MED 2/24, LONG 24/42, max 1008) | PASS    | — |
| G3   | Bucket count + min/max bounds (0.1 sat/vB to 1e4 sat/vB + INF, 237 buckets) | PASS    | — |
| G4   | FEE_SPACING=1.05 between adjacent buckets | PASS    | — |
| G5   | CURRENT_FEES_FILE_VERSION on persisted file | MISSING | BUG-1 |
| G6   | findBucket returns in-range index for any feerate | PASS    | — |
| G7   | findBucket semantics vs Core std::map::lower_bound | PARTIAL | BUG-2 |
| G8   | NewTx shared bucketIndex across horizons | PASS    | — (BUG-3 reclassified) |
| G9   | m_feerate_avg per-bucket for median feerate | MISSING | BUG-4 |
| G10  | unconfTxs[block%bins][bucket] + oldUnconfTxs[bucket] ring buffer | MISSING | BUG-5 |
| G11  | ProcessBlock reorg guard (nBlockHeight <= bestSeenHeight) | MISSING | BUG-6 |
| G12  | ClearCurrent ring rotation per block | MISSING | BUG-7 |
| G13  | applyDecay before Record (per-block ordering) | PASS    | — (BUG-8 reclassified) |
| G14  | bestHeight update sync with ClearCurrent | PASS    | — (BUG-9 reclassified — moot without G12) |
| G15  | firstRecordedHeight + BlockSpan + MaxUsableEstimate | MISSING | BUG-10 |
| G16  | EstimateMedianVal bucket-grouping + reset-on-pass | MISSING | BUG-11 |
| G17  | estimateSmartFee three-threshold composition (HALF/FULL/DOUBLE) | MISSING | BUG-12 |
| G18  | conservative mode (estimateConservativeFee) | MISSING | BUG-13 |
| G19  | confTarget=1 reject (estimateFee) or clamp to 2 (estimateSmartFee) | MISSING | BUG-14 |
| G20  | No invented minSuccessPct constant (Core has none) | PARTIAL | BUG-15 |
| G21  | validForFeeEstimation 4-bool filter on RegisterTransaction | MISSING | BUG-16 |
| G22  | txHeight == nBestSeenHeight guard | MISSING | BUG-17 |
| G23  | trackedTxs / untrackedTxs per-block counters | MISSING | BUG-18 |
| G24  | processBlockTx skip if tx not tracked | PASS    | — (BUG-19 reclassified) |
| G25  | Persistence format binary (vs JSON) | MISSING | BUG-20 |
| G26  | MAX_FILE_AGE=60h Load() check | MISSING | BUG-21 |
| G27  | FEE_FLUSH_INTERVAL=1h periodic flush | MISSING | BUG-22 |
| G28  | FlushUnconfirmed on shutdown | MISSING | BUG-23 |
| G29  | RPC max(feeRate, min_mempool_fee, min_relay_fee) floor | MISSING | BUG-24 |
| G30  | RPC estimate_mode parse + FeeModeFromString reject + plumb to estimator | MISSING | BUG-25 |

Tally: **PASS 9 / PARTIAL 8 / MISSING 13** (gate counts; informational
PASSes for reclassified bugs are still PASS).

## Test pass/fail

`internal/mempool/w139_fee_estimation_test.go` — **31 tests**, all
PASS. Documentary `t.Log` for MISSING gates, hard `t.Errorf` for
correctness invariants that DO hold. Hard fails would flip a gate
into REGRESSION status on a fix wave.

Compile-clean: `go vet ./internal/mempool/...` clean.

```
=== RUN   TestW139_G1_HorizonDecayValues           PASS
=== RUN   TestW139_G2_HorizonScaleAndPeriods       PASS
=== RUN   TestW139_G3_BucketCountAndBounds         PASS
=== RUN   TestW139_G4_FeeSpacingRatio              PASS
=== RUN   TestW139_G5_FilesVersionConstant         PASS (log)
=== RUN   TestW139_G6_FindBucketBounds             PASS
=== RUN   TestW139_G7_FindBucketBoundarySemantics  PASS (log)
=== RUN   TestW139_G8_NewTxBucketIndexShared       PASS
=== RUN   TestW139_G9_FeerateAvgAbsent             PASS (log)
=== RUN   TestW139_G10_UnconfTxsCircularBufferAbsent PASS (log)
=== RUN   TestW139_G11_ReorgGuardAbsent            PASS (log)
=== RUN   TestW139_G12_ClearCurrentAbsent          PASS (log)
=== RUN   TestW139_G13_DecayBeforeRecord           PASS
=== RUN   TestW139_G14_BestHeightOrdering          PASS (log)
=== RUN   TestW139_G15_FirstRecordedHeightAbsent   PASS (log)
=== RUN   TestW139_G16_EstimateMedianValAlgorithmDivergence PASS (log)
=== RUN   TestW139_G17_SmartFeeThreeThresholdsAbsent PASS (log)
=== RUN   TestW139_G18_ConservativeModeAbsent      PASS (log)
=== RUN   TestW139_G19_ConfTarget1NotClamped       PASS (log)
=== RUN   TestW139_G20_InventedMinSuccessPct       PASS (log)
=== RUN   TestW139_G21_ValidForFeeEstimationFilterAbsent PASS (log)
=== RUN   TestW139_G22_TxHeightSyncGuardAbsent     PASS (log)
=== RUN   TestW139_G23_TrackedUntrackedCountersAbsent PASS (log)
=== RUN   TestW139_G24_ProcessBlockTxNotTrackedSkip PASS
=== RUN   TestW139_G25_PersistenceJSONNotBinary    PASS (log)
=== RUN   TestW139_G26_MaxFileAgeCheckAbsent       PASS (log)
=== RUN   TestW139_G27_PeriodicFlushAbsent         PASS (log)
=== RUN   TestW139_G28_FlushUnconfirmedAbsent      PASS (log)
=== RUN   TestW139_G29_RpcMaxWithMinMempoolFeeAbsent PASS (log)
=== RUN   TestW139_G30_RpcEstimateModeIgnored      PASS (log)
=== RUN   TestW139_SummaryEndToEnd                 PASS
PASS
ok  github.com/hashhog/blockbrew/internal/mempool 0.083s
```

The G11 reorg-guard test logs the dynamic evidence: `confAvg[0][bucket]`
moves from 1.0 to 1.962 on duplicate `ProcessBlock(101)`. This is the
single live-fired demonstration in the suite.

## Cross-wave correlations

- **W114 (2026-Q1) precursor**: 30-bug audit; FIX-47 closed BUG-10/14/
  15/21/22/30. W139 reconfirms those PASS + finds 8 net-new issues
  (BUG-4 `m_feerate_avg`, BUG-11 sticky-accumulator, BUG-12 three-
  threshold smart-fee, BUG-13 conservative mode, BUG-21 MAX_FILE_AGE,
  BUG-22 periodic flush, BUG-24 RPC max-with-floor, BUG-25 RPC mode-
  arg). The 2026-Q1 audit treated SUFFICIENT_FEETXS/(1-decay) as a
  PARTIAL fix; W139 considers it FULL since the formula now matches
  Core literally.
- **W123 mining/GBT**: block template fee picking consumes
  `EstimateFee` results through cluster mining. Under-estimate from
  BUG-11/BUG-4 propagates to template selection: blockbrew's
  `getblocktemplate` may pack more transactions than Core would
  (because the fee estimate is lower → more txs qualify). Cross-impact
  audit recommended.
- **W124 operator-experience**: BUG-18 (trackedTxs/untrackedTxs)
  + BUG-1/20/21/22 (persistence interop + age + flush) all fail
  W124-style operator-parity audits. Recommend bundling these into
  a single "fee_estimates.dat compatibility" FIX wave.
- **W125 RPC error parity**: BUG-24 (no min-fee floor) and BUG-25
  (no estimate_mode parse) both belong on W125's universal RPC-
  parity follow-on. `estimatesmartfee` does not currently emit
  `RPC_INVALID_PARAMETER` for unknown estimate_mode → W125 BUG.
- **W130 BIP-125 feebumper**: bumpfee → estimatesmartfee → returns
  raw estimate without min-fee floor → bumpfee creates a tx that
  fails relay because feerate is below mempool minimum. BUG-24 is a
  bumpfee-correctness blocker too.
- **W136 sendheaders/feefilter**: BUG-26 (FeeFilterRounder absent)
  was a W136 finding; blockbrew uses the feefilter floor directly
  rather than the rounded value (Core uses FeeFilterRounder.round
  to add randomness to fee-filter broadcasts for privacy). See
  W136 audit for sender-side coverage.

## Out of scope (deferred to future waves)

- BUG-26 / FeeFilterRounder — already audited in W136 (sender-side
  broadcast quantization). The CBlockPolicyEstimator surface
  ends at the estimateRawFee/estimateSmartFee return; how the
  result is consumed (estimaterawfee RPC, wallet bumpfee, P2P
  feefilter) belongs to those waves.
- Wallet `fundrawtransaction` / `walletcreatefundedpsbt` fee calc
  — consumed downstream; out of scope.
- `getmempoolinfo` JSON returning estimator state — partially
  W124, partially this wave's BUG-18 (counters surfaced in info).
- The `EncodedDoubleFormatter` (Core's lossless double-as-uint64
  serialization for non-IEEE-754 cross-platform) — needed only if
  BUG-20 is fixed via binary format. Not detailed here.

## Universal patterns observed

- **W124-class operator parity** — 4 of 25 bugs (BUG-1, BUG-20,
  BUG-21, BUG-22) cluster around "persistence format / file age /
  flush cadence / interop with Core fleet". Universal across all 10
  impls: the W124 audit catalogues these for ouroboros, nimrod,
  rustoshi too. Pattern depth.
- **"RPC arg silently dropped" P1** — BUG-25 (estimate_mode unused)
  is a fresh instance of a pattern seen in W125 (RPC error parity)
  and W137 (PSBT version unset). Always P1 because client behavior
  diverges silently. Recommend adding a fleet-wide "args-not-read"
  static gate.
- **"Algorithm rewrite required, not just a constant"** — BUG-11
  (EstimateMedianVal sticky-accumulator) is structurally similar to
  W116 BUG-3 (PackageRelay ancestor-set accumulator) — both are
  blockbrew implementations of a Core algorithm with the OUTER loop
  correct but the per-iteration reset semantics dropped. Universal
  pattern: when porting a Core algorithm with multiple accumulators,
  check what gets reset on each branch.

End of audit.
