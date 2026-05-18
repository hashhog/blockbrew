# W153 — Mempool eviction + tx-removed signals + min-relay fee (blockbrew)

**Wave:** W153 — `CTxMemPool::TrimToSize`,
`CTxMemPool::GetMinFee` (rolling-fee decay),
`trackPackageRemoved`, `removeForBlock`, `removeForReorg`,
`removeConflicts`, `RemoveStaged`, `Expire`,
`DEFAULT_MAX_MEMPOOL_SIZE_MB=300`,
`DEFAULT_MEMPOOL_EXPIRY_HOURS=336`,
`DEFAULT_INCREMENTAL_RELAY_FEE=100` (post-July-2025 Core; was 1000),
`DEFAULT_MIN_RELAY_TX_FEE=100` (post-July-2025 Core; was 1000),
`MemPoolRemovalReason` enum + ZMQ/REST/fee-est/wallet fan-out,
`MaybeUpdateMempoolForReorg`, `prioritisetransaction` /
`getprioritisedtransactions` RPCs, `getmempoolinfo` shape.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/txmempool.cpp:861-911` — `TrimToSize(sizelimit, pvNoSpendsRemaining)` —
  evicts worst-chunk via `m_txgraph->GetWorstMainChunk` while
  `DynamicMemoryUsage() > sizelimit`; bumps `rollingMinimumFeeRate` to
  evicted-chunk-feerate + `incremental_relay_feerate`; records freed
  outpoints into `pvNoSpendsRemaining` so the caller (ATMP) can drop
  orphan-tx cached state.
- `bitcoin-core/src/txmempool.cpp:829-851` — `GetMinFee(sizelimit)`:
  rolling-fee floor with halflife decay; base halflife
  `ROLLING_FEE_HALFLIFE = 12*60*60` (12 h);
  halflife/2 when `DynamicMemoryUsage() < sizelimit/2`,
  halflife/4 when `< sizelimit/4`; decay only after
  `lastRollingFeeUpdate + 10s`; zeroed when
  rolling < `incremental_relay_feerate/2`; floored at
  `incremental_relay_feerate`.
- `bitcoin-core/src/txmempool.cpp:853-859` — `trackPackageRemoved(rate)`
  bumps `rollingMinimumFeeRate` to `rate` (sat/kvB) when greater;
  clears `blockSinceLastRollingFeeBump` so the next `GetMinFee` call
  does not decay immediately.
- `bitcoin-core/src/txmempool.cpp:405-431` — `removeForBlock(vtx, height)`:
  evicts confirmed txs with `REASON::BLOCK`; for each confirmed tx
  calls `removeConflicts(tx)` (REASON::CONFLICT) AND
  `ClearPrioritisation(hash)`; sets `lastRollingFeeUpdate = GetTime()`
  + `blockSinceLastRollingFeeBump = true`; emits
  `MempoolTransactionsRemovedForBlock` validation-interface signal
  carrying every removed entry.
- `bitcoin-core/src/txmempool.cpp:388-403` — `removeConflicts(tx)`
  walks `mapNextTx` for each input, recursively removes any in-mempool
  spending tx via `removeRecursive(... CONFLICT)`, and clears
  prioritisation on each conflict's hash.
- `bitcoin-core/src/txmempool.cpp:333-386` — `removeForReorg(chain, filter)`:
  walks `mapTx`, calls the filter `bool(txiter)` (Core's
  `check_final_and_mature`) which evaluates `IsFinalTx(... tip+1)` AND
  `CheckSequenceLocksAtTip` AND coinbase maturity; collects failures
  + descendants and `removeUnchecked(... REORG)` them.
- `bitcoin-core/src/txmempool.cpp:811-827` — `Expire(time)`: walks
  the time-ordered index, stages every entry older than `time` plus
  all descendants, and `RemoveStaged(stage, REASON::EXPIRY)`.
- `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg` — driver
  that, on each `DisconnectTip` inside `ActivateBestChainStep`, calls
  `mempool.removeForReorg(...)` then re-adds the just-disconnected
  block's non-coinbase txs into the mempool (via individual
  `AcceptToMemoryPool` calls) BEFORE the next `ConnectTip` runs.
- `bitcoin-core/src/policy/policy.h:48,70` — Core defaults
  **lowered 2025-07-29** by glozow commit `66559d1a4a`:
  `DEFAULT_INCREMENTAL_RELAY_FEE{100}` (was 1000 prior),
  `DEFAULT_MIN_RELAY_TX_FEE{100}` (was 1000 prior).
- `bitcoin-core/src/policy/policy.h:68` — `DUST_RELAY_TX_FEE{3000}`
  (UNCHANGED, separate from MIN_RELAY).
- `bitcoin-core/src/kernel/mempool_options.h:19,23,40-44` —
  `DEFAULT_MAX_MEMPOOL_SIZE_MB{300}`,
  `DEFAULT_MEMPOOL_EXPIRY_HOURS{336}`,
  `max_size_bytes{DEFAULT_MAX_MEMPOOL_SIZE_MB * 1'000'000}`,
  `expiry{hours{336}}`,
  `incremental_relay_feerate{DEFAULT_INCREMENTAL_RELAY_FEE}`,
  `min_relay_feerate{DEFAULT_MIN_RELAY_TX_FEE}`.
- `bitcoin-core/src/init.cpp:511,650,673,677` — `-mempoolexpiry`,
  `-limitancestorcount`, `-incrementalrelayfee`, `-datacarrier` CLI
  flags (none present in blockbrew).
- `bitcoin-core/src/zmq/zmqpublishnotifier.cpp:212-293` — ZMQ
  publishers: hash topics REVERSE the hash byte-order
  (`data[31 - i] = hash.begin()[i]`) so wire output is DISPLAY order;
  `NotifyTransactionRemoval(tx, mempool_sequence)` emits sequence
  label `R` after every mempool drop.
- `bitcoin-core/src/txmempool.h:212` —
  `ROLLING_FEE_HALFLIFE = 60 * 60 * 12` (12 hours — there is ONE
  halflife constant; `halflife /= 2` / `/= 4` are runtime divisions,
  not separate `HALFLIFE_SMALL / HALFLIFE_LARGE` constants — the
  prompt's "HALFLIFE_LARGE=900 / HALFLIFE_SMALL=600" reference is
  outdated wording; Core's actual constant is the single 12 h value).
- `bitcoin-core/src/txmempool.cpp:778-781` — `DynamicMemoryUsage()`:
  `MallocUsage(sizeof(CTxMemPoolEntry) + 9*sizeof(void*)) * mapTx.size() + mapNextTx + mapDeltas + txns_randomized + m_txgraph->GetMainMemoryUsage() + cachedInnerUsage`
  — i.e. **heap overhead INCLUDING per-entry struct + maps + txgraph
  + serialised-tx innerUsage**, NOT raw tx vsize. A typical mainnet
  mempool with `mapTx.size() ≈ 50_000` consumes ~250–300 MB of
  `DynamicMemoryUsage` for ~30–60 MB of raw tx vsize — a ~5–10× ratio.

**Files audited**
- `internal/mempool/mempool.go` — `Config{MaxSize,MinRelayFeeRate,IncrementalRelayFee,MaxOrphanTxs}`,
  `DefaultMempoolExpiryHours = 336`, `rollingFeeHalflife`,
  `MemPoolRemovalReason{Unknown,Expiry,SizeLimit,Reorg,Block,Conflict,Replaced}`,
  `maybeEvictLocked` (line 2205-2276 — TrimToSize analogue),
  `trackPackageRemovedLocked` (2190-2203),
  `getMinFeeRateLocked` (2622-2684), `BlockConnected` (2393-2425),
  `BlockDisconnected` (2429-2441), `Expire` (2448-2479),
  `RemoveForReorg` (2494-2528), `removeWithDescendantsLocked`,
  `removeSingleTxLocked` (1882-1961), `OnTxEvicted` callback hook
  (594-611), `mapDeltas` (633), `isDust` (1439-1467),
  `totalSize` accounting (337, 577, 1353, 2050-2055, 2213, 2725).
- `internal/mempool/cluster.go` — `ClusterManager`,
  `GetWorstChunkForEviction` (1173-1198).
- `internal/mempool/persist.go` — `unbroadcastCount` read at
  line 414-422 but field is always 0 on Dump (line 256-259 comment
  "blockbrew does not yet track an unbroadcast set").
- `internal/rpc/methods.go` — `handleGetMempoolInfo` (1290-1322)
  HARDCODES `MaxMempool=300_000_000`, `MempoolMinFee/MinRelayTxFee/IncrementalRelayFee=0.00001`,
  `UnbroadcastCount=0`, `Usage = TotalSize()` (line 1307 comment
  "Simplified: actual usage would include overhead").
- `internal/rpc/extra_methods.go` — `handlePrioritiseTransaction`
  (344-420), `handleGetPrioritisedTransactions` (429+).
- `internal/rpc/rest.go` — `handleRESTMempoolInfo` (461-477),
  `handleRESTMempoolContents` (479-496) — both delegate to the
  hardcoded `handleGetMempoolInfo`.
- `internal/rpc/types.go:233-247` — `MempoolInfo` JSON shape;
  field `UnbroadcastCount` plumbed but always zero.
- `cmd/blockbrew/main.go` — `-maxmempool`, `-minrelayfee`,
  `-mempoolfullrbf` (lines 467-469); `mempool.New` wiring (812-828);
  `OnTxEvicted` registration (1002-1004) — fee-est only; ZMQ
  fan-out for accept exists (1157) but NO removal fan-out;
  `chainMgr.SetOnBlockDisconnected` (880-890) — calls
  `mp.BlockDisconnected` but never `mp.RemoveForReorg`;
  `mp.Load(LoadOptions{MaxAge: 14*24*time.Hour})` on startup (1008);
  no periodic `mp.Expire` ticker anywhere (only `orphanExpireTicker`,
  1415-1424).
- `cmd/blockbrew/zmqpub.go` — `zmqSeqLabelTxRemove = 'R'` defined
  (line 35) but **never referenced**; `PublishTxAccepted` (250-278)
  exists, `PublishTxRemoved` ABSENT; `hash[:]` written raw at
  222/236/256/271 (INTERNAL byte-order, NOT display order Core uses).

---

## Gate matrix (40 sub-gates / 14 behaviours)

| #  | Behaviour | Sub-gate | Verdict |
|----|-----------|----------|---------|
| 1  | DEFAULT_MAX_MEMPOOL_SIZE_MB=300 enforced | G1: `-maxmempool=300` MB → 300_000_000 byte cap | PASS (`main.go:467,815`) |
| 1  | … | G2: cap measured against **DynamicMemoryUsage** (Core: ~5-10× raw tx vsize) | **BUG-1 (P0-CDIV)** — `mp.totalSize` accumulates raw vsize only (`mempool.go:1353,2050-2055,2213`); blockbrew accepts ~5-10× more raw tx data than Core at the same `-maxmempool=300`. See BUG-1 below. |
| 2  | DEFAULT_MEMPOOL_EXPIRY_HOURS=336 | G3: constant exists | PASS (`mempool.go:26`, `DefaultMempoolExpiryHours = 336`) |
| 2  | … | G4: `mp.Expire(cutoff)` invoked periodically | **BUG-2 (P0)** — ZERO production callers of `mp.Expire` (grep across `internal/`, `cmd/` matches only tests + the function itself). The `orphanExpireTicker` at `main.go:1415-1424` calls `mp.ExpireOrphans()` (20-min orphan window) but NEVER `mp.Expire`. The 14-day mempool-expiry is DEAD CODE. See BUG-2. |
| 2  | … | G5: `-mempoolexpiry=<n>` CLI flag | **BUG-3 (P1)** — flag absent. `cfg.MempoolExpiry`, `mempoolexpiry` — zero matches in `cmd/`. No operator override of the hardcoded `14*24*time.Hour` baked into `mp.Load(LoadOptions{MaxAge: ...})` at `main.go:1008`. |
| 3  | DEFAULT_MIN_RELAY_TX_FEE=100 sat/kvB | G6: blockbrew default matches Core current (100 sat/kvB post-July-2025) | **BUG-4 (P0-CDIV)** — blockbrew defaults `MinRelayFeeRate = 1000` (`mempool.go:337, 390, 643`) and `-minrelayfee 0.00001 BTC/kvB = 1000 sat/kvB` (`main.go:468, 813`) — **10× Core's current default of 100**. A tx Core accepts at 0.1 sat/vB is rejected by blockbrew with `ErrInsufficientFee`. See BUG-4 (W151 BUG-1 re-anchor: Core lowered values 2025-07-29, blockbrew never tracked). |
| 4  | DEFAULT_INCREMENTAL_RELAY_FEE=100 sat/kvB | G7: blockbrew default matches Core current | **BUG-4 cross-cite** — blockbrew defaults `IncrementalRelayFee = 1000` (`mempool.go:338, 391, 646`); Core current is 100. RBF Rule 4 demands 10× the additional fee Core demands. The eviction rolling-fee bump (`trackPackageRemovedLocked` at `mempool.go:2236-2237`) also adds 10× the bump Core adds. |
| 4  | … | G8: `-incrementalrelayfee=<amt>` CLI flag | **BUG-5 (P1)** — flag absent. `cfg.IncrementalRelayFee`, `incrementalrelayfee` — zero matches in `cmd/`. Operator cannot tune. |
| 5  | Rolling-fee decay (GetMinFee semantics) | G9: 12h base halflife | PASS (`mempool.go:21`, `rollingFeeHalflife = 12*60*60`). |
| 5  | … | G10: halflife/2 when `totalSize < sizelimit/2` | PASS (`mempool.go:2654-2658`) **but** comparison uses `mp.totalSize` (raw vsize) not `DynamicMemoryUsage` (BUG-1 cascade) → halflife adapts wrongly. |
| 5  | … | G11: halflife/4 when `totalSize < sizelimit/4` | PASS (`mempool.go:2654-2656`) — same caveat as G10. |
| 5  | … | G12: zero rolling when `< incremental/2` | PASS (`mempool.go:2666-2669`). |
| 5  | … | G13: decay only after `+10s` cooldown | PASS (`mempool.go:2649`). |
| 5  | … | G14: floored at `incrementalRelay` (not `minRelay`) | **BUG-6 (P1)** — `getMinFeeRateLocked` floors at `mp.config.MinRelayFeeRate` (`mempool.go:2680-2683`) in addition to `IncrementalRelayFee`. Core's `GetMinFee` returns `std::max(rolling, incremental_relay_feerate)` — no `min_relay_feerate` floor inside `GetMinFee` itself (the min-relay floor is enforced separately at ATMP). blockbrew double-counts the floor. With defaults that match (both 1000) this is a no-op; the moment an operator sets one without the other (BUG-4 fix or BUG-5 fix), the gates diverge. |
| 6  | TrimToSize semantics | G15: while-loop on `totalSize > maxSize` | PASS (`mempool.go:2213`). |
| 6  | … | G16: bumps rolling = `removedRate + incrementalRelay` | PASS (`mempool.go:2237, 2265`). |
| 6  | … | G17: track-package-removed sets `blockSinceLastRollingFeeBump = false` | PASS (`mempool.go:2198-2202`). |
| 6  | … | G18: `pvNoSpendsRemaining` orphan-cleanup outparam wired to caller | **BUG-7 (P1)** — `maybeEvictLocked` does NOT return / populate the freed-outpoint list. Core's `TrimToSize(sizelimit, pvNoSpendsRemaining)` records every input of an evicted tx whose parent is no longer in the pool, so `ATMP` can drop the orphan-tx cache for outpoints that will never be spent. blockbrew's ATMP / orphan-pool keeps stale cache entries pointing at freed outpoints. |
| 6  | … | G19: `m_have_changeset` invariant — TrimToSize MUST NOT fire mid-package-eval | **BUG-8 (P1)** — Core asserts `Assume(!m_have_changeset)` at `txmempool.cpp:863` to prevent TrimToSize from running while a package is being staged. blockbrew has no `m_have_changeset` equivalent; `maybeEvictLocked` is called unconditionally from `AddTransaction` (`mempool.go:1369`) AND from package-accept (`mempool.go:3602`) without any "package commit in-flight" guard. Concurrent (package-add + Trim) under the same `mp.mu` is fine, but the package atomicity invariant Core protects is absent. |
| 7  | MemPoolRemovalReason enum | G20: enum exists with 7 values (Unknown + 6 Core values) | PASS (`mempool.go:480-501`); `String()` returns Core-canonical lowercase names (505-522). |
| 7  | … | G21: REASON::BLOCK fired on confirmed-tx eviction | PASS (`mempool.go:2409`). |
| 7  | … | G22: REASON::CONFLICT fired on conflict-tx eviction | PASS (`mempool.go:2414`). |
| 7  | … | G23: REASON::REPLACED fired on RBF eviction | PASS (`mempool.go:1344`). |
| 7  | … | G24: REASON::SIZELIMIT fired on Trim eviction | PASS (`mempool.go:2240, 2272`). |
| 7  | … | G25: REASON::EXPIRY fired on Expire | PASS (`mempool.go:2476`); but Expire never runs (BUG-2). |
| 7  | … | G26: REASON::REORG fired on RemoveForReorg | PASS (`mempool.go:2525`); but RemoveForReorg never runs (BUG-9). |
| 8  | removed-signal fan-out | G27: OnTxEvicted callback wired into FeeEstimator UnregisterTransaction | PASS (`main.go:1002-1004`). |
| 8  | … | G28: OnTxEvicted fans out to ZMQ pubsequence label 'R' | **BUG-10 (P0-CDIV)** — `zmqSeqLabelTxRemove = 'R'` defined (`zmqpub.go:35`) but the symbol has **ZERO REFERENCES**. No `PublishTxRemoved` function. `OnTxEvicted` callback at `main.go:1002` is `func(txHash, _ reason) { feeEstimator.UnregisterTransaction(txHash) }` — does NOT call `zmqPub`. Core's `NotifyTransactionRemoval` (sequence 'R') is wired through `MempoolTransactionsRemovedForBlock` / `TransactionRemovedFromMempool` validation-interface signals. blockbrew skips the whole ZMQ removal path. See BUG-10. |
| 8  | … | G29: OnTxEvicted fans out to wallet `transactionRemovedFromMempool` (REPLACED → mark-as-bumped) | **BUG-11 (P0-CDIV)** — grep across `internal/wallet/` and `cmd/blockbrew/main.go` for `OnTxEvicted` / `transactionRemovedFromMempool` returns ZERO production wallet calls. The wallet has no per-tx hook for REPLACED → "this output is now superseded; reconsider as bumped"; for CONFLICT/EXPIRY/SIZELIMIT → "candidate for re-broadcast"; for REORG → "may re-confirm differently". W120 BUG-9 / FIX-73 wired the REASON parameter but never wired the wallet consumer. See BUG-11. |
| 8  | … | G30: OnTxEvicted fans out to REST `/rest/mempool/contents` invalidation signal | N/A — REST is poll-only in Core too. |
| 8  | … | G31: OnTxEvicted fans out to BlockFilterIndex / mempool sequence counter | PARTIAL — fee-estimator only; mempool sequence counter increments on accept (`zmqpub.go:269` `mempoolSeq` for 'A') but is NEVER incremented on removal because no removal publisher exists. The whole `sequence` topic's removal-tracking guarantee is broken. |
| 9  | BlockConnected / BlockDisconnected | G32: BlockConnected sets `lastRollingFeeUpdate = GetTime()` + `blockSinceLastRollingFeeBump = true` | PASS (`mempool.go:2423-2424`). |
| 9  | … | G33: BlockConnected calls `ClearPrioritisation(hash)` for every confirmed tx (Core line 420) | **BUG-12 (P1)** — `BlockConnected` removes the tx but never deletes from `mp.mapDeltas`. A re-broadcast of a confirmed tx weeks later (e.g. a reorg-revived tx) would still carry the stale delta. Core's `removeForBlock` line 420 explicitly calls `ClearPrioritisation(tx->GetHash())`. |
| 9  | … | G34: BlockDisconnected re-adds non-coinbase via AcceptToMemoryPool | PASS (`mempool.go:2434-2440`). |
| 9  | … | G35: BlockDisconnected (driven by chainMgr.SetOnBlockDisconnected hook) ALSO calls RemoveForReorg | **BUG-9 (P0-CDIV)** — `chainMgr.SetOnBlockDisconnected` at `main.go:880-890` calls `mp.BlockDisconnected(block)` but NEVER `mp.RemoveForReorg()`. RemoveForReorg has the right shape but ZERO production callers. Non-final / immature-coinbase txs that became invalid after the reorg STAY IN THE MEMPOOL. The W101 test file (`internal/consensus/w101_activate_best_chain_test.go:358-383`) flags exactly this gap and the comment says "Fix: call mp.RemoveForReorg() in the OnBlockConnected hook in main.go." — comment-as-confession that this is a known live bug. See BUG-9. |
| 10 | MaybeUpdateMempoolForReorg driver | G36: holds OnBlockDisconnected sequence stable across DisconnectTip / ConnectTip pairs (no half-state) | PARTIAL — `DisconnectBlock` defer-fires the callback OUTSIDE `cm.mu` (`chainmanager.go:1380-1385`); for a multi-block reorg, the BlockDisconnected calls are interleaved with subsequent ConnectBlock calls under different locks. Without RemoveForReorg between them (BUG-9), the mempool sees intermediate states where re-added txs may be temporarily invalid before the next reorg step recomputes locks. |
| 11 | ZMQ hash byte-order (W141 carry-forward) | G37: hashblock / hashtx wire bytes are DISPLAY order (Core line 215-216 reverses) | **BUG-13 (P0-CDIV cross-cite W141 BUG-1+2+3)** — `zmqpub.go:222,236,256,271` writes `hash[:]` raw, which is INTERNAL byte-order. Core writes `data[31-i] = hash.begin()[i]` (DISPLAY order). Downstream consumers (electrs, fulcrum, mempool.space, nbxplorer, btcrpcexplorer) all expect Core-compat display-order — blockbrew's ZMQ output is byte-reversed relative to every other indexer in the ecosystem. The W141 BUG-1+2+3 finding for blockbrew was logged but the fix has not landed. See BUG-13. |
| 12 | prioritisetransaction RPC | G38: dispatched, deltas stack, dummy=0 enforced | PASS (`server.go:589-590`, `extra_methods.go:367-420`). |
| 12 | … | G39: getprioritisedtransactions RPC dispatched | PASS (`extra_methods.go:429+`). |
| 12 | … | G40: deltas cleared from `mapDeltas` on block-connect (Core ClearPrioritisation) | **BUG-12 cross-cite**. |
| 13 | getmempoolinfo shape | G41: `mempoolminfee` reflects rolling fee + minrelay | **BUG-14 (P0-CDIV, W151 BUG-6 re-anchor)** — `methods.go:1310-1312` HARDCODES `MempoolMinFee=0.00001`, `MinRelayTxFee=0.00001`, `IncrementalRelayFee=0.00001` regardless of runtime config OR rolling-fee state. The `mp.GetMinFeeRate()` getter exists but is not called from `handleGetMempoolInfo`. Same for `MaxMempool=300_000_000` hardcoded ignoring operator override. Field always reports defaults. |
| 13 | … | G42: `usage` is `DynamicMemoryUsage()` not raw vsize | **BUG-15 (P1)** — `methods.go:1307` `Usage: s.mempool.TotalSize()` with inline comment "Simplified: actual usage would include overhead" — comment-as-confession. Core's `getmempoolinfo.usage` is the dynamic memory usage (heap overhead); blockbrew reports raw vsize. RPC consumer that gates on `usage / maxmempool` ratio sees the wrong fullness. |
| 13 | … | G43: `unbroadcastcount` reflects actual unbroadcast set size | **BUG-16 (P1)** — `methods.go:1313` `UnbroadcastCount: 0`. `persist.go:256-259` comment "blockbrew does not yet track an unbroadcast set". Core tracks `m_unbroadcast_txids` and exposes count. blockbrew's RPC always lies as 0. |
| 14 | -limit{ancestor,descendant}{count,size} CLI plumbing | G44: flags present | **BUG-17 (P1)** — `cmd/blockbrew/main.go` does NOT register `-limitancestorcount`, `-limitdescendantcount`, `-limitancestorsize`, `-limitdescendantsize`, or `-datacarrier{size}`. The `Config.AncestorLimit/DescendantLimit/AncestorSizeLimitKvB/DescendantSizeLimitKvB` fields exist in `Config` (`mempool.go:347-363`) but no flag wires them — they ride the defaults only. Operator cannot override Core's `25/25/101/101`. |

---

## BUG-1 (P0-CDIV) — `MaxSize` enforced against raw tx vsize, not `DynamicMemoryUsage`; effective mempool capacity is 5–10× Core's

**Severity:** P0-CDIV. The single most-impactful divergence in this
wave. Bitcoin Core's `TrimToSize` and `GetMinFee` both consult
`DynamicMemoryUsage()` (`txmempool.cpp:778-781`):

```cpp
return memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 9 * sizeof(void*)) * mapTx.size()
     + memusage::DynamicUsage(mapNextTx)
     + memusage::DynamicUsage(mapDeltas)
     + memusage::DynamicUsage(txns_randomized)
     + m_txgraph->GetMainMemoryUsage()
     + cachedInnerUsage;
```

This is **heap overhead** — per-entry struct allocations, the
`mapNextTx` index, the txgraph, the prioritisation map, plus the
per-tx `cachedInnerUsage` (which itself includes the serialised tx
bytes, the vector of inputs, the witness data, the script blobs, and
their malloc padding). For a representative mainnet mempool with
~50,000 transactions:

| Component | Approx |
|-----------|--------|
| `mapTx` entries (`CTxMemPoolEntry` ~480 B + 9-ptr padding) | ~30 MB |
| `mapNextTx` index (per-input) | ~10 MB |
| `m_txgraph->GetMainMemoryUsage()` | ~20 MB |
| `cachedInnerUsage` (serialised tx + inputs + witness) | ~150 MB |
| **Total DynamicMemoryUsage** | **~210 MB** |
| **Raw sum of `entry.GetTxSize()` (vsize)** | **~30 MB** |

I.e. `DynamicMemoryUsage / sum(vsize) ≈ 7×` on a typical mempool.

blockbrew's `mp.totalSize` (`mempool.go:577`) is the **sum of raw
vsizes only**:

```go
// mempool.go:1353 (AddTransaction)
mp.totalSize += vsize    // vsize = (weight + 3) / 4 — raw vbyte count, no overhead

// mempool.go:2213 (maybeEvictLocked)
for mp.totalSize > mp.config.MaxSize && len(mp.pool) > 0 { ... }
```

With `MaxSize = 300_000_000` bytes (300 MB; matches Core's
`DEFAULT_MAX_MEMPOOL_SIZE_MB=300` byte-for-byte), Core evicts at
~50k entries / 30 MB vsize. blockbrew does NOT evict until raw vsize
reaches 300 MB — which on the same mempool composition means
~500_000 entries before the first eviction fires.

Consequences:

1. **Mempool DoS surface ~10× wider than Core.** An adversary running
   a "mempool flooder" can hold ~10× as many transactions in
   blockbrew's mempool at the same resident-memory budget the
   operator configured.
2. **Process RSS grows ~10× past the configured `-maxmempool`.**
   Operator running `-maxmempool=300` sees their blockbrew node use
   ~3 GB of resident memory for mempool data before TrimToSize fires.
   On a memory-constrained host this is the difference between OOM
   and stable.
3. **Rolling-fee halflife thresholds are wrong** (BUG-1 cascade into
   G10 / G11). `getMinFeeRateLocked` at `mempool.go:2654` compares
   `mp.totalSize` to `sizelimit/4` / `sizelimit/2` — these
   thresholds were designed against DynamicMemoryUsage. Halflife
   shortens (3 h / 6 h instead of 12 h) far later than it should,
   keeping the rolling fee floor elevated longer than Core does.
4. **Fee-estimator drift** (downstream effect of (3)) — the
   smartfee bucket data is informed by removal timing, which is
   distorted.

**File:** `internal/mempool/mempool.go:577, 1353, 2050-2055, 2213,
2653-2658, 2725`; `internal/rpc/methods.go:1306-1307`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:778-781` (DynamicMemoryUsage),
`:868` (TrimToSize loop predicate), `:837/839`
(GetMinFee halflife thresholds).

**Fix sketch:** add `cachedInnerUsage` tracking — accumulate
`mempool.estimateMemUsage(entry)` per AddTransaction; include
cluster manager memory; compare against `MaxSize` directly. Roughly
~10 LOC + a helper that approximates `RecursiveDynamicUsage` for
Go objects.

---

## BUG-2 (P0) — `mp.Expire()` has ZERO production callers; the 336-hour mempool-expiry is dead code

**Severity:** P0. Bitcoin Core's `Expire` (`txmempool.cpp:811-827`)
is the mechanism that bounds mempool growth from accumulating txs
that have not been mined for 14 days (`DEFAULT_MEMPOOL_EXPIRY_HOURS=336`).
It is invoked from `LimitMempoolSize` (every periodic flush) and
from `TrimToSize` callers. Without it, a tx with fee just above the
relay floor that never quite makes it into a block (common during
low-feerate periods) **stays in the mempool indefinitely** until
SIZELIMIT or block-confirm removes it.

blockbrew defines `Expire(cutoff time.Time)` correctly at
`mempool.go:2448-2479` — walks entries, collects expired txs +
descendants, removes with `MempoolRemovalReasonExpiry`. The
function works. The constant `DefaultMempoolExpiryHours = 336` is
defined at line 26. But:

```
$ grep -rn "\.Expire(" cmd/ internal/ | grep -v "_test.go\|ExpireOrphan"
# (empty — zero production callers)
```

The `orphanExpireTicker` at `cmd/blockbrew/main.go:1415-1424` ticks
every `OrphanExpireDriverInterval` (1 min) and calls
`mp.ExpireOrphans()` — but ExpireOrphans only touches the
**orphan-tx pool** (20-min expiry). The full-mempool 14-day expiry
NEVER fires.

Failure mode: a node that has been up for >14 days with consistent
mempool entries accumulates an unbounded long tail of low-feerate
txs that have neither been mined nor evicted by TrimToSize (because
the mempool stays just below the 300 MB / -maxmempool ceiling).
Once `maybeEvictLocked` finally fires, it kicks out the wrong txs
(SIZELIMIT picks low-fee chunks, regardless of age) and the rolling
fee floor goes up needlessly. Operator sees `getmempoolinfo.size`
growing slowly past the expected steady-state.

Cross-cite to BUG-1: with the 5-10× capacity overhead bug,
LIMITMEMPOOLSIZE never gets close to firing in the first place, so
BUG-2 is more likely to be the dominant eviction mechanism. After
fixing BUG-1, BUG-2 must be fixed concurrently or the node spends
much more time at the rolling-fee floor.

**File:** `internal/mempool/mempool.go:26, 2448-2479` (definition);
`cmd/blockbrew/main.go:1408-1424` (only ticker is the orphan one).

**Core ref:** `bitcoin-core/src/txmempool.cpp:811-827` (Expire),
`bitcoin-core/src/validation.cpp::LimitMempoolSize` (the driver,
called from each `MaybeUpdateMempoolForReorg` and from
`PeriodicFlush`).

**Fix sketch:** add a 1-hour ticker beside `orphanExpireTicker`
that calls `mp.Expire(time.Now().Add(-DefaultMempoolExpiryHours * time.Hour))`.
~6 LOC.

---

## BUG-3 (P1) — `-mempoolexpiry` CLI flag absent

**Severity:** P1. Core's `-mempoolexpiry=<n>` (`init.cpp:511`)
exposes `DEFAULT_MEMPOOL_EXPIRY_HOURS=336` as an operator override.
A node operator who wants a more aggressive expiry (e.g. 24 h to
match a private testnet's block cadence) or a more lenient one
(e.g. 1000 h on a historical-data-collection node) cannot configure
blockbrew without source patch.

The constant is hardcoded TWICE: at `mempool.go:26` (the package
constant used by no caller — see BUG-2) AND at
`cmd/blockbrew/main.go:1008` as a literal `14 * 24 * time.Hour`
inside `mp.Load(LoadOptions{MaxAge: 14 * 24 * time.Hour})` (the
mempool.dat reload age-filter).

**File:** `cmd/blockbrew/main.go:1008` (literal); `Config` struct
in `mempool.go:335-384` has no `MempoolExpiry` field.

**Core ref:** `bitcoin-core/src/init.cpp:511`.

---

## BUG-4 (P0-CDIV) — IncrementalRelayFee & MinRelayFeeRate default 1000 sat/kvB; Core's current default is 100 (10× over)

**Severity:** P0-CDIV. This is the W151 BUG-1 re-anchor with a
sharper-than-realized impact: on **2025-07-29** Core merged commit
`66559d1a4a` ("[policy] lower default minrelaytxfee and
incrementalrelayfee to 100sat/kvB") by glozow. Prior to that, both
defaults were 1000 sat/kvB. blockbrew tracked the pre-2025-07
defaults and has never followed the lowered values.

```go
// mempool.go:389-391
MaxSize:                300_000_000,
MinRelayFeeRate:        1000,        // <- Core: 100 (since 2025-07-29)
IncrementalRelayFee:    1000,        // <- Core: 100 (since 2025-07-29)

// mempool.go:642-647
if config.MinRelayFeeRate == 0 { config.MinRelayFeeRate = 1000 }
if config.IncrementalRelayFee == 0 { config.IncrementalRelayFee = 1000 }

// main.go:468 — CLI default
flag.Float64Var(&cfg.MinRelayFee, "minrelayfee", 0.00001, ...) // 0.00001 BTC/kvB = 1000 sat/kvB
```

Concrete divergences:

1. **RBF Rule 4 fee-bump** (W151 BUG-1, re-anchor): replacement
   must pay `(vsize × IncrementalRelayFee + 999) / 1000` extra
   satoshis (`mempool.go:2883`). At blockbrew's 1000 sat/kvB this is
   1 sat/vB; Core's 100 sat/kvB makes the bump 0.1 sat/vB. A
   141-vbyte P2WPKH replacement requires 141 extra sats on blockbrew
   vs ~15 sats on Core — **~10× the fee bump**.
2. **TrimToSize rolling-fee floor bump** (`mempool.go:2236-2237,
   2265`): the eviction bump is `chunkRate + IncrementalRelayFee`.
   At blockbrew's 1000, an eviction near the chain-tip rate spikes
   the rolling floor ~1 sat/vB higher than Core does, suppressing
   marginal-fee tx admission for the next decay window.
3. **getMinFee floor** (`mempool.go:2680-2683`): every minimum-fee
   query is floored at 1000 sat/kvB regardless of mempool state.
   Cross-impl: any operator who connects blockbrew to a Core
   node-cluster expecting parity sees blockbrew reject txs Core
   accepts at the same feerate.
4. **Cross-impl mining decisions**: getblocktemplate's
   `min_relay_fee` field (advertised at `0.00001 BTC/kvB`) tells
   external miners blockbrew won't mine sub-1-sat/vB txs even
   though the operator using `-minrelayfee=0.000001` (Core's new
   default expressed in BTC/kvB) would expect 0.1 sat/vB inclusion.

The blockbrew `mempool.go` comments at lines 390 and 391 still say
"1 sat/vB" — comment-as-confession: 1000 sat/kvB = 1.0 sat/vB,
which is correct in absolute terms but obscures the fact that
Core's CURRENT minimum is 0.1 sat/vB, ten times lower.

This is also a `static_assert` symmetry gap: Core's
`bitcoin-core/src/policy/policy.h:48` and `:70` enforce
`DEFAULT_INCREMENTAL_RELAY_FEE == DEFAULT_MIN_RELAY_TX_FEE` by
sharing values. blockbrew's two constants are equal by happy
coincidence; no compile-time assert prevents future drift.

**File:** `internal/mempool/mempool.go:337, 338, 389-391, 642-647`;
`cmd/blockbrew/main.go:468, 813`.

**Core ref:** `bitcoin-core/src/policy/policy.h:48` and `:70`
(values 100 since `66559d1a4a`, 2025-07-29).

**Excerpt (blockbrew default, pre-lowering Core values)**
```go
func DefaultConfig() Config {
    return Config{
        MaxSize:                300_000_000, // 300 MB
        MinRelayFeeRate:        1000,        // 1 sat/vB  <- comment is misleading; Core current is 0.1
        IncrementalRelayFee:    1000,        // 1 sat/vB  <- same
        ...
    }
}
```

**Impact:** 10× fee-bump for RBF; 10× higher rolling-fee floor;
admits NO low-fee txs that Core 27+ admits. Cross-impl
divergence on every fee comparison.

---

## BUG-5 (P1) — `-incrementalrelayfee` CLI flag absent

**Severity:** P1. Core's `-incrementalrelayfee=<amt>` (`init.cpp:673`)
overrides `DEFAULT_INCREMENTAL_RELAY_FEE`. blockbrew has no such
flag; operators who want to track Core's new 100 sat/kvB default
without rebuilding cannot do so. Without this flag, BUG-4 cannot be
worked around without source patch.

**File:** `cmd/blockbrew/main.go:445-496` (parseFlags — no
incrementalrelayfee registration).

**Core ref:** `bitcoin-core/src/init.cpp:673`.

---

## BUG-6 (P1) — `getMinFeeRateLocked` floors at `MinRelayFeeRate` in addition to `IncrementalRelayFee`; Core only floors at incremental

**Severity:** P1. Core's `GetMinFee` returns
`std::max(CFeeRate(llround(rollingMinimumFeeRate)), m_opts.incremental_relay_feerate)`
(`txmempool.cpp:850`) — the rolling fee is floored at the incremental
relay rate ONLY. The `min_relay_feerate` floor is enforced separately
at ATMP / sendrawtransaction.

blockbrew's `getMinFeeRateLocked` at `mempool.go:2674-2683` floors
at BOTH:

```go
result := rolling
if incremental > result {
    result = incremental
}
if mp.config.MinRelayFeeRate > result {       // <-- extra floor, not in Core
    result = mp.config.MinRelayFeeRate
}
return result
```

With default values where `MinRelayFeeRate == IncrementalRelayFee`,
the extra check is a no-op. The bug becomes visible the moment
either constant is overridden (e.g. fixing BUG-4 piecewise: lowering
IncrementalRelayFee to 100 while leaving MinRelayFeeRate at 1000
keeps the floor at 1000, silently nullifying the IncrementalRelayFee
change for eviction purposes).

**File:** `internal/mempool/mempool.go:2674-2683`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:850`.

---

## BUG-7 (P1) — `maybeEvictLocked` lacks `pvNoSpendsRemaining` outparam; orphan-pool cache becomes stale on eviction

**Severity:** P1. Core's TrimToSize signature is
`TrimToSize(size_t sizelimit, std::vector<COutPoint>* pvNoSpendsRemaining = nullptr)`
(`txmempool.cpp:861`). For each evicted tx, every input whose
parent-txid is no longer in the pool is recorded into the outparam
(line 898-904). The caller (ATMP, validation.cpp) uses this list to
drop entries from the orphan-tx cache that reference outpoints
which will never be spent — orphan-tx promotion logic on the next
`AddTransaction` no longer needs to inspect them.

blockbrew's `maybeEvictLocked` (`mempool.go:2212-2275`) returns
`void`. No equivalent of `pvNoSpendsRemaining` is collected. The
orphan-pool at `mp.orphans` (line 576) keeps full entries with
`missingOut []wire.OutPoint` (line 453-458) whose outpoints may
reference txs that were just evicted. On every subsequent
`processOrphansLocked` (line 2331), blockbrew re-scans these
orphans looking for parents that will never reappear — wasted work
+ orphan-cache bloat over time.

**File:** `internal/mempool/mempool.go:2212-2275, 2331-2361`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:861, 898-904`;
`bitcoin-core/src/validation.cpp::AcceptToMemoryPoolWorker`
(consumer of pvNoSpendsRemaining).

---

## BUG-8 (P1) — `maybeEvictLocked` not gated on a `m_have_changeset`-equivalent invariant

**Severity:** P1. Core asserts `Assume(!m_have_changeset)` at the
top of TrimToSize (`txmempool.cpp:863`) — this prevents eviction
from running while a package-eval changeset is being staged but not
yet committed. Without the guard, an in-flight package evaluation
could see entries disappear from under it.

blockbrew has no `m_have_changeset` flag. `maybeEvictLocked` is
called unconditionally:
- from `AddTransaction` after every successful add (`mempool.go:1369`),
- from package-accept (`mempool.go:3602`).

Both callers hold `mp.mu`, so cross-goroutine eviction races are
prevented. But within a single package-eval call sequence, blockbrew
runs Trim per-tx instead of once at end-of-package — meaning
intermediate package-add states transiently see different mempool
fullness than Core would compute.

**File:** `internal/mempool/mempool.go:1369, 3602` (callers);
`maybeEvictLocked` at 2212-2275 (no guard).

**Core ref:** `bitcoin-core/src/txmempool.cpp:863` (assertion),
`txmempool.h:696-701` (m_have_changeset).

---

## BUG-9 (P0-CDIV) — `RemoveForReorg` has ZERO production callers; reorg leaves invalid txs in the mempool

**Severity:** P0-CDIV. Bitcoin Core's `MaybeUpdateMempoolForReorg`
(`validation.cpp`) is called from `ActivateBestChainStep` after
every `DisconnectTip`. It invokes
`mempool.removeForReorg(active_chain, check_final_and_mature)` to
purge:

- non-final txs (nLockTime / BIP-68 sequence-locks no longer
  satisfied at the NEW tip height + MTP),
- coinbase-spend txs whose source coinbase is now <100 confirmations
  (immature again because the chain shortened).

blockbrew defines `RemoveForReorg` correctly at `mempool.go:2494-2528`.
The function shape matches Core: walks `mp.pool`, filters via
`txInvalidAtTip` (line 2541-2565) which checks `consensus.IsFinalTx(tx,
tipHeight+1, tipMTP)` AND coinbase maturity, collects descendants,
removes them with REASON::REORG. The implementation is correct.

BUT:

```
$ grep -rn "\.RemoveForReorg(" cmd/ internal/ | grep -v "_test.go"
internal/consensus/w101_activate_best_chain_test.go:358:    // but does NOT call mp.RemoveForReorg(). The fix is to add:
internal/consensus/w101_activate_best_chain_test.go:359:    //   mp.RemoveForReorg()
internal/consensus/w101_activate_best_chain_test.go:383:    "Fix: call mp.RemoveForReorg() in the OnBlockConnected hook in main.go.")
```

Zero production callers. The only references are in `w101_*_test.go`
which **flags the gap as a known live bug** and tells the reader the
fix is "call mp.RemoveForReorg() in the OnBlockConnected hook" — a
comment-as-confession that the work was identified but never landed.

The chain manager's `SetOnBlockDisconnected` hook in `main.go:880-890`:

```go
chainMgr.SetOnBlockDisconnected(func(block *wire.MsgBlock, height int32) {
    mp.BlockDisconnected(block)            // re-add txs from popped block
    if cfg.TxIndex && chainDB != nil { ... } // txindex rewind
    if blockFilterIndex != nil { ... }     // BIP-157 rewind
})
```

… does NOT call `mp.RemoveForReorg()` AT ALL. The `mp.BlockDisconnected`
call re-adds non-coinbase txs from the popped block, but does NOT
re-evaluate the rest of the mempool against the new (lower) tip.

Failure modes:

1. **Non-final txs persist past a reorg**: a tx with
   `nLockTime = tipHeight + 5` admitted at tipHeight = N (so it was
   final there) survives a reorg from N+10 back to N — at the new
   tip N the tx is again non-final and SHOULD be evicted, but isn't.
   On the next mining cycle, blockbrew tries to include it; the
   block fails to validate; mining wastes the slot.
2. **Coinbase-maturity violations persist**: a tx that spends
   coinbase H, admitted at tipHeight = H+150, survives a reorg back
   to H+50. The coinbase output is now immature again. The tx is
   still in the mempool; getblocktemplate offers it to miners; the
   resulting block fails CheckBlock and the chain stalls or the
   block is rejected by peers.
3. **BIP-68 sequence-lock violations persist**: same shape as (1),
   for relative-locktime txs.
4. **Cross-impl divergence**: every other hashhog impl (per W153
   prompt) tracks MaybeUpdateMempoolForReorg. blockbrew's mempool
   on a reorged chain diverges from a peer Core node's view.

This is a P0-CDIV not just a P0 because the mempool contains
consensus-invalid txs that will be relayed onward to peers as INV
items, and `sendrawtransaction` would re-relay the bad tx —
indirectly polluting the network mempool state.

**File:** `cmd/blockbrew/main.go:880-890` (the hook that should
also call `mp.RemoveForReorg`); `mempool.go:2494-2528` (correct
implementation, zero callers).

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`,
`txmempool.cpp:333-386` (removeForReorg implementation).

**Excerpt (blockbrew, the missing call)**
```go
chainMgr.SetOnBlockDisconnected(func(block *wire.MsgBlock, height int32) {
    mp.BlockDisconnected(block)
    // MISSING: mp.RemoveForReorg()  // purge non-final + immature-coinbase txs
    ...
})
```

**Impact:** mempool state diverges from chain validity after every
reorg. Mining offers consensus-invalid txs. P2P relays
consensus-invalid txs. Cross-impl drift.

---

## BUG-10 (P0-CDIV) — `OnTxEvicted` does NOT fan out to ZMQ; `zmqSeqLabelTxRemove = 'R'` is defined but never referenced

**Severity:** P0-CDIV. Bitcoin Core's `CZMQPublishSequenceNotifier::NotifyTransactionRemoval`
(`zmqpublishnotifier.cpp:288-293`) emits sequence-topic frame
`<32-byte hash (display order)> | 'R' | <8-byte LE sequence>` on
EVERY mempool removal — fee-est evictions, RBF replacements,
size-limit trims, expiry, reorg invalidations. Indexers (electrs,
fulcrum, mempool.space, btcrpcexplorer, nbxplorer) gate their
in-memory mempool projection on this signal — a tx that disappears
from the node's mempool without an 'R' notification leaves the
indexer's view stale.

blockbrew:

```go
// zmqpub.go:35 — symbol defined
zmqSeqLabelTxRemove        byte = 'R'

// grep -rn "zmqSeqLabelTxRemove" cmd/ internal/
// → ONE match: the definition itself. Zero references.
```

There is NO `PublishTxRemoved` function in `zmqpub.go`. The
`OnTxEvicted` callback in `main.go:1002-1004` is:

```go
mp.OnTxEvicted = func(txHash wire.Hash256, _ mempool.MemPoolRemovalReason) {
    feeEstimator.UnregisterTransaction(txHash)
}
```

— only the fee estimator is notified. The ZMQ publisher is not even
referenced. The MemPoolRemovalReason parameter is explicitly
discarded with `_`.

The comment at `main.go:1001-1002` admits the gap:

```
// FIX-73 (W120 BUG-9): callback now carries a MemPoolRemovalReason.
// The fee estimator does not yet differentiate reasons (Core's
// CBlockPolicyEstimator::removeTx ignores the reason flag too — it just
// drops the entry from bucketMap regardless), so we pass through here.
// Future wallet wiring + ZMQ pubrawtx "R" prefix will read the reason.
```

— **comment-as-confession** that "Future wallet wiring + ZMQ pubrawtx
'R' prefix" was identified in FIX-73 but never landed. The
mempool-side reason classification was carefully built (BUG-21..26
in this audit's gate matrix) for downstream consumers, and then
the downstream consumers were never wired.

Failure modes:

1. **electrs / fulcrum mempool drift**: a tx evicted by blockbrew
   stays in electrs's mempool view until electrs's own periodic
   refresh polls `getrawmempool`. Window: up to 30 seconds.
2. **mempool.space cumulative inaccuracy**: mempool.space relies on
   the sequence stream for incremental updates; without 'R'
   notifications, the displayed mempool grows unboundedly relative
   to blockbrew's actual state.
3. **Lightning node fee-bumping**: c-lightning / LND watch ZMQ for
   tx-eviction signals to know when to re-broadcast a stuck HTLC
   refund. Missing 'R' frames → stuck HTLCs not re-broadcast →
   funds-at-risk during channel close.
4. **Sequence-topic invariant broken**: Core's sequence guarantee
   is that each `m_mempool_sequence` increment corresponds to
   exactly one mempool add or remove. blockbrew's sequence counter
   (`zmqpub.go:75 mempoolSeq`) only increments on accept (line 269),
   leaving gaps in the counter that consumers cannot interpret.

Cross-cite: this is the SAME pattern as W141 BUG-1+2+3 (ZMQ
byte-order divergence) — blockbrew ships ZMQ publishers with
partial Core-parity but misses important downstream-consumer
requirements.

**File:** `cmd/blockbrew/zmqpub.go:35` (definition only),
`cmd/blockbrew/main.go:1002-1004` (callback, no ZMQ);
`mempool.go:594-611` (callback hook design notes).

**Core ref:** `bitcoin-core/src/zmq/zmqpublishnotifier.cpp:288-293`
(NotifyTransactionRemoval).

**Excerpt (blockbrew, the broken sequence-topic invariant)**
```go
// zmqpub.go:268-276 — accept side increments mempoolSeq
if p.cfg.Sequence != "" {
    mseq := atomic.AddUint64(&p.mempoolSeq, 1) - 1   // ++ on accept
    body := make([]byte, 32+1+8)
    copy(body[:32], hash[:])
    body[32] = zmqSeqLabelTxAccept
    binary.LittleEndian.PutUint64(body[33:], mseq)
    ...
}

// remove side: ABSENT. mempoolSeq never increments on removal.
// Result: consumers see seq=0,1,2,3,5,6 (no 4!) → gap detected → reset.
```

**Impact:** every ZMQ-driven downstream tool sees blockbrew's
mempool as a write-only stream of additions; removals are invisible.

---

## BUG-11 (P0-CDIV) — Wallet has NO `transactionRemovedFromMempool` hook; REPLACED / CONFLICT / EXPIRY / REORG never reach the wallet

**Severity:** P0-CDIV. Bitcoin Core's
`CWallet::transactionRemovedFromMempool(tx, reason, mempool_sequence)`
(`wallet/wallet.cpp:1407`) is fired on every mempool removal:

| Reason | Wallet action |
|--------|---------------|
| REPLACED | Mark the original wallet tx as "replaced-by-fee" so the UI shows it as superseded (the replacement may confirm). |
| CONFLICT | Wait for block-disconnect signal to undo. |
| BLOCK | Already-counted by the wallet's block-connect handler; no-op. |
| EXPIRY | Mark for possible re-broadcast on next periodic resend. |
| SIZELIMIT | Same as EXPIRY. |
| REORG | Note that the tx may re-confirm differently; defer to next AcceptToMemoryPool. |

blockbrew's `internal/wallet/wallet.go` has **no equivalent**.
A grep:

```
$ grep -rn "OnTxEvicted\|transactionRemovedFromMempool" internal/wallet/
# → no matches
```

The `mempool.go:606-611` comment explicitly says:

```
// Wallet semantics (Core src/wallet/wallet.cpp:1407
// CWallet::transactionRemovedFromMempool):
//   - REPLACED → wallet marks tx as replaced-by-fee (still possibly mined)
//   - CONFLICT / BLOCK → wallet typically waits for block-disconnect to undo
//   - EXPIRY / SIZELIMIT / REORG → wallet may abandon or re-broadcast
```

— but `mp.OnTxEvicted` is only consumed by the fee estimator
(`main.go:1002`). The wallet is never registered.

Wallet failure modes:

1. **Stuck "pending" tx in UI after RBF**: user broadcasts tx A;
   later submits replacement A' which evicts A; blockbrew accepts
   A' but the wallet's `mapWallet` still holds A as "pending" —
   the user sees TWO pending txs instead of one bumped one.
2. **Coin abandonment loss after EXPIRY**: a wallet-broadcast tx
   that expires after 14 days (post BUG-2 fix) leaves the inputs
   listed as "spent by pending tx" forever. The wallet does not
   know to re-mark the inputs as available.
3. **Wallet balance under-counts after CONFLICT**: tx A spends
   UTXO U; a competing tx A' arrives in a block (resolves the
   conflict in A's favour-of-eviction); wallet's `mapWallet`
   still treats U as spent by A → balance under-counts by U.value
   until next wallet rescan.

W120 BUG-9 (FIX-73) plumbed the REASON parameter through the
mempool but stopped at the boundary; the wallet integration that
gave the FIX a wallet-correctness purpose was never built.

**File:** `cmd/blockbrew/main.go:1002-1004` (single-consumer
callback); `internal/wallet/wallet.go` (no
transactionRemovedFromMempool hook anywhere).

**Core ref:** `bitcoin-core/src/wallet/wallet.cpp:1407`.

---

## BUG-12 (P1) — `BlockConnected` does NOT clear `mp.mapDeltas` for confirmed txs (Core: `ClearPrioritisation`)

**Severity:** P1. Bitcoin Core's `removeForBlock` (line 420):

```cpp
for (const auto& tx : vtx) {
    txiter it = mapTx.find(tx->GetHash());
    if (it != mapTx.end()) { ... removeUnchecked(it, MemPoolRemovalReason::BLOCK); }
    removeConflicts(*tx);
    ClearPrioritisation(tx->GetHash());   // <-- always, regardless of in-pool status
}
```

`ClearPrioritisation(hash)` (`txmempool.cpp:644-650`) drops the
hash from `mapDeltas`. Blockbrew's `BlockConnected` (`mempool.go:2393-2425`):

```go
for _, tx := range block.Transactions {
    txHash := tx.TxHash()
    mp.removeSingleTxLocked(txHash, MempoolRemovalReasonBlock)
    // MISSING: delete(mp.mapDeltas, txHash)
    for _, in := range tx.TxIn {
        if spendingTx, ok := mp.outpoints[in.PreviousOutPoint]; ok {
            mp.removeWithDescendantsLocked(spendingTx, MempoolRemovalReasonConflict)
            // MISSING: delete(mp.mapDeltas, spendingTx)
        }
    }
}
```

`removeSingleTxLocked` (line 1905-1961) deletes from `mp.pool` and
`mp.outpoints` but never touches `mp.mapDeltas`. The delta for a
confirmed tx survives indefinitely.

Failure mode: a user `prioritisetransaction txid +10000` before
broadcasting; the tx confirms in a block; weeks later a reorg
re-pops the block and the tx re-enters the mempool via
`BlockDisconnected → AddTransaction`. The stale +10000 delta is
silently re-applied, defending the tx against RBF replacement at a
priority the user no longer intended.

Memory leak (secondary): a `mapDeltas` entry is 40+ bytes
(`Hash256` + int64 + map overhead). For a busy node with many
prioritised txs this leaks ~1 MB/year of map memory.

**File:** `internal/mempool/mempool.go:2393-2425` (BlockConnected);
`mempool.go:1905-1961` (removeSingleTxLocked, doesn't touch mapDeltas).

**Core ref:** `bitcoin-core/src/txmempool.cpp:420`
(removeForBlock's ClearPrioritisation), `:644-650`
(ClearPrioritisation impl).

---

## BUG-13 (P0-CDIV cross-cite W141 BUG-1+2+3) — ZMQ hashblock / hashtx / sequence frames carry INTERNAL byte-order, Core sends DISPLAY order

**Severity:** P0-CDIV. **Same finding as W141 BUG-1+2+3 — re-anchored
because the bug is still live.** Bitcoin Core's ZMQ publishers
reverse byte-order before writing the wire frame
(`zmq/zmqpublishnotifier.cpp:215-217, 226-228, 259-261`):

```cpp
uint8_t data[32];
for (unsigned int i = 0; i < 32; i++) {
    data[31 - i] = hash.begin()[i];   // <-- explicit reverse → DISPLAY order
}
return SendZmqMessage(MSG_HASHBLOCK, data, 32);
```

This produces a wire byte sequence whose hex matches the block /
tx id as seen in `getblockhash` / `bitcoin-cli`.

blockbrew (`cmd/blockbrew/zmqpub.go:222, 236, 256, 271`):

```go
hash := block.Header.BlockHash()    // returns INTERNAL byte order (Hash256 = [32]byte LE)
if err := p.sendTopic(zmqTopicHashBlock, p.cfg.HashBlock, hash[:]); err != nil { ... }
//                                                          ^^^^^^^
//                                          raw INTERNAL bytes — NOT reversed
```

`internal/wire/types.go:54-65` confirms `Hash256.String()` REVERSES
for display:

```go
type Hash256 [32]byte
func (h Hash256) String() string {
    var reversed [32]byte
    for i := 0; i < 32; i++ {
        reversed[i] = h[31-i]
    }
    return hex.EncodeToString(reversed[:])
}
```

So `hash[:]` is internal-order. The ZMQ wire frame is byte-reversed
relative to Core, breaking every downstream indexer that expects
Core-compat output:

- **electrs**: parses hashblock as if display-order; sees a hash
  that doesn't match any header the chain produced; logs
  "unknown block hash" warnings; eventually re-syncs from getblock.
- **fulcrum**: same as electrs.
- **mempool.space**: backend mempool-block reconstruction fails to
  match the published hashtx frames to its in-memory tx cache.
- **nbxplorer / btcrpcexplorer**: same.
- **Lightning watchtowers (Eye of Satoshi etc.)**: hash-based
  channel-close detection misses the broadcast event.

The W141 audit flagged this and the prompt for W153 specifically
called it out as a check to cross-cite. The fix is 3-line per
publish site (`PublishBlockConnected` + `PublishTxAccepted` +
the absent `PublishTxRemoved` if BUG-10 is also fixed), reversing
the hash bytes before write.

**File:** `cmd/blockbrew/zmqpub.go:222, 236, 256, 271`;
`internal/wire/types.go:54-65`.

**Core ref:** `bitcoin-core/src/zmq/zmqpublishnotifier.cpp:215-217`
(hashblock), `:226-228` (hashtx), `:259-261` (sequence).

**Excerpt (blockbrew, raw internal-order write)**
```go
// zmqpub.go:222 — Core writes data[31-i] = hash.begin()[i]; blockbrew writes raw
if err := p.sendTopic(zmqTopicHashBlock, p.cfg.HashBlock, hash[:]); err != nil { ... }
```

**Impact:** all ZMQ-driven downstream tools see byte-reversed hashes
relative to every other Bitcoin node implementation. Cross-impl
ecosystem break.

---

## BUG-14 (P0-CDIV, W151 BUG-6 re-anchor) — `getmempoolinfo` hardcodes `mempoolminfee`, `minrelaytxfee`, `incrementalrelayfee`, `maxmempool`; ignores runtime config + rolling-fee state

**Severity:** P0-CDIV. W151 BUG-6 flagged this in the package-relay
audit. The bug is still live. `internal/rpc/methods.go:1290-1322`:

```go
return &MempoolInfo{
    Loaded:             true,
    Size:               s.mempool.Count(),
    Bytes:              s.mempool.TotalSize(),
    Usage:              s.mempool.TotalSize(), // Simplified: actual usage would include overhead
    TotalFee:           totalFee,
    MaxMempool:         300_000_000, // 300 MB default     <-- hardcoded
    MempoolMinFee:      0.00001,     // 1 sat/vB in BTC/kvB <-- hardcoded
    MinRelayTxFee:      0.00001,     // 1 sat/vB in BTC/kvB <-- hardcoded
    IncrementalRelayFee: 0.00001,                          // <-- hardcoded
    UnbroadcastCount:   0,
    FullRBF:            s.mempool.FullRBF(),
}, nil
```

Every fee-related field is a literal constant. There are EIGHT
operator-visible knobs (`-maxmempool`, `-minrelayfee`,
`-incrementalrelayfee`, the rolling-fee dynamic state) and ALL of
them are ignored by this RPC. The `mp.GetMinFeeRate()` getter
exists (line 2616-2620) and returns the live rolling-fee floor; it
is not called from `handleGetMempoolInfo`.

Failure modes:

1. **Operator running `-maxmempool=2000`** (2 GB) sees
   `getmempoolinfo.maxmempool = 300000000` (300 MB) — monitoring
   tooling reports the node is "97% full" when it's actually 17%.
2. **Operator running `-minrelayfee=0.000003`** (3 sat/vB, e.g.
   private testnet) sees `minrelaytxfee = 0.00001` (1 sat/vB) —
   wallet rejects sub-3-sat/vB txs at submission but the RPC
   advertises a lower floor.
3. **Mempool full → rolling fee elevated**: `mempoolminfee` should
   ratchet up to the rolling floor + incremental relay, telling
   external estimators what fee is needed to enter. blockbrew
   always reports 0.00001 BTC/kvB regardless of mempool state.
   smartfee tools compute against this static value and produce
   bad recommendations.
4. **REST `/rest/mempool/info.json`** (`rest.go:461-477`) delegates
   to `handleGetMempoolInfo` — same broken values exposed
   unauthenticated.

**File:** `internal/rpc/methods.go:1290-1322`;
`internal/rpc/rest.go:461-477` (REST aliasing).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`.

---

## BUG-15 (P1) — `getmempoolinfo.usage` is raw vsize, not `DynamicMemoryUsage()`; comment-as-confession

**Severity:** P1 (BUG-1 sibling — same root cause, separate
RPC-shape impact). `methods.go:1307`:

```go
Usage: s.mempool.TotalSize(), // Simplified: actual usage would include overhead
```

— comment-as-confession (8th distinct blockbrew instance per
W149/W151 tracking). Core's `getmempoolinfo.usage` is documented
as "Total memory usage for the mempool" and is `DynamicMemoryUsage()`
in bytes. blockbrew reports raw tx vsize (~10× under-reporting).
Combined with BUG-14's hardcoded `maxmempool=300_000_000`, the
ratio `usage / maxmempool` displayed by monitoring (`grafana` /
`prometheus` exporters / `mempool-observer.io`) is incorrect by
a constant factor that doesn't normalize against operator
configuration.

**File:** `internal/rpc/methods.go:1307`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::MempoolInfoToJSON`.

---

## BUG-16 (P1) — `getmempoolinfo.unbroadcastcount` always 0; no unbroadcast set tracking

**Severity:** P1. Core tracks `m_unbroadcast_txids` for txs that
were submitted via `sendrawtransaction` / `submitpackage` but have
not yet been INV-relayed to any peer. The set is periodically
re-broadcast by the wallet broadcaster until at least one peer
acknowledges. `getmempoolinfo.unbroadcastcount` exposes the set
size to operator tooling so a stuck wallet tx is visible.

blockbrew:

```go
// methods.go:1313
UnbroadcastCount: 0,

// persist.go:256-259 (Dump)
// Unbroadcast set: still zero — blockbrew does not yet track an
// unbroadcast set (out of scope for FIX-76).
if err := wire.WriteCompactSize(xw, 0); err != nil {
    return fmt.Errorf("mempool dump: write unbroadcast: %w", err)
}
```

— field plumbed, value always 0, comment admits the gap.

**File:** `internal/rpc/methods.go:1313`;
`internal/mempool/persist.go:256-259, 414-422`.

**Core ref:** `bitcoin-core/src/txmempool.cpp` `m_unbroadcast_txids`.

---

## BUG-17 (P1) — No CLI flags for `-limit{ancestor,descendant}{count,size}`, `-datacarrier{size}`, `-bytespersigop`

**Severity:** P1 (multi-flag bundle). Core exposes:

- `-limitancestorcount=<n>` (`init.cpp:650`) — default 25
- `-limitdescendantcount=<n>` (`init.cpp:651` analogue) — default 25
- `-limitancestorsize=<n>` — default 101 (kvB)
- `-limitdescendantsize=<n>` — default 101 (kvB)
- `-datacarrier` (`init.cpp:677`) — default true
- `-datacarriersize=<n>` (`init.cpp:678`) — default 83
- `-bytespersigop=<n>` — default 20

blockbrew's `Config` struct (`mempool.go:347-363`) exposes
`AncestorLimit / DescendantLimit / AncestorSizeLimitKvB /
DescendantSizeLimitKvB` as override fields, but `cmd/blockbrew/main.go`
does NOT register any CLI flag that wires them. They ride the
defaults (`mempool.go:271-287`) forever. Operators running
private-testnet stress tests with deeper ancestor chains, or
restrictive nulldata policies, cannot configure.

**File:** `cmd/blockbrew/main.go:445-496` (parseFlags — no
limitancestor* / datacarrier* registrations);
`internal/mempool/mempool.go:347-363` (Config fields exist but
unwired).

**Core ref:** `bitcoin-core/src/init.cpp:650-678`.

---

## BUG-18 (P1) — `BlockConnected` removes confirmed tx via `removeSingleTxLocked` but NOT via descendant-walk; orphan-in-block scenarios leak

**Severity:** P1 (edge case). `mempool.go:2407-2410`:

```go
for _, tx := range block.Transactions {
    txHash := tx.TxHash()
    mp.removeSingleTxLocked(txHash, MempoolRemovalReasonBlock)
    ...
}
```

For each tx in the connected block, blockbrew removes just that one
entry. Core's `removeUnchecked` does the same — but Core's
correctness depends on the block being topologically complete
(every tx is either in the block or remains in the mempool as a
descendant). When a block contains txs A, B, C in topological order
and a mempool-only descendant D (child of C) exists, Core's
sequence is: remove A, remove B, remove C — D is now an orphan of a
removed parent. Core's `removeUnchecked` cascades to D via
`txgraph` re-linearisation. blockbrew's `removeSingleTxLocked`
does NOT cascade (it's specifically the no-descendant-walk variant).

In practice this is mostly self-healing because D's UTXO references
the just-confirmed parent C's output, and D is still valid (the
input is now confirmed instead of in-mempool). But D's
`Depends` slice still contains C, the per-entry ancestor accounting
is now stale, and the cluster manager still has a node for C that
will only get cleaned up on the next `RemoveTransaction`.

Core's `removeForBlock` correctness comes from the loop's
topology: A is removed → ancestor stats of B/C/D recomputed; B
is removed → stats of C/D recomputed; etc. blockbrew leaves
`mp.pool[C]` deleted but `mp.pool[D].Depends = [C]` still references
a deleted parent.

**File:** `mempool.go:2393-2425` (BlockConnected),
`:1905-1961` (removeSingleTxLocked).

**Core ref:** `bitcoin-core/src/txmempool.cpp:405-431` (removeForBlock).

---

## BUG-19 (P1) — `BlockConnected` conflict detection uses raw outpoint match, missing the `txConflict.GetHash() != tx.GetHash()` self-exclusion guard

**Severity:** P1. Core's `removeConflicts` (`txmempool.cpp:388-403`):

```cpp
const CTransaction &txConflict = it->second->GetTx();
if (Assume(txConflict.GetHash() != tx.GetHash()))   // <-- self-conflict guard
{
    ClearPrioritisation(txConflict.GetHash());
    removeRecursive(it->second, MemPoolRemovalReason::CONFLICT);
}
```

The `Assume(... != ...)` guards against the theoretical case where
the conflicting tx in `mapNextTx` is the same tx being processed
(impossible by topology, but Core asserts defensively).

blockbrew's `BlockConnected` (`mempool.go:2412-2416`):

```go
for _, in := range tx.TxIn {
    if spendingTx, ok := mp.outpoints[in.PreviousOutPoint]; ok {
        mp.removeWithDescendantsLocked(spendingTx, MempoolRemovalReasonConflict)
        // MISSING: if spendingTx == txHash { skip }
    }
}
```

If the freshly-confirmed tx (already removed at line 2409) somehow
left an entry in `mp.outpoints` pointing back at itself, blockbrew
would call `removeWithDescendantsLocked(txHash, REASON::CONFLICT)`
on the just-removed tx, firing a SECOND `OnTxEvicted(txHash, CONFLICT)`
after the first `OnTxEvicted(txHash, BLOCK)`. Fee estimator double-
removal is a no-op (UnregisterTransaction is idempotent), but the
ZMQ sequence counter would increment twice (BUG-10 path, if fixed),
and a future wallet-side consumer (BUG-11 fix) would see a tx go
BLOCK→CONFLICT in the same call.

The `removeSingleTxLocked` at line 1905-1961 already cleans up
`mp.outpoints` on remove, so in practice the dangling outpoint
shouldn't exist — but blockbrew's invariants don't guarantee this.

**File:** `mempool.go:2412-2416`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:396-400`.

---

## BUG-20 (P1) — `MempoolFullRBFExplicit` field is operator-trust footgun; defaults to `false` for zero-value Config

**Severity:** P1. `mempool.go:382-383, 654-663`:

```go
MempoolFullRBF         bool
MempoolFullRBFExplicit bool
...
if !config.MempoolFullRBFExplicit {
    // Operator (or test caller) did not explicitly set MempoolFullRBF.
    config.MempoolFullRBF = DefaultMempoolFullRBF  // true
    config.MempoolFullRBFExplicit = true
}
```

The two-field design (value + explicit-sentinel) defends against
the zero-value-Config trap (W120 BUG-5 / FIX-68). But the sentinel
defaults to `false` for any caller that constructs a `Config{}`
without going through `DefaultConfig()`. If a future refactor
forgets to set `MempoolFullRBFExplicit = true` for a test fixture
that EXPLICITLY wants `MempoolFullRBF: false`, the `New` constructor
will silently overwrite it to `true` (the default), corrupting the
test's intent.

A safer pattern: use a `*bool` pointer (nil = not set) or a
dedicated `OptionalBool` type. Or remove `MempoolFullRBFExplicit`
entirely and use a struct-tag-driven default.

**File:** `internal/mempool/mempool.go:382-383, 654-663`.

**Impact:** test-fixture brittleness; not a runtime bug today, but
the design invites future regressions of the W120 BUG-5 class.

---

## BUG-21 (P1) — `RemoveForReorg` re-evaluates BIP-68 sequence locks WITHOUT BIP-113 next-block MTP

**Severity:** P1. `mempool.go:2541-2565` (txInvalidAtTip):

```go
func (mp *Mempool) txInvalidAtTip(tx *wire.MsgTx, tipHeight int32, tipMTP uint32) bool {
    // Gate 1 — non-final tx.
    if !consensus.IsFinalTx(tx, tipHeight+1, tipMTP) {
        return true
    }
    // Gate 2 — immature coinbase spend.
    if mp.utxoSet != nil {
        for _, in := range tx.TxIn {
            utxo := mp.utxoSet.GetUTXO(in.PreviousOutPoint)
            if utxo != nil && utxo.IsCoinbase {
                ...
            }
        }
    }
    return false
}
```

Core's `removeForReorg` filter callback
(`check_final_and_mature` in `validation.cpp`) ALSO calls
`CheckSequenceLocksAtTip` — BIP-68 relative locktime evaluation
against the NEW tip's MTP. blockbrew only checks `IsFinalTx` (BIP-113
absolute lock) and coinbase maturity. A tx with BIP-68 relative
locks (nSequence < 0xfffffffd, ENABLE flag clear) that became valid
at tipHeight=N may again be invalid at the post-reorg tipHeight=N-5
— blockbrew leaves it in the mempool, getblocktemplate offers it
to miners, the mined block fails CheckBlock with
`bad-txns-nonfinal`.

The bug is gated by BUG-9 (RemoveForReorg has zero callers); if
BUG-9 is fixed but BUG-21 isn't, the fix is partial.

**File:** `internal/mempool/mempool.go:2541-2565`.

**Core ref:** `bitcoin-core/src/validation.cpp::CheckSequenceLocksAtTip`,
`txmempool.cpp:333-386` (removeForReorg filter callback).

---

## BUG-22 (P1) — `BlockDisconnected` re-adds txs unconditionally via `AddTransaction`; ignores per-tx policy failures

**Severity:** P1. `mempool.go:2434-2440`:

```go
for i, tx := range block.Transactions {
    if i == 0 {
        continue // Skip coinbase
    }
    _ = mp.AddTransaction(tx) // Ignore errors
}
```

The `_ =` discards every error. AddTransaction runs the full ATMP
pipeline (script checks, BIP-68 locks, fee floor, ancestor limits,
etc.). On a reorg-deep enough to expose changed policy state, txs
that were valid at confirmation time may now violate policy (e.g.
new policy version, mempool full, prioritisation lapsed) — they
fall on the floor silently. The chain manager doesn't know which
txs failed to re-enter the mempool. The wallet doesn't know its
unspent outputs are about to be unspent-by-no-pending-tx-at-all.

Core's `MaybeUpdateMempoolForReorg` collects re-add failures and
emits validation-interface `MempoolTransactionsRemovedForBlock`
with the actual outcomes; blockbrew throws the information away.

**File:** `internal/mempool/mempool.go:2434-2440`.

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`.

---

## BUG-23 (P2) — `MempoolInfo.Bytes` JSON field shape diverges from Core (Core: `bytes` is sum of `GetTxSize()`)

**Severity:** P2. Core's `getmempoolinfo.bytes` is `int64`
documented as "Sum of all virtual transaction sizes as defined in
BIP 141" — equivalent to blockbrew's `TotalSize()` (vsize sum).
This field IS correctly populated in blockbrew (`methods.go:1306`).
The bug is that the SAME getter (`s.mempool.TotalSize()`) is ALSO
used at line 1307 for `usage` (BUG-15). Two distinct concepts
(vsize vs heap usage) share one source value, masking BUG-1's
divergence in any monitoring that compares them.

**File:** `internal/rpc/methods.go:1306-1307`.

**Impact:** monitoring contract — operators cannot distinguish
"mempool is large" (bytes high) from "mempool overhead is high"
(usage > bytes).

---

## Summary

**Bug count:** 23 (BUG-1 through BUG-23).

**Severity distribution:**
- **P0-CDIV:** 7 (BUG-1, BUG-4, BUG-9, BUG-10, BUG-11, BUG-13, BUG-14)
- **P0:** 1 (BUG-2)
- **P1:** 14 (BUG-3, BUG-5, BUG-6, BUG-7, BUG-8, BUG-12, BUG-15,
  BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21, BUG-22)
- **P2:** 1 (BUG-23)

Total: 7 + 1 + 14 + 1 = 23. ✓

**Fleet patterns confirmed:**

- **"dead-code pipeline"** (BUG-2 `mp.Expire`, BUG-9 `mp.RemoveForReorg`) —
  TWO distinct mempool-mutation functions correctly implemented with
  Core-mirroring shape, both with zero production callers. Same
  shape as W138 `ChainstateManager` dead-class fleet pattern
  (9 of 10 impls).
- **"comment-as-confession"** (8th–12th distinct blockbrew instances):
  - BUG-10: `main.go:1001` "Future wallet wiring + ZMQ pubrawtx 'R' prefix will read the reason"
  - BUG-15: `methods.go:1307` "Simplified: actual usage would include overhead"
  - BUG-16: `persist.go:257` "blockbrew does not yet track an unbroadcast set"
  - BUG-4: `mempool.go:390, 391` "1 sat/vB" — misleading given Core lowered to 0.1
  - BUG-9: `w101_*_test.go:383` "Fix: call mp.RemoveForReorg() in the OnBlockConnected hook in main.go" (test-file-as-confession)
- **"dead-data plumbing"** (BUG-10 `zmqSeqLabelTxRemove = 'R'` symbol
  defined, never referenced; BUG-16 `UnbroadcastCount` always 0) —
  fleet-wide pattern, 10th+ distinct blockbrew instance.
- **"hardcoded constant should be params-aware / config-aware"**
  (BUG-14 `getmempoolinfo` hardcodes all 4 fee fields; BUG-15 usage
  hardcoded; BUG-3 / BUG-5 / BUG-17 CLI flags absent) — fleet
  pattern, ~6 distinct blockbrew instances.
- **"carry-forward re-anchor"** — THREE re-anchors in this single audit:
  - BUG-4 (W151 BUG-1 IncrementalRelayFee=1000): ~1.5 months
    after first flagged. Severity has WORSENED because Core lowered
    the value to 100 on 2025-07-29, making blockbrew now 10× over
    instead of equal-to.
  - BUG-13 (W141 BUG-1+2+3 ZMQ byte-order): still live since
    W141 (~7 days ago per memory).
  - BUG-14 (W151 BUG-6 getmempoolinfo hardcoded fields): still live
    since W151.
- **"two-pipeline guard" (17th distinct extension)** — BUG-6 floors
  `getMinFeeRateLocked` at both `IncrementalRelayFee` AND
  `MinRelayFeeRate`; Core floors only at incremental. This is a
  third-floor pipeline (rolling-rate / incremental / minrelay)
  where Core has two.
- **"DynamicMemoryUsage vs raw vsize divergence" (NEW pattern)** —
  BUG-1 + BUG-15 + BUG-23 cluster. First time a fleet audit
  identifies the 5–10× heap-overhead-vs-vsize gap as a single
  architectural issue with multiple RPC + eviction surface points.
- **"three-pipeline drift" (BUG-9 sibling)** — Two distinct
  mempool-mutation paths after reorg: `BlockDisconnected` re-adds
  via AddTransaction (line 2434-2440); no `RemoveForReorg` ever
  fires. Core has THREE: removeForReorg, BlockDisconnected
  re-broadcast, AND ConnectTip post-reorg cleanup. blockbrew has
  ONE.
- **"reject-string wire-parity slippage" (NEW)** — BUG-4's
  `ErrInsufficientFee` carries blockbrew-specific format string
  `"%.1f sat/kvB below minimum %d sat/kvB"` (line 1198-1199);
  Core's reject reason is the canonical token `"mempool min fee not met"`
  (`validation.cpp::PolicyScriptChecks`). Cross-impl SPV / wallet
  tooling that gates on Core-canonical reject tokens can't parse
  blockbrew's reason string.

**Top three findings:**

1. **BUG-9 (P0-CDIV — RemoveForReorg has zero production callers).**
   Reorg leaves consensus-invalid txs in the mempool: non-final
   (BIP-113), sequence-lock-violating (BIP-68 — also see BUG-21),
   immature-coinbase-spending. These get offered to miners via
   getblocktemplate and re-relayed via INV; the resulting blocks
   fail CheckBlock at peers. The fix is 1 line in
   `cmd/blockbrew/main.go:880-890` (the
   `chainMgr.SetOnBlockDisconnected` hook). The test file
   `w101_activate_best_chain_test.go:383` literally documents the
   fix as a one-line addition that has been deferred. ~7 days
   live since W101.

2. **BUG-1 (P0-CDIV — `MaxSize` enforced against raw vsize, ~5–10× wider than Core).**
   Mempool DoS surface ~10× wider; RSS grows ~10× past
   `-maxmempool`; rolling-fee halflife thresholds use the wrong
   denominator; fee-estimator drift cascades from delayed eviction.
   The single most-impactful divergence in this wave; affects every
   eviction-related downstream consumer.

3. **BUG-4 (P0-CDIV — Default fees 10× Core's current).** Re-anchor
   of W151 BUG-1 with WORSENED severity: Core lowered
   `DEFAULT_INCREMENTAL_RELAY_FEE` and `DEFAULT_MIN_RELAY_TX_FEE`
   from 1000 to 100 sat/kvB on 2025-07-29 (commit `66559d1a4a`).
   blockbrew still defaults to 1000. RBF Rule 4 demands 10× the
   bump; getMinFee floor is 10× too high; cross-impl fee
   comparisons all diverge. Bundle BUG-4 with BUG-5
   (`-incrementalrelayfee` CLI flag absent) to give operators a
   path to track Core without rebuilding.

Cross-cuts: BUG-10 + BUG-11 + BUG-13 form a "removed-signal fan-out
is entirely broken" cluster — fee-estimator works, ZMQ removal
publishers absent, wallet integration absent, byte-order wrong on
the ZMQ paths that DO exist. Fixing all three is a ~3-day project
that closes 1 P0 finding plus 2 P0-CDIVs and aligns blockbrew with
every ecosystem indexer's expectations.
