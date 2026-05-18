# W138 — AssumeUTXO snapshots audit (blockbrew)

**Wave**: W138 (DISCOVERY, not fix)
**Date**: 2026-05-18
**Impl**: blockbrew (Go)
**Scope**: SnapshotMetadata header codec + `loadtxoutset` RPC + CLI
`loadSnapshotFromFile` + `ActivateSnapshot` semantics + BackgroundChainState
validator + `assumeutxohash` sanity + snapshot-chainstate persistence +
`dumptxoutset` (incl. rollback path) + `getchainstates`.
**Verdict**: **BUGS FOUND** — **23 distinct bug IDs (BUG-1..BUG-23)**,
including **3 P0-CDIV** (background-validator hash-algorithm mismatch
makes the safety net permanently broken; the in-memory-cache-only
snapshot writer silently omits UTXOs that have spilled to disk
producing torn snapshots; the snapshot CoinsCount header is unsigned
LE-encoded but uses unspaced framing rather than Core's coupled tx-hash
+ compact-size grouping in one boundary case — see BUG-13), **5 P1**
(no persisted `m_from_snapshot_blockhash` on disk → snapshot lineage
not recoverable across restart; `getchainstates` always reports
`validated:true` regardless of whether the active chainstate came from
a snapshot; `MaybeValidateSnapshot` / `InvalidateCoinsDBOnDisk` not
implemented; no `WriteSnapshotBaseBlockhash` /
`FindAssumeutxoChainstateDir` equivalents; `loadtxoutset` RPC refuses
**all** loads rather than the Core gate ("snapshot already loaded")
so even the on-line-RPC-only Core flow is unsupported), and 15
HIGH/MED/LOW gaps in network-magic ordering, interrupt support, cache
rebalancing, work comparison, dumptxoutset progress reporting, RPC
result fields, and historical-chainstate exposure.

**Bitcoin Core references**:
- `bitcoin-core/src/node/utxo_snapshot.h` — `SnapshotMetadata`
  (magic `'u','t','x','o',0xff` / VERSION=2 / MessageStartChars network
  magic / base_blockhash / coins_count); per-field rejection conditions
  on the unserialise side; `SNAPSHOT_BLOCKHASH_FILENAME =
  "base_blockhash"`; `SNAPSHOT_CHAINSTATE_SUFFIX = "_snapshot"`;
  `WriteSnapshotBaseBlockhash` / `ReadSnapshotBaseBlockhash` /
  `FindAssumeutxoChainstateDir`.
- `bitcoin-core/src/node/utxo_snapshot.cpp` — afile.tell() trailing-data
  warning on the base-blockhash sidecar file.
- `bitcoin-core/src/validation.cpp` —
  `ActivateSnapshot:5588` (table lookup, base-block lookup, invalid-
  chain check, best-header ancestor check, mempool-empty check, cache
  resize via `IBD_CACHE_PERC=0.01` + `SNAPSHOT_CACHE_PERC=0.99`,
  cleanup_bad_snapshot lambda, post-population work comparison vs
  active tip, `WriteSnapshotBaseBlockhash`, `AddChainstate`,
  `PopulateBlockIndexCandidates`, `MaybeRebalanceCaches`);
  `PopulateAndValidateSnapshot:5754` (per-coin guards lines
  5814-5883: nHeight≤baseHeight, outpoint.n<UINT32_MAX, MoneyRange,
  EmplaceCoinInternalDANGER, batch flush every 120k coins on
  CRITICAL cache state, SetBestBlock(GetRandHash()) hack, final
  SetBestBlock(base_blockhash), trailing-byte EOF check,
  FlushSnapshotToDisk, ComputeUTXOStats hash-serialized check,
  SnapshotUTXOHashBreakpoint interruption, fake BLOCK_OPT_WITNESS on
  every index in [AFTER_GENESIS_START..tip], dirty_blockindex insert,
  `index->m_chain_tx_count = au_data.m_chain_tx_count`);
  `MaybeValidateSnapshot:5967` (background validator: target reached,
  snapshot==target, ForceFlushStateToDisk, ComputeUTXOStats, hash
  compare, SetTargetBlock(nullptr), `InvalidateCoinsDBOnDisk`,
  `m_assumeutxo` enum transitions VALIDATED/UNVALIDATED/INVALID,
  fatalError on hash mismatch, return SnapshotCompletionResult).
- `bitcoin-core/src/rpc/blockchain.cpp` — `loadtxoutset:3368`
  (AutoFile open, `chainman.ActivateSnapshot`, RemoveLocalServices
  NODE_NETWORK, AddLocalServices NODE_NETWORK_LIMITED, result keys
  coins_loaded/tip_hash/base_height/path); `dumptxoutset:3074`
  (rollback `latest`/`rollback`/named-rollback, `fs::is_fifo` /
  `temppath = path + ".incomplete"` atomic write, `NetworkDisable` +
  `TemporaryRollback` RAII wrappers, `PrepareUTXOSnapshot` +
  `WriteUTXOSnapshot`, rpc_interruption_point every 5000 iter,
  CHECK_NONFATAL(written_coins_count == coins_count), result keys
  coins_written/base_hash/base_height/path/txoutset_hash/nchaintx);
  `getchainstates:3462` (HistoricalChainstate + CurrentChainstate
  ordered by work, per-chain fields blocks/bestblockhash/bits/target/
  difficulty/verificationprogress/snapshot_blockhash/
  coins_db_cache_bytes/coins_tip_cache_bytes/validated).
- `bitcoin-core/src/kernel/chainstatemanager_opts.h` —
  `ChainstateManagerOpts` fields used by snapshot infra:
  `coins_db{}` / `coins_view{}` (cache sizing), `notifications`,
  `signals`.
- `bitcoin-core/src/kernel/chainparams.h:34` — `AssumeutxoData`
  (height + AssumeutxoHash hash_serialized + m_chain_tx_count +
  blockhash) and `AssumeutxoForHeight` / `AssumeutxoForBlockhash` /
  `GetAvailableSnapshotHeights`.

BIPs: none (assumeutxo is implementation-level — no BIP).

**Source under audit**:
- `blockbrew/internal/consensus/assumeutxo.go` (781 LOC):
  `SnapshotMetadata`, `WriteSnapshot`, `LoadSnapshot`,
  `LoadSnapshotCoins`, `AssumeUTXOParams.ForHeight/ForBlockHash/
  AvailableHeights`, `Chainstate`, `DualChainstateManager.{Active,
  Background}Chainstate / CheckBackgroundValidation /
  SetValidationCallback`, `MainnetAssumeUTXOParams /
  Testnet4AssumeUTXOParams`.
- `blockbrew/internal/consensus/utxohash.go` (161 LOC):
  `WriteTxOutSer` (per-coin record), `ComputeHashSerialized` (Core's
  HASH_SERIALIZED), `ComputeMuHashUTXO` (Core's MUHASH3072 — fleet
  parity).
- `blockbrew/internal/rpc/methods.go::handleDumpTxOutSet` (lines
  2430-2676), `::writeUtxoSnapshotFile` (2748-2834),
  `::handleLoadTxOutSet` (2836-2891 — gate-and-refuse handler),
  `::handleGetChainStates` (2893-2946).
- `blockbrew/cmd/blockbrew/main.go::loadSnapshotFromFile` (1934-2103).
- `blockbrew/internal/storage/chainstate.go::ChainState` (170-203).
- `blockbrew/internal/consensus/w102_assumeutxo_audit_test.go` (30 gates
  already documented — W138 audits the SAME subsystem against an updated
  matrix and surfaces additional gaps and re-classifies severity).

---

## Severity matrix

| ID | Severity | Subsystem | Synopsis |
|----|----------|-----------|----------|
| BUG-1  | **P0-CDIV** | BackgroundValidator | `CheckBackgroundValidation` calls `ComputeUTXOHash` (custom SHA256-once) but compares against `AssumeUTXOData.HashSerialized` which is `ComputeHashSerialized` (SHA256d-over-TxOutSer) — the two functions are documented to diverge and a G15 test in W102 explicitly asserts they diverge. Background validator can **never** report success. |
| BUG-2  | **P0-CDIV** | DumpSnapshot | `WriteSnapshot` iterates `utxoSet.cache` only (assumeutxo.go:262-269). At any post-flush moment the cache holds **a subset** of the UTXO set; spilled coins are silently dropped. Real-world dumptxoutset on a node past genesis flush produces an incomplete snapshot with the WRONG `coins_written`/`txoutset_hash`. Core walks `CCoinsViewCursor` over the chainstate DB. |
| BUG-3  | **P0-CDIV** | LoadSnapshotCoins | `LoadSnapshotCoins` does NOT call `SetBestBlock(base_blockhash)` on the coins-cache view after the population loop — Core does this at validation.cpp:5870 as a structural invariant ("any subsequent flush stamps this hash"). Result: a SIGKILL between LoadSnapshotCoins return and the explicit `loaded.Flush()` in main.go:2076 produces a chainstate DB whose best-block is genesis but whose UTXO records are at the snapshot height. |
| BUG-4  | P1 | Persistence | No `SNAPSHOT_BLOCKHASH_FILENAME` sidecar / `WriteSnapshotBaseBlockhash` / `FindAssumeutxoChainstateDir` equivalent. After a successful `-load-snapshot`, the snapshot lineage (which block the snapshot was based on, whether background validation was completed) is **not recoverable across restart**. blockbrew records only `BestHash`+`BestHeight` in `ChainState` (storage/chainstate.go:170-173) — no `m_from_snapshot_blockhash`, no `m_assumeutxo` enum. |
| BUG-5  | P1 | RPC | `loadtxoutset` RPC is gated to refuse-and-direct-at-CLI for ALL inputs (methods.go:2882-2890) — operators on Core get a usable RPC that can activate snapshots on a running node provided header sync is far enough; blockbrew refuses unconditionally. The audit-trail comment cites the rustoshi 1d0a325 / hotbuns e355cd7 pattern but unlike those refs blockbrew has all the other-impl plumbing in place; the gate is over-conservative. (At minimum, snapshot lineage / fresh-chainstate / `m_from_snapshot_blockhash==nil` should be checked and refusal only when activation cannot proceed — Core returns `RPC_INTERNAL_ERROR` with the actual reason.) |
| BUG-6  | P1 | BackgroundValidator | `DualChainstateManager` is defined (assumeutxo.go:587-724) but `loadSnapshotFromFile` never constructs one — the IBD-from-genesis background validation thread that compares the validated UTXO hash against the snapshot is **dead code**. Even if BUG-1 were fixed the safety net wouldn't fire. |
| BUG-7  | P1 | Persistence | After `-load-snapshot`, the active `ChainState.BestHash` is set to the snapshot tip (main.go:2083-2088), but the **historical chainstate path** that Core keeps (separate `chainstate_snapshot/` leveldb dir) is not created. blockbrew uses a SINGLE chainstate, so the post-snapshot `getchainstates` array has only one entry — Core's array always has two during the snapshot→background-validated window. |
| BUG-8  | P1 | RPC | `handleGetChainStates` (methods.go:2929-2942) hardcodes `Validated: true` regardless of whether the active chainstate came from a snapshot whose background validation has not yet completed. Core sets `validated=false` while `m_assumeutxo == UNVALIDATED` (rpc/blockchain.cpp:3505). Operators reading `validated` cannot distinguish a real validated chain from an active-after-snapshot-but-not-yet-background-validated chain. |
| BUG-9  | HIGH | DumpSnapshot | `DumpTxOutSetResult.NChainTx` is populated with `coinsCount` (methods.go:2832) but Core's `nchaintx` field is `tip->m_chain_tx_count` (cumulative tx count from genesis). Coin-count and tx-count differ by ~8x on mainnet (~160M coins vs ~1.3B txs at h=944,183); operators copying blockbrew's `nchaintx` into a Core assumeutxo entry would get a wrong value. |
| BUG-10 | HIGH | DumpSnapshot | No FIFO / named-pipe support. Core's dumptxoutset (rpc/blockchain.cpp:3137) checks `fs::is_fifo(path_info)` and writes directly to the pipe instead of via `<path>.incomplete` + rename — both because a FIFO can't be renamed and because the consumer is reading concurrently. blockbrew's `writeUtxoSnapshotFile` (methods.go:2767-2823) refuses if `os.Stat(path)` succeeds (any existing entry), so a pre-created FIFO is rejected outright. |
| BUG-11 | HIGH | LoadSnapshot | No interrupt / cancellation. Core's `PopulateAndValidateSnapshot` checks `m_interrupt` every 120,000 coins (validation.cpp:5841-5843) and aborts with `"Aborting after an interrupt was requested"`. blockbrew's `LoadSnapshotCoins` (assumeutxo.go:417-477) runs the entire 160M+ coin load with no abort signal; SIGINT during a 30-minute snapshot import leaves the process running until completion. |
| BUG-12 | HIGH | DumpSnapshot | No `rpc_interruption_point` inside the `WriteSnapshot` loop. Core checks the interruption point every 5000 iterations (rpc/blockchain.cpp:3316). blockbrew's `WriteSnapshot` (assumeutxo.go:330-346) runs the entire UTXO walk without checking for shutdown — RPC client timeout / `Ctrl+C` of the daemon leaves the temp file half-written. |
| BUG-13 | HIGH | DumpSnapshot | `WriteSnapshot`'s tx-grouping protocol does not exactly mirror Core's. Core writes `last_hash` + `WriteCompactSize(coins.size())` + per-coin `WriteCompactSize(n) + Coin`. blockbrew does the same in the happy path but flushes coins-for-current-txid only when `coin.outpoint.Hash != lastTxid && len(txCoins) > 0` (assumeutxo.go:330-335). The first coin gets `lastTxid = coin.outpoint.Hash; txCoins = append(...)` and the flush only fires on the **next** txid — so the very last txid's coins are flushed only via the trailing `flushTxCoins()` post-loop. This is correct in isolation but **fails when CoinsCount > 0 but the cache iteration produced zero entries** (e.g. all entries are nil): metadata announces N coins but the file contains 0 coin records, and the trailing-byte check on the reader passes because EOF hits immediately. |
| BUG-14 | HIGH | LoadSnapshot | `LoadSnapshot` (the wrapper at assumeutxo.go:509-525) calls `LoadSnapshotCoins(sr, db, math.MaxInt32)` deliberately disabling the per-coin height guard (BUG-W102-01). The function is documented for "tests and dump/load symmetry" but is still exported and exists in the binary — a future caller that reaches for the "simple" API gets the no-height-check version. Should be private or removed. |
| BUG-15 | HIGH | DumpSnapshot/Lock | `handleDumpTxOutSet` calls `s.chainMgr.BestBlock()` (methods.go:2506) without taking the chain-manager mutex; between that call and `s.chainMgr.ReorgTo(targetNode)` (line 2630) the tip can advance. Core wraps the entire RPC in `cs_main` (the dual-purpose `LOCK(node.chainman->GetMutex())` block at rpc/blockchain.cpp:3199). |
| BUG-16 | HIGH | ActivateSnapshot | No post-population **final work comparison vs active tip**. Core does this at validation.cpp:5706-5708: a user could have loaded a snapshot very late in the IBD process and Core refuses to load a useless lighter chainstate. blockbrew's `loadSnapshotFromFile` checks `BUG-W102-06` (best-header ancestor) but does NOT compare cumulative work — a snapshot whose tip has less work than the current active chainstate would be loaded anyway. |
| BUG-17 | MED | LoadSnapshot | After `loadSnapshotFromFile` returns success, the segwit OP_WITNESS flag is **not** stamped onto the headers in `[AFTER_GENESIS_START..snapshot_tip]`. Core does this at validation.cpp:5930-5945 to prevent `Chainstate::NeedsRedownload()` from triggering a reindex on next boot. In blockbrew nothing sets the flag, so on restart the BlockNode segwit-bit may be stale and any consumer keying off "segwit activation height" sees an inconsistent value. |
| BUG-18 | MED | LoadSnapshot | After `loadSnapshotFromFile` returns success, `index->m_chain_tx_count = au_data.m_chain_tx_count` is **not** stamped onto the snapshot tip block. Core sets this at validation.cpp:5949. blockbrew has no per-block `ChainTxCount` field on BlockNode at all, so the cumulative-tx accounting is permanently zero from genesis to the snapshot height — `getblockchaininfo` / `verificationprogress` cannot use chain-tx-count to estimate progress through the snapshot window. |
| BUG-19 | MED | DumpSnapshot/Pruning | `handleDumpTxOutSet` (methods.go:2607-2612) documents pruning support as a no-op because "Pruning MISSING in blockbrew" (Cat-C reference); Core does a `BlockManager::IsPruneMode() && target_index->nHeight < GetFirstBlock()->nHeight` guard (rpc/blockchain.cpp:3164-3170). Once pruning lands the rollback target may be unreachable; today this is a latent gap rather than an immediate bug, but it should be flagged so the pruning wave revisits it. |
| BUG-20 | MED | DumpSnapshot | `WriteSnapshot` does NOT compute / surface the `txoutset_hash` field from the file stream directly. The dumptxoutset response gets it from a SECOND walk via `ComputeHashSerialized(us)` (methods.go:2815). The two walks see the SAME `utxoSet.cache` so they agree, but if a coin is added between (a) the WriteSnapshot loop and (b) the ComputeHashSerialized call, the file and reported hash diverge silently. Core computes both in the same UTXO cursor pass (rpc/blockchain.cpp:3211 `PrepareUTXOSnapshot` returns coins-cursor + stats atomically). |
| BUG-21 | MED | LoadSnapshot | Trailing-byte check uses `r.Read(probe[:])` which can return `(0, nil)` for a non-EOF reader that has not yet produced bytes — the audit code handles this case with `case err == nil: return ErrSnapshotTrailingBytes` but this means a stalled `io.Reader` (e.g. a paused FIFO consumer) would be reported as trailing-byte error rather than as a true I/O stall. Core uses an `AutoFile` exception-based read which forces a definite EOF or read. |
| BUG-22 | MED | RPC/Metadata | `LoadTxOutSetResult` struct (methods.go:2958-2964) is defined with fields `coins_loaded` / `tip_hash` / `base_height` / `path` (matches Core's loadtxoutset response) but is never used — the handler refuses unconditionally. If BUG-5 is addressed and the RPC is enabled, the result struct works; documenting the dead pin here so it doesn't drift before activation. |
| BUG-23 | LOW | Observability | The `Testnet4AssumeUTXOParams` slice is empty (assumeutxo.go:778-781). A testnet4 operator who downloads a snapshot from a third party and passes `-load-snapshot=...` gets `"snapshot block hash ... not recognised"` with no hint that the slice is empty by design. (Already listed as BUG-W102-16 — re-listed for completeness in the W138 matrix.) |

---

## 30-gate audit matrix

| # | Gate | Reference | Status |
|---|------|-----------|--------|
| G1 | Magic bytes `'u','t','x','o',0xff` | utxo_snapshot.h:28 | PRESENT — `SnapshotMagic` (assumeutxo.go:46) |
| G2 | VERSION=2 pinned + supported_versions set check | utxo_snapshot.h:39 | PARTIAL — `SnapshotVersion=2` pin (assumeutxo.go:49) but only checks `m.Version != SnapshotVersion` (no "supported_versions" set; future v3 readers would simply break) |
| G3 | Per-field rejection on metadata.Unserialize | utxo_snapshot.h:73-104 | PRESENT — `Deserialize` returns sentinel errors |
| G4 | Network-magic mismatch → diagnostic with from/to chain names | utxo_snapshot.h:91-101 | PARTIAL — `ErrNetworkMismatch` is generic, no friendly chain-name decode |
| G5 | `WriteSnapshotBaseBlockhash` sidecar | utxo_snapshot.h:118 + .cpp:22-46 | **MISSING** — BUG-4 |
| G6 | `ReadSnapshotBaseBlockhash` sidecar incl. trailing-data warning | utxo_snapshot.h:123 + .cpp:48-81 | **MISSING** — BUG-4 |
| G7 | `FindAssumeutxoChainstateDir` (chainstate_snapshot/ dir) | utxo_snapshot.h:132 + .cpp:83-92 | **MISSING** — BUG-4 / BUG-7 |
| G8 | AssumeutxoData fields {height, hash_serialized, m_chain_tx_count, blockhash} | chainparams.h:34-49 | PRESENT — `AssumeUTXOData` (assumeutxo.go:107-112) |
| G9 | `AssumeutxoForBlockhash` / `AssumeutxoForHeight` / `GetAvailableSnapshotHeights` | chainparams.h:119-128 + 92 | PRESENT — `ForHeight` / `ForBlockHash` / `AvailableHeights` |
| G10 | Mainnet table has 4 Core canonical entries (840k/880k/910k/935k) | bitcoin-core/src/chainparams.cpp | PRESENT — plus blockbrew-local 944183 entry |
| G11 | Testnet4 table populated for testnet4 snapshot loads | bitcoin-core/src/chainparams.cpp | **MISSING** — BUG-23 (empty) |
| G12 | `ActivateSnapshot:5600-5601` — "snapshot already loaded" guard | validation.cpp:5600 | **MISSING** — blockbrew lacks an in-RAM chainstate registry so the check is structurally unrepresentable. (BUG-5 forces refusal of all RPC loads instead.) |
| G13 | `ActivateSnapshot:5603-5609` — table-lookup-by-hash → ErrUnknownSnapshotHeight | validation.cpp:5603 | PRESENT — `loadSnapshotFromFile` step 4 (main.go:2000-2004) |
| G14 | `ActivateSnapshot:5611-5615` — base block in m_blockman.LookupBlockIndex | validation.cpp:5611 | PARTIAL — `headerIndex.GetNode(meta.BlockHash)` is checked at step 6 (BUG-W102-05) but only nil-tolerantly; absence does NOT abort. |
| G15 | `ActivateSnapshot:5617-5620` — `start_block_invalid` (BLOCK_FAILED_VALID) reject | validation.cpp:5617 | PRESENT — `baseNode.Status.IsInvalid()` (main.go:2024-2028) |
| G16 | `ActivateSnapshot:5622-5624` — base block on best-header chain | validation.cpp:5622 | PRESENT — `headerIndex.BestTip().GetAncestor(...)` (main.go:2032-2040) |
| G17 | `ActivateSnapshot:5626-5629` — mempool empty | validation.cpp:5626 | PARTIAL — `mempoolSize > 0` is checked but `loadSnapshotFromFile` is always called with `mempoolSize=0` from boot (main.go:795) — gate cannot fire in production. |
| G18 | `ActivateSnapshot:5641-5675` — cache resize IBD_CACHE_PERC / SNAPSHOT_CACHE_PERC | validation.cpp:5641 | **MISSING** — no two-cache split, no resize before/after PopulateAndValidateSnapshot |
| G19 | `cleanup_bad_snapshot` lambda — DeleteCoinsDBFromDisk + chainstate_snapshot rm | validation.cpp:5677-5694 | **MISSING** — BUG-4 / BUG-6 (no separate chainstate dir; on hash mismatch the corrupted UTXOs sit in the active chainDB) |
| G20 | `PopulateAndValidateSnapshot:5797-5862` — per-coin loop | validation.cpp:5797 | PARTIAL — height/MoneyRange/outpoint.n guards present (BUG-W102-01..03 fixed); `coins_per_txid > coins_left` check present; **interrupt check MISSING** — BUG-11 |
| G21 | `:5840-5856` — batched flush + SetBestBlock(GetRandHash) hack on CRITICAL cache | validation.cpp:5840 | **MISSING** — `LoadSnapshotCoins` accumulates everything in cache then defers flush; for a 160M-coin snapshot this is a peak-RAM disaster |
| G22 | `:5870` — `SetBestBlock(base_blockhash)` immediately after the loop | validation.cpp:5870 | **MISSING** — BUG-3 |
| G23 | `:5872-5883` — trailing-byte EOF check | validation.cpp:5872 | PRESENT — BUG-W102-04 fixed (assumeutxo.go:482-491) but BUG-21 (case 3 non-EOF zero-read) is a fragility |
| G24 | `:5891` — `FlushSnapshotToDisk(snapshot_loaded=true)` | validation.cpp:5891 | PARTIAL — `loaded.Flush()` in main.go:2076, but Core's flush is per-batch (G21) so memory profile differs |
| G25 | `:5912-5915` — `AssumeutxoHash{maybe_stats->hashSerialized} != au_data.hash_serialized` | validation.cpp:5912 | PRESENT — `ComputeHashSerialized` comparison (main.go:2058-2065) |
| G26 | `:5930-5945` — fake BLOCK_OPT_WITNESS in [AFTER_GENESIS_START..tip] | validation.cpp:5930 | **MISSING** — BUG-17 |
| G27 | `:5949` — stamp `m_chain_tx_count` on snapshot tip | validation.cpp:5949 | **MISSING** — BUG-18 (no field on BlockNode) |
| G28 | `:5717-5727` — `AddChainstate` + `PopulateBlockIndexCandidates` + `MaybeRebalanceCaches` | validation.cpp:5717 | **MISSING** — single-chainstate model only (BUG-6) |
| G29 | `MaybeValidateSnapshot:5967-6077` — background validator (hash compare, transitions, fatalError) | validation.cpp:5967 | PARTIAL — `DualChainstateManager.CheckBackgroundValidation` defined but (a) uses wrong hash algo BUG-1, (b) never wired BUG-6, (c) no `InvalidateCoinsDBOnDisk` BUG-6 |
| G30 | `dumptxoutset:3074` + `loadtxoutset:3368` + `getchainstates:3462` parity | rpc/blockchain.cpp | PARTIAL — dumptxoutset PRESENT incl. rollback path BUT cache-only-walk BUG-2 + nchaintx wrong BUG-9 + no FIFO BUG-10 + no interrupt BUG-12 + tip-race BUG-15 + dual-walk-hash drift BUG-20. loadtxoutset REFUSES unconditionally BUG-5. getchainstates always reports validated:true BUG-8, never exposes historical chainstate BUG-7. |

---

## Top findings (5)

1. **BUG-1 P0-CDIV: BackgroundValidator hash-algorithm mismatch makes the
   safety net permanently broken.** `DualChainstateManager.
   CheckBackgroundValidation` (assumeutxo.go:677) calls `ComputeUTXOHash`
   (custom SHA256-once-over-bespoke-serialization) and compares to
   `AssumeUTXOData.HashSerialized` which is produced by
   `ComputeHashSerialized` (SHA256d-over-TxOutSer per Core's
   coinstats.cpp::HASH_SERIALIZED). The two algorithms are documented to
   diverge (W102 G15 test asserts they DO diverge for the same UTXO
   set). If the background validator were ever wired (BUG-6: it isn't),
   it would mark **every** snapshot as INVALID and shut the node down on
   schedule.

2. **BUG-2 P0-CDIV: dumptxoutset writes only the in-memory cache, silently
   dropping spilled coins.** `WriteSnapshot` (assumeutxo.go:262-269)
   iterates `utxoSet.cache` only. At any moment past initial flush (~5M
   entries on a default cache) the cache is a SUBSET of the UTXO set;
   `dumptxoutset` then writes an incomplete snapshot, computes
   `txoutset_hash` over the same subset, and reports a coin count that
   matches the truncated file but disagrees with the chain. Core walks
   `CCoinsViewCursor` over the chainstate DB (rpc/blockchain.cpp:3211
   `PrepareUTXOSnapshot` returns a cursor, line 3315
   `pcursor->Valid()`). Production dumptxoutset on a node past genesis-
   flush — i.e. **every** real deploy — produces a torn snapshot.

3. **BUG-3 P0-CDIV: LoadSnapshotCoins does not stamp the coins-cache
   best-block at population-end.** Core sets `coins_cache.SetBestBlock(
   base_blockhash)` at validation.cpp:5870 immediately after the coin
   loop and BEFORE the FlushSnapshotToDisk call. blockbrew's
   `LoadSnapshotCoins` (assumeutxo.go:407-496) leaves the
   `chainDB`-backed UTXOSet's best-block invariant at "whatever was
   there before" — for a fresh chainstate this is genesis hash zero or
   uninitialised. A SIGKILL between LoadSnapshotCoins return and the
   explicit `loaded.Flush()` in main.go:2076 leaves the chainstate DB
   in a state where the UTXO records claim height ~944,183 but the
   best-block metadata claims height 0. On restart the chain-state load
   reads the BestHash=genesis sentinel and assumes a fresh chain — the
   snapshot UTXOs are inaccessible. (W102-era audit explicitly accepted
   the deferred-flush as a feature; W138 re-classifies the missing
   SetBestBlock-before-flush as a P0-CDIV bug because Core's snapshot
   contract is "every flush must stamp a base blockhash".)

4. **BUG-4 P1: No `m_from_snapshot_blockhash` persistence.** Core writes
   a sidecar file `chainstate_snapshot/base_blockhash` after
   `ActivateSnapshot` (utxo_snapshot.cpp:22-46) and reads it at boot
   (`FindAssumeutxoChainstateDir` + `ReadSnapshotBaseBlockhash`) so the
   snapshot lineage and background-validation completion state are
   recoverable across restart. blockbrew's `ChainState` struct
   (storage/chainstate.go:170-173) is only `BestHash` + `BestHeight`;
   after a successful `-load-snapshot`, restart the node, and there is
   no way to tell from disk whether the active chainstate is "validated
   from genesis" or "loaded from snapshot, pending background
   validation". The `Validated:true` hardcoding in
   `handleGetChainStates` (BUG-8) is downstream of this gap.

5. **BUG-6 P1: DualChainstateManager is dead code.** `assumeutxo.go:587-
   724` defines a full 3-chainstate model
   (active+background+expected-hash with `CheckBackgroundValidation`
   and `SetValidationCallback`) but `loadSnapshotFromFile` (main.go:
   1954-2103) never constructs one; the chain manager that starts at
   `main.go:802` is a single chainstate. The blockbrew node accepts a
   snapshot on hash-check alone with NO background re-validation thread
   running an IBD-from-genesis pass that would catch a corrupt/forged
   snapshot whose first-time hash check matches by collision (the whole
   point of Core's `MaybeValidateSnapshot`). Combined with BUG-1 this
   means there is no realistic path to background-validation success
   today.

---

## Universal patterns spotted

- **"defined-but-not-wired" subsystem** (BUG-6 + BUG-8 + BUG-22):
  `DualChainstateManager` / `LoadTxOutSetResult` / `Chainstate.role`
  transitions are all defined in source, exported, and covered by unit
  tests but **never instantiated** in production. This is a continuation
  of the same pattern documented across W117/W120/W122/FIX-71/FIX-81
  (FIX-71 "plumb-gate-then-flip cross-wave activation"): blockbrew has a
  history of landing the API and tests in one wave and never wiring the
  call-site in the next. The fix-wave pattern would be a single
  one-call-site CL ("construct DualChainstateManager in main.go after
  loadSnapshotFromFile success") followed by a follow-on CL that flips
  BUG-1 (fix the hash-algorithm) and a third CL that wires the
  background IBD pass.

- **"cache-only walks" producing torn snapshots** (BUG-2): same shape as
  past audit findings where an iterator walks a subset of the source-
  of-truth. Audit framework should add a universal gate: "any function
  that produces a deterministic view over a versioned store must walk
  the store directly, not a cache; if it walks a cache, the cache must
  be flushed first and verified to be the entire view." (Compare with
  `ComputeHashSerialized` which ALSO walks the cache only — same bug
  shape; producing a digest that doesn't actually digest the chainstate.)

- **"refuse-and-direct-at-CLI" pattern as workaround for activation
  complexity** (BUG-5): hotbuns e355cd7 / rustoshi 1d0a325 introduced
  this in 2026-05-05 cross-impl audit to avoid silent corruption when
  RPC could not atomically activate a snapshot in a running daemon. The
  pattern is correct as a one-step gate ("until we wire X, refuse") but
  blockbrew adopted the gate AND then went further by not wiring the
  background validator either (BUG-6). End state: neither the RPC nor
  the CLI exercises the full safety net.

- **"single-chainstate model" structurally precluding Core-parity
  features** (BUG-7 + BUG-12 + BUG-29 partial): blockbrew has one
  `*ChainDB` + one `*UTXOSet`; Core has `m_snapshot_chainstate` +
  `m_ibd_chainstate` (background) sharing the `BlockManager`. Several
  audit gates (G7 chainstate_snapshot dir, G12 "already loaded" guard,
  G28 AddChainstate) cannot be represented at all without the multi-
  chainstate refactor. This is a structural cat-A audit finding, not a
  one-line fix.

---

## Test plan

Tests land in `internal/consensus/w138_assumeutxo_test.go` with the
convention used by W102: tests that pass today PIN current behaviour
(forward-regression); tests that document an unimplemented gate
`t.Skip("W138 audit: BUG-N — ...")`. The W102 test file is preserved
as-is (W138 audits the same subsystem with an updated matrix); the
W138 file references W102 IDs where they overlap.

Running `go test ./internal/consensus/ -run W138` should produce: all
present-gate tests pass, all skipped tests print their BUG-id reason.

(Concurrent-wave consideration: parallel W### waves may touch
`internal/consensus/utxohash.go` / `ComputeHashSerialized` / `WriteTxOutSer`
— the W138 test file does NOT depend on those internals for present-gate
checks; it pins via the `SnapshotMagic` / `SnapshotVersion` /
`AssumeUTXOData.ForBlockHash` API surface.)
