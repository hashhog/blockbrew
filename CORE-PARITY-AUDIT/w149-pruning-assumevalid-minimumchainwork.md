# W149 — Pruning + assumevalid + minimumchainwork (blockbrew)

**Wave:** W149 — `FindFilesToPrune`, `FindFilesToPruneManual`,
`UnlinkPrunedFiles`, `PruneOneBlockFile`, `m_have_pruned`,
`MIN_BLOCKS_TO_KEEP=288`, `MIN_DISK_SPACE_FOR_BLOCK_FILES=550`,
`-prune=N` sentinel (0/1/≥550), `BLOCK_ASSUMED_VALID`, `fScriptChecks`,
`-assumevalid` CLI override, `defaultAssumeValid` per-network,
`nMinimumChainWork` per-network, `UpdateIBDStatus` /
`IsTipRecent(MinimumChainWork(), max_tip_age)`,
`pruneblockchain` RPC, `getblockchaininfo` pruning fields.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/blockstorage.cpp:336-342` — `-prune` parse:
  `0 = off`, `1 = manual` (PRUNE_TARGET_MANUAL sentinel = `UINT64_MAX`,
  unreachable target so `FindFilesToPrune`'s usage check never trips),
  `≥550 MiB = automatic`.
- `bitcoin-core/src/node/blockstorage.cpp` —
  `FindFilesToPrune(set_files_to_prune, last_block_can_prune, m_chainman)`,
  `FindFilesToPruneManual(set_files_to_prune, nManualPruneHeight, chain_tip)`,
  `PruneOneBlockFile(fileNumber)` (resets `m_blockfile_info.at(fileNumber)`,
  walks chain index and CLEARS `BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO` flags
  AND zeros `nFile/nDataPos/nUndoPos` on every CBlockIndex whose data lived
  in that file), `UnlinkPrunedFiles(set_files_to_prune)`, `FlushBlockFile`,
  `PruneAndFlush`, `CheckDiskSpace(GetBlocksDir(), MIN_DISK_SPACE_FOR_BLOCK_FILES)`.
- `bitcoin-core/src/node/blockstorage.h:408` — `PRUNE_TARGET_MANUAL = UINT64_MAX`.
- `bitcoin-core/src/init.cpp` — `MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB`;
  `-prune=N` argument parse, `m_have_pruned` persistence as
  `fHavePruned` flag in the block-index leveldb (`PruneFlag()`,
  `WritePruneFlag()`).
- `bitcoin-core/src/validation.cpp:4297-4430` — `AcceptBlock` (always
  writes block body to disk; pruning happens later).
- `bitcoin-core/src/validation.cpp` (ConnectBlock ~2280-2310) —
  `BLOCK_ASSUMED_VALID` skips signature checks ONLY (`fScriptChecks`
  gate); BIP-30 / BIP-34 / nSubsidy / MoneyRange / undo-data generation
  all remain enforced.
- `bitcoin-core/src/validation.cpp` — `m_assumed_valid_blocks` counter
  (exposed via `getblockchaininfo.verificationprogress` math and
  `getchaintips.status="assumed-valid"`).
- `bitcoin-core/src/kernel/chainparams.cpp:109/110, 232/233, 332/333,
  423/424, 435/436, 557/558` — per-network `nMinimumChainWork` +
  `defaultAssumeValid` (mainnet/testnet3/testnet4/signet/regtest).
- `bitcoin-core/src/init.cpp` — `-assumevalid=<hex>` argument:
  default = chainparams `defaultAssumeValid`; empty string OR `0` = disable
  the optimisation entirely.
- `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291` —
  `IsInitialBlockDownload` / `UpdateIBDStatus`: `m_cached_is_ibd`
  latched to false ONLY when **both** `chainstate.m_chain.Tip()->nChainWork
  >= MinimumChainWork()` AND `IsTipRecent(max_tip_age)`. Latch is one-way.
- `bitcoin-core/src/net_processing.cpp:1280` —
  `MinimumConnectedChainWork` peer-acceptance gate (peers whose advertised
  best-known-block work is below the active tip's work × headers-sync
  protect window get disconnected after `CHAIN_SYNC_TIMEOUT`).
- `bitcoin-core/src/rpc/blockchain.cpp::pruneblockchain` — dual-mode:
  argument > 1_000_000_000 = unix-timestamp lookup, else absolute height;
  refuses if pruning disabled; clamps to `tip - MIN_BLOCKS_TO_KEEP`.
- `bitcoin-core/src/rpc/blockchain.cpp::getblockchaininfo` — emits
  `pruned`, `pruneheight`, `automatic_pruning`, `prune_target_size`.

**Files audited**
- `internal/storage/prune.go` — `Pruner`, `PruneConfig`, `MaybePrune`,
  `PruneOneBlockFile`, `UnlinkPrunedFile`, `CalculateCurrentUsage`,
  `lastSafeHeight`, `IsEnabled`, `IsAutomatic`, `IsPrunedBlockError`,
  `HasBlockBody`, `MinBlocksToKeep`, `MinPruneTargetMiB`,
  `MinPruneTargetBytes`.
- `internal/storage/flatfile.go` — `BlockStore`, `saveState`,
  `loadState` (state persistence, `flatFileStateKey="F"`,
  `blockFileInfoPrefix="f"`), `DeleteBlockIndex`, `DeleteUndoIndex`,
  `WriteAndIndexBlock`, `WriteAndIndexUndo`, `HasBlock`, `HasUndo`,
  `ErrDiskFull` (defined unused).
- `internal/consensus/chaincfg.go` — `ChainParams.AssumeValidHash` and
  `ChainParams.MinimumChainWork` (per-network); mainnet `109/110`,
  testnet3 `288-294` (no AssumeValidHash), regtest `354` (zero),
  signet `418-422` (no AssumeValidHash), testnet4 `481-500`.
- `internal/consensus/chainmanager.go` — `assumeValidHash`,
  `assumeValidHeight`, `isIBD` flag (line 77, 250, 500, 527, 556,
  966-967, 1002-1015, 1243-1250), `skipScripts` derivation (line 524),
  `generateUndo` derivation (line 556), `IBD-exit` gate (line 966),
  `IBD-side reject` (line 500), `ReorgTo`.
- `internal/consensus/headerindex.go` — `AddHeader` `minPowChecked`
  gate (line 394-491, `ErrTooLittleChainwork`), `StatusDataStored`
  flag (line 43), `MarkDataStored` / `MarkUndoStored` (line 545-569).
- `internal/p2p/sync.go` — `MaxTipAge = 24*time.Hour` (line 81),
  `needsHeadersSync` (line 506-516), `computeMinimumRequiredWork`
  (line 521-535), `updateIBDStatus` (line 2599-2624), `IsIBDActive`,
  prune-mode getdata gate (line 1288-1296).
- `internal/p2p/peermgr.go` — `AdvertiseNodeNetworkLimited` (line 145),
  `ServiceNodeNetworkLimited = 1 << 10` (msg_version.go:17).
- `internal/rpc/methods.go` — `handleGetBlockchainInfo` pruning fields
  (line 123-139), `pruner.HavePruned` is never consulted.
- `internal/rpc/server.go` — RPC dispatch table (line 516-746). No
  `pruneblockchain` case.
- `internal/rpc/types.go` — `BlockchainInfo` JSON shape (line 83-112).
- `cmd/blockbrew/main.go` — `-prune` flag (line 477, 537-546),
  `cfg.Prune` plumbing (line 727-744), no `-assumevalid` flag at all,
  `AssumeValidHash` injection (line 807, 1845).

---

## Gate matrix (32 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | -prune=N CLI parse | G1: `0` → archive (off) | PASS (`main.go:727-728`) |
| 1 | … | G2: `1` → manual mode (auto-prune disabled, RPC-driven) | PARTIAL — flag accepts and sets `Manual=true` (`main.go:728-729`), pruner suppresses auto-pass (`prune.go:252-257`); but **BUG-3** below shows the manual sweep RPC does not exist, so manual mode is permanently inert |
| 1 | … | G3: `2..549` → reject with floor error | PASS (`main.go:541-546`) |
| 1 | … | G4: `≥550` → auto-prune target in MiB | PASS (`main.go:730-732`) |
| 1 | … | G5: `<0` → reject | PASS (`main.go:537-540`) |
| 2 | FindFilesToPrune semantics | G6: usage+buffer < target → no-op | PASS (`prune.go:273-280`) |
| 2 | … | G7: prune oldest-fileNum first | PASS (`prune.go:299`) |
| 2 | … | G8: skip currentFileNum (the open writer) | PASS (`prune.go:310-312`) |
| 2 | … | G9: refuse files whose `HeightLast > tip - 288` | PASS (`prune.go:317-319`) |
| 2 | … | G10: clear `BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO` on every CBlockIndex whose data lived in pruned file | **BUG-1 (P0-CDIV)** — `MaybePrune` deletes per-block position index rows (`prune.go:328-335`) but never clears `StatusDataStored` / `StatusHaveUndo` on the corresponding `BlockNode`s in the header index |
| 2 | … | G11: persist `m_have_pruned` flag to disk | **BUG-2 (P1)** — `havePruned` is an in-memory `atomic.Bool` (`prune.go:94, 119, 370`); never written to the flatfile state record (`saveState`/`loadState` at flatfile.go:548-636 omits the field). On restart the node "forgets" it was ever pruned, and any code that gates on `m_have_pruned` (Core uses it to refuse to disable pruning post-facto and to require `-reindex`) is dead. |
| 2 | … | G12: `CheckDiskSpace(MIN_DISK_SPACE_FOR_BLOCK_FILES)` before each write | **BUG-4 (P1)** — `ErrDiskFull` defined but never returned (`flatfile.go:178`); no `syscall.Statfs` runtime gate. Disk-full aborts the write with a raw I/O error path rather than `MIN_DISK_SPACE_FOR_BLOCK_FILES` pre-flight |
| 3 | -prune=1 manual + pruneblockchain RPC | G13: `pruneblockchain` JSON-RPC handler dispatched | **BUG-3 (P0-CDIV)** — there is NO `pruneblockchain` case in the RPC dispatch table (`server.go:516-746` enumerates getblockchaininfo, dumptxoutset, loadtxoutset, etc. — pruneblockchain is absent). Calls return method-not-found |
| 3 | … | G14: dual-mode argument (height vs unix-timestamp > 1e9) | N/A (handler absent) |
| 3 | … | G15: clamp `height > tip - 288` down to safe horizon | N/A (handler absent) |
| 3 | … | G16: error when pruning disabled | N/A (handler absent) |
| 4 | -assumevalid CLI parse | G17: `-assumevalid=<hex>` overrides chainparams default | **BUG-5 (P0-CDIV)** — there is NO `-assumevalid` flag at all in `parseFlags` (`main.go:445-496`). The only AssumeValidHash source is `chainParams.AssumeValidHash` (`main.go:807, 1845`). Operator cannot override per-network default, cannot opt out, cannot pass a more-recent block |
| 4 | … | G18: `-assumevalid=0` disables script-skip entirely | **BUG-5 cross-cite** |
| 4 | … | G19: `-assumevalid=` (empty) reset to chainparams default | **BUG-5 cross-cite** |
| 5 | defaultAssumeValid per-network | G20: mainnet default present | PASS (`chaincfg.go:189-194`, matches Core `00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac` height 938343) |
| 5 | … | G21: testnet3 default present | **BUG-6 (P1)** — blockbrew `chaincfg.go:222-296` omits `AssumeValidHash`; Core sets `000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4` (height 4842348). Testnet3 IBD is much slower than Core (full script verification all the way to tip) |
| 5 | … | G22: testnet4 default present | PASS (`chaincfg.go:481-486`, matches Core `0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a` h=123613) |
| 5 | … | G23: signet default present | **BUG-7 (P1)** — blockbrew `chaincfg.go:359-425` omits `AssumeValidHash`; Core sets `00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329` (height 293175). Signet IBD slower than Core |
| 5 | … | G24: regtest default = uint256{} (no skip) | PASS (`chaincfg.go:299-357`, field omitted = zero) |
| 6 | BLOCK_ASSUMED_VALID semantics | G25: skip ONLY script signature checks | **BUG-8 (P0-CDIV)** "assume-valid scope creep" — `chainmanager.go:556` derives `generateUndo := !skipScripts || !cm.isIBD`. When `skipScripts && cm.isIBD` (the canonical IBD assume-valid path), **undo data generation is skipped** — Core skips ONLY `fScriptChecks`, never undo |
| 6 | … | G26: BIP-30 / BIP-34 / nSubsidy / MoneyRange still enforced | PASS — the gates run before the `if !skipScripts` script-validation block at `chainmanager.go:904` |
| 6 | … | G27: `m_assumed_valid_blocks` counter exposed via getblockchaininfo | **BUG-9 (P1)** no equivalent counter; `verificationprogress` is a simple `tipHeight / bestHeaderHeight` ratio (`methods.go:208-216`) instead of Core's tx-count-weighted progress incorporating m_assumed_valid_blocks |
| 7 | nMinimumChainWork wiring | G28: per-network parameter set (mainnet/testnet3/testnet4/signet ≠ 0, regtest = 0) | PASS (`chaincfg.go:204-208 / 290-294 / 354 / 418-422 / 496-500`) |
| 7 | … | G29: header-acceptance min_pow_checked gate | PASS (`headerindex.go:479-491`) |
| 7 | … | G30: PRESYNC/REDOWNLOAD pipeline triggered when tip work < MinimumChainWork | PASS (`sync.go:488-494, 506-516`) |
| 8 | UpdateIBDStatus / IsInitialBlockDownload | G31: IBD-exit requires `tip_work >= MinimumChainWork` AND `tip recent` | **BUG-10 (P0-CDIV)** — `sync.go::updateIBDStatus` (line 2599-2624) tests **only** `time.Since(tipTime) <= MaxTipAge`. The MinimumChainWork half of Core's `IsTipRecent(MinimumChainWork(), max_tip_age)` clause is missing. A faked-low-work but recent-timestamp tip would prematurely exit IBD |
| 8 | … | G32: there is ONE IBD flag, not two diverging caches | **BUG-11 (P0-CDIV)** — blockbrew has TWO `isIBD`-like flags: `SyncManager.ibdActive` (atomic.Bool, gated on tip-age, sync.go) AND `ChainManager.isIBD` (plain bool under cm.mu, gated on `tipHeight == assumeValidHeight`, chainmanager.go:966). They diverge by construction and by timing |

---

## BUG-1 (P0-CDIV) — Prune leaves `StatusDataStored` set on BlockNodes whose blk file was unlinked

**Severity:** P0-CDIV. Bitcoin Core's `PruneOneBlockFile`
(node/blockstorage.cpp) walks the entire block index and, for every
`CBlockIndex* pindex` whose `pindex->nFile == fileNumber`, clears
`pindex->nStatus &= ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)` and zeros
`nFile`, `nDataPos`, `nUndoPos`. This is what allows `FindNextBlocksToDownload`
(net_processing) and `ActivateBestChainStep` to RE-REQUEST the body of
a pruned-then-needed block on a subsequent deep reorg, and what makes
`getchaintips` correctly report `status="headers-only"` for a chain
whose body was pruned.

blockbrew's `MaybePrune` (`prune.go:328-335`) walks heights and calls
`p.bs.DeleteBlockIndex(hash)` + `p.bs.DeleteUndoIndex(hash)` — these
delete the per-block position rows in Pebble, but the
`consensus.BlockNode` objects held in the in-memory `HeaderIndex` still
have `StatusDataStored | StatusHaveUndo` set from the original
`MarkDataStored`/`MarkUndoStored` calls. `recalculateBestTipLocked`'s
filter at `headerindex.go:751-760` is:

```go
if node.Status&StatusDataStored == 0 {
    continue // skip data-absent candidates
}
// ... walk ancestor chain, also filtered on StatusDataStored
```

After a prune sweep this filter will continue to ACCEPT pruned
candidates as eligible best-tip, then `ConnectBlock` will try to call
`cm.chainDB.GetBlock(hash)` (chainmanager.go:1702) which returns
`os.ErrNotExist`, and the reorg fails with `"block ... not found for
reorg"`. Net result: the prune sweep silently corrupts the chain
manager's view of which blocks are connectable.

**File:** `internal/storage/prune.go:328-335` (delete loop) + cross-file
gap to `internal/consensus/headerindex.go` (no `ClearDataStored` /
`MarkPruned` API).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::PruneOneBlockFile`
(walks block index and clears HAVE_DATA / HAVE_UNDO).

**Excerpt (blockbrew, missing index-side clear)**
```go
for h := int32(fi.HeightFirst); h <= int32(fi.HeightLast); h++ {
    hash, err := p.chainDB.GetBlockHashByHeight(h)
    if err != nil {
        continue
    }
    _ = p.bs.DeleteBlockIndex(hash)
    _ = p.bs.DeleteUndoIndex(hash)
    // MISSING: cm.headerIndex.MarkPruned(hash)  // clear StatusDataStored | StatusHaveUndo
}
```

**Impact:** prune + reorg → reorg fails to find the block body and
errors out instead of refusing on `BLOCK_HAVE_DATA` absence; `getchaintips`
reports stale "active"/"valid-fork" for header-only pruned chains;
`recalculateBestTipLocked` may pick a pruned tip as best-candidate and
loop on ConnectBlock failure.

---

## BUG-2 (P1) — `m_have_pruned` flag never persisted; in-memory only

**Severity:** P1. Bitcoin Core writes `fHavePruned = true` into the
block-index leveldb the first time a prune pass frees a file
(`WritePruneFlag` / `ReadPruneFlag`). On restart, the flag is read back
and `m_have_pruned` is set BEFORE any further sweep runs. This drives
several behaviours: refusal to disable pruning post-facto without
`-reindex`, advertising NODE_NETWORK_LIMITED with the correct
`NETWORK_LIMITED_MIN_BLOCKS=288` from the very first version handshake
(rather than after the first sweep), and `getchaintips`
status reporting.

blockbrew's `havePruned` is `atomic.Bool` on the `Pruner` struct
(`prune.go:94`), set to `true` only inside `MaybePrune` after a
successful unlink (`prune.go:370`). It is never persisted. On every
restart the value resets to `false` regardless of on-disk state. The
only consumer is `Pruner.HavePruned()` (`prune.go:115-120`), and a
grep over `internal/` shows zero call sites — the flag is plumbed but
unread (dead-data plumbing pattern, fleet repeat).

**File:** `internal/storage/prune.go:94, 115-120, 370`;
`internal/storage/flatfile.go:548-583` (`saveState` omits the field).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::WritePruneFlag`,
`ReadPruneFlag`.

**Impact:** restart-after-prune misreports `m_have_pruned=false` until
the next sweep, which (a) is benign on a still-pruning auto-mode node
because the next pass will reset it within minutes, but (b) on a
manual-mode `-prune=1` node where no sweep ever fires automatically,
the flag stays `false` forever and operator tooling that reads it
sees the wrong state.

---

## BUG-3 (P0-CDIV) — `pruneblockchain` RPC does not exist

**Severity:** P0-CDIV. Bitcoin Core's `pruneblockchain` RPC is the
ONLY way to free data when `-prune=1` (manual mode). Without it,
manual mode is fundamentally non-functional: the operator sets
`-prune=1`, the daemon advertises NODE_NETWORK_LIMITED, but the
blk*.dat directory grows without bound because nothing ever triggers a
sweep.

blockbrew's RPC dispatch (`internal/rpc/server.go:516-746`) enumerates
~150 methods (getblockchaininfo, getblockcount, getrawmempool,
dumptxoutset, loadtxoutset, gettxoutsetinfo, getblockfilter, etc.).
There is no `case "pruneblockchain":`. The method silently returns
`Method not found`. The startup log at `main.go:736` says "Pruning
enabled: manual mode (-prune=1); auto-prune off, pruneblockchain RPC
required" — which is a **comment-as-confession** that the operator is
being directed at an RPC that does not exist.

**File:** `internal/rpc/server.go:516-746` (RPC table, no
pruneblockchain case); `cmd/blockbrew/main.go:736` (log line directs
at non-existent RPC).

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp::pruneblockchain`.

**Impact:**
- `-prune=1` manual mode is **functionally dead**: the daemon enters
  the mode, advertises NODE_NETWORK_LIMITED, but cannot ever prune.
  The on-disk footprint grows unbounded.
- Cross-impl divergence: operators porting bitcoin.conf from Core that
  rely on a cron-driven `bitcoin-cli pruneblockchain $((tipHeight-1000))`
  loop see all calls fail; the chaindir fills the disk.
- Fleet pattern: this is the same shape as W138 BUG-class
  "wiring-look-but-no-wire" — the CLI flag accepts the value, the
  log line confirms the mode, the only path that activates the mode
  is missing.

---

## BUG-4 (P1) — `MIN_DISK_SPACE_FOR_BLOCK_FILES` is enforced on CLI but never at runtime

**Severity:** P1. Bitcoin Core's `MIN_DISK_SPACE_FOR_BLOCK_FILES = 50 MiB`
is used both as the `-prune=N` floor AND as a runtime gate in
`FlushStateToDisk` / `FindBlockPos`: before each new file is opened,
`CheckDiskSpace(GetBlocksDir(), MIN_DISK_SPACE_FOR_BLOCK_FILES)` runs;
if free space is below the threshold, the node enters
`SHUTDOWN_DISKSPACE` error state and shuts down cleanly. This is what
prevents a runaway prune-mode node from corrupting Pebble when the
volume fills.

blockbrew uses `MinPruneTargetMiB = 550` (`prune.go:23-30`) as the
floor for `-prune=N` only. `ErrDiskFull = errors.New("flatfile: disk
full")` is defined at `flatfile.go:178` but **never returned** by any
code path. There is no `syscall.Statfs` call anywhere in
`internal/storage/`. Disk-full aborts a write with a raw `*os.PathError`
from `WriteAt`, which the caller turns into a generic error and
continues processing (the next batch retries, fails the same way, and
the node spins).

**File:** `internal/storage/flatfile.go:178` (`ErrDiskFull` defined),
`internal/storage/prune.go:14-31` (constant defined but no runtime
consumer).

**Core ref:** `bitcoin-core/src/util/fs_helpers.cpp::CheckDiskSpace`,
`bitcoin-core/src/init.cpp` (`MIN_DISK_SPACE_FOR_BLOCK_FILES`).

**Impact:** disk-full failures during IBD do not result in clean
shutdown; the node loops on retry-fail until killed externally. On a
prune-mode node this can also lead to a windowed corruption where the
chainstate is updated past a block whose body could not be written.

---

## BUG-5 (P0-CDIV) — `-assumevalid` CLI flag does not exist

**Severity:** P0-CDIV. Bitcoin Core's `-assumevalid=<hex>` flag is the
canonical operator-knob for the assume-valid optimisation:
- default = chainparams `defaultAssumeValid` per network,
- `-assumevalid=` (empty) = reset to chainparams default,
- `-assumevalid=0` = disable the optimisation entirely (validate every
  signature from genesis),
- `-assumevalid=<hex>` = use a more-recent (or older) block hash.

blockbrew's `parseFlags` (`cmd/blockbrew/main.go:445-496`) defines NO
such flag. The only source of `AssumeValidHash` is the per-network
default in `chaincfg.go`, plumbed at `main.go:807` and `main.go:1845`:

```go
chainMgrCfg := consensus.ChainManagerConfig{
    ...
    AssumeValidHash: chainParams.AssumeValidHash,
    ...
}
```

The operator has no in-band way to:
- disable the optimisation for paranoia / security audits,
- bump assume-valid to a more recent block for faster IBD,
- override a stale chainparams default after a release that ships a
  new defaultAssumeValid upstream.

**File:** `cmd/blockbrew/main.go:445-496` (parseFlags, no
`-assumevalid` registration); chaincfg.go:189-194/481-486 (only
source).

**Core ref:** `bitcoin-core/src/init.cpp` (`-assumevalid` parse);
`bitcoin-core/src/validation.cpp::ChainstateManager::Options::assumed_valid_block`.

**Impact:**
- No security knob: a CVE in a single ECDSA verifier cannot be
  worked around with `-assumevalid=0`. Operator must hot-patch the
  source and rebuild.
- No operator override of stale defaults: when upstream chainparams
  ships a fresher block, blockbrew operators wait for a hashhog release.
- Cross-fleet: every other hashhog impl exposes `-assumevalid`; this
  is a missing-feature parity gap.

---

## BUG-6 (P1) — `defaultAssumeValid` missing for testnet3

**Severity:** P1. `bitcoin-core/src/kernel/chainparams.cpp:233` sets
`consensus.defaultAssumeValid = uint256{"000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4"}`
for testnet3 (height 4,842,348). blockbrew's
`TestnetParams()` (`chaincfg.go:222-296`) does NOT set `AssumeValidHash`
— the field defaults to the zero value, which `chainmanager.go:517`
treats as "no assume-valid" via `cm.assumeValidHash.IsZero()`.

Consequence: every testnet3 IBD revalidates every signature from
genesis to tip, taking several hours longer than Core (or hashhog
impls with the value set).

**File:** `internal/consensus/chaincfg.go:222-296` (testnet3 block,
AssumeValidHash field omitted).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:233`.

**Impact:** slow testnet3 IBD; cross-impl divergence in IBD wall-clock
time on the same network.

---

## BUG-7 (P1) — `defaultAssumeValid` missing for signet

**Severity:** P1. Identical shape to BUG-6 for signet.
`bitcoin-core/src/kernel/chainparams.cpp:424` sets
`consensus.defaultAssumeValid = uint256{"00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329"}`
for default-signet (height 293,175). blockbrew's `SignetParams()`
(`chaincfg.go:359-425`) omits the field.

**File:** `internal/consensus/chaincfg.go:359-425` (signet block).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:424`.

**Impact:** slow signet IBD; cross-impl divergence in IBD wall-clock
time on default-signet.

---

## BUG-8 (P0-CDIV) — Assume-valid scope creep: skips undo-data generation, not just signatures

**Severity:** P0-CDIV ("assume-valid scope creep" — first blockbrew
instance of the fleet-wide W145 pattern reported for hotbuns
W145 BUG-2..6 cluster). Bitcoin Core's `BLOCK_ASSUMED_VALID`
optimisation is **strictly** "skip signature verification"
(`fScriptChecks` gate at `validation.cpp:2280-2310`). Every other
gate — undo-data generation, MoneyRange, BIP-30, BIP-34, nSubsidy,
maturity, sigops — runs unconditionally. The undo data MUST be
generated and persisted, because the block may later need to be
disconnected during a reorg.

blockbrew's `chainmanager.go:556` derives:

```go
generateUndo := !skipScripts || !cm.isIBD
```

When `skipScripts && cm.isIBD` (the canonical IBD assume-valid path),
`generateUndo` is `false`. The first-pass loop (line 866) skips
`blockUndo.TxUndos = append(...)`. The block-persist path (line 994,
1015, 1053) writes the chainstate WITHOUT a corresponding
`WriteBlockUndoBatch`. The header-index `MarkUndoStored` call at line
961-963 is gated on `generateUndo` and therefore skipped — so
`StatusHaveUndo` is never set on the BlockNode.

**Consequences when a reorg ever targets a height in the assume-valid
range:** `DisconnectBlock` at chainmanager.go:1402 calls
`cm.chainDB.ReadBlockUndo(hash)` which returns "not found", and the
disconnect fails with `"failed to read undo data for block ..."`. The
reorg aborts mid-way, leaving the chain at a partial state. Combined
with `MaxReorgDepth=100` (W148 BUG-5), the practical effect is: ANY
reorg crossing the assume-valid boundary is impossible.

**File:** `internal/consensus/chainmanager.go:556` (`generateUndo`
derivation), 866 (undo append gated), 961-963 (MarkUndoStored gated),
1402-1405 (DisconnectBlock requires undo data).

**Core ref:** `bitcoin-core/src/validation.cpp:2280-2310`
(`fScriptChecks` gate isolates ONLY the script check; undo generation
runs unconditionally in the same `ConnectBlock`).

**Excerpt (blockbrew, scope creep)**
```go
// Track total fees and undo data.
// Skip undo data generation during assume-valid IBD for performance.
var totalFees int64
generateUndo := !skipScripts || !cm.isIBD   // <-- COMMENT ADMITS THE BUG
var blockUndo *storage.BlockUndo
if generateUndo {
    blockUndo = &storage.BlockUndo{
        TxUndos: make([]storage.TxUndo, 0, len(block.Transactions)-1),
    }
}
```

The inline comment "Skip undo data generation during assume-valid IBD
for performance" is a **comment-as-confession** (fleet pattern, 6th
distinct instance) — it admits the scope was widened beyond Core's.

**Impact:**
- Reorgs across the assume-valid boundary are impossible — they fail
  with "failed to read undo data". On mainnet with the default
  assumeValidHash at height 938343, ANY reorg from height >938343
  down to <938343 fails.
- `getchaintips` cannot accurately report a `valid-fork` for a chain
  that diverges below the assume-valid boundary (the disconnect-replay
  needed to evaluate the fork is impossible).
- Cross-cite with W148 BUG-5 (`MaxReorgDepth=100`): even short reorgs
  near the assume-valid horizon are doubly blocked.

---

## BUG-9 (P1) — `m_assumed_valid_blocks` counter not surfaced

**Severity:** P1. Core's `ChainstateManager::m_assumed_valid_blocks`
counts the number of blocks below `defaultAssumeValid` that have been
connected with `fScriptChecks=false`. The counter feeds:
- `getblockchaininfo.verificationprogress` (weighted by tx count, not
  height, so the progress bar accelerates through assume-valid
  ranges),
- `getchaintips` `status="assumed-valid"` label for the active chain
  during IBD.

blockbrew's `handleGetBlockchainInfo` (`internal/rpc/methods.go:141-160`)
computes `verificationProgress` as a simple `tipHeight /
bestHeaderHeight` ratio (line 209-216 inside `handleGetSyncState`),
with no awareness of the assume-valid horizon. No `assumed-valid`
status label is emitted by `getchaintips`.

**File:** `internal/rpc/methods.go:141-160`, `208-216`.

**Core ref:**
`bitcoin-core/src/validation.cpp::ChainstateManager::m_assumed_valid_blocks`,
`bitcoin-core/src/rpc/blockchain.cpp::getchaintips`.

**Impact:** monitoring divergence — operators tooling that scrapes
`getchaintips.status` from a hashhog fleet sees different status
labels on blockbrew vs Core for the same chain state.

---

## BUG-10 (P0-CDIV) — `UpdateIBDStatus` ignores the MinimumChainWork half of `IsTipRecent`

**Severity:** P0-CDIV. Bitcoin Core's `IsInitialBlockDownload` (or
the post-22.0 `UpdateIBDStatus` latching path) requires **BOTH**
conditions to leave IBD:
1. `chainstate.m_chain.Tip()->nChainWork >= MinimumChainWork()`
2. `chainstate.m_chain.Tip()->GetBlockTime() >= GetTime() - max_tip_age`

blockbrew's `SyncManager.updateIBDStatus` (`internal/p2p/sync.go:2599-2624`)
tests **only** condition (2):

```go
tipTime := time.Unix(int64(tipNode.Header.Timestamp), 0)
if time.Since(tipTime) <= MaxTipAge {
    // Tip is recent enough — latch IBD to false.
    if sm.ibdActive.CompareAndSwap(true, false) {
        ...
    }
}
```

There is no `tipNode.TotalWork.Cmp(sm.chainParams.MinimumChainWork) >= 0`
check. A peer that feeds us a low-work fork with a recent timestamp
(easily forgeable for testnet/signet, requires real PoW for mainnet
but the gate is meant as defense-in-depth) would cause blockbrew to
prematurely report `IBD=false` via `getblockchaininfo`. Tools that
make eligibility decisions based on IBD-state (e.g., wallets that
delay accepting payments until IBD ends) would act on a low-work
chain.

**File:** `internal/p2p/sync.go:2599-2624`.

**Core ref:** `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291`
(`UpdateIBDStatus` joint MinimumChainWork + IsTipRecent gate).

**Excerpt (blockbrew, missing half)**
```go
func (sm *SyncManager) updateIBDStatus() {
    // Fast path: already left IBD — never flip back.
    if !sm.ibdActive.Load() {
        return
    }
    // ... fetch tipNode ...
    tipTime := time.Unix(int64(tipNode.Header.Timestamp), 0)
    if time.Since(tipTime) <= MaxTipAge {
        // MISSING: tipNode.TotalWork.Cmp(sm.chainParams.MinimumChainWork) < 0 → return
        if sm.ibdActive.CompareAndSwap(true, false) { ... }
    }
}
```

**Impact:** premature IBD exit on low-work-but-recent chains;
defense-in-depth gap on testnet/signet; benign-but-incorrect on
mainnet (Core's belt-and-suspenders rationale).

---

## BUG-11 (P0-CDIV) — Two `isIBD` flags coexist with divergent semantics

**Severity:** P0-CDIV ("two-pipeline guard 16th distinct extension"
this would be — first time the IBD STATE itself is doubled across
subsystems within one impl). blockbrew has TWO separate IBD flags:

1. **`SyncManager.ibdActive`** (`atomic.Bool`, declared sync.go:200-210)
   — gated on `tip-age <= MaxTipAge` (BUG-10 above), drives the
   `getblockchaininfo.initial_block_download` JSON field and various
   P2P gates (sync.go:761 etc.).

2. **`ChainManager.isIBD`** (plain `bool` under `cm.mu`, declared
   chainmanager.go:77, init at line 250) — gated on
   `cm.tipHeight == cm.assumeValidHeight` (chainmanager.go:966-967),
   drives `generateUndo` (BUG-8), the side-branch reject path
   (chainmanager.go:500), and the chainstate-flush cadence
   (line 1002-1015).

These two flags transition independently:
- `SyncManager.ibdActive` flips when wall-clock catches up to the
  tip timestamp (typical IBD finish point).
- `ChainManager.isIBD` flips only when `tipHeight ==
  assumeValidHeight` is **exactly** met. If the chain extends past
  assumeValidHeight before the gate ever fires (it's an `==` not a
  `>=`!), or if assume-valid hash never resolves (regtest, testnet3,
  signet — see BUG-6/BUG-7), the gate fires **never** and
  `ChainManager.isIBD` stays `true` forever.

**Failure modes:**
- Regtest: `assumeValidHash.IsZero()` so `cm.assumeValidHeight = 0`.
  `cm.isIBD` is true at startup. The gate `cm.tipHeight ==
  cm.assumeValidHeight` becomes `cm.tipHeight == 0` — true ONLY at
  the genesis tip, false after the first block. Once the gate fires
  at tipHeight=0 (which it does on the first ConnectBlock that
  arrives at height 1, AFTER the tip update at line 947 makes
  tipHeight=1 but BEFORE line 966 — actually NO, line 966 fires
  WITH `cm.tipHeight == 1` at that point so it never fires on
  regtest at all). **`cm.isIBD` stays `true` for the life of the
  process on regtest**, and BUG-8's `generateUndo := !skipScripts
  || !cm.isIBD` still resolves to `true` because skipScripts is
  also false on regtest. So regtest behavior accidentally works,
  but the `if cm.isIBD` gate at line 500 means **regtest rejects
  EVERY non-tip-extending block at all heights** (no side-branches,
  no reorg blocks).
- Mainnet, post-assume-valid sync: a node already past height
  938343 that restarts will have `tipHeight=950000` and resolve
  `assumeValidHeight=938343`. `tipHeight == assumeValidHeight`
  is FALSE forever. `cm.isIBD` stays `true`. Side-branches via
  P2P during regular operation are then **rejected with `"block
  does not connect to tip during IBD"`** (chainmanager.go:500-503).
- Mainnet, fresh IBD that overshoots assumeValidHeight in one
  ConnectBlock call: the gate at line 966 uses `==` not `>=`, so
  if a batch lands the post-assumeValid block first, the gate
  never fires.

Compounding this: line 524 derives `skipScripts := cm.assumeValidHeight
> 0 && node.Height <= cm.assumeValidHeight` — uses `<=`, the correct
form for the script-skip optimisation, but the IBD-exit gate at line
966 uses `==`. Two adjacent gates on the same field disagree on the
comparator.

**File:** `internal/consensus/chainmanager.go:77, 250, 500, 966-967`;
`internal/p2p/sync.go:200-210, 2599-2624`.

**Core ref:** `bitcoin-core/src/validation.cpp` —
`ChainstateManager::m_cached_is_ibd` is the ONE flag, latched once,
used everywhere.

**Excerpt (blockbrew, gate comparator mismatch)**
```go
// chainmanager.go:524 — uses <= (correct for script-skip)
skipScripts := cm.assumeValidHeight > 0 && node.Height <= cm.assumeValidHeight

// chainmanager.go:966 — uses == (WRONG, fires only on the exact assumeValid block)
if cm.isIBD && cm.tipHeight == cm.assumeValidHeight {
    cm.isIBD = false
    ...
}
```

**Impact:**
- Restart-after-sync on mainnet: side-branches rejected with stale
  IBD message; getblockchaininfo correctly says IBD=false (driven by
  the OTHER flag in sync.go) but the chain manager refuses to accept
  the same blocks the sync layer is processing.
- Regtest: side-branch acceptance permanently broken (cm.isIBD never
  flips → line 500 always rejects).
- `==` vs `>=`: skip-once IBD-exit gate misses if the connect that
  would tip-height==assumeValidHeight is part of a batch that lands
  the next block before the check.

---

## BUG-12 (P0) — Reorg `GetBlock` failure on pruned chain treated as fatal error, not "need to redownload"

**Severity:** P0. `ReorgTo` at `chainmanager.go:1701-1708` resolves
each connect-list block via `cm.chainDB.GetBlock(node.Hash)`. On a
prune-mode node, blocks older than `tip - MIN_BLOCKS_TO_KEEP=288` may
have been unlinked. A reorg request to a side branch whose body was
pruned will fail with `"block %s not found for reorg: %w"` and bubble
the error up; the chain stays at the old tip.

Core handles this case via `BLOCK_HAVE_DATA` filtering in
`FindMostWorkChain` (`validation.cpp:3114-3171`) — pruned candidates
are filtered out at selection time, so `ActivateBestChain` never
selects them. blockbrew's `recalculateBestTipLocked` filter
(headerindex.go:751-760) uses `StatusDataStored`, but BUG-1 above
shows that flag is never cleared on prune — so pruned blocks pass
the filter, get selected as best-tip candidates, and the reorg fails
at GetBlock time instead of at candidate-selection time.

**File:** `internal/consensus/chainmanager.go:1701-1708`.

**Core ref:** `bitcoin-core/src/validation.cpp:3114-3171`
(`FindMostWorkChain` filters on `BLOCK_HAVE_DATA`).

**Impact:** prune+reorg interaction is broken (cross-cite BUG-1).
Operators running prune mode see opaque "block not found for reorg"
errors after honest reorgs that Core handles transparently.

---

## BUG-13 (P1) — `MinBlocksToKeep=288` is hard-coded; not params-aware

**Severity:** P1. Bitcoin Core's `MIN_BLOCKS_TO_KEEP` is also `288`
(`validation.h:75-76`), and Core also hard-codes it. The constant is
indirectly tied to the cmpct-block depth window (BIP-152's
`MAX_BLOCKTXN_DEPTH`). However, Core exposes
`-blockreconstructionextratxn` and other tuneables for testing; the
fleet pattern observed in W138 etc. is that hard-coding without an
override hook makes regtest scenarios hard to construct.

blockbrew's `storage.MinBlocksToKeep = 288` (`prune.go:21`) is
imported in two places (`prune.go:387-392, main.go:741`). Regtest
tests that want to exercise prune behaviour have to manipulate at
least 288 tip blocks to get a single file pruned — coarsely.

**File:** `internal/storage/prune.go:21`.

**Impact:** test ergonomics; no consensus risk. Listed for fleet
pattern continuity (consensus.go-pattern, params-aware constants).

---

## BUG-14 (P1) — Auto-prune fires from `OnBlockConnected`; no time-based or batched trigger

**Severity:** P1. Core's `ChainstateManager::ActivateBestChainStep`
calls `FlushStateToDisk(FlushStateMode::IF_NEEDED)` which has internal
heuristics: prune fires at most every X seconds or after Y blocks,
batched. blockbrew's auto-prune (`main.go:1080` per the file index)
fires `MaybePrune` from `OnBlockConnected` — i.e., on **every**
connected block (post-IBD; during IBD the hook is also wired).
`CalculateCurrentUsage` is O(numFiles) and `MaybePrune`'s short-circuit
at `prune.go:273-280` is cheap, but the per-block hook means we run
the O(numFiles) sum on every connect just to discover we're not over
target.

This is correctness-neutral but does scale poorly past ~10k blockfiles
(~1.2 TB). Not a blocker, but worth flagging.

**File:** `internal/storage/prune.go:225-281`; `cmd/blockbrew/main.go:1080`
(per file grep: `OnBlockConnected` hook).

**Core ref:** `bitcoin-core/src/validation.cpp::FlushStateToDisk`
heuristics + `nLastBlockFile` cache.

**Impact:** O(numFiles) cost on every connected block; mild perf
regression at archive scale, no consensus impact.

---

## BUG-15 (P1) — `lastSafeHeight` uses `int32` arithmetic — would wrap on chain longer than 2.1B blocks

**Severity:** P1 (cosmetic / type-tightness; theoretical). `prune.go:387-392`
computes `tipHeight - MinBlocksToKeep` in `int32`. If `tipHeight`
ever overflowed (it cannot in practice on Bitcoin), the subtraction
would wrap. The guard `tipHeight <= MinBlocksToKeep` correctly
short-circuits the boundary case.

This is **also** a companion to the W132 `MsgTx.Version int32-vs-uint32`
finding flagged in the priority queue — the broader pattern in
blockbrew is that height values are mixed `int32` (consensus / prune)
vs `uint32` (BlockFileInfo `HeightFirst`/`HeightLast` are unsigned per
`prune.go:317, 328`). The conversions `int32(fi.HeightLast)` at line
317 / 328 silently truncate the sign bit if a hypothetical
`HeightLast > 0x7FFFFFFF` ever arose, which would never happen on
mainnet but is a fleet typing-inconsistency worth recording.

**File:** `internal/storage/prune.go:317, 328, 387-392`.

**Impact:** theoretical only; consistency / type-tightness gap.

---

## BUG-16 (P1) — `chaincfg.go` MinimumChainWork uses pointer-shared `*big.Int` across all nodes

**Severity:** P1. The mainnet/testnet3/testnet4/signet `MinimumChainWork`
field is a `*big.Int` (`chaincfg.go:64-70`). The construction at line
204-208 (and equivalents) returns the pointer from a once-initialised
closure. Any caller that does `params.MinimumChainWork.Add(...)` would
mutate the shared global. Grep shows no such mutator today, but the
type contract leaks — Core's `uint256` is value-typed for exactly this
reason. A future refactor that subtracted "remaining work to MinChainWork"
and stored the result back risks silent global corruption.

**File:** `internal/consensus/chaincfg.go:64-70, 204-208, 290-294, 354,
418-422, 496-500`.

**Core ref:** `bitcoin-core/src/consensus/params.h::nMinimumChainWork`
(value-typed `uint256`).

**Impact:** API contract leakage; no current consumer corrupts the
value, but the type doesn't prevent it.

---

## BUG-17 (P1) — `havePruned` is dead-data plumbing (consumer absent)

**Severity:** P1 ("dead-data plumbing" fleet pattern, ~9th distinct
blockbrew instance per W138/W140 tracking). `Pruner.HavePruned()`
(`prune.go:115-120`) returns the in-memory atomic. A grep over
`internal/`, `cmd/` shows **zero call sites** for the method. The
flag is set inside `MaybePrune` (line 370) but never consulted:
- `getblockchaininfo` uses `s.pruner.IsEnabled()` (not HavePruned)
  to decide whether to emit `pruned=true`,
- the operator-knob check `WritePruneFlag → m_have_pruned` from Core
  has no analogue,
- the "refuse to disable pruning" check has no analogue.

The field is the inverse of BUG-2 (which observes the value isn't
persisted). Together: the persistence gap is moot because the
in-memory value is never read either.

**File:** `internal/storage/prune.go:94, 115-120, 370`.

**Impact:** classic dead-data plumbing. Cleanup candidate.

---

## BUG-18 (P0-CDIV) — Pruner does NOT call `Flush` before unlinking; raw `os.Remove` may race against in-flight `WriteBlock`

**Severity:** P0-CDIV. Bitcoin Core's `FindFilesToPrune` is called by
`FlushStateToDisk` AFTER the chainstate batch has been committed and
the block-file write streams have been synced. `PruneOneBlockFile`
runs under the same `cs_main` window as the chainstate commit, so no
concurrent `WriteBlock` can target the file being pruned.

blockbrew's `MaybePrune` (`prune.go:242-382`) is invoked from
`OnBlockConnected`. It holds `p.mu` (the prune serialiser) but does
NOT hold the BlockStore's `bs.mu`. The check at line 310 (skip
`currentFileNum`) protects against the most common race, but:
- `UnlinkPrunedFile` (line 197-222) only takes `bs.mu.RLock()` briefly
  to read the filename strings — it does not hold the lock across the
  `os.Remove` calls,
- a concurrent block-write could (in principle) be rotating to a new
  fileNum during the prune sweep,
- there is no fdatasync between "BlockStore wrote the file" and
  "Pruner unlinks the file" — a kernel that hadn't flushed the
  writeback would lose the unlink-recoverable data.

The risk is small in practice (most file ops are sequential on a
single goroutine), but the lock structure is weaker than Core's
single-cs_main discipline, and there is no `FlushBlockFile` /
`PruneAndFlush` analogue that fences the unlink against pending
writes.

**File:** `internal/storage/prune.go:197-223, 242-382`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::FlushBlockFile`,
`PruneAndFlush`.

**Impact:** rare race window; on a high-throughput auto-prune mainnet
node, a block-write that begins between the `CurrentFile()` read at
line 292 and the `os.Remove` at line 216-221 could write into a
file that is then unlinked seconds later. Modern fs handles
unlinked-open-fd fine, but the on-disk state is briefly inconsistent
with the in-memory `BlockStore.fileInfo`.

---

## BUG-19 (P1) — Pruning sweep loses orphan-side-branch blocks (no GetAllBlockHashesAtHeight)

**Severity:** P1. `MaybePrune` at line 328-335 does:

```go
for h := int32(fi.HeightFirst); h <= int32(fi.HeightLast); h++ {
    hash, err := p.chainDB.GetBlockHashByHeight(h)
    if err != nil {
        continue
    }
    _ = p.bs.DeleteBlockIndex(hash)
    _ = p.bs.DeleteUndoIndex(hash)
}
```

`GetBlockHashByHeight` returns the **canonical** (active-chain) hash
at height `h`. Side-branch blocks at the same height that were written
into the same blk*.dat file have separate hashes; their `B`-prefix
position-index entries are NEVER deleted. After the unlink at
line 343, those side-branch blocks' position entries point at a
non-existent file — calls to `GetBlock(sideBranchHash)` return
`os.ErrNotExist`, the error propagates as "block not found", and
the side-branch is effectively bricked without being cleaned up.

Core walks the **block index** (which has both branches), not the
height index, precisely to handle this. blockbrew's height-walk skips
the side-branch position rows.

**File:** `internal/storage/prune.go:328-335`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::PruneOneBlockFile`
(walks `m_block_index` not `m_chain`).

**Impact:** orphan position rows persist forever in Pebble; cumulative
storage waste; `GetBlock` on a known-pruned side-branch hash returns
a different error than the canonical-chain pruned-hash path.

---

## BUG-20 (P1) — Manual-mode log line directs operator at non-existent RPC

**Severity:** P1 ("comment-as-confession" / "log-as-confession", 7th
distinct fleet instance). `cmd/blockbrew/main.go:736` logs:

```go
log.Printf("Pruning enabled: manual mode (-prune=1); auto-prune off, pruneblockchain RPC required")
```

This is the only operator-visible signal that `-prune=1` mode is
active. It explicitly tells the operator to use `pruneblockchain`. As
BUG-3 establishes, this RPC does not exist. The log message ships
operators into a tooling dead-end.

**File:** `cmd/blockbrew/main.go:736`.

**Impact:** operator UX; cross-cite BUG-3.

---

## BUG-21 (P2) — `BlockchainInfo.PruneHeight` is `int32` JSON-emitted as `omitempty`; legitimate `pruneheight=0` after manual sweep to genesis would be hidden

**Severity:** P2. `internal/rpc/types.go:103`:

```go
PruneHeight int32 `json:"pruneheight,omitempty"`
```

`omitempty` on `int32` suppresses the field when the value is `0`.
Core's `getblockchaininfo` always emits `pruneheight` when `pruned=true`,
even if it equals `0` (the field is absent only when pruning is
disabled). The `omitempty` choice means a node that pruned ZERO files
so far reports differently from a node that hasn't pruned at all —
which is fine — but a node that legitimately has pruneheight=0
(unreachable in practice since prune always advances above genesis,
but the type contract leaks) would be misreported.

**File:** `internal/rpc/types.go:101-103`.

**Impact:** monitoring contract gap; cosmetic.

---

## BUG-22 (P0-CDIV) — `-reindex` flag rejected with hard error; no operator path after prune corruption

**Severity:** P0-CDIV. Bitcoin Core's `-reindex` rebuilds chainstate
from blk*.dat. This is the canonical recovery path when prune
corruption (BUG-1, BUG-12, BUG-19) leaves the chainstate inconsistent
with the on-disk blockstore. blockbrew refuses to start when `-reindex`
is set (`cmd/blockbrew/main.go:485` per the flag definition: "NOT YET
IMPLEMENTED — blockbrew refuses to start").

The honest-refusal is good UX (better than silent no-op), but combined
with BUG-1/BUG-12/BUG-19 it means **there is no operator recovery from
a corrupt prune-mode chainstate** short of `rm -rf datadir/chaindata`
and re-IBD from scratch. On a mainnet node with 6+ days of IBD, this
is a 6-day recovery window per prune-related corruption event.

**File:** `cmd/blockbrew/main.go:485`.

**Core ref:** `bitcoin-core/src/init.cpp` (`-reindex`).

**Impact:** prune-mode recoverability is one-shot ("delete everything,
re-IBD"). Not a divergence from Core's BEHAVIOUR (Core would also
rebuild from blk*.dat) but a divergence from Core's RECOVERY-TIME
guarantees.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CDIV:** 8 (BUG-1, BUG-3, BUG-5, BUG-8, BUG-10, BUG-11, BUG-18, BUG-22)
- **P0:** 1 (BUG-12)
- **P1:** 11 (BUG-2, BUG-4, BUG-6, BUG-7, BUG-9, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-19, BUG-20)
- **P2:** 1 (BUG-21)

Wait — recount P1: BUG-2, BUG-4, BUG-6, BUG-7, BUG-9, BUG-13, BUG-14,
BUG-15, BUG-16, BUG-17, BUG-19, BUG-20 = 12. Total:
8 + 1 + 12 + 1 = 22. ✓

**Fleet patterns confirmed:**
- "dead-data plumbing" (BUG-2 / BUG-17) — `havePruned` set but never read AND never persisted
- "wiring-look-but-no-wire" (BUG-3) — `-prune=1` accepted, logged, NODE_NETWORK_LIMITED advertised, but the only RPC that activates the mode is absent
- "comment-as-confession" (BUG-8 line 555 "Skip undo data generation during assume-valid IBD for performance"; BUG-20 log line at main.go:736) — 7th and 8th distinct blockbrew instances
- "assume-valid scope creep" (BUG-8) — first blockbrew instance of the W145 hotbuns pattern (drops undo data, not just signatures)
- "two-pipeline guard 16th distinct extension" (BUG-11) — first time the IBD STATE itself is doubled across subsystems within one impl
- "comparator mismatch on adjacent gates" (BUG-11 line 524 `<=` vs line 966 `==`)
- "hardcoded constant should be params-aware" (BUG-13) — `MinBlocksToKeep=288`
- "int32-vs-uint32 inconsistency" (BUG-15) — companion to W132 MsgTx.Version finding
- "no operator-knob exists" (BUG-5 `-assumevalid` absent) — symmetric to W148 BUG-6
- "operator-recovery dead-end" (BUG-22) — combined with prune corruption bugs, only path is rm -rf

**Top three findings:**
1. **BUG-8 (P0-CDIV assume-valid scope creep)** — `generateUndo := !skipScripts || !cm.isIBD`
   drops undo-data generation for assume-valid IBD blocks. ANY reorg
   crossing the assume-valid horizon (height 938343 on mainnet) is
   then impossible because DisconnectBlock cannot find the undo data.
   First blockbrew instance of the fleet-wide W145 scope-creep
   pattern (hotbuns W145 BUG-2..6 cluster).
2. **BUG-3 (P0-CDIV pruneblockchain RPC absent)** — `-prune=1` manual
   mode is functionally dead because the only RPC that drives a sweep
   is missing from the dispatch table. Operator log line directs at
   non-existent RPC. Datadir grows unbounded in manual mode.
3. **BUG-1 + BUG-11 + BUG-12 cluster (prune-and-reorg interaction)** —
   prune deletes position-index rows but never clears `StatusDataStored`
   on the BlockNode (BUG-1); recalculateBestTipLocked selects pruned
   candidates (BUG-11); ReorgTo's GetBlock then fails with "block not
   found for reorg" (BUG-12). Three bugs forming one architectural
   gap: there is no `MarkPruned`/`ClearDataStored` API.
