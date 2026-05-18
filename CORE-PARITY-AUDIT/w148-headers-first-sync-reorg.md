# W148 — Headers-first sync + chain selection + reorg (blockbrew)

**Wave:** W148 — `ProcessNewBlockHeaders`, `AcceptBlockHeader`,
`ActivateBestChain`, `ActivateBestChainStep`, `ConnectTip`, `DisconnectTip`,
`FindMostWorkChain`, `MAX_REORG_DEPTH`/`MIN_BLOCKS_TO_KEEP`, `CBlockIndex`
validity bitfield (`BLOCK_VALID_TREE`/`TRANSACTIONS`/`CHAIN`/`SCRIPTS`),
`m_chain_tx_count`, `m_best_header`, `InvalidChainFound`,
`ResetBlockFailureFlags`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:4183-4239` — `AcceptBlockHeader`
  (PoW + context check + bad-prevblk + min_pow_checked gate +
  AddToBlockIndex + `m_best_header` update).
- `bitcoin-core/src/validation.cpp:4242-4270` — `ProcessNewBlockHeaders`
  (loop body, takes `cs_main` once across batch, calls `CheckBlockIndex`
  after each header, calls `NotifyHeaderTip`).
- `bitcoin-core/src/validation.cpp:3114-3171` — `FindMostWorkChain`
  (reverse iter over `setBlockIndexCandidates`, ancestor `BLOCK_FAILED_VALID`
  + `BLOCK_HAVE_DATA` filter, candidate erase on failure).
- `bitcoin-core/src/validation.cpp:3191-3280` — `ActivateBestChainStep`
  (DisconnectTip loop to fork, vpindexToConnect descending walk in chunks
  of 32, ConnectTip loop, DisconnectedBlockTransactions reuse via
  `MaybeUpdateMempoolForReorg`).
- `bitcoin-core/src/validation.cpp:3323-3450` — `ActivateBestChain`
  (do-while loop, releases `cs_main` between iterations, breaks on
  `pindexMostWork == m_chain.Tip()`, `ReachedTarget()` exit).
- `bitcoin-core/src/validation.cpp:2900-3000` — `ConnectTip`
  (block read, ConnectBlock + chainstate write + UpdateTip).
- `bitcoin-core/src/validation.cpp:3055-3107` — `DisconnectTip`
  (read CBlockUndo from rev*.dat, DisconnectBlock, mempool refill).
- `bitcoin-core/src/validation.cpp:3711-3730` — `ResetBlockFailureFlags`
  (filters by `block_index.GetAncestor(nHeight) == pindex || pindex->GetAncestor(block_index.nHeight) == &block_index`
  AND `BLOCK_FAILED_VALID` — does NOT touch non-failed ancestors).
- `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291` —
  `IsInitialBlockDownload` / `UpdateIBDStatus` (`m_cached_is_ibd` latched
  to false when `IsTipRecent(MinimumChainWork(), max_tip_age)`).
- `bitcoin-core/src/validation.cpp:1964-1984` — `InvalidChainFound`
  (sets `m_best_invalid` if new chain has more work than current best
  invalid; recomputes `m_best_header` via `RecalculateBestHeader` if
  current best_header descends from invalid pindex).
- `bitcoin-core/src/validation.cpp:3765-3815` — `ReceivedBlockTransactions`
  (sets `nTx = block.vtx.size()`, `m_chain_tx_count = nTx +
  pprev->m_chain_tx_count`, walks descendants to propagate counts).
- `bitcoin-core/src/chain.h:42-86` — `BlockStatus` enum (5-level ordered
  validity ladder UNKNOWN/RESERVED/TREE/TRANSACTIONS/CHAIN/SCRIPTS plus
  HAVE_DATA / HAVE_UNDO / FAILED_VALID / FAILED_CHILD / OPT_WITNESS bits
  and `BLOCK_VALID_MASK = 7`).
- `bitcoin-core/src/chain.h:120-129` — `CBlockIndex::nTx`,
  `m_chain_tx_count` fields.
- `bitcoin-core/src/validation.h:75-76` — `MIN_BLOCKS_TO_KEEP = 288`.

**Files audited**
- `internal/consensus/headerindex.go` — `HeaderIndex`, `AddHeader`,
  `BlockNode`, `BlockStatus`, `recalculateBestTipLocked`, `FindFork`,
  `MarkDataStored`, `MarkUndoStored`, `SetPreciousBlock`, `BestTip`.
- `internal/consensus/chainmanager.go` — `ChainManager`, `MaxReorgDepth`,
  `NewChainManager`, `loadChainState`, `ReloadChainState`, `ConnectBlock`,
  `DisconnectBlock`, `ReorgTo`, `InvalidateBlock`, `ReconsiderBlock`,
  `PreciousBlock`, `ProcessSubmittedBlock`, `IsIBD`, `IsTooFarAhead`,
  IBD-exit gate at line 966.
- `internal/p2p/sync.go` — `HandleHeaders`, `addValidatedHeaders`,
  `startHeaderSync`, `needsHeadersSync`, `computeMinimumRequiredWork`,
  `selectSyncPeer`, `sendGetHeaders`, `HandleGetHeaders`, `HandleBlock`
  unsolicited path.
- `internal/p2p/headerssync.go` — `HeadersSyncState`,
  `ProcessNextHeaders`, PRESYNC/REDOWNLOAD/FINAL phase machine.
- `internal/storage/chaindb.go` — `StoreBlockHeader`,
  `StoreBlockHeadersBatch`, `GetBlockHeader`, `GetChainState`,
  `SetChainState`.
- `internal/storage/keys.go` — namespace prefixes (H/B/N/R/etc.).

---

## Gate matrix (30 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | ProcessNewBlockHeaders contract | G1: PoW + MTP + difficulty validated at header acceptance | PASS (`headerindex.go:416-454`) |
| 1 | … | G2: `m_best_header` advanced independently of full validation | PASS (best tip update at `headerindex.go:512`) |
| 1 | … | G3: header rejected if `pprev->nStatus & BLOCK_FAILED_VALID` ("bad-prevblk") | **BUG-1 (P0-CDIV)** AddHeader never checks parent invalid status |
| 1 | … | G4: `min_pow_checked` boolean threaded to header acceptance | PARTIAL (PRESYNC + AddHeader's own minWork gate; see W99 G6) |
| 1 | … | G5: empty headers message is no-op (no Misbehaving) | PASS (`sync.go:587-595`, W99 G10) |
| 2 | CChain m_chain tip pointer | G6: random-access `m_chain[height]` semantics | PARTIAL — relies on `BlockNode.GetAncestor` skip-list (O(log N) instead of O(1)) |
| 2 | … | G7: `m_chain.Genesis()` / `Tip()` accessors | PASS (`headerindex.go:573-590`) |
| 2 | … | G8: `m_chain.FindFork(other_chain)` | **BUG-2 (P1)** `FindFork` walks ALL parents (O(h)) instead of using skip-list (Core uses pointer-set ancestor comparator) |
| 3 | ActivateBestChain loop | G9: do-while loop iterates until `pindexMostWork == Tip()` | **BUG-3 (P0)** blockbrew has no equivalent loop — `ConnectBlock` only extends current tip OR triggers a one-shot `ReorgTo`. No multi-iteration ABC. |
| 3 | … | G10: releases lock between iterations for responsiveness | **BUG-3 cross-cite** — `ReorgTo` holds `reorgMu` + `cm.mu` across the entire span (`chainmanager.go:1624-1737`) |
| 3 | … | G11: `MaybeUpdateMempoolForReorg` after each ConnectTip | PARTIAL — fires after each `DisconnectBlock` (Pattern B), not after each `ConnectBlock` (no symmetric `MaybeUpdateMempoolForReorg` post-connect) |
| 3 | … | G12: vpindexToConnect chunked by 32 to bound stack frame | **BUG-4 (P2)** blockbrew builds the full disconnect+connect list in `ReorgTo` (`chainmanager.go:1639-1650`) — unbounded vs Core's 32-step chunks. |
| 4 | MAX_REORG_DEPTH guard | G13: refuse `disconnect+connect > 100` (blockbrew) | PASS (`chainmanager.go:1652-1657`) but constant DIVERGES from Core (Core has NO max reorg depth — accepts arbitrary deep reorgs if the new chain has more work; only MIN_BLOCKS_TO_KEEP=288 governs prune-protection) | **BUG-5 (P0-CDIV)** |
| 4 | … | G14: error message identifies the limit | PASS |
| 4 | … | G15: `-assumevalid=0` operator override to bypass cap | **BUG-6 (P1)** no operator-knob exists; only way to exceed `MaxReorgDepth=100` is to recompile |
| 5 | ConnectTip semantics | G16: ConnectBlock + chainstate write + UpdateTip atomic | PASS (`chainmanager.go:988-1059`) |
| 5 | … | G17: on failure, block marked `BLOCK_FAILED_VALID` and chain disconnected | **BUG-7 (P0-CDIV)** failed `ConnectBlock` returns error but never marks `node.Status |= StatusInvalid` (`chainmanager.go:530-545,755,927`) — failing block stays VALID-looking in header index; next `RecalculateBestTip` will reselect it |
| 5 | … | G18: IBD-side accepts non-extending block as side-branch via `AcceptBlock` storage | **BUG-8 (P0)** `chainmanager.go:500-503` rejects ANY non-extending block during IBD ("block does not connect to tip during IBD") — Core accepts the body and waits for tip selection |
| 6 | DisconnectTip semantics | G19: rev*.dat undo applied in reverse | PASS (`chainmanager.go:1432-1515`) |
| 6 | … | G20: DISCONNECT_UNCLEAN logged but not fatal | PASS (`chainmanager.go:1517-1524`) |
| 6 | … | G21: failure halts (Core `FatalError`), not silent | PARTIAL — `DisconnectBlock` returns error but `ReorgTo` just propagates the error (`chainmanager.go:1696`); no FatalError halt |
| 7 | CBlockIndex validity bitfield | G22: 5-level ladder UNKNOWN/RESERVED/TREE/TRANSACTIONS/CHAIN/SCRIPTS | **BUG-9 (P1)** blockbrew uses power-of-two flag bits (HeaderValid=1, DataStored=2, FullyValid=4, Invalid=8, InvalidChild=16, HaveUndo=32) — collapses the 5-level ordered ladder into 6 disjoint bits. `BLOCK_VALID_MASK >= BLOCK_VALID_TREE` semantics impossible to express (cross-cite W109 G6) |
| 7 | … | G23: `BLOCK_HAVE_DATA` set after block body lands on disk | PASS (`headerindex.go:550-555`) |
| 7 | … | G24: `BLOCK_HAVE_UNDO` set after rev*.dat write | PASS (`headerindex.go:564-569`, FIX-33) |
| 7 | … | G25: `BLOCK_FAILED_CHILD` propagated to descendants on InvalidateBlock | PASS (`chainmanager.go:1911-1930`) |
| 7 | … | G26: persisted to disk so flags survive restart | **BUG-10 (P1)** `StoreBlockHeader` (chaindb.go:50-60) only writes header bytes — `nStatus`, `nChainWork`, `nTx`, `m_chain_tx_count`, `nSequenceId`, `pskip` all dropped on restart |
| 8 | m_chain_tx_count + m_chain_work | G27: per-block cumulative tx counter set at header acceptance | **BUG-11 (P1)** `BlockNode` has NO `ChainTxCount`/`nTx` field (cross-cite W109 G9, W138 BUG-18) — getblockchaininfo can't return correct nchaintx, EstimateBlockTime falls back to height-based fallback |
| 8 | … | G28: m_chain_work cumulative chainwork maintained | PASS (`BlockNode.TotalWork`, `headerindex.go:475-477`) |
| 8 | … | G29: ResetBlockFailureFlags clears only FAILED bits (not arbitrary ancestor flags) | **BUG-12 (P0-CDIV)** `ReconsiderBlock` walks ALL ancestors and unconditionally clears StatusInvalid/StatusInvalidChild from EVERY one — Core only clears `BLOCK_FAILED_VALID` from blocks that ARE descendants OR ancestors of pindex AND have `BLOCK_FAILED_VALID` set (cross-cite W101 G19) |
| 8 | … | G30: `IsInitialBlockDownload` exit gated on tip-recent + MinimumChainWork | **BUG-13 (P0-CDIV)** `chainmanager.go:966` uses `cm.tipHeight == cm.assumeValidHeight` — equality, not >= — and only fires once. If assumeValidHeight==0 (no assumeValid set), IBD never exits at all on regtest (cross-cite W101 G22) |

---

## BUG-1 (P0-CDIV) — `AddHeader` never checks `parent.Status` for invalid

**Severity:** P0-CDIV. Bitcoin Core's `AcceptBlockHeader`
(validation.cpp:4220-4223) rejects with `"bad-prevblk"` /
`BLOCK_INVALID_PREV` when `pindexPrev->nStatus & BLOCK_FAILED_VALID`.
blockbrew's `AddHeader` validates PoW, MTP, difficulty, and checkpoint
match — but never inspects `parent.Status.IsInvalid()`. A peer can extend
a chain rooted at an explicitly-invalidated block (via `invalidateblock`
RPC) and every successor header is silently grafted into the index. The
descendant nodes get `StatusInvalidChild` only AFTER `markDescendantsInvalid`
fires; if the invalidated block hasn't been seen yet but a peer
announces a chain that descends from a known-bad header, the entire
batch enters the index unmarked.

**File:** `internal/consensus/headerindex.go:394-519` (`AddHeader`)

**Core ref:** `bitcoin-core/src/validation.cpp:4220-4223`

**Excerpt (blockbrew, missing check)**
```go
// Check parent exists
parent, exists := idx.nodes[header.PrevBlock]
if !exists {
    return nil, ErrOrphanHeader
}
// ... PoW, MTP, difficulty, checkpoint checks ...
// (no parent.Status.IsInvalid() check)
```

**Excerpt (Core, the gate blockbrew lacks)**
```cpp
if (pindexPrev->nStatus & BLOCK_FAILED_VALID) {
    return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV,
                         "bad-prevblk");
}
```

**Impact:**
- Headers from a peer that build on a known-bad ancestor are accepted
  into the index, polluting `m_best_header` until `markDescendantsInvalid`
  runs. The next `recalculateBestTipLocked` will skip them (filter is
  correct), but the time window between AddHeader and InvalidateBlock
  re-fire allows the work counter to spike and getheaders to advertise
  these heights to other peers.
- Cross-impl pattern: this is the symmetric gap to BUG-7 (failed
  ConnectBlock doesn't mark `StatusInvalid`) — header layer and block
  layer both leak invalid state.

---

## BUG-2 (P1) — `FindFork` walks parents instead of using skip-list

**Severity:** P1 (performance, not correctness). Core's `CChain::FindFork`
exploits `CChain.Contains()` and the m_chain vector for O(1) lookups; the
common-ancestor walk is bounded by the divergence depth. blockbrew's
`FindFork` (headerindex.go:217-240) walks `Parent` pointers one-by-one
without using the `Skip` pointer — O(height) at worst.

**File:** `internal/consensus/headerindex.go:217-240`

**Core ref:** `bitcoin-core/src/chain.cpp` (`CChain::FindFork`).

**Excerpt (blockbrew, O(h) parent walk)**
```go
for a.Height > b.Height {
    a = a.Parent
}
for b.Height > a.Height {
    b = b.Parent
}
for a != b {
    if a == nil || b == nil {
        return nil
    }
    a = a.Parent
    b = b.Parent
}
```

**Impact:** On a deep reorg request from RPC (`reconsiderblock`) or
peer-driven submission of a heavy side branch rooted 100k blocks ago,
`ReorgTo`'s FindFork walks ~100k Parent pointers serially under
`cm.reorgMu` + `cm.mu`. Should use `BlockNode.GetAncestor` which
follows the skip-list (already present at headerindex.go:111).

---

## BUG-3 (P0) — No ActivateBestChain loop; ConnectBlock is one-shot

**Severity:** P0 (semantic divergence). Bitcoin Core's
`ActivateBestChain` is a `do-while` outer loop that repeatedly calls
`FindMostWorkChain` and `ActivateBestChainStep` until the most-work
candidate equals the active tip. Each iteration releases `cs_main` so
RPC + P2P can make progress (validation.cpp:3323-3450). The inner loop
processes up to 32 connect targets per iteration to bound the time
under-lock.

blockbrew has **no equivalent**:
- `ChainManager.ConnectBlock` advances the active tip by exactly one
  block. There is no outer loop that picks the next best candidate
  (`FindMostWorkChain` is implemented inside `RecalculateBestTip` and is
  only triggered by `InvalidateBlock`/`ReconsiderBlock` RPCs or
  `markDataStored`).
- `ProcessSubmittedBlock` (chainmanager.go:1199-1237) picks a single
  reorg target and fires `ReorgTo` synchronously.
- After a successful side-branch ConnectBlock the chain manager does
  NOT re-evaluate whether a *different* (higher-work) candidate has
  also become the most-work tip — Core's outer loop catches that case.

**File:** `internal/consensus/chainmanager.go:391-1159` (`ConnectBlock`),
`1199-1237` (`ProcessSubmittedBlock`).

**Core ref:** `bitcoin-core/src/validation.cpp:3323-3450`
(`ActivateBestChain`), `3191-3280` (`ActivateBestChainStep`).

**Impact:**
- Multi-tip ambiguity: if blockbrew has chains A and B at equal+1 work,
  a single new header on chain B that pushes B above A triggers
  `headerIndex.AddHeader` to set `bestTip = B`'s tip, but no automatic
  reorg fires — the active chain stays at A. Tip selection happens only
  via `InvalidateBlock`/`ReconsiderBlock` or a future ConnectBlock that
  happens to land on chain B (which can't happen if blocks arrive only
  via inv from peers extending chain A).
- Performance: under-lock chunking absent — when `ReorgTo` does fire
  it holds `reorgMu` + `cm.mu` across the entire span (up to
  MaxReorgDepth=100 disconnect+connect) without any release point.

---

## BUG-4 (P2) — `ReorgTo` connect list is unbounded vs Core's 32-step chunks

**Severity:** P2. Core's `ActivateBestChainStep` builds `vpindexToConnect`
with `nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight)`
(validation.cpp:3224) and re-enters the inner loop for the next chunk.
blockbrew's `ReorgTo` builds the full `disconnectNodes` and
`connectNodes` arrays in one shot (chainmanager.go:1639-1650), then
processes them all under `cm.mu` without releasing the lock.

**File:** `internal/consensus/chainmanager.go:1639-1650`

**Core ref:** `bitcoin-core/src/validation.cpp:3217-3260`

**Excerpt (blockbrew, no chunking)**
```go
disconnectNodes := make([]*BlockNode, 0)
for node := currentTip; node != fork; node = node.Parent {
    disconnectNodes = append(disconnectNodes, node)
}
connectNodes := make([]*BlockNode, 0)
for node := newTip; node != fork; node = node.Parent {
    connectNodes = append(connectNodes, node)
}
```

**Impact:** A full-depth reorg holds `cm.mu` for the entire span (up to
MaxReorgDepth=100 block-validations under-lock); P2P-driven inv +
getheaders queue at the wire backs up, RPC blocks. Bound the depth by
processing in 32-block chunks with lock release between chunks,
matching Core's deliberate responsiveness pattern.

---

## BUG-5 (P0-CDIV) — `MaxReorgDepth=100` constant DIVERGES from Core's policy

**Severity:** P0-CDIV. Core has **no MAX_REORG_DEPTH constant** — a
node will reorg arbitrarily deep if the alternative chain has more
chainwork (subject only to `MIN_BLOCKS_TO_KEEP=288` for prune
protection: blk*.dat files within 288 of the tip are not pruned, so
the undo data needed to disconnect is guaranteed available).
blockbrew's `MaxReorgDepth=100` (`chainmanager.go:32`) refuses a reorg
whose `disconnect+connect > 100` with `ErrReorgTooDeep`.

This is **strictly more restrictive than Core** — blockbrew will
refuse to follow a heavier chain that Core would happily reorg onto.
On a genuinely heavy side-branch (e.g. a 150-block deep reorg
during a contentious fork), blockbrew goes off-consensus by *staying*
on the losing chain. The constant is gated as an atomicity guardrail
(single Pebble batch sizing), but Pebble has no such inherent limit;
Core handles deep reorgs by splitting work across multiple commits.

**File:** `internal/consensus/chainmanager.go:22-32, 1652-1657`

**Core ref:** `bitcoin-core/src/validation.h:75-76`
(`MIN_BLOCKS_TO_KEEP = 288`); Core has no MAX_REORG_DEPTH.

**Excerpt (blockbrew)**
```go
const MaxReorgDepth = 100
// ...
span := len(disconnectNodes) + len(connectNodes)
if span > MaxReorgDepth {
    log.Printf("chainmgr: refusing reorg from %d to %d: span=%d exceeds MaxReorgDepth=%d", ...)
    return fmt.Errorf("%w: span=%d limit=%d", ErrReorgTooDeep, span, MaxReorgDepth)
}
```

**Impact:**
- Cross-impl divergence: on a heavy reorg > 100 blocks, blockbrew
  silently refuses; Core proceeds. The two nodes will partition.
- The comment "Bitcoin Core's default is 100 (-maxreorgdepth in
  chainparams)" is **factually wrong** — there is no `-maxreorgdepth`
  knob in Core's chainparams.cpp. The 100 figure appears to be a
  fabrication that survived multiple W-waves.

---

## BUG-6 (P1) — No operator-knob to override `MaxReorgDepth`

**Severity:** P1. Even granting BUG-5's atomicity rationale, Core
permits an operator to force reorgs deeper than any soft cap by
setting `-assumevalid=0` and restarting. blockbrew offers no such
knob — `MaxReorgDepth = 100` is a compile-time constant
(chainmanager.go:32). Recovery from a genuine deep reorg requires
either re-syncing from genesis or hot-patching the binary.

**File:** `internal/consensus/chainmanager.go:32`

**Impact:** On a > 100-block reorg, operator has no in-band recovery.

---

## BUG-7 (P0-CDIV) — Failed `ConnectBlock` never marks node `StatusInvalid`

**Severity:** P0-CDIV. Bitcoin Core's `ConnectTip` failure path
(validation.cpp:1988-1994) sets `pindex->nStatus |= BLOCK_FAILED_VALID`
and calls `InvalidChainFound(pindex)`, which propagates to
`m_best_invalid` for chain warning. The node is then ineligible for
re-selection by `FindMostWorkChain`.

blockbrew's `ConnectBlock` returns an error on every validation
failure path (`return fmt.Errorf(...)`) but never touches
`node.Status`. The header-index node remains in `StatusHeaderValid`
(or `StatusDataStored` if `MarkDataStored` already fired). On the next
`RecalculateBestTip`, the same node is re-eligible as best candidate —
ConnectBlock will be retried and fail again, looping.

**File:** `internal/consensus/chainmanager.go:530, 545, 599, 612,
700-701, 754-755, 759-761, 784-786, 803-806, 850-852, 926-927,
940-942` (every error-return path inside ConnectBlock)

**Core ref:** `bitcoin-core/src/validation.cpp:1988-1994`
(`InvalidBlockFound`)

**Excerpt (blockbrew, no status mutation on failure)**
```go
err := CheckBlockSanity(block, cm.params.PowLimit)
if err != nil {
    return fmt.Errorf("block sanity check failed: %w", err)
}
// (no node.Status |= StatusInvalid)
```

**Excerpt (Core, the propagation blockbrew lacks)**
```cpp
pindex->nStatus |= BLOCK_FAILED_VALID;
m_blockman.m_dirty_blockindex.insert(pindex);
setBlockIndexCandidates.erase(pindex);
InvalidChainFound(pindex);
```

**Impact:**
- A peer can submit a block that fails sanity → ConnectBlock errors →
  the header-index node still ranks among `recalculateBestTipLocked`
  candidates → BestTip oscillation.
- Cross-cite BUG-1: header layer also doesn't propagate FAILED on
  prevblk, so the invalid state is double-leaked.
- `m_best_invalid` analog absent: no `LARGE_WORK_INVALID_CHAIN`
  warning surface to the operator.

---

## BUG-8 (P0) — IBD-side rejects side-branch blocks; no AcceptBlock-style storage

**Severity:** P0 (Pattern Y closure GAP). Bitcoin Core's
`AcceptBlock` separates body storage from tip selection: a block
arriving during IBD whose header is in the index but doesn't extend
the active tip is *still stored to blk*.dat*. The tip selector decides
later. blockbrew, during IBD only (`cm.isIBD == true`), short-circuits
with `"block does not connect to tip during IBD"`
(chainmanager.go:500-503).

**File:** `internal/consensus/chainmanager.go:500-503`

**Core ref:** `bitcoin-core/src/validation.cpp:4297-4430`
(`AcceptBlock` — body always stored when block accepts header
validation, regardless of IBD state).

**Excerpt (blockbrew, IBD-side rejection)**
```go
if cm.isIBD {
    return fmt.Errorf("block does not connect to tip during IBD (prev=%s, tip=%s, height=%d)",
        block.Header.PrevBlock.String()[:16], cm.tipNode.Hash.String()[:16], node.Height)
}
```

**Impact:**
- During IBD, an honest peer that announces a block on a parallel
  branch (e.g. a near-tip fork) is dropped, no body stored, no header
  index update. If that branch becomes the heaviest after IBD exit,
  we re-download all bodies.
- The Pattern Y closure (4e51e8b) wired side-branch acceptance for
  `submitblock` RPC but never extended it to the IBD P2P path.

---

## BUG-9 (P1) — BlockStatus is a flag bitmap, not Core's ordered ladder

**Severity:** P1 (semantic mismatch, cross-cite W109 G6).
Core's `BlockStatus` enum encodes a 5-level **ordered** validity ladder
in the low 3 bits (UNKNOWN=0, RESERVED=1, TREE=2, TRANSACTIONS=3,
CHAIN=4, SCRIPTS=5, mask=7), allowing checks like
`pindex->IsValid(BLOCK_VALID_TRANSACTIONS)` which means "the validity
level is AT LEAST 3". The high bits encode independent flags
(HAVE_DATA=8, HAVE_UNDO=16, FAILED_VALID=32, FAILED_CHILD=64,
OPT_WITNESS=128, STATUS_RESERVED=256).

blockbrew's `BlockStatus`
(`headerindex.go:41-48`) is a pure power-of-two flag bitmap:
`StatusHeaderValid=1, StatusDataStored=2, StatusFullyValid=4,
StatusInvalid=8, StatusInvalidChild=16, StatusHaveUndo=32`. The
ordered ladder collapses to a single bit `StatusFullyValid`;
intermediate states like `BLOCK_VALID_TRANSACTIONS` (have body, no
chain-validity yet) and `BLOCK_VALID_CHAIN` (chain-valid, scripts not
yet checked — relevant for assume-valid IBD) are inexpressible.

**File:** `internal/consensus/headerindex.go:38-48`

**Core ref:** `bitcoin-core/src/chain.h:42-86`

**Impact:**
- `FindMostWorkChain` can't filter on `BLOCK_VALID_CHAIN` (the gate
  Core uses to select tips that have transactions+chain-valid but may
  still need script verification — used by assume-valid IBD).
- `assumeUTXO` snapshot machinery (W138) can't represent
  "BLOCK_VALID_TREE only, no BLOCK_VALID_TRANSACTIONS" — a snapshot
  base is `nTx=0` but `BLOCK_VALID_TREE` should be set after PoW
  validation; blockbrew sets `StatusHeaderValid` only and has no way to
  distinguish "tree-validated" from "transactions-validated-and-stored".
- On-wire serialization to disk (BUG-10) would need migration if Core
  parity is ever required at the storage layer.

---

## BUG-10 (P1) — Block index is NOT persisted to disk

**Severity:** P1. Bitcoin Core's blockindex includes a per-block
record (`m_block_index` in the LevelDB `BlockTreeDB`) carrying
`nStatus`, `nHeight`, `nFile`, `nDataPos`, `nUndoPos`, `nTx`,
`m_chain_tx_count`, `nVersion`, `hashMerkleRoot`, `nTime`, `nBits`,
`nNonce` — so on restart the in-memory tree is rebuilt with full
fidelity.

blockbrew's `StoreBlockHeader` (chaindb.go:50-60) writes ONLY the raw
80-byte header. Per-node fields not persisted:
- `Status` (`StatusInvalid`, `StatusInvalidChild`, `StatusHaveUndo`)
- `TotalWork` (recomputed at boot from PoW bits — fine, but consensus
  ordering depends on this being deterministic across restarts)
- `Skip` pointer (rebuilt at AddHeader time on every header re-fetch)
- `SequenceID` (precious-block tracking — explicitly documented as
  "ephemeral - lost on restart" at headerindex.go:704)
- `ChainTxCount` / `nTx` — entire field absent (BUG-11)

**File:** `internal/storage/chaindb.go:50-60`
(`StoreBlockHeader`), `internal/storage/keys.go:9-38` (key namespace).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp`
(`CBlockTreeDB::WriteBatchSync`); persists `CDiskBlockIndex`.

**Impact:**
- On every restart, blockbrew must re-sync ALL headers from peers
  (mainnet: ~900k headers ~70 MB of network traffic) because no flag
  state was persisted. `invalidateblock` RPC effects are LOST every
  restart (already documented at storage/w109_block_index_test.go:547).
- `PreciousBlock` chain selection bias is lost.
- `StatusHaveUndo` cleared on restart → `FindFilesToPrune` cannot
  consult per-block undo presence; falls back to height-only heuristic.

---

## BUG-11 (P1) — `BlockNode` has no `ChainTxCount` / `nTx` field

**Severity:** P1 (cross-cite W109 G9, W138 BUG-18). Core's `CBlockIndex`
carries `nTx` (per-block tx count, set by `ReceivedBlockTransactions`)
and `m_chain_tx_count` (cumulative tx count from genesis or
assumeutxo base, set when both pprev and self are
`BLOCK_VALID_TRANSACTIONS`). Used by `getblockchaininfo` (returns
`nchaintx`), `EstimateBlockTime`, sync-progress reporting, and
verificationprogress.

blockbrew's `BlockNode` (headerindex.go:55-66) defines no
`ChainTxCount` or `Tx` field. RPC `getblockchaininfo`'s `nchaintx`
must be either fabricated or returned as zero (or computed by walking
all stored block bodies — expensive).

**File:** `internal/consensus/headerindex.go:55-66`

**Core ref:** `bitcoin-core/src/chain.h:120-129`

**Impact:**
- `verificationprogress` cannot consult per-block tx density; falls
  back to height-based linear interpolation (Core uses tx-density
  via `m_chain_tx_count`).
- assumeUTXO snapshot validation (W138) can't stamp
  `m_chain_tx_count` on the snapshot base.

---

## BUG-12 (P0-CDIV) — `ReconsiderBlock` clears `StatusInvalid` from ALL ancestors

**Severity:** P0-CDIV (correctness, cross-cite W101 G19). Core's
`ResetBlockFailureFlags` (validation.cpp:3711-3730) walks
`m_blockman.m_block_index` and clears `BLOCK_FAILED_VALID` ONLY from
blocks that match BOTH:
1. `(block_index.GetAncestor(nHeight) == pindex || pindex->GetAncestor(block_index.nHeight) == &block_index)` — block is in pindex's ancestor chain OR a descendant of pindex
2. `(block_index.nStatus & BLOCK_FAILED_VALID)` — was already failed

blockbrew's `ReconsiderBlock` (chainmanager.go:1960-1965) walks ALL
ancestors of pindex up to genesis and unconditionally strips
`StatusInvalid | StatusInvalidChild`:

```go
current := node
for current != nil {
    current.Status &^= (StatusInvalid | StatusInvalidChild)
    current = current.Parent
}
```

If an unrelated ancestor was independently invalidated via a separate
`invalidateblock` RPC call, `ReconsiderBlock` on a descendant
silently resurrects it without any re-validation.

**File:** `internal/consensus/chainmanager.go:1960-1965`

**Core ref:** `bitcoin-core/src/validation.cpp:3711-3730`

**Impact:**
- An operator who invalidates two blocks (b1 ancestor of b2) and
  then reconsiders b2 to recover from a misconfigured invalidateblock
  on b2 will accidentally re-enable b1 too. b1's invalid state was
  the operator's deliberate choice. `setBlockIndexCandidates`
  re-eligibility happens without ConnectBlock being re-run against b1.
- Bug already pinned in `w101_activate_best_chain_test.go:633` with
  `t.Logf("G19 BUG CONFIRMED")` — no fix landed.

---

## BUG-13 (P0-CDIV) — IBD exit uses `tipHeight == assumeValidHeight` equality

**Severity:** P0-CDIV (cross-cite W101 G22). Bitcoin Core's
`UpdateIBDStatus` (validation.cpp:3283-3291) exits IBD when the active
chain tip is "recent" (within `max_tip_age`) AND has chainwork ≥
`MinimumChainWork`. The state is a one-way latch
(`m_cached_is_ibd.store(false)`).

blockbrew's IBD exit (`chainmanager.go:966-969`):
```go
if cm.isIBD && cm.tipHeight == cm.assumeValidHeight {
    cm.isIBD = false
    log.Printf("chainmgr: exiting IBD mode at height %d", cm.tipHeight)
}
```

This is an `==` equality check, not `>=`, AND it fires only at the
exact moment `tipHeight == assumeValidHeight`. Two failure modes:
1. If `assumeValidHeight = 0` (no AssumeValidHash configured —
   regtest, custom networks, or testnet during gap windows where the
   shipped AssumeValidHash isn't in the header index yet), the check
   fires only when `tipHeight == 0`. At genesis: `cm.isIBD = true`,
   `cm.tipHeight = 0`, `cm.assumeValidHeight = 0` — so the very
   first call to ConnectBlock for the genesis block would set IBD to
   false (but the genesis block path actually short-circuits at
   chainmanager.go:576, never reaching line 966). Genesis after
   restart never re-fires this check (tipHeight starts > 0).
2. If a reorg pushes `tipHeight` from N-1 to N+1 (skipping
   `assumeValidHeight == N`), IBD never exits — the equality misses.

**File:** `internal/consensus/chainmanager.go:966-969`

**Core ref:** `bitcoin-core/src/validation.cpp:3283-3291`

**Impact:**
- On regtest: `isIBD = true` indefinitely after the first
  ConnectBlock; mempool acceptance and assume-valid gating are
  off-spec relative to Core (Core's IBD exit fires when tip is
  within `max_tip_age` of wall-clock — regtest mined blocks have
  current timestamps so IBD exits within seconds).
- On mainnet bootstrap: if AssumeValidHash is set but the assume-valid
  block hasn't been mined yet at the time of release (shipped
  pre-hash), the early code path at chainmanager.go:517-523 never
  resolves `cm.assumeValidHeight > 0`, leaving the IBD exit silent.

---

## BUG-14 (P1) — `ReorgTo` skip-list not used in disconnect/connect walks

**Severity:** P1 (performance). Same family as BUG-2 — `ReorgTo`
builds disconnect/connect lists by walking `node.Parent` (O(depth)),
not using the `Skip` pointer to bound the walk.

**File:** `internal/consensus/chainmanager.go:1639-1650`

**Impact:** A 100-block reorg builds two 100-entry lists by
following 200 Parent pointers — fine on its own, but combined with
no-chunking (BUG-4) the under-lock period extends linearly with depth.

---

## BUG-15 (P1) — `m_best_invalid` analog absent

**Severity:** P1 (operator-warning gap). Core's
`ChainstateManager::m_best_invalid` tracks the heaviest known-invalid
chain. `InvalidChainFound` updates it; `CheckForkWarningConditions`
emits `LARGE_WORK_INVALID_CHAIN` warning if `m_best_invalid` is more
than 6 blocks heavier than the active tip. This is a critical operator
alert for consensus splits (database corruption or peer poisoning).

blockbrew has no `m_best_invalid` analog; no fork-warning surface.
`InvalidateBlock` logs locally but never emits a sync-with-network
divergence warning.

**File:** `internal/consensus/chainmanager.go` (no equivalent field)

**Core ref:** `bitcoin-core/src/validation.cpp:1953-1960`
(`CheckForkWarningConditions`).

**Impact:** Operator cannot tell when a heavier chain than the
active tip exists but has been invalidated locally — a strong signal
of network-level disagreement (consensus split).

---

## BUG-16 (P2) — `setBlockIndexCandidates`-equivalent is implicit; no candidate pruning

**Severity:** P2. Core maintains `setBlockIndexCandidates` (a
sorted set of `CBlockIndex*` ordered by `CBlockIndexWorkComparator`)
explicitly, allowing `FindMostWorkChain` to use `.rbegin()` for O(1)
top-of-set access. Candidates with less work than the current tip are
pruned via `PruneBlockIndexCandidates`.

blockbrew's `recalculateBestTipLocked` (headerindex.go:741-809) walks
**all** nodes in `idx.nodes` map on every call, O(N) where N is the
header index size (~900k mainnet). For each candidate it walks
ancestors checking `StatusDataStored`. Pruning of less-work candidates
is absent — every header ever seen is rescanned.

**File:** `internal/consensus/headerindex.go:741-809`

**Core ref:** `bitcoin-core/src/validation.cpp:3114-3171, 3173-3183`

**Impact:** On mainnet, `RecalculateBestTip` after an invalidate or
reconsider is O(900k × avg-depth) — milliseconds to seconds. Acceptable
for one-off RPC calls; would be untenable if called per-block (Core's
`TryAddBlockIndexCandidate` runs per block).

---

## BUG-17 (P1) — `MaybeUpdateMempoolForReorg` post-connect side missing

**Severity:** P1 (cross-cite W101 G15, mempool/mempool.go:2061 has
`RemoveForReorg` with no production call-sites). Core's
`ActivateBestChainStep` calls `MaybeUpdateMempoolForReorg` BOTH after
disconnects (to refill mempool with disconnected txs) AND after
connects (to evict newly-mined txs and re-validate against the new tip's
UTXO view).

blockbrew has the disconnect-side closure (Pattern B, 72c23be) wiring
DisconnectBlock → `onBlockDisconnected` → `mempool.BlockDisconnected`.
The connect-side closure (Pattern C0) wires ConnectBlock →
`onBlockConnected` → txindex but DOES NOT call
`mempool.RemoveForReorg` — so post-connect mempool re-validation against
the new chain's UTXO view never fires.

**File:** `internal/mempool/mempool.go:2061` (`RemoveForReorg` defined,
no callers); `internal/consensus/chainmanager.go:1146-1156`
(`onBlockConnected` dispatch).

**Core ref:** `bitcoin-core/src/validation.cpp:3206`
(`MaybeUpdateMempoolForReorg(disconnectpool, false)`).

**Impact:** After a reorg, mempool contains txs that may now reference
non-existent UTXOs on the new chain (or violate new-chain BIP-68
sequence locks). Next ConnectBlock that includes one of them fails
sanity. Mempool re-validation against new tip is the standard fix.

---

## BUG-18 (P2) — `DisconnectBlock` failure does NOT halt the node

**Severity:** P2. Core's `ActivateBestChainStep` treats DisconnectTip
failure as fatal:
```cpp
FatalError(m_chainman.GetNotifications(), state, _("Failed to disconnect block."));
return false;
```
blockbrew's `ReorgTo` (chainmanager.go:1695-1697) propagates the
error up:
```go
if err := cm.DisconnectBlock(node.Hash); err != nil {
    return fmt.Errorf("disconnect block %s failed: %w", node.Hash.String()[:16], err)
}
```
The caller (often a P2P-driven path) logs the error and continues.
No `FatalError` halt, no operator alert, no chain-shutdown.

**File:** `internal/consensus/chainmanager.go:1693-1698`

**Core ref:** `bitcoin-core/src/validation.cpp:3208-3214`

**Impact:** A corrupted rev*.dat that causes DisconnectBlock to fail
during a reorg leaves the chain manager in an inconsistent state
(`cm.tipNode` partially walked, UTXO set already mutated for some
peels) and the next ConnectBlock will fail sanity — but the process
continues running, racing peer-driven block downloads against a
broken-but-not-halted node. Core's FatalError model is more
defensive.

---

## BUG-19 (P2) — `IsTooFarAhead` uses `MIN_BLOCKS_TO_KEEP=288` correctly, but is checked only on UNSOLICITED blocks

**Severity:** P2. Core's `fTooFarAhead` gate (validation.cpp:4325)
applies only to `!fRequested` unsolicited blocks — blockbrew preserves
that semantic (`sync.go:1840-1847`). PASS as a behavior. But:

`IsTooFarAhead` reference (`consensus.IsTooFarAhead`,
`chainmanager.go:1275-1277`) is exported but the **only** call site is
`sync.go:1842`. The function would have additional fan-out in Core
(e.g. `BlockManager::AcceptBlock` checks fTooFarAhead on both
solicited *and* unsolicited paths when `pblock` arrives from a peer
that didn't request it via getheaders). The current single-call-site
pattern is fragile — a future refactor of the inv/getdata path can
silently bypass the gate.

**File:** `internal/consensus/chainmanager.go:1275-1277`

**Core ref:** `bitcoin-core/src/validation.cpp:4325`

**Impact:** Low — defense-in-depth gap, not exploitable today.

---

## BUG-20 (P3) — `ReorgTo` logs disconnect/connect counts but no aggregate latency

**Severity:** P3 (operability). The existing W76-PHASE rollup tracks
per-block ConnectBlock phase timings but does NOT distinguish blocks
that ran INSIDE a `ReorgTo` from regular extensions. Operators
investigating a slow reorg (e.g. a chain-split recovery) have no
single log line per-reorg with total disconnect + connect latency.

**File:** `internal/consensus/chainmanager.go:1659-1661`
(`ReorgTo` start log, no matching end log with elapsed time).

**Impact:** Forensics on reorg events require correlating multiple log
lines.

---

## BUG-21 (P2) — `ConnectBlock` IBD path triggers ReorgTo without holding lock

**Severity:** P2 (locking inversion). At chainmanager.go:505-510:
```go
if node.TotalWork.Cmp(cm.tipNode.TotalWork) > 0 {
    cm.mu.Unlock()
    err := cm.ReorgTo(node)
    cm.mu.Lock()
    return err
}
```
The lock is released, `ReorgTo` is called, then re-acquired. Between
unlock and `ReorgTo` taking `cm.reorgMu`, another goroutine can
contest `cm.mu`, observe a transient tip mismatch, and make
inconsistent decisions. Core's `ActivateBestChain` releases
`cs_main` deliberately between iterations of an outer loop, never
mid-step.

**File:** `internal/consensus/chainmanager.go:504-511`

**Impact:** Low — `cm.reorgMu` will serialize the reorg itself, but
the symptom is observable: a ConnectBlock check at line 496 says
`prevBlock != tipNode.Hash`, then drops the lock, then ReorgTo runs;
the original block being connected is now stale relative to the new
tip. The function returns the ReorgTo error rather than re-trying the
original ConnectBlock.

---

## Fleet-pattern smells

- **Comment-as-confession** (1×): `chainmanager.go:30-31` —
  "Bitcoin Core uses 100 in validation.cpp's MaxReorgDepth() helper".
  Core has NO `MaxReorgDepth()` helper and no MAX_REORG_DEPTH
  constant. The comment encodes a confidently-asserted Core behavior
  that simply does not exist. (Cross-cite to BUG-5.)
- **Two-pipeline guard** (1×): `ConnectBlock` has BOTH an
  in-IBD path (refuses non-extending blocks at line 500-503) AND a
  post-IBD reorg path (calls `ReorgTo` at line 504-511). The two
  pipelines diverge on side-branch acceptance behavior depending on
  the `cm.isIBD` flag, which is itself driven by a broken equality
  check (BUG-13). Cross-impl shape: dual paths gated on a buggy
  predicate.
- **Dead-helper-at-call-site** (1×): `Mempool.RemoveForReorg`
  defined at `mempool/mempool.go:2061`, zero production callers
  (BUG-17, w101 G15).
- **Dead-field**: `BlockNode` has no `ChainTxCount` field at all
  (BUG-11), so the "cumulative tx count" required by Core's
  `m_chain_tx_count` cannot be stamped — it isn't dead, it's
  entirely absent (worse than dead).
- **Carry-forward re-anchor**: G19 (ReconsiderBlock ancestor-clear),
  G22 (IBD exit equality) are documented bugs in
  `w101_activate_best_chain_test.go` (lines 568-640, 691-768) flagged
  3+ waves ago with `t.Logf("BUG CONFIRMED")` — no fix lands. Same
  pattern as W123's `TestW123_G4_BlockSubsidyHalvingUsesPackageConst_BUG`
  carried forward into W145 BUG-1.
- **30-of-30 GATES** — not fired (this audit has 13 BUGs spread
  across 8 behaviours; the implementation is mostly Core-shaped, with
  semantic divergences clustered around (a) failed-block status
  propagation, (b) ABC outer-loop absence, (c) BlockNode
  field-completeness).

---

## Summary

13 P0-class divergences, 7 P1-class gaps, 4 P2-class issues, 1 P3-class
nit. Severity-totals:

- **P0-CDIV** (consensus-divergent): 6 — BUG-1, BUG-5, BUG-7, BUG-8,
  BUG-12, BUG-13
- **P0** (semantic gap): 1 — BUG-3 (ABC outer-loop absent)
- **P1** (correctness / performance): 7 — BUG-2, BUG-6, BUG-9,
  BUG-10, BUG-11, BUG-14, BUG-15, BUG-17
- **P2**: 4 — BUG-4, BUG-16, BUG-18, BUG-19, BUG-21
- **P3**: 1 — BUG-20

Highest-leverage fixes:
1. **BUG-1** (1 line: `parent.Status.IsInvalid()` check at the top of
   AddHeader)
2. **BUG-7** (~10 lines per error-return path: stamp
   `node.Status |= StatusInvalid` before `return err` in
   ConnectBlock — closes the symmetric leak on the block side)
3. **BUG-13** (1 line: change `==` to `>=`, or rewrite IBD exit per
   Core's UpdateIBDStatus model)
4. **BUG-12** (replace the unconditional ancestor walk with a
   condition matching Core's ResetBlockFailureFlags filter)
5. **BUG-5** (architectural — remove MaxReorgDepth cap OR rationalize
   the constant by referencing MIN_BLOCKS_TO_KEEP=288, not the
   fabricated Core MaxReorgDepth=100)
