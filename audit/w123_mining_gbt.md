# W123 — Mining / Block Template / GBT Parity Audit (blockbrew)

**Wave**: W123 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**Verdict**: **14 BUGS** (2 P0-CDIV, 2 P1, 9 P2, 1 low-prio); 12 PRESENT; 5 PARTIAL
**Reference**:
  - `bitcoin-core/src/node/miner.cpp` (BlockAssembler)
  - `bitcoin-core/src/rpc/mining.cpp` (getblocktemplate / submitblock / getmininginfo)
  - `bitcoin-core/src/policy/feefrac.cpp` + `policy/policy.cpp::GetSigOpsAdjustedWeight`
  - `bitcoin-core/src/txmempool.cpp::GetBlockBuilderChunk`
  - BIPs 22 / 23 / 9 / 141 / 145 / 152 / 431 / 94

## Summary

blockbrew has a **substantially complete BlockAssembler / GBT stack**, but
**two P0-CDIV gaps** sit at the heart of the FIX-72 follow-through. FIX-72
(commit `dc8e1a0`) wired `GetModifiedFee` into RBF Rule 3
(`Mempool.checkRBFLocked`), `getmempoolentry.modifiedfee`,
`getprioritisedtransactions`, and the new `prioritisetransaction` RPC — but
**did not touch the mining-side selection path** at
`internal/mining/mining.go:312-327`.  The intent of the FIX-72 audit note
("submitheader still outstanding, mining-side, distinct from this fix") was
that submitheader was the only mining-side gap; in reality
**`prioritisetransaction` does not affect block construction at all**, which
is the strictest possible read of "mining-side modified-fee variance".

A separate **P0-CDIV** finding: blockbrew's `consensus.CalcBlockSubsidy`
reads the **package-level** `SubsidyHalvingInterval = 210_000`, ignoring
`chainParams.SubsidyHalvingInterval`.  On regtest (halving=150) every block
past height 150 over-pays subsidy by up to 50× (block 150-299 still pays
50 BTC instead of 25 BTC, 300-449 still pays 50 BTC instead of 12.5 BTC,
and so on).  Empirically verified by `TestW123_G4`:
`CalcBlockSubsidy(150) == 5_000_000_000` (50 BTC) instead of the expected
`2_500_000_000` (25 BTC).

The cluster-mempool machinery
(`internal/mempool/cluster.go::GetChunksForMining`,
`ClusterManager.GetChunksForMining`, `DepGraph` + `findBestChunk`) is
~1200 LOC of well-engineered Linearization but **never called from the
mining path** — `selectTransactions` (mining.go:312) calls
`GetSortedByAncestorFeeRate` even though the function comment at
mempool.go:2102 self-documents as:

```
// Deprecated: Use GetChunksForMining for cluster-based optimal ordering.
```

This is the **dead-helper-at-mining-call-site** pattern (counterpart of W121's
"dead-helper-at-BIP-324-message-table" pattern observed across hotbuns,
clearbit, lunarblock).

## Bug ladder

| ID | Sev | Gate | Location | Title |
|----|-----|------|----------|-------|
| BUG-1 | P0-CDIV | G4 | `internal/consensus/difficulty.go:162` | `CalcBlockSubsidy` ignores `chainParams.SubsidyHalvingInterval`; uses package const |
| BUG-2 | P0-CDIV | G5 | `internal/mining/mining.go:312, 327` | Mining selection uses raw `entry.FeeRate`; FIX-72 `prioritisetransaction` invisible to block construction |
| BUG-3 | P1 | G7 | `internal/mining/mining.go:312` | Cluster `GetChunksForMining` dead-helper-at-mining-call-site |
| BUG-4 | P2 | G8 | `internal/rpc/types.go:432-443` | `getmininginfo` missing `currentblockweight` / `currentblocktx` / `signet_challenge` |
| BUG-5 | P2 | G11 | `internal/rpc/extra_methods.go:709` | `blockmintxfee` hardcoded; `-minrelaytxfee` / `-blockmintxfee` CLI absent |
| BUG-6 | P2 | G13 | `cmd/blockbrew/*` + `rpc/methods.go:1666` | `-blockmaxweight` CLI flag missing |
| BUG-7 | P2 | G14 | `internal/mempool/mempool.go` | `Mempool.GetTransactionsUpdated()` counter missing (longpoll prereq) |
| BUG-8 | P2 | G15 | `internal/rpc/types.go::BlockTemplateResult` | `longpollid` field missing (cross-ref W108 G5) |
| BUG-9 | P2 | G19 | `internal/rpc/extra_methods.go:664` | `getmininginfo` does not compute `networkhashps`; field absent |
| BUG-10 | P2 | G23 | `internal/rpc/methods.go:1660` | GBT longpoll wait loop entirely missing — synchronous handler |
| BUG-11 | P2 | G24 | `internal/rpc/methods.go:1660` | `mode="proposal"` not implemented (cross-ref W108 G1) |
| BUG-12 | P1 | G27 | `internal/mining/mining.go::selectTransactions` | TRUC mining trusts admission-time invariant; no v3-specific guard at selection |
| BUG-13 | P1 | G28 | `internal/mining/mining.go::selectTransactions` | Package mining: 3+-tx atomic admission relies on `AncestorFee` aggregation |
| BUG-14 | P2 | G30 | `internal/rpc/server.go` | `submitheader` RPC absent (cross-ref W108 G30) |

(G20 `getblocksubsidy` is the low-prio item — Core has never had this RPC.)

## Gate-by-gate

### G1 — Block weight 4M enforcement (PRESENT)

`selectTransactions` uses `if totalWeight+txWeight >= maxWeight { skip }`
(`mining.go:336`), matching Core `miner.cpp:241`'s `>=` comparator
(`nBlockWeight + chunk.size >= nBlockMaxWeight`). `consensus.MaxBlockWeight =
4_000_000`. Verified by W108 G13/G15.

### G2 — Block sigops 80,000 enforcement (PRESENT)

`mining.go:350` uses `>=` exactly as Core `miner.cpp:244`. `MaxBlockSigOpsCost
= 80_000`. Verified by W108 G11.

### G3 — Coinbase witness commitment (PRESENT)

`CreateCoinbaseTx` (mining.go:478-491) emits 38-byte `OP_RETURN` push of
`0xaa21a9ed` + 32-byte commitment, with the coinbase's witness reserved value
(32 zero bytes) assigned to `TxIn[0].Witness`. Core `validation.cpp:3997`
parity.

### G4 — BUG-1 P0-CDIV: Block subsidy halving uses **package const**

```go
// internal/consensus/difficulty.go:162
func CalcBlockSubsidy(height int32) int64 {
    halvings := height / SubsidyHalvingInterval // ← PACKAGE CONST 210_000
    // ...
}
```

`chainParams.SubsidyHalvingInterval` (chaincfg.go:319 = 150 on regtest) is
**ignored**. Empirically, `CalcBlockSubsidy(150)` returns 50 BTC (5_000_000_000
sats) on every chain — should be 25 BTC on regtest.

Impact:
- **Mainnet / testnet4**: invisible (chain-param == package-const = 210_000).
- **Regtest**: ALL mined blocks past height 150 over-pay subsidy.
- **Signet / custom chains**: silently inherit mainnet halving schedule.

Fix shape:
```go
func CalcBlockSubsidy(params *ChainParams, height int32) int64 {
    halvings := height / params.SubsidyHalvingInterval
    // ...
}
```
And thread `chainParams` through `mining.GenerateTemplate` to the call site.

Core reference: `validation.cpp::GetBlockSubsidy(int nHeight, const
Consensus::Params& consensusParams)` reads `consensusParams.nSubsidyHalvingInterval`.

### G5 — BUG-2 P0-CDIV (FIX-72 KEY GAP): Mining uses RAW fee, not MODIFIED

```go
// internal/mining/mining.go:311-328
func selectTransactions(mp MempoolProvider, ...) (...)  {
    entries := mp.GetSortedByAncestorFeeRate() // ← RAW ancestor feerate
    // ...
    for _, entry := range entries {
        if entry.FeeRate < minFeeRate {        // ← RAW FeeRate
            continue
        }
        // ...
    }
}
```

`GetSortedByAncestorFeeRate` (mempool.go:2103) sorts by `entry.AncestorFeeRate()`
which reads `entry.AncestorFee / entry.AncestorSize` — **both raw**.
`PrioritiseTransaction` (mempool.go:696-712) only writes to `mapDeltas`; it
never updates `entry.Fee`, `entry.FeeRate`, `entry.AncestorFee`, or
`entry.AncestorSize`.

Empirically verified: `PrioritiseTransaction(txid, +1_000_000)` makes
`GetModifiedFee(entry)` return `1_001_000` (FIX-72 wiring works), but
`entry.FeeRate` stays at `5.0` sat/vB.

**Operator-visible consequence**: an operator who calls
`prioritisetransaction <txid> 0 100000` to boost a low-fee tx sees:
- `getmempoolentry.modifiedfee` → +100,000 (FIX-72)
- `getprioritisedtransactions` → +100,000 (FIX-72)
- Replacement-by-fee Rule 3 → ✓ uses modified fee (FIX-72)
- **`getblocktemplate.transactions` ordering → ✗ ignores delta**
- **Actual mining inclusion → ✗ ignores delta**

This is **the strictest possible read** of "mining-side modified-fee variance"
called out in FIX-72's commit body.

Core reference: `txmempool.cpp:641, 1022` —
`m_txgraph->SetTransactionFee(*it, it->GetModifiedFee())` is called every time
a delta is applied, causing cluster chunks to re-linearize against the new
modified feerate.

Fix shape (two viable paths):
1. **In-place**: PrioritiseTransaction sets `entry.AncestorFee += delta` and
   recomputes `entry.FeeRate` and `entry.AncestorFeeRate`. Cheap; minimal
   shape change. But duplicates `mapDeltas` and breaks the "delta is
   purely additive against a default-zero base" semantics.
2. **Cluster-aware**: add `ClusterManager.SetTransactionFee(txid, modifiedFee)`,
   call it from `PrioritiseTransaction`, and migrate `selectTransactions`
   to `GetChunksForMining` (closes BUG-3 below in the same change).

Path 2 is preferred — it also closes the BUG-3 dead-helper.

### G6 — Ancestor-aware mempool selection (PARTIAL)

`GetSortedByAncestorFeeRate` + parent-inclusion check (mining.go:374) handle
single-parent CPFP correctly. Falls down on multi-parent cluster
linearization — see G7.

### G7 — BUG-3 P1: Cluster mining dead-helper-at-call-site

`internal/mempool/cluster.go` has:
- `Cluster.findBestChunk` (line 706) — optimal feerate subset
- `Cluster.GetChunks` (line 657) — linearized chunks
- `ClusterManager.GetChunksForMining` (line 1150) — flat sorted chunk stream
- `Mempool.GetTransactionsForMining` (line 2130) — cluster-linearized order
- `Mempool.GetChunksForMining` (line 2122) — alias

**None of these are called from `mining.selectTransactions`**.

Core's `txmempool.cpp::GetBlockBuilderChunk` returns one chunk at a time from
the TxGraph in optimal order; `miner.cpp:296-340` loops on those chunks.
blockbrew's mining path is the pre-cluster greedy ancestor-feerate sort. The
result is suboptimal for clusters that contain a low-fee parent + high-fee
child sibling on a different cluster — Core picks the high-feerate cluster's
chunks first; blockbrew picks the higher single-tx ancestor-feerate first,
which can leave revenue on the table.

This compounds with BUG-2: even if BUG-2 is fixed in-place (path 1 above),
the cluster linearization still won't re-run when a delta is applied,
because `cluster.AddTransaction` (mempool.go:1357) was called once at admission
with the original (raw) fee.

### G8 — BUG-4 P2: `getmininginfo` missing optional Core fields

```go
// internal/rpc/types.go:432-443
type MiningInfo struct {
    Blocks         int32          `json:"blocks"`
    Bits           string         `json:"bits"`
    Difficulty     float64        `json:"difficulty"`
    Target         string         `json:"target"`
    NetworkHash    float64        `json:"networkhashps"` // ← was deleted? see G19
    // ...
}
```

Missing vs Core `mining.cpp:467-487`:
- `currentblockweight` (conditional on `BlockAssembler::m_last_block_weight`)
- `currentblocktx` (conditional on `BlockAssembler::m_last_block_num_txs`)
- `signet_challenge` (conditional on signet)

Impact: signet operators cannot read the block-signing challenge from RPC.
Low-impact otherwise.

### G9 — submitblock validation pipeline (PARTIAL)

`handleSubmitBlock` (rpc/methods.go:1889) calls `CheckBlockSanity` →
`AddHeader` → `StoreBlock` → `ProcessSubmittedBlock`, with consensus errors
mapped to BIP-22 strings via `bip22ResultString`.  `ErrSideBranchAccepted`
→ "inconclusive" matches Core `mining.cpp:1101`'s `sc->found` path. Good.

Gaps (NEW finding):
- **No `UpdateUncommittedBlockStructures` call** before
  `ProcessSubmittedBlock`. Core (`mining.cpp:1088`,
  `validation.cpp:4018`) auto-injects the witness commitment into the
  coinbase if missing — a tolerant behavior that blockbrew lacks. A
  submitblock with the witness commitment omitted by a buggy miner will
  fail in blockbrew but succeed in Core.
- **No "duplicate-invalid" distinction** (W108 G22 carry-forward) — Core
  `mining.cpp:744-749` and `validation.cpp` separate
  `BLOCK_FAILED_VALID` ("duplicate-invalid") from `BLOCK_VALID_SCRIPTS`
  ("duplicate") and headers-known-but-scripts-not-validated
  ("duplicate-inconclusive"). blockbrew always returns "duplicate".

### G10 — BIP-152 wire (PRESENT)

`sendcmpct` / `cmpctblock` / `getblocktxn` / `blocktxn` all dispatched
(p2p/message.go:303-315). `CompactBlockBuilder` + `PartiallyDownloadedBlock`
unit-tested. **Gap**: HighBandwidth (sendcmpct `announce=1`) flag is
tracked on the peer (`compactblock.go:621 announcesHB`) but no automatic
HB-promotion heuristic — Core
`net_processing.cpp::AnnounceCompactBlocks` promotes peers that
successfully reconstruct.

### G11 — BUG-5 P2: `blockmintxfee` hardcoded

```go
// internal/rpc/extra_methods.go:709
return &MiningInfo{
    // ...
    BlockMinTxFee: 0.00001, // ← hardcoded
    // ...
}
```

`mining.TemplateConfig.MinTxFeeRate` (mining.go:64) exists but
`handleGetBlockTemplate` (rpc/methods.go:1666) leaves it zero. No CLI
flag parser for `-minrelaytxfee` / `-blockmintxfee` in `cmd/blockbrew`.

Core: `ApplyArgsManOptions(BlockAssembler::Options).blockMinFeeRate`
(rpc/mining.cpp:475).

### G12 — Mempool dynamic min fee not consulted by mining (PARTIAL)

Mempool has `getMinFeeRateLocked` (mempool.go:2643) — rolling minimum that
decays with halflife. Used by ATMP (mempool.go:1197). Mining
(`selectTransactions`) does **not** consult it — only `config.MinTxFeeRate`.

Core `miner.cpp:298` early-exits the loop the moment `chunk_feerate_vsize`
falls below `blockMinFeeRate`. blockbrew can include below-floor txs
that have been re-evicted in the meantime.

### G13 — BUG-6 P2: `-blockmaxweight` CLI flag missing

`handleGetBlockTemplate` (rpc/methods.go:1666) never sets
`TemplateConfig.MaxWeight`, so `GenerateTemplate` (mining.go:208) falls
back to `consensus.MaxBlockWeight` = 4_000_000. There is no CLI flag in
`cmd/blockbrew` to override.  Core has `-blockmaxweight` with
`ClampOptions(MINIMUM_BLOCK_RESERVED_WEIGHT..MAX_BLOCK_WEIGHT)`.

### G14 — BUG-7 P2: `Mempool.GetTransactionsUpdated()` missing

Core `txmempool.cpp:196`:

```cpp
unsigned int CTxMemPool::GetTransactionsUpdated() const {
    return nTransactionsUpdated;
}
```

Incremented in every add / remove. Used by GBT longpoll. blockbrew Mempool
has no such counter — direct prerequisite for BUG-8/BUG-10.

### G15 — BUG-8 P2: `longpollid` field missing

W108 G5 carry-forward. `BlockTemplateResult` (rpc/types.go:452-473) has
no `longpollid` field. Core mining.cpp:1002:

```cpp
result.pushKV("longpollid", tip.GetHex() + ToString(nTransactionsUpdatedLast));
```

### G16 — Nonce iteration (PRESENT, partial extranonce)

`mineBlock` iterates `nonce 0..maxTries` (mining.go:696) with
`DefaultMaxTries = 1_000_000`. Coinbase scriptSig has extranonce slot
(default 8 zero bytes) but no automatic extranonce-rolling when nonce
exhausts.

### G17 — Coinbase scriptSig size 2..100 (PRESENT)

`ErrCoinbaseScriptSize` sentinel exists; mapped to `"bad-cb-length"` by
`bip22ResultString`. `CreateCoinbaseTx` produces scriptSig within range
for all realistic heights.

### G18 — Segwit serialization in submitblock (PRESENT)

`wire.MsgBlock.Deserialize` handles BIP-141 marker/flag.
`handleSubmitBlock` decodes via `block.Deserialize`.
`checkWitnessCommitment` validates.

### G19 — BUG-9 P2: `networkhashps` not computed by `getmininginfo`

W108 G29 carry-forward — and looking at the current `MiningInfo` struct
(rpc/types.go:432-443), the `NetworkHash` field appears to have been
**deleted** since W108 (rather than left zero). The W108 audit listed
`NetworkHash float64` in MiningInfo; current type does not declare it.

`handleGetNetworkHashPS` exists (wave47b_methods.go:63) but
`handleGetMiningInfo` (extra_methods.go:664) does not call it.

Core `mining.cpp:472`:
```cpp
obj.pushKV("networkhashps", getnetworkhashps().HandleRequest(request));
```

### G20 — `getblocksubsidy` RPC (low-prio MISSING)

Not exported by Core (BCH/BSV-only fork RPC). Functional access via
`getblocktemplate.coinbasevalue` or compute from header.

### G21 — Target encoding (PRESENT)

`fmt.Sprintf("%064x", target)` (rpc/methods.go:1704) — lowercase 64
nibbles. Core mining.cpp:1003 `hashTarget.GetHex()` parity.

### G22 — Merkle root recomputed on tx override (PRESENT)

`BlockMiner.GenerateBlock` (mining.go:642-657) recomputes merkle root +
witness commitment when caller substitutes txs.
`UpdateCoinbaseWitnessCommitment` patches in-place (mining.go:710).

### G23 — BUG-10 P2: GBT longpoll wait loop missing

`handleGetBlockTemplate` is synchronous (rpc/methods.go:1660) — returns
immediately. Core `mining.cpp:797-866` implements a 60-second wait loop
on tip changes OR mempool deltas (with 5-second debounce).

Without G14 (`nTransactionsUpdated` counter) and G15 (`longpollid`
field), pools can't long-poll; with those, pools could poll constantly
on a non-changing template.

### G24 — BUG-11 P2: `mode="proposal"` not implemented

W108 G1 carry-forward. `handleGetBlockTemplate` ignores all params. No
`TestBlockValidity` equivalent exposed for proposal mode. Core
`mining.cpp:730-751` parses params → `DecodeHexBlk` → `TestBlockValidity`
→ `BIP22ValidationResult`.

### G25 — Witness commitment placement (PRESENT)

`CreateCoinbaseTx` (mining.go:485) appends commitment as last output, 0
value, OP_RETURN-prefixed.  `checkWitnessCommitment`
(blockvalidation.go:213) searches from last to first — matches Core's
`GetWitnessCommitmentIndex`.

### G26 — Witness sigops counting (PRESENT)

`computeTxSigOpsCost` (mining.go:411) includes legacy + P2SH +
witness sigops when UTXO view available. Core
`consensus/tx_verify.cpp::GetTransactionSigOpCost` parity.

### G27 — BUG-12 P1: TRUC mining (PARTIAL)

`truc_policy.go` enforces TRUC at mempool admission. Mining
(`selectTransactions`) has no v3-specific guard — relies on the invariant
that the mempool can never hold an oversized v3 cluster. Untested edge:
evicting a v3 parent without also evicting the child.

### G28 — BUG-13 P1: Package mining (PARTIAL)

CPFP pairs work — ancestor-feerate sort + parent-inclusion check.
3+-tx packages depend on `AncestorFee` aggregating all chain ancestors
correctly. Core's `GetBlockBuilderChunk` delivers whole-cluster atoms
regardless of admission grouping.

### G29 — Coinbase reward (PRESENT)

`GenerateTemplate` computes `subsidy + sum(raw entry.Fee)`. This is
**correct** per Core `miner.cpp:270` (`nFees += entry.GetFee()`, **not**
`GetModifiedFee`) — miners collect actual fees, not operator notional
deltas. G4 still applies (subsidy itself wrong on non-mainnet).

### G30 — BUG-14 P2: `submitheader` RPC

W108 G30 carry-forward. `internal/rpc/server.go` dispatch has no case for
`submitheader`. Core `mining.cpp:1108`: `DecodeHexBlockHeader` →
`ProcessNewBlockHeaders`. Internal `HeaderIndex.AddHeader` exists; just
no RPC route.

## Test plan

`internal/mining/w123_gbt_test.go` adds 30 `TestW123_Gn_*` gates plus a
summary. All 30 + summary PASS today (audit doc, not fixes); the BUG-* ones
print a structured log entry referencing the line numbers above. The two
empirical assertions:

- `TestW123_G4_BlockSubsidyHalvingUsesPackageConst_BUG` — verifies
  `CalcBlockSubsidy(150) == 5_000_000_000` on regtest where 150 == regtest
  `SubsidyHalvingInterval`. Should be 25 BTC after the fix.
- `TestW123_G5_MiningUsesRawFeeNotModified_BUG` — verifies that after
  `PrioritiseTransaction(txid, +1_000_000)`, `GetModifiedFee` reflects the
  delta but `entry.FeeRate` does not.

Baseline pre-existing failures from W108 (G12, G23 SizeLimit constant) are
unchanged.

## Fix sequencing recommendation

The natural FIX-N follow-on is a two-stage:

**Stage 1 (FIX-N, narrow)** — close G4 + G5 as paired P0-CDIV:
1. Thread `chainParams.SubsidyHalvingInterval` into `CalcBlockSubsidy`.
2. Either add a `GetSortedByModifiedAncestorFeeRate()` (path 1) or migrate
   selection to `GetChunksForMining` + add
   `ClusterManager.SetTransactionFee` driven by `PrioritiseTransaction`
   (path 2, also closes BUG-3 G7).

Path 2 is strictly preferred (closes 1 P0 + 1 P1 in the same change and
removes ~1200 LOC of dead-helper).

**Stage 2 (FIX-N+1, broad)** — close the P2 GBT-completeness cluster:
G8 (currentblockweight/currentblocktx/signet_challenge),
G11 (`-minrelaytxfee` / `-blockmintxfee` flags),
G13 (`-blockmaxweight`),
G14+G15+G23 (longpoll: `nTransactionsUpdated` + `longpollid` field + wait loop),
G19 (`networkhashps` inline call),
G24 (proposal mode),
G30 (`submitheader`).

P1 G27/G28 (TRUC + package mining) can be deferred — they may be
PRESENT after stress-test corroboration.

Cumulative bug ladder for the new W123 wave (P0=2, P1=2, P2=9,
low-prio=1) sits well within typical wave density for blockbrew.
