# W154 — CreateNewBlock + BlockAssembler + block template construction (blockbrew)

**Wave:** W154 — `BlockAssembler::CreateNewBlock`, `addPackageTxs`
(`addChunks` in modern Core), `GetMinimumTime` (BIP-94 timewarp),
`UpdateTime`, `GenerateCoinbaseCommitment` (BIP-141 0xaa21a9ed),
`RegenerateCommitments`, `ApplyArgsManOptions` (`-blockmaxweight` /
`-blockreservedweight` / `-blockmintxfee` / `-printpriority`),
`ComputeBlockVersion`, BIP-34 coinbase height encoding (`CScript() <<
nHeight`), `MAX_SEQUENCE_NONFINAL` + `nLockTime = nHeight-1`,
`TestChunkBlockLimits` / `TestChunkTransactions`, `MAX_BLOCK_WEIGHT`,
`WITNESS_SCALE_FACTOR`, `DEFAULT_BLOCK_RESERVED_WEIGHT=8000`,
`MINIMUM_BLOCK_RESERVED_WEIGHT=2000`, `DEFAULT_BLOCK_MIN_TX_FEE`,
`MAX_BLOCK_SIGOPS_COST`, `MAX_BLOCK_SERIALIZED_SIZE`, `getblocktemplate`
RPC shape (Core rpc/mining.cpp:920-1023), `generatetoaddress`,
`generatetodescriptor`, `generateblock`, `submitblock`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/miner.h:83-84` — `nBlockMaxWeight{DEFAULT_BLOCK_MAX_WEIGHT}`,
  `blockMinFeeRate{DEFAULT_BLOCK_MIN_TX_FEE=1}` (sat/kvB).
- `bitcoin-core/src/policy/policy.h:25-36` — `DEFAULT_BLOCK_MAX_WEIGHT=MAX_BLOCK_WEIGHT`,
  `DEFAULT_BLOCK_RESERVED_WEIGHT=8000`, `MINIMUM_BLOCK_RESERVED_WEIGHT=2000`,
  `DEFAULT_BLOCK_MIN_TX_FEE=1` (one sat per kvB).
- `bitcoin-core/src/consensus/consensus.h` — `MAX_BLOCK_WEIGHT=4000000`,
  `WITNESS_SCALE_FACTOR=4`, `MAX_BLOCK_SIGOPS_COST=80000`,
  `MAX_BLOCK_SERIALIZED_SIZE=4000000`.
- `bitcoin-core/src/consensus/validation.h:18` —
  `MINIMUM_WITNESS_COMMITMENT=38` bytes (OP_RETURN + push36 + 4-byte
  magic 0xaa21a9ed + 32-byte commitment).
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime(pindexPrev,
  difficulty_adjustment_interval)`: `min_time = pindexPrev->MTP+1`; at
  retarget boundary on **all networks** (Core comment: "Account for BIP94
  timewarp rule on all networks. This makes future activation safer"),
  also bounded below by `prev->GetBlockTime() - MAX_TIMEWARP=600`.
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime`: `nNewTime =
  max(GetMinimumTime(...), NodeClock::now())`; recomputes `nBits` after
  bumping time when `fPowAllowMinDifficultyBlocks` is set.
- `bitcoin-core/src/node/miner.cpp:67-77` — `RegenerateCommitments`:
  erases the existing witness commitment output, re-calls
  `GenerateCoinbaseCommitment`, rebuilds `hashMerkleRoot`.
- `bitcoin-core/src/node/miner.cpp:79-88` — `ClampOptions`: clamps
  `block_reserved_weight` to `[MINIMUM_BLOCK_RESERVED_WEIGHT,
  MAX_BLOCK_WEIGHT]`, clamps `nBlockMaxWeight` to
  `[*block_reserved_weight, MAX_BLOCK_WEIGHT]`, clamps
  `coinbase_output_max_additional_sigops` to `[0, MAX_BLOCK_SIGOPS_COST]`.
- `bitcoin-core/src/node/miner.cpp:98-109` — `ApplyArgsManOptions`:
  `-blockmaxweight`, `-blockmintxfee`, `-printpriority`,
  `-blockreservedweight` plumbing.
- `bitcoin-core/src/node/miner.cpp:111-120` — `resetBlock`:
  `nBlockWeight = *Assert(m_options.block_reserved_weight)`,
  `nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops`.
- `bitcoin-core/src/node/miner.cpp:122-237` — `CreateNewBlock` happy path,
  including `m_lock_time_cutoff = pindexPrev->GetMedianTimePast()` (BIP-113),
  `ComputeBlockVersion(pindexPrev, params)`, regtest-only `-blockversion`
  override, `nLockTime = nHeight - 1`, `nSequence = MAX_SEQUENCE_NONFINAL =
  0xFFFFFFFE`, `BIP34: CScript() << nHeight` + tiny-height OP_0 padding
  to guarantee scriptSig ≥ 2 bytes, `GenerateCoinbaseCommitment(*pblock,
  pindexPrev)`, `UpdateTime(pblock, params, pindexPrev)`,
  `GetNextWorkRequired(pindexPrev, pblock, params)`,
  optional `TestBlockValidity(check_pow=false, check_merkle_root=false)`.
- `bitcoin-core/src/node/miner.cpp:239-247` — `TestChunkBlockLimits`:
  `if (nBlockWeight + chunk.size >= nBlockMaxWeight)` and
  `if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST)`.
- `bitcoin-core/src/node/miner.cpp:252-260` — `TestChunkTransactions`:
  `IsFinalTx(tx, nHeight, m_lock_time_cutoff)` for every tx in the chunk.
- `bitcoin-core/src/node/miner.cpp:279-334` — `addChunks`: pulls full
  cluster chunks via `m_mempool->GetBlockBuilderChunk()`, applies
  `blockMinFeeRate` filter on the **chunk feerate** (package-feerate),
  bails after `MAX_CONSECUTIVE_FAILURES=1000` if
  `nBlockWeight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA=4000 > nBlockMaxWeight`.
- `bitcoin-core/src/validation.cpp:3997-4019` — `GenerateCoinbaseCommitment`:
  if `GetWitnessCommitmentIndex(block) == NO_WITNESS_COMMITMENT`, builds
  OP_RETURN scriptPubKey of `MINIMUM_WITNESS_COMMITMENT=38` bytes with
  the 4-byte 0xaa21a9ed magic and `SHA256d(witnessroot || reserved)`.
- `bitcoin-core/src/validation.cpp:4151-4159` — `ContextualCheckBlock`
  BIP-34 scriptSig prefix gate: `block.vtx[0]->vin[0].scriptSig` must
  start with `CScript() << nHeight` exactly.
- `bitcoin-core/src/validation.cpp:3997-4055` — `GenerateCoinbaseCommitment` +
  `IsBlockMutated` (CVE-2012-2459 mutated-merkle).
- `bitcoin-core/src/rpc/mining.cpp:630-700` — GBT request/response shape:
  `capabilities`, `rules`, `vbavailable`, `vbrequired`, `previousblockhash`,
  `transactions[{data,txid,hash,depends,fee,sigops,weight}]`, `coinbaseaux`,
  `coinbasevalue`, `longpollid`, `target`, `mintime`, `mutable[time,transactions,
  prevblock]`, `noncerange`, `sigoplimit`, `sizelimit`, `weightlimit`
  (only when post-segwit), `curtime`, `bits`, `height`,
  `default_witness_commitment`, `signet_challenge`.
- `bitcoin-core/src/rpc/mining.cpp:903-936` — per-tx loop building
  `transactions[]`: `setTxIndex` map → `depends[]` is populated by
  scanning `tx.vin[].prevout.hash` against the in-template `setTxIndex`;
  `fee` from `block_template->getTxFees()`; `sigops` from
  `block_template->getTxSigops()` divided by `WITNESS_SCALE_FACTOR` on
  pre-segwit chains; `weight` from `GetTransactionWeight(tx)`.
- `bitcoin-core/src/rpc/mining.cpp:1007-1019` — pre-segwit-aware
  GBT field shaping: `sigoplimit = MAX_BLOCK_SIGOPS_COST` then divided
  by 4 if `fPreSegWit`; `sizelimit = MAX_BLOCK_SERIALIZED_SIZE = 4_000_000`
  then divided by 4 if `fPreSegWit`; `weightlimit = MAX_BLOCK_WEIGHT`
  **only emitted when post-segwit**.
- `bitcoin-core/src/rpc/mining.cpp:970-989` — `setClientRules`:
  for every vbavailable/locked_in/active rule not in the client's
  declared capabilities, either clear the bit in `block.nVersion` (for
  optional rules) or throw `RPC_INVALID_PARAMETER` (for mandatory rules
  like `!segwit`).
- `bitcoin-core/src/primitives/transaction.h` — `CTxIn::MAX_SEQUENCE_NONFINAL
  = 0xFFFFFFFE` (timelock-enforcing); `SEQUENCE_FINAL = 0xFFFFFFFF`
  (bypass).

**Files audited**
- `internal/mining/mining.go` — `TemplateGenerator.GenerateTemplate`
  (lines 142-294), `selectTransactions` (lines 311-400),
  `computeTxSigOpsCost` (lines 411-435), `CreateCoinbaseTx`
  (lines 438-494), `serializeBlockHeight` (lines 498-513),
  `scriptNumSerialize` (lines 517-546), `BlockMiner.GenerateBlock`
  (lines 611-690), `mineBlock` (lines 693-707),
  `UpdateCoinbaseWitnessCommitment` (lines 710-725); package
  constants `DefaultBlockReservedWeight=8000`,
  `MinimumBlockReservedWeight=2000`, `blockFullEnoughWeightDelta=4000`,
  `maxConsecutiveFailures=1000`, `coinbaseMaxSequenceNonfinal=0xFFFFFFFE`.
- `internal/rpc/methods.go` — `handleGetBlockTemplate`
  (lines 1660-1794), `handleGenerateToAddress` (lines 2990-3064),
  `handleGenerateToDescriptor` (lines 3066-3146),
  `handleGenerateBlock` (lines 3148-3338), `handleGenerate`
  (lines 3335-3343 deprecated stub), `createBlockMiner`
  (lines 3344-3357), `bip22ResultString` (lines 1800-1887).
- `internal/rpc/types.go` — `BlockTemplateResult` shape
  (lines 452-473), `BlockTemplateTx` shape (lines 475-484),
  `GenerateBlockResult` (lines 549-553).
- `internal/rpc/server.go:613-628` — RPC dispatch for `getblocktemplate`,
  `submitblock`, `submitblockbatch`, `generatetoaddress`,
  `generatetodescriptor`, `generateblock`, `generate`.
- `internal/consensus/params.go:4-132` — `MaxBlockWeight=4_000_000`,
  `WitnessScaleFactor=4`, `MaxBlockSigOpsCost=80_000`,
  `SubsidyHalvingInterval=210_000` (package const),
  `InitialSubsidy=50*SatoshiPerBitcoin`, `CoinbaseMaturity=100`,
  `MaxTimewarp=600`, `MaxBlockSize=1_000_000` (legacy pre-segwit cap).
- `internal/consensus/difficulty.go:162-170` — `CalcBlockSubsidy(height
  int32) int64` (reads PACKAGE const, NOT params — W145 BUG-1
  carry-forward).
- `internal/consensus/chaincfg.go:22, 319` — `ChainParams.SubsidyHalvingInterval`
  field (regtest sets 150, ignored by `CalcBlockSubsidy`).
- `internal/consensus/merkle.go:7-107` — `CalcMerkleRoot` (wrapper
  drops mutated flag), `CalcMerkleRootMutation`,
  `CalcWitnessMerkleRoot`, `CalcWitnessCommitment` (uses `CalcMerkleRoot`,
  not the mutation-aware path).
- `internal/consensus/versionbits.go:375-394` — `ComputeBlockVersion`.
- `internal/wire/types.go:220-225` — `MsgTx.Version int32` (W132 BUG-1
  carry-forward — block-template coinbase hard-codes `Version: 2`).
- `internal/wire/types.go:446-454` — `BlockHeader.Version int32`.
- `internal/mempool/mempool.go:436-450, 2082-2113` —
  `TxEntry.AncestorFeeRate` / `GetSortedByAncestorFeeRate`
  (vbyte-based, not weight-based; selection uses individual rate not
  package).
- `internal/mempool/mempool.go:1110-1128` — coinbase-maturity admit
  gate (`tipHeight - utxo.Height < CoinbaseMaturity` — W150 BUG-9
  off-by-one carry-forward).
- `cmd/blockbrew/main.go` — `parseFlags` (no `-blockmaxweight`,
  no `-blockmintxfee`, no `-blockreservedweight`,
  no `-blockversion` regtest override).

---

## Gate matrix (33 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR | G1: `MaxBlockWeight = 4_000_000` | PASS (`params.go:9`) |
| 1 | … | G2: `WitnessScaleFactor = 4` | PASS (`params.go:12`) |
| 1 | … | G3: `MaxBlockSigOpsCost = 80_000` | PASS (`params.go:15`) |
| 1 | … | G4: `MaxBlockSize = 1_000_000` (pre-segwit) | PASS (`params.go:6`) |
| 2 | Reserved weight | G5: `DefaultBlockReservedWeight = 8000` | PASS (`mining.go:23`) |
| 2 | … | G6: `MinimumBlockReservedWeight = 2000` (lower clamp) | PARTIAL — constant defined (`mining.go:24`) but `ClampOptions` analogue is absent; the value is **dead** (zero call sites) |
| 2 | … | G7: `DEFAULT_BLOCK_MAX_WEIGHT = MAX - DEFAULT_BLOCK_RESERVED_WEIGHT` (default 3_992_000 usable) | PARTIAL — derived correctly inside `GenerateTemplate` (`mining.go:222`) but there is **no `-blockmaxweight` operator override** |
| 3 | addPackageTxs / addChunks | G8: package (chunk) feerate selection | **BUG-1 (P0)** — `selectTransactions` walks individual TxEntry's sorted by `AncestorFeeRate` and applies `entry.FeeRate < minFeeRate` (individual rate); chunks are not pulled as atomic units, so a high-feerate CPFP child that appears **before** its lower-feerate parent in the sort is permanently **dropped** rather than included with the parent. Cross-cite Core `addChunks` at `miner.cpp:279-334` |
| 3 | … | G9: `MAX_CONSECUTIVE_FAILURES=1000` early-exit | PASS (`mining.go:26, 338-340`) |
| 3 | … | G10: `BLOCK_FULL_ENOUGH_WEIGHT_DELTA=4000` predicate | PASS (`mining.go:25, 339`) |
| 3 | … | G11: `IsFinalTx(tx, nHeight, MTP)` per chunk | PASS (`mining.go:364`) |
| 4 | GenerateCoinbaseCommitment (BIP-141) | G12: OP_RETURN + 0xaa21a9ed magic | PASS (`mining.go:480-484`) |
| 4 | … | G13: commitment hash = SHA256d(witnessRoot ‖ reservedValue) | PASS (`merkle.go:98-107`) |
| 4 | … | G14: witness reserved value pushed onto coinbase witness | PASS (`mining.go:490`, 32 zero bytes) |
| 4 | … | G15: commitment NOT regenerated on tx-list replacement (RegenerateCommitments analogue) | **BUG-2 (P0)** — `handleGenerateBlock` replaces `block.Transactions[1:]` with user-supplied txs but does NOT recompute the coinbase output value (`subsidy + fees` left over from the **mempool** template, never adjusted to the actual fees of the supplied txs). The resulting block fails `bad-cb-amount`. Same shape in `BlockMiner.GenerateBlock` |
| 5 | BlockMerkleRoot / BlockWitnessMerkleRoot | G16: BlockMerkleRoot uses CVE-2012-2459-aware path | **BUG-3 (P0-CDIV cross-cite)** — `CalcMerkleRoot` calls `CalcMerkleRootMutation` and discards the `mutated` flag (`merkle.go:17-20`). `CalcWitnessCommitment` then re-uses `CalcMerkleRoot` (`merkle.go:98-107`), so the template's witness commitment is computed without ever checking for mutated trees. Same root-cause as W142 fleet-wide finding |
| 5 | … | G17: coinbase wtxid forced to zero in witness merkle | PASS (`merkle.go:90`) |
| 6 | mintime (BIP-113 + BIP-94) | G18: parent MTP + 1 | PASS (`mining.go:272`) |
| 6 | … | G19: at retarget boundary, max(MTP+1, prev.time − MAX_TIMEWARP) on ALL networks (Core "future activation safer") | **BUG-4 (P1-CDIV)** — gated on `tg.chainParams.EnforceBIP94` (`mining.go:273-279`), which is false on mainnet/testnet3/signet. Core applies BIP-94 timewarp clamp **unconditionally** (`miner.cpp:43`). Mainnet GBT under-reports `mintime` at every 2016-block boundary; downstream pool software relying on `mintime` may build blocks Core would reject |
| 7 | ComputeBlockVersion (BIP-9 / BIP-320) | G20: `VERSIONBITS_TOP_BITS (0x20000000)` + signaling bits for STARTED/LOCKED_IN deployments | PASS (`mining.go:157`, `versionbits.go:378-394`) |
| 7 | … | G21: GBT `setClientRules` clears unsupported optional bits + throws on unsupported mandatory rules | **BUG-5 (P1-CDIV)** — `handleGetBlockTemplate` ignores the `template_request` JSON entirely; capabilities/rules from the caller are never parsed (`methods.go:1660-1672`). A non-segwit-aware miner that called with no `rules` field gets a segwit-active template and silently produces an invalid block. Core throws `RPC_INVALID_PARAMETER` for unsupported mandatory rules |
| 8 | coinbase scriptSig length | G22: scriptSig length 2..100 bytes post-BIP-34 | PARTIAL — `CreateCoinbaseTx` always appends 8-byte extraNonce (`mining.go:443-449`), so the minimum length is 9 bytes (above the 2-byte floor). But there is **no enforcement against the upper 100-byte cap** — a caller passing a 100-byte `extraNonce` plus the BIP-34 height push (≥2 bytes) trips `bad-cb-length` on submit |
| 8 | … | G23: BIP-34 `CScript() << nHeight` prefix | PASS (`serializeBlockHeight` at `mining.go:498-513` matches Core's `CScript()<<int` encoding for height 0..16 → OP_N opcode, ≥17 → `[len][LE]`) |
| 8 | … | G24: `nLockTime = nHeight - 1` | PASS (`mining.go:457-460`) |
| 8 | … | G25: `nSequence = MAX_SEQUENCE_NONFINAL = 0xFFFFFFFE` | PASS (`mining.go:34, 469`) |
| 9 | nVersion regtest override | G26: regtest-only `-blockversion=N` operator override | **BUG-6 (P2)** — Core `miner.cpp:143-145` lets `-blockversion` override `ComputeBlockVersion` on `MineBlocksOnDemand` networks (regtest/signet test). blockbrew has no `-blockversion` flag at all (`parseFlags` does not register it). Regtest scenarios that need a specific block version cannot use the GBT path |
| 10 | GBT reserved weight + sigops headroom | G27: GBT-side `nBlockSigOpsCost` starts at `coinbase_output_max_additional_sigops` | **BUG-7 (P2)** — `selectTransactions` starts `totalSigOps = 0` (`mining.go:317`) instead of reserving for the coinbase output. Real coinbases typically use 1-2 sigops; under-reservation pushes the block ~4 sigops over the 80k cap in pathological cases. Off-by-tiny in practice but distinct from Core |
| 10 | … | G28: `-blockreservedweight` operator override | **BUG-8 (P1)** — no flag registered (`parseFlags` lacks it); `DefaultBlockReservedWeight=8000` is hard-coded with no override hook. Same hard-code shape as W149's `MinBlocksToKeep` |
| 10 | … | G29: `-blockmaxweight` operator override | **BUG-8 cross-cite** — no flag registered |
| 10 | … | G30: `-blockmintxfee` operator override | **BUG-8 cross-cite** + **BUG-9 (P1)** — `MinTxFeeRate` defaults to `0.0` (`TemplateConfig.MinTxFeeRate`); Core defaults to `DEFAULT_BLOCK_MIN_TX_FEE=1` sat/kvB. blockbrew miners pay zero floor by default, accepting **dust-rate** txs that Core would skip |
| 11 | package-feerate-not-individual-feerate | G31: per-tx threshold compares package feerate (`entry.AncestorFeeRate`) | **BUG-10 (P1)** — line 327 compares `entry.FeeRate` (individual) not `entry.AncestorFeeRate`. Comment at line 296-310 claims "ancestor fee rate algorithm (CPFP-aware)" — **comment-as-confession** mismatched against code |
| 11 | … | G32: `nTime` source uses `GetAdjustedTime` / `NodeClock` (mockable for tests) | **BUG-11 (P2)** — `mining.go:161` uses raw `time.Now().Unix()`; Core uses `NodeClock::now()` which is mockable via `SetMockTime` / `MockableClock`. Regtest tests that want deterministic timestamps via mock-time cannot |
| 11 | … | G33: BlockAssembler runs `TestBlockValidity(check_pow=false, check_merkle_root=false)` on the template before returning | **BUG-12 (P1)** — no `TestBlockValidity` analogue. A template with a structural defect (e.g. sigop over-count missed by `computeTxSigOpsCost`) is returned to the miner; the rejection only surfaces at `submitblock` after the miner burned hashes |

---

## BUG-1 (P0) — `selectTransactions` is per-tx, not per-package (chunk); CPFP children dropped if sorted before parent

**Severity:** P0 (revenue-loss / Core-divergence on package mining).
Bitcoin Core's `addChunks` (`node/miner.cpp:279-334`) pulls
**clusters** (linearised packages) from the mempool via
`GetBlockBuilderChunk()` and either includes the entire chunk as one
atomic unit or skips it. This is what makes CPFP work for block
construction: a child paying enough extra to cover its lower-feerate
parent gets included **with** the parent.

blockbrew iterates individual `TxEntry`s sorted by `AncestorFeeRate`
(`mining.go:312-397`). When a high-feerate CPFP child appears in the
sort **before** its parent (which has a lower individual feerate, even
though its ancestor feerate is artificially boosted by the descendant —
note this is NOT the descendant feerate path), the child fails the
`allParentsIncluded` check and is **skipped**. The parent appears later
and is included on its own individual feerate. The child is never
revisited.

The mempool sort key is `AncestorFeeRate = AncestorFee / AncestorSize`
(`mempool.go:436-442`). A child's `AncestorFee` includes its parents'
fees, so a high-fee child does pull its parents up in the ordering, but
the sort does NOT guarantee parent-before-child within an equal-rate
package. Even when it does, the **per-tx feerate filter** at line 327
(`entry.FeeRate < minFeeRate`) can drop a low-individual-rate parent
that the package-rate inclusion would have kept.

**File:** `internal/mining/mining.go:311-400`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:279-334`.

**Excerpt (blockbrew, dropped-child shape)**
```go
for _, entry := range entries {                       // sorted by AncestorFeeRate
    if entry.FeeRate < minFeeRate { continue }         // individual rate filter
    // ...
    for _, dep := range entry.Depends {
        if !included[dep] { allParentsIncluded = false }
    }
    if !allParentsIncluded {
        consecutiveFailed++
        continue                                       // CHILD SKIPPED, never retried
    }
```

**Impact:**
- Revenue loss on every block where mempool contains CPFP packages;
  the miner leaves money on the table proportional to the dropped
  childrens' fee delta.
- Cross-impl divergence: the same mempool state produces a strictly
  lower-fee block in blockbrew than in Core, observable via
  `getblocktemplate.coinbasevalue` diff against a Core node.
- Fleet pattern: this is the same shape as the W153/W152 "individual
  vs package-feerate" finding tracked elsewhere — first explicit BUG
  filing inside the BlockAssembler.

---

## BUG-2 (P0) — `handleGenerateBlock` does not recompute coinbase value after replacing txs; produces `bad-cb-amount`

**Severity:** P0. `handleGenerateBlock` (`methods.go:3148-3338`) and
`BlockMiner.GenerateBlock(txs)` (`mining.go:611-690`) both follow the
same shape:

1. Generate template from the **mempool** (`tg.GenerateTemplate(...)`).
2. Keep the coinbase, REPLACE `block.Transactions[1:]` with the
   caller's `txs`.
3. Recompute `MerkleRoot` and witness commitment.
4. Mine the block.

But the coinbase's `TxOut[0].Value` was set inside `CreateCoinbaseTx`
to `subsidy + totalFees` where `totalFees` came from the **mempool
selection in step 1**, not from the caller's `txs`. When the caller
passes a different tx set, the fees are different, but the coinbase
still pays the mempool-template fee total.

If caller's txs pay LESS than the mempool template, the coinbase
over-pays and the block is rejected with `bad-cb-amount`. If MORE,
the miner under-pays themselves but the block is still valid (Core
allows under-claiming the subsidy; the unclaimed amount is burned).

**File:** `internal/mining/mining.go:626-658` (`BlockMiner.GenerateBlock`
`txs != nil` branch); `internal/rpc/methods.go:3246-3270`
(`handleGenerateBlock`).

**Core ref:** `bitcoin-core/src/node/miner.cpp:67-77`
(`RegenerateCommitments` — but Core's `generateblock` actually
constructs the coinbase from scratch with the supplied tx set's fee
total; see `rpc/mining.cpp::generateblock`).

**Excerpt (blockbrew, missing fee-recompute)**
```go
// handleGenerateBlock — methods.go:3246
// Replace transactions with the provided ones
coinbase := block.Transactions[0]
block.Transactions = make([]*wire.MsgTx, 0, len(txs)+1)
block.Transactions = append(block.Transactions, coinbase)
block.Transactions = append(block.Transactions, txs...)

// Recalculate merkle root
// ... (no fee recomputation; coinbase.TxOut[0].Value untouched)
```

**Impact:**
- `generateblock <addr> []` (empty tx list, mempool has txs) → coinbase
  pays the mempool fee total, but no fee txs are in the block → block
  fails `bad-cb-amount` and the RPC returns an error.
- `generateblock <addr> ["txid_a"]` (one tx, mempool also has txs with
  different fees) → coinbase pays the WRONG fee total → block fails
  `bad-cb-amount`.
- Test-suite impact: `regtest` `generateblock` tests that pre-stage
  the mempool then call `generateblock` with a specific tx subset
  hit this bug.

---

## BUG-3 (P0-CDIV cross-cite W142 fleet) — `CalcWitnessCommitment` uses mutation-blind merkle root

**Severity:** P0-CDIV. Bitcoin Core's `BlockWitnessMerkleRoot`
(`consensus/merkle.cpp`) returns the witness merkle root with a
`mutated` out-parameter so the caller can distinguish CVE-2012-2459
duplicate-leaf attacks from genuine merkle mismatches. Validation paths
treat `mutated == true` as a **transient** block error (must reject
without permanently marking invalid).

blockbrew's `CalcMerkleRoot` (`merkle.go:17-20`) explicitly drops
the mutated flag:

```go
func CalcMerkleRoot(hashes []wire.Hash256) wire.Hash256 {
    root, _ := CalcMerkleRootMutation(hashes)   // mutated flag discarded
    return root
}
```

`CalcWitnessCommitment` (`merkle.go:95-107`) calls
`CalcWitnessMerkleRoot` which in turn calls `CalcMerkleRoot` — so the
template's witness commitment is computed against a mutation-blind
merkle root. The validation-side helper is also affected (see W142
audit for fleet-wide context).

On the **mining side specifically**, this means the template generator
will silently produce a valid-looking commitment even for a mutated
witness merkle tree. An adversary controlling the mempool ordering
could in principle stage txs that cause the witness merkle to mutate
in a way that flips the wtxid in the coinbase commitment but not the
on-wire tree — both forms produce the same block hash but only one is
"the real one" per Core's distinction.

**File:** `internal/consensus/merkle.go:17-20, 95-107`.

**Core ref:** `bitcoin-core/src/consensus/merkle.cpp:46-63`,
`bitcoin-core/src/validation.cpp::CheckWitnessMalleation`.

**Cross-cite:** W142 BUG-x fleet-wide CVE-2012-2459 finding (6+ impls
confirm — first blockbrew BlockAssembler-side instance).

**Impact:** parity / defence-in-depth gap; not exploitable on its own
in production today because the validation side ALSO drops the flag
(matching bug), but the fix surface is **two-pipeline-wide**: every
caller of `CalcMerkleRoot` is silently CVE-2012-2459-blind.

---

## BUG-4 (P1-CDIV) — BIP-94 timewarp clamp gated on `EnforceBIP94`; Core applies unconditionally

**Severity:** P1-CDIV. Bitcoin Core `node/miner.cpp:36-47` applies the
BIP-94 timewarp clamp on **all networks** at every retarget boundary,
explicitly commenting "Account for BIP94 timewarp rule on all networks.
This makes future activation safer":

```cpp
int64_t GetMinimumTime(const CBlockIndex* pindexPrev,
                       const int64_t difficulty_adjustment_interval) {
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    const int height{pindexPrev->nHeight + 1};
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time,
                                     pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}
```

blockbrew's `GenerateTemplate` (`mining.go:269-279`) gates the clamp
on `tg.chainParams.EnforceBIP94`:

```go
minTime := mtp + 1
if tg.chainParams.EnforceBIP94 &&
   newHeight%int32(tg.chainParams.DifficultyAdjInterval) == 0 {
    timeWarpMin := int64(tipNode.Header.Timestamp) - consensus.MaxTimewarp
    if timeWarpMin > minTime { minTime = timeWarpMin }
}
```

`EnforceBIP94` is **only** set for testnet4. On mainnet, testnet3 and
signet the GBT `mintime` field can therefore be **lower** than Core's,
which means: a pool whose template-builder honours `mintime` exactly
will produce blocks Core would reject at retarget boundaries (when
the wall-clock has fallen behind `prev.time - 600s`).

**File:** `internal/mining/mining.go:269-279`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`.

**Impact:**
- Mainnet pool divergence at every 2016-block boundary if the
  template-builder is behind on wall-clock; downstream miners can
  construct blocks that Core rejects.
- Cross-impl divergence: `getblocktemplate.mintime` is non-identical
  between blockbrew and Core on mainnet at retarget boundaries.

---

## BUG-5 (P1-CDIV) — `getblocktemplate` ignores `template_request`; no `setClientRules` enforcement

**Severity:** P1-CDIV. Bitcoin Core's GBT (`rpc/mining.cpp:626-664`)
parses the JSON `template_request` argument:

- `mode` — `"template"`, `"proposal"`, or `"longpoll"`.
- `capabilities[]` — client-supported features (`"longpoll"`,
  `"coinbasevalue"`, `"proposal"`, etc.).
- `rules[]` — client-supported softfork rules (`"segwit"`, `"taproot"`,
  `"signet"`, …).
- `longpollid` — for longpoll mode.

Then `rpc/mining.cpp:970-989` enforces: for each `vbavailable`,
`locked_in`, or `active` rule **not** in `setClientRules`, either
- clear the bit in `block.nVersion` (optional rule), or
- throw `RPC_INVALID_PARAMETER` (mandatory rule like `!segwit`).

blockbrew's `handleGetBlockTemplate` (`methods.go:1660-1794`) discards
the JSON argument entirely:

```go
func (s *Server) handleGetBlockTemplate(params json.RawMessage) (interface{}, *RPCError) {
    if s.templateGen == nil { ... }
    config := mining.TemplateConfig{ MinerAddress: nil }   // <-- no params used
    template, err := s.templateGen.GenerateTemplate(config)
    // ...
```

Consequences:
- A non-segwit-aware miner that does not include `"segwit"` in `rules`
  still receives a segwit-active template (segwit bit set, witness
  commitment included). It silently mines an invalid block.
- `longpoll` mode is not supported at all (no `longpollid` field
  emitted; see BUG-13).
- `proposal` mode (validate-only) not supported.
- `mode = "proposal"` (Core uses this for `submitblock`-style template
  validation) silently behaves as `mode = "template"`.

**File:** `internal/rpc/methods.go:1660-1672`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:626-664, 970-989`.

**Impact:**
- Non-segwit pool software (rare today, but exists for testing /
  embedded) silently produces invalid blocks.
- Pool software expecting `longpollid` cannot use blockbrew without
  custom adaptation.
- Spec divergence: Bitcoin Core throws for unsupported mandatory
  rules; blockbrew never does.

---

## BUG-6 (P2) — `-blockversion` regtest override not exposed

**Severity:** P2. Bitcoin Core `node/miner.cpp:143-145` lets regtest /
test scenarios override the computed block version with
`-blockversion=N`:

```cpp
if (chainparams.MineBlocksOnDemand()) {
    pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
}
```

blockbrew's `parseFlags` (`cmd/blockbrew/main.go`) does not register
`-blockversion`. Regtest tests that want to construct a specific
version (e.g. to test BIP-9 signalling thresholds) cannot use the
GBT path.

**File:** `cmd/blockbrew/main.go::parseFlags` (no `-blockversion`).

**Core ref:** `bitcoin-core/src/node/miner.cpp:143-145`.

**Impact:** test-ergonomics on regtest; no consensus risk.

---

## BUG-7 (P2) — `nBlockSigOpsCost` starts at 0, not at `coinbase_output_max_additional_sigops`

**Severity:** P2. Bitcoin Core `node/miner.cpp:111-120` initialises
the sigops counter in `resetBlock` with:

```cpp
nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops;
```

The default `coinbase_output_max_additional_sigops = 400` (it accounts
for the worst-case witness commitment + miner-script sigops). blockbrew's
`selectTransactions` starts `totalSigOps = 0` (`mining.go:317`). Real
coinbases use 1-2 sigops (OP_RETURN commitment + miner script
P2PKH/P2WPKH/etc.) so the under-reservation is small in practice, but
a pathological miner-script with many CHECKSIG opcodes plus heavy
mempool sigop pressure can push the block over the 80k cap.

**File:** `internal/mining/mining.go:317`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:115`.

**Impact:** ~4-sigops under-reservation. Rare consensus rejection
window on heavy-sigops mempools.

---

## BUG-8 (P1) — `-blockmaxweight`, `-blockreservedweight`, `-blockmintxfee` operator knobs absent

**Severity:** P1 ("operator-knob absent" fleet pattern, 5th blockbrew
instance). Bitcoin Core lets operators tune block-template construction
via:
- `-blockmaxweight=N` — override `nBlockMaxWeight` (default
  `DEFAULT_BLOCK_MAX_WEIGHT = MAX_BLOCK_WEIGHT = 4_000_000`).
- `-blockreservedweight=N` — override `block_reserved_weight` (default
  8000, clamped to `[MINIMUM_BLOCK_RESERVED_WEIGHT=2000, MAX_BLOCK_WEIGHT]`).
- `-blockmintxfee=<amount>` — override `blockMinFeeRate` (default 1
  sat/kvB).
- `-printpriority` — toggle the per-tx fee-rate log line.

blockbrew's `parseFlags` registers none of these. `TemplateConfig`
accepts `MaxWeight`/`MaxSigOpsCost`/`MinTxFeeRate` fields but they
are never populated from CLI flags — only by direct programmatic
callers (which there are none of in `cmd/blockbrew`).

**File:** `cmd/blockbrew/main.go::parseFlags`,
`internal/mining/mining.go:58-65, 142-235`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:98-109`
(`ApplyArgsManOptions`).

**Impact:** operators cannot tune block construction; defaults are
the only behaviour. Pool operators who customise these on Core would
have to fork blockbrew.

---

## BUG-9 (P1) — `MinTxFeeRate` defaults to 0.0 instead of Core's `DEFAULT_BLOCK_MIN_TX_FEE = 1` sat/kvB

**Severity:** P1. Bitcoin Core's default `blockMinFeeRate` is 1
sat/kvB (`policy/policy.h:36`), meaning chunks below 1 sat/kvB are
skipped. blockbrew's `handleGetBlockTemplate` (`methods.go:1666`)
constructs `mining.TemplateConfig{MinerAddress: nil}` with
`MinTxFeeRate` defaulting to the zero value (`0.0`). `selectTransactions`
then runs `if entry.FeeRate < minFeeRate { continue }` which becomes
`if FeeRate < 0`. Effectively no floor.

blockbrew miners will pack the block with dust-rate txs that Core would
have skipped, wasting block weight on minimum-feerate inclusions.

**File:** `internal/rpc/methods.go:1666-1668`,
`internal/mining/mining.go:60, 327`.

**Core ref:** `bitcoin-core/src/policy/policy.h:36`.

**Impact:** revenue divergence; blockbrew GBT templates are not
byte-equivalent to Core's even on identical mempools because of the
floor.

---

## BUG-10 (P1) — Per-tx filter uses individual feerate, not package (ancestor) feerate

**Severity:** P1. `selectTransactions` sorts by `AncestorFeeRate`
(via `mp.GetSortedByAncestorFeeRate()`) but then filters with
`entry.FeeRate < minFeeRate` (individual rate) at line 327. Core's
`addChunks` filters on `chunk_feerate` (package rate) at
`miner.cpp:298`. This is the same bug class as BUG-1 from the other
angle: parents whose individual rate is below `minFeeRate` but whose
package rate (with high-fee children) is above are erroneously
skipped, **dropping the entire package** including the children.

The function header comment claims "ancestor fee rate algorithm
(CPFP-aware)" — but the operational filter is individual rate.
Comment-as-confession fleet pattern (~9th distinct blockbrew instance
per audit tracking).

**File:** `internal/mining/mining.go:296-310` (comment), 327 (code).

**Core ref:** `bitcoin-core/src/node/miner.cpp:298`.

**Impact:** package-feerate-blind selection; revenue loss on every
block with CPFP packages.

---

## BUG-11 (P2) — `nTime` uses raw `time.Now().Unix()`, not a mockable clock

**Severity:** P2. Bitcoin Core uses `NodeClock::now()` for the
template timestamp (`miner.cpp:147`), which is mockable via
`SetMockTime` for test scenarios. blockbrew uses
`time.Now().Unix()` (`mining.go:161`) — there is no `MockableClock`
analogue in the consensus or mining package.

Regtest scenarios that want deterministic block timestamps (e.g.
to test BIP-113 boundary behaviour, BIP-94 timewarp activation, or
difficulty-retarget edge cases) cannot use mock time. Tests must
instead pass through real wall-clock and rely on `mining.go:168-170`
clamping the timestamp upward against MTP — which masks but does not
fix the test ergonomics gap.

**File:** `internal/mining/mining.go:161`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:147`,
`bitcoin-core/src/util/time.cpp::NodeClock`.

**Impact:** test-ergonomics; not a consensus bug. Also: `uint32(time.Now().Unix())`
will wrap in year 2106 — same Y2106 marker as W148 finding.

---

## BUG-12 (P1) — No `TestBlockValidity` analogue; structural template defects only surface at submit

**Severity:** P1. Bitcoin Core `node/miner.cpp:223-228` runs
`TestBlockValidity(m_chainstate, *pblock, check_pow=false,
check_merkle_root=false)` on every assembled template before returning
it. This catches structural defects (sigop over-count, tx-weight cap
breach, BIP-141 commitment shape, etc.) **before** the miner burns
hashes.

blockbrew's `GenerateTemplate` returns the assembled block without
any structural revalidation. A defect introduced by a buggy
`computeTxSigOpsCost` estimate (e.g. when `utxoView == nil` and the
output-only-sigops path under-counts a tx) means the miner finds a
valid nonce, calls `submitblock`, and is rejected — wasting all the
hashing work in between.

**File:** `internal/mining/mining.go:142-294` (no test-validity step
before return).

**Core ref:** `bitcoin-core/src/node/miner.cpp:223-228`.

**Impact:** wasted mining work on defective templates; cross-impl
divergence in the "did the template build cleanly" signal pool
software relies on.

---

## BUG-13 (P1-CDIV) — GBT response missing `capabilities`, `longpollid`, signet `signet_challenge`

**Severity:** P1-CDIV. Core's GBT response (rpc/mining.cpp:947-1023)
emits:
- `capabilities` — server-supported features (`["proposal"]` for Core).
- `longpollid` — `tip.GetHex() + ToString(nTransactionsUpdatedLast)`
  for longpoll subscription.
- `signet_challenge` — signet challenge script (when applicable).
- `signet_target` — signet PoW target (when applicable).

blockbrew's `BlockTemplateResult` (`types.go:452-473`) defines none
of these fields. Pool software that subscribes to longpoll for tip
notification cannot use blockbrew (no `longpollid` → cannot construct
the next request). Signet miners cannot get the signet challenge.

**File:** `internal/rpc/types.go:452-473`,
`internal/rpc/methods.go:1770-1793`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:948, 1002, 1024-1040`.

**Impact:** missing fields → pool-software incompatibility; signet
mining unsupported.

---

## BUG-14 (P1-CDIV) — GBT `sizelimit` always `MaxBlockSize = 1_000_000`; Core emits 4_000_000 post-segwit

**Severity:** P1-CDIV. Core `rpc/mining.cpp:1007-1019`:

```cpp
int64_t nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE;  // 4_000_000
if (fPreSegWit) {
    nSizeLimit /= WITNESS_SCALE_FACTOR;          // → 1_000_000
}
result.pushKV("sizelimit", nSizeLimit);
```

Similarly `sigoplimit = MAX_BLOCK_SIGOPS_COST` (80000) divided by 4
pre-segwit. And `weightlimit` is **only emitted** when post-segwit
(`if (!fPreSegWit) result.pushKV("weightlimit", MAX_BLOCK_WEIGHT)`).

blockbrew's `handleGetBlockTemplate` (`methods.go:1786-1788`) emits:
```go
SigOpLimit:  consensus.MaxBlockSigOpsCost,    // always 80000
SizeLimit:   consensus.MaxBlockSize,          // always 1_000_000
WeightLimit: consensus.MaxBlockWeight,        // always 4_000_000
```

Post-segwit (mainnet h≥481824) blockbrew under-reports `sizelimit`
by a factor of 4 (1 MB vs 4 MB). A pool computing
`sizelimit - blockSize` to know how much room remains will think the
block is full at 1 MB and stop adding txs.

Pre-segwit (theoretical / regtest with `SegwitHeight > 0`)
blockbrew over-reports `sigoplimit` by a factor of 4 (80k vs 20k).

**File:** `internal/rpc/methods.go:1786-1788`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1007-1019`.

**Impact:** GBT consumer divergence; under-utilisation of post-segwit
block weight; over-utilisation of pre-segwit sigops budget.

---

## BUG-15 (P1) — GBT per-tx `Depends[]` always empty

**Severity:** P1. Core `rpc/mining.cpp:917-923` builds `depends[]` by
scanning each tx's inputs against the in-template `setTxIndex` map:

```cpp
UniValue deps(UniValue::VARR);
for (const CTxIn &in : tx.vin) {
    if (setTxIndex.contains(in.prevout.hash))
        deps.push_back(setTxIndex[in.prevout.hash]);
}
entry.pushKV("depends", std::move(deps));
```

blockbrew hard-codes empty (`methods.go:1695`):
```go
Depends: []int{}, // Simplified
```

Pool software uses `depends[]` to ensure parents are included before
children when assembling the final block from the template; an empty
list misleads the pool into thinking every tx is independent.

**File:** `internal/rpc/methods.go:1695`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:917-923`.

**Impact:** pool-software incompatibility; CPFP packages that DO get
into the template are reported as independent, so downstream pools
that drop low-feerate txs without checking dependencies could break
the package.

---

## BUG-16 (P0) — GBT per-tx `Fee` always 0; pool software has no fee data

**Severity:** P0. Core emits `fee` (the absolute fee in satoshis) for
every tx in the template (`mining.cpp:926`). blockbrew hard-codes 0
(`methods.go:1696`):

```go
Fee: 0, // Would need fee tracking per tx
```

`BlockTemplate` does carry `Fees int64` (total fees) and
`TxSigOpsCost []int64` (per-tx sigops), but not per-tx fees. The
comment is a **comment-as-confession** (fleet pattern, ~10th distinct
blockbrew instance).

Pool software that re-orders or drops txs based on individual fee
values cannot operate against blockbrew. Some pools that pay miners
proportional to in-block fees would also misreport.

**File:** `internal/rpc/methods.go:1696`,
`internal/mining/mining.go:36-56` (`BlockTemplate` struct lacks
`TxFees []int64`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:899, 926`.

**Impact:** pool incompatibility; coinbase fee data correct in
aggregate (`coinbasevalue`) but per-tx unavailable.

---

## BUG-17 (P0-CDIV carry-forward W145) — `CalcBlockSubsidy` ignores `params.SubsidyHalvingInterval`

**Severity:** P0-CDIV (carry-forward; W145 BUG-1 has been open since
W123 ~3 weeks ago and is now confirmed still in place inside
BlockAssembler).

`mining.go:237` calls `consensus.CalcBlockSubsidy(newHeight)`, which
at `difficulty.go:162-170` reads the **package-level constant**
`SubsidyHalvingInterval = 210_000` (params.go:27) — NOT the per-network
`ChainParams.SubsidyHalvingInterval` field. Regtest sets the field to
`150` (chaincfg.go:319) — completely **dead data**:

```go
// chaincfg.go regtest block:
SubsidyHalvingInterval: 150, // Faster halving for testing
```

```go
// difficulty.go:162 — reads PACKAGE const, not params
func CalcBlockSubsidy(height int32) int64 {
    halvings := height / SubsidyHalvingInterval  // <-- 210_000, always
    ...
}
```

**On regtest**, BlockAssembler at height 150 should pay 25 BTC (1
halving). It instead pays 50 BTC. The template's `coinbasevalue` is
2× too high; the assembled block is rejected at validation with
`bad-cb-amount`. **Regtest mining is silently broken past h=150.**

This is W145 BUG-1 + BUG-14 (dead field + wrong-constant) confirmed
still in place in the BlockAssembler flow.

**File:** `internal/consensus/difficulty.go:162-170`,
`internal/consensus/chaincfg.go:319` (dead regtest field).

**Core ref:** `bitcoin-core/src/validation.cpp::GetBlockSubsidy`
(takes `const Consensus::Params&` not a constant).

**Carry-forward age:** open since W123 (~3 weeks). Now also tracked
inside the mining flow (this audit).

**Impact:**
- Regtest mining broken past h=150 (every regtest fixture that crosses
  150 blocks fails).
- Same shape will appear if any future network ships a different
  halving interval (e.g. signet variants).
- Cross-cite: this audit's BUG-17 + W145's BUG-1 are the same bug
  surfaced in two places.

---

## BUG-18 (P2-CDIV carry-forward W150) — Mempool coinbase-maturity off-by-one tightens BlockAssembler eligibility

**Severity:** P2-CDIV (carry-forward; W150 BUG-9). The mempool admit
gate at `mempool.go:1110-1128` checks
`age := tipHeight - utxo.Height` and rejects on `age < 100`. The next
block built by BlockAssembler is at `newHeight = tipHeight + 1`, so
the true age in-block is `newHeight - utxo.Height`. The mempool
requires `tipHeight - utxo.Height >= 100`, i.e. tx is admitted only
when the in-block age is **>= 101**.

Core's CheckTxInputs gate is `(pindexPrev->nHeight + 1) - coin.nHeight >= 100`,
i.e. the tx is valid in-block when in-block age is **>= 100**.

Effect: blockbrew's BlockAssembler cannot include a coinbase spend
until 1 block AFTER Core would. This is a fee-loss for the miner (a
just-matured coinbase-spending tx waits an extra block), and a
divergence in the eligibility window.

**File:** `internal/mempool/mempool.go:1118-1128`.

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp::CheckTxInputs`.

**Carry-forward age:** open since W150.

**Impact:** ~1-block reduction in mempool's coinbase-spending tx
inclusion window vs Core; minor fee-loss.

---

## BUG-19 (P1) — `coinbase.scriptSig` upper bound (100 bytes) not enforced in `CreateCoinbaseTx`

**Severity:** P1. Bitcoin Core's consensus rule (validation.cpp BIP-34
+ `consensus/tx_check.cpp`) requires `coinbase.scriptSig.size() ∈ [2,
100]`. blockbrew's `CreateCoinbaseTx` (`mining.go:438-494`) constructs
the scriptSig from `heightScript + extraNonce`:

```go
scriptSig := heightScript                       // 2..10 bytes typically
if len(extraNonce) > 0 {
    scriptSig = append(scriptSig, extraNonce...)
} else {
    scriptSig = append(scriptSig, make([]byte, 8)...)
}
```

No upper-bound check. A caller passing `extraNonce` of length 96+
produces a scriptSig over the 100-byte cap → submitblock returns
`bad-cb-length`. `handleGenerateBlock` and `handleGenerateToAddress`
pass `nil` for `extraNonce` (default 8 bytes appended), so the
production RPC path is safe — but the API surface is.

**File:** `internal/mining/mining.go:443-449`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp::CheckTransaction`
(coinbase scriptSig length gate).

**Impact:** API-surface footgun; not currently triggerable via stock
RPCs but exposed via direct mining lib use.

---

## BUG-20 (P2 carry-forward W132) — `MsgTx.Version int32` used for coinbase template tx

**Severity:** P2 (carry-forward; W132 BUG-1, ~3 weeks open).
`internal/wire/types.go:221` keeps `MsgTx.Version int32`. The mining
template's coinbase (`mining.go:462`) hard-codes `Version: 2` (a
positive literal that fits cleanly in int32 either way). So this BUG
does NOT bite the mining flow today.

It WILL bite if blockbrew ever ships a flag like Core's `-blockversion`
that lets the operator set a high-bit value, or if a future BIP defines
tx-version bit 31. Tracked for fleet pattern continuity.

**File:** `internal/wire/types.go:221`,
`internal/mining/mining.go:462`.

**Core ref:** `bitcoin-core/src/primitives/transaction.h`
(`CTransaction::nVersion` is **unsigned**).

**Carry-forward age:** W132 BUG-1, ~3 weeks open.

**Impact:** none today; latent.

---

## BUG-21 (P2) — Per-tx fee accounting absent; coinbase-fee total may diverge under chunked-mempool reorderings

**Severity:** P2. `BlockTemplate` carries `Fees int64` (total) but no
`TxFees []int64` (per-tx). Combined with BUG-16 (per-tx fee in GBT is
always 0), this means:
- `coinbasevalue` is correct (computed from `totalFees` accumulator).
- GBT consumers cannot reconstruct fees per tx.
- Internally, the template generator cannot recompute coinbase value
  if the tx list is later mutated (see BUG-2).

A `TxFees []int64` parallel slice (matching `TxSigOpsCost []int64`'s
shape) would close BUG-2 + BUG-16 simultaneously.

**File:** `internal/mining/mining.go:36-56`.

**Core ref:** `bitcoin-core/src/node/miner.h::CBlockTemplate::vTxFees`.

**Impact:** structural gap underpinning BUG-2 and BUG-16.

---

## BUG-22 (P1) — `selectTransactions` does not honour BIP-68 sequence-lock (CSV)

**Severity:** P1. Core `addChunks` → `TestChunkTransactions` calls
`IsFinalTx(tx, nHeight, m_lock_time_cutoff)` per chunk — and
separately, the mempool only admits txs whose sequence-locks
(`CheckSequenceLocks`) are satisfied at the next tip. blockbrew's
`selectTransactions` calls `IsFinalTx` (lock-time, BIP-113-style) but
does **not** re-check `CheckSequenceLocks` at template-build time.
The mempool admit was correct at admission time, but if a
sequence-locked tx was admitted at tip=H-1 and the BlockAssembler
later builds for tip=H, the lock should still be satisfied — so this
is only a defence-in-depth gap, not an active consensus break.

Still: Core does run the sequence-lock check at template time too,
not just at admit time, because mempool-admit happens before tip
changes have been processed against the candidate package.

**File:** `internal/mining/mining.go:311-400` (no `CheckSequenceLocks`).

**Core ref:** `bitcoin-core/src/node/miner.cpp::CheckSequenceLocks`
in the assembler path (via `m_mempool->CheckSequenceLocks` during
chunk inclusion).

**Impact:** defence-in-depth gap; a stale-mempool admit could survive
a reorg into the template even though the new tip's MTP/height would
re-fail the CSV check.

---

## BUG-23 (P2) — `BlockMiner.GenerateBlock` calls `headerIndex.AddHeader(header, minPowChecked=true)` unconditionally

**Severity:** P2. `mining.go:678` passes `minPowChecked=true` to
`AddHeader` for every mined block:

```go
if _, err := m.headerIndex.AddHeader(block.Header, true); err != nil {
```

The comment justifies this by claiming "the miner assembled this
block locally; its chain work is already known to meet the threshold
(we are mining on top of the active tip which is necessarily above
MinimumChainWork)". But on regtest with `MinimumChainWork = big.NewInt(0)`,
this is harmless; on mainnet, this bypasses the `min_pow_checked`
gate that would normally reject pre-MinimumChainWork headers — which
is fine here because by the time we're mining, the tip is past
MinimumChainWork. So this is correctness-neutral but plumbing-wise
loose; an operator who set MinimumChainWork artificially high (or who
mined on a side-fork below it) would silently bypass the gate.

**File:** `internal/mining/mining.go:678`.

**Core ref:** `bitcoin-core/src/validation.cpp::AcceptBlockHeader`
(`min_pow_checked` is set by the caller's chain-work context).

**Impact:** plumbing tightness gap; no current consumer hits it.

---

## BUG-24 (P2) — `nil tipNode` from `GetNode(tipHash)` would panic with no guard

**Severity:** P2. `mining.go:144-167`:

```go
tipHash, tipHeight := tg.chainMgr.BestBlock()
tipNode := tg.headerIndex.GetNode(tipHash)
newHeight := tipHeight + 1
// ...
blockVersion := consensus.ComputeBlockVersion(tipNode, ...)
// ...
mtp := tipNode.GetMedianTimePast()             // panics if tipNode == nil
```

If `headerIndex.GetNode(tipHash)` returns `nil` (race between `BestBlock()`
returning a hash and `headerIndex` pruning/not-yet-inserting that
hash), the code panics. In production this is mostly impossible
because the chain manager + header index are consistent, but during
startup or reorg races there's a window.

**File:** `internal/mining/mining.go:144-167`.

**Impact:** rare panic window during startup / reorg races; nil-guard
hardening.

---

## Summary

**Bug count:** 24 (BUG-1 through BUG-24).

**Severity distribution:**
- **P0 / P0-CDIV:** 6 (BUG-1, BUG-2, BUG-3, BUG-16, BUG-17, plus
  classification of BUG-3 as carry-forward to W142 fleet)
  → recount: BUG-1 (P0), BUG-2 (P0), BUG-3 (P0-CDIV), BUG-16 (P0),
  BUG-17 (P0-CDIV carry-forward W145) = **5 P0-class**.
- **P1 / P1-CDIV:** 11 (BUG-4, BUG-5, BUG-8, BUG-9, BUG-10, BUG-12,
  BUG-13, BUG-14, BUG-15, BUG-19, BUG-22).
- **P2 / P2-CDIV:** 8 (BUG-6, BUG-7, BUG-11, BUG-18, BUG-20, BUG-21,
  BUG-23, BUG-24).

Recount: 5 + 11 + 8 = 24. ✓

**Carry-forwards confirmed open**
- **W145 BUG-1 (P0-CDIV)** `CalcBlockSubsidy` ignores
  `params.SubsidyHalvingInterval` — re-confirmed inside BlockAssembler
  as **BUG-17** of this audit. Regtest mining broken past h=150.
  ~3 weeks open.
- **W145 BUG-14 (P0-DEAD)** `ChainParams.SubsidyHalvingInterval` set
  by all 5 networks but read by zero production paths — same bug,
  cross-referenced under BUG-17.
- **W132 BUG-1 (P2)** `MsgTx.Version int32` — re-confirmed at
  `internal/wire/types.go:221`, used inside coinbase template
  construction (`mining.go:462`). Currently dormant (positive literal
  assigned), tracked as **BUG-20**.
- **W144 BUG-5 (P1)** STANDARD-flag set missing 9-10 of 13 (W152
  verified 10 missing) — does NOT apply to the BlockAssembler
  surface; flagged elsewhere (mempool / policy).
- **W150 BUG-9 (P2-CDIV)** coinbase-maturity off-by-one in mempool —
  re-confirmed inheriting into BlockAssembler tx-selection as
  **BUG-18**.

**Fleet patterns confirmed**
- **"comment-as-confession" (4 distinct instances this wave)** —
  BUG-10 ("ancestor fee rate algorithm (CPFP-aware)" comment vs
  individual-rate code), BUG-15 (`// Simplified`), BUG-16 (`// Would
  need fee tracking per tx`), BUG-20 carry-forward (W132 known but
  unfixed). Brings blockbrew comment-as-confession total to ~12
  distinct instances per audit tracking.
- **"two-pipeline drift" (BUG-2 + BUG-17)** — coinbase value is
  computed inside `CreateCoinbaseTx` from mempool-fee-total, then
  txs are replaced without recomputing coinbase value
  (two-pipeline-handoff misses); subsidy is computed from package
  const, halving-interval is set per-network in chainparams
  (two-pipeline write+read disconnect).
- **"operator-knob absence" (BUG-6 + BUG-8 cluster)** — 4 missing
  Core flags (`-blockmaxweight`, `-blockreservedweight`,
  `-blockmintxfee`, `-blockversion`); symmetric to W148 BUG-6 +
  W149 BUG-5 (no `-assumevalid`).
- **"dead-data plumbing" (BUG-17 cross-cite W145 BUG-14)** —
  `ChainParams.SubsidyHalvingInterval` is set by all 5 networks but
  read by zero production paths. Same shape as W138 9-impl
  ChainstateManager pattern, W149 `havePruned` flag.
- **"hardcoded-constants-not-params-aware" (BUG-17, BUG-14)** —
  subsidy halving interval; pre-segwit divide-by-4 on `sizelimit` /
  `sigoplimit`; weight-vs-size in GBT.
- **"reject-string wire-parity slippage"** — BUG-2 and BUG-19 both
  potentially produce `bad-cb-amount` / `bad-cb-length` via paths
  Core wouldn't take, masking the actual divergence in operator
  logs.
- **"package vs individual feerate"** — BUG-1 + BUG-10 form one
  architectural gap visible from two angles (selection algorithm
  + filter).
- **"GBT response field gaps"** — BUG-13 + BUG-14 + BUG-15 + BUG-16
  are 4 distinct missing/wrong fields in the GBT response shape,
  collectively making blockbrew's GBT response non-substitutable
  for Core's against pool software.

**Top three findings**
1. **BUG-17 (P0-CDIV carry-forward W145)** — `CalcBlockSubsidy`
   still reads package const, ignoring `params.SubsidyHalvingInterval`.
   Regtest mining broken past h=150; mainnet currently uses the right
   value by coincidence (210000 = const). ~3 weeks open since first
   filing in W123. Now confirmed bites the BlockAssembler flow
   (template's `coinbasevalue` is double the correct amount past
   regtest h=150).
2. **BUG-2 (P0)** — `handleGenerateBlock` and `BlockMiner.GenerateBlock`
   replace `block.Transactions[1:]` with user-supplied txs but do
   NOT recompute the coinbase output value. The leftover-from-mempool
   `subsidy + totalFees` causes `bad-cb-amount` rejection on submit
   whenever the caller's tx fees differ from the mempool template's
   fee total. Production `generateblock` RPC is broken for any
   non-empty `txs` parameter that differs from the mempool snapshot.
3. **BUG-1 + BUG-10 cluster (P0 + P1)** — `selectTransactions` walks
   individual `TxEntry`s rather than mempool chunks, and filters on
   `entry.FeeRate` (individual) rather than `entry.AncestorFeeRate`
   (package). CPFP children whose parents have low individual feerate
   are dropped, and packages whose parent fails the
   `minFeeRate` filter take their children down with them. Combined
   with BUG-9 (`MinTxFeeRate=0.0` default), the practical impact is:
   blockbrew GBT templates miss revenue on every CPFP package that
   Core would include. Comment-as-confession at line 296-310
   ("CPFP-aware") confirms the intent but the code never matched.
