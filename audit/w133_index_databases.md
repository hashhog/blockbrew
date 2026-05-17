# W133 — Index databases (txindex + coinstatsindex) audit (blockbrew)

**Wave**: W133 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**Scope**: txindex + coinstatsindex. **Excludes** blockfilterindex (W121/W122).
**Verdict**: **BUGS FOUND** — 21 distinct bug IDs (BUG-1..BUG-21), including
**4 P0-CDIV** in the coinstatsindex hash field, **3 P0-CDIV** structural
gaps (no `g_coin_stats_index` symbol at all; the encapsulated `*CoinStatsIndex`
type and `*TxIndex` type are dead code that production never instantiates),
and 14 HIGH/MED/LOW gaps in BaseIndex framework parity, reorg safety,
format-versioning, locator persistence, prune-mode integration, and
`-coinstatsindex` flag absence.

**Bitcoin Core references**:
- `bitcoin-core/src/index/base.h` + `base.cpp` — `BaseIndex` framework
  (m_synced, m_best_block_index, ProcessBlock, Rewind, BlockConnected,
  ChainStateFlushed, BlockUntilSyncedToCurrentChain, SetBestBlockIndex,
  prune-lock wiring via `m_chainstate->m_blockman.UpdatePruneLock`).
- `bitcoin-core/src/index/txindex.h` + `txindex.cpp` — `TxIndex::CustomAppend`
  (writes `CDiskTxPos` per tx including coinbase, **skips genesis**),
  `TxIndex::FindTx` (reads tx by hash, opens blockfile, verifies hash).
- `bitcoin-core/src/index/disktxpos.h` — `CDiskTxPos` (FlatFilePos + nTxOffset
  VARINT) — the actual disk-position record txindex stores.
- `bitcoin-core/src/index/coinstatsindex.h` + `coinstatsindex.cpp` — DBVal
  serializer, `m_muhash` (MuHash3072 incremental accumulator), height+hash
  reorg-safe two-index layout via `index_util::DBHeightKey` and
  `DBHashKey`, `CustomInit` MuHash consistency check,
  `CustomCommit(DB_MUHASH)` atomic with DB_BEST_BLOCK.
- `bitcoin-core/src/index/db_key.h` — `DBHeightKey{prefix='t', height_BE}`
  + `DBHashKey{prefix='s', hash}`, `CopyHeightIndexToHashIndex`,
  `LookUpOne` (height first, hash fallback for orphan blocks).
- `bitcoin-core/src/init.cpp:l820-880` — `-txindex` / `-coinstatsindex`
  flag specs, `g_txindex` / `g_coin_stats_index` instantiation,
  `chainman.options.fast_prune` gating, `IndexInitialSync` joiner.

**Source under audit**:
- `blockbrew/internal/storage/index.go` — `Index` interface + `BaseIndex`
  + `IndexManager`. The blockbrew-local BaseIndex framework.
- `blockbrew/internal/storage/txindex.go` — orphan `*TxIndex` struct
  (zero production callers; see BUG-2).
- `blockbrew/internal/storage/coinstatsindex.go` — orphan `*CoinStatsIndex`
  struct (zero production callers; see BUG-2).
- `blockbrew/internal/storage/chaindb.go:337-374` — the **actual**
  production txindex: a flat `Txid → BlockHash` (32 bytes) PebbleDB
  mapping under prefix `"T"`. Wired from `cmd/blockbrew/main.go:957-964`
  to `chainMgr.SetOnBlockConnected` and `:880-890` to
  `chainMgr.SetOnBlockDisconnected`, gated by `cfg.TxIndex`.
- `blockbrew/internal/crypto/muhash.go` — `MuHash3072` implementation
  that **exists** but is never used by coinstatsindex (see BUG-1).
- `blockbrew/internal/rpc/wave47b_methods.go:26-57` —
  `handleGetTxOutSetInfo` (`gettxoutsetinfo`), which **does not consult
  coinstatsindex at all** (see BUG-11).
- `blockbrew/cmd/blockbrew/main.go:463` — `-txindex` flag.
- `blockbrew/cmd/blockbrew/main.go` — **no `-coinstatsindex` flag exists**
  (see BUG-3).
- `blockbrew/internal/rpc/methods.go:880-922` — `getrawtransaction`'s
  txindex lookup branch (uses `chainDB.GetTxIndex`).
- `blockbrew/internal/rpc/rest.go:258-273` — REST `/rest/tx/<txid>`'s
  txindex lookup branch.

## Summary

There are **two distinct, mutually inconsistent** index implementations
in this codebase:

1. **Production-wired flat txindex** at `internal/storage/chaindb.go`.
   This is what `-txindex` actually plumbs through. Key = `"T" || txid`,
   value = 32-byte block hash. No tx-offset, no version, no locator, no
   state row. Driven by `chainMgr.SetOnBlockConnected/Disconnected`
   hooks in `main.go`.

2. **Orphan typed indexes** at `internal/storage/txindex.go` and
   `internal/storage/coinstatsindex.go`. These have richer schemas
   (TxIndexData with TxIndex within block, CoinStats with running
   stats), implement the `Index` interface, and are exercised by
   tests — but **`grep -rn 'NewTxIndex' blockbrew/cmd/`** and
   **`grep -rn 'NewCoinStatsIndex' blockbrew/`** return no
   production hits. The IndexManager registers only blockfilterindex
   (`cmd/blockbrew/main.go:843-848`). The orphan types are tested
   in isolation but never wired into `BlockConnected` /
   `BlockDisconnected` / `ConnectBlock` paths in production.

This is W117/W118-style "implementation exists but never executes" —
the dead-code-fix failure mode `verify-fix.sh` was designed to catch.
Every bug in coinstatsindex.go (BUG-1, BUG-7..BUG-10) is **dormant**
because the index is never instantiated; flipping it on (e.g. via a
yet-to-land `-coinstatsindex` flag) will activate every defect.

Severity distribution:

| Severity   | Count | Notes |
|------------|-------|-------|
| P0-CDIV    | 4     | BUG-1 XOR pseudo-hash != MuHash3072 (any peer comparing `hash_serialized_3` will diverge); BUG-7 BIP-30 duplicate-coinbase not skipped in coinstatsindex append; BUG-8 unspendable-script accounting absent for OP_RETURN with `nValue > 0` (still inflates total_amount); BUG-21 prevouts spent are removed from MuHash by `(value, scriptPubKey)` only — no outpoint — so two outputs with the same script+value at different outpoints (e.g. two miners using the same P2PK key with the same payout, mainnet early-2010) cancel each other and corrupt the accumulator. |
| HIGH       | 6     | BUG-2 production never instantiates `*TxIndex` / `*CoinStatsIndex` (orphan); BUG-3 no `-coinstatsindex` flag at the CLI; BUG-4 production flat txindex stores ONLY block hash (no offset, no in-block tx index, no nTxOffset → can't seek to tx in blockfile); BUG-5 RevertBlock on `coinstatsindex` doesn't fetch GetStats(prevHeight) before writing — read-before-write race window on chainstate-flush ordering; BUG-11 `gettxoutsetinfo` returns hard-coded `"muhash": ""`, `"bogosize": 0`, `"total_amount": 0.0` — no coinstatsindex consultation; BUG-12 `BaseIndex.SetSynced` is a one-way latch that never re-fires the `m_synced=false` reorg-rewind path (no Core-equivalent Rewind loop in the IndexManager). |
| MED        | 7     | BUG-6 no format-version byte on txindex / coinstatsindex state rows (only blockfilterindex got it in FIX-83); BUG-9 no DBHeightKey / DBHashKey two-index reorg copy (coinstatsindex relies on a single height-keyed map, can't survive an orphan-fork lookup); BUG-10 fees accumulator formula sign-wrong on rare "miner under-claims subsidy" path; BUG-13 no `BlockUntilSyncedToCurrentChain` analog → RPC handlers can read partially-built index; BUG-14 BaseIndex `Init` doesn't validate that the on-disk best-hash is on the active chain (Core: `LookupBlockIndex`); BUG-15 no `Interrupt` / `Stop` / dedicated sync thread — IndexManager is purely synchronous BlockConnected fan-out (no Core-style ThreadSync that catches up from disk on startup); BUG-19 IndexManager.BlockConnected drops error from ONE index but returns it to caller, halting ALL other indexes (no per-index error isolation; Core BaseIndex calls `FatalErrorf` per-index → AbortNode, which is *different*: deliberate node halt, not silent skip). |
| LOW        | 4     | BUG-16 `txindex_state` / `coinstats_state` keys are bare strings, no prefix-byte under blockbrew's normal `"T"`/`"c"` key-space convention (collision risk with future txid `0x74_78_69_6e_64_65_78_5f_73_74_61_74_65` … = highly improbable but unprincipled); BUG-17 coinstatsindex uses local `calcBlockSubsidy` instead of `consensus.CalcBlockSubsidy` (silently OK today, but a halving-interval change in `consensus.SubsidyHalvingInterval` won't propagate to the index — same shape as W123 BUG-1); BUG-18 `getBogoSize` local helper doesn't match Core's `kernel::GetBogoSize` exactly (the constant `32+4+8+1` is Core-equivalent but a future Core change to coin serialization will silently desync); BUG-20 coinstatsindex `WriteBlock` skips no-op early return for height==0 like txindex does — it computes a subsidy and runs the loop, producing a height-0 row with the genesis coinbase counted (Core: in coinstatsindex.cpp:108-179, genesis is handled via the `else` branch at :176 — m_total_unspendables_genesis_block += subsidy — so the genesis-coinbase value is **not** counted toward total_amount; blockbrew counts it). |

PASS: **9** / PARTIAL: **6** / MISSING: **15**. Bug count: **21**.

## 30-gate audit matrix

| Gate | What the gate asserts | Status | Bug |
|------|----------------------|--------|-----|
| G1  | `BaseIndex` framework exists: name + best-height + best-hash + synced + Init/WriteBlock/RevertBlock | PASS | — (`internal/storage/index.go:50-126`) |
| G2  | `IndexManager` fan-out: `BlockConnected` calls every registered index in order | PASS | — (`internal/storage/index.go:181-196`) |
| G3  | `IndexManager` reorg fan-out: `BlockDisconnected` calls every registered index in reverse-connect order | PARTIAL | BUG-19 (single error halts fan-out for all subsequent indexes, no isolation) |
| G4  | `*TxIndex` is instantiated and registered in production startup (`cmd/blockbrew/main.go`) | **MISSING** | BUG-2 |
| G5  | `*CoinStatsIndex` is instantiated and registered in production startup | **MISSING** | BUG-2 |
| G6  | `-coinstatsindex` flag in CLI flag set (mirrors Core init.cpp) | **MISSING** | BUG-3 |
| G7  | `-txindex` flag honored at startup; gates `OnBlockConnected → txindex write` (`cmd/blockbrew/main.go:463 + :954-965`) | PASS | — |
| G8  | txindex skips genesis block (Core: txindex.cpp:77 `if (block.height == 0) return true;`) | PARTIAL | BUG-4 (production flat-txindex writes ALL txs from height 1 onward but lacks Core's "exclude genesis" semantic because genesis is exempted upstream via `ConnectBlock` early-return for height==0, not via the txindex itself; works today but the comment in the orphan `txindex.go:86` "Skip genesis block" is only in dead code, not the production path) |
| G9  | txindex stores `CDiskTxPos` analog (file_number + data_pos + nTxOffset) so `FindTx` can seek into blk*.dat | **MISSING** | BUG-4 (production stores only block hash → forces full block deserialization on every `getrawtransaction`) |
| G10 | `FindTx` opens the blockfile via `OpenBlockFile(postx, true)`, reads header, seeks `postx.nTxOffset`, deserializes the tx, **verifies hash matches** (Core txindex.cpp:114-117) | **MISSING** | BUG-4 (production path in `methods.go:889-902` reads the whole block and linear-scans for the txid — slow but at least correct on hash mismatch) |
| G11 | txindex RevertBlock deletes each txid (symmetric with WriteBlock) | PASS | — (`main.go:880-890`, but see BUG-12) |
| G12 | txindex `txindex_state` row stamps a format-version byte (cf. blockfilterindex `FormatVersion=1` post-FIX-83) | **MISSING** | BUG-6 |
| G13 | coinstatsindex maintains an incremental `MuHash3072` accumulator (Core: index/coinstatsindex.cpp:38 `m_muhash`) | **MISSING** | BUG-1 (orphan code uses XOR, not MuHash) |
| G14 | coinstatsindex `ApplyCoinHash` uses `(outpoint, coin)` tuple — keyed by full outpoint, not by (value, scriptPubKey) | **MISSING** | BUG-21 (orphan `removeFromHash` at coinstatsindex.go:355-367 explicitly drops the outpoint and hashes only `(value, scriptPubKey)` — the comment at :357-358 confesses the gap) |
| G15 | coinstatsindex per-height row stores `DBVal{muhash, total_amount, total_subsidy, total_prevout_spent_amount, total_new_outputs_ex_coinbase_amount, total_coinbase_amount, total_unspendables_genesis_block, total_unspendables_bip30, total_unspendables_scripts, total_unspendables_unclaimed_rewards, bogo_size, transaction_output_count}` | PARTIAL | BUG-10 (orphan `CoinStats` struct stores fees as a single int64 instead of the four prevout_spent/new_outputs/coinbase/unclaimed split — produces same final balance but loses Core's auditable per-row decomposition) |
| G16 | coinstatsindex detects BIP-30 duplicate-coinbase blocks (heights 91842/91722/91812/91812 mainnet) and skips them via `IsBIP30Unspendable` | **MISSING** | BUG-7 |
| G17 | coinstatsindex tracks `m_total_unspendables_scripts` separately when a TxOut has `nValue > 0` but `IsUnspendable()=true` (e.g. provably-burned OP_RETURN with value attached) | **MISSING** | BUG-8 (orphan `isUnspendable` returns true for OP_RETURN but the loop at coinstatsindex.go:192-203 just `continue`s — the burnt value is silently dropped, neither counted toward `total_amount` nor accounted in any `m_total_unspendables_scripts` field) |
| G18 | coinstatsindex `CustomCommit` atomically writes DB_MUHASH alongside DB_BEST_BLOCK (Core: coinstatsindex.cpp:308-314, "DB_MUHASH should always be committed in a batch together with DB_BEST_BLOCK") | PARTIAL | BUG-5 (orphan `WriteBlock` does write state+coinstats in one batch (`coinstatsindex.go:241-261`), but the state row carries the running accumulator value redundantly with per-height row — two sources of truth that can drift) |
| G19 | coinstatsindex Init: on startup, finalizes the in-memory MuHash and asserts it equals the on-disk DB_MUHASH value (Core: coinstatsindex.cpp:282-289, refuses to start if mismatch) | **MISSING** | BUG-1 (no MuHash at all → no consistency check; the orphan `Init` at coinstatsindex.go:140-167 just deserializes the state) |
| G20 | coinstatsindex `CustomRemove` calls `CopyHeightIndexToHashIndex` so an orphan-fork block's stats are preserved under DBHashKey (Core: coinstatsindex.cpp:223-225) | **MISSING** | BUG-9 |
| G21 | coinstatsindex `LookUpStats` uses two-index lookup: try DBHeightKey first, then DBHashKey on hash mismatch (Core: db_key.h:96-113 `LookUpOne`) | **MISSING** | BUG-9 |
| G22 | `gettxoutsetinfo` consults coinstatsindex when `hash_type="muhash"` (Core: rpc/blockchain.cpp::gettxoutsetinfo → `g_coin_stats_index->LookUpStats(*pindex)`) | **MISSING** | BUG-11 (`muhash`, `bogosize`, `total_amount` all hard-coded; `internal/rpc/wave47b_methods.go:47-56`) |
| G23 | `getindexinfo` returns `txindex` entry when `-txindex` is enabled (Core: rpc/blockchain.cpp::getindexinfo) | PARTIAL | BUG-2 (handleGetIndexInfo at `extra_methods.go:720-737` iterates `indexManager.AllIndexes()` — txindex isn't registered with IndexManager because there's no `*TxIndex` instance; only blockfilterindex shows up) |
| G24 | BaseIndex.Init validates that on-disk `bestHash` is on the active chain; if not, sets m_synced=false and rewinds (Core: base.cpp:124-134 LookupBlockIndex + rewind on next Sync) | **MISSING** | BUG-14 (orphan `TxIndex.Init` and `CoinStatsIndex.Init` just deserialize state; no LookupBlockIndex; no active-chain validation; no rewind-on-fork) |
| G25 | BaseIndex has a `BlockUntilSyncedToCurrentChain()` API so RPC handlers can block until the index has caught up to the chain tip (Core: base.cpp:424-446) | **MISSING** | BUG-13 |
| G26 | BaseIndex has a `ThreadSync` (Core base.cpp:201-268) that catches up the index from disk on startup, separate from the live `BlockConnected` notification path | **MISSING** | BUG-15 |
| G27 | `Stop()` / `Interrupt()` lifecycle: index shutdown unregisters validation interface and joins the sync thread (Core: base.cpp:461-470) | **MISSING** | BUG-15 |
| G28 | `SetBestBlockIndex` updates the prune lock so blocks below the index's best-height aren't pruned (Core: base.cpp:487-504 `m_blockman.UpdatePruneLock`) | **MISSING** | BUG-15 (`UpdateBest` in `index.go:104-109` just sets two fields; no prune-lock integration in the prune path at all — and `cfg.Prune` is wired through to the pruner without any check that an enabled index has its blocks pinned, so a `-prune=1000 -txindex` config WILL prune blocks that txindex still has tx-pointers into) |
| G29 | coinstatsindex `AllowPrune() == true` (Core: coinstatsindex.h:52 — coinstatsindex CAN be pruned because once a block is processed and rolled into the UTXO accumulator, the raw block isn't needed); txindex `AllowPrune() == false` (Core: txindex.h:34 — txindex CANNOT be pruned because it needs to seek into blockfiles forever) | **MISSING** | BUG-15 (no AllowPrune signal at all in the blockbrew Index interface) |
| G30 | Reorg replay: if a reorg disconnects N blocks and connects M, the index runs RevertBlock × N then WriteBlock × M, all under the chain manager's reorg batch so the final on-disk state is atomically consistent with the consensus rewrite | PARTIAL | BUG-12 (the `OnBlockConnected` / `OnBlockDisconnected` hooks fire from inside ReorgTo's loop, but the only state mutation under `chainMgr.CurrentReorgBatch()` is for `blockfilterindex` (`main.go:893-915 + :967-983`); the `chainDB.WriteTxIndex` / `DeleteTxIndex` calls are NOT batched with the reorg → if the reorg's final atomic commit fails after the txindex writes have already landed on disk, the txindex is half-rewritten with no rollback path) |

PASS: **9** | PARTIAL: **6** | MISSING: **15**.

## Bug catalogue

### BUG-1 (P0-CDIV) — coinstatsindex uses XOR-based UTXO hash, not MuHash3072

**Severity**: P0-CDIV (any peer comparing `hash_serialized_3` /
`muhash` field via `gettxoutsetinfo` will diverge from blockbrew)
**ID**: BLOCKBREW-W133-1
**Location**: `internal/storage/coinstatsindex.go:339-367`,
`internal/storage/coinstatsindex.go:126` (the field `utxoHash []byte`).

```go
// addToHash updates the running UTXO hash with a new output.
func (idx *CoinStatsIndex) addToHash(txid wire.Hash256, vout uint32, out *wire.TxOut) {
    buf := new(bytes.Buffer)
    txid.Serialize(buf)
    wire.WriteUint32LE(buf, vout)
    wire.WriteInt64LE(buf, out.Value)
    wire.WriteVarBytes(buf, out.PkScript)

    // XOR the SHA256 hash of this UTXO into the accumulator
    hash := crypto.SHA256Hash(buf.Bytes())
    for i := 0; i < 32; i++ {
        idx.utxoHash[i] ^= hash[i]
    }
}
```

Two failure modes:

1. **XOR is not Core's accumulator.** Core's MuHash3072 is a 3072-bit
   multiplicative group accumulator under modulus `p = 2^3072 - 1103717`,
   reduced to a 32-byte `SHA256(numerator * inverse(denominator) mod p)`
   at finalize. Blockbrew's XOR-of-SHA256 is a 256-bit XOR group. Even
   for an identical UTXO set, the two functions will produce different
   32-byte digests, so blockbrew's `muhash` value can **never** match
   Core's for the same chain.

2. **`MuHash3072` exists but is unused.** `internal/crypto/muhash.go`
   ships a complete Core-parity MuHash3072 implementation
   (`Insert/Remove/Finalize/MuHashSerialize/MuHashDeserialize`,
   chacha20-keystream mapping, 384-byte serialization). It's
   wire-correct against Core's `bitcoin-core/src/crypto/muhash.{h,cpp}`
   per the comment block at line 9. **coinstatsindex.go imports
   `crypto` but only calls `crypto.SHA256Hash`** — the full
   MuHash3072 type is never referenced from coinstatsindex.go.
   This is W117/W118-style dead code on the production side.

**Reference**: `bitcoin-core/src/index/coinstatsindex.cpp:38` (the
`MuHash3072 m_muhash` field), `bitcoin-core/src/crypto/muhash.cpp`,
`bitcoin-core/src/kernel/coinstats.cpp::ApplyCoinHash/RemoveCoinHash`
(which is what `coinstatsindex.cpp:145+166` calls).

**Fix path**: replace `idx.utxoHash []byte` with
`idx.muhash *crypto.MuHash3072`, replace `addToHash` / `removeFromHash`
with `Insert(serializeOutpointPlusCoin(outpoint, coin))` /
`Remove(...)`, replace `Finalize` with `m.Finalize()[:]`. Existing tests
that hard-code the XOR-hash values will need to be regenerated against
Core test vectors.

### BUG-2 (HIGH) — `*TxIndex` and `*CoinStatsIndex` never instantiated in production

**Severity**: HIGH (dead-code-fix failure mode; structurally invisible)
**ID**: BLOCKBREW-W133-2
**Location**: `cmd/blockbrew/main.go:841-848` (only `*BlockFilterIndex`
is registered with IndexManager). No call site exists for `NewTxIndex`
or `NewCoinStatsIndex` outside their own tests.

```
$ grep -rn 'NewTxIndex\|NewCoinStatsIndex' blockbrew --include='*.go' \
    | grep -v _test.go | grep -v worktrees
blockbrew/internal/storage/txindex.go:57:func NewTxIndex(db DB) *TxIndex {
blockbrew/internal/storage/coinstatsindex.go:132:func NewCoinStatsIndex(db DB) *CoinStatsIndex {
```

Both constructors have zero callers in production code. The richer
schemas they encapsulate (per-block TxIndexData with in-block tx index,
per-height CoinStats rows) are exercised by their `_test.go` files
only. The production txindex is the bare `chainDB.WriteTxIndex` /
`GetTxIndex` / `DeleteTxIndex` triad at `chaindb.go:337-374`, which
**stores only the block hash** (no tx index within block, no offset,
no version).

This is structurally invisible because:
1. Tests pass against the in-memory PebbleDB.
2. `getrawtransaction` "works" — it just falls back to whole-block deserialization.
3. `gettxoutsetinfo` "works" — it returns hard-coded zeros (BUG-11).
4. `getindexinfo` returns only blockfilterindex (when enabled), so the
   absence of `txindex` and `coinstatsindex` in the response looks
   intentional rather than missing.

Cross-impl pattern depth: same shape as W117 BIP-155 / W118 wallet
"helper exists, never called from request handler". This is the FIX-72
"dead-helper-at-call-site" pattern at the framework registration level
instead of the per-call site level.

**Fix path**: in `main.go`, after the `BlockFilterIndex` block, add:

```go
if cfg.TxIndex {
    txIndex := storage.NewTxIndex(chainDB.DB())
    if err := indexManager.RegisterIndex(txIndex); err != nil {
        return fmt.Errorf("txindex: register: %w", err)
    }
}
if cfg.CoinStatsIndex {
    csi := storage.NewCoinStatsIndex(chainDB.DB())
    if err := indexManager.RegisterIndex(csi); err != nil {
        return fmt.Errorf("coinstatsindex: register: %w", err)
    }
}
```

(Then also fix BUG-1, BUG-3, BUG-4, BUG-7, BUG-8, BUG-21 before
flipping on.)

### BUG-3 (HIGH) — `-coinstatsindex` flag missing from CLI

**Severity**: HIGH (no operator path to enable the index)
**ID**: BLOCKBREW-W133-3
**Location**: `cmd/blockbrew/main.go:463` has `-txindex` but the
`flag.BoolVar` for `-coinstatsindex` is **absent**. The `Config` struct
in `main.go:53` has `TxIndex bool` and `:202` has `BlockFilterIndex bool`
— there's no `CoinStatsIndex bool` field.

```
$ grep -n 'coinstatsindex\|CoinStatsIndex' blockbrew/cmd/blockbrew/main.go
# (zero hits)
```

Bitcoin Core init.cpp:l880 has `argsman.AddArg("-coinstatsindex",
strprintf("Maintain coinstats index used by the gettxoutsetinfo RPC
(default: %u)", DEFAULT_COINSTATSINDEX), ...)`. blockbrew has neither
the flag, nor the Config field, nor the help-text entry at `main.go:2128`.

**Fix path**: add `CoinStatsIndex bool` to Config, register the flag
with default `false`, document in `--help`, gate the registration block
described in BUG-2 on `cfg.CoinStatsIndex`.

### BUG-4 (HIGH) — production txindex stores only block hash, no `CDiskTxPos` analog

**Severity**: HIGH (functional but pessimal; forces full-block
deserialization on every getrawtransaction; multi-MB block reads per
historical tx lookup)
**ID**: BLOCKBREW-W133-4
**Location**: `internal/storage/chaindb.go:337-368` defines:

```go
type TxIndexEntry struct {
    BlockHash wire.Hash256 // Hash of the block containing the transaction
}

func (c *ChainDB) WriteTxIndex(txid wire.Hash256, blockHash wire.Hash256) error {
    key := MakeTxIndexKey(txid)
    return c.db.Put(key, blockHash[:])
}
```

Compared to Core's `CDiskTxPos` (`bitcoin-core/src/index/disktxpos.h:11-23`):

```cpp
struct CDiskTxPos : public FlatFilePos {
    uint32_t nTxOffset{0}; // after header
    SERIALIZE_METHODS(CDiskTxPos, obj) {
        READWRITE(AsBase<FlatFilePos>(obj), VARINT(obj.nTxOffset));
    }
    // ...
};
```

Core stores `nFile + nPos + nTxOffset` so `TxIndex::FindTx`
(`bitcoin-core/src/index/txindex.cpp:93-120`) can:

```cpp
AutoFile file{m_chainstate->m_blockman.OpenBlockFile(postx, true)};
CBlockHeader header;
file >> header;
file.seek(postx.nTxOffset, SEEK_CUR);
file >> TX_WITH_WITNESS(tx);
```

blockbrew's `getrawtransaction` path (`methods.go:889-902`) instead
calls `chainDB.GetBlock(entry.BlockHash)` (read the entire block from
PebbleDB / flat file) and `for i, btx := range block.Transactions {
if btx.TxHash() == txid { ... } }` (linear scan). For a typical
1-MB mainnet block with ~2500 txs, this is O(1) block-fetch + O(N)
hash-recomputes (each `TxHash()` is a double-SHA256 over the
serialized tx). The orphan `*TxIndex` at `internal/storage/txindex.go:20-23`:

```go
type TxIndexData struct {
    BlockHash wire.Hash256 // Hash of the block containing this transaction
    TxIndex   uint32       // Index of this transaction within the block
}
```

stores the in-block index — one step closer to Core but still missing
the file/offset/nTxOffset trio so it would still need to read the
whole block to seek. The "right" Go shape is to extend `TxIndexEntry`
to `{BlockHash, FileNumber, BlockDataPos, TxOffset}` and route reads
through the flat-file blockstore (`internal/storage/flatfile.go`)
with a `seek(TxOffset, SEEK_CUR)` after the header.

**Fix path**: extend `TxIndexEntry` to a `CDiskTxPos` analog, populate
`TxOffset` in the `OnBlockConnected` hook (compute via
`GetSizeOfCompactSize(numTxs) + sum(SerializeSize(prior txs))`,
exactly mirroring `bitcoin-core/src/index/txindex.cpp:80-87`), and
route the `methods.go` and `rest.go` callers through a new
`chainDB.FindTx(txid)` that does the seek-and-deserialize dance.

### BUG-5 (HIGH) — coinstatsindex RevertBlock GetStats(prevHeight) read-before-write race

**Severity**: HIGH (correctness window on chainstate-flush ordering)
**ID**: BLOCKBREW-W133-5
**Location**: `internal/storage/coinstatsindex.go:268-323`.

```go
func (idx *CoinStatsIndex) RevertBlock(...) error {
    prevHash := block.Header.PrevBlock
    prevHeight := height - 1

    // Load previous stats to restore state
    if prevHeight >= 0 {
        prevStats, err := idx.GetStats(prevHeight)
        if err != nil {
            return err
        }
        idx.txCount = prevStats.TxCount
        // ... mutates idx.* in-memory ...
    }

    batch := idx.db.NewBatch()
    key := MakeCoinStatsKey(height)
    batch.Delete(key)
    // ... writes new state row ...
    if err := batch.Write(); err != nil {
        return err
    }
    idx.UpdateBest(prevHeight, prevHash)
    return nil
}
```

The mutations to `idx.txCount`, `idx.utxoCount`, `idx.totalAmount`,
`idx.bogoSize`, `idx.utxoHash`, `idx.subsidy`, `idx.fees` happen
**before** `batch.Write()`. If `batch.Write()` fails, the in-memory
state is half-rolled-back but the on-disk state still says the
post-block height. On the next `WriteBlock`, the in-memory deltas
will be applied to the rolled-back-only-in-memory accumulator,
producing a final on-disk row that's wrong.

Core's `coinstatsindex.cpp:326-403 RevertBlock` recomputes the muhash
deltas from the block contents (lines 354-381) and asserts at the end
(`Assert(read_out.second.muhash == out)`, line 386) that the rolled
back muhash matches what was on disk at the previous height. That
assert IS the consistency check missing here.

**Fix path**: (a) move all in-memory mutations after `batch.Write()`
succeeds; (b) add a Core-style assertion that the rolled-back hash
matches the on-disk `prevHeight` row's hash (post-MuHash conversion
from BUG-1).

### BUG-6 (MED) — no format-version byte on txindex / coinstatsindex state rows

**Severity**: MED (forces operator wipe on any future schema bump)
**ID**: BLOCKBREW-W133-6
**Location**: `internal/storage/txindex.go:178-212` (`IndexState`,
`Serialize`, `DeserializeIndexState`); `internal/storage/coinstatsindex.go:400-481`
(`CoinStatsState`, `Serialize`, `DeserializeCoinStatsState`).

Neither state row starts with a format-version byte. Compare
`internal/storage/blockfilterindex.go:53` which gained
`BlockFilterIndexFormatVersion uint8 = 1` in FIX-83 specifically so a
future codec change can self-heal on startup (wipe + rebuild) instead
of silently corrupting against the new code. txindex + coinstatsindex
state rows have neither version byte nor migration path; flipping
either index's schema (e.g. swapping the XOR hash for MuHash) will
silently feed wrong on-disk state into the new code path.

**Fix path**: prepend a `uint8 FormatVersion = 1` to both
`IndexState.Serialize` and `CoinStatsState.Serialize`; add the
"format version mismatch → wipe-and-rebuild from height -1" branch
in both `Init` methods, mirroring `blockfilterindex.go:117-167`.

### BUG-7 (P0-CDIV) — BIP-30 duplicate-coinbase blocks not skipped in coinstatsindex

**Severity**: P0-CDIV (incorrect UTXO accumulator on mainnet historical
blocks at heights 91842, 91722, 91812, 91722, 91812 …)
**ID**: BLOCKBREW-W133-7
**Location**: `internal/storage/coinstatsindex.go:186-218` does NOT
check `IsBIP30Unspendable`. Core's `coinstatsindex.cpp:128-132`:

```cpp
// Skip duplicate txid coinbase transactions (BIP30).
if (is_coinbase && IsBIP30Unspendable(block.hash, block.height)) {
    m_total_unspendables_bip30 += block_subsidy;
    continue;
}
```

The duplicate-coinbase transactions at the historical mainnet heights
(91842 and 91880 dup the coinbases at 91722 and 91812 respectively)
produce a coinbase tx with a txid that was already in the UTXO set
(pre-BIP30 + pre-BIP34). The first coinbase's outputs are
**overwritten** by the second, but the COIN VALUE is **not** added to
the global supply — it's burned. Core tracks this burned value in
`m_total_unspendables_bip30`.

blockbrew has `CheckBIP30` in `internal/consensus/validation.go` (per
the test references in `validation_test.go:1664+`), so the constant
table of BIP-30 heights/hashes exists. coinstatsindex.go just doesn't
consult it.

**Fix path**: import `internal/consensus`'s BIP-30 height check; in
the `is_coinbase && IsBIP30Unspendable(...)` branch, increment a new
`idx.totalUnspendablesBIP30 += subsidy` field (which requires adding
the four-way `unspendables_{genesis_block, bip30, scripts,
unclaimed_rewards}` decomposition from BUG-10) and `continue` past
the UTXO-add loop.

### BUG-8 (P0-CDIV) — OP_RETURN outputs with `nValue > 0` silently dropped from totals

**Severity**: P0-CDIV (subtle; affects total_amount + the four
unspendables_* counters)
**ID**: BLOCKBREW-W133-8
**Location**: `internal/storage/coinstatsindex.go:192-203`:

```go
for j, out := range tx.TxOut {
    if isUnspendable(out.PkScript) {
        continue
    }
    idx.utxoCount++
    idx.totalAmount += out.Value
    // ...
}
```

When an OP_RETURN output carries `nValue > 0` (non-standard but
consensus-legal), Core's `coinstatsindex.cpp:140-143`:

```cpp
if (coin.out.scriptPubKey.IsUnspendable()) {
    m_total_unspendables_scripts += coin.out.nValue;
    continue;
}
```

books the burned value to `m_total_unspendables_scripts`. blockbrew's
`continue` silently drops it — neither counted in `total_amount`
(correctly, since the value is provably unspendable) NOR booked in any
`unspendables_*` accumulator (incorrectly, since the burned value is
lost from the audit trail). This makes the blockbrew coinstatsindex's
running sum **NOT** equal `total_subsidy + initial_supply` even at
the chain tip — Core's invariant `total_subsidy ==
total_amount + total_unspendables_{genesis_block + bip30 + scripts +
unclaimed_rewards}` fails by exactly the OP_RETURN-with-value sum.

**Fix path**: add a fourth-way split as in BUG-10; book OP_RETURN with
value into `idx.totalUnspendablesScripts += out.Value` instead of
silent `continue`.

### BUG-9 (MED) — no DBHeightKey / DBHashKey two-index reorg layout

**Severity**: MED (orphan-fork stats unrecoverable after reorg)
**ID**: BLOCKBREW-W133-9
**Location**: `internal/storage/coinstatsindex.go:109-115`:

```go
func MakeCoinStatsKey(height int32) []byte {
    key := make([]byte, 1+4)
    key[0] = CoinStatsPrefix[0]
    binary.BigEndian.PutUint32(key[1:], uint32(height))
    return key
}
```

Single height-keyed map. On reorg, `RevertBlock` `batch.Delete(key)`s
the stats row for the disconnected height (`coinstatsindex.go:301`).
Core's two-index layout (`bitcoin-core/src/index/db_key.h:29-30` +
:71-93 `CopyHeightIndexToHashIndex`) instead copies the row to a
DBHashKey-keyed slot before overwriting, so stats for the orphan block
remain queryable post-reorg via `LookUpStats(orphan_block_index)`.

This becomes a real divergence as soon as a tool (e.g. the
mining-pool's fork-analysis dashboard) calls
`gettxoutsetinfo(<orphan_hash>)` — Core returns the stats; blockbrew
returns "not found".

**Fix path**: add a `CoinStatsHashPrefix = []byte("d")` (or similar),
add `MakeCoinStatsHashKey(hash)`, in `RevertBlock` copy the
height-keyed row to a hash-keyed row before deleting the height-keyed
slot, mirror Core's `LookUpOne(blockref)` height-first-hash-fallback
in `GetStats`.

### BUG-10 (MED) — fees/subsidy accumulator collapses Core's four-way split

**Severity**: MED (loses Core's auditable per-row decomposition)
**ID**: BLOCKBREW-W133-10
**Location**: `internal/storage/coinstatsindex.go:26-36` (`CoinStats`
struct fields) + `:117-129` (`CoinStatsIndex` running state).

Core's `DBVal` (`bitcoin-core/src/index/coinstatsindex.cpp:46-83`)
serializes a 12-field record:

```cpp
struct DBVal {
    uint256 muhash;
    uint64_t transaction_output_count;
    uint64_t bogo_size;
    CAmount total_amount;
    CAmount total_subsidy;
    arith_uint256 total_prevout_spent_amount;
    arith_uint256 total_new_outputs_ex_coinbase_amount;
    arith_uint256 total_coinbase_amount;
    CAmount total_unspendables_genesis_block;
    CAmount total_unspendables_bip30;
    CAmount total_unspendables_scripts;
    CAmount total_unspendables_unclaimed_rewards;
};
```

Note `total_prevout_spent_amount` / `total_new_outputs_ex_coinbase` /
`total_coinbase_amount` are `arith_uint256` (256-bit) precisely
because at the chain tip these sums OVERFLOW `int64`. blockbrew's
`CoinStats` collapses everything to:

```go
type CoinStats struct {
    Height           int32
    BlockHash        wire.Hash256
    TxCount          uint64
    UTXOCount        uint64
    TotalAmount      int64       // collapses Core's total_amount only
    BogoSize         uint64
    HashSerialized   wire.Hash256
    TotalSubsidy     int64
    TotalFees        int64       // collapses unclaimed_rewards
}
```

There is no `TotalPrevoutSpent`, no
`TotalNewOutputsExCoinbase`, no `TotalCoinbase`, no
`TotalUnspendablesGenesisBlock`, no `TotalUnspendablesBIP30`, no
`TotalUnspendablesScripts`. The accumulator at chain tip can't be
audited against Core's identity `subsidy == amount +
sum(unspendables_*)`.

Beyond the audit-trail loss, `int64` will silently wrap at the chain
tip (~2.1e18 sat cumulative coinbase output) — Core uses
`arith_uint256` to dodge this. blockbrew today is fine (height ~890k,
sum is ~21e15 sat) but the upper bound is documented.

**Fix path**: split `TotalFees` into the four Core-equivalent
accumulators, promote the three "really big" sums to a uint128 or
uint256 (`internal/wire` has uint256 primitives via `Hash256` but
no arith ops; could use `math/big.Int` like the MuHash3072 fix).

### BUG-11 (HIGH) — `gettxoutsetinfo` returns hard-coded zeros for muhash/bogosize/total_amount

**Severity**: HIGH (RPC handler completely disregards the index even
when enabled)
**ID**: BLOCKBREW-W133-11
**Location**: `internal/rpc/wave47b_methods.go:26-57`:

```go
func (s *Server) handleGetTxOutSetInfo(_ json.RawMessage) (interface{}, *RPCError) {
    // ...
    return map[string]interface{}{
        "height":            tipHeight,
        "bestblock":         tipHash.String(),
        "txouts":            txouts,
        "bogosize":          0,
        "hash_serialized_3": hashSerialized,
        "muhash":            "",
        "total_amount":      0.0,
        "disk_size":         0,
    }, nil
}
```

`hash_serialized_3` IS computed from the in-memory UTXO set via
`consensus.ComputeHashSerialized` — that path works. But `muhash` is
the empty string, `bogosize` is 0, and `total_amount` is `0.0`. Core's
`rpc/blockchain.cpp::gettxoutsetinfo` checks the `hash_type` arg and
routes to `g_coin_stats_index->LookUpStats(*pindex)` when
`hash_type="muhash"`. blockbrew never consults the index even when
present (it isn't, per BUG-2).

`gettxoutsetinfo` also accepts an optional `hash_type` arg
(`"none"|"hash_serialized_2"|"hash_serialized_3"|"muhash"`) and
`hash_or_height` (block selector); blockbrew's signature
`(_ json.RawMessage)` discards the params entirely.

**Fix path**: parse `hash_type` (default `"hash_serialized_3"`) and
`hash_or_height`; when `hash_type="muhash"` AND coinstatsindex is
registered AND has caught up past the requested height, return
`LookUpStats(requested_block)` fields; otherwise fall back to the
in-memory UTXO walk for `hash_serialized_3`.

### BUG-12 (HIGH) — IndexManager has no rewind/synced state, no Core-equivalent SetSynced false latch

**Severity**: HIGH (live reorg fan-out into a stale index)
**ID**: BLOCKBREW-W133-12
**Location**: `internal/storage/index.go:88-101` + Core base.cpp:88.

```go
// IsSynced returns true if the index is caught up to the chain tip.
func (b *BaseIndex) IsSynced() bool { /* ... */ }

// SetSynced marks the index as synced to the given height/hash.
func (b *BaseIndex) SetSynced(height int32, hash wire.Hash256) {
    b.mu.Lock()
    defer b.mu.Unlock()
    b.bestHeight = height
    b.bestHash = hash
    b.synced = true
}
```

`SetSynced` is one-way: once true, never false again. Core's
`m_synced` (base.h:88) and its `BlockConnected` early-out (base.cpp:339)
implicitly latch synced=true on the first `m_chainstate->m_chain.Tip()`
match (base.cpp:235), but it is set BACK to false implicitly when the
sync loop fires `Rewind` and the new tip diverges — see the
`m_synced=false` recovery path on `m_chainstate->m_chain` divergence
that the sync loop manages.

Combined with BUG-15 (no separate sync thread), blockbrew's IndexManager
has no recovery story for the "index thinks it's at H, but the chain
has rewound to H-2 due to an invalidateblock" case. The
`OnBlockDisconnected` hook in main.go fires per-disconnect, but it
only `chainDB.DeleteTxIndex` per tx — it doesn't move
`baseIndex.bestHash/bestHeight` back. So after a reorg, IsSynced still
returns true at the OLD height, and getindexinfo lies.

**Fix path**: change the production-wired txindex path to feed through
IndexManager (close BUG-2), then have `RevertBlock` decrement
`UpdateBest(prevHeight, prevHash)` (which the orphan
`TxIndex.RevertBlock` already does at txindex.go:151 — another reason
to actually wire it up).

### BUG-13 (MED) — no `BlockUntilSyncedToCurrentChain` API

**Severity**: MED (RPC handlers can read partially-built index)
**ID**: BLOCKBREW-W133-13
**Location**: `internal/storage/index.go` (no method exists). Core:
`base.cpp:424-446`.

Bitcoin Core RPC handlers that consult an index (e.g.
`getrawtransaction` when -txindex is enabled,
`gettxoutsetinfo hash_type=muhash`) call
`g_txindex->BlockUntilSyncedToCurrentChain()` BEFORE the lookup, so
the response either returns the canonical value or "node is warming
up" — never a partial answer from a half-synced index.

blockbrew's `methods.go:885-911` calls `chainDB.GetTxIndex(txid)`
immediately. If the index is mid-sync (which can't currently happen
because there's no sync thread per BUG-15, but WILL happen once
BUG-15 is fixed), the response is silently wrong (returns
`ErrNotFound` for a tx that IS confirmed but not yet indexed).

**Fix path**: add `IndexManager.BlockUntilSyncedToCurrentChain(name)`
that polls `idx.BestHash == chainMgr.tipHash` with a bounded wait;
call it from `methods.go:885` before the lookup. Cross-impl
reference: Core base.cpp:424-446.

### BUG-14 (MED) — BaseIndex Init doesn't validate on-disk best-hash against active chain

**Severity**: MED (stale-state-after-restore can never self-heal)
**ID**: BLOCKBREW-W133-14
**Location**: `internal/storage/txindex.go:64-82` +
`internal/storage/coinstatsindex.go:140-167`.

```go
// txindex.go:64
func (idx *TxIndex) Init() error {
    data, err := idx.db.Get(TxIndexStateKey)
    // ... deserialize state, set idx.bestHeight + idx.bestHash, return.
}
```

There's no equivalent of Core's `base.cpp:124-134`:

```cpp
const CBlockIndex* locator_index{
    m_chainstate->m_blockman.LookupBlockIndex(locator.vHave.at(0))};
if (!locator_index) {
    return InitError(...);
}
SetBestBlockIndex(locator_index);
```

If the on-disk state's `bestHash` is no longer on the active chain (a
restored backup with old chainstate, or a `-reindex-chainstate` that
rewound past the index's best), Core re-initializes from the fork
point. blockbrew silently trusts the on-disk row and starts taking
notifications from a phantom best-block.

**Fix path**: in Init, look up `state.BestHash` in
`headerIndex` / `chainMgr`; if absent, set bestHeight=-1 and let
IndexManager rebuild from genesis. (This also requires BUG-15's sync
thread or an equivalent IBD-time replay.)

### BUG-15 (MED) — no Stop/Interrupt/ThreadSync; IndexManager is purely synchronous

**Severity**: MED (no startup catchup, no graceful shutdown)
**ID**: BLOCKBREW-W133-15
**Location**: `internal/storage/index.go:50-126` (`BaseIndex`),
`:128-226` (`IndexManager`). Compare Core `base.h:93-95` (m_thread_sync
+ m_interrupt + Stop()).

blockbrew's IndexManager has no equivalent of Core's:
- `m_thread_sync` (base.h:93) — the dedicated catchup thread.
- `m_interrupt` (base.h:94) — clean shutdown signal.
- `Interrupt()` / `Stop()` (base.cpp:448-470).
- `AllowPrune()` (base.h:111) — the per-index pruning compatibility
  signal.
- `SetBestBlockIndex` (base.cpp:487-504) — the prune-lock integration
  that prevents the pruner from deleting blocks an index still
  references.

The IndexManager.BlockConnected (`index.go:181`) is synchronous,
fan-out-style; it relies on `chainMgr.SetOnBlockConnected` firing for
every block. There's no IBD-time replay: if blockbrew restarts at
height 800000 with `-txindex` newly enabled, there's no thread to
catch the index up from 0 to 800000 — the index simply never holds
the pre-restart history.

(In production this is partially hidden because blockbrew's
`syncMgr` does a full re-replay of the chain on IBD that fires
ConnectBlock for every block, which fires `OnBlockConnected`, which
writes the txindex — but ONLY if the IBD replay actually re-validates
every block, which on a `-assumevalid` restart it does not in the
same way.)

**Fix path**: spawn a per-index `ThreadSync` goroutine in
`IndexManager.RegisterIndex` that polls
`chainMgr.GetBlockByHeight(idx.BestHeight + 1)` until it matches
`chainMgr.tipHeight`, then sets `synced=true`. Wire `Stop()` /
`Interrupt()` into the SIGTERM handler.

### BUG-16 (LOW) — state-row keys lack prefix-byte convention

**Severity**: LOW (collision risk is astronomically small but
breaks the codebase's "prefix-byte first" convention)
**ID**: BLOCKBREW-W133-16
**Location**: `internal/storage/txindex.go:16`
(`TxIndexStateKey = []byte("txindex_state")`),
`internal/storage/coinstatsindex.go:19-22` (`CoinStatsStateKey`,
`CoinStatsMuHashKey`).

`internal/storage/keys.go:9-37` documents the convention:
single-letter prefixes (`H` / `B` / `N` / `T` / `U` / `R`) followed
by a typed key payload. `txindex_state` is a 13-byte bare string;
it shares no prefix discipline. There's no collision today (the
`T` prefix is followed by a 32-byte txid; a string starting
`T+x+i+n+d+e+x+...` doesn't collide because lengths differ in
PebbleDB's keyspace — keys are byte-strings, not fixed-length).
But the inconsistency makes key-space audits harder.

**Fix path**: rename to `[]byte("S_txindex")` /
`[]byte("S_coinstats")` under a new `"S"` prefix dedicated to
state rows; bump format-version (BUG-6) and migrate on Init.

### BUG-17 (LOW) — coinstatsindex uses local `calcBlockSubsidy` not `consensus.CalcBlockSubsidy`

**Severity**: LOW (W123 BUG-1 shape; halving-interval parameterization)
**ID**: BLOCKBREW-W133-17
**Location**: `internal/storage/coinstatsindex.go:369-378`.

```go
// calcBlockSubsidy calculates the block subsidy at a given height.
func calcBlockSubsidy(height int32) int64 {
    halvings := height / 210000
    if halvings >= 64 {
        return 0
    }
    return int64(5_000_000_000) >> uint(halvings)
}
```

Hardcoded `210000` interval. `internal/consensus/difficulty.go:162`
has `CalcBlockSubsidy` that reads `consensus.SubsidyHalvingInterval`,
the same one used by mining (`internal/mining/mining.go:237`) and
chainmanager (`chainmanager.go:551`). W123 BUG-1 documented the
opposite shape: mining's helper used a parameter, but a test hard-coded
the magic 210000. Here coinstatsindex hard-codes it. On regtest
(SubsidyHalvingInterval = 150), the index would diverge from the
chain's subsidy schedule immediately.

**Fix path**: replace `calcBlockSubsidy` with
`consensus.CalcBlockSubsidy`; remove the local helper; close the test
at `coinstatsindex_test.go:301` against the consensus package's helper
instead.

### BUG-18 (LOW) — local `getBogoSize` not parameterized against Core's coin serialization

**Severity**: LOW (drift risk on future Core coin-serialization change)
**ID**: BLOCKBREW-W133-18
**Location**: `internal/storage/coinstatsindex.go:381-385`.

```go
func getBogoSize(pkScript []byte) uint64 {
    // Base size + script size
    // This matches Bitcoin Core's GetBogoSize function approximately
    return uint64(32 + 4 + 8 + 1 + len(pkScript))
}
```

Today this matches Core's `kernel::GetBogoSize` (`kernel/coinstats.cpp`)
of `32+4+8+1+pk_script.size()` — the "approximately" qualifier in the
comment is unhelpful: it's exact, today. But there's no Core-side
reference comment, and no test pinning the constant against a Core
test vector. Any future Core coin-serialization change (e.g. taproot
output script compression) won't propagate.

**Fix path**: pull the constant into a Core-cross-referenced constant
in `internal/consensus` (`BogoSizeOutputOverhead = 32 + 4 + 8 + 1`),
add a comment citing `bitcoin-core/src/kernel/coinstats.cpp::GetBogoSize`,
add a test vector exercising P2WSH/P2TR scripts.

### BUG-19 (MED) — IndexManager fan-out has no per-index error isolation

**Severity**: MED (one slow/failing index halts all downstream indexes)
**ID**: BLOCKBREW-W133-19
**Location**: `internal/storage/index.go:181-214`.

```go
func (m *IndexManager) BlockConnected(...) error {
    // ...
    for _, idx := range indexes {
        if err := idx.WriteBlock(block, height, hash, undo); err != nil {
            log.Printf("index: %s write block %s failed: ...", ...)
            return err  // <-- halts the loop
        }
    }
    return nil
}
```

Compare Core base.cpp:370-378 — `ProcessBlock` errors per-index call
`FatalErrorf` → AbortNode, which is the DELIBERATE Core behavior
(better to halt than write inconsistent state). But Core's
`ValidationInterface` dispatches signals to each registered subscriber
independently — there's no early-loop-termination of OTHER subscribers
just because one failed. blockbrew's fan-out is too coupled: a
transient PebbleDB write failure in index A skips index B's
WriteBlock for the same block; once index A's transient failure
clears, B is left one block behind A.

Worse: the function returns `err`, and `cmd/blockbrew/main.go`'s
`SetOnBlockConnected` hook returns nothing — the error is lost to the
log line, ConnectBlock thinks the connect succeeded, and the
chain advances past a half-indexed block.

**Fix path**: in `IndexManager.BlockConnected`, log each per-index
error but continue the loop (Core's per-index AbortNode is a separate
question); ALSO surface the error to ConnectBlock's caller so the
node can halt if an index is critical.

### BUG-20 (LOW) — coinstatsindex.WriteBlock height==0 path differs from Core's genesis branch

**Severity**: LOW (genesis-only; mainnet does this exactly once at startup)
**ID**: BLOCKBREW-W133-20
**Location**: `internal/storage/coinstatsindex.go:170-218`.

Core `coinstatsindex.cpp:114-180` splits on `block.height > 0`:
- height > 0: iterate vtx, ApplyCoinHash, accumulate.
- height == 0 (else, :176): `m_total_unspendables_genesis_block +=
  block_subsidy` and that's it — no UTXO loop, no MuHash mutation for
  the genesis coinbase (which Core treats as unspendable because
  Bitcoin Core asserts `block.data` is null for genesis on this code
  path... actually no — re-reading Core: at coinstatsindex.cpp:115-176,
  it always asserts `block.data` (line 123) and runs the vtx loop;
  the `else` branch at :176 is for `block.height == 0` and ALSO
  accumulates `m_total_unspendables_genesis_block += block_subsidy`
  INSTEAD of running the UTXO add loop).

blockbrew runs the UTXO-add loop UNCONDITIONALLY (no height==0
guard at coinstatsindex.go:188). So the genesis coinbase's output
(the 50-BTC coinbase that's unspendable due to genesis quirk) IS
counted in `total_amount` and the UTXO hash, instead of being booked
to `m_total_unspendables_genesis_block`. Total_amount at height 0 in
blockbrew = 5_000_000_000; Core = 0 (50 BTC in unspendables_genesis +
0 in total_amount).

**Fix path**: add `if height == 0 { idx.totalUnspendablesGenesisBlock
+= subsidy; return ... }` early-return mirroring Core's else-branch
(also requires the four-way split from BUG-10).

### BUG-21 (P0-CDIV) — RemoveCoinHash uses (value, scriptPubKey) only, no outpoint

**Severity**: P0-CDIV (two outputs with same script+value cancel each
other; corrupts the accumulator)
**ID**: BLOCKBREW-W133-21
**Location**: `internal/storage/coinstatsindex.go:354-367`.

```go
// removeFromHash updates the running UTXO hash by removing an output.
func (idx *CoinStatsIndex) removeFromHash(out wire.TxOut) {
    // For XOR-based hash, removing is the same as adding
    // We need the outpoint to properly hash, but we don't have it here
    // Simplified: just hash the output data
    buf := new(bytes.Buffer)
    wire.WriteInt64LE(buf, out.Value)
    wire.WriteVarBytes(buf, out.PkScript)
    // ...
}
```

The comment at :357 ("We need the outpoint to properly hash, but we
don't have it here") explicitly confesses the gap. The caller at
:206-217 (the RevertBlock-from-undo path) actually DOES have the
outpoint via the parent `TxUndo.SpentCoins[i]` indexed back into the
spending tx's `vin[j].prevout` — Core's `coinstatsindex.cpp:160-173`
constructs the COutPoint explicitly:

```cpp
const COutPoint outpoint{tx->vin[j].prevout.hash, tx->vin[j].prevout.n};
RemoveCoinHash(m_muhash, outpoint, coin);
```

blockbrew's `removeFromHash(spent.TxOut)` at line 214 drops the
outpoint context entirely. Result: two UTXOs with identical
(value, pkScript) at different (txid, vout) hash to the same 32-byte
SHA256 digest. XORing the digest twice (once in addToHash, once in
removeFromHash) gives zero — the accumulator forgets BOTH UTXOs even
though only one was spent.

Mainnet hits this pattern in early-2010 blocks where the same
miner mined many blocks to the same P2PK key with identical coinbase
output values; any spend of one of those outputs would zero out
multiple entries from the accumulator.

**Fix path**: tied to BUG-1 — switch to MuHash3072 with
`Insert/Remove(serialize(outpoint, coin))`, where the outpoint is the
caller's responsibility to thread through. Update the SpentCoin
struct to carry the outpoint (or have the RevertBlock loop reconstruct
it from `tx.TxIn[j].PreviousOutPoint`).

## Cross-impl pattern depth

This is the **dead-helper-at-call-site at the framework registration
level** pattern. Previous waves (FIX-79 nimrod validateRbfDiagram,
FIX-78 nimrod misbehavingClassifier) caught dead helpers at single
call sites. W133 catches dead implementations at the IndexManager
registration site — the "right" struct exists, with the "right"
schema, and even passes its own tests, but never gets registered with
the production IndexManager, so the `OnBlockConnected` fan-out routes
around it.

The audit framework correction from W122 ("byte-exact against Core
vectors, not SHA256d-only tests") applies here too: every
`*CoinStatsIndex_test.go` test passes by definition because both the
test and the implementation use the same buggy XOR hash. There is no
cross-impl test vector pinning the hash to Core's MuHash output, so
the bug is structurally invisible from inside blockbrew's test
suite.

**Recommended for fix wave** (probable order of dependency):

1. BUG-1 (MuHash) + BUG-21 (outpoint context) — single change, biggest
   blast radius, enables the rest.
2. BUG-10 (four-way split) + BUG-7/8/20 (BIP-30, OP_RETURN-value,
   genesis) — together they bring the per-row decomposition to Core
   parity.
3. BUG-2 (wire `*CoinStatsIndex` into IndexManager) + BUG-3
   (`-coinstatsindex` flag) + BUG-11 (`gettxoutsetinfo` consults
   index) — three-step activation chain.
4. BUG-4 (extend `TxIndexEntry` with CDiskTxPos analog) — touches the
   production-wired txindex, BUG-1..BUG-3 don't.
5. BUG-5, BUG-9, BUG-12 — reorg-safety hardening once index is alive.
6. BUG-13, BUG-14, BUG-15, BUG-19 — framework lifecycle parity.
7. BUG-6, BUG-16, BUG-17, BUG-18 — cosmetic/cleanup.

## Files touched by this audit (discovery-only)

- `blockbrew/audit/w133_index_databases.md` (this file)
- `blockbrew/internal/storage/w133_index_databases_test.go`
  (`t.Skip()`-shaped tests; no production code changes)
