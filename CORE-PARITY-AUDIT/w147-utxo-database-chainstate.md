# W147 — UTXO database / chainstate (CCoinsView + CCoinsViewCache + CCoinsViewDB)

**Wave:** W147 — `CCoinsView` interface contract; `CCoinsViewCache` DIRTY/FRESH
flag machinery; `CCoinsViewDB` leveldb backend with `'C'+COutPoint` keys + Coin
compression; `obfuscate_key` XOR-mask layer; `FlushStateToDisk` trigger matrix;
`(height<<1) | is_coinbase` varint encoding; `AccessCoin` / `SpendCoin` flag
plumbing.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/txdb.cpp:23-27` — DB key constants:
  `DB_COIN{'C'}`, `DB_BEST_BLOCK{'B'}`, `DB_HEAD_BLOCKS{'H'}`,
  `DB_COINS{'c'}` (legacy v0.14).
- `bitcoin-core/src/txdb.cpp:41-49` — `CoinEntry` serialization: 1-byte tag
  `'C'` + uint256 hash + `VARINT(outpoint.n)` (NOT raw uint32 LE).
- `bitcoin-core/src/txdb.cpp:72-78` — `CCoinsViewDB::GetCoin(outpoint)` returns
  `std::optional<Coin>`; asserts `!coin.IsSpent()`.
- `bitcoin-core/src/txdb.cpp:81-90` — `HaveCoin` + `GetBestBlock`.
- `bitcoin-core/src/txdb.cpp:92-98` — `GetHeadBlocks` reads `DB_HEAD_BLOCKS`
  (mid-flush atomicity marker).
- `bitcoin-core/src/txdb.cpp:100-164` — `BatchWrite(cursor, hashBlock)`
  TWO-PHASE atomicity: writes `DB_HEAD_BLOCKS{hashBlock, old_tip}` + erases
  `DB_BEST_BLOCK` BEFORE the coin writes; flips back to `DB_BEST_BLOCK=hashBlock`
  in the final batch. On startup, if `DB_BEST_BLOCK` is null and
  `DB_HEAD_BLOCKS` has two entries → impossible-tip crash recovery requires
  reindex.
- `bitcoin-core/src/txdb.cpp:171-242` — `CCoinsViewDBCursor` iterates `DB_COIN`
  prefix; mandatory for `gettxoutsetinfo` / `dumptxoutset`.
- `bitcoin-core/src/coins.h:30-90` — `Coin` serialization: `VARINT(code =
  (nHeight*2) | fCoinBase)` + `Using<TxOutCompression>(out)`.
  `TxOutCompression` = `VARINT(CompressAmount(nValue))` +
  `ScriptCompression(scriptPubKey)`.
- `bitcoin-core/src/coins.h:109-200` — `CCoinsCacheEntry` with explicit
  `DIRTY = (1<<0)` / `FRESH = (1<<1)` bit flags + doubly-linked list of
  flagged entries (`m_sentinel`).
- `bitcoin-core/src/coins.cpp:89-130` — `AddCoin`: FRESH only set when the
  existing entry is spent AND `!IsDirty()` (so spentness still flushes).
- `bitcoin-core/src/coins.cpp:153-175` — `SpendCoin`: if entry IsFresh →
  ERASE from cache (no tombstone needed). Otherwise SetDirty + Clear (writes
  spent tombstone to parent on flush).
- `bitcoin-core/src/coins.cpp:208-277` — `CCoinsViewCache::BatchWrite`
  propagates FRESH flag correctly between cache levels; throws
  `std::logic_error("FRESH flag misapplied to coin that exists in parent
  cache")` on contract violation.
- `bitcoin-core/src/coins.cpp:279-300` — `Flush` vs `Sync`: Flush erases the
  cache (will_erase=true), Sync keeps it warm (will_erase=false).
- `bitcoin-core/src/compressor.cpp:55-138` — `CompressScript` recognizes 6
  special forms (P2PKH=0, P2SH=1, P2PK compressed even/odd=2/3, P2PK
  uncompressed even/odd=4/5). `nSize >= 6` encodes raw size as
  `nSize - nSpecialScripts`. NO P2WPKH / P2WSH / P2TR special forms in Core.
- `bitcoin-core/src/compressor.cpp:149-192` — `CompressAmount`: mantissa+
  exponent encoding (NOT identity).
- `bitcoin-core/src/dbwrapper.h:192` — `OBFUSCATION_KEY{"\000obfuscate_key",
  14}` — explicit-size 14-byte key stored at zero-prefixed key.
- `bitcoin-core/src/dbwrapper.cpp:217-262` — `CDBWrapper` constructor reads
  or generates the obfuscate key on open; every value is XOR'd through it on
  Read/Write.
- `bitcoin-core/src/dbwrapper.h:96-102, 207-219` — `Write()`/`Read()` apply
  `m_obfuscation` to value bytes.
- `bitcoin-core/src/validation.cpp:2700-2900` — `FlushStateToDisk(mode)`
  dispatches on `FlushStateMode{NONE, IF_NEEDED, PERIODIC, ALWAYS}`; consults
  `dbcache` (default 450 MiB) + `m_last_flush` + `nMempoolUsage` to decide.
- `bitcoin-core/src/kernel/caches.h:15` — `DEFAULT_DB_CACHE_BATCH = 32 MiB`
  (per-write-batch size).
- `bitcoin-core/src/kernel/caches.h:13` — `DEFAULT_KERNEL_CACHE = 450 MiB`.

**Files audited (blockbrew)**
- `internal/consensus/utxoset.go` — `UTXOSet`, FRESH/DIRTY plumbing,
  `Flush()`, `FlushBatch()`, `CompressScript`/`DecompressScript`,
  `SerializeUTXOEntry`/`DeserializeUTXOEntry`, `writeVaruint`/`readVaruint`,
  `AccessByTxid`, `ApplyTxInUndo`, `SpendUTXOWithCoin` (1210 LOC).
- `internal/consensus/core_compressor.go` — `CoreCompressScript`,
  `CoreCompressAmount`, `WriteCoreVarInt` (Core-byte-compatible compression
  USED ONLY for snapshot import/export; 424 LOC).
- `internal/consensus/utxohash.go` — `WriteTxOutSer`, HASH_SERIALIZED /
  MuHash3072 (161 LOC).
- `internal/storage/keys.go` — `MakeUTXOKey`, `UTXOPrefix`, key encoding
  (87 LOC).
- `internal/storage/chaindb.go` — `ChainDB` wrapper, `SetChainState`,
  `WriteBlockUndoBatch`, batch helpers (374 LOC).
- `internal/storage/chainstate.go` — `ChainState` (best hash + height),
  `BlockUndo` serialization (203 LOC).
- `internal/storage/pebbledb.go` — `PebbleDB` backend, default config,
  iterator (399 LOC).
- `internal/storage/db.go` — `DB` interface (49 LOC).
- `internal/storage/undo_compress.go` — Third copy of CompressScript (for
  undo blobs; intentional cross-package duplication).
- `internal/consensus/chainmanager.go:580-1060` — UTXO flush + chainstate
  write integration.
- `cmd/blockbrew/main.go:272-280, 474` — `-dbcache` config default (2560
  MiB).

---

## Gate matrix (30 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | CCoinsView interface contract | G1: GetCoin returns Optional (or pointer + ok) | PASS (`utxoset.go:83-124` GetUTXO returns `*UTXOEntry`) |
| 1 | … | G2: HaveCoin cheap-existence query | PARTIAL (`utxoset.go:224-246` HasUTXO exists but always touches DB Has on miss) |
| 1 | … | G3: GetBestBlock returns chainstate tip hash | PASS (`chaindb.go:240-249` GetChainState) |
| 1 | … | G4: BatchWrite atomic commit takes (cursor, hashBlock) | **BUG-1 (P0-CDIV)** `FlushBatch` takes only the batch; mid-flush atomicity marker (DB_HEAD_BLOCKS) absent |
| 1 | … | G5: Cursor() iterator over coin DB | **BUG-2 (P1)** no `CCoinsViewDBCursor` analog — iteration over UTXO DB done ad-hoc via PebbleDB.NewIterator with raw prefix |
| 2 | CCoinsViewCache DIRTY+FRESH | G6: DIRTY flag set on cache modification | PARTIAL (`utxoset.go:144` uses `u.dirty[outpoint] = true` — DIRTY is implicit via map presence, no bitflag) |
| 2 | … | G7: FRESH flag set when entry never read from parent | **BUG-3 (P0)** `AddUTXO` unconditionally sets `fresh=true` even when overwriting an entry that was already in cache from DB |
| 2 | … | G8: FRESH+spend → erase from cache, no tombstone | PARTIAL (works at `SpendUTXO:167-170` but predicated on the buggy FRESH set above; can still produce UTXO RESURRECTION via ApplyTxInUndo path) |
| 2 | … | G9: doubly-linked sentinel list for flagged entries | FAIL (`utxoset.go:39-59` uses three Go maps; no sentinel list; `m_dirty_count` not tracked) |
| 2 | … | G10: FRESH propagated correctly between cache levels | N/A — blockbrew has only 1 cache level (no parent/grandparent stack) |
| 3 | CCoinsViewDB key encoding | G11: 1-byte tag `'C'` (0x43) | **BUG-4 (P0-CDIV)** uses `'U'` (0x55) instead — `UTXOPrefix = []byte("U")` |
| 3 | … | G12: hash 32B + VARINT(n) (NOT uint32 LE) | **BUG-5 (P0-CDIV)** uses `BigEndian.PutUint32(key[33:], outpoint.Index)` — 4B BE; Core uses VARINT (1-5 bytes) |
| 3 | … | G13: DB_BEST_BLOCK = 'B' (1 byte) | **BUG-6 (P0-CDIV)** uses `[]byte("chainstate")` (10 bytes) |
| 3 | … | G14: DB_HEAD_BLOCKS = 'H' for mid-flush atomicity | **BUG-7 (P0)** no DB_HEAD_BLOCKS analog; ANY crash mid-flush leaves chainstate `BestHash` pointing at a tip whose coin writes were only partially committed (Pebble batch is atomic per chunk; but `flushLocked` chunks across multiple batches — line 281-292) |
| 4 | Coin compression | G15: CompressAmount mantissa+exponent | **BUG-8 (P0-CDIV)** on-disk `SerializeUTXOEntry` writes raw amount via CompactSize. `CompressAmount` exists in `core_compressor.go` but is used ONLY for snapshot dump/load |
| 4 | … | G16: CompressScript 6 forms (P2PKH/P2SH/P2PK comp×2/uncomp×2) | **BUG-9 (P0-CDIV)** chainstate `CompressScript:619-670` uses 6 forms but DIFFERENT tag set: P2PKH=0,P2SH=1,P2WPKH=2,P2WSH=3,P2TR=4,unknown=5 vs Core's P2PKH=0,P2SH=1,P2PKComp=2/3,P2PKUncomp=4/5 (no segwit special forms in Core) |
| 4 | … | G17: P2PK compression decompresses pubkey via secp256k1 | PASS (`core_compressor.go:182-205` — but only on snapshot path) |
| 4 | … | G18: Same compression used everywhere (disk + snapshot) | **BUG-10 (P0)** THREE coexisting compression schemes: `CompressScript` (disk), `CoreCompressScript` (snapshot), and `compressScript` in `undo_compress.go` (undo blobs); intentional and documented but means a disk file written by blockbrew CANNOT be read by Core (no migration path) |
| 5 | obfuscate_key XOR mask | G19: 8-byte obfuscate key stored in DB | **BUG-11 (P0-CDIV)** ENTIRELY ABSENT in chainstate; mempool persist.go uses XOR obfuscation but chainstate values are stored cleartext (zero-byte search of an IBD'd pebble DB reveals consensus-relevant script fragments) |
| 5 | … | G20: XOR'd on every read + write | FAIL — no XOR layer in PebbleDB.Get/Put |
| 5 | … | G21: key is "\x00obfuscate_key" (14 bytes with leading NUL) | FAIL — no obfuscation key key |
| 6 | FlushStateToDisk triggers | G22: mode enum NONE/IF_NEEDED/PERIODIC/ALWAYS | **BUG-12 (P0)** no FlushStateMode equivalent; single `MaybeFlush(forceAfterBlocks)` covers IBD; shutdown path / reorg path / pruning path all reuse this one trigger (W100 audit also caught this) |
| 6 | … | G23: dbcache default = 450 MiB | **BUG-13 (P1)** default = 2560 MiB (5.7× Core's default); not a divergence per se but breaks "drop-in datadir" claim in README |
| 6 | … | G24: DEFAULT_DB_CACHE_BATCH = 32 MiB per partial batch | **BUG-14 (P1)** uses 2 GiB cap (line 279 `maxBatchBytes`) — 64× larger than Core; correct for Pebble's 4 GiB limit but allocations the entire IBD UTXO into one batch |
| 7 | (height<<1)|coinbase encoding | G25: VARINT (7-bit per byte) | **BUG-15 (P0-CDIV)** uses CompactSize (1-9 byte length-prefixed; `writeVaruint:751`) for the `heightCode`; Core uses serialize.h VARINT (Different byte layout — a height=300_000 coin encodes as 3 bytes Core / 5 bytes blockbrew) |
| 7 | … | G26: shift back on read | PASS (`utxoset.go:854-855`) |
| 7 | … | G27: encoding cross-impl-compatible with Core | FAIL — composite of BUG-8 + BUG-15 + BUG-9 means blockbrew's on-disk Coin is byte-incompatible with Core's |
| 8 | AccessCoin / SpendCoin flag plumbing | G28: SpendCoin marks DIRTY on cache so flush emits delete | PASS (`utxoset.go:153-174` deletes from `dirty` and adds to `deleted`) |
| 8 | … | G29: AccessCoin falls back through cache→parent | PASS (`utxoset.go:83-124` GetUTXO checks cache then DB) |
| 8 | … | G30: ApplyTxInUndo + Spend re-adds with correct FRESH semantics | **BUG-3 cross-cite** — restored entry marked FRESH; if re-spent before flush, the on-disk row stays alive → UTXO resurrection class |

---

## BUG-1 (P0-CDIV) — `BatchWrite` skips the DB_HEAD_BLOCKS mid-flush atomicity marker

**Severity:** P0-CDIV. Core's `CCoinsViewDB::BatchWrite` writes
`DB_HEAD_BLOCKS = {hashBlock, old_tip}` AND erases `DB_BEST_BLOCK` BEFORE the
coin writes, then flips back to `DB_BEST_BLOCK = hashBlock` after they complete.
A crash mid-flush leaves a two-element `DB_HEAD_BLOCKS` and null `DB_BEST_BLOCK`
— so on next startup the node knows it must reindex from the old_tip rather
than silently load a partial UTXO set.

**File:** `internal/consensus/utxoset.go:269-364` (flushLocked),
`internal/consensus/chainmanager.go:1023-1040` (FlushBatch into shared batch),
`internal/storage/chainstate.go:169-203` (ChainState format).

**Core ref:** `bitcoin-core/src/txdb.cpp:100-164`.

**Description:** `flushLocked` chunks the in-memory cache into per-2-GiB
batches (line 279-292). A crash between two chunks leaves SOME coin writes
committed, others not — and `BestHash` was either NOT yet written (`shouldFlush`
gate) OR was written via a separate later batch. There is NO two-phase marker
the next startup can use to detect "this datadir was mid-flush; refuse to load
without reindex." Compared to Core, the worst-case crash window is *silent
UTXO loss* (partial writes silently retained as if they were a complete flush).

**Excerpt:**
```go
// utxoset.go:281-330
batch := u.db.DB().NewBatch()
chunks := 0
flushChunk := func() error {
    if batch.Len() == 0 { return nil }
    if err := batch.Write(); err != nil { return err }
    chunks++
    batch = u.db.DB().NewBatch()
    return nil
}
for outpoint := range u.dirty {
    entry := u.cache[outpoint]
    ...
    if approxBatchBytes >= maxBatchBytes {
        if err := flushChunk(); err != nil { return err }
        approxBatchBytes = 0
    }
}
// No DB_HEAD_BLOCKS marker is written at the start.
// No DB_BEST_BLOCK erase before the chunked writes.
```

**Impact:** Datadirs that experience a crash during a large flush (e.g.
snapshot import) can silently drift from the announced tip. Recovery requires
`-reindex-chainstate` but the node can't detect that it should.

---

## BUG-2 (P1) — No `CCoinsViewDBCursor` over coin DB; iteration is ad-hoc

**Severity:** P1 (correctness/RPC-coverage). Bitcoin Core exposes
`CCoinsViewDB::Cursor()` so `gettxoutsetinfo`, `dumptxoutset`, MuHash3072,
and assumeUTXO snapshot writers can stream the UTXO set without loading it
into memory. blockbrew's `ComputeHashSerialized` only iterates the **in-memory
cache** (see comment at `utxohash.go:91-96`: "this only iterates the IN-MEMORY
cache … does not yet produce a correct digest mid-IBD when the UTXO set has
spilled to disk").

**File:** `internal/consensus/utxohash.go:91-96, 129-144`,
`internal/consensus/utxoset.go` (no `Cursor()` method).

**Core ref:** `bitcoin-core/src/txdb.cpp:171-242`.

**Description:** Tagged in a comment as a known limitation. `gettxoutsetinfo`
and `dumptxoutset` results are silently WRONG when the UTXO set has been
flushed (i.e., for any node past the first IBDFlushInterval boundary). The
sort-and-hash path will only see coins still in cache after `Flush` evictions
(`utxoset.go:341-361` rebuilds the cache map keeping only a fraction).

**Excerpt:**
```go
// utxohash.go:91-96 (comment)
// A production Core implementation walks the chainstate DB cursor; we'll
// switch to that once the snapshot writer does too. This is therefore safe
// to use AFTER a LoadSnapshot (which puts every coin into the cache) but does
// not yet produce a correct digest mid-IBD when the UTXO set has spilled
// to disk.
```

**Impact:** `gettxoutsetinfo.hash_serialized_3` is fleet-incompatible with
Core and other blockbrew nodes mid-IBD; `dumptxoutset` produces snapshots
that miss every flushed coin (catastrophic correctness loss for the snapshot
output).

---

## BUG-3 (P0) — `AddUTXO` unconditionally sets FRESH; UTXO-resurrection on undo

**Severity:** P0. Core's `AddCoin` (`coins.cpp:89-130`) sets FRESH only when
`!it->second.IsDirty()` — i.e. the existing entry was clean (just read from
parent), OR the entry didn't exist at all. blockbrew unconditionally sets
`fresh=true` on every Add — even when the entry being added is restoring a
coin that was previously flushed to disk during a reorg.

**File:** `internal/consensus/utxoset.go:132-149`.

**Core ref:** `bitcoin-core/src/coins.cpp:96-114`.

**Description:** `ApplyTxInUndo` at `utxoset.go:1116-1150` calls `u.AddUTXO`
to restore a spent coin during disconnect. The coin was deleted from the
on-disk DB on the original flush. Restoring it now marks it FRESH=true. If
this same coin is then spent AGAIN inside the same flush window (very common
in reorgs — disconnect block B, then connect block B' that spends the same
input), the FRESH+spend path at `SpendUTXO:167-170` SKIPS the disk delete
("never written to disk, skip writing a tombstone"). But the coin IS on
disk — so we leave a stale on-disk row that GetUTXO will then resurrect.

**Excerpt:**
```go
// utxoset.go:143-148
u.cache[outpoint] = entry
u.dirty[outpoint] = true
// Mark as FRESH: this entry has never been written to disk.
// If it's spent before the next flush, we skip the write entirely.
u.fresh[outpoint] = true
delete(u.deleted, outpoint) // Clear any pending deletion
```

**Impact:** Reorg-then-respend produces a phantom UTXO on disk. Subsequent
GetUTXO reads (after the next cache flush evicts the in-memory tombstone)
will resurrect the supposedly-spent coin → double-spend admissibility.
Concretely: any consensus check that round-trips through the on-disk view
can be tricked into accepting a tx that re-spends a coin already consumed
on the post-reorg chain.

---

## BUG-4 (P0-CDIV) — UTXO key uses `'U'` instead of Core's `'C'`

**Severity:** P0-CDIV (byte-incompatible chainstate format).

**File:** `internal/storage/keys.go:27-79`.

**Core ref:** `bitcoin-core/src/txdb.cpp:23`.

**Description:** Core uses `static constexpr uint8_t DB_COIN{'C'}` (0x43).
blockbrew defines `UTXOPrefix = []byte("U")` (0x55). A blockbrew pebbledb
chainstate is not byte-compatible with a Bitcoin Core chainstate at the key
level.

**Excerpt:**
```go
// keys.go:27-78
UTXOPrefix = []byte("U")
...
func MakeUTXOKey(outpoint wire.OutPoint) []byte {
    key := make([]byte, 1+32+4)
    key[0] = UTXOPrefix[0]
    copy(key[1:33], outpoint.Hash[:])
    binary.BigEndian.PutUint32(key[33:], outpoint.Index)
    return key
}
```

**Impact:** No cross-impl chainstate compatibility (`-load-snapshot` from
Core dump would land coins under `C` prefix but lookups go to `U`). Combined
with BUG-5, BUG-6, BUG-8, BUG-9, BUG-15: blockbrew's chainstate is a separate
format that requires its own backup/restore tooling — no datadir interop.

---

## BUG-5 (P0-CDIV) — UTXO key uses 4-byte big-endian uint32 for vout, not VARINT

**Severity:** P0-CDIV (byte-incompatible).

**File:** `internal/storage/keys.go:72-79`.

**Core ref:** `bitcoin-core/src/txdb.cpp:48` — `SERIALIZE_METHODS(CoinEntry,
obj) { READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n)); }`.

**Description:** Core encodes `outpoint.n` as a `VARINT` (1-5 bytes,
mantissa-MSB-first, 7-bit-per-byte continuation encoding). blockbrew encodes
it as 4 bytes big-endian. For the typical case of `n < 128`, Core uses 1
byte vs blockbrew's 4 — chainstate is 3 bytes per coin larger than Core's
even before considering script/amount compression deltas.

**Excerpt:**
```go
// keys.go:73-79
func MakeUTXOKey(outpoint wire.OutPoint) []byte {
    key := make([]byte, 1+32+4)
    key[0] = UTXOPrefix[0]
    copy(key[1:33], outpoint.Hash[:])
    binary.BigEndian.PutUint32(key[33:], outpoint.Index)
    return key
}
```

**Impact:** Per-coin key overhead ~3 bytes larger than Core; ~500 MB extra
on a full IBD's ~160M coins. More importantly: byte-incompatible with Core's
chainstate, so dumptxoutset snapshots cannot be exchanged on the key level.

---

## BUG-6 (P0-CDIV) — Best-block stored at `"chainstate"` key, not `'B'`

**Severity:** P0-CDIV.

**File:** `internal/storage/keys.go:33-34`.

**Core ref:** `bitcoin-core/src/txdb.cpp:24` — `DB_BEST_BLOCK{'B'}` is a
**single-byte** key.

**Description:** blockbrew uses `[]byte("chainstate")` — a 10-byte ASCII
string. Core uses a single-byte 0x42 (`'B'`) key. Combined with BUG-4 (UTXO
prefix is `'U'`), a single blockbrew pebbledb cannot host a Core chainstate
on overlapping keys without collisions.

**Excerpt:**
```go
// keys.go:33-34
// ChainStateKey stores the current chain tip hash and height.
ChainStateKey = []byte("chainstate")
```

**Impact:** Key bytes diverge from Core. No interop. Also the
serialization differs (BUG-7 below).

---

## BUG-7 (P0) — DB_HEAD_BLOCKS analog absent; no two-phase-commit marker

**Severity:** P0 (durability under crash).

**File:** `internal/storage/keys.go` (no constant defined),
`internal/storage/chaindb.go:240-260`.

**Core ref:** `bitcoin-core/src/txdb.cpp:25, 92-98, 128-130, 158`.

**Description:** Core writes `DB_HEAD_BLOCKS = Vector(hashBlock, old_tip)`
into the same batch that ERASES `DB_BEST_BLOCK`, BEFORE coin writes begin.
The final batch erases DB_HEAD_BLOCKS and writes DB_BEST_BLOCK back to
hashBlock. A crash anywhere mid-flush leaves DB_HEAD_BLOCKS=2-element vector
and DB_BEST_BLOCK absent, which `GetHeadBlocks` detects on next start and
forces reindex (`txdb.cpp:111-117`).

blockbrew has no equivalent. `SetChainStateBatch` (`chaindb.go:258-260`)
writes a single `ChainState{BestHash, BestHeight}` blob, and the chunked
flush at `utxoset.go:269-340` commits multi-batch UTXO writes without a
sentinel marker — so a crash after some chunks land but before chainstate
flips leaves the disk silently inconsistent.

**Excerpt:**
```go
// chainmanager.go:1023-1040
if shouldFlush {
    type batchFlusher interface { FlushBatch(storage.Batch) error }
    if f, ok := cm.utxoSet.(batchFlusher); ok {
        if err := f.FlushBatch(batch); err != nil { ... }
    }
}
if writeChainState {
    cm.chainDB.SetChainStateBatch(batch, &storage.ChainState{
        BestHash:   hash,
        BestHeight: node.Height,
    })
}
if err := batch.Write(); err != nil { ... }
```

This single-batch is fine for the small-flush case, but `FlushBatch` at
`utxoset.go:443-489` does NOT chunk — it expects the caller's batch to
absorb everything. The chunking-flushLocked path (line 269-364) does NOT
write chainstate at all — it's called by the non-batch `Flush()` paths
(shutdown, snapshot import).

**Impact:** A SIGKILL during snapshot import (`-load-snapshot`) leaves the
chainstate at the pre-import tip with PARTIAL post-import UTXOs already
committed. Subsequent reads will see a "Frankenstein" UTXO set that combines
the old chain's tip metadata with new chain's coins. No automatic detection.

---

## BUG-8 (P0-CDIV) — Amount stored uncompressed; `CompressAmount` never reaches disk

**Severity:** P0-CDIV.

**File:** `internal/consensus/utxoset.go:824-843`, `core_compressor.go:218-257`.

**Core ref:** `bitcoin-core/src/compressor.cpp:149-192`, `coins.h:64-78`.

**Description:** Core's on-disk Coin serializes `nValue` as
`VARINT(CompressAmount(nValue))` (mantissa+exponent encoding). blockbrew's
`SerializeUTXOEntry` writes the raw `entry.Amount` through `writeVaruint`
(CompactSize). For a 50 BTC coinbase (5e9 sat), Core encodes in 3 bytes
(compressed value 0x32 + VARINT) vs blockbrew's 9 bytes (CompactSize-FE for
uint32 range). For typical mixed-amount UTXO sets the on-disk Coin is
1.5-2× larger than Core's.

The `CompressAmount` function IS implemented in `core_compressor.go:218`
but is used ONLY by the snapshot dump/load path, never by the chainstate
read/write path. Classic "well-engineered helper never wired" pattern.

**Excerpt:**
```go
// utxoset.go:824-843
func SerializeUTXOEntry(entry *UTXOEntry) []byte {
    var buf bytes.Buffer
    heightCode := uint64(entry.Height) << 1
    if entry.IsCoinbase { heightCode |= 1 }
    writeVaruint(&buf, heightCode)
    writeVaruint(&buf, uint64(entry.Amount))   // raw sat amount, no compression
    compressedScript := CompressScript(entry.PkScript)
    writeVaruint(&buf, uint64(len(compressedScript)))
    buf.Write(compressedScript)
    return buf.Bytes()
}
```

**Impact:** Disk size 1.5-2× larger than Core; cross-impl interop impossible.

---

## BUG-9 (P0-CDIV) — `CompressScript` tag table diverges from Core

**Severity:** P0-CDIV (chainstate byte-incompatible).

**File:** `internal/consensus/utxoset.go:554-562, 619-670`.

**Core ref:** `bitcoin-core/src/compressor.cpp:55-138`.

**Description:** Core's compressor tag table:
```
0x00 = P2PKH
0x01 = P2SH
0x02 = P2PK with 0x02 prefix (compressed even)
0x03 = P2PK with 0x03 prefix (compressed odd)
0x04 = P2PK uncompressed (even Y)
0x05 = P2PK uncompressed (odd Y)
nSize >= 6 = raw script of length (nSize - 6)
```

blockbrew's chainstate tag table:
```
0x00 = P2PKH
0x01 = P2SH
0x02 = P2WPKH     ← WRONG (Core treats as raw)
0x03 = P2WSH      ← WRONG
0x04 = P2TR       ← WRONG
0x05 = unknown / raw  ← WRONG (Core's 0x05 = uncompressed P2PK odd)
```

Core has NO special compression form for P2WPKH / P2WSH / P2TR — they're
stored raw (since their script bytes ARE the witness program, fully
compressed already). blockbrew "compresses" them by stripping the
1-byte witness version + 1-byte push opcode, saving ~2 bytes per output —
but does so at tags Core uses for P2PK pubkey recovery.

**Excerpt:**
```go
// utxoset.go:554-562
const (
    scriptTypeP2PKH   = 0x00
    scriptTypeP2SH    = 0x01
    scriptTypeP2WPKH  = 0x02   // collides with Core's compressed-P2PK-even
    scriptTypeP2WSH   = 0x03   // collides with Core's compressed-P2PK-odd
    scriptTypeP2TR    = 0x04   // collides with Core's uncompressed-P2PK-even
    scriptTypeUnknown = 0x05   // collides with Core's uncompressed-P2PK-odd
)
```

Compare `core_compressor.go:31-42` which DEFINES the correct Core-compatible
tags but uses them ONLY in the snapshot path. Two coexisting tag tables in
the same codebase.

**Impact:** A Core-dumped UTXO snapshot loaded raw into blockbrew's
chainstate would misread tag 0x02 as P2WPKH, decompressing 32 bytes from a
20-byte P2PK pubkey hash → garbled scriptPubKey → script-validation
divergence. Strictly worse than just-different-tags: silent corruption.

---

## BUG-10 (P0) — Three coexisting CompressScript implementations

**Severity:** P0 (maintenance + correctness drift).

**File:** `internal/consensus/utxoset.go:619-670` (chainstate disk),
`internal/consensus/core_compressor.go:98-128` (snapshot dump/load),
`internal/storage/undo_compress.go:99-200` (undo blob compression).

**Description:** "TWO/THREE-PIPELINE GUARD" pattern from the fleet audit
playbook. Three separate `CompressScript`-shaped functions in three packages,
each with subtly different tag tables and special-form handling:

1. `consensus.CompressScript` — non-Core tags (BUG-9), used on `'U'`-prefixed
   chainstate.
2. `consensus.CoreCompressScript` — Core tags, used on `dumptxoutset`
   snapshots only.
3. `storage.compressScript` — also non-Core tags, used on `'R'`-prefixed
   undo blobs.

Per `undo_compress.go:26-30`:
> The script-compression helpers below are an intentional duplicate of the
> ones in internal/consensus/utxoset.go. Storage cannot import consensus
> (consensus imports storage), and lifting them into a shared package would
> be a larger refactor than this perf fix justifies.

This "intentional" duplication means:
- Adding a new compression tag requires touching THREE files.
- A new special-form check (e.g. P2A) would need to be added 3× or all 3
  paths drift.
- The snapshot path's tags will silently disagree with the chainstate path's
  tags forever.

**Impact:** Maintenance smell that has already produced BUG-9. Any future
optimization (e.g. compress P2A outputs) is a 3× change with high risk of
drift. Counts as the well-known "three-pipeline guard" anti-pattern.

---

## BUG-11 (P0-CDIV) — `obfuscate_key` XOR mask absent from chainstate

**Severity:** P0-CDIV / minor security defense-in-depth gap.

**File:** `internal/storage/pebbledb.go:180-220` (Get/Put — no XOR layer),
`internal/storage/keys.go` (no obfuscate key constant).

**Core ref:** `bitcoin-core/src/dbwrapper.h:192` — `OBFUSCATION_KEY{"\000
obfuscate_key", 14}`; `bitcoin-core/src/dbwrapper.cpp:217-262` (load + apply
on every Read/Write).

**Description:** Core stores an 8-byte random `obfuscate_key` under the
14-byte key `"\x00obfuscate_key"` and XOR's it (looped to value length)
through every value byte on write/read. The purpose is primarily anti-virus
false-positives — script bytes containing OP_RETURN patterns or known-malware
byte sequences would otherwise trip a/v scans on Windows during IBD.

blockbrew's `PebbleDB.Put` (`pebbledb.go:200-202`) writes raw cleartext bytes.
A grep across an IBD'd blockbrew chainstate would show recognizable script
fragments (P2WSH redeem scripts, OP_RETURN data carriers).

**Excerpt:**
```go
// pebbledb.go:200-202
func (p *PebbleDB) Put(key, value []byte) error {
    return p.db.Set(key, value, pebble.NoSync)
}
```

**Impact:** Three-fold:
1. Cross-impl interop: a Core chainstate dropped into a blockbrew datadir
   would be unreadable (values XOR'd with Core's obfuscate key).
2. Defense-in-depth gap on Windows hosts running a/v software.
3. Marketing claim "Core-compatible chainstate" is false.

---

## BUG-12 (P0) — No FlushStateMode dispatch (NONE/IF_NEEDED/PERIODIC/ALWAYS)

**Severity:** P0 (operational coverage). Also tracked by W100 audit.

**File:** `internal/consensus/utxoset.go:368-384` (single MaybeFlush helper),
`internal/consensus/chainmanager.go:972-974` (only IBD-block-count trigger).

**Core ref:** `bitcoin-core/src/validation.h:54-60`, `validation.cpp:2700-2900`.

**Description:** Core has 4 distinct flush modes:
- `NONE` — post-ActivateBestChain no-op
- `IF_NEEDED` — emergency flush when cache CRITICAL
- `PERIODIC` — every ~1h or large cache
- `ALWAYS` (`FORCE_FLUSH`) — shutdown + force

blockbrew has ONE: `MaybeFlush(forceAfterBlocks)` which only triggers on
`blocksSinceFlush >= forceAfterBlocks` OR `cacheBytes > maxCacheBytes`. No
"emergency flush" hook on memory pressure observed from outside the UTXOSet.
No "periodic by wallclock" trigger.

**Excerpt:**
```go
// utxoset.go:368-384
func (u *UTXOSet) MaybeFlush(forceAfterBlocks int) error {
    u.mu.Lock()
    defer u.mu.Unlock()
    u.blocksSinceFlush++
    if u.cacheBytes > u.maxCacheBytes || u.blocksSinceFlush >= forceAfterBlocks {
        return u.flushLocked()
    }
    return nil
}
```

**Impact:** Long-running nodes with low block rate (post-IBD steady-state)
never flush by time, only by block count. A bug that causes cache bloat
without crossing the byte threshold silently keeps the chainstate stale on
disk for hours. Shutdown path also relies on this single trigger.

---

## BUG-13 (P1) — Default `-dbcache` 2560 MiB vs Core's 450 MiB

**Severity:** P1 (operational behavior surprise).

**File:** `cmd/blockbrew/main.go:474`.

**Core ref:** `bitcoin-core/src/kernel/caches.h:13` — `DEFAULT_KERNEL_CACHE =
450 MiB`.

**Description:** blockbrew defaults to `-dbcache=2560` (2.5 GiB), 5.7×
Core's 450 MiB default. While larger caches speed up IBD, this is invisible
to operators copying Core launch incants and silently uses 5.7× more memory
than expected.

**Excerpt:**
```go
// cmd/blockbrew/main.go:474
flag.IntVar(&cfg.DBCache, "dbcache", 2560, "Database cache size in MiB
  (split: 80% UTXO cache + 20% Pebble block cache; recommend 4096+ for
  active IBD)")
```

**Impact:** On a 4 GiB box with the docs' "use the Core defaults" advice,
blockbrew silently consumes 2.5 GiB before any block validation. OOM risk
on small VMs. README does not document the larger default.

---

## BUG-14 (P1) — Per-flush batch cap 2 GiB vs Core's 32 MiB

**Severity:** P1.

**File:** `internal/consensus/utxoset.go:279-280`.

**Core ref:** `bitcoin-core/src/kernel/caches.h:15` —
`DEFAULT_DB_CACHE_BATCH = 32 MiB`.

**Description:** Core writes partial batches every 32 MiB inside
`CCoinsViewDB::BatchWrite` (`txdb.cpp:142-154`). blockbrew uses 2 GiB chunks
(64× larger). The justification (Pebble's 4 GiB hard cap) is correct, but
Core's intent is to minimize per-crash data loss — a 32 MiB chunk caps loss
at ~640k coins; a 2 GiB chunk caps at ~40M coins.

**Excerpt:**
```go
// utxoset.go:279-280
const maxBatchBytes = 2 * 1024 * 1024 * 1024 // 2 GiB
```

**Impact:** Crash mid-flush loses up to 64× more recent work than Core would.
Combined with BUG-7 (no DB_HEAD_BLOCKS marker), the loss is silent.

---

## BUG-15 (P0-CDIV) — `heightCode` written as CompactSize, not Core's VARINT

**Severity:** P0-CDIV.

**File:** `internal/consensus/utxoset.go:749-783, 827-832`.

**Core ref:** `bitcoin-core/src/coins.h:64-78` —
`::Serialize(s, VARINT(code));`.

**Description:** Core writes `heightCode = (nHeight*2) | fCoinBase` as a
`VARINT` (Core's `serialize.h` 7-bits-per-byte, big-endian-with-MSB-
continuation encoding — totally different from CompactSize). blockbrew's
`writeVaruint` (line 751) writes CompactSize (the P2P wire format: 1, 3, 5,
or 9 bytes with explicit FD/FE/FF marker bytes).

For a typical chainstate (heights up to 1M, doubled to ~2M), Core's VARINT
encodes in 3 bytes; blockbrew's CompactSize uses 3 bytes (FE marker + 4-byte
LE) for any value ≥ 0xFD. So byte counts differ for ALL height codes ≥ 253
— i.e., every coin from block 127 onward.

Critically, the BYTE LAYOUT differs (continuation MSB vs marker-prefix), so
even where lengths match the bytes don't.

**Excerpt:**
```go
// utxoset.go:751-781 — CompactSize, NOT Core's VARINT
func writeVaruint(w *bytes.Buffer, val uint64) {
    switch {
    case val < 0xFD:
        w.WriteByte(byte(val))
    case val <= 0xFFFF:
        w.WriteByte(0xFD)  // marker
        ...
}
```

vs the correct Core VARINT implementation at `core_compressor.go:263-289`
(`WriteCoreVarInt`) which IS used by the snapshot path. So blockbrew has
both encodings in tree but the wrong one reaches chainstate disk.

**Impact:** On-disk Coin record byte-incompatible with Core's. Combined with
BUG-8 (amount compression), BUG-9 (script compression tags), BUG-11
(obfuscate_key absence) → at no point is a blockbrew chainstate readable
by Core or vice versa.

---

## BUG-16 (P1) — `HaveCoin` always touches disk on cache miss; no cheap existence test

**Severity:** P1 (performance + correctness divergence).

**File:** `internal/consensus/utxoset.go:224-246`.

**Core ref:** `bitcoin-core/src/coins.cpp:188-191` — `HaveCoin` is
`HaveCoinInCache || base->HaveCoin` and Core's `CCoinsViewDB::HaveCoin` calls
`m_db->Exists()` (a bloom-filter-accelerated probe) NOT `Read`.

**Description:** blockbrew's `HasUTXO` calls `u.db.DB().Has(key)` which on
PebbleDB requires `pebble.DB.Get()` (`pebbledb.go:210-220`), which reads the
value into memory before discarding. Pebble's iterator API has `SeekPrefixGE
+ HasNext` that's cheaper for existence-only checks, but blockbrew doesn't
use it.

**Excerpt:**
```go
// pebbledb.go:210-220
func (p *PebbleDB) Has(key []byte) (bool, error) {
    _, closer, err := p.db.Get(key)   // full read
    if err == pebble.ErrNotFound { return false, nil }
    if err != nil { return false, err }
    closer.Close()
    return true, nil
}
```

**Impact:** Hot-path `HasUTXO` calls (e.g. BIP-30 duplicate-coinbase check)
do unnecessary value reads. Per-call overhead ~10× higher than a true
existence probe. Not consensus-affecting; performance only.

---

## BUG-17 (P1) — `CoinEntry` opaque-tag-byte not exposed; cursor cannot filter on `'C'`

**Severity:** P1.

**File:** `internal/storage/pebbledb.go:243-262`, `internal/storage/keys.go`.

**Core ref:** `bitcoin-core/src/txdb.cpp:43-49` — `CoinEntry::key{DB_COIN}`
serializes the tag byte FIRST so iterators can early-exit when the tag
changes (`txdb.cpp:228-230` `Valid() = keyTmp.first == DB_COIN`).

**Description:** Core's `Cursor()` checks `keyTmp.first == DB_COIN` after
each `Next()`, so iteration terminates the instant the cursor walks past the
last coin key into `DB_BEST_BLOCK` / `DB_HEAD_BLOCKS` keys. blockbrew's
PebbleDB iterator uses a bounded range
(`opts.LowerBound, opts.UpperBound`) but cannot distinguish the `'U'`-prefix
range from the `'V'`-prefix range without re-checking key[0] on every Next.
Today there's no `'V'` key in use, so this is latent — but the moment a new
key prefix is added between `'U'` and the next existing prefix, cursors will
silently over-iterate.

**Impact:** Future maintenance bug carrier. Reorgs after a new key prefix is
introduced (e.g. assumeUTXO snapshot index) may iterate into wrong-keytype
rows and decode them as Coin → deserialization error or worse,
mis-deserialization.

---

## BUG-18 (P2) — `DeserializeUTXOEntry` script-size cap is 10000, Core's is 10003

**Severity:** P2 (latent edge case).

**File:** `internal/consensus/utxoset.go:868-870`.

**Core ref:** `bitcoin-core/src/script/script.h:39` — `MAX_SCRIPT_SIZE =
10000`; Core's compressor.cpp on read replaces over-large scripts with
`OP_RETURN` (line 95-138 in DecompressScript).

**Description:** blockbrew rejects script lengths > 10000 with an error
(returns nil, errors.New("script too large")). Core's `DecompressScript`
silently replaces over-large bodies with a single OP_RETURN byte. This is
a documented behavior used to preserve unspendable but oversized scripts.

**Excerpt:**
```go
// utxoset.go:868-870
if scriptLen > 10000 {
    return nil, errors.New("script too large")
}
```

The snapshot path at `core_compressor.go:404-409` DOES implement the
OP_RETURN swap correctly, confirming the divergence is between
chainstate-read and snapshot-read paths.

**Impact:** A future protocol upgrade allowing > 10000-byte scripts (or a
legacy block already on chain with such a script via OP_RETURN datacarrier)
fails to deserialize from blockbrew's chainstate but loads cleanly from a
Core dump. Today there are no such on-chain scripts so the divergence is
latent.

---

## BUG-19 (P1) — `flushLocked` does not write chain state; race with `SetChainState`

**Severity:** P1 (atomicity).

**File:** `internal/consensus/utxoset.go:269-364`.

**Core ref:** `bitcoin-core/src/txdb.cpp:128-159` — `BatchWrite` writes
chain state IN THE SAME BATCH as the coin writes.

**Description:** Core's `CCoinsViewDB::BatchWrite` is the ONLY way to flush
coins, and it WRITES `DB_BEST_BLOCK` in the final sub-batch. blockbrew has
TWO flush paths:

1. `Flush()` → `flushLocked()` (line 249-364) — chunks coin writes but
   NEVER writes chain state. Used by shutdown, snapshot import, manual
   flush.
2. `FlushBatch(batch)` (line 443-489) — writes coin updates into a
   caller-supplied batch; caller (chainmanager) adds chain state to the
   same batch. Used by IBD periodic flush.

Path #1 leaves the on-disk chain state untouched. If `BestHash` was written
by a previous batch and points at a tip whose coins are NOW being newly
flushed by path #1, the gap between the coin write and the next chain-state
write is unprotected — any startup in that window sees inconsistent state.

**Excerpt:**
```go
// utxoset.go:269-364 — flushLocked has no equivalent to txdb.cpp:159
// "batch.Write(DB_BEST_BLOCK, hashBlock)".
func (u *UTXOSet) flushLocked() error {
    ...
    for outpoint := range u.dirty { ... batch writes ... }
    for outpoint := range u.deleted { ... batch deletes ... }
    if err := flushChunk(); err != nil { return err }
    // Returns without writing chain state.
}
```

**Impact:** Shutdown-on-IBD path: Flush() at shutdown writes coins but not
chain state; a subsequent startup reads stale `BestHash` (the
last-checkpointed value, NOT the just-flushed tip). Subsequent IBD restarts
from the previous checkpoint, potentially re-validating up to
`flushInterval=2000` blocks of work.

---

## BUG-20 (P2) — `estimateEntrySize` ignores Go map overhead per entry

**Severity:** P2.

**File:** `internal/consensus/utxoset.go:126-130`.

**Core ref:** `bitcoin-core/src/coins.h:87-89` —
`DynamicMemoryUsage() = memusage::DynamicUsage(out.scriptPubKey)`.

**Description:** blockbrew estimates 100 bytes "map overhead" per entry,
hardcoded. Real Go map cost per entry (hmap bucket + key + value pointer) is
closer to 48 bytes on amd64, BUT Go maps over-allocate by load-factor 6.5
and grow by power-of-two — actual memory consumption is 1.5-2× the
estimated size on average.

**Excerpt:**
```go
// utxoset.go:126-130
func estimateEntrySize(entry *UTXOEntry) int64 {
    return int64(36 + 8 + len(entry.PkScript) + 4 + 1 + 100)
}
```

**Impact:** maxCacheBytes accounting drifts by ~30% under real load. Cache
flush triggers earlier than expected, or memory consumption silently
exceeds the configured `-dbcache`. Not consensus-affecting.

---

## BUG-21 (P1) — `Cursor()` interface from DB type not exposed for UTXO iteration

**Severity:** P1.

**File:** `internal/storage/db.go:38-49`, `internal/storage/pebbledb.go:243-262`.

**Core ref:** `bitcoin-core/src/dbwrapper.h:120-170` (`CDBIterator`).

**Description:** The `DB.NewIterator(prefix)` interface is present and
correct, but no public method on `UTXOSet` exposes it for safe iteration
that traverses both cache AND disk. Callers wanting to walk every coin must
either (a) walk the in-memory cache only (as `collectAndSortCacheCoins`
does — BUG-2 cross-cite) or (b) directly grab `u.db.DB().NewIterator(UTXOPrefix)`
and skip cache, missing all unflushed entries.

**Impact:** Any future consumer (RPC `gettxoutsetinfo` accurate path,
`dumptxoutset` flushing path, MuHash periodic recompute) must implement its
own cache+disk merge join, an error-prone pattern that will produce
divergent UTXO summaries across implementations.

---

## BUG-22 (P2) — `ChainState` serialization stores int32 height as LE 4-byte; Core stores VARINT

**Severity:** P2 (interop only).

**File:** `internal/storage/chainstate.go:175-202`.

**Core ref:** Bitcoin Core stores no explicit height; the chain state is
just `hashBestChain` (32 bytes) at `DB_BEST_BLOCK` (`txdb.cpp:85-90`). Height
is recovered via `m_blockman` BlockIndex on startup.

**Description:** blockbrew's ChainState carries both `BestHash` AND
`BestHeight`. Core stores only the hash and looks up the height from the
BlockIndex (so the height is implicitly verified against the block tree).
blockbrew's stored height is trusted blindly on startup
(`chainmanager.go:loadChainState`).

**Excerpt:**
```go
// chainstate.go:175-181
func (cs *ChainState) Serialize() []byte {
    buf := new(bytes.Buffer)
    cs.BestHash.Serialize(buf)
    wire.WriteInt32LE(buf, cs.BestHeight)
    return buf.Bytes()
}
```

**Impact:** If the on-disk height drifts from the headerindex height (e.g.
via a botched reorg), blockbrew silently trusts the on-disk value where
Core would re-derive from the block tree.

---

## BUG-23 (P2) — `UndoBlockPrefix = 'R'` clashes with Core's `'r'` rev-file prefix

**Severity:** P2 (interop).

**File:** `internal/storage/keys.go:30-31`.

**Core ref:** Bitcoin Core stores undo data in `rev*.dat` flat files, NOT
in the leveldb chainstate at all (`blockstorage.cpp:WriteBlockUndo`).

**Description:** blockbrew inlines undo blobs in pebbledb under the `'R'`
prefix. Core uses block-file flat storage (`rev00000.dat` etc.). This is
not a divergence per se — both approaches durably persist undo — but it
means blockbrew's pebbledb grows linearly with chain history (W84 mentions
that undo "still flows through Pebble" deliberately for reorg speed). The
'R' key prefix doesn't collide with anything in the Core scheme today, but
note that Core's lowercase `'r'` is reserved for the rev-file index.

**Impact:** Pebble compaction overhead per startup includes the full undo
blob set, ~30 GiB for mainnet vs Core's much smaller leveldb (which only
indexes rev-files). Not consensus-affecting.

---

## BUG-24 (P2) — `MaybeFlushIBD` block-count interval hardcoded to 2000

**Severity:** P2.

**File:** `internal/consensus/utxoset.go:25-27, 381-384`.

**Core ref:** Core's flush is triggered by `dbcache` usage AND elapsed time
(default 1h), NOT block count.

**Description:** `IBDFlushInterval = 2000` is hardcoded. Operators cannot
adjust without recompiling. Combined with BUG-12 (no time-based trigger),
this is the ONLY operational lever for flush cadence during IBD.

**Excerpt:**
```go
// utxoset.go:25-27
const IBDFlushInterval = 2000
```

**Impact:** Operators tuning blockbrew for low-RAM hosts cannot reduce the
flush interval; they're stuck with 2000 blocks of pending UTXO writes
buffered. Tuning lever absent.

---

## BUG-25 (P3) — `prefixUpperBound` overflow case returns nil; pebble iterator scans entire keyspace

**Severity:** P3 (defense-in-depth).

**File:** `internal/storage/pebbledb.go:273-291`.

**Description:** When `prefix` is all-0xFF, `prefixUpperBound` returns nil
which Pebble treats as "no upper bound" → iterate the entire keyspace.
Today no blockbrew key prefix is `0xFF`, so the bug is latent.

**Excerpt:**
```go
// pebbledb.go:283-291
for i := len(upper) - 1; i >= 0; i-- {
    upper[i]++
    if upper[i] != 0 {
        return upper
    }
}
// prefix was all 0xFF, no upper bound possible
return nil
```

**Impact:** Future use of `0xFF` prefix for any key class would cause that
class's iterator to silently scan all later prefixes too. Belt-and-braces
fix: return `prefix` unchanged or an explicit error.

---

## Fleet-pattern smells observed

1. **Two/three-pipeline guard (CompressScript ×3)** — BUG-10. Three coexisting
   compression schemes in three packages, two with intentionally divergent
   tag tables. Joins the fleet pattern tracked in W141 and earlier.
2. **Well-engineered helper never wired** — BUG-8, BUG-15. `CompressAmount`
   and `WriteCoreVarInt` are byte-perfect Core ports … used only by the
   snapshot path. The chainstate disk format silently uses non-Core encodings.
3. **Comment-as-confession** — BUG-2 explicit in `utxohash.go:91-96`:
   > "This is therefore safe to use AFTER a LoadSnapshot … but does not yet
   > produce a correct digest mid-IBD when the UTXO set has spilled to disk."
4. **Dead-helper at call-site** — `CoreCompressScript` exists, is exported, is
   tested, but is never called by `SerializeUTXOEntry`. Mirrors W141's
   pattern label for blockbrew.
5. **Carry-forward re-anchor candidates** — BUG-3 (FRESH overgeneralized) +
   BUG-7 (no DB_HEAD_BLOCKS) + BUG-19 (flushLocked skips chain state) all
   touch the chainstate atomicity gate together; any single fix is risky
   without the other two.
6. **Compounding-divergence stack** — BUG-4 (key prefix 'U'≠'C') × BUG-5
   (vout BE uint32 vs VARINT) × BUG-6 ("chainstate"≠'B') × BUG-8 (amount
   uncompressed) × BUG-9 (script tags collide) × BUG-11 (no obfuscate_key)
   × BUG-15 (CompactSize vs VARINT) = SEVEN independent layers of on-disk
   incompatibility with Core. None alone is a chain-split risk; together
   they mean blockbrew's "chainstate" cannot interop with any other impl.

---

## Severity histogram

| Sev | Count | IDs |
|-----|-------|-----|
| P0-CDIV | 8 | 1, 4, 5, 6, 8, 9, 11, 15 |
| P0 | 4 | 3, 7, 10, 12 |
| P1 | 7 | 2, 13, 14, 16, 17, 19, 21 |
| P2 | 5 | 18, 20, 22, 23, 24 |
| P3 | 1 | 25 |
| **Total** | **25** | |

8 P0-CDIV findings on a single subsystem is a high-water mark for blockbrew;
the chainstate format is effectively a separate dialect rather than a Core
parity port.
