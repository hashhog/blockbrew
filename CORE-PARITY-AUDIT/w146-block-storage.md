# W146 — Block storage layer (blockbrew)

**Wave:** W146 — `blkXXXXX.dat` + `revXXXXX.dat` flat-file storage,
`FindBlockPos` rotation / `BLOCKFILE_CHUNK_SIZE` preallocation, magic-
prefixed framing, `BlockManager::WriteBlock` / `WriteBlockUndo` durability,
block-index leveldb keys (`'b' / 'f' / 'l' / 'F' / 'R' / 't'`), reindex
flag, recovery on partial write.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/blockstorage.h:118-129` — constants
  (`BLOCKFILE_CHUNK_SIZE=0x1000000=16 MiB`, `UNDOFILE_CHUNK_SIZE=0x100000=1 MiB`,
  `MAX_BLOCKFILE_SIZE=0x8000000=128 MiB`, `STORAGE_HEADER_BYTES=8`,
  `UNDO_DATA_DISK_OVERHEAD=8+32=40`).
- `bitcoin-core/src/node/blockstorage.cpp:58-62` — DB prefix bytes
  (`DB_BLOCK_FILES='f'`, `DB_BLOCK_INDEX='b'`, `DB_FLAG='F'`,
  `DB_REINDEX_FLAG='R'`, `DB_LAST_BLOCK='l'`).
- `bitcoin-core/src/node/blockstorage.cpp:833-921` — `FindNextBlockPos`:
  per-chain-type cursor, rotate when `nSize + nAddSize >= MAX_BLOCKFILE_SIZE`,
  `m_block_file_seq.Allocate(pos, nAddSize, out_of_space)` returns
  preallocated bytes via `posix_fallocate`.
- `bitcoin-core/src/node/blockstorage.cpp:1134-1165` — `WriteBlock`:
  open file at returned pos, write `MessageStart() << block_size` then
  `TX_WITH_WITNESS(block)`, `fclose` (BufferedWriter flushes on scope exit).
- `bitcoin-core/src/node/blockstorage.cpp:967-1034` — `WriteBlockUndo`:
  `FindUndoPos(state, nFile, pos, blockundo_size + UNDO_DATA_DISK_OVERHEAD)`,
  then `MessageStart << blockundo_size` then `blockundo` then a SHA256d
  checksum over `(pprev.blockhash || blockundo)`.
- `bitcoin-core/src/node/blockstorage.cpp:1036-1132` — `ReadBlock` /
  `ReadRawBlock`: open file, parse `MessageStartChars`, reject on
  `blk_start != GetParams().MessageStart()` ("Block magic mismatch"),
  reject `blk_size > MAX_SIZE (0x02000000 = 32 MiB)`, then deserialize.
- `bitcoin-core/src/node/blockstorage.cpp:683-727` — `ReadBlockUndo`:
  `HashVerifier` checks the SHA256d checksum (`hashChecksum !=
  verifier.GetHash()` → reject).
- `bitcoin-core/src/node/blockstorage.cpp:732-769` — `FlushBlockFile` +
  `FlushUndoFile`: `m_block_file_seq.Flush(pos, fFinalize)` truncates
  preallocated tail and fsync's; undo path is **separate** and called
  on rotation + on the catch-up block.
- `bitcoin-core/src/flatfile.cpp:59-86` — `FlatFileSeq::Allocate`:
  `CeilDiv(pos.nPos + add_size, m_chunk_size)`, `CheckDiskSpace`,
  `AllocateFileRange` via `posix_fallocate`.
- `bitcoin-core/src/util/fs_helpers.cpp:181-220` — `AllocateFileRange`:
  posix_fallocate primary path, fallback to ftruncate+pwrite-zeros on
  unsupported FS. Actually reserves disk blocks (NOT a sparse file).
- `bitcoin-core/src/node/blockstorage.cpp:74-86, 1167-1209` — reindex
  flag (`DB_REINDEX_FLAG='R'`) + `xor.dat` obfuscation key created in
  `InitBlocksdirXorKey`.
- `bitcoin-core/src/index/txindex.cpp:31` — `DB_TXINDEX='t'`; stores
  `(Txid → CDiskTxPos{nFile,nPos,VARINT(nTxOffset)})`.
- `bitcoin-core/src/index/disktxpos.h:11-23` — `CDiskTxPos` extends
  `FlatFilePos` with `nTxOffset` (byte offset of this tx within the
  serialized block), so `getrawtransaction` can read a single tx without
  loading the entire block.
- `bitcoin-core/src/kernel/messagestartchars.h:11` — `MessageStartChars
  = std::array<uint8_t, 4>` (raw bytes, not a uint32, so on-disk
  encoding is byte-order independent).
- `bitcoin-core/src/serialize.h:34` — `MAX_SIZE = 0x02000000` (32 MiB)
  cap on deserialize length prefix.

**Files audited (impl):**
- `internal/storage/flatfile.go` (870 LOC) — `BlockStore`,
  `WriteBlock`, `WriteUndo`, `ReadBlock`, `ReadUndo`,
  `WriteAndIndexBlock`, `WriteAndIndexUndo`, `BlockFileInfo`,
  `flushFile`, `allocateSpace`, state persistence.
- `internal/storage/chaindb.go` — `StoreBlockAt`, `WriteBlockUndo`,
  `WriteBlockUndoBatch`, `ReadBlockUndo`, header batching.
- `internal/storage/keys.go` — DB prefix bytes
  (`'H' / 'B' / 'N' / 'T' / 'U' / 'R'`).
- `internal/storage/chainstate.go` — `BlockUndo`, `TxUndo`, `SpentCoin`
  serialization.
- `internal/storage/undo_compress.go` — v1 compressed undo blob (0xFF
  tag + dispatch). blockbrew-specific extension, not in Core.
- `internal/storage/prune.go` — `Pruner`, `PruneOneBlockFile`,
  `UnlinkPrunedFile`, `MaybePrune`.
- `internal/consensus/chainmanager.go:585, 994, 1016, 1054, 1402,
  2194` — production undo write call sites.
- `internal/p2p/sync.go:1879-1892` — `StoreBlockAt` call site (block
  body persisted to flatfile during sync).
- `cmd/blockbrew/main.go:610-628, 710-720, 1808-1820` —
  `networkMagic`, `NewBlockStore` wiring; refusal to start on
  `-reindex`.
- `internal/p2p/message.go:29-33` — magic constants
  (`MainnetMagic 0xD9B4BEF9`, etc — little-endian uint32 interp of
  Core's MessageStart byte sequence).
- `internal/consensus/chaincfg.go:200, 286, 351, 414, 492` —
  per-network `NetworkMagic [4]byte` arrays.

---

## Gate matrix (32 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | blk*.dat framing | G1: 4-byte magic prefix, on-disk byte order matches Core | PASS (`flatfile.go:278-281` LE write of `0xD9B4BEF9` → bytes `F9 BE B4 D9`) |
| 1 | … | G2: 4-byte little-endian size after magic | PASS (`flatfile.go:280`) |
| 1 | … | G3: per-network magic plumbed through `networkMagic()` | PASS (`main.go:612-628`) |
| 1 | … | G4: ReadBlock rejects on magic mismatch | PASS (`flatfile.go:351-354`) |
| 1 | … | G5: Size prefix capped at Core's MAX_SIZE = 32 MiB | **BUG-1 (P1)** caps at `maxFileSize` = 128 MiB |
| 2 | rev*.dat framing | G6: magic+size prefix on each undo blob | **BUG-2 (P1-DEAD)** WriteUndo never invoked in production — undo lives in LevelDB blob |
| 2 | … | G7: SHA256d checksum over `(pprev.blockhash \|\| blockundo)` after blob | **BUG-3 (P0-CDIV)** completely missing — silent disk-corruption on undo data goes undetected (cross-cite BUG-2 — dead path AND broken) |
| 2 | … | G8: per-input prevout values (height + coinbase + TxOut) | PASS in legacy format (`chainstate.go:30-99`) |
| 3 | FindBlockPos rotation | G9: rotate at `nSize + nAddSize >= MAX_BLOCKFILE_SIZE` | PASS (`flatfile.go:247` `currentPos+totalSize > maxFileSize`) but **BUG-4 (P2)** uses strict `>` vs Core's `>=` — boundary-equal blocks go in old file |
| 3 | … | G10: per-chain-type cursor (NORMAL vs ASSUMED) | **BUG-5 (P2-DEAD)** assumeUTXO snapshot blockfile segregation absent (single cursor; W138 confirmed assumeUTXO scaffolding is dead) |
| 3 | … | G11: preallocate in `BLOCKFILE_CHUNK_SIZE` (16 MiB) chunks via posix_fallocate | **BUG-6 (P0)** `os.File.Truncate` creates SPARSE file — disk blocks NOT actually reserved; out-of-space detection only at write time, not allocate time |
| 3 | … | G12: separate `UNDOFILE_CHUNK_SIZE` (1 MiB) preallocation on rev files | **BUG-7 (P1)** WriteUndo opens rev file with no preallocation whatsoever |
| 3 | … | G13: `-fastprune` test mode (`max_blockfile_size = 0x10000 = 64 kB`) | **BUG-8 (P3)** missing — no analogous test knob |
| 4 | FlushBlockFile durability | G14: fsync block file on rotation | PASS (`flatfile.go:249, 514-540`) |
| 4 | … | G15: truncate preallocated tail on finalize | PASS (`flatfile.go:531-537`) |
| 4 | … | G16: **separate** FlushUndoFile fsync of rev file on rotation | **BUG-9 (P1)** no FlushUndoFile equivalent; rev files never explicitly fsync'd on rotation |
| 4 | … | G17: `cursor.undo_height` heuristic to trim catch-up undo file | **BUG-10 (P2-DEAD)** undo-vs-block cursor split absent (cross-cite BUG-2) |
| 5 | Block-index leveldb keys | G18: `'b' + hash` → CBlockIndex entry | **BUG-11 (P1-CDIV)** blockbrew uses `'H' + hash` for the 80-byte header only; CBlockIndex equivalent lives in in-memory `headerIndex` not persisted under `'b'` |
| 5 | … | G19: `'f' + filenum` → BlockFileInfo | PASS (`flatfile.go:545, 570-580` — agrees with Core) |
| 5 | … | G20: `'l'` → last block file index | **BUG-12 (P2-CDIV)** blockbrew uses `'F'` (capital) for a combined "last file + count + position" blob; Core uses `'l'` for last-file scalar only |
| 5 | … | G21: `'F' + name` → flag entries | **BUG-13 (P0-CDIV)** Key-prefix CONFLICT: blockbrew's `flatFileStateKey = "F"` (`flatfile.go:544`) collides with Core's `DB_FLAG = 'F'` (Core uses two-byte prefix `'F' + name`). On any Core-compat datadir share this guarantees a corrupted decode |
| 5 | … | G22: `'R'` → reindex flag | **BUG-14 (P0-CDIV)** Key-prefix CONFLICT: blockbrew uses `'R' + hash` (32 + 1 = 33 bytes) for **legacy undo blobs** (`keys.go:31`); Core uses `'R'` (1 byte, no suffix) for the **reindex flag**. Adjacent keys; iteration semantics differ. Either node mis-reads the other |
| 5 | … | G23: `'t' + txid` → txindex | **BUG-15 (P1-CDIV)** blockbrew uses `'T'` (uppercase) for txindex; Core uses lowercase `'t'` |
| 6 | WriteBlock atomicity | G24: blk*.dat write+fsync BEFORE leveldb index commit | PASS-with-caveat (`flatfile.go:286-313`: blockData written → file.Sync → batch.Write of fileInfo state → then **separate** db.Put of pos index). But **BUG-16 (P1)** the pos-index Put (`'P' + hash → FlatFilePos`) is NOT batched with the chain-state ConnectBlock batch — crash between WriteAndIndexBlock and `cm.chainDB.batch.Write()` leaves block on disk + pos indexed but no chain-state advance |
| 6 | … | G25: ConnectBlock chain-state + undo committed in a single batch | PASS (`chainmanager.go:1004-1044`) |
| 6 | … | G26: full block body and undo land via Pebble batch with chain-state | **BUG-17 (P0)** undo blob committed via `WriteBlockUndoBatch` (Pebble path under `'R' + hash`) but block BODY committed via separate flatfile path; ordering inverted vs Core's WriteBlock-before-batch invariant (cross-cite BUG-2 — production undo never goes to disk via `rev*.dat`) |
| 7 | ReadBlock + checksum | G27: magic-mismatch rejection | PASS (`flatfile.go:351-354`) |
| 7 | … | G28: re-validate CheckProofOfWork against header bits after deserialize | **BUG-18 (P2)** ReadBlock returns bytes — caller is responsible. Core's `BlockManager::ReadBlock` re-runs `CheckProofOfWork` (`blockstorage.cpp:1057-1061`) inside the read path, making it impossible to forget |
| 7 | … | G29: signet block-solution check on signet | **BUG-19 (P2-DEAD)** signet block-solution recheck on read absent |
| 7 | … | G30: xor.dat obfuscation key on blocks dir | **BUG-20 (P2-CDIV)** absent — blockbrew blk*.dat files are plaintext. Core (since v25, 2023) obfuscates with a per-datadir XOR key from `blocks/xor.dat` to defeat anti-virus pattern-matching false positives |
| 8 | Recovery on partial write | G31: `'R'` reindex flag triggers full block-file replay | **BUG-21 (P0)** `-reindex` HONEST-DEFERRED — blockbrew refuses to start with `--reindex` (`main.go:319-324`). No recovery path at all for corruption / partial write |
| 8 | … | G32: bad-magic at expected pos → file truncation recovery | **BUG-22 (P1)** `ErrBadMagic` propagated up as plain error; no truncation/recovery logic, no automatic rewind of `currentPos` |

---

## BUG-1 (P1) — ReadBlock size cap = maxFileSize (128 MiB) vs Core's MAX_SIZE (32 MiB)

**Severity:** P1. Memory-bomb / pathological-buffer hazard.

After parsing the 4-byte size prefix, blockbrew checks `size > bs.maxFileSize`
(128 MiB). Core uses the deserialization-wide ceiling `MAX_SIZE = 0x02000000`
(32 MiB, `serialize.h:34`). A corrupted size prefix between 32 MiB and 128 MiB
is accepted by blockbrew (and a 128 MiB `make([]byte, size)` allocation
fires) where Core rejects.

In practice, real block bodies cap at `MAX_BLOCK_SERIALIZED_SIZE = 4 MB`
(`consensus.h:13`), so this is not a consensus issue — only a memory-hardening
gap on a corrupted file read.

**File:** `internal/storage/flatfile.go:357-360`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1110-1114` and
`bitcoin-core/src/serialize.h:34`

**Excerpt (blockbrew)**
```go
size := binary.LittleEndian.Uint32(header[4:8])
if size > bs.maxFileSize {
    return nil, ErrBlockTooLarge
}
data := make([]byte, size)
```

**Core**
```cpp
if (blk_size > MAX_SIZE) {
    LogError("Block data is larger than maximum deserialization size for %s: %s versus %s while reading raw block",
        pos.ToString(), blk_size, MAX_SIZE);
    return util::Unexpected{ReadRawError::IO};
}
```

**Impact:** corrupted blk*.dat read with size prefix in (32 MiB, 128 MiB] →
multi-megabyte allocation per request. Trivial-DoS surface if attacker can
poison the on-disk file.

---

## BUG-2 (P1-DEAD) — `BlockStore.WriteUndo` + `WriteAndIndexUndo` are DEAD CODE

**Severity:** P1-DEAD (fleet pattern: assumeutxo-class dead module).

`flatfile.go` defines a complete rev*.dat write path: `WriteUndo` (372 LOC
incl. allocation), `WriteAndIndexUndo` (idempotency wrapper), `ReadUndo`,
`ReadUndoByHash`, `GetUndoPos` / `IndexUndo` / `HasUndo` /
`DeleteUndoIndex`, all keyed under `UndoPosPrefix = "p"` in `BlockStore.db`.

But **no production call site invokes any of them.** A `grep -rn
'WriteAndIndexUndo\|bs\.WriteUndo\|blockStore\.WriteUndo'` across the
non-test, non-worktree tree returns only the definitions themselves. Every
production undo write goes through `ChainDB.WriteBlockUndoBatch` /
`WriteBlockUndo` → `MakeUndoBlockKey(hash) = "R" + hash` → straight into
Pebble as a single value blob (`chaindb.go:268-313`).

The dead-code surface is therefore: 4 functions, ~120 LOC, full leveldb
key infrastructure (`'p' + hash`, `MakeUndoPosKey`, etc), one
`v1-compressed-undo` wire format extension (`undo_compress.go`), and the
`BlockFileInfo.UndoSize` accounting field that the production path never
populates.

This is the same dead-class pattern catalogued fleet-wide in W138
(ChainstateManager / BackgroundValidator / run_background_validation —
9 of 10 impls).

**File:** `internal/storage/flatfile.go:371-477, 799-816`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:967-1034`

**Excerpt (the dead production call sites)**
```go
// flatfile.go:801 — defined but never called from non-test code
func (bs *BlockStore) WriteAndIndexUndo(hash wire.Hash256, fileNum int32, undoData []byte) (FlatFilePos, error) {
    ...
}

// chaindb.go:269 — the ACTUAL production path; writes undo to Pebble under "R"+hash
func (c *ChainDB) WriteBlockUndoBatch(batch Batch, hash wire.Hash256, undo *BlockUndo) {
    key := MakeUndoBlockKey(hash)  // "R" + hash
    batch.Put(key, undo.Serialize())
}
```

**Impact:** ~120 LOC of unreachable code maintained on every refactor.
More importantly, all the rev*.dat invariants in this audit (BUG-3,
BUG-7, BUG-9, BUG-10) sit on top of code that the production node never
executes — so even if the bugs are fixed, they only matter once
blockbrew wires the dead path to the production undo writer.

---

## BUG-3 (P0-CDIV) — undo data has no checksum

**Severity:** P0-CDIV. Silent corruption fork.

Core wraps every blockundo write in a `HashWriter` keyed by
`pprev.blockhash`, then appends the resulting `uint256` checksum to the
on-disk blob (`blockstorage.cpp:991-1000`). On read, `HashVerifier`
re-runs the same hash chain and rejects with "Checksum mismatch" if the
blob has drifted (`blockstorage.cpp:711-723`).

blockbrew's `BlockUndo.Serialize()` (`chainstate.go:101-128`) writes only
the TxUndo count and serialized SpentCoin records — no leading prev-hash,
no trailing checksum, no per-blob integrity machinery. When the Pebble
blob is corrupted (bit-flip on the underlying SSD, partial fsync, prune
race), `DeserializeBlockUndo` either succeeds with garbage values (most
common: stale heights, miscounted coins) or fails with a deserialize
error. The garbage-values path is the consensus risk: `DisconnectBlock`
restores the wrong UTXOs and the node forks.

This applies BOTH to the dead rev*.dat path (BUG-2) AND to the live
Pebble `"R" + hash` blob path.

**File:** `internal/storage/chainstate.go:101-128`, `flatfile.go:372-427`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:991-1000` (write),
`:683-727` (read).

**Excerpt (blockbrew — no checksum)**
```go
func (bu *BlockUndo) Serialize() []byte {
    return serializeBlockUndoCompressed(bu)
}
// serializeBlockUndoCompressed writes the compressed form: 0xFF tag, count,
// per-TxUndo runs. NO leading pprev hash, NO trailing SHA256d.
```

**Core**
```cpp
// Calculate checksum
HashWriter hasher{};
hasher << block.pprev->GetBlockHash() << blockundo;
// Write undo data & checksum
fileout << blockundo << hasher.GetHash();
```

**Impact:** consensus-divergent on disk corruption. The deserialize-success
path silently reorgs to a UTXO-incorrect state and forks from Core peers.

---

## BUG-4 (P2) — rotation predicate uses strict `>` vs Core's `>=`

**Severity:** P2.

`flatfile.go:247` rotates when `bs.currentPos + totalSize > bs.maxFileSize`
(strict). Core rotates on `nSize + nAddSize >= max_blockfile_size`
(`blockstorage.cpp:866`). When a block fits **exactly** at the boundary
(`currentPos + totalSize == 128 MiB`), blockbrew packs it into the current
file (so file ends at exactly 128 MiB) while Core opens a new file (so
the boundary-equal block becomes file N+1's first block).

Behavioral divergence with regard to which file holds a given block;
not consensus, but breaks blockfile-layout interop and file-by-file
pruning math.

**File:** `internal/storage/flatfile.go:247`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:866`

---

## BUG-5 (P2-DEAD) — no NORMAL vs ASSUMED blockfile cursor split

**Severity:** P2-DEAD (cross-cite W138 assumeutxo dead-class).

Core maintains an `array<optional<BlockfileCursor>, NUM_TYPES>` indexed by
`BlockfileType` (`blockstorage.h:267-279`) so an assumeUTXO snapshot
syncs its background-validation block range into a DIFFERENT blkXXXXX.dat
file than the post-snapshot tip — preventing wild height-range mixing
that would break the prune heuristic.

blockbrew has a single `currentFileNum / currentPos` pair
(`flatfile.go:188-189`) with no cursor type. blocks at every height share
the same active file. This is harmless today only because W138 confirmed
blockbrew's assumeUTXO (`DualChainstateManager`) is itself dead code.

**File:** `internal/storage/flatfile.go:182-194`

**Core ref:** `bitcoin-core/src/node/blockstorage.h:267-279`

---

## BUG-6 (P0) — preallocation uses sparse-file `Truncate`, not `posix_fallocate`

**Severity:** P0. Resource-management correctness.

`allocateSpace` (`flatfile.go:479-511`) calls `file.Truncate(newSize)` to
"pre-allocate space in chunks." On Linux/macOS this creates a SPARSE
file — the apparent file size grows but no disk blocks are reserved.
Reads of unwritten regions return zeros without occupying disk.

Core's `FlatFileSeq::Allocate` calls `AllocateFileRange`
(`fs_helpers.cpp:181-220`) which uses `posix_fallocate(fileno, 0,
nEndPos)` (Linux) or `fcntl(F_PREALLOCATE)` (macOS) or a ftruncate +
manual-zero loop fallback. These ACTUALLY reserve disk blocks and return
the canonical out-of-space error at allocate time (not write time).

Two consequences:
1. blockbrew's `out_of_space` semantics are wrong — `allocateSpace`
   returns nil even when the underlying filesystem will refuse the
   eventual write. Core's `notifications.fatalError(_("Disk space is too
   low!"))` (`blockstorage.cpp:912`) fires from `FindNextBlockPos`;
   blockbrew has no equivalent and instead surfaces ENOSPC mid-write.
2. The `m_check_for_pruning` flag in Core is set only when `Allocate`
   actually allocated bytes (`blockstorage.cpp:915-917`). blockbrew's
   pruner check uses `CalculateCurrentUsage` which sums
   `BlockFileInfo.Size + UndoSize` — the **metadata** sizes — so the
   pruner never sees the slack-space inflation the way Core does
   (cross-cite BUG-19 prune.go usage math).

**File:** `internal/storage/flatfile.go:479-511`

**Core ref:** `bitcoin-core/src/flatfile.cpp:59-86`,
`bitcoin-core/src/util/fs_helpers.cpp:181-220`.

**Excerpt (blockbrew — sparse)**
```go
const chunkSize = 16 << 20
if neededSize > currentSize {
    newSize := ((neededSize + chunkSize - 1) / chunkSize) * chunkSize
    if newSize > int64(bs.maxFileSize) {
        newSize = int64(bs.maxFileSize)
    }
    if err := file.Truncate(newSize); err != nil {  // <-- SPARSE FILE
        return err
    }
}
```

**Impact:** late-stage ENOSPC on a near-full filesystem instead of an
early-detected allocate-time failure. blockbrew can fsync a block to a
file that has no backing extents and then return success — until the
next allocation request which fails halfway through with disk-full while
the chain state has already committed.

---

## BUG-7 (P1) — undo file has zero preallocation

Cross-cite BUG-2 (dead path), BUG-9 (no flush).

`WriteUndo` opens the rev*.dat file with `os.O_RDWR|os.O_CREATE` and
immediately seeks to `fi.UndoSize`. No `UNDOFILE_CHUNK_SIZE` (1 MiB)
preallocation chunk is enforced. Every write grows the file by exactly
its payload size. Heavy write amplification on the LSM tree.

**File:** `internal/storage/flatfile.go:372-417`

**Core ref:** `bitcoin-core/src/node/blockstorage.h:121` +
`bitcoin-core/src/node/blockstorage.cpp:1228-1229`.

---

## BUG-8 (P3) — no `-fastprune` test mode

`max_blockfile_size = 0x10000` (64 kB) under `m_opts.fast_prune`
(`blockstorage.cpp:857-862`) is missing. Affects only test ergonomics —
test runs cannot exercise the rotation logic without writing many
blocks.

**File:** `internal/storage/flatfile.go:182-220`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:854-863`

---

## BUG-9 (P1) — no separate `FlushUndoFile`

The block-file flush (`flushFile`, `flatfile.go:514-540`) only operates
on `blkXXXXX.dat`. There is no analogous `flushUndoFile` for `revXXXXX.dat`.
Even when block-file rotation occurs (`flatfile.go:249`), the
corresponding rev file is never explicitly fsync'd.

Core deliberately keeps undo flushes **decoupled** from block flushes
because rev writes lag block writes (block-order vs validation-order)
and the heuristic at `blockstorage.cpp:1015-1023` only flushes the rev
file when "we've written the last block." blockbrew loses this entire
distinction.

**File:** `internal/storage/flatfile.go:513-540`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:732-769,
1015-1023`.

---

## BUG-10 (P2-DEAD) — no `cursor.undo_height` tracking

Cross-cite BUG-2 (dead path).

Core's `BlockfileCursor.undo_height` (`blockstorage.h:174`) is the
heuristic that lets `WriteBlockUndo` trim partially-filled rev files on
file-rotation. blockbrew has no per-blockfile undo-height field at all;
`BlockFileInfo.HeightLast` covers both axes (block headers AND
not-yet-validated undo data).

---

## BUG-11 (P1-CDIV) — `'b' + hash` block-index entry absent

Core stores a serialized `CDiskBlockIndex` (height, work, prev,
nFile, nPos, nUndoPos, status, nTx) under `'b' + hash`
(`blockstorage.cpp:100`). blockbrew stores ONLY the 80-byte
`BlockHeader` under `'H' + hash` (`keys.go:41`); height + work + chain
metadata live in the **in-memory** `headerIndex` and are reconstructed
on every startup by replaying header rows.

Functionally adequate for blockbrew today, but precludes cross-impl
chainstate interop and forces an O(N-headers) reload on startup that
Core does once.

**File:** `internal/storage/keys.go:11, 40-46` and `chaindb.go:51-127`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:100,
:59 DB_BLOCK_INDEX='b'`.

---

## BUG-12 (P2-CDIV) — `'l'` last-block-file scalar absent

Core stores a single VARINT under `'l'` (`DB_LAST_BLOCK`). blockbrew
combines `currentFileNum + currentPos + numFiles` into a packed blob
under `'F'` (`flatfile.go:544, 549-583`). Different key, different
contents, different schema. Cross-cite BUG-13 (the `'F'` collision).

---

## BUG-13 (P0-CDIV) — `'F'` key prefix COLLIDES with Core's `DB_FLAG`

**Severity:** P0-CDIV (datadir interop class).

blockbrew uses the single byte `'F'` as the full key (1-byte LevelDB key)
for the packed flatfile-state blob (`flatfile.go:544`). Core uses
`std::make_pair(DB_FLAG = 'F', name)` — `'F'` followed by a string name
— as the prefix for **arbitrary string flags** stored via `WriteFlag` /
`ReadFlag` (`blockstorage.cpp:107-119`). Examples in production:
`'F' + "fxxxxxxxxx"` (HD wallet flag), `'F' + "prunemode"`, etc.

The keys are length-disjoint (1 byte vs ≥2 bytes), so they technically
do not literally collide on key equality. But:

1. The single-byte `'F'` key is **inside** the LevelDB iterator range
   that Core uses to enumerate every `('F', name)` flag at startup. A
   blockbrew datadir opened by Core would parse the packed flatfile
   state as a flag name → bogus flag → undefined behavior.
2. The reverse — a Core datadir opened by blockbrew — has zero `'F'`-key
   value, so `loadState` returns ErrNotFound and silently starts from
   scratch on top of the existing data. **This is a classic
   silent-resync-on-restart hazard.**

**File:** `internal/storage/flatfile.go:544`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:60, 107-119`.

---

## BUG-14 (P0-CDIV) — `'R'` key prefix COLLIDES with Core's `DB_REINDEX_FLAG`

**Severity:** P0-CDIV (datadir interop class).

`keys.go:31` defines `UndoBlockPrefix = []byte("R")`, used to store legacy
undo blobs under `'R' + hash` (33 bytes). Core uses single-byte `'R'`
(no suffix) for the reindex flag set via `WriteReindexing`
(`blockstorage.cpp:74-78`).

Key-length-disjoint but iterator-range-overlapping (same as BUG-13).
Worse: blockbrew **writes** thousands of `'R' + hash` keys per node
lifetime, salting Core's reindex-flag key range with undo blob data.
If a Core node ever opened a blockbrew datadir, `ReadReindexing` would
fail to find the 1-byte `'R'` key (returning `fReindexing = false`)
even though the datadir is full of partial blockbrew data.

Additionally, the reindex flag itself is **never written** by blockbrew
because `-reindex` is honest-deferred (`main.go:319-324`) — there is no
recovery path that could plausibly need to set it. Cross-cite BUG-21.

**File:** `internal/storage/keys.go:30-31`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:61, 74-86`.

---

## BUG-15 (P1-CDIV) — `'T'` (uppercase) txindex vs Core's `'t'` (lowercase)

Cross-cite W133 audit (carry-forward).

`keys.go:24` defines `TxIndexPrefix = []byte("T")`. Core uses
`'t'` (`txindex.cpp:31` `DB_TXINDEX`). Plus the value format is
different: blockbrew stores 32-byte block hash; Core stores
`CDiskTxPos{FlatFilePos, VARINT(nTxOffset)}` (`disktxpos.h:11`).

blockbrew's `getrawtransaction` therefore must `ReadBlock(blockHash)`
and re-scan the txid sequence to find the requested tx, where Core
seeks directly to the tx-within-block offset.

**File:** `internal/storage/keys.go:24-25, 64-70`, `internal/storage/txindex.go`.

**Core ref:** `bitcoin-core/src/index/txindex.cpp:31, 53-65` and
`bitcoin-core/src/index/disktxpos.h:11-23`.

---

## BUG-16 (P1) — pos-index Put not batched with chain-state batch

**Severity:** P1. Crash-recovery atomicity.

`WriteAndIndexBlock` (`flatfile.go:782-797`) is a two-step that internally
opens its own `saveState` batch then immediately calls `IndexBlock`
which does `bs.db.Put(MakeBlockPosKey(hash), pos)` as a **separate**
write (`flatfile.go:713`). The block-data write + fileInfo metadata
land in one batch; the per-hash position-index entry lands in a second,
unbatched single-key Put.

Then the caller (ConnectBlock) opens its OWN batch for chain state /
undo / height. Three Pebble round-trips, no atomicity guarantee across
them. Crash after blk*.dat fsync + fileInfo batch.Write but before
IndexBlock's db.Put → block bytes on disk, fileInfo metadata bumped,
but no `'P' + hash` row → on restart `HasBlock` returns false, the same
peer re-serves the block, `WriteAndIndexBlock` re-writes it (idempotency
guard fires only because the prior duplicate would also still be
missing).

Core writes `block_pos` into `m_dirty_blockindex` and commits in
`WriteBlockIndexDB()` (`blockstorage.cpp:91-101`) as part of the same
batch that holds CBlockFileInfo updates.

**File:** `internal/storage/flatfile.go:702-714, 782-797`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:91-101`.

---

## BUG-17 (P0) — block body and undo on different storage backends

**Severity:** P0. WriteBlockUndo invariant violated.

Core's invariant: every successfully-connected block has BOTH a `blk*.dat`
entry AND a matching `rev*.dat` entry; the position index entry
(`'b' + hash` with `nFile,nPos,nUndoPos`) is the single atom committed
together with chain state.

blockbrew's reality:
1. Block body → flatfile blk*.dat (`StoreBlockAt` → `WriteAndIndexBlock`).
2. Undo data → Pebble `'R' + hash` (`WriteBlockUndoBatch`).
3. Block position → Pebble `'P' + hash` (separate unbatched Put,
   see BUG-16).
4. Chain state → Pebble `chainstate` key (in ConnectBlock batch).

Four storage atoms across two on-disk subsystems with no enforced
ordering between (1)+(3) and the ConnectBlock batch. Any crash window
between steps leaves a recovery shape that does not match anything in
Core's recovery vocabulary; `LoadBlockIndex` would not even know where
to start.

The cross-cite is BUG-2: the rev*.dat path is dead, so the in-tree
parallel architecture (write undo to rev file, write pos to leveldb,
commit chain state) cannot save blockbrew from this — it would still
need to plug both writes into a unified batch.

**Files:** `internal/p2p/sync.go:1879-1892`,
`internal/consensus/chainmanager.go:988-1060`,
`internal/storage/flatfile.go:782-797`, `chaindb.go:269-272`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1134-1165,
967-1034` (the two writes are sequenced WITH a single block index entry
holding both positions).

---

## BUG-18 (P2) — ReadBlock does not re-run CheckProofOfWork

Core's `BlockManager::ReadBlock` (`blockstorage.cpp:1057-1061`) ALWAYS
re-runs `CheckProofOfWork(block_hash, block.nBits, GetConsensus())`
after deserialize — making it impossible to read a corrupted block from
disk and feed it to consensus without an integrity check.

blockbrew's `ReadBlock` (`flatfile.go:317-369`) returns raw bytes; the
caller is responsible. Most callers (RPC, sync.go,
`headerIndex.LoadHeaders`) deserialize but do not re-run PoW. A
bit-flipped block on disk with a (still valid LE-uint32) size prefix
and an intact magic byte sequence would deserialize, fail merkle root,
and propagate as an undifferentiated decode error.

**File:** `internal/storage/flatfile.go:317-369`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1036-1075`.

---

## BUG-19 (P2-DEAD) — signet block-solution recheck on read absent

Core's `BlockManager::ReadBlock` calls `CheckSignetBlockSolution` for
signet networks (`blockstorage.cpp:1063-1066`). blockbrew has no
equivalent in the read path. Dead today only because the signet block
solution path itself is wired-but-quiet in blockbrew (see W126).

---

## BUG-20 (P2-CDIV) — no `xor.dat` obfuscation key

Since Core v25, the `blocks/` directory contains a 64-bit
`xor.dat` obfuscation key. Every byte read/written to blkXXXXX.dat and
revXXXXX.dat is XOR'd against this rolling key — primarily to stop AV
vendors from flagging the file contents on pattern match
(`blockstorage.cpp:1167-1209`). blockbrew writes plaintext blk files.

Datadir-interop concern: a Core datadir copied to blockbrew has
XOR'd files; blockbrew would read magic bytes XOR'd with the per-datadir
key and reject the very first block read.

**File:** `internal/storage/flatfile.go:197-220` (no xor.dat read/write)

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1167-1209`.

---

## BUG-21 (P0) — `-reindex` honest-deferred → no on-disk recovery path

**Severity:** P0. Recovery story missing.

`main.go:319-324` causes blockbrew to **refuse to start** when the
operator passes `-reindex`:
```go
if cfg.Reindex {
    fmt.Fprintln(os.Stderr, "Error: -reindex is not yet implemented in blockbrew.")
    fmt.Fprintln(os.Stderr, "       Workaround: wipe the chaindata/ directory ...")
    fmt.Fprintln(os.Stderr, "       Tracking: see meta-repo CLAUDE.md ...")
    return 1
}
```

This is the recommended escape hatch when blk*.dat / Pebble data has
diverged or partially corrupted. Without `-reindex`, the operator's only
remedy is `rm -rf` followed by full re-sync. Core can reconstruct the
chain index from the on-disk blk files in hours; blockbrew has to
re-download from peers (days at mainnet scale).

Compound with BUG-3 (no undo checksum) + BUG-6 (sparse preallocation +
late ENOSPC) + BUG-17 (split block/undo storage) and the lack of any
in-tree recovery becomes the single largest operational gap in the
storage layer.

**File:** `cmd/blockbrew/main.go:312-324`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:74-86` + the
entire reindex loop in `ImportBlocks` (`:1244-1330`).

---

## BUG-22 (P1) — `ErrBadMagic` returned to caller without recovery

When `ReadBlock` finds the wrong magic at the expected position
(`flatfile.go:351-354`), it returns plain `ErrBadMagic`. No truncation
of the corrupted tail, no recovery rewind of `currentFileNum/Pos`, no
log line for the operator. Core does not handle this case either — it
fatal-errors the node — but at least surfaces it via
`m_opts.notifications.fatalError`. blockbrew silently propagates as a
generic read error to the RPC client.

**File:** `internal/storage/flatfile.go:344-354`, `:438-466`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1104-1108`.

---

## Fleet-pattern smells

1. **Dead-class assumeUTXO-style (BUG-2, BUG-5, BUG-10):** `WriteUndo` /
   `WriteAndIndexUndo` / `'p' + hash` UndoPos index / `BlockFileInfo.UndoSize`
   accounting / `BlockfileCursor.undo_height` semantics — full rev*.dat
   subsystem defined and TESTED in `undo_test.go` / `bench_test.go`, but
   the production path uses Pebble blobs under `'R' + hash` instead.
   Matches W138 fleet-wide pattern: 9 of 10 impls have an
   "assumeUTXO/snapshot/background-validator" scaffold with no live
   callers. blockbrew adds a second instance of the same pattern, this
   time on the rev*.dat subsystem.

2. **Two-pipeline guard (BUG-2 + BUG-17):** the in-tree dead rev*.dat
   pipeline and the live Pebble `'R' + hash` pipeline coexist. Reads
   would try the dead path's `GetUndoPos` if `WriteAndIndexUndo` ever
   wired up, but no production reader does either. 14th distinct
   extension of the fleet-wide two-pipeline-guard pattern catalogued
   since W76.

3. **Carry-forward re-anchor:** W133 (index databases) already flagged
   the `'T'` vs `'t'` prefix divergence (BUG-15). 6+ weeks unaddressed.
   The pattern is now a fleet-tag.

4. **Comment-as-confession (no clean instance here, but):**
   `main.go:316-323` is the closest analogue — the `-reindex`
   honest-defer banner literally tells the operator "this is not
   implemented, your only remedy is rm -rf chaindata." BUG-21.

5. **Three-pipeline-guard variant:** block body has THREE possible
   storage locations: blk*.dat (live), `'B' + hash` Pebble blob
   (legacy, lazy-migration read fallback per `chaindb.go:183-213`),
   and (per BUG-11) the headerIndex in-memory mirror of header
   data. Symmetric with the undo dead/live split.

6. **Key-prefix-collision class (BUG-13, BUG-14):** TWO single-byte
   keys (`'F'` and `'R'`) reused for entirely different blockbrew-side
   purposes than Core. Combined effect: ANY attempt to share a datadir
   between Core and blockbrew (e.g. operator preserving blocks/ across
   an impl swap) is broken at the key-decode boundary.

---

## Summary

22 BUGs catalogued (1 P0-CDIV consensus-class via undo corruption, 2
P0-CDIV interop-class via key collisions, 3 P0 storage-correctness,
2 P1-DEAD, 4 P1-CDIV, 1 P1 atomicity, 3 P2-CDIV, 2 P2-DEAD, 3 P2,
2 P3).

**Highest-priority fixes** (in order of consensus exposure):
- **BUG-3** undo checksum missing → silent corruption fork (cross-cite
  BUG-2 dead path).
- **BUG-13 / BUG-14** key-prefix collisions with `DB_FLAG='F'` and
  `DB_REINDEX_FLAG='R'` → silent silent-resync hazards on any
  Core⇄blockbrew datadir share.
- **BUG-17** block body and undo on different storage backends → no
  unified-batch atomicity across the connect path.
- **BUG-21** no `-reindex` → no on-disk recovery, only `rm -rf` +
  full re-sync.
- **BUG-6** sparse-file preallocation → late ENOSPC, no early
  out-of-space detection.

**Lowest-priority** are the dead-code items (BUG-2, BUG-5, BUG-10,
BUG-19): can be deleted with no production impact, or wired up
properly with the higher-priority bugs as prerequisites.
