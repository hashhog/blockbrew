# W156 — BIP-152 cmpctblock / blocktxn / getblocktxn wire deep-dive (blockbrew)

**Wave:** W156 — wire-level deep-dive of `sendcmpct` / `cmpctblock` /
`getblocktxn` / `blocktxn`. W126 covered the fundamentals (Discovery,
2026-05-17, recorded 10 bugs W126-BUG-1..10); W156 narrows to the wire
format, short-ID derivation, partial-block reconstruction edge cases,
and the receive/send asymmetry highlighted by W141 (ZMQ hash byte-order)
and W152 (unidirectional tx-relay).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/blockencodings.cpp` —
  `CBlockHeaderAndShortTxIDs::FillShortTxIDSelector` (line 35-44, SipHash
  key = `SHA256(DataStream{header,nonce}).GetUint64(0/1)`),
  `GetShortID` (line 46-50, `(*m_hasher)(wtxid.ToUint256()) & 0xffffffffffffL`),
  `PartiallyDownloadedBlock::InitData` (line 59-181: 12 gates incl.
  null-header reject, BlockTxCount overflow, prefilled index overflow,
  short-ID bucket-12 cap, two-mempool-match clear, extra-txn loop),
  `FillBlock` (line 191-236: vtxMissing-exact + `header.SetNull()` +
  `IsBlockMutated` post-fill collision check).
- `bitcoin-core/src/blockencodings.h` — `PrefilledTransaction.index`
  uint16 (line 77, COMPACTSIZE-encoded), `BlockTransactionsRequest.indexes`
  uint16 vector serialized via `DifferenceFormatter` (line 49-53),
  `BlockTxCount() > uint16_max` post-deserialize check (line 124-127),
  `SHORTTXIDS_LENGTH=6` (line 103), `CBlockHeaderAndShortTxIDs` short-id
  serialized via `CustomUintFormatter<6>` (LE, line 123).
- `bitcoin-core/src/net_processing.cpp` — `MAX_CMPCTBLOCK_DEPTH=5`
  (line 138), `MAX_BLOCKTXN_DEPTH=10` + `static_assert <= MIN_BLOCKS_TO_KEEP`
  (line 140-141), `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK` (line ~145),
  `MaybeSetPeerAsAnnouncingHeaderAndIDs` (line 1272-1329: 3-cap,
  rotation, outbound-preference), HB cmpctblock-announce path
  (line 5891-5914: cached `m_most_recent_compact_block`),
  CMPCTBLOCK receive (line 4466-4712:
  `LoadingBlocks` gate, prev-block-not-found → getheaders,
  anti-DoS work threshold, `ProcessNewBlockHeaders`,
  `MaybePunishNodeForBlock(via_compact_block=true)`,
  `vExtraTxnForCompact` orphan pool, `InitData`+`FillBlock`,
  `mapBlockSource` with `via_compact_block=false`),
  GETBLOCKTXN serve (line 4245-4304:
  `m_most_recent_block` fast path, MAX_BLOCKTXN_DEPTH fallback
  via `getdata MSG_WITNESS_BLOCK`), BLOCKTXN receive
  (line 4714-4726: `LoadingBlocks` gate, `ProcessCompactBlockTxns`),
  SENDCMPCT receive (line 3901-3917: v != CMPCTBLOCKS_VERSION drop,
  `m_provides_cmpctblocks`, `m_requested_hb_cmpctblocks`,
  `m_bip152_highbandwidth_from`), VERACK sends sendcmpct(hb=false,v=2)
  (line 3864-3871).
- `bitcoin-core/src/protocol.h:484` — `MSG_CMPCT_BLOCK = 4` (used in
  getdata to request a cmpctblock from a peer).

**Files audited**
- `internal/p2p/compactblock.go` — `CmpctBlockVersion=2` (line 19),
  `ShortIDLength=6` (line 22), `MaxHBPeers=3` (line 25),
  `MaxCmpctBlockDepth=5` (line 33), `MaxBlocktxnDepth=10` (line 41),
  `maxBlockTxCount` (line 46), `shortIDCollisionBucketLimit=12`
  (line 52), `SipHashKey` (line 64), `ComputeSipHashKey` (line 70-79),
  `siphash24` (line 83-144), `ComputeShortID` (line 175-178),
  `CompactBlockBuilder.Build` (line 198-220), `PartiallyDownloadedBlock`
  (line 223), `InitData` (line 279-473), `FillBlock` (line 549-599),
  `CompactBlockState` (line 616), `SetSendCmpct` (line 636-646),
  `WantsHBCompactBlocks` (line 656), `CreateGetBlockTxn` (line 685-697),
  `DecodeGetBlockTxnIndexes` (line 700-712), `CreateBlockTxn` (line 716-730),
  `ExtraTx` (line 258).
- `internal/p2p/msg_cmpctblock.go` — `MsgCmpctBlock` (line 11-16:
  `PrefilledTx.Index uint32`, not uint16); `Serialize` writes 6-byte LE
  short-ids (line 41-47) and `WriteCompactSize(Index)` (line 53-54);
  `Deserialize` caps at `MaxInvVects=50000` (line 81-82, 98-99);
  `MsgGetBlockTxn`/`MsgBlockTxn` (line 119-212): `Indexes uint32`
  vector, `Serialize` writes COMPACTSIZE values, `Deserialize` stores
  raw (no DifferenceFormatter applied at the message layer).
- `internal/p2p/msg_simple.go` — `MsgSendCmpct` (line 133-163:
  `AnnounceUsingCmpctBlock bool`, `CmpctBlockVersion uint64`).
- `internal/p2p/peer.go` — `OnSendCmpct/OnCmpctBlock/OnGetBlockTxn/
  OnBlockTxn` listener registration (line 80-83); pre-handshake
  allowed-set includes `MsgSendCmpct` (line 561); dispatch in
  `handleMessage` (line 649-671); `checkHandshakeComplete` sends
  `sendcmpct(announce=false, version=2)` after VERACK (line 907-913).
- `internal/p2p/sync.go` — `OnSendCmpct: log only` (line 1010-1013),
  `OnCmpctBlock: getdata fallback` (line 1014-1042),
  `OnGetBlockTxn: log+ignore` (line 1043-1064),
  `OnBlockTxn: log+ignore` (line 1065-1069),
  `HandleGetData` (line 1264-1318: no case for `InvTypeCmpct=4`,
  no case for `InvTypeWtx=5`, no case for `InvTypeFilteredBlock=3`).
- `internal/p2p/peermgr.go` — `AnnounceBlock` (line 748-770: headers
  or inv, never cmpctblock); `RelayTransaction` (line 786-828).
- `internal/p2p/msg_inv.go` — `InvType` constants (line 14-21):
  `InvTypeError=0`, `InvTypeTx=1`, `InvTypeBlock=2`,
  `InvTypeFilteredBlock=3`, **no `InvTypeCmpct=4`**, `InvTypeWtx=5`,
  `InvTypeWitnessTx=0x40000001`, `InvTypeWitnessBlock=0x40000002`.
- `internal/p2p/message.go` — Command-to-type dispatch (line 257-380:
  every BIP-152 type is registered); `MaxInvVects=50000`,
  `MaxGetDataSize=1000` (line 73-83).
- `internal/p2p/bip324.go:369` — `"sendcmpct": 0x14` BIP-324 ID
  short-message-id mapping (PRESENT, verified against Core protocol.h).
- `internal/p2p/w126_bip152_test.go` — prior W126 audit fixture
  (10 W126-BUGs documented as t.Skip xfails: receive-side
  reconstruction, getblocktxn serve, blocktxn process, header
  pipeline, anti-DoS, IBD guard, misbehave-on-invalid, most-recent
  cache, v1 forward-spec, MSG_CMPCT_BLOCK getdata serve).

---

## Gate matrix (33 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | sendcmpct outbound | G1: sent after VERACK (handshake complete) | PASS (`peer.go:907-913`) |
| 1 | … | G2: format = 1B announce ‖ 8B LE uint64 version | PASS (`msg_simple.go:143-151`) |
| 1 | … | G3: outbound announce bit = false (we want LB receive) | PASS (`peer.go:911`) |
| 1 | … | G4: outbound version = 2 (segwit / wtxid short-ids) | PASS (`peer.go:912`, `compactblock.go:19`) |
| 2 | sendcmpct inbound | G5: v≠2 silently drops `m_provides_cmpctblocks` | PASS (`compactblock.go:641-645`) — matches Core net_processing.cpp:3907 |
| 2 | … | G6: `m_bip152_highbandwidth_from` (announce bit) per-peer | PASS (`compactblock.go:643-644`) |
| 2 | … | G7: blocksonly mode rejects sendcmpct(hb=true) registration | **BUG-1 (P1)** — no `-blocksonly` gate. Core net_processing.cpp:1279 declines `MaybeSetPeerAsAnnouncingHeaderAndIDs` when `m_opts.ignore_incoming_txs` is true |
| 2 | … | G8: peer sending sendcmpct AFTER VERACK is accepted (not just before) | PASS — `peer.go:561` allows in pre-handshake set, but dispatch at 649 also accepts post-VERACK |
| 3 | Short-ID derivation | G9: key = first 16 bytes of `SHA256(header_serialize ‖ LE-u64 nonce)` | PASS (`compactblock.go:70-79`) |
| 3 | … | G10: k0/k1 = `ReadLE64(key[0:8])` / `ReadLE64(key[8:16])` | PASS (`compactblock.go:85-86`) |
| 3 | … | G11: short-id = `siphash24(key, wtxid) & 0xFFFFFFFFFFFF` (48 bits) | PASS (`compactblock.go:175-178`) |
| 3 | … | G12: v2 uses wtxid (not txid) | PASS (`compactblock.go:214` — `block.Transactions[i].WTxHash()`) |
| 4 | cmpctblock build | G13: prefill coinbase at index 0 unconditionally | PASS (`compactblock.go:204-208`) |
| 4 | … | G14: empty-block (no txns) handling — what does Build emit? | **BUG-2 (P2)** — `if len(block.Transactions) > 0` (line 205) means a hypothetical empty block emits `MsgCmpctBlock{}` with zero prefilled and zero short-ids, which the receiver rejects with "no transactions" (line 289). Core's CTOR requires `block.vtx.size() >= 1` (asserts via `shorttxids(block.vtx.size() - 1)` underflow if empty) — undefined-behaviour vs blockbrew's silent-empty divergence |
| 5 | cmpctblock wire format | G15: prefilled.Index field is uint16 (BIP-152) | **BUG-3 (P0-CDIV)** — `PrefilledTx.Index uint32` (`msg_cmpctblock.go:20`). Core's `PrefilledTransaction.index` is `uint16_t` (blockencodings.h:77). Wire is COMPACTSIZE so receive-side accepts the same range, BUT (a) blockbrew can SERIALIZE a prefilled index in [0x10000, 0xFFFFFFFF] which Core rejects on decode with "indexes overflowed 16 bits" (blockencodings.h:125-127), and (b) the InitData uint16-overflow check at compactblock.go:329 saves us from receive-side abuse but the *encode* path silently produces wire-incompatible cmpctblocks |
| 5 | … | G16: BlockTxCount > uint16_max post-deserialize rejection | **BUG-4 (P1)** — Core's `SERIALIZE_METHODS(CBlockHeaderAndShortTxIDs, …)` (blockencodings.h:124-127) reads `BlockTxCount() > std::numeric_limits<uint16_t>::max() → throws`. blockbrew's `Deserialize` (`msg_cmpctblock.go:80-83, 97-99`) caps each vector at `MaxInvVects=50000` separately. A peer can send 35000 short-ids + 35000 prefilled = 70000 total slots, exceeding 65535. Core rejects; blockbrew accepts |
| 5 | … | G17: short-id wire format = 6-byte LE | PASS (`msg_cmpctblock.go:41-47`) |
| 5 | … | G18: cmpctblock cap = MAX_BLOCK_WEIGHT/MIN_TX_WEIGHT (~66666) — not MAX_INV_VECTS (50000) | **BUG-5 (P1)** — `MaxInvVects=50000` is too tight. `maxBlockTxCount` (compactblock.go:46) is the correct cap in `InitData` (line 296) but the deserializer cap at `MaxInvVects` rejects valid Core-produced cmpctblocks containing 50001..66666 short-ids before InitData ever runs |
| 6 | InitData reconstruction | G19: null-header reject | PASS (`compactblock.go:284-286`) |
| 6 | … | G20: empty-body reject | PASS (`compactblock.go:289-291`) |
| 6 | … | G21: max-block-tx-count DoS guard | PASS (`compactblock.go:295-299`) |
| 6 | … | G22: double-init guard | PASS (`compactblock.go:302-305`) |
| 6 | … | G23: prefilled differential index = `last + cur + 1` | PASS (`compactblock.go:324`) |
| 6 | … | G24: prefilled-index uint16 overflow guard | PASS (`compactblock.go:329`) but see BUG-3 |
| 6 | … | G25: prefilled-index ≤ shortids.size + i | PASS (`compactblock.go:337`) |
| 6 | … | G26: nil prefilled tx reject | PASS (`compactblock.go:318`) |
| 6 | … | G27: short-id bucket-12 hash-flooding DoS | **BUG-6 (P2)** — blockbrew's bucket function is `sid % (len(ShortIDs)+1)` (`compactblock.go:382`). Core uses `std::unordered_map.bucket(sid)` which uses libstdc++'s actual bucket-hash. The two distributions diverge. Worst-case: an attacker producing colliding short-IDs that hash to the same Go-modulus bucket bypasses the cap entirely (since they don't collide in libstdc++'s buckets); inverse, a Core-permitted block could be rejected by blockbrew |
| 6 | … | G28: short-id duplicate detection | PASS (`compactblock.go:391-393`) but the bucket check at line 384 fires FIRST in the loop on collision, so the canonical "first-collision returns ShortIDCollision" path differs from Core which exits the loop body with the bucket check, falls through, and only THEN does the duplicates check |
| 6 | … | G29: mempool match — `have_txn` tracking, two-match clear | PASS (`compactblock.go:400-437`) |
| 6 | … | G30: extra-txn match — wtxid differ clears slot | **BUG-7 (P1)** — bookkeeping bug: the extra-txn loop at `compactblock.go:442-470` calls `p.mempoolCount--; p.extraCount--` on the clear-branch. If the slot was filled by the **mempool** loop (`mempoolCount++` only, `extraCount` never incremented for this slot), then the `extraCount--` here decrements a counter that the slot never contributed to. `extraCount` can go negative; the public `Stats()` accessor surfaces it. Core's `extra_count` is symmetric only because Core's variable counts the same kind of mempool-or-extra fill |
| 6 | … | G31: extra-txn early-exit check `mempool_count == shorttxids.size()` | PASS (`compactblock.go:467-469`) |
| 7 | InitData edge case — extraTxn wire-up | G32: receive-side InitData consults a real `vExtraTxnForCompact` pool | **BUG-8 (P1 DEAD-DATA)** — `ExtraTx` type is exported, the receive-side loop (compactblock.go:442) consults `extraTxn`, the test fixture passes a non-empty slice — but PRODUCTION code (sync.go:1014-1042) does not assemble any `vExtraTxnForCompact` and the entire receive-side InitData path is never called from production (sync.go falls back to full-block getdata before reaching InitData). Even if W126-BUG-1 fixed mempool wiring, the extra-pool would still be empty |
| 8 | FillBlock | G33: vtxMissing size exactness check | PASS (`compactblock.go:586-588`) |
| 8 | … | G34: double-call protection via header.IsNull / clear | PASS (`compactblock.go:555, 581-582`) |
| 8 | … | G35: IsBlockMutated post-fill check (short-ID collision) | PASS (`compactblock.go:594-596`) |
| 9 | cmpctblock receive — top-of-handler | G36: drop while LoadingBlocks/IBD active | **BUG-9 (P2)** carry-forward W126-BUG-6 — no `LoadingBlocks` / `IsIBDActive` gate in `OnCmpctBlock`. Core net_processing.cpp:4468-4472 drops |
| 9 | … | G37: prev-block-not-found → `MaybeSendGetHeaders` | **BUG-10 (P1)** carry-forward W126-BUG-5 — `OnCmpctBlock` never inspects `cmpctblock.Header.PrevBlock`. Core line 4483-4489 issues getheaders if prev is unknown |
| 9 | … | G38: anti-DoS work threshold reject | **BUG-11 (P1)** carry-forward W126-BUG-5 — no `prev_block->nChainWork + GetBlockProof(header) < GetAntiDoSWorkThreshold()` check (Core line 4490-4493). Spam vector: peer can force per-message getdata roundtrips with zero-work headers |
| 9 | … | G39: feed embedded header into ProcessNewBlockHeaders | **BUG-12 (P0-DEAD)** carry-forward W126-BUG-4 — `OnCmpctBlock` does NOT call header acceptance. Core line 4503 calls `ProcessNewBlockHeaders({{cmpctblock.header}}, /*min_pow_checked=*/true, …)` ALWAYS, regardless of fallback choice. blockbrew discards the header completely and requests the block by hash. If every peer used HB cmpctblock-only announcements (no parallel headers/inv), blockbrew would never learn about new tips |
| 9 | … | G40: MaybePunishNodeForBlock on header rejection | **BUG-13 (P2)** carry-forward W126-BUG-7 — gate unreachable until BUG-12 fixed |
| 10 | cmpctblock receive — reconstruction path | G41: receive path consults mempool / extra-txn / produces partial-block | **BUG-14 (P0-DEAD)** carry-forward W126-BUG-1 — `OnCmpctBlock` at sync.go:1015-1016 confesses "We don't have a mempool, so we can't reconstruct". Yet blockbrew DOES have a mempool (internal/mempool/) — the comment is stale + load-bearing. The full Build/InitData/FillBlock pipeline is wired, tested, exported — and never invoked from production |
| 10 | … | G42: getblocktxn issued for missing slots | **BUG-15 (P0-DEAD)** — `CreateGetBlockTxn` (compactblock.go:685) is defined, tested in `compactblock_test.go`, but has ZERO non-test callers. Production cmpctblock receive falls back to `getdata(MSG_WITNESS_BLOCK)` (sync.go:1036-1041), defeating the entire point of BIP-152 (a full block download instead of a few-KB blocktxn round-trip) |
| 11 | getblocktxn serve | G43: handler reads requested block + sends BLOCKTXN | **BUG-16 (P0-DEAD)** carry-forward W126-BUG-2 — `OnGetBlockTxn` (sync.go:1043-1064) is log-only. The depth check at line 1054 computes correctly but BOTH branches `return` without serving. `CreateBlockTxn` (compactblock.go:716) is defined, tested, never called in production |
| 11 | … | G44: MAX_BLOCKTXN_DEPTH=10 fallback queues getdata(MSG_WITNESS_BLOCK) | **BUG-17 (P1)** carry-forward W126-BUG-2 depth-prong — sync.go:1054-1060 has the depth comparison but the "would fall back to full block" branch is comment-only (`TODO(BUG-3)`). Core line 4299-4302 queues `CInv{MSG_WITNESS_BLOCK, blockhash}` on the peer's getdata queue |
| 11 | … | G45: m_most_recent_block fast-path cache | **BUG-18 (P2)** carry-forward W126-BUG-8 — no cache. Every cmpctblock serve forces a disk read (gated on BUG-16 anyway) |
| 11 | … | G46: OOB index in req.indexes → Misbehaving | **BUG-19 (P2)** carry-forward W126-BUG-2 OOB-prong — `OnGetBlockTxn` never walks the index array, so Core's "if req.indexes[i] >= block.vtx.size() → Misbehaving" check (net_processing.cpp:2603-2604) is dead code in blockbrew |
| 12 | blocktxn receive | G47: handler decodes + invokes FillBlock | **BUG-20 (P0-DEAD)** carry-forward W126-BUG-3 — `OnBlockTxn` (sync.go:1065-1069) is log-only. `PartiallyDownloadedBlock.FillMissingTransactions` + `FillBlock` are wired but never called from production |
| 13 | HB peer selection & announce | G48: MaxHBPeers=3 list maintained + rotation | **BUG-21 (P0-DEAD)** carry-forward W112-BUG-1 / W126-BUG-1 — `MaxHBPeers=3` (compactblock.go:25) is a defined constant with ZERO consumers. No `lNodesAnnouncingHeaderAndIDs`-equivalent. `MaybeSetPeerAsAnnouncingHeaderAndIDs` analogue absent |
| 13 | … | G49: outbound preference + 3-cap eviction logic | **BUG-21 cross-cite** — Core line 1298-1322 prefers outbound peers when evicting and protects the last outbound HB slot. blockbrew has nothing |
| 13 | … | G50: `OnSendCmpct` triggers HB-list consideration | **BUG-22 (P1)** — `OnSendCmpct` at sync.go:1010-1013 is `log.Printf` only. It should drive HB-list updates and reply with a low-bandwidth `sendcmpct(false, 2)` when evicting a peer from our HB list (Core line 1315-1320) |
| 13 | … | G51: AnnounceBlock dispatches `cmpctblock` to HB peers | **BUG-23 (P0-DEAD)** carry-forward W112-BUG-1 — `peermgr.go:748-770 AnnounceBlock` switches only on `peer.SendsHeaders()` (headers vs inv). `peer.WantsHBCompactBlocks()` is exported, tested, never consulted. CompactBlockBuilder is exported, tested, never invoked from `AnnounceBlock` |
| 13 | … | G52: most_recent_compact_block cache for re-announces | **BUG-24 (P2)** carry-forward W126-BUG-8 — gated on G51 |
| 14 | getdata(MSG_CMPCT_BLOCK=4) serve | G53: `InvTypeCmpct=4` defined | **BUG-25 (P1 WIRE-INTEROP)** carry-forward W126-BUG-10 — `msg_inv.go:14-20` enumerates `InvTypeError=0, InvTypeTx=1, InvTypeBlock=2, InvTypeFilteredBlock=3, InvTypeWtx=5, InvTypeWitnessTx=0x40000001, InvTypeWitnessBlock=0x40000002`. **`InvTypeCmpct=4` (Core MSG_CMPCT_BLOCK, protocol.h:484) is missing entirely**. blockbrew CANNOT respond to a peer's `getdata(MSG_CMPCT_BLOCK)` request — `HandleGetData`'s switch (sync.go:1284-1313) has cases only for `InvTypeBlock` and `InvTypeTx`. A peer attempting to fetch the block via the BIP-152 fast path gets silent no-op |
| 14 | … | G54: depth ≤ MAX_CMPCTBLOCK_DEPTH=5 → cmpctblock reply | **BUG-25 cross-cite** |
| 14 | … | G55: depth > MAX_CMPCTBLOCK_DEPTH → full block reply | **BUG-25 cross-cite** |

---

## BUG-1 (P1) — `blocksonly` mode does not refuse sendcmpct(hb=true) registration

**Severity:** P1. Bitcoin Core's
`MaybeSetPeerAsAnnouncingHeaderAndIDs` (net_processing.cpp:1276-1279)
short-circuits when `m_opts.ignore_incoming_txs` is true:

```cpp
// When in -blocksonly mode, never request high-bandwidth mode from peers.
// Our mempool will not contain the transactions necessary to reconstruct
// the compact block.
if (m_opts.ignore_incoming_txs) return;
```

The rationale: a `-blocksonly` node has an empty mempool, so compact
block reconstruction via short-IDs is guaranteed to round-trip every
non-coinbase transaction via `getblocktxn`. Worse than baseline. blockbrew
has no `-blocksonly`-equivalent in `cmd/blockbrew/main.go` (separate
discovery), so the gate is moot today, but the absence of the check means
that if/when blocksonly is added, the receive path will accept HB-cmpct
peers and trigger O(N) round-trips per block.

**File:** `internal/p2p/compactblock.go:636-646` (SetSendCmpct unconditional);
`internal/p2p/sync.go:1010-1013` (OnSendCmpct logs only).

**Core ref:** `bitcoin-core/src/net_processing.cpp:1276-1279`.

**Impact:** when blocksonly is eventually added (separate parity gap),
the cmpct-receive path will degrade rather than fall back to plain block
relay.

---

## BUG-2 (P2) — Empty-block cmpctblock build emits silently-invalid wire format

**Severity:** P2. `CompactBlockBuilder.Build` (compactblock.go:198-220):

```go
if len(block.Transactions) > 0 {
    msg.PrefilledTxs = []PrefilledTx{
        {Index: 0, Tx: block.Transactions[0]},
    }
}
```

An empty `block.Transactions` slice (e.g., a test-injected malformed
block, or a future block format that omits coinbase) produces a
cmpctblock with zero prefilled and zero short-ids. On receive, blockbrew's
own InitData rejects this with "no transactions" (compactblock.go:289-291).
Core's CTOR (blockencodings.cpp:20-33) constructs
`shorttxids(block.vtx.size() - 1)` — if `block.vtx.size()=0`, this is
`shorttxids((size_t)-1)` = catastrophic allocation. The Core path is
asserted-against via the `CBlock` invariant that coinbase is at index 0.

blockbrew accepts a `block.Transactions=nil` input silently and emits
the empty cmpctblock; the divergence is benign but a latent wire
mismatch that a fuzz harness will find quickly.

**File:** `internal/p2p/compactblock.go:198-220`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:20-33` (CTOR assumes
non-empty vtx).

**Impact:** test/fuzz consistency gap.

---

## BUG-3 (P0-CDIV) — `PrefilledTx.Index` is `uint32`; Core requires `uint16`

**Severity:** P0-CDIV (wire-format divergence). Core's
`PrefilledTransaction.index` is `uint16_t`
(`bitcoin-core/src/blockencodings.h:77`), and the serialization uses
`READWRITE(COMPACTSIZE(obj.index), …)` (line 80). Compactsize accepts
0..2^64-1, but the post-deserialize check at `blockencodings.h:124-127`:

```cpp
if (obj.BlockTxCount() > std::numeric_limits<uint16_t>::max()) {
    throw std::ios_base::failure("indexes overflowed 16 bits");
}
```

caps total tx count at 65535. blockbrew's `PrefilledTx.Index uint32`
(`msg_cmpctblock.go:20`) violates this:
- **Encode side:** if blockbrew produces a cmpctblock for a block with
  > 65535 transactions (impossible on consensus today but trivially
  testable on regtest with synthetic blocks), the wire output Core
  rejects with "indexes overflowed 16 bits".
- **Decode side:** `MsgCmpctBlock.Deserialize` (`msg_cmpctblock.go:101-112`)
  reads `WriteCompactSize`-encoded Index into `uint32(idx)` without the
  uint16 cap. The uint16 overflow check in
  `PartiallyDownloadedBlock.InitData` (compactblock.go:329) catches the
  cumulative-prefilled-index overflow, but the PER-RECORD Index field
  can be 0..2^32-1 at the wire layer — wider than Core accepts.

The Differential encoding then makes this even worse: a malicious peer
can send a prefilled.Index just below 2^32, which after the +1 of
differential decoding wraps `int32(0xFFFFFFFE) + 1` = `int32(-1)` and
the cumulative check would skip the boundary.

**File:** `internal/p2p/msg_cmpctblock.go:20` (type), 53-54 (Serialize),
107 (Deserialize); `internal/p2p/compactblock.go:324` (cumulative add).

**Core ref:** `bitcoin-core/src/blockencodings.h:77, 80, 124-127`.

**Impact:**
- Wire interop: blockbrew can produce cmpctblocks that Core rejects.
- DoS: a peer sending a deliberately-overflowing prefilled.Index can
  trick blockbrew's differential decoder into wrap-arounds that bypass
  the BlockTxCount overflow guard.

**Excerpt (blockbrew, uint32 type)**
```go
// PrefilledTx is a prefilled transaction in a compact block.
type PrefilledTx struct {
    Index uint32       // Differentially encoded index
    Tx    *wire.MsgTx
}
```

---

## BUG-4 (P1) — `BlockTxCount > uint16_max` post-deserialize check is absent

**Severity:** P1. Cross-cite with BUG-3. Core's
`SERIALIZE_METHODS(CBlockHeaderAndShortTxIDs, …)`
(blockencodings.h:121-130) reads the message and then asserts:

```cpp
if (obj.BlockTxCount() > std::numeric_limits<uint16_t>::max()) {
    throw std::ios_base::failure("indexes overflowed 16 bits");
}
```

where `BlockTxCount() = shorttxids.size() + prefilledtxn.size()` (line 119).

blockbrew's `MsgCmpctBlock.Deserialize` (`msg_cmpctblock.go:65-115`)
caps each vector at `MaxInvVects=50000`:
```go
if count > MaxInvVects {
    return ErrTooManyInvVects
}
```
applied separately to `ShortIDs` (line 81) and `PrefilledTxs` (line 98).
A peer can send `40000 short-ids + 40000 prefilled = 80000 total` —
each vector under MaxInvVects, but BlockTxCount=80000 > 65535. Core
rejects this in the deserializer; blockbrew passes the message into
`InitData`, where the `maxBlockTxCount = MAX_BLOCK_WEIGHT/MIN_TX_WEIGHT
~ 66666` guard at compactblock.go:296-299 catches it (close to but not
exactly the uint16 cap). The semantic gap: Core's bound is uint16-tight;
blockbrew's bound is consensus-tight. The two differ by ~1300 tx-slots.

**File:** `internal/p2p/msg_cmpctblock.go:65-115`; check should be added
between the prefilled-count read (line 98) and the prefilled loop (line 101).

**Core ref:** `bitcoin-core/src/blockencodings.h:124-127`.

**Impact:** wire-deserializer accepts a superset of what Core accepts.
A subtle interop divergence used to construct cross-impl chain-split
test cases.

---

## BUG-5 (P1) — `MaxInvVects=50000` cap is too tight for cmpctblock vectors

**Severity:** P1. The per-vector cap at `MsgCmpctBlock.Deserialize`
lines 81-82, 98-99 uses `MaxInvVects = 50000`. The correct cap for
cmpctblock vectors is `MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT
= 4_000_000 / 60 ≈ 66666` (Core blockencodings.cpp:64). A Core-produced
cmpctblock with 50001..66666 short-ids is valid on Core's wire but
rejected by blockbrew's deserializer BEFORE reaching the InitData guard
that uses the correct constant.

In practice, today's mainnet blocks rarely exceed ~3500 tx (Erlay
testbed has produced ~5000), so the 50000 cap never trips. On regtest
or future high-throughput blocks, this becomes a hard interop break.

**File:** `internal/p2p/msg_cmpctblock.go:81, 98`. Same issue likely on
the blocktxn count cap at line 201.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:64`,
`bitcoin-core/src/consensus/consensus.h:MIN_SERIALIZABLE_TRANSACTION_WEIGHT`.

**Impact:** wire-interop ceiling lowered from ~66666 to 50000 tx per
block. Theoretical today, practical on regtest / future versions.

---

## BUG-6 (P2) — Short-ID bucket-12 hash-flooding cap uses wrong bucket function

**Severity:** P2. Core's check (blockencodings.cpp:104-111):

```cpp
if (shorttxids.bucket_size(shorttxids.bucket(cmpctblock.shorttxids[i])) > 12)
    return READ_STATUS_FAILED;
```

uses `std::unordered_map<uint64_t, uint16_t>::bucket(sid)`, which on
libstdc++ is implemented as `hash(key) % bucket_count()` where
`bucket_count()` is at least the requested size (with some prime
rounding) and `hash(uint64_t)` is the identity function on libstdc++.

blockbrew's approximation (compactblock.go:382):
```go
bucket := sid % uint64(len(cmpctblock.ShortIDs)+1)
bucketSizes[bucket]++
if bucketSizes[bucket] > shortIDCollisionBucketLimit {
    return 0, ErrShortIDCollision
}
```

uses `+1` as the divisor (off-by-one), and crucially uses the raw
`sid` as the hash. For a SipHash-based short-id this is fine in
distribution but **different concrete buckets**. Concrete consequence:

- An attacker producing 12 short-ids that all collide in **Core's**
  libstdc++ bucket layout will trigger the cap on Core but will
  scatter across `len+1` buckets on blockbrew and pass.
- The inverse: a malicious sequence that maxes out one of blockbrew's
  buckets will be rejected here but accepted by Core.

Result: cross-impl divergence on attacker-chosen cmpctblocks. blockbrew
rejects messages Core accepts (and vice versa).

The W126 audit notes the comment-as-confession at line 354-359 ("We
approximate bucket membership by the short ID itself"). This audit
catalogues it as a discrete bug.

**File:** `internal/p2p/compactblock.go:382-386`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:104-111`.

**Impact:** symmetric cross-impl divergence on hash-flooding probes;
fuzz-test fork-detection candidate.

---

## BUG-7 (P1) — extra-txn loop double-counts on `extraCount--` when slot was mempool-filled

**Severity:** P1 (statistics-only; one symptom). The extra-txn loop
(`compactblock.go:442-470`):

```go
for _, extra := range extraTxn {
    ...
    if !haveTxn[slot] {
        p.txnAvailable[slot] = extra.Tx
        haveTxn[slot] = true
        p.mempoolCount++
        p.extraCount++
    } else {
        // Two extra/mempool txns match the same short ID; only clear if
        // the witness hashes differ (Core blockencodings.cpp:162-167).
        if p.txnAvailable[slot] != nil &&
            p.txnAvailable[slot].WTxHash() != extra.Wtxid {
            p.txnAvailable[slot] = nil
            p.mempoolCount--
            p.extraCount--   // <-- always-decrement
        }
    }
}
```

If `slot` was filled by the mempool-loop earlier (which incremented
`mempoolCount++` only — `extraCount` never touched), then this branch
decrements `extraCount` for a slot that never contributed to it.
`extraCount` can go negative.

Core's structure is symmetric because the same `mempool_count` variable
is incremented in BOTH the mempool and extra loops on +1, and decremented
on -1 in both clear-branches (blockencodings.cpp:135 + 166).
blockbrew splits the counter into `mempoolCount` (shared) and `extraCount`
(extra-only) but the decrement code path treats them as if always
parallel.

`Stats()` (compactblock.go:609-613) exposes `extraCount` publicly; a
negative value would propagate to test fixtures and any production
observability that records "from-extra-pool fill ratio".

**File:** `internal/p2p/compactblock.go:457-465`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:147-176`.

**Impact:** statistics-skewed (negative-going extraCount); fixable by
matching mempool-loop semantics or by tracking per-slot `filledBy`
(MEMPOOL/EXTRA) so the decrement only fires when the slot's prior
filler was actually extra.

---

## BUG-8 (P1 DEAD-DATA) — `vExtraTxnForCompact` orphan-pool wire-up absent in production

**Severity:** P1 ("dead-data plumbing" fleet pattern, ~10th distinct
blockbrew instance per W138/W140/W141/W149 tracking). The `ExtraTx`
type is exported (compactblock.go:258), the `InitData` parameter
accepts a non-empty `[]ExtraTx` slice and the loop at
compactblock.go:442-470 correctly consults it. The unit test
`TestInitDataExtraTxn` in compactblock_test.go:357-400 exercises the
loop.

**Production code never assembles `vExtraTxnForCompact`.** Even if
W126-BUG-1 (HB reconstruction wire-up) were fixed, the production call
would be `pdb.InitData(cmpctblock, mempool, nil)` — empty extra pool.

Core's `vExtraTxnForCompact` (defined in net_processing.cpp, populated
at orphan-pool eviction and replaced-tx points) is the second-line
defense for cmpctblock reconstruction when mempool eviction has
dropped a txn that the announcing peer still has via their orphan pool.
Without it, a non-trivial fraction of cmpctblocks degrade to full
getdata round-trips even after a healthy mempool reconstruction is
otherwise possible.

**File:** `internal/p2p/compactblock.go:255-261` (ExtraTx defined);
**zero production callers**.

**Core ref:** Core net_processing.cpp `vExtraTxnForCompact` declaration
+ population sites in orphan-pool / replaced-tx handlers.

**Impact:** even with W126-BUG-1 fixed, cmpct reconstruction success
rate is below Core's. Lower bandwidth efficiency post-fix.

---

## BUG-9 (P2) — `OnCmpctBlock` / `OnBlockTxn` lack `LoadingBlocks` / IBD guard (W126-BUG-6)

**Severity:** P2. Carry-forward of W126-BUG-6. Bitcoin Core
(net_processing.cpp:4468-4472):

```cpp
if (m_chainman.m_blockman.LoadingBlocks()) {
    LogDebug(BCLog::NET, "Unexpected cmpctblock message received from peer %d\n", pfrom.GetId());
    return;
}
```

guards both CMPCTBLOCK (line 4468) and BLOCKTXN (line 4717). blockbrew
has `SyncManager.IsIBDActive()` but neither handler consults it
(sync.go:1014, 1065). Today benign because handlers are log-only
(BUG-12/BUG-14/BUG-20), but becomes load-bearing once the receive
pipeline is wired.

**File:** `internal/p2p/sync.go:1014, 1065`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4468-4472, 4717-4720`.

**Impact:** gated on receive-side wiring; flagged for forward-fix.

---

## BUG-10 (P1) — `OnCmpctBlock` never inspects `header.PrevBlock`; orphan path absent (W126-BUG-5)

**Severity:** P1. Carry-forward of W126-BUG-5 orphan-prong. Core
(net_processing.cpp:4483-4489):

```cpp
const CBlockIndex* prev_block = m_chainman.m_blockman.LookupBlockIndex(cmpctblock.header.hashPrevBlock);
if (!prev_block) {
    if (!m_chainman.IsInitialBlockDownload()) {
        MaybeSendGetHeaders(pfrom, GetLocator(m_chainman.m_best_header), peer);
    }
    return;
}
```

blockbrew (sync.go:1014-1042) never reads `msg.Header.PrevBlock`.
Result: when a peer announces a cmpctblock whose parent header
blockbrew has not yet learned about (a common case on a slow IBD or
shortly after a reorg), blockbrew issues `getdata(BLOCK)` for the
announced hash, gets a notfound or hangs.

**File:** `internal/p2p/sync.go:1014-1042`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4483-4489`.

**Impact:** orphan cmpctblocks cause stalled downloads instead of the
correct getheaders fallback.

---

## BUG-11 (P1) — Anti-DoS work-threshold gate absent on CMPCTBLOCK (W126-BUG-5)

**Severity:** P1. Carry-forward of W126-BUG-5 work-prong. Core
(net_processing.cpp:4490-4493):

```cpp
} else if (prev_block->nChainWork + GetBlockProof(cmpctblock.header) < GetAntiDoSWorkThreshold()) {
    LogDebug(BCLog::NET, "Ignoring low-work compact block from peer %d\n", pfrom.GetId());
    return;
}
```

blockbrew has no equivalent. A malicious peer can announce
zero-difficulty cmpctblocks built off any known prev_block; blockbrew
issues a full getdata(BLOCK) per message, amplifying the attacker's
bandwidth cost by 1000x for the 32-byte hash.

**File:** `internal/p2p/sync.go:1014-1042`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4490-4493`.

**Impact:** spam-amplification DoS vector. Throw-cost-asymmetric attack.

---

## BUG-12 (P0-DEAD) — `OnCmpctBlock` does not feed embedded header into ProcessNewBlockHeaders (W126-BUG-4)

**Severity:** P0-DEAD. Carry-forward of W126-BUG-4. Core
(net_processing.cpp:4503-4509):

```cpp
const CBlockIndex *pindex = nullptr;
BlockValidationState state;
if (!m_chainman.ProcessNewBlockHeaders({{cmpctblock.header}}, /*min_pow_checked=*/true, state, &pindex)) {
    if (state.IsInvalid()) {
        MaybePunishNodeForBlock(pfrom.GetId(), state, /*via_compact_block=*/true, "invalid header via cmpctblock");
        return;
    }
}
Assert(pindex);
```

ALWAYS runs the cmpctblock-embedded header through the header
acceptance pipeline. blockbrew's `OnCmpctBlock` (sync.go:1014-1042)
discards the parsed message entirely and immediately falls back to
`getdata(MSG_WITNESS_BLOCK)`. The header is never inserted into
`headerIndex` from this path.

Today's saving grace: blockbrew is never selected as any peer's HB
recipient (because BUG-21 keeps `WantsHBCompactBlocks` dead), so
cmpctblock announcements arrive only after an inv/headers exchange
that has already populated the header index. If/when blockbrew offers
HB-receive (sends `sendcmpct(announce=true)`) or a peer aggressively
sends cmpctblock to all peers regardless of HB negotiation, this is a
hard chain-discovery break.

**File:** `internal/p2p/sync.go:1014-1042`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4503-4509`.

**Impact:** if blockbrew ever requests HB-receive (which would be a
P1 future fix), it would silently fail to discover tip via the cmpct
path. Today: gated on no-HB-receive being the de-facto state.

---

## BUG-13 (P2) — MaybePunishNodeForBlock on invalid cmpctblock header is dead (W126-BUG-7)

**Severity:** P2. Carry-forward of W126-BUG-7. Core
(net_processing.cpp:4505) calls `MaybePunishNodeForBlock(..., via_compact_block=true, …)`
on `ProcessNewBlockHeaders` failure. Gated on BUG-12 — blockbrew
never validates the header in this path, so the punish-on-invalid is
trivially unreachable. Recorded for completeness.

**File:** `internal/p2p/sync.go:1014-1042`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4505`.

**Impact:** zero DoS-score for peers sending arbitrary invalid headers
via cmpctblock.

---

## BUG-14 (P0-DEAD) — Receive-side PartiallyDownloadedBlock pipeline never invoked from production (W126-BUG-1)

**Severity:** P0-DEAD. Carry-forward of W126-BUG-1. `OnCmpctBlock`
(sync.go:1014-1042):

```go
OnCmpctBlock: func(p *Peer, msg *MsgCmpctBlock) {
    // We don't have a mempool, so we can't reconstruct the block from
    // short IDs. Fall back to requesting the full block via getdata.
    blockHash := msg.Header.BlockHash()
    ...
    inv := &MsgGetData{
        InvList: []*InvVect{
            {Type: InvTypeWitnessBlock, Hash: blockHash},
        },
    }
    p.SendMessage(inv)
}
```

The comment is a **comment-as-confession** (fleet pattern, ~12th
distinct blockbrew instance per W138/W140/W141/W149/W155 tracking) AND
load-bearing AND stale: blockbrew DOES have a mempool
(`internal/mempool/`) wired into the production node, RPC, ZMQ, and
fee-estimation. The handler simply does not consult it.

The full reconstruction pipeline is wired:
- `PartiallyDownloadedBlock` (compactblock.go:223),
- `InitData(cmpctblock, mempool, extraTxn)` (compactblock.go:279),
- `GetMissingIndexes` (line 506),
- `FillMissingTransactions` (line 520),
- `FillBlock(vtxMissing, segwitActive)` (line 549).

Tested in `compactblock_test.go` and `w126_bip152_test.go`. Production:
zero callers.

**File:** `internal/p2p/sync.go:1014-1042`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4577-4654`
(full receive-side reconstruction including `PartiallyDownloadedBlock`
+ `InitData` + missing-tx tracking).

**Impact:** every cmpctblock arrival triggers a full block download.
BIP-152's primary purpose (bandwidth reduction for block propagation)
is defeated end-to-end. blockbrew is effectively a "headers-and-inv
plus full-block" node despite implementing the full BIP-152 wire
protocol.

---

## BUG-15 (P0-DEAD) — `CreateGetBlockTxn` has zero production callers

**Severity:** P0-DEAD. Companion to BUG-14. `CreateGetBlockTxn`
(compactblock.go:685-697) constructs a `MsgGetBlockTxn` from a
missing-index slice using the correct differential encoding. The
function is exported, tested in compactblock_test.go, and called by
NO production code path. Grep across `internal/` + `cmd/` confirms
zero call sites outside `_test.go` files.

**File:** `internal/p2p/compactblock.go:685-697`; grep result: only
`_test.go` files cite it.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4609-4620` calls
`MakeAndPushMessage(pfrom, NetMsgType::GETBLOCKTXN, req)` after
collecting missing-indexes from the partial block.

**Impact:** even if BUG-14 wired up `PartiallyDownloadedBlock`, the
missing-tx round-trip would not fire because nothing dispatches a
`getblocktxn`. The full BIP-152 receive pipeline (cmpct → init →
collect missing → getblocktxn → blocktxn → fill → process) is broken
at this stage too.

---

## BUG-16 (P0-DEAD) — `OnGetBlockTxn` is log-only (W126-BUG-2)

**Severity:** P0-DEAD. Carry-forward of W126-BUG-2. The handler
(sync.go:1043-1064):

```go
OnGetBlockTxn: func(p *Peer, msg *MsgGetBlockTxn) {
    if sm.headerIndex != nil {
        tipHeight := sm.headerIndex.BestHeight()
        if node := sm.headerIndex.GetNode(msg.BlockHash); node != nil {
            depth := tipHeight - node.Height
            if depth > MaxBlocktxnDepth {
                log.Printf(...)
                // TODO(BUG-3): once OnGetBlockTxn serving is implemented,
                // send full block via getdata here instead of blocktxn.
                return
            }
        }
    }
    log.Printf("[compact] Received getblocktxn from %s, ignoring", p.Address())
}
```

Both branches `return` without producing a reply. `CreateBlockTxn`
(compactblock.go:716-730) exists, is tested, never called from
production. Result: peers that have negotiated cmpctblock with us and
request a missing-tx response get nothing — they wait for the message
to time out, then re-request the block via plain getdata, doubling
their round-trip cost.

**File:** `internal/p2p/sync.go:1043-1064`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4245-4304`
(full serve path including `m_most_recent_block` fast-path,
`ReadBlock` from disk, OOB-index Misbehaving, depth-fallback getdata).

**Impact:** blockbrew is non-reciprocal — accepts compact block
negotiation from peers but refuses to serve the corresponding
missing-tx round-trip. Peers waste timeout windows and may discourage
blockbrew as an unresponsive cmpct peer.

---

## BUG-17 (P1) — MAX_BLOCKTXN_DEPTH fallback does not queue full-block getdata (W126-BUG-2)

**Severity:** P1. Carry-forward of W126-BUG-2 depth-prong. When the
requested block is deeper than `MAX_BLOCKTXN_DEPTH=10`, Core
(net_processing.cpp:4299-4302) queues `CInv{MSG_WITNESS_BLOCK,
blockhash}` on the peer's getdata queue so the response loop sends a
full block instead:

```cpp
LogDebug(BCLog::NET, "Peer %d sent us a getblocktxn for a block > %i deep\n",
         pfrom.GetId(), MAX_BLOCKTXN_DEPTH);
CInv inv{MSG_WITNESS_BLOCK, req.blockhash};
WITH_LOCK(peer.m_getdata_requests_mutex, peer.m_getdata_requests.push_back(inv));
```

blockbrew's handler (sync.go:1054-1060) computes the depth check
correctly and even logs the right message, but the comment-confession
`// TODO(BUG-3): once OnGetBlockTxn serving is implemented, send full
block via getdata here instead of blocktxn.` admits the actual queue
push is missing. The branch just `return`s.

**File:** `internal/p2p/sync.go:1054-1060`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4299-4302`.

**Impact:** even in the depth-fallback case (which Core engineered as
a graceful degradation), blockbrew sends NO reply. The peer sees a
timeout. Symmetric tarpitting from BUG-16.

---

## BUG-18 (P2) — No `m_most_recent_block` / `m_most_recent_compact_block` cache (W126-BUG-8)

**Severity:** P2. Carry-forward of W126-BUG-8. Core caches the
most-recently-mined block in two forms:
1. `m_most_recent_block` (full CBlock) for the GETBLOCKTXN fast-path
   (net_processing.cpp:4254-4263) — avoids a disk read when the peer
   requests txns from the very block we just announced.
2. `m_most_recent_compact_block` (cached CBlockHeaderAndShortTxIDs)
   for re-announce dispatch to HB peers (net_processing.cpp:5898-5912)
   — avoids re-computing short-IDs per HB peer.

blockbrew has neither. Today gated on BUG-16/BUG-23 (nothing to cache
until serve/announce paths exist); flagged for forward-fix.

**File:** `internal/p2p/peermgr.go` (no cache); `internal/p2p/sync.go`
(no cache).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4254-4263, 5898-5912`.

**Impact:** performance regression once BUG-16/BUG-23 are wired —
every serve forces disk read and short-id recomputation.

---

## BUG-19 (P2) — OOB-index Misbehaving check on getblocktxn req.indexes is dead code (W126-BUG-2)

**Severity:** P2. Carry-forward of W126-BUG-2 OOB-prong. Core
(net_processing.cpp:2603-2604):

```cpp
if (req.indexes[i] >= block.vtx.size()) {
    Misbehaving(peer, "getblocktxn with out-of-bounds tx indices");
    return;
}
```

blockbrew never walks `req.Indexes` in `OnGetBlockTxn`, so the OOB
check (and corresponding peer DoS-score punishment) is unreachable.
Gated on BUG-16.

**File:** `internal/p2p/sync.go:1043-1064`; `CreateBlockTxn`
(compactblock.go:716-730) has a `return nil, fmt.Errorf("requested
index %d out of range", idx)` check at line 723-725 but no
peer-side punishment.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2603-2604`.

**Impact:** Misbehaving-on-OOB is dead code; gated on BUG-16.

---

## BUG-20 (P0-DEAD) — `OnBlockTxn` is log-only (W126-BUG-3)

**Severity:** P0-DEAD. Carry-forward of W126-BUG-3. The handler
(sync.go:1065-1069):

```go
OnBlockTxn: func(p *Peer, _ *MsgBlockTxn) {
    // Response to our getblocktxn request. Since we fall back to full
    // block download, we shouldn't receive these. Ignore.
    log.Printf("[compact] Received blocktxn from %s, ignoring", p.Address())
}
```

`FillMissingTransactions` (compactblock.go:520) and `FillBlock`
(line 549) exist, are tested, never called from production.

Today benign because BUG-15 ensures blockbrew never sends a
`getblocktxn`, so the only path to receive `blocktxn` is an unsolicited
spam message — which we correctly ignore. Becomes a P0-DEAD pipeline
break once BUG-14 + BUG-15 are fixed.

**File:** `internal/p2p/sync.go:1065-1069`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4714-4726`
(`ProcessCompactBlockTxns(pfrom, peer, resp)`).

**Impact:** receive-side completion of the cmpct → getblocktxn →
blocktxn → fill pipeline is broken at the final step.

---

## BUG-21 (P0-DEAD) — `MaxHBPeers=3` HB-list is absent (W126-BUG-1 / W112-BUG-1)

**Severity:** P0-DEAD. Carry-forward of W126-BUG-1 / W112-BUG-1.
`MaxHBPeers = 3` (compactblock.go:25) is a defined constant with ZERO
consumers. Grep across `internal/` + `cmd/` shows no
`lNodesAnnouncingHeaderAndIDs`-equivalent list, no
`MaybeSetPeerAsAnnouncingHeaderAndIDs` analogue, no outbound-peer-
preference logic in HB eviction. The whole 3-HB-peer mechanism Core
(net_processing.cpp:1272-1329) implements is structurally absent.

The constant exists; the policy doesn't. Pure dead-data.

**File:** `internal/p2p/compactblock.go:25` (constant);
`internal/p2p/peermgr.go` (no HB list); `internal/p2p/sync.go`
(no HB list).

**Core ref:** `bitcoin-core/src/net_processing.cpp:1272-1329`.

**Impact:**
- We are NEVER an HB-source: no peer ever receives our cmpctblock
  announcement on the lower-latency path.
- We are NEVER an HB-recipient with policy enforcement: even if a peer
  flagged us as their HB recipient via `sendcmpct(announce=true)`,
  we'd accept it but never use the negotiated path correctly.

---

## BUG-22 (P1) — `OnSendCmpct` is log-only; doesn't drive HB-list selection

**Severity:** P1. Companion to BUG-21. The listener at sync.go:1010-1013:

```go
OnSendCmpct: func(p *Peer, msg *MsgSendCmpct) {
    log.Printf("[compact] Peer %s supports compact blocks: version=%d, announce=%v",
        p.Address(), msg.CmpctBlockVersion, msg.AnnounceUsingCmpctBlock)
}
```

never updates an HB-out list (BUG-21), never replies with
`sendcmpct(false, 2)` to evict an old HB peer (Core line 1315-1320),
never re-orders the HB list to favour newly-validated outbound peers.

The `MaybeSetPeerAsAnnouncingHeaderAndIDs` call that Core triggers from
`ProcessBlockAvailability` / post-validation is the canonical hook;
blockbrew's equivalent (`onBlockConnected` chain) never references the
compact-block HB pathway at all.

**File:** `internal/p2p/sync.go:1010-1013`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:1310-1322` (HB
eviction + announce); `bitcoin-core/src/net_processing.cpp:2220`
(post-block-valid HB selection trigger).

**Impact:** HB negotiation is one-shot at sendcmpct receipt — no
mid-connection re-evaluation.

---

## BUG-23 (P0-DEAD) — `AnnounceBlock` never dispatches `cmpctblock` to HB peers (W112-BUG-1)

**Severity:** P0-DEAD. Carry-forward of W112-BUG-1.
`peermgr.go:748-770`:

```go
func (pm *PeerManager) AnnounceBlock(header wire.BlockHeader, hash wire.Hash256) {
    pm.mu.RLock()
    defer pm.mu.RUnlock()

    headersMsg := &MsgHeaders{Headers: []wire.BlockHeader{header}}
    invMsg := &MsgInv{
        InvList: []*InvVect{
            {Type: InvTypeBlock, Hash: hash},
        },
    }

    for _, info := range pm.peers {
        peer := info.peer
        if !peer.IsConnected() {
            continue
        }
        if peer.SendsHeaders() {
            peer.SendMessage(headersMsg)
        } else {
            peer.SendMessage(invMsg)
        }
    }
}
```

The two-arm switch on `SendsHeaders()` gives every peer either HEADERS
or INV — never CMPCTBLOCK. Core's `SendMessages` path
(net_processing.cpp:5891-5913) reads `state.m_requested_hb_cmpctblocks`
and dispatches a cmpctblock when the peer has flagged themselves as
HB-from-us. blockbrew's `peer.WantsHBCompactBlocks()` (peer.go:1291)
is exported, tested, never consulted in `AnnounceBlock`.

`CompactBlockBuilder` (compactblock.go:181-220) is exported, tested,
called only from test files.

**File:** `internal/p2p/peermgr.go:748-770`;
`internal/p2p/compactblock.go:181-220` (Builder unused);
`internal/p2p/peer.go:1290-1295` (WantsHBCompactBlocks dead).

**Core ref:** `bitcoin-core/src/net_processing.cpp:5891-5913`.

**Impact:** end-to-end announce-side is dead. blockbrew never benefits
nor causes its peers to benefit from BIP-152 announce-side bandwidth
reduction. Every block we announce goes via plain headers/inv +
full-block-getdata.

---

## BUG-24 (P2) — `m_most_recent_compact_block` cache for announce-side absent (W126-BUG-8)

**Severity:** P2. Carry-forward of W126-BUG-8. Gated on BUG-23; once
HB-announce is wired, we'd want to cache the
`CBlockHeaderAndShortTxIDs` for the most-recently-validated tip so the
3 HB peers each get the same precomputed message instead of
recomputing short-IDs three times.

**File:** `internal/p2p/peermgr.go`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:5898-5912`.

**Impact:** gated on BUG-23. Forward-fix.

---

## BUG-25 (P1 WIRE-INTEROP) — `InvTypeCmpct=4` (MSG_CMPCT_BLOCK) is missing (W126-BUG-10)

**Severity:** P1 WIRE-INTEROP. Carry-forward of W126-BUG-10.
`msg_inv.go:14-20` enumerates:

```go
const (
    InvTypeError         InvType = 0
    InvTypeTx            InvType = 1
    InvTypeBlock         InvType = 2
    InvTypeFilteredBlock InvType = 3
    InvTypeWtx           InvType = 5
    InvTypeWitnessTx     InvType = 0x40000001
    InvTypeWitnessBlock  InvType = 0x40000002
)
```

**`InvTypeCmpct = 4` (Core MSG_CMPCT_BLOCK per protocol.h:484) is
missing.** Consequences:

1. **HandleGetData (sync.go:1284-1313)** has no case for `InvTypeCmpct`.
   If a peer sends `getdata(MSG_CMPCT_BLOCK, hash)`, blockbrew falls
   through the switch silently (no notfound, no reply). The peer waits
   for a cmpctblock that never arrives. Core
   (net_processing.cpp:2456-2473) handles this case by checking depth
   ≤ `MAX_CMPCTBLOCK_DEPTH=5` and replying with either CMPCTBLOCK or
   full-block.

2. **Reverse-direction:** blockbrew never SENDS `getdata(MSG_CMPCT_BLOCK)`
   either, so we can't issue the BIP-152 "fetch by cmpctblock" request
   to peers who advertise our recent block via INV but want us to
   prefer the cmpct path.

This is the **W152-pattern echo (unidirectional)** the audit was
specifically asked to check: just as W152 BUG-3+2 found that
`HandleGetData` is a TODO stub for `InvTypeTx`/`InvTypeWtx`, here we
find that `HandleGetData` has no case at all for `InvTypeCmpct`. The
type is not even defined. The W141 byte-order echo (LE vs Core's
display-order in ZMQ hashes) does NOT apply here — cmpctblock's
short-id derivation uses the correct CSHA256 output read as LE, and
the inv-vector hash on the wire is internal byte-order (matching Core).

**File:** `internal/p2p/msg_inv.go:14-20`;
`internal/p2p/sync.go:1284-1313` (HandleGetData switch).

**Core ref:** `bitcoin-core/src/protocol.h:484`;
`bitcoin-core/src/net_processing.cpp:2456-2473`.

**Impact:**
- Wire-interop: peers cannot fetch our recent blocks via the BIP-152
  fast-path getdata. Silent no-op.
- Bandwidth: an HB-receiving peer who wants to use the cmpct path
  is forced to fall back to full-block getdata.
- Cross-cite W152: blockbrew is unidirectional on getdata for both
  tx (W152) and cmpctblock (this audit). The pattern is repeating
  across BIP families — sendcmpct receives, but getdata serving is a
  partial stub.

---

## BUG-26 (P1) — `MsgGetBlockTxn` deserializer does not auto-decode differential indexes (asymmetric round-trip)

**Severity:** P1. `CreateGetBlockTxn` (compactblock.go:685-697) encodes
the missing-indexes array using differential encoding (`cur - prev - 1`)
BEFORE handing off to `MsgGetBlockTxn{Indexes: encoded}`. Then
`MsgGetBlockTxn.Serialize` (msg_cmpctblock.go:128-140) writes each
`encoded[i]` as compactsize.

The inverse path (`Deserialize`, msg_cmpctblock.go:144-163) reads
compactsize values and stores them raw in `m.Indexes`. The caller is
expected to call `DecodeGetBlockTxnIndexes` (compactblock.go:700-712)
separately.

**Asymmetry:** Serialize takes logical (absolute) indexes, Deserialize
produces wire (differential) indexes. The two halves of a hypothetical
`Marshal/Unmarshal(msg) == msg` round-trip do not compose without an
external decoder call. Any future caller that calls
`Serialize(msg)` followed by `Deserialize` on the resulting bytes will
get back a different `msg`.

This is identical in shape to the W141 byte-order divergence — the
encode path applies a transform the decode path does not invert.

**File:** `internal/p2p/msg_cmpctblock.go:128-163`;
`internal/p2p/compactblock.go:685-712`.

**Core ref:** `bitcoin-core/src/blockencodings.h:23-43`
(`DifferenceFormatter::Ser` and `::Unser` are symmetric — the
transform is bidirectional).

**Impact:** test-and-fuzz hazard. Any in-process round-trip (e.g.,
"serialize then re-deserialize for validation") double-encodes. Also,
the type contract makes the field semantically polymorphic
(absolute on the in-memory side post-Create, differential on the
in-memory side post-Deserialize) — error-prone for future contributors.

---

## Summary

**Bug count:** 26 (BUG-1 through BUG-26).

**Severity distribution:**
- **P0-CDIV:** 1 (BUG-3 — `PrefilledTx.Index uint32` wire-format divergence)
- **P0-DEAD:** 7 (BUG-12, BUG-14, BUG-15, BUG-16, BUG-20, BUG-21, BUG-23)
- **P1:** 12 (BUG-1, BUG-4, BUG-5, BUG-7, BUG-8, BUG-10, BUG-11, BUG-17, BUG-22, BUG-25, BUG-26 + counted-once for the WIRE-INTEROP P1 subset)
- **P2:** 6 (BUG-2, BUG-6, BUG-9, BUG-13, BUG-18, BUG-19, BUG-24)

Recount: P0-CDIV 1 + P0-DEAD 7 + P1 11 + P2 7 = 26.

(P1 recount: BUG-1, BUG-4, BUG-5, BUG-7, BUG-8, BUG-10, BUG-11, BUG-17,
BUG-22, BUG-25, BUG-26 = 11. P2 recount: BUG-2, BUG-6, BUG-9, BUG-13,
BUG-18, BUG-19, BUG-24 = 7. 1+7+11+7 = 26. ✓)

**Fleet patterns confirmed:**
- "dead-data plumbing" (BUG-8 `ExtraTx` orphan-pool, BUG-21
  `MaxHBPeers`, BUG-22 `WantsHBCompactBlocks`) — 3 distinct W156
  instances; ~10th-12th blockbrew distinct instance overall per
  W138/W140/W141/W149/W155 tracking
- "comment-as-confession" (BUG-14 sync.go:1015 "We don't have a
  mempool" — load-bearing AND stale; BUG-17 sync.go:1057 `TODO(BUG-3)`
  comment admits depth-fallback never wired) — 2 new instances; ~12th
  and 13th distinct blockbrew instance
- "W152 echo / unidirectional pattern" (BUG-25 `InvTypeCmpct=4` absent
  in HandleGetData; BUG-15 `CreateGetBlockTxn` no production callers;
  BUG-23 `AnnounceBlock` never sends cmpctblock) — confirms the
  unidirectional asymmetry pattern from W152 in a 3rd BIP family
  (cmpctblock joins tx and wtx)
- "W141 echo (byte-order divergence on hash)" — DOES NOT apply here.
  Short-id SipHash key derivation uses correct CSHA256 + LE-uint64
  read, matching Core. The cmpctblock-embedded header hash is
  internal-byte-order on wire (matches Core's `uint256` serialization).
  W141 echo is specifically a ZMQ-pub side artefact and is NOT shared
  by the cmpctblock pipeline. Negative finding worth recording.
- "wire-format type-width divergence" (BUG-3 uint32 vs uint16 on
  PrefilledTx.Index, BUG-4 BlockTxCount uint16 cap absent, BUG-5
  MaxInvVects too tight) — 3 W156 instances; same shape as the W132
  `MsgTx.Version int32→uint32` fleet finding (was 1-line P0)
- "exported-tested-not-wired" (BUG-14 PartiallyDownloadedBlock,
  BUG-15 CreateGetBlockTxn, BUG-16 CreateBlockTxn, BUG-20
  FillMissingTransactions, BUG-21 MaxHBPeers, BUG-22
  WantsHBCompactBlocks, BUG-23 CompactBlockBuilder) — entire BIP-152
  receive AND send pipeline is implementation-complete on the
  library side and wiring-broken on the listener/peermgr side
- "asymmetric encode/decode round-trip" (BUG-26
  MsgGetBlockTxn.Indexes) — first W156 instance; companion to W141
  byte-order asymmetry pattern (encode applies a transform decode
  does not invert)
- "TODO-as-bug-tracker in production code" (BUG-17 sync.go:1057
  `TODO(BUG-3)` annotation in production handler comment) — first
  W156 instance; suggests the audit's own findings are being deferred
  via inline comments instead of resolved
- "every gate-of-the-receive-pipeline-broken" (BUG-9 LoadingBlocks +
  BUG-10 orphan + BUG-11 anti-DoS + BUG-12 ProcessNewBlockHeaders +
  BUG-13 punish + BUG-14 reconstruction + BUG-15 getblocktxn dispatch
  + BUG-20 blocktxn fill) — first W156 instance of the W138
  "30-of-30-gates-buggy" pattern restricted to a single receive
  pipeline (cmpctblock); 8 of 8 receive-side gates downstream of
  message dispatch are broken or absent

**W156-specific new patterns (first observation this wave):**
1. **"BIP-152 fast path entirely bypassed"** — the entire
   negotiate-send-receive cycle is structurally present on the wire
   (sendcmpct goes out, sendcmpct comes in, cmpctblock arrives,
   getblocktxn arrives, blocktxn arrives) but every receive handler
   degrades to "fall back to full block" or "log+ignore". Net effect:
   blockbrew negotiates BIP-152 but operates as if BIP-152 didn't exist.
2. **"missing inv type number"** — BUG-25's specific failure mode
   (`InvTypeCmpct=4` not defined) is more severe than the W126-BUG-10
   description suggested: it's not just a missing handler, the type
   number itself is unreserved in the enum. Any future code that
   accidentally invents `InvType(4)` would collide.
3. **"comment migrated faster than the code"** — the load-bearing
   `// We don't have a mempool, so we can't reconstruct the block`
   comment at sync.go:1015 was true at some point in history, but
   blockbrew now has a fully wired internal/mempool/ subsystem. The
   comment frozen a design choice past its expiration date.

**Top three findings:**

1. **BUG-25 (P1 WIRE-INTEROP) — `InvTypeCmpct=4` is missing entirely**
   — not only is HandleGetData unable to serve a peer's
   `getdata(MSG_CMPCT_BLOCK)` request, the enum constant is not
   defined in the InvType list at all. Direct W152 echo: the
   unidirectional getdata-serve pattern repeats in a third BIP family.
   Peers attempting the BIP-152 fast-path fetch get silent no-op and
   eventually time out. Fix: 1-line constant addition plus a case in
   HandleGetData; ~5 LOC total.

2. **BUG-3 (P0-CDIV) — `PrefilledTx.Index uint32` violates BIP-152's
   uint16 type contract** — wire-format divergence with two attack
   surfaces: (a) blockbrew CAN serialize cmpctblocks Core rejects with
   "indexes overflowed 16 bits"; (b) the decode path's
   `int32(uint32Index) + 1` arithmetic can wrap around when fed a
   prefilled.Index near 2^32, bypassing the cumulative-overflow guard.
   Companion to W132 `MsgTx.Version int32→uint32` fleet finding. Fix:
   change field type to `uint16`, add BlockTxCount > uint16-max
   post-deserialize check (BUG-4 companion); ~3 LOC.

3. **BUG-14 + BUG-15 + BUG-16 + BUG-20 + BUG-21 + BUG-23 cluster
   (P0-DEAD pipeline — the entire BIP-152 receive AND send is wired
   on the message types and reconstruction primitives but every entry
   point in production code falls back to plain block relay)** — the
   single most architecturally damaging finding. Six BUGs (out of 26)
   describe one phenomenon: blockbrew implements BIP-152 wire format
   correctly, exports the reconstruction APIs, tests them in isolation,
   and then routes EVERY production message handler to the
   pre-BIP-152 path. The fix is not a code addition — the reconstruction
   library is in place — it's a wiring exercise across
   `sync.go:OnCmpctBlock/OnGetBlockTxn/OnBlockTxn` (3 handlers),
   `peermgr.go:AnnounceBlock` (1 dispatcher), plus the HB-list
   bookkeeping (~50 LOC). This is the priority post-W156 fix for
   blockbrew's BIP-152 parity.
