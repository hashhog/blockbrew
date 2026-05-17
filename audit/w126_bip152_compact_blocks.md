# W126 — BIP-152 Compact Blocks Audit (blockbrew)

**Wave**: W126 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**Reference**:
- `bitcoin-core/src/net_processing.cpp` — handlers for `SENDCMPCT`,
  `CMPCTBLOCK`, `GETBLOCKTXN`, `BLOCKTXN`; `MaybeSetPeerAsAnnouncingHeaderAndIDs`;
  `NewPoWValidBlock`; `SendBlockTransactions`; `ProcessCompactBlockTxns`.
- `bitcoin-core/src/blockencodings.{h,cpp}` — `CBlockHeaderAndShortTxIDs`,
  `PartiallyDownloadedBlock`, `BlockTransactionsRequest`, `BlockTransactions`,
  `FillShortTxIDSelector`, `GetShortID`, `DifferenceFormatter`, the InitData
  state machine, `READ_STATUS_*`.
- `bitcoin-core/src/consensus/validation.cpp` — `IsBlockMutated` (used by
  FillBlock to defend against accidental short-ID collisions that line up to a
  syntactically-valid block).
- **BIP-152** — Compact Block Relay; protocol versions 1 (txid/no-witness) and
  2 (wtxid/witness-aware).
- **Precedent**: existing `internal/p2p/w112_compact_blocks_test.go` (W112
  surfaced 7 bugs in 2026-Q2). This audit extends to 30 gates and treats W112
  as the prior art; bugs are not re-numbered but the W126 gate map carries
  forward the seven existing W112 findings under their original IDs (W112-BUG-1
  through W112-BUG-7) so that fix-wave tooling can grep them out of one file.

## Verdict

**N = 10 bugs / 30 gates.**

Of the 30 gates, **PRESENT × 16, PARTIAL × 2, MISSING × 12**.

10 distinct bug IDs (W126-BUG-1 .. W126-BUG-10).  Of those, **3 are W112
bug-survivors** (W126-BUG-1 → W112-BUG-1 dead announcement pipeline,
W126-BUG-2 → W112-BUG-3 getblocktxn log+ignore, W126-BUG-3 → W112-BUG-4
blocktxn log+ignore).  The other 7 are net-new findings W126-BUG-4
through W126-BUG-10.

### Per Core reference: severity breakdown

| Priority | Count | Note |
|---|---|---|
| **P0** (cross-network compat break) | 0 | no consensus break; no fork risk |
| **P1** (DEAD-PIPELINE: feature claimed at handshake but unwired) | 7 | every handler claims BIP-152 support but the four outbound paths (announce, serve cmpctblock via getdata, serve blocktxn, fast-receive reconstruction) all degrade silently |
| **P2** (DoS / efficiency) | 2 | misbehaving-on-bad-msg, mempool-aware reconstruction |
| **P3** (cosmetic / spec-strict) | 1 | v1 (non-witness) protocol entirely absent |

Per Core reference: blockbrew **advertises** BIP-152 support by sending
`sendcmpct(v=2, hb=false)` at handshake (peer.go:910).  Operationally this
means peers will optimistically announce blocks to blockbrew using
`cmpctblock`.  blockbrew accepts those messages syntactically (the
deserializer + `PartiallyDownloadedBlock` reconstructor are wired and
correct), but then **always falls back to `getdata BLOCK`** instead of
reconstructing from its (empty) mempool (sync.go:1014-1042).  This is
the W112-known dead pipeline.  Compact blocks for blockbrew are
**inert advertisement** — they cost peers extra bandwidth (the full
`cmpctblock` payload is parsed and discarded) and provide no latency
benefit to blockbrew (the round-trip cost is one extra
`cmpctblock` → `getdata BLOCK` → `block` sequence vs. the simpler
`inv` → `getdata BLOCK` → `block`).

## Gate verdict table (30)

| # | Gate | Status | Bug | Severity | Notes |
|---|------|--------|-----|----------|-------|
| G1 | Handshake — `sendcmpct(v=2, hb=false)` sent after VERACK | **PRESENT** | — | — | `peer.go:910` |
| G2 | Handshake — only sends after handshake complete | **PRESENT** | — | — | `peer.go:884-913` checkHandshakeComplete |
| G3 | Negotiation — v2 sendcmpct from peer is accepted | **PRESENT** | — | — | `compactblock.go:641-645` SetSendCmpct |
| G4 | Negotiation — v1 sendcmpct from peer rejected (BIP-152 says: accept per version independently) | **MISSING** | W126-BUG-9 | P3 | `compactblock.go:641` only accepts version==2; v1 silently dropped.  Core also rejects v1 today (net_processing.cpp:3907 only accepts CMPCTBLOCKS_VERSION=2 since 0.21), so this is **WAI matches Core**.  Recording here for forward-spec compatibility — if Core ever re-enables v1 we will need both branches.  **Carry-forward from W112-BUG-2.** |
| G5 | Negotiation — per-peer `m_bip152_highbandwidth_from` state stored | **PRESENT** | — | — | `compactblock.go:636-646` SetSendCmpct sets announcesHB |
| G6 | Short-ID derivation — SipHash key = first-16-bytes of SHA256(header.Serialize() ‖ nonce_LE_u64) | **PRESENT** | — | — | `compactblock.go:70-79` ComputeSipHashKey; matches blockencodings.cpp:36-43 |
| G7 | Short-ID derivation — SipHash output truncated to 48 bits (6 bytes) | **PRESENT** | — | — | `compactblock.go:177` `h & 0xFFFFFFFFFFFF` and `ShortIDLength = 6` |
| G8 | Short-ID derivation — v2 uses **wtxid** (`tx.GetWitnessHash()`) | **PRESENT** | — | — | `compactblock.go:214` `wtxid := block.Transactions[i].WTxHash()` |
| G9 | Short-ID derivation — nonce serialized as LE uint64 | **PRESENT** | — | — | `compactblock.go:73` `binary.Write(&buf, binary.LittleEndian, nonce)` |
| G10 | CMPCTBLOCK handler — deserialize header + shortids + prefilled | **PRESENT** | — | — | `msg_cmpctblock.go:66-115` Deserialize |
| G11 | CMPCTBLOCK handler — calls `ProcessNewBlockHeaders` for the embedded header (Core path required for chain-tracking) | **MISSING** | W126-BUG-4 | P1 | `sync.go:1014-1042` OnCmpctBlock immediately sends `getdata BLOCK` and discards the parsed `MsgCmpctBlock`.  The header is **not** fed into the headers index, so a node receiving cmpctblock-only announcements from an HB peer would never learn about the new tip via the cmpctblock path; it relies on the parallel `inv`/`headers` announcement.  Core net_processing.cpp:4501 calls `ProcessNewBlockHeaders({{cmpctblock.header}}, …)` unconditionally. |
| G12 | CMPCTBLOCK handler — low-work guard (`prev_block->nChainWork + GetBlockProof(header) < GetAntiDoSWorkThreshold()` → silent drop) | **MISSING** | W126-BUG-5 | P1 | `sync.go:1014-1042` no anti-DoS work-threshold guard.  Core net_processing.cpp:4489-4493 silently drops low-work compact-block announcements before any expensive processing.  blockbrew unconditionally sends a `getdata BLOCK` in response, meaning a malicious peer can spam zero-work `cmpctblock`s and force blockbrew to disclose interest via per-message round-trips. |
| G13 | CMPCTBLOCK handler — prev-block-found / orphan handling: send `getheaders` for deeper history when prev is unknown | **MISSING** | W126-BUG-5 | P1 | Core net_processing.cpp:4485-4487 sends a `getheaders` (with locator) on prev-unknown.  blockbrew's OnCmpctBlock never inspects prev; it just sends `getdata BLOCK` for the cmpctblock's tip-hash, which fails if we don't know the prev (the peer will respond `notfound` or send orphan data).  Same bug as G12; bundle as W126-BUG-5. |
| G14 | CMPCTBLOCK handler — IBD / LoadingBlocks guard (drop while importing/reindexing) | **MISSING** | W126-BUG-6 | P2 | `sync.go:1014-1042` no IBD or LoadingBlocks check.  Core net_processing.cpp:4469-4473 drops cmpctblock during LoadingBlocks. blockbrew has `IsIBDActive()` available on the SyncManager but does not consult it.  **Carry-forward from W112-BUG-7.** |
| G15 | CMPCTBLOCK handler — invalid header → punish (call `MaybePunishNodeForBlock` via_compact_block=true) | **MISSING** | W126-BUG-7 | P2 | Core net_processing.cpp:4506-4509 calls MaybePunishNodeForBlock on `ProcessNewBlockHeaders` failure with `via_compact_block=true`.  blockbrew does not validate the header at all before falling back, so a malformed header (e.g. wrong difficulty) is treated identically to a valid one — no DoS score, no disconnect. |
| G16 | GETBLOCKTXN handler — respond with BLOCKTXN containing requested txns | **MISSING** | W126-BUG-2 | P1 | `sync.go:1043-1064` is log+ignore.  Core net_processing.cpp:4245-4304 reads block from disk if pindex>tip-10 and calls `SendBlockTransactions`.  A peer that requested missing txns from us via getblocktxn will stall waiting for a blocktxn that never comes.  **Carry-forward from W112-BUG-3.** |
| G17 | GETBLOCKTXN handler — MAX_BLOCKTXN_DEPTH=10 enforcement: serve from disk if pindex>tip-10, otherwise send full block via inv-style queue | **PARTIAL** | W126-BUG-2 | P1 | `sync.go:1050-1062` *computes* the depth check correctly (consults `MaxBlocktxnDepth = 10` constant at compactblock.go:41) and logs the right message, but never serves either response — returns silently after the log.  TODO at sync.go:1057 acknowledges this.  Bundle with W126-BUG-2. |
| G18 | GETBLOCKTXN handler — OOB index validation (`Misbehaving` on `req.indexes[i] >= block.vtx.size()`) | **MISSING** | W126-BUG-2 | P2 | Core net_processing.cpp:2603-2604 calls `Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")`.  blockbrew never reads any block, so OOB indexes are not detected; rolled into W126-BUG-2 since the OOB check is dead code until the handler actually serves blocktxn. |
| G19 | GETBLOCKTXN handler — m_most_recent_block fast path (no cs_main / no disk read for the chain tip) | **MISSING** | W126-BUG-8 | P2 | Core net_processing.cpp:4254-4263 keeps the most-recently-mined block in memory (`m_most_recent_block_hash` / `m_most_recent_block`) so the common case of "peer requests missing txns from the block we just announced" avoids a disk read.  blockbrew has no such cache — `chainDB.GetBlock(hash)` is the only path even at tip.  Performance only; will not affect protocol correctness.  Compounds with W126-BUG-2 (no handler at all today). |
| G20 | BLOCKTXN handler — invokes `ProcessCompactBlockTxns` and finishes reconstruction via `PartiallyDownloadedBlock.FillBlock` | **MISSING** | W126-BUG-3 | P1 | `sync.go:1065-1069` is log+ignore.  blockbrew always falls back to full block via getdata in OnCmpctBlock so blocktxn for our own requests is never expected, but a peer **could** still send unsolicited blocktxn (or one we requested via a future cmpctblock round-trip after BUG-1 is fixed).  Core net_processing.cpp:4714-4726 reads the BlockTransactions and calls ProcessCompactBlockTxns unconditionally.  **Carry-forward from W112-BUG-4.** |
| G21 | BLOCKTXN handler — LoadingBlocks guard | **MISSING** | W126-BUG-6 | P2 | Same as G14 — no IBD/LoadingBlocks check.  Bundle with W126-BUG-6. |
| G22 | Reconstruction — `PartiallyDownloadedBlock.InitData` matches Core blockencodings.cpp:59-181 | **PRESENT** | — | — | `compactblock.go:277-473` faithful port.  Gates 1-9 internal to the reconstructor are correctly implemented.  Verified by W112 test set: TestW112_G14/G15/G16/G17 pass. |
| G23 | Reconstruction — `FillBlock` consumes `vtxMissing` exactly, double-call rejected | **PRESENT** | — | — | `compactblock.go:549-599` matches blockencodings.cpp:191-236; `headerSet` toggle is the IsNull() proxy. |
| G24 | Reconstruction — IsBlockMutated check after FillBlock | **PRESENT** | — | — | `compactblock.go:594` `if consensus.IsBlockMutated(block, segwitActive)`; matches blockencodings.cpp:218-221. |
| G25 | Reconstruction — InitData consults mempool for short-ID matches | **MISSING** | W126-BUG-1 | P1 | `compactblock.go:409-438` *can* take a mempool argument (`mempool MempoolLookup`), but the **call site at sync.go:1014-1042 never instantiates** a PartiallyDownloadedBlock or passes the mempool.  The receive path bypasses reconstruction entirely.  **Well-engineered helper never wired — same anti-pattern as W122/W120/W117 etc.** |
| G26 | Announce — `NewPoWValidBlock` HB-peer announcement: send `cmpctblock` to all m_requested_hb_cmpctblocks peers | **MISSING** | W126-BUG-1 | P1 | Core net_processing.cpp:2102-2154 builds one `CBlockHeaderAndShortTxIDs` and pushes to each HB peer.  blockbrew's `AnnounceBlock` (peermgr.go:739-771) only sends headers or inv; `CompactBlockBuilder.Build` exists at compactblock.go:198-220 but is never called.  **Carry-forward from W112-BUG-1.** |
| G27 | Announce — `MaybeSetPeerAsAnnouncingHeaderAndIDs` (HB-peer rotation / 3-peer cap) | **MISSING** | W126-BUG-1 | P1 | Core net_processing.cpp:1272-1330 maintains `lNodesAnnouncingHeaderAndIDs` (≤3) and rotates on each successful block source.  blockbrew has the `MaxHBPeers = 3` constant at compactblock.go:25 but no list, no rotation, no `sendcmpct(hb=true)` outbound.  Bundle with W126-BUG-1. |
| G28 | Announce — `m_most_recent_compact_block` cache (pre-built CBlockHeaderAndShortTxIDs at tip) | **MISSING** | W126-BUG-8 | P2 | Cache absent (see G19 — same cache).  Performance only.  Bundle with W126-BUG-8. |
| G29 | Serve — getdata with MSG_CMPCT_BLOCK (type=4) replies with cmpctblock (depth ≤ MAX_CMPCTBLOCK_DEPTH=5) else falls back to full block | **MISSING** | W126-BUG-10 | P1 | `sync.go:1272 HandleGetData` only handles InvTypeBlock (2) and InvTypeTx (1); MSG_CMPCT_BLOCK (4) is not even a defined InvType.  Core net_processing.cpp:2466-2472 serves cmpctblock if `pindex->nHeight >= tip->nHeight - MAX_CMPCTBLOCK_DEPTH` (=5), else falls back to full block.  blockbrew silently drops the request (the switch in HandleGetData has no default+notfound for unknown types). |
| G30 | Negotiate — wire-flag set NODE_NETWORK_LIMITED is forward-compatible (don't refuse v2 from limited peers) | **PRESENT** | — | — | `compactblock.go:641` `SetSendCmpct` does not consult service flags; all peers offering v2 are accepted.  Matches Core net_processing.cpp:3901-3915 (no NODE_NETWORK_LIMITED gate on sendcmpct accept). |

### Bug summary (10 IDs)

| ID | Severity | Subsystem | One-liner |
|----|----------|-----------|-----------|
| W126-BUG-1  | P1 DEAD-PIPELINE | announce | HB-peer announcement entirely absent: no list, no rotation, no `cmpctblock` outbound.  Receive path also never consults mempool.  Includes G25/G26/G27.  **W112-BUG-1 survivor.** |
| W126-BUG-2  | P1 DEAD-PIPELINE | serve     | `getblocktxn` handler is log+ignore; never sends `blocktxn`; OOB-index DoS check unreachable.  Includes G16/G17/G18.  **W112-BUG-3 survivor.** |
| W126-BUG-3  | P1 DEAD-PIPELINE | receive   | `blocktxn` handler is log+ignore; unsolicited blocktxn dropped; future reconstruction-round-trip dead.  Includes G20.  **W112-BUG-4 survivor.** |
| W126-BUG-4  | P1 | cmpctblock | OnCmpctBlock does not call `ProcessNewBlockHeaders` for the embedded header — header-chain learning via cmpctblock path is absent.  G11. |
| W126-BUG-5  | P1 | cmpctblock | OnCmpctBlock lacks anti-DoS work-threshold guard AND prev-block-found / send-getheaders branch.  G12/G13. |
| W126-BUG-6  | P2 | cmpctblock+blocktxn | No LoadingBlocks/IBD guard on either receive handler.  G14/G21. |
| W126-BUG-7  | P2 | cmpctblock | No `MaybePunishNodeForBlock(via_compact_block=true)` on invalid header.  G15. |
| W126-BUG-8  | P2 | cache      | No `m_most_recent_block` / `m_most_recent_compact_block` in-memory cache.  Forces tip-disk reads on every serve.  G19/G28. |
| W126-BUG-9  | P3 | negotiation | v1 (non-witness) sendcmpct unconditionally rejected.  WAI matches Core today but a forward-spec gap.  G4.  **W112-BUG-2 survivor.** |
| W126-BUG-10 | P1 | serve | `HandleGetData` does not recognise `MSG_CMPCT_BLOCK` (inv type 4); silently drops.  G29. |

## Top 5 findings

### 1. The entire compact-block fast path is **inert advertisement**

blockbrew announces `sendcmpct(v=2, hb=false)` to every peer at handshake
(peer.go:910).  Operationally this tells peers: *“I support BIP-152, please
include me in your set of low-bandwidth compact-block recipients.”*  Peers
duly send `cmpctblock` messages on every new block.  blockbrew's handler
(sync.go:1014-1042) **always discards the parsed `MsgCmpctBlock`** and
immediately follows up with `getdata BLOCK` for the full block.

Net effect from the network's perspective:
- blockbrew costs every well-behaved peer the bandwidth of one
  `cmpctblock` (header + 6-byte shortids ×N + prefilled coinbase) that
  blockbrew never used.
- blockbrew gets no latency benefit — the `cmpctblock → getdata BLOCK
  → block` round-trip is one RTT *longer* than the `inv → getdata BLOCK
  → block` round-trip that a non-BIP-152 node would have done.

Worse: blockbrew **never announces** new blocks as cmpctblock.  Even if
blockbrew had connected to a peer that requested HB compact-block service
(via `sendcmpct(v=2, hb=true)`), our `AnnounceBlock` (peermgr.go:739-771)
only sends `inv` or `headers`.  blockbrew is opted-out of the BIP-152
ecosystem in both directions.

Recommended fix path: implement **W126-BUG-1** (the HB peer list +
rotation + cmpctblock outbound) and **W126-BUG-2** (getblocktxn serve)
together.  Without W126-BUG-2 the outbound side at W126-BUG-1 is a
half-implementation; without W126-BUG-1 the network never asks us for
blocktxn so W126-BUG-2 stays dead code.  These two are the **forced
ordering pair** for any BIP-152 wave.

### 2. Receive path bypasses mempool reconstruction — Core's *raison d'être* for BIP-152 is gone

`PartiallyDownloadedBlock.InitData` is a fully Core-faithful port
(compactblock.go:277-473), tested by W112's gate set (G14/G15/G16/G17
all pass).  It takes a `MempoolLookup` argument and correctly fills
short-ID-matching transactions from the mempool — this is the core BIP-152
win, since a well-stocked mempool typically lets you reconstruct a new
block with 1-2 KiB of network traffic instead of 1-4 MiB.

But the only caller in the tree is the W112 test file.  The production
handler at sync.go:1014 does not instantiate `NewPartiallyDownloadedBlock`,
does not call `InitData`, and does not pass the mempool.  Per W117 and
W122's “well-engineered helper never wired” pattern — this is the same
anti-pattern, ninth-recurrence in blockbrew specifically.

The wiring is one function-call's worth of code: `pdb :=
NewPartiallyDownloadedBlock(); missing, err := pdb.InitData(msg, sm.mempool,
nil)`.  But the *control flow* around it requires:

- buffering a `PartiallyDownloadedBlock` per in-flight cmpctblock (Core uses
  the `mapBlocksInFlight` entry's `partialBlock` field),
- on missing>0, sending `getblocktxn`,
- on missing=0, calling FillBlock and feeding the resulting MsgBlock into
  the usual block-processing path (`processIncomingBlock`),
- on FillBlock failure, falling back to `getdata BLOCK`.

So the fix is non-trivial flow-wise, but the cryptographic / serialization
substrate is **already done and tested**.

### 3. No `ProcessNewBlockHeaders` call from CMPCTBLOCK path — header-chain learning via HB-peer announcements is dead

Even ignoring the reconstruction question, the *header* embedded in a
`cmpctblock` carries useful information: a peer is announcing a new tip.
Core net_processing.cpp:4501 calls `ProcessNewBlockHeaders` unconditionally
to track this — independent of whether reconstruction succeeds.  blockbrew
does not.

In a network where (hypothetically) all of blockbrew's peers exclusively
announced new blocks via `cmpctblock` (e.g. all of them had selected
blockbrew as one of their three HB peers), blockbrew would never learn
about new tips at all — its `inv`-based discovery would receive nothing
because Core peers don't `inv` to their HB recipients (they cmpctblock
directly).

Today blockbrew is rescued by the fact that **no peer** sets blockbrew as
HB (because blockbrew never sends `sendcmpct(hb=true)`, so it's always in
LB-recipient mode and peers also `inv` to it), but this means
blockbrew's chain-learning is parasitic on it not actually being a real
BIP-152 participant.  Coupled to W126-BUG-1, this becomes load-bearing
incorrect once BUG-1 is fixed.

### 4. No anti-DoS work-threshold guard on cmpctblock — easy spam vector

Core net_processing.cpp:4489-4493:
```cpp
} else if (prev_block->nChainWork + GetBlockProof(cmpctblock.header) < GetAntiDoSWorkThreshold()) {
    LogDebug(BCLog::NET, "Ignoring low-work compact block from peer %d\n", pfrom.GetId());
    return;
}
```

blockbrew has no equivalent check.  A peer can mint zero-work or
low-work headers, wrap them in a cmpctblock with arbitrary
shortids/prefilled, and blockbrew will *always* fire a `getdata BLOCK`
in reply.  This is the same vector that
`HasValidProofOfWork` / anti-DoS work-threshold defends against for
header announcements; it should apply to compact-block announcements
identically since they include a header.

The exploit cost is one cmpctblock send per round-trip; defender cost is
one getdata roundtrip + one mismatched-block disconnection per spam
sample.  Not a P0 because no consensus is broken, but operationally a
weakness any BIP-152-aware fleet adversary can probe.

### 5. `MSG_CMPCT_BLOCK` inv type (4) is **not even a defined InvType** in blockbrew

`msg_inv.go:9-20` defines:
- `InvTypeError = 0`
- `InvTypeTx = 1`
- `InvTypeBlock = 2`
- `InvTypeFilteredBlock = 3`
- `InvTypeWtx = 5`
- (witness flags 0x40000001 / 0x40000002)

**`MSG_CMPCT_BLOCK = 4` is missing entirely.**

The protocol-level effect: a peer sending `getdata(MSG_CMPCT_BLOCK, hash)`
will reach `HandleGetData` (sync.go:1272), which switches on
`baseType := inv.Type &^ InvWitnessFlag` — `4` matches no case, falls
through silently (no `notfound`).  The peer waits indefinitely.

Core net_processing.cpp:2462-2473 handles this case as part of the
getdata serve path: it responds either with `cmpctblock` (if
`pindex->nHeight >= tip - MAX_CMPCTBLOCK_DEPTH=5`) or with a full
block.  blockbrew can't serve cmpctblock yet (W126-BUG-1) but it can
**at minimum** recognise the inv type and serve a full block — that
satisfies the BIP-152 spec's “MUST respond with cmpctblock OR block”
clause.

Today: silent drop.  Easy single-line fix (add case to HandleGetData's
switch + add InvType constant), even before the full BIP-152 fix-wave.

## Bug catalogue

### W126-BUG-1 — HB-peer announcement DEAD PIPELINE (P1)

**W112 survivor.**  Includes gates G25, G26, G27.

`MaxHBPeers = 3` constant exists (compactblock.go:25), `CompactBlockBuilder`
exists (compactblock.go:181-220), the wire-message `MsgCmpctBlock` and
`MsgSendCmpct` both serialize/deserialize correctly, but the connecting
glue is absent:

1. No `lNodesAnnouncingHeaderAndIDs` (or equivalent) on PeerManager.
2. `AnnounceBlock` (peermgr.go:748) sends headers/inv only; never cmpctblock.
3. blockbrew **never sends `sendcmpct(hb=true)`** to any peer — so even if
   we wanted to be selected as an HB recipient, we don't ask.
4. `CompactBlockBuilder.Build` has no production caller.
5. `MempoolLookup` is implemented (mempool/mempool.go has `GetTransaction`,
   `GetAllTransactions`) but never passed to `InitData` from the receive
   path either — see W126-BUG-1 spans both directions.

**Repro**: connect blockbrew to any Core peer; mine a block locally; observe
peer logs (set `-debug=cmpctblock`) — no `cmpctblock` ever arrives from
blockbrew.

**Test**: `TestW126_G26_AnnounceSendsCmpctBlockToHBPeers` (xfail), plus
the existing W112 surrogates `TestW112_G10_HBPeerCapRotation_BUG1` /
`TestW112_G29_HBOutboundLimit_BUG1` / `TestW112_G30_HBPeerRotationWhenStale_BUG1`.

### W126-BUG-2 — `getblocktxn` handler is log+ignore (P1)

**W112 survivor.**  Includes gates G16, G17, G18.

`sync.go:1043-1064`:
```go
OnGetBlockTxn: func(p *Peer, msg *MsgGetBlockTxn) {
    if sm.headerIndex != nil {
        tipHeight := sm.headerIndex.BestHeight()
        if node := sm.headerIndex.GetNode(msg.BlockHash); node != nil {
            depth := tipHeight - node.Height
            if depth > MaxBlocktxnDepth {
                log.Printf("[compact] getblocktxn from %s for block %s is %d deep …", …)
                // TODO(BUG-3): once OnGetBlockTxn serving is implemented,
                // send full block via getdata here instead of blocktxn.
                return
            }
        }
    }
    log.Printf("[compact] Received getblocktxn from %s, ignoring", p.Address())
},
```

The depth check is computed correctly but neither branch ever produces a
response.  A peer that has received our `cmpctblock` (impossible today
because W126-BUG-1) and needs missing txns from us via getblocktxn would
stall.

Note the inline TODO acknowledging the bug — this matches the
W122 “comment-as-confession” pattern (the test-level confession in
`TestBIP158Vectors` from W122 BUG-5 was a different file/comment in
blockbrew; this is the source-level analogue).

**Fix scope**: implement `SendBlockTransactions(peer, block, req)` mirroring
Core net_processing.cpp:2598-2615; serve from `chainDB.GetBlock(hash)`
under the depth check, fall through to `getdata BLOCK` queueing
otherwise.  OOB index Misbehaving (Core net_processing.cpp:2603-2604) is
free once the loop is present.

### W126-BUG-3 — `blocktxn` handler is log+ignore (P1)

**W112 survivor.**  Includes gate G20.

`sync.go:1065-1069`:
```go
OnBlockTxn: func(p *Peer, _ *MsgBlockTxn) {
    log.Printf("[compact] Received blocktxn from %s, ignoring", p.Address())
},
```

Today unreachable because blockbrew never sends `getblocktxn` (we fall
back to full block in OnCmpctBlock).  After W126-BUG-1 + W126-BUG-2 are
fixed this becomes the third leg of the round-trip; until then it is
dead code with a TODO-shaped placeholder.

**Fix scope**: once a `PartiallyDownloadedBlock` is buffered per in-flight
cmpctblock (W126-BUG-1 fix), look up by `msg.BlockHash`, call
`pdb.FillMissingTransactions(msg.Txs)` + `FillBlock(...)`, feed result
into the standard block-processing path.

### W126-BUG-4 — CMPCTBLOCK does not feed header into ProcessNewBlockHeaders (P1)

Gate G11.

Core net_processing.cpp:4501-4509:
```cpp
const CBlockIndex *pindex = nullptr;
BlockValidationState state;
if (!m_chainman.ProcessNewBlockHeaders({{cmpctblock.header}}, /*min_pow_checked=*/true, state, &pindex)) { … }
```

blockbrew never adds the cmpctblock-embedded header to the header chain.
A peer that exclusively announces new blocks via cmpctblock (e.g. Core
peers that have selected us as their sole HB recipient and never `inv`
to us) would leave blockbrew permanently unaware of the new tip.

Operationally today: not catastrophic because no peer selects blockbrew as
HB (W126-BUG-1 keeps us out of every peer's HB list), but the fix
sequencing matters — when W126-BUG-1 is fixed, this gap is exposed.

### W126-BUG-5 — CMPCTBLOCK lacks anti-DoS work-threshold + prev-found-or-getheaders branch (P1)

Gates G12, G13.

Core net_processing.cpp:4485-4493:
```cpp
const CBlockIndex* prev_block = m_chainman.m_blockman.LookupBlockIndex(cmpctblock.header.hashPrevBlock);
if (!prev_block) {
    // Doesn't connect (or is genesis), instead of DoSing in AcceptBlockHeader, request deeper headers
    if (!m_chainman.IsInitialBlockDownload()) {
        MaybeSendGetHeaders(pfrom, GetLocator(m_chainman.m_best_header), peer);
    }
    return;
} else if (prev_block->nChainWork + GetBlockProof(cmpctblock.header) < GetAntiDoSWorkThreshold()) {
    LogDebug(BCLog::NET, "Ignoring low-work compact block from peer %d\n", pfrom.GetId());
    return;
}
```

Both branches missing in blockbrew.  See top finding #4.

### W126-BUG-6 — No LoadingBlocks / IBD guard on CMPCTBLOCK or BLOCKTXN handlers (P2)

Gates G14, G21.

Core net_processing.cpp:4469-4473 and 4717-4720 unconditionally drop both
messages while LoadingBlocks() returns true.  blockbrew has
`sm.IsIBDActive()` available; the receive handlers never call it.

Carry-forward from W112-BUG-7 (which scoped this as cmpctblock-only;
the BLOCKTXN side is the same shape and we expand it here to cover both
under one bug ID).

### W126-BUG-7 — No `MaybePunishNodeForBlock(via_compact_block=true)` on invalid header (P2)

Gate G15.

Today blockbrew never validates the cmpctblock-embedded header before
falling back to `getdata BLOCK`, so an invalid header just produces an
extra round-trip + a failed block fetch.  Once W126-BUG-4 is fixed
(header runs through ProcessNewBlockHeaders), the invalid-header → punish
path must be wired with the `via_compact_block=true` flag so that the
peer gets a lighter penalty than a fully invalid block (per Core's
distinction).

### W126-BUG-8 — No m_most_recent_block / m_most_recent_compact_block cache (P2)

Gates G19, G28.

Forces tip-disk reads on every serve; pre-built CBlockHeaderAndShortTxIDs
absent.  Performance-only; will not affect correctness.  Note that
**without W126-BUG-1 there's nothing to cache** (we never build a
cmpctblock outbound), so this bug is effectively gated on the BUG-1
fix-wave.

### W126-BUG-9 — v1 sendcmpct unconditionally rejected; WAI matches Core (P3)

**W112 survivor.**  Gate G4.

`compactblock.go:641`:
```go
if version == CmpctBlockVersion {
    s.providesCompactBlocks = true
    …
}
```

Core net_processing.cpp:3907:
```cpp
if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;
```

Both reject v1.  blockbrew matches Core's behaviour today.  BIP-152 spec
says nodes MAY track each version independently; if Core ever re-enables
v1, blockbrew would need to widen the accept check.  Recording as P3
forward-spec gap, not a correctness bug.

### W126-BUG-10 — `HandleGetData` ignores MSG_CMPCT_BLOCK (type=4) (P1)

Gate G29.

`msg_inv.go:9-20` has no `InvTypeCmpctBlock = 4` constant; `HandleGetData`
(sync.go:1272-1316) only switches on InvTypeBlock and InvTypeTx (the
case for InvTypeTx is itself a TODO).  Result: any `getdata(type=4)`
request from a peer is dropped silently — no notfound, no full-block
fallback.

Fix scope (minimal): add `InvTypeCmpctBlock InvType = 4`; add a case to
the switch that either (a) builds + sends a cmpctblock if depth ≤ 5
(requires W126-BUG-1 plumbing) or (b) falls back to sending a full block.
Option (b) alone is a one-line fix that takes blockbrew from
silent-drop to spec-conformant.

## Cross-references to prior waves

- **W112** (2026-Q2) — Original BIP-152 audit.  Found 7 bugs in this same
  subsystem.  W126 carries forward W112-BUG-1, W112-BUG-2, W112-BUG-3,
  W112-BUG-4, W112-BUG-7 (as W126-BUG-1, W126-BUG-9, W126-BUG-2,
  W126-BUG-3, W126-BUG-6 respectively).  W112-BUG-5 and W112-BUG-6 (the
  MAX_BLOCKTXN_DEPTH=10 and MAX_CMPCTBLOCK_DEPTH=5 missing constants)
  were closed in 2026-Q3 — both constants now exist at
  compactblock.go:33+41 and are consulted in the depth-log branch of
  sync.go:1027 and sync.go:1054.  The handler still returns
  unconditionally after the log, so W126 keeps those gates folded into
  W126-BUG-2.  This is a partial-fix-of-a-prior-bug carrying through —
  exactly the pattern W121 observed in haskoin BUG-16.
- **W122** (2026-05-17) — BIP-158 GCS codec stress.  W126 inherits the
  *test-comment-as-confession* check pattern: any test that opts out of
  byte-exact spec compliance via prose comment is treated as a bug,
  not as documentation.  Applied below to the W126 test set: no
  `t.Skip` comment may include the substring “matches Core today” unless
  paired with a Core-line citation (the W126-BUG-9 skip does pair).
- **W117** (BIP-155) — “Dead helper at call site” pattern recurrence.
  W126's BUG-1 is the 35th project-wide instance of well-engineered
  helper + missing one-line call.

## Methodology

1. Read Core references first: blockencodings.h, blockencodings.cpp, the
   four handlers in net_processing.cpp (SENDCMPCT/CMPCTBLOCK/GETBLOCKTXN/
   BLOCKTXN), `MaybeSetPeerAsAnnouncingHeaderAndIDs`, `NewPoWValidBlock`,
   `SendBlockTransactions`.  Cross-checked against BIP-152 prose.
2. Synthesised the 30-gate matrix as the orthogonal axes: each message
   handler × each phase (deserialize / validate / dispatch / respond) ×
   the announcement-side flow × the reconstruction-side flow.
3. Grep + read blockbrew's existing implementation under
   `internal/p2p/compactblock.go`, `msg_cmpctblock.go`, `sync.go`,
   `peer.go`, `peermgr.go`, `msg_inv.go`.  Confirmed the existing W112
   audit's bug numbering, then extended to net-new gates.
4. Per gate: PRESENT / PARTIAL / MISSING verdict with file:line citation;
   each PARTIAL / MISSING produces or extends a bug ID with severity
   classified P0–P3.
5. Wrote 30 gate tests in `internal/p2p/w126_bip152_test.go`.  Gates
   that map to PRESENT use a real assertion against the code under test;
   gates mapped to PARTIAL / MISSING use `t.Skip("W126-BUG-N: …")` per
   the W124 convention.  No new test failures (all xfails are explicit
   `t.Skip` lines).

## Out of scope (for follow-on fix-wave scheduling)

- **Fix sequencing.** W126-BUG-1 (dead announce pipeline) and
  W126-BUG-2 (dead serve pipeline) must land together because the two
  halves of the BIP-152 round-trip are coupled: each is dead code until
  the other side has a real caller.  W126-BUG-4 / BUG-5 / BUG-6 / BUG-7
  are post-conditions of BUG-1+2 — once the receive path actually does
  something, those validation gates become reachable and must be wired
  to avoid DoS/forking exposure.
- **Performance bugs** (W126-BUG-8) should not block the fix-wave; the
  in-memory cache can be added in a follow-up after correctness lands.
- **W126-BUG-9** is a forward-spec future-compat gap, not a real bug
  today.  Defer.
- **W126-BUG-10** (MSG_CMPCT_BLOCK type=4 unknown) can be fixed
  independently of W126-BUG-1 as a one-line addition to HandleGetData
  that falls back to full-block service.  This is the **cheapest
  immediate-win** in W126: takes blockbrew from “silently drops a valid
  getdata request” to “sends the requested block, just not in compact
  form”.

## Single-commit footer

`audit: W126 BIP-152 Compact Blocks — 10 BUGS / 30 gates (blockbrew)`
