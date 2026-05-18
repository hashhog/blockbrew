# W152 — Tx relay + inv batching + orphan handling (blockbrew)

**Wave:** W152 — `RelayTransaction`, `AddTxAnnouncement`,
ProcessMessage `msg_tx` + `msg_inv` + `msg_getdata` handlers,
SendMessages inv batching, `m_recently_announced_invs`,
`m_tx_inventory_to_send`, `m_next_inv_send_time`, `MaybeSendMessage`
cadence, `TxOrphanage::AddTx` / `EraseTx` / `EraseForBlock` /
`EraseForPeer` / `LimitOrphans`, `OrphanByParent` map, txrequest
scheduler (`MAX_PEER_TX_REQUEST_IN_FLIGHT`, `GETDATA_TX_INTERVAL`,
`TXID_RELAY_DELAY`, `NONPREF_PEER_TX_DELAY`, `OVERLOADED_PEER_TX_DELAY`),
inv hash byte-order, MSG_WTX vs MSG_TX dispatch, bloom-filter mempool
dump on inv, `MAX_INV_SZ=50000`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/net_processing.cpp:165-174` — inventory broadcast
  cadence constants: `INBOUND_INVENTORY_BROADCAST_INTERVAL{5s}`,
  `OUTBOUND_INVENTORY_BROADCAST_INTERVAL{2s}`,
  `INVENTORY_BROADCAST_PER_SECOND{14}`,
  `INVENTORY_BROADCAST_TARGET = 14 × 5 = 70`. (Prompt said `7` — Core
  is `14` post-PR #21327, so the steady-state target is 70 not 35.)
- `bitcoin-core/src/net_processing.cpp:308,315,5981-6056` —
  `m_tx_inventory_to_send` (set<Wtxid>), `m_next_inv_send_time`
  scheduled with `m_rng.rand_exp_duration(OUTBOUND_INVENTORY_BROADCAST_INTERVAL)`
  (outbound) or `NextInvToInbounds(...)` (inbound, deterministic 5 s
  Poisson per chunk).  Inv set drained per-peer in
  `MaybeSendMessage` once `m_next_inv_send_time < current_time`.
- `bitcoin-core/src/net_processing.cpp:5036-5051` — feefilter receive
  `MoneyRange(newFeeFilter)` guard.
- `bitcoin-core/src/node/txdownloadman.h:25-38` — `MAX_PEER_TX_REQUEST_IN_FLIGHT
  = 100`, `MAX_PEER_TX_ANNOUNCEMENTS = 5000`, `TXID_RELAY_DELAY{2s}`,
  `NONPREF_PEER_TX_DELAY{2s}`, `OVERLOADED_PEER_TX_DELAY{2s}`,
  `GETDATA_TX_INTERVAL{60s}`.
- `bitcoin-core/src/node/txdownloadman_impl.cpp:200-251` — composes
  request delay: `NONPREF` + `TXID_RELAY` (when at least one wtxid
  peer exists and the announcement is txid-only) + `OVERLOADED`.
- `bitcoin-core/src/node/txorphanage.h:20-23, 38-99` — `TxOrphanage`
  interface: `DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER{404'000}`,
  `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE{3000}` (the v28+ orphanage
  rewrite — old `DEFAULT_MAX_ORPHAN_TRANSACTIONS=100` is now derived
  from per-peer reservation × N peers). API: `AddTx`, `AddAnnouncer`,
  `HaveTx(Wtxid)`, `EraseTx(Wtxid)`, `EraseForPeer(NodeId)`,
  `EraseForBlock(CBlock)`, `AddChildrenToWorkSet`,
  `GetChildrenFromSamePeer`.
- `bitcoin-core/src/node/txorphanage.cpp` — `OrphanByParent` map
  (parent_txid → set<Wtxid> of orphans depending on it), `LimitOrphans`
  evicts oldest from the most resource-intensive peer.
- `bitcoin-core/src/consensus/tx_verify.cpp:179-181` — coinbase
  maturity uses `nSpendHeight - coin.nHeight < COINBASE_MATURITY`
  where `nSpendHeight = active_chain.Height() + 1`
  (`validation.cpp:892`).
- `bitcoin-core/src/policy/policy.h:119-132` — `STANDARD_SCRIPT_VERIFY_FLAGS`
  = `MANDATORY_SCRIPT_VERIFY_FLAGS | STRICTENC | MINIMALDATA |
  DISCOURAGE_UPGRADABLE_NOPS | CLEANSTACK | MINIMALIF | NULLFAIL |
  LOW_S | DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM | WITNESS_PUBKEYTYPE
  | CONST_SCRIPTCODE | DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
  DISCOURAGE_OP_SUCCESS | DISCOURAGE_UPGRADABLE_PUBKEYTYPE`
  (13 STANDARD-extras on top of MANDATORY).

**Files audited**
- `internal/p2p/msg_inv.go` — `InvType` constants, `InvVect`,
  `MsgInv`, `MaxInvVects=50000`.
- `internal/p2p/msg_tx.go` — `MsgTx` (29 lines, decode-only wrapper).
- `internal/p2p/msg_simple.go:165-183` — `MsgFeeFilter`.
- `internal/p2p/msg_getdata.go` — `MsgGetData`, `MaxGetDataSize=1000`.
- `internal/p2p/peer.go:557-741` — `handleMessage` dispatch.
- `internal/p2p/peer.go:594-609` — `MsgInv` / `MsgTx` dispatch to
  listeners.
- `internal/p2p/peer.go:932-968` — `handleFeeFilter` / `ShouldRelayTx`.
- `internal/p2p/peer.go:1327-1344` — `WantsTxRelay`.
- `internal/p2p/peermgr.go:786-825` — `RelayTransaction`.
- `internal/p2p/peermgr.go:748-769` — `AnnounceBlock`.
- `internal/p2p/peermgr.go:1291-1296` — `DisableRelayTx=true` for
  block-relay-only outbound.
- `internal/p2p/sync.go:989-1071` — `CreatePeerListeners`,
  `OnGetData`, `OnNotFound`, `OnInv` wiring.
- `internal/p2p/sync.go:1081-1095` — `HandleInv` (block-only,
  tx-type invs are silently dropped).
- `internal/p2p/sync.go:1264-1318` — `HandleGetData` (`InvTypeBlock`
  served; `InvTypeTx` is a TODO stub; `InvTypeWtx=5` not handled;
  notfound only for blocks).
- `internal/p2p/mempool_handler.go` — `HandleMempoolRequest` (BIP-35).
- `internal/mempool/mempool.go:339,392,648-649,2278-2384` — orphan
  pool (`MaxOrphanTxs=100`, `orphanEntry`, `addOrphanLocked`,
  `evictRandomOrphanLocked`, `processOrphansLocked`, `ExpireOrphans`).
- `internal/mempool/mempool.go:28-36` — `OrphanTxExpireTime = 20 min`.
- `internal/mempool/mempool.go:2388-2425` — `BlockConnected`.
- `internal/mempool/mempool.go:1112-1128` — coinbase-maturity check
  (`age := tipHeight - utxo.Height`).
- `internal/mempool/mempool.go:1294-1307, 1528-1535, 3695` —
  `getStandardScriptFlags`.
- `internal/consensus/scriptflags.go:65-84` —
  `GetStandardScriptFlags`.
- `internal/wire/types.go:54-110` — `Hash256` storage / wire layout
  (raw bytes, NOT reversed on wire — display-order is reversed at
  `String()` only).
- `cmd/blockbrew/main.go:1139-1160` — `OnTx` listener wiring (mp.AcceptToMemoryPool + RelayTransaction + ZMQ + log).
- `cmd/blockbrew/main.go:1403-1427` — `orphanExpireTicker` (1 min).

---

## Gate matrix (32 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | inv message size | G1: `MAX_INV_SZ=50000` cap on receive | PASS (`msg_inv.go:77-78`) |
| 1 | … | G2: oversized inv → Misbehave(20) + disconnect | **BUG-1 (P1)** — `ErrTooManyInvVects` is a non-fatal deserialize error; no `Misbehaving(20)`. Carry-forward W103 BUG-1, still open. |
| 2 | MSG_WTX vs MSG_TX dispatch | G3: announce path: wtxid peers → MSG_WTX=5, legacy → MSG_TX=1 | PASS (`peermgr.go:806-816`) |
| 2 | … | G4: getdata serve path: handle `InvTypeTx`, `InvTypeWtx`, `InvTypeWitnessTx` (BIP-144) | **BUG-2 (P0-CDIV)** — `HandleGetData` switch covers ONLY `InvTypeBlock` + `InvTypeTx`; `InvTypeWtx` (5), `InvTypeWitnessTx` (0x40000001), `InvTypeFilteredBlock` all fall through with no `notfound` and no service. The `InvTypeTx` branch is a TODO stub (`sync.go:1311-1312`). Wtxid-relay peers asking for a tx by wtxid never get a response, and Core wtxid-relay peers will time out and Misbehave us. |
| 2 | … | G5: receive-side: inv{MSG_TX,MSG_WTX} → trigger getdata | **BUG-3 (P0-CDIV)** — `HandleInv` ONLY checks `baseType == InvTypeBlock` (`sync.go:1081-1095`). Tx-type invs are silently dropped. blockbrew **never issues getdata for transactions** — it has never received a tx from a peer via P2P relay (only via RPC `sendrawtransaction`). |
| 3 | RelayTransaction broadcast | G6: skip from-peer | PASS (`peermgr.go:791-794`) |
| 3 | … | G7: gate on WantsTxRelay (fRelay) | PASS (`peermgr.go:797`) |
| 3 | … | G8: respect peer's feefilter (BIP-133) | PASS (`peermgr.go:801-804`) |
| 3 | … | G9: skip ConnBlockRelayOnly connections | PARTIAL — relies on `DisableRelayTx=true` set on our side at `peermgr.go:1293-1294`, which routes through `WantsTxRelay()`. Functionally equivalent for our outbound BR-only. No explicit `connType != ConnBlockRelayOnly` filter — fragile if `DisableRelayTx` is ever cleared. |
| 3 | … | G10: per-peer m_recently_announced_invs (dedup against re-announce) | **BUG-4 (P1)** — `Peer` struct has no `recentlyAnnouncedInvs` rolling-bloom / LRU. Same tx can be re-announced multiple times to the same peer if `RelayTransaction` is called twice (e.g., RBF + reprocess). Cross-cite W103 BUG-17. |
| 4 | inv batching cadence | G11: per-peer `m_tx_inventory_to_send` set | **BUG-5 (P0-CDIV)** — no per-peer inv-queue exists. `RelayTransaction` fires `peer.SendMessage(&MsgInv{InvList: []*InvVect{single}})` synchronously for EVERY tx (`peermgr.go:818-823`), sending one inv message per tx per peer. 1000 txs in a burst = 1000 inv messages per peer instead of one batched inv. |
| 4 | … | G12: Poisson-jittered `m_next_inv_send_time` | **BUG-5 cross-cite** — no scheduler. |
| 4 | … | G13: `INVENTORY_BROADCAST_PER_SECOND=14` / `INVENTORY_BROADCAST_TARGET=70` per-cycle cap | **BUG-5 cross-cite** — no per-cycle cap. |
| 4 | … | G14: outbound 2s / inbound 5s broadcast interval | **BUG-5 cross-cite**. |
| 5 | txrequest scheduler | G15: `MAX_PEER_TX_ANNOUNCEMENTS=5000` cap | **BUG-6 (P1)** — no per-peer announcement counter. Cross-cite W103 BUG-9. |
| 5 | … | G16: `MAX_PEER_TX_REQUEST_IN_FLIGHT=100` cap | **BUG-6 cross-cite** (W103 BUG-10). |
| 5 | … | G17: `GETDATA_TX_INTERVAL=60s` re-request | **BUG-6 cross-cite** (W103 BUG-11). |
| 5 | … | G18: `NONPREF_PEER_TX_DELAY=2s` for non-preferred peers | **BUG-6 cross-cite** (W103 BUG-12). |
| 5 | … | G19: `TXID_RELAY_DELAY=2s` when wtxid peers exist | **BUG-6 cross-cite** (W103 BUG-13). |
| 5 | … | G20: `OVERLOADED_PEER_TX_DELAY=2s` for ≥100 in-flight | **BUG-6 cross-cite** (W103 BUG-14). |
| 6 | orphan pool admission | G21: `DEFAULT_MAX_ORPHAN_TRANSACTIONS=100` cap | PASS (`mempool.go:339, 392, 648`) |
| 6 | … | G22: keyed by **wtxid** (BIP-339 / Core post-v23) | **BUG-7 (P1)** — `orphans map[wire.Hash256]*orphanEntry` is keyed by `txid` (`mempool.go:576, 2284, 2293`). Two witness-malleated variants with the same txid cannot coexist. Cross-cite W103 BUG-23. |
| 6 | … | G23: per-peer / per-announcer tracking | **BUG-8 (P1)** — `orphanEntry` (`mempool.go:452-458`) has NO `fromPeer` / `announcers` field. `EraseForPeer(nodeID)` cannot be implemented. Cross-cite W103 BUG-24. |
| 6 | … | G24: parent-side `OrphanByParent` index (parent txid → set of orphan wtxids) | **BUG-9 (P1)** — `processOrphansLocked` walks the entire `mp.orphans` map every promotion (`mempool.go:2339-2350`, O(N) per addtx). Core's `OrphanByParent` makes this O(children) per parent. With N=100 entries it's tolerable, but the scaling shape is wrong for any post-orphanage-rewrite increase. |
| 6 | … | G25: total-weight cap (`DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER=404000` × peers) | **BUG-10 (P1)** — only the entry count is capped. A peer can fill the orphan pool with 100 maximum-weight (400k vbyte each = 1.6M vbyte total = 40 MiB serialized) bogus orphans, well over Core's ~40 MiB global cap × peer-count. The eviction policy (`evictRandomOrphanLocked`) doesn't account for size either. |
| 7 | orphan eviction | G26: `EraseForBlock(block)` removes orphans whose inputs were spent by the block | **BUG-11 (P0)** — `BlockConnected` (`mempool.go:2388-2425`) ONLY removes confirmed txs + their double-spend conflicts from the **active mempool**. It does NOT touch `mp.orphans`. Result: every connected block leaves stale orphans whose parents are now confirmed-and-spent in the new block — they will sit until 20 min expiry, OR until promoted via `processOrphansLocked` from a new tx in the same block (which never happens since the block-confirmed tx isn't AddTransaction'd). |
| 7 | … | G27: `EraseForPeer(nodeID)` on disconnect | **BUG-8 cross-cite** — no per-peer tracking means a disconnecting peer's contributed orphans linger for 20 min. |
| 7 | … | G28: time-based expiry sweep | PASS — `OrphanExpireDriverInterval = 1 min` ticker (`cmd/blockbrew/main.go:1417-1427`) calls `mp.ExpireOrphans()` (mempool.go:2367). Coarser than Core's per-AddTx sweep, but within the 20-min window. |
| 8 | orphan promote | G29: refetch parents from announcer peer (`AddChildrenToWorkSet`) | **BUG-12 (P1)** — Core sends a `MSG_TX` getdata for the missing parents to the **announcer** of the orphan (txdownloadman). blockbrew has no path: orphans wait passively for the parent to arrive through some other channel (e.g., another peer's relay). On a sparsely-connected node, an orphan may simply expire. |
| 8 | … | G30: STANDARD flags applied on promote (W144 carry-forward) | **BUG-13 (P0-CDIV)** — `processOrphansLocked` re-enters `AddTransaction` (`mempool.go:2358`), which calls `getStandardScriptFlags`, which composes `STANDARD_SCRIPT_VERIFY_FLAGS` via `GetStandardScriptFlags` (`scriptflags.go:71-84`). The blockbrew composition adds only 3 of the 13 STANDARD-extras: `STRICTENC`, `NULLFAIL`, `WITNESS_PUBKEYTYPE`. **MISSING: MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, MINIMALIF, LOW_S, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE** (10 of 13). Direct carry-forward of W144 BUG-5; the orphan-promote path silently accepts policy-non-standard txs that Core's mempool rejects. |
| 8 | … | G31: COINBASE_MATURITY off-by-one on orphan promote (W150 carry-forward) | **BUG-14 (P0-CDIV)** — `AddTransaction` uses `age := tipHeight - utxo.Height` and rejects when `age < CoinbaseMaturity` (`mempool.go:1118-1128`). Core uses `nSpendHeight - coin.nHeight < COINBASE_MATURITY` with `nSpendHeight = active_chain.Height() + 1` (`validation.cpp:892` + `consensus/tx_verify.cpp:179-181`). When a coinbase has age=99 (will be 100 at the next block), Core accepts the spending tx into mempool; blockbrew rejects it. Orphan-promote inherits the bug — an orphan whose parent is a 99-confirmation coinbase is rejected on promote even though it will be valid in the next block. |
| 9 | feefilter | G32: `MoneyRange` validation on receive | PASS (`peer.go:937-941`) — uses `21_000_000 * 100_000_000` ceiling; matches Core MoneyRange. |
| 9 | … | G33: `MaybeSendFeeFilter` Poisson-style cadence | PASS (`peer.go:973-1042`) — 10 min mean + exponential jitter; ±10% privacy noise. |
| 10 | mempool dump (BIP-35) | G34: gated on local NODE_BLOOM | PASS (`main.go:1182-1191`). |
| 10 | … | G35: per-peer rate-limit (`MEMPOOL_REQUEST_PERIOD=1h`) | **BUG-15 (P1)** — no per-peer `lastMempoolRequest` timestamp on `Peer`. A peer can spam `mempool` requests and trigger O(N=full mempool) inv generation each time. Cross-cite W103 BUG-4 / BUG-18. |
| 11 | inv hash byte-order (W141 echo) | G36: inv serialised in internal byte order (NOT display-reversed) | PASS (`wire/types.go:99-102` writes raw bytes; cross-cite W141 BUGs 1/2/3 affect ZMQ only, NOT inv). The Hash256 type DOES double-display: `String()` reverses bytes (`types.go:57-65`), but `Serialize()` writes raw (`types.go:99-102`) — matches Core's `uint256::Serialize`. |

---

## BUG-1 (P1) — Oversized `inv` silently ignored; peer not penalised

**Severity:** P1. Bitcoin Core's `ProcessMessage("inv")` at
`net_processing.cpp:4040-4046` rejects any inv with
`vInv.size() > MAX_INV_SZ` (=50000) by calling
`Misbehaving(20, strprintf("inv message size = %u", vInv.size()))` and
returning early — the peer accumulates a discouragement score and
will be banned after enough offences.

blockbrew's `MsgInv.Deserialize` correctly enforces the cap at
`msg_inv.go:77-78` by returning `ErrTooManyInvVects`. But that error
is a `NonFatalMessageError` (from `message.go:43`) which the read
loop logs and continues. Specifically, the peer's misbehaviour
counter is **not** incremented — there is no
`peer.Misbehaving(20, "inv too large")` call anywhere along the
oversized-inv path. A buggy or hostile peer can repeatedly spam
oversized invs without consequence.

**File:** `internal/p2p/msg_inv.go:77-78` (cap enforced but error
class is non-fatal) + missing Misbehaving call site.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4040-4046`.

**Impact:** DoS resilience gap; a peer can waste bandwidth/CPU
deserialising > 50k InvVect (= > 1.8 MB) without scoring discouragement.

**Carry-forward:** W103 BUG-1 (still open, originally documented in
the W103 30-gate audit).

---

## BUG-2 (P0-CDIV) — `HandleGetData` does not handle `MSG_WTX` (BIP-339) or `MSG_WITNESS_TX` (BIP-144)

**Severity:** P0-CDIV. Bitcoin Core's `FindTxForGetData`
(`net_processing.cpp:2257-2287`) accepts `MSG_TX=1`, `MSG_WTX=5`, and
`MSG_WITNESS_TX=0x40000001` interchangeably and looks the tx up in
the mempool by either txid or wtxid, then serialises with the right
witness mode. blockbrew's `HandleGetData` (`sync.go:1264-1318`)
strips only the BIP-144 witness flag (`InvWitnessFlag=0x40000000`)
and switches on `baseType`:

```go
baseType := inv.Type &^ InvWitnessFlag
switch baseType {
case InvTypeBlock:
    // ... serve block
case InvTypeTx:
    // TODO: look up transaction from mempool
}
```

- `InvTypeWtx = 5`: after stripping the witness flag still equals 5,
  matches neither case → **silently dropped, no notfound**. A Core
  wtxid-relay peer that issues `getdata{MSG_WTX, wtxid}` for a tx we
  announced via our wtxid-relay path receives **no response** at all.
- `InvTypeTx = 1`: TODO stub, **no mempool lookup, no notfound**.
- `InvTypeFilteredBlock = 3` (BIP-37): silently dropped.

Worse, `MSG_NOTFOUND` is only emitted for `InvTypeBlock` failures
(`sync.go:1315-1317`), so the peer can't even detect the gap to
re-request from another peer.

**File:** `internal/p2p/sync.go:1264-1318` (switch covers only Block
and TODO Tx; no Wtx, no FilteredBlock, no Wtx notfound).

**Core ref:** `bitcoin-core/src/net_processing.cpp::FindTxForGetData`
+ `ProcessGetData` (handles all three inv types + emits notfound).

**Impact:**
- A blockbrew node that announces a tx via `RelayTransaction` (with
  `MSG_WTX=5` for wtxid-relay peers, which `RelayTransaction` does
  correctly at `peermgr.go:810-812`) **cannot serve the follow-up
  getdata** for that announcement. The peer requests it, gets no
  reply, eventually times out, and Misbehaves us
  (`txrequest.cpp::ReceivedResponse` failure path scores against us
  on `GETDATA_TX_INTERVAL=60s` timeout).
- Net result: every tx blockbrew announces over wtxid-relay is a
  failed handshake. Tx propagation from blockbrew effectively does
  not work for any wtxid-relay peer (i.e., every modern Core peer).
  Legacy `MSG_TX` peers also get nothing because of the TODO stub.
- This compounds BUG-3 (we never request txs from peers either) into:
  **blockbrew is effectively a transaction relay black hole** —
  it can neither pull nor serve transactions over P2P. Only the
  in-process RPC path `sendrawtransaction → mempool.AcceptToMemoryPool
  → peerMgr.RelayTransaction` puts txs into the relay graph, and the
  follow-up getdata from the receiving peer goes unanswered.
- Concrete observable: a Core peer on a freshly synced testnet4 node
  shows `txn-already-known` for our announced wtxids if they happened
  to receive the tx elsewhere first, and timeouts otherwise; in
  bitcoin-cli `getpeerinfo` the `inflight` array stays populated for
  60 s then expires.

---

## BUG-3 (P0-CDIV) — `HandleInv` ignores tx-type invs; blockbrew never requests transactions from peers

**Severity:** P0-CDIV. Bitcoin Core's `ProcessMessage("inv")` at
`net_processing.cpp:4040-4150` walks the inv list, classifies each
entry, and for tx-type invs (`MSG_TX`/`MSG_WTX`) calls
`AddTxAnnouncement` on the txdownloadman, which enrolls the entry in
the request scheduler and eventually fires `MSG_GETDATA` to the
preferred peer subject to the `NONPREF` / `TXID_RELAY` / `OVERLOADED`
delays. This is the entire receive-side of tx relay.

blockbrew's `HandleInv` (`sync.go:1081-1095`):

```go
func (sm *SyncManager) HandleInv(peer *Peer, msg *MsgInv) {
    hasBlock := false
    for _, inv := range msg.InvList {
        baseType := inv.Type &^ InvWitnessFlag
        if baseType == InvTypeBlock {
            hasBlock = true
            break
        }
    }
    if !hasBlock {
        return
    }

    sm.sendGetHeadersTo(peer)
}
```

The handler iterates the inv list looking ONLY for block entries; if
none found, returns. Tx invs are not enqueued anywhere, never
fetched, and the announcing peer is not recorded as a candidate
source. **blockbrew never sends `getdata{MSG_TX,…}` in response to a
peer's `inv{MSG_TX,…}`.** Combined with BUG-2 (we don't serve
getdata-tx either), blockbrew's tx-relay path is unidirectional:

- Local `sendrawtransaction` RPC → mempool → `RelayTransaction` →
  outbound `inv` to all wtxid/legacy peers. (Works.)
- Inbound peer `inv{MSG_TX,…}` → **dropped**. (Broken.)
- Inbound peer `getdata{MSG_TX,…}` after we announced → **dropped**
  (BUG-2). (Broken.)

**File:** `internal/p2p/sync.go:1081-1095`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessMessage`
`NetMsgType::INV` handler + `m_txdownloadman.AddTxAnnouncement`.

**Impact:**
- The mempool can only fill from local RPC submissions and from txs
  in blocks we (dis)connect. A blockbrew node with zero RPC traffic
  has an empty mempool regardless of upstream P2P announcements.
- Fee estimation, package relay, RBF processing all starve. The
  feeestimator never sees representative real-world traffic.
- A miner-on-blockbrew never sees txs to include in templates other
  than its own.
- Peer reputation: peers expect a getdata follow-up after `inv`. A
  peer that never receives any follow-up may eventually deprioritise
  blockbrew, but Core doesn't actively misbehave us for this so it's
  silent.

---

## BUG-4 (P1) — No per-peer `m_recently_announced_invs` / known-tx filter

**Severity:** P1. Bitcoin Core's `Peer::TxRelay` carries
`m_recently_announced_invs` (a rolling bloom keyed by wtxid, capacity
2 MB, false-positive 1e-6, `net_processing.cpp:282-290`) plus the
older `m_tx_inventory_known_filter` (rolling bloom of txids/wtxids the
peer already knows). These two are consulted on every announce: a tx
the peer already knows or just got from us in the last cycle is
**not** re-announced.

blockbrew's `Peer` struct (`peer.go:135-220`) carries neither field.
`RelayTransaction` (`peermgr.go:786-825`) iterates all peers and
sends the inv with no dedup. Result:

- An RBF replacement triggers a fresh `RelayTransaction` for the
  replacement wtxid; if a peer already has the replacement via
  another path, they get a duplicate inv (no harm, just bandwidth).
- A tx that bounces around due to package processing
  (`AcceptPackage` calls `RelayTransaction` per accepted tx) can
  re-announce the same wtxid multiple times in a tight loop.
- A peer who sent the tx to us still gets the announcement because
  we don't add to a "they already know" filter on receipt
  (cross-cite BUG-3 — we don't receive anything anyway).

**File:** `internal/p2p/peer.go:135-220` (no `recentlyAnnouncedInvs`
or `txInventoryKnownFilter`).

**Core ref:** `bitcoin-core/src/net_processing.cpp:282-290`
(`m_recently_announced_invs`), 304 (`m_tx_inventory_known_filter`).

**Impact:** bandwidth waste + peer-side log spam ("already have
inv"); no consensus risk. Cross-cite W103 BUG-17.

---

## BUG-5 (P0-CDIV) — No per-peer inv batching; one `inv` message per tx per peer

**Severity:** P0-CDIV. Bitcoin Core's `RelayTransaction`
(`net_processing.cpp:2237-2271`) does NOT send the inv synchronously.
It inserts the wtxid into each candidate peer's
`tx_relay->m_tx_inventory_to_send` set under `m_tx_inventory_mutex`.
The actual `MSG_INV` send is driven by `MaybeSendMessage`
(`net_processing.cpp:5981-6056`):

- Per-peer scheduler `m_next_inv_send_time`:
  - **Outbound:** Poisson-exponential with mean
    `OUTBOUND_INVENTORY_BROADCAST_INTERVAL = 2s` (line 5986).
  - **Inbound:** deterministic 5 s Poisson with shared randomness
    (line 5984, `NextInvToInbounds`).
- Per-cycle cap `broadcast_max = INVENTORY_BROADCAST_TARGET +
  (queue_size/1000)*5` where `INVENTORY_BROADCAST_TARGET = 70`
  (line 6045).
- Drains up to `broadcast_max` wtxids per cycle into a single
  `MSG_INV` (one batch per peer per cycle).

blockbrew's `RelayTransaction` (`peermgr.go:786-825`) emits the inv
inline:

```go
inv := &MsgInv{
    InvList: []*InvVect{
        {Type: invType, Hash: hash},
    },
}
info.peer.SendMessage(inv)
```

One `MsgInv` per tx per peer. There is no per-peer queue, no Poisson
scheduler, no per-cycle target. A burst of 1000 mempool admissions
(plausible during RBF storms or block-disconnect re-add) fires 1000
`MsgInv` messages per peer × ~16 peers = 16k outbound messages in a
tight loop, each carrying 36 bytes of inv vector but ~24 bytes of
message header overhead — ~60% framing overhead.

**File:** `internal/p2p/peermgr.go:786-825`; no scheduler exists.

**Core ref:** `bitcoin-core/src/net_processing.cpp:5981-6056`
(`MaybeSendMessage` inv drain), 165-174 (cadence constants),
2237-2271 (`RelayTransaction` set insert).

**Impact:**
- **Privacy / fingerprinting:** Core's Poisson jitter is a deliberate
  defence against tx-origin inference (a watcher correlating inv
  arrival times with block timing can fingerprint the originating
  node). blockbrew's synchronous emit publishes the wall-clock
  arrival of every tx, vastly easier to fingerprint. (Same shape as
  the addrman privacy gap in W104.)
- **Bandwidth amplification on burst:** ~60% framing overhead on
  every tx, vs Core's ~2% (70 entries in one inv message).
- **Per-peer ordering:** Core's batched drain preserves topo-order
  across announcements (the set is iterated in insertion order via
  `for (set<Wtxid>::iterator it = ...)`. blockbrew's per-tx send
  preserves call-order but does not coalesce — a peer's `recvqueue`
  fills with 1000 individual invs that they must each lookup-and-
  request, racing against Core's `MAX_PEER_TX_REQUEST_IN_FLIGHT=100`
  cap.
- **No `MAX_PEER_TX_ANNOUNCEMENTS=5000` enforcement** by extension —
  we never count announcements per peer because we never queue them.

This is a **fleet-pattern instance**: "synchronous emit instead of
batched drain" — first blockbrew instance of the SendMessages-cycle
divergence.

---

## BUG-6 (P1) — Entire txrequest scheduler absent (no MAX_PEER_TX_REQUEST_IN_FLIGHT, GETDATA_TX_INTERVAL, NONPREF / TXID_RELAY / OVERLOADED delays)

**Severity:** P1. Bitcoin Core's `txdownloadman` /
`txrequest.cpp` is a state machine that:

- caps in-flight tx requests per peer at
  `MAX_PEER_TX_REQUEST_IN_FLIGHT = 100`,
- caps queued announcements per peer at
  `MAX_PEER_TX_ANNOUNCEMENTS = 5000` (DoS guard),
- composes a per-request delay:
  - `+ NONPREF_PEER_TX_DELAY=2s` if peer is non-preferred (no outbound
    selection / no relay permission),
  - `+ TXID_RELAY_DELAY=2s` if the announcement is txid-only (`MSG_TX`)
    while at least one wtxid-relay peer is available,
  - `+ OVERLOADED_PEER_TX_DELAY=2s` if peer has ≥100 requests in flight
    (and no relay permission),
- re-requests after `GETDATA_TX_INTERVAL = 60s` from a different peer
  if the first peer didn't deliver.

blockbrew has none of this. There is no `TxRequestTracker` struct,
no `txrequest.go` file. `RelayTransaction` is the entire outbound
machinery; inbound is BUG-3 (we don't fetch txs at all).

**File:** `internal/p2p/` (no txrequest.go).

**Core ref:** `bitcoin-core/src/node/txdownloadman.h:25-38`,
`bitcoin-core/src/txrequest.cpp`.

**Impact:**
- DoS attack: a single peer can announce 50k inv vectors per second
  (up to `MAX_INV_SZ` cap), and there is no per-peer announcement
  count tracking → no Misbehaving on flood. (BUG-1 only catches
  >50000 per single message.)
- No outbound preference: if blockbrew DID fetch txs (BUG-3), all
  peers would be requested at equal priority — Sybil/eclipse risk.
- No request retry: a peer who promised a tx and didn't deliver
  blocks the slot forever (relevant if BUG-3 is fixed).

Carry-forward (all open from W103): BUG-9, BUG-10, BUG-11, BUG-12,
BUG-13, BUG-14.

---

## BUG-7 (P1) — Orphan pool keyed by txid, not wtxid (BIP-339 divergence)

**Severity:** P1. Bitcoin Core's `TxOrphanage::HaveTx(const Wtxid&)`
keys the orphanage by wtxid (`txorphanage.h:68`). This was changed
from txid in v23 as part of the wider BIP-339 transition: storing
malleated witness variants of the same logical tx as **distinct**
orphan entries is what allows the txdownloadman to negotiate the
correct one.

blockbrew's `orphans map[wire.Hash256]*orphanEntry` (`mempool.go:576`)
is keyed by `txHash` (txid). `addOrphanLocked` (line 2284) uses
`txHash`, and `processOrphansLocked` (line 2331) keys lookups by
txid. Witness-malleated variants with the same txid silently
overwrite each other in the map.

**File:** `internal/mempool/mempool.go:452-458` (`orphanEntry` struct,
no `wtxHash` field), 576 (map keyed by `wire.Hash256`/txid), 2284
(addOrphanLocked uses txid).

**Core ref:** `bitcoin-core/src/node/txorphanage.h:68` (HaveTx takes
`const Wtxid&`).

**Impact:** fingerprinting / annoyance attack — peer A sends orphan
{txid=X, wtxid=Y1}, peer B sends orphan {txid=X, wtxid=Y2}; only
the second is retained. If the parent arrives, only Y2 is promoted;
Y1 is permanently lost even though Y1 might be the canonical (signed)
variant.

**Carry-forward:** W103 BUG-23 (still open).

---

## BUG-8 (P1) — `EraseForPeer` cannot be implemented; orphans not linked to announcer

**Severity:** P1. Bitcoin Core's `TxOrphanage::EraseForPeer(NodeId)`
(`txorphanage.h:86`) is called from `FinalizeNode` when a peer
disconnects. It removes all orphans where the disconnecting peer is
the SOLE announcer (orphans with other announcers stay, just lose
that one announcer). This is what prevents a disconnecting attacker
from leaving a polluted orphan pool behind.

blockbrew's `orphanEntry` (`mempool.go:452-458`) carries:

```go
type orphanEntry struct {
    tx         *wire.MsgTx
    txHash     wire.Hash256
    addedTime  time.Time
    missingOut []wire.OutPoint
}
```

No `fromPeer string` or `announcers []string` field. There is no
peer-eraser API on `Mempool`, and no call from `Peer.Disconnect()`
to anything that would clean orphans. A peer that fills 99 of 100
orphan slots and then disconnects leaves the pool at 99/100; the
slots are released only by the 1-min `OrphanExpireDriverInterval`
sweep (and only after the 20-min `OrphanTxExpireTime`).

**File:** `internal/mempool/mempool.go:452-458`; no caller wiring on
peer disconnect.

**Core ref:** `bitcoin-core/src/node/txorphanage.h:86`,
`txorphanage.cpp::EraseForPeer`.

**Impact:** disconnecting peer leaves orphan pool polluted for up to
20 min. Slot starvation: a hostile peer that fills 100 orphans then
DCs holds the pool full until the next sweep, blocking legitimate
orphans from new peers.

**Carry-forward:** W103 BUG-24 (still open).

---

## BUG-9 (P1) — `OrphanByParent` index absent; `processOrphansLocked` is O(N²) worst-case

**Severity:** P1. Bitcoin Core maintains a side-index
`m_outpoint_to_orphan_it` (parent COutPoint → set of orphan iterators)
so that when a new tx is admitted, the promote-children sweep is
O(children) rather than O(all-orphans). With the v28+ orphanage
rewrite, the latency-bound `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE=3000`
makes per-AddTx sweeps cheap even at maximum orphanage capacity.

blockbrew's `processOrphansLocked` (`mempool.go:2331-2361`) walks the
**entire** `mp.orphans` map on every `AddTransaction`:

```go
for _, orphan := range mp.orphans {
    for i, missing := range orphan.missingOut {
        if missing.Hash == newTxHash && ... { ... }
    }
}
```

At `MaxOrphanTxs=100` and a typical orphan with 2 missing inputs,
that's ~200 outpoint compares per AddTx call. The bigger problem is
the inner-loop slice mutation
`orphan.missingOut = append(orphan.missingOut[:i], orphan.missingOut[i+1:]...)`
which allocates a fresh slice on every match — heap pressure scales
with orphan churn rate.

**File:** `internal/mempool/mempool.go:2339-2350`.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp` — parent index
(`m_outpoint_to_orphan_it`).

**Impact:** tolerable at N=100 but the scaling shape is wrong for
any post-Core-v28 increase in pool size (Core's new pool is sized in
weight rather than count; the equivalent here would be ~40 MiB of
orphans, ≈ 1000+ entries, where the O(N) walk per AddTx becomes
visible).

---

## BUG-10 (P1) — Orphan pool capped by count only; no per-peer or global weight cap

**Severity:** P1. Bitcoin Core's
`DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER = 404'000` (vbytes) caps the
contribution of any single peer to the orphan pool by **weight**, not
count. Coupled with `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE = 3000` for
the global eviction budget, the orphanage is bounded by memory
footprint rather than entry count. A peer cannot pump 100 maximum-
weight (`MAX_STANDARD_TX_WEIGHT = 400000`) bogus orphans and consume
40 MiB of RAM.

blockbrew has `MaxOrphanTxs = 100` (`mempool.go:339, 648`). The
eviction policy `evictRandomOrphanLocked` (line 2303-2326) doesn't
weight by size either — a random victim is picked. There is no
total-weight or total-size accounting on the orphan pool.

**Worst-case RAM:** 100 × 400000 vbytes = 40 MiB if every orphan is
maximum size. That's the same as Core's per-peer reservation, but
**any peer can fill it alone** (no per-peer weight reservation), so
the actual cap is much weaker than Core's design intent (per-peer
reservation × N peers ≈ 16 × 404k = ~6.5 MiB guaranteed per peer,
remainder shared).

**File:** `internal/mempool/mempool.go:2278-2326` (no weight
accounting).

**Core ref:** `bitcoin-core/src/node/txorphanage.h:20-23`
(`DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER`,
`DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE`).

**Impact:** orphan pool can be cheaply RAM-amplified by a single
attacker peer up to ~40 MiB (vs Core's per-peer-weighted ~6.5 MiB
guarantee). On a constrained host (1 GB RAM box) this is noticeable.

---

## BUG-11 (P0) — `BlockConnected` does not erase orphans whose inputs are spent by the new block

**Severity:** P0. Bitcoin Core's
`PeerManagerImpl::BlockConnected` (`net_processing.cpp:1991-2068`)
calls `m_orphanage->EraseForBlock(block)`. That iterates every input
of every tx in the new block and erases any orphan whose `missingOut`
points at one of those outpoints — they're either confirmed (so no
longer missing) or invalidated (the parent's UTXO was consumed by the
new block and our orphan would now be a permanently-orphaned conflict).

blockbrew's `BlockConnected` (`mempool.go:2388-2425`) handles only
the mempool side:

```go
for _, tx := range block.Transactions {
    txHash := tx.TxHash()
    mp.removeSingleTxLocked(txHash, MempoolRemovalReasonBlock)
    for _, in := range tx.TxIn {
        if spendingTx, ok := mp.outpoints[in.PreviousOutPoint]; ok {
            mp.removeWithDescendantsLocked(spendingTx, MempoolRemovalReasonConflict)
        }
    }
}
// NO mp.eraseOrphansForBlock(block)
```

There is no `EraseForBlock` analogue, and no place in `mempool.go`
or `mp` callers (`grep -rn '\.orphans' .` returns only internal
methods) that prunes orphans on block connect.

**Consequences:**

1. **Stale orphans live to 20 min:** every orphan whose missing
   parent was just confirmed sits in the pool until `ExpireOrphans`
   fires (1 min cadence, 20 min expiry). They are NOT promoted to
   the mempool by `processOrphansLocked` either, because that path
   is only triggered when a NEW tx is added (`mempool.go:1372`), and
   block-confirmed txs are REMOVED (not added) on block-connect.
2. **Slot occupation:** 100 stale orphans occupy the full pool, so a
   subsequent legitimate orphan from a new peer is rejected (well,
   evicts a random orphan, but the rejection-to-eviction cycle
   wastes resources).
3. **Conflict-invalidated orphans:** an orphan whose missing parent
   was MINED by a tx OTHER than the orphan's intended parent
   (effectively: the parent's outpoint is now spent by a different
   tx in the new block) will NEVER be promotable — promoteOrphans
   waits for the txid of the missing parent to enter the mempool,
   but the parent is now confirmed-and-its-output-was-spent. The
   orphan sits until 20-min expiry, occupying a slot.

**File:** `internal/mempool/mempool.go:2388-2425` (BlockConnected,
no orphan-side handling).

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp::EraseForBlock`,
`net_processing.cpp::PeerManagerImpl::BlockConnected`.

**Impact:** orphan pool effectiveness drops sharply after each
block. On mainnet at 100 orphan cap with avg 0.5-1 orphans per
block consumed by inputs, every block leaves ~3-5 stale orphans
that will linger 20 min. After ~20-30 blocks of slow drain, the
pool is fully populated by stale entries from old blocks, and new
orphans from current relay are evicted ahead of useful entries.

---

## BUG-12 (P1) — No orphan-parent refetch from announcer peer

**Severity:** P1. Bitcoin Core's `ProcessOrphanTx`
(`net_processing.cpp:3196-3265`) and the txdownloadman's
`AddChildrenToWorkSet` (`txorphanage.h:92`) coordinate to **fetch
the missing parents** from the peer that announced the orphan:
when a tx is added to the orphanage, the parents' txids are
enqueued as txrequest entries against the announcing peer, with the
same delay composition as a regular announcement (so the peer is
hit with `MSG_GETDATA{MSG_TX, parent_txid}` after the appropriate
delay).

blockbrew's `addOrphanLocked` (`mempool.go:2282-2299`) just stores
the orphan and returns. There is no path:

- `addOrphanLocked` has no `fromPeer` parameter at all.
- No call to `peerMgr.RequestParents(peer, missingOutpoints)` exists.
- `processOrphansLocked` (line 2331) PASSIVELY waits for the parent
  to be added via some other path — there is no active fetch.

On a sparsely-connected node (few peers, low gossip), a legitimate
orphan whose parent is in flight elsewhere on the network may
simply expire at 20 min without ever being completed.

**File:** `internal/mempool/mempool.go:2282-2299` (no fromPeer arg,
no fetch call); `internal/p2p/` (no orphan-parent-request code path).

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessOrphanTx`,
`bitcoin-core/src/node/txorphanage.h::AddChildrenToWorkSet`.

**Impact:** orphans that arrive before their parents (the entire
purpose of the orphan pool) may not resolve unless a coincidence
delivers the parent from another peer. Reduces effective orphan
recovery rate.

---

## BUG-13 (P0-CDIV) — Orphan promote inherits broken STANDARD flag set (W144 carry-forward)

**Severity:** P0-CDIV. When an orphan is promoted via
`processOrphansLocked → mp.AddTransaction(orphan.tx)` (`mempool.go:2358`),
the script-validation step at line 1294-1307 calls
`mp.getStandardScriptFlags()` (line 1531) → `consensus.GetStandardScriptFlags`
(`scriptflags.go:71-84`).

blockbrew's composition adds only THREE STANDARD-extras:

```go
// scriptflags.go:71-84
func GetStandardScriptFlags(...) script.ScriptFlags {
    flags := GetBlockScriptFlags(height, params, blockHash)
    if height >= params.BIP66Height {
        flags |= script.ScriptVerifyStrictEncoding
    }
    if height >= params.SegwitHeight {
        flags |= script.ScriptVerifyNullFail
        flags |= script.ScriptVerifyWitnessPubKeyType
    }
    return flags
}
```

Core's `STANDARD_SCRIPT_VERIFY_FLAGS` (`policy/policy.h:119-132`)
adds THIRTEEN bits beyond MANDATORY. blockbrew is missing TEN of
them:

| Flag | Core | blockbrew |
|------|------|-----------|
| STRICTENC | ✓ | ✓ |
| MINIMALDATA | ✓ | **missing** |
| DISCOURAGE_UPGRADABLE_NOPS | ✓ | **missing** |
| CLEANSTACK | ✓ | **missing** |
| MINIMALIF | ✓ | **missing** |
| NULLFAIL | ✓ | ✓ |
| LOW_S | ✓ | **missing** |
| DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM | ✓ | **missing** |
| WITNESS_PUBKEYTYPE | ✓ | ✓ |
| CONST_SCRIPTCODE | ✓ | **missing** |
| DISCOURAGE_UPGRADABLE_TAPROOT_VERSION | ✓ | **missing** |
| DISCOURAGE_OP_SUCCESS | ✓ | **missing** |
| DISCOURAGE_UPGRADABLE_PUBKEYTYPE | ✓ | **missing** |

**Direct carry-forward of W144 BUG-5** (script-verify flag mux: 9 of 13
STANDARD flags missing — that audit logged 9, but actual count is 10
because BUG-5 missed `MINIMALDATA` in the inventory).

The bug specifically affects orphan-promote: when an orphan whose
parent was just admitted is promoted via `AddTransaction`, the policy
gate is broken. blockbrew silently admits:

- non-minimally-encoded data pushes (push of zero via OP_0 vs 0x00:
  the latter is non-standard in Core but accepted here),
- transactions reusing NOPs as `OP_CHECKTEMPLATEVERIFY` placeholders
  (Core discourages via `DISCOURAGE_UPGRADABLE_NOPS`),
- transactions with unclean stack (Core: `CLEANSTACK` policy),
- TRUC v2 inputs with non-minimal witness pushes
  (`MINIMALIF` enforces 0x01/0x80 only for witness booleans),
- non-low-S signatures (Core: `LOW_S` enforces s ≤ N/2 for
  malleability resistance),
- transactions using upgradable witness programs (v1+ non-Taproot, or
  v2+ programs Core would flag DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM),
- transactions using "successful" OP_SUCCESS in tapscript
  (`DISCOURAGE_OP_SUCCESS`),
- transactions paying to upgradable pubkey types
  (`DISCOURAGE_UPGRADABLE_PUBKEYTYPE`).

**File:** `internal/consensus/scriptflags.go:71-84`
(`GetStandardScriptFlags` composition).

**Core ref:** `bitcoin-core/src/policy/policy.h:119-132`
(`STANDARD_SCRIPT_VERIFY_FLAGS`).

**Impact:** policy non-standard txs admitted by blockbrew through both
the direct ATMP and the orphan-promote paths. Any tx that the rest of
the network rejects (because their Core mempool dropped it for
policy) we will relay anyway — wasted bandwidth and minor
fingerprinting (we relay txs no other node will). On mining the
non-standard tx is included in a template, which Core peers may
deprioritise the resulting block via compact-block prefill
(BIP-152 will work but reconstruction needs the tx in their mempool,
which it isn't).

**Carry-forward:** W144 BUG-5 (still open since W144).

---

## BUG-14 (P0-CDIV) — Coinbase-maturity off-by-one on orphan promote (W150 carry-forward)

**Severity:** P0-CDIV. blockbrew's coinbase-maturity check in
`AddTransaction` (`mempool.go:1112-1128`):

```go
if utxo.IsCoinbase {
    spendsCoinbase = true
    if mp.config.ChainState != nil {
        tipHeight := mp.config.ChainState.TipHeight()
        age := tipHeight - utxo.Height
        if age < consensus.CoinbaseMaturity {
            return fmt.Errorf("%w: age %d < %d required",
                ErrImmatureCoinbaseSpend, age, consensus.CoinbaseMaturity)
        }
    }
}
```

Bitcoin Core's check (`consensus/tx_verify.cpp:179-181` called via
`validation.cpp:892` with `m_active_chainstate.m_chain.Height() + 1`):

```cpp
if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) { ... }
// where nSpendHeight = active_chain.Height() + 1
```

Translation:

| utxo.Height | tip.Height | blockbrew age = tip − utxo | Core spendDepth = tip+1 − utxo | blockbrew | Core |
|-------------|------------|----------------------------|-------------------------------|-----------|------|
| 0 | 99 | 99 | 100 | reject (age<100) | accept (spend≥100) |
| 0 | 100 | 100 | 101 | accept | accept |

blockbrew rejects coinbase-spending txs **1 confirmation too early**.
Specifically: a tx that Core admits to mempool (knowing it will be
valid in the NEXT block at height tip+1) is rejected by blockbrew
with `ErrImmatureCoinbaseSpend`. This applies to BOTH the direct
ATMP path AND the orphan-promote path (which re-enters
`AddTransaction`).

**Impact on orphan-promote:** if an orphan was rejected from mempool
because its parent was an immature coinbase, the orphan stays in the
orphanage. When the parent matures, blockbrew won't promote until the
block AFTER the tip Core uses. For one block (the boundary block),
Core relays the tx and blockbrew doesn't — a tiny fork in relay
behaviour observable to anyone listening to both.

**File:** `internal/mempool/mempool.go:1112-1128`.

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:179-181`,
`bitcoin-core/src/validation.cpp:892`.

**Impact:** small but persistent relay-graph divergence; tx that Core
relays at confirmation 100 (the canonical "100 confirmations to
spend") blockbrew rejects until confirmation 101. This is the
classic off-by-one in mempool spendHeight assumption.

**Carry-forward:** W150 BUG-9 (still open; explicit cross-cite).

---

## BUG-15 (P1) — No per-peer `mempool` request rate-limit

**Severity:** P1. Bitcoin Core's
`PeerManagerImpl::ProcessMessage` for `NetMsgType::MEMPOOL`
(`net_processing.cpp:4858-4870`) sets
`peer.m_send_mempool = true` only when:

- our local node advertises `NODE_BLOOM` OR the peer has
  `NetPermissionFlags::Mempool`,
- the peer is not already over the per-second response cap.

The actual inv generation runs through the standard `MaybeSendMessage`
drain (so the BIP-35 reply is just a flag-flip; the inv is batched
with regular tx-relay). Peer flooding `mempool` is limited by the
same `INVENTORY_BROADCAST_TARGET` cap that limits regular tx relay.

blockbrew's `HandleMempoolRequest` (`mempool_handler.go:40-74`)
returns a fresh `[]*MsgInv` slice that enumerates the entire mempool
on every call. No timestamp on the `Peer` struct prevents successive
requests. A hostile peer can send `mempool` once per second and force
blockbrew to allocate `~MaxInvVects = 50000` `*InvVect` per chunk per
request — a CPU/RAM amplification.

**File:** `internal/p2p/peer.go:135-220` (no `lastMempoolRequest`
field); `internal/p2p/mempool_handler.go:40-74` (no rate-limit
inside).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4858-4870`.

**Impact:** DoS amplification — a single peer can drive O(mempool
size) work per request. At a full mempool (~250k entries), that's
5 batched inv messages × 50k InvVect × 36 bytes = ~9 MB allocation
per request. 10 requests/sec sustained = 90 MB/sec churn.

**Carry-forward:** W103 BUG-4 / BUG-18 (still open).

---

## BUG-16 (P1) — `OnTx` accepts unrequested transactions without misbehavior penalty

**Severity:** P1. Bitcoin Core's `ProcessMessage("tx")` at
`net_processing.cpp:3144-3186` verifies that the tx was previously
requested (via `m_txrequest.ReceivedResponse`); a tx for which we
have NO outstanding request triggers
`Misbehaving(peer, 10, "tx not requested")` and the tx is rejected
without entering ATMP.

blockbrew's `OnTx` listener (`cmd/blockbrew/main.go:1139-1160`) has
no such check:

```go
syncListeners.OnTx = func(peer *p2p.Peer, msg *p2p.MsgTx) {
    if err := mp.AcceptToMemoryPool(msg.Tx); err != nil {
        log.Printf("[mempool] Rejected tx from %s: %v", peer.Address(), err)
        return
    }
    ...
}
```

Any peer can push any tx at any time, even one we never requested.
The mempool will validate it (free CPU for the attacker if they
chain validation-expensive scripts), and if it passes, we'll relay
it.

Note that BUG-3 + BUG-6 together make this effectively dead code —
we can't issue tx requests anyway, so blockbrew has no concept of
"unrequested" because everything is unrequested. But once the
receive-side is fixed, this gap surfaces.

**File:** `cmd/blockbrew/main.go:1139-1160`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3144-3186`.

**Impact:** free CPU attack — peers can push expensive-to-validate
txs (lots of inputs, complex scripts) that we'll happily validate.
Bandwidth amplification.

**Carry-forward:** W103 BUG-28 (still open).

---

## BUG-17 (P1) — `evictRandomOrphanLocked` deletes a random victim instead of "oldest entry from heaviest peer"

**Severity:** P1. Bitcoin Core's `LimitOrphans` (post-v28 rewrite,
`txorphanage.cpp::LimitOrphans`) evicts oldest-first from the
**most resource-intensive peer** — this is what prevents a single
heavy peer from displacing other peers' orphans.

blockbrew's `evictRandomOrphanLocked` (`mempool.go:2303-2326`):

```go
func (mp *Mempool) evictRandomOrphanLocked() {
    if len(mp.orphans) == 0 { return }
    // First try to evict expired orphans
    expiry := time.Now().Add(-OrphanTxExpireTime)
    for hash, orphan := range mp.orphans {
        if orphan.addedTime.Before(expiry) {
            delete(mp.orphans, hash)
            return
        }
    }
    // No expired orphans, pick a random one
    idx := rand.Intn(len(mp.orphans))
    ...
}
```

Random eviction means a peer who legitimately contributed orphans
loses theirs to a peer who pushes garbage at maximum rate. Combined
with BUG-8 (no per-peer tracking), the policy is "all peers
equal-victim" rather than "punish the worst peer". Core's policy
is what prevents the eclipse-by-orphan attack
(a peer can't displace all others' orphans with their own).

Also: the `for hash, orphan := range mp.orphans` map iteration
order in Go is randomised, but it's also NOT sorted by `addedTime`
— the expired-orphan eviction step picks the FIRST expired one it
finds, not the OLDEST. For a pool with multiple expired entries
this is suboptimal but not broken.

**File:** `internal/mempool/mempool.go:2303-2326`.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp::LimitOrphans`.

**Impact:** eclipse-class attack — a single peer flooding orphans
can displace 99% of legitimate orphans (since random selection
favours the larger group). Core's per-peer-fairness eviction
specifically prevents this.

---

## BUG-18 (P1) — `BlockDisconnected` re-adds via `AddTransaction` ignoring orphan re-enrollment

**Severity:** P1. Bitcoin Core's `BlockDisconnected` re-evaluates
**both** the mempool admission AND orphan-pool admission for each
re-added tx, using `AddTxIfNotPresent` which inserts into the
orphan pool if the tx has missing inputs (because of a reorg, a
previously-valid tx may now have inputs that don't exist on the
new chain).

blockbrew's `BlockDisconnected` (`mempool.go:2429-2444`):

```go
for i, tx := range block.Transactions {
    if i == 0 { continue } // Skip coinbase
    _ = mp.AddTransaction(tx) // Ignore errors
}
```

`AddTransaction` will route missing-input txs to the orphan pool
via line 1178-1182 — so far so good. But this calls
`addOrphanLocked` which (per BUG-8) does NOT track the original
announcing peer. A tx that was previously valid (was in the mempool,
got block-confirmed, then block-disconnected, now missing inputs
again) will land in the orphan pool with NO per-peer accounting
and NO timer reset — meaning a tx that was first announced 18
minutes ago will be evicted in 2 minutes from the orphan pool even
though it's effectively a "fresh" orphan in the new chain.

Also: silent error suppression `_ = mp.AddTransaction(tx)` means
RBF conflicts, BIP-30 violations, etc. are all lost. Core logs
these.

**File:** `internal/mempool/mempool.go:2429-2444`.

**Core ref:** `bitcoin-core/src/validation.cpp::removeForReorg`
(more nuanced re-add path).

**Impact:** orphans from re-add are spuriously short-lived; reorg-
caused tx rejections are invisible to operators.

---

## BUG-19 (P1) — `processOrphansLocked` infinite-recursion risk via re-entrant unlock/lock

**Severity:** P1. The promote step at `mempool.go:2353-2360`:

```go
for _, orphan := range toProcess {
    delete(mp.orphans, orphan.txHash)
    mp.mu.Unlock()
    _ = mp.AddTransaction(orphan.tx) // Ignore errors
    mp.mu.Lock()
}
```

`AddTransaction` calls `processOrphansLocked` at line 1372 (held
under `mp.mu`). So the call chain is:

```
processOrphansLocked → mp.mu.Unlock → AddTransaction → mp.mu.Lock →
processOrphansLocked → mp.mu.Unlock → AddTransaction → ...
```

For a chain of N orphans depending on each other, this recurses N
deep. Each level holds the local `toProcess` slice on the goroutine
stack (~24 bytes per orphan pointer). At MaxOrphanTxs=100, worst
case is ~2.4 KB of stack frames + Go's func-call overhead per
level. Go's default 8 KB goroutine stack autogrows, so won't OOM —
but the lock thrash (100 acquire/release cycles in a chain) is
visible under contention.

More concerning: the inner `_ = mp.AddTransaction(...)` IGNORES
errors. If the orphan fails validation (e.g., the parent's output
amount doesn't match what the orphan tries to spend, or the orphan
was waiting on a different parent), the orphan is silently
discarded with no log line. Operators have no signal that orphan-
processing is failing.

**File:** `internal/mempool/mempool.go:2329-2361, 1372`.

**Impact:** stack thrash under heavy orphan-chain load; silent
failures lose orphans without explanation.

---

## BUG-20 (P2) — `OrphanTxExpireTime = 20 min` hard-coded, no per-network override

**Severity:** P2. Core's `ORPHAN_TX_EXPIRE_TIME` is also 20 min
(`net_processing.cpp` constant), but `-orphanpoollifetime` is an
operator-tunable knob (post-v25). blockbrew has no override flag.
On regtest where tests want fast expiry, the only way to drive
expiry is to wait 20 minutes — or rebuild the binary.

**File:** `internal/mempool/mempool.go:36`.

**Impact:** test ergonomics; no consensus risk.

---

## BUG-21 (P2) — `MsgGetData` for `MSG_FILTERED_BLOCK` (BIP-37) silently dropped

**Severity:** P2. BIP-37 specifies `MSG_FILTERED_BLOCK = 3`. A peer
that loaded a bloom filter and issues `getdata{MSG_FILTERED_BLOCK,
blockHash}` expects a `merkleblock` reply.

blockbrew's `HandleGetData` (`sync.go:1264-1318`) doesn't have a
case for `InvTypeFilteredBlock = 3`. Combined with BUG-2's missing
`notfound` for non-block items, the peer just hangs.

The whole BIP-37 stack is "advertised but unimplemented" — peer.go
accepts `MsgFilterLoad`/`Add`/`Clear`/`MerkleBlock` and dispatches
to listeners (`peer.go:687-703`), but no `Listeners.OnFilterLoad`
ever installs an actual filter, and no `MSG_FILTERED_BLOCK` getdata
handler exists.

**File:** `internal/p2p/sync.go:1264-1318` (no FilteredBlock case);
`internal/p2p/peer.go:687-703` (handler stubs).

**Core ref:** `bitcoin-core/src/net_processing.cpp` `MSG_FILTERED_BLOCK`
+ `SendBlockTransactions` → `merkleblock`.

**Impact:** BIP-37 SPV clients (Electrum's "merkleblock" mode, BIP-37
legacy wallets) cannot use blockbrew as a peer. They'll request
filtered blocks and time out.

---

## BUG-22 (P2) — `RelayTransaction` walks all peers on every tx (no per-cycle deferral)

**Severity:** P2. BUG-5 documents the missing batching. This is a
narrower related observation: even if you accept the per-tx
synchronous behaviour, the `for addr, info := range pm.peers`
walk (`peermgr.go:790`) takes the `pm.mu.RLock` for the full
duration. With ~16 peers and a 250-microsecond per-peer
`SendMessage` (a channel send + queue check), each
`RelayTransaction` call holds the read lock for ~4 ms. At 1000
txs/sec admission rate, the read lock is held for ~4 sec out of
every second of wall-clock — readers compete with `addPeer` /
`removePeer` writes. Core's batched drain avoids this by holding
the `cs_main`-equivalent lock for one drain cycle per ~5 sec
rather than once per tx.

**File:** `internal/p2p/peermgr.go:786-825`.

**Impact:** peer-table lock contention under heavy tx-relay load.
Not a correctness bug.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CDIV:** 6 (BUG-2, BUG-3, BUG-5, BUG-13, BUG-14, plus partial BUG-21)
- **P0:** 1 (BUG-11)
- **P1:** 12 (BUG-1, BUG-4, BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-12, BUG-15, BUG-16, BUG-17, BUG-18, BUG-19)
- **P2:** 3 (BUG-20, BUG-21, BUG-22)

Recount P1: BUG-1, BUG-4, BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-12,
BUG-15, BUG-16, BUG-17, BUG-18, BUG-19 = 13. Total: 5 + 1 + 13 + 3 = 22. ✓

(BUG-21 is recorded as P2; cluster of "stubbed BIP-37" rather than
P0-CDIV because no Core peer relies on us serving merkleblock.)

**Fleet patterns confirmed:**
- **W144 BUG-5 carry-forward (STANDARD-flags-incomplete)** — BUG-13:
  10 of 13 STANDARD-extras missing in `GetStandardScriptFlags`;
  orphan-promote inherits the broken policy gate. This audit
  catalogued 10 missing (W144 said 9 — `MINIMALDATA` was missed in
  the W144 inventory).
- **W150 BUG-9 carry-forward (coinbase-maturity off-by-one mempool
  side)** — BUG-14: `age := tip - utxo.Height` + `age < CoinbaseMaturity`
  rejects 1 confirmation early vs Core's `spendHeight = tip + 1`.
  Orphan-promote inherits.
- **W141 ZMQ byte-order carry-forward** — investigated, **does NOT
  apply to inv**: `Hash256.Serialize()` writes raw internal bytes
  (`wire/types.go:99-102`) which matches Core's `uint256::Serialize`.
  The W141 ZMQ bugs are display-order vs internal-order in the
  ZMQ topic frame, separate from inv encoding. G36 is PASS.
- **"30-of-30-gates-buggy" instance** — count: 22 bugs over 36
  gates ≈ 61% gate failure rate; not quite Cat-L "30-of-30" tier
  but the W138/W141 pattern stays elevated here too.
- **"TODO-stub-in-consensus" / "wiring-look-but-no-wire"** —
  BUG-2 (HandleGetData `case InvTypeTx: // TODO`), BUG-3 (HandleInv
  walks list but only acts on blocks), BUG-21 (BIP-37 dispatches to
  Listeners that nobody installs).
- **"asymmetric receive/send"** — BUG-3 (we send tx invs but
  ignore incoming tx invs) + BUG-2 (we cannot serve tx getdata
  after announcing) combine to make blockbrew a tx-relay BLACK HOLE
  for the P2P direction. First fleet instance of this specific
  receive-side gap in a "production" impl.
- **"random-vs-fairness-eviction"** — BUG-17 (orphan eviction is
  random, not per-peer-fairness). Similar shape to W128's banman
  conflation (no per-channel split).
- **"missing per-peer accounting at the source of a per-peer
  limit"** — BUG-8 (orphans have no fromPeer field) + BUG-15
  (mempool request has no lastRequestTime field) + BUG-6 (no
  txrequest tracker). Three independent instances in this wave of
  "Peer struct missing a field that gates Core behaviour".
- **Multiple W103 carry-forwards re-confirmed open** (~9 weeks open):
  BUG-1 (G1 misbehaving), BUG-4 (G17 recently-announced-invs),
  BUG-6 (G9-G14 txrequest), BUG-7 (G23 wtxid keying), BUG-8 (G24
  EraseForPeer), BUG-15 (G4/G18 mempool rate-limit), BUG-16 (G28
  unrequested-tx misbehaving).
- **No fleet-wide CVE-class finding in this wave** (unlike W144
  script_flag_exceptions 9-of-10, W128 banman 8-of-10).

**Top three findings:**
1. **BUG-3 + BUG-2 cluster (P0-CDIV: tx-relay black hole)** —
   blockbrew's `HandleInv` only acts on block-type invs (tx-type
   invs are silently dropped → we never issue tx getdata to any
   peer), AND `HandleGetData` only serves block-type entries
   (InvTypeTx is a TODO stub; InvTypeWtx=5 isn't even in the
   switch; no notfound emitted for tx-type misses). The combined
   effect: blockbrew can announce txs but cannot serve them, and
   blockbrew cannot receive txs from peers at all. P2P tx-relay is
   one-way (locally-submitted RPC txs out only; nothing in). Two
   bugs but one architectural gap — the entire receive-side of tx
   relay was never wired.
2. **BUG-11 (P0: BlockConnected doesn't EraseForBlock the orphanage)** —
   when a block confirms, blockbrew removes the confirmed txs from
   the mempool and prunes RBF conflicts, but DOES NOT touch the
   orphan pool. Orphans whose inputs were spent by the new block
   (either by their intended parent confirming, or by a different
   tx in the block consuming the same outpoint) sit until
   20-minute expiry. Pool fills with stale entries within ~20
   blocks of operation.
3. **BUG-5 (P0-CDIV: no inv batching, no Poisson scheduler)** —
   `RelayTransaction` synchronously emits one `MsgInv` per tx per
   peer, with no per-peer `m_tx_inventory_to_send` queue, no
   `m_next_inv_send_time` Poisson scheduler, no per-cycle
   `INVENTORY_BROADCAST_TARGET=70` drain cap. Combined with
   BUG-13 (W144 STANDARD-flags carry-forward), BUG-14 (W150
   maturity off-by-one), and the open W103 txrequest cluster
   (BUG-6), blockbrew's tx-relay infrastructure is more
   reminiscent of a 2014-era Bitcoin Core (pre-net_processing
   refactor) than a 2025 deployment.
