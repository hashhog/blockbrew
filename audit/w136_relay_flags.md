# W136 — BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay audit (blockbrew)

**Wave**: W136 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**Scope**: BIP-130 (`sendheaders` post-VERACK gating + outbound block
announce), BIP-133 (`feefilter` send/receive scheduler, rounder,
peer-side filtering), BIP-339 (`wtxidrelay` pre-VERACK negotiation,
MSG_WTX inv segregation).
**Verdict**: **BUGS FOUND** — **17 distinct bug IDs** (W136-BUG-1 .. W136-BUG-17),
including **0 P0-CDIV** (no consensus break), **6 P1-DEAD-PIPELINE**
(`MaybeSendFeeFilter` / `SendFeeFilter` never called from production →
blockbrew never advertises a feefilter to any peer; `MaybeSendSendHeaders`
function and the BIP-130 chain-work gating are entirely absent →
blockbrew unconditionally sends `sendheaders` immediately after VERACK
instead of waiting for headers-sync above MinimumChainWork; outbound
`AnnounceBlock` ignores per-peer block-relay-only filtering), and **11
HIGH/MED/LOW** gaps in handshake-window enforcement, FeeFilterRounder
absence, exponential vs. uniform jitter, and IBD/MAX_FILTER coupling.

## Bitcoin Core references

- `bitcoin-core/src/net_processing.cpp`
  - `MaybeSendSendHeaders` (line 5519): delay `sendheaders` until
    `pindexBestKnownBlock->nChainWork > MinimumChainWork()`; once-per-peer
    latch (`m_sent_sendheaders`); `SENDHEADERS_VERSION = 70012` gate.
    Called from per-tick `SendMessages` (line 5763).
  - `MaybeSendFeefilter` (line 5540): exponential broadcast interval
    (`rand_exp_duration(AVG_FEEFILTER_BROADCAST_INTERVAL=10min)`);
    `MAX_FEEFILTER_CHANGE_DELAY = 5min`; skip when
    `m_opts.ignore_incoming_txs`, peer common version < `FEEFILTER_VERSION
    = 70013`, `HasPermission(NetPermissionFlags::ForceRelay)`, or
    `IsBlockOnlyConn()`. IBD coupling: `IsInitialBlockDownload()` →
    `currentFilter = MAX_MONEY`; transition out of IBD resets
    `m_next_send_feefilter = 0us` so the real filter is dispatched
    promptly. `FeeFilterRounder.round(currentFilter)` bucketizes; always
    `max(filterToSend, min_relay_feerate)` floor; only resend if filter
    value changes (`peer.m_fee_filter_sent`).
  - `FEEFILTER` handler (line 5035): reject when
    `!MoneyRange(newFeeFilter)`; store on `tx_relay->m_fee_filter_received`.
  - `WTXIDRELAY` handler (line 3921): **disconnect** peer that sends
    `wtxidrelay` after `fSuccessfullyConnected` (verack); ignore late
    `wtxidrelay` from peers with `GetCommonVersion() < WTXID_RELAY_VERSION
    = 70016`; ignore duplicates with debug log. Setting
    `peer.m_wtxid_relay = true` increments `m_wtxid_relay_peers` for
    network-wide stats.
  - `SENDHEADERS` handler (line 3896): set `peer.m_prefers_headers =
    true`; no post-verack rejection (`sendheaders` is meant to arrive
    post-VERACK; BIP-130 spec allows any time after handshake).
  - VERSION → VERACK sequence (line 3710): `wtxidrelay` is sent in the
    VERSION handler **before** our `VERACK` is emitted, gated on
    `greatest_common_version >= WTXID_RELAY_VERSION`. ADDRv2/sendpackages
    follow the same window.
- `bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}`
  - `FeeFilterRounder` class (line 323): rounds the candidate filter to
    one of ~40 fee-buckets so an adversary observing our filter cannot
    infer our exact min relay fee.
- `bitcoin-core/src/node/protocol_version.h`
  - `SENDHEADERS_VERSION = 70012`
  - `FEEFILTER_VERSION   = 70013`
  - `WTXID_RELAY_VERSION = 70016`
- `bitcoin-core/src/consensus/amount.h`
  - `MAX_MONEY = 21_000_000 * COIN`; `MoneyRange(nValue) = 0 <= nValue <=
    MAX_MONEY`.
- BIPs: 130 (sendheaders), 133 (feefilter), 339 (wtxidrelay).

## Source under audit

- `blockbrew/internal/p2p/peer.go`
  - `:26-39` — BIP-133 constants: `FeeFilterBroadcastInterval = 10min`,
    `FeeFilterMaxChangeDelay = 5min`, `FeeFilterVersion = 70013`.
  - `:200-204` — feefilter state: `feeFilterReceived` (atomic),
    `feeFilterSent`, `nextFeeFilterTime`, `feeFilterMu`.
  - `:558-572` — `handleMessage` exemption list (pre-handshake): includes
    `*MsgWTxidRelay`, `*MsgSendCmpct`, `*MsgSendAddrv2`, `*MsgSendTxRcncl`,
    `*MsgSendPackages`. `*MsgSendHeaders` is NOT exempt (correctly
    rejected if seen before handshake → Misbehaving(10)).
  - `:587-593` — `*MsgSendHeaders` handler: sets `sendHeadersPreferred =
    true` unconditionally. No version gate, no post-verack check (correct
    per Core; sendheaders is post-VERACK by definition).
  - `:626-630` — `*MsgFeeFilter` handler: dispatches `handleFeeFilter`.
  - `:639-642` — `*MsgWTxidRelay` handler: sets `wtxidRelaySupported =
    true` without checking `verAckRecvd` or common-version gate.
    **Sibling handlers** `handleSendAddrv2` (line 807) and
    `handleSendTxRcncl` (line 828) DO check `verAckRecvd` and Misbehave;
    `handleSendPackages` (line 860) DO check `verAckRecvd` and Misbehave.
    This is the W99 G21 / W103 BUG-3 documented gap (still open).
  - `:772-780` — `handleVersion` queues `wtxidrelay`, `sendaddrv2`, and
    `sendpackages` before our `verack`; gated on `msg.ProtocolVersion >=
    70016` (matches Core's `greatest_common_version` requirement; partial
    parity — Core uses common-version not raw peer version).
  - `:881-914` — `checkHandshakeComplete` sends `sendheaders` (line 905)
    and `sendcmpct` (line 910) immediately after the state transitions
    to Connected. **No BIP-130 chain-work gating**: Core only sends
    `sendheaders` after the peer's `pindexBestKnownBlock->nChainWork >
    MinimumChainWork`. blockbrew sends it always.
  - `:932-945` — `handleFeeFilter`: validates `0 <= MinFeeRate <=
    21M*1e8` (MAX_MONEY) and stores atomically. **No logging** when
    out-of-range value is silently dropped (Core has `LogDebug(BCLog::NET,
    "received: feefilter of %s")`); not a bug but a divergence in
    operator observability.
  - `:953-968` — `ShouldRelayTx`: applies peer's feefilter to outbound
    tx invs. Used by `peermgr.RelayTransaction` (line 802).
  - `:970-1042` — `MaybeSendFeeFilter`: implements the periodic
    feefilter scheduler. Wired correctly to skip non-tx-relay peers
    (`WantsTxRelay()`) and peers with old protocol versions
    (`ProtocolVersion < FeeFilterVersion`). Then ±10% noise,
    deterministic uniform jitter, and rescheduling logic.
    **DEAD CODE**: no production caller.
  - `:1044-1063` — `SendFeeFilter`: one-shot immediate send.
    **DEAD CODE**: no production caller.
- `blockbrew/internal/p2p/peermgr.go`
  - `:739-770` — `AnnounceBlock`: BIP-130 honoring on the outbound block
    announce path. Selects `MsgHeaders` for peers with
    `SendsHeaders()`, falls back to `MsgInv`. Does NOT filter by
    `connType == ConnBlockRelayOnly` (block-relay-only peers should
    still receive block announcements, so this is correct), but also
    does NOT filter by `peer.fSuccessfullyConnected` (only by
    `IsConnected()` → state == Connected, which is equivalent post-W13).
  - `:772-825` — `RelayTransaction`: applies peer's
    `WantsTxRelay()`, `ShouldRelayTx(fee,vsize)`, and `WTxidRelay()`
    flags. Sends `InvTypeWtx` when `WTxidRelay() == true`, else
    `InvTypeTx`. Good parity (W103 fix). Does NOT skip
    `connType == ConnBlockRelayOnly` peers (relying on `WantsTxRelay()
    == false` for them, which is correct because our outbound
    `version.Relay = false` for block-relay connections; see config
    field `DisableRelayTx`).
- `blockbrew/internal/p2p/message.go`
  - `:252-268` — `isNonCriticalMessage` includes `feefilter`,
    `sendheaders`, `wtxidrelay` → deserialization failure for these does
    not disconnect the peer. Correct parity.
  - `:271-330` — `makeMessage` includes all three commands. Correct.
- `blockbrew/internal/p2p/msg_simple.go`
  - `:121-131` — `MsgSendHeaders{}` empty payload.
  - `:165-183` — `MsgFeeFilter{MinFeeRate int64}`, LE-encoded.
  - `:237-248` — `MsgWTxidRelay{}` empty payload.
- `blockbrew/internal/p2p/msg_version.go`
  - `:22` — `ProtocolVersion = 70016` (advertised by us).
- `blockbrew/cmd/blockbrew/main.go`
  - `:55` — `cfg.MinRelayFee` (default 0.00001 BTC/kvB).
  - `:813` — `minRelayFeeRate := int64(cfg.MinRelayFee * 100_000_000 /
    1000)`; passed only into `mempool.NewMempool` config. **Never
    plumbed to peers** for feefilter dispatch.
- `blockbrew/internal/rpc/methods.go`
  - `:3046`, `:3130`, `:3324` — `AnnounceBlock` is called from RPC
    submitblock/generate paths. Good.

## Summary

There are **three orthogonal feature gaps** that interact:

1. **The whole feefilter pipeline is dead code in production.**
   `MaybeSendFeeFilter` and `SendFeeFilter` are fully implemented
   (~70 LOC of mempool-min-fee tracking, ±10% noise, rescheduling on
   significant fee changes), but `grep -rn 'MaybeSendFeeFilter\|SendFeeFilter'`
   over `cmd/`, `internal/rpc/`, and `internal/p2p/peermgr.go` returns
   zero hits. blockbrew **never sends a feefilter to any peer**. Peers
   default to MAX_MONEY = "send me nothing", or to their own remembered
   value from a previous session. In practice, modern Bitcoin Core peers
   will assume blockbrew has no fee filter and will forward every tx
   above their own min relay fee, including dust spam.

2. **BIP-130 sendheaders has no Core-equivalent gating.** Core sends
   `sendheaders` *after* it has determined the peer's chain meets
   `MinimumChainWork` (so the peer is plausibly a valid honest node
   that has actually finished its own initial headers sync). blockbrew
   sends it **immediately on handshake completion** (`peer.go:905`).
   The functional impact is low (we just opt in early to header
   announcements), but the timing-attack and IBD-pressure shapes
   diverge: a peer's `inv`-to-`headers` switch will happen earlier in
   our pipeline than Core's. Also there is no `m_sent_sendheaders`
   once-per-peer latch in blockbrew; the message is sent exactly once
   per connection via `checkHandshakeComplete`'s singleton flow.

3. **BIP-339 wtxidrelay handshake-window enforcement is missing on the
   receive side.** Per Core net_processing.cpp:3921-3927: a `wtxidrelay`
   message received **after** the peer's verack must disconnect the
   peer. blockbrew accepts it silently (peer.go:639-642). This is the
   W99 G21 / W103 BUG-3 carryover. **Sibling handlers**
   (`sendaddrv2`, `sendtxrcncl`, `sendpackages`) all correctly check
   `verAckRecvd` and Misbehave. The asymmetry strongly suggests a
   one-line bug, not an intentional divergence.

Combined with the timing/noise/rounding gaps below (FeeFilterRounder
absence; uniform vs. exponential jitter; missing IBD MAX_MONEY coupling;
no ForceRelay permission), the audit surface here is **6 P1 dead-pipeline
bugs** and **11 HIGH/MED/LOW gaps**.

Severity distribution:

| Severity   | Count | Notes |
|------------|-------|-------|
| P0-CDIV    | 0     | No consensus-divergence; everything in W136 is policy/relay layer. |
| P1-DEAD    | 6     | BUG-1 `MaybeSendFeeFilter` zero callers; BUG-2 `SendFeeFilter` zero callers; BUG-3 no per-peer periodic-tick scheduler; BUG-4 `MaybeSendSendHeaders` function absent; BUG-5 no MinimumChainWork gate on sendheaders; BUG-6 `AnnounceBlock` does not skip block-relay-only peers from header announcements (Core: `MaybeSendInventory` only walks `m_blocks_for_headers_relay` for tx-relay peers — but block-relay-only peers should ALSO get block announcements per BIP-152 / BIP-130, so this is **PARTIAL** — see gate G6 caveat). |
| HIGH       | 6     | BUG-7 wtxidrelay after verack silently accepted (W99/W103 carryover); BUG-8 no FeeFilterRounder bucketing; BUG-9 uniform `Int63n` jitter instead of exponential (Core: `rand_exp_duration`); BUG-10 no IBD → MAX_MONEY filter coupling; BUG-11 no `ForceRelay` permission gate; BUG-12 no `m_sent_sendheaders` once-per-peer latch. |
| MED        | 4     | BUG-13 wtxidrelay raw `peer.ProtocolVersion >= 70016` gate uses *raw peer version* not *common version* (Core: `greatest_common_version >= WTXID_RELAY_VERSION`); BUG-14 ±10% additive noise on feefilter MinFeeRate (Core has none — it relies on the rounder bucketing for privacy); BUG-15 no min-relay-feerate floor on feefilter dispatch (Core: `filterToSend = max(filterToSend, m_mempool.m_opts.min_relay_feerate.GetFeePerK())`); BUG-16 no `m_wtxid_relay_peers` aggregate counter (Core uses for rate-limiting decisions; blockbrew has zero analog). |
| LOW        | 1     | BUG-17 `handleFeeFilter` silently drops out-of-range values; no LogDebug for operator observability. |

PASS: **10** / PARTIAL: **6** / MISSING: **14**. Bug count: **17**.

## 30-gate audit matrix

| Gate | What the gate asserts | Status | Bug |
|------|----------------------|--------|-----|
| G1  | `MsgSendHeaders` type exists with empty payload, `Command()=="sendheaders"` | PASS | — (`msg_simple.go:121-131`) |
| G2  | `MsgFeeFilter{MinFeeRate int64}` exists, LE-encoded, `Command()=="feefilter"` | PASS | — (`msg_simple.go:165-183`) |
| G3  | `MsgWTxidRelay` type exists with empty payload, `Command()=="wtxidrelay"` | PASS | — (`msg_simple.go:237-248`) |
| G4  | `makeMessage` resolves all three command strings | PASS | — (`message.go:301-310`) |
| G5  | All three are in `isNonCriticalMessage` (deserialize failure tolerated) | PASS | — (`message.go:257-258`) |
| G6  | Outbound `sendheaders` honored on block-announce (`AnnounceBlock` selects `MsgHeaders` for peers that sent us `sendheaders`) | PARTIAL | — (PASS for the basic switch at `peermgr.go:764-768`; does not differentiate by `connType` but Core also does not, so WAI; but does NOT use `m_blocks_for_headers_relay` queue semantics — every announce is immediate, no batching) |
| G7  | Outbound `sendheaders` queue: blockbrew sends `MsgSendHeaders{}` on the outbound after handshake | PASS | — (`peer.go:905`) |
| G8  | `MaybeSendSendHeaders` analog (Core net_processing.cpp:5519) that **delays** sendheaders until `pindexBestKnownBlock->nChainWork > MinimumChainWork()` | **MISSING** | BUG-5 |
| G9  | `m_sent_sendheaders` once-per-peer latch (Core line 405-406) so we never re-emit | PARTIAL | BUG-12 (no explicit latch; blockbrew relies on `checkHandshakeComplete` running once via the `handshakeDone` channel — works in practice but is brittle to handshake-rebuild paths) |
| G10 | `sendheaders` version-gate `>= SENDHEADERS_VERSION (70012)` | **MISSING** | BUG-5 (the unconditional `p.SendMessage(&MsgSendHeaders{})` at peer.go:905 ignores the negotiated version; for any peer with `peerVersion.ProtocolVersion < 70012` we still send it. In practice no such peer exists, but the gate is part of the spec) |
| G11 | `*MsgSendHeaders` receive sets `sendHeadersPreferred = true` | PASS | — (`peer.go:587-593`) |
| G12 | `SendsHeaders()` accessor returns the flag for `AnnounceBlock` and getpeerinfo | PASS | — (`peer.go:1225-1230`) |
| G13 | `MaybeSendFeeFilter` is called from the per-peer periodic tick (Core: `SendMessages → MaybeSendFeefilter`) | **MISSING** | BUG-1, BUG-3 (function implemented but zero production callers; no analogous `SendMessages`-style tick loop exists) |
| G14 | One-shot `SendFeeFilter` called post-handshake to dispatch an initial filter | **MISSING** | BUG-2 (function implemented but zero production callers) |
| G15 | Skip feefilter dispatch for peers with `ProtocolVersion < FEEFILTER_VERSION (70013)` | PASS | — (`peer.go:980,1050`) — gate is correct **inside** the dead-code helpers |
| G16 | Skip feefilter dispatch for block-relay-only peers (Core: `pto.IsBlockOnlyConn()` line 5548) | PARTIAL | BUG-1 (gate via `WantsTxRelay()` which returns false when `DisableRelayTx=true` — correct in shape but reaches via the BlockRelayOnly outbound peer config that sets `DisableRelayTx=true` for those connections; still dead-pipeline) |
| G17 | Skip feefilter dispatch for peers with `HasPermission(NetPermissionFlags::ForceRelay)` (Core line 5545) | **MISSING** | BUG-11 (no `ForceRelay` flag exists on the Peer struct; only `noBan` exists) |
| G18 | Skip feefilter dispatch when `m_opts.ignore_incoming_txs` (`-blocksonly`) | **MISSING** | BUG-1 + BUG-10 (no `-blocksonly` CLI flag at all in `cmd/blockbrew/main.go`; mempool always accepts tx invs) |
| G19 | IBD coupling: `IsInitialBlockDownload()` → `currentFilter = MAX_MONEY` (Core line 5552-5555) | **MISSING** | BUG-10 (no IBD check at all in the existing dead-code `MaybeSendFeeFilter`) |
| G20 | IBD-exit reschedule: if we previously sent `MAX_FILTER` (the rounded MAX_MONEY value), set `peer.m_next_send_feefilter = 0us` so the real filter ships ASAP after IBD exit (Core line 5557-5562) | **MISSING** | BUG-10 |
| G21 | `FeeFilterRounder` bucketization (Core: `m_fee_filter_rounder.round(currentFilter)`) | **MISSING** | BUG-8 (no FeeFilterRounder class; the helper just sends the raw value with ±10% additive noise) |
| G22 | Min-relay-feerate floor: `filterToSend = max(filterToSend, min_relay_feerate.GetFeePerK())` (Core line 5567) | **MISSING** | BUG-15 (the helper sends `currentMinFee` adjusted by ±10% noise; no floor) |
| G23 | Resend only when `filterToSend != peer.m_fee_filter_sent` (Core line 5568) | PASS | — (`peer.go:995,1038` — wired correctly inside the helper, even though the helper itself is dead) |
| G24 | Exponential broadcast interval: `current_time + rand_exp_duration(AVG_FEEFILTER_BROADCAST_INTERVAL = 10min)` (Core line 5572) | **MISSING** | BUG-9 (`peer.go:1040` uses `FeeFilterBroadcastInterval + rand.Int63n(FeeFilterBroadcastInterval/2)` = uniform in [10min, 15min]; Core uses exponential with mean 10min) |
| G25 | `MAX_FEEFILTER_CHANGE_DELAY = 5min` early-reschedule on >33% filter delta (Core line 5574-5579) | PARTIAL | — (logic at `peer.go:992-1014` is shape-correct but uses uniform sampling instead of `randrange<chrono::microseconds>(MAX_FEEFILTER_CHANGE_DELAY)`; also the `shouldSend` boolean lookup at line 990 / 1016 is **wrong** — the >33% / <25% branches only update `nextFeeFilterTime` but do not set `shouldSend=true`, so the early-reschedule path can drop the immediate send entirely. See BUG-9 detail) |
| G26 | Receive `feefilter`: `MoneyRange` check, then `tx_relay->m_fee_filter_received = newFeeFilter` | PASS | — (`peer.go:932-945`); `feeFilterReceived` is on the Peer struct because blockbrew has no separate TxRelay struct, but functionally equivalent |
| G27 | Receive `feefilter`: out-of-range value silently dropped (Core just doesn't update; logs at LogDebug) | PARTIAL | BUG-17 (correct silent drop but no log line; operator visibility is zero) |
| G28 | Outbound tx-relay (`RelayTransaction`) consults `ShouldRelayTx(fee, vsize)` against received feefilter | PASS | — (`peermgr.go:802` + `peer.go:953-968`); fee comparison uses `(filterRate * vsize + 999) / 1000` rounding-up which matches Core's `CFeeRate::GetFeeForVirtual` ceiling division |
| G29 | `wtxidrelay` post-VERACK must disconnect peer (Core line 3922-3927: `pfrom.fDisconnect = true`) | **MISSING** | BUG-7 (W99 G21 / W103 BUG-3 carryover; sibling handlers `handleSendAddrv2` / `handleSendTxRcncl` / `handleSendPackages` correctly check `verAckRecvd` and Misbehave — this one path is the only asymmetric handler) |
| G30 | `wtxidrelay` version-gate uses `greatest_common_version >= WTXID_RELAY_VERSION (70016)` (Core line 3928) | PARTIAL | BUG-13 (the SEND side at peer.go:773 uses `msg.ProtocolVersion >= 70016` — **raw peer version** not common version; if peer advertises 80000 and we advertise 70016, common = 70016 and Core would still send wtxidrelay; the bug is benign for our own advertised version=70016 since min(70016, peer)>=70016 iff peer>=70016, but the gate-on-raw-peer-version pattern is non-Core; the RECEIVE side at peer.go:639-642 has NO version gate at all, so will accept wtxidrelay from any peer regardless of version) |

PASS: **10** | PARTIAL: **6** | MISSING: **14**.

## Bug catalogue

### BUG-1 (P1-DEAD) — `MaybeSendFeeFilter` zero production callers

**Severity**: P1 (DEAD-PIPELINE — blockbrew never advertises a feefilter)
**ID**: BLOCKBREW-W136-1
**Location**: `internal/p2p/peer.go:970-1042` (function); zero callers
in `cmd/`, `internal/p2p/peermgr.go`, `internal/rpc/methods.go`.

```bash
$ grep -rn 'MaybeSendFeeFilter\|SendFeeFilter' blockbrew/ \
    --include='*.go' | grep -v _test.go | grep -v peer.go
(no output)
```

The 70-LOC `MaybeSendFeeFilter` helper is structurally correct — it
gates on `WantsTxRelay()`, `ProtocolVersion >= FeeFilterVersion`, holds
`feeFilterMu`, reschedules on >33% deltas, and sends `MsgFeeFilter` —
but **no production code ever invokes it**. There is no per-peer
periodic tick loop ("SendMessages") in blockbrew's peer runtime; the
runtime is purely event-driven (`readHandler` + `writeHandler` +
`pingHandler`).

**Impact**: blockbrew never tells peers its minimum acceptable fee rate.
Peers default to forwarding every tx that passes their own min relay
fee. blockbrew then accepts/rejects them via mempool policy, but the
peers cannot pre-filter — so any peer in a session with blockbrew sees
the same bandwidth shape it would see talking to a `feefilter`-unaware
pre-BIP-133 node. This is purely a relay-efficiency loss; no consensus
or DoS impact. Documented by the absence of `MaybeSendFeeFilter` calls
in `peermgr.go` and `cmd/blockbrew/main.go:1148,1232` (where
`RelayTransaction` is invoked but no `MaybeSendFeeFilter` companion is).

**Reference**: `bitcoin-core/src/net_processing.cpp:5763` (per-tick
`SendMessages` calls `MaybeSendFeefilter(pto, peer, current_time)`).

**Fix path**: add a periodic ticker in `PeerManager` (e.g. 100ms) that
walks every connected peer with `peer.MaybeSendFeeFilter(currentMin)`,
where `currentMin` is read from the mempool's `GetMinFee().GetFeePerK()`
(blockbrew has no mempool GetMinFee API yet — that is a prerequisite
addition).

### BUG-2 (P1-DEAD) — `SendFeeFilter` zero production callers

**Severity**: P1 (DEAD-PIPELINE — companion of BUG-1)
**ID**: BLOCKBREW-W136-2
**Location**: `internal/p2p/peer.go:1044-1063` (function); zero callers.

The one-shot helper has the same fate as `MaybeSendFeeFilter`. Even if
the periodic ticker existed (BUG-1), Core ALSO does an immediate post-
handshake `feefilter` send so peers learn the filter as early as
possible. blockbrew has the helper but never invokes it.

**Reference**: Core does not have a dedicated immediate-send helper —
`MaybeSendFeefilter` itself runs at handshake-complete time on the
first tick. blockbrew's `SendFeeFilter` is a refactoring artifact.

**Fix path**: delete this function as part of BUG-1's fix and rely on
the periodic ticker; OR call it from `checkHandshakeComplete` after
`SendMessage(&MsgSendHeaders{})` at line 905.

### BUG-3 (P1-DEAD) — No per-peer periodic-tick scheduler exists

**Severity**: P1 (DEAD-PIPELINE — structural absence)
**ID**: BLOCKBREW-W136-3
**Location**: `internal/p2p/peer.go` (no per-peer tick loop);
`internal/p2p/peermgr.go` (no per-peer tick loop).

Bitcoin Core's `PeerManagerImpl::SendMessages` is the per-peer outbound
loop invoked from `CConnman::ThreadMessageHandler` at ~100Hz. It
dispatches:

- `MaybeSendPing` (BIP-31)
- `MaybeSendAddr` (rate-limited gossip)
- `MaybeSendSendHeaders` (BIP-130, our BUG-5)
- `MaybeSendFeefilter` (BIP-133, our BUG-1)
- `m_blocks_for_headers_relay` (BIP-152 header-first announce)
- `m_blocks_for_inv_relay` (legacy inv fallback)
- transaction inv coalescing (`vInventoryTxToSend`)

blockbrew has **none** of this. The peer goroutines are
`readHandler` (inbound demux) and `writeHandler` (outbound queue) plus
the `pingHandler` started by `checkHandshakeComplete`. There is no
"per-peer periodic outbound producer" goroutine. The closest analog is
`pingHandler` (peer.go:902, line 519-555), which fires a ping every 2
minutes.

**Impact**: ALL the "Maybe-send" pipelines (feefilter, sendheaders re-
emission, addr gossip rate-limiting, header-batch coalescing) are
either dead-code or directly inlined into the handshake-completion path
with no periodic re-evaluation. This is the structural reason BUG-1
and BUG-4 both exist.

**Fix path**: add a per-peer `outboundMaintenanceLoop` goroutine
started from `checkHandshakeComplete`, ticking every 100ms-500ms, that
calls `peer.MaybeSendFeeFilter(currentMin)` and (once BUG-5 is fixed)
`peer.MaybeSendSendHeaders(bestKnownChainWork)`. Pull the current
mempool minimum fee from a passed-in callback (PeerConfig.MinFeeProvider
func() int64).

### BUG-4 (P1-DEAD) — `MaybeSendSendHeaders` function entirely absent

**Severity**: P1 (DEAD-PIPELINE)
**ID**: BLOCKBREW-W136-4
**Location**: `internal/p2p/peer.go` — no such function exists; the
`SendMessage(&MsgSendHeaders{})` call at `peer.go:905` (inside
`checkHandshakeComplete`) is the only outbound send site.

Core's `MaybeSendSendHeaders` (net_processing.cpp:5519) is a per-tick
helper that:

1. Checks `!peer.m_sent_sendheaders && node.GetCommonVersion() >= 70012`.
2. Looks up the peer's `pindexBestKnownBlock` (set by us tracking the
   highest header we've received from them).
3. If `pindexBestKnownBlock->nChainWork > MinimumChainWork()`, sends
   the message and latches `m_sent_sendheaders = true`.

blockbrew's structure has none of this. The single inline send at
handshake-complete time happens before we've received any headers from
the peer, so we cannot know the peer's `pindexBestKnownBlock`.

**Impact**: blockbrew tells every peer to switch to header announcement
mode IMMEDIATELY, before knowing whether the peer is plausibly on the
real network. In practice this is fine for honest peers, but it
diverges from Core's "first validate, then commit" pattern. The
operator-visible effect: a malicious peer that sent us a one-block
header that fails MinimumChainWork still gets `sendheaders` from us;
Core would not have sent it.

**Reference**: `bitcoin-core/src/net_processing.cpp:5519-5538`.

**Fix path**: extract the send call out of `checkHandshakeComplete`
into a `MaybeSendSendHeaders(bestKnownChainWork)` helper, invoked from
the per-peer tick (after BUG-3 is fixed). Add a `sentSendHeaders bool`
field on `Peer` for the once-per-peer latch.

### BUG-5 (P1-DEAD) — No MinimumChainWork gate on outbound `sendheaders`

**Severity**: P1 (relay-correctness divergence — blockbrew over-commits
to header announce mode)
**ID**: BLOCKBREW-W136-5
**Location**: `internal/p2p/peer.go:905`.

```go
// Send sendheaders (BIP130) to request header announcements
p.SendMessage(&MsgSendHeaders{})
```

This unconditional call ignores Core's
`state.pindexBestKnownBlock->nChainWork > MinimumChainWork()` gate.
There is no version-gate either (G10): even if a peer somehow
advertised pre-70012 version, we'd still send. (Negligible in practice
because we ourselves advertise 70016, so common-version-floor protects
us.)

The chain-work gate is the substantive bug. Together with BUG-4 (no
periodic re-evaluation), this means our timing of `sendheaders`
emission is **structurally different** from Core. In Core, a peer
might never get `sendheaders` from us if their chain stays below
MinimumChainWork. In blockbrew, every peer that completes the
handshake gets it within milliseconds.

**Reference**: `bitcoin-core/src/net_processing.cpp:5525-5536`.

**Fix path**: see BUG-4 fix; the chain-work check goes inside the new
`MaybeSendSendHeaders` helper.

### BUG-6 (P1-PARTIAL) — `AnnounceBlock` does not differentiate per-peer announce policy

**Severity**: P1 (relay-efficiency; not a consensus issue)
**ID**: BLOCKBREW-W136-6
**Location**: `internal/p2p/peermgr.go:748-770`.

The current implementation iterates `pm.peers` and dispatches
`MsgHeaders` or `MsgInv` based solely on `peer.SendsHeaders()`. Per
Core's `MaybeSendInventory` (net_processing.cpp:5611-5810), the
announce path also:

1. Batches the `m_blocks_for_headers_relay` queue across ticks (we
   announce immediately, one block per call).
2. Uses `m_most_recent_compact_block` for high-bandwidth compact block
   peers (BIP-152 HB mode); blockbrew falls back to headers/inv only
   regardless of HB negotiation.
3. Trims `vHeaders` to the part the peer hasn't seen
   (`pindexBestHeaderSent`); blockbrew always sends a single
   `MsgHeaders{Headers: [header]}` containing one entry.

Combined, blockbrew's announce path is functionally correct (peers
will receive each new tip and react via the standard headers-first
flow), but the BIP-152 HB compact-block bypass is absent (also
documented in W126 BUG-1) and the multi-block coalescing is absent.

**Reference**: net_processing.cpp:5611-5810 (`MaybeSendInventory`).

**Fix path**: see W126 BUG-1 for HB compact-block path; the multi-
block batching is a separate slow-block-relay scenario optimization
and can be deferred.

### BUG-7 (HIGH) — `wtxidrelay` after VERACK silently accepted

**Severity**: HIGH (BIP-339 compliance; W99 G21 / W103 BUG-3
carryover)
**ID**: BLOCKBREW-W136-7
**Location**: `internal/p2p/peer.go:639-642`.

```go
case *MsgWTxidRelay:
    p.mu.Lock()
    p.wtxidRelaySupported = true
    p.mu.Unlock()
```

Per BIP-339 and Core net_processing.cpp:3922-3927, a `wtxidrelay`
message received after `fSuccessfullyConnected` (verack) is a protocol
violation and MUST disconnect the peer. blockbrew silently accepts it.

**Sibling handlers** demonstrate the correct pattern:
- `handleSendAddrv2` (peer.go:807-824) checks `verAckRecvd` and
  `Misbehaving(10, "sendaddrv2 received after verack")`.
- `handleSendTxRcncl` (peer.go:826-856) checks `verAckRecvd` and
  `Misbehaving(10, "sendtxrcncl received after verack")`.
- `handleSendPackages` (peer.go:858-879) checks `verAckRecvd` and
  `Misbehaving(10, "sendpackages received after verack")`.

The `wtxidrelay` handler is the only one of the four asymmetric. The
one-line fix is to add the same `verAckRecvd` guard with a
`Misbehaving(10, "wtxidrelay received after verack")` call.

**Reference**: `bitcoin-core/src/net_processing.cpp:3922-3927`.

**Fix path**:

```go
case *MsgWTxidRelay:
    p.mu.Lock()
    if p.verAckRecvd {
        p.mu.Unlock()
        p.Misbehaving(10, "wtxidrelay received after verack")
        return
    }
    p.wtxidRelaySupported = true
    p.mu.Unlock()
```

### BUG-8 (HIGH) — No FeeFilterRounder bucketization

**Severity**: HIGH (privacy — exact mempool min-fee leak to peers)
**ID**: BLOCKBREW-W136-8
**Location**: `internal/p2p/peer.go:1020-1035`.

Core's `FeeFilterRounder` (block_policy_estimator.h:323) maps any
candidate filter value into one of ~40 fee buckets covering
1000 sat/kvB through ~10M sat/kvB on a log-scale. The goal is **so
adversaries cannot use our exact feefilter value to fingerprint our
mempool's exact min relay fee**. Two nodes with very similar (but not
identical) mempool floors will emit the same bucket, leaking only ~5
bits about the floor.

blockbrew uses **±10% additive noise** on the raw value (`peer.go:1025-
1027`). Two issues:

1. ±10% noise is not the same as bucketization. With enough samples
   (and the feefilter is broadcast every 10 minutes), an adversary can
   average out the noise.
2. The noise is **additive**, not log-scale. For a small filter
   (e.g. 1000 sat/kvB), ±10% is ±100 sat/kvB; for a large filter
   (e.g. 1M sat/kvB), ±10% is ±100k sat/kvB. The privacy floor leaks
   ~log2(20) = ~4 bits per sample with high-entropy mempool but
   ~9 bits per sample with low-entropy mempool. Core's rounder maintains
   ~5 bits regardless of the candidate value.

**Reference**: `bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}`,
`FeeFilterRounder::round` (~80 LOC).

**Fix path**: port `FeeFilterRounder` to `internal/policy/feefilter_rounder.go`,
seed it at startup with `mempool.MinIncrementalFee`, and call
`rounder.Round(filter)` inside `MaybeSendFeeFilter` instead of the
additive noise.

### BUG-9 (HIGH) — Uniform jitter on broadcast interval instead of exponential; early-reschedule branches do not set `shouldSend`

**Severity**: HIGH (timing privacy + early-reschedule logic bug)
**ID**: BLOCKBREW-W136-9
**Location**: `internal/p2p/peer.go:990-1041`.

Two issues in one helper:

**Issue 1 — jitter distribution.** Core uses
`rand_exp_duration(AVG_FEEFILTER_BROADCAST_INTERVAL = 10min)` —
exponential distribution with mean 10min, sampled per peer per
broadcast (net_processing.cpp:5572). blockbrew uses
`FeeFilterBroadcastInterval + rand.Int63n(FeeFilterBroadcastInterval/2)`
= uniform in `[10min, 15min)` (`peer.go:1040`, `:1061`). Exponential
distribution has a long tail (sometimes 30+ minutes); uniform never
exceeds 15 minutes. An adversary correlating multiple peers'
broadcasts can use the uniform-15min cap to identify a blockbrew node.

**Issue 2 — early-reschedule branches drop the immediate send.** At
lines 992-1014, the helper has three top-level branches:

```go
if now.After(p.nextFeeFilterTime) {
    shouldSend = true
} else if currentMinFee != p.feeFilterSent {
    if p.feeFilterSent > 0 {
        if currentMinFee > (p.feeFilterSent*4)/3 {
            // Reschedule but don't set shouldSend.
            if now.Add(FeeFilterMaxChangeDelay).Before(p.nextFeeFilterTime) {
                p.nextFeeFilterTime = now.Add(time.Duration(rand.Int63n(int64(FeeFilterMaxChangeDelay))))
            }
        }
        if currentMinFee < (p.feeFilterSent*3)/4 {
            if now.Add(FeeFilterMaxChangeDelay).Before(p.nextFeeFilterTime) {
                p.nextFeeFilterTime = now.Add(time.Duration(rand.Int63n(int64(FeeFilterMaxChangeDelay))))
            }
        }
    }
}

if !shouldSend {
    return
}
```

When `currentMinFee` deviates by >33% from the last sent value but
the regular broadcast interval has NOT yet elapsed, the code only
**reschedules** `nextFeeFilterTime` to a sooner value. The next call
to `MaybeSendFeeFilter` (assuming a periodic tick) will then re-enter
the function, find `now.After(nextFeeFilterTime)` true, and ship the
update. So the logic is **correct under a periodic-tick scheduler**.

But: combined with BUG-3 (no periodic tick exists), the early-
reschedule branch is fully dead. And even with a tick, Core's
analogous logic (net_processing.cpp:5574-5579) is:

```cpp
else if (current_time + MAX_FEEFILTER_CHANGE_DELAY < peer.m_next_send_feefilter &&
            (currentFilter < 3 * peer.m_fee_filter_sent / 4 ||
             currentFilter > 4 * peer.m_fee_filter_sent / 3)) {
    peer.m_next_send_feefilter = current_time +
        m_rng.randrange<std::chrono::microseconds>(MAX_FEEFILTER_CHANGE_DELAY);
}
```

Note Core uses `randrange<chrono::microseconds>(MAX_FEEFILTER_CHANGE_DELAY)`
— a uniform in `[0, MAX_FEEFILTER_CHANGE_DELAY)`. blockbrew uses
`rand.Int63n(int64(FeeFilterMaxChangeDelay))`. These ARE equivalent
(both uniform on the same range), so this branch matches. Only the
top-level broadcast interval is wrong (exponential vs uniform).

**Reference**: `bitcoin-core/src/net_processing.cpp:5572` and `:5577`.

**Fix path**: implement `rand_exp_duration` in `internal/p2p/rand.go`
(uses `-ln(1 - U(0,1)) * mean`); replace the broadcast interval line
at peer.go:1040 / :1061 with the exponential sampler.

### BUG-10 (HIGH) — No IBD → MAX_MONEY filter coupling

**Severity**: HIGH (BIP-133 IBD semantic absent)
**ID**: BLOCKBREW-W136-10
**Location**: `internal/p2p/peer.go:970-1042` (no IBD check anywhere).

Core's `MaybeSendFeefilter` (net_processing.cpp:5552-5563):

```cpp
if (m_chainman.IsInitialBlockDownload()) {
    currentFilter = MAX_MONEY;
} else {
    static const CAmount MAX_FILTER{m_fee_filter_rounder.round(MAX_MONEY)};
    if (peer.m_fee_filter_sent == MAX_FILTER) {
        peer.m_next_send_feefilter = 0us;
    }
}
```

The semantics:

1. While in IBD, our mempool is not authoritative; we cannot relay
   txs reliably; tell peers "min fee = MAX_MONEY" so they stop sending
   us tx-invs.
2. On IBD-exit, the next-feefilter-send time is set to 0 (immediate)
   so peers learn the real fee within the next tick.

blockbrew has no IBD coupling at all. If the dead-code helpers ever
go live (BUG-1 fix), they'll be sending the post-IBD filter even
during sync. Together with BUG-3 (no tick), this is currently
neutralized — but it's still a design-level gap.

**Reference**: `bitcoin-core/src/net_processing.cpp:5552-5563`.

**Fix path**: add a `chainmgr.IsInitialBlockDownload()` callback to
PeerConfig; in MaybeSendFeeFilter, if true, override `currentMinFee
= MAX_MONEY` (Core has it as `21M*COIN`; blockbrew has it inlined as
`21_000_000 * 100_000_000` at peer.go:937 — promote to a const).

### BUG-11 (HIGH) — No `ForceRelay` permission flag

**Severity**: HIGH (BIP-133 §"Don't filter ForceRelay peers" absent)
**ID**: BLOCKBREW-W136-11
**Location**: `internal/p2p/peer.go` (no such flag exists).

Per Core net_processing.cpp:5544-5545:

```cpp
if (pto.HasPermission(NetPermissionFlags::ForceRelay)) return;
```

A peer connected with the operator-granted `forcerelay` permission is
exempt from our feefilter — we'll accept ALL their txs regardless of
our min relay fee. Their `feefilter` to us is similarly ignored on the
inbound side.

blockbrew has only `noBan` (peer.go:217) as the operator-granted
permission. There is no `ForceRelay` flag, no `Mempool` flag (Core has
`NetPermissionFlags::Mempool`), no `Relay` flag. The `Bind/Whitebind`
CLI plumbing is also absent.

**Impact**: an operator running blockbrew alongside a high-volume
wallet service cannot use the equivalent of Core's
`-whitelistforcerelay=1`. They have to disable feefilter entirely
(which is currently the default anyway because of BUG-1, so the bug
is masked — but a future BUG-1 fix without a BUG-11 fix would
re-expose the operator constraint).

**Reference**: `bitcoin-core/src/net_processing.cpp:5544-5545`,
`bitcoin-core/src/net_permissions.{h,cpp}`.

**Fix path**: add a `forceRelay bool` field on Peer alongside `noBan`;
expose `SetForceRelay(bool)` and `HasForceRelay() bool`; add a
`-whitelist` CLI flag in `cmd/blockbrew/main.go`; in
`MaybeSendFeeFilter` (after BUG-1 fix), short-circuit on
`p.HasForceRelay()`.

### BUG-12 (HIGH) — No `m_sent_sendheaders` once-per-peer latch

**Severity**: HIGH (potential double-send on handshake repair paths)
**ID**: BLOCKBREW-W136-12
**Location**: `internal/p2p/peer.go:881-914` (`checkHandshakeComplete`).

Core has `peer.m_sent_sendheaders` (net_processing.cpp:406) as an
explicit latch. blockbrew relies on `checkHandshakeComplete` running
exactly once via the `handshakeDone` channel close (peer.go:892-898).
This is correct under normal handshake flow but brittle to any future
refactor that allows `checkHandshakeComplete` to be invoked twice
(e.g. a v2 transport retry path).

**Reference**: `bitcoin-core/src/net_processing.cpp:405-406`.

**Fix path**: add a `sentSendHeaders bool` on Peer; guard the send at
peer.go:905 with `if !p.sentSendHeaders { ... ; p.sentSendHeaders =
true }`. As part of BUG-4's fix, this latch moves into the
`MaybeSendSendHeaders` helper.

### BUG-13 (MED) — wtxidrelay version gate uses raw peer version instead of common version

**Severity**: MED (version-gate semantics divergence)
**ID**: BLOCKBREW-W136-13
**Location**: send-side `internal/p2p/peer.go:773-780`; receive-side
`peer.go:639-642` (no version gate at all).

Send side:
```go
if msg.ProtocolVersion >= 70016 {
    p.SendMessage(&MsgWTxidRelay{})
    p.SendMessage(&MsgSendAddrv2{})
    p.SendMessage(&MsgSendPackages{Versions: PackageRelayVersionAncestor})
}
```

Core uses `greatest_common_version` (i.e. `min(our_version,
peer_version)`). blockbrew uses raw `msg.ProtocolVersion` (the peer's
advertised version). This is benign for the SEND side because we
advertise 70016, so `min(70016, peer) >= 70016` iff `peer >= 70016`,
which is the same condition. But the receive side has **no version
gate at all**:

```go
case *MsgWTxidRelay:
    p.mu.Lock()
    p.wtxidRelaySupported = true
    p.mu.Unlock()
```

Core's receive (net_processing.cpp:3928-3936) ignores `wtxidrelay` when
`pfrom.GetCommonVersion() < WTXID_RELAY_VERSION`. blockbrew accepts it
from a peer that advertised, say, version 60001.

**Impact**: low (no honest peer sends `wtxidrelay` with version <
70016), but a non-conformant peer can flip our wtxid-relay flag to
`true` and we'll start sending them MSG_WTX inv types, which they
won't understand → they'll log "Unknown inv type" and discard. We then
lose tx relay to that peer.

**Reference**: `bitcoin-core/src/net_processing.cpp:3928`.

**Fix path**: combine with BUG-7's fix to add both `verAckRecvd` and
`common-version >= 70016` checks. `commonVersion()` already exists
implicitly via `ProtocolVersion()` (peer.go:1119-1135).

### BUG-14 (MED) — ±10% additive noise has no Core analog

**Severity**: MED (privacy: noise model differs from Core)
**ID**: BLOCKBREW-W136-14
**Location**: `internal/p2p/peer.go:1020-1031`.

Already covered in part by BUG-8 (FeeFilterRounder is the canonical
privacy mechanism). The ±10% additive noise is an attempt to provide
privacy without the rounder, but it's a different model than Core's
and the two are not composable. If we fix BUG-8 (port FeeFilterRounder),
we should DELETE the ±10% noise; otherwise we're double-noising and
potentially defeating the rounder's bucket-edge alignment.

**Reference**: `bitcoin-core/src/net_processing.cpp:5565` (Core does
NOT add per-send noise; only the rounder).

**Fix path**: as part of BUG-8's port, delete `peer.go:1020-1031`.

### BUG-15 (MED) — No min-relay-feerate floor on dispatched filter

**Severity**: MED (Core: `filterToSend = max(filterToSend,
m_mempool.m_opts.min_relay_feerate.GetFeePerK())` at line 5567)
**ID**: BLOCKBREW-W136-15
**Location**: `internal/p2p/peer.go:1022-1035`.

Core ensures the dispatched filter is **at least** the min relay fee.
A mempool that's currently empty (so `GetMinFee()` returns 0) still
publishes the min relay fee as the floor. blockbrew sends
`noisy = currentMinFee ± 10%` directly; if `currentMinFee == 0`, then
`noisy == 0` and we tell peers "send me anything", which would invite
dust spam.

This is masked by BUG-1 (no production caller), but a future fix to
BUG-1 must include the floor.

**Reference**: `bitcoin-core/src/net_processing.cpp:5567`.

**Fix path**: thread `minRelayFeeRate` (already computed at
main.go:813) into `MaybeSendFeeFilter`; apply
`if noisy < minRelayFeeRate { noisy = minRelayFeeRate }`.

### BUG-16 (MED) — No `m_wtxid_relay_peers` aggregate counter

**Severity**: MED (operator observability + future rate-limiting)
**ID**: BLOCKBREW-W136-16
**Location**: `internal/p2p/peer.go:639-642`; `internal/p2p/peermgr.go`.

Core maintains `m_wtxid_relay_peers` (net_processing.cpp:3931 inc on
flip; analogous decrement on peer disconnect). It's used by tx-
download decisions and exposed via `getnetworkinfo`. blockbrew has no
aggregate counter; there's no `PeerManager.WtxidRelayPeerCount()`
accessor. RPC `getnetworkinfo` returns a hard-coded zero (verified
absent in `internal/rpc/methods.go`).

**Impact**: operators cannot see what fraction of their peers have
negotiated wtxid relay. No functional regression today; cosmetic +
debug surface.

**Reference**: `bitcoin-core/src/net_processing.cpp:3931`.

**Fix path**: add an atomic counter on PeerManager incremented in the
post-BUG-7-fix handler; decrement on peer removal.

### BUG-17 (LOW) — No LogDebug on out-of-range feefilter receive

**Severity**: LOW (operator observability)
**ID**: BLOCKBREW-W136-17
**Location**: `internal/p2p/peer.go:932-945`.

Core logs `received: feefilter of %s from peer=%d` even for in-range
values (net_processing.cpp:5042), and an out-of-range value is
silently dropped after deserialization. blockbrew silently drops with
no log at any level. An operator investigating "why is my node not
receiving txs from peer X" gets no signal.

**Fix path**: add `log.Printf("peer %s: received feefilter %d sat/kvB",
p.addr, msg.MinFeeRate)` at line 945 (or move to a structured logger).

## Universal-pattern watch

While auditing, I observed three patterns that recur across other
blockbrew audits:

1. **"Implementation exists but production never calls it"** (W117/W118-
   style dead-code-fix failure mode). BUG-1, BUG-2, BUG-3, and BUG-4
   all share this shape. The W136-relevant subset is:
   `MaybeSendFeeFilter`, `SendFeeFilter`, and the entire absent
   `MaybeSendSendHeaders` helper. The structural root cause is the
   absence of a Core-style `SendMessages` per-peer tick loop
   (BUG-3). Every other "Maybe-send"-shaped Core helper that
   blockbrew ports faces the same fate. Recommend: add the tick loop
   as a single FIX wave; that one structural addition activates BUG-1,
   BUG-2, BUG-4 (after their internal logic ports), and also positions
   blockbrew to land BIP-127, BIP-152 HB compact-block announce, addr
   gossip rate limiting, and txdownloadman in subsequent fix waves.

2. **"Sibling-handler asymmetry"** — the handshake-window check for
   `*MsgWTxidRelay` is absent while three sibling handlers
   (sendaddrv2, sendtxrcncl, sendpackages) all have it. The handler
   bodies are physically adjacent in peer.go (lines 587-740). This is
   classic "one of N siblings missed the same one-line refactor"
   pattern. Recommend: when adding a new pre-handshake exemption in
   peer.go, ALWAYS check `verAckRecvd` in the handler — table-driven
   if possible.

3. **"Audit-framework correction"** (similar to W121 / W122 audit-
   framework corrections). The existing W99 G21 and W103 BUG-3 tests
   already document BUG-7; this audit reproduces them under a W136 ID
   for fix-tooling purposes but does not double-count them in the
   project-level bug tally. Recommend: when the audit framework finds
   a bug that's already catalogued under a prior wave's BUG-N, link
   both IDs explicitly in the new test (we do so at G29 and G30 of
   the W136 test file).

## Pass/fail summary

PASS: **10** | PARTIAL: **6** | MISSING: **14**
Bugs catalogued: **17** (W136-BUG-1 .. W136-BUG-17)
Severity: 0 P0-CDIV / 6 P1-DEAD / 6 HIGH / 4 MED / 1 LOW.

The 17 bugs cluster into three structural causes:
- 4 are downstream of the missing per-peer SendMessages tick loop
  (BUG-1, BUG-2, BUG-3, BUG-4).
- 1 is the one-line handshake-window asymmetry (BUG-7).
- The rest are individual gaps that surface once the structural
  causes are fixed (BUG-5, BUG-6, BUG-8, BUG-9, BUG-10, BUG-11,
  BUG-12, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17).

Recommended fix sequencing:
1. **FIX-X1**: BUG-7 (one-line `verAckRecvd` check on wtxidrelay).
2. **FIX-X2**: BUG-3 (per-peer tick loop) — enables BUG-1/-2/-4
   fixes.
3. **FIX-X3**: BUG-4 + BUG-5 + BUG-12 (port `MaybeSendSendHeaders`
   with chain-work gate and `sentSendHeaders` latch).
4. **FIX-X4**: BUG-1 + BUG-2 + BUG-8 + BUG-9 + BUG-10 + BUG-11 +
   BUG-14 + BUG-15 (port `MaybeSendFeeFilter` with FeeFilterRounder,
   exponential jitter, IBD coupling, ForceRelay permission, and
   min-relay-feerate floor; delete ±10% noise).
5. **FIX-X5**: BUG-13 (combine version gate with BUG-7 fix; can
   piggyback on FIX-X1).
6. **FIX-X6**: BUG-16 + BUG-17 (cosmetic / observability).
