# W134 — BIP-37 Bloom Filter (legacy SPV) audit (blockbrew)

**Wave**: W134 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**Scope**: filterload / filteradd / filterclear / merkleblock /
MSG_FILTERED_BLOCK; NODE_BLOOM service bit; PartialMerkleTree
construction; BIP-37 / BIP-111 historical behavior. Core kept the
serving code (still active behind `-peerbloomfilters=1` in 28.x).

**Verdict**: **BUGS FOUND** — 19 distinct bug IDs (BUG-1 .. BUG-19).
BIP-37 is **deprecated for serving** (Core's default `-peerbloomfilters=false`),
so blockbrew's "intentionally not served" shape is broadly acceptable.
However, blockbrew partially exposes the messages, partially gates them,
and silently drops them rather than the Core-spec "disconnect when peer
sends bloom messages and NODE_BLOOM not advertised". The shape is
"half-implemented" rather than "intentionally not served". Several bugs
are real CDIV-class behaviors (peer-disconnect-on-violation absent),
several are documentation/consistency drift, and the bulk are MISSING
sub-systems (CBloomFilter itself, per-peer filter state, MSG_FILTERED_BLOCK
in HandleGetData, BLOOM_UPDATE_MASK constant, etc.).

**Bitcoin Core references**:

- `bitcoin-core/src/common/bloom.h` (L17-31, L44-81, L108-126)
  - `MAX_BLOOM_FILTER_SIZE = 36000`, `MAX_HASH_FUNCS = 50`
  - `bloomflags` enum (`BLOOM_UPDATE_NONE = 0`, `BLOOM_UPDATE_ALL = 1`,
    `BLOOM_UPDATE_P2PUBKEY_ONLY = 2`, `BLOOM_UPDATE_MASK = 3`)
  - `CBloomFilter` class (vData / nHashFuncs / nTweak / nFlags + Hash /
    insert / contains / IsWithinSizeConstraints / IsRelevantAndUpdate)
  - `CRollingBloomFilter` (used for tx-inventory / addr-known sets)

- `bitcoin-core/src/common/bloom.cpp`
  - L23 `LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455`
  - L24 `LN2 = 0.6931471805599453094172321214581765680755001343602552`
  - L26-42 `CBloomFilter` constructor (filter size + hash-funcs formulas
    clamped to MAX limits)
  - L44-48 `Hash(nHashNum, vDataToHash)` —
    `MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash) %
    (vData.size() * 8)`
  - L50-60 `insert(vKey)` — CVE-2013-5700 empty-vData short-circuit
    BEFORE the divide-by-zero in Hash() can fire
  - L62-67 `insert(outpoint)` — DataStream serialization of COutPoint
  - L69-81 `contains(vKey)` — same CVE-2013-5700 guard, returns **true**
    for empty filter
  - L83-88 `contains(outpoint)`
  - L90-93 `IsWithinSizeConstraints` —
    `vData.size() <= MAX_BLOOM_FILTER_SIZE && nHashFuncs <= MAX_HASH_FUNCS`
  - L95-161 `IsRelevantAndUpdate(tx)` —
    1. empty vData → match-all (return true)
    2. txid match (line 102-104)
    3. scriptPubKey pushdata scan (line 113-134) — on match, insert
       outpoint per `(nFlags & BLOOM_UPDATE_MASK)`:
       - `BLOOM_UPDATE_ALL` → always insert outpoint
       - `BLOOM_UPDATE_P2PUBKEY_ONLY` → only insert if `Solver()` returns
         `TxoutType::PUBKEY` or `TxoutType::MULTISIG`
    4. prevout (outpoint) match (line 144) — early-return on any match
    5. scriptSig pushdata scan (line 148-157)

- `bitcoin-core/src/merkleblock.h` + `merkleblock.cpp`
  - `BitsToBytes` / `BytesToBits` — bit packing **least-significant
    bit first** (line 16-18)
  - `CPartialMerkleTree` — `CalcTreeWidth(height)`, `CalcHash`,
    `TraverseAndBuild`, `TraverseAndExtract`, serialization
    `(nTransactions, vHash, vBits as bytes)`
  - `CMerkleBlock(block, filter)` — invokes `filter->IsRelevantAndUpdate`
    for **every** tx in the block (filter is mutated in place) and
    records matched (idx, txid) pairs in `vMatchedTxn`

- `bitcoin-core/src/net_processing.cpp`
  - L293-297 `m_bloom_filter` (unique_ptr<CBloomFilter>) PT_GUARDED_BY
    + `m_relay_txs` GUARDED_BY `m_bloom_filter_mutex` (per-peer state)
  - L1613-1614 NODE_BLOOM advertised when `NetPermissionFlags::BloomFilter`
    set (`-whitelist=…@bloomfilter` permission)
  - L2438-2460 `getdata`: `inv.IsMsgFilteredBlk()` → build CMerkleBlock
    via peer's `m_bloom_filter` (if loaded) → send merkleblock + the
    matched txs as separate `tx` messages
  - L3676-3691 version message: initialise `m_relay_txs` from fRelay,
    but also create the tx_relay struct when **NODE_BLOOM** is
    advertised (so the peer can turn relay on later via a filter)
  - L4853-4855 "mempool" requires `peer.m_our_services & NODE_BLOOM`
  - L4963-4986 **`FILTERLOAD`**: 4-step path
    1. NODE_BLOOM check (`peer.m_our_services & NODE_BLOOM == 0` →
       fDisconnect)
    2. deserialize filter
    3. `IsWithinSizeConstraints` → if not, `Misbehaving(peer, "too-large bloom filter")`
       (score 100 → disconnect)
    4. Install filter on `tx_relay->m_bloom_filter`, set
       `tx_relay->m_relay_txs = true`, set
       `pfrom.m_bloom_filter_loaded = true`, `pfrom.m_relays_txs = true`
  - L4988-5014 **`FILTERADD`**: 4-step path
    1. NODE_BLOOM check → fDisconnect
    2. deserialize data
    3. `vData.size() > MAX_SCRIPT_ELEMENT_SIZE` (520) →
       `Misbehaving(peer, "bad filteradd message")` (score 100)
    4. If no filter loaded → also `Misbehaving(peer, "bad filteradd message")`
       (per the `bad = true` else branch at L5006-5008)
  - L5016-5033 **`FILTERCLEAR`**: NODE_BLOOM check → fDisconnect.
    Then atomically: `tx_relay->m_bloom_filter = nullptr`,
    `tx_relay->m_relay_txs = true` (filterclear flips relay BACK ON!),
    `pfrom.m_bloom_filter_loaded = false`, `pfrom.m_relays_txs = true`

- `bitcoin-core/src/protocol.h`
  - L137-178 `NODE_BLOOM` documentation references
  - L316-317 `NODE_BLOOM = (1 << 2)`
  - L483 `MSG_FILTERED_BLOCK = 3` (BIP-37 inventory type)
  - L510-521 `IsMsgFilteredBlk()` / `IsGenBlkMsg`

- `bitcoin-core/src/protocol.cpp`
  - L70 `MSG_FILTERED_BLOCK` → "merkleblock" command name

- `bitcoin-core/src/init.cpp`
  - L572 `-peerbloomfilters` flag spec (default
    `DEFAULT_PEERBLOOMFILTERS = false` per net_processing.h:44)
  - L1104-1105 `if (-peerbloomfilters) g_local_services |= NODE_BLOOM`

- `bitcoin-core/src/net_processing.h:44`
  - `DEFAULT_PEERBLOOMFILTERS = false` — Core's documented default

- `bitcoin-core/src/script/script.h:28`
  - `MAX_SCRIPT_ELEMENT_SIZE = 520` — the bound `filteradd` enforces

**BIPs**:
- **BIP-37** — Connection Bloom filtering (filterload / filteradd /
  filterclear / merkleblock; MSG_FILTERED_BLOCK; BLOOM_UPDATE_*; FP rate
  sizing; PartialMerkleTree)
- **BIP-111** — NODE_BLOOM service bit (service-bit 2) + requirement
  that a node not advertising NODE_BLOOM disconnect peers sending
  filterload / filteradd / filterclear / mempool messages

**Source under audit**:

- `blockbrew/internal/p2p/msg_bloom.go` — `MsgFilterLoad` (filter,
  HashFuncs, Tweak, Flags), `MsgFilterAdd` (Data), `MsgFilterClear` (no
  payload), `MsgMerkleBlock` (Header, TxCount, Hashes, Flags).
- `blockbrew/internal/p2p/msg_version.go:13` — `ServiceNodeBloom = 1 << 2`.
- `blockbrew/internal/p2p/message.go:255-268` — `isNonCriticalMessage`.
- `blockbrew/internal/p2p/message.go:271-355` — `makeMessage` (registers
  filterload / filteradd / filterclear / merkleblock).
- `blockbrew/internal/p2p/peer.go:92-96` — `PeerListeners.OnFilterLoad /
  OnFilterAdd / OnFilterClear / OnMerkleBlock`.
- `blockbrew/internal/p2p/peer.go:687-703` — dispatch arms.
- `blockbrew/internal/p2p/peermgr.go:1651-1654` — NODE_BLOOM advertise
  gate.
- `blockbrew/internal/p2p/sync.go:1264-1318` — `HandleGetData` (does
  **not** handle `InvTypeFilteredBlock`).
- `blockbrew/internal/p2p/msg_inv.go:17` — `InvTypeFilteredBlock = 3`
  constant present.
- `blockbrew/cmd/blockbrew/main.go:476` — `-peerbloomfilters` flag,
  default `false`.
- `blockbrew/cmd/blockbrew/main.go:1050, 1298` —
  `AdvertiseNodeBloom: cfg.PeerBloomFilters` propagation.
- `blockbrew/internal/rpc/wave47b_methods.go:322-578` — local
  `buildPartialMerkleTree` / `parsePartialMerkleTree` (RPC `gettxoutproof`
  / `verifytxoutproof`).

## Summary

The wire-level façade is in place: messages parse and round-trip,
NODE_BLOOM is correctly defined and gated, the default of
`-peerbloomfilters=false` matches Core. Everything **behind** the wire
is absent or wrong:

1. **No `CBloomFilter` class at all** — no `MurmurHash3`, no
   `nHashNum * 0xFBA4C795 + nTweak` hash schedule, no constructor with
   FP-rate sizing, no `insert` / `contains` / `IsWithinSizeConstraints`
   / `IsRelevantAndUpdate`, no `LN2SQUARED` / `LN2` / `BLOOM_UPDATE_MASK`.
   The entire BIP-37 *filtering* layer is missing (BUG-1, BUG-2, BUG-3,
   BUG-4, BUG-5).
2. **No per-peer filter state** — `OnFilterLoad / OnFilterAdd /
   OnFilterClear / OnMerkleBlock` callbacks are defined on
   `PeerListeners` but **never wired** anywhere in production code
   (dead-helper pattern; same dead-helper class as W110). filterload
   bytes are parsed and discarded; no `m_bloom_filter` lives on `Peer`
   (BUG-6).
3. **No NODE_BLOOM gate on incoming filter messages** — Core disconnects
   a peer that sends filterload/filteradd/filterclear without us
   advertising NODE_BLOOM. blockbrew accepts the message, parses it,
   and silently drops the result. This is a real BIP-111 protocol
   violation (BUG-7).
4. **No `Misbehaving(peer, 100)` for oversized / un-keyed filteradd** —
   Core treats filteradd > 520 bytes OR filteradd without a prior
   filterload as score-100 misbehaviour. blockbrew rejects > 520 at the
   `ReadVarBytes` layer (which terminates the connection via the
   non-NonFatalMessageError path FIX-35 added), but does **not** detect
   the "filteradd without filterload" case (because no per-peer filter
   state exists to check against). For the size case, the disconnect
   reason is generic "deserialize error" instead of Core's
   "bad filteradd message" misbehaviour (BUG-8, BUG-9).
5. **No `MSG_FILTERED_BLOCK` handler in HandleGetData** — Core's
   `ProcessGetBlockData` switches on `inv.IsMsgFilteredBlk()` and
   constructs a `CMerkleBlock` from the peer's installed bloom filter
   plus sends the matched txs as separate `tx` messages. blockbrew's
   `HandleGetData` only switches on `InvTypeBlock` and `InvTypeTx`
   (line 1287-1311) — a peer requesting MSG_FILTERED_BLOCK gets
   silently nothing back, no `notfound` either (BUG-10).
6. **`merkleblock` BIP-37 "send matched txs after the merkleblock" is
   missing** — Core net_processing.cpp:2456-2457 also sends each
   `vMatchedTxn` as a separate `tx` message after the merkleblock so
   the SPV peer doesn't have to round-trip for them. blockbrew has no
   merkleblock-send path, so this BIP-37 spec requirement is doubly
   absent (BUG-11).
7. **No `m_bloom_filter_loaded` / `m_relays_txs` tracking on Peer** —
   `Peer.RelayTxes()` returns only the immutable `peerVersion.Relay`
   bit. There is no notion of "the peer turned relay on via filterload"
   or "the peer turned relay back on via filterclear" (BUG-12).
8. **PartialMerkleTree implementations exist in two places** — `MsgMerkleBlock`
   carries the wire bytes (deserialized into `Hashes` + `Flags`), and a
   separate `buildPartialMerkleTree` / `parsePartialMerkleTree` lives in
   `internal/rpc/wave47b_methods.go` (used by `gettxoutproof` /
   `verifytxoutproof`). They are not unified and can drift (BUG-13).
9. **Magic number `520` in MsgFilterAdd** — no link to
   `MAX_SCRIPT_ELEMENT_SIZE`; if Core ever raised the script-element
   bound, blockbrew's filteradd would silently desync. Core uses the
   same symbol in both places (BUG-14).
10. **`MsgMerkleBlock.Deserialize` hash-count sanity bound is `TxCount*2+1`
    but the BIP-37 spec actually says `N <= total_transactions`** — the
    `2*N-1` bound is the merkle-*node* count (used for the bit array),
    not the hash count. The hash bound is looser than necessary and
    can let a malicious peer waste a bit of memory before downstream
    rejection (BUG-15).
11. **`MsgMerkleBlock.Deserialize` flag-bytes cap is `1<<20`** (1 MiB)
    — independent of the block's total tx count. Core's protocol-spec
    bound is `ceil((2*N-1) / 8)` ≤ ~32 KiB for a 1M-tx block. The 1 MiB
    cap is harmless today (no block has 8M txs) but it's the wrong
    cardinality (BUG-16).
12. **`MsgMerkleBlock.TxCount` is `uint32`** which is correct, but the
    sanity check uses `uint64(m.TxCount)*2+1` which is fine. Core uses
    `unsigned int`. PASS-with-pedantic-note.
13. **`OnMerkleBlock` callback exists for an *outgoing* concept** — Core
    is the one that *sends* merkleblocks; only an SPV client *receives*
    them. blockbrew is a full node, so receiving merkleblock from a
    peer is nonsensical — the callback is dead weight (BUG-17).
14. **The blockbrew RPC `gettxoutproof` / `verifytxoutproof` use a
    locally-implemented `buildPartialMerkleTree`** that mirrors the
    BIP-37 wire format but is not unified with the P2P-level
    `MsgMerkleBlock`. The RPC path is the *only* live producer of
    PartialMerkleTree bytes in blockbrew today (no P2P producer exists),
    yet the bit-packing endianness (LSB-first per BIP-37) and the
    `CeilDiv` for flag bytes are duplicated. This is forward-regression
    bait if Core ever clarifies the bit ordering (BUG-13b).
15. **`PeerBloomFilters` default is `false`** matching Core's
    `DEFAULT_PEERBLOOMFILTERS = false` — PASS, no bug. (W110
    documented this; W134 confirms still true.)
16. **`isNonCriticalMessage` whitelists `filterload`, `filterclear`,
    `merkleblock` but not `filteradd`** — FIX-35 explicitly removed
    `filteradd` per the W110 fix. So a `filteradd` deserialization
    error closes the connection (matching Core's
    `Misbehaving(peer, 100)`), but a `filterload` deserialization error
    is silently swallowed (NonFatalMessageError) — which **does not**
    match Core. A filterload that fails to deserialize should also
    disconnect, because the only way to fail is corrupt wire or
    malicious peer (BUG-18).
17. **`-peerbloomfilters` has no per-permission override** — Core also
    honors `NetPermissionFlags::BloomFilter` (whitelisted peers can
    have bloom on even if global is off). blockbrew has no permission
    system at all, so this is a deliberate "won't implement" gap
    rather than a bug — documented for completeness (BUG-19).

Severity distribution:

| Severity | Count | Notes |
|----------|-------|-------|
| P0-CDIV  | 0     | No consensus divergence — BIP-37 is *relay* policy. The CDIV class for bloom filter would be: blockbrew advertises NODE_BLOOM but lies about serving (peer expects merkleblock, gets nothing). With `-peerbloomfilters=false` default, blockbrew never *advertises* NODE_BLOOM, so the protocol mismatch is not user-visible by default. The `BUG-7` and `BUG-10` cases are protocol-spec violations, not consensus divergences. |
| HIGH     | 5     | BUG-1 entire CBloomFilter implementation missing; BUG-6 per-peer filter state absent (dead-helper); BUG-7 NODE_BLOOM gate on incoming filter messages absent (BIP-111 violation); BUG-10 MSG_FILTERED_BLOCK not handled in HandleGetData; BUG-12 `m_bloom_filter_loaded` / `m_relays_txs` state-machine missing. |
| MED      | 7     | BUG-2 LN2SQUARED / LN2 constants absent; BUG-3 MurmurHash3 absent; BUG-4 BLOOM_UPDATE_MASK constant absent; BUG-5 IsRelevantAndUpdate logic absent (P2PUBKEY_ONLY / UPDATE_ALL / scriptPubKey scan / outpoint check); BUG-8 filteradd-without-prior-filterload not flagged as Misbehaving; BUG-9 filteradd-oversize disconnect reason text drift vs Core; BUG-11 the "send matched txs after merkleblock" follow-up missing. |
| LOW      | 7     | BUG-13 PartialMerkleTree implementation duplicated in `wave47b_methods.go`; BUG-13b RPC-side bit-packing endianness duplicate-of-truth; BUG-14 magic number 520 in MsgFilterAdd not symbolic; BUG-15 hash-count sanity bound is `2*N+1` instead of `N`; BUG-16 flag-bytes cap is `1<<20` instead of `CeilDiv(2*N-1, 8)`; BUG-17 `OnMerkleBlock` callback dead weight (full node never receives merkleblock); BUG-18 filterload-deserialize-error is non-fatal (asymmetric with filteradd which is fatal post-FIX-35); BUG-19 no permission system → no `-whitelist=…@bloomfilter` parity. |

PASS: **8** / PARTIAL: **5** / MISSING: **17**. Bug count: **19**.

## 30-gate audit matrix

| Gate | What the gate asserts | Status | Bug |
|------|----------------------|--------|-----|
| G1 | `MAX_BLOOM_FILTER_SIZE = 36000` constant present | PASS | — |
| G2 | `MAX_HASH_FUNCS = 50` constant present | PASS | — |
| G3 | `LN2SQUARED` / `LN2` constants present | **MISSING** | BUG-2 |
| G4 | `CBloomFilter` constructor: filter size formula `min(-1/LN2SQUARED * nElements * log(nFPRate), MAX*8)/8` | **MISSING** | BUG-1 |
| G5 | `CBloomFilter` constructor: `nHashFuncs = min(vData*8/nElements*LN2, MAX_HASH_FUNCS)` | **MISSING** | BUG-1 |
| G6 | `MurmurHash3` 32-bit hash function present | **MISSING** | BUG-3 |
| G7 | `Hash(i, vData)` uses `MurmurHash3(i * 0xFBA4C795 + nTweak, vData) % (vData.size() * 8)` | **MISSING** | BUG-1 |
| G8 | `insert(vKey)` sets `nHashFuncs` bits via Hash schedule, with CVE-2013-5700 empty-vData guard | **MISSING** | BUG-1 |
| G9 | `contains(vKey)` returns `true` on empty vData (CVE-2013-5700) and AND of bits otherwise | **MISSING** | BUG-1 |
| G10 | `IsWithinSizeConstraints` checks `vData.size() <= 36000 && nHashFuncs <= 50` | **MISSING** | BUG-1 |
| G11 | `BLOOM_UPDATE_NONE = 0` | PASS | — |
| G12 | `BLOOM_UPDATE_ALL = 1` | PASS | — |
| G13 | `BLOOM_UPDATE_P2PUBKEY_ONLY = 2` | PASS | — |
| G14 | `BLOOM_UPDATE_MASK = 3` constant present (used to extract update-flag bits from nFlags) | **MISSING** | BUG-4 |
| G15 | `IsRelevantAndUpdate(tx)`: empty filter → match-all; txid match; scriptPubKey pushdata scan; outpoint match; scriptSig pushdata scan | **MISSING** | BUG-5 |
| G16 | UPDATE_ALL: matched output's outpoint inserted | **MISSING** | BUG-5 |
| G17 | UPDATE_P2PUBKEY_ONLY: only TxoutType::PUBKEY or MULTISIG outpoints inserted | **MISSING** | BUG-5 |
| G18 | UPDATE_NONE: filter never mutated by match | **MISSING** | BUG-5 |
| G19 | filterload wire: `MsgFilterLoad.Deserialize` enforces filter ≤ 36000 and hash_funcs ≤ 50 | PASS | — |
| G20 | filteradd wire: `MsgFilterAdd.Deserialize` rejects data > 520 (`MAX_SCRIPT_ELEMENT_SIZE`); `MAX_SCRIPT_ELEMENT_SIZE` is a symbolic constant | PARTIAL | BUG-14 |
| G21 | filterclear wire: zero-payload Deserialize succeeds | PASS | — |
| G22 | merkleblock wire: round-trip Serialize/Deserialize | PASS | — |
| G23 | `NODE_BLOOM = 1 << 2` constant present and OR'd into advertised services when `-peerbloomfilters=true` | PASS | — |
| G24 | `-peerbloomfilters` flag default is `false` matching `DEFAULT_PEERBLOOMFILTERS` | PASS | — |
| G25 | Incoming filterload disconnects peer if `NODE_BLOOM` not advertised (BIP-111 §"Behavior") | **MISSING** | BUG-7 |
| G26 | Incoming filteradd disconnects peer if `NODE_BLOOM` not advertised | **MISSING** | BUG-7 |
| G27 | Incoming filterclear disconnects peer if `NODE_BLOOM` not advertised | **MISSING** | BUG-7 |
| G28 | Incoming filteradd without prior filterload triggers Misbehaving (score 100) | **MISSING** | BUG-8 |
| G29 | `getdata(MSG_FILTERED_BLOCK)` → construct `CMerkleBlock` from peer's filter → send merkleblock + matched txs as separate `tx` messages | **MISSING** | BUG-10, BUG-11 |
| G30 | per-peer `m_bloom_filter` + `m_bloom_filter_loaded` + `m_relays_txs` state machine: filterload sets relay_txs=true; filterclear flips relay BACK ON; OnFilter* callbacks wired in production code | **MISSING** | BUG-6, BUG-12 |

PASS: **8** / PARTIAL: **1** / MISSING: **21**. Bug count: **19**.

## Bug catalogue

### BUG-1 (HIGH) — CBloomFilter implementation absent entirely

There is no `BloomFilter` struct anywhere in `blockbrew/internal/`.

- No constructor: blockbrew cannot construct a filter from `(nElements,
  fpRate, nTweak, nFlags)` because the LN2SQUARED / LN2 sizing formula
  is absent.
- No `insert(vKey)` / `insert(outpoint)` / `contains(vKey)` /
  `contains(outpoint)`.
- No `IsRelevantAndUpdate(tx)` — the per-tx match check that powers
  filtered-block construction.
- No CVE-2013-5700 empty-vData short-circuit (only matters if filter
  exists — moot today, but a foot-gun if ever added).
- No `IsWithinSizeConstraints` — would be a one-line guard if the
  type existed.

This is intentional given Core's deprecation, but blockbrew also
parses `filterload` wire bytes and discards them silently, so the
overall shape is "half-implemented" rather than "intentionally not
served". A proper "not served" stance would refuse the message at
the wire level when `NODE_BLOOM` is not advertised (see BUG-7).

**Reference**: `bitcoin-core/src/common/bloom.h:44-81`,
`bitcoin-core/src/common/bloom.cpp:26-161`.
**Site**: no symbol named `BloomFilter` anywhere in `blockbrew/internal/`.

### BUG-2 (MED) — LN2SQUARED / LN2 constants absent

`LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455`
and `LN2 = 0.6931471805599453094172321214581765680755001343602552` are
defined at file scope in `bitcoin-core/src/common/bloom.cpp:23-24` and
used by the `CBloomFilter` constructor for the optimal filter-size and
hash-function-count formulas. blockbrew has no equivalent.

Subordinate to BUG-1 (no constructor to use them in), but worth listing
because the **precision** of LN2SQUARED (52 decimal digits) is what
guarantees that two implementations produce bit-identical filters
given the same `(nElements, fpRate)` pair. A drift here is a silent
divergence in the *false-positive rate* — not the filter contents, but
the filter *size* — which still desyncs a fleet-wide BIP-37 spec test.

**Reference**: `bitcoin-core/src/common/bloom.cpp:23-24`.
**Site**: no constant or literal `0.480453…` in `blockbrew/internal/`.

### BUG-3 (MED) — MurmurHash3 32-bit hash function absent

Core's `CBloomFilter::Hash` uses `MurmurHash3(seed, data)` from
`bitcoin-core/src/hash.h`. blockbrew has no `MurmurHash3` implementation
in `internal/crypto/`, `internal/script/`, or `internal/p2p/`.
Subordinate to BUG-1.

**Reference**: `bitcoin-core/src/common/bloom.cpp:44-48`.
**Site**: `grep -rn 'MurmurHash3' blockbrew/internal/` returns no hits.

### BUG-4 (MED) — BLOOM_UPDATE_MASK constant absent

`BLOOM_UPDATE_MASK = 3` is used by Core (bloom.cpp:123, 125) to extract
the two update-flag bits from `nFlags`, so that an SPV client which
sets reserved high bits in `nFlags` doesn't accidentally enable a
non-existent update mode. blockbrew's `msg_bloom.go:18-26` defines
`BloomUpdateNone`, `BloomUpdateAll`, `BloomUpdateP2PubkeyOnly` but not
`BloomUpdateMask`. A future bloom-filter implementation that branched
on raw `nFlags` (e.g. `nFlags == BloomUpdateAll`) instead of
`(nFlags & 3) == BloomUpdateAll` would mis-handle peers that set
reserved bits.

**Reference**: `bitcoin-core/src/common/bloom.h:30-31`.
**Site**: `blockbrew/internal/p2p/msg_bloom.go:18-26` — three constants,
not four.

### BUG-5 (MED) — IsRelevantAndUpdate logic absent

The whole tx-matching logic — empty-vData match-all, txid check,
scriptPubKey pushdata scan (with `UPDATE_ALL` / `UPDATE_P2PUBKEY_ONLY`
outpoint insertion paths), outpoint check, scriptSig pushdata scan — is
absent. Subordinate to BUG-1.

**Reference**: `bitcoin-core/src/common/bloom.cpp:95-161`.

### BUG-6 (HIGH) — Per-peer filter state absent (dead-helper)

`OnFilterLoad` / `OnFilterAdd` / `OnFilterClear` / `OnMerkleBlock`
callbacks exist on `PeerListeners` (`peer.go:92-96`) and dispatch arms
exist (`peer.go:687-703`), but they are **never set** in any production
code. `grep -rn 'OnFilterLoad\s*:' blockbrew/internal/ blockbrew/cmd/`
excluding tests returns zero hits.

The `Peer` struct also has no `bloomFilter *BloomFilter` field — there
is nowhere on a per-peer basis to *install* the filter even if the
callback were wired. Core's `Peer::TxRelay` struct (the per-peer
container that holds `m_bloom_filter` plus the `m_bloom_filter_mutex`
plus `m_relay_txs`) has no equivalent here. This is the W110
"dead-helper" finding restated for W134.

**Reference**: `bitcoin-core/src/net_processing.cpp:293-297` (per-peer
struct), `:4976-4982` (filterload installs the filter).
**Site**: `blockbrew/internal/p2p/peer.go:92-96, 687-703` (callbacks
exist but never wired); `blockbrew/internal/p2p/peer.go` `type Peer
struct {…}` has no bloom-related fields.

### BUG-7 (HIGH) — Incoming filter messages not disconnect-gated by NODE_BLOOM (BIP-111 violation)

Per BIP-111 §"Behavior": "Bloom filter related messages without NODE_BLOOM
should be rejected." Core's `net_processing.cpp:4964-4967, 4989-4992,
5017-5020` implements this by setting `pfrom.fDisconnect = true` if a
peer sends filterload / filteradd / filterclear when
`peer.m_our_services & NODE_BLOOM == 0`.

blockbrew's `peer.go:687-703` dispatches to `OnFilter*` callbacks
unconditionally (and silently drops because the callbacks are nil per
BUG-6). There is no NODE_BLOOM gate at the dispatch layer.

In practice, since blockbrew's default `-peerbloomfilters=false` means
NODE_BLOOM is never advertised, no well-behaved peer would ever send
filterload here. But a malicious or buggy peer that sends bloom
messages anyway gets silently tolerated, contra BIP-111. Real
CDIV-class behavior: differential BIP-111 conformance tests will see
blockbrew accept where Core disconnects.

**Reference**: `bitcoin-core/src/net_processing.cpp:4963-4967, 4988-4992,
5016-5020`; BIP-111.
**Site**: `blockbrew/internal/p2p/peer.go:687-703` — no
`!ServiceNodeBloom advertised → disconnect` arm.

### BUG-8 (MED) — filteradd without prior filterload not flagged as Misbehaving

Core's `net_processing.cpp:5002-5008`:

```cpp
} else if (auto tx_relay = peer.GetTxRelay(); tx_relay != nullptr) {
    LOCK(tx_relay->m_bloom_filter_mutex);
    if (tx_relay->m_bloom_filter) {
        tx_relay->m_bloom_filter->insert(vData);
    } else {
        bad = true;          // <-- sets bad=true if no filter loaded
    }
}
if (bad) Misbehaving(peer, "bad filteradd message");   // score 100 = disconnect
```

A peer that sends `filteradd` before `filterload` is misbehaving. Core
catches this and disconnects with score 100. blockbrew has no per-peer
filter state (BUG-6), so it has nothing to check against and silently
accepts the filteradd bytes.

**Reference**: `bitcoin-core/src/net_processing.cpp:5002-5012`.
**Site**: dispatch arm at `blockbrew/internal/p2p/peer.go:692-694` has
no precondition check.

### BUG-9 (MED) — filteradd oversize disconnect reason drift

FIX-35 removed `filteradd` from `isNonCriticalMessage`, so a
filteradd > 520 bytes causes Deserialize to return a fatal error and
the connection terminates. Good. But the error message is the generic
"deserialize filteradd: read VarBytes: length 521 exceeds max 520",
not Core's specific "bad filteradd message" (which maps to
`Misbehaving(peer, score=100)` and produces a distinct log line). For
operator-facing observability and W125-style RPC-error-parity tests,
this is a cosmetic drift but a real one.

**Reference**: `bitcoin-core/src/net_processing.cpp:5011`.
**Site**: `blockbrew/internal/p2p/msg_bloom.go:95-99` —
`ReadVarBytes(r, MaxFilterAddDataSize)`.

### BUG-10 (HIGH) — MSG_FILTERED_BLOCK not handled in HandleGetData

`blockbrew/internal/p2p/sync.go:1264-1318` `HandleGetData` switch
arm has `InvTypeBlock` and `InvTypeTx` only — no `InvTypeFilteredBlock`
(or `InvTypeWitnessFilteredBlock`, which Core comments out anyway at
`protocol.h:489` because BIP-37 was finalized pre-segwit and no
witness-aware merkleblock spec was ever ratified).

Core's `net_processing.cpp:2438-2460` builds a `CMerkleBlock` from the
peer's installed `m_bloom_filter` and sends it. blockbrew silently
does nothing for an incoming
`getdata(type=MSG_FILTERED_BLOCK, hash=blkhash)`: no `merkleblock`,
no `notfound`, no log line. A well-behaved SPV peer would hang on the
read.

(This is moot in practice because blockbrew never advertises
NODE_BLOOM by default, so no peer should send the request — but a
peer that sends it anyway gets pathological treatment.)

**Reference**: `bitcoin-core/src/net_processing.cpp:2438-2460`.
**Site**: `blockbrew/internal/p2p/sync.go:1286-1313`.

### BUG-11 (MED) — Matched-txs follow-up after merkleblock missing

Core's `net_processing.cpp:2456-2458`:

```cpp
for (const auto& [tx_idx, _] : merkleBlock.vMatchedTxn)
    MakeAndPushMessage(pfrom, NetMsgType::TX, TX_NO_WITNESS(*pblock->vtx[tx_idx]));
```

After sending merkleblock, Core sends the matched txs as separate `tx`
messages so the SPV peer doesn't have to round-trip individual
getdata(tx) requests. This is part of the BIP-37 spec
("matched transactions").

Subordinate to BUG-10 (no merkleblock-send path at all).

**Reference**: `bitcoin-core/src/net_processing.cpp:2456-2458`; BIP-37
"Filtered blocks" section.

### BUG-12 (HIGH) — m_bloom_filter_loaded / m_relays_txs state machine missing

Core tracks two distinct booleans per peer:

- `m_bloom_filter_loaded` — set true on filterload, false on
  filterclear.
- `m_relays_txs` — set true on filterload, set true also on
  filterclear (filterclear *enables* relay), and initialised from
  fRelay in the version message.

blockbrew's `Peer.RelayTxes()` (peer.go:1303-1313) reads only
`peerVersion.Relay`, which is the immutable initial-handshake bit.
Filterload / filterclear do not flip this. As a consequence, even if
the rest of the bloom subsystem were wired, the relay state would not
update.

The version-handshake-side of this (which Core does at
`net_processing.cpp:3682-3691` — create `tx_relay` struct if
`fRelay || NODE_BLOOM`) is also absent: blockbrew's peer creation
unconditionally creates the per-peer state.

**Reference**: `bitcoin-core/src/net_processing.cpp:3682-3691,
4978-4983, 5025-5031`.
**Site**: `blockbrew/internal/p2p/peer.go:1303-1313, 1327-1344`.

### BUG-13 (LOW) — PartialMerkleTree duplicated in RPC code

`MsgMerkleBlock.{Serialize,Deserialize}` (msg_bloom.go:127-171) handles
the wire-level partial merkle tree, but the *construction* logic
(`CalcHash`, `TraverseAndBuild`, `BitsToBytes`) is reimplemented in
`internal/rpc/wave47b_methods.go:388-452` as a closure inside
`buildPartialMerkleTree`. Since blockbrew has no P2P producer
(BUG-10), the RPC path is the only live code; but if BUG-10 is ever
fixed, the two paths will need to share a `BuildPartialMerkleTree`
helper and they currently don't.

#### BUG-13b (LOW) — RPC bit-packing endianness duplicate-of-truth

`buildPartialMerkleTree` packs flag bits via
`flagBytes[i/8] |= 1 << (i % 8)` (LSB-first, matching Core's
`BitsToBytes` at `merkleblock.cpp:17`). Verifies. But this is a
duplicate of truth; any clarification of bit-ordering in Core would
require two-place updates here.

**Reference**: `bitcoin-core/src/merkleblock.cpp:13-29`.
**Site**: `blockbrew/internal/rpc/wave47b_methods.go:388-452, 479-577`.

### BUG-14 (LOW) — MaxFilterAddDataSize is a magic 520, not symbolic

`blockbrew/internal/p2p/msg_bloom.go:84` declares
`MaxFilterAddDataSize = 520`. The number `520` corresponds to
`MAX_SCRIPT_ELEMENT_SIZE` in
`bitcoin-core/src/script/script.h:28`. blockbrew has no such symbol
in `internal/script/`. The literal `520` recurs in other places
(MAX_SCRIPT_ELEMENT_SIZE-style validation) but is never named. If Core
ever raised the limit, blockbrew would silently desync.

**Reference**: `bitcoin-core/src/script/script.h:28`.
**Site**: `blockbrew/internal/p2p/msg_bloom.go:84`.

### BUG-15 (LOW) — MsgMerkleBlock hash-count sanity bound is `2*TxCount+1` (too loose)

`msg_bloom.go:160` rejects when
`hashCount > uint64(m.TxCount)*2+1`. The BIP-37 spec bound on N
(number of hashes) is `N <= total_transactions` (i.e. `N <= TxCount`).
The `2*N-1` bound that appears in the BIP-37 size formula is the
*total tree node* count, not the hash count. blockbrew's check accepts
a 1000-hash merkleblock for a 500-tx block; Core's bound is tighter.

This is a memory-DoS hardening miss, not a consensus drift; a
malicious peer can prepare a ~2× oversize merkleblock that blockbrew
accepts and Core rejects. In practice, downstream `parsePartialMerkleTree`
will catch many such cases via the structural traversal, but the wire
check is the cheap first line.

**Reference**: BIP-37 "Partial Merkle branch format" — N ≤ total tx.
**Site**: `blockbrew/internal/p2p/msg_bloom.go:160`.

### BUG-16 (LOW) — MsgMerkleBlock flag-bytes cap is `1<<20`

`msg_bloom.go:169` reads `Flags` with cap `1 << 20` (1 MiB). The
BIP-37 protocol bound is `ceil((2*N-1)/8)` where N is hashCount.
For a typical-block N = ~3000 the cap should be ~750 bytes. The 1 MiB
cap is harmless today (no block has 4M nodes) but unprincipled.

**Reference**: BIP-37 size formula.
**Site**: `blockbrew/internal/p2p/msg_bloom.go:169`.

### BUG-17 (LOW) — OnMerkleBlock callback dead weight

A full node *sends* merkleblock; it does not *receive* merkleblock.
The `OnMerkleBlock` callback (peer.go:96, dispatch at :700-702) is
defined for completeness but no production code wires it, and no
production code ever will, because blockbrew is not an SPV client.
Its presence is misleading and bloats the callback API surface.

**Reference**: BIP-37 — "Filtered blocks are sent in response to
getdata MSG_FILTERED_BLOCK"; merkleblock travels server→client only.
**Site**: `blockbrew/internal/p2p/peer.go:96, 700-702`.

### BUG-18 (LOW) — filterload deserialize error is non-fatal (asymmetric with filteradd post-FIX-35)

FIX-35 removed `filteradd` from `isNonCriticalMessage`. But `filterload`
remains in the list (`message.go:259`):

```go
"filterload", "filterclear", "merkleblock",
```

This means a peer that sends a malformed `filterload` (e.g. HashFuncs
> 50, which is the wire-level reject path) has the error swallowed via
NonFatalMessageError and the connection persists. Core treats this
as `Misbehaving(peer, "too-large bloom filter", score=100)` —
disconnect. Asymmetric: filteradd-oversize is fatal, filterload-bad is
non-fatal. They should both be fatal.

W110 G29a actually tests for the *opposite* property (asserts the
error is NOT NonFatalMessageError) — but G29a was written BEFORE FIX-35
and asserts what the deserialize path returns *before* wrapping. The
end-to-end peer behavior is still wrong: `ReadMessage` will wrap the
error per the `isNonCriticalMessage` table, the peer stays connected,
and the malformed filterload was Core's "score=100" trigger.

Fix would be a one-line removal of `filterload` from
`isNonCriticalMessage`, paralleling FIX-35 for filteradd.

**Reference**: `bitcoin-core/src/net_processing.cpp:4972-4975`.
**Site**: `blockbrew/internal/p2p/message.go:259`.

### BUG-19 (LOW) — No per-peer permission system → no `-whitelist=…@bloomfilter`

Core's `NetPermissionFlags::BloomFilter` permits a whitelisted peer
to use bloom filters even if `-peerbloomfilters=false` globally
(`net_processing.cpp:1613-1614`). blockbrew has no permission system
at all (no `NetPermissionFlags` equivalent), so this is "won't
implement" rather than a bug per se — documented for completeness.

**Reference**: `bitcoin-core/src/net_processing.cpp:1613-1614`.
**Site**: no permission system anywhere in `blockbrew/internal/`.

## Cross-cutting observations

- **Same dead-helper pattern as W110**: callbacks defined,
  zero production wiring. Same shape as W118 wallet audit's
  "PSBT subsystems implemented but never invoked from production
  endpoints". Promote this to a fleet-wide pattern: "wire surfaces
  without semantic backing" — at minimum, audit gates should run a
  `grep -rn '<callback name>:\s*func' production code` and FAIL if
  zero hits.

- **"Half-served" is worse than "not served"** — blockbrew accepts
  the wire bytes but silently drops the result. A peer that sends
  filterload then `getdata(MSG_FILTERED_BLOCK)` will get nothing
  back, with no error indication. Either fully serve or fully refuse
  (disconnect with NODE_BLOOM-absent). The half-served stance fails
  BIP-111 conformance tests.

- **`PartialMerkleTree` is half-shared**: the wire bytes are unified
  through `MsgMerkleBlock`, but the construction / extraction logic
  is duplicated in `internal/rpc/wave47b_methods.go`. If BUG-10 is
  ever fixed, this duplication will become a real correctness risk.

## Test plan

The W134 test file `internal/p2p/w134_bip37_bloom_filter_test.go`
contains one test per gate (G1..G30), reusing PASS gates from W110
(which audits the wire-message layer) and skipping the MISSING /
PARTIAL gates with `t.Skip("BUG-N: …")` so the bug list is
machine-readable from `go test -v`. Tests:

- G1..G2: constants present (PASS, reuse W110)
- G3..G10: CBloomFilter implementation (MISSING, skip with BUG-1..5)
- G11..G13: BLOOM_UPDATE_* enum (PASS, reuse W110)
- G14: BLOOM_UPDATE_MASK constant (MISSING, skip with BUG-4)
- G15..G18: IsRelevantAndUpdate paths (MISSING, skip with BUG-5)
- G19: filterload wire-level size + hash-funcs check (PASS)
- G20: filteradd wire-level 520-byte cap (PARTIAL — wire enforces,
  no MAX_SCRIPT_ELEMENT_SIZE symbol)
- G21: filterclear zero-payload (PASS)
- G22: merkleblock wire round-trip (PASS)
- G23: NODE_BLOOM service-bit gating (PASS)
- G24: -peerbloomfilters default = false (PASS)
- G25..G27: NODE_BLOOM-absent → disconnect on incoming filter*
  (MISSING, skip with BUG-7)
- G28: filteradd-without-filterload → Misbehaving (MISSING, skip with
  BUG-8)
- G29: MSG_FILTERED_BLOCK handler in HandleGetData (MISSING, skip
  with BUG-10)
- G30: per-peer m_bloom_filter / m_bloom_filter_loaded / m_relays_txs
  state machine (MISSING, skip with BUG-6 + BUG-12)

All tests compile and either PASS or skip with the bug ID listed.
No production-code change.
