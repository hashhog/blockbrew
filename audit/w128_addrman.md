# W128 — AddrMan + connman + peer selection audit (blockbrew)

**Scope**: AddrMan add/select/good/attempt/connected/terrible; bucketing by
source-IP + ASN; ThreadOpenConnections; outbound peer selection;
AttemptToEvictConnection; banman + discouragement.
**Excludes**: BIP-155 addrv2 wire format (W117), addr relay scheduling (W104),
asmap codec / interpreter (W115) — referenced where they intersect.

**Bitcoin Core references**:
- `bitcoin-core/src/addrman.cpp` + `addrman.h` + `addrman_impl.h`
- `bitcoin-core/src/net.cpp` (CConnman, ThreadOpenConnections,
  AttemptToEvictConnection, MaybePickPreferredNetwork)
- `bitcoin-core/src/node/eviction.cpp` (SelectNodeToEvict + 4 protectors)
- `bitcoin-core/src/banman.cpp` + `banman.h`
- `bitcoin-core/src/util/asmap.cpp` + `asmap.h` (intersect)

**blockbrew implementation**:
- `internal/p2p/addrbook.go` (433 LOC) — flat-map "AddressBook" stands in for
  Core's AddrMan
- `internal/p2p/peermgr.go` (2006 LOC) — connman + outbound loop + eviction +
  banman all rolled into PeerManager
- `internal/p2p/asmap.go` (401 LOC) — asmap interpreter (W115)

**Verdict**: **27 BUGS / 30 gates**. blockbrew's AddrMan-equivalent is
fundamentally a flat-map cache with no Sybil-resistant bucketing, no
test-before-evict, no IsTerrible, no peers.dat. Outbound loop uses a fixed
30s ticker rather than Core's prioritised one-attempt-per-iteration with
preferred_net for empty reachable networks. Eviction is in the right
shape but uses subnet-only grouping for protection (with asmap-aware
fallback that lands on the same 5-byte ASN key as the diversity tracker)
and lacks Core's deterministic netgroup keyed 4-peer protect step. Banman
is IP-only — no subnet ban, no discouragement bloom filter, every ban is
a hard reject. Severity weighted: **5 P0-CDIV / 9 P0 / 7 P1 / 4 P2 / 2 P3**.

> Cross-wave overlap: W104 (AddrMan 30 gates), W115 (asmap 30 gates),
> W117 (BIP-155 30 gates), W99 (netproc 30 gates) all touch adjacent
> territory. W128 focuses on the **connman/eviction/banman** axis plus
> the bucketing structure where it directly enables peer selection.
> Gates that exactly duplicate a prior wave (e.g. asmap codec) are
> consolidated into single gates here.

---

## Gate matrix

| # | Gate | Status | Refs | Priority |
|---|------|--------|------|----------|
| G1 | NEW_BUCKET_COUNT = 1024, TRIED_BUCKET_COUNT = 256, BUCKET_SIZE = 64 | **MISSING** | BUG-1 | P0 |
| G2 | NEW_BUCKETS_PER_SOURCE_GROUP = 64, TRIED_BUCKETS_PER_GROUP = 8, NEW_BUCKETS_PER_ADDRESS = 8 | **MISSING** | BUG-1 | P0 |
| G3 | GetNewBucket/GetTriedBucket/GetBucketPosition hash-keyed via 256-bit nKey + cheap_hash | **MISSING** | BUG-2 | P0-CDIV |
| G4 | `Add` rejects non-routable, applies time_penalty, stochastic multi-bucket reroll | **PARTIAL** | BUG-3 | P0 |
| G5 | `Good` moves from new → tried, test-before-evict on collision (m_tried_collisions) | **MISSING** | BUG-4 | P0 |
| G6 | `Attempt(addr, fCountFailure, time)` updates last_try, nAttempts only after Good | **PARTIAL** | BUG-5 | P1 |
| G7 | `Connected(addr, time)` updates nTime when >20min stale (privacy-preserving) | **MISSING** | BUG-6 | P1 |
| G8 | `SetServices(addr, nServices)` updates entry service flags on version | **MISSING** | BUG-7 | P1 |
| G9 | `IsTerrible` covers 5 cases (1min, +10min, HORIZON 30d, RETRIES=3, MAX_FAILURES=10/MIN_FAIL=7d) | **MISSING** | BUG-8 | P0 |
| G10 | `GetChance` deprioritises recent retries (×0.01) + 0.66^min(nAttempts,8) decay | **PARTIAL** | BUG-9 | P1 |
| G11 | `Select(new_only, networks)` 50/50 new/tried + bucket-iterate + chance gate | **MISSING** | BUG-10 | P0-CDIV |
| G12 | `SelectTriedCollision` + `ResolveCollisions` (test-before-evict workflow) | **MISSING** | BUG-11 | P0 |
| G13 | `GetAddr(max_addresses, max_pct, network, filtered)` returns sampled randomised slice | **MISSING** | BUG-12 | P0 |
| G14 | nKey randomised per-launch (Core: insecure_rand.rand256()) | **MISSING** | BUG-13 | P0-CDIV |
| G15 | NetGroupManager::GetGroup hashed INTO bucket selection (asmap or /16 fallback) | **MISSING** | BUG-14 | P0-CDIV |
| G16 | peers.dat persistence (Serialize/Unserialize with format byte) | **MISSING** | BUG-15 | P0 |
| G17 | `addr_token_bucket` per-peer rate limit + AverageAddressMessageProcessingTime tracking | **MISSING** | BUG-16 | P1 |
| G18 | ADDRMAN_MIN_FAIL=7d, ADDRMAN_MAX_FAILURES=10, ADDRMAN_RETRIES=3 constants exposed | **MISSING** | BUG-17 | P0 |
| G19 | ThreadOpenConnections: Poisson next_feeler / next_extra_block_relay / next_extra_network_peer | **PARTIAL** | BUG-18 | P0 |
| G20 | MaybePickPreferredNetwork: every reachable empty network gets an attempt | **MISSING** | BUG-19 | P0 |
| G21 | `outbound_ipv46_peer_netgroups` set enforced (1-per-netgroup for IPv4/IPv6) | **PARTIAL** | BUG-20 | P0-CDIV |
| G22 | ConnectionType: MANUAL / OUTBOUND_FULL_RELAY / BLOCK_RELAY / FEELER / ADDR_FETCH / INBOUND / PRIVATE_BROADCAST | **PARTIAL** | BUG-21 | P1 |
| G23 | Anchors: 2 BLOCK_RELAY anchors from previous session, attempted first | **PRESENT** | — | — |
| G24 | Fixed seeds fallback when reachable_empty_networks not seeded after 60s | **MISSING** | BUG-22 | P1 |
| G25 | AttemptToEvictConnection: ProtectNoBan + ProtectOutbound + ProtectEvictionCandidatesByRatio (4-stage) | **PARTIAL** | BUG-23 | P0-CDIV |
| G26 | Eviction protect: 4 netgroup-keyed + 8 min-ping + 4 tx-time + 8 block-relay + 4 block-time | **PARTIAL** | BUG-24 | P0 |
| G27 | BanMan IsBanned matches CSubNet, supports subnet ban with /CIDR (not just IP) | **MISSING** | BUG-25 | P0 |
| G28 | BanMan IsDiscouraged uses CRollingBloomFilter (50000, 0.000001) (distinct from Ban) | **MISSING** | BUG-26 | P0 |
| G29 | banlist persisted to banlist.dat with format compatible w/ Core | **PARTIAL** | BUG-27 | P2 |
| G30 | DEFAULT_MISBEHAVING_BANTIME = 86400s; DUMP_BANS_INTERVAL = 15min | **PARTIAL** | — | P3 |

---

## Bugs

### BUG-1 — Flat map replaces 1024-new + 256-tried bucket structure  [P0]
**Gate**: G1, G2
**Files**: `internal/p2p/addrbook.go:217-228` (AddressBook), :255-258 (cap)
**Core**: `addrman_impl.h:26-33` (NEW_BUCKET_COUNT 1024, TRIED_BUCKET_COUNT 256,
BUCKET_SIZE 64); `addrman.h:23-27` (TRIED_BUCKETS_PER_GROUP 8,
NEW_BUCKETS_PER_SOURCE_GROUP 64, NEW_BUCKETS_PER_ADDRESS 8).
**Description**: `AddressBook.addrs` is a flat `map[string]*KnownAddress`
keyed on `host:port`, hard-capped at `AddressBookMaxSize=10000`. Core
maintains a tried table of 256 buckets × 64 slots and a new table of
1024 buckets × 64 slots, with each address occupying up to 8 new buckets
(`ADDRMAN_NEW_BUCKETS_PER_ADDRESS`). The flat structure has no Sybil
resistance: an attacker who poisons 10 000 entries simply fills the
entire address book. Core's design guarantees that to fill all 1024
new buckets an attacker must hold 1024×64×8 = 524 288 distinct entries
across 16 384 distinct /16 source groups (or AS groups when asmap is
loaded), making eclipse attack 524k× more expensive.
**Recovery**: replace `AddressBook.addrs` with two slice-of-slice
structures `vvNew [1024][64]int64` and `vvTried [256][64]int64`, plus
`mapInfo map[int64]*AddrInfo` keyed by `nid_type` (int64 to dodge the
2024 nid overflow CVE). Re-implement `Add`/`Good`/`Select`/`GetAddr`
against this structure.

### BUG-2 — Bucketing hash absent; no source-group, no nKey   [P0-CDIV]
**Gate**: G3
**Files**: `internal/p2p/addrbook.go:236-265` (AddAddress); no GetTriedBucket /
GetNewBucket / GetBucketPosition anywhere in the package.
**Core**: `addrman.cpp:28-47` — `GetTriedBucket` hashes `nKey || GetKey() ||
group || (hash1 % 8)`; `GetNewBucket` mixes nKey + ourgroup + sourcegroup;
`GetBucketPosition` hashes nKey + 'N'/'K' + bucket + GetKey().
**Description**: blockbrew has no bucket-hash function at all. Every
address landing path goes through `AddAddress` → flat map insert. There
is no per-address mapping to a (bucket, position) pair, so no Sybil
resistance can exist. **P0-CDIV** because two blockbrew nodes started
on the same data set will pick wildly different first-200 outbound
attempts compared to Core, and the same node restarted will pick
entirely differently — selection is determined by Go's randomised map
iteration order rather than by a deterministic, cryptographically-keyed
hash.
**Recovery**: implement `AddrInfo.GetTriedBucket(nKey, netgroupman)`,
`GetNewBucket(nKey, src, netgroupman)`, `GetBucketPosition(nKey, fNew,
bucket)` exactly mirroring `bitcoin-core/src/addrman.cpp:28-47`. The 256-bit
nKey must be persisted per-launch in peers.dat (BUG-13/15) and randomised
on first run.

### BUG-3 — `Add` does not apply time_penalty; no stochastic multi-bucket reroll  [P0]
**Gate**: G4
**Files**: `internal/p2p/addrbook.go:236-265` (AddAddress)
**Core**: `addrman.cpp:530-604` (AddSingle) — applies `time_penalty` to nTime
(0 if addr==source), increments nRefCount up to 8 with 2^N stochastic
re-roll, sets nTime from incoming, updates services bitwise-OR.
**Description**: blockbrew's `AddAddress` only writes `LastSeen=now()` on
existing entries. No nTime field, no time_penalty, no nServices field at
all on `KnownAddress`. The struct has `Addr.Services` only (set at insert).
Service bits are never updated when a peer later advertises additional
services. The stochastic multi-bucket rule (`if (insecure_rand.randrange(1
<< nRefCount) != 0) return false`) is entirely absent because
multi-bucket placement doesn't exist (BUG-1).
**Recovery**: as part of BUG-1's recovery, port `AddrManImpl::AddSingle` in
full including time_penalty + nServices |= incoming + bucket reroll.

### BUG-4 — `Good` missing; no new→tried promotion; no test-before-evict  [P0]
**Gate**: G5
**Files**: `internal/p2p/addrbook.go:354-362` (MarkSuccess — single LOC stub)
**Core**: `addrman.cpp:606-659` (Good_) — moves entry to tried, on collision
adds to `m_tried_collisions` set (cap 10) and defers via
`SelectTriedCollision`/`ResolveCollisions` workflow.
**Description**: `MarkSuccess` is a 3-line wrapper that sets LastSuccess and
zeros Attempts. There is no concept of "tried" vs "new" tables, no
collision handling, no test-before-evict, no `m_tried_collisions`. The
W104 audit (G6/G12) already flagged this; **this wave** notes the
**connection-management consequence**: feeler connections cannot resolve
tried-table collisions because the tried table doesn't exist, so
blockbrew silently loses the eclipse-resistance guarantee Core gets from
its test-before-evict discipline.
**Recovery**: implement `AddrMan.Good_(addr, test_before_evict, time)` per
Core; add `m_tried_collisions` set; wire `SelectTriedCollision()` into
the feeler path (which already exists in peermgr at lines 1008-1013
but currently calls `addrBook.PickAddress()` blindly).

### BUG-5 — `Attempt` does not gate counter on `m_last_good`  [P1]
**Gate**: G6
**Files**: `internal/p2p/addrbook.go:343-351` (MarkAttempt)
**Core**: `addrman.cpp:673-691` (Attempt_) — `if (fCountFailure &&
info.m_last_count_attempt < m_last_good) { info.m_last_count_attempt = time;
info.nAttempts++; }` — the `m_last_count_attempt < m_last_good` guard
prevents a long outage from inflating nAttempts past the IsTerrible
threshold.
**Description**: blockbrew's `MarkAttempt` always increments `Attempts++`
unconditionally. There is no `m_last_good` reference, no
`m_last_count_attempt` field. After a long outage (network down for an
hour) blockbrew will burn nAttempts past `MaxNewAttempts=10` and mark
the address `IsBad()`, even though the *node* is the one that's
unreachable, not the peers. Core specifically guards against this with
the `last_count_attempt < last_good` check: once Good has fired anywhere
in the system, only the first failure post-Good counts.
**Recovery**: add `m_last_good` to AddrMan top-level + `m_last_count_attempt`
to KnownAddress; gate the `nAttempts++` increment on
`fCountFailure && m_last_count_attempt < m_last_good`.

### BUG-6 — `Connected(addr, time)` missing entirely  [P1]
**Gate**: G7
**Files**: nothing in `internal/p2p/`; no `Connected` method on AddressBook.
**Core**: `addrman.cpp:857-874` (Connected_) — updates `info.nTime = time`
when `time - info.nTime > 20min`. `net_processing.cpp` calls this on
**disconnect** (not connect — to avoid leaking topology to spies); the
nTime field is what gets gossiped to other peers in addr messages.
**Description**: blockbrew has no AddressBook.Connected callback at all.
The `LastSuccess` field is set at the moment of MarkSuccess (handshake
completion) and never refreshed during the connection's lifetime. As a
result the `nTime` (LastSeen) values gossiped back to peers via
`MsgAddr` go stale even for currently-connected peers, and Core peers
receiving our gossip will see those addresses as "old" and may
deprioritise them.
**Recovery**: add `AddressBook.Connected(addr, time)` that updates
LastSeen with the 20-minute staleness threshold. Wire from
`peermgr.removePeer` (called on disconnect) — explicitly NOT from
connection establishment to match Core's anti-topology-leak design.

### BUG-7 — `SetServices(addr, nServices)` missing  [P1]
**Gate**: G8
**Files**: nothing in `internal/p2p/`; no SetServices method.
**Core**: `addrman.cpp:876-890` (SetServices_) — updates `info.nServices =
nServices` from the actual VERSION message handshake. Used to merge
late-learned service bits (e.g. NODE_NETWORK_LIMITED came in via DNS
seed without the bit set; we learn it on handshake).
**Description**: blockbrew sets `NetAddress.Services=0` for DNS-seeded
addresses (peermgr.go:870-874) and never updates it. Outbound peer
selection in Core uses `m_msgproc->HasAllDesirableServiceFlags(addr.nServices)`
(net.cpp:2852) to gate non-feeler connections — without SetServices,
blockbrew never sees the actual learned services so this gate is
effectively bypassed.
**Recovery**: add `AddressBook.SetServices(addr, services)`; wire from
peer.go on receipt of MsgVersion (Peer.handleVersion).

### BUG-8 — IsTerrible 5-condition predicate replaced by 1-line IsBad  [P0]
**Gate**: G9
**Files**: `internal/p2p/addrbook.go:162-167` (IsBad)
**Core**: `addrman.cpp:49-72` (IsTerrible) — five conditions:
1. `now - m_last_try <= 1min` → false (don't evict a fresh attempt)
2. `nTime > now + 10min` → true (came in a flying DeLorean — clock-skew detection)
3. `now - nTime > ADDRMAN_HORIZON (30d)` → true
4. `m_last_success == 0 && nAttempts >= 3` → true
5. `now - m_last_success > 7d && nAttempts >= 10` → true
**Description**: blockbrew's IsBad checks only condition (4) approximately
(`MaxNewAttempts=10` for never-succeeded; never-true for succeeded). All
the other conditions are missing. **Most critical missing case**: the
10-minute future-timestamp guard (case 2) — a malicious peer can gossip
addresses with nTime far in the future, and blockbrew will happily store
them without flagging. Core both removes such entries AND uses them as
an indicator the source peer is misbehaving.
**Recovery**: implement `KnownAddress.IsTerrible(now)` covering all 5
conditions; expose `ADDRMAN_HORIZON=30d`, `ADDRMAN_RETRIES=3`,
`ADDRMAN_MAX_FAILURES=10`, `ADDRMAN_MIN_FAIL=7d` constants.

### BUG-9 — GetChance lacks 0.66^nAttempts decay  [P1]
**Gate**: G10
**Files**: `internal/p2p/addrbook.go:182-214` (Chance)
**Core**: `addrman.cpp:74-87` (GetChance):
```
fChance = 1.0
if now - m_last_try < 10min: fChance *= 0.01
fChance *= pow(0.66, min(nAttempts, 8))   // 66% decay per attempt, capped at 8
```
**Description**: blockbrew's Chance does:
- if recently attempted: 0.5 (if past success) or 0 (otherwise)
- bonus *2 for prior success
- divide by `(Attempts+1)` (only when LastSuccess.IsZero)
- *1.5 if LastSeen < 3h

The `0.66^min(nAttempts,8)` exponential is replaced by `1/(Attempts+1)`
(harmonic, ~1/n decay) AND only applies when no prior success.
**Behaviour divergence**: a peer with 3 prior failures gets Chance=0.25
in blockbrew (1/4) but Chance=0.288 in Core (0.66^3=0.287496). Closer
to Core after 8 attempts (0.0303 vs 0.111 — significantly more permissive
in blockbrew, so more retries spent on dead peers). Also the *2 success
bonus has no Core analog and biases selection toward addresses we've
already connected to.
**Recovery**: replace Chance body with the exact 2-line Core formula.

### BUG-10 — `Select(new_only, networks)` algorithm absent  [P0-CDIV]
**Gate**: G11
**Files**: `internal/p2p/addrbook.go:304-340` (PickAddress)
**Core**: `addrman.cpp:693-773` (Select_) — 50/50 new/tried table choice,
bucket iteration (`bucket_count` is 1024 or 256), bucket-position scan,
chance gate with `chance_factor *= 1.2` rejection-sampling.
**Description**: blockbrew's PickAddress is a weighted-random pick over
the **entire flat map** with Chance() as the weight. This means
addresses without any successful connection compete on equal footing
with successful ones (modulo the *2 bonus from BUG-9). Core's algorithm
**explicitly** distinguishes new-table (untrusted) from tried-table
(known-reachable) and gives each a 50% share; this is what makes
eclipse via gossip-flooding hard: the attacker would have to fill 50%
of the tried table to bias selection, which requires real handshake
success.
**No `new_only` parameter** — feeler connections (which should sample only
from new table per Core net.cpp:2809) instead sample from the entire pool.
**No `networks` parameter** — there is no way to bias selection to a
particular Network (IPv4 / IPv6 / Tor / I2P / CJDNS); this kills the
MaybePickPreferredNetwork extra-network-peer feature (BUG-19).
**Recovery**: full Select_ port using BUG-1's vvNew/vvTried.

### BUG-11 — SelectTriedCollision + ResolveCollisions missing  [P0]
**Gate**: G12
**Files**: nothing in `internal/p2p/`.
**Core**: `addrman.cpp:892-981` — `SelectTriedCollision` returns the
to-be-evicted tried-table address paired with the new candidate;
feeler thread connects to that address; if connection fails, the new
candidate replaces it via `Good_(.., test_before_evict=false)`. This is
THE eclipse defence: a new gossip-learned address can only enter the
tried table by proving the existing occupant of its bucket position is
unreachable.
**Description**: completely absent. `m_tried_collisions` set absent.
Feeler path in `connectionHandler` at line 1009 calls `addrBook.PickAddress()`,
which has no notion of test-before-evict targets. blockbrew's feelers
therefore probe random addresses to determine reachability but never
use the result to evict stale tried-table entries (because there's no
tried table).
**Recovery**: paired with BUG-4 — both depend on the new/tried split.

### BUG-12 — GetAddr(max_addresses, max_pct, network, filtered) missing  [P0]
**Gate**: G13
**Files**: only AddressBook.AllAddresses (returns everything), Good (returns
addresses with LastSuccess set). No max-count / max-percent / network /
filtered semantics.
**Core**: `addrman.cpp:792-831` (GetAddr_) — samples `min(max_pct * size /
100, max_addresses)` entries via Fisher-Yates partial shuffle, with
optional network filter and IsTerrible filter.
**Description**: blockbrew has no GetAddr equivalent for responding to
incoming `getaddr` messages. The peermgr does call `addrBook.AddAddresses`
on incoming addr messages but exposes NO outbound getaddr handler returning
addresses from our book. Searching `getaddr` in the codebase:
- peer.go line ~770: SendMessage(&MsgGetAddr{}) — **outbound only**
- nothing handles **inbound** getaddr by returning our address book.

This means blockbrew never gossips addresses to peers, ever. Other nodes
on the network do not learn our peers from us, breaking the gossip
fabric. A network of 100% blockbrew nodes would not propagate addresses
at all.
**Recovery**: add `AddressBook.GetAddr(max_addresses=1000, max_pct=23,
network=nil, filtered=true)` per Core spec; wire to `Peer.handleGetAddr`
inbound dispatch.

### BUG-13 — nKey not randomised, not persisted  [P0-CDIV]
**Gate**: G14
**Files**: nothing in `internal/p2p/`.
**Core**: `addrman.cpp:89-94` (AddrManImpl ctor) —
`nKey{deterministic ? uint256{1} : insecure_rand.rand256()}`; serialised
to peers.dat byte 0..31.
**Description**: no nKey field exists. The whole point of nKey is to
prevent an attacker from precomputing which bucket their addresses will
land in (which is the entire basis of Sybil resistance). Without it,
even if BUG-1/BUG-2 were fixed, the bucket assignment would be globally
deterministic and an attacker could pre-compute exactly how many
distinct entries they need to fill a target node's tried table.
**P0-CDIV** because once BUG-1/2 are fixed, two blockbrew nodes with the
same peers.dat will still pick different first-N peers because of nKey
randomisation, matching Core exactly.
**Recovery**: add `nKey [32]byte` to AddressBook, randomise on first
run, persist as bytes 0..31 of peers.dat (after format header).

### BUG-14 — GetGroup not threaded INTO bucket selection  [P0-CDIV]
**Gate**: G15
**Files**: `internal/p2p/asmap.go:383-401` (GetGroup) — exists, returns
correct bytes; `internal/p2p/peermgr.go:1225-1234` (getNetGroup) — used
ONLY as a diversity-tracking opaque key, never fed to a bucket hash
because the bucket hash doesn't exist (BUG-2). FIX-51 was the deferred
plan to wire asmap into AddrMan bucketing per the W104 commit history
and `asmap.go:381` "Note: this is not yet wired into AddrMan bucket
hashing (deferred to FIX-51)".
**Core**: `addrman.cpp:31` — `GetTriedBucket` consumes `netgroupman.GetGroup(*this)`
INSIDE the hash; `:38` — `GetNewBucket` consumes both ourgroup and
sourcegroup. This is the **single most important** Sybil-resistance
input.
**Description**: even when asmap is loaded, the AS-derived group is
**not** used in bucket hashing because the bucket structure doesn't
exist. The asmap value flows into `pm.subnetCounts[group]` and is
consulted only to enforce "1 outbound connection per group" diversity
in `pickAddressWithDiversity` — a coarser, weaker check than Core's.
**Recovery**: BUG-2 + BUG-14 are coupled. Once GetTriedBucket /
GetNewBucket exist, GetGroup must be called inside them per Core.

### BUG-15 — peers.dat persistence ENTIRELY MISSING  [P0]
**Gate**: G16
**Files**: nothing in `internal/p2p/`; AddressBook has no Save/Load methods.
**Core**: `addrman.cpp:112-378` (Serialize / Unserialize) — versioned
binary format including nKey, nNew, nTried, all entries, bucket index
restoration logic across asmap version changes.
**Description**: This was flagged by W104 BUG-21. The W128 angle is the
**operational consequence**: every restart of a blockbrew node is a
cold start. The address book is reconstructed entirely from DNS seeds,
which is exactly what an attacker who controls DNS resolution wants —
they can serve different addresses on each restart and bias the entire
peer set. Anchors (`anchors.json`, peermgr.go:1916-2006) exist but only
persist the 2 BLOCK_RELAY anchors, not the broader AddrMan.
**Recovery**: implement `Serialize`/`Deserialize` on AddressBook (post
BUG-1/2/13). Use the same `peers.dat` filename / format as Core for
zero migration cost if anyone wants to copy a Core peers.dat in.

### BUG-16 — addr_token_bucket per-peer rate limit missing  [P1]
**Gate**: G17
**Files**: nothing in `internal/p2p/`.
**Core**: `net_processing.cpp` — every Peer has `addr_token_bucket = 1.0`
with `MAX_ADDR_TO_SEND=1000` cap, drained on each received addr, refilled
at `MAX_ADDR_RATE_PER_SECOND=0.1` (one address per 10 seconds). Peers
exceeding the budget have their excess addresses silently dropped.
Documented in W104 G26 — restated here because connection-rate flooding
is part of the connman's concern.
**Description**: blockbrew accepts up to `MaxAddresses=1000` per addr
message but applies no rate limit. A misbehaving peer can fill our
address book with garbage at message-frequency rather than 0.1/s.
**Recovery**: add `addrTokenBucket float64` to Peer, drain per accepted
address, refill on `AverageAddressMessageProcessingTime` (also missing).

### BUG-17 — ADDRMAN_* constants not exposed  [P0]
**Gate**: G18
**Files**: `internal/p2p/addrbook.go:93-113` — only `MinRetryInterval=10min`,
`MaxAttempts=3`, `MaxNewAttempts=10`, `AddressBookMaxSize=10000`.
**Core**: `addrman.h:23-41` — `ADDRMAN_TRIED_BUCKETS_PER_GROUP=8`,
`ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP=64`, `ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8`,
`ADDRMAN_HORIZON=30d`, `ADDRMAN_RETRIES=3`, `ADDRMAN_MAX_FAILURES=10`,
`ADDRMAN_MIN_FAIL=7d`, `ADDRMAN_REPLACEMENT=4h`, `ADDRMAN_SET_TRIED_COLLISION_SIZE=10`,
`ADDRMAN_TEST_WINDOW=40min`.
**Description**: All the Core invariants from `addrman.h` are missing as
public constants. `MaxAttempts=3` is a *misnomer* — it's used in IsBad
only when LastSuccess.IsZero(), so the actual threshold for never-succeeded
addresses is `MaxNewAttempts=10` (matches Core's ADDRMAN_MAX_FAILURES).
The 3 value doesn't correspond to anything in Core.
**Recovery**: add the constants; reconcile MaxAttempts (rename to
ADDRMAN_RETRIES=3 for the gossip-once-succeeded threshold, since W104
G8 noted this).

### BUG-18 — ThreadOpenConnections lacks Poisson timing  [P0]
**Gate**: G19
**Files**: `internal/p2p/peermgr.go:953-1046` (connectionHandler)
**Core**: `net.cpp:2562-2876` (ThreadOpenConnections) — uses
`rng.rand_exp_duration(FEELER_INTERVAL=2min)` for `next_feeler`,
`rand_exp_duration(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min)` for
`next_extra_block_relay`, `rand_exp_duration(EXTRA_NETWORK_PEER_INTERVAL=5min)`
for `next_extra_network_peer`.
**Description**: blockbrew uses a `ConnectionAttemptInterval=30s` fixed
ticker for outbound full-relay + block-relay. It DOES use Poisson for
feelers and extra-block-relay (peermgr.go:1006, 1017 — `poissonDuration`
helper), but the Poisson distribution implementation at lines 1050-1069
has bugs:
- `delay = -float64(mean) * (1.0 / (1.0 - u + 0.000001))` — this is NOT
  exponential. Exponential is `-mean * ln(u)` not `mean / (1-u)`. The
  current formula has heavy-tailed Pareto-like distribution unbounded at
  u→1 (capped at 4× mean by the postcondition, which itself diverges
  from Core).
- The cap at 4× mean changes the distribution shape vs. Core's true
  exponential.
- No `next_extra_network_peer` timer.
**P0** because: predictable connection timing is a fingerprint —
attackers timing inbound connections can identify blockbrew nodes
by their non-exponential, 30s-modular outbound cadence.
**Recovery**: replace the formula with `delay = -float64(mean) * math.Log(u)`;
remove the 4× cap; add `nextExtraNetworkPeer` timer; drop the 30s
ticker for outbound full-relay in favour of the same Poisson cadence
Core uses (within the iterating connect loop).

### BUG-19 — MaybePickPreferredNetwork missing  [P0]
**Gate**: G20
**Files**: nothing in `internal/p2p/`.
**Core**: `net.cpp:2514-2528` (MaybePickPreferredNetwork) — shuffles
{IPv4, IPv6, Tor, I2P, CJDNS} and returns the first network that is
(a) reachable, (b) has 0 current outbound connections, (c) has at least
one address in AddrMan. Used to ensure we attempt at least one outbound
peer per reachable network type once full-relay is saturated, mitigating
single-network eclipse.
**Description**: blockbrew has no network-preference logic. The
addrBook.AddAddressV2 path explicitly **discards** Tor/I2P/CJDNS
addresses (W104 BUG-1, peermgr.go addrbook.go:286-289 "TODO"), so even
if MaybePickPreferredNetwork were ported there'd be no Tor/I2P/CJDNS
addresses to attempt — but the gap exists at the connman layer
independent of W104.
**Recovery**: after fixing W104 BUG-1 (store Tor/I2P/CJDNS), add
`MaybePickPreferredNetwork()` per Core; thread `preferred_net` into
the outbound select path.

### BUG-20 — outbound_ipv46_peer_netgroups: limit is 1 per asmap-group BUT 2 per /16 fallback  [P0-CDIV]
**Gate**: G21
**Files**: `internal/p2p/peermgr.go:1236-1245` (maxPeersPerGroup)
**Core**: `net.cpp:2656,2690` — `outbound_ipv46_peer_netgroups` is a
**std::set**, so by construction allows exactly 1 outbound per netgroup
regardless of asmap presence.
**Description**: blockbrew's maxPeersPerGroup returns 1 with asmap loaded
(matching Core) but **2** without asmap (`MaxPeersPerSubnet=2`). This
diverges from Core in the no-asmap case — Core treats the /16 group as
unique (`GetGroup` returns `[NET_IPV4, /16 prefix]` and the set still
allows only 1). For blockbrew nodes running without an asmap (which is
the default), this means an attacker controlling a /16 can establish 2
outbound connections from us to themselves, halving the eclipse
threshold relative to Core. P0-CDIV because two networks of blockbrew
+ Core mixed will diverge in attack resistance per netgroup.
**Recovery**: change `MaxPeersPerSubnet=2` → `1`; rename to
`MaxPeersPerNetGroup=1`. Document if the `2` was an intentional relaxation.

### BUG-21 — ConnectionType incomplete: missing ADDR_FETCH and PRIVATE_BROADCAST  [P1]
**Gate**: G22
**Files**: `internal/p2p/peermgr.go:24-49` (ConnType enum)
**Core**: `node/connection_types.h` — 7 types: MANUAL, OUTBOUND_FULL_RELAY,
BLOCK_RELAY, FEELER, ADDR_FETCH, INBOUND, PRIVATE_BROADCAST.
**Description**: blockbrew has 5 types (ConnFullRelay, ConnBlockRelayOnly,
ConnFeeler, ConnInbound, ConnManual). ADDR_FETCH and PRIVATE_BROADCAST
are missing.
- **ADDR_FETCH**: a short-lived outbound connection that requests an addr
  message and immediately disconnects. Used to bootstrap on empty addrman.
  Without it, blockbrew falls back to feeler probes which take 2+ minutes
  to materialize an initial set of usable addresses.
- **PRIVATE_BROADCAST**: post-2024 Core feature for unlinkable
  transaction announcement (one-off connection that sends a single tx and
  disconnects). blockbrew doesn't implement private broadcast at all.
**Recovery**: add the two enum values; implement ADDR_FETCH path
(short-lived getaddr-then-disconnect) parallel to feeler.

### BUG-22 — Fixed seeds fallback missing  [P1]
**Gate**: G24
**Files**: nothing in `internal/p2p/`. Search for FixedSeeds returns 0 hits
in internal/.
**Core**: `net.cpp:2606-2645` — when (a) `-dnsseed=0` or DNS is unreachable
AND (b) addrman is empty for some reachable network AND (c) 60s have
passed, Core loads `m_params.FixedSeeds()` (chainparams hard-coded list
of fallback IP addresses for each network) into addrman.
**Description**: blockbrew has DNS seeds (peermgr.go:1116-1140) but no
fallback. If all DNS seeds are unreachable (e.g. air-gapped network with
NAT64 issues, or simply DNS-blocking firewall), blockbrew will idle
indefinitely with empty addrman. Core would still connect via fixed
seeds.
**Recovery**: ship a hard-coded list of fallback IPs per network in
`internal/consensus/chainparams.go` matching `bitcoin-core/src/chainparamsseeds.h`.

### BUG-23 — AttemptToEvictConnection structure diverges from Core 4-stage pipeline  [P0-CDIV]
**Gate**: G25
**Files**: `internal/p2p/peermgr.go:1487-1614` (tryEvictInboundPeer)
**Core**: `node/eviction.cpp:178-240` (SelectNodeToEvict) — strict pipeline:
1. ProtectNoBanConnections (filter out NetPermissionFlags::NoBan)
2. ProtectOutboundConnections (filter out non-INBOUND)
3. EraseLastKElements(CompareNetGroupKeyed, 4) — 4 deterministic netgroup-keyed
4. EraseLastKElements(ReverseCompareNodeMinPingTime, 8) — 8 best ping
5. EraseLastKElements(CompareNodeTXTime, 4) — 4 most-recent tx
6. EraseLastKElements(CompareNodeBlockRelayOnlyTime, 8) — 8 block-relay
7. EraseLastKElements(CompareNodeBlockTime, 4) — 4 most-recent block
8. ProtectEvictionCandidatesByRatio (longest-uptime half + 25% disadvantaged-net)
9. prefer_evict filter
10. Identify most-populated netgroup, evict youngest member.
**Description**: blockbrew's tryEvictInboundPeer:
1. Builds a `subnetBest` map keeping 1 per subnet (loose analog of #3)
2. Adds top-4 by lastBlockTime to protected set
3. Adds top-4 by PingLatency to protected set
4. Adds top-4 longest-connected to protected set
5. Picks the OVER-REPRESENTED-subnet candidate; tie-break by newest connection.

Steps #5-#7 from Core (TXTime, BlockRelayOnlyTime, ProtectByRatio,
prefer_evict, ProtectNoBan, ProtectOutbound) are MISSING. The
overall structure protects 4+4+4 = up to 12 peers and 1-per-subnet,
where Core protects 4+8+4+8+4 = up to 28 + the half-uptime + 25%
network-diverse. Core protects roughly 50% of inbound; blockbrew
protects far less which means an attacker establishing 117 inbound
to use up our slots and trigger eviction can chase out far more
honest peers than they could against Core.

**Severity P0-CDIV**: under sustained inbound flood, blockbrew and
Core will pick different victims, with **systematically different**
outcomes — blockbrew evicts more honest inbound peers under the
same attack workload.
**Recovery**: port `node/eviction.cpp` SelectNodeToEvict end-to-end —
this is the easiest of the P0-CDIVs to land because the algorithm is
a self-contained ~100 LOC of sort+erase chains.

### BUG-24 — Eviction protect: no per-disadvantaged-network ratio  [P0]
**Gate**: G26
**Files**: `internal/p2p/peermgr.go:1487-1614` (tryEvictInboundPeer)
**Core**: `node/eviction.cpp:105-176` (ProtectEvictionCandidatesByRatio) —
reserve up to 25% of protected slots for {Tor, I2P, CJDNS, localhost}
peers; round-robin allocation; fill remaining 25% by longest uptime.
**Description**: blockbrew has no network-class awareness in eviction —
PeerInfo.subnet is the /16 or asmap-derived bytes, with no NET_ONION /
NET_I2P / NET_CJDNS / NET_LOCAL classification. Tor inbound peers are
treated identically to IPv4 inbound for protection, undoing Core's
deliberate over-protection of disadvantaged (high-latency, often
single-hop-discoverable) networks.
**Recovery**: add `Network` field to PeerInfo (set from peer.addr +
inbound_onion detection); port ProtectEvictionCandidatesByRatio.

### BUG-25 — BanMan supports IP only, NOT CSubNet (CIDR ban)  [P0]
**Gate**: G27
**Files**: `internal/p2p/peermgr.go:476-508` (BanPeer), :679-697 (IsBanned)
**Core**: `banman.h:67-69`, `banman.cpp:104-122,130-154` — Ban(CSubNet,
...) accepts a CIDR, IsBanned(CNetAddr) iterates and calls
`sub_net.Match(net_addr)`.
**Description**: blockbrew's BanPeer accepts an `addr string`, calls
`extractIP(addr)` to strip the port, and stores as plain IP string in
`banned map[string]*BanInfo`. There is no way to ban a /16 or /24 via
setban. Operators must add 256 individual IPs to ban a /24. The Bitcoin
Core setban RPC supports both `<address>` and `<subnet>` (e.g.
`192.168.0.0/16`), and `bitcoin-cli help setban` documents this.
**Recovery**: refactor `banned` to `map[string]*BanInfo` keyed by a
`CIDR or IP` normalised string; on IsBanned, iterate banned entries
and CIDR-match (Go's `net.IPNet.Contains`).

### BUG-26 — Discouragement bloom filter missing; ban is hard reject  [P0]
**Gate**: G28
**Files**: `internal/p2p/peermgr.go:476-508,679-697` (Ban path)
**Core**: `banman.h:98` — `CRollingBloomFilter m_discouraged{50000, 0.000001}`;
`banman.cpp:83-87,124-128` — Discourage(addr) inserts into filter;
IsDiscouraged checks contains. In net.cpp:1813-1818, accepting an
inbound from a *discouraged* peer is allowed unless inbound slots are
almost full, in which case discouraged peers are dropped — a SOFTER
treatment than IsBanned (always reject).
**Description**: blockbrew has no Discourage path. Every misbehavior
triggers `BanPeer` (peermgr.go:644 `pm.BanPeer(addr, DefaultBanDuration,
...)`) which is a hard 24h IP block. Core's design specifically
**rejects** the unbounded-banlist approach (`banman.h:58-61` quotes the
2024 CVE disclosure) and uses a 50k-element rolling bloom to
**probabilistically** discourage. The bloom filter has bounded memory
(~125 KB) and gradually forgets, so misbehaving peers eventually get
re-allowed.
**Recovery**: add `discouraged *RollingBloomFilter` to PeerManager (5000
elements, 0.001 fp rate); add Discourage(ip) + IsDiscouraged(ip); split
`handlePeerBan` into Discourage (soft, no setban RPC entry) and Ban
(hard, setban RPC). Bonus W104 ties here: Core also uses the discouraged
filter for inbound peer admission decisions (`prefer_evict` flag).

### BUG-27 — Banlist persisted as JSON, not Core-compatible banlist.dat  [P2]
**Gate**: G29
**Files**: `internal/p2p/peermgr.go:1813-1914` (saveBanList, loadBanList)
**Core**: `addrdb.cpp` CBanDB — writes a serialized banlist.json
(actually JSON, since the 2018 banlist.dat → banlist.json migration in
PR #14123) or banlist.dat (legacy binary).
**Description**: blockbrew uses JSON like Core's post-2018 path but the
schema differs:
- blockbrew: `{"bans": {"<ip>": {"ban_until": "ISO8601", "ban_reason": "...",
  "ban_created": "ISO8601"}}}`
- Core: `[ ... array of {"version": 1, "address": "...", "ban_created":
  unix_seconds, "banned_until": unix_seconds} ]`

A blockbrew banlist.json cannot be loaded by Core and vice versa. Low
severity because it's operational only.
**Recovery**: align JSON schema with Core's `banlist.json`.

---

## Sub-area summary

| Sub-area | Gates | Bugs | Worst |
|----------|-------|------|-------|
| AddrMan structure & bucketing | G1-G3, G14-G15 | 4 (1+2+13+14) | P0-CDIV |
| AddrMan operations (Add/Good/Attempt/Connected/SetServices) | G4-G8 | 5 (3+4+5+6+7) | P0 |
| AddrMan quality (IsTerrible, GetChance) | G9-G10 | 2 (8+9) | P0 |
| AddrMan selection (Select, SelectTriedCollision, GetAddr) | G11-G13 | 3 (10+11+12) | P0-CDIV |
| Persistence & constants | G16-G18 | 3 (15+16+17) | P0 |
| ThreadOpenConnections | G19-G24 | 5 (18+19+20+21+22) | P0-CDIV |
| AttemptToEvictConnection | G25-G26 | 2 (23+24) | P0-CDIV |
| BanMan + discouragement | G27-G30 | 3 (25+26+27) | P0 |

---

## Top-5 findings (severity-weighted)

1. **BUG-2 (P0-CDIV, G3)**: Bucketing hash absent. No `GetTriedBucket` /
   `GetNewBucket` / `GetBucketPosition`. Whole Sybil-resistance edifice
   missing. Blocks BUG-4/10/11/14.
2. **BUG-23 (P0-CDIV, G25)**: AttemptToEvictConnection 5-stage pipeline
   compressed to 3-stage; misses TX-time, block-relay-only-time, and
   ProtectByRatio. Under inbound flood, blockbrew systematically evicts
   more honest peers than Core.
3. **BUG-12 (P0, G13)**: GetAddr response handler is **entirely missing** —
   blockbrew never gossips addresses to peers. A network of 100% blockbrew
   nodes would not propagate addresses at all.
4. **BUG-15 (P0, G16)**: peers.dat persistence missing. Every restart is a
   cold start through DNS seeds; DNS-resolution attacker can bias the
   initial peer set on each restart.
5. **BUG-26 (P0, G28)**: Discouragement rolling-bloom filter missing.
   Every misbehavior is a 24h hard ban; this is exactly the unbounded-
   banlist anti-pattern Core warns against (banman.h:58-61) and the
   ban map can grow without bound under a misbehavior-fuzz attack.

---

## Cross-wave audit-framework notes

- This audit confirms W104 BUG-21 (no peers.dat) and W104 BUG-6+12 (no
  buckets) at the **operational consequence level**: not just "the
  structure is wrong" but "the structure being wrong breaks
  consensus-adjacent invariants (CDIV) in eviction and outbound
  selection".
- This audit confirms W115 G14 + G15 (asmap not used for bucketing) but
  identifies the wider implication: even FIX-51 (the planned asmap
  integration) is **inert** as long as BUG-1/2 are unresolved.
- This audit **disagrees** with the W104 audit's framing of the
  AddressBook as "AddrMan-equivalent". A flat map is not a partial
  AddrMan; it's a different data structure entirely, with NONE of the
  Sybil-resistance properties Core's AddrMan guarantees.

---

## Out of scope (deferred)

- BIP-155 addrv2 (W117) — Tor v3 / I2P / CJDNS storage gap noted as
  contributor to BUG-19 but not re-audited here.
- Addr relay scheduling (W104) — ADDRESS_RELAY_INTERVAL, m_addr_known
  bloom filter, etc. covered in W104.
- Asmap codec internals (W115) — only the integration with bucketing
  re-audited here as BUG-14.
- Peer-misbehavior scoring (W99) — covered there; W128 only re-audits
  the IP-only Ban flow as BUG-25/26.
