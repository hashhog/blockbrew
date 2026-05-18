# W151 — Package relay + BIP-125 RBF rules 2-5 (blockbrew)

**Wave:** W151 — `AcceptPackage`, `AcceptMultipleTransactions`, `AcceptSubPackage`,
`PackageMempoolChecks`, `IsTopoSortedPackage`, `IsWellFormedPackage`,
`IsChildWithParents`, `IsChildWithParentsTree`, `IsConsistentPackage`,
`GetPackageHash`; BIP-125 Rules 2/3/4/5 (`HasNoNewUnconfirmedInputs`,
`EntriesAndTxidsDisjoint`, `PaysForRBF`, `GetEntriesForConflicts`),
`MAX_REPLACEMENT_CANDIDATES=100`, `MAX_PACKAGE_COUNT=25`,
`MAX_PACKAGE_WEIGHT=404000`, `MAX_BIP125_RBF_SEQUENCE=0xFFFFFFFD`,
`DEFAULT_INCREMENTAL_RELAY_FEE=100`, `DEFAULT_MIN_RELAY_TX_FEE=100`,
`WALLET_INCREMENTAL_RELAY_FEE=5000`, `submitpackage` RPC,
`testmempoolaccept` RPC (package mode), BIP-331 `sendpackages` /
`getpkgtxns` / `pkgtxns` wire messages, ATMP `m_allow_replacement`
gate (`bip125-replacement-disallowed`), `ReplacementChecks`,
`PackageRBFChecks`, `ImprovesFeerateDiagram`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/policy/rbf.h:26` — `MAX_REPLACEMENT_CANDIDATES{100}`
  (Rule #5 cap on UNIQUE CLUSTERS, not individual tx count, post-Core-27
  cluster mempool).
- `bitcoin-core/src/policy/rbf.cpp:24-50` — `IsRBFOptIn` (BIP-125 §"Summary"
  signal: tx itself OR walk in-mempool ancestors via
  `CalculateMemPoolAncestors`).
- `bitcoin-core/src/policy/rbf.cpp:58-83` — `GetEntriesForConflicts` →
  `GetUniqueClusterCount(iters_conflicting) > MAX_REPLACEMENT_CANDIDATES`
  ("too many conflicting clusters (%u > 100)"); then
  `pool.CalculateDescendants(it, all_conflicts)` for fee/eviction math.
- `bitcoin-core/src/policy/rbf.cpp:85-98` — `EntriesAndTxidsDisjoint`:
  the replacement's in-mempool ancestor set MUST NOT intersect the set of
  direct conflict txids ("%s spends conflicting transaction %s").
- `bitcoin-core/src/policy/rbf.cpp:100-125` — `PaysForRBF`:
  - **Rule 3:** `replacement_fees >= original_fees` (modified fees, NOT
    raw); on fail emits "rejecting replacement %s, less fees than
    conflicting txs; %s < %s".
  - **Rule 4:** `(replacement_fees - original_fees) >= relay_fee.GetFee(replacement_vsize)`;
    on fail emits "rejecting replacement %s, not enough additional fees
    to relay; %s < %s". `relay_fee` is the mempool's
    `m_opts.incremental_relay_feerate` (NOT min relay).
- `bitcoin-core/src/policy/rbf.cpp:127-140` — `ImprovesFeerateDiagram`
  (Core 27+ cluster-mempool): replacement must strictly improve the
  feerate diagram via `changeset.CalculateChunksForRBF()`; failure
  emits "replacement-failed".
- `bitcoin-core/src/policy/packages.h:19,24` — `MAX_PACKAGE_COUNT{25}`,
  `MAX_PACKAGE_WEIGHT = 404'000`.
- `bitcoin-core/src/policy/packages.cpp:43-50` — `IsTopoSortedPackage`.
- `bitcoin-core/src/policy/packages.cpp:52-77` — `IsConsistentPackage`:
  immediately returns `false` if any tx has `vin.empty()` (CRITICAL — no
  inputs in an unconfirmed tx = malformed package).
- `bitcoin-core/src/policy/packages.cpp:79-117` — `IsWellFormedPackage`:
  count + weight + duplicates ("package-contains-duplicates") +
  topo-sort ("package-not-sorted") + IsConsistentPackage
  ("conflict-in-package"), all stamped on a `PackageValidationState`.
- `bitcoin-core/src/policy/packages.cpp:119-149` — `IsChildWithParents`
  + `IsChildWithParentsTree`.
- `bitcoin-core/src/policy/packages.cpp:151-170` — `GetPackageHash`:
  SHA-256 of WTxIDs sorted in little-endian numeric order. Used to
  dedup BIP-331 package requests.
- `bitcoin-core/src/policy/policy.h:48,70` — `DEFAULT_INCREMENTAL_RELAY_FEE{100}`,
  `DEFAULT_MIN_RELAY_TX_FEE{100}`. **Both 100 sat/kvB.**
- `bitcoin-core/src/node/mempool_args.cpp:69` —
  `static_assert(DEFAULT_MIN_RELAY_TX_FEE == DEFAULT_INCREMENTAL_RELAY_FEE)`
  (Core enforces equality at compile time).
- `bitcoin-core/src/wallet/wallet.h:124` —
  `WALLET_INCREMENTAL_RELAY_FEE = 5000` sat/kvB (5 sat/vB; the wallet
  uses a higher floor than node so future-node-policy bumps don't break
  in-flight RBF replacements).
- `bitcoin-core/src/util/rbf.h:21` — `SignalsOptInRBF(const CTransaction& tx)`.
- `bitcoin-core/src/validation.cpp:837-840` — ATMP `PreChecks`:
  `if (!args.m_allow_replacement)` → reject with
  `"bip125-replacement-disallowed"` (TX_MEMPOOL_POLICY). This is the
  context-aware "replacement is being attempted but caller said no
  replacements" gate (e.g. test-accept mode).
- `bitcoin-core/src/validation.cpp:892` — ATMP uses
  `m_active_chainstate.m_chain.Height() + 1` for `CheckTxInputs`
  ("mempool holds txs for next block"). Cross-cite W150 BUG-9
  off-by-one.
- `bitcoin-core/src/validation.cpp:984-1035` — `ReplacementChecks`:
  `GetEntriesForConflicts` (Rule #5) → loop modified-fee sum → `PaysForRBF`
  (Rules 3+4) → stage removal → cluster size limit
  (`CheckMemPoolPolicyLimits`) → `ImprovesFeerateDiagram`.
- `bitcoin-core/src/validation.cpp:1037-1196` — `PackageRBFChecks`:
  package must be 1-parent-1-child, no in-mempool ancestors,
  aggregate-conflicts pass `GetEntriesForConflicts` (Rule 5 uses TOTAL
  cluster count for the package, not per-tx), `PaysForRBF` against
  aggregate fees + vsize, `ImprovesFeerateDiagram`.
- `bitcoin-core/src/validation.cpp:1432-1564` —
  `AcceptMultipleTransactionsInternal`: `IsWellFormedPackage` first,
  then `PreChecks` loop (with `m_viewmempool.PackageAddTransaction`
  feeding child inputs from in-package parents), TRUC, package feerate
  vs `CheckFeeRate`, `PackageRBFChecks` if any RBF detected,
  `CheckMemPoolPolicyLimits`, `CheckEphemeralSpends`, `PolicyScriptChecks`,
  `SubmitPackage`.
- `bitcoin-core/src/validation.cpp:1622-1771` — `AcceptPackage` dispatcher:
  context-free `IsWellFormedPackage` + `IsChildWithParents`, then
  per-tx `AcceptSubPackage({tx}, args)` first (single-tx pass), then
  package eval of the survivors that failed with `TX_RECONSIDERABLE` or
  `TX_MISSING_INPUTS`.
- `bitcoin-core/src/validation.cpp:1807-1834` — `ProcessNewPackage`
  entry-point (test-accept path goes through `AcceptMultipleTransactionsAndCleanup`,
  not the dispatcher; production path uses `AcceptPackage`).
- BIP-125 §"Summary" — opt-in via nSequence ≤ `MAX_BIP125_RBF_SEQUENCE`
  (`SEQUENCE_FINAL - 2 = 0xFFFFFFFD`).
- BIP-331 — `sendpackages` versions bitfield, `getpkgtxns` /
  `pkgtxns` round-trip.

**Files audited**
- `internal/mempool/mempool.go` —
  - constants: `MaxRBFReplacedTxs = 100` (line 195),
    `MaxBIP125RBFSequence = 0xFFFFFFFD` (line 210),
    `DefaultMempoolFullRBF = true` (line 225),
    `MaxPackageCount = 25` (line 258), `MaxPackageWeight = 404_000`
    (line 262), `MinRelayFeeRate = 1000` (line 390),
    `IncrementalRelayFee = 1000` (line 391).
  - RBF entry-point: `validateTransactionLocked` (line 3611-3717,
    package-mode) + `AcceptToMemoryPool`/`AddTransaction` (line 1088-1346,
    single-tx mode) → both gather `conflictingTxs` → call
    `checkRBFLocked` (line 2729-2907).
  - `signalsRBF` (line 2918-2925), `SignalsRBFForRPC` (line 2939-2941),
    `signalsBIP125ReplaceableLocked` (line 833-855),
    `MempoolFullRBF` accessor (line 858-865, accessor name `FullRBF`
    actually).
  - Rule 2: `checkRBFNoNewUnconfirmedInputsLocked` (line 2961-2996).
  - Rule 5: `if totalEvicted > MaxRBFReplacedTxs` (line 2855-2858)
    — counts INDIVIDUAL TXS, NOT clusters (see BUG-3).
  - Rule 3: `if newFee < totalConflictingFee` (line 2873-2876), uses
    `getModifiedFeeLocked` (line 2835/2845).
  - Rule 4: `minFeeBump := (newVSize * mp.config.IncrementalRelayFee + 999) / 1000`
    (line 2883), `if newFee-totalConflictingFee < minFeeBump` (line 2884).
  - Feerate diagram: `checkRBFImprovesFeerateDiagramLocked` (line 3016-3198).
  - Package: `IsTopoSortedPackage` (line 3221-3237), `IsConsistentPackage`
    (line 3241-3263), `IsChildWithParents` (line 3267-3290),
    `IsChildWithParentsTree` (line 3294-3314), `CheckPackage`
    (line 3317-3358), `AcceptPackage` (line 3363-3386),
    `acceptSingleTxPackage` (line 3389-3452), `acceptMultiTxPackage`
    (line 3456-3605).
- `internal/rpc/methods.go` — `handleSubmitPackage` (line 1105-1276),
  `handleGetMempoolInfo` (line 1290-1322).
- `internal/rpc/rawtx_methods.go` — `handleTestMempoolAccept` (line
  206-374). Per-tx-loop independent processing, no package mode.
- `internal/rpc/server.go:570-573` — RPC dispatch table (submitpackage +
  testmempoolaccept).
- `internal/rpc/bumpfee_methods.go` — `handleBumpFee` / `handlePSBTBumpFee`
  delegating to `wallet.BumpFee`.
- `internal/wallet/bumpfee.go` — `BumpFee` (line 116-274); auto-mode bump
  computation at line 217 (`bump := int64(math.Ceil(1.0 * float64(vsize)))`
  = 1 sat/vB hard-coded), explicit-mode at line 211-215 (only checks
  `req.FeeRate > origFeeRate`).
- `internal/wallet/wallet.go:162` — `BIP125RBFSequence uint32 = 0xFFFFFFFD`
  (wallet's copy, parallel to `mempool.MaxBIP125RBFSequence`).
- `internal/wallet/wallet.go:970` — `CreateTransaction` emits
  `Sequence: BIP125RBFSequence` on every input (post FIX-61).
- `internal/p2p/msg_packages.go` — `MsgSendPackages`, `MsgGetPkgTxns`,
  `MsgPkgTxns` (BIP-331 wire codecs).
- `internal/p2p/peer.go:105-107,189,562,725-738,779,858-879,1259` —
  package-relay listener slots, peer-side `packageVersions` field,
  handshake send of `MsgSendPackages{PackageRelayVersionAncestor}` at
  line 779.
- `cmd/blockbrew/main.go:1193-1234` — production wiring of
  `OnGetPkgTxns` / `OnPkgTxns` handlers (`OnSendPackages` intentionally
  unwired — comment at line 1195).
- `cmd/blockbrew/main.go:469` — `-mempoolfullrbf` CLI flag (default
  `true`, wired via `cfg.MempoolFullRBF`).

---

## Gate matrix (40 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | BIP-125 Rule 1 signaling | G1: `MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD` constant | PASS (`mempool.go:210`, `wallet.go:162`) |
| 1 | … | G2: signaling probe is `nSequence ≤ 0xFFFFFFFD` (NOT `< SEQUENCE_FINAL`) | PASS (`mempool.go:2920`) |
| 1 | … | G3: ancestor-walk fallback if tx itself doesn't signal | PASS (`mempool.go:2767-2775`) |
| 1 | … | G4: skipped under `-mempoolfullrbf=true` | PASS (`mempool.go:2760`) |
| 2 | BIP-125 Rule 2 (no new unconfirmed inputs) | G5: allowed-set = direct conflicts ∪ ancestors of conflicts | PASS (`mempool.go:2970-2978`) |
| 2 | … | G6: confirmed (UTXO-set) inputs always allowed | PASS (`mempool.go:2985-2987`) |
| 3 | BIP-125 Rule 3 (replacement_fees ≥ original) | G7: uses MODIFIED fees, not raw | PASS (`mempool.go:2835` via `getModifiedFeeLocked`; post-FIX-72) |
| 3 | … | G8: ≥ not > (equal fees allowed; Rule 4 enforces bump separately) | PASS (`mempool.go:2873` `if newFee < totalConflictingFee`) |
| 3 | … | G9: includes conflict's descendant fees | PASS (`mempool.go:2843-2848`) |
| 3 | … | G10: wallet-side bumpfee Rule 3 precise formula `old_fee + incrementalRelayFee.GetFee(vsize)` | **BUG-7 (P0-CDIV)** — `wallet/bumpfee.go:217` uses hard-coded `1 * vsize` (1 sat/vB) instead of `IncrementalRelayFee.GetFee(vsize)`. Cross-cite W130 BUG-1 (wallet-test pin), `WALLET_INCREMENTAL_RELAY_FEE = 5000` (W130 BUG-2) is absent. This is the TWO-PIPELINE GUARD: wallet bump computation uses a different formula AND a different constant than the relay-side Rule 4 check |
| 4 | BIP-125 Rule 4 (PaysForRBF additional ≥ relay × vsize) | G11: uses `IncrementalRelayFee` separate from `MinRelayFeeRate` | PASS by name (`mempool.go:2879-2883`); BUT see G12 |
| 4 | … | G12: default `IncrementalRelayFee = 100 sat/kvB` (Core's `DEFAULT_INCREMENTAL_RELAY_FEE`) | **BUG-1 (P0-CDIV)** — blockbrew defaults to `1000` (`mempool.go:391` `IncrementalRelayFee: 1000` + `mempool.go:645-646`), **10× Core's default**. RBF Rule 4 demands 10× the additional fee Core demands. Cross-impl divergence: a replacement that Core accepts at 0.5 sat/vB bump fails blockbrew at 0.5 sat/vB bump (blockbrew requires 1 sat/vB bump = 10×) |
| 4 | … | G13: `static_assert(DEFAULT_MIN_RELAY_TX_FEE == DEFAULT_INCREMENTAL_RELAY_FEE)` parity invariant | **BUG-1 cross-cite** — blockbrew defaults match each other (both `1000`) but both are 10× Core's default. No equivalent of Core's compile-time assert protecting future drift |
| 4 | … | G14: wallet-side `WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB` floor | **BUG-2 (P1)** — blockbrew wallet has NO equivalent constant (`grep -r WALLET_INCREMENTAL` returns only test pins flagging absence, W130 BUG-2). bumpfee auto-mode picks fixed 1 sat/vB instead of `max(node_incremental, wallet_incremental)` |
| 4 | … | G15: rounding-up via `(vsize * rate + 999) / 1000` | PASS (`mempool.go:2883`); matches Core `CFeeRate::GetFee` (rounds up) |
| 5 | BIP-125 Rule 5 (≤ MAX_REPLACEMENT_CANDIDATES) | G16: cap value = 100 | PASS (`mempool.go:195` `MaxRBFReplacedTxs = 100`) |
| 5 | … | G17: count UNIQUE CLUSTERS (Core 27+ cluster mempool), not individual txs | **BUG-3 (P0-CDIV)** — `mempool.go:2855` counts individual txs. **Comment-as-confession** at line 2853-2854: `"Core counts unique clusters; blockbrew counts individual txs (equivalent for non-cluster-mempool deployments)"`. blockbrew SHIPS a cluster mempool (`internal/mempool/cluster.go`, `mp.clusters.GetCluster`) — the equivalence note is FALSE. A replacement evicting a single 101-tx cluster passes Core's Rule 5 (`num_clusters = 1 ≤ 100`) but fails blockbrew (`totalEvicted = 101 > 100`) |
| 6 | EntriesAndTxidsDisjoint | G18: replacement's mempool ancestors don't intersect direct conflicts | PASS (`mempool.go:2796-2815`) |
| 6 | … | G19: walks ancestors AND checks the parent itself | PASS (`mempool.go:2811-2814`) |
| 7 | ImprovesFeerateDiagram (Core 27+) | G20: replacement strictly improves chunk-based feerate diagram | PASS (`mempool.go:3016-3198`); algorithm matches Core's `CalculateChunksForRBF` shape (simulated cluster replacement) |
| 7 | … | G21: error stamp matches Core wire token `"replacement-failed"` | **BUG-9 (P1)** — blockbrew returns `ErrRBFFeerateDiagram = "insufficient feerate: does not improve feerate diagram"` (`mempool.go:95`). Core: `"replacement-failed"` (`rbf.cpp:137`) on `DiagramCheckError::FAILURE`. Monitoring tooling that greps reject reasons sees different tokens |
| 8 | ATMP `m_allow_replacement` gate | G22: when caller (test-accept / package-eval-without-replacement) disables replacement, conflicting inputs reject with `"bip125-replacement-disallowed"` | **BUG-4 (P0-CDIV)** — blockbrew has NO `m_allow_replacement` flag anywhere in the mempool API. AcceptToMemoryPool unconditionally takes the RBF path on conflict. testmempoolaccept does not enter checkRBFLocked at all (BUG-13 below), so the "test accept with replacement disabled" semantics is meaningless. The `"bip125-replacement-disallowed"` wire token never fires — search returns zero matches |
| 9 | `IsConsistentPackage` semantics | G23: returns false on any tx with `vin.empty()` | **BUG-5 (P0-CDIV)** — `mempool.go:3241-3263` does NOT check for empty TxIn. Core (`packages.cpp:57-63`) explicitly returns `false` on empty vin and documents this as critical because an unconfirmed tx with no inputs is malformed. blockbrew accepts a package where one tx has zero inputs — IsConsistentPackage returns true → CheckPackage passes → AcceptPackage proceeds → the empty-vin tx then fails in PreChecks with a worse error path |
| 10 | `MAX_PACKAGE_*` constants | G24: count = 25 | PASS (`mempool.go:258`) |
| 10 | … | G25: weight = 404_000 | PASS (`mempool.go:262`) |
| 10 | … | G26: weight enforced for single-tx packages too (Core comment: "better to report per-tx weight violation for len=1", but the check runs) | **BUG-10 (P1)** — `mempool.go:3327` gates weight on `if len(txns) > 1`. A single 405_000-weight tx in a 1-tx package passes CheckPackage entirely; the per-tx `MaxStandardTxWeight` check fires later, but the package-level signal is wrong (caller cannot distinguish "package too large" from "single tx too large"). Cross-cite W116 BUG-9 (already documented but unfixed) |
| 10 | … | G27: submitpackage RPC enforces upper bound on package length | **BUG-11 (P1, cross-cite W116 BUG-4)** — `handleSubmitPackage` (`methods.go:1105-1276`) checks `len(rawTxs) == 0` but NEVER checks `len(rawTxs) > 25`. Caller submits 1000 txs → AcceptPackage decodes all 1000 → CheckPackage rejects with `package exceeds maximum transaction count`, but the 1000-tx decode cost has already been spent (CPU + alloc DoS surface). Core rejects at the JSON-arg parse boundary |
| 11 | submitpackage maxfeerate enforcement | G28: maxfeerate rejection PREVENTS acceptance, not post-accept removal | **BUG-12 (P1, cross-cite W116 BUG-2)** — `methods.go:1259-1273` applies maxfeerate AFTER AcceptPackage has admitted the txs. Comment at line 1263-1265: "In a production implementation, we would prevent acceptance entirely rather than accepting then removing. For now, we just warn." **Comment-as-confession** — operator can submit a package with maxfeerate=1 sat/vB; if the package pays 100 sat/vB it lands in the mempool first, then the RPC result annotates "max-fee-exceeded" but the tx is NOT removed. Funds-at-risk: the tx then relays to peers |
| 12 | testmempoolaccept package mode | G29: when `len(rawtxs) > 1`, route through ProcessNewPackage(test_accept=true) | **BUG-13 (P1, cross-cite W116 BUG-1)** — `handleTestMempoolAccept` (`rawtx_methods.go:206-374`) loops independently per tx. NO package mode. NO RBF check (the per-tx loop has no `mp.checkRBFLocked` call). NO script validation. NO BIP-68 / sequence-lock. NO chain-limit check. NO TRUC check. NO IsWitnessStandard. NO IsConsistentPackage cross-tx conflict detection. **THIRD validation pipeline diverging from production AcceptToMemoryPool AND from AcceptPackage**. N-pipeline drift (3 ATMP pipelines): `AddTransaction` (line 1088), `validateTransactionLocked` (line 3611), `handleTestMempoolAccept` (line 234) |
| 12 | … | G30: per-tx result includes `package-error` field | **BUG-14 (P1, cross-cite W116 BUG-6)** — `TestMempoolAcceptResult` has no `package-error` field; Core always emits it on package-level failure |
| 12 | … | G31: per-tx result includes `fees.effective-feerate` and `fees.effective-includes` | **BUG-15 (P1, cross-cite W116 BUG-5)** — `FeeInfo` has only `Base`; Core ships `effective-feerate` (BTC/kvB) and `effective-includes` (wtxid array) for package-feerate-attributable txs |
| 13 | P2P package-relay infrastructure (BIP-331) | G32: sendpackages bitfield with `PackageRelayVersionAncestor` advertised in handshake | PASS (`peer.go:779`) |
| 13 | … | G33: getpkgtxns / pkgtxns codecs present | PASS (`msg_packages.go:60-145`) |
| 13 | … | G34: production OnGetPkgTxns handler fetches by wtxid, returns pkgtxns | PASS (`main.go:1202-1211`) — but note BUG-19 below on `peer.SendMessage(reply)` of empty response |
| 13 | … | G35: production OnPkgTxns feeds through AcceptPackage | PARTIAL (`main.go:1215-1234`) — wires through, BUT calls `mp.AcceptPackage(msg.Txs)` directly with NO topology gate. A peer pushing a non-child-with-parents arrangement (e.g. a 25-tx chain A→B→C→…→Y) is silently swallowed by AcceptPackage's own IsChildWithParentsTree check (line 3375), but the peer is NOT misbehaviour-scored for the protocol violation. **BUG-17** |
| 13 | … | G36: peer-side `packageVersions` bitfield USED for outbound relay decisions | **BUG-18 (P0-CDIV "dead-data plumbing")** — `peer.go:189` stores `packageVersions`, `peer.go:1259` exposes it via accessor; **zero production callers consult it before sending getpkgtxns / pkgtxns**. A grep over `cmd/blockbrew`, `internal/p2p/sync.go` for `PackageVersions()` returns nothing. The bitfield is recorded, the handshake-side acknowledgment is sent, the listener slot exists — but the outbound side never asks "does this peer support packages?". blockbrew NEVER sends getpkgtxns/pkgtxns outbound; only services inbound requests |
| 13 | … | G37: BIP-331 `ancestor-package id` = `GetPackageHash` (SHA-256 of wtxids sorted as LE numbers) | **BUG-19 (P1)** — blockbrew has NO `GetPackageHash` analogue (grep returns zero matches across the repo). Without it, the node cannot identify or dedup package-relay requests — a peer that re-pushes the same package gets re-processed. Also the BIP-331 `ancpkginfo` (announcement) message has no implementation; only the 3 messages from §"sendpackages / getpkgtxns / pkgtxns" exist |
| 14 | `getmempoolinfo` consistency | G38: `mempoolminfee`, `minrelaytxfee`, `incrementalrelayfee` reflect actual config | **BUG-6 (P0-CDIV)** — `handleGetMempoolInfo` (`methods.go:1310-1312`) HARDCODES `MempoolMinFee: 0.00001`, `MinRelayTxFee: 0.00001`, `IncrementalRelayFee: 0.00001` regardless of operator config. The `getmempoolinfo` field never updates when `-minrelayfee` is overridden via CLI (`main.go:468`). Cross-cite W120 BUG-5 / FIX-68 which fixed the `fullrbf` field — the dust+relay fields were left in the same broken shape |
| 14 | … | G39: emits Core's `incrementalrelayfee` field as the CURRENT `IncrementalRelayFee` config value | **BUG-6 cross-cite** — even when reading the real config, the value (1000 sat/kvB = 0.00001 BTC/kvB) does not equal Core's default 0.000001 (100 sat/kvB) |
| 14 | … | G40: emits Core's `incrementalrelayfee` field at all (vs `incrementalRelayFee` Go-naming) | PASS by name (`types.go:239` JSON tag `incrementalrelayfee`) |

---

## BUG-1 (P0-CDIV) — `IncrementalRelayFee` default is 10× Core's; Rule 4 stringency divergence

**Severity:** P0-CDIV ("default-constants-divergent" fleet pattern). Bitcoin
Core ships `DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB` at
`bitcoin-core/src/policy/policy.h:48`. blockbrew defaults to
`IncrementalRelayFee: 1000 sat/kvB` at `internal/mempool/mempool.go:391`
and re-applies the same default in `New()` at `mempool.go:645-647`:

```go
IncrementalRelayFee:    1000,        // 1 sat/vB
```

The inline comment "1 sat/vB" admits the unit (1000 sat/kvB = 1 sat/vB),
but the value itself is **10× Core's default** (0.1 sat/vB). The
consequence at the RBF Rule 4 site (`mempool.go:2879-2887`):

```go
minFeeBump := (newVSize * mp.config.IncrementalRelayFee + 999) / 1000
if newFee-totalConflictingFee < minFeeBump {
    return fmt.Errorf("%w: ... not enough additional fees to relay; %d < %d", ...)
}
```

For a 250-vsize replacement:
- **Core:** `minFeeBump = ceil(250 * 100 / 1000) = 25 sat`. Any replacement
  paying 25+ extra sat passes Rule 4.
- **blockbrew:** `minFeeBump = ceil(250 * 1000 / 1000) = 250 sat`. The
  same replacement at 25 extra sat fails with
  `"insufficient fee: rejecting replacement, not enough additional fees to relay; 25 < 250"`.

This is a **wire-policy divergence**: blockbrew rejects replacements that
Core accepts. A wallet (or pool with cross-impl fee-bumping logic) that
satisfies Core's Rule 4 silently fails on a blockbrew peer; the
replacement does not propagate through a blockbrew-heavy network slice.

**Same direction for `MinRelayFeeRate`:** `mempool.go:390` defaults
to 1000 sat/kvB (Core's default `DEFAULT_MIN_RELAY_TX_FEE = 100`).
Cross-cite W150 BUG-6 / BUG-18 (W150 documented the dust-vs-min-relay
asymmetry and the missing `-incrementalrelayfee` CLI knob but did NOT
flag the 10× default divergence).

Core enforces equality at compile time:

```cpp
// bitcoin-core/src/node/mempool_args.cpp:69
static_assert(DEFAULT_MIN_RELAY_TX_FEE == DEFAULT_INCREMENTAL_RELAY_FEE);
```

blockbrew's defaults happen to match each other (1000 vs 1000) but both
diverge from Core's 100. **There is no equivalent compile-time assert
in blockbrew**, so a future tuning of one without the other would
silently break the invariant (Rule 4 incremental floor must equal min
relay floor by Core's convention).

**File:** `internal/mempool/mempool.go:390-391, 642-647, 2883`.

**Core ref:** `bitcoin-core/src/policy/policy.h:48,70`;
`bitcoin-core/src/node/mempool_args.cpp:69`.

**Impact:**
- Rule 4 is 10× stricter than Core; replacements accepted by Core get
  rejected with `insufficient fee` on blockbrew peers.
- `getmempoolinfo.incrementalrelayfee` value reported to wallets (BUG-6)
  is 10× higher; wallet-side rebump logic targets the wrong floor.
- Mempool min-fee (dynamic fee under pressure) starts at 10× Core's
  base, biasing inclusion against low-fee txs.

---

## BUG-2 (P1, fleet pattern) — `WALLET_INCREMENTAL_RELAY_FEE = 5000` constant absent

**Severity:** P1 ("missing-Core-constant" fleet pattern; cross-cite
W130 BUG-2). Bitcoin Core's wallet ships
`WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB` (5 sat/vB) at
`bitcoin-core/src/wallet/wallet.h:124`. The wallet uses
`max(node_incremental_relay_fee, WALLET_INCREMENTAL_RELAY_FEE)` in its
auto-bump calculation (`wallet/feebumper.cpp:135-137`) to future-proof
against node-side relay-fee bumps: when a node operator raises
`-incrementalrelayfee` from 100 to 200, in-flight wallet-issued RBF
replacements should still relay.

blockbrew's `internal/wallet/bumpfee.go:217` hardcodes:

```go
bump := int64(math.Ceil(1.0 * float64(vsize)))  // 1 sat/vB
```

A separate constant for the wallet floor does not exist (grep for
`WALLET_INCREMENTAL` returns only the W130 test pins flagging absence).
This is a TWO-PIPELINE GUARD failure: the wallet's bump computation
diverges from the relay's Rule 4 check both in formula AND in
constant. Today's value (1 sat/vB) happens to be below the relay floor
of 1 sat/vB (BUG-1's inflated default), so the bump fee passes Rule 4
by being EQUAL — a flush state that has no margin. If an operator
later wires `-incrementalrelayfee=2000` (2 sat/vB), every wallet
auto-bump silently produces a sub-Rule-4 replacement that the local
mempool rejects.

**File:** `internal/wallet/bumpfee.go:217` (hardcoded +1 sat/vB);
no `WALLET_INCREMENTAL_RELAY_FEE` constant anywhere in
`internal/wallet/`.

**Core ref:** `bitcoin-core/src/wallet/wallet.h:124`;
`bitcoin-core/src/wallet/feebumper.cpp:135-137`.

**Impact:** wallet auto-bump produces sub-relay-floor replacements when
the operator tunes `-incrementalrelayfee` upward. Cross-impl wallet
behavior diverges from Core for any non-default `incrementalrelayfee`.

---

## BUG-3 (P0-CDIV) — Rule 5 counts individual txs, not unique clusters; comment-as-confession

**Severity:** P0-CDIV. Bitcoin Core's `GetEntriesForConflicts`
(`bitcoin-core/src/policy/rbf.cpp:58-83`) enforces Rule 5 by counting
UNIQUE CLUSTERS:

```cpp
auto num_clusters = pool.GetUniqueClusterCount(iters_conflicting);
if (num_clusters > MAX_REPLACEMENT_CANDIDATES) {
    return strprintf("rejecting replacement %s; too many conflicting clusters (%u > %d)", ...);
}
```

The semantic shifted with Core 27's cluster-mempool (PR #28676): a
replacement that evicts ONE cluster of 200 transactions is acceptable
(`num_clusters = 1 ≤ 100`), but evicting 101 separate single-tx clusters
is not. This caps the re-sorting work the node must do.

blockbrew at `internal/mempool/mempool.go:2855-2858`:

```go
if totalEvicted > MaxRBFReplacedTxs {
    return fmt.Errorf("%w: would evict %d transactions (max %d)",
        ErrRBFTooManyConflicts, totalEvicted, MaxRBFReplacedTxs)
}
```

counts individual transactions. The inline comment at line 2853-2854 is
a **comment-as-confession** (fleet pattern):

```go
// MAX_REPLACEMENT_CANDIDATES (100). Mirrors GetEntriesForConflicts
// (rbf.cpp:64-75). Core counts unique clusters; blockbrew counts individual
// txs (equivalent for non-cluster-mempool deployments).
```

The comment claims the two are "equivalent for non-cluster-mempool
deployments" — but blockbrew SHIPS a cluster mempool
(`internal/mempool/cluster.go`, `mp.clusters.GetCluster`,
`Cluster.GetChunks`, `Cluster.recomputeLinearization`). The equivalence
note is FALSE: blockbrew has clusters AND counts individual txs, which
means Rule 5 fires for replacement scenarios Core allows.

**Concrete failure mode:** a CPFP chain of 25 txs (A→B→…→Y, a single
cluster) competing for inclusion is later replaced by a fee-bumped
root replacement (replacing A). Core: `num_clusters = 1`, accept.
blockbrew: `totalEvicted = 25 + descendants of A's children = up to
25 * 25 = 625` (if Y has 25 mempool children itself, etc.) — easily
exceeds 100. The fee-bump fails Rule 5 on blockbrew even though Core
allows it.

**File:** `internal/mempool/mempool.go:2851-2858` (count site +
comment-as-confession).

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:58-83` (cluster count).

**Impact:**
- Wire-policy divergence: replacements Core allows fail blockbrew with
  `would evict N transactions (max 100)`.
- Particularly bad for L2 (Lightning) channel-close replacements that
  fee-bump deep CPFP chains; blockbrew refuses bumps Core accepts.
- Cross-impl funds-at-risk: a Lightning peer that hits a blockbrew
  node first sees its anchor-bump rejected.

---

## BUG-4 (P0-CDIV) — `m_allow_replacement` gate absent; `bip125-replacement-disallowed` wire token never fires

**Severity:** P0-CDIV. Bitcoin Core's ATMP `Workspace` carries an
`m_allow_replacement` flag (`bitcoin-core/src/validation.cpp:465`)
that callers (test-accept mode, certain package-eval contexts) set to
false to opt out of replacement. The PreChecks check at
`validation.cpp:837-840`:

```cpp
if (ptxConflicting) {
    if (!args.m_allow_replacement) {
        return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "bip125-replacement-disallowed");
    }
    ws.m_conflicts.insert(ptxConflicting->GetHash());
}
```

generates the wire-canonical `"bip125-replacement-disallowed"` reject
token (consumed by RPC reject-reason output, ZMQ pubrawtxrejected,
peer logging).

blockbrew has NO `m_allow_replacement` analog. `AcceptToMemoryPool` and
`AddTransaction` (`mempool.go:1099-1106`) ALWAYS take the RBF path on
conflict:

```go
if existingTxHash, ok := mp.outpoints[in.PreviousOutPoint]; ok {
    if conflictingTxs == nil {
        conflictingTxs = make(map[wire.Hash256]bool)
    }
    conflictingTxs[existingTxHash] = true
}
```

Search for `"bip125-replacement-disallowed"` over the repository
returns zero matches. The wire-token never fires.

Cross-impact:
- testmempoolaccept (`rawtx_methods.go:206`) has no RBF path at all
  (BUG-13), so it cannot exercise the "what would Core say if this
  ATTEMPTED to replace but replacement is disabled here?" semantics.
- AcceptPackage's `acceptMultiTxPackage` (`mempool.go:3456-3605`) does
  not distinguish package-RBF from package-extension. A package
  containing a tx that conflicts with a mempool tx silently triggers
  the per-tx checkRBFLocked path — Core's PackageRBFChecks
  (`validation.cpp:1037-1196`) restricts package-RBF to 1-parent-1-child
  topology with no in-mempool ancestors; blockbrew has no such
  restriction.

**File:** `internal/mempool/mempool.go:1099-1106` (unconditional RBF
take-path); zero usages of any `AllowReplacement` field anywhere.

**Core ref:** `bitcoin-core/src/validation.cpp:465, 563, 837-840`
(field + check); `bitcoin-core/src/validation.cpp:1037-1196`
(PackageRBFChecks).

**Impact:**
- Wire-token divergence: monitoring tools that grep for
  `bip125-replacement-disallowed` see it never emitted from blockbrew.
- Package-RBF rules unenforced: blockbrew accepts package-RBF
  topologies (multi-parent, with in-mempool ancestors) that Core
  rejects with `package RBF failed: ...`.

---

## BUG-5 (P0-CDIV) — `IsConsistentPackage` accepts empty-vin tx

**Severity:** P0-CDIV. Bitcoin Core's `IsConsistentPackage`
(`bitcoin-core/src/policy/packages.cpp:52-77`) immediately returns
`false` if any tx has empty vin:

```cpp
for (const auto& tx : txns) {
    if (tx->vin.empty()) {
        // This function checks consistency based on inputs, and we can't do that if there are
        // no inputs. Duplicate empty transactions are also not consistent with one another.
        // This doesn't create false negatives, as unconfirmed transactions are not allowed to
        // have no inputs.
        return false;
    }
    // ...
}
```

The comment explicitly notes that unconfirmed txs are not allowed to
have no inputs (Coinbase is the only no-input form, and coinbase is
banned from the mempool).

blockbrew's `IsConsistentPackage` at
`internal/mempool/mempool.go:3241-3263` does not check
`len(tx.TxIn) == 0`:

```go
func IsConsistentPackage(txns []*wire.MsgTx) bool {
    txids := make(map[wire.Hash256]bool)
    spentOutpoints := make(map[wire.OutPoint]bool)

    for _, tx := range txns {
        txid := tx.TxHash()
        if txids[txid] {
            return false
        }
        txids[txid] = true

        // Check for conflicting inputs
        for _, in := range tx.TxIn {           // <-- empty range, no iteration, no check
            if spentOutpoints[in.PreviousOutPoint] {
                return false
            }
            spentOutpoints[in.PreviousOutPoint] = true
        }
    }
    return true
}
```

A package containing one empty-vin tx passes IsConsistentPackage →
CheckPackage passes → AcceptPackage proceeds to per-tx PreChecks where
the empty-vin tx is finally caught (CheckTransactionSanity rejects
"tx must have at least one input"). The error path is then "tx-level
sanity failure" instead of "package-level malformed". Wire-token
divergence + extra work expended before rejection.

**File:** `internal/mempool/mempool.go:3241-3263`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:57-63`.

**Impact:**
- Wire-token divergence: package error class for empty-vin should be
  `PCKG_POLICY` "conflict-in-package" / "malformed"; blockbrew emits
  per-tx sanity error.
- CPU DoS surface: a malicious peer can submit a 25-tx package where
  the LAST tx has empty vin — blockbrew runs full CheckPackage
  validation (counting, weight summing, topo-sort, full conflict
  scan over 24 non-empty txs) before catching the empty-vin in
  AcceptPackage's PreChecks. Core fails-fast in IsConsistentPackage.

---

## BUG-6 (P0-CDIV) — `getmempoolinfo` HARDCODES relay-fee fields

**Severity:** P0-CDIV. `handleGetMempoolInfo` at
`internal/rpc/methods.go:1303-1321`:

```go
return &MempoolInfo{
    Loaded:             true,
    Size:               s.mempool.Count(),
    Bytes:              s.mempool.TotalSize(),
    Usage:              s.mempool.TotalSize(),
    TotalFee:           totalFee,
    MaxMempool:         300_000_000, // 300 MB default
    MempoolMinFee:      0.00001,     // <-- HARDCODED 1 sat/vB in BTC/kvB
    MinRelayTxFee:      0.00001,     // <-- HARDCODED
    IncrementalRelayFee: 0.00001,    // <-- HARDCODED
    UnbroadcastCount:   0,
    FullRBF:            s.mempool.FullRBF(),    // <-- ONLY this is wired
}, nil
```

The W120 BUG-5 fix (`FIX-68`) wired `FullRBF` to consult the actual
mempool config (`s.mempool.FullRBF()`). The same fix was NOT applied
to the three relay-fee fields. Operators who:
- set `-minrelayfee=0.00010` (10 sat/vB) on the CLI (line 468 in
  main.go),
- query `getmempoolinfo`,

see `minrelaytxfee: 0.00001` — the wrong value. Wallets that scrape
this field to set their own minimum tx fee target the wrong relay
floor. Mining-fee estimators (electrs, mempool.space, esplora) drive
off this field to size up the local relay policy.

Additionally, `MaxMempool` is HARDCODED at 300_000_000 bytes regardless
of operator-set `-maxmempool=N MB` (line 467 in main.go) — same
defect class.

`UnbroadcastCount` is HARDCODED at 0 — Core tracks unbroadcasted
locally-submitted txs (`txmempool.cpp::CTxMemPool::m_unbroadcast_txids`);
blockbrew never populates this counter.

**File:** `internal/rpc/methods.go:1290-1322`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1080-1110`
(`getmempoolinfo`).

**Impact:**
- Wallet / monitoring divergence: scrapers see wrong `mempoolminfee`
  → mis-sized fee estimates → either over-paying or under-paying.
- Operator-knob invisible: tuning `-minrelayfee` or `-maxmempool`
  doesn't change RPC output → operator believes the knob is broken,
  retries with wrong values.
- `unbroadcastcount` always 0 → wallets can't detect orphaned local
  txs that never propagated (Core uses this for re-broadcast logic).

---

## BUG-7 (P0-CDIV "two-pipeline guard") — wallet bumpfee Rule 3 math diverges from relay Rule 4

**Severity:** P0-CDIV ("two-pipeline guard" fleet pattern, 17th distinct
instance in blockbrew per W138/W140/W148/W149 tracking; first
specifically for RBF). Two parallel pipelines compute the minimum fee
bump for an RBF replacement:

1. **Relay-side Rule 4 (`mempool.go:2879-2887`):**
   ```go
   minFeeBump := (newVSize * mp.config.IncrementalRelayFee + 999) / 1000
   ```
   Uses `IncrementalRelayFee` config (BUG-1: default 1000 sat/kvB) and
   the ceiling-division formula matching Core's `CFeeRate::GetFee`.

2. **Wallet-side bumpfee (`wallet/bumpfee.go:204-225`):**
   ```go
   if req.FeeRate > 0 {
       if req.FeeRate <= origFeeRate {
           return nil, ErrBumpFeeRateTooLow
       }
       newFee = int64(math.Ceil(req.FeeRate * float64(vsize)))
   } else {
       bump := int64(math.Ceil(1.0 * float64(vsize)))   // <-- HARDCODED 1 sat/vB
       if bump < 1 {
           bump = 1
       }
       newFee = oldFee + bump
   }
   if newFee <= oldFee {
       return nil, ErrBumpFeeRateTooLow
   }
   ```
   Hardcoded "+1 sat/vB" instead of `IncrementalRelayFee.GetFee(vsize)`.
   Different formula (`math.Ceil(rate * vsize)` vs
   `(vsize * rate + 999) / 1000`) and different constant source
   (literal `1.0` vs `mp.config.IncrementalRelayFee`).

The two pipelines silently agree TODAY because:
- Wallet uses `+1 sat/vB` literal.
- Relay defaults to `IncrementalRelayFee = 1000 sat/kvB = 1 sat/vB`.

If an operator (1) tunes `-minrelayfee` via CLI (existing knob,
`main.go:468`) AND (2) the wallet ever picks that up — the formulae
will start producing different bumps. The wallet has NO knowledge of
`-minrelayfee` because the configuration is not threaded into
`wallet.BumpFee` at all (`InputUTXOs` and `FeeRate` are the only inputs).

Additionally per Core's `feebumper.cpp:93` the wallet should compute
the precise Rule 3 floor as
`new_total_fee >= old_fee + incrementalRelayFee.GetFee(max_tx_size)` —
blockbrew's wallet only checks `req.FeeRate > origFeeRate` (line 212)
which is necessary-but-insufficient (W130 BUG-1 pin at
`w130_bip125_feebumper_rule3_test.go:106-112`).

**File:** `internal/wallet/bumpfee.go:204-225`,
`internal/mempool/mempool.go:2879-2887`.

**Core ref:** `bitcoin-core/src/wallet/feebumper.cpp:93, 135-137`
(precise formula + `WALLET_INCREMENTAL_RELAY_FEE` max-with-node).

**Impact:**
- Two-pipeline drift latent: any future tuning of either pipeline
  silently breaks RBF replacements (wallet produces sub-Rule-4 tx that
  relay rejects).
- Cross-cite W130 BUG-1, BUG-2, BUG-3 — three wallet-side Rule 3
  audit pins already document the gap; this audit catches that the
  relay side has its own copy of the formula.
- Symmetric with W148 BUG-5 (MaxReorgDepth=100 hard-coded in chain
  manager, separate from sync.go's reorg gate) — same fleet pattern.

---

## BUG-8 (P0-CDIV) — RBF feerate-diagram check skipped when `affectedClusters` is empty

**Severity:** P0-CDIV. The diagram check at
`internal/mempool/mempool.go:3030-3034`:

```go
// If no clusters are tracked (e.g. empty or single-tx mempool with no
// cluster manager data), skip the diagram check — we cannot compute it.
if len(affectedClusters) == 0 {
    return nil
}
```

**Comment-as-confession**: "we cannot compute it" — so the check
returns nil (PASS). But "no cluster manager data" should NOT
short-circuit to PASS. Core's `ImprovesFeerateDiagram` always runs;
when the diagram cannot be computed (no conflicts → no comparison →
empty changeset), it returns `DiagramCheckError::UNCALCULABLE` and
Core stamps `"replacement-failed"`.

In blockbrew, a malicious replacement that triggers an empty
`affectedClusters` (e.g. a conflict whose conflict-tx is in the pool
but never made it into a cluster — a brief race during cluster
re-linearization, or a TXO map-only entry pre-cluster-AddTransaction)
slips through the diagram gate. The actual eviction still occurs at
`AddTransaction:1342-1346`, so the conflict tx is removed and the
replacement admitted — even though the diagram check was supposed to
ensure the replacement strictly improves total mempool feerate.

This is a SOUNDNESS gap: the gate exists for a reason (preventing
free relay of equivalent-feerate replacements that just barely beat
Rule 4); short-circuiting on "can't compute" defeats it.

**File:** `internal/mempool/mempool.go:3030-3034`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:127-140` —
`UNCALCULABLE` is a FAILURE error class, not a pass.

**Impact:**
- Feerate-diagram bypass: a corner-case replacement can land without
  improving the mempool's feerate diagram. Quantitative effect is
  small (single tx slipping past a defensive gate) but the
  qualitative invariant ("replacement strictly improves diagram") is
  weakened.

---

## BUG-9 (P1) — `replacement-failed` wire-token divergence on diagram-check failure

**Severity:** P1 ("wire-string parity slippage" fleet pattern).
`mempool.go:95`:

```go
ErrRBFFeerateDiagram = errors.New("insufficient feerate: does not improve feerate diagram")
```

Core (`bitcoin-core/src/policy/rbf.cpp:137`) stamps the static string
`"replacement-failed"` (TX_RECONSIDERABLE class) on
`DiagramCheckError::FAILURE`. The two strings serve the same role
(reject-reason emitted to RPC / ZMQ / log), but a monitoring tool
filtering for `replacement-failed` sees blockbrew always pass, and a
monitoring tool filtering for "insufficient feerate" matches multiple
unrelated paths (Rule 3, Rule 4, mempool min-fee). Cross-cite W125
reject-string sweep.

**File:** `internal/mempool/mempool.go:95`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:137`.

**Impact:** monitoring contract drift; no consensus risk.

---

## BUG-10 (P1) — `MaxPackageWeight` not enforced for single-tx packages (W116 BUG-9 unfixed)

**Severity:** P1 (carry-forward from W116 BUG-9 — already documented
in `mempool/w116_package_relay_test.go:56-61` but still present).
`mempool.go:3327-3335`:

```go
if len(txns) > 1 {
    var totalWeight int64
    for _, tx := range txns {
        totalWeight += consensus.CalcTxWeight(tx)
    }
    if totalWeight > MaxPackageWeight {
        return ErrPackageTooLarge
    }
}
```

The weight check is gated on `len(txns) > 1`. A single-tx package
with weight > 404_000 (theoretically possible since
`MAX_STANDARD_TX_WEIGHT = 400_000` is below `MAX_PACKAGE_WEIGHT = 404_000`,
but a non-standard sigops-heavy tx weighted >400_000 could reach here)
passes CheckPackage without a package-level weight signal. Core's
comment at `packages.cpp:89-90` notes the same intent ("better to
report per-tx weight violation for len=1") but Core's actual check is
NOT gated — it just falls through to the per-tx STANDARD_TX_WEIGHT
check.

The blockbrew gate has the semantic effect of NOT reporting
"package-too-large" on a single-tx oversized package; the per-tx
`MaxStandardTxWeight` check at `mempool.go:3631` then fires with a
different error class. Caller cannot distinguish "package-level"
from "tx-level" weight failure.

**File:** `internal/mempool/mempool.go:3327`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:87-92`.

**Impact:** wire-token / error-class drift; cross-cite W116 BUG-9.

---

## BUG-11 (P1) — `submitpackage` RPC has no upper-bound check on package length

**Severity:** P1 (carry-forward W116 BUG-4 — already documented but
unfixed). `handleSubmitPackage` at `methods.go:1105-1146`:

```go
if len(rawTxs) == 0 {
    return nil, &RPCError{Code: RPCErrInvalidParams, Message: "Package must contain at least one transaction"}
}
// ... decode all rawTxs ...
```

There is no `if len(rawTxs) > 25 { return error }` gate. A caller
submits 1000 raw txs → blockbrew runs `hex.DecodeString` + `MsgTx.Deserialize`
for each → builds a 1000-element `[]*wire.MsgTx` → calls
`AcceptPackage` → which inside `CheckPackage` (line 3322) rejects with
`ErrPackageTooManyTxs = "package exceeds maximum transaction count"`.
The 1000-tx decode cost was wasted.

Core (`bitcoin-core/src/rpc/mempool.cpp::submitpackage`) rejects at the
JSON-arg parse boundary:

```cpp
RPCResult{RPCResult::Type::OBJ, "", "",
    {
        // ... "Array must contain between 1 and 25 transactions." ...
```

Core's `RPCHelpMan` validation rejects the malformed input before the
hex decode loop runs.

**File:** `internal/rpc/methods.go:1122-1124`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::submitpackage` (RPC
arg validation).

**Impact:**
- CPU DoS: an attacker with RPC creds submits 100_000-tx packages
  repeatedly; each consumes ~100_000 × (hex_decode + Deserialize) ≈
  significant CPU before rejection. Multiplied by request rate, this
  is a DoS surface.
- Memory DoS: 100_000 `*wire.MsgTx` allocations before rejection.

---

## BUG-12 (P1) — `submitpackage` maxfeerate enforced AFTER acceptance (W116 BUG-2 unfixed)

**Severity:** P1 (carry-forward W116 BUG-2 — still present).
`methods.go:1259-1273`:

```go
// Check if any transaction exceeds maxfeerate
if maxFeeRate > 0 && pkgResult != nil {
    for _, txResult := range pkgResult.TxResults {
        if txResult.Accepted && txResult.EffectiveFeerate*1000 > maxFeeRate {
            // Remove transactions that exceed the fee rate
            // Note: In a production implementation, we would prevent acceptance entirely
            // rather than accepting then removing. For now, we just warn.
            rpcResult := result.TxResults[txResult.WTxID.String()]
            if rpcResult != nil {
                rpcResult.Error = fmt.Sprintf("max-fee-exceeded: %.8f BTC/kvB", ...)
            }
        }
    }
}
```

**Comment-as-confession** at line 1263-1265 admits the semantics is
wrong: "we would prevent acceptance entirely rather than accepting then
removing. For now, we just warn." The txs are already in the
mempool AND already started relaying to peers via the RBF eviction
path. The maxfeerate is a safety knob meant to PREVENT a
typo-induced over-fee submission; here it just annotates the RPC
result after the fact.

Core (`bitcoin-core/src/validation.cpp:1456-1465`) checks maxfeerate
per-workspace INSIDE `AcceptMultipleTransactionsInternal` and aborts
the entire package on failure:

```cpp
if (args.m_client_maxfeerate && CFeeRate(ws.m_modified_fees, ws.m_vsize) > args.m_client_maxfeerate.value()) {
    ws.m_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "max feerate exceeded", "");
    package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
    ...
    return PackageMempoolAcceptResult(package_state, std::move(results));
}
```

**File:** `internal/rpc/methods.go:1259-1273`.

**Core ref:** `bitcoin-core/src/validation.cpp:1456-1465`.

**Impact:**
- Funds-at-risk: a typo (`maxfeerate=0.00001` BTC/kvB → 1 sat/vB by
  accident when the user meant 100 sat/vB) on a 1-BTC-fee tx
  silently broadcasts the over-fee tx; the post-acceptance "warn"
  doesn't undo the relay.
- The RPC's documented safety knob is non-functional.

---

## BUG-13 (P1) — `testmempoolaccept` is a third validation pipeline; bypasses RBF, scripts, sequence locks, chain limits, TRUC (W116 BUG-1 unfixed; N-pipeline drift)

**Severity:** P1 (carry-forward W116 BUG-1; cross-cite "N-pipeline
drift" fleet pattern, 3rd distinct mempool pipeline in blockbrew).
`handleTestMempoolAccept` at `rawtx_methods.go:206-374` runs:

1. Hex decode
2. MsgTx deserialize
3. HasTransaction check
4. CheckTransactionSanity
5. IsCoinbaseTx reject
6. CalcTxWeight / MaxStandardTxWeight
7. UTXO lookup + fee computation
8. Min-fee-rate check
9. Max-fee-rate check

It DOES NOT run:
- `checkRBFLocked` (Rules 1-5)
- `validateScriptsLocked` (script verification)
- `checkSequenceLocksLocked` (BIP-68)
- `checkChainLimitsWithSizeLocked` (ancestor/descendant limits)
- `singleTRUCChecks` (BIP-431)
- `isDust` (W150 BUG-6 scope)
- `isWitnessStandard` (BIP-141 standardness)
- `checkRBFNoNewUnconfirmedInputsLocked` (Rule 2)
- `IsConsistentPackage` cross-tx conflict detection (for multi-tx
  rawtxs arg)
- `PackageRBFChecks` (multi-tx package RBF)

This is the **THIRD validation pipeline** in blockbrew:
1. `AddTransaction` / `AcceptToMemoryPool` (`mempool.go:1088-1346`)
   — full ATMP for single tx.
2. `validateTransactionLocked` (`mempool.go:3611-3717`) — package-mode
   tx eval inside `acceptMultiTxPackage`.
3. `handleTestMempoolAccept` (`rawtx_methods.go:206-374`) — partial
   re-implementation of (1) missing 8+ gates.

A test-accept of a tx that fails script validation, BIP-68 sequence
locks, RBF Rule 2, TRUC topology, etc., returns `allowed=true` from
blockbrew but is rejected at actual send time. Wallets that trust
testmempoolaccept for pre-broadcast simulation get incorrect signal.

Cross-impact:
- For `len(rawtxs) > 1`, Core runs `AcceptMultipleTransactionsAndCleanup`
  (`validation.cpp:1820`) — full package-aware path. blockbrew runs
  the same independent per-tx loop with no package context (BUG-1
  documented at W116 BUG-1 already). Package feerate elevation,
  CPFP via parent-pays-for-child, and TRUC topology are not modelled.

**File:** `internal/rpc/rawtx_methods.go:206-374`.

**Core ref:** `bitcoin-core/src/validation.cpp:1820`
(`AcceptMultipleTransactionsAndCleanup` test-accept path).

**Impact:**
- Wallets misled by `allowed=true` for txs that will reject on send.
- N-pipeline drift: 3 ATMP pipelines, each with different gate-sets;
  fixes to one don't propagate to the others.

---

## BUG-14 (P1) — `testmempoolaccept` per-tx result missing `package-error` field (W116 BUG-6 unfixed)

**Severity:** P1 (carry-forward W116 BUG-6). `TestMempoolAcceptResult`
(`rawtx_methods.go:192-199`):

```go
type TestMempoolAcceptResult struct {
    TxID         string   `json:"txid"`
    WTxID        string   `json:"wtxid,omitempty"`
    Allowed      bool     `json:"allowed"`
    VSize        int64    `json:"vsize,omitempty"`
    Fees         *FeeInfo `json:"fees,omitempty"`
    RejectReason string   `json:"reject-reason,omitempty"`
}
```

Core emits `package-error` when `len(rawtxs) > 1` and a package-level
validation error occurs (e.g. `package-not-sorted`,
`package-too-many-transactions`, `conflict-in-package`,
`package RBF failed: ...`). blockbrew has no analog.

**File:** `internal/rpc/rawtx_methods.go:192-199`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::testmempoolaccept`.

**Impact:** Wallet/tooling cannot distinguish package-level failures
from per-tx failures.

---

## BUG-15 (P1) — `testmempoolaccept` missing `fees.effective-feerate` and `fees.effective-includes` (W116 BUG-5 unfixed)

**Severity:** P1 (carry-forward W116 BUG-5). `FeeInfo` (`rawtx_methods.go:202-204`):

```go
type FeeInfo struct {
    Base float64 `json:"base"`
}
```

Core's `testmempoolaccept` includes:
- `fees.base` (raw fee in BTC)
- `fees.effective-feerate` (BTC/kvB; for package-feerate attribution)
- `fees.effective-includes` (array of wtxids whose feerates contribute
  to the effective-feerate)

These are critical for CPFP-aware fee estimation by wallets — a child
test-accept should report the effective package feerate including the
contribution of a not-yet-broadcast parent.

**File:** `internal/rpc/rawtx_methods.go:202-204`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::testmempoolaccept`.

**Impact:** wallet CPFP fee logic gets wrong feerate input from
blockbrew.

---

## BUG-16 (P1) — Empty `MsgPkgTxns` reply sent on no-matches (peer learns nothing useful)

**Severity:** P1. `main.go:1202-1211`:

```go
syncListeners.OnGetPkgTxns = func(peer *p2p.Peer, msg *p2p.MsgGetPkgTxns) {
    reply := &p2p.MsgPkgTxns{}
    for _, w := range msg.WTxIDs {
        if tx := mp.GetTxByWTxid(w); tx != nil {
            reply.Txs = append(reply.Txs, tx)
        }
    }
    // Even an empty reply is meaningful (peer learns we have none of them).
    peer.SendMessage(reply)
}
```

The intent comment "even an empty reply is meaningful" is questionable
per BIP-331: the protocol says a node responds with `pkgtxns` containing
the requested package's full tx set, OR (preferred) with `notfound` for
the missing wtxids. Sending an empty `pkgtxns` is non-canonical;
Core's net_processing sends `MSG_TX` `notfound` entries for each
missing wtxid instead. A peer receiving an empty `pkgtxns` may either
re-request (futile loop) or treat as "you have NONE of them"
(blockbrew's intent) — interop is undefined.

Additionally, BIP-331 specifies a peer should request a package via
`getpkgtxns` only when it has previously announced via `ancpkginfo`
that it knows about the package. blockbrew has no `ancpkginfo`
implementation (cross-cite BUG-19) so any incoming `getpkgtxns` is
fundamentally underspecified.

**File:** `cmd/blockbrew/main.go:1202-1211`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` (notfound on
unknown wtxid).

**Impact:** BIP-331 non-canonical wire behavior; potential request
loop with peers that re-ask on empty pkgtxns.

---

## BUG-17 (P1) — Inbound `pkgtxns` not validated for child-with-parents topology before AcceptPackage

**Severity:** P1. `main.go:1215-1234`:

```go
syncListeners.OnPkgTxns = func(peer *p2p.Peer, msg *p2p.MsgPkgTxns) {
    if len(msg.Txs) == 0 {
        return
    }
    result, err := mp.AcceptPackage(msg.Txs)
    if err != nil {
        log.Printf("[mempool] Rejected pkgtxns from %s: %v", peer.Address(), err)
        return
    }
    // ... relay ...
}
```

A peer pushes a non-child-with-parents arrangement (e.g. a chain
A→B→C→D, 4 txs but no single child with all 3 as parents). `AcceptPackage`
internally calls `IsChildWithParentsTree` (`mempool.go:3375`) and
rejects with `ErrPackageNotChildWithParents`. The error is logged but
the peer is NOT misbehaviour-scored.

BIP-331 §"sendpackages" + §"pkgtxns" specifies the package MUST be an
ancestor package (the announcer's ancestor-package format). A peer
that ships a non-conforming package commits a protocol violation;
Core misbehaviour-scores the peer (Misbehaving(10, ...) per net_processing
patterns).

**File:** `cmd/blockbrew/main.go:1215-1234`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` (Misbehaving on
malformed package).

**Impact:** missed DoS misbehaviour-tracking; an attacker can
repeatedly ship malformed packages without consequence.

---

## BUG-18 (P0-CDIV "dead-data plumbing") — peer `packageVersions` never consulted for outbound package-relay decisions

**Severity:** P0-CDIV ("dead-data plumbing" fleet pattern, ~10th
distinct blockbrew instance per W138/W140/W149 tracking). The
package-relay handshake records the peer's bitfield:

```go
// peer.go:189
packageVersions uint64

// peer.go:871 (handleSendPackages)
p.packageVersions |= msg.Versions

// peer.go:1259
func (p *Peer) PackageVersions() uint64 {
    return p.packageVersions
}
```

A grep over `cmd/blockbrew`, `internal/p2p/sync.go`,
`internal/p2p/peermgr.go`, `internal/p2p/mempool_handler.go` for
`PackageVersions()` or `packageVersions` consumers returns ZERO:

```bash
$ grep -rn "PackageVersions\|packageVersions" cmd/ internal/ --include="*.go" | grep -v "_test.go\|peer.go"
(no output)
```

The field is set, the accessor exists, the handshake-side
acknowledgment is sent, the listener slot is wired (BUG-17 path) —
but the **outbound side never asks "does this peer support packages?"**.
blockbrew never sends `getpkgtxns` or `pkgtxns` outbound. Package-relay
is half-implemented: receive-only.

Consequence: a fee-bumped CPFP package created locally (e.g. via
submitpackage RPC) is broadcast as individual `inv` messages per tx,
not as a package. Peer-side mempools that operate under stricter
min-relay floors than blockbrew see the low-fee child and drop it
before they ever learn there's a high-fee parent — defeating CPFP.

**File:** `internal/p2p/peer.go:189, 1259`; absence in
`cmd/blockbrew/main.go`, `internal/p2p/sync.go`,
`internal/p2p/peermgr.go`.

**Core ref:** `bitcoin-core/src/net_processing.cpp`
(`m_recently_announced_invs` / package broadcasting).

**Impact:**
- CPFP broken on the relay path: a parent-child package broadcast as
  separate INVs fails to land on peers with higher min-relay floors.
- BIP-331 advertisement is a lie: blockbrew advertises
  `sendpackages{PackageRelayVersionAncestor}` but does not actually
  relay packages outbound.

---

## BUG-19 (P1) — `GetPackageHash` (BIP-331 ancestor-package-id) absent; no `ancpkginfo` message

**Severity:** P1. Bitcoin Core's
`bitcoin-core/src/policy/packages.cpp:151-170`:

```cpp
uint256 GetPackageHash(const std::vector<CTransactionRef>& transactions)
{
    std::vector<Wtxid> wtxids_copy;
    std::transform(transactions.cbegin(), transactions.cend(),
                   std::back_inserter(wtxids_copy),
                   [](const auto& tx){ return tx->GetWitnessHash(); });
    std::sort(wtxids_copy.begin(), wtxids_copy.end(), [](const auto& lhs, const auto& rhs) {
        return std::lexicographical_compare(...);  // little-endian numeric sort
    });
    HashWriter hashwriter;
    for (const auto& wtxid : wtxids_copy) {
        hashwriter << wtxid;
    }
    return hashwriter.GetSHA256();
}
```

is the BIP-331 ancestor-package-id used to:
- Dedup `ancpkginfo` announcements on receive
- Identify which package a `getpkgtxns` is requesting
- Track recently-announced packages per-peer

blockbrew has no `GetPackageHash` analog; grep across the repo returns
zero matches. Also no `MsgAncPkgInfo` codec (the BIP-331 message
announcing "I have a package whose ancestor-package-id is X").

The 3 BIP-331 messages blockbrew implements (`sendpackages`,
`getpkgtxns`, `pkgtxns`) are the subset that does not require an
ancestor-package-id, but without `ancpkginfo` the protocol is
incomplete — a peer cannot announce which packages it has, and
blockbrew cannot ask for specific packages by id.

**File:** `internal/p2p/msg_packages.go` (only sendpackages /
getpkgtxns / pkgtxns); absence of any GetPackageHash function in
`internal/`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:151-170`;
BIP-331 §"Implementation".

**Impact:** BIP-331 partial implementation; cannot interoperate with
nodes that announce via `ancpkginfo`.

---

## BUG-20 (P1) — RBF eviction order: `removeWithDescendantsLocked` runs BEFORE `mp.outpoints` update

**Severity:** P1 (subtle invariant-leak). `mempool.go:1322-1353` in
`AddTransaction`:

```go
// Update ancestor/descendant tracking
mp.updateAncestorStateLocked(entry)
mp.updateDescendantStateLocked(entry)

// Execute RBF replacements if any.
if len(conflictingTxs) > 0 {
    for conflictHash := range conflictingTxs {
        mp.removeWithDescendantsLocked(conflictHash, MempoolRemovalReasonReplaced)
    }
}

// Add to pool
mp.pool[txHash] = entry
for _, in := range tx.TxIn {
    mp.outpoints[in.PreviousOutPoint] = txHash
}
mp.totalSize += vsize
```

The order is:
1. ancestor/descendant tracking update (line 1334-1335)
2. Conflict eviction (line 1342-1346)
3. Pool insert + outpoints update (line 1349-1352)

But `updateAncestorStateLocked` / `updateDescendantStateLocked` walk
`mp.pool` and `mp.outpoints` — at the time they run, the conflict tx
is STILL in the pool (it gets removed in step 2). The new entry's
ancestor set is computed including the about-to-be-evicted conflict's
ancestors. After step 2, the ancestor set is stale.

Core's `MemPoolAccept::Finalize` (`validation.cpp::~1500`) builds the
changeset and applies it atomically: removals AND additions happen in
one batch. blockbrew's interleaved order leaves a brief window
(within a single locked section, so no observer can see it) where the
new entry's ancestor stats reference a tx that's been removed by the
next statement.

The practical impact is minor — the per-entry `AncestorFee` /
`AncestorSize` fields may be marginally wrong after a RBF eviction
of an ancestor — but Core's invariant is "changeset applied
atomically", and blockbrew's pipeline drifts.

**File:** `internal/mempool/mempool.go:1334-1346`.

**Core ref:** `bitcoin-core/src/validation.cpp::MemPoolAccept::Finalize`.

**Impact:** subtle ancestor/descendant stat drift after RBF; may
affect `getmempoolentry.ancestorfees` / `descendantfees` for the
replacement.

---

## BUG-21 (P2) — `MaxRBFReplacedTxs` and `MaxPackageCount` not exposed as operator-knobs

**Severity:** P2. blockbrew constants:
- `MaxRBFReplacedTxs = 100` (`mempool.go:195`)
- `MaxPackageCount = 25` (`mempool.go:258`)
- `MaxPackageWeight = 404_000` (`mempool.go:262`)

are package-level constants. Core also hard-codes them
(`MAX_REPLACEMENT_CANDIDATES`, `MAX_PACKAGE_COUNT`, `MAX_PACKAGE_WEIGHT`)
so this is not a divergence by itself. But Core ships
`-mempoolfullrbf` and W150 BUG-18 already flagged the missing
`-incrementalrelayfee` / `-limitancestorcount` etc. — these RBF/package
limits are similarly absent as operator-knobs.

Listed for fleet-pattern continuity ("no operator-knob exists"
recurring theme); not a consensus risk.

**File:** `internal/mempool/mempool.go:195, 258, 262`.

**Impact:** test ergonomics; cross-impl operator-config divergence.

---

## BUG-22 (P1) — `acceptMultiTxPackage` does not call `checkRBFLocked` for in-mempool conflicts; package-RBF semantics absent

**Severity:** P1. `acceptMultiTxPackage` (`mempool.go:3456-3605`) loops
each tx through `validateTransactionLocked` (line 3507) which does
detect mempool conflicts at line 3647-3651:

```go
if existingTxHash, ok := mp.outpoints[in.PreviousOutPoint]; ok {
    existingEntry := mp.pool[existingTxHash]
    if existingEntry != nil && !mp.config.MempoolFullRBF && !signalsRBF(existingEntry.Tx) {
        return 0, 0, ErrRBFNotSignaled
    }
}
```

But it does NOT call `checkRBFLocked`. Rule 2 / 3 / 4 / 5 are not
enforced for package-level RBF. The tx that conflicts is then handed
to `addTransactionLocked` (line 3579) which calls `addPoolEntry` —
but `addPoolEntry` doesn't take the conflict-eviction path either;
the conflict tx is NEVER removed from the mempool, and the
double-spend invariant is now broken (`mp.outpoints` still maps the
prevout to the conflict tx, while the new tx with the same prevout
is now in `mp.pool`).

Core has `PackageRBFChecks` (`validation.cpp:1037-1196`) which:
1. Restricts package-RBF to 1-parent-1-child topology.
2. Requires no in-mempool ancestors for either workspace.
3. Aggregates all conflicts → `GetEntriesForConflicts` (cluster count
   Rule 5).
4. Aggregates fees + vsize → `PaysForRBF`.
5. Runs `ImprovesFeerateDiagram` over the changeset.

blockbrew skips ALL FIVE in `acceptMultiTxPackage`. The single-tx
`acceptSingleTxPackage` path calls `mp.AddTransaction` (line 3434)
which DOES route through `checkRBFLocked`, so single-tx submissions
do get Rule-3/4/5 checks. The multi-tx path is the gap.

**File:** `internal/mempool/mempool.go:3456-3605` (no checkRBFLocked
call); `mempool.go:3647-3651` (conflict detection without RBF gates).

**Core ref:** `bitcoin-core/src/validation.cpp:1037-1196`.

**Impact:**
- Package-RBF accepts replacements that don't pay Rule 3 / Rule 4 /
  Rule 5; mempool free-relay surface.
- Double-spend invariant: post-multi-tx-RBF, `mp.outpoints` may map
  a prevout to a tx no longer in `mp.pool` (or worse, two different
  txs share the same outpoint logically).

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CDIV:** 8 (BUG-1, BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8, BUG-18)
- **P1:** 13 (BUG-2, BUG-9, BUG-10, BUG-11, BUG-12, BUG-13, BUG-14,
  BUG-15, BUG-16, BUG-17, BUG-19, BUG-20, BUG-22)
- **P2:** 1 (BUG-21)

**Fleet patterns confirmed:**
- "two-pipeline guard 17th distinct blockbrew extension" (BUG-7) —
  first RBF-specific instance: wallet bumpfee Rule 3 math diverges
  from relay Rule 4 math (different formula, different constant).
- "comment-as-confession" 9th and 10th distinct blockbrew instances
  (BUG-3 cluster-counting and BUG-12 maxfeerate post-accept; BUG-8
  short-circuit "we cannot compute it" is an 11th).
- "dead-data plumbing" ~10th distinct blockbrew instance (BUG-18:
  peer `packageVersions` recorded but never consulted for outbound
  decisions).
- "wiring-look-but-no-wire" (BUG-18: package-relay advertised on
  handshake, OnPkgTxns/OnGetPkgTxns wired, but outbound relay path
  doesn't exist).
- "N-pipeline drift" 3rd distinct mempool pipeline instance (BUG-13:
  testmempoolaccept is the 3rd ATMP path — alongside AddTransaction
  and validateTransactionLocked — missing 8+ gates the other two
  enforce).
- "default-constants-divergent" (BUG-1: `IncrementalRelayFee = 1000`
  vs Core's `100`; `MinRelayFeeRate = 1000` vs Core's `100`;
  both 10× upstream).
- "missing-Core-constant" (BUG-2: `WALLET_INCREMENTAL_RELAY_FEE`
  absent; cross-cite W130 BUG-2).
- "wire-string parity slippage" (BUG-9: `insufficient feerate: does
  not improve feerate diagram` vs Core's `replacement-failed`).
- "carry-forward unfixed audit findings" — W116 BUG-1/2/4/5/6/9 still
  present (cross-cite BUG-10/11/12/13/14/15); W130 BUG-1/2 still
  present (cross-cite BUG-2/7).
- "operator-knob absent" (BUG-21: `MaxRBFReplacedTxs`, `MaxPackageCount`,
  `MaxPackageWeight` hard-coded; cross-cite W150 BUG-18 / BUG-19).
- "wire-policy divergence" (BUG-1, BUG-3, BUG-4, BUG-5, BUG-22:
  multiple gates accept/reject txs that Core's opposite-decisions).
- "hardcoded RPC reply" (BUG-6: `getmempoolinfo` hardcodes 3 relay-fee
  fields + maxmempool + unbroadcastcount regardless of config).

**Top three findings:**

1. **BUG-1 + BUG-3 cluster (P0-CDIV Rule 4 + Rule 5 wire-policy
   divergence)** — blockbrew's `IncrementalRelayFee = 1000 sat/kvB`
   is 10× Core's `DEFAULT_INCREMENTAL_RELAY_FEE = 100`, making RBF
   Rule 4 require 10× the additional fee Core demands (replacements
   Core accepts get rejected). Compounded by BUG-3: Rule 5 counts
   individual txs (with comment-as-confession claiming "equivalent
   for non-cluster-mempool deployments" but blockbrew ships a cluster
   mempool), so a 25-tx CPFP chain replacement that Core's `num_clusters
   = 1` accepts fails blockbrew's `totalEvicted = 25..625 > 100`.
   Combined: a fee-bumped Lightning channel-close at +0.5 sat/vB
   touching a 25-tx cluster — Core accepts, blockbrew double-rejects.

2. **BUG-4 + BUG-22 cluster (P0-CDIV `m_allow_replacement` gate absent
   + package-RBF semantics absent)** — blockbrew has no
   `m_allow_replacement` flag, so the `bip125-replacement-disallowed`
   wire token never fires. More critically, `acceptMultiTxPackage`
   never calls `checkRBFLocked` — Rule 2/3/4/5 + ImprovesFeerateDiagram
   are unenforced for multi-tx package-RBF, AND the conflict tx is
   not removed (`mp.outpoints` invariant breaks). A package
   containing a tx that double-spends a mempool tx lands without
   any RBF check. Core's PackageRBFChecks restricts package-RBF to
   1-parent-1-child + no in-mempool ancestors; blockbrew has no
   such restriction.

3. **BUG-13 + BUG-18 cluster (P1 N-pipeline drift +
   dead-data-plumbing in package-relay)** — `testmempoolaccept` is
   the 3rd ATMP pipeline missing 8+ gates the other two enforce
   (RBF, scripts, BIP-68, chain limits, TRUC, dust, witness-standard,
   cross-tx conflicts). Wallets relying on `allowed=true` for
   pre-broadcast simulation get incorrect signal. Meanwhile,
   `peer.packageVersions` is recorded on handshake but never
   consulted by the outbound relay path — blockbrew advertises
   `PackageRelayVersionAncestor` on the wire but never sends
   `getpkgtxns`/`pkgtxns` outbound. Locally-created CPFP packages
   (via submitpackage) broadcast as separate INVs, defeating CPFP
   on peers with higher min-relay floors.
