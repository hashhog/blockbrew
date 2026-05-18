# W143 — Block-level validation audit (blockbrew)

**Wave:** W143 — CheckBlock + ContextualCheckBlock + ContextualCheckBlockHeader
+ ConnectBlock (the four block-entry gates in Core's validation pipeline).
Sigops budget, BIP-34 coinbase height, BIP-30 duplicate-coinbase, merkle
root + CVE-2012-2459, MoneyRange, vin/vout shape, coinbase uniqueness,
weight/size limit, block timestamp future-bound and MTP-bound.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp` — `CheckBlock` (3918), `CheckBlockHeader`
  (3828), `CheckMerkleRoot` (3837), `ContextualCheckBlock` (4129),
  `ContextualCheckBlockHeader` (4080), `IsBlockMutated` (4027), BIP-30
  ConnectBlock site (2402–2476).
- `bitcoin-core/src/consensus/tx_check.cpp` — `CheckTransaction`.
- `bitcoin-core/src/consensus/merkle.cpp` — `ComputeMerkleRoot`,
  `BlockMerkleRoot`, CVE-2012-2459 doc.
- `bitcoin-core/src/consensus/consensus.h` — `MAX_BLOCK_SIGOPS_COST=80_000`,
  `MAX_BLOCK_WEIGHT=4_000_000`, `MAX_BLOCK_SERIALIZED_SIZE=4_000_000`,
  `WITNESS_SCALE_FACTOR=4`.
- `bitcoin-core/src/consensus/params.h` — `BIP34Height`, `BIP34Hash`,
  `BIP65Height`, `BIP66Height`, `nSubsidyHalvingInterval`.
- `bitcoin-core/src/chain.h` — `MAX_FUTURE_BLOCK_TIME=7200`.
- `bitcoin-core/src/deploymentstatus.h` — `DeploymentActiveAfter`,
  `DeploymentActiveAt`.
- `bitcoin-core/src/script/script.h` — `CScript::push_int64`.
- `bitcoin-core/src/consensus/validation.h` — `GetWitnessCommitmentIndex`,
  `MINIMUM_WITNESS_COMMITMENT=38`, `GetBlockWeight`.

**BIPs:** BIP-30 (duplicate coinbase), BIP-34 (coinbase height),
BIP-65 (CLTV — version-bits), BIP-66 (DERSIG — version-bits), BIP-113
(MTP for IsFinalTx), BIP-141 (block weight), BIP-325 (signet block
solution).

**Methodology**
1. Read every Core ref end-to-end (CheckBlock + CheckBlockHeader +
   CheckMerkleRoot + ContextualCheckBlock + ContextualCheckBlockHeader
   + ConnectBlock BIP-30 site + CheckTransaction + ComputeMerkleRoot).
2. Build a 30-gate matrix split across the 8 behaviours from the wave
   brief.
3. Audit each gate against blockbrew at the file:line level.
4. Each divergence becomes a `BUG-<n>`; severity drawn from
   `consensus-split / wrong-error-for-RPC / DoS / dead-code` axis.

**Files audited:**
- `internal/consensus/blockvalidation.go` (CheckBlockSanity,
  CheckBlockContext, checkWitnessCommitment, checkBIP34Height,
  encodeBIP34Height, decodeScriptNum, IsBIP30Repeat, IsBIP30Unspendable,
  CheckBIP30, CalcMedianTimePast, CheckBlockTimestamp, IsBlockMutated).
- `internal/consensus/txvalidation.go` (CheckTransactionSanity,
  IsCoinbaseTx, CheckTransactionInputs).
- `internal/consensus/merkle.go` (CalcMerkleRoot, CalcMerkleRootMutation,
  CalcWitnessMerkleRoot, CalcWitnessCommitment).
- `internal/consensus/sigops.go` (CountBlockSigOpsCost,
  GetTransactionSigOpCost, CountSigOpsInaccurate / Accurate /
  CountWitnessSigOps).
- `internal/consensus/weight.go` (CalcBlockWeight, CalcTxWeight).
- `internal/consensus/chainmanager.go` (ConnectBlock — BIP-30 site,
  sigops-cost cap, subsidy + fee gate, MTP collection).
- `internal/consensus/headerindex.go` (header acceptance — PoW + MTP +
  BIP-94 + future-time).
- `internal/consensus/difficulty.go` (CalcBlockSubsidy).
- `internal/consensus/params.go` (`SubsidyHalvingInterval`,
  `MaxBlockSigOpsCost`, `MaxBlockWeight`, `MaxTimeAdjustment`).
- `internal/consensus/chaincfg.go` (per-network `BIP34Height`,
  `BIP34Hash`, `SubsidyHalvingInterval`).
- `internal/p2p/sync.go:1939` (validationWorker → CheckBlockSanity).
- `internal/rpc/methods.go:1947,2071` (submitblock → CheckBlockSanity).

---

## Gate matrix (30 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | MAX_BLOCK_SIGOPS_COST=80_000 | G1: legacy sigops × 4 in CheckBlock (context-free) | **BUG-1** (P1): not in `CheckBlockSanity`; only enforced inside `ConnectBlock` |
| 1 | … | G2: per-input P2SH + witness sigops in ConnectBlock | PASS (`chainmanager.go:801-802`) |
| 1 | … | G3: total > 80_000 → "bad-blk-sigops" | PASS (`chainmanager.go:803-806`) |
| 1 | … | G4: legacy uses INACCURATE counting (CHECKMULTISIG=20) | PASS (`sigops.go:30-34`, `chainmanager.go:720-723,796-799`) |
| 2 | BIP-34 coinbase height | G5: CScriptNum push (`CScript() << nHeight`) | PASS (`blockvalidation.go:288-330`, encode-then-prefix-compare) |
| 2 | … | G6: OP_0 for nHeight=0; OP_1..OP_16 for 1..16 | PASS (`blockvalidation.go:304-311`) |
| 2 | … | G7: gated on `>= BIP34Height` (matches `DeploymentActiveAfter`) | PASS (`blockvalidation.go:177-181`) |
| 2 | … | G8: `decodeScriptNum` helper alive | **BUG-2** (P3-DEAD): defined `blockvalidation.go:333-352`, no callers |
| 2 | … | G9: version-byte rejection at header acceptance time | **BUG-3** (P1): no `block.Version < 2/3/4` check in `headerindex.go`; deferred to `CheckBlockContext` |
| 3 | BIP-30 duplicate coinbase | G10: heights 91842 + 91880 exemption (with EXACT hash) | PASS (`blockvalidation.go:365-375`) |
| 3 | … | G11: BIP34 short-circuit via `BIP34Hash` ancestor lookup | PASS (`blockvalidation.go:440-444`, uses `>= BIP34Height+1` window) |
| 3 | … | G12: BIP34_IMPLIES_BIP30_LIMIT=1_983_702 re-enable | PASS (`blockvalidation.go:420,448-450`) |
| 3 | … | G13: BIP-30 ancestor walk skipped when `params.BIP34Hash.IsZero()` | **BUG-4** (P2): blockbrew skips short-circuit on testnet4/regtest/signet — defensible perf optimisation but means BIP-30 enforced "forever" on these nets (Core's behaviour matches in practice; flagged for awareness, not divergence) |
| 4 | Merkle root + CVE-2012-2459 | G14: `mutated` flag propagated from `ComputeMerkleRoot` to CheckMerkleRoot | PASS (`blockvalidation.go:111-118`, `merkle.go:34-69`) |
| 4 | … | G15: mismatch → `ErrBadMerkleRoot` (Core: "bad-txnmrklroot") | PASS (`blockvalidation.go:112-115`); error-string differs from Core wire `bad-txnmrklroot` — irrelevant for consensus |
| 4 | … | G16: mutation → `ErrBlockMutated`; caller treats as transient | PASS (`blockvalidation.go:116-118`, `sync.go:1951` `transientMutation` branch) |
| 4 | … | G17: witness merkle mutation flag propagated | **BUG-5** (P1, cross-references W142-BUG-2): `CalcWitnessMerkleRoot` (`merkle.go:82-93`) discards the `mutated` flag from `CalcMerkleRoot` |
| 5 | MoneyRange | G18: each `tx.vout[i].nValue >= 0` and `<= MAX_MONEY` | PASS (`txvalidation.go:79-85`) |
| 5 | … | G19: running sum `totalOutput <= MAX_MONEY` | PASS (`txvalidation.go:86-90`) |
| 5 | … | G20: coinbase value gate `coinbase.GetValueOut() <= subsidy + fees` | PASS (`chainmanager.go:933-943`) |
| 6 | vin/vout + exactly one coinbase | G21: empty block rejected | PASS (`blockvalidation.go:75-77`) |
| 6 | … | G22: `block.vtx[0]` is coinbase | PASS (`blockvalidation.go:80-82`) |
| 6 | … | G23: `block.vtx[i]` for `i > 0` is NOT coinbase | PASS (`blockvalidation.go:85-89`) |
| 6 | … | G24: empty `tx.vin` and empty `tx.vout` rejected | PASS (`txvalidation.go:60-65`) |
| 7 | Block size / weight | G25: `vtx.size() * 4 > MAX_BLOCK_WEIGHT` early reject | **BUG-6** (P2): not present; only `CalcBlockWeight > MaxBlockWeight` (subsumes in practice) |
| 7 | … | G26: stripped × 4 > MAX_BLOCK_WEIGHT independent check | **BUG-7** (P2): not present (subsumed by full weight check; differs from Core CheckBlock 3947) |
| 7 | … | G27: weight check re-run **after** witness commitment validated (CheckBlock cannot mark permanently invalid until coinbase witness is confirmed) | **BUG-8** (P1-MUTABILITY): weight checked once in `CheckBlockSanity` (`blockvalidation.go:121-124`), never re-run in `CheckBlockContext` after the witness reserved value is validated — Core's two-phase gate is missing |
| 8 | Block timestamp | G28: `header.Time() > now() + MAX_FUTURE_BLOCK_TIME(7200)` rejected | PASS (`blockvalidation.go:68-72` and `headerindex.go:447-449`) |
| 8 | … | G29: `header.Time() <= MTP(prev 11)` rejected | PASS (`headerindex.go:420-424`); also redundantly in `CheckBlockContext` (`blockvalidation.go:147-151`) |
| 8 | … | G30: signet block solution checked when `signet_challenge` is set | **BUG-9** (P0-CONSENSUS-signet): `CheckSignetBlockSolution` is **entirely missing**; `signetParams` is wired (`chaincfg.go:360-...`), `--network=signet` is dispatched (`cmd/blockbrew/main.go:622,...`) but no BIP-325 challenge is validated, breaking signet at block 1 |

---

## BUG-1 (P1) — `CheckBlockSanity` is missing the legacy-sigops budget cap

**Severity:** P1 — context-free check absent from blockbrew's sanity gate.
Caught downstream in `ConnectBlock`, but means any code path that calls
`CheckBlockSanity` in isolation (validationWorker, `submitblock` RPC)
accepts mathematically impossible blocks.

**File:** `internal/consensus/blockvalidation.go:60-127`
(`CheckBlockSanity`)

**Core ref:** `bitcoin-core/src/validation.cpp:3969-3977`

```cpp
// This underestimates the number of sigops, because unlike ConnectBlock it
// does not count witness and p2sh sigops.
unsigned int nSigOps = 0;
for (const auto& tx : block.vtx)
{
    nSigOps += GetLegacySigOpCount(*tx);
}
if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops", "out-of-bounds SigOpCount");
```

**Description:** Core's `CheckBlock` sums `GetLegacySigOpCount` across all
txs (vin + vout, INACCURATE multisig=20) and rejects when the total ×
WITNESS_SCALE_FACTOR exceeds 80_000. This is a **context-free** check
because legacy sigops only count opcodes in scriptSig + scriptPubKey,
not P2SH redeem-scripts or witnesses. blockbrew defers the entire
sigops cap to `ConnectBlock` (`chainmanager.go:719-806`), so:

- `internal/p2p/sync.go:1939` (`validationWorker`) accepts a block
  whose legacy sigops alone exceed 80_000 — it only fails at the
  later `ConnectBlock` step.
- `internal/rpc/methods.go:1947,2071` (`submitblock` RPC) **only**
  calls `CheckBlockSanity` for the validity probe, so an RPC client
  can pass blocks that Core would reject at sanity-time.

**Impact:** Block-acceptance path widens. Not a consensus divergence
(ConnectBlock still rejects), but breaks Core's invariant that
`CheckBlock(...) == true ⇒ block has the chance to connect`. The
sync worker logs `failed sanity check` only for the cases it actually
catches; sigops-bombs now silently flow into ConnectBlock and rollback
the whole UTXO modification stack — wasted work + a clearer DoS
attenuation point.

---

## BUG-2 (P3-DEAD) — `decodeScriptNum` is defined but never called

**Severity:** P3 — dead code, latent bug surface.

**File:** `internal/consensus/blockvalidation.go:332-352`

**Core ref:** `bitcoin-core/src/script/script.h::CScriptNum`

**Description:** `decodeScriptNum` is a 20-line helper that parses a
minimally-encoded `CScriptNum` from a byte slice, intended for BIP-34
coinbase-height extraction. The current BIP-34 check (`checkBIP34Height`,
`blockvalidation.go:288-299`) takes the opposite (and correct) approach
of **encoding** the expected height via `encodeBIP34Height` and doing a
byte-prefix `bytes.Equal`. The `decodeScriptNum` path is therefore dead.

**Excerpt:**

```go
// decodeScriptNum decodes a minimally-encoded script number (little-endian with sign bit).
func decodeScriptNum(data []byte) int64 {
	if len(data) == 0 {
		return 0
	}
	var result int64
	for i := 0; i < len(data); i++ {
		result |= int64(data[i]) << uint(8*i)
	}
	if data[len(data)-1]&0x80 != 0 {
		result &= ^(int64(0x80) << uint(8*(len(data)-1)))
		result = -result
	}
	return result
}
```

`grep -rn decodeScriptNum internal/` returns only its definition; the
identically-named helper in `internal/mining/mining_test.go:266` is a
test-only copy. The function is also subtly **non-minimal-encoding aware**
(would silently accept zero-padded mantissas) and has no overflow guard,
so re-introducing it as a fallback would mask a divergence rather than
fix one.

**Impact:** Bit-rot risk — a future audit may try to "wire it up"
without realising the encode-then-compare path is the correct one. The
fleet pattern from W127/W137 ("declared-defined-deinit-but-never-populate")
applies here: signal vs. real load-bearing implementation is muddled.
Recommended: delete.

---

## BUG-3 (P1) — Block version-height gate not enforced at header acceptance

**Severity:** P1 — header-time DoS amplification.

**File:** `internal/consensus/headerindex.go` (no version check) vs
`internal/consensus/blockvalidation.go:131-144` (deferred check inside
`CheckBlockContext`).

**Core ref:** `bitcoin-core/src/validation.cpp:4112-4118`
(`ContextualCheckBlockHeader`)

```cpp
// Reject blocks with outdated version
if ((block.nVersion < 2 && DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_HEIGHTINCB)) ||
    (block.nVersion < 3 && DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_DERSIG)) ||
    (block.nVersion < 4 && DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_CLTV))) {
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, strprintf("bad-version(0x%08x)", block.nVersion),
                             strprintf("rejected nVersion=0x%08x block", block.nVersion));
}
```

**Description:** Core's `ContextualCheckBlockHeader` rejects v<2 above
BIP34Height, v<3 above BIP66Height, v<4 above BIP65Height **at header
acceptance time** (inside `AcceptBlockHeader`). blockbrew's header-index
acceptance (`headerindex.go:380-510`) checks PoW, difficulty, MTP,
checkpoints, BIP-94 timewarp and min-pow — **but not the version-byte
floor**. The version-byte check is deferred to `CheckBlockContext`
(`blockvalidation.go:131-144`), which only runs once the full block
arrives.

**Impact:** A peer can flood blockbrew with low-version-byte headers
above the buried activation heights and grow the in-memory header
index until the corresponding block bodies are downloaded and
`ConnectBlock` rejects them — wasting bandwidth and CPU on PoW checks
for headers that Core would have killed at the AcceptHeader gate.
Compounds with `CheckForkConflictsWithCheckpoint` (W15 history) where
header-spam was the same class of attack.

---

## BUG-4 (P2) — BIP-30 short-circuit ancestor walk skipped on networks with `BIP34Hash == 0`

**Severity:** P2 — defensible optimisation but a deliberate divergence
from Core's no-op pathway; flagged for awareness.

**File:** `internal/consensus/blockvalidation.go:440-444` (`CheckBIP30`)

**Core ref:** `bitcoin-core/src/validation.cpp:2459-2462`

```cpp
assert(pindex->pprev);
CBlockIndex* pindexBIP34height = pindex->pprev->GetAncestor(params.GetConsensus().BIP34Height);
//Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == params.GetConsensus().BIP34Hash));
```

**Description:** Core unconditionally walks `pprev->GetAncestor(BIP34Height)`
and compares against `BIP34Hash`. When `BIP34Hash` is zero (testnet4,
regtest, signet — all networks where BIP34 is active from genesis), the
comparison always fails (any real block hash ≠ zero), so `fEnforceBIP30`
stays true and the duplicate-output loop runs for every block forever.
This is observed-behaviour Core. blockbrew elides the walk via
`!params.BIP34Hash.IsZero()` (line 440), which is **semantically
equivalent** (the comparison would have failed anyway) but means the
chain-of-reasoning differs from Core's literal code path.

**Excerpt:**

```go
if enforce && height > params.BIP34Height && ancestorHashAt != nil && !params.BIP34Hash.IsZero() {
    if ancHash, ok := ancestorHashAt(params.BIP34Height); ok && ancHash == params.BIP34Hash {
        enforce = false
    }
}
```

**Impact:** None observable today. Will become a divergence if Core
ever introduces a fork-via-genesis-aware optimisation that uses the
`BIP34Hash == 0` predicate as a sentinel for a different code path.
Recommended: keep the optimisation but add a comment that explicitly
calls out the "always-true `enforce` on testnet4/regtest/signet"
observation, to prevent a future contributor from "fixing" it to
match Core literally.

---

## BUG-5 (P1) — `CalcWitnessMerkleRoot` discards the CVE-2012-2459 mutation flag

**Severity:** P1 — cross-references W142-BUG-2 (witness-tree mutation
detection).

**File:** `internal/consensus/merkle.go:82-93`

**Core ref:** `bitcoin-core/src/consensus/merkle.cpp:76-85`
(`BlockWitnessMerkleRoot` propagates `mutated*` via `ComputeMerkleRoot`).

**Description:** Core's `IsBlockMutated` (validation.cpp:4027-4055)
calls `CheckMerkleRoot` (txid tree) AND `CheckWitnessMalleation` (witness
tree). blockbrew's `IsBlockMutated` (`blockvalidation.go:523-553`) calls
`CalcMerkleRootMutation` for txids — but `CalcWitnessMerkleRoot`
internally calls the non-mutation-aware `CalcMerkleRoot`, dropping the
mutation signal:

```go
func CalcWitnessMerkleRoot(wtxids []wire.Hash256) wire.Hash256 {
	// ...
	hashes[0] = wire.Hash256{}
	return CalcMerkleRoot(hashes)  // ← drops the *mutated flag
}
```

`CalcWitnessCommitment` then takes that root and double-hashes it with
the reserved value, so the witness commitment compare is still
byte-exact — **but** an attacker could craft a witness tree with
adjacent-pair-duplicated wtxids that hashes to a valid commitment
without actually being the unique witness set, and we'd never raise
the mutation flag. The blockbrew `checkWitnessCommitment` path
(`blockvalidation.go:262-269`) is robust because Core's commitment
check is itself mutation-resistant by design (the commitment is
recomputed from the witness leaves), so this is a **defence-in-depth**
gap rather than a live exploit. Still worth fixing because the W142
audit already flagged it (BUG-2) and the W126 BIP-152 reconstruct
path uses `IsBlockMutated` directly.

**Impact:** `IsBlockMutated` cannot detect a mutated witness tree even
when called from the compact-block reconstruction path
(`internal/p2p/compactblock.go:594`). Two impls would re-request the
block; an honest legitimate copy may have the same wtxid mutation
signal but no other check catches it.

---

## BUG-6 (P2) — Missing early `vtx.size() * 4 > MAX_BLOCK_WEIGHT` reject

**Severity:** P2 — Core fast-path missing; subsumed by full weight
calc in practice.

**File:** `internal/consensus/blockvalidation.go:60-127`
(`CheckBlockSanity`)

**Core ref:** `bitcoin-core/src/validation.cpp:3947`

```cpp
if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");
```

**Description:** Core has three OR'd predicates: (a) empty block,
(b) `vtx.size() * 4 > MAX_BLOCK_WEIGHT` (catches pathological tx-count
even before serialisation), (c) `stripped * 4 > MAX_BLOCK_WEIGHT`.
blockbrew has (a) and (CalcBlockWeight > MaxBlockWeight, which covers
both (b) and (c) because every tx is at least 1 byte stripped, so
`stripped * 4 >= vtx.size() * 4`). The fast-path early reject is
absent — `CalcBlockWeight` calls `CalcTxWeight` for every tx (each
re-serialises the tx twice), so a pathological block with 1M dummy txs
takes O(N) work instead of Core's O(1) reject.

**Impact:** DoS amplification. Not exploitable on the wire (a 1M-tx
block is itself too large to deliver) but rejects blocks 4× more
slowly than Core in the limit.

---

## BUG-7 (P2) — Stripped-size check absent

**Severity:** P2 — strict subset of the full-weight check; cosmetic.

**File:** `internal/consensus/blockvalidation.go:121-124`

**Core ref:** `bitcoin-core/src/validation.cpp:3947` (third predicate in
the OR-chain).

**Description:** Core checks `GetSerializeSize(TX_NO_WITNESS(block)) * 4
> MAX_BLOCK_WEIGHT` (the pre-segwit "1 MB base block" rule, now
restated as `stripped * 4 > 4 MB`). blockbrew's `CalcBlockWeight =
stripped * 3 + total`. Since `total >= stripped`, `CalcBlockWeight
>= stripped * 4`. Thus `stripped * 4 > 4 MB` implies `CalcBlockWeight >
4 MB`, and the explicit stripped check is redundant.

**Impact:** None — strictly subsumed. Flagged for parity-completeness.

---

## BUG-8 (P1) — Block-weight check not re-run after witness commitment validated

**Severity:** P1 — Core deliberately splits the weight check so that
mark-permanently-invalid only fires on weight after the coinbase
witness reserved value is known to be tight. blockbrew checks weight
once at sanity-time; the result is permanently cached as
`StatusFullyValid` if it passes, with no second gate.

**File:** `internal/consensus/blockvalidation.go:121-124`
(weight check in sanity), `blockvalidation.go:131-205` (no weight
check in `CheckBlockContext`)

**Core ref:** `bitcoin-core/src/validation.cpp:4173-4181`

```cpp
// After the coinbase witness reserved value and commitment are verified,
// we can check if the block weight passes (before we've checked the
// coinbase witness, it would be possible for the weight to be too
// large by filling up the coinbase witness, which doesn't change
// the block hash, so we couldn't mark the block as permanently
// failed).
if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-weight", strprintf("%s : weight limit failed", __func__));
}
```

**Description:** Core's comment is explicit: an attacker can stuff
the coinbase witness with arbitrary bytes that don't affect the
block hash but inflate `GetBlockWeight`. If we mark the block
permanently invalid on first weight-check (which blockbrew effectively
does — `node.Status |= StatusFullyValid` is set after the entire
ConnectBlock succeeds, but the **sanity** check rejects on weight
without distinguishing "transient weight bloat via mutable witness"
from "real over-weight block"), the legitimate (un-mutated) form
loses access. blockbrew's `CheckBlockSanity` rejects with
`ErrBlockWeightTooHigh`, which the sync path (`sync.go:1951`) does
**not** treat as transient (only `ErrBlockMutated` is). So a peer
shipping an over-weight mutated block would taint the hash for the
honest form.

**Impact:** Same DoS surface as CVE-2012-2459 (`ErrBlockMutated`
already handled): an attacker can pre-load blockbrew's invalid-block
list with the hash of a legitimate future block by shipping a
witness-inflated copy first. The legitimate form would be **rejected
as a known-bad hash**. Recommended fix: treat
`ErrBlockWeightTooHigh` as a transient-class error in the sync path,
**or** split the weight check into sanity (using stripped × 4) and
contextual (using full weight) the way Core does.

---

## BUG-9 (P0-CONSENSUS, signet) — `CheckSignetBlockSolution` is missing

**Severity:** **P0-CONSENSUS for signet operation.** Affects
`--network=signet` runs only. Mainnet/testnet/regtest unaffected.

**File:** `internal/consensus/blockvalidation.go:60-127`
(`CheckBlockSanity` — no signet branch), `internal/consensus/chaincfg.go:359-...`
(`SignetParams` wired but no challenge field), `cmd/blockbrew/main.go:622+`
(`--network=signet` dispatched).

**Core ref:** `bitcoin-core/src/validation.cpp:3930-3933`

```cpp
// Signet only: check block solution
if (consensusParams.signet_blocks && fCheckPOW && !CheckSignetBlockSolution(block, consensusParams)) {
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-signet-blksig", "signet block signature validation failure");
}
```

Plus `bitcoin-core/src/signet.cpp` (the entire BIP-325 verifier:
challenge script + signature pulled from coinbase witness commitment
push, then evaluated against the signet challenge).

**Description:** Signet (BIP-325) requires every block to carry a
signed solution to the signet challenge in the coinbase scriptSig
pushdata. blockbrew has signet wired through CLI / config / chain
params, but `CheckBlockSanity` has no signet branch and there is no
`CheckSignetBlockSolution`-equivalent anywhere in the tree:

```
$ grep -rn "signet_blocks\|signet_challenge\|CheckSignetBlockSolution" internal/consensus/
(no matches)
```

`SignetParams()` (`chaincfg.go:359-...`) is the only signet-aware
function in the consensus package. It sets the network name and pow
limit but provides no challenge bytes.

**Impact:** When blockbrew is started with `--network=signet` it will
**accept any PoW-valid block** at the signet difficulty, regardless of
whether the block carries a valid signet signature. This is a **full
consensus break against the Bitcoin Core signet implementation** for
this network — blockbrew will fork off the signet chain at block 1
because any block with the trivial signet PoW (which is very low) is
acceptable to blockbrew but only the canonical-signer's blocks are
acceptable to Core.

**Recommended:** Either (a) wire the BIP-325 verifier and add a
`SignetChallenge []byte` field to ChainParams (full fix), or (b)
refuse to start with `--network=signet` until (a) lands (safe
short-term).

---

## Additional sub-findings (not numbered — too small for individual
BUGs but worth recording)

### S1 — Regtest `SubsidyHalvingInterval` not consulted

`internal/consensus/difficulty.go:162` defines
`CalcBlockSubsidy(height int32) int64` and uses the **package-level
constant** `SubsidyHalvingInterval = 210_000`
(`params.go:27`) instead of `params.SubsidyHalvingInterval`. The
regtest params object is initialised with `SubsidyHalvingInterval:
150` (`chaincfg.go:319`) but **the field is never read by
`CalcBlockSubsidy`**. This is a definite regtest subsidy bug
(blockbrew over-pays the subsidy on regtest after block 150 because
the first halving never happens until block 210_000). Mining /
generate-RPC paths and the `ErrBadCoinbaseValue` check
(`chainmanager.go:939`) all consult `CalcBlockSubsidy` so the gate
mis-fires on regtest.

This belongs under W144 / W148 ("subsidy / coinbase mechanics")
more than W143, but is mentioned here because the BIP-30 ConnectBlock
audit surfaces the call site.

### S2 — `MaxBlockSize = 1_000_000` is dead consensus, alive in RPC

`internal/consensus/params.go:5-6` defines `MaxBlockSize = 1_000_000`
(the pre-segwit base block limit). `grep -rn 'MaxBlockSize\b'`:

- `params.go:5` — definition
- `rpc/methods.go:1787` — `getblocktemplate` `sizelimit` field

No consensus enforcement against this value (correct — `MAX_BLOCK_WEIGHT
= 4_000_000` is the post-BIP141 cap, which we do enforce). But the
RPC field reports `1_000_000`, which mismatches Core's
`getblocktemplate` (it reports `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000`
or `MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR = 1_000_000` for the
**virtual** size limit — Core's value depends on the segwit branch
taken). This is W124-class (operator-experience) more than W143; flagged
to deduplicate.

### S3 — `CheckBlock` result not cached (`block.fChecked`)

Core's `CheckBlock` caches the all-passed result on the in-memory
`CBlock` object via `block.fChecked = true` so a subsequent ConnectBlock
call skips the re-validation. blockbrew has no equivalent — every
ConnectBlock re-runs `CheckBlockSanity` from scratch (only skipped
during IBD via `if !cm.isIBD` at chainmanager.go:527). Performance
issue, not consensus. P2 / P3.

---

## Cross-references and shared findings

- **W142** (segwit witness validation, May 2026) — BUG-2 in that audit
  is the same root cause as **BUG-5** here (mutation flag not
  propagated through `CalcWitnessMerkleRoot`). Fix one, the other
  closes.
- **W142** — BUG-7 (64-byte tx detection in `IsBlockMutated`) is a
  sibling of the same `IsBlockMutated` weakness; fixing both gives
  blockbrew full parity with Core's mutation detection.
- **W132** (nSequence / CSV / MTP, May 2026) — overlap with G29
  (timestamp vs MTP). G29 audited PASS here; no new findings.
- **W93** (BIP-30 ancestor lookup off-by-one, fixed earlier) — the
  fix is preserved at `blockvalidation.go:440-444`; covered by G11.

---

## Fleet-pattern smell

1. **"Defined but never wired" (W137 / W138 pattern):** `decodeScriptNum`
   is a clean instance of dead-helper-at-call-site; one of the impl
   patterns the fleet has been calling out for 4 audits running. Three
   instances across blockbrew (this `decodeScriptNum`, the
   W138 `DualChainstateManager`, and the W141 `assumeUTXO` background
   validator).

2. **"Context-free check deferred to context-dependent gate":**
   `BUG-1` (sigops in CheckBlock) and `BUG-3` (version in header
   acceptance) both move a check from where Core does it (cheap, early)
   to where blockbrew does it (expensive, late). The blockbrew layout
   prefers a thicker `ConnectBlock` over the Core `CheckBlock /
   ContextualCheckBlock / ConnectBlock` triad. Coincides with the
   "two-pipeline guard absent" pattern at the test-only sanity layer
   (`validationWorker`, `submitblock` RPC).

3. **"Signet wired through CLI/config but unimplemented in the
   validator":** `BUG-9` is the cleanest instance in the fleet of
   "operator-facing config knob present, deep validator support
   missing" (compare W134 fRelay, W136 feefilter "knob plumbed,
   sender never fires"). Strongest "advertise without honour" instance
   in W143.

4. **`MaxBlockSize` constant: half-dead.** S2 above — defined,
   surfaced via RPC, never enforced. Three-week half-life in the
   audit fleet ("defined for show" pattern, prior W128 / W135
   examples).

5. **Compounding "early-reject elided" stack:** BUG-1 + BUG-6 + BUG-7
   all elide Core's early-reject paths in favour of a single big
   `CalcBlockWeight + sigops-in-ConnectBlock` path. Functionally
   correct, performance-wise a measurable regression on pathological
   blocks. Compounds with the missing `block.fChecked` cache (S3).
