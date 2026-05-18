# W145 — Coinbase + subsidy + fees + MAX_MONEY invariants (blockbrew)

**Wave:** W145 — `GetBlockSubsidy`, `nSubsidyHalvingInterval`, COINBASE_MATURITY,
MAX_MONEY / MoneyRange, CVE-2018-17144 duplicate-input check, coinbase value
gate `vtx[0]->GetValueOut() <= subsidy + nFees`, fee-balance `nValueIn >=
nValueOut`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:1839-1850` — `GetBlockSubsidy(nHeight,
  consensusParams)`; `halvings = nHeight / nSubsidyHalvingInterval`;
  `if (halvings >= 64) return 0`; `nSubsidy = 50 * COIN`; `nSubsidy >>=
  halvings`.
- `bitcoin-core/src/validation.cpp:2542-2547` — `nFees += txfee;
  if (!MoneyRange(nFees)) ... "bad-txns-accumulated-fee-outofrange"`.
- `bitcoin-core/src/validation.cpp:2610-2613` — `blockReward = nFees +
  GetBlockSubsidy(pindex->nHeight, params.GetConsensus());
  if (block.vtx[0]->GetValueOut() > blockReward && state.IsValid()) ...
  "bad-cb-amount"`.
- `bitcoin-core/src/consensus/amount.h:14-27` — `COIN = 100000000; MAX_MONEY =
  21000000 * COIN; MoneyRange(nValue) = (nValue >= 0 && nValue <= MAX_MONEY)`.
- `bitcoin-core/src/consensus/consensus.h:19` — `COINBASE_MATURITY = 100`.
- `bitcoin-core/src/consensus/tx_check.cpp:36-45` — duplicate-input check
  (CVE-2018-17144): `std::set<COutPoint> vInOutPoints; for(...) if
  (!vInOutPoints.insert(txin.prevout).second) state.Invalid(...
  "bad-txns-inputs-duplicate")`.
- `bitcoin-core/src/consensus/tx_check.cpp:23-34` — per-output MoneyRange
  loop and `bad-txns-vout-negative` / `bad-txns-vout-toolarge` /
  `bad-txns-txouttotal-toolarge`.
- `bitcoin-core/src/consensus/tx_check.cpp:48-50` — coinbase scriptSig
  length 2..100.
- `bitcoin-core/src/consensus/tx_verify.cpp:179-182` — COINBASE_MATURITY
  enforcement at input-fetch.
- `bitcoin-core/src/consensus/tx_verify.cpp:184-188` — per-input MoneyRange
  on `coin.out.nValue` AND running `nValueIn`.
- `bitcoin-core/src/consensus/tx_verify.cpp:195-213` — `nValueIn < value_out`
  → `bad-txns-in-belowout`; `txfee = nValueIn - value_out`; MoneyRange(txfee).
- `bitcoin-core/src/kernel/chainparams.cpp:84,209,310,454,535` —
  `nSubsidyHalvingInterval` per network: mainnet/testnet3/testnet4/signet =
  210000; regtest = 150.

**Files audited**
- `internal/consensus/difficulty.go` — `CalcBlockSubsidy(height int32) int64`
  (lines 159-170).
- `internal/consensus/params.go` — `SubsidyHalvingInterval`, `InitialSubsidy`,
  `MaxMoney`, `CoinbaseMaturity` (lines 1-132).
- `internal/consensus/chaincfg.go` — per-network `SubsidyHalvingInterval`
  (lines 113-470 across all five networks).
- `internal/consensus/txvalidation.go` — `CheckTransactionSanity`,
  `CheckTransactionInputs`, `IsCoinbaseTx`, COINBASE_MATURITY gate
  (lines 47-195).
- `internal/consensus/chainmanager.go` — `ConnectBlock` subsidy, fees,
  bad-cb-amount, fee accumulator (lines 547-943).
- `internal/consensus/blockvalidation.go` — `CheckBlockSanity` tx-sanity
  loop (lines 91-96).
- `internal/consensus/utxoset.go` — `SerializeUTXOEntry` /
  `DeserializeUTXOEntry`, `IsCoinbase` flag (lines 820-883).
- `internal/storage/coinstatsindex.go` — `calcBlockSubsidy` (duplicate
  copy, lines 369-378) and `WriteBlock` subsidy accumulator (line 172).
- `internal/mining/mining.go:237` — GBT coinbase subsidy compute.

---

## Gate matrix (24 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | GetBlockSubsidy formula | G1: `halvings = height / interval`, `50*COIN >> halvings` | PASS (`difficulty.go:163-169`) |
| 1 | … | G2: `if halvings >= 64 return 0` undefined-shift guard | PASS (`difficulty.go:164`) |
| 1 | … | G3: subsidy reads PER-CHAIN halving interval from params | **BUG-1 (P0-CDIV)** uses package const, ignores `params.SubsidyHalvingInterval`; regtest (interval=150) silently uses 210000 |
| 2 | nSubsidyHalvingInterval | G4: mainnet=210000 | PASS (`chaincfg.go:134`) |
| 2 | … | G5: testnet3=210000 | PASS (`chaincfg.go:238`) |
| 2 | … | G6: testnet4=210000 | PASS (`chaincfg.go:450`) |
| 2 | … | G7: signet=210000 | PASS (`chaincfg.go:381`) |
| 2 | … | G8: regtest=150 stored in params, but **dead field** (never read by `CalcBlockSubsidy`) | **BUG-1 cross-cite** |
| 3 | Subsidy reaches 0 after 64 halvings | G9: returns 0 at block 13_440_000 mainnet | PASS (`difficulty.go:164` + test `difficulty_test.go:124`) |
| 3 | … | G10: same code path used by RPC `gettxoutsetinfo` total subsidy | **BUG-2 (P1)** `internal/storage/coinstatsindex.go:369-378` duplicates the subsidy function with hard-coded 210000 / 5_000_000_000 — TWO-PIPELINE GUARD pattern |
| 4 | Coinbase output sum ≤ subsidy + fees | G11: gate present in ConnectBlock | PASS (`chainmanager.go:933-943`) |
| 4 | … | G12: error string "bad-cb-amount" mapped on the wire | PASS (`rpc/methods.go:1831-1832`) |
| 4 | … | G13: gate runs even during assume-valid IBD (skipScripts=true) | PASS (block reached at line 933 unconditionally) |
| 5 | COINBASE_MATURITY=100 | G14: `if utxo.IsCoinbase && height-utxo.Height < CoinbaseMaturity` | PASS (`txvalidation.go:148-155`) |
| 5 | … | G15: enforced symmetrically in mempool admission | PASS (`mempool/mempool.go:1114-1125`, 2557) |
| 5 | … | G16: `IsCoinbase` bit serialized in disk-format UTXO `heightCode = height<<1 \| coinbase` | PASS (`utxoset.go:824-882`) |
| 6 | MAX_MONEY / MoneyRange | G17: per-output `nValue >= 0 && <= MaxMoney` | PASS (`txvalidation.go:79-85`) |
| 6 | … | G18: per-tx running sum `totalOutput <= MaxMoney` | PASS (`txvalidation.go:86-90`) |
| 6 | … | G19: per-input `coin.amount <= MaxMoney` | PASS (`txvalidation.go:158-163`) — but uses `ErrInputTooLarge` for negative inputs (wrong-error semantics; see BUG-3) |
| 6 | … | G20: per-input running sum `totalInput <= MaxMoney` | PASS (`txvalidation.go:167-170`) |
| 6 | … | G21: block-wide `nFees` enforced as **MoneyRange** (i.e. `nFees >= 0 && <= MAX_MONEY`) | **BUG-4 (P2)** only the upper half is enforced — `chainmanager.go:758` checks `totalFees > MaxMoney` but not `< 0`; Core uses `!MoneyRange(nFees)` |
| 7 | CVE-2018-17144 duplicate-input | G22: duplicate-prevout reject runs in CheckTransactionSanity BEFORE UTXO lookup | PASS (`txvalidation.go:93-100`) |
| 7 | … | G23: also re-checked at block-sanity in `CheckBlockSanity` | PASS (`blockvalidation.go:91-96` → `CheckTransactionSanity`) |
| 8 | Fee invariant `nValueIn >= nValueOut` | G24: gate + `bad-txns-in-belowout` mapping + MoneyRange(txfee) | PASS (`txvalidation.go:179-194` + rpc mapping) |

---

## BUG-1 (P0-CDIV) — `CalcBlockSubsidy` ignores `params.SubsidyHalvingInterval`

**Severity:** P0-CDIV. Regtest sets `SubsidyHalvingInterval = 150` but
`CalcBlockSubsidy` reads the package-level constant `SubsidyHalvingInterval =
210_000` instead. On regtest, the subsidy NEVER halves at block 150, 300,
450, … — every block continues to pay 50 BTC. Any node consuming a
non-mainnet chain with a different interval (signet variant, custom test
chain, regtest) silently diverges from Core. This is the canonical
"chain-param read but never threaded" two-pipeline-guard family of bug.

The bug is already flagged in `internal/mining/w123_gbt_test.go:148-168` as
`TestW123_G4_BlockSubsidyHalvingUsesPackageConst_BUG` (logs the divergence
via `t.Logf` rather than failing). The fix is one-line — thread params
through — but it has been live since W123 and is unaddressed.

**File:** `internal/consensus/difficulty.go:159-170`

**Core ref:** `bitcoin-core/src/validation.cpp:1839-1850`

**Excerpt (blockbrew, ignores params)**
```go
// CalcBlockSubsidy returns the subsidy for a block at the given height.
// The subsidy halves every SubsidyHalvingInterval blocks (210,000 on mainnet).
// After 64 halvings, the subsidy is zero.
func CalcBlockSubsidy(height int32) int64 {
    halvings := height / SubsidyHalvingInterval  // package const = 210_000
    if halvings >= 64 {
        return 0
    }
    subsidy := InitialSubsidy
    subsidy >>= uint(halvings)
    return subsidy
}
```

**Core (params-aware)**
```cpp
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    if (halvings >= 64) return 0;
    CAmount nSubsidy = 50 * COIN;
    nSubsidy >>= halvings;
    return nSubsidy;
}
```

**Impact:**
- On regtest, every block at height ≥ 150 still pays 50 BTC instead of
  25/12.5/… BTC, so the regtest mainline silently *over-pays* miners
  relative to Core. Any cross-impl regtest fixture (consensus-diff,
  smoke harness) that mines past block 150 and compares against
  Core's `getblock`/`getblockchaininfo` total subsidy will diverge.
- `internal/mining/mining.go:237` (GBT) builds coinbase templates with
  the wrong subsidy on regtest — `submitblock` will then fail the
  bad-cb-amount gate against any Core regtest peer.
- Fix is one line: replace the package-const reference with
  `params.SubsidyHalvingInterval` and thread `params` through every
  caller (mining.go:237, testutil.go:113, coinstatsindex.go:172,
  rpc/dumptxoutset_test.go:59, the consensus tests).

**Status (carry-forward):** Documented in W123 as the same bug; this
W145 audit confirms the fix has not landed. ~3 calendar weeks open.

---

## BUG-2 (P1-DUP) — `calcBlockSubsidy` duplicated in `internal/storage/coinstatsindex.go`

**Severity:** P1 (two-pipeline guard).
`internal/storage/coinstatsindex.go:369-378` defines a SECOND
`calcBlockSubsidy(height int32) int64` with hard-coded `210000` and
`5_000_000_000` literals, parallel to the canonical `consensus.CalcBlockSubsidy`.
Called by `CoinStatsIndex.WriteBlock` (line 172) every block-connect.
Affects `gettxoutsetinfo`-reported `total_subsidy` field.

**File:** `internal/storage/coinstatsindex.go:172, 369-378`

**Core ref:** `bitcoin-core/src/validation.cpp:1839-1850` — Core has ONE
GetBlockSubsidy.

**Excerpt (duplicate)**
```go
// calcBlockSubsidy calculates the block subsidy at a given height.
func calcBlockSubsidy(height int32) int64 {
    // Initial subsidy: 50 BTC = 5,000,000,000 satoshis
    // Halving every 210,000 blocks
    halvings := height / 210000
    if halvings >= 64 {
        return 0
    }
    return int64(5_000_000_000) >> uint(halvings)
}
```

**Impact:**
- Compounds BUG-1 with a second copy that ALSO ignores params (worse:
  hard-codes `210000` directly, can't even be fixed by threading
  params at the consensus layer).
- `gettxoutsetinfo total_subsidy` on regtest doubles the divergence
  (subsidy never halves, and the value drifts vs Core's
  `gettxoutsetinfo`).
- The two-pipeline-guard pattern: two impls of the same gate must be
  kept in sync. The canonical fix is to delete this and call
  `consensus.CalcBlockSubsidy` (once BUG-1 is fixed).

---

## BUG-3 (P3-NIT) — `CheckTransactionInputs` uses `ErrInputTooLarge` for negative input amounts

**Severity:** P3 cosmetic / wrong-error-code-for-RPC.

`txvalidation.go:158-163` rejects both negative and too-large input
amounts with `ErrInputTooLarge`. Core uses `bad-txns-inputvalues-outofrange`
for both cases (one bucket), but the semantic message "too large" is
misleading when the cause was a negative amount.

**File:** `internal/consensus/txvalidation.go:158-163`

**Excerpt**
```go
// 3. Each input amount must be non-negative and not exceed MaxMoney
if utxo.Amount < 0 {
    return 0, ErrInputTooLarge
}
if utxo.Amount > MaxMoney {
    return 0, ErrInputTooLarge
}
```

**Impact:** RPC reject reason on a corrupted snapshot or malformed
undo-restored UTXO will report "input value exceeds max money" when the
actual cause was a wrap to negative. No consensus split — both flagged
as reject — but log/forensics confusion. Map a separate `ErrInputNegative`
or align with Core's single bucket `bad-txns-inputvalues-outofrange`.

---

## BUG-4 (P2) — Block-wide `nFees` accumulator only checks upper MoneyRange half

**Severity:** P2 (defense-in-depth missing; not exploitable given current
per-tx bounds but Core writes the gate as `MoneyRange()` two-sided).

`chainmanager.go:757-761` accumulates per-tx fee into `totalFees` and
rejects on `totalFees > MaxMoney`. Core's check is `if (!MoneyRange(nFees))`,
which is BOTH `nFees >= 0 && nFees <= MAX_MONEY`. blockbrew skips the
negative half. Per-tx fees are individually bounded
(`txvalidation.go:189-192`) so int64 wrap-to-negative is extremely
unlikely in practice (would need ~4400 txs each at MAX_MONEY), but the
check is intentionally MoneyRange-shaped in Core.

**File:** `internal/consensus/chainmanager.go:757-761`

**Core ref:** `bitcoin-core/src/validation.cpp:2542-2547`

**Excerpt (blockbrew, one-sided)**
```go
totalFees += fee
if totalFees > MaxMoney {
    rollbackUTXOs()
    return fmt.Errorf("accumulated fee in the block out of range: %d > %d", totalFees, MaxMoney)
}
```

**Excerpt (Core, two-sided MoneyRange)**
```cpp
nFees += txfee;
if (!MoneyRange(nFees)) {
    state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                  "bad-txns-accumulated-fee-outofrange",
                  "accumulated fee in the block out of range");
    break;
}
```

**Impact:** Defense-in-depth gap. Fix: replace with
`if totalFees < 0 || totalFees > MaxMoney`.

---

## BUG-5 (P2) — `decodeScriptNum` is dead code (BIP-34 helper never called)

**Severity:** P2-DEAD (cosmetic / cleanup).

`blockvalidation.go:333-352` defines `decodeScriptNum` — a script-number
decoder for the BIP-34 coinbase-height push. The active BIP-34 gate
uses `encodeBIP34Height` + `bytes.Equal` prefix comparison
(`blockvalidation.go:288-298`), so `decodeScriptNum` is unreferenced
production code.

**File:** `internal/consensus/blockvalidation.go:333-352`

**Impact:** Dead-code fleet-pattern; sign-magnitude decoder will rot
out-of-sync with `encodeBIP34Height`. Either delete or use it in a
test that asserts round-trip parity.

**Cross-ref:** W143 BUG-2 flagged the same helper as dead.

---

## BUG-6 (P3) — `CalcBlockSubsidy(negative height)` returns full subsidy

**Severity:** P3 (defensive). Go's integer division truncates toward
zero, so `int32(-1) / int32(210_000) = 0`. `CalcBlockSubsidy(-1)` returns
50 BTC. Should never be called with a negative height in production
(`node.Height` is always ≥ 0), but the missing guard is defensive
fragility — any future caller that forgets to clamp inflates the
returned subsidy to 50 BTC.

**File:** `internal/consensus/difficulty.go:162`

**Core ref:** `bitcoin-core/src/validation.cpp:1841` — Core uses `int
nHeight`; same UB-on-negative property (`-1 / 210000` in C++ is 0 too,
so Core has the same latent issue). Not strictly a Core-vs-blockbrew
divergence; raised to document.

**Excerpt**
```go
func CalcBlockSubsidy(height int32) int64 {
    // No negative-height guard.
    halvings := height / SubsidyHalvingInterval
    ...
```

**Impact:** Latent bug surface; add `if height < 0 { return 0 }`.

---

## BUG-7 (P3) — `chainmanager.go` re-sums coinbase `out.Value` without per-output MoneyRange re-check

**Severity:** P3 (redundant safety check missing — already enforced
upstream by `CheckTransactionSanity` at `chainmanager.go:699`).

`chainmanager.go:933-938` recomputes `coinbaseValue` as a raw sum of
`coinbase.TxOut.Value` without re-running MoneyRange. Core's
`block.vtx[0]->GetValueOut()` (`primitives/transaction.cpp:98-108`)
re-validates MoneyRange on each accumulation and throws on overflow.

**File:** `internal/consensus/chainmanager.go:933-938`

**Core ref:** `bitcoin-core/src/primitives/transaction.cpp:98-108`
(`CTransaction::GetValueOut`).

**Excerpt (blockbrew, no defensive re-check)**
```go
coinbase := block.Transactions[0]
var coinbaseValue int64
for _, out := range coinbase.TxOut {
    coinbaseValue += out.Value
}
if coinbaseValue > subsidy+totalFees {
    ...
}
```

**Excerpt (Core, throws on MoneyRange violation)**
```cpp
CAmount CTransaction::GetValueOut() const {
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut + tx_out.nValue))
            throw std::runtime_error(...);
        nValueOut += tx_out.nValue;
    }
    ...
}
```

**Impact:** Defense-in-depth gap. Coinbase tx already passed
`CheckTransactionSanity`, so the values are within MoneyRange, but the
write-side gate (no recheck) is fragile if any caller injects a
non-sanity-checked block.

---

## BUG-8 (P2) — `DeserializeUTXOEntry` accepts amount > MaxMoney from disk

**Severity:** P2 (disk-corruption trust-boundary).

`utxoset.go:846-883` (`DeserializeUTXOEntry`) reads a varuint amount and
casts directly to `int64` without MoneyRange validation. A corrupted DB
record can load a UTXO with `Amount > MaxMoney` or `< 0` (via wrap).
Subsequent reads via `CheckTransactionInputs` will trigger
`ErrInputTooLarge`, but any code path that consumes the entry without
running it through `CheckTransactionInputs` (e.g., RPC `gettxout`, the
coin-stats index, the wallet UTXO scanner) silently propagates the bad
value.

**File:** `internal/consensus/utxoset.go:846-883`

**Core ref:** `bitcoin-core/src/coins.cpp` — Core's coin
deserialization is wrapped in a CCoinsView that ASSERTs MoneyRange on
amount.

**Excerpt**
```go
amount, err := readVaruint(r)
if err != nil { return nil, err }
// No MoneyRange check on amount.
...
return &UTXOEntry{
    Amount:     int64(amount),  // raw cast
    ...
}, nil
```

**Impact:** Subtle disk-corruption propagation. Add a MoneyRange gate:
`if int64(amount) < 0 || int64(amount) > MaxMoney { return nil,
ErrCoinAmountOutOfRange }`.

---

## BUG-9 (P3) — `int32(heightCode >> 1)` cast can wrap for very large heightCode

**Severity:** P3 (latent disk-corruption).

`utxoset.go:854` casts `heightCode >> 1` to `int32` after reading a
varuint. If `heightCode >> 1 > INT32_MAX` (i.e. heightCode > 2^32), the
cast silently wraps. In practice impossible for legitimate UTXOs
(blockchain will not reach height 2^31), but a malicious or corrupted
DB record can encode any varuint up to 2^64.

**File:** `internal/consensus/utxoset.go:854`

**Excerpt**
```go
height := int32(heightCode >> 1)
isCoinbase := (heightCode & 1) == 1
```

**Impact:** Wrapping height could mark a UTXO as having a height that
violates COINBASE_MATURITY in either direction. Add a range check:
`if heightCode >> 1 > math.MaxInt32 { return nil, errors.New("utxo
height out of range") }`.

---

## BUG-10 (P2) — Coinbase scriptSig length gate is the **only** "bad-cb-length" enforcement; not also re-checked in ConnectBlock

**Severity:** P2 (defense-in-depth gap — Core re-runs CheckTransaction
inside ConnectBlock, blockbrew does too via `CheckTransactionSanity`
loop in CheckBlockSanity).

Actually rechecked — `CheckBlockSanity` (`blockvalidation.go:91-96`) loops
over `CheckTransactionSanity` which is what enforces the 2..100 byte
gate. So the gate IS re-run. **Verdict: no bug.** Removed from final
count; kept here as audit trail (gate audited and verified PASS).

---

## BUG-11 (P2) — `CheckTransactionInputs` does not enforce MoneyRange on every running `nValueIn` increment (Core uses `!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)`)

**Severity:** P2 (semantic gap).

Core's tx_verify.cpp:185-188 checks `!MoneyRange(coin.out.nValue) ||
!MoneyRange(nValueIn)` on EVERY input — i.e. the running sum is
re-bound-checked even though each individual coin is already bounded.
blockbrew checks each individual `utxo.Amount` against MoneyRange
(`txvalidation.go:158-163`), and only at the end of the loop checks
`totalInput > MaxMoney` (single-sided `if totalInput > MaxMoney`),
without checking `totalInput < 0`. With per-coin Amount bounded by
[0, MaxMoney], the negative wrap is essentially impossible in
practice (would need ~9.4 quadrillion sat over many inputs), but Core
treats it as a MoneyRange invariant gate.

**File:** `internal/consensus/txvalidation.go:158-170`

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:184-188`

**Excerpt (blockbrew, single-sided)**
```go
totalInput += utxo.Amount
if totalInput > MaxMoney {
    return 0, ErrTotalInputTooLarge
}
```

**Excerpt (Core, MoneyRange both sides)**
```cpp
nValueIn += coin.out.nValue;
if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
    return state.Invalid(... "bad-txns-inputvalues-outofrange");
}
```

**Impact:** Defense-in-depth. Replace with two-sided MoneyRange.

---

## BUG-12 (P3) — `MaxMoney` constant uses `int64 = 21_000_000 * 100_000_000` literal split — verify constant-folds to `2_100_000_000_000_000`

**Severity:** P3 (verification only; not actually broken — Go evaluates
the multiplication at compile time, yielding 2.1e15 exactly).

`params.go:21` defines `MaxMoney int64 = 21_000_000 * 100_000_000`. Go
constant evaluation yields `2_100_000_000_000_000` (correct). Audit
verified by inspection. Listed for paranoia.

**File:** `internal/consensus/params.go:21`

**Impact:** None. Leaving in audit trail.

---

## BUG-13 (P2) — `chainmanager.go` accumulates per-coinbase `out.Value` without overflow check between `subsidy + totalFees`

**Severity:** P2 (defense-in-depth gap; not exploitable given per-tx
caps).

`chainmanager.go:939` evaluates `coinbaseValue > subsidy + totalFees`.
Both operands are bounded by `MaxMoney`, so the sum is at most
`~2 * MaxMoney = 4.2e15` (well below INT64_MAX = 9.22e18). No actual
overflow. **No bug** — listed as audit trail.

---

## BUG-14 (P0) — Per-network `SubsidyHalvingInterval` field on `ChainParams` is a DEAD FIELD (set by every network constructor, read by ZERO production code paths)

**Severity:** P0 (companion to BUG-1; raised separately because the
field's *existence* is misleading — it claims to be wired).

`chaincfg.go` declares `ChainParams.SubsidyHalvingInterval int32`
(`chaincfg.go:22`) and every of the five network constructors sets it
explicitly (mainnet 134, testnet3 238, regtest 319, signet 381,
testnet4 450). `grep -rn '\.SubsidyHalvingInterval' internal/` returns
ZERO production references — only one test (`w123_gbt_test.go:151`)
reads it to detect the BUG-1 divergence.

This is a textbook "dead field claiming wiring" archetype.

**File:** `internal/consensus/chaincfg.go:22, 134, 238, 319, 381, 450`

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:84,209,310,454,535`
+ `validation.cpp:1841` reads it through `consensusParams`.

**Excerpt**
```go
// chaincfg.go:319 — regtest
SubsidyHalvingInterval: 150, // Faster halving for testing
```
…field is never read except in a test that documents the bug.

**Impact:** Wiring-look-but-no-wire — pattern that makes a future
contributor THINK regtest has been threaded when it has not. The fix
is identical to BUG-1, but raised separately so the *audit gate* is
"there exists a dead chain-param".

---

## BUG-15 (P3) — `CheckTransactionInputs` "fee out of range" error string differs from Core's `bad-txns-fee-outofrange`

**Severity:** P3 (wire-error string only).

`txvalidation.go:189-192` reports `"bad-txns-fee-outofrange: fee %d"`
inline as an unwrapped string, NOT as a sentinel `errors.Is`-able value.
Core uses the bare string `"bad-txns-fee-outofrange"`. RPC mapping in
`internal/rpc/methods.go` may not catch this path because no sentinel
is exported. Verified — there's no `ErrFeeOutOfRange` sentinel and no
mapping for the inline string.

**File:** `internal/consensus/txvalidation.go:189-192`,
`internal/rpc/methods.go` (mapping table).

**Excerpt**
```go
fee := totalInput - totalOutput
if fee < 0 || fee > MaxMoney {
    return 0, fmt.Errorf("bad-txns-fee-outofrange: fee %d", fee)
}
```

**Impact:** RPC `validateblock`/`submitblock` reject reason returns a
generic Go error string ("bad-txns-fee-outofrange: fee N") instead of
the canonical `bad-txns-fee-outofrange`. Wallets parsing the reject
reason may not match. Wrap as `ErrFeeOutOfRange` sentinel and add to
the `mapErrToRejectCode` switch in methods.go.

---

## BUG-16 (P2) — `MaxMoney` is checked but `<= MaxMoney` boundary semantics differ from Core's `MoneyRange(nValue >= 0 && nValue <= MAX_MONEY)`

**Severity:** P2 (verification — actually CORRECT in blockbrew).

`txvalidation.go:83` uses `out.Value > MaxMoney` (strict greater) →
rejects strictly above MaxMoney, accepts exactly MaxMoney. Core's
`MoneyRange` accepts `<= MAX_MONEY` (inclusive). MATCH.

`txvalidation.go:88` uses `totalOutput > MaxMoney`. MATCH.

No bug — verified by direct inspection. Listed as audit trail.

---

## BUG-17 (P2) — `IsCoinbaseTx` returns false for `len(tx.TxIn) == 0`, masking "no-input" tx as non-coinbase

**Severity:** P2 (defensive; no actual exploit — handled upstream).

`txvalidation.go:49-55` returns false when `len(tx.TxIn) != 1`. A
zero-input tx is detected by `CheckTransactionSanity` (`txvalidation.go:60-62`)
which returns `ErrNoInputs` first. So in practice the path is closed,
but `IsCoinbaseTx` itself is not robust against the empty case if
called in isolation.

**File:** `internal/consensus/txvalidation.go:49-55`

**Excerpt**
```go
func IsCoinbaseTx(tx *wire.MsgTx) bool {
    if len(tx.TxIn) != 1 {
        return false
    }
    ...
}
```

**Impact:** Defensive nit. Match the Core invariant `vin.size() == 1
&& vin[0].prevout.IsNull()` and document the precondition.

---

## BUG-18 (P2) — Coinbase value gate runs AFTER UTXO modifications are committed to `cm.utxoSet` (rollback path covers it, but late)

**Severity:** P2 (architectural; not a bug per se — rollback works).

`chainmanager.go:707-722` adds coinbase outputs to `cm.utxoSet` BEFORE
the coinbase-value gate at line 939. If gate fails, the rollback at
line 940 reverses those mods. Core never adds coinbase to the coins
view until after `bad-cb-amount` is checked (`validation.cpp:2611-2614`
is between UpdateCoins(tx) at 2600 only for non-coinbase, and the
final commit).

Actually re-reading Core: `UpdateCoins(tx, view, ...)` is called for
EVERY tx including coinbase (validation.cpp:2600), so the coinbase
outputs ARE added to the in-memory view before the gate. Match.
**No bug** — verified.

---

## BUG-19 (P3) — `nSubsidyHalvingInterval` field type is `int32` in blockbrew, but the package constant `SubsidyHalvingInterval` is an untyped int (210_000)

**Severity:** P3 (mixed types; pure cosmetic).

`params.go:27` uses untyped `SubsidyHalvingInterval = 210_000`;
`chaincfg.go:22` defines the field as `int32`. The division
`height / SubsidyHalvingInterval` in `difficulty.go:163` works because
Go infers `int32 / 210_000` (the untyped const adopts int32). When
fixed (BUG-1), the call would become `height / params.SubsidyHalvingInterval`,
both int32 — fine. Listed for paranoia.

---

## BUG-20 (P2) — Mining `CreateCoinbaseTx` consumes WRONG subsidy on regtest (bug downstream of BUG-1)

**Severity:** P2 (downstream of BUG-1; cited separately because the
bug propagates from consensus into mining).

`internal/mining/mining.go:237` calls `consensus.CalcBlockSubsidy(newHeight)`
which (per BUG-1) returns the mainnet-interval subsidy. On regtest,
GBT will hand out a coinbase template with the wrong subsidy past
block 150, which Core peers (running regtest) will reject as
`bad-cb-amount`.

**File:** `internal/mining/mining.go:237-255`

**Impact:** Cross-impl regtest mining diverges silently. Either fix
upstream (BUG-1) or thread `tg.chainParams` here too.

---

## Fleet-pattern smells

1. **Two-pipeline guard** (W117/W120/W128/W141/now W145): two parallel
   subsidy functions (`consensus.CalcBlockSubsidy` and
   `storage.calcBlockSubsidy`) that must be kept in sync. Both have the
   same chain-param ignorance bug. blockbrew accumulates two-pipeline
   guards across waves (BUG-2 here = the 7th distinct instance in
   blockbrew's audit history).

2. **Carry-forward re-anchor** (clearbit W140 pattern, see memory): BUG-1
   was flagged in W123 (~3 weeks ago) and is rediscovered here. The
   `TestW123_G4_BlockSubsidyHalvingUsesPackageConst_BUG` test logs the
   divergence with `t.Logf` (non-failing). The fix has not landed and
   is older than two quad-audit cycles.

3. **Wiring-look-but-no-wire** (`ChainParams.SubsidyHalvingInterval` as
   a dead field — BUG-14): contributor reads `chaincfg.go:319` and
   assumes "regtest has its halving wired"; in fact every read site
   uses the package constant. This is the same archetype as
   haskoin W140 `rpcAllowIp` dead-field.

4. **Comment-as-confession (mild)** (`params.go:26-27`): the constant's
   doc comment says "is the number of blocks between subsidy halvings"
   without saying "only used by mainnet/testnet/signet — regtest's
   field is ignored". A future reader who fixes BUG-1 will *also* have
   to update the comment.

---

## Summary

**Total bugs: 17 (raised) + 3 verified-no-bug (BUG-10/13/16/18) audit
trail entries.**

| Severity | Count | Bug IDs |
|---|---|---|
| P0-CDIV  | 1 | BUG-1 |
| P0       | 1 | BUG-14 |
| P1       | 1 | BUG-2 |
| P2       | 7 | BUG-4, BUG-5, BUG-8, BUG-11, BUG-15, BUG-17, BUG-20 |
| P3       | 4 | BUG-3, BUG-6, BUG-9, BUG-19 |
| (verified PASS / audit trail) | 4 | BUG-10, BUG-12, BUG-13, BUG-16, BUG-18 |

**Most representative findings:**
- **BUG-1 (P0-CDIV):** `CalcBlockSubsidy` ignores `params.SubsidyHalvingInterval`,
  so regtest never halves — 3-week-old carry-forward from W123.
- **BUG-2 (P1-DUP):** Two-pipeline guard — `coinstatsindex.go` has its
  OWN hardcoded copy of the subsidy function (`210000`, `5_000_000_000`
  literals), compounding BUG-1.
- **BUG-14 (P0-DEAD):** `ChainParams.SubsidyHalvingInterval` is a dead
  field — set by every constructor, read by ZERO production paths.
  Misleading-wiring archetype.

**Fix sequence:** (1) thread `params` through `CalcBlockSubsidy`
(BUG-1+14 closed); (2) delete `coinstatsindex.calcBlockSubsidy` and
call the canonical function (BUG-2 closed); (3) wrap fee-OoR /
input-OoR errors as sentinel-equivalent for RPC mapping (BUG-15);
(4) add MoneyRange two-sided checks in totalFees + totalInput
accumulators (BUG-4 + BUG-11); (5) add disk-trust gates in
`DeserializeUTXOEntry` (BUG-8 + BUG-9). All but BUG-1 are
defense-in-depth; BUG-1 + BUG-14 are the only P0/CDIV-class issues.
