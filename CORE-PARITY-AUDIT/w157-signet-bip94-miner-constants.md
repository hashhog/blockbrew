# W157 — Signet block solution + BIP-94 timewarp + miner-side header constants (blockbrew)

**Wave:** W157 — `CheckSignetBlockSolution`, `SignetTxs::Create`,
`FetchAndClearCommitmentSection`, `SIGNET_HEADER = {0xec, 0xc7, 0xda, 0xa2}`,
`signet_challenge`, `signet_blocks`, signet network magic derived from
`sha256d(signet_challenge)[:4]`, `BLOCK_SCRIPT_VERIFY_FLAGS =
P2SH|WITNESS|DERSIG|NULLDUMMY`, `-signetchallenge` CLI override,
`MAX_TIMEWARP = 600`, `consensus.enforce_BIP94`, BIP-94
"time-timewarp-attack" reject at retarget boundary (validation.cpp:4097-4104),
miner-side `GetMinimumTime` always-on at retarget boundary on ALL networks
(miner.cpp:36-47), `UpdateTime` re-emits `GetNextWorkRequired` after
testnet min-diff bumps, `GenerateCoinbaseCommitment` (BIP-141 0xaa21a9ed
prefix), `ComputeBlockVersion` (BIP-9 versionbits), `nBits` compact
encoding, regtest opts.enforce_bip94 CLI plumbing.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/signet.h:21` — `bool CheckSignetBlockSolution(const
  CBlock& block, const Consensus::Params& consensusParams)`.
- `bitcoin-core/src/signet.cpp:28` — `static constexpr uint8_t
  SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};` (the 4-byte
  signet-solution prefix that lives inside the coinbase witness commitment).
- `bitcoin-core/src/signet.cpp:30` — `BLOCK_SCRIPT_VERIFY_FLAGS = P2SH |
  WITNESS | DERSIG | NULLDUMMY` (4-flag script-verify set used by
  signet solution validation).
- `bitcoin-core/src/signet.cpp:32-57` — `FetchAndClearCommitmentSection`
  (extracts the signet-solution suffix after the 4-byte header from the
  coinbase OP_RETURN witness commitment script).
- `bitcoin-core/src/signet.cpp:59-68` — `ComputeModifiedMerkleRoot`
  (re-derives the merkle root after the signet-solution bytes have been
  redacted from the coinbase scriptPubKey).
- `bitcoin-core/src/signet.cpp:70-123` — `SignetTxs::Create`: builds
  the `to_spend` + `to_sign` synthetic txs that commit to the modified
  merkle root + block.nVersion + hashPrevBlock + nTime.
- `bitcoin-core/src/signet.cpp:126-153` — `CheckSignetBlockSolution`:
  genesis is always valid; otherwise builds the synthetic tx pair and
  runs `VerifyScript(...BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)` against
  the signet_challenge.
- `bitcoin-core/src/consensus/params.h:121` — `bool enforce_BIP94;`
  per-chain consensus parameter (Core sets TRUE only for testnet4 and
  for regtest when `-enforce_bip94=1`; FALSE for mainnet/testnet3/signet).
- `bitcoin-core/src/consensus/params.h:139-140` — `bool
  signet_blocks{false}; std::vector<uint8_t> signet_challenge;` —
  the signet-specific consensus fields.
- `bitcoin-core/src/consensus/consensus.h:35` — `static constexpr
  int64_t MAX_TIMEWARP = 600;` (BIP-94 600-second clamp).
- `bitcoin-core/src/pow.cpp:14-48` — `GetNextWorkRequired`:
  off-retarget returns `pindexLast->nBits` (or the testnet min-diff
  walk-back); at retarget boundary calls `CalculateNextWorkRequired`.
- `bitcoin-core/src/pow.cpp:50-85` — `CalculateNextWorkRequired`: at
  retarget, when `enforce_BIP94 == true` uses the FIRST block of the
  period as the difficulty base; otherwise uses `pindexLast->nBits`.
- `bitcoin-core/src/validation.cpp:4097-4104` — consensus-side BIP-94
  "time-timewarp-attack" reject: when `enforce_BIP94 == true`, at every
  retarget boundary (`nHeight % DifficultyAdjustmentInterval() == 0`),
  reject any block whose timestamp is more than `MAX_TIMEWARP=600` s
  earlier than the immediately preceding block's timestamp.
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime`: **on
  ALL networks**, regardless of `enforce_BIP94`, the miner-side
  `min_time` is clamped to `max(parent.MTP + 1, parent.nTime -
  MAX_TIMEWARP)` at retarget boundaries. Core comment: "Account for
  BIP94 timewarp rule on all networks. This makes future activation safer."
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime`: `nNewTime =
  max(GetMinimumTime(...), NodeClock::now())`; recomputes `nBits` after
  bumping time when `fPowAllowMinDifficultyBlocks` is set.
- `bitcoin-core/src/kernel/chainparams.cpp:411-521` — `SigNetParams`
  ctor: when `-signetchallenge` is not set, uses the default mainnet-signet
  challenge `0x512103ad5e0…52ae` (1-of-2 multisig of two Bitcoin Core
  contributors); when set, the operator can run a custom signet network.
  In either case `consensus.signet_blocks = true` and
  `consensus.signet_challenge.assign(bin.begin(), bin.end())`.
- `bitcoin-core/src/kernel/chainparams.cpp:476-479` — signet
  `pchMessageStart` (network magic) is derived dynamically:
  `HashWriter h; h << consensus.signet_challenge; uint256 hash =
  h.GetHash(); std::copy_n(hash.begin(), 4, pchMessageStart.begin());`.
  Hard-coding the magic is correct only for the default signet challenge.
- `bitcoin-core/src/kernel/chainparams.cpp:454-466` — signet
  `nSubsidyHalvingInterval = 210000`, `BIP34Height/BIP65/BIP66/CSV/Segwit
  = 1`, `signet_blocks = true`, `enforce_BIP94 = false`,
  `fPowAllowMinDifficultyBlocks = false`, `powLimit =
  0x00000377ae000000…`.
- `bitcoin-core/src/init.cpp` — `-signetchallenge=<hex>`,
  `-signetseednode=<host>` CLI flags (only meaningful when
  `-chain=signet`).

**Files audited**
- `internal/consensus/chaincfg.go:359-425` — `SignetParams()` (the
  entire signet chain-params definition, including network magic).
- `internal/consensus/chaincfg.go:1-100` — `ChainParams` struct shape
  (note absence of `SignetBlocks` and `SignetChallenge` fields, and the
  `EnforceBIP94 bool` field that gates both validation and miner sides).
- `internal/consensus/params.go:47-52` — `MaxTimewarp int64 = 600`.
- `internal/consensus/genesis.go:116-140` — `SignetGenesisBlock` /
  `signetGenesisCoinbaseTx` (genesis hash
  `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6`).
- `internal/consensus/headerindex.go:420-449` — header-acceptance
  BIP-94 timewarp check (`EnforceBIP94`-gated).
- `internal/consensus/blockvalidation.go:60-205` — `CheckBlockSanity`
  + `CheckBlockContext` (no signet-specific gates here).
- `internal/consensus/chainmanager.go:442-1015` — `ConnectBlock`
  (no signet solution verification anywhere).
- `internal/consensus/difficulty.go:159-353` — `CalcBlockSubsidy`
  (210k hardcoded, params-blind), `GetNextWorkRequired`,
  `CalculateNextWorkRequired` (BIP-94 retarget-base correctly
  `EnforceBIP94`-gated).
- `internal/mining/mining.go:36-294` — `GenerateTemplate`,
  `BlockTemplate.MinTime` derivation (BIP-94 timewarp on the miner side
  is gated by `EnforceBIP94`, see BUG-6).
- `internal/mining/mining.go:585-690` — `BlockMiner.GenerateBlocks` /
  `GenerateBlock`.
- `internal/rpc/methods.go:1660-1794` — `handleGetBlockTemplate`
  (W155 BUG-1 + BUG-7 carry-forwards, see BUG-15 + BUG-13 below).
- `internal/rpc/methods.go:3148-3360` — `handleGenerateBlock`
  (W154 BUG-2 + W155 BUG-25 carry-forward, see BUG-14 below).
- `internal/rpc/extra_methods.go:664-714` — `handleGetMiningInfo`.
- `internal/rpc/types.go:424-443` — `MiningInfo` JSON shape.
- `internal/p2p/message.go:28-34` — network-magic constants.
- `cmd/blockbrew/main.go:425-435, 580-643, 1779-1780` — signet network
  routing (chain params, default port, RPC port, P2P magic).

---

## Gate matrix (30 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | CheckSignetBlockSolution | G1: `CheckSignetBlockSolution(block, consensusParams)` exists | **BUG-1 (P0-CONS, carry-forward W143 BUG-9, ~3 wk open)** — function does not exist anywhere in the codebase; `grep -rn 'CheckSignet\|SignetTxs\|SIGNET_HEADER\|FetchAndClearCommitmentSection' internal/ cmd/` returns ZERO production-code matches. Signet chain accepts any block whose PoW meets the trivial signet target → forks off Core at block 1 (h=1 is signed) |
| 1 | … | G2: `SIGNET_HEADER = {0xec, 0xc7, 0xda, 0xa2}` constant defined | **BUG-1 cross-cite** — constant absent |
| 1 | … | G3: `FetchAndClearCommitmentSection` extracts signet-solution suffix from coinbase OP_RETURN | **BUG-1 cross-cite** — helper absent |
| 1 | … | G4: `SignetTxs::Create` builds synthetic `to_spend` / `to_sign` tx pair | **BUG-1 cross-cite** — helper absent |
| 1 | … | G5: `ComputeModifiedMerkleRoot` (merkle root after redacting signet-solution bytes) | **BUG-1 cross-cite** — helper absent |
| 1 | … | G6: `VerifyScript(..., P2SH \| WITNESS \| DERSIG \| NULLDUMMY, sigcheck)` runs against the signet_challenge | **BUG-1 cross-cite** — no verification call exists |
| 1 | … | G7: genesis bypass (`if (block.GetHash() == hashGenesisBlock) return true;`) | **BUG-1 cross-cite** — code that would gate is absent |
| 2 | signet_challenge plumbed in ChainParams | G8: `ChainParams.SignetChallenge []byte` field exists | **BUG-2 (P0-CDIV, carry-forward W155 BUG-7)** — `ChainParams` (chaincfg.go:10-71) has NO `SignetChallenge` field, NO `SignetBlocks bool` field. Without this field, even if `CheckSignetBlockSolution` were implemented it would have nothing to verify against |
| 2 | … | G9: signet_challenge defaulted to Core's default-signet challenge `0x512103ad5e0…52ae` | **BUG-2 cross-cite** — no default value because no field |
| 2 | … | G10: `-signetchallenge=<hex>` CLI flag exposed for custom signet networks | **BUG-3 (P1)** — `cmd/blockbrew/main.go:445-496` defines NO `-signetchallenge` flag. Operators cannot run a custom signet (this is the entire point of signet — pluggable challenges for test networks) |
| 3 | signet network magic derived from challenge | G11: pchMessageStart derived as `sha256d(signet_challenge)[:4]` at runtime | **BUG-4 (P1)** — `internal/p2p/message.go:33` hard-codes `SignetMagic uint32 = 0x40CF030A` (the default-signet magic). Setting a custom `-signetchallenge` in Core changes the network magic; blockbrew would advertise the wrong magic and immediately disconnect from any custom-signet peer. Compounds with BUG-3 |
| 4 | BIP-94 consensus-side timewarp (testnet4 only) | G12: `if (consensusParams.enforce_BIP94 && nHeight % DifficultyAdjustmentInterval() == 0) reject if block.nTime < parent.nTime - MAX_TIMEWARP` | PASS (`headerindex.go:435-439`) — gated by `EnforceBIP94`, matches Core `validation.cpp:4097-4104` |
| 4 | … | G13: reject string "time-timewarp-attack" preserved | PARTIAL — `ErrTimeWarpAttack` is a free-form English sentinel ("block timestamp violates BIP-94 timewarp rule at difficulty adjustment boundary"); the BIP22 mapping in `bip22ResultString` (rpc/methods.go:1800-1887) has no entry for `ErrTimeWarpAttack`, so submitblock returns `"rejected"` (catch-all) instead of `"time-timewarp-attack"`. **BUG-5 (P1)** |
| 5 | BIP-94 miner-side GetMinimumTime (ALL networks) | G14: `min_time = max(MTP+1, prev.nTime - MAX_TIMEWARP)` at retarget boundaries on EVERY network, regardless of enforce_BIP94 | **BUG-6 (P0-CDIV)** — `mining.go:273` and `methods.go:1781` both gate the BIP-94 clamp on `tg.chainParams.EnforceBIP94 && newHeight%DifficultyAdjInterval == 0`. Core's `GetMinimumTime` (`miner.cpp:36-47`) has NO `enforce_BIP94` gate at all — the clamp is unconditional on every network. Core's inline comment is verbatim: "Account for BIP94 timewarp rule on all networks. This makes future activation safer". On mainnet/testnet3/signet the blockbrew template's `mintime` is `MTP+1`, while Core's may be larger (`prev.nTime - 600`). A pool that hands the template directly to a miner who uses `curtime` < blockbrew-mintime is fine, but a pool that pushes `mintime` to a hash-rate stratum and the stratum reports back `nTime = mintime` will produce a block Core would have rejected once BIP-94 is enabled on mainnet |
| 5 | … | G15: UpdateTime re-runs `GetNextWorkRequired` after timestamp bump on testnet `fPowAllowMinDifficultyBlocks` | PARTIAL — mining.go does call `GetNextWorkRequired(... header.Timestamp ...)` once after MTP-bump (line 181-187), but does NOT re-run it after a hypothetical future `UpdateTime` call. blockbrew has no `UpdateTime` function. The single-pass derivation works in practice because the same `header.Timestamp` is used throughout, but the architecture is one phase shy of Core. **BUG-7 (P2)** |
| 6 | signet difficulty adjustment | G16: signet uses standard 2016-block retarget (no fPowAllowMinDifficultyBlocks) | PASS — `chaincfg.go:393-394` sets `MinDiffReductionTime: false, PowNoRetargeting: false`, matches Core's signet `fPowAllowMinDifficultyBlocks=false, fPowNoRetargeting=false` |
| 6 | … | G17: signet uses signet powLimit `0x00000377ae000000…` | PASS — `chaincfg.go:376` sets `PowLimitBits: 0x1e0377ae` (the compact-form encoding of Core's signet powLimit), but **BUG-8 (P1)** — `chaincfg.go:377` sets `PowLimit: mainnetPowLimit` (the LIMIT, not the signet-specific one). Compact-form decode would give the correct target, but downstream comparisons that use `params.PowLimit` directly (e.g. as upper bound on accepted bits, `difficulty.go:348`) treat signet as having mainnet's powLimit `00000000ffff…` — much looser than signet's actual `00000377ae…`. A maliciously-crafted header with bits between signet-pow-limit and mainnet-pow-limit would pass CheckProofOfWork and be added to the header index |
| 7 | signet halving interval | G18: `nSubsidyHalvingInterval = 210000` for signet | PARTIAL — `chaincfg.go:381` sets `SubsidyHalvingInterval: SubsidyHalvingInterval` (the 210000 package constant), but **BUG-9 (P0-CDIV, carry-forward W145 BUG-1, ~3 wk open)** — `consensus.CalcBlockSubsidy(height)` at `difficulty.go:162` ignores `params.SubsidyHalvingInterval` entirely; it reads the package-level `SubsidyHalvingInterval = 210000`. For signet/mainnet this is invisible (same number), but the API contract is broken and regtest mining is busted past block 150 (chainparams says halving=150, code keeps paying 50 BTC). Direct re-confirmation of W145 BUG-1, BUG-14, W154 BUG-17 — STILL OPEN |
| 8 | signet genesis | G19: signet genesis hash `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6` | PASS — `genesis.go:116-140` produces a header that hashes to the correct signet genesis (verified mainnet handshake), Timestamp 1598918400 + Nonce 52613770 + Bits 0x1e0377ae |
| 8 | … | G20: signet genesis coinbase uses the mainnet `genesisCoinbaseTx` (`The Times 03/Jan/2009 …`) | PASS but **BUG-10 (P2)** — `genesis.go:117-119` literally `return genesisCoinbaseTx()` (the mainnet coinbase). Core's signet genesis uses the SAME coinbase by design (BIP325 §3) so the byte sequence happens to match, but the inline comment "creates the coinbase transaction for signet genesis" is misleading — there is no signet-specific coinbase, the same tx is shared by all four chains. Comment-as-confession candidate |
| 9 | signet network routing | G21: signet `-network=signet` → `SignetParams()` | PASS (`main.go:428-429`, `1779-1780`) |
| 9 | … | G22: signet default port 38333 + RPC port 38332 | PASS (`main.go:588-589, 605-606`) |
| 9 | … | G23: signet network magic dispatch | PASS (`main.go:622-623`) but cross-cite **BUG-4** for custom-signet |
| 10 | signet GBT response shape | G24: `signet_challenge` field emitted by getblocktemplate when chain is signet | **BUG-11 (P1-CDIV, carry-forward W155 BUG-7)** — `BlockTemplateResult` (rpc/types.go:452-…) has NO `SignetChallenge` field. Even with the placeholder `gbtRules = append(gbtRules, "!signet")` (methods.go:1749), miners that ask for a signet template get no challenge to sign, no way to compute the solution |
| 10 | … | G25: `!signet` in `rules[]` array on signet | PASS (`methods.go:1748-1751`) |
| 10 | … | G26: GBT enforces that client included `"signet"` in `setClientRules` on signet chains | **BUG-12 (P0-CDIV, carry-forward W155 BUG-2, W108 G4)** — handleGetBlockTemplate doesn't parse `params` at all (W155 BUG-1), so the client-rules check cannot run; Core `mining.cpp:850-851` throws an RPCError. blockbrew silently emits a signet template that a Core-aware miner would reject |
| 10 | … | G27: getmininginfo emits `signet_challenge` field on signet | **BUG-13 (P1)** — `MiningInfo` struct (`rpc/types.go:432-443`) has no `SignetChallenge` field. `handleGetMiningInfo` (extra_methods.go:664-714) populates no signet-specific data. Cross-cite W123 BUG-4 |
| 11 | regtest / generateblock interaction | G28: regtest `-enforce_bip94=1` CLI flag plumbs through to `params.EnforceBIP94` | **BUG-14 (P2)** — Core regtest exposes the opt via `RegTestOptions::enforce_bip94` (`chainparams.cpp:547`). blockbrew has no equivalent flag; regtest `EnforceBIP94` is hard-coded false (`chaincfg.go:332` does not set the field). Regtest scenarios that exercise the BIP-94 timewarp gate (e.g. consensus-diff / signet-handshake regression) cannot be constructed |
| 11 | … | G29: `handleGenerateBlock` recomputes coinbase value after tx-list replacement | **BUG-15 (P0, carry-forward W154 BUG-2 + W155 BUG-25)** — `methods.go:3248-3252` reuses the coinbase from the mempool-driven template without adjusting `subsidy + fees` to the actual fees of the supplied txs. Produces `bad-cb-amount` for any non-empty tx-list passed to generateblock |
| 11 | … | G30: `handleGenerateBlock` for signet REGENERATES the witness commitment but does NOT add a signet solution to it | **BUG-16 (P1, partially blocked by BUG-1)** — even with BUG-1 fixed, the generateblock path at `methods.go:3261-3271` would need to RE-RUN signet-solution computation after the tx-list edit. Currently it only recomputes the witness commitment magic. Same shape in `BlockMiner.GenerateBlock` (`mining.go:644-657`) |

---

## BUG-1 (P0-CONS, carry-forward W143 BUG-9 ~3 weeks open) — `CheckSignetBlockSolution` is entirely absent — signet chain split at block 1

**Severity:** P0-CONS (consensus-divergence). Direct verification of the
finding originally landed in W143 BUG-9 on 2026-04-29 and re-confirmed
in W155 BUG-25 indirectly. **STILL OPEN as of 2026-05-18.**

`grep -rn 'CheckSignet\|SignetTxs\|SIGNET_HEADER\|FetchAndClearCommitmentSection\|SignetChallenge\|signetChallenge\|signet_challenge\|signet_blocks' internal/ cmd/`
returns ZERO production-code matches in blockbrew. The only matches are
inside test files (`internal/mining/w108_gbt_test.go:110-117`,
`internal/mining/w123_gbt_test.go:23, 290-298`) — both of which
explicitly document the gap as a known BUG.

Bitcoin Core's `CheckSignetBlockSolution` (`signet.cpp:126-153`) is
invoked from `validation.cpp::CheckBlock` (search for the signet
validation hook) — every non-genesis signet block must carry a valid
signet solution embedded in the coinbase OP_RETURN witness commitment,
prefixed with the 4-byte `SIGNET_HEADER = {0xec, 0xc7, 0xda, 0xa2}`,
followed by the scriptSig + scriptWitness that successfully spends the
synthetic `to_spend` output paying to `signet_challenge`. Without the
solution check, the chain reduces to a low-difficulty PoW chain that
ANY actor can mine.

blockbrew's `ConnectBlock` (`chainmanager.go:442-1015`) runs:
- `CheckBlockSanity` (PoW, timestamp, coinbase, merkle, weight),
- `CheckBlockContext` (BIP-34/65/66, witness commitment magic, IsFinalTx),
- `CheckBIP30`,
- the two-pass tx validation loop (CheckTransactionInputs, BIP-68,
  script validation).

There is NO signet-specific gate at any point. Signet's PoW limit
(`0x1e0377ae` ≈ trivial CPU difficulty) means ANY actor can mine blocks
that pass blockbrew's validation but Core would reject.

**Failure surface:**
- A blockbrew node on `-network=signet` immediately accepts the first
  non-genesis block mined by ANYONE who can solve the trivial signet
  PoW (effectively any CPU in seconds). It does NOT require the
  signet-challenge signature.
- Honest signet miners construct blocks with the signed signet solution
  in the coinbase OP_RETURN; blockbrew accepts them (they pass PoW)
  AND it accepts impostor blocks (also pass PoW). Whichever arrives
  first wins.
- blockbrew's tip will rapidly diverge from Core's signet tip; the
  divergence is permanent because both chains satisfy PoW.

**File:** absence across `internal/consensus/` and `internal/`.
Specifically `chainmanager.go::ConnectBlock` (line 442-1015) has no
signet-solution gate.

**Core ref:** `bitcoin-core/src/signet.cpp:126-153` (CheckSignetBlockSolution).

**Excerpt (Core, the missing function)**
```cpp
bool CheckSignetBlockSolution(const CBlock& block, const Consensus::Params& consensusParams)
{
    if (block.GetHash() == consensusParams.hashGenesisBlock) return true;
    const CScript challenge(consensusParams.signet_challenge.begin(),
                            consensusParams.signet_challenge.end());
    const std::optional<SignetTxs> signet_txs = SignetTxs::Create(block, challenge);
    if (!signet_txs) return false;
    // ... build PrecomputedTransactionData, TransactionSignatureChecker ...
    if (!VerifyScript(scriptSig, signet_txs->m_to_spend.vout[0].scriptPubKey,
                      &witness, BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)) {
        return false;
    }
    return true;
}
```

**Impact:**
- blockbrew on signet is **effectively a separate, trivially-mineable
  chain** that shares only the genesis with Core's signet.
- Any consensus-diff harness pointed at blockbrew vs Core on signet
  diverges at h=1.
- This is a textbook P0-CONS finding: SAME network, SAME PoW limit,
  DIFFERENT chain.

---

## BUG-2 (P0-CDIV, carry-forward W155 BUG-7) — `ChainParams` has no `SignetChallenge` or `SignetBlocks` fields

**Severity:** P0-CDIV. Core's `Consensus::Params` (`consensus/params.h:139-140`)
defines:

```cpp
bool signet_blocks{false};
std::vector<uint8_t> signet_challenge;
```

These are the two consensus parameters that turn an arbitrary CBlock
into a SIGNET-validated block. `signet_blocks` is the boolean toggle;
`signet_challenge` is the bytes of the script that the signet-solution
must satisfy.

blockbrew's `ChainParams` (`chaincfg.go:10-71`) defines neither field.
Even if `CheckSignetBlockSolution` (BUG-1) were implemented tomorrow,
the call would have nothing to verify the solution against — no
challenge bytes to thread into the VerifyScript call. The structural
gap is one level lower than BUG-1 and is the architectural pre-requisite
for any fix.

**File:** `internal/consensus/chaincfg.go:10-71` (ChainParams struct).
`SignetParams()` (line 359-425) sets every field that exists but cannot
set fields that don't exist.

**Core ref:** `bitcoin-core/src/consensus/params.h:135-140`.

**Impact:**
- BUG-1's fix is gated on this field being added first.
- Without the field, GBT cannot emit `signet_challenge` (BUG-11),
  getmininginfo cannot emit it (BUG-13), and a custom-signet operator
  has no in-band way to express the challenge.

---

## BUG-3 (P1) — `-signetchallenge` CLI flag does not exist

**Severity:** P1. Core's `init.cpp` defines `-signetchallenge=<hex>`
which, in `SigNetParams` ctor (`chainparams.cpp:417-446`), either
defaults to the Core-built-in challenge for the public signet (a
1-of-2 multisig of Anthony Towns + Karl-Johan Alm) when unset, or
constructs a custom-signet chain from the hex blob when set. The
custom-signet path is the **entire reason** signet exists: pluggable
proof-of-work-less test networks.

blockbrew's `parseFlags` (`cmd/blockbrew/main.go:445-496`) defines
NO `-signetchallenge` flag. The operator cannot run a custom signet.
Compounds with BUG-2 (no field to plumb the value into) and BUG-4
(network magic hard-coded to default-signet).

**File:** `cmd/blockbrew/main.go:445-496` (parseFlags).

**Core ref:** `bitcoin-core/src/init.cpp` (`-signetchallenge` flag).

**Impact:**
- blockbrew cannot participate in any custom signet test network
  (the canonical use case for signet in test infrastructure).
- For the default signet, the gap is invisible until BUG-1/BUG-2 are
  closed — once they are, custom-signet support is the natural next
  fix.

---

## BUG-4 (P1) — Signet network magic is hard-coded; Core derives it from the challenge at runtime

**Severity:** P1. Core derives the signet `pchMessageStart` (network
magic) dynamically at startup (`chainparams.cpp:475-479`):

```cpp
HashWriter h{};
h << consensus.signet_challenge;
uint256 hash = h.GetHash();
std::copy_n(hash.begin(), 4, pchMessageStart.begin());
```

For the default-signet challenge, this produces `0x0a 0x03 0xcf 0x40`
(blockbrew's hard-coded `[]byte{0x0a, 0x03, 0xcf, 0x40}` and the LE-
encoded `SignetMagic uint32 = 0x40CF030A`). For a custom-signet
challenge, the magic is different — derived from sha256d of that
challenge.

blockbrew's `internal/p2p/message.go:33` hard-codes
`SignetMagic uint32 = 0x40CF030A` and `chaincfg.go:414` sets
`NetworkMagic: [4]byte{0x0a, 0x03, 0xcf, 0x40}`. With a custom signet
challenge (BUG-3 closure), blockbrew would advertise the wrong magic
and be unable to handshake with any custom-signet peer.

**File:** `internal/p2p/message.go:33`,
`internal/consensus/chaincfg.go:414`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:475-479`.

**Impact:**
- Default signet handshake works (magic happens to be hard-coded
  correctly).
- Custom signet handshake fails immediately on every peer.
- Gates the operator-utility of BUG-3's fix.

---

## BUG-5 (P1) — `ErrTimeWarpAttack` does not map to Core reject string `"time-timewarp-attack"`

**Severity:** P1. `headerindex.go:21` defines `ErrTimeWarpAttack` as
the free-form English sentinel `"block timestamp violates BIP-94
timewarp rule at difficulty adjustment boundary"`. Core's reject string
is the much shorter, BIP22-canonical `"time-timewarp-attack"`
(`validation.cpp:4102`).

`bip22ResultString` (`rpc/methods.go:1800-1887`) does not include a
case for `ErrTimeWarpAttack`; it falls into the `default:` branch
(`return "rejected"`). A submitblock that hits the BIP-94 gate on
testnet4 returns `"rejected"` instead of `"time-timewarp-attack"`,
breaking mining-pool tooling that switches on the canonical token.

**File:** `internal/consensus/headerindex.go:21`,
`internal/rpc/methods.go:1800-1887`.

**Core ref:** `bitcoin-core/src/validation.cpp:4102`.

**Impact:**
- Reject-string wire-parity slippage on testnet4 BIP-94 rejections.
- Cross-cite: fleet pattern from W125 / W145 ("reject-string
  wire-parity slippage", per fleet-pattern tracking) — 10th distinct
  blockbrew instance.

---

## BUG-6 (P0-CDIV) — Miner-side BIP-94 timewarp clamp is `EnforceBIP94`-gated; Core applies it on ALL networks

**Severity:** P0-CDIV ("scope misnarrowed"). Core has TWO BIP-94 sites:

- **Consensus side** (`validation.cpp:4097-4104`) — gated by
  `consensusParams.enforce_BIP94`, which is true ONLY on testnet4.
- **Miner side** (`miner.cpp:36-47`) — `GetMinimumTime` clamps to
  `max(MTP+1, prev.nTime - MAX_TIMEWARP)` at retarget boundaries on
  **EVERY** network, regardless of `enforce_BIP94`. Core comment is
  verbatim: "Account for BIP94 timewarp rule on all networks. This
  makes future activation safer."

blockbrew gates BOTH sites identically:

`mining.go:269-279`:
```go
// Compute MinTime per GetMinimumTime (Core node/miner.cpp:36-47):
// always MTP+1; at retarget boundaries also bounded by
// prevBlock.time − MAX_TIMEWARP (BIP-94 timewarp rule).
minTime := mtp + 1
if tg.chainParams.EnforceBIP94 &&
    newHeight%int32(tg.chainParams.DifficultyAdjInterval) == 0 {
    timeWarpMin := int64(tipNode.Header.Timestamp) - consensus.MaxTimewarp
    if timeWarpMin > minTime {
        minTime = timeWarpMin
    }
}
```

On mainnet/testnet3/signet, `EnforceBIP94 == false`, so the clamp is
skipped entirely. blockbrew's GBT `mintime` is `MTP+1`; Core's may be
larger (`prev.nTime - 600` if MTP+1 < `prev.nTime - 600`).

**File:** `internal/mining/mining.go:269-279`. Also surfaced in the
comment at `internal/rpc/methods.go:1780-1781` (which correctly
DOCUMENTS the always-on Core behavior but delegates the implementation
to `template.MinTime` which has the bug).

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`.

**Excerpt (Core, always-on)**
```cpp
int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes future
    // activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}
```

**Excerpt (blockbrew, EnforceBIP94-gated → broken on mainnet/testnet3/signet)**
```go
if tg.chainParams.EnforceBIP94 &&
    newHeight%int32(tg.chainParams.DifficultyAdjInterval) == 0 {
    timeWarpMin := int64(tipNode.Header.Timestamp) - consensus.MaxTimewarp
    ...
}
```

**Impact:**
- A blockbrew mainnet/testnet3/signet GBT template at a retarget
  boundary that ALSO has `MTP+1 < prev.nTime - 600` emits a
  `mintime` lower than Core's. A pool that uses the `mintime` as
  the lower bound for stratum work distribution risks producing a
  block that, were BIP-94 to be activated on mainnet (the entire
  rationale for the always-on miner-side rule), would be rejected.
- The fix is a 1-line dependency drop: remove the `EnforceBIP94`
  gate from `mining.go:273-274`.
- Cross-cite: W154 BUG-6 P0-CDIV (the W154 confirmation of this
  finding) — STILL OPEN per memory index.
- Fleet pattern: "scope misnarrowed (subset of Core)" — 4th
  blockbrew instance per W128 + W137 + W144 tracking.

---

## BUG-7 (P2) — No `UpdateTime` analogue; testnet min-difficulty re-target hot path is single-pass

**Severity:** P2. Core's `node/miner.cpp:49-65` defines a separate
`UpdateTime` function that gets called after the BlockAssembler emits
the initial template, when the wall-clock has moved past the time
captured at template construction:

```cpp
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(GetMinimumTime(...), TicksSinceEpoch(NodeClock::now()))};
    if (nOldTime < nNewTime) pblock->nTime = nNewTime;
    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }
    return nNewTime - nOldTime;
}
```

The re-run of `GetNextWorkRequired` after `nTime` is bumped is critical
on testnet (`fPowAllowMinDifficultyBlocks=true`): a stale template held
in a pool for >20 minutes can become eligible for the min-difficulty
exception, but the template's `bits` field would still be the
non-min-difficulty target. Core's `UpdateTime` re-runs the calc.

blockbrew has no `UpdateTime` function. The single-pass derivation in
`GenerateTemplate` (`mining.go:158-203`) captures `header.Timestamp`
once and never re-runs `GetNextWorkRequired`. In practice the gap is
small because blockbrew templates are typically consumed promptly, but
a pool that holds a template >20 min on testnet3 sees the wrong bits.

**File:** `internal/mining/mining.go:158-203` (no UpdateTime).

**Core ref:** `bitcoin-core/src/node/miner.cpp:49-65`.

**Impact:**
- Testnet/regtest stale-template recalculation broken.
- Mainnet/signet unaffected (no min-difficulty rule).

---

## BUG-8 (P1) — Signet `PowLimit` set to mainnet powLimit, not signet's `0x00000377ae…`

**Severity:** P1. Core's `SigNetParams` (`chainparams.cpp:467`) sets
`consensus.powLimit = uint256{"00000377ae000000000000000000000000000000000000000000000000000000"}`
— a tight bound roughly 256× harder than mainnet's powLimit.
`PowLimitBits = 0x1e0377ae` is the compact-form encoding of this
target.

blockbrew's `SignetParams()` (`chaincfg.go:376-377`):
```go
PowLimitBits:           0x1e0377ae,
PowLimit:               mainnetPowLimit, // Same as mainnet
```

The inline comment "Same as mainnet" admits the bug (comment-as-confession
candidate, 11th distinct blockbrew instance). The PowLimitBits field
is correct, but `PowLimit` (the *big.Int upper bound) is the
mainnet `0x00000000ffffffff…`.

Downstream callers that compare a header's target against `PowLimit`:
- `difficulty.go:347-350` (in `CalculateNextWorkRequired`): caps the
  retargeted target at `params.PowLimit`. On signet, this allows
  retargeted targets up to mainnet powLimit, much looser than the
  intended signet bound.
- `headerindex.go:416` (PoW check via `CheckProofOfWork(hash, bits,
  idx.params.PowLimit)`): rejects only headers whose CLAIMED target
  exceeds PowLimit. A header claiming any bits between signet
  powLimit and mainnet powLimit passes (because mainnet powLimit is
  used as the cap).

**File:** `internal/consensus/chaincfg.go:376-377`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:467`.

**Impact:**
- Signet headers with targets up to mainnet powLimit pass the
  blockbrew PoW gate; Core rejects them as `bad-diffbits`.
- A signet block whose `nBits` encodes a target ABOVE Core's
  signet powLimit but BELOW mainnet powLimit would be accepted by
  blockbrew, fork-out from Core.
- Compounds with BUG-1: even before signet-solution validation
  is added, the PoW gate is too loose on signet.

---

## BUG-9 (P0-CDIV carry-forward W145 BUG-1, ~3 weeks open) — `CalcBlockSubsidy` ignores `params.SubsidyHalvingInterval`

**Severity:** P0-CDIV (consensus-divergence). Carry-forward of W145
BUG-1, W145 BUG-14, W154 BUG-17 — ALL STILL OPEN.

`internal/consensus/difficulty.go:162-170`:
```go
func CalcBlockSubsidy(height int32) int64 {
    halvings := height / SubsidyHalvingInterval   // PACKAGE-LEVEL const = 210000
    if halvings >= 64 {
        return 0
    }
    subsidy := InitialSubsidy
    subsidy >>= uint(halvings)
    return subsidy
}
```

The function ignores any `params *ChainParams` argument — there is no
plumbing. `chainmanager.go:551` calls `CalcBlockSubsidy(node.Height)`.
`mining.go:237` calls `consensus.CalcBlockSubsidy(newHeight)`.
`coinstatsindex.go:370-378` has a SECOND copy of the same hardcoded
math (two-pipeline guard 17th distinct extension).

Test `internal/mining/w123_gbt_test.go:148-168` explicitly documents
this as BUG-1 P0-CDIV.

For mainnet/testnet3/testnet4/signet the hardcoded `210000` matches
chainparams, so the bug is invisible. For regtest (`SubsidyHalvingInterval:
150`, `chaincfg.go:319`) the bug fires from block 150 onward:
- expected subsidy at h=150: 25 BTC,
- actual subsidy at h=150: 50 BTC.

Regtest miners pay themselves DOUBLE the consensus-correct subsidy
from h=150 onward; any block accepted-from-peer would fail
`bad-cb-amount`.

**File:** `internal/consensus/difficulty.go:162-170` (primary),
`internal/storage/coinstatsindex.go:370-378` (second hardcoded copy).

**Core ref:** `bitcoin-core/src/validation.cpp::GetBlockSubsidy`
(`return nSubsidy >> halvings;` driven by
`consensusParams.nSubsidyHalvingInterval`).

**Impact:**
- Regtest interop broken from h=150.
- GBT on regtest gives miners `coinbasevalue` that Core would reject.
- This is the W145 BUG-1 / W154 BUG-17 carry-forward re-confirmation
  — landed for fix nominally 3 weeks ago, still STILL OPEN. Priority-1
  in the auto-memory fix backlog.

---

## BUG-10 (P2) — `signetGenesisCoinbaseTx` literally returns `genesisCoinbaseTx()` with misleading docstring

**Severity:** P2 (cosmetic / docstring). `internal/consensus/genesis.go:116-119`:

```go
// signetGenesisCoinbaseTx creates the coinbase transaction for signet genesis.
func signetGenesisCoinbaseTx() *wire.MsgTx {
    return genesisCoinbaseTx()
}
```

The docstring claims signet has its own coinbase derivation, but the
function trivially returns the mainnet coinbase. Core's signet genesis
uses the SAME coinbase tx (BIP325 §3 — the genesis coinbase doesn't
need to be signed by the signet challenge because the genesis is
unconditionally valid in `CheckSignetBlockSolution`), so the BEHAVIOR
is correct, but the docstring + function existence imply otherwise.

The same pattern is repeated in `regtestGenesisCoinbaseTx` (line 91-93)
and `testnetGenesisCoinbaseTx` (line 65-67). Three triplicate wrappers
around `genesisCoinbaseTx`.

**File:** `internal/consensus/genesis.go:65-67, 91-93, 116-119`.

**Impact:**
- Misleading API surface; cleanup candidate.
- Comment-as-confession candidate (function name suggests
  signet-specific derivation, body proves it isn't).

---

## BUG-11 (P1-CDIV carry-forward W155 BUG-7) — `BlockTemplateResult` has no `signet_challenge` field

**Severity:** P1-CDIV. Carry-forward of W155 BUG-7. Core's GBT
response shape (`rpc/mining.cpp:1024-1026`):
```cpp
if (consensusParams.signet_blocks) {
    result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge));
}
```

blockbrew's `BlockTemplateResult` (`internal/rpc/types.go:452-…`) has
NO `SignetChallenge` field, no `signet_challenge` JSON key. Even with
the `gbtRules = append(gbtRules, "!signet")` (rpc/methods.go:1749-1751)
placeholder, miners that ask for a signet template get NO challenge
to sign against. A signet pool cannot use blockbrew's GBT.

**File:** `internal/rpc/types.go:452-…` (BlockTemplateResult struct).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1024-1026`.

**Impact:**
- Signet miners cannot use blockbrew GBT.
- Companion of BUG-2 (no field in ChainParams) — BOTH must close
  for signet mining to work.

---

## BUG-12 (P0-CDIV carry-forward W155 BUG-2 + W108 G4) — GBT doesn't enforce `"signet"` in clientRules on signet chain

**Severity:** P0-CDIV. Carry-forward of W155 BUG-2 and W108 G4. Core's
GBT (`rpc/mining.cpp:850-851`):
```cpp
if (consensusParams.signet_blocks && !setClientRules.count("signet")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER, ...);
}
```

The check enforces that a caller asking for a signet template must
have included `"signet"` in its `rules[]` array — the BIP-22
capability negotiation. Blocks of clients that don't understand
signet should not receive a signet template (they would be unable
to produce a signed block, and the miner-pool would silently produce
unsignable blocks).

blockbrew's `handleGetBlockTemplate` (`methods.go:1660-1794`)
discards the `params json.RawMessage` argument entirely (W155 BUG-1).
The client-rules check cannot run because the rules array is never
parsed.

**File:** `internal/rpc/methods.go:1660-1670`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:850-851`.

**Impact:**
- Older mining tools that don't know about signet still receive a
  signet template — they will produce blocks that lack the signet
  solution, all rejected.
- Fix is blocked by W155 BUG-1 (the entire `params` parse pipeline
  needs to exist first).

---

## BUG-13 (P1 carry-forward W123 G8) — `MiningInfo` JSON has no `signet_challenge` / `currentblockweight` / `currentblocktx`

**Severity:** P1. `MiningInfo` (`rpc/types.go:432-443`) is missing 3
Core fields:
- `signet_challenge` (on signet only),
- `currentblockweight` (from `BlockAssembler::m_last_block_weight`),
- `currentblocktx` (from `BlockAssembler::m_last_block_num_txs`).

Core's `getmininginfo` (`rpc/mining.cpp`) emits all three. blockbrew's
`handleGetMiningInfo` (`extra_methods.go:664-714`) emits none of them.

**File:** `internal/rpc/types.go:432-443`,
`internal/rpc/extra_methods.go:664-714`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getmininginfo`.

**Impact:**
- Pool-monitoring tooling that polls `getmininginfo.signet_challenge`
  / `currentblockweight` / `currentblocktx` gets `undefined` from
  blockbrew.
- Cross-cite W123 BUG-4 P2.

---

## BUG-14 (P2) — No `-enforce_bip94` regtest CLI flag

**Severity:** P2 (test ergonomics). Core's `CRegTestParams` ctor
(`chainparams.cpp:547`) reads `opts.enforce_bip94`, plumbed from
`-enforce_bip94=<bool>` CLI flag (in the regtest options block).
This is how regression tests for BIP-94 are constructed: spin up
regtest, set `-enforce_bip94=1`, walk to the first retarget boundary,
submit a block whose `nTime < parent.nTime - 600` and verify
`time-timewarp-attack` reject.

blockbrew's regtest params (`chaincfg.go:308-356`) DO NOT set
`EnforceBIP94` (default-zero / false). There is no CLI flag to flip
it. Regtest cannot exercise the BIP-94 consensus gate, only testnet4
can — and testnet4 retargets every 2016 blocks (~2 weeks of mining
on real testnet4 difficulty, infeasible in a CI test).

**File:** `internal/consensus/chaincfg.go:308-356`,
`cmd/blockbrew/main.go:445-496` (no flag).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:547`.

**Impact:**
- BIP-94 consensus gate has no regtest coverage.
- Companion to W148 BUG-6, W154 BUG-6 / BUG-8 cluster ("operator-knob
  absence") — 5th distinct blockbrew instance per W148+W154 tracking.

---

## BUG-15 (P0 carry-forward W154 BUG-2 + W155 BUG-25) — `handleGenerateBlock` does NOT recompute coinbase value after replacing txs

**Severity:** P0 (consensus-relevant). Carry-forward of W154 BUG-2
and W155 BUG-25. **STILL OPEN as of 2026-05-18.**

`internal/rpc/methods.go:3246-3252`:
```go
block := template.Block

// Replace transactions with the provided ones
coinbase := block.Transactions[0]
block.Transactions = make([]*wire.MsgTx, 0, len(txs)+1)
block.Transactions = append(block.Transactions, coinbase)
block.Transactions = append(block.Transactions, txs...)
```

The `coinbase` is reused from the mempool-driven template. Its
`TxOut[0].Value` is `subsidy + fees-from-mempool`. The user-supplied
`txs` have a DIFFERENT total fee. After substitution, the coinbase
value still reflects the OLD fees.

Same shape in `BlockMiner.GenerateBlock` (`mining.go:611-690`).

Submitting the resulting block to ConnectBlock fails with
`ErrBadCoinbaseValue` → BIP22 `"bad-cb-amount"`.

**File:** `internal/rpc/methods.go:3246-3252`, `internal/mining/mining.go:629-657`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::generateblock` calls
`RegenerateCommitments` which calls `GenerateCoinbaseCommitment`
which recomputes the witness commitment AND the coinbase value via
`block_template_pre_validate`.

**Impact:**
- generateblock with a non-empty tx-list always produces invalid blocks.
- Submitblock then rejects with `bad-cb-amount`.

---

## BUG-16 (P1 blocked by BUG-1) — `handleGenerateBlock` does not regenerate signet solution after tx-list edit

**Severity:** P1 (currently blocked by BUG-1 / BUG-2 — once those are
fixed, this becomes the next gap).

After BUG-1/BUG-2 close, every signet block must carry a fresh
signet-solution committed in the coinbase OP_RETURN witness commitment.
If `handleGenerateBlock` edits the tx list (and recomputes the merkle
root / witness commitment), the SIGNET SOLUTION embedded inside the
witness commitment becomes stale — it commits to the original merkle
root, not the post-edit one.

Core's `generateblock` invokes `RegenerateCommitments`, which DOES
re-run signet-solution computation. blockbrew's
`handleGenerateBlock` (`methods.go:3261-3271`) only recomputes the
witness commitment magic, not the signet solution.

**File:** `internal/rpc/methods.go:3261-3271`, `internal/mining/mining.go:644-657`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:67-77` (`RegenerateCommitments`)
+ signet hook.

**Impact:**
- Blocked by BUG-1 / BUG-2; tagged for follow-up.

---

## BUG-17 (P1) — `EnforceBIP94` is a single-bit toggle; Core couples consensus + miner halves but blockbrew flips only the consensus half

**Severity:** P1 ("scope-narrowed mirror"). Core has TWO BIP-94 sites
that share a SINGLE consensus parameter (`enforce_BIP94`):
- consensus-side reject at retarget boundary (`validation.cpp:4097`)
  is gated by `enforce_BIP94`.
- miner-side `GetMinimumTime` clamp (`miner.cpp:36`) IGNORES
  `enforce_BIP94` (always-on).

blockbrew has the same single `EnforceBIP94 bool` field on
`ChainParams`, but uses it for BOTH gates (BUG-6). The single-bit
encoding makes it structurally impossible to express Core's
"consensus-gated, miner-always-on" combination without splitting the
field. A correct fix is to either:
- thread a second boolean (`AlwaysApplyMinerSideBIP94`), OR
- drop the `EnforceBIP94` gate from miner.go entirely and always apply
  the clamp.

**File:** `internal/consensus/chaincfg.go:43`,
`internal/mining/mining.go:273`.

**Impact:**
- Architectural finding underpinning BUG-6.
- Cleanest fix is the second option (drop the gate from miner.go).

---

## BUG-18 (P1) — Two-pipeline guard 18th distinct extension: `CalcNextRequiredDifficulty` (no BIP-94) coexists with `CalculateNextWorkRequired` (BIP-94-aware)

**Severity:** P1 ("two-pipeline guard"). `difficulty.go` defines TWO
retarget-calculation entry points:

- `CalcNextRequiredDifficulty(params, prevBits, firstTimestamp, lastTimestamp)`
  (line 129) — takes raw bits + timestamps, does NOT consult
  `params.EnforceBIP94`, always uses `prevBits` as the base.
- `CalculateNextWorkRequired(params, height, lastNode, provider)`
  (line 311) — same retarget math, but BIP-94-aware:
  ```go
  if params.EnforceBIP94 {
      baseBits = firstNode.Header.Bits   // CORRECT
  } else {
      baseBits = lastNode.Header.Bits
  }
  ```

`mining.go:189-201` falls back to `CalcNextRequiredDifficulty` (the
broken one) when `tg.blockProvider == nil` (the "early-init regtest
tests" fallback). The two-pipeline guard catches the case where the
fallback path drifts from the production path.

**File:** `internal/consensus/difficulty.go:129-156, 311-353`.

**Core ref:** `bitcoin-core/src/pow.cpp::CalculateNextWorkRequired`
(single function, all callers go through it).

**Impact:**
- Tests that exercise the early-init fallback get non-BIP-94 retarget
  even when running against testnet4 params.
- Fleet pattern: 18th distinct two-pipeline guard instance, per
  W144/W145 tracking.

---

## BUG-19 (P1) — `ErrTimeWarpAttack` message includes English explanation, not Core canonical token

**Severity:** P1 (reject-string wire-parity). `internal/consensus/headerindex.go:21`:
```go
ErrTimeWarpAttack = errors.New("block timestamp violates BIP-94 timewarp rule at difficulty adjustment boundary")
```

The error text is human-readable English. Core's reject string is
`"time-timewarp-attack"` (`validation.cpp:4102`). Companion to BUG-5
(which describes the lack of bip22 mapping). The error MESSAGE itself
is the wire-parity problem; if anyone wraps the error and surfaces
.Error() to the wire (e.g. via consensus-diff JSON reports), the
English text appears instead of the canonical token.

**File:** `internal/consensus/headerindex.go:21`.

**Core ref:** `bitcoin-core/src/validation.cpp:4102`.

**Impact:**
- consensus-diff JSON outputs the English text; cross-impl regression
  tests can't grep for `"time-timewarp-attack"` to confirm parity.
- Companion to BUG-5; close together.

---

## BUG-20 (P2) — `handleGetBlockTemplate` constructs template with `MinerAddress: nil`; signet mining workflow doesn't pay anyone

**Severity:** P2 (operational). `methods.go:1666-1668`:
```go
config := mining.TemplateConfig{
    MinerAddress: nil, // Caller needs to set this
}
```

The comment says "Caller needs to set this" — but the caller is the
RPC client, and the RPC doesn't accept a `coinbaseaddr` parameter (it
isn't part of BIP-22). Core's GBT response embeds the coinbasevalue
and lets the caller fabricate their own coinbase via the
`default_witness_commitment` field; blockbrew's `CreateCoinbaseTx`
silently emits an `OP_RETURN`-style empty scriptPubKey when
`MinerAddress` is nil. The resulting template is unusable for actual
mining.

**File:** `internal/rpc/methods.go:1666-1668`.

**Core ref:** Core GBT does not embed the coinbase; the caller builds
it from `default_witness_commitment` + `coinbasevalue`.

**Impact:**
- GBT template's coinbase is broken for any caller that doesn't
  manually rebuild it.
- Signet mining workflow is doubly broken: BUG-1 + BUG-11 + BUG-20.

---

## BUG-21 (P2) — Comment-as-confession at `mining.go:148-156` documents the W144 BIP-9 ComputeBlockVersion gap but doesn't fix it

**Severity:** P2 (documentation drift). `mining.go:148-156` contains a
60-line block-comment lecturing on `ComputeBlockVersion` correctness:
"start with VERSIONBITS_TOP_BITS (0x20000000) and OR in the signaling
bits for every deployment currently in STARTED or LOCKED_IN state.
Hardcoding 0x20000000 is wrong — it silently omits miner signaling
for active BIP9 deployments."

The fix calls `consensus.ComputeBlockVersion(tipNode,
tg.chainParams.Deployments, tg.chainParams, nil)` — the LAST argument
is `nil`. That's the `*VersionBitsCache` parameter. Without the cache,
ComputeBlockVersion has to walk the chain re-computing deployment
state on every call (O(retarget_period * deployments_count)) per
template, AND any side-effecting state caching is lost. The function
LANDED, but the cache-management half is dead-data plumbing.

**File:** `internal/mining/mining.go:148-157`.

**Impact:**
- Template generation is slower than Core's by O(retarget_period)
  per call.
- Symptom of the broader "ComputeBlockVersion landed but no cache"
  gap (cross-cite W127 / W128 BIP-9 cache audits).
- 12th distinct blockbrew comment-as-confession per W144/W145 tracking.

---

## BUG-22 (P2) — Signet `BIP34Hash` not set (matches Core, but the field-existence pattern leaks)

**Severity:** P2 (architectural). Core sets `consensus.BIP34Hash =
uint256{}` for signet (`chainparams.cpp:456`) because signet activates
BIP-34 at height 1 — no historical block exists where the BIP-34
short-circuit grandfathered older blocks.

blockbrew's `SignetParams` omits the field (defaults to zero
`wire.Hash256{}`), which matches Core's behavior. But the gap is in
`internal/consensus/blockvalidation.go` (CheckBIP30 short-circuit
path) — when `BIP34Hash` is zero, the short-circuit cannot fire (it
needs to compare against a real hash). On signet this is the correct
behavior because BIP-34 is active at h=1, but the codepath has no
test that documents the zero-hash → no-short-circuit interaction.

**File:** `internal/consensus/chaincfg.go:368-422` (SignetParams).

**Impact:**
- Cosmetic / coverage gap; no consensus impact.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CONS:** 1 (BUG-1)
- **P0-CDIV:** 5 (BUG-2, BUG-6, BUG-9, BUG-12, BUG-15)
- **P0:** 0
- **P1-CDIV:** 1 (BUG-11)
- **P1:** 11 (BUG-3, BUG-4, BUG-5, BUG-8, BUG-13, BUG-14, BUG-16,
  BUG-17, BUG-18, BUG-19, BUG-20)
- **P2:** 4 (BUG-7, BUG-10, BUG-21, BUG-22)

Total: 1 + 5 + 1 + 11 + 4 = 22. ✓

**P0-class count:** 6 (BUG-1 + BUG-2 + BUG-6 + BUG-9 + BUG-12 + BUG-15).

**Carry-forward count (open from earlier waves):**
- BUG-1 = W143 BUG-9 (~3 wk open)
- BUG-2 = W155 BUG-7 + structural
- BUG-9 = W145 BUG-1 / W145 BUG-14 / W154 BUG-17 (~3 wk open)
- BUG-11 = W155 BUG-7
- BUG-12 = W155 BUG-2 / W108 G4
- BUG-15 = W154 BUG-2 / W155 BUG-25 (~1 wk open)
- BUG-13 = W123 BUG-4

7 carry-forwards out of 22 = pattern of "audit catches what fixes
miss" — typical for a 5th-wave-on-same-domain audit.

**Top three findings:**

1. **BUG-1 (P0-CONS — `CheckSignetBlockSolution` absent, ~3 weeks open)** —
   blockbrew on `-network=signet` accepts ANY block whose PoW meets
   the trivial signet target. Since signet PoW is trivially CPU-mineable,
   ANY actor can mine blockbrew-acceptable but Core-rejected blocks.
   blockbrew's signet tip diverges from Core's at h=1 and stays
   diverged forever. Re-confirmation of W143 BUG-9 — verified STILL
   OPEN. Fleet-wide pattern: signet-CheckSignetBlockSolution-absent
   (W143+W155 echo). The architectural pre-requisite for the fix is
   BUG-2 (the `SignetChallenge []byte` field in `ChainParams` needs
   to exist first), then BUG-1 itself can land.

2. **BUG-6 (P0-CDIV — miner-side `GetMinimumTime` BIP-94 clamp
   `EnforceBIP94`-gated)** — Core's `node/miner.cpp:36-47` applies
   the `prev.nTime - MAX_TIMEWARP` clamp on EVERY network
   unconditionally (Core comment: "Account for BIP94 timewarp rule on
   all networks. This makes future activation safer"). blockbrew gates
   the clamp on `tg.chainParams.EnforceBIP94`, which is false for
   mainnet/testnet3/signet. blockbrew's GBT `mintime` on those
   networks at retarget boundaries undershoots Core's, breaking
   future-BIP-94-activation safety. 1-line fix: drop the
   `EnforceBIP94` gate from `mining.go:273-274`. Companion of W154
   BUG-6 P0-CDIV. Fleet pattern: BIP-94 timewarp absent on miner side
   (W143+W154 fleet pattern).

3. **BUG-9 (P0-CDIV — `CalcBlockSubsidy` ignores
   `params.SubsidyHalvingInterval`, ~3 weeks open)** — re-confirmation
   of W145 BUG-1, W145 BUG-14, W154 BUG-17 — ALL STILL OPEN.
   Regtest miners pay themselves 50 BTC at h=150 (Core: 25 BTC). Any
   regtest block accepted-from-peer would fail `bad-cb-amount`.
   Two-pipeline guard 17th distinct extension: `coinstatsindex.go:370`
   has a SECOND copy of the same hardcoded math. The carry-forward
   re-anchor (4th instance of the same finding being re-flagged in
   successive audits) suggests the fix wave hasn't actually scheduled
   the work yet.

**Fleet patterns confirmed (this audit):**
- "signet-CheckSignetBlockSolution-absent" — W143+W155+W157 echo;
  re-anchor.
- "BIP-94 timewarp absent on miner side" — W143+W154+W157 echo;
  re-anchor.
- "comment-as-confession 11th-12th distinct" (BUG-8 "Same as mainnet",
  BUG-21 60-line lecture).
- "carry-forward re-anchor 4th instance" (BUG-9 = W145+W154+W157).
- "two-pipeline guard 17th-18th distinct extension" (BUG-9
  coinstatsindex.go + BUG-18 CalcNextRequiredDifficulty vs
  CalculateNextWorkRequired).
- "dead-data plumbing" (BUG-21 VersionBitsCache nil).
- "scope misnarrowed 4th distinct blockbrew" (BUG-6).
- "ChainParams field-but-not-read" (W145 BUG-14 fleet pattern echoes
  via BUG-2 — the inverse, ChainParams field-doesn't-exist).
- "operator-knob absence 5th distinct" (BUG-3 `-signetchallenge`,
  BUG-14 `-enforce_bip94`).
- "reject-string wire-parity slippage 10th-11th distinct" (BUG-5,
  BUG-19).

**Suggested fix order (after this audit closes):**
1. **BUG-2** (3-line ChainParams field add) — pre-requisite for BUG-1.
2. **BUG-1** (~200 LOC `CheckSignetBlockSolution` + helpers port from
   Core) — closes P0-CONS, restores signet chain parity.
3. **BUG-6** (1-line gate removal in `mining.go:273-274`) — closes
   P0-CDIV miner-side BIP-94 parity.
4. **BUG-9** (~10 LOC `CalcBlockSubsidy(params, height)` signature
   change + thread through 3 call sites + 1 coinstatsindex.go fix) —
   closes regtest interop, re-anchor.
5. **BUG-15** (~30 LOC `RegenerateCommitments`-equivalent helper in
   miner.go + thread into both call sites) — closes generateblock
   regtest workflow.
6. BUG-3 / BUG-4 / BUG-8 / BUG-11 / BUG-13 (signet-cluster cleanups,
   ~30 LOC each).
7. BUG-5 / BUG-19 (~5 LOC each, reject-string aliasing).
8. BUG-14 (regtest CLI flag).
9. BUG-17 / BUG-18 (architectural; defer until BUG-6 is in).
10. BUG-7 / BUG-10 / BUG-12 / BUG-16 / BUG-20 / BUG-21 / BUG-22
    (cosmetic / blocked / cleanup).
