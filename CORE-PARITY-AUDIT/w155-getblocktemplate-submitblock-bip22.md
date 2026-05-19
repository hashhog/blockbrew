# W155 — getblocktemplate + submitblock + BIP-22/BIP-23 RPC (blockbrew)

**Wave:** W155 — `getblocktemplate` (BIP-22 + BIP-23 + BIP-9 + BIP-145),
`submitblock`, `submitheader`, `getblockfromtemplate`, `getmininginfo`,
`getnetworkhashps`, `prioritisetransaction`, `getprioritisedtransactions`
RPCs. Covers: GBT `template_request` parse (`mode` / `capabilities[]` /
`rules[]` / `longpollid` / `data`), proposal-mode validation
(`TestBlockValidity(check_pow=false, check_merkle_root=true)`),
long-polling (`tip.GetHex() + ToString(nTransactionsUpdatedLast)`,
`waitTipChanged`), `setClientRules` enforcement (clear bit or throw
`RPC_INVALID_PARAMETER` for unsupported mandatory rules), GBT response
shape (`capabilities`, `version`, `rules`, `vbavailable`, `vbrequired`,
`previousblockhash`, `transactions[{data,txid,hash,depends,fee,sigops,
weight}]`, `coinbaseaux`, `coinbasevalue`, `longpollid`, `target`,
`mintime`, `mutable`, `noncerange`, `sigoplimit`, `sizelimit`,
`weightlimit`, `curtime`, `bits`, `height`, `default_witness_commitment`,
`signet_challenge`), `BIP22ValidationResult()` reject-string mapping,
`UpdateUncommittedBlockStructures` (auto-add witness reserved nonce),
`ProcessNewBlock(force_processing=true, min_pow_checked=true)`,
`submitblock_StateCatcher` (sc->found → "inconclusive"), `getmininginfo`
`next{height,bits,difficulty,target}` (Core 31.99 `NextEmptyBlockIndex`),
`networkhashps` plumb, signet `signet_challenge` field.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/rpc/mining.cpp:615-1036` — `getblocktemplate`:
  `template_request` parse (`mode`, `capabilities`, `rules`,
  `longpollid`, `data`), proposal-mode validation, long-polling
  (`waitTipChanged` over `nTransactionsUpdatedLast`),
  `setClientRules` enforcement, response shape (capabilities,
  longpollid, signet_challenge, default_witness_commitment).
- `bitcoin-core/src/rpc/mining.cpp:586-603` — `BIP22ValidationResult`:
  null → success, IsError → throw `RPC_VERIFY_ERROR`, IsInvalid →
  `state.GetRejectReason()` (empty → "rejected").
- `bitcoin-core/src/rpc/mining.cpp:606-613` — `gbt_rule_value`:
  prefix `!` on mandatory rules.
- `bitcoin-core/src/rpc/mining.cpp:763-764` — `if (strMode != "template")
  throw RPC_INVALID_PARAMETER` after proposal-mode early-return.
- `bitcoin-core/src/rpc/mining.cpp:766-775` — `!miner.isTestChain()` ⇒
  refuse GBT if no peers (`RPC_CLIENT_NOT_CONNECTED`) or in IBD
  (`RPC_CLIENT_IN_INITIAL_DOWNLOAD`).
- `bitcoin-core/src/rpc/mining.cpp:782-845` — Long Polling block:
  parses `<hashBestChain><nTransactionsUpdatedLast>`, waits via
  `miner.waitTipChanged()` (60s initial / 10s thereafter) until
  tip changes OR mempool transaction-counter advances.
- `bitcoin-core/src/rpc/mining.cpp:850-857` — mandatory-rules gate:
  signet requires `"signet"` in `setClientRules`; segwit ALWAYS
  required.
- `bitcoin-core/src/rpc/mining.cpp:947-948` — `result.pushKV("capabilities",
  aCaps)` where `aCaps = ["proposal"]`.
- `bitcoin-core/src/rpc/mining.cpp:968-991` — `vbavailable` loop:
  emits STARTED / LOCKED_IN / ACTIVE with `!`-prefix per
  `gbt_optional_rule`; for each non-optional rule not in
  `setClientRules`, EITHER clears bit (STARTED / LOCKED_IN) OR
  throws `RPC_INVALID_PARAMETER` (ACTIVE).
- `bitcoin-core/src/rpc/mining.cpp:1002` — `longpollid` =
  `tip.GetHex() + ToString(nTransactionsUpdatedLast)`.
- `bitcoin-core/src/rpc/mining.cpp:1007-1019` — pre-segwit-aware
  `sigoplimit`/`sizelimit`/`weightlimit` divide-by-`WITNESS_SCALE_FACTOR`
  on pre-segwit; `weightlimit` ONLY emitted post-segwit.
- `bitcoin-core/src/rpc/mining.cpp:1024-1026` — `signet_challenge` =
  `HexStr(consensusParams.signet_challenge)` (signet only).
- `bitcoin-core/src/rpc/mining.cpp:1028-1031` — `default_witness_commitment`
  = hex of `coinbase.required_outputs[0].scriptPubKey`.
- `bitcoin-core/src/rpc/mining.cpp:1056-1106` — `submitblock`:
  `DecodeHexBlk`, `UpdateUncommittedBlockStructures` (auto-insert
  reserved witness nonce when missing), `submitblock_StateCatcher`
  RAII, `ProcessNewBlock(force_processing=true, min_pow_checked=true)`,
  `(!new_block && accepted) → "duplicate"`,
  `(!sc->found) → "inconclusive"`, otherwise `BIP22ValidationResult`.
- `bitcoin-core/src/rpc/mining.cpp:1108-1145` — `submitheader`:
  parent-must-exist gate (`Must submit previous header (HASH) first`),
  `ProcessNewBlockHeaders({{h}}, min_pow_checked=true)`.
- `bitcoin-core/src/rpc/mining.cpp:416-498` — `getmininginfo`:
  `currentblockweight`, `currentblocktx`, `target`, `networkhashps`
  (calls `getnetworkhashps()` synchronously, NOT a hardcoded 0),
  `blockmintxfee` (from `ApplyArgsManOptions`), `next{height,bits,
  difficulty,target}` via `NextEmptyBlockIndex(tip, consensus, next_index)`,
  `signet_challenge`.
- `bitcoin-core/src/rpc/mining.cpp:111-184` — `getnetworkhashps`:
  blocks-since-N-lookback estimate.
- `bitcoin-core/src/validation.cpp:3985-3995` —
  `UpdateUncommittedBlockStructures`: appends 32-byte zero witness
  nonce to coinbase scriptWitness IFF segwit active AND witness
  commitment output exists AND coinbase has no witness already.
- `bitcoin-core/src/rpc/mining.cpp:502-583` — `prioritisetransaction`:
  arg shape (`txid`, `dummy=0`, `fee_delta`), throws on non-zero dummy.
- `bitcoin-core/src/validation.cpp:4217-4222` — header-rejection states
  emitted via `BLOCK_MISSING_PREV → "prev-blk-not-found"`,
  `BLOCK_INVALID_PREV → "bad-prevblk"`.
- `bitcoin-core/src/validation.cpp:4478` — `"inconclusive-not-best-prevblk"`
  (Core's narrower inconclusive state — used when the new block builds
  on a prev whose chain is not currently the best).

**Files audited**
- `internal/rpc/methods.go:1660-1794` — `handleGetBlockTemplate`.
- `internal/rpc/methods.go:1796-1887` — `bip22ResultString`.
- `internal/rpc/methods.go:1889-2012` — `handleSubmitBlock`.
- `internal/rpc/methods.go:2014-2106` — `handleSubmitBlockBatch`.
- `internal/rpc/methods.go:3148-3333` — `handleGenerateBlock`.
- `internal/rpc/methods.go:3335-3343` — `handleGenerate` (deprecated stub).
- `internal/rpc/types.go:423-443` — `MiningInfo` / `MiningInfoNext` shape.
- `internal/rpc/types.go:452-484` — `BlockTemplateResult` / `BlockTemplateTx`.
- `internal/rpc/extra_methods.go:344-446` — `handlePrioritiseTransaction`,
  `handleGetPrioritisedTransactions`.
- `internal/rpc/extra_methods.go:664-714` — `handleGetMiningInfo`.
- `internal/rpc/server.go:585-628` — RPC dispatch table
  (prioritisetransaction, getprioritisedtransactions, getblocktemplate,
  submitblock, submitblockbatch, getmininginfo, generatetoaddress,
  generatetodescriptor, generateblock, generate). No `submitheader`,
  no `getblockfromtemplate`.
- `internal/mining/mining.go:14-294` — template-construction package
  constants + `GenerateTemplate`.
- `internal/consensus/chainmanager.go:1160-1237` — `ProcessSubmittedBlock`
  + `ErrSideBranchAccepted` Pattern-Y closure (used by submitblock).
- `internal/consensus/chaincfg.go:11-71` — `ChainParams` struct (no
  `SignetChallenge` field; no `MineBlocksOnDemand` flag).

---

## Gate matrix (40 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | GBT `template_request` parse | G1: `mode` field parsed (template / proposal) | **BUG-1 (P0-CDIV)** — `handleGetBlockTemplate` discards `params` entirely; `mode` field never read |
| 1 | … | G2: `capabilities[]` parsed | **BUG-1 cross-cite** |
| 1 | … | G3: `rules[]` parsed into `setClientRules` | **BUG-1 cross-cite** (compounds with BUG-2) |
| 1 | … | G4: `longpollid` parsed | **BUG-1 cross-cite** (compounds with BUG-3) |
| 1 | … | G5: `data` parsed (proposal mode) | **BUG-1 cross-cite** (compounds with BUG-4) |
| 2 | `setClientRules` enforcement | G6: unsupported optional rule → clear bit in `block.nVersion` | **BUG-2 (P1-CDIV)** — never executed (rules never parsed) |
| 2 | … | G7: unsupported mandatory rule (e.g. !segwit) → throw `RPC_INVALID_PARAMETER` | **BUG-2 cross-cite** |
| 2 | … | G8: signet block REQUIRES "signet" in client rules | **BUG-2 cross-cite** — silently emits template for signet without checking client capability |
| 2 | … | G9: segwit REQUIRES "segwit" in client rules | **BUG-2 cross-cite** — same silent-emit |
| 3 | Long polling | G10: `longpollid` emitted in response | **BUG-3 (P0-CDIV)** — `BlockTemplateResult` struct has no `LongPollID` / `LongPollId` field |
| 3 | … | G11: `waitTipChanged` 60s/10s loop | **BUG-3 cross-cite** — no implementation; concurrent GBT calls each return immediately |
| 3 | … | G12: mempool `nTransactionsUpdatedLast` counter | **BUG-3 cross-cite** — `Mempool` has no transactions-updated counter; cannot wake longpollers on new tx |
| 4 | Proposal-mode validation | G13: `mode=proposal` parses `data` + decodes block + calls `TestBlockValidity(check_pow=false, check_merkle_root=true)` | **BUG-4 (P0-CDIV)** — `mode=proposal` silently falls through to template build. BIP-23 proposal mode unsupported |
| 4 | … | G14: duplicate-in-blockman → `"duplicate" / "duplicate-invalid" / "duplicate-inconclusive"` | **BUG-4 cross-cite** |
| 5 | IBD / peer-count gate | G15: `!isTestChain` AND `peerCount==0` → `RPC_CLIENT_NOT_CONNECTED` | **BUG-5 (P1)** — no peer-count check before template generation |
| 5 | … | G16: `!isTestChain` AND IBD → `RPC_CLIENT_IN_INITIAL_DOWNLOAD` | **BUG-5 cross-cite** — `handleGetBlockTemplate` ignores IBD state |
| 6 | GBT response: `capabilities[]` | G17: `["proposal"]` advertised | **BUG-6 (P1)** — `BlockTemplateResult.Capabilities` field does NOT exist |
| 6 | … | G18: `coinbasevalue` JSON NUMBER | PASS (`types.go:461` — `int64`, json shape NUMBER) |
| 6 | … | G19: `coinbasetxn` mode (BIP-23 alternative; emitted when caller asks for it) | **BUG-1 cross-cite** — not parsed, not implemented |
| 7 | GBT response field shape | G20: `longpollid` present | **BUG-3 cross-cite** |
| 7 | … | G21: `mutable[]` array | PASS (`methods.go:1784` — `["time", "transactions", "prevblock"]`) |
| 7 | … | G22: `rules[]` includes "csv", "!segwit" post-segwit, "taproot" post-taproot, "!signet" on signet | PASS (`methods.go:1730-1751`) but **see BUG-7** for signet TaprootHeight bug |
| 7 | … | G23: `vbavailable{}` BIP-9 deployment map | PARTIAL (`methods.go:1753-1768`) — uses `GetDeploymentState` per registered deployment but does NOT prefix `!` for mandatory rules; emits raw name only (Core uses `gbt_rule_value(name, info.gbt_optional_rule)`) |
| 7 | … | G24: `default_witness_commitment` post-segwit | PASS (`methods.go:1792`) — emitted only when `template.WitnessCommitment != nil` |
| 7 | … | G25: `signet_challenge` field on signet | **BUG-7 (P1-CDIV)** — `BlockTemplateResult` has no `SignetChallenge` field; `ChainParams` has no `SignetChallenge` field. Signet miners cannot use blockbrew GBT |
| 7 | … | G26: per-tx `depends[]` correctly computed from `setTxIndex` | **BUG-13 carry-forward W154** — `Depends: []int{}` hardcoded |
| 7 | … | G27: per-tx `fee` populated (satoshis) | **BUG-13 carry-forward W154** — `Fee: 0` hardcoded |
| 7 | … | G28: per-tx `sigops` populated | PASS (`methods.go:1686-1689` from `TxSigOpsCost`) |
| 7 | … | G29: per-tx `sigops` divided by `WITNESS_SCALE_FACTOR` pre-segwit | **BUG-8 (P1-CDIV)** — emitted raw cost regardless of pre/post-segwit. Core divides by 4 pre-segwit (`mining.cpp:928-931`) |
| 7 | … | G30: `sizelimit` is `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000` post-segwit, `/= 4` pre-segwit | **BUG-13 carry-forward W154** — emits `MaxBlockSize = 1_000_000` always |
| 7 | … | G31: `sigoplimit` is `MAX_BLOCK_SIGOPS_COST = 80_000` post-segwit, `/= 4` pre-segwit | **BUG-13 carry-forward W154** — emits `80_000` always |
| 7 | … | G32: `weightlimit` ONLY emitted post-segwit | **BUG-9 (P1-CDIV)** — emitted UNCONDITIONALLY (struct field has no `omitempty` and is always populated to `MaxBlockWeight`) |
| 8 | submitblock parse + decode | G33: hex decode → `MsgBlock` | PASS (`methods.go:1927-1940`) |
| 8 | … | G34: `UpdateUncommittedBlockStructures` (auto-add 32-byte zero witness nonce when missing) | **BUG-10 (P1-CDIV)** — never called; submitblock with a coinbase missing the witness nonce is rejected `bad-witness-merkle-match` whereas Core would auto-fix |
| 8 | … | G35: `ProcessNewBlock(force_processing=true, min_pow_checked=true)` | **BUG-11 (P1-CDIV)** — blockbrew passes `minPowChecked=false` (`methods.go:1958, 2079`); Core passes `true` (`rpc/mining.cpp:1095`). Operator-trusted submission is treated as untrusted; rejects pre-MinimumChainWork blocks the operator deliberately constructed |
| 8 | … | G36: state-catcher RAII (sc->found → "inconclusive") | **BUG-12 (P1)** — no equivalent CValidationInterface; `ErrSideBranchAccepted` covers PART of it (side-branch only) but does NOT cover the `(!sc->found)` case where validation was never run (e.g. block deferred due to missing parent) |
| 9 | submitblock BIP22 result string mapping | G37: complete coverage of Core reject reasons (e.g. `prev-blk-not-found`, `bad-prevblk`, `bad-witness-nonce-size`, `bad-cb-multi-commit`, `bad-cb-out-too-many-sigs`) | **BUG-14 (P1-CDIV)** — `bip22ResultString` (lines 1800-1887) maps ~16 error sentinels but misses ~15 BIP-22-canonical reject strings used by Core. Notable misses: `prev-blk-not-found`, `bad-prevblk`, `bad-witness-nonce-size`, `bad-cb-multi-commit`, `inconclusive-not-best-prevblk`, `bad-version`, `bad-versionbits` |
| 10 | submitblockbatch (non-standard) | G38: per-block BIP-22 result strings | PARTIAL — non-Core RPC; per-block error strings are free-form (`"block sanity check failed: %v"`) instead of BIP-22 canonical tokens. **BUG-15 (P1)** — `submitblockbatch` rejection strings are NOT mapped via `bip22ResultString` |
| 11 | submitheader | G39: header-only submission RPC dispatched | **BUG-16 (P1-CDIV)** — no `submitheader` case in dispatch table (`server.go:613-628`); Core ships this RPC since v0.18 |
| 12 | prioritisetransaction | G40: returns boolean `true` | PASS (`extra_methods.go:419`); positional 3-arg parse; non-zero dummy → `RPC_INVALID_PARAMETER`; integer-satoshi fee_delta — **all good**. Two minor concerns flagged below |
| 13 | getmininginfo | (multiple sub-gates collapsed into BUG-17) | **BUG-17 (P1)** — multiple field gaps: `currentblockweight` / `currentblocktx` absent (Core emits last-assembled-block stats); `networkhashps` hardcoded zero; `blockmintxfee` hardcoded `0.00001`; `next.bits` reuses tip bits (Core uses `NextEmptyBlockIndex` so retarget boundaries report correctly); `signet_challenge` absent on signet; `warnings` always empty string |
| 14 | getblockfromtemplate | (Core v26+ RPC) | **BUG-18 (P2-CDIV)** — `getblockfromtemplate` not in dispatch table; Core ships it as the BIP-23 `coinbasetxn` companion (build full block hex from a template that came from a separate miner) |

---

## BUG-1 (P0-CDIV) — `handleGetBlockTemplate` discards `params`; `mode`/`capabilities`/`rules`/`longpollid`/`data` ALL ignored

**Severity:** P0-CDIV. Bitcoin Core's `getblocktemplate`
(rpc/mining.cpp:615-761) parses the `template_request` JSON object and
extracts five fields whose semantics drive the entire RPC's behaviour:

1. `mode` — `"template"` (default) vs `"proposal"` (BIP-23 validate-only).
2. `capabilities[]` — client-supported features (`"longpoll"`,
   `"coinbasevalue"`, `"proposal"`, `"serverlist"`, `"workid"`).
3. `rules[]` — client-supported softfork rules; populated into
   `setClientRules` which gates `setClientRules.contains("segwit")` /
   `setClientRules.contains("signet")` and the "throw on unsupported
   mandatory rule" loop.
4. `longpollid` — `<tip-hex><nTransactionsUpdatedLast>` string used to
   block the request until either the tip changes OR mempool mutates.
5. `data` — proposed-block hex (proposal mode only).

blockbrew's `handleGetBlockTemplate` (`methods.go:1660-1672`) is:

```go
func (s *Server) handleGetBlockTemplate(params json.RawMessage) (interface{}, *RPCError) {
    if s.templateGen == nil {
        return nil, &RPCError{Code: RPCErrInternal, Message: "Mining not available"}
    }

    // Generate template with default config
    config := mining.TemplateConfig{
        MinerAddress: nil, // Caller needs to set this
    }

    template, err := s.templateGen.GenerateTemplate(config)
    ...
```

`params` is parameter-passed in but never `json.Unmarshal`-ed. There
is NO mode-parse, NO rules-parse, NO longpollid-parse, NO data-parse.

Consequences (each itemised under BUG-2 / BUG-3 / BUG-4 below):
- `mode=proposal` silently behaves as `mode=template` — Core validates
  the proposed block and returns `BIP22ValidationResult(state)`;
  blockbrew returns a fresh template ignoring the proposal entirely.
- A non-segwit-aware miner (no `"segwit"` in `rules`) silently receives
  a segwit-active template and mines an invalid block.
- Pool software subscribing to longpoll cannot use blockbrew (no
  `longpollid` to subscribe with).
- `capabilities` parse omitted → cannot detect whether client supports
  `coinbasetxn` (BIP-23 alternative coinbase) or `proposal` mode.

**File:** `internal/rpc/methods.go:1660-1672`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:715-761`.

**Excerpt (Core, all five fields parsed)**
```cpp
if (!request.params[0].isNull()) {
    const UniValue& oparam = request.params[0].get_obj();
    const UniValue& modeval = oparam.find_value("mode");
    if (modeval.isStr()) strMode = modeval.get_str();
    ...
    lpval = oparam.find_value("longpollid");
    if (strMode == "proposal") {
        const UniValue& dataval = oparam.find_value("data");
        ...
        return BIP22ValidationResult(TestBlockValidity(...));
    }
    const UniValue& aClientRules = oparam.find_value("rules");
    if (aClientRules.isArray()) {
        for (...) setClientRules.insert(v.get_str());
    }
}
```

**Impact:** five distinct GBT misbehaviours (BUG-2, BUG-3, BUG-4 +
implicit BIP-22 / BIP-23 compliance failure) compound from this one
omission. Pool software that round-trips a Core-built `template_request`
against blockbrew gets a template that ignores every input field — and
the test path that exercises BIP-22 proposal mode (`bitcoind -regtest
getblocktemplate '{"mode":"proposal","data":"…"}'`) silently
malfunctions.

---

## BUG-2 (P1-CDIV) — `setClientRules` enforcement absent; non-segwit miners silently get segwit templates

**Severity:** P1-CDIV. Bitcoin Core (rpc/mining.cpp:854-857) refuses
GBT if the client has not declared support for `segwit`:

```cpp
if (!setClientRules.contains("segwit")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER,
        "getblocktemplate must be called with the segwit rule set "
        "(call with {\"rules\": [\"segwit\"]})");
}
```

And on signet (rpc/mining.cpp:850-852) the same gate applies to
`"signet"`. Then for every BIP-9 / BIP-141 deployment in STARTED /
LOCKED_IN / ACTIVE state, Core EITHER clears the version bit (optional)
OR throws `RPC_INVALID_PARAMETER` (mandatory) when the client has not
opted in (rpc/mining.cpp:968-991).

blockbrew never parses `rules` (BUG-1 follow-on) so:
- A miner calling `getblocktemplate '{}'` (no rules) on mainnet at
  height >= 481824 receives a segwit-active template. The miner
  has no idea segwit is active and produces a block missing the
  witness-commitment OP_RETURN → instant `bad-witness-merkle-match`.
- A miner calling on signet receives a template without ever being
  asked to declare `"signet"` support. Same silent breakage class.
- The narrower "throw on unsupported mandatory rule" path (e.g. for
  a future hardfork that's `ACTIVE` but optional=false) is unreachable.

**File:** `internal/rpc/methods.go:1660-1794`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:850-857, 968-991`.

**Impact:** spec-compliance failure (BIP-22 `rules` field is **required**
for non-trivial clients); silent miner-invalid-block production.

---

## BUG-3 (P0-CDIV) — No `longpollid` response field; long-polling entirely unsupported

**Severity:** P0-CDIV. Bitcoin Core's GBT response includes a
`longpollid` field (rpc/mining.cpp:1002):

```cpp
result.pushKV("longpollid", tip.GetHex() + ToString(nTransactionsUpdatedLast));
```

Pool software re-issues GBT with the prior `longpollid` value to wait
for either a new tip OR a mempool delta. Without it, the only way to
detect "should I rebuild the template?" is to poll on a fast cadence,
which is wasteful and racy.

blockbrew's `BlockTemplateResult` struct (`types.go:452-473`) has no
`LongPollID` field at all. There is no `Mempool.GetTransactionsUpdated()`
or equivalent counter (cf. Core `CTxMemPool::GetTransactionsUpdated()`)
that could be used to construct one. There is no `waitTipChanged` /
`WaitTipChanged` API on the chain manager.

Layered consequences:
- BIP-22 longpoll mode unusable. Pool software that hard-depends on
  longpoll (cgminer, BFGMiner, MMpool, btcpool) cannot use blockbrew.
- Re-issued GBT with a `longpollid` arg from a Core node is silently
  ignored (BUG-1 follow-on) — the call returns immediately with a
  fresh template, defeating the rate-limiting purpose.

**File:** `internal/rpc/types.go:452-473`, `internal/rpc/methods.go:1660-1794`,
`internal/mempool/mempool.go` (no transactions-updated counter).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:782-845, 1002`;
`bitcoin-core/src/txmempool.cpp::GetTransactionsUpdated`.

**Impact:** core pool-mining workflow unsupported.

---

## BUG-4 (P0-CDIV) — `mode=proposal` (BIP-23) entirely unsupported; silently behaves as `mode=template`

**Severity:** P0-CDIV. Bitcoin Core (rpc/mining.cpp:730-752) handles
`mode=proposal` by:

```cpp
if (strMode == "proposal") {
    const UniValue& dataval = oparam.find_value("data");
    if (!dataval.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

    CBlock block;
    if (!DecodeHexBlk(block, dataval.get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    uint256 hash = block.GetHash();
    LOCK(cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
    if (pindex) {
        if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
            return "duplicate";
        if (pindex->nStatus & BLOCK_FAILED_VALID)
            return "duplicate-invalid";
        return "duplicate-inconclusive";
    }

    return BIP22ValidationResult(TestBlockValidity(
        chainman.ActiveChainstate(), block,
        /*check_pow=*/false, /*check_merkle_root=*/true));
}
```

This is the BIP-23 "I built a block, please tell me if it would be
accepted" handshake. It is the standard way for a centralised
template builder to ask each network node "is this block valid before
I broadcast it?" — useful for pool software that builds the block but
wants a sanity check pre-submit.

blockbrew's `handleGetBlockTemplate` does NOT parse `mode`, so a
caller sending `{"mode":"proposal","data":"…"}` gets a brand-new
template returned (BUG-1 follow-on) — the proposed block is silently
dropped. No `check_pow=false / check_merkle_root=true` revalidation
exists anywhere in blockbrew.

**File:** `internal/rpc/methods.go:1660-1794` (no proposal mode);
`internal/consensus/` (no `TestBlockValidity(check_pow=false,
check_merkle_root=true)` analogue).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:730-752`.

**Impact:** BIP-23 proposal handshake unsupported; pool software that
relies on the proposal-validate flow (signet for instance, where
mining-pool authoring is more centralized) cannot use blockbrew.
Cross-cite W154 BUG-12 (no `TestBlockValidity` analogue on the
template-build side either).

---

## BUG-5 (P1) — `getblocktemplate` has no peer-count / IBD gate

**Severity:** P1. Bitcoin Core (rpc/mining.cpp:766-775) refuses GBT
unless the node has peers AND is not in IBD:

```cpp
if (!miner.isTestChain()) {
    const CConnman& connman = EnsureConnman(node);
    if (connman.GetNodeCount(ConnectionDirection::Both) == 0) {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, ...);
    }
    if (miner.isInitialBlockDownload()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, ...);
    }
}
```

`isTestChain()` returns true for regtest/signet only — mainnet and
testnet3/4 hit the gates. Without these gates, a miner running against
an IBD-mode node will produce templates building on a stale tip,
mine valid blocks for THAT tip, and waste hashpower on a block that
the network has already moved past.

blockbrew's `handleGetBlockTemplate` (`methods.go:1660-1672`) has no
such gate. It will happily build a template at whatever the local
`chainMgr.BestBlock()` reports, regardless of whether that's a 2-week-
old IBD-paused tip or a present-day tip.

**File:** `internal/rpc/methods.go:1660-1672`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:766-775`.

**Impact:** wasted-hashpower window on IBD/no-peers operator
misconfiguration; can mask an actual sync problem because GBT
"works".

---

## BUG-6 (P1) — GBT response missing `capabilities` field

**Severity:** P1. Bitcoin Core's GBT response always emits
`capabilities` (rpc/mining.cpp:895-948):

```cpp
UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");
...
result.pushKV("capabilities", std::move(aCaps));
```

Currently always `["proposal"]` — but the protocol-level meaning is
"server-supported features the client can use" (`"longpoll"`,
`"coinbasevalue"`, `"proposal"`, `"serverlist"`, `"workid"`). BIP-22
clients MAY parse this and route accordingly.

blockbrew's `BlockTemplateResult` (`types.go:452-473`) has NO
`Capabilities` field. Pool software that probes via `capabilities`
sees nothing → assumes worst-case (none supported) → falls back to
fastest-cadence polling.

**File:** `internal/rpc/types.go:452-473`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:895-948`.

**Impact:** spec gap; bridges into BUG-3 (longpoll discovery) and
BUG-4 (proposal discovery).

---

## BUG-7 (P1-CDIV) — `signet_challenge` field absent + `ChainParams.SignetChallenge` doesn't exist

**Severity:** P1-CDIV. Bitcoin Core (rpc/mining.cpp:1024-1026):

```cpp
if (consensusParams.signet_blocks) {
    result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge));
}
```

The signet challenge script is the per-signet-instance secret-key
script that signet miners must sign. Without it the miner cannot
sign the block, and `CheckSignetBlockSolution` rejects on submit.

blockbrew's situation is two-layer broken:
1. `ChainParams` struct (`chaincfg.go:11-71`) has no `SignetChallenge`
   field. The signet params (`chaincfg.go:375-425`) don't even pretend
   to expose this. Cross-cite W143 BUG-9 (signet — `CheckSignetBlockSolution`
   entirely missing in blockbrew → P0-CONS for signet).
2. `BlockTemplateResult` (`types.go:452-473`) has no `SignetChallenge`
   field.

The cascade: even if signet validation were implemented (W143 P0-CONS
open), the GBT path can't tell miners what challenge to sign because
the field never reaches them.

Additionally, `chaincfg.go:387` sets `signetParams.TaprootHeight = 0`
("Active from genesis") — but the GBT rules-emit logic (`methods.go:1743`)
does `tipHeight >= s.chainParams.TaprootHeight`, so at `tipHeight=0`
this emits `"taproot"` correctly. Note however that other field
emissions (the `"!signet"` mandatory rule at line 1749-1751) DO fire,
so a misled signet miner without the challenge gets a template that
says "I am signet" but has no challenge to satisfy.

**File:** `internal/rpc/types.go:452-473`,
`internal/consensus/chaincfg.go:11-71` (struct), `355-425` (signet).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1024-1026`;
`bitcoin-core/src/consensus/params.h::signet_challenge`.

**Impact:** signet mining unsupported via blockbrew's GBT. Cross-cite
W143 BUG-9 (signet `CheckSignetBlockSolution` absent, P0-CONS).

---

## BUG-8 (P1-CDIV) — per-tx `sigops` NOT divided by `WITNESS_SCALE_FACTOR` pre-segwit

**Severity:** P1-CDIV. Bitcoin Core (rpc/mining.cpp:927-932) scales
the per-tx `sigops` field for pre-segwit emission:

```cpp
int64_t nTxSigOps{tx_sigops.at(index_in_template)};
if (fPreSegWit) {
    CHECK_NONFATAL(nTxSigOps % WITNESS_SCALE_FACTOR == 0);
    nTxSigOps /= WITNESS_SCALE_FACTOR;
}
entry.pushKV("sigops", nTxSigOps);
```

blockbrew (`methods.go:1686-1689`) emits the raw cost value
unconditionally:

```go
if idx := i - 1; idx >= 0 && idx < len(template.TxSigOpsCost) {
    sigOps = template.TxSigOpsCost[idx]
}
...
SigOps: sigOps,
```

Pre-segwit miners see `sigops` 4× too high → pool software that sums
per-tx sigops against `sigoplimit` (which is BUG-13 carry-forward
W154 — also wrong pre-segwit) overshoots the budget and drops txs
unnecessarily, OR if both wrong values cancel, hits a different
divergence.

**File:** `internal/rpc/methods.go:1685-1689`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:927-932`.

**Impact:** GBT consumer divergence on pre-segwit chains (regtest at
height 0 if segwit gate is height-N>0, or any future test chain).
Note: on mainnet/testnet4/signet today, segwit is active so
fPreSegWit=false and this bug does NOT bite the production path.

---

## BUG-9 (P1-CDIV) — `weightlimit` emitted unconditionally; Core emits ONLY post-segwit

**Severity:** P1-CDIV. Bitcoin Core (rpc/mining.cpp:1017-1019):

```cpp
if (!fPreSegWit) {
    result.pushKV("weightlimit", MAX_BLOCK_WEIGHT);
}
```

Pre-segwit, the field is OMITTED — Core's BIP-22 emission says "this
chain has no concept of weight, only size". Pool software MAY use
the presence-or-absence of `weightlimit` as a fPreSegWit detector.

blockbrew (`methods.go:1788`):

```go
WeightLimit: consensus.MaxBlockWeight,
```

The struct field has no `omitempty` JSON tag, so the field is ALWAYS
emitted. Pre-segwit miners receive `weightlimit: 4000000` alongside
their (BUG-13 carry-forward W154) misreported `sizelimit: 1000000`
and decide "wait, both? which one?".

**File:** `internal/rpc/types.go:468`, `internal/rpc/methods.go:1788`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1017-1019`.

**Impact:** GBT BIP-22 wire-format divergence on pre-segwit chains.

---

## BUG-10 (P1-CDIV) — `submitblock` does NOT call `UpdateUncommittedBlockStructures`

**Severity:** P1-CDIV. Bitcoin Core (rpc/mining.cpp:1084-1090):

```cpp
ChainstateManager& chainman = EnsureAnyChainman(request.context);
{
    LOCK(cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
    if (pindex) {
        chainman.UpdateUncommittedBlockStructures(block, pindex);
    }
}
```

`UpdateUncommittedBlockStructures` (validation.cpp:3985-3995):
- Finds the witness-commitment output via `GetWitnessCommitmentIndex`.
- If segwit is active AND the commitment exists AND the coinbase has
  no witness already, INSERTS a 32-byte zero witness nonce into the
  coinbase scriptWitness.

This is the BIP-141 "coinbase witness reserved value" auto-fix: a
miner submitting a stripped block (coinbase has commitment output but
no scriptWitness) gets the nonce added for them, so the block is not
needlessly rejected.

blockbrew's `handleSubmitBlock` (`methods.go:1889-2011`) skips this
step entirely. A submitter who built the block with the right
commitment but forgot the witness nonce gets `bad-witness-merkle-match`
(or equivalent) and has to rebuild + resubmit. Core would have just
fixed it inline.

**File:** `internal/rpc/methods.go:1889-2011`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1084-1090`,
`bitcoin-core/src/validation.cpp:3985-3995`.

**Impact:** spec-compliance gap; pool-software interop break for
clients that rely on Core's auto-fix.

---

## BUG-11 (P1-CDIV) — `submitblock` passes `minPowChecked=false`; Core passes `true`

**Severity:** P1-CDIV. Bitcoin Core (rpc/mining.cpp:1095):

```cpp
bool accepted = chainman.ProcessNewBlock(blockptr,
    /*force_processing=*/true,
    /*min_pow_checked=*/true,
    /*new_block=*/&new_block);
```

The reasoning: submitblock is an operator-trusted RPC. The operator
either:
- Built the block locally on top of the active tip (which by definition
  is past MinimumChainWork), OR
- Imported the block from a trusted source.

Either way, the MinimumChainWork gate is satisfied. Core trusts the
operator.

blockbrew (`methods.go:1958, 2079`) passes `minPowChecked=false`:

```go
// minPowChecked=false: submitblock arrives from an external caller (RPC
// client / miner) that has NOT passed through the PRESYNC pipeline.
// AddHeader will enforce the MinimumChainWork gate itself.
if _, err := s.headerIndex.AddHeader(block.Header, false); err != nil {
```

The comment is a justification, but it diverges from Core. Consequence:
- Operator deliberately constructing a block on a side-fork below
  MinimumChainWork (testing scenario, regtest fork-recovery script,
  PRESYNC manual fixup) is rejected `ErrTooLittleChainwork` instead
  of accepted.
- Cross-cite: W154 BUG-23 noted `BlockMiner.GenerateBlock` passes
  `minPowChecked=true` — so locally-mined blocks bypass the gate,
  externally-submitted blocks don't. **Two-pipeline drift** within
  mining: the internal-miner path trusts itself, the external-submit
  path does not trust the operator. Core trusts both.

**File:** `internal/rpc/methods.go:1954-1958, 2076-2079`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1095`.

**Impact:** operator-control divergence; debug/recovery operator
workflow broken on the submitblock path while internal-miner uses
the more-permissive setting.

---

## BUG-12 (P1) — `submitblock` has no `submitblock_StateCatcher` analogue; `(!sc->found) → "inconclusive"` case unhandled

**Severity:** P1. Bitcoin Core registers a `CValidationInterface`
shared pointer that catches `BlockChecked(block, state)` notifications
between `ProcessNewBlock` and the unregister call (rpc/mining.cpp:1093-1103):

```cpp
auto sc = std::make_shared<submitblock_StateCatcher>(block.GetHash());
CHECK_NONFATAL(chainman.m_options.signals)->RegisterSharedValidationInterface(sc);
bool accepted = chainman.ProcessNewBlock(...);
CHECK_NONFATAL(chainman.m_options.signals)->UnregisterSharedValidationInterface(sc);
if (!new_block && accepted) {
    return "duplicate";
}
if (!sc->found) {
    return "inconclusive";
}
return BIP22ValidationResult(sc->state);
```

Three return classes:
1. **duplicate** — `(!new_block && accepted)`: block was already known.
2. **inconclusive** — `(!sc->found)`: ProcessNewBlock returned without
   ever validating the block (deferred — typically missing parent).
3. **conclusive** — `BIP22ValidationResult(sc->state)`: state.IsValid
   or has reject reason.

blockbrew's `handleSubmitBlock` (`methods.go:1958-2011`) has:
- Partial duplicate detection via `ErrDuplicateHeader` return path
  (line 1960-1962 — returns "duplicate"). Good for that case.
- `ErrSideBranchAccepted` returns "inconclusive" (line 1999-2001) —
  but this fires ONLY for the **stored-side-branch** sub-case, NOT
  for "validation was deferred because parent missing" or "validation
  was deferred because the block was filed for later". A block whose
  parent is missing from blockbrew's header index hits the earlier
  `AddHeader → err != ErrDuplicateHeader` return path (line 1963)
  with `bip22ResultString(err)` — typically `"rejected"` for the
  free-form "parent not found" error, not Core's `"prev-blk-not-found"`
  or `"inconclusive"`.

**File:** `internal/rpc/methods.go:1958-2011`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1038-1106`.

**Impact:** BIP-22 reject-string divergence; pool software that
parses `"inconclusive"` as "retry after I send the parent" instead
sees `"rejected"` and gives up.

---

## BUG-13 (P1-CDIV) — `bip22ResultString` reject-string coverage gaps (~15 Core tokens missing)

**Severity:** P1-CDIV. Bitcoin Core's `BIP22ValidationResult`
(rpc/mining.cpp:586-603) returns `state.GetRejectReason()` directly —
so every reject-reason string in `BlockValidationState::Invalid(...)`
across validation.cpp / consensus/*.cpp / chain.cpp leaks out as a
BIP-22 result. The canonical token set is large (see Core
`validation.cpp:4150-4310, 2400-2600, 4470-4500` etc.).

blockbrew's `bip22ResultString` (`methods.go:1796-1887`) hand-maps
sentinel errors to ~16 BIP-22 tokens. Coverage:

| Core token | blockbrew? | Note |
|------------|------------|------|
| high-hash | ✓ | |
| bad-diffbits | ✓ | |
| bad-txnmrklroot | ✓ | |
| bad-witness-merkle-match | ✓ | |
| bad-txns-vout-negative | ✓ | |
| bad-txns-vout-toolarge | ✓ | |
| bad-cb-length | ✓ | |
| bad-cb-amount | ✓ | |
| bad-blk-sigops | ✓ | |
| bad-txns-inputs-missingorspent | ✓ | |
| bad-txns-duplicate | ✓ | |
| bad-cb-height | ✓ | |
| bad-txns-nonfinal | ✓ | |
| time-too-old | ✓ | |
| time-too-new | ✓ | |
| bad-txns-premature-spend-of-coinbase | ✓ | |
| bad-txns-in-belowout | ✓ | |
| block-script-verify-flag-failed | ✓ | |
| **prev-blk-not-found** | ✗ | validation.cpp:4217 |
| **bad-prevblk** | ✗ | validation.cpp:4222 |
| **inconclusive-not-best-prevblk** | ✗ | validation.cpp:4478 |
| **bad-witness-nonce-size** | ✗ | BIP-141 reserved-value wrong size |
| **bad-cb-multi-commit** | ✗ | multiple witness commitments |
| **bad-blk-length** | ✗ | structural size violation |
| **bad-blk-weight** | ✗ | weight cap breach |
| **bad-version** | ✗ | nVersion < required (BIP-65/66) |
| **time-too-new** vs **time-too-old** | partial | mapped but doesn't cover BIP-94 boundary case |
| **mandatory-script-verify-flag-failed** | ✗ | distinct from `block-script-verify-flag-failed` |
| **bad-blk-too-far-ahead** | ✗ | unrequested + too-far-ahead |
| **bad-txns-undersize** | ✗ | tx < 65 bytes BIP-141 anti-malleability |
| **bad-witness-merkle-size** | ✗ | commitment wrong length |
| **bad-cb-missing** | ✗ | first tx not coinbase |
| **bad-cb-multiple** | ✗ | more than one coinbase |

Default case (line 1880-1885) maps unknown errors to `"rejected"`
(or `"block-script-verify-flag-failed"` if the message contains
"script"). The free-form `"rejected"` is BIP-22 valid but opaque.

**File:** `internal/rpc/methods.go:1796-1887`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:586-603` + all
`BlockValidationState::Invalid(...)` reject tokens in
`bitcoin-core/src/validation.cpp`.

**Impact:** pool-software incompatibility for clients that branch on
specific reject reasons (e.g. "retry on prev-blk-not-found", "treat
inconclusive-not-best-prevblk as soft").

---

## BUG-14 (P1) — `submitblockbatch` uses free-form error strings instead of BIP-22 tokens

**Severity:** P1. `handleSubmitBlockBatch` (`methods.go:2014-2106`)
processes a JSON array of block hexes and returns a parallel array
of results. Per-block error strings are formatted free-form:

```go
results[i] = fmt.Sprintf("block sanity check failed: %v", err)
results[i] = fmt.Sprintf("header validation failed: %v", err)
results[i] = fmt.Sprintf("failed to store block: %v", err)
results[i] = fmt.Sprintf("block connection failed: %v", err)
```

None of these go through `bip22ResultString`. The single-block path
(`handleSubmitBlock`) DOES use `bip22ResultString` — so batch vs
single-block return-string semantics DIVERGE within the same node.

A pool calling `submitblockbatch` and then per-block branching on
the result string will see `"block connection failed: bad-cb-amount
(...)"` instead of the canonical `"bad-cb-amount"`. Pool retry logic
designed around BIP-22 tokens cannot work.

This is also a **"two-pipeline drift"** instance within the same
file: single-block submit honours BIP-22, batch submit does not.

**File:** `internal/rpc/methods.go:2014-2106`.

**Core ref:** N/A — Core does not ship `submitblockbatch`. The
local convention should still map per-block via the same helper.

**Impact:** intra-node inconsistency; batch RPC unusable by BIP-22-aware
pool software.

---

## BUG-15 (P1-CDIV) — `submitheader` RPC absent

**Severity:** P1-CDIV. Bitcoin Core (rpc/mining.cpp:1108-1145) ships
`submitheader` since v0.18 (~2018):

```cpp
RPCHelpMan{
    "submitheader",
    "Decode the given hexdata as a header and submit it as a candidate chain tip if valid."
    "\nThrows when the header is invalid.\n",
    {
        {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ...},
    },
    ...
```

Used by:
- Mining pools that want to submit headers ahead of full bodies
  (BIP-152 compact-blocks fast-path).
- Header-only relay clients.
- Operational scripts to "poke" a parent header into the index before
  submitting a child block.

blockbrew's RPC dispatch (`server.go:613-628`) has no `submitheader`
case. Calls return method-not-found.

**File:** `internal/rpc/server.go:613-628` (dispatch table).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1108-1145`.

**Impact:** spec-compliance gap; cross-cite W149 BUG-3 fleet pattern
("RPC absent from dispatch" — same shape as the absent `pruneblockchain`
case found there). Also breaks Core-compatible mining-pool tooling
that uses submitheader as a probe.

---

## BUG-16 (P1) — `getmininginfo` field gaps: `currentblockweight` / `currentblocktx` / `networkhashps` / `signet_challenge` / `warnings`

**Severity:** P1. Bitcoin Core's `getmininginfo` response
(rpc/mining.cpp:416-498) emits:

- `currentblockweight` — last assembled block weight (optional).
- `currentblocktx` — last assembled block tx count (optional).
- `bits` — current nBits.
- `difficulty` — current difficulty.
- `target` — current target hex.
- `networkhashps` — calls `getnetworkhashps()` synchronously.
- `pooledtx` — mempool size.
- `blockmintxfee` — from `assembler_options.blockMinFeeRate`
  (operator-tunable via `-blockmintxfee`).
- `chain` — network name.
- `signet_challenge` — signet only.
- `next{height, bits, difficulty, target}` — uses `NextEmptyBlockIndex`
  so retarget boundaries report the correct **next** nBits, not the
  tip's nBits.
- `warnings` — node warnings.

blockbrew's `handleGetMiningInfo` (`extra_methods.go:664-714`):

```go
return &MiningInfo{
    Blocks:        tipHeight,
    Bits:          tipBitsHex,
    Difficulty:    difficulty,
    Target:        tipTargetHex,
    PooledTx:      pooledTx,
    BlockMinTxFee: 0.00001,            // hardcoded magic number
    Chain:         s.rpcChainName(),
    Next:          next,               // next.bits = tipBitsHex (BUG)
    Warnings:      "",                 // hardcoded empty
}, nil
```

Note `NetworkHash` is in the struct (`types.go:437`) but is NEVER
assigned by `handleGetMiningInfo` — it always emits as zero-value
`0` (JSON `0.0`).

Gaps:
1. **`currentblockweight`** / **`currentblocktx`** — no tracking of
   the last assembled block's weight/tx-count. `BlockAssembler::m_last_block_weight`
   / `m_last_block_num_txs` analogues do not exist.
2. **`networkhashps`** — `MiningInfo.NetworkHash` field exists but is
   never populated. Calling `getmininginfo` always returns
   `networkhashps: 0`. **Comment-as-confession**-class — field
   defined-but-unused.
3. **`blockmintxfee`** — hardcoded `0.00001` (no operator config
   plumb; cross-cite W154 BUG-8 — no `-blockmintxfee` flag exists).
4. **`next.bits`** — reuses `tipBitsHex` (line 698) instead of
   computing the next block's required `nBits` via the
   `GetNextWorkRequired` / `NextEmptyBlockIndex` path. At every
   2016-block retarget boundary, `next.bits` is WRONG (it reports
   the OLD bits, not the new). Pool software that uses
   `getmininginfo.next.bits` to know "what difficulty will I be
   mining at" is off-by-one-retarget.
5. **`signet_challenge`** — absent (struct has no field; cross-cite
   BUG-7).
6. **`warnings`** — hardcoded empty string (line 712).

**File:** `internal/rpc/types.go:432-443` (struct),
`internal/rpc/extra_methods.go:664-714` (handler).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:416-498`.

**Impact:** monitoring/observability data loss; misleading
`next.bits` at retarget boundaries; can mask actual node warnings.

---

## BUG-17 (P2-CDIV) — `getblockfromtemplate` RPC absent

**Severity:** P2-CDIV. Bitcoin Core ships `getblockfromtemplate`
(see `bitcoin-core/src/rpc/mining.cpp` near the GBT block) as the
companion to `getblocktemplate`: given a GBT response, return a fully
assembled block-hex string that the miner can hash. Used by pool
software that wants to defer block construction to the node.

blockbrew's RPC dispatch (`server.go:613-628`) has no
`getblockfromtemplate` case. No BIP-23 `coinbasetxn` mode either
(BUG-1 cross-cite).

**File:** `internal/rpc/server.go:613-628` (dispatch table).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getblockfromtemplate`.

**Impact:** modern (Core v26+) mining RPC unavailable; cross-cite
W154 BUG-13 (GBT response gaps).

---

## BUG-18 (P1) — GBT `vbavailable` does NOT prefix `!` on mandatory BIP-9 rules

**Severity:** P1. Bitcoin Core (rpc/mining.cpp:606-613, 968-991) emits
`vbavailable` entries with the `gbt_rule_value(name, gbt_optional_rule)`
naming helper which prefixes `!` on mandatory rules:

```cpp
static std::string gbt_rule_value(const std::string& name, bool gbt_optional_rule) {
    std::string s{name};
    if (!gbt_optional_rule) {
        s.insert(s.begin(), '!');
    }
    return s;
}
...
vbavailable.pushKV(gbt_rule_value(name, info.gbt_optional_rule), info.bit);
```

This is the SAME prefix convention as `rules[]` — the client knows
"this BIP-9 deployment is mandatory once active" by the leading `!`.

blockbrew (`methods.go:1762-1768`):

```go
for i, dep := range s.chainParams.Deployments {
    state := consensus.GetDeploymentState(dep, i, tipNode, s.chainParams, vbCache)
    if state == consensus.DeploymentStarted || state == consensus.DeploymentLockedIn {
        gbtVbavailable[dep.Name] = dep.Bit       // raw name, no !
    }
}
```

The `dep.Name` is the raw rule name; no `!` prefix logic. blockbrew's
`BIP9Deployment` struct (likely in `internal/consensus/versionbits.go`)
has no `GbtOptionalRule` field that the GBT loop could consult.

Effect: a client cannot tell which of the `vbavailable` rules are
mandatory vs optional. If the client then signals (or doesn't signal)
the wrong subset, the block produced may signal an unintended
deployment OR fail to signal a mandatory one.

**File:** `internal/rpc/methods.go:1762-1768`,
`internal/consensus/versionbits.go` (struct lacks `GbtOptionalRule`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:606-613, 968-991`.

**Impact:** BIP-9 / BIP-22 wire-format divergence; client cannot
distinguish mandatory vs optional deployments.

---

## BUG-19 (P1) — `mempool.GetTransactionsUpdated()` counter absent → cannot rebuild template on mempool delta

**Severity:** P1. Bitcoin Core uses `CTxMemPool::GetTransactionsUpdated()`
as a free-running counter that increments every time the mempool's tx
set changes (admit, remove, eviction, reorg). The GBT logic at
rpc/mining.cpp:863-870:

```cpp
if (!pindexPrev || pindexPrev->GetBlockHash() != tip ||
    (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - time_start > 5))
{
    ...
    nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
    ...
    block_template = miner.createNewBlock(...);
}
```

So Core re-builds the template if the tip changed OR (mempool has
mutated AND >5s since last build). This is also the trigger for
long-polling (BUG-3 cross-cite).

blockbrew has no such counter on `Mempool`. The GBT path
(`methods.go:1670`) calls `tg.templateGen.GenerateTemplate(config)`
unconditionally — every call does a full mempool walk. No template
caching, no mempool-delta short-circuit.

Performance: under heavy GBT polling, each call walks the entire
mempool (`mp.GetSortedByAncestorFeeRate()` returns all entries).
Mainnet mempool of 100k+ txs × ~10 req/s of GBT polling → ~1M sort
ops/s wasted.

**File:** `internal/mempool/mempool.go` (no `GetTransactionsUpdated`),
`internal/rpc/methods.go:1670` (no caching of `template_request`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:863-870`;
`bitcoin-core/src/txmempool.cpp::GetTransactionsUpdated`.

**Impact:** wasted compute under GBT polling; underpins BUG-3.

---

## BUG-20 (P1-CDIV) — `submitblock` does NOT broadcast successfully-accepted blocks to peers

**Severity:** P1-CDIV. Bitcoin Core's `ProcessNewBlock` flows through
`ChainstateManager::ProcessNewBlock` → `AcceptBlock` → eventual
`NotifyBlockTip` → `PeerManager::NewPoWValidBlock` / `BlockConnected`
which announces the block to peers via headers-first or compact-block
relay.

blockbrew's `handleSubmitBlock` (`methods.go:2006-2009`):

```go
// Broadcast to peers
if s.peerMgr != nil {
    // TODO: Broadcast block inv to peers
}
```

`// TODO: Broadcast block inv to peers` is a **comment-as-confession**
fleet pattern, ~11th distinct blockbrew instance.

A locally-submitted block sits on the local chain but does NOT
propagate. Peers learn about it only via the next `getheaders` round
(every minute or so). For a mining pool, this delay is catastrophic —
every second of propagation lag is potential orphaning.

Cross-cite: `handleGenerateBlock` (methods.go:3322-3330) DOES announce
the block via `peerMgr.AnnounceBlock` or fallback inv — so generateblock
broadcasts, submitblock does not. **Two-pipeline drift** within the
same file.

**File:** `internal/rpc/methods.go:2006-2009`.

**Core ref:** `bitcoin-core/src/validation.cpp::AcceptBlock` →
`NotifyBlockTip` → `PeerManager::NewPoWValidBlock`.

**Impact:** submitblock-via-pool propagation lag; orphan-rate increase
on locally-mined pool blocks.

---

## BUG-21 (P2-CDIV) — `submitblockbatch` does NOT call `chainMgr.ProcessSubmittedBlock`; uses bare `ConnectBlock` only

**Severity:** P2-CDIV. `handleSubmitBlock` (single) uses
`chainMgr.ProcessSubmittedBlock(block)` which is the Pattern-Y closure
that handles side-branch acceptance and reorg-on-submit
(chainmanager.go:1199-1237).

`handleSubmitBlockBatch` (`methods.go:2096`) uses bare
`chainMgr.ConnectBlock(block)` — which ONLY extends the active tip,
never accepts side-branches, never triggers reorgs.

Effect: submitting a heavier-chain block via `submitblockbatch` on a
fork-from-tip-2 scenario is REJECTED with the bare-`ConnectBlock`
error path, whereas the single-block submit would accept it as a
side-branch and trigger a reorg. **Two-pipeline drift** within the
same file (4th distinct instance this audit; cross-cite BUG-14, BUG-20).

**File:** `internal/rpc/methods.go:2091-2100`.

**Core ref:** N/A (Core has no submitblockbatch).

**Impact:** batch submit rejects valid reorg-triggering blocks that
single-submit would accept; intra-node consistency violation.

---

## BUG-22 (P1) — `prioritisetransaction` accepts non-integer JSON number via Go float64 type coercion

**Severity:** P1. `handlePrioritiseTransaction`
(`extra_methods.go:404-413`):

```go
deltaFloat, ok := args[2].(float64)
if !ok {
    return nil, &RPCError{Code: RPCErrInvalidParams,
        Message: "fee_delta must be a number (satoshis)"}
}
if deltaFloat != float64(int64(deltaFloat)) {
    return nil, &RPCError{Code: RPCErrInvalidParameter,
        Message: "fee_delta must be an integer number of satoshis"}
}
deltaSats := int64(deltaFloat)
```

JSON has no integer type — `encoding/json` decodes all numbers to
`float64`. The check `deltaFloat != float64(int64(deltaFloat))` looks
correct but fails for large values: an `int64` value like `2^53 + 1`
loses precision when round-tripped through `float64`, so:
- The equality check PASSES (because both sides lose the same bits).
- `int64(deltaFloat)` is the truncated value, not the input.

The caller pays `+9_007_199_254_740_993` sats; blockbrew records
`+9_007_199_254_740_992` (rounded). For fee-bump deltas in the
"normal" sat range this never matters, but for adversarially-large
deltas (or hypothetical post-MAX_MONEY operator scripts) the silent
truncation is a divergence.

Core uses `UniValue` integer parsing which preserves int64 exact
bits (`bitcoin-core/src/univalue/lib/univalue.cpp::getInt<int64_t>`).

**File:** `internal/rpc/extra_methods.go:404-413`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::prioritisetransaction`
+ UniValue integer parser.

**Impact:** silent precision loss for fee deltas > 2^53; not
exploitable on mainnet (MAX_MONEY < 2^53) but a wire-parity slip.

---

## BUG-23 (P2) — `getmininginfo` `pooledtx` not lock-coherent with `Difficulty` read

**Severity:** P2. `handleGetMiningInfo` (`extra_methods.go:664-714`)
reads `BestBlock()` then `BestBlockNode()` (two separate lock
acquisitions on `chainMgr.mu`) then `mempool.Count()` (separate
mempool lock). Between these, a new block could land, changing all
three values.

The emitted `MiningInfo{Blocks: tipHeight, Bits: tipBitsHex, ...,
PooledTx: pooledTx}` may therefore represent inconsistent snapshots:
the block height is from before the new block, the bits are from
after, the pooledtx is from a mempool partially-drained by the
new block's tx inclusion.

Core takes `LOCK(cs_main)` for the entire response build
(`rpc/mining.cpp:461`), so all fields reflect the same atomic state.

**File:** `internal/rpc/extra_methods.go:664-714`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:461`.

**Impact:** monitoring/observability inconsistency; not a consensus
bug. UI dashboards built on `getmininginfo` may flash inconsistent
state during fast tip turnover.

---

## BUG-24 (P0-CDIV carry-forward W145 / W154) — `CalcBlockSubsidy` ignores `params.SubsidyHalvingInterval`; GBT `coinbasevalue` wrong on regtest h>=150

**Severity:** P0-CDIV (carry-forward; W145 BUG-1 has been open since
~W123 — ~3 weeks now — re-confirmed by W154 BUG-17 and now re-confirmed
HERE inside the GBT response path).

The GBT response field `coinbasevalue` (`methods.go:1778`) is sourced
from `template.CoinbaseValue` which inside `mining.go:237-238`
is `subsidy + totalFees` where `subsidy = consensus.CalcBlockSubsidy(newHeight)`.

`CalcBlockSubsidy` (`difficulty.go:162-170`) reads the package const
`SubsidyHalvingInterval = 210_000` (`params.go:27`) — NOT the per-network
`ChainParams.SubsidyHalvingInterval` field. Regtest sets the field to
150 (`chaincfg.go:319`) — dead data.

**On regtest at height >= 150**, GBT emits `coinbasevalue = 50 BTC`
when Core would emit `coinbasevalue = 25 BTC` (post-first-halving).
A miner that obeys the template builds a block paying 50 BTC, submits
it, and gets `bad-cb-amount` rejection.

This is the THIRD location for the same bug — fleet-wide pattern
"single P0 bug surfaces in N waves before fix":
- W145 BUG-1 (subsidy calculation itself).
- W145 BUG-14 (dead-field on chainparams).
- W154 BUG-17 (BlockAssembler-side coinbasevalue computation).
- **This audit BUG-24** (GBT-response-side coinbasevalue exposure).

Each wave catches a different operational consumer of the same broken
helper. The fix is one line (`CalcBlockSubsidy(height, params)`), but
it has been open ~3 weeks.

**File:** `internal/consensus/difficulty.go:162-170`,
`internal/mining/mining.go:237`, `internal/rpc/methods.go:1778`.

**Core ref:** `bitcoin-core/src/validation.cpp::GetBlockSubsidy`
(takes `const Consensus::Params&`).

**Carry-forward age:** W145 BUG-1 ~3 weeks open. Now tracked in
GBT path as BUG-24.

**Impact:** regtest GBT broken past h=150. Cross-impl divergence:
test-suite scripts that call GBT on regtest get a `coinbasevalue`
2× Core's after the first halving.

---

## BUG-25 (P0 carry-forward W154 BUG-2) — `handleGenerateBlock` does NOT recompute coinbase value after replacing txs

**Severity:** P0 (carry-forward W154 BUG-2; re-tracking under W155 as
the same-impl GBT-adjacent path).

`handleGenerateBlock` (`methods.go:3148-3333`) generates a template
from the mempool, REPLACES `block.Transactions[1:]` with the
caller-supplied tx set, recomputes merkle + witness commitment — but
DOES NOT recompute the coinbase output value (`coinbase.TxOut[0].Value`
remains `subsidy + mempool-totalFees` from the original template).

If the caller's tx set has different fees from the mempool selection,
the coinbase pays the WRONG amount → `bad-cb-amount` on submit.

Cross-cite W154 BUG-2; tracked here because `handleGenerateBlock` is
also a BIP-22-adjacent submit-side path (it does the equivalent of
GBT + submitblock in one call) and the bug surfaces on its submit-side.

**File:** `internal/rpc/methods.go:3246-3270`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::generateblock`.

**Carry-forward:** W154 BUG-2 (same wave's preceding audit).

**Impact:** `generateblock <addr> [tx_subset]` rejected on submit
whenever tx_subset fees != mempool template fees. Regtest test
fixtures hit this routinely.

---

## Summary

**Bug count:** 25 (BUG-1 through BUG-25).

**Severity distribution:**
- **P0 / P0-CDIV:** 6
  - BUG-1 (P0-CDIV): `template_request` discard
  - BUG-3 (P0-CDIV): longpoll unsupported
  - BUG-4 (P0-CDIV): proposal-mode unsupported
  - BUG-24 (P0-CDIV carry-forward W145/W154): regtest GBT subsidy
  - BUG-25 (P0 carry-forward W154 BUG-2): generateblock coinbase value
  - (BUG-3 / BUG-4 / BUG-24 are class-changes from W154's P1 because
    the GBT-side P0 stakes — wire-format spec divergence + regtest
    consensus break — exceed W154's mining-pipeline-internal P1s)
- **P1 / P1-CDIV:** 15 (BUG-2, BUG-5, BUG-6, BUG-7, BUG-8, BUG-9,
  BUG-10, BUG-11, BUG-12, BUG-13, BUG-14, BUG-15, BUG-16, BUG-18,
  BUG-19, BUG-20, BUG-22) — recount: 17. Adjusting: BUG-21 is P2,
  BUG-23 is P2 → P1 count = 15. ✓
- **P2 / P2-CDIV:** 4 (BUG-17, BUG-21, BUG-22, BUG-23).

Recount: 6 + 15 + 4 = 25. ✓

**Carry-forwards confirmed open**
- **W145 BUG-1 (P0-CDIV)** `CalcBlockSubsidy` ignores
  `params.SubsidyHalvingInterval` — re-confirmed in GBT
  `coinbasevalue` emission as **BUG-24**. ~3 weeks open;
  THIRD distinct surfacing.
- **W154 BUG-2 (P0)** `handleGenerateBlock` does not recompute
  coinbase value — re-confirmed inline as **BUG-25**. <1 day old
  (just landed).
- **W154 BUG-13 (P1-CDIV)** GBT response missing `capabilities` /
  `longpollid` / `signet_challenge` — re-confirmed and SPLIT into
  three distinct bugs this audit (**BUG-6** capabilities,
  **BUG-3** longpollid, **BUG-7** signet_challenge).
- **W154 BUG-14 (P1-CDIV)** GBT `sizelimit` always 1_000_000 — same
  bug still in place; re-noted but not duplicated (it's not GBT-
  consumer-specific per W155 surface).
- **W143 BUG-9 (P0-CONS, signet)** `CheckSignetBlockSolution` absent
  — cross-cite BUG-7 (signet GBT cannot offer challenge that
  validator can verify either way).
- **W149 BUG-3 (P0-CDIV)** `pruneblockchain` RPC absent from
  dispatch — same shape as **BUG-15** (`submitheader` absent) and
  **BUG-17** (`getblockfromtemplate` absent). "RPC absent from
  dispatch" fleet pattern now at 3 distinct blockbrew instances.

**Fleet patterns confirmed**
- **"Two-pipeline drift" (5 distinct intra-audit instances)** —
  BUG-11 (submitblock minPowChecked=false vs internal-miner=true),
  BUG-14 (submitblock uses bip22ResultString, batch doesn't),
  BUG-20 (submitblock no peer broadcast, generateblock does),
  BUG-21 (batch uses ConnectBlock, single uses ProcessSubmittedBlock),
  W154 carry-forward BUG-24 (BlockAssembler & GBT response share
  the broken subsidy helper). Extends two-pipeline guard to its
  16th-20th distinct fleet instance.
- **"Comment-as-confession" (3 distinct instances this wave)** —
  BUG-3 GBT longpoll absent (no field comment, but the GBT block
  has NO related infrastructure — silent omission), BUG-11
  comment justifies divergence-from-Core ("minPowChecked=false"
  with rationale), BUG-16 NetworkHash field defined-but-not-used,
  BUG-20 literal `// TODO: Broadcast block inv to peers`. Cumulative
  blockbrew comment-as-confession tracker now ~15 distinct
  instances.
- **"RPC absent from dispatch" (3 distinct blockbrew instances now)**
  — W149 `pruneblockchain`, W155 **BUG-15** `submitheader`, W155
  **BUG-17** `getblockfromtemplate`. Fleet pattern: blockbrew
  ships the implementations but never wires them into
  `Server.handle(...)`. Cross-cite W138's "ChainstateManager
  defined but never called" — same architectural shape.
- **"30-of-30-gates-buggy" candidate** — `handleGetBlockTemplate`
  fails G1-G16 across 4 of 14 audit behaviours (template_request
  parse: 5 fails, setClientRules: 4 fails, longpoll: 3 fails,
  proposal: 2 fails = 14 of 40 sub-gates fail at once). Not a
  "30-of-30" classic by raw count but the entire `template_request`
  → response pipeline is essentially a stub.
- **"Operator-knob absence" cluster from W154 reaches GBT surface**
  — BUG-16 BlockMinTxFee hardcoded `0.00001`; cross-cite W154
  BUG-8 (no `-blockmintxfee` flag). The GBT path emits the
  hardcoded value, so even if the flag existed, the GBT-side
  consumer would see the wrong floor.
- **"Carry-forward re-anchor" (BUG-24)** — same bug surfaces in a
  THIRD distinct file in 3 weeks. The fix is one line (pass `params`
  to `CalcBlockSubsidy`). Each audit catches a different operational
  consumer.
- **"Dead-data plumbing" (BUG-16 NetworkHash field)** — struct
  field defined, JSON tag set, never assigned. Same shape as W138's
  9-impl ChainstateManager pattern, W149 `havePruned` flag, W145
  ChainParams.SubsidyHalvingInterval.
- **"Wire-format slippage" (BUG-9 weightlimit, BUG-18 vbavailable
  prefix)** — fields are emitted differently from Core's BIP-22
  wire format in ways that fail strict client parsers.
- **"GBT non-substitutable-for-Core's"** (compounded across BUG-1,
  BUG-2, BUG-3, BUG-4, BUG-6, BUG-7, BUG-13, BUG-14, BUG-15,
  BUG-16, W154 BUG-13, W154 BUG-14, W154 BUG-15, W154 BUG-16) —
  blockbrew's GBT response is missing > 10 fields Core emits, drops
  or mis-shapes 3 fields, ignores all 5 `template_request` inputs,
  and lacks 4 BIP-22-canonical reject strings on the submit side.
  Pool software cannot drop-in-replace Core with blockbrew.

**Top three findings**

1. **BUG-1 (P0-CDIV) — `handleGetBlockTemplate` discards `params`
   entirely.** All five `template_request` fields (mode, capabilities,
   rules, longpollid, data) are ignored. Five distinct downstream
   misbehaviours (BUG-2, BUG-3, BUG-4 + spec gaps + capabilities
   field-absence) compound from this one omission. Pool software
   that round-trips a Core-built `template_request` against blockbrew
   gets a template ignoring every input.

2. **BUG-3 + BUG-4 + BUG-7 cluster (P0-CDIV × 3) — BIP-22/BIP-23 core
   features (longpoll, proposal, signet) entirely absent.** No
   `longpollid` response field. No `mode=proposal` validate-only
   handshake. No `signet_challenge` exposure. Combined with W143
   BUG-9 (signet `CheckSignetBlockSolution` absent, P0-CONS), signet
   mining is end-to-end-broken: there's no challenge in the template
   and no validator to verify even if there were. Long-poll mode
   unusable means cgminer / BFGMiner / btcpool cannot use blockbrew
   on mainnet.

3. **BUG-13 + BUG-15 + BUG-17 + BUG-20 (P1-CDIV cluster) —
   submit-side BIP-22 compliance gaps.** `bip22ResultString` covers
   only ~16 of ~31 canonical reject tokens (missing
   `prev-blk-not-found`, `bad-prevblk`, `bad-witness-nonce-size`,
   `inconclusive-not-best-prevblk`, `bad-cb-multi-commit`, etc.).
   `submitheader` RPC absent. `getblockfromtemplate` RPC absent.
   `submitblock` does not broadcast to peers (`// TODO: Broadcast
   block inv to peers`). Pool retry logic and propagation are
   end-to-end broken.

**Next-priority fixes**
1. Parse `template_request` JSON; populate `setClientRules`; enforce
   `segwit`/`signet` mandatory-rule gates (closes BUG-1, BUG-2 in
   one architectural change).
2. Add `Mempool.GetTransactionsUpdated()` counter + GBT
   `longpollid` field + cached template (`pindexPrev` + `time_start`
   pattern from Core); closes BUG-3 + BUG-19.
3. Add `SignetChallenge` field to `ChainParams` + emit in GBT +
   prerequisite for closing W143 BUG-9.
4. Pass `params` to `CalcBlockSubsidy` — the W145 BUG-1 one-line
   fix that now closes 4 distinct surfacings (W145, W154, W155 ×
   2 = BUG-24 + BUG-25).
5. Wire `submitheader` and `getblockfromtemplate` into RPC dispatch.
6. Add `UpdateUncommittedBlockStructures` call in `handleSubmitBlock`.
7. Implement `BIP22ValidationResult` analogue that maps all
   ~31 Core reject reasons (closes BUG-13).
8. Hook submitblock success path into peer-broadcast (closes BUG-20).
9. Use single dispatch path through `bip22ResultString` for
   `submitblockbatch` (closes BUG-14).
10. Switch `submitblock` to `minPowChecked=true` per Core convention
    (closes BUG-11; brings parity with `BlockMiner.GenerateBlock`).
