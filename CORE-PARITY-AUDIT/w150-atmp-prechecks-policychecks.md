# W150 — AcceptToMemoryPool + PreChecks + PolicyScriptChecks + ConsensusScriptChecks (blockbrew)

**Wave:** W150 — `MemPoolAccept::AcceptSingleTransaction`,
`MemPoolAccept::PreChecks` (~validation.cpp:782-1024),
`MemPoolAccept::PolicyScriptChecks` (~validation.cpp:1135-1156),
`MemPoolAccept::ConsensusScriptChecks` (~validation.cpp:1162-1190),
`PreCheckEphemeralTx`, `Finalize`, `IsStandardTx`,
`ValidateInputsStandardness`, `IsWitnessStandard`,
`Consensus::CheckTxInputs`, the `bypass_limits` / `m_package_feerates`
mode bits, the reject-token wire-string vocabulary, and the
`-acceptnonstdtxn` / `-minrelaytxfee` / `-incrementalrelayfee` /
`-datacarrier` / `-datacarriersize` / `-permitbaremultisig` /
`-bytespersigop` operator-knob set.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:782-1024` — `MemPoolAccept::PreChecks`.
  Drives the full ATMP pipeline: `CheckTransaction` → coinbase reject →
  `IsStandardTx` (gated on `require_standard`) → `tx-size-small` (65-byte
  CVE-2017-12842 floor) → `CheckFinalTxAtTip` (BIP-113) → wtxid/txid
  exact-dupe two-probe → conflict scan + `bip125-replacement-disallowed`
  reject (when `!m_allow_replacement`) → input-cache + missing-input vs
  already-known disambiguation → `CalculateLockPointsAtTip` +
  `CheckSequenceLocksAtTip` (BIP-68) → `Consensus::CheckTxInputs`
  (`bad-txns-premature-spend-of-coinbase`, MoneyRange, sufficient-fee) →
  `ValidateInputsStandardness` (BIP-54 + per-input P2SH redeem-script
  sigops) → `IsWitnessStandard` → sigops cap → ephemeral-dust 0-fee gate →
  fee gate (unless `bypass_limits || m_package_feerates`) → TRUC checks
  → conflicts → ReplacementChecks.
- `bitcoin-core/src/validation.cpp:1135-1156` — `PolicyScriptChecks`:
  `CheckInputScripts(STANDARD_SCRIPT_VERIFY_FLAGS, …)` → if fail, maps
  to `TX_NOT_STANDARD` with token
  `"mempool-script-verify-flag-failed (<ScriptErrorString>)"`.
- `bitcoin-core/src/validation.cpp:1162-1190` — `ConsensusScriptChecks`:
  `CheckInputScripts(GetBlockScriptFlags(tip), …)` → if fail, maps to
  `TX_CONSENSUS` with token
  `"block-script-verify-flag-failed (<ScriptErrorString>)"`.
- `bitcoin-core/src/validation.cpp:2120-2122` — the two error tokens
  emitted by `CheckInputScripts` depending on whether
  `flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS` is set.
- `bitcoin-core/src/policy/policy.cpp:27-69` — `GetDustThreshold` /
  `IsDust`. Spending-cost calculation uses tx serialized size + segwit-
  discounted input size; multiplied by `dust_relay_fee` (NOT
  `min_relay_fee`). `IsUnspendable` short-circuits to zero. Default:
  `DUST_RELAY_TX_FEE = 3000` sat/kvB.
- `bitcoin-core/src/policy/policy.cpp:71-78` — `GetDust(tx, fee)`
  returns the indices of EVERY dust output; called by `IsStandardTx` to
  count dust outputs and reject if `> MAX_DUST_OUTPUTS_PER_TX (=1)`.
- `bitcoin-core/src/policy/policy.cpp:100-165` — `IsStandardTx` runs
  version range, weight cap, scriptSig size + push-only, output
  standardness, MULTISIG bare-multisig (gated on `permit_bare_multisig`),
  datacarrier cumulative budget against `max_datacarrier_bytes`, and
  `GetDust` cap.
- `bitcoin-core/src/policy/policy.cpp:170-194` — `CheckSigopsBIP54`:
  total non-witness sigops across the entire transaction (scriptSig
  accurate + prevout scriptPubKey P2SH-accurate) must not exceed
  `MAX_TX_LEGACY_SIGOPS = 2500`.
- `bitcoin-core/src/policy/policy.cpp:214-263` —
  `ValidateInputsStandardness`: BIP-54 + per-input
  `MAX_P2SH_SIGOPS = 15` + `WITNESS_UNKNOWN` early-reject token
  `"bad-txns-nonstandard-inputs"`.
- `bitcoin-core/src/policy/policy.cpp:265-352` — `IsWitnessStandard`:
  P2A witness-stuffing, P2SH-wrapped redeem-script extraction, non-witness
  + witness rejection, P2WSH script/depth/item caps, P2TR annex +
  tapscript caps.
- `bitcoin-core/src/policy/policy.h:75-78, 119-132` — `DEFAULT_ANCESTOR_LIMIT`,
  `DEFAULT_DESCENDANT_LIMIT`, `STANDARD_SCRIPT_VERIFY_FLAGS` (14 bits:
  MANDATORY × 7 + STRICTENC + MINIMALDATA + DISCOURAGE_UPGRADABLE_NOPS +
  CLEANSTACK + MINIMALIF + NULLFAIL + LOW_S +
  DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM + WITNESS_PUBKEYTYPE +
  CONST_SCRIPTCODE + DISCOURAGE_UPGRADABLE_TAPROOT_VERSION +
  DISCOURAGE_OP_SUCCESS + DISCOURAGE_UPGRADABLE_PUBKEYTYPE).
- `bitcoin-core/src/policy/policy.h:84` —
  `MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR =
  100_000` bytes, gated by `-datacarrier`/`-datacarriersize`.
- `bitcoin-core/src/policy/policy.h:90` —
  `EXTRA_DESCENDANT_TX_SIZE_LIMIT = 10_000` for the CPFP carve-out.
- `bitcoin-core/src/policy/policy.h:95` — `MAX_DUST_OUTPUTS_PER_TX = 1`.
- `bitcoin-core/src/consensus/tx_check.cpp:15-56` — `CheckTransaction`
  wire-tokens: `bad-txns-vin-empty`, `bad-txns-vout-empty`,
  `bad-txns-oversize`, `bad-txns-vout-negative`,
  `bad-txns-vout-toolarge`, `bad-txns-txouttotal-toolarge`,
  `bad-txns-inputs-duplicate`, `bad-cb-length`, `bad-txns-prevout-null`.
- `bitcoin-core/src/consensus/tx_verify.cpp:164-200` —
  `Consensus::CheckTxInputs`: passes `nSpendHeight = chain.Height() + 1`
  (NOT `chain.Height()`!); wire-tokens
  `bad-txns-inputs-missingorspent`,
  `bad-txns-premature-spend-of-coinbase`,
  `bad-txns-inputvalues-outofrange`, `bad-txns-in-belowout`.
- `bitcoin-core/src/init.cpp:677-681` — `-datacarrier` (default true) +
  `-datacarriersize` (default 100_000); `-permitbaremultisig` (default
  true); `-bytespersigop` (default 20); `-minrelaytxfee` (default 1000);
  `-incrementalrelayfee` (default 1000); `-acceptnonstdtxn` (default
  false on mainnet, true on regtest/testnet); `-limitancestorcount` /
  `-limitancestorsize` / `-limitdescendantcount` / `-limitdescendantsize`.
- `bitcoin-core/src/rpc/protocol.h:47-49, 54-55` — three distinct
  sendrawtransaction error codes: `RPC_VERIFY_ERROR = -25`,
  `RPC_VERIFY_REJECTED = -26`, `RPC_VERIFY_ALREADY_IN_UTXO_SET = -27`.
- `bitcoin-core/src/rpc/util.cpp:391-401` —
  `RPCErrorFromTransactionError` distinguishes `MEMPOOL_REJECTED → -26`
  vs `ALREADY_IN_UTXO_SET → -27` vs default `-25`.

**Files audited**
- `internal/mempool/mempool.go` — `AcceptToMemoryPool` (line 886-888,
  alias), `AddTransaction` (line 899-1375) entry point + ATMP pipeline,
  `getStandardScriptFlags` (line 1531-1536), `getConsensusScriptFlags`
  (line 1548-1551), `validateScriptsLocked` (line 1555-1591), `isDust`
  (line 1439-1467), `isStandardOutputScript` (line 1480-1505),
  `isUnknownWitnessProgram` (line 1511-1526), `checkSequenceLocksLocked`
  (line 1676-1721), `checkChainLimitsWithSizeLocked` (line 1740-1851),
  `checkRBFLocked` (line 2746-2907), `BlockDisconnected` (line 2429-2441,
  reorg-readd path), `processOrphansLocked` (line 2331-2361),
  `AcceptPackage` / `acceptSingleTxPackage` / `acceptMultiTxPackage`
  (line 3363-…).
- `internal/mempool/witness_policy.go` — `isWitnessStandard` (line 74-195),
  `evalPushScriptToStack` (line 204-285).
- `internal/consensus/scriptflags.go` — `GetBlockScriptFlags` (line 15-63),
  `GetStandardScriptFlags` (line 71-84). Defines what bits each set
  enables; the production hot path for both PolicyScriptChecks and
  ConsensusScriptChecks.
- `internal/consensus/txvalidation.go` — `CheckTransactionSanity` (line
  58-128), `CheckTransactionInputs` (line 132-…), `ErrDuplicateInput`
  sentinel (line 19).
- `internal/consensus/params.go` — `MaxStandardTxSigOpsCost`,
  `MaxP2SHSigOpsPerInput`, `MaxTxLegacySigOps`, `DustRelayFeeRate`,
  `MinRelayTxFee` constants (line 107-131).
- `internal/wire/types.go:220-225` — `MsgTx.Version` field type
  (`int32`, NOT Core's `uint32_t` since PR #29796 — W132 carry-forward).
- `internal/rpc/methods.go:972-1067` — `handleSendRawTransaction`:
  collapses every reject to `RPCErrVerify=-25`.
- `internal/rpc/wallet_methods.go:131-133`,
  `internal/rpc/multiwallet_methods.go:378-380`,
  `internal/rpc/bumpfee_methods.go:72-75`,
  `internal/rpc/payjoin_sender.go:243-247` — four additional
  in-process callers of `AcceptToMemoryPool`.
- `cmd/blockbrew/main.go:445-496` (flag parsing — note absence),
  `cmd/blockbrew/main.go:1139-1160` (`syncListeners.OnTx` — P2P
  entry-point), `cmd/blockbrew/main.go:815-828` (mempool wiring).

---

## Gate matrix (38 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | ATMP entry point + pipeline ordering | G1: `AcceptToMemoryPool` alias of `AddTransaction` | PASS (`mempool.go:886-888`) |
| 1 | … | G2: cheap-checks-first ordering matches Core | PARTIAL — order is broadly faithful (sanity → coinbase → version → weight → tx-size-small → scriptSig → outputs → IsFinalTx → sigops → inputs → fee → dust → witness → BIP-68 → chain limits → TRUC → scripts) |
| 2 | `CheckTransaction` wire tokens | G3: `bad-txns-vin-empty` token | **BUG-1 (P1)** — `ErrNoInputs = "transaction has no inputs"`, not `bad-txns-vin-empty` |
| 2 | … | G4: `bad-txns-vout-empty` token | **BUG-1 cross-cite** — `ErrNoOutputs = "transaction has no outputs"` |
| 2 | … | G5: `bad-txns-inputs-duplicate` token | **BUG-1 cross-cite** — `ErrDuplicateInput = "transaction contains duplicate inputs"` |
| 2 | … | G6: `bad-txns-oversize` token | **BUG-1 cross-cite** — `ErrOversizedTx = "transaction exceeds maximum weight"` |
| 2 | … | G7: `bad-txns-prevout-null` token | **BUG-1 cross-cite** — `ErrNullInput = "non-coinbase transaction has null input"` |
| 2 | … | G8: `bad-cb-length` token (coinbase scriptSig 2-100) | **BUG-1 cross-cite** — `ErrCoinbaseScriptSize = "coinbase script size out of range"` |
| 3 | `tx-size-small` floor (CVE-2017-12842) | G9: 65-byte non-witness minimum enforced | PASS (`mempool.go:947-955`) |
| 3 | … | G10: reject-token matches Core `"tx-size-small"` | **BUG-1 cross-cite** — `ErrTxTooSmall = "transaction non-witness size below minimum (65 bytes)"` |
| 4 | `IsStandardTx` policy gates | G11: TX_MIN/MAX_STANDARD_VERSION enforced | PASS (`mempool.go:933-939`) — but **BUG-2** below: `tx.Version` is `int32` not Core's `uint32_t` (W132 carry-forward) |
| 4 | … | G12: `MAX_STANDARD_SCRIPTSIG_SIZE=1650` | PASS (`mempool.go:967-970`) |
| 4 | … | G13: scriptSig push-only | PASS (`mempool.go:971-973`) |
| 4 | … | G14: bare-multisig output type rejected when `!permit_bare_multisig` | **BUG-3 (P1)** — bare multisig is NEITHER classified as standard NOR rejected (`isStandardOutputScript` line 1480 does not consider `consensus.IsMultisig`), and the `-permitbaremultisig` knob does not exist. Core REJECTS bare multisig by default; blockbrew rejects it as "nonstandard output" via the `default` arm. Net effect is similar but the knob is gone |
| 4 | … | G15: `GetDust` returns ALL dust outputs; `MAX_DUST_OUTPUTS_PER_TX=1` enforced | **BUG-4 (P0-CDIV)** — blockbrew's dust check (`mempool.go:1214-1229`) loops over outputs and rejects on the FIRST dust output when `fee != 0`. There is no `MAX_DUST_OUTPUTS_PER_TX` cap when `fee == 0` (Core allows EXACTLY 1 ephemeral-dust output at zero fee; blockbrew allows UNLIMITED). A 0-fee tx with 100 dust outputs (each 1-sat OP_RETURN dust analogue) passes blockbrew's gate but Core rejects |
| 4 | … | G16: `-datacarrier` operator-knob (default true) | **BUG-5 (P1)** — there is no `-datacarrier` flag at all. OP_RETURN outputs are ALWAYS relayed; operators cannot disable nulldata relay |
| 4 | … | G17: `-datacarriersize` operator-knob (default 100_000) | **BUG-5 cross-cite** — `MaxOpReturnRelay = 100_000` is hard-coded in `mempool.go:252`; no CLI override |
| 5 | Dust math (DUST_RELAY_TX_FEE) | G18: dust threshold uses `DUST_RELAY_TX_FEE = 3000`, NOT min-relay 1000 | **BUG-6 (P0-CDIV)** — `mempool.go:1465`: `dustThreshold := spendingSize * mp.config.MinRelayFeeRate / 1000` — uses `MinRelayFeeRate` (default 1000), not `DustRelayFeeRate` (Core default 3000). Result: dust threshold is 1/3 of Core's. A 200-sat P2PKH output Core rejects as dust passes blockbrew; mempool fills with low-relay-cost dust that Core peers refuse to forward |
| 5 | … | G19: spending-size accounts for the OUTPUT size + the input cost | **BUG-7 (P1)** — blockbrew computes only the input spending size (148 / 68 / 58), not the **output serialized size + input size** Core uses (`GetSerializeSize(txout)` + input cost). Misses ~31-34 bytes of cost per output → underestimates the dust threshold further |
| 5 | … | G20: `IsUnspendable` (OP_RETURN, empty) short-circuits to 0 | PASS (`mempool.go:1442-1444`) |
| 5 | … | G21: P2A `AnchorDust=240` cap is a blockbrew invention (cross-cite W135 BUG-5) | **BUG-8 (P1)** — `mempool.go:1449-1451` AnchorDust cap is not in Core; P2A is a 4-byte scriptPubKey, GetDustThreshold computes its 240-sat threshold naturally. The hardcoded cap rejects P2A outputs Core would accept |
| 6 | `Consensus::CheckTxInputs` semantics | G22: coinbase maturity uses `nSpendHeight = chain.Height() + 1` | **BUG-9 (P0-CDIV off-by-one)** — `mempool.go:1118-1126` uses `tipHeight = ChainState.TipHeight()` (NOT `+1`). Core uses `tip+1` because the mempool holds txs for the NEXT block. Result: a coinbase output at height `H`, with chain tip `H+99`, would be accepted by blockbrew (`100 == COINBASE_MATURITY` passes `< 100` check as false) at tip `H+99` (depth 99 in blockbrew's math → reject), but Core uses `nSpendHeight = H+100` so depth is `100 == COINBASE_MATURITY` (NOT `< 100`, passes). At tip `H+98`, both reject. Net effect: blockbrew rejects mature coinbase one block earlier than Core — a tx using a `H`-coinbase, evaluated at tip `H+99`, passes Core but fails blockbrew |
| 6 | … | G23: `bad-txns-premature-spend-of-coinbase` token | **BUG-1 cross-cite** — `ErrImmatureCoinbaseSpend = "immature coinbase spend: output does not have enough confirmations"` |
| 6 | … | G24: per-input MoneyRange + accumulated MoneyRange | PASS (`mempool.go:1133-1144`) |
| 6 | … | G25: `bad-txns-inputvalues-outofrange` token | PARTIAL — wire string IS emitted (`mempool.go:1134, 1142`) but only via raw `fmt.Errorf`, NOT a sentinel; callers cannot `errors.Is` |
| 6 | … | G26: `bad-txns-in-belowout` token (negative fee) | **BUG-1 cross-cite** — `ErrNegativeFee = "transaction fee is negative"`, not `"bad-txns-in-belowout"` |
| 7 | PolicyScriptChecks (PolicyScriptChecks → STANDARD flags) | G27: `STANDARD_SCRIPT_VERIFY_FLAGS` matches Core's 14-bit set | **BUG-10 (P1, carry-forward W144 BUG-5)** — `consensus/scriptflags.go:71-84` adds ONLY STRICTENC + NULLFAIL + WITNESS_PUBKEYTYPE on top of consensus flags. Missing 9 of 13 Core STANDARD bits: MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, MINIMALIF, LOW_S, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE |
| 7 | … | G28: STANDARD-pass + CONSENSUS-pass two-pass split exists | PASS (`mempool.go:1294-1307`) — `validateScriptsLocked` runs at STANDARD flags, then re-runs at CONSENSUS flags only if they differ |
| 7 | … | G29: STANDARD-fail token `"mempool-script-verify-flag-failed (<name>)"` | **BUG-1 cross-cite** — `ErrScriptValidation = "script validation failed"` wrapped with inner error; no per-flag mnemonic |
| 7 | … | G30: CONSENSUS-fail token `"block-script-verify-flag-failed (<name>)"` | **BUG-1 cross-cite** — `ErrTxConsensus` wrapped, no per-flag mnemonic |
| 7 | … | G31: skip second pass when flags coincide | PASS (`mempool.go:1299`) |
| 8 | `bypass_limits` + `m_package_feerates` semantics | G32: reorg-readd skips fee gate + TRUC | **BUG-11 (P1)** — `BlockDisconnected` at `mempool.go:2429-2441` simply calls `mp.AddTransaction(tx)` per non-coinbase tx, with NO bypass_limits equivalent. Core sets `bypass_limits=true` for reorg-readd so the txs that were valid in the (now-disconnected) block are not re-rejected for falling below the current mempool min feerate. blockbrew's reorg readd will lose any tx whose feerate is below the rolling min |
| 8 | … | G33: package validation skips per-tx fee gate when feerate eval is package-aggregate | PARTIAL — package path exists (`AcceptPackage`) but the per-tx fee gate at `mempool.go:1194-1200` is NOT bypassed when called from the package path; only the package-aggregate path checks aggregate feerate separately |
| 9 | RBF / replacement | G34: `bip125-replacement-disallowed` token when caller forbids replacement | **BUG-12 (P1)** — there is no equivalent `m_allow_replacement` switch. Every ATMP path on a conflict either runs RBF (`checkRBFLocked`) or rejects with `ErrDoubleSpend`. The `-walletrbf` / per-package "no replacement" gate has no analogue |
| 9 | … | G35: `-mempoolfullrbf` plumbed | PASS (cfg.MempoolFullRBF, fix-68) |
| 10 | Sigops gates | G36: `MAX_STANDARD_TX_SIGOPS_COST = 16_000` | PASS (`mempool.go:1027-1034`) |
| 10 | … | G37: per-P2SH-input `MAX_P2SH_SIGOPS = 15` | PASS (`mempool.go:1041-1058`) |
| 10 | … | G38: `MAX_TX_LEGACY_SIGOPS = 2500` (BIP-54) | PASS (`mempool.go:1064-1086`) |
| 11 | sendrawtransaction error mapping | G39: `MEMPOOL_REJECTED → RPC_VERIFY_REJECTED=-26` | **BUG-13 (P1)** — `internal/rpc/methods.go:1037`: `RPCErrVerify=-25` for every ATMP reject. Core distinguishes -25 (verify error) from -26 (network-rule reject) from -27 (already-in-utxo-set) |
| 11 | … | G40: `ALREADY_IN_UTXO_SET → RPC_VERIFY_ALREADY_IN_UTXO_SET=-27` | **BUG-13 cross-cite** |

---

## BUG-1 (P1) — Reject-token wire-string parity slippage (fleet pattern, 9-token sweep)

**Severity:** P1 ("reject-string wire-parity slippage" fleet pattern,
~10th distinct blockbrew instance per W125/W148 tracking).

Bitcoin Core's ATMP and CheckTransaction emit a stable, well-known set
of `bad-txns-…` / `bad-cb-…` tokens that monitoring tools, mempool
graphers, P2P fingerprinters, mempool replay harnesses, and other Bitcoin
implementations key off. blockbrew's ATMP path returns Go error sentinels
whose `.Error()` strings are English prose and do NOT contain the Core
token. Both layers are observable by external callers: the prose form
leaks through `sendrawtransaction` as the "Transaction rejected: …"
suffix.

Token-by-token table:

| Core token | blockbrew sentinel | Site |
|------------|--------------------|------|
| `bad-txns-vin-empty` | `ErrNoInputs = "transaction has no inputs"` | `consensus/txvalidation.go:13` |
| `bad-txns-vout-empty` | `ErrNoOutputs = "transaction has no outputs"` | `consensus/txvalidation.go:14` |
| `bad-txns-inputs-duplicate` | `ErrDuplicateInput = "transaction contains duplicate inputs"` | `consensus/txvalidation.go:19` |
| `bad-txns-oversize` | `ErrOversizedTx = "transaction exceeds maximum weight"` | `consensus/txvalidation.go:15` |
| `bad-txns-prevout-null` | `ErrNullInput = "non-coinbase transaction has null input"` | `consensus/txvalidation.go:21` |
| `bad-cb-length` | `ErrCoinbaseScriptSize = "coinbase script size out of range"` | `consensus/txvalidation.go:20` |
| `bad-txns-vout-negative` | `ErrNegativeOutput = "transaction output value is negative"` | `consensus/txvalidation.go:16` |
| `bad-txns-vout-toolarge` | `ErrOutputTooLarge = "transaction output value exceeds max money"` | `consensus/txvalidation.go:17` |
| `bad-txns-txouttotal-toolarge` | `ErrTotalOutputTooLarge = "total transaction output exceeds max money"` | `consensus/txvalidation.go:18` |
| `tx-size-small` | `ErrTxTooSmall = "transaction non-witness size below minimum (65 bytes)"` | `mempool/mempool.go:43` |
| `bad-txns-premature-spend-of-coinbase` | `ErrImmatureCoinbaseSpend = "immature coinbase spend: output does not have enough confirmations"` | `mempool/mempool.go:104` |
| `bad-txns-in-belowout` | `ErrNegativeFee = "transaction fee is negative"` | `mempool/mempool.go:50` |
| `bad-txns-inputs-missingorspent` | `ErrMissingInputs = "transaction references missing inputs"` | `mempool/mempool.go:49` |
| `mempool-script-verify-flag-failed (<name>)` | `ErrScriptValidation = "script validation failed"` | `mempool/mempool.go:53` |
| `block-script-verify-flag-failed (<name>)` | `ErrTxConsensus` | `mempool/mempool.go:180` |
| `bad-txns-too-many-sigops` | `ErrTxSigOpsCostTooHigh = "transaction sigops cost exceeds maximum standard limit (16000)"` | `mempool/mempool.go:112` |

**File:** `internal/consensus/txvalidation.go:13-30`,
`internal/mempool/mempool.go:40-180`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:15-56`,
`bitcoin-core/src/validation.cpp:802-866, 942, 2120-2122`.

**Impact:**
- Cross-impl monitoring breaks. Tooling that parses
  `sendrawtransaction` errors to classify rejects (e.g. mempool
  observers, electrs/fulcrum diagnostic loops, miner relay debugging)
  needs to maintain per-impl mappings.
- Bitcoin Core peer parity: when blockbrew rejects a tx on policy
  grounds, the operator who needs to compare blockbrew's reject reason
  against `bitcoin-cli sendrawtransaction` sees different strings and
  cannot eyeball the divergence.
- "Reject-string wire-parity slippage" fleet pattern, ~10th distinct
  blockbrew instance.

---

## BUG-2 (P1) — `tx.Version` is `int32` not `uint32` (W132 BUG-1 carry-forward)

**Severity:** P1 (W132 carry-forward, ~3 weeks open). Bitcoin Core
since PR #29796 stores `nVersion` as `uint32_t`
(`bitcoin-core/src/primitives/transaction.h:185, 191, 293, 361`).
blockbrew still uses `int32` (`internal/wire/types.go:221`). The
standardness check at `mempool/mempool.go:933-939` compares
`tx.Version < TxMinStandardVersion || tx.Version > TxMaxStandardVersion`.
With `int32`, the raw wire bytes `0xff 0xff 0xff 0xff` parse to
`tx.Version = -1` — which fails the `< 1` arm and is rejected as
"version out of standard range". Core, with `uint32`, parses the
same bytes to `4294967295`, fails the `> 3` arm, ALSO rejects.

**Result-equivalent for standardness**, but the underlying TYPE matters
for any consensus comparison site that does arithmetic on `tx.Version`:

- BIP-68 sequence-lock gate at `mempool/mempool.go:1681`:
  `if tx.Version < 2 { return nil }` — with `int32`, a wire-byte
  `tx.Version = -1` is treated as < 2 and skips BIP-68. With `uint32`,
  same bytes parse to `4294967295` and BIP-68 IS evaluated. This is the
  W132 P0-CDIV "bit-31 inversion" failure mode applied to mempool acceptance.
- TRUC policy at `mempool/truc_policy.go` (not audited here) similarly
  compares `tx.Version == 3` — depends on whether int32-vs-uint32
  matters at the exact value, but the TYPE mismatch is the carry.

**File:** `internal/wire/types.go:221` (struct), `internal/mempool/mempool.go:936, 1681`.

**Core ref:** `bitcoin-core/src/primitives/transaction.h:293`.

**Impact:** W132 BUG-1 carry-forward, now ~3 weeks open.
W132 already flagged the consensus-side path (1-line fix); this audit
records the mempool-side observable.

---

## BUG-3 (P1) — Bare multisig: no `-permitbaremultisig` knob; classification missing

**Severity:** P1. Bitcoin Core's `IsStandardTx` at
`policy.cpp:152-154` classifies a MULTISIG scriptPubKey (1-of-N or m-of-N
bare multisig) and, when `permit_bare_multisig` is false, rejects with
token `"bare-multisig"`. The `-permitbaremultisig` CLI flag controls this
gate (default `true` for Core 27+; some forks ship it false).

blockbrew's `isStandardOutputScript` (`mempool/mempool.go:1480-1505`)
does NOT enumerate multisig as a distinct branch. A 1-of-1 or 2-of-3
bare multisig scriptPubKey falls through to the `default` arm: if it's
not a witness program, it's rejected as nonstandard output. So bare
multisig is implicitly REJECTED by blockbrew always — but:
1. No `-permitbaremultisig` operator-knob exists to re-enable it.
2. The reject token is `ErrNonStandardOutput = "nonstandard output script"`,
   NOT Core's `"bare-multisig"` (cross-cite BUG-1).
3. blockbrew has NO check on the `m`/`n` bounds Core enforces for
   "standard" multisig (`n < 1 || n > 3`, `m < 1 || m > n`).

**File:** `internal/mempool/mempool.go:1480-1505` (no MULTISIG branch);
`cmd/blockbrew/main.go:445-496` (no `-permitbaremultisig` flag).

**Core ref:** `bitcoin-core/src/policy/policy.cpp:80-98` (`IsStandard`
multisig classification + m-of-n bounds);
`bitcoin-core/src/policy/policy.cpp:152-154` (bare-multisig reject).

**Impact:**
- No operator path to relay/mine bare multisig (relevant for legacy
  applications and some atomic swap tools).
- Cross-impl divergence: Core operators with `-permitbaremultisig=true`
  (default) can relay bare multisig; blockbrew never can.

---

## BUG-4 (P0-CDIV) — `MAX_DUST_OUTPUTS_PER_TX=1` cap absent: 0-fee tx may have unbounded dust outputs

**Severity:** P0-CDIV. Bitcoin Core's `IsStandardTx` at
`policy.cpp:158-162` counts the total number of dust outputs via
`GetDust(tx, dust_relay_fee)` and rejects if
`> MAX_DUST_OUTPUTS_PER_TX (=1)`. Critically, **this cap is enforced
for ALL transactions, including 0-fee** — Core's ephemeral-anchor
exception permits exactly ONE dust output at 0 fee, not more.

blockbrew's dust check at `mempool/mempool.go:1214-1229` is a
single-pass loop:

```go
for i, out := range tx.TxOut {
    if !mp.isDust(out) {
        continue
    }
    if fee == 0 {
        // Ephemeral anchor / 0-fee CPFP carrier: dust is permitted.
        continue   // <-- SKIPS rather than counting
    }
    return fmt.Errorf("%w (%w): output %d value %d", ...)
}
```

When `fee == 0`, the loop `continue`s on EVERY dust output without
maintaining a count. A 0-fee transaction with 100 dust outputs (e.g.,
100 P2WPKH outputs at 1 satoshi each) is ACCEPTED by blockbrew. Core
rejects all but the first.

**Failure scenarios:**
- Mempool DoS: an attacker submits a 0-fee tx with 1000 dust outputs.
  blockbrew accepts; Core rejects. blockbrew's mempool is now polluted
  with a "no-fee, unbounded-output" tx that can only be CPFP'd by a
  child that pays for the entire stuffing. The cluster carries dead
  weight.
- Cross-relay split: blockbrew advertises the tx via inv; Core peers
  request it and reject ("dust"); blockbrew's mempool retains it; Core
  peers do not.
- BIP-431 TRUC sibling-eviction interaction: an ephemeral-anchor TRUC
  tx with 50 dust outputs is accepted; the TRUC child is rejected
  because the parent's effective feerate (post-CPFP) cannot cover 50
  dust outputs' relay cost.

**File:** `internal/mempool/mempool.go:1214-1229`.

**Core ref:** `bitcoin-core/src/policy/policy.cpp:158-162` (GetDust count),
`bitcoin-core/src/policy/policy.h:95` (`MAX_DUST_OUTPUTS_PER_TX = 1`).

**Excerpt (blockbrew, missing count + cap)**
```go
for i, out := range tx.TxOut {
    if !mp.isDust(out) {
        continue
    }
    if fee == 0 {
        // Ephemeral anchor / 0-fee CPFP carrier: dust is permitted.
        continue   // <-- MISSING: counter++, then check counter > MAX_DUST_OUTPUTS_PER_TX
    }
    return fmt.Errorf("%w (%w): output %d value %d", ...)
}
```

**Impact:** P0-CDIV — mempool acceptance divergence. blockbrew accepts
0-fee txs with >1 dust output; Core rejects them. Cross-impl relay
break + mempool DoS surface.

---

## BUG-5 (P1) — No `-datacarrier` / `-datacarriersize` operator-knob; cap is hard-coded

**Severity:** P1 ("operator-knob absence" fleet pattern). Bitcoin Core's
`-datacarrier` (default `true`) controls whether nulldata outputs are
relayed at all. `-datacarriersize` (default `MAX_OP_RETURN_RELAY =
100_000`) sets the per-tx cumulative budget. Together they let
operators (a) disable nulldata relay entirely, (b) raise/lower the
budget for testing / mining pool policy.

blockbrew has neither flag. `MaxOpReturnRelay = 100_000`
(`mempool.go:252`) is hard-coded. OP_RETURN outputs are always
relayed. The budget is enforced (`mempool.go:992-998`) but not
configurable.

**File:** `internal/mempool/mempool.go:252, 992-998`;
`cmd/blockbrew/main.go:445-496` (no flags).

**Core ref:** `bitcoin-core/src/init.cpp:677-681`.

**Impact:** operator-knob absence. Mining pools and relay-policy
experimenters cannot disable OP_RETURN relay or tune the budget. Cross-impl
divergence on policy knobs.

---

## BUG-6 (P0-CDIV) — Dust math uses `MinRelayFeeRate` instead of `DustRelayFeeRate` (3x undercount)

**Severity:** P0-CDIV. Bitcoin Core's `GetDustThreshold`
(`policy.cpp:27-64`) takes a `CFeeRate dustRelayFeeIn` parameter that
defaults to `DUST_RELAY_TX_FEE = 3000 sat/kvB`. This is INTENTIONALLY
HIGHER than `min_relay_feerate` (1000 sat/kvB default) — Core does
not want to relay outputs that are too small to be economically
spendable at the relay-floor feerate, with a 3x safety factor.

blockbrew's `isDust` (`mempool/mempool.go:1465`):

```go
dustThreshold := spendingSize * mp.config.MinRelayFeeRate / 1000
```

uses `MinRelayFeeRate` (default 1000), NOT a separate dust rate. The
threshold is therefore 1/3 of Core's. Consequence:

- A 200-sat P2PKH output: Core dust threshold ≈ 546 sat (uses dust
  rate 3000, 182 byte cost) → REJECT. blockbrew threshold ≈ 148 sat
  (uses relay rate 1000) → ACCEPT.
- A 100-sat P2WPKH output: Core threshold ≈ 294 sat → REJECT.
  blockbrew threshold ≈ 68 sat → ACCEPT.

**File:** `internal/mempool/mempool.go:1465`.

**Core ref:** `bitcoin-core/src/policy/policy.cpp:27-64, 66-69`;
`bitcoin-core/src/policy/policy.h` (`DUST_RELAY_TX_FEE = 3000`).

**Excerpt (blockbrew, wrong fee rate)**
```go
// CURRENT (wrong):
dustThreshold := spendingSize * mp.config.MinRelayFeeRate / 1000
// CORE-EQUIVALENT:
//   dustThreshold := spendingSize * mp.config.DustRelayFeeRate / 1000
// where DustRelayFeeRate defaults to consensus.DustRelayFeeRate = 3000
// (which is in fact defined in internal/consensus/params.go:128 but
//  never read here).
```

Note the comedy: blockbrew DEFINES `consensus.DustRelayFeeRate = 3000`
in `internal/consensus/params.go:128`, with the exact Core comment
"fee rate below which outputs are considered dust (3000 sat/kvB)" —
but never USES it. The mempool reads `MinRelayFeeRate` instead.
**"Dead-data plumbing" fleet pattern**, ~11th distinct blockbrew
instance: the constant is defined, named, commented to Core parity,
and never read at the one site that needs it.

**Impact:** P0-CDIV mempool acceptance divergence. blockbrew's mempool
accepts outputs Core peers reject. Cross-impl relay split for outputs
in the (Core-dust ≈ 546 .. blockbrew-dust ≈ 148) window. Mempool fills
with sub-economic outputs that Core peers refuse to forward.

---

## BUG-7 (P1) — Dust math omits output serialized size

**Severity:** P1. Bitcoin Core's `GetDustThreshold` at `policy.cpp:46`:

```cpp
uint64_t nSize{GetSerializeSize(txout)};  // <-- INCLUDES the output itself
// ... then adds input cost:
if (txout.scriptPubKey.IsWitnessProgram(...)) {
    nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);
} else {
    nSize += (32 + 4 + 1 + 107 + 4); // the 148 mentioned above
}
return dustRelayFeeIn.GetFee(nSize);
```

The threshold accounts for BOTH the output's serialized size (~31-34
bytes for typical outputs) AND the input cost to spend it. blockbrew
(`mempool/mempool.go:1454-1466`) accounts ONLY for the input cost (148
/ 68 / 58), missing the output side. The result is an additional
~30-byte undercount on top of the 3x fee-rate undercount (BUG-6).

**File:** `internal/mempool/mempool.go:1453-1466`.

**Core ref:** `bitcoin-core/src/policy/policy.cpp:46-62`.

**Impact:** another layer of dust-acceptance divergence. Stacks with
BUG-6 to make blockbrew's effective dust threshold roughly 1/4 of
Core's.

---

## BUG-8 (P1) — `AnchorDust=240` P2A cap is a blockbrew invention not present in Core

**Severity:** P1 (cross-cite W135 BUG-5, on isDust). Core treats P2A
(BIP-431 ephemeral anchor) as a 4-byte scriptPubKey. `GetDustThreshold`
computes its threshold via the normal flow:
`(GetSerializeSize(txout) + input cost) * dust_relay_fee / 1000`.
Result ≈ 240 sat at default dust rate 3000 sat/kvB.

blockbrew hardcodes a cap (`mempool/mempool.go:1449-1451`):

```go
if consensus.IsPayToAnchor(txOut.PkScript) {
    return txOut.Value > AnchorDust // P2A is only standard if value <= AnchorDust
}
```

Note the INVERTED predicate: `txOut.Value > AnchorDust` returns TRUE
("is dust") when the value is HIGHER than AnchorDust. Core does the
opposite: a P2A with value HIGHER than the dust threshold passes the
dust check unchanged. blockbrew REJECTS a P2A output with value 1000
sat as nonstandard via the dust gate; Core accepts it (1000 > 240
threshold means NOT dust).

**File:** `internal/mempool/mempool.go:1449-1451`.

**Core ref:** none — Core does not special-case P2A in dust math.

**Impact:** P2A outputs with non-anchor-sized value rejected as
nonstandard. Cross-impl divergence on ephemeral-anchor relay.

---

## BUG-9 (P0-CDIV) — Coinbase maturity uses `tipHeight` instead of `tipHeight + 1`

**Severity:** P0-CDIV off-by-one. Bitcoin Core's `Consensus::CheckTxInputs`
(`tx_verify.cpp:164-200`) is called from `MemPoolAccept::PreChecks` at
`validation.cpp:892` with `nSpendHeight = m_active_chainstate.m_chain.Height() + 1`
— because the mempool holds txs for the NEXT block. The maturity check
at `tx_verify.cpp:179`:

```cpp
if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY)
```

evaluates depth against `tip + 1`.

blockbrew's maturity check at `mempool/mempool.go:1118-1126`:

```go
if utxo.IsCoinbase {
    if mp.config.ChainState != nil {
        tipHeight := mp.config.ChainState.TipHeight()  // <-- TipHeight(), NOT TipHeight()+1
        age := tipHeight - utxo.Height
        if age < consensus.CoinbaseMaturity {
            return fmt.Errorf("%w: age %d < %d required",
                ErrImmatureCoinbaseSpend, age, consensus.CoinbaseMaturity)
        }
    }
}
```

uses `tipHeight = ChainState.TipHeight()` (no `+1`).

**Failure mode:** a coinbase at height `H`, spent in a tx submitted to
the mempool when chain tip is `H+99`:
- Core: `nSpendHeight = H+100`, `nSpendHeight - coin.nHeight = 100`,
  `100 < 100` is false → ACCEPT.
- blockbrew: `tipHeight - utxo.Height = 99`, `99 < 100` is true →
  REJECT with `ErrImmatureCoinbaseSpend`.

blockbrew rejects mature coinbase ONE BLOCK EARLIER than Core. A tx
that Core's mempool accepts is rejected by blockbrew's. The tx becomes
valid on blockbrew only at tip `H+100` (one block later than Core).

Edge cases: this is the classic ATMP off-by-one. The consensus-side
`Consensus::CheckTxInputs` (in `internal/consensus/txvalidation.go:148-155`)
correctly takes a `txHeight int32` parameter and computes
`confirmations := txHeight - utxo.Height`; the callers ARE responsible
for passing tip+1 in ATMP context. Searching for the consensus call:

```go
// internal/consensus/txvalidation.go:148-155 — consensus-side correct
// but only used by block-connect path which passes the block's own height.
// MEMPOOL path does its OWN maturity check at mempool.go:1118-1126
// and forgets the +1.
```

The check is duplicated — once in consensus, once in mempool — and the
mempool copy gets the offset wrong. **"Two-pipeline guard" fleet
pattern**, ~17th distinct blockbrew instance.

**File:** `internal/mempool/mempool.go:1118-1126`.

**Core ref:** `bitcoin-core/src/validation.cpp:892` (call site with
`+1`), `bitcoin-core/src/consensus/tx_verify.cpp:179` (depth check).

**Impact:**
- One-block delay before a coinbase becomes spendable in blockbrew's
  mempool, compared to Core.
- Cross-impl relay split: a tx using a just-matured coinbase, accepted
  by Core, fails to enter blockbrew's mempool. Wallets that use blockbrew
  as a backend report "ATMP rejected: immature" while Core wallets
  accept the same tx.
- Miners using blockbrew see lower coinbase-driven mempool throughput.

---

## BUG-10 (P1) — `GetStandardScriptFlags` missing 9 of 13 Core STANDARD bits (W144 BUG-5 carry-forward)

**Severity:** P1 (W144 BUG-5 carry-forward, ~3 days open). Bitcoin
Core's `STANDARD_SCRIPT_VERIFY_FLAGS` (`policy/policy.h:119-132`)
adds 13 policy-only bits on top of the 7 MANDATORY bits. blockbrew's
`GetStandardScriptFlags` (`consensus/scriptflags.go:71-84`) adds only
3 of the 13:

| Core STANDARD bit | blockbrew |
|-------------------|-----------|
| SCRIPT_VERIFY_STRICTENC | ✓ (gated on BIP66Height — see W144 BUG-13: Core treats as always-on policy) |
| SCRIPT_VERIFY_NULLFAIL | ✓ (gated on SegwitHeight) |
| SCRIPT_VERIFY_WITNESS_PUBKEYTYPE | ✓ (gated on SegwitHeight) |
| SCRIPT_VERIFY_MINIMALDATA | **MISSING** |
| SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS | **MISSING** |
| SCRIPT_VERIFY_CLEANSTACK | **MISSING** |
| SCRIPT_VERIFY_MINIMALIF | **MISSING** |
| SCRIPT_VERIFY_LOW_S | **MISSING** |
| SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM | **MISSING** |
| SCRIPT_VERIFY_CONST_SCRIPTCODE | **MISSING** |
| SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION | **MISSING** |
| SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS | **MISSING** |
| SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE | **MISSING** |

This is precisely what the W144 audit caught for blockbrew (BUG-5).
The mempool/ATMP context here is the SECOND failure surface: missing
STANDARD bits at PolicyScriptChecks means blockbrew's mempool will
ACCEPT transactions that Core's mempool REJECTS as nonstandard:

- A tx with a non-minimal push (`0x01 0x00` instead of `OP_0`) Core
  rejects via SCRIPT_VERIFY_MINIMALDATA; blockbrew accepts.
- A tx with extra stack data after script execution Core rejects via
  CLEANSTACK; blockbrew accepts.
- A tx using an upgradeable NOP (OP_NOP4-10) Core rejects via
  DISCOURAGE_UPGRADABLE_NOPS; blockbrew accepts.
- A tx using a high-S signature Core rejects via LOW_S; blockbrew accepts.

The relay-split is one-directional: blockbrew accepts a strict superset
of what Core accepts. Cross-impl mempool divergence: blockbrew's mempool
fills with non-standard-by-Core txs that Core peers reject.

**File:** `internal/consensus/scriptflags.go:71-84`.

**Core ref:** `bitcoin-core/src/policy/policy.h:119-132`,
`bitcoin-core/CORE-PARITY-AUDIT/w144-script-verify-flags.md` BUG-5.

**Impact:** carry-forward from W144 (~3 days open). The W144 audit
recorded the issue at the script-engine-flags layer; this audit records
the policy-acceptance observable: blockbrew's mempool admits ~9
classes of non-standard tx that Core's mempool refuses.

---

## BUG-11 (P1) — `BlockDisconnected` reorg-readd calls `AddTransaction` without `bypass_limits` semantics

**Severity:** P1. Bitcoin Core's reorg-disconnect path
(`validation.cpp:315`) re-submits the disconnected block's transactions
through `MempoolAccept` with `bypass_limits=true`. This bypasses
several mempool-only gates:

- The min-relay-fee gate (`validation.cpp:948`): `if (!bypass_limits
  && !args.m_package_feerates && !CheckFeeRate(…)) return false;`
- The TRUC checks (`validation.cpp:954-969`): `if (!args.m_bypass_limits) { … SingleTRUCChecks(…); }`
- The ancestor/descendant chain-limit gate (`Workspace::PolicyChecks`,
  not audited here but the rationale is "re-add what was valid in a
  block, even if it now breaks ancestor counts after the reorg
  shuffle").

This is necessary because txs that were validly mined in the now-disconnected
block must remain mempool-eligible regardless of the current rolling
fee or chain-position constraints — otherwise a reorg can permanently
evict txs that were trivially valid.

blockbrew's `BlockDisconnected` at `mempool/mempool.go:2429-2441`:

```go
func (mp *Mempool) BlockDisconnected(block *wire.MsgBlock) {
    mp.mu.Lock()
    mp.chainHeight--
    mp.mu.Unlock()

    // Re-add transactions from the disconnected block (skip coinbase)
    for i, tx := range block.Transactions {
        if i == 0 {
            continue // Skip coinbase
        }
        _ = mp.AddTransaction(tx) // Ignore errors
    }
}
```

calls `AddTransaction` with NO bypass_limits equivalent. Every reorg-readd
goes through the full pipeline:
- The fee gate at `mempool.go:1196-1200`: a reorg that bumps the
  rolling fee will REJECT a reorg-readd of a low-fee tx.
- The TRUC check at `mempool.go:1267-1272`: a TRUC tx whose parent
  was in the disconnected block but is also re-added in the same
  loop may transiently fail until the parent re-enters; the simple
  in-order `for i, tx := range` loop does not guarantee parent-first
  ordering after the topology shuffle.
- Chain limits at `mempool.go:1256-1258`: the reorg-readd may
  temporarily violate ancestor/descendant counts during the in-order
  re-add.

The `_ = mp.AddTransaction(tx)` discards the error, so failures are
silent. There is no log line. Operators tracking mempool size after a
reorg see fewer txs than expected without explanation.

**File:** `internal/mempool/mempool.go:2429-2441`.

**Core ref:** `bitcoin-core/src/validation.cpp:315` (call site with
`bypass_limits=true`), `validation.cpp:948, 954-969` (bypass-limits
checks).

**Impact:**
- Reorg silently loses txs that Core preserves.
- Cross-impl divergence on reorg-readd: a blockbrew node and a Core
  node with the same mempool snapshot, hit by the same reorg, end up
  with different mempools.
- TRUC re-add ordering bug: parent/child ordering in the disconnected
  block may not survive re-add because the parent tx might be
  rejected (e.g., temporarily because the next non-coinbase tx is the
  child and is processed before its parent re-enters), then the child
  re-add fails too.

---

## BUG-12 (P1) — No `m_allow_replacement` switch for "no-RBF" ATMP context

**Severity:** P1. Bitcoin Core's `ATMPArgs` has
`m_allow_replacement` (`validation.cpp:447, 838-839`) which, when
false, makes any conflict reject with token
`"bip125-replacement-disallowed"` instead of running ReplacementChecks.
This is used in contexts where the caller specifically does NOT want
to evict mempool entries — e.g., package validation when the package
itself is a replacement and a sub-tx must not separately trigger RBF;
or the `testmempoolaccept` RPC with `maxfeerate=0`.

blockbrew has no equivalent. Every conflict in `AddTransaction` at
`mempool.go:1149-1160` either runs `checkRBFLocked` or rejects with
`ErrDoubleSpend`. There is no context where the caller can say "I do
NOT want to evict anything, just reject if this would replace".

**File:** `internal/mempool/mempool.go:1149-1160` (no
`m_allow_replacement` analogue at call sites for `AcceptToMemoryPool`).

**Core ref:** `bitcoin-core/src/validation.cpp:447, 838-839`.

**Impact:** package and `testmempoolaccept` semantics diverge from
Core. A caller cannot ask "would this tx replace anything?" without
ACTUALLY replacing.

---

## BUG-13 (P1) — `sendrawtransaction` collapses every reject to RPC error code -25; -26 / -27 unreachable

**Severity:** P1. Bitcoin Core distinguishes three sendrawtransaction
error codes:

| Code | Meaning | Trigger |
|------|---------|---------|
| -25 | RPC_VERIFY_ERROR | Generic verification error |
| -26 | RPC_VERIFY_REJECTED | Network-rule reject (MEMPOOL_REJECTED) |
| -27 | RPC_VERIFY_ALREADY_IN_UTXO_SET | tx already confirmed |

blockbrew's `handleSendRawTransaction` at `internal/rpc/methods.go:1037`:

```go
if err := s.mempool.AcceptToMemoryPool(tx); err != nil {
    return nil, &RPCError{Code: RPCErrVerify, Message: fmt.Sprintf("Transaction rejected: %v", err)}
}
```

All four other ATMP callers
(`wallet_methods.go:131-133`, `multiwallet_methods.go:378-380`,
`bumpfee_methods.go:72-75`, `payjoin_sender.go:243-247`) use the SAME
pattern — collapse to `RPCErrVerify=-25`. None inspect the error
sentinel to distinguish mempool-policy reject from already-known-utxo.

**File:** `internal/rpc/methods.go:1037`, plus 4 other call sites.

**Core ref:** `bitcoin-core/src/rpc/util.cpp:391-401`,
`bitcoin-core/src/rpc/protocol.h:47-49, 54-55`.

**Impact:**
- Wallet front-ends (e.g., BlueWallet, Sparrow) that parse the RPC
  error code to render different UI for "tx already in chain" vs
  "tx rejected by policy" see -25 for everything and cannot
  distinguish.
- Bitcoin Core's test harness (`test/functional/test_framework`)
  asserts specific error codes on negative tests; blockbrew fails
  every such assertion.
- Cross-impl monitoring: tools that scrape RPC error codes for
  mempool-reject classification (e.g., observing whether a particular
  feerate is currently below the relay floor) cannot.

---

## BUG-14 (P1) — `processOrphansLocked` recursive `AddTransaction` under lock release race

**Severity:** P1. `processOrphansLocked` at `mempool.go:2331-2361`
processes orphans whose missing parent was just added. For each
ready-orphan, it:

1. Deletes the orphan from `mp.orphans`.
2. Unlocks `mp.mu` (line 2357).
3. Calls `mp.AddTransaction(orphan.tx)` recursively (line 2358) —
   which takes `mp.mu.Lock()` again.
4. Re-takes `mp.mu` (line 2359) after AddTransaction returns.

During the unlock window (steps 2-4), another goroutine can:
- Add another tx whose hash collides with the orphan's eventual txid
  (rare).
- Modify the orphan pool (process another orphan).
- Receive a block that confirms an ancestor of the orphan, invalidating
  the recursive promote.

The unlock-relock pattern is necessary because `AddTransaction` takes
`mp.mu.Lock()` (line 903), but the pattern itself is fragile. Core's
equivalent (`txmempool.cpp::OrphanReprocess`) holds `cs_main` AND
`m_pool.cs` for the entire promote loop — no unlock-relock.

Additionally, `processOrphansLocked` only does a SINGLE-step promote:
if the promoted orphan unblocks a grandchild orphan in the same call,
that grandchild is NOT promoted in this pass. The next ATMP call (for
some other tx) might trigger it indirectly, or the grandchild orphan
might expire before any tx unblocks it. Core's
`ATMP::ProcessOrphanTransactions` is iterative and promotes ALL
transitively-resolvable orphans in a tight loop.

**File:** `internal/mempool/mempool.go:2331-2361`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessMessage`
calls `m_orphanage.AddTx` → `ProcessOrphanTx` which iteratively promotes.

**Impact:**
- Orphan-promote race window (small).
- Transitively-resolvable orphan chains do not unblock together;
  grandchildren wait for an unrelated ATMP call.

---

## BUG-15 (P0-CDIV) — `bad-txns-inputvalues-outofrange` uses raw `fmt.Errorf` not a sentinel; callers cannot classify

**Severity:** P0-CDIV (correctness-of-classification). The MoneyRange
gates at `mempool/mempool.go:1133-1144` reject with raw
`fmt.Errorf("bad-txns-inputvalues-outofrange: …")`:

```go
if utxo.Amount < 0 || utxo.Amount > consensus.MaxMoney {
    return fmt.Errorf("bad-txns-inputvalues-outofrange: input %s value %d",
        in.PreviousOutPoint.Hash, utxo.Amount)
}
totalInputValue += utxo.Amount
if totalInputValue < 0 || totalInputValue > consensus.MaxMoney {
    return fmt.Errorf("bad-txns-inputvalues-outofrange: accumulated %d",
        totalInputValue)
}
```

Neither path wraps an `Err…` sentinel. Callers cannot `errors.Is(err,
ErrMoneyRange)`. Two issues:

1. The wire-token is leaked but the sentinel taxonomy is broken —
   callers that want to classify MoneyRange-class rejects can ONLY do
   `strings.Contains(err.Error(), "bad-txns-inputvalues-outofrange")`,
   which is fragile.
2. This is the ONLY token in the entire ATMP path that DOES match
   Core's wire-string (cross-cite BUG-1: every other token is English
   prose). The asymmetry is bewildering: one Core-canonical token in a
   sea of English prose, AND it's the one without a sentinel.

Severity P0-CDIV not P1 because this is a CVE-class overflow attack
class (CVE-2010-5139 territory): a malicious node could feed blockbrew
a tx whose inputs sum past `MAX_MONEY`; the reject is correct, but the
caller (the P2P layer) cannot programmatically classify the reject to
decide whether to ban-score the peer.

**File:** `internal/mempool/mempool.go:1133-1144`.

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:186-188`.

**Impact:** correct gate, but ban-score downgrade — the P2P layer at
`OnTx` (`cmd/blockbrew/main.go:1140-1142`) just logs "Rejected tx from
…" and continues. There is no peer-misbehavior classification because
the error cannot be classified.

---

## BUG-16 (P1) — No `-acceptnonstdtxn` operator-knob

**Severity:** P1 ("operator-knob absence" fleet pattern). Bitcoin
Core's `-acceptnonstdtxn` (default `false` on mainnet, `true` on
regtest/testnet) controls whether `IsStandardTx` gates are enforced at
ATMP. This is essential for testing: regtest miners need to relay
non-standard txs (e.g. anyone-can-spend outputs, large OP_RETURN
payloads) to exercise consensus paths.

blockbrew has no flag. The standardness gates at
`mempool/mempool.go:933-1001` (version range, scriptSig, output script,
datacarrier budget) are always enforced. There is no way to relax them
for regtest.

**File:** `cmd/blockbrew/main.go:445-496` (no flag);
`internal/mempool/mempool.go:933-1001` (always-on gates).

**Core ref:** `bitcoin-core/src/init.cpp` (`-acceptnonstdtxn` flag).

**Impact:**
- Regtest test parity: blockbrew cannot replay Core's regtest test
  vectors that rely on non-standard relay.
- Custom-script research and consensus-edge debugging require code
  changes + recompile rather than a CLI flag.

---

## BUG-17 (P1) — No `-bytespersigop` operator-knob; constant hardcoded but unused

**Severity:** P1 ("dead-data plumbing" + "operator-knob absence").
Bitcoin Core's `-bytespersigop` (default 20) scales the effective vsize
used in feerate calculations: a tx's effective vsize is
`max(actualVSize, sigopCost * bytespersigop)`. This is the
"sigop-adjusted vsize" used at feerate and BIP-431 TRUC vsize gates.

blockbrew defines `consensus.DefaultBytesPerSigOp = 20`
(`internal/consensus/params.go:125`) with the comment "Mirrors Bitcoin
Core policy/policy.h:50 DEFAULT_BYTES_PER_SIGOP = 20." A grep over
`internal/mempool/`, `internal/consensus/`, and `cmd/blockbrew/` shows
the constant is **read by zero production paths**. The feerate at
`mempool/mempool.go:1195` is computed as raw vsize (not sigop-adjusted):

```go
feeRate := float64(fee) / float64(vsize) * 1000 // sat/kvB
```

**File:** `internal/consensus/params.go:125` (constant defined);
`internal/mempool/mempool.go:1195` (uses raw vsize).

**Core ref:** `bitcoin-core/src/init.cpp` (`-bytespersigop`);
`bitcoin-core/src/policy/policy.cpp::GetVirtualTransactionSize`
(`MAX(weight/4, sigops*bytespersigop)`).

**Impact:** mempool feerate accounting under-charges txs with many
sigops (e.g. 15-of-15 multisig P2SH). A tx with 250 sigops in 250 vB
(sigop-adjusted vsize = 5000 vB) gets the relay fee for 250 vB
instead of 5000 — a 20x undercharge for sigop-heavy txs. Cross-impl
divergence on what tx feerate is competitive.

---

## BUG-18 (P1) — No `-minrelaytxfee` / `-incrementalrelayfee` operator-knob

**Severity:** P1. Bitcoin Core exposes both as CLI flags
(`-minrelaytxfee` default 1000, `-incrementalrelayfee` default 1000).
blockbrew exposes ONLY `-minrelayfee` (line 468) as a single
BTC/kvB-denominated flag that maps to `MinRelayFeeRate`. There is no
flag for `IncrementalRelayFee`; the value is fixed at
`mempool/mempool.go:391` and `mempool.go:645-647` at 1000 sat/kvB.

Operators who need a higher incremental-relay floor (e.g. mining pool
policy that wants RBF replacements to cover ≥ 2 sat/vB additional
relay cost) cannot configure it.

**File:** `cmd/blockbrew/main.go:468` (only -minrelayfee);
`internal/mempool/mempool.go:391, 645-647` (IncrementalRelayFee hard-coded).

**Core ref:** `bitcoin-core/src/init.cpp` (`-incrementalrelayfee`).

**Impact:** operator cannot tune RBF Rule 4 minimum bump.

---

## BUG-19 (P1) — No `-limitancestorcount` / `-limitdescendantcount` / `-limitancestorsize` / `-limitdescendantsize` operator-knobs

**Severity:** P1. blockbrew's Config struct
(`internal/mempool/mempool.go:347-363`) exposes AncestorLimit,
DescendantLimit, AncestorSizeLimitKvB, DescendantSizeLimitKvB —
documented as "Matches Core -limitancestorcount" etc. — but the four
corresponding CLI flags do NOT exist in `cmd/blockbrew/main.go:445-496`.

The Config fields are settable from code (and tests use them) but
operators have no way to override defaults from the command line. The
docstrings claim parity that the CLI does not deliver — "**wiring-look-
but-no-wire**" fleet pattern.

**File:** `cmd/blockbrew/main.go:445-496` (no flags);
`internal/mempool/mempool.go:347-363` (Config docstrings claim flag parity).

**Core ref:** `bitcoin-core/src/node/mempool_args.cpp:39-46`.

**Impact:** "wiring-look-but-no-wire" fleet pattern. Documentation
claims operator-knobs exist; CLI does not expose them.

---

## BUG-20 (P1) — No `bip125-replacement-disallowed` reject path; no `txn-already-known` distinction

**Severity:** P1. Two Core tokens absent from blockbrew's ATMP:

1. **`bip125-replacement-disallowed`** — covered in BUG-12 (no
   `m_allow_replacement` switch).
2. **`txn-already-known`** — Core's two-arm classification at
   `validation.cpp:858-866`: when inputs are missing, scan the cache
   for our OWN outputs; if any is present we've ALREADY confirmed this
   tx (we just removed it from the mempool on BlockConnected). The
   distinction matters: `txn-already-known` is TX_CONFLICT (do NOT
   enqueue as orphan); `bad-txns-inputs-missingorspent` is
   TX_MISSING_INPUTS (DO enqueue as orphan).

blockbrew has the equivalent gate at `mempool/mempool.go:1168-1176`
that returns `ErrTxnAlreadyKnown` — but the wire-token is the English
prose `"tx %s already committed (output %d in UTXO set)"`, not Core's
`"txn-already-known"`. Cross-cite BUG-1 fleet pattern.

**File:** `internal/mempool/mempool.go:1168-1176`.

**Core ref:** `bitcoin-core/src/validation.cpp:858-866`.

**Impact:** Cross-impl wire-string divergence; monitoring tools
cannot distinguish `txn-already-known` from `bad-txns-inputs-missingorspent`
from blockbrew's reject prose.

---

## BUG-21 (P2) — `BlockDisconnected` processes txs in block order, not parent-first

**Severity:** P2 (related to BUG-11). `BlockDisconnected` at
`mempool/mempool.go:2429-2441` re-adds txs in `range block.Transactions`
order (block tx-index order). The block's order is roughly
topology-respecting (parent before child) BUT a block can contain two
unrelated tx chains, AND a TRUC tx can be a parent of a non-TRUC tx
that comes after it in the block.

If a parent re-add fails (BUG-11's fee gate, etc.), the child re-add
also fails because the parent UTXO is no longer in the chain (it
was an unconfirmed mempool tx). The errors are silent.

Core handles this via its `MempoolAccept` package path with
`bypass_limits=true`, OR by enqueueing the failed tx into the orphan
pool — blockbrew does neither.

**File:** `internal/mempool/mempool.go:2429-2441`.

**Core ref:** `bitcoin-core/src/validation.cpp:315` (uses
`AcceptMultipleTransactions` for the disconnected block, which
handles topology).

**Impact:** silent reorg-readd losses cascade through parent-child
chains.

---

## BUG-22 (P2) — Maturity check skipped silently when `ChainState == nil`

**Severity:** P2. The coinbase-maturity gate at
`mempool/mempool.go:1118-1126`:

```go
if utxo.IsCoinbase {
    spendsCoinbase = true
    if mp.config.ChainState != nil {       // <-- only if wired
        tipHeight := mp.config.ChainState.TipHeight()
        // ... maturity check ...
    }
}
```

is gated on `ChainState != nil`. Test callers (Config without
ChainState wired) SKIP the maturity check entirely — `spendsCoinbase`
is still set, but no maturity gate runs. In production, ChainState IS
wired (`cmd/blockbrew/main.go` constructs it), so this is benign in
production. But:

- Unit tests that test maturity behavior must explicitly wire
  ChainState.
- A future refactor that nil-ifies ChainState in some context would
  silently disable the gate.

**File:** `internal/mempool/mempool.go:1118-1126`.

**Core ref:** `bitcoin-core/src/validation.cpp:892` (always-on call).

**Impact:** test-only divergence today; latent gap.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CDIV:** 4 (BUG-4 dust-cap, BUG-6 dust-rate, BUG-9 maturity off-by-one, BUG-15 MoneyRange sentinel)
- **P1:** 16 (BUG-1 wire-strings, BUG-2 int32 version, BUG-3 bare-multisig, BUG-5 datacarrier knob, BUG-7 dust output-size, BUG-8 anchor-dust, BUG-10 STANDARD flags, BUG-11 reorg-readd, BUG-12 m_allow_replacement, BUG-13 RPC codes, BUG-14 orphan-promote, BUG-16 acceptnonstdtxn knob, BUG-17 bytespersigop, BUG-18 incrementalrelayfee knob, BUG-19 limit-knobs, BUG-20 reject-tokens)
- **P2:** 2 (BUG-21 reorg-order, BUG-22 nil-ChainState gate)

**Fleet patterns confirmed:**

- **"Reject-string wire-parity slippage"** (BUG-1) — 9 distinct Core
  wire-tokens replaced by English-prose Go sentinels. ~10th distinct
  blockbrew instance per W125 / W148 tracking. Companion to lunarblock
  W145 9-token sweep.
- **"Operator-knob absence"** (BUG-5 datacarrier, BUG-16 acceptnonstdtxn,
  BUG-17 bytespersigop, BUG-18 incrementalrelayfee, BUG-19 chain-limits)
  — 5 distinct knobs absent in one wave. Cross-cites W144 / W148 /
  W149 patterns.
- **"Wiring-look-but-no-wire"** (BUG-19) — Config fields document
  "Matches Core -limitancestorcount" but the CLI flag is absent.
  Companion to W138 BUG-class ChainstateManager wiring.
- **"Dead-data plumbing"** (BUG-6 `consensus.DustRelayFeeRate`
  defined and never read; BUG-17 `DefaultBytesPerSigOp` defined and
  never read; BUG-19 Config docstrings claim flag parity that the
  CLI does not deliver) — ~11th, 12th distinct blockbrew instance
  per W138/W140 tracking.
- **"Two-pipeline guard"** (BUG-9 mempool maturity duplicates the
  consensus-side `CheckTransactionInputs` check and gets the +1 wrong)
  — ~17th distinct blockbrew instance.
- **"Carry-forward"** (BUG-2 W132 int32 version ~3 weeks; BUG-10
  W144 BUG-5 STANDARD flags ~3 days) — repeat catches in the same impl,
  symmetric to the fleet pattern.
- **"Comment-as-confession"** (BUG-6 implicit: code does not read the
  3000 sat/kvB constant whose comment promises Core parity) —
  silent divergence between docstring and behavior.

**Top three findings:**

1. **BUG-6 + BUG-7 (P0-CDIV dust math)** — blockbrew's mempool uses
   `MinRelayFeeRate` (1000) instead of Core's `DUST_RELAY_TX_FEE`
   (3000) for the dust threshold, AND omits the output's serialized
   size from the spending-cost calculation. Net effect: blockbrew's
   effective dust threshold is ~1/4 of Core's. The mempool accepts
   sub-economic outputs that Core peers refuse to relay. The
   `consensus.DustRelayFeeRate = 3000` constant IS defined (with
   correct Core-parity comment) but never read at the only site
   that needs it.

2. **BUG-4 (P0-CDIV `MAX_DUST_OUTPUTS_PER_TX` cap absent)** — a 0-fee
   tx with 100+ dust outputs is ACCEPTED by blockbrew; Core rejects
   all but 1. Cross-impl relay split + mempool DoS surface +
   BIP-431 TRUC sibling-eviction interaction.

3. **BUG-9 (P0-CDIV coinbase-maturity off-by-one)** — blockbrew's
   ATMP maturity check uses `tipHeight` instead of Core's `tipHeight + 1`.
   blockbrew rejects mature coinbase one block earlier than Core. A
   tx using a just-matured coinbase, accepted by Core, fails to enter
   blockbrew's mempool until the chain advances one more block.
   This is the classic ATMP "+1 for next block" omission, doubled
   by the two-pipeline-guard pattern (the consensus-side
   `CheckTransactionInputs` takes a `txHeight` parameter and is
   correct; the mempool-side copy gets it wrong).

**Carry-forward:**
- BUG-2 (W132 int32-vs-uint32 Version): ~3 weeks open, finally caught
  at the mempool acceptance observable.
- BUG-10 (W144 BUG-5 GetStandardScriptFlags 9-of-13 missing): ~3
  days open, now visible at the policy-acceptance layer.
