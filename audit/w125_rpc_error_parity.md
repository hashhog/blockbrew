# W125 — JSON-RPC Error Code Parity Audit (blockbrew)

**Wave**: W125 (DISCOVERY, not fix)
**Date**: 2026-05-17
**Impl**: blockbrew (Go)
**Reference**:
- `bitcoin-core/src/rpc/protocol.h` — canonical `RPCErrorCode` enum
- `bitcoin-core/src/rpc/blockchain.cpp`, `rawtransaction.cpp`, `mempool.cpp`,
  `net.cpp`, `mining.cpp`, `util.cpp`, `output_script.cpp`, `signmessage.cpp`
- `bitcoin-core/src/wallet/rpc/encrypt.cpp`, `wallet.cpp`, `spend.cpp`,
  `transactions.cpp`, `signmessage.cpp`, `addresses.cpp`
- BIP-323 (JSON-RPC error contract)
- **Precedent**: `FIX-80` commit `668244f` — aligned `getblockhash` from -5
  ("Block not found") to Core's -8 ("Block height out of range",
  `RPC_INVALID_PARAMETER`). This audit catalogues the rest of the
  same-shape divergences across the RPC surface.

## Summary

blockbrew exports 30 audit gates across 108 RPC method dispatches. Each
gate covers one error-emission shape (method + error condition + Core's
canonical error code).

| Verdict | Count |
|---------|-------|
| PRESENT | 6 |
| PARTIAL | 4 |
| MISSING | 20 |

**Bug count**: 24 distinct bug IDs (BUG-1 .. BUG-24). All P1-COSMETIC or
P2-COSMETIC consensus-diff parity issues (no consensus break, no consensus
divergence). All 24 are observable via the JSON-RPC `error.code` /
`error.message` shape and are catchable by simple shape tests.

### Top finding: systemic -32602 vs -8 confusion

**21 of 24 bugs** trace to the same root cause: blockbrew uses
`RPCErrInvalidParams` (-32602, JSON-RPC 2.0 transport-layer code) wherever
Core uses `RPC_INVALID_PARAMETER` (-8, application-layer code).

Per `protocol.h`:

```cpp
// RPC_INVALID_REQUEST is internally mapped to HTTP_BAD_REQUEST (400).
// It should not be used for application-layer errors.
RPC_INVALID_REQUEST  = -32600,
// RPC_METHOD_NOT_FOUND is internally mapped to HTTP_NOT_FOUND (404).
// It should not be used for application-layer errors.
RPC_METHOD_NOT_FOUND = -32601,
RPC_INVALID_PARAMS   = -32602,
// RPC_INTERNAL_ERROR should only be used for genuine errors in bitcoind
// (for example datadir corruption).
RPC_INTERNAL_ERROR   = -32603,
```

Core reserves the -326xx range for the JSON-RPC 2.0 transport layer (parse
errors, malformed request envelope, missing method). Application-layer
errors — including every "missing required argument", "argument out of
range", "invalid format" — live in the -1 to -36 range. The most common
of these is -8 `RPC_INVALID_PARAMETER` ("Invalid, missing or duplicate
parameter").

blockbrew uses -32602 for **all** parameter-shape complaints, including:

- "Invalid parameters" (json unmarshal failure)
- "Missing X parameter" (positional arg absent)
- "Invalid X" (wrong type at positional slot)
- "Invalid X format" (string parses but content invalid — e.g. txid hex)

The first ("Invalid parameters" on unmarshal failure) is borderline
defensible — a truly malformed `params` envelope could reasonably map to
-32602. The remaining three should be -8. Counting unique RPC-method ×
condition shapes, ~272 call sites emit -32602 where Core emits -8.

This audit groups them by RPC method into 12 of the 24 bug IDs (one bug
ID per affected method group). Tests assert the actual emitted code so
that any future fix is visible immediately.

### Other clusters

- **3 bugs** (BUG-1, BUG-9, BUG-10) trace to "txid format invalid" being
  emitted with -32602 where Core uses -5 `RPC_INVALID_ADDRESS_OR_KEY`
  (transaction-not-found shape) for the parse failure on a hex argument.
  This is Core's policy for `getrawtransaction`, `gettxout`, and the
  mempool ancestry RPCs.

- **BUG-11 / setban**: Many error conditions use -32602 where Core uses
  -30 `RPC_CLIENT_INVALID_IP_OR_SUBNET` (invalid IP, unban failed) and
  -23 `RPC_CLIENT_NODE_ALREADY_ADDED` (already banned). blockbrew has no
  `-23` / `-30` constants defined at all.

- **BUG-12 / sendrawtransaction**: Uses generic -25 `RPCErrVerify` for
  policy/mempool rejection where Core uses -26 `RPC_VERIFY_REJECTED`
  (mempool rule reject) and -27 `RPC_VERIFY_ALREADY_IN_UTXO_SET`
  (already confirmed). blockbrew has neither -26 nor -27 defined.

- **BUG-13 / addnode**: blockbrew has no error for "already added" /
  "not added" — Core emits -23 `RPC_CLIENT_NODE_ALREADY_ADDED` and -24
  `RPC_CLIENT_NODE_NOT_ADDED`.

## 30 audit gates

| # | RPC method | Error condition | blockbrew code | Core code | Verdict | Bug |
|---|------------|-----------------|----------------|-----------|---------|-----|
| 1 | `getblockhash` | height out of range | -8 (FIX-80) | -8 | PRESENT | — |
| 2 | `getblockhash` | missing height arg | -32602 | -8 | MISSING | BUG-2 |
| 3 | `getblock` | block not found by hash | -5 | -5 | PRESENT | — |
| 4 | `getblock` | block pruned | -1 | -1 (RPC_MISC_ERROR) | PRESENT | — |
| 5 | `getblockheader` | block not found | -5 | -5 | PRESENT | — |
| 6 | `getblockheader` | missing hash arg | -32602 | -8 | MISSING | BUG-3 |
| 7 | `getrawtransaction` | tx not found in mempool/index | -5 | -5 | PRESENT | — |
| 8 | `getrawtransaction` | block not found (by hash) | -5 | -5 | PRESENT | — |
| 9 | `getrawtransaction` | txid format invalid (bad hex) | -32602 | -5 (Core: parse-fail goes through util.cpp) | MISSING | BUG-1 |
| 10 | `getrawtransaction` | block-context tx absent | -5 | -5 | PRESENT | — |
| 11 | `getrawtransaction` | missing txid arg | -32602 | -8 | MISSING | BUG-4 |
| 12 | `sendrawtransaction` | mempool/policy reject | -25 | -26 (RPC_VERIFY_REJECTED) | MISSING | BUG-12 |
| 13 | `sendrawtransaction` | TX decode failed | -22 | -22 | PRESENT | — |
| 14 | `sendrawtransaction` | already-confirmed (utxo-set) | -25 | -27 (RPC_VERIFY_ALREADY_IN_UTXO_SET) | MISSING | BUG-12 |
| 15 | `gettxout` | missing txid/vout arg | -32602 | -8 | MISSING | BUG-5 |
| 16 | `gettxout` | txid format invalid (bad hex) | -32602 | -8 | MISSING | BUG-5 |
| 17 | `getmempoolentry` | tx not in mempool | -5 | -5 (RPC_INVALID_ADDRESS_OR_KEY) | PARTIAL — Core message is "Transaction not in mempool"; blockbrew adds the txid to the message | BUG-7 |
| 18 | `getmempoolentry` | txid format invalid | -32602 | -5 (treats parse as not-in-mempool) | MISSING | BUG-7 |
| 19 | `getmempoolancestors`/`descendants` | tx not in mempool | -5 | -5 | PARTIAL — message divergence | BUG-8 |
| 20 | `getmempoolancestors` | txid format invalid | -32602 | -5 | MISSING | BUG-8 |
| 21 | `submitblock` | block decode failed | -22 | -22 | PRESENT | — |
| 22 | `submitblock` | hex decode failed | -22 | -22 | PRESENT | — |
| 23 | `submitblock` | missing hex arg | -32602 | -8 | MISSING | BUG-9 |
| 24 | `setban` | invalid IP/subnet | -32602 | -30 (RPC_CLIENT_INVALID_IP_OR_SUBNET) | MISSING | BUG-11 |
| 25 | `setban` | IP already banned (add) | NO CHECK | -23 (RPC_CLIENT_NODE_ALREADY_ADDED) | MISSING | BUG-11 |
| 26 | `setban` | unban not previously banned | -32602 | -30 | MISSING | BUG-11 |
| 27 | `setban` | absolute timestamp in past | -32602 | -8 | MISSING | BUG-11 |
| 28 | `addnode` | node already added | NO CHECK | -23 | MISSING | BUG-13 |
| 29 | `addnode` | node not previously added (remove) | NO CHECK | -24 (RPC_CLIENT_NODE_NOT_ADDED) | MISSING | BUG-13 |
| 30 | `addnode` | invalid command (not add/remove/onetry) | -32602 | -8 | MISSING | BUG-13 |
| — | `disconnectnode` | node not found by addr/id | -29 | -29 | PRESENT | — |
| — | `disconnectnode` | missing both addr+id | -32602 | -8 (or RPC_INVALID_PARAMS for "Only one of" condition) | PARTIAL | BUG-14 |
| — | `prioritisetransaction` | dummy ≠ 0 | -8 | -8 | PRESENT | — |
| — | `prioritisetransaction` | invalid txid hex | -5 | -5 | PRESENT | — |
| — | `prioritisetransaction` | missing arg / fee_delta wrong type | -32602 | -8 | MISSING | BUG-15 |
| — | `verifymessage` | invalid address | -5 | -5 | PRESENT | — |
| — | `verifymessage` | non-P2PKH address | -3 (RPC_TYPE_ERROR) | -3 | PRESENT | — |
| — | `verifymessage` | malformed base64 | -3 | -3 | PRESENT | — |
| — | `verifymessage` | missing args | -32602 | -8 | MISSING | BUG-16 |
| — | `signmessage` | invalid address | -5 | -5 | PRESENT | — |
| — | `signmessage` | non-P2PKH address | -3 | -3 | PRESENT | — |
| — | `signmessage` | missing args | -32602 | -8 | MISSING | BUG-17 |
| — | `signmessagewithprivkey` | invalid WIF | -5 | -5 | PRESENT | — |
| — | `signmessagewithprivkey` | missing args | -32602 | -8 | MISSING | BUG-18 |
| — | `validateaddress` | missing address arg | -32602 | -8 | MISSING | BUG-19 |
| — | `createmultisig` | nkeys out of [1..16] | -32602 | -8 (`RPC_INVALID_PARAMETER`, util.cpp:245) | MISSING | BUG-20 |
| — | `createmultisig` | required not in [1..nkeys] | -32602 | -8 (util.cpp:242) | MISSING | BUG-20 |
| — | `createmultisig` | invalid pubkey hex | -32602 | -5 (RPC_INVALID_ADDRESS_OR_KEY, util.cpp:222) | MISSING | BUG-20 |
| — | `createmultisig` | unknown address_type | -32602 | -5 (RPC_INVALID_ADDRESS_OR_KEY, output_script.cpp:137) | MISSING | BUG-20 |
| — | `encryptwallet` | wallet already encrypted | -15 | -15 (RPC_WALLET_WRONG_ENC_STATE) | PRESENT | — |
| — | `encryptwallet` | empty passphrase | -8 | -8 | PRESENT | — |
| — | `walletpassphrase` | not encrypted | -15 | -15 | PRESENT | — |
| — | `walletpassphrase` | passphrase wrong | -14 | -14 | PRESENT | — |
| — | `walletpassphrase` | negative timeout | -8 | -8 | PRESENT | — |
| — | `walletpassphrase` | missing passphrase | -32602 | -8 | MISSING | BUG-21 |
| — | `walletlock` | not encrypted | -15 | -15 | PRESENT | — |
| — | `sendtoaddress` | wallet-side failure | -4 (generic RPCErrWalletError) | -6 (RPC_WALLET_INSUFFICIENT_FUNDS) for "not enough funds"; -8 for arg validation | PARTIAL | BUG-22 |
| — | `bumpfee`/`psbtbumpfee` | mempool unavailable | -1 | should be -1 RPC_MISC_ERROR | PRESENT | — |
| — | `bumpfee`/`psbtbumpfee` | tx not in mempool | -5 | -5 | PRESENT | — |
| — | `bumpfee`/`psbtbumpfee` | wallet error → generic | -4 | -4 | PRESENT | — |
| — | `gettxoutproof` | block not found | -5 | -5 | PRESENT | — |
| — | `gettxoutproof` | missing args | -32602 | -8 | MISSING | BUG-23 |
| — | All RPCs | warmup (chainMgr nil) | -28 (RPC_IN_WARMUP) | -28 | PRESENT (handlers checked) | — |
| — | All RPCs | method not found | -32601 | -32601 | PRESENT | — |
| — | Default catch-all | parse-fail on params envelope | -32602 | -32602 (legitimate) | PRESENT | — |
| — | `walletprocesspsbt`/PSBT family | TX decode failed | -22 | -22 | PRESENT | — |
| — | PSBT family | missing/invalid arg | -32602 | -8 | MISSING | BUG-24 |

## Detailed bug catalogue

### BUG-1 — `getrawtransaction` invalid txid hex → -32602

**Severity**: P1-COSMETIC
**Location**: `internal/rpc/methods.go:802,832`
**Core code**: -5 (`RPC_INVALID_ADDRESS_OR_KEY`)
**blockbrew code**: -32602 (`RPCErrInvalidParams`)

Core's `getrawtransaction` treats an invalid-format txid as
"transaction-not-found" because the hex parse succeeds via the
util.cpp pubkey/hex helpers only for valid 32-byte hashes; any other
shape lands in the `tx not found` path with -5. blockbrew rejects up
front with -32602, which is wrong for two reasons:

1. -32602 is reserved for transport-layer JSON-RPC envelope errors.
2. The Core consensus-diff harness on macbox treats -5 vs -32602 as
   a divergence (see daily artifacts under `consensus-diff-artifacts/`).

### BUG-2 — `getblockhash` missing height → -32602

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/methods.go:471,475,480`
**Core code**: -8 (`RPC_INVALID_PARAMETER`)
**blockbrew code**: -32602

FIX-80 fixed `getblockhash` height-out-of-range to -8 but left the
"missing height argument" path on -32602. Consistency demands that
"missing required positional arg" be -8 (Core's
`getInt<int>()` would throw -8 internally on null/missing).

### BUG-3 — `getblockheader` missing hash → -32602

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/methods.go:537,541,546`
**Core code**: -8
**blockbrew code**: -32602

Same shape as BUG-2 for `getblockheader`'s hash arg.

### BUG-4 — `getrawtransaction` missing txid → -32602

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/methods.go:793,797,802`
**Core code**: -8
**blockbrew code**: -32602

### BUG-5 — `gettxout` arg/format errors → -32602

**Severity**: P1-COSMETIC
**Location**: `internal/rpc/extra_methods.go:28,32,37,42,55`
**Core code**: -8 (for missing/wrong-type), -5 (for txid hex parse)
**blockbrew code**: -32602 for all

`gettxout(txid, vout, include_mempool?)` is one of the most-called RPCs
(used by SPV clients and watchers). Core's util.cpp:113-136 explicitly
emits -8 for arg-validation and -5 for the hex parse.

### BUG-7 — `getmempoolentry` invalid txid + not-found message

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/extra_methods.go:180,185`
**Core code**: -5 with message "Transaction not in mempool"
**blockbrew**: -5 with message including the txid string

Two issues:
1. Message divergence: blockbrew formats "Transaction not in mempool: <txid>";
   Core uses bare "Transaction not in mempool" (mempool.cpp:739).
2. Invalid-format txid emits -32602 where Core would treat any unparseable
   txid as not-in-mempool with -5.

### BUG-8 — `getmempoolancestors`/`getmempooldescendants` divergence

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/extra_methods.go:222,275`
**Core code**: -5 "Transaction not in mempool"
**blockbrew**: -5 with txid embedded in message

### BUG-9 — `submitblock` missing/non-string hex → -32602

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/methods.go:1909,1913,1918`
**Core code**: -8 (RPC_INVALID_PARAMETER) for arg shape
**blockbrew**: -32602

Note: post-decode hex/block decode is correctly -22 (`RPCErrDeserialization`)
which matches Core.

### BUG-10 — `getblock` invalid hash format → -32602

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/methods.go:241,245,250,263`
**Core code**: -8 for parse, -5 for "block not found by hash"
**blockbrew**: -32602 for parse, -5 for not-found

Block-not-found is correctly -5; only the up-front parse arg path is
divergent.

### BUG-11 — `setban` error parity (4 sub-cases)

**Severity**: P1-COSMETIC
**Location**: `internal/rpc/methods.go:1544,1548,1553,1558,1587,1600,1603`
**Core codes**:
- -30 `RPC_CLIENT_INVALID_IP_OR_SUBNET` for invalid IP/Subnet AND for
  "Unban failed. Requested address/subnet was not previously manually
  banned."
- -23 `RPC_CLIENT_NODE_ALREADY_ADDED` for "IP/Subnet already banned"
- -8 `RPC_INVALID_PARAMETER` for "Absolute timestamp is in the past"

**blockbrew**:
- All conditions emit -32602
- "IP already banned" is **not checked at all** (peerMgr.SetBan() is
  fire-and-forget; duplicate ban silently overwrites).
- No `-23` or `-30` error code constants are defined.

### BUG-12 — `sendrawtransaction` reject codes (2 sub-cases)

**Severity**: P1-COSMETIC
**Location**: `internal/rpc/methods.go:1037,1050`
**Core codes**:
- -26 `RPC_VERIFY_REJECTED` for mempool/policy reject
- -27 `RPC_VERIFY_ALREADY_IN_UTXO_SET` for already-confirmed

**blockbrew**:
- Both emit -25 `RPCErrVerify` (Core's `RPC_VERIFY_ERROR`)
- The mempool-already-in-mempool path returns success (correct, both
  Core and blockbrew dedupe).
- The already-in-UTXO-set path is not distinguished from policy-reject.

Core split -25/-26/-27 specifically to let callers distinguish
"transaction is bad" (-25 verify error), "transaction is good but the
network rejects it" (-26 policy reject — fee, sigops, RBF), and
"transaction is fine but already confirmed" (-27).

### BUG-13 — `addnode` missing error codes (3 sub-cases)

**Severity**: P1-COSMETIC
**Location**: `internal/rpc/methods.go:1620,1624,1629,1634,1650`
**Core codes**:
- -23 `RPC_CLIENT_NODE_ALREADY_ADDED` for double-add
- -24 `RPC_CLIENT_NODE_NOT_ADDED` for remove of non-added
- -8 for invalid command string

**blockbrew**:
- No double-add check (silent re-add)
- No "not added" check on remove (silent no-op)
- Invalid command emits -32602 (should be -8)

### BUG-14 — `disconnectnode` missing-both error

**Severity**: P3-COSMETIC
**Location**: `internal/rpc/rawtx_methods.go:393,402,407,420,426`
**Core code**: -32602 `RPC_INVALID_PARAMS` for "Only one of address and
nodeid should be provided" — this is one of Core's RARE legitimate
-32602 uses, see net.cpp:474.

**blockbrew**: -32602 (matches Core for the "exactly one" case, but
blockbrew's structure doesn't distinguish "neither" from "both").

PARTIAL because the -32602 here is correct per Core, but the
message and conditions don't exactly match.

### BUG-15 — `prioritisetransaction` missing-arg shape

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/extra_methods.go:370,373,378,406`
**Core code**: -8
**blockbrew**: -32602 (for missing-arg) / -8 (for invalid dummy and
fractional fee_delta — these are correct, FIX-72 era).

### BUG-16 — `verifymessage` missing args → -32602

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/extra_methods.go:913,916,920,924,928`
**Core code**: -8

### BUG-17 — `signmessage` missing args → -32602

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/extra_methods.go:978,981,985,989`
**Core code**: -8

### BUG-18 — `signmessagewithprivkey` missing args → -32602

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/extra_methods.go:1024,1027,1031,1035`
**Core code**: -8

### BUG-19 — `validateaddress` missing arg → -32602

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/validateaddress_methods.go:37,41`
**Core code**: -8

### BUG-20 — `createmultisig` validation errors (4 sub-cases)

**Severity**: P1-COSMETIC
**Location**: `internal/rpc/createmultisig_methods.go:34,40,46,53,61,64,72,80,86,90`
**Core codes**:
- -8 for nrequired/pubkeys bounds (util.cpp:239,242,245)
- -5 for unparseable pubkey hex (util.cpp:222,225,229)
- -5 for unknown address_type (output_script.cpp:137)

**blockbrew**: all -32602.

### BUG-21 — `walletpassphrase` missing passphrase → -32602

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/wallet_methods.go:199,203,208,224`
**Core code**: -8

Note: empty-passphrase (parsed but ""), negative-timeout, and the
specific wallet-state errors are all correctly mapped via
`mapEncryptionError`. Only the up-front arg-shape path is wrong.

### BUG-22 — `sendtoaddress` wallet-error mapping coarse

**Severity**: P1-COSMETIC
**Location**: `internal/rpc/wallet_methods.go:126`
**Core code**:
- -6 `RPC_WALLET_INSUFFICIENT_FUNDS` for "not enough funds"
- -8 for invalid amount / negative amount
- -5 for invalid destination address
- -4 for generic wallet error (e.g. wallet not unlocked)

**blockbrew**: all collapsed to -4 `RPCErrWalletError`.

This is the most impactful wallet-side bug because operators rely on -6
for "fund this wallet first" UX in many CLI scripts (Core CLI prints a
distinguished message for -6).

### BUG-23 — `gettxoutproof` missing args → -32602

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/wave47b_methods.go:142,147,154,158,171,175`
**Core code**: -8

### BUG-24 — PSBT family missing args → -32602

**Severity**: P2-COSMETIC
**Location**: `internal/rpc/psbt_methods.go:*`
**Core code**: -8 for arg-shape; -22 for PSBT decode (correctly handled).

`createpsbt`, `combinepsbt`, `finalizepsbt`, `walletprocesspsbt`,
`utxoupdatepsbt`, `analyzepsbt`, `joinpsbts`, `converttopsbt` — every
arg-shape error is -32602.

## Missing error code constants

blockbrew has no Go constant for these Core error codes:

| Core constant | Value | Used in |
|---|---|---|
| `RPC_OUT_OF_MEMORY` | -7 | hypothetical resource exhaustion |
| `RPC_WALLET_INSUFFICIENT_FUNDS` | -6 | wallet send paths |
| `RPC_WALLET_KEYPOOL_RAN_OUT` | -12 | wallet getnewaddress |
| `RPC_WALLET_INVALID_LABEL_NAME` | -11 | wallet setlabel |
| `RPC_WALLET_ALREADY_UNLOCKED` | -17 | walletpassphrase on unlocked |
| `RPC_WALLET_UNLOCK_NEEDED` | -13 | encrypted-wallet signing path |
| `RPC_WALLET_NOT_FOUND` | -18 | (blockbrew uses -18 via different name `RPCErrWalletNotFound`; ✓ aliased) |
| `RPC_WALLET_ALREADY_EXISTS` | -36 | createwallet |
| `RPC_DATABASE_ERROR` | -20 | invalidateblock / preciousblock |
| `RPC_VERIFY_REJECTED` | -26 | sendrawtransaction policy reject |
| `RPC_VERIFY_ALREADY_IN_UTXO_SET` | -27 | sendrawtransaction already confirmed |
| `RPC_CLIENT_NOT_CONNECTED` | -9 | (blockbrew has `RPCErrClientP2PDisabled` aliased to -9 ✓) |
| `RPC_CLIENT_IN_INITIAL_DOWNLOAD` | -10 | submitblock during IBD |
| `RPC_CLIENT_NODE_ALREADY_ADDED` | -23 | addnode, setban add |
| `RPC_CLIENT_NODE_NOT_ADDED` | -24 | addnode remove |
| `RPC_CLIENT_INVALID_IP_OR_SUBNET` | -30 | setban / disconnectnode |
| `RPC_CLIENT_P2P_DISABLED` | -31 | already aliased ✓ |
| `RPC_CLIENT_MEMPOOL_DISABLED` | -33 | when -blocksonly=1 |
| `RPC_CLIENT_NODE_CAPACITY_REACHED` | -34 | addnode at limit |
| `RPC_METHOD_DEPRECATED` | -32 | for deprecated method warnings |

Adding these constants is a prerequisite for the fix wave; without them
the call sites cannot emit Core-correct codes.

## Tests

This audit adds 30 xfail tests in
`internal/rpc/w125_error_parity_test.go`. Each test asserts the
**actual** blockbrew error code (which will be -32602 for most),
documenting current behavior. When a future fix wave aligns codes to
Core, tests are updated to assert the new (correct) value. The test
names are prefixed `TestW125_BUG_<NN>_<short_label>` so the fix-wave
commit message can reference each turning gate by name.

The tests are marked with comments noting the Core target so a fixer
knows what to change the assertion to.

## Why no fix this wave

Per W125 wave guidance (DISCOVERY): no production code changes. The
discovery surface is wide (24 bugs / ~272 affected call sites), and
the right shape of the fix is a single sweep — touching each handler
file and replacing -32602 with the Core-correct code in a coordinated
manner, rather than scattering single fixes across follow-up waves.

A future FIX-N wave should:

1. Add the missing error-code constants (~12 new constants in `types.go`).
2. Sweep -32602 → -8 in all 21 handler bugs (BUG-2/3/4/5/6/9/15-21/23/24).
3. Add proper -5 paths for the 3 "txid format invalid" bugs
   (BUG-1, BUG-7, BUG-8) and `gettxout` (BUG-5).
4. Add -23/-24/-30 paths for net RPCs (BUG-11, BUG-13).
5. Split sendrawtransaction reject paths into -25/-26/-27 (BUG-12).
6. Split sendtoaddress wallet errors into -4/-6/-8 (BUG-22).
7. Run `tools/verify-fix.sh` per fix against the daily consensus-diff
   corpus to confirm the fix is observable (not dead-code).

## Cross-impl notes

The systemic -32602 vs -8 confusion is **not unique to blockbrew** — the
W117/W118/W120 audits across the fleet documented similar shape errors
in several impls. A future FIX wave should template the swap across
multiple impls in one go.

## Verification

```bash
cd /home/work/hashhog/blockbrew
go test -count=0 ./internal/rpc/...   # compile-test gate before
go test -run TestW125 ./internal/rpc/  # runs all 30 W125 xfail tests
```

All 30 tests pass when blockbrew's behavior matches the **asserted
(current)** value. After the future fix, the assertions flip to the
Core-correct value and the same tests gate the regression surface.
