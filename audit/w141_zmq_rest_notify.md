# W141 — ZMQ + REST + Notification scripts audit (blockbrew)

**Wave:** W141 — ZMQ pub-sub notifier interface, REST HTTP API, and notification
script hooks (-blocknotify / -walletnotify / -alertnotify /
-startupnotify / -shutdownnotify).

**Scope:** discovery only — no production code changes. One forward-regression
test file `internal/rpc/w141_zmq_rest_notify_test.go` containing skipped
tests with `Skip()` strings that describe each bug.

**Bitcoin Core references**
- `bitcoin-core/src/zmq/zmqnotificationinterface.cpp` (lifecycle + dispatch)
- `bitcoin-core/src/zmq/zmqpublishnotifier.cpp` (per-topic publisher, byte order)
- `bitcoin-core/src/zmq/zmqabstractnotifier.h` (`DEFAULT_ZMQ_SNDHWM = 1000`)
- `bitcoin-core/src/rest.cpp` (HTTP endpoints + wire format)
- `bitcoin-core/src/init.cpp` (`-blocknotify`, `-startupnotify`,
  `-shutdownnotify`)
- `bitcoin-core/src/node/kernel_notifications.cpp::AlertNotify`
- `bitcoin-core/src/wallet/init.cpp` (`-walletnotify`)
- `bitcoin-core/src/common/system.cpp::runCommand`

**BIPs:** none. (REST endpoints implement Core's de-facto REST API; BIP-64
documents `getutxos` binary layout.)

**Methodology**
1. Read every Core ref above end-to-end.
2. Build a 30-gate matrix split across 3 subsystems (10 ZMQ + 10 REST +
   10 NOTIFY).
3. For each gate, classify blockbrew against the Core reference.
4. Catalogue every divergence as a `BUG-<n>`; severity drawn from
   the corruption / DoS / data-leak axis.
5. Emit one skipped Go test per gate so the audit shape is durable in CI
   (forward-regression: any future fix flips a Skip into a Fail).

**Worktree:** committed from the W141-isolated working copy
(`/home/work/hashhog/blockbrew`); does not collide with the concurrent
agent's PSBT branch under `.claude/worktrees/agent-aedc450cd089d7f4c/`.

---

## Subsystem A — ZMQ publisher (10 gates / 8 BUGs)

Files audited: `cmd/blockbrew/zmqpub.go`, `cmd/blockbrew/zmqpub_test.go`,
`cmd/blockbrew/main.go` (wiring sites).

| Gate | Behaviour | Verdict |
|------|-----------|---------|
| A1   | Five topics: `pubhashblock` / `pubhashtx` / `pubrawblock` / `pubrawtx` / `pubsequence` declared | PASS (`zmqpub.go:21-27`) |
| A2   | Block-hash bytes published in **reversed** (display) order on the wire | **BUG-1** (CDIV) |
| A3   | Tx-hash bytes published in **reversed** order | **BUG-2** (CDIV) |
| A4   | Sequence body hash bytes in **reversed** order | **BUG-3** (CDIV) |
| A5   | Sequence(D) block-disconnect emitted on reorg / invalidateblock | **BUG-4** (P1 missing) |
| A6   | Sequence(R) tx-removed emitted when mempool evicts | **BUG-5** (P1 missing) |
| A7   | `pubhashtx` / `pubrawtx` also fire for txs **inside a connected block** (Core: `BlockConnected` → loop tx) | **BUG-6** (P1 missing) |
| A8   | IBD gating: `UpdatedBlockTip` short-circuits in `fInitialDownload` | **BUG-7** (P2 missing) |
| A9   | Per-topic outbound HWM (`-zmqpub<topic>hwm`, default 1000) | **BUG-8** (P2 missing) |
| A10  | `ZMQ_LINGER=0` on shutdown so pending sends drop within `zmq_ctx_term` | **BUG-9** (P3 missing, depends on zmq4 capability) |

### BUG-1 (CDIV) — hashblock bytes published in internal (LE) byte order

**Where:** `cmd/blockbrew/zmqpub.go:222`
**Core:** `zmqpublishnotifier.cpp:210-219` reverses every byte
(`data[31 - i] = hash.begin()[i]`) before sending. The wire payload is
display / big-endian / RPC-hex order.

**blockbrew:** passes `hash[:]` straight to `sendTopic` — that's the
internal little-endian hash. Subscribers built against Core get a
reversed 32-byte buffer.

**Impact:** every external `pubhashblock` subscriber (electrs, fulcrum,
nbxplorer, mempool.space, electronicash, any block-explorer indexer)
sees a different hash than Core publishes. SPV/light-wallet bridges
that key on hashblock to invalidate caches will desync silently.

**Fix:** copy `hash[31-i]` into a 32-byte buffer (mirror Core's
`for (i=0; i<32; ++i) data[31-i] = hash.begin()[i];`).

### BUG-2 (CDIV) — hashtx bytes published in internal byte order

**Where:** `zmqpub.go:256` (`p.sendTopic(zmqTopicHashTx, ..., hash[:])`)
**Core:** `zmqpublishnotifier.cpp:221-230` reverses bytes.
**Impact:** same as BUG-1 but for transactions. Any tx-watching
subscriber (electrs, fulcrum, mempool.space, payment gateways watching
for incoming UTXOs) sees mismatched 32-byte buffers.
**Fix:** same: reverse into a stack buffer before send.

### BUG-3 (CDIV) — sequence body hash bytes in internal byte order

**Where:** `zmqpub.go:235-237` (block-connect), `zmqpub.go:270-273`
(tx-accept), would also affect the missing D/R hooks (BUG-4/5).
**Core:** `zmqpublishnotifier.cpp:256-265` (`SendSequenceMsg`) reverses
the 32-byte hash before the 1-byte label.
**Impact:** the wire format of every sequence message diverges from
Core. Tools using sequence to track block/tx state (the canonical use
case for `pubsequence`) see mismatched hashes.
**Fix:** reverse before write.

### BUG-4 (P1 MISSING) — no sequence(D) / hashblock fan-out on block disconnect

**Where:** `cmd/blockbrew/main.go:880-925` (`SetOnBlockDisconnected`)
**Core:** `zmqnotificationinterface.cpp:198-211` (`BlockDisconnected`):
- emits `hashtx` / `rawtx` for every tx in the disconnected block (so
  the tx is re-broadcast as "live in mempool" again — they get readded);
- emits `sequence(D)` for the block hash.

**blockbrew:** the disconnected-block callback only touches mempool +
txindex + filter index. **Zero ZMQ fan-out.** External tooling that
follows `pubsequence` will miss every reorg.

**Impact:** subscribers cannot detect reorgs via ZMQ at all. Tools that
deliberately wait for `sequence(D)` to roll back side state (electrs
chain-tip cache, mempool.space, payment processors with confirmation
counters) lose correctness on every reorg.

**Fix:** add a `PublishBlockDisconnected(block, height)` helper and
wire it in `SetOnBlockDisconnected` BEFORE the early returns.

### BUG-5 (P1 MISSING) — no sequence(R) / hashtx fan-out on mempool removal

**Where:** none (search grepped — `PublishTxRemoved` not implemented).
**Core:** `zmqnotificationinterface.cpp:170-178`
(`TransactionRemovedFromMempool`) fires `NotifyTransactionRemoval` →
`sequence(R)` for every non-block removal (expire, eviction, replaced,
conflict, sizelimit, reorg).
**Impact:** wallets relying on `sequence(R)` (e.g. nbxplorer's
"transaction replaced" detection) silently lose RBF / eviction
visibility.
**Fix:** add `PublishTxRemoved(tx, reason)` and wire it from every
removal site in `internal/mempool` (eviction, RBF, expiry, reorg). The
caller passes a `mempool_sequence` argument matching Core's monotonic
counter.

### BUG-6 (P1 MISSING) — pubhashtx / pubrawtx never fire for txs **in a connected block**

**Where:** `cmd/blockbrew/main.go:1076-1079` only calls
`PublishBlockConnected`; the block-connect callback does not iterate
`block.Transactions` to emit `hashtx`/`rawtx` for each tx.
**Core:** `zmqnotificationinterface.cpp:180-196` (`BlockConnected`)
iterates `pblock->vtx` and calls `notifier->NotifyTransaction(tx)` on
every tx → that fires both hashtx and rawtx.

This is documented Core behaviour: a tx is broadcast twice on
`hashtx`/`rawtx` — once on mempool entry, once when mined. The second
firing is how light wallets confirm pending txs without polling
`gettransaction`.

**Impact:** subscribers waiting on `hashtx` for a confirmation signal
never see one — they must fall back to polling RPC.
**Fix:** in the connect-block callback (after consensus apply, before
ZMQ block-connect message) loop the block's txs and call
`PublishTxConfirmedInBlock(tx)` (a new helper that fires hashtx+rawtx
only — no sequence(A), no mempool_sequence increment, because the tx
already left the mempool when admitted).

### BUG-7 (P2 MISSING) — no IBD gating on `UpdatedBlockTip`

**Where:** `zmqpub.go:216-246` (`PublishBlockConnected`) — fires for
every connected block, including during initial block download.
**Core:** `zmqnotificationinterface.cpp:151-159`
(`UpdatedBlockTip`) short-circuits `if (fInitialDownload || pindexNew
== pindexFork) return;`.
**Impact:** during a fresh sync (hundreds of thousands of blocks),
blockbrew floods every PUB subscriber. If a subscriber is slow
(electrs/fulcrum on a small disk), the HWM kicks in (Core: drop;
blockbrew: depends on zmq4 default — see BUG-8) and either the
publisher or subscriber wedges.
**Fix:** plumb an `IsInIBD()` accessor from the chain manager into the
publisher; early-return from `PublishBlockConnected` when in IBD.
Connect-time tx ZMQ messages were never emitted by Core during IBD
either (the BlockConnected → tx loop also gates on `role.historical`
— see `zmqnotificationinterface.cpp:182`).

### BUG-8 (P2 MISSING) — no `-zmqpub<topic>hwm` flag / default HWM

**Where:** no CLI flag exists. `cmd/blockbrew/main.go:486-490` only
declares the five endpoint flags.
**Core:** `zmqnotificationinterface.cpp:69` reads
`gArgs.GetIntArg(arg + "hwm", DEFAULT_ZMQ_SNDHWM)` (default 1000) per
notifier and calls `SetOutboundMessageHighWaterMark`. The notifier
then sets `ZMQ_SNDHWM` on the socket before bind.
**zmq4 capability:** the Go library supports
`sock.SetOption(zmq4.OptionHWM, n)` (`zmq4@v0.17.0/pub.go:96-107`).
**Impact:** at the zmq4 default of `hwm=0` (unbounded queue), a slow
subscriber wedges memory growth on the publisher. Core's bounded 1000
caps memory at ~32 KB (hashtx) to a few MB (rawblock). blockbrew has
no upper bound.
**Fix:** declare `-zmqpubhashblockhwm`, `-zmqpubhashtxhwm`,
`-zmqpubrawblockhwm`, `-zmqpubrawtxhwm`, `-zmqpubsequencehwm`
(default 1000 each); call `sock.SetOption(zmq4.OptionHWM, hwm)` after
`zmq4.NewPub` and before `sock.Listen`.

### BUG-9 (P3 MISSING) — no `ZMQ_LINGER=0` on close

**Where:** `zmqpub.go:160-164` (`Stop()`) calls `ep.socket.Close()`
directly.
**Core:** `zmqpublishnotifier.cpp:185-187` sets `ZMQ_LINGER=0` before
`zmq_close` so pending sends to disconnected subscribers don't block
shutdown.
**zmq4 caveat:** the Go library doesn't expose a LINGER option (search:
no `LINGER` in `zmq4@v0.17.0/*.go`). May be a "wontfix" but worth
documenting so future migration to an upstream binding (czmq) carries
the requirement.
**Impact:** in a pathological case (subscriber TCP-stalled while
holding HWM<message-rate), shutdown can hang until OS-level socket
close. Low-frequency in practice.
**Fix:** when zmq4 grows linger support, wire it; until then, document
in `zmqpub.go` so the requirement isn't forgotten.

### Subsystem A summary

| Severity | Count |
|----------|------:|
| CDIV     | 3     |
| P1 MISSING | 3   |
| P2 MISSING | 2   |
| P3 MISSING | 1   |
| **Total ZMQ BUGs** | **9** |

The three CDIV bugs (1/2/3) are the highest impact — every external ZMQ
subscriber against blockbrew receives byte-reversed hashes vs every
other Core-compatible node. This breaks fleet-level interop with the
entire "Bitcoin sidecar" ecosystem.

---

## Subsystem B — REST API (10 gates / 9 BUGs)

Files audited: `internal/rpc/rest.go`, `internal/rpc/rest_test.go`.

| Gate | Behaviour | Verdict |
|------|-----------|---------|
| B1   | `/rest/block/`, `/rest/block/notxdetails/`, `/rest/tx/`, `/rest/headers/`, `/rest/chaininfo`, `/rest/mempool/{info,contents}`, `/rest/getutxos`, `/rest/blockhashbyheight/`, `/rest/blockfilter`, `/rest/blockfilterheaders` registered | PASS (mostly — see B2) |
| B2   | `/rest/blockpart/`, `/rest/spenttxouts/`, `/rest/deploymentinfo/` registered (Core 27+) | **BUG-10** (P2 missing 3 endpoints) |
| B3   | `/rest/getutxos` binary output: `bitmap` written with `CompactSize` length prefix (per `std::vector<unsigned char>` serialization) | **BUG-11** (CDIV) |
| B4   | `/rest/getutxos` binary output: each CCoin prefixed by 4-byte `nTxVerDummy = 0` (Core's `READWRITE(nTxVerDummy, obj.nHeight, obj.out)`) | **BUG-12** (CDIV) |
| B5   | `/rest/getutxos` binary output: outer `outs` vector preceded by `CompactSize` count | **BUG-13** (CDIV) |
| B6   | `/rest/getutxos` value: stored as int64 satoshis throughout (no float64 round-trip) | **BUG-14** (P1 CDIV — large-amount rounding) |
| B7   | `/rest/headers/<hash>.<ext>?count=N` (modern path); `/rest/headers/<count>/<hash>.<ext>` is deprecated fallback | **BUG-15** (P2 — only deprecated path supported) |
| B8   | `/rest/blockfilterheaders/<filtertype>/<hash>.<ext>?count=N` (modern path) accepted alongside deprecated `<filtertype>/<count>/<hash>.<ext>` | **BUG-16** (P2 — only deprecated path supported) |
| B9   | Warmup gating: every REST handler returns `503 Service Unavailable: Service temporarily unavailable: <state>` while node initialising | **BUG-17** (P2 missing) |
| B10  | `/rest/blockfilter` / `/rest/blockfilterheaders` block until BIP-157 index is synced (`BlockFilterIndex::BlockUntilSyncedToCurrentChain`) before reading | **BUG-18** (P2 missing; cross-ref W133 G25 / BUG-13) |

### BUG-10 (P2 MISSING) — three Core REST endpoints absent

**Where:** `internal/rpc/rest.go:85-113` (`RegisterRESTHandlers`).
**Core:** `rest.cpp:1141-1159` (`uri_prefixes` table) registers
`/rest/blockpart/`, `/rest/spenttxouts/`, `/rest/deploymentinfo/`
(`rest_block_part`, `rest_spent_txouts`, `rest_deploymentinfo`).
blockbrew does not register any of the three.

**Impact:**
- `/rest/blockpart/` — partial-block fetch (offset+size in the on-disk
  block file). Used by light clients fetching specific tx ranges.
- `/rest/spenttxouts/` — block undo data over REST. Used by indexers
  that want to reconstruct prevouts without re-fetching the
  predecessor block. Added in Core 27.
- `/rest/deploymentinfo/` — softfork deployment status. Used by
  monitoring tools to track activation thresholds.

**Fix:** add three handlers; for `spenttxouts` and `deploymentinfo`,
reuse existing RPC implementations (`getblockundo` / `getdeploymentinfo`)
the same way `chaininfo` reuses `getblockchaininfo` (rest.go:444-459).

### BUG-11 (CDIV) — getutxos binary bitmap missing CompactSize prefix

**Where:** `rest.go:584-585` (`buf.Write(bitmap)` raw).
**Core:** `rest.cpp:1039` (`ssGetUTXOResponse << ... << bitmap << outs;`)
where `bitmap` is `std::vector<unsigned char>` — Bitcoin Core's
`Serialize(stream, std::vector<unsigned char>)` writes a `CompactSize`
length prefix before the data (`bitcoin-core/src/serialize.h` —
`Serialize<>` for vector). blockbrew omits the prefix.

**Impact:** a binary-mode `getutxos` client decoding per BIP-64 reads:

```
[4 LE chainHeight][32 chainTipHash][CompactSize bitmap_len][bitmap...][CompactSize utxo_count][utxos...]
```

blockbrew emits:
```
[4 LE chainHeight][32 chainTipHash][bitmap...][per-utxo, no count]
```

Any binary-format client (Core's own `bitcoin-cli` REST tooling,
electrum-server's REST consumer) fails to parse. This is the canonical
binary wire mismatch.

**Fix:** prepend `CompactSize(len(bitmap))` before `buf.Write(bitmap)`.
Use the existing `writeVarBytes` helper at `rest.go:1157-1171` (which
combines varint length + payload).

### BUG-12 (CDIV) — getutxos CCoin missing nTxVerDummy

**Where:** `rest.go:588-597` (per-utxo write).
**Core:** `rest.cpp:64-67`:

```cpp
SERIALIZE_METHODS(CCoin, obj) {
    uint32_t nTxVerDummy = 0;
    READWRITE(nTxVerDummy, obj.nHeight, obj.out);
}
```

Each CCoin is **4 bytes of zero** then `nHeight` (u32 LE) then `out`
(CTxOut: int64 nValue + CompactSize scriptlen + script). blockbrew
writes only height + value + script, missing the leading 4-byte zero.

**Impact:** every CCoin in the response is offset by 4 bytes. Any
client doing `<height> = ssGetUTXOResponse.ReadLE32()` reads zeros
(from the missing dummy field) instead of the height. Same as BUG-11
— hard wire-format break.

**Fix:** write 4 zero bytes via `writeUint32LE(&buf, 0)` before the
height in the CCoin loop.

### BUG-13 (CDIV) — getutxos outer outs[] missing CompactSize count

**Where:** `rest.go:587-597` loop body — no outer count.
**Core:** writes `outs` as `std::vector<CCoin>`, which prepends a
CompactSize count then iterates serializing each CCoin.

**Impact:** even if BUG-11 + BUG-12 are fixed, a client reading the
`outs` vector cannot know how many CCoins follow. Must guess via
trailing-EOF, which is impossible in HTTP-streamed bodies. Wire-format
break.

**Fix:** between the bitmap write and the CCoin loop, write
`CompactSize(len(result.UTXOs))` (use `writeVarBytes`-equivalent: the
CompactSize codec is identical at the prefix).

### BUG-14 (P1 CDIV) — getutxos uses float64 BTC then `* 100_000_000` to satoshis

**Where:** `rest.go:592-593`:
```go
valueSats := int64(utxo.Value * 100_000_000)
writeInt64LE(&buf, valueSats)
```
Where `utxo.Value` is `float64` BTC (see `RESTUTXOInfo` at
`rest.go:631-635`). Earlier at `queryUTXOs` (`rest.go:670`):
`Value: float64(entry.Amount) / 100_000_000,`

**Impact:** for values > 2^53 satoshis (~90 million BTC, theoretically
within int64 range but above float64 mantissa), the round-trip
`int64 → float64 → int64` is lossy. More importantly, for normal
amounts like `5,000,000,000` satoshis (50 BTC), the round-trip is
exact only because 50.0 is a clean binary float, but `0.0001` BTC
(10,000 sats) round-tripped through `* 100_000_000.0` yields
`9999.999999...` → `int64` truncates to **9999** sats. Off-by-one in
binary output for any non-power-of-two satoshi amount.

Core stores `CAmount nValue` (int64 sats) throughout `CTxOut` —
never goes through float.

**Fix:** keep `RESTUTXOInfo.Value` as int64 satoshis internally
(matches Core's `CAmount`); for JSON output, convert at the boundary
with `BitcoinAmount`-style formatting; for binary output, write the
internal int64 directly.

### BUG-15 (P2 MISSING) — /rest/headers/ only accepts deprecated /count/hash form

**Where:** `rest.go:309-313`:
```go
parts := strings.SplitN(path, "/", 2)
if len(parts) != 2 {
    restError(w, http.StatusBadRequest, "invalid URI format. Expected /rest/headers/<count>/<hash>.<ext>")
```

**Core:** `rest.cpp:191-205` accepts BOTH:
- deprecated `/rest/headers/<count>/<hash>` (path-size 2)
- modern `/rest/headers/<hash>?count=<count>` (path-size 1; count from
  `req->GetQueryParameter("count").value_or("5")`)

The modern form is what `bitcoin-cli` and most current REST clients
emit. blockbrew rejects the modern form with HTTP 400.

**Fix:** when `len(parts) == 1`, parse `r.URL.Query().Get("count")`
(default `"5"`); both code paths converge at the count-validation
step.

### BUG-16 (P2 MISSING) — /rest/blockfilterheaders/ only accepts deprecated /type/count/hash form

**Where:** `rest.go:1027-1031` requires `len(parts) == 3`.
**Core:** `rest.cpp:510-524` accepts BOTH path sizes (deprecated 3
with embedded count; modern 2 with query parameter).
**Fix:** same shape as BUG-15: when `parts == 2`, read `count` from
the query string.

### BUG-17 (P2 MISSING) — no warmup gating

**Where:** every REST handler in `rest.go` starts straight at request
processing. No `CheckWarmup` analog.
**Core:** `rest.cpp:171-177` (`CheckWarmup`) called as the first line
of every REST handler. Returns `HTTP 503 Service Unavailable: Service
temporarily unavailable: <status>` while `RPCIsInWarmup()` is true.

blockbrew has RPC-side warmup gating
(`internal/rpc/types.go:26 RPCErrInWarmup`,
`internal/rpc/methods.go:54` etc.) but never applies it to REST.

**Impact:** during the first few seconds of startup (before the chain
state is loaded), a REST request like `/rest/chaininfo.json` either
panics (nil-deref on chainMgr) or returns stale/empty data. Core
returns a 503 with a structured retry-friendly message.

**Fix:** add a `s.isWarmingUp()` accessor (true while
`chainMgr`/`headerIndex` not set OR initial load not done). Gate each
REST handler at the top.

### BUG-18 (P2 MISSING) — no BlockUntilSyncedToCurrentChain on filter REST

**Where:** `rest.go:981-985` (`bfi.GetFilter(node.Height)`) +
`rest.go:1099-1110` (filter-headers loop).
**Core:** `rest.cpp:563` (`index_ready = index->BlockUntilSyncedToCurrentChain();`)
blocks the request until the BIP-157 index has caught up with the
active chain. Without this, a request immediately after a new block
connect can get "filter not found" until the index thread catches up
asynchronously — flaky semantics.

**Cross-ref:** W133 G25 / BUG-13 (also documents the lack of
BlockUntilSyncedToCurrentChain on RPC); this is the REST analog.

**Fix:** add `BlockUntilSyncedToCurrentChain()` to `BlockFilterIndex`
(blocking wait with a chan signalled by the indexer worker); call it
before the per-height read in both `handleRESTBlockFilter` and
`handleRESTBlockFilterHeaders`.

### Subsystem B summary

| Severity | Count |
|----------|------:|
| CDIV     | 4     |
| P1 CDIV  | 1     |
| P2 MISSING | 4   |
| **Total REST BUGs** | **9** |

The four wire-format CDIVs (10, 11, 12, 13) cluster in one handler
(`getutxos`); a single rewrite of the binary serialiser flips all four.
The two path-form bugs (15, 16) are independent. Warmup (17) and
filter-sync (18) sit on missing primitives shared with RPC-side
audits.

---

## Subsystem C — Notification scripts (10 gates / 5 BUGs)

Files audited: `cmd/blockbrew/notify.go` (systemd `sd_notify`),
`cmd/blockbrew/main.go` (no `-*notify` flags),
`cmd/blockbrew/w124_operator_test.go` (prior partial audit — see
**cross-ref** below).

This subsystem is partially audited by **W124** already (the operator
experience wave); W141 extends and refines.

### Cross-reference — what W124 already documented

- **W124 BUG-10 (P2 missing):** no `-startupnotify` / `-shutdownnotify`
  CLI flags. (`cmd/blockbrew/w124_operator_test.go:406-416`).
- **W124 BUG-16 (P2 missing):** no `-blocknotify` / `-alertnotify` /
  `-walletnotify` CLI flags. (`w124_operator_test.go:571-592`).

W141 confirms both, adds 3 more gates on top.

| Gate | Behaviour | Verdict |
|------|-----------|---------|
| C1   | `-blocknotify=<cmd>` with `%s = blockhash` substitution | **BUG-19** (P2 missing — W124 BUG-16 sub-case) |
| C2   | `-alertnotify=<cmd>` with `%s = sanitised message` substitution | **BUG-20** (P2 missing — W124 BUG-16 sub-case) |
| C3   | `-walletnotify=<cmd>` with `%s=TxID`, `%w=wallet`, `%b=blockhash|unconfirmed`, `%h=blockheight|-1` | **BUG-21** (P2 missing — W124 BUG-16 sub-case) |
| C4   | `-startupnotify=<cmd>` fired after init complete | absorbed in W124 BUG-10 |
| C5   | `-shutdownnotify=<cmd>` fired during shutdown, joined synchronously | absorbed in W124 BUG-10 |
| C6   | Notify executions decoupled — each in its own goroutine, detached, never blocks consensus | (would be enforced if hooks existed) |
| C7   | `%s` substitution is **literal text replacement** — `-blocknotify="echo %s"` joins via shell, no exec-list escaping (Core: `system(strCmd)`). Notify command is therefore **shell-evaluated**; documented attack surface. | **BUG-22** (operator hardening): doc gap — there is no place to document the shell-injection surface because the hooks don't exist; once they're added, the operator-facing docs MUST warn about untrusted `%s` content. |
| C8   | `-alertnotify` arguments **sanitised** before substitution (`SanitizeString` in Core; single-quote-wrapped) | **BUG-23** (depends on BUG-20): when alertnotify is added, the `%s` must be sanitised (strip non-`SAFE_CHARS_USER_COMMENT`) before substitution and quoted. Otherwise an alert containing a backtick or `$( )` enables RCE. Core enforces this at `kernel_notifications.cpp:39-42`. |
| C9   | `walletnotify` `%w` escaping rule: per Core's `wallet/init.cpp:75` help text, `%w` is wallet-name and **must not** be quoted by the operator. Core relies on `ShellEscape` for the wallet-name itself but documents the requirement explicitly. | depends on BUG-21 |
| C10  | systemd `sd_notify` status string is newline-/control-char-sanitised (so a status line containing `STOPPING=1\n` cannot inject a second systemd directive) | **BUG-24** (P3 hardening) — `notify.go:72-74` writes `status` directly with no escape. A status payload built from untrusted-derived data (e.g. peer-supplied subver, or a remote alert message) could inject `STOPPING=1\n` or `MAINPID=…\n` directives. Currently the only call sites pass internal strings, so the exposure is latent; add escaping before any external-derived input is wired to `notifyStatus`. |

### BUG-19 (P2 MISSING) — no -blocknotify hook

**Where:** none — no flag parsing, no callback wiring.
**Core:** `init.cpp:498` declares `-blocknotify=<cmd>`; `init.cpp:2009-
2018` wires it: on every `NotifyBlockTip` with `sync_state == POST_INIT`,
spawns a detached thread running `runCommand(replaced_cmd)`.
**Impact:** the canonical Bitcoin "blockchain webhook" hook is unwired.
Operators using blockbrew for any "block-arrived" downstream automation
(payment-confirmation queues, watchtower triggers, sidechain pegs)
have no way to subscribe except polling RPC or wiring ZMQ — which is
heavier-weight than a fork-exec.

### BUG-20 (P2 MISSING) — no -alertnotify hook

**Where:** none. blockbrew has no alert subsystem at all (warning
emission is `log.Printf` only).
**Core:** `node/kernel_notifications.cpp:30-47` (`AlertNotify`) wired
from `KernelNotifications::warningSet` (kernel_notifications.cpp:82-
84). Fires when chain-state notes a soft-fork-warning, large reorg,
or transaction-pool overflow.

**Impact:** operators cannot get paged on consensus-relevant warnings
(48-block stale tip, unknown softfork detected, etc.). The only signal
is to tail the log.

### BUG-21 (P2 MISSING) — no -walletnotify hook

**Where:** none. The wallet subsystem (internal/wallet) has no
external-hook plumbing.
**Core:** `wallet/init.cpp:75` declares; `wallet/wallet.cpp:1480` +
`3069` set up the notify on every tx-status change.
**Impact:** the standard "wallet event webhook" for confirmation
counters, RBF replacement tracking, etc., is unwired.

### BUG-22 (DOCUMENTATION GAP, depends on BUG-19/20/21)

When the three hooks above are added, operator-facing docs MUST warn:

> `%s` substitution is **literal**. blockbrew (matching Core) uses
> `runCommand(strCmd)` which delegates to `/bin/sh -c <cmd>`. Any
> shell metacharacter in the substituted value (block hash is hex so
> safe; alert messages and wallet names are NOT safe) will be
> shell-evaluated. Always wrap `%s` in single quotes in the operator's
> `-blocknotify`/`-walletnotify` template.

Without this warning at the time of hook introduction, the first
attacker-controlled `subver` field or P2P address that flows into an
alert message becomes a one-shot RCE.

### BUG-23 (P2 — depends on BUG-20)

When `-alertnotify` is wired, blockbrew must implement Core's
sanitisation pass: `SanitizeString(msg, SAFE_CHARS_USER_COMMENT)`
before substitution, then wrap the substituted text in single quotes
(`'msg'`). Mirrors `kernel_notifications.cpp:39-42`. Skipping this
sanitisation is a CVE-class issue (alert content can be P2P-attacker-
controlled via a soft-fork-warning message).

### BUG-24 (P3 — sd_notify status escaping)

**Where:** `cmd/blockbrew/notify.go:72-74`:
```go
func notifyStatus(status string) {
    _, _ = sdNotify("STATUS=" + status + "\n")
}
```

**Issue:** if `status` contains an unescaped `\n`, systemd parses each
line as an independent directive. A status of
`"foo\nSTOPPING=1\nSTATUS=really bad"` would tell systemd the daemon
is shutting down.

**Current exposure:** all current callers (`notifyReady`,
`notifyStatus` from internal IBD progress) pass curated internal
strings; the exposure is **latent**. As soon as any peer-controlled
data (subver, agent string, IP) is plumbed in for richer status —
"Connected to peer @<addr>", "synced from <subver>" — the latency
closes and becomes exploitable by any P2P peer.

**Fix:** sanitise `status` by replacing `\n`, `\r`, `\x00` with `' '`
before concatenation. Cheap; do it now while the surface is still
internal-only.

### Subsystem C summary

| Severity | Count |
|----------|------:|
| P2 MISSING | 3   |
| Doc-gap  | 1     |
| P2 (depends) | 1 |
| P3 hardening | 1 |
| **Total NOTIFY BUGs** | **6** (with W124 cross-refs absorbing 5 of the 8 gates) |

Counting the 6 unique BUGs (19–24) and acknowledging W124's prior
BUG-10/16 partially covers 19/20/21 + 4/5 — the net additional NEW
issues uncovered by W141 are: **BUG-22** (doc gap),
**BUG-23** (sanitisation requirement), **BUG-24** (sd_notify escape).

---

## Aggregate findings

| Subsystem | BUGs | CDIV | P1 | P2 | P3 |
|-----------|-----:|-----:|---:|---:|---:|
| ZMQ       | 9    | 3    | 3  | 2  | 1  |
| REST      | 9    | 5    | 0  | 4  | 0  |
| NOTIFY    | 6    | 0    | 0  | 4  | 2  |
| **Total** | **24** | **8** | **3** | **10** | **3** |

**Top 5 findings, ordered by user-visible blast radius:**

1. **ZMQ BUG-1/2/3 (CDIV).** Every external ZMQ subscriber (Core-tested
   downstream) reads hashes in the wrong byte order. Critical interop
   break with the entire "Bitcoin sidecar" tool ecosystem.
2. **REST BUG-11/12/13/14 (CDIV).** `/rest/getutxos` binary output is
   byte-incompatible with Core in three independent ways (missing
   bitmap CompactSize, missing nTxVerDummy per CCoin, missing outer
   outs count, plus float64 lossy round-trip). BIP-64 clients fail to
   parse the response.
3. **ZMQ BUG-4/5/6 (P1 missing).** No fan-out on block disconnect, no
   fan-out on mempool removal, no per-tx fan-out on block connect.
   Reorgs are invisible to ZMQ subscribers — every Core-trained
   downstream tool (electrs, fulcrum, mempool.space, nbxplorer) will
   silently desync.
4. **NOTIFY BUG-19/20/21 + W124 BUG-10.** Five operator script hooks
   missing (`-blocknotify`, `-alertnotify`, `-walletnotify`,
   `-startupnotify`, `-shutdownnotify`). Standard Bitcoin operator
   workflow has no exec-fan-out at all.
5. **REST BUG-17 / BUG-18 (P2 missing).** No warmup gating on any REST
   handler (early-startup requests get nil-derefs or empty payloads
   instead of HTTP 503); no `BlockUntilSyncedToCurrentChain` blocking
   wait on filter REST (flaky semantics at block-connect boundaries).

**Universal patterns observed:**

- **"byte-reversal-omitted"** (ZMQ BUG-1/2/3): the consistent skip of
  Core's display-order reversal on hash payload. Worth watching as a
  fleet-wide pattern in W141 sibling audits (clearbit, hotbuns, etc.)
  — Bitcoin Core's `data[31-i] = hash.begin()[i]` is easy to miss when
  porting because Go/Zig/Lua have first-class slice-copy idioms that
  don't naturally reverse.
- **"binary-wire-format-shortcut"** (REST BUG-11/12/13): when a
  developer ports a Core response, they often "look at the bytes I
  send" and miss the length-prefixes and serialization framing that
  C++'s `<<` operator inserts implicitly. Pattern: every place
  blockbrew emits binary, audit against Core's actual serialiser
  output, not against a human-readable hex-dump.
- **"shell-injection-via-percent-s"** (NOTIFY BUG-22/23): the
  `-*notify=<cmd>` family interprets `%s` literally inside a shell
  string. Any port adding these hooks WITHOUT the SanitizeString +
  single-quote-wrap will introduce a CVE. blockbrew is currently
  safe because the hooks don't exist; W141 documents the trap so a
  future fix wave doesn't fall in.
