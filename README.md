# blockbrew

A Bitcoin full node written from scratch in Go. Part of the [Hashhog](https://github.com/hashhog/hashhog) project.

## Status — v1.0.0

**Label: "Validated — DISPUTED"** (`receipts/RELEASE-v1.0-SCORECARD.md`,
§The table). blockbrew is the one node in the fleet whose Validated label is
contradicted by a second committed artifact, and the suffix is part of the label
so a skim cannot miss it — the detail is two paragraphs down, and the governing
document says the pair "must not be counted either way until adjudicated". If the
later capture is authoritative, blockbrew is not Validated and the fleet count is
4/10, not 5/10.

The undisputed half of the label — "reproduced Core's UTXO set from genesis with
all scripts verified" — means one specific thing: blockbrew connected every mainnet block from block 0
to height 958,794 with its assumevalid gate off, serialized its entire UTXO set,
and produced the byte string
`29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` over
166,180,925 coins — the same value Bitcoin Core's `dumptxoutset` produced at that
height. A single wrong coin anywhere in fifteen years changes that hash — the *capture* is unfakeable. **The lineage under it is not checkable from a clone:** what the ledger row records is height, hash and coin count; that the chain beneath was built from genesis with assumevalid off rests on the row's `lineage receipt` column, and four of the five rows point at logs under `/home/work/genesis-ibd/logs/` — outside any repository and uncommitted — while blockbrew's says only `--commit` (`receipts/TRUST-ANCHOR.md:141-145`). The git
tag `v0.1.0-rc2` (`receipts/RELEASE-v1.0-FREEZE.md`) marks the same bar: `rc` in this
project certifies that reproduction and nothing else
(`receipts/beta1-tag-drafts-2026-08-20.md:23-27`). Neither label certifies wallet
or fund-custody readiness — see `SECURITY.md`.

**But two committed artifacts disagree about whether blockbrew has actually done
that, and nothing in the repository resolves them** — the release scorecard
reports both rather than picking one:

- `receipts/TRUST-ANCHOR.md:143` records a MATCH — 2026-08-14T18:20:25Z, height
  958794, `hash_serialized_3`
  `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0`,
  166,180,925 coins. `receipts/r4-blockbrew-t2-3-2026-08-14.md` narrates it.
- `receipts/T2-capture-blockbrew-20260815T125623Z.md`, dated one day later, says
  "blockbrew does NOT reproduce C(958794). Do NOT tag." with
  `24ec9202799b6eafbee0a931fb6f4ac543c0e520652cbae594cec6c3168e7a5a` and
  166,180,926 coins — one coin more than the anchor.

The committed genesis → 250000 replay ledger
(`CORE-PARITY-AUDIT/replay-ledgers/blockbrew-av0-danger-ledger.txt`) is the
**pre-fix** run and ends `overall=FAIL@250000`, wedged at height 231020 on the
empty-`scriptPubKey` bug fixed in `fa082e8`. The post-fix pass to 250000 exists
only as prose in `receipts/bug-ledger.md:1298` and `docs/METHODOLOGY.md:154`; no
post-fix ledger file was ever committed.

**Operator RPC parity: 58 of Bitcoin Core's 85.** From the 103-method R5
operator probe run 2026-09-01
(`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`): blockbrew 58 PASS /
27 FAIL, Bitcoin Core 85 PASS on the same probe, 18 methods unmeasured
(`SKIP-REGTEST`) for every node including Core. Most failures are error-code
mismatches (e.g. `getblockstats` on a missing block returns `-1` where Core
returns `-5`).

**Known gaps in this repo** (`receipts/UNIT-BASELINE-v1.0.md`, 2026-09-01): the
unit suite went 31 failing → 0, but two gaps are carried as explicit skips —
`GAP W124-BUG17-KNOBS` (`verifychain` `-checkblocks`/`-checklevel` knobs) and
`BUG-6` (per-transaction ZMQ fan-out; `zmqpub.go` has only
`PublishBlockConnected`/`PublishTxAccepted`). Separately, the assumeUTXO
snapshot-boot gate: `receipts/boot-smoke-4-red-triaged-2026-08-16.md:28-45` found
`loadtxoutset` deserialising into a throwaway in-memory DB and returning success
without activating the snapshot, while `CORE-PARITY-AUDIT/_loop-ledger.md`
(2026-08-21) records that `ActivateSnapshotWithBackground` was wired to that
handler in `a38b4c1` *before* the receipt was written, and concludes the finding
needs an empirical re-run of `tools/boot-smoke.sh` to settle. Treat assumeUTXO
activation as unsettled.

**Fleet-wide comparison:** `receipts/RELEASE-v1.0-SCORECARD.md` in the
[hashhog meta-repo](https://github.com/hashhog/hashhog).

> Paths beginning `receipts/`, `tools/`, `docs/` and `CORE-PARITY-AUDIT/` refer to
> the hashhog meta-repo, not to this repository.
> **Two notes on the citations above.** The R5 probe JSON is **gitignored** in the
> meta-repo (`.gitignore:60  tools/diff-test-artifacts/`), so a stranger cloning
> either repository cannot read it; regenerate it with `python3 tools/r5_probe.py`
> against a running fleet. The nightly `diffguard-*.log` files are likewise
> gitignored (`.gitignore:43  *.log`). Paths under `receipts/`, `docs/` and
> `CORE-PARITY-AUDIT/` are tracked, but in the **meta-repo**, not here.

## Known limitations

**GAP-BB-FLUSH-RACE — the UTXO flush is not serialised against block
connection.** Found 2026-09-02 by adversarial review; reproduced by four
probes committed at `internal/consensus/flush_race_gap_test.go` (skipped, with
the reason in the file header).

The coins-database marker that says which block the on-disk UTXO set reflects
is enforced only *inside* a flush call. Nothing prevents a flush from running
concurrently with a connect or a reorg, so:

- A `scantxoutset`-driven flush during a **rejected** `ConnectBlock` makes that
  block's spends durable. `rollbackUTXOs` undoes them in memory only.
- The same during a **failed reorg** is permanent and needs no crash, despite
  the reorg path's own comment claiming the on-disk state is untouched until
  its final batch write.

**What this means if you run this node:** under concurrent `scantxoutset` (or
any other RPC that drives a UTXO scan) at the moment a block is rejected or a
reorg fails, the persisted coin set can end up reflecting state that was never
accepted. The block hash and tip stay correct, so the node looks healthy. This
is pre-existing, not a regression; the marker work in `f369d96`/`dd791f6`
made it visible.

Closing it needs a transaction boundary between "flush the coin set" and
"connect a block" — a design change rather than a patch. Two rounds of
path-by-path fixes each closed their named paths and exposed the next one,
which is why this is written down instead of patched again. The reasoning is
in the meta-repo at `CORE-PARITY-AUDIT/_loop-ledger.md`.

**Related, and closed:** crash recovery used to re-apply already-applied
coinbase-only blocks, resurrecting a coinbase a later block had already spent.
That is fixed and pinned (`internal/consensus/coins_marker_invariant_test.go`);
it is what led to the review that found the race above.

## Quick Start

### Build from Source

```bash
# Requires Go 1.24.0 or newer (pinned in go.mod); no cgo or system libraries beyond build-essential.
# Install dependencies (Debian/Ubuntu)
sudo apt-get install -y build-essential

# Build
make build
# or: go build -o blockbrew ./cmd/blockbrew

# Run on testnet4
./blockbrew -network testnet4

# Run on mainnet
./blockbrew -network mainnet -datadir ~/.blockbrew
```

## Features

- Full block and transaction validation (BIP-16, BIP-34, BIP-65, BIP-66, BIP-68, BIP-141, SegWit, Taproot)
- Script interpreter supporting P2PKH, P2SH, P2WPKH, P2WSH, and P2TR
- Cryptographic primitives (SHA256, RIPEMD160, secp256k1, ECDSA, Schnorr)
- Address encoding (Base58Check, Bech32, Bech32m)
- Headers-first sync with parallel block downloads
- UTXO set with L1 cache, script compression, and batched flushes
- Pebble database backend tuned for Bitcoin workloads
- Chain manager with block connection, reorg handling, and undo data
- Transaction mempool with fee tracking, CPFP, orphan pool, and eviction
- Package relay (submitpackage RPC)
- Fee estimation with confirmation tracking
- Block template construction (transaction selection, witness commitment)
- HD wallet (BIP-32/39/84, P2WPKH addresses)
- Multi-wallet support (create, load, unload, backup, list)
- Wallet encryption with passphrase
- Address labels (setlabel, listlabels, getaddressesbylabel)
- PSBT support (BIP-174/370: create, decode, combine, finalize, analyze, join, convert, wallet process, utxo update)
- Output descriptors (getdescriptorinfo, deriveaddresses)
- assumeUTXO (dumptxoutset, loadtxoutset, getchainstates) — snapshot *activation* is disputed between two committed receipts; see Status above
- Block indexes (txindex, BIP-157/158 blockfilterindex via getblockfilter, getindexinfo)
- Chain management RPCs (invalidateblock, reconsiderblock, preciousblock)
- Checkpoint verification with fork rejection during header sync
- Signature verification cache (avoids redundant script checks during IBD)
- Parallel script validation for IBD performance
- Misbehavior scoring and peer banning
- REST API (block, headers, tx in JSON/hex/binary)
- Regtest mode with generatetoaddress, generatetodescriptor, generateblock, and generate RPCs
- pprof profiling endpoint for CPU, memory, and trace analysis

## Configuration

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-network` | Network: mainnet, testnet, regtest, signet | `mainnet` |
| `-datadir` | Data directory | `~/.blockbrew` |
| `-listen` | P2P listen address | network default |
| `-nolisten` | Disable inbound P2P connections | `false` |
| `-rpcbind` | RPC listen address | network default |
| `-rpcuser` | RPC username | `blockbrew` |
| `-rpcpassword` | RPC password | |
| `-maxoutbound` | Maximum outbound connections | `8` |
| `-maxinbound` | Maximum inbound connections | `117` |
| `-maxmempool` | Maximum mempool size in MB | `300` |
| `-minrelayfee` | Minimum relay fee (BTC/kvB) | `0.00001` |
| `-txindex` | Enable transaction index | disabled |
| `-parallelscripts` | Enable parallel script validation | `true` |
| `-mineraddress` | Address for mining rewards | |
| `-wallet` | Wallet file name | `wallet.dat` |
| `-loglevel` | Log level: debug, info, warn, error | `info` |
| `-pprof` | pprof HTTP server address (e.g., `localhost:6060`) | disabled |
| `-version` | Print version and exit | |

## RPC API

> **Parity note.** These methods are modelled on Bitcoin Core's, but shape parity is not
> behaviour parity. On the 2026-09-01 operator probe blockbrew answers 58 of the 103
> probed methods correctly against Core's 85, and 27 probes fail — mostly on error
> codes (`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`).

### Blockchain

| Method | Description |
|--------|-------------|
| `getblockchaininfo` | Returns blockchain processing state info |
| `getblockcount` | Returns height of the most-work fully-validated chain |
| `getbestblockhash` | Returns hash of the best (tip) block |
| `getblockhash` | Returns hash of block at given height |
| `getblock` | Returns block data for a given hash |
| `getblockheader` | Returns block header data |
| `getdifficulty` | Returns proof-of-work difficulty |
| `getchaintips` | Returns information about all known tips in the block tree |
| `gettxout` | Returns details about an unspent transaction output |
| `getindexinfo` | Returns index status information |
| `getblockfilter` | Returns BIP-157/158 compact block filter |
| `invalidateblock` | Marks a block as invalid |
| `reconsiderblock` | Removes invalidity status from a block |
| `preciousblock` | Treats a block as if it were received first at its height |
| `getchainstates` | Returns chainstate info (for assumeUTXO) |
| `dumptxoutset` | Dumps the UTXO set to a file |
| `loadtxoutset` | Loads a UTXO snapshot for assumeUTXO |

### Transactions

| Method | Description |
|--------|-------------|
| `getrawtransaction` | Returns raw transaction data |
| `sendrawtransaction` | Submits a raw transaction to the network |
| `decoderawtransaction` | Decodes a hex-encoded raw transaction |
| `createrawtransaction` | Creates an unsigned raw transaction |
| `signrawtransactionwithwallet` | Signs a raw transaction with wallet keys |
| `decodescript` | Decodes a hex-encoded script |
| `testmempoolaccept` | Tests whether a raw transaction would be accepted by the mempool |

### Mempool

| Method | Description |
|--------|-------------|
| `getmempoolinfo` | Returns mempool state details |
| `getrawmempool` | Returns all transaction IDs in the mempool |
| `getmempoolentry` | Returns mempool data for a given transaction |
| `getmempoolancestors` | Returns all in-mempool ancestors for a transaction |
| `getmempooldescendants` | Returns all in-mempool descendants for a transaction |
| `submitpackage` | Submits a package of transactions |

### Network

| Method | Description |
|--------|-------------|
| `getnetworkinfo` | Returns P2P networking state info |
| `getpeerinfo` | Returns data about each connected peer |
| `getconnectioncount` | Returns the number of connections |
| `addnode` | Adds or removes a peer |
| `disconnectnode` | Disconnects a peer |
| `listbanned` | Lists all banned IPs/subnets |
| `setban` | Adds or removes an IP/subnet from the ban list |
| `clearbanned` | Clears all banned IPs |

### Mining

| Method | Description |
|--------|-------------|
| `getblocktemplate` | Returns a block template for mining |
| `submitblock` | Submits a new block to the network |
| `submitblockbatch` | Submits multiple blocks in one call |
| `getmininginfo` | Returns mining-related information |
| `estimatesmartfee` | Estimates fee rate for confirmation within N blocks |
| `generatetoaddress` | Mines blocks to an address (regtest only) |
| `generatetodescriptor` | Mines blocks to a descriptor (regtest only) |
| `generateblock` | Mines a block with specific transactions (regtest only) |
| `generate` | Mines blocks (regtest only) |

### Wallet

| Method | Description |
|--------|-------------|
| `createwallet` | Creates a new wallet |
| `loadwallet` | Loads a wallet from disk |
| `unloadwallet` | Unloads a wallet |
| `listwallets` | Lists loaded wallets |
| `listwalletdir` | Lists wallet files in the wallet directory |
| `backupwallet` | Backs up the wallet to a file |
| `getnewaddress` | Generates a new receiving address |
| `getbalance` | Returns wallet balance |
| `listunspent` | Lists unspent outputs |
| `sendtoaddress` | Sends bitcoin to an address |
| `listtransactions` | Lists wallet transactions |
| `getwalletinfo` | Returns wallet state info |
| `getaddressinfo` | Returns address info |
| `walletpassphrase` | Unlocks an encrypted wallet |
| `walletlock` | Locks the wallet |
| `setlabel` | Sets an address label |
| `listlabels` | Lists all labels |
| `getaddressesbylabel` | Returns addresses with a given label |

### Descriptors and PSBT

| Method | Description |
|--------|-------------|
| `getdescriptorinfo` | Analyzes and checksums an output descriptor |
| `deriveaddresses` | Derives addresses from a descriptor |
| `createpsbt` | Creates a PSBT |
| `decodepsbt` | Decodes a base64 PSBT |
| `combinepsbt` | Combines multiple PSBTs |
| `finalizepsbt` | Finalizes a PSBT |
| `converttopsbt` | Converts a raw transaction to a PSBT |
| `walletprocesspsbt` | Signs a PSBT with wallet keys |
| `analyzepsbt` | Analyzes a PSBT for completion status |
| `joinpsbts` | Joins multiple PSBTs into one |
| `utxoupdatepsbt` | Updates PSBT with UTXO data |

### Utility

| Method | Description |
|--------|-------------|
| `validateaddress` | Validates a Bitcoin address |
| `verifymessage` | Verifies a signed message |
| `getinfo` | Returns general node info |
| `uptime` | Returns server uptime in seconds |
| `stop` | Stops the node |
| `help` | Lists available RPC commands |

## Monitoring

### pprof

Enable the pprof HTTP endpoint for runtime profiling:

```bash
./blockbrew -pprof localhost:6060
```

Then use Go's profiling tools:

```bash
# CPU profile (30 seconds)
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# Heap profile
go tool pprof http://localhost:6060/debug/pprof/heap

# Goroutine dump
curl http://localhost:6060/debug/pprof/goroutine?debug=2

# Execution trace
go tool trace <(curl http://localhost:6060/debug/pprof/trace?seconds=5)
```

## Architecture

blockbrew is structured as a standard Go project with the main entrypoint in `cmd/blockbrew/` and all core logic in `internal/` packages. The `wire` package handles Bitcoin protocol message serialization with varint and CompactSize encoding. The `crypto` package provides SHA256d, RIPEMD160, secp256k1 ECDSA and Schnorr verification. The `address` package encodes and decodes Base58Check, Bech32, and Bech32m addresses. The `script` package implements a complete Bitcoin script interpreter covering P2PKH, P2SH, P2WPKH, P2WSH, and P2TR.

The `consensus` package contains block and transaction validation, the chain manager, UTXO set management, and profiling support. The UTXO set uses an L1 in-memory cache with script compression for compact storage and batched flushes to the underlying Pebble database. Chain management handles block connection and disconnection with undo data for reorganizations. A signature verification cache avoids redundant script checks during IBD, and parallel script validation distributes signature verification across multiple goroutines.

The `storage` package provides the Pebble database backend, chosen for its write-optimized LSM-tree design that handles Bitcoin's heavy write workload during IBD. The `p2p` package manages peer connections with TCP version/verack handshakes, DNS seed discovery, misbehavior scoring, and ban lists. Headers-first sync with checkpoint verification rejects forks below known-good heights. Block download runs in parallel with stall detection.

The `mempool` package implements transaction pool management with fee tracking, Child-Pays-For-Parent (CPFP), an orphan pool for transactions with missing inputs, and eviction policies. The `mining` package constructs block templates by selecting transactions for optimal feerate and generating witness commitments. The `rpc` package exposes a JSON-RPC server with HTTP Basic Auth that follows Bitcoin Core's method names and response shapes, supporting batch requests, wallet operations, PSBT workflows, and a REST API for block/tx queries in JSON, hex, and binary formats. Shape parity is not behaviour parity — the 2026-09-01 operator probe scores blockbrew 58 against Core's 85, with most failures on error codes.

The `wallet` package provides BIP-32/39/84 HD key derivation with P2WPKH address generation, multi-wallet support (create, load, unload, backup), passphrase encryption, and address labeling. Go's goroutine model provides the concurrency backbone: each peer connection runs in its own goroutine, and IBD leverages goroutine pools for parallel script validation while maintaining single-goroutine UTXO state updates.

## Project Structure

```
cmd/blockbrew/     main entrypoint, CLI, configuration
internal/
  consensus/       validation, chain manager, UTXO set, profiling
  script/          script interpreter
  p2p/             peer-to-peer networking, sync
  storage/         database layer (pebble)
  mempool/         transaction pool, fee estimation
  rpc/             JSON-RPC server, REST API
  wallet/          hd wallet (bip32/39/84)
  mining/          block template and PoW
  crypto/          hashing, keys, ecdsa, schnorr
  wire/            protocol serialization
  address/         address encoding
```

## Running Tests

```bash
make test              # unit tests
make test-race         # with race detector
make bench             # benchmarks
make profile-cpu       # CPU profiling
```

## License

MIT
