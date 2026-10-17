# Running blockbrew

## Networks and ports

| `-network=` | Chain | P2P port | RPC port | Data subdirectory |
|---|---|---|---|---|
| `mainnet` (default) | mainnet | 8333 | 8332 | none (`$DATADIR` itself) |
| `testnet4` | testnet4 | 48333 | 48332 | `testnet4/` |
| `testnet` | testnet3 | 18333 | 18332 | `testnet/` |
| `signet` | default signet | 38333 | 38332 | `signet/` |
| `regtest` | regtest | 18444 | 18443 | `regtest/` |

Ports can be changed with `-listen=<host:port>` (P2P) and `-rpcbind=<host:port>` (RPC). RPC
binds to `127.0.0.1` unless you say otherwise.

## Command-line flags

Flags use Go's syntax: `-flag=value` or `-flag value`, and booleans as `-flag` or
`-flag=false`. `./blockbrew -h` prints this list with the full help text.

### General

| Flag | Default | Meaning |
|---|---|---|
| `-network` | `mainnet` | `mainnet`, `testnet4`, `testnet` (testnet3), `signet`, `regtest` |
| `-datadir` | `~/.blockbrew` | data directory |
| `-conf` | see below | path to a config file |
| `-daemon` | false | fork into the background |
| `-pid` | `<datadir>/blockbrew.pid` | pid file |
| `-version` | | print the version and exit |

### Validation and storage

| Flag | Default | Meaning |
|---|---|---|
| `-dbcache` | 2560 | cache size in MiB: 80% UTXO cache, 20% Pebble block cache |
| `-assumevalid` | built-in per network | skip script checks below this block hash; `-assumevalid=0` verifies every script |
| `-par` | 0 | script-check threads: 0 = all cores, 1 = serial, n<0 = leave \|n\| cores free |
| `-parallelscripts` | true | enable parallel script validation |
| `-prune` | 0 | 0 = keep all blocks; 1 = manual (`pruneblockchain`); ≥550 = target MiB of block files. 2–549 are rejected |
| `-txindex` | false | transaction index (needed by `getrawtransaction` for confirmed transactions) |
| `-blockfilterindex` | false | BIP-157/158 basic filter index (`getblockfilter`, `/rest/blockfilter`) |
| `-coinstatsindex` | false | per-height UTXO statistics for `gettxoutsetinfo` at a past height |
| `-txospenderindex` | false | spent-outpoint index for `gettxspendingprevout` on confirmed spends |
| `-load-snapshot` | | load a Core-format UTXO snapshot at startup on a fresh datadir |
| `-reindex` | false | not implemented; the node refuses to start when it is set |

### P2P

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `:<network P2P port>` | P2P listen address |
| `-nolisten` | false | no inbound connections |
| `-maxoutbound` | 8 | outbound connection limit |
| `-maxinbound` | 117 | inbound connection limit |
| `-connect` | | connect only to these `ip:port` peers (repeatable or comma-separated); disables DNS seeds and automatic outbound |
| `-nodnsseed` | false | skip DNS seeds but keep automatic outbound |
| `-fixedseeds` | true | fall back to built-in seed addresses when DNS seeding finds nothing |
| `-externalip` | | address to advertise (repeatable) |
| `-discover` | true | learn our public address from peers (off when `-externalip` is set) |
| `-asmap` | | ASMap file for AS-level peer diversity |
| `-bip324v2` | true | BIP-324 v2 encrypted transport, with v1 fallback. Env: `BLOCKBREW_BIP324_V2=0/1` |
| `-packagerelay` | false | BIP-331 package relay messages. Env: `BLOCKBREW_PACKAGE_RELAY=0/1` |
| `-peerbloomfilters` | false | advertise NODE_BLOOM and serve BIP-37 filters |

### Mempool and mining

| Flag | Default | Meaning |
|---|---|---|
| `-maxmempool` | 300 | mempool size limit in MB |
| `-minrelayfee` | 0.000001 | minimum relay fee in BTC/kvB (100 sat/kvB, as in Core) |
| `-mempoolfullrbf` | true | accept replacements without BIP-125 signalling |
| `-mineraddress` | | payout address for block templates |

### RPC and REST

| Flag | Default | Meaning |
|---|---|---|
| `-rpcbind` | `127.0.0.1:<network RPC port>` | RPC listen address |
| `-rpcuser` | `blockbrew` | RPC user name |
| `-rpcpassword` | empty | RPC password. Cookie auth works regardless |
| `-rest` | false | serve unauthenticated REST under `/rest/` on the RPC port |
| `-rpc-tls-cert`, `-rpc-tls-key` | | serve RPC and REST over HTTPS; both must be given |
| `-rpcready-notify` | true | send systemd `READY=1` once RPC is up, when `NOTIFY_SOCKET` is set |
| `-wallet` | `wallet.dat` | wallet file name |

### Logging, metrics, notifications

| Flag | Default | Meaning |
|---|---|---|
| `-loglevel` | `info` | `debug`, `info`, `warn`, `error` |
| `-debug` | | log categories (repeatable): `net`, `mempool`, `validation`, `rpc`, ..., `all`, `none`, `-<cat>` to negate |
| `-logfile` | stderr | log file; `SIGHUP` reopens it |
| `-printtoconsole` | false | also log to the console when `-logfile` is set |
| `-metricsport` | 9332 | Prometheus `/metrics` on `0.0.0.0:<port>`; 0 disables |
| `-healthport` | 0 | `/healthz` and `/readyz` on `127.0.0.1:<port>`; 0 disables |
| `-pprof` | | Go pprof server address, e.g. `localhost:6060` |
| `-zmqpubhashblock`, `-zmqpubhashtx`, `-zmqpubrawblock`, `-zmqpubrawtx`, `-zmqpubsequence` | | ZMQ endpoints, as in Core (e.g. `tcp://127.0.0.1:28332`) |

## Config file

blockbrew reads a Core-style `key=value` file. It looks for, in order:

1. the file given by `-conf=<path>` (missing file is an error);
2. `<datadir>/blockbrew.conf` (the top-level datadir, not the network subdirectory);
3. `~/.blockbrew/blockbrew.conf`.

Keys are flag names without the leading dash. Lines starting with `#` are comments; inline
comments are not supported. Keys inside `[main]`, `[test]`, `[testnet4]`, `[signet]` or
`[regtest]` apply only to that network. Flags on the command line override the file;
unknown keys are logged and ignored.

```ini
rpcuser=alice
rpcpassword=change-me

[regtest]
txindex=1
```

Try it on a throwaway regtest node:

```bash
export DATADIR=$(mktemp -d)
printf 'rpcuser=alice\nrpcpassword=change-me\n\n[regtest]\ntxindex=1\n' > "$DATADIR/blockbrew.conf"
./blockbrew -network=regtest -datadir="$DATADIR" -metricsport=0 > "$DATADIR/node.log" 2>&1 &
sleep 2
curl -s --user alice:change-me -d '{"method":"getindexinfo","params":[]}' http://127.0.0.1:18443/
curl -s --user alice:change-me -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

`config.example.toml` in the repository root uses TOML sections that this parser does not
recognise; use the format above.

## Data directory

For a regtest node started with `-datadir=$DATADIR`. `blocks/`, `chaindata/`, `.cookie` and
the pid file exist as soon as the node is up; the others are written once there is
something to save, at the latest on the first clean shutdown.

```
$DATADIR/regtest/
  blocks/blk00000.dat   raw blocks (Core-style flat files)
  chaindata/            Pebble database: block index, chainstate, indexes
  wallets/<name>/       wallets created with createwallet
  wallet.dat            default wallet (-wallet)
  mempool.dat           mempool saved at shutdown
  fee_estimates.json    fee estimator state
  peers.json            address book
  anchors.json          block-relay-only anchors kept across restarts
  .cookie               RPC cookie (deleted at shutdown)
  blockbrew.pid         pid file
```

On mainnet the same layout sits directly in `$DATADIR`.

## Resources

- Disk: an unpruned mainnet node stores every block, as Core does; plan for at least 1 TB of
  SSD. `-prune=550` or more keeps only recent block files (headers, the UTXO set and the
  last 288 blocks are always kept).
- Memory: resident memory grows with `-dbcache`. The default 2560 MiB is fine for
  following the tip; a larger value (4096 or more) speeds up initial sync. Loading a
  snapshot with `-load-snapshot` peaks at about three times the UTXO share of `-dbcache`.
- CPU: script checks use every core by default (`-par`).

## Subcommands

| Command | What it does |
|---|---|
| `blockbrew version` | print the version |
| `blockbrew wallet create` | print a new BIP-39 mnemonic (does not create a wallet file) |
| `blockbrew wallet import` | validate a mnemonic read from stdin |
| `blockbrew import-blocks -network=<net> -datadir=<dir>` | connect blocks read from stdin, framed as `[height u32 LE][size u32 LE][raw block]` |

To create and use wallets, use the `createwallet` and `loadwallet` RPCs on a running node.

## Monitoring

`/metrics` on the metrics port is in Prometheus text format. With `-pprof=localhost:6060`
the standard Go endpoints are available:

```bash
go tool pprof http://localhost:6060/debug/pprof/heap
curl -s 'http://localhost:6060/debug/pprof/goroutine?debug=1' | head
```
