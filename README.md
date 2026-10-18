# blockbrew

A Bitcoin full node written from scratch in Go. One of the ten [hashhog](https://github.com/hashhog) nodes.

> **Experimental.** hashhog nodes are independent re-implementations of Bitcoin Core for research and testing. Do not use them with real funds.

## Status

| Area | State |
|---|---|
| Consensus | Block, transaction and script validation through Taproot. Passes all of Bitcoin Core's `script_tests.json` and `sighash.json` vectors; see [docs/status.md](docs/status.md) to rerun them. |
| Mainnet validation | Syncs mainnet. Its UTXO-set hasher reproduces Core's `hash_serialized_3` at height 958,794 from Core's snapshot file; a from-genesis replay to that height has not been re-run on the current code. See [docs/status.md](docs/status.md). |
| RPC | 143 JSON-RPC methods modelled on Core's, plus a REST interface. Known differences in [docs/rpc.md](docs/rpc.md). |
| P2P | Headers-first sync, inbound and outbound peers, BIP-324 v2 transport, addrv2, compact blocks (partial). |
| Wallet | HD wallet (BIP-32/39/84), multi-wallet, PSBT, descriptors. No custody audit. |
| Known limitations | UTXO flush is not serialised against block connection; `-reindex` is not implemented. See [docs/status.md](docs/status.md). |

Last updated: 2026-10-16.

## Quick start

Needs Go 1.24 or newer ([go.dev/dl](https://go.dev/dl/)), a C compiler, `pkg-config`, and
libsecp256k1 0.4 or newer built with the ellswift module (Debian 13 packages 0.5.0). The
build uses cgo. On Debian/Ubuntu:

```bash
sudo apt-get install -y build-essential pkg-config libsecp256k1-dev git
git clone https://github.com/hashhog/blockbrew.git
cd blockbrew
make build
./blockbrew -version
```

Start a regtest node in a throwaway data directory and make an RPC call:

```bash
export DATADIR=$(mktemp -d)
./blockbrew -network=regtest -datadir="$DATADIR" -metricsport=0 > "$DATADIR/node.log" 2>&1 &
sleep 2
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

More detail, including a reproducible-build recipe, is in [docs/building.md](docs/building.md).

## Running

```bash
./blockbrew -network=mainnet  -datadir="$HOME/.blockbrew"
./blockbrew -network=testnet4 -datadir="$HOME/.blockbrew"
./blockbrew -network=signet   -datadir="$HOME/.blockbrew"
./blockbrew -network=regtest  -datadir="$HOME/.blockbrew"
```

`-network=testnet` selects testnet3. For every network except mainnet the node uses a
subdirectory named after the network (`$DATADIR/regtest`, `$DATADIR/testnet4`, ...).

| Network | P2P port | RPC port |
|---|---|---|
| mainnet | 8333 | 8332 |
| testnet4 | 48333 | 48332 |
| testnet3 | 18333 | 18332 |
| signet | 38333 | 38332 |
| regtest | 18444 | 18443 |

RPC binds to `127.0.0.1` by default. A Prometheus metrics endpoint listens on
`0.0.0.0:9332` unless you pass `-metricsport=0` or another port.

A full mainnet node keeps every block, like Core without pruning: plan for at least
1 TB of fast disk. `-prune=550` (or larger, in MiB) keeps only recent blocks. The UTXO cache
is set by `-dbcache` (default 2560 MiB); give the machine at least 8 GB of RAM, more for a
faster initial sync.

All flags, the config file format, the data directory layout and logging are in
[docs/running.md](docs/running.md).

## RPC

blockbrew aims to match Bitcoin Core's JSON-RPC interface: same method names, parameters
and result shapes. It accepts HTTP Basic auth with either the `.cookie` file written to the
data directory at startup or `-rpcuser`/`-rpcpassword`:

```bash
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" \
  -d '{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:18443/
```

The method list and known differences from Core are in [docs/rpc.md](docs/rpc.md).

## Development

```bash
make test
```

runs `go test ./...` (see [docs/status.md](docs/status.md) for what it covers).

```
cmd/blockbrew/      node entrypoint, flags, config file, ZMQ, logging
cmd/script_test/    runs Core's script_tests.json against the interpreter
cmd/sighash_test/   runs Core's sighash.json against the sighash code
internal/consensus/ validation, chain manager, UTXO set, snapshots
internal/script/    script interpreter
internal/p2p/       peers, addrman, header and block sync
internal/mempool/   mempool policy, package relay, fee estimation
internal/rpc/       JSON-RPC and REST server
internal/wallet/    HD wallet, PSBT, descriptors
```

The full map is in [docs/architecture.md](docs/architecture.md). See
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
