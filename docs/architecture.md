# Architecture

blockbrew is a single Go binary. `cmd/blockbrew/main.go` parses flags and the config file,
opens storage, builds the chain manager, mempool, peer manager, wallet manager and RPC
server, and wires them together. Everything else lives under `internal/`.

## Moving parts

| Part | Where | What it does |
|---|---|---|
| Wire format | `internal/wire` | transaction, block and header types; CompactSize and serialization |
| Crypto | `internal/crypto` | SHA-256d, RIPEMD-160, ECDSA and Schnorr (cgo libsecp256k1), ElligatorSwift and ChaCha20-Poly1305 for BIP-324, MuHash, message signing |
| Addresses | `internal/address` | Base58Check, Bech32, Bech32m |
| Script | `internal/script` | interpreter (`engine.go`), opcodes, sighash (legacy, BIP-143, BIP-341), miniscript |
| Consensus | `internal/consensus` | chain parameters and checkpoints (`params.go`, `checkpoints.go`), header index, difficulty, block and transaction checks (`blockvalidation.go`, `txvalidation.go`), version bits, sigop and weight limits, signature cache, parallel script check queue (`checkqueue.go`) |
| Chain manager | `internal/consensus/chainmanager.go` | connects and disconnects blocks, writes undo data, chooses the most-work chain and reorganises, `invalidateblock` / `reconsiderblock` / `preciousblock` |
| UTXO set | `internal/consensus/utxoset.go` | in-memory coin cache over the database, Core's coin compression, batched flushes |
| assumeUTXO | `internal/consensus/assumeutxo.go`, `utxohash.go` | Core-format snapshot read/write, `hash_serialized_3` |
| Storage | `internal/storage` | Pebble key-value store (`pebbledb.go`, `chaindb.go`), flat `blk*.dat` block files (`flatfile.go`), pruning, txindex, BIP-158 filter index, coinstats index, spender index |
| P2P | `internal/p2p` | peers and handshake (`peer.go`, `msg_version.go`), v1 and BIP-324 v2 transport, address manager and addrv2, DNS and fixed seeds, ASMap, headers-first sync (`headerssync.go`, `sync.go`), block download, compact blocks, BIP-157 filter messages, misbehaviour and bans (`peermgr.go`) |
| Mempool | `internal/mempool` | acceptance policy, RBF, TRUC (v3) policy, packages, clusters, orphans, eviction, `mempool.dat` persistence, fee estimation |
| Mining | `internal/mining` | block templates (transaction selection, witness commitment) and regtest block generation |
| RPC | `internal/rpc` | HTTP JSON-RPC server and dispatch table (`server.go`), method handlers (`*_methods.go`, `methods.go`), REST (`rest.go`), BIP-78 PayJoin endpoint |
| Wallet | `internal/wallet` | BIP-32/39/84 keys, descriptors, coin selection, encryption, PSBT, fee bumping, multi-wallet manager, on-disk storage |
| ZMQ, logging, daemon | `cmd/blockbrew` | ZMQ publishers (`zmqpub.go`), log categories (`loglevel.go`), daemonize and pid file, systemd notify |

## Concurrency

Each peer connection runs in its own goroutines. Block connection and UTXO updates are done
by the chain manager under its lock; script checks for a block are fanned out to a worker
pool sized by `-par`. RPC requests are served concurrently by Go's HTTP server.

## On-disk state

See the data directory layout in [running.md](running.md#data-directory). Block bodies are
in flat `blk*.dat` files under `blocks/`; the block index, undo data, chainstate and the
optional indexes are in the Pebble database under `chaindata/`.

## Helper programs

| Program | Purpose |
|---|---|
| `cmd/script_test` | runs Bitcoin Core's `script_tests.json` through the interpreter |
| `cmd/sighash_test` | runs Bitcoin Core's `sighash.json` through the sighash code |
| `cmd/verifyscript_shim` | line-oriented JSON wrapper around the script interpreter, for external differential test drivers |
