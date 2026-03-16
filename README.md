# blockbrew

A Bitcoin full node written in Go.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
blockbrew is a from-scratch Bitcoin full node implementation that does exactly that —
syncs the blockchain, validates blocks, and participates in the peer-to-peer network.

## Current status

- [x] Binary serialization (varint, compact size, tx, block)
- [x] Cryptographic primitives (SHA256, RIPEMD160, secp256k1, ECDSA, Schnorr)
- [x] Address encoding (Base58Check, Bech32, Bech32m)
- [x] Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- [x] Consensus rules (difficulty, BIP34/65/66/68, segwit, taproot)
- [x] Database layer (Pebble backend, tuned for Bitcoin workloads)
- [x] Block and transaction validation (merkle tree, sigops, witness)
- [x] P2P networking (message serialization, peer discovery, sync)
- [x] Chain manager (block connection, reorg handling, undo data)
- [x] UTXO set (L1 cache, script compression, batched flushes)
- [x] Mempool (fee tracking, CPFP, orphan pool, eviction)
- [x] Block template construction (tx selection, witness commitment)
- [x] JSON-RPC server (Bitcoin Core compatible API)
- [x] HD Wallet (BIP32/BIP39/BIP84, P2WPKH addresses)
- [x] Performance optimizations (parallel script validation, IBD tuning)
- [ ] Full mainnet IBD completion

## Quick start

```bash
make build
./blockbrew --network regtest --datadir ~/.blockbrew
./blockbrew wallet create
```

## Project structure

```
cmd/blockbrew/     main entrypoint, CLI, configuration
internal/
  consensus/       validation, chain manager, UTXO set, profiling
  script/          script interpreter
  p2p/             peer-to-peer networking, sync
  storage/         database layer (pebble)
  mempool/         transaction pool, fee estimation
  rpc/             JSON-RPC server
  wallet/          hd wallet (bip32/39/84)
  mining/          block template and PoW
  crypto/          hashing, keys, ecdsa, schnorr
  wire/            protocol serialization
  address/         address encoding
```

## Running tests

```bash
make test              # unit tests
make test-race         # with race detector
make bench             # benchmarks
make profile-cpu       # CPU profiling
```

Enable pprof at runtime:

```bash
./blockbrew --pprof localhost:6060
# then: go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
```
