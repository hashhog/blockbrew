# blockbrew

A Bitcoin full node written in Go.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
blockbrew is a from-scratch Bitcoin full node implementation that does exactly that —
syncs the blockchain, validates blocks, and participates in the peer-to-peer network.

## Current status

- [x] Project scaffold and module layout
- [x] Binary serialization (varint, compact size, tx, block)
- [x] Cryptographic primitives (SHA256, RIPEMD160, secp256k1, ECDSA, Schnorr)
- [x] Address encoding (Base58Check, Bech32, Bech32m)
- [x] Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- [x] Consensus parameters and difficulty calculations
- [x] Genesis blocks (mainnet, testnet, regtest, signet)
- [x] Database layer (Pebble backend, chain state, block storage)
- [x] Block and transaction validation (merkle tree, sigops, BIP34, witness)
- [x] P2P message serialization (version, inv, headers, block, tx, etc)
- [x] P2P connection management and handshake
- [x] Peer manager (DNS discovery, connection limits, addr relay)
- [x] Header synchronization (header index, getheaders/headers, checkpoints)
- [x] Block download and IBD pipeline (parallel download, validation, connection)
- [x] Chain manager (block connection, reorg handling)
- [x] UTXO set (caching, script compression, undo data for reorgs)
- [x] Mempool (tx validation, fee tracking, CPFP, orphan pool, eviction)
- [x] Fee estimation (bucketed histogram, decay, smart fee estimates)
- [x] Block template construction (tx selection, coinbase, witness commitment)
- [x] JSON-RPC server (Bitcoin Core compatible API)
- [x] HD Wallet (BIP32/BIP39/BIP84, P2WPKH addresses, encrypted storage)
- [x] CLI and application entry point (flags, graceful shutdown, subcommands)
- [x] Comprehensive test suite (unit tests, integration tests, benchmarks)

## Quick start

```bash
go build -o blockbrew ./cmd/blockbrew
./blockbrew --version
./blockbrew --network regtest --datadir ~/.blockbrew
```

Or use the Makefile:

```bash
make build
make test
```

Wallet commands:

```bash
./blockbrew wallet create    # Generate new wallet mnemonic
./blockbrew wallet import    # Import wallet from mnemonic
./blockbrew help             # Show all options
```

## Project structure

```
cmd/blockbrew/     main entrypoint, CLI, configuration
internal/
  address/         address encoding (base58, bech32)
  crypto/          hashing, keys, ecdsa, schnorr
  wire/            protocol message serialization
  consensus/       consensus rules, validation, chain manager
  script/          script interpreter
  p2p/             peer-to-peer networking, sync, block download
  storage/         database layer (pebble, chain state)
  mempool/         transaction memory pool, fee estimation
  rpc/             JSON-RPC server
  wallet/          hd wallet (bip32/39/84, signing, storage)
  mining/          block template and PoW
  testutil/        test helpers and utilities
tests/             integration tests
scripts/           build and test scripts
```

## Running tests

```bash
# Run all unit tests
go test ./...

# Run with race detector
go test -race ./...

# Run with coverage
go test -cover ./...

# Run integration tests
go test -tags integration ./tests/

# Run benchmarks
go test -bench=. ./internal/wire/ ./internal/crypto/ ./internal/consensus/ ./internal/storage/

# Or use the test script
./scripts/test.sh
```
