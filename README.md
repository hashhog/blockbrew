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
- [ ] Block header validation and chain sync
- [ ] Mempool
- [ ] RPC interface
- [ ] Wallet

## Quick start

```bash
go build -o blockbrew ./cmd/blockbrew
./blockbrew --datadir ~/.blockbrew
```

Or use the Makefile:

```bash
make build
make test
```

## Project structure

```
cmd/blockbrew/     main entrypoint
internal/
  address/         address encoding (base58, bech32)
  crypto/          hashing, keys, ecdsa, schnorr
  wire/            protocol message serialization
  consensus/       consensus rules and validation
  script/          script interpreter
  p2p/             peer-to-peer networking and messages
  storage/         database layer (pebble, chain state)
  mempool/         transaction memory pool
  rpc/             JSON-RPC server
  wallet/          key management
  mining/          block template and PoW
```

## Running tests

```bash
go test ./...
```
