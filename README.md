# blockbrew

A Bitcoin full node written in Go.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
blockbrew is a from-scratch Bitcoin full node implementation that does exactly that —
syncs the blockchain, validates blocks, and participates in the peer-to-peer network.

## Current status

- [x] Project scaffold and module layout
- [ ] Binary serialization (varint, compact size)
- [ ] P2P message framing and handshake
- [ ] Block header validation and chain sync
- [ ] Script interpreter
- [ ] UTXO set and block validation
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
  wire/            protocol message serialization
  consensus/       consensus rules and validation
  script/          script interpreter
  p2p/             peer-to-peer networking
  storage/         block and UTXO storage
  mempool/         transaction memory pool
  rpc/             JSON-RPC server
  wallet/          key management
  mining/          block template and PoW
```

## Running tests

```bash
go test ./...
```
