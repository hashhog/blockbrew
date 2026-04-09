# blockbrew

A Bitcoin full node written from scratch in Go. Part of the [Hashhog](https://github.com/hashhog/hashhog) project.

## Quick Start

### Build from Source

```bash
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
- assumeUTXO (dumptxoutset, loadtxoutset, getchainstates)
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

The `mempool` package implements transaction pool management with fee tracking, Child-Pays-For-Parent (CPFP), an orphan pool for transactions with missing inputs, and eviction policies. The `mining` package constructs block templates by selecting transactions for optimal feerate and generating witness commitments. The `rpc` package exposes a Bitcoin Core-compatible JSON-RPC server with HTTP Basic Auth, supporting batch requests, wallet operations, PSBT workflows, and a REST API for block/tx queries in JSON, hex, and binary formats.

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
