# Changelog

All notable changes to blockbrew are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-31

First stable release of blockbrew, a Bitcoin full node written from scratch
in Go, part of the [hashhog](https://github.com/hashhog/hashhog) fleet of ten
independent node implementations that cross-validate each other and Bitcoin
Core.

### Highlights

- Full block and transaction validation (BIP-16, BIP-34, BIP-65, BIP-66,
  BIP-68, BIP-141 SegWit, BIP-341 Taproot), with an `--assumevalid=0` mode
  that re-derives the UTXO set from genesis with scripts on.
- Script interpreter covering P2PKH, P2SH, P2WPKH, P2WSH, and P2TR; ECDSA and
  Schnorr signature verification backed by libsecp256k1 via cgo.
- Headers-first sync with parallel block download, checkpoint verification,
  misbehavior scoring, and work-based fork download at any depth on archive
  nodes (reorg cap 288, gated on pruning, per Core).
- Pebble-backed storage with atomic block-connect batches (body + undo +
  height index + UTXO set + chainstate in one batch), a SIGKILL-during-flush
  durability regression guard, and `flushchainstate` on graceful stop.
- Mempool with fee tracking, CPFP, package relay (`submitpackage`), Core v31
  cluster limits, BIP-125 RBF rules, TRUC (v3) policy, and eviction.
- Fee estimation with confirmation tracking; mining / block template
  construction with witness commitment.
- HD wallet (BIP-32/39/84), multi-wallet support, wallet encryption, address
  labels, PSBT (BIP-174/370) workflows, and output descriptors.
- assumeUTXO (`dumptxoutset`, `loadtxoutset`, `getchainstates`) and block
  indexes (txindex, BIP-157/158 blockfilterindex, coinstatsindex).
- JSON-RPC surface ported against Bitcoin Core, including `verifychain`,
  `submitblock`/`submitheader`, `combinerawtransaction`, `logging`, `ping`,
  `waitfornewblock`/`waitforblock`/`waitforblockheight`, plus a REST API.
- ZMQ notification interface (`hashblock`, `hashtx`, `rawblock`, `rawtx`,
  `sequence`), including per-transaction fan-out on block connect per Core's
  `CZMQNotificationInterface::BlockConnected`.
- BIP-35 `mempool` serving, BIP-155 addrv2 handling, BIP-324 v2 transport
  (ElligatorSwift), and BIP-339 wtxid relay.

### Fixed since the 0.1.0 development line (selection)

- Chain selection: `preciousblock` on an equal-work side chain now reorgs as
  Bitcoin Core does — RPC-`submitblock`ed side-branch bodies are marked
  `BLOCK_HAVE_DATA` (sync-path parity), so `recalculateBestTipLocked`'s
  data gate admits them as candidates.
- Chain manager: serialised `InvalidateBlock` against `ReorgTo`
  (rollback/reorg race); the G3 ancestor-data walk in tip recalculation is
  now linear instead of quadratic.
- Consensus: unconditional P2SH|WITNESS|TAPROOT script flags with Core's
  replace-then-OR semantics; flag-gated P2SH and witness sigop counting;
  coinbase sigops counted toward `MAX_BLOCK_SIGOPS_COST`; empty
  scriptPubKey outputs are spendable (Core `CScript::IsUnspendable` parity);
  tapscript script-path sighash commits the annex (BIP-341).
- Policy: closed five `testmempoolaccept` dry-run false-accepts;
  standardness-before-inputs ordering; BIP-68 mempool version gate compares
  unsigned (Core `uint32_t` parity).
- P2P: fresh socket dial for BIP-324 v1 fallback; discourage + disconnect on
  oversize inv/getdata; tx request/serve relay loop; merkle/witness
  malleation classified as transient `BLOCK_MUTATED`.
- Sync: single-flighted block-download loop; self-healing drain-rebuild
  livelock recovery (GEN-BREW-665671/GEN-BREW-444534).
- Wallet: PSBT change-derive/sign/finalize/fee on blank imported wallets;
  `getdescriptorinfo` checksum-of-input.

### Known gaps (documented in-tree as skipped sentinel tests)

- Tor v3 / I2P / CJDNS connectivity (W117 BUG-2/3/4/9; `getnetworkinfo`
  network list BUG-5; `getpeerinfo` network field BUG-8).
- `getblocktemplate` `sizelimit` reports the legacy 1 MB constant instead of
  Core's post-segwit `MAX_BLOCK_SERIALIZED_SIZE` (W108 G12/G23).
- Mempool: children of confirmed parents not evicted on block connect
  (W106 G9); `IsConsistentPackage` accepts empty-vin txs (W106 G30).
- `-checkblocks` / `-checklevel` startup dials (W124 BUG-17, CLI half);
  assorted ZMQ/REST/operator-experience items tracked as W141/W124
  sentinels.
