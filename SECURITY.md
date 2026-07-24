# Security Policy — blockbrew

blockbrew is a from-scratch Bitcoin full-node implementation in Go, part of the
[hashhog](https://github.com/hashhog) fleet of ten independent nodes that
cross-validate each other and Bitcoin Core.

> **STAGED PRE-DRAFT (2026-07-24).** This wrapper is written ahead of blockbrew's first
> tag. Its genesis (`--assumevalid=0`) from-genesis validation lineage is in progress;
> the tag (`v0.1.0-rc1`) is cut once it reproduces the **C(958794)** UTXO commitment
> byte-for-byte (see `../receipts/NODE4-BLOCKBREW-T2-CAPTURE-RUNBOOK.md`). Evidence
> specifics marked ⟦at tag⟧ are recorded when the T2 capture verifies.

## Project maturity — read this first

blockbrew targets the **tagged-validator** bar: a node you can build, run *beside*
Bitcoin Core in watchtower mode, and trust to track consensus. Its live-fleet instance
tracks the Core mainnet tip byte-for-byte (`fleet-snapshot.sh` agreement), and its
correctness rests on an **`--assumevalid=0` genesis lineage** that re-derives the UTXO
set from block 0 with scripts on, reproducing the reference Core UTXO commitment
`C(958794)` (`hash_serialized_3 = 29692050…`) byte-for-byte ⟦at tag⟧ — trusting no
checkpoint.

**It is NOT fund-capable for general custody.** The intended trust model for this
release is: run it alongside Core with `consensus-diff` as a live divergence alarm.
There are no fund-grade guarantees. Run from a pinned commit.

## Supported versions

| Version | Supported |
|---------|-----------|
| `v0.1.0-rc1` (pinned ⟦at tag⟧) | Validator RC — best-effort; no security SLA until the final `v0.1.0` |
| pre-release (`master`) | Best-effort |

## Reporting a vulnerability

**Please do NOT open a public GitHub issue** for anything in the consensus, P2P, or
wallet paths — a public report could put real Bitcoin nodes or funds at risk.

Report privately to the maintainer:

- **Email:** `max@dockyard.navy`  <!-- TODO(max): confirm or replace with a dedicated security alias -->

Include the affected path, a deterministic reproduction (a diff-test corpus entry,
regtest script, or malformed message), impact, and any suggested fix. We coordinate a
fix + disclosure timeline and credit you if you wish.

## In scope (highest priority)

- **Consensus divergence** — blockbrew accepting a block/tx Core rejects, or vice-versa.
  This is the core concern; divergences carry Core `file:line` citations (see
  `../CORE-PARITY-AUDIT/`).
- **Remotely-triggerable crashes / OOM / resource exhaustion** in the P2P or block/tx
  decode paths.
- **Chainstate corruption on crash.** blockbrew's storage is pebble-backed; it carries a
  SIGKILL-during-flush durability regression guard (P0.5) and a synchronous
  `flushchainstate` on graceful stop. Regressions here are in scope.
- **Wallet funds-safety** — silent wrong-key signing, a spend the node reports valid that
  the network rejects, un-recoverable backups, fee miscalculation stranding funds.

## Custody caveats (not consensus, but real — for the fund track, not this validator tag)

⟦at tag⟧ Record any funds-safety caveats surfaced by the release audit here (the other
flagships filed items like default-wallet backup traps and `prevtxs`-ignoring signing).
These gate fund-capability (P2), not the watchtower-validator tag.

## Out of scope

- IBD/sync performance characteristics.
- Issues requiring an already-compromised host.

## Disclosure

Coordinated disclosure. Consensus fixes are verified with `../tools/verify-fix.sh` and
gated through the differential corpus before they are considered landed.
