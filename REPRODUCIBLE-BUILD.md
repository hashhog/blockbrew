# Reproducible build — blockbrew

How to build the blockbrew validator and verify it. Part of the tagged-validator release
wrapper (see `SECURITY.md` and `../receipts/PRODUCTION-GATE.md` "three bars").

> **STAGED PRE-DRAFT (2026-07-24).** Written ahead of the first tag. The pinned release
> commit + its authoritative sha256 are recorded when `v0.1.0-rc1` is cut (after the
> C(958794) T2 capture — see `../receipts/NODE4-BLOCKBREW-T2-CAPTURE-RUNBOOK.md`).

## Reference build (current `master`)

| | |
|---|---|
| Commit | `2846653` (HEAD at the time of this note) |
| Binary | `blockbrew/blockbrew` |
| **sha256** | `d16de08bfec805360fa3c1dd257476935d095b1fa7a6c4ae77e76b9b1b2810e5` |
| Toolchain | `go 1.24.1 linux/amd64` |
| Target | `Linux amd64` |
| Build | `go build -o blockbrew ./...` |

> At tag time, re-record this table for the pinned rc commit, and confirm the
> genesis-blockbrew binary that produced the C(958794) lineage matches it
> (`sha256sum blockbrew/blockbrew`).

## Build

```bash
git clone git@github.com:hashhog/blockbrew.git
cd blockbrew
# install Go 1.24.1 (via golang.org/dl or your package manager)
go build -o blockbrew ./...
sha256sum blockbrew
```

## Verify

Reproducibility holds **when the toolchain and target match**: same `go 1.24.1`, same
`Linux amd64`, a clean checkout of the tagged commit.

**Honest caveats** (a hash mismatch under a *different* environment is expected, not
tampering):
- Go binaries embed build metadata (module versions, build paths via `-trimpath`'s
  absence, VCS stamps). Different Go versions, build flags, or paths produce different
  bytes. Add `-trimpath` and set `-buildvcs=false` for a more portable hash.
- For an exact match, build with the pinned `go 1.24.1` on a comparable Linux host.
- The stronger guarantee this release rests on is **behavioural, not bit-level**: the
  binary validates Bitcoin mainnet in consensus with Bitcoin Core — trustless-from-genesis
  (`--assumevalid=0`), byte-exact at the live tip (`fleet-snapshot.sh` agreement), and it
  reproduces the reference Core UTXO commitment C(958794) byte-for-byte from a genesis
  lineage ⟦recorded at tag⟧. Run it beside Core with `consensus-diff` as a live divergence
  alarm; that is the intended trust model (validator, **not** custody).

## Scope of this release

- **Is:** a trustless-from-genesis validating node, byte-exact with Core, to run beside
  Core in watchtower mode.
- **Is not:** fund-capable (do not custody funds — see `SECURITY.md`).

The release-gate smoke check is `tools/smoke-harness.sh --node=blockbrew` (regtest boot +
genesis-state RPC + clean shutdown), which must pass at the tagged commit.
