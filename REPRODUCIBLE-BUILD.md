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
| Commit | `e7d0afe` (v0.1.0-rc1) |
| **sha256** | `241f779c1fdc286bc524af6328ae7c7da4c033b60af7ca1dfb4520232c3823df` |
| Toolchain | `go 1.24.1 linux/amd64` |
| Target | `Linux amd64` |
| Build | `go build -o blockbrew ./...` |

> Recorded at tag time (2026-08-15) for v0.1.0-rc1 = `e7d0afe`. LINEAGE NOTE:
> the from-genesis C(958794) validation ran on the `103ea46`-era binary; the
> consensus delta `103ea46..e7d0afe` is one Core-parity witness-commitment
> restructure (zero-split-verified) plus reason-token maps and the
> capture/recovery tooling fixes included in this tag. Evidence + independent
> hash cross-check: `receipts/r4-blockbrew-t2-3-2026-08-14.md` (T2-3).

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
