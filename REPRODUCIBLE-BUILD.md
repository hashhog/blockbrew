# Reproducible build — blockbrew

How to build the blockbrew validator and verify it. Part of the tagged-validator release
wrapper (see `SECURITY.md` and `../receipts/PRODUCTION-GATE.md` "three bars").

> **⚠ DO NOT BUILD `v0.1.0-rc1`.** That tag contains `e7d0afe`, whose
> `AdoptAppliedBlock` advances the chain tip without re-applying the block's UTXO
> mutations, silently corrupting a partially-committed chainstate (measured in the
> wild: C(958794) with the correct block hash but 166,180,926 coins against the
> pinned 166,180,925). Superseded by **`v0.1.0-rc2`**. Details:
> `../receipts/cache-accounting-and-adoption-rollforward-2026-08-16.md`.

## Reference build (`v0.1.0-rc2`)

| | |
|---|---|
| Commit | `bb1ffcf` (v0.1.0-rc2) |
| Binary | `blockbrew/blockbrew` |
| **sha256** | `7dc2bbe6ce57bcdb59db2c1574f0f6ed06a239e89e2f18e80d2ed1713f0f5021` |
| Toolchain | `go 1.24.1 linux/amd64` |
| Target | `Linux amd64` |
| Build | `./build-all.sh blockbrew` (canonical; wraps `go build -o blockbrew ./...`) |

> Recorded at tag time (2026-08-16) for v0.1.0-rc2 = `bb1ffcf`, from the
> canonical `build-all.sh` rebuild.
>
> LINEAGE NOTE (unchanged from rc1): the from-genesis C(958794) validation ran
> on the `103ea46`-era binary; the consensus delta `103ea46..e7d0afe` is one
> Core-parity witness-commitment restructure (zero-split-verified) plus
> reason-token maps and the capture/recovery tooling fixes. Evidence +
> independent hash cross-check: `receipts/r4-blockbrew-t2-3-2026-08-14.md`
> (T2-3). That capture predates the rc1 adoption defect by ~24h and was taken
> from a chainstate built entirely by ordinary connects, so the T2-3 result
> stands on its own evidence.
>
> Superseding delta `e7d0afe..bb1ffcf`: adoption now performs a tolerant
> roll-forward off a durable-only evidence probe, committed atomically with the
> tip (Core `validation.cpp::RollforwardBlock` semantics).

## Previous tags

| tag | commit | status |
|---|---|---|
| `v0.1.0-rc1` | `16c68b0` | **WITHDRAWN — do not build.** Chainstate-corrupting adoption path (see banner above). Tag left in place because it was published; it is superseded, not deleted. |

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
