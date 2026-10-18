# Building blockbrew

## Toolchain

| Requirement | Version | Why |
|---|---|---|
| Go | 1.24.0 or newer (`go.mod`); 1.24.1 is what the project builds with | compiler |
| C compiler (`gcc`) | any recent | cgo |
| `pkg-config` | any | locates libsecp256k1 |
| libsecp256k1 | 0.4.0 or newer, with the `ellswift`, `extrakeys` and `schnorrsig` modules | BIP-324 ElligatorSwift and Schnorr code in `internal/crypto` is cgo-linked to it |

Debian 13 (trixie) ships libsecp256k1 0.5.0, which works:

```bash
sudo apt-get install -y build-essential pkg-config libsecp256k1-dev git
pkg-config --modversion libsecp256k1
```

Check that the ellswift header is present:

```bash
ls /usr/include/secp256k1_ellswift.h
```

If your distribution's package is older than 0.4.0 or the header is missing, build
libsecp256k1 from source with `--enable-module-ellswift` and point `PKG_CONFIG_PATH` at it.

All Go dependencies are fetched by the Go toolchain from `go.mod` / `go.sum`.

## Build

```bash
make build            # same as: go build -o blockbrew ./cmd/blockbrew
./blockbrew -version
```

The binary links dynamically against `libsecp256k1.so`:

```bash
ldd blockbrew | grep secp256k1
```

Other Makefile targets:

| Target | What it does |
|---|---|
| `make test` | `go test ./...` |
| `make test-race` | the suite under the race detector |
| `make bench` | benchmarks for `wire`, `crypto`, `consensus`, `storage` |
| `make profile-cpu` / `profile-mem` / `profile-trace` | write `cpu.prof` / `mem.prof` / `trace.out` from the consensus benchmarks |
| `make clean` | removes the binary and profile files |

## Reproducible builds

Go embeds build metadata (module versions, VCS stamp and, without `-trimpath`, the build
path) in the binary. Two builds of the same commit produce the same bytes only with the same
Go version, the same target, the same libsecp256k1 and the same flags. For a hash that does
not depend on where you checked the source out, build with:

```bash
go build -trimpath -buildvcs=false -o blockbrew ./cmd/blockbrew
sha256sum blockbrew
```

and compare the hash with someone who built the same commit with the same Go version on
the same OS and architecture.

## Docker

The repository contains a `Dockerfile` and `docker-compose.yml`. They are not covered by
these docs and have not been verified to build; its builder image is Debian 12 (bookworm),
so check the libsecp256k1 requirement above before relying on it. Build from source
instead.
