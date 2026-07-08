# Stage 1: Build
FROM golang:1.24-bookworm AS builder
WORKDIR /build
# libsecp256k1-dev + pkg-config are required: signature verification and the
# BIP-324 ElligatorSwift codec are cgo bindings to libsecp256k1
# (internal/crypto). Without these the cgo build fails to find secp256k1.h /
# the pkg-config .pc file.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsecp256k1-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*
COPY . .
RUN go build -o blockbrew ./cmd/blockbrew/

# Stage 2: Runtime
FROM debian:bookworm-slim
# libsecp256k1-2 is the runtime shared library the cgo-linked binary needs at
# load time (the -dev package is build-only).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libsecp256k1-2 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/blockbrew /usr/local/bin/blockbrew
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8333 8332
ENTRYPOINT ["blockbrew"]
CMD ["-datadir", "/data", "-network", "mainnet"]
