# Stage 1: Build
FROM golang:1.24-bookworm AS builder
WORKDIR /build
# internal/crypto binds libsecp256k1 via cgo (ECDSA / Schnorr / BIP-324
# ElligatorSwift). Debian bookworm's libsecp256k1-dev predates the ellswift
# module (no secp256k1_ellswift.h), so build v0.7.1 from source. The default
# prefix (/usr/local) lands the .pc file and headers on pkg-config's and the
# compiler's default search paths.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool pkg-config git ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch v0.7.1 https://github.com/bitcoin-core/secp256k1 /tmp/secp256k1 && \
    cd /tmp/secp256k1 && \
    ./autogen.sh && \
    ./configure && \
    make -j"$(nproc)" && \
    make install && \
    rm -rf /tmp/secp256k1
COPY . .
RUN go build -o blockbrew ./cmd/blockbrew/

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*
# Runtime half of the source-built libsecp256k1 from the builder (the
# cgo-linked binary loads libsecp256k1.so.2 at startup).
COPY --from=builder /usr/local/lib/libsecp256k1.so* /usr/local/lib/
RUN ldconfig
ENV LD_LIBRARY_PATH=/usr/local/lib
COPY --from=builder /build/blockbrew /usr/local/bin/blockbrew
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8333 8332
ENTRYPOINT ["blockbrew"]
CMD ["-datadir", "/data", "-network", "mainnet"]
