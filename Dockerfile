# Stage 1: Build
FROM golang:1.24-bookworm AS builder
WORKDIR /build
COPY . .
RUN go build -o blockbrew ./cmd/blockbrew/

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/blockbrew /usr/local/bin/blockbrew
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8333 8332
ENTRYPOINT ["blockbrew"]
CMD ["-datadir", "/data", "-network", "mainnet"]
