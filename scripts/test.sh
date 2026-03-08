#!/bin/bash
set -e

cd "$(dirname "$0")/.."

echo "=== Running vet ==="
go vet ./...

echo "=== Running tests ==="
go test -v -race -count=1 ./...

echo "=== Running coverage ==="
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -1

echo "=== Running benchmarks ==="
go test -bench=. -benchmem -run=^$ ./internal/wire/ ./internal/crypto/ ./internal/consensus/ ./internal/storage/

echo "=== All tests passed ==="
