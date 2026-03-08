.PHONY: all build test test-race vet lint clean bench profile-cpu profile-mem profile-trace

all: vet test build

build:
	go build -o blockbrew ./cmd/blockbrew

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

clean:
	rm -f blockbrew cpu.prof mem.prof trace.out

# Benchmarks
bench:
	go test -bench=. -benchmem ./internal/wire/ ./internal/crypto/ ./internal/consensus/ ./internal/storage/

bench-consensus:
	go test -bench=. -benchmem ./internal/consensus/

bench-verbose:
	go test -bench=. -benchmem -benchtime=3s -v ./internal/consensus/

# Profiling
profile-cpu:
	go test -bench=. -cpuprofile=cpu.prof -benchmem ./internal/consensus/
	@echo "Run: go tool pprof -http=:8080 cpu.prof"

profile-mem:
	go test -bench=. -memprofile=mem.prof -benchmem ./internal/consensus/
	@echo "Run: go tool pprof -http=:8080 mem.prof"

profile-trace:
	go test -bench=. -trace=trace.out ./internal/consensus/
	@echo "Run: go tool trace trace.out"

# Combined profile target
profile-all: profile-cpu profile-mem
	@echo "CPU profile: cpu.prof"
	@echo "Memory profile: mem.prof"
	@echo "View with: go tool pprof -http=:8080 <profile>"
