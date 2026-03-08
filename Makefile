.PHONY: all build test vet lint clean

all: vet test build

build:
	go build -o blockbrew ./cmd/blockbrew

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

clean:
	rm -f blockbrew
