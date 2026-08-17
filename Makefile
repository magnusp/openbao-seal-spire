.PHONY: all build test test-fast test-slow clean

BINARY_NAME=openbao-seal-spire
BIN_DIR=bin

all: build

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/openbao-seal-spire

test: test-fast

test-fast:
	go test -v -short ./internal/...

test-slow:
	go test -v -tags=integration ./test/integration/...

clean:
	rm -rf $(BIN_DIR)
