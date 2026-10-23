# Modified 2026-10-23: build the 911VulScan product command.
BINARY_NAME=vulscan
BUILD_DIR=bin
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X github.com/puhaoyang78/911VulScan/apps/vulscan-cli/cmd.version=$(VERSION)"

.PHONY: build clean test lint install

build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./main.go

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./...

lint:
	go vet ./...

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
