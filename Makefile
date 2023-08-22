SHELL := /bin/bash

GOCMD=go
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOBUILD=$(GOCMD) build
GOINSTALL=$(GOCMD) install

BINARY_NAME=tyk
BINARY_LINUX=tyk
BUILD_PLATFORM=linux/amd64
TAGS=coprocess grpc goplugin
CONF=tyk.conf

TEST_REGEX=.
TEST_COUNT=1

BENCH_REGEX=.
BENCH_RUN=NONE

.PHONY: test
test:
	$(GOTEST) -run=$(TEST_REGEX) -count=$(TEST_COUNT) ./...

# lint runs all local linters that must pass before pushing

.PHONY: lint-check
lint-check:
	golangci-lint run ./cli/linter/...
	golangci-lint run ./gateway/...
	golangci-lint run ./api/...
	golangci-lint run ./gateway/...

lint: lint-fast lint-check
	goimports -local github.com/TykTechnologies,github.com/TykTechnologies/tyk/internal -w .
	gofmt -w .
	faillint -ignore-tests -paths "$(shell grep -v '^#' .faillint | xargs echo | sed 's/ /,/g')" ./...