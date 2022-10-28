SHELL := /bin/bash

GOCMD=go
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOBUILD=$(GOCMD) build
GOINSTALL=$(GOCMD) install

BINARY_NAME=tyk
BINARY_LINUX=tyk
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
.PHONY: lint lint-install lint-fast
lint: lint-install
	goimports -local github.com/TykTechnologies -w .
	gofmt -w .
	faillint -ignore-tests -paths "$(shell grep -v '^#' .faillint | xargs echo | sed 's/ /,/g')" ./...

lint-fast:
	go generate ./...
	go test -count 1 -v ./cli/linter/...
	go fmt ./...
	go mod tidy

lint-install: lint-fast
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.45.0
	go install github.com/fatih/faillint@latest

.PHONY: bench
bench:
	$(GOTEST) -run=$(BENCH_RUN) -bench=$(BENCH_REGEX) ./...

.PHONY: clean
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

.PHONY: dev
dev:
	$(GOBUILD) -tags "$(TAGS)" -o $(BINARY_NAME) -v .
	./$(BINARY_NAME) --conf $(CONF)

.PHONY: build
build:
	$(GOBUILD) -tags "$(TAGS)" -o $(BINARY_NAME) -v .

.PHONY: build-linux
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -tags "$(TAGS)" -o $(BINARY_LINUX) -v .

.PHONY: install
install:
	$(GOINSTALL) -tags "$(TAGS)"

.PHONY: db-start
db-start: redis-start mongo-start

.PHONY: db-stop
db-stop: redis-stop mongo-stop

# Docker start redis
.PHONY: redis-start
redis-start:
	docker run -itd --rm --name redis -p 127.0.0.1:6379:6379 redis:4.0-alpine redis-server --appendonly yes

.PHONY: redis-stop
redis-stop:
	docker stop redis

.PHONY: redis-cli
redis-cli:
	docker exec -it redis redis-cli

# Docker start mongo
.PHONY: mongo-start
mongo-start:
	docker run -itd --rm --name mongo -p 127.0.0.1:27017:27017 mongo:3.4-jessie

.PHONY: mongo-stop
mongo-stop:
	docker stop mongo

.PHONY: mongo-shell
mongo-shell:
	docker exec -it mongo mongo

.PHONY: docker docker-std

docker:
	docker build --no-cache --rm -t internal/tyk-gateway --squash .

docker-std: build
	docker build --no-cache -t internal/tyk-gateway:std -f ci/Dockerfile.std .

