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
.PHONY: lint lint-install lint-fast
lint:
	task lint

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
	$(GOBUILD) -tags "$(TAGS)" -o $(BINARY_NAME) -trimpath .

.PHONY: build-linux
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -tags "$(TAGS)" -o $(BINARY_LINUX) -v .

# TYK_LOGLEVEL=debug dlv --listen=localhost:2345 --headless=true --api-version=2 --accept-multiclient exec -- ./tyk --conf=tyk_gw.conf
build-debug:
	$(GOBUILD) -gcflags="all=-N -l" -tags "$(TAGS)" -o $(BINARY_NAME) .

# build plugins for tests
build-plugins:
	@go build -tags goplugin -buildmode=plugin -gcflags "all=-N -l" -o ./test/goplugins/goplugins_debug.so ./test/goplugins/
	@go build -tags goplugin -buildmode=plugin -race -o ./test/goplugins/goplugins_race.so ./test/goplugins/
	@go build -tags goplugin -buildmode=plugin -o ./test/goplugins/goplugins.so ./test/goplugins/

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
	docker build --platform ${BUILD_PLATFORM} --rm -t internal/tyk-gateway .

docker-std: build
	docker build --platform ${BUILD_PLATFORM} --no-cache -t internal/tyk-gateway:std -f ci/Dockerfile.std .