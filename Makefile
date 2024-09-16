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

#The name of the kind cluster used for development
CLUSTER_NAME ?= kind
NAMESPACE ?=tyk

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

.PHONY: create-kind-cluster
create-kind-cluster:	## Create kind cluster
	kind create cluster --config k8s/kind.yaml --name=${CLUSTER_NAME}

.PHONY: delete-kind-cluster
delete-kind-cluster:	## Delete kind cluster
	kind delete cluster --name=${CLUSTER_NAME}

.PHONY: install-k8s-tools
install-k8s-tools:	## Install k8s tools
	./k8s/installRequirements.sh

.PHONY: generate-k8s-value-files
generate-k8s-value-files:
	helm repo add tyk-helm https://helm.tyk.io/public/helm/charts/
	helm repo update
	helm show values tyk-helm/tyk-oss > k8s/ossValues.yaml
	helm show values tyk-helm/tyk-control-plane > k8s/controlPlaneValues.yaml
	helm show values tyk-helm/tyk-data-plane > k8s/dataPlaneValues.yaml

.PHONY: install-redis-and-mongo-k8s
install-redis-and-mongo: redis-k8s mongo-k8s

.PHONY: redis-k8s
redis-k8s:
	helm upgrade tyk-redis oci://registry-1.docker.io/bitnamicharts/redis -n ${NAMESPACE} --install --version 19.0.2

# does not work on Mac M1
.PHONY: mongo-k8s
mongo-k8s:
	./k8s/installMongo.sh ${NAMESPACE}

.PHONY: install-simple-redis-and-mongo-k8s
install-simple-redis-and-mongo-k8s: simple-redis-k8s simple-mongo-k8s

.PHONY: simple-redis-k8s
simple-redis-k8s:
	helm upgrade --install redis tyk-helm/simple-redis -n tyk --create-namespace

.PHONY: simple-mongo-k8s
simple-mongo-k8s:
	helm upgrade --install mongo tyk-helm/simple-mongodb -n tyk --create-namespace

.PHONY: tyk-oss
tyk-oss:
	helm install tyk-oss tyk-helm/tyk-oss -n tyk --create-namespace -f k8s/ossValues.yaml

.PHONY: tyk-control-plane
tyk-control-plane:
	helm install tyk-control-plane tyk-helm/tyk-control-plane -n tyk --create-namespace -f k8s/controlPlaneValues.yaml

.PHONY: tyk-data-plane
tyk-data-plane:
	helm install tyk-data-plane tyk-helm/tyk-data-plane -n tyk --create-namespace -f k8s/dataPlaneValues.yaml

.PHONY: tyk-oss-default
tyk-oss-default:
	helm install tyk-oss tyk-helm/tyk-oss -n tyk --create-namespace

.PHONY: tyk-control-plane-default
tyk-control-plane-default:
	helm install tyk-control-plane tyk-helm/tyk-control-plane -n tyk --create-namespace

.PHONY: tyk-data-plane-default
tyk-data-plane-default:
	helm install tyk-data-plane tyk-helm/tyk-data-plane -n tyk --create-namespace

.PHONY: load-gw-image
load-gw-image:
	kind load docker-image docker.io/internal/tyk-gateway -n kind

.PHONY: upgrade-oss-local
upgrade-to-local-image:
	helm upgrade --install tyk-oss tyk-helm/tyk-oss -n tyk --set gateway.image.tag=latest --set gateway.image.repository=internal/tyk-gateway
