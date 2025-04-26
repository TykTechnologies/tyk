ARG GO_VERSION=1.23
FROM golang:${GO_VERSION}-bullseye as builder
# Build essentials

RUN apt update && apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev curl wget libbz2-dev -y

## This just installs whatever is is bullseye, makes docker build (fast/small)-(er)
RUN	apt install python3 -y

# Build gateway
WORKDIR /opt/tyk-gateway

ADD go.mod go.sum /opt/tyk-gateway/

RUN --mount=type=cache,mode=0755,target=/go/pkg/mod \
    --mount=type=cache,mode=0755,target=/root/.cache/go-build \
    go mod download

ADD . /opt/tyk-gateway

RUN --mount=type=cache,mode=0755,target=/go/pkg/mod \
    --mount=type=cache,mode=0755,target=/root/.cache/go-build \
    make build


RUN 	echo "Tyk: $(/opt/tyk-gateway/tyk --version 2>&1)" && \
	echo "Go: $(go version)" && \
	echo "Python: $(python3 --version)"

FROM debian:bookworm-slim
WORKDIR /opt/tyk-gateway
COPY --from=builder /opt/tyk-gateway /opt/tyk-gateway
COPY tyk.conf.example tyk.conf

ENTRYPOINT ["/opt/tyk-gateway/tyk"]