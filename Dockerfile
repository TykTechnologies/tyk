FROM debian:bullseye as assets

# This Dockerfile facilitates bleeding edge development docker image builds
# directly from source. To build a development image, run `make docker`.
# If you need to tweak the environment for testing, you can override the
# `GO_VERSION` and `PYTHON_VERSION` as docker build arguments.

ARG GO_VERSION=1.16
ARG PYTHON_VERSION=3.7.13

WORKDIR /assets

RUN	apt update && apt install wget -y && \
 	wget -q https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz && \
	wget -q https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tar.xz

FROM debian:bullseye

ARG GO_VERSION=1.16
ARG PYTHON_VERSION=3.7.13

COPY --from=assets /assets/ /tmp/
WORKDIR /tmp

# Install Go

ENV PATH=$PATH:/usr/local/go/bin

RUN	tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
	go version

# Build essentials

RUN apt update && apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev curl wget libbz2-dev -y

# Install $PYTHON_VERSION

## This just installs whatever is is bullseye, makes docker build (fast/small)-(er)
RUN	apt install python3 -y

## This runs python code slower, but the process finishes quicker
# RUN	tar -xf Python-${PYTHON_VERSION}.tar.xz && ls -la && \
#	cd Python-${PYTHON_VERSION}/ && \
#	./configure --enable-shared && make build_all && \
#	make altinstall && \
#	ldconfig $PWD

## This runs python code faster, but is expensive to build and runs regression tests
# RUN	tar -xf Python-${PYTHON_VERSION}.tar.xz && ls -la && \
#	cd Python-${PYTHON_VERSION}/ && \
#	./configure --enable-shared --enable-optimizations && make -j 2 && \
#	make altinstall && \
#	ldconfig $PWD

# Clean up build assets
RUN find /tmp -type f -delete

# Build gateway

RUN mkdir /opt/tyk-gateway
WORKDIR /opt/tyk-gateway
ADD . /opt/tyk-gateway

RUN make build && go clean -modcache

COPY tyk.conf.example tyk.conf

RUN 	echo "Tyk: $(/opt/tyk-gateway/tyk --version 2>&1)" && \
	echo "Go: $(go version)" && \
	echo "Python: $(python3 --version)"

ENTRYPOINT ["/opt/tyk-gateway/tyk"]