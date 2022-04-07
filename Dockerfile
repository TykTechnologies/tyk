FROM debian:bullseye as assets

ARG GO_VERSION=1.15.15
ARG PYTHON_VERSION=3.7.13

WORKDIR /opt

RUN	apt update && apt install wget -y && \
 	wget -q https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz && \
	wget -q https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tar.xz

FROM debian:bullseye

ARG GO_VERSION=1.15.15
ARG PYTHON_VERSION=3.7.13

COPY --from=assets /opt/ /opt/
WORKDIR /opt

# Install Go

ENV PATH=$PATH:/usr/local/go/bin

RUN	tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
	go version

# Build essentials

RUN apt update && apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev curl wget libbz2-dev -y

# Install python3.7

RUN	tar -xf Python-${PYTHON_VERSION}.tar.xz && ls -la && \
	cd Python-${PYTHON_VERSION}/ && \

## This runs python code faster, but is expensive to build and runs regression tests
#	./configure --enable-shared --enable-optimizations && make -j 2 && \

## This runs python code slower, but the process finishes quicker
	./configure --enable-shared && make build_all && \

	make altinstall && \
	ldconfig $PWD && \
	python3.7 --version

# Build gateway

WORKDIR /opt/tyk-gateway
ADD . /opt/tyk-gateway

RUN make build

COPY tyk.conf.example tyk.conf

RUN 	echo "Tyk: $(/opt/tyk-gateway/tyk --version 2>&1)" && \
	echo "Go: $(go version)" && \
	echo "Python: $(python3.7 --version)"

ENTRYPOINT ["/opt/tyk-gateway/tyk"]