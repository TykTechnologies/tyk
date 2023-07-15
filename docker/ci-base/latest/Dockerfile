ARG BASE_IMAGE=golang:1.19

# Install docker from docker image
FROM docker:24-cli AS docker

# Download docker-compose
FROM golang:1.20 AS docker-compose

# Install docker-compose
ARG COMPOSE_VERSION=v2.2.3
ADD curl -sSL https://github.com/docker/compose/releases/download/$COMPOSE_VERSION/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
RUN chmod +x /usr/local/bin/docker-compose

# The tooling, built with go 1.20
FROM golang:1.20 AS schema-gen
ENV CGO_ENABLED=0
ENV GOBIN=/usr/local/bin
RUN go install github.com/TykTechnologies/exp/cmd/schema-gen@main

# The CI image
FROM $BASE_IMAGE

LABEL description="Image for GitHub CI base workflow"

# Go binaries install path
ENV GOBIN=/usr/local/bin
WORKDIR /usr/local/bin

# Install Task
ARG TASK_VERSION=v3.27.1
RUN curl -sSL https://github.com/go-task/task/releases/download/${TASK_VERSION}/task_linux_amd64.tar.gz | tar -zxv

# Install required packages
RUN apt update && \
    apt install -y \
        curl \
        wget \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        python3-setuptools \
        python3-grpcio \
        python3-protobuf \
        build-essential \
        zlib1g-dev \
        libncurses5-dev \
        libgdbm-dev \
        libnss3-dev \
        libssl-dev \
        libsqlite3-dev \
        libreadline-dev \
        libffi-dev \
        libluajit-5.1-dev \
        libbz2-dev && \
    rm -rf /root/.cache && apt-get -y autoremove && apt-get clean

# Set binary install path, install tooling from builder
COPY --from=schema-gen /usr/local/bin/ /usr/local/bin/
COPY --from=docker /usr/local/bin/docker /usr/local/bin/
COPY --from=docker /usr/local/bin/docker-compose /root/.docker/cli-plugins/

RUN docker compose version && python3 -V

# Add gateway source tree
WORKDIR /src
ADD https://raw.githubusercontent.com/TykTechnologies/tyk/master/.taskfiles/deps/Taskfile.yml /src/

# Install tooling with task
RUN --mount=type=cache,mode=0755,target=/go/pkg/mod task

# Clean up work directory
RUN rm -rf /src && mkdir /src

# Set envs

ARG GITHUB_SHA
ARG GITHUB_TAG
ENV GITHUB_SHA ${GITHUB_SHA}
ENV GITHUB_TAG ${GITHUB_TAG}

ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python

ENV PYTHON_VERSION=3.9
