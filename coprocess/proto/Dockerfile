FROM golang:1.17

# install protobuf
ENV PB_VER 3.20.2
ENV PB_URL https://github.com/google/protobuf/releases/download/v${PB_VER}/protoc-${PB_VER}-linux-x86_64.zip

RUN apt-get -qq update && apt-get -qqy install curl git make unzip gettext rsync

RUN mkdir -p /tmp/protoc && \
    curl -L ${PB_URL} > /tmp/protoc/protoc.zip && \
    cd /tmp/protoc && \
    unzip protoc.zip && \
    cp /tmp/protoc/bin/protoc /usr/local/bin && \
    cp -R /tmp/protoc/include/* /usr/local/include && \
    chmod go+rx /usr/local/bin/protoc && \
    cd /tmp && \
    rm -r /tmp/protoc

# Get the source from GitHub
RUN go get -u google.golang.org/grpc

# Install protoc-gen-go
RUN go get -u github.com/golang/protobuf/protoc-gen-go

ARG PYTHON_VERSION=3.9.2

# Install $PYTHON_VERSION

## This just installs whatever is is bullseye, makes docker build (fast/small)-(er)
RUN	apt install python3 pip -y && python3 -V

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

RUN python3 -m pip install --upgrade pip
RUN pip3 install grpcio grpcio-tools