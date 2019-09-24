FROM golang:1.12
LABEL io.tyk.vendor="Tyk" \
      version="1.0" \
      description="Base image for builds"

ENV GOPATH=/

RUN apt-get update && apt-get dist-upgrade -y && \
    apt-get install -y ca-certificates \
                       git \
                       locales \
                       curl \
                       jq \
                       rpm \
                       build-essential \
                       libluajit-5.1-2 \
                       libluajit-5.1-dev \
                       luarocks \
                       python3-setuptools \
                       python3-dev \
                       python3-pip \
                       ruby-dev 
RUN luarocks install lua-cjson
RUN pip3 install grpcio protobuf
RUN mkdir -p $GOPATH ~/rpmbuild/SOURCES ~/rpmbuild/SPECS
RUN go get github.com/mitchellh/gox
RUN gem install fpm rake package_cloud
