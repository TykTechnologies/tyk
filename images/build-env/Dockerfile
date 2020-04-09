FROM golang:1.12
LABEL io.tyk.vendor="Tyk" \
      version="1.3" \
      description="Base image for builds"

ENV GOPATH=/
ENV PACKER_VERSION="1.5.4"

RUN apt-get update && apt-get dist-upgrade -y && \
    apt-get install -y ca-certificates \
                       git \
                       locales \
                       curl \
                       jq \
                       rpm \
                       dpkg-sig \
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
RUN curl https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_linux_amd64.zip \
        -o /tmp/packer.zip && cd /usr/local/bin && unzip /tmp/packer.zip
