FROM golang:1.22-bookworm

# Build essentials

RUN apt update && apt install git build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev curl wget libbz2-dev -y

# Build gateway
RUN mkdir /opt/tyk-gateway
WORKDIR /opt/tyk-gateway
ADD go.mod go.sum /opt/tyk-gateway/
RUN go mod download
ADD . /opt/tyk-gateway

RUN git config --global --add safe.directory /opt/tyk-gateway

RUN make build

COPY tyk.conf.example tyk.conf

RUN 	echo "Tyk: $(/opt/tyk-gateway/tyk --version 2>&1)" && \
	echo "Go: $(go version)" && \
	echo "Python: $(python3 --version)"

ENTRYPOINT ["/opt/tyk-gateway/tyk"]