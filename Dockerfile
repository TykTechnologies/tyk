FROM golang:1.15 as builder

RUN apt-get install make

WORKDIR /opt/tyk-gateway
ADD . /opt/tyk-gateway

RUN make build

RUN /opt/tyk-gateway/tyk --version

FROM debian:bullseye

WORKDIR /opt/tyk-gateway

COPY --from=builder /opt/tyk-gateway/tyk tyk
COPY templates/ ./templates/
COPY apps/app_sample.json apps/app_sample.json
COPY tyk.conf.example tyk.conf

RUN /opt/tyk-gateway/tyk --version

ENTRYPOINT ["/opt/tyk-gateway/tyk"]