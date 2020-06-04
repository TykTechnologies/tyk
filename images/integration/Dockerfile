FROM debian:buster-slim

ADD gateway.tar.gz /opt/tyk-gateway

VOLUME ["/opt/tyk-gateway/conf"]
WORKDIR /opt/tyk-gateway

ENTRYPOINT ["/opt/tyk-gateway/tyk", "--conf=/opt/tyk-gateway/conf/tyk.conf"]
