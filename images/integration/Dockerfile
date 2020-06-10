FROM debian:buster-slim

ARG conf_file=/conf/tyk/tyk.conf

ADD gateway.tar.gz /opt/tyk-gateway

VOLUME ["/conf"]
WORKDIR /opt/tyk-gateway

ENTRYPOINT ["/opt/tyk-gateway/tyk", "--conf=${conf_file}"]
