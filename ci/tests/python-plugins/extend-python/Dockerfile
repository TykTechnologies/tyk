ARG BASE_IMAGE

FROM debian:bookworm-slim as deb_extractor
RUN cd /tmp && \
    apt-get update && apt-get download \
    apt-get install -y python3-setuptools libpython3-dev python3-dev python3-grpcio  && \
    mkdir /dpkg && \
    for deb in *.deb; do dpkg --extract $deb /dpkg || exit 10; done

FROM ${BASE_IMAGE}

# For Python plugins
COPY --from=deb_extractor /dpkg /

EXPOSE 8080 80 443

ENV PORT=8080

WORKDIR /opt/tyk-gateway/

ENTRYPOINT ["/opt/tyk-gateway/tyk" ]
CMD [ "--conf=/opt/tyk-gateway/tyk.conf" ]