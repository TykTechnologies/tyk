ARG BASE_IMAGE
ARG DEBIAN_BASE=debian:12-slim
FROM ${BASE_IMAGE} as TYK

FROM ${DEBIAN_BASE}

# For Python plugins
RUN apt-get update
RUN apt-get install -y python3-setuptools libpython3-dev python3-dev python3-grpcio

EXPOSE 8080 80 443

ENV PORT=8080

COPY --from=TYK /opt/tyk-gateway /opt/tyk-gateway

WORKDIR /opt/tyk-gateway/

ENTRYPOINT ["/opt/tyk-gateway/tyk" ]
CMD [ "--conf=/opt/tyk-gateway/tyk.conf" ]
