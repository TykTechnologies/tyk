ARG BASE_IMAGE
FROM ${BASE_IMAGE} as tyk

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y python3-setuptools libpython3-dev python3-dev python3-grpcio

COPY --from=tyk /opt/tyk-gateway/ /opt/tyk-gateway/

EXPOSE 8080 80 443

ENV PORT=8080

WORKDIR /opt/tyk-gateway/

ENTRYPOINT ["/opt/tyk-gateway/tyk" ]
CMD [ "--conf=/opt/tyk-gateway/tyk.conf" ]