ARG BASE_IMAGE
FROM ${BASE_IMAGE} as tyk

FROM debian:bookworm-slim

COPY --from=tyk /opt/tyk-gateway/tyk /opt/tyk-gateway/tyk

WORKDIR /tmp

ADD . .

RUN apt-get update && apt-get install -y busybox

RUN rm -f bundle.zip && /opt/tyk-gateway/tyk bundle build -y

ENTRYPOINT [ "busybox" ]

CMD [ "httpd", "-f", "-p", "0.0.0.0:80" ]
