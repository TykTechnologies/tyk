ARG BASE_IMAGE

FROM debian:bookworm-slim as build
RUN apt-get update && apt-get install -y python3-setuptools libpython3-dev python3-dev python3-grpcio

FROM ${BASE_IMAGE}

# For Python plugins
COPY --from=build /usr/bin/python3 /usr/bin/python3
COPY --from=build /usr/lib/python3.*/ /usr/lib/python3.*/
COPY --from=build /usr/lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu
COPY --from=build /usr/include/python3.*/ /usr/include/python3.*/
COPY --from=build /usr/lib/python3/dist-packages/ /usr/lib/python3/dist-packages/

EXPOSE 8080 80 443

ENV PORT=8080

WORKDIR /opt/tyk-gateway/

ENTRYPOINT ["/opt/tyk-gateway/tyk" ]
CMD [ "--conf=/opt/tyk-gateway/tyk.conf" ]