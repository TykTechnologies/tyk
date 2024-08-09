FROM debian:bookworm-slim as build
RUN apt-get install -y python3-setuptools libpython3-dev python3-dev python3-grpcio

ARG BASE_IMAGE
FROM ${BASE_IMAGE}

# For Python plugins
COPY --from=build /usr/bin/python3 /usr/bin/python3
COPY --from=build /usr/lib/python3.*/ /usr/lib/python3.*/
COPY --from=build /usr/lib/x86_64-linux-gnu/ /usr/lib/x86_64-linux-gnu/
COPY --from=build /usr/include/python3.*/ /usr/include/python3.*/
COPY --from=build /usr/lib/python3/dist-packages/ /usr/lib/python3/dist-packages/

EXPOSE 8080 80 443

ENV PORT=8080

WORKDIR /opt/tyk-gateway/

ENTRYPOINT ["/opt/tyk-gateway/tyk" ]
CMD [ "--conf=/opt/tyk-gateway/tyk.conf" ]