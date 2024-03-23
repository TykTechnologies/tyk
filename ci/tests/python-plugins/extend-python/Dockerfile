ARG BASE_IMAGE
FROM ${BASE_IMAGE}

# For Python plugins
RUN apt-get install -y python3-setuptools libpython3-dev python3-dev python3-grpcio

EXPOSE 8080 80 443

ENV PORT=8080

WORKDIR /opt/tyk-gateway/

ENTRYPOINT ["/opt/tyk-gateway/tyk" ]
CMD [ "--conf=/opt/tyk-gateway/tyk.conf" ]