ARG BASE_IMAGE
FROM ${BASE_IMAGE} AS base

FROM python:3.11-bookworm
COPY --from=base /opt/tyk-gateway/ /opt/tyk-gateway/
RUN pip install setuptools && pip install google && pip install 'protobuf==4.24.4'

EXPOSE 8080 80 443

ENV PYTHON_VERSION=3.11
ENV PORT=8080

WORKDIR /opt/tyk-gateway/

ENTRYPOINT ["/opt/tyk-gateway/tyk" ]
CMD [ "--conf=/opt/tyk-gateway/tyk.conf" ]
