# Generated by: tyk-ci/wf-gen
# Generated on: Wed 17 Feb 08:13:53 UTC 2021

# Generation commands:
# ./pr.zsh -title Remove changelog -branch goreleaser/more -p
# m4 -E -DxREPO=tyk


ARG BASE_IMAGE=debian:buster-slim
ARG PORTS
ARG TARBALL

FROM $BASE_IMAGE

RUN apt-get update \
 && apt-get dist-upgrade -y ca-certificates \
 && apt-get autoremove -y

WORKDIR /opt/tyk-gateway
COPY $TARBALL .

EXPOSE $PORTS

ENTRYPOINT ["/opt/tyk-gateway/tyk" ]
CMD [ "--conf=/opt/tyk-gateway/tyk.conf" ]
