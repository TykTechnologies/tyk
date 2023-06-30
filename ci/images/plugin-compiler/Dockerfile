ARG BASE_IMAGE=tykio/golang-cross:1.16-bullseye
FROM ${BASE_IMAGE}

LABEL description="Image for plugin development"


# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
ENV PLUGIN_SOURCE_PATH=/plugin-source

RUN mkdir -p $PLUGIN_SOURCE_PATH

RUN apt-get remove -y --allow-remove-essential --auto-remove mercurial \
	&& rm /usr/bin/passwd && rm /usr/sbin/adduser

# This is already vendored from release pipeline
WORKDIR /opt/tyk-gateway/src
ADD . /opt/tyk-gateway/src

# TYK_GW_PATH points to the GOHOME source for gateway.
ENV TYK_GW_PATH /go/src/github.com/TykTechnologies/tyk

# This has to mirror the before goreleaser step in release.yml;
# It builds the go source tree for $GOHOME builds from gw.

RUN --mount=type=cache,mode=0755,target=/go/pkg/mod true && \
          mkdir -p /go/src && \
          go mod tidy && \
          go mod vendor && \
          cp -r -f vendor/* /go/src && \
          mkdir -p $TYK_GW_PATH && \
          cp -r ./* $TYK_GW_PATH && \
          find /go/src -name vendor | xargs --no-run-if-empty -d '\n' rm -rf

ENV GO111MODULE=off

ARG GITHUB_SHA
ARG GITHUB_TAG
ENV GITHUB_SHA ${GITHUB_SHA}
ENV GITHUB_TAG ${GITHUB_TAG}

COPY ci/images/plugin-compiler/data/build.sh /build.sh
RUN chmod +x /build.sh

ENTRYPOINT ["/build.sh"]
