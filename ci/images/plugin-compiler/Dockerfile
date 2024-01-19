ARG BASE_IMAGE=tykio/golang-cross:1.22
FROM ${BASE_IMAGE}

LABEL description="Image for compiling and testing Tyk Gateway plugins"

ENV WORKSPACE_ROOT=/opt/tyk github.com/TykTechnologies/tyk

ENV GO111MODULE=on

# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
ENV PLUGIN_SOURCE_PATH=/plugin-source

RUN mkdir -p $TYK_GW_PATH $PLUGIN_SOURCE_PATH

RUN apt-get remove -y --allow-remove-essential --auto-remove mercurial ruby* python* || true \
	&& rm /usr/bin/passwd && rm /usr/sbin/adduser

ADD go.mod go.sum $TYK_GW_PATH
WORKDIR $TYK_GW_PATH

RUN --mount=type=cache,mode=0755,target=/go/pkg/mod go mod download

ADD . $TYK_GW_PATH

# Provide a gateway test binary for testing plugin loading.
RUN --mount=type=cache,mode=0755,target=/go/pkg/mod GOBIN=/usr/local/bin go install -tags=goplugin -trimpath .

ARG GITHUB_SHA
ARG GITHUB_TAG
ARG GO_VERSION=1.17
ARG PYTHON_VERSION=3.9
ENV GITHUB_SHA ${GITHUB_SHA}
ENV GITHUB_TAG ${GITHUB_TAG}

COPY ci/images/plugin-compiler/data/build.sh /build.sh
RUN chmod +x /build.sh

ENTRYPOINT ["/build.sh"]
