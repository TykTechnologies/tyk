ARG BASE_IMAGE=tykio/golang-cross:1.25-bullseye
FROM ${BASE_IMAGE}

LABEL description="Image for plugin development"

ENV TYK_GW_PATH=/go/src/github.com/TykTechnologies/tyk

ENV GO111MODULE=on

# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
ENV PLUGIN_SOURCE_PATH=/plugin-source

RUN mkdir -p $TYK_GW_PATH $PLUGIN_SOURCE_PATH

# remove for avoiding CVEs
RUN apt-get purge -y --allow-remove-essential --auto-remove wget curl automake cmake python* docker* libsqlite* qemu* \
	&& rm -f /usr/bin/passwd /usr/sbin/adduser /usr/bin/goreleaser

ADD go.mod go.sum $TYK_GW_PATH
WORKDIR $TYK_GW_PATH

RUN --mount=type=cache,mode=0755,target=/go/pkg/mod \
    --mount=type=cache,mode=0755,target=/root/.cache/go-build \
    go mod download

ADD . $TYK_GW_PATH

# Provide a gateway test binary for testing plugin loading.
RUN --mount=type=cache,mode=0755,target=/go/pkg/mod \
    --mount=type=cache,mode=0755,target=/root/.cache/go-build \
    GOBIN=/usr/local/bin go install -tags=goplugin -trimpath .

ARG GITHUB_SHA
ARG GITHUB_TAG
ENV GITHUB_SHA=${GITHUB_SHA}
ENV GITHUB_TAG=${GITHUB_TAG}

ARG BUILD_TAG
ENV BUILD_TAG=${BUILD_TAG}

COPY ci/images/plugin-compiler/data/build.sh /build.sh
RUN chmod +x /build.sh

ENTRYPOINT ["/build.sh"]
