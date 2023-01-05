# Go version here should match https://github.com/TykTechnologies/golang-cross/blob/master/.github/workflows/release.yml#L16
ARG GOLANG_CROSS

FROM tykio/golang-cross:${GOLANG_CROSS}
LABEL description="Image for plugin development"

ARG TYK_GW_TAG

ENV TYK_GW_PATH=/go/src/github.com/TykTechnologies/tyk

ENV GO111MODULE=on

# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
ENV PLUGIN_SOURCE_PATH=/plugin-source

# Upgrade certificates
RUN apt-get update && apt-get install ca-certificates libgnutls30 -y

RUN mkdir -p $TYK_GW_PATH $PLUGIN_SOURCE_PATH

COPY ci/images/plugin-compiler/data/build.sh /build.sh
RUN chmod +x /build.sh

COPY . $TYK_GW_PATH

ENTRYPOINT ["/build.sh"]

