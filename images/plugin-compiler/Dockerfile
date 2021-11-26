# Go version here should match https://github.com/TykTechnologies/golang-cross/blob/<branch>/.github/workflows/release.yml#L38

FROM golang:1.15.15
LABEL description="Image for plugin development"

ARG TYK_GW_TAG
ENV TYK_GW_PATH=/go/src/github.com/TykTechnologies/tyk
# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
ENV PLUGIN_SOURCE_PATH=/plugin-source
# This is the temporary path where the plugin will be built
ENV PLUGIN_BUILD_PATH=/go/src/plugin-build

RUN mkdir -p $TYK_GW_PATH $PLUGIN_SOURCE_PATH $PLUGIN_BUILD_PATH
COPY images/plugin-compiler/data/build.sh /build.sh
RUN chmod +x /build.sh

ENTRYPOINT ["/build.sh"]

