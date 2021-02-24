# Go version here should match https://github.com/TykTechnologies/golang-cross/blob/master/.github/workflows/release.yml#L16

FROM golang:1.15.8-buster
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

RUN curl -sL "https://api.github.com/repos/TykTechnologies/tyk/tarball/${TYK_GW_TAG}" | \
    tar -C $TYK_GW_PATH --strip-components=1 -xzf - 

ENTRYPOINT ["/build.sh"]

