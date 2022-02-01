# Go version here should match https://github.com/TykTechnologies/golang-cross/blob/master/.github/workflows/release.yml#L16

FROM golang:1.12-stretch
LABEL description="Image for plugin development"

ARG TYK_GW_TAG

ENV TYK_GW_PATH=/go/src/github.com/TykTechnologies/tyk

ENV GO111MODULE=on

# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
ENV PLUGIN_SOURCE_PATH=/plugin-source

# Try upgrade certificates
RUN apt-get upgrade ca-certificates

RUN mkdir -p $TYK_GW_PATH $PLUGIN_SOURCE_PATH

COPY images/plugin-compiler/data/build.sh /build.sh
RUN chmod +x /build.sh

RUN cd $TYK_GW_PATH &&  \
    git clone --depth 1 --branch $TYK_GW_TAG  https://github.com/TykTechnologies/tyk .

ENTRYPOINT ["/build.sh"]
