# Go version here should match https://github.com/TykTechnologies/golang-cross/blob/master/.github/workflows/release.yml#L16

FROM golang:1.15-buster
LABEL description="Image for plugin development"

ARG GW_VERSION
#WORKDIR /__w/tyk/
#RUN git clone --depth 1 --branch $GW_VERSION  https://github.com/TykTechnologies/tyk
# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
ENV PLUGIN_SOURCE_PATH=/plugin-source

RUN mkdir -p  $PLUGIN_SOURCE_PATH
COPY images/plugin-compiler/data/build.sh /build.sh
# COPY ./ $TYK_GW_PATH/
# RUN cd $TYK_GW_PATH && go mod tidy && go mod vendor
RUN chmod +x /build.sh

ENTRYPOINT ["/build.sh"]

