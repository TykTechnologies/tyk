FROM tykio/tyk-build-env:latest
LABEL io.tyk.vendor="Tyk" \
      version="1.0" \
      description="Image for plugin development"

ENV GOPATH=/go
ARG TYK_GW_TAG
# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
ENV PLUGIN_SOURCE_PATH=/plugin-source
# This is the temporary path where the plugin will be built
ENV PLUGIN_BUILD_PATH=/go/src/plugin-build

RUN mkdir -p $PLUGIN_SOURCE_PATH $PLUGIN_BUILD_PATH
COPY images/plugin-compiler/data/build.sh /build.sh
RUN chmod +x /build.sh

COPY vendor/ $GOPATH/src/

ENTRYPOINT ["/build.sh"]

