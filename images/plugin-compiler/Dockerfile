FROM tykio/tyk-build-env:latest
LABEL io.tyk.vendor="Tyk" \
      version="1.0" \
      description="Image for plugin development"

ARG TYK_GW_TAG
ENV GOPATH=/go
ENV TYK_GW_PATH=${GOPATH}/src/github.com/TykTechnologies/tyk
# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
ENV PLUGIN_SOURCE_PATH=/plugin-source
# This is the temporary path where the plugin will be built
ENV PLUGIN_BUILD_PATH=/go/src/plugin-build

RUN mkdir -p $TYK_GW_PATH $PLUGIN_SOURCE_PATH $PLUGIN_BUILD_PATH
COPY data/build.sh /build.sh
RUN chmod +x /build.sh

RUN curl -sL "https://api.github.com/repos/TykTechnologies/tyk/tarball/${TYK_GW_TAG}" | \
    tar -C $TYK_GW_PATH --strip-components=1 -xzf - 
RUN yes | cp -r $TYK_GW_PATH/vendor $GOPATH/src && rm -rf $TYK_GW_PATH/vendor

ENTRYPOINT ["/build.sh"]

