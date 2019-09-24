FROM tykio/tyk-build-env:latest
LABEL io.tyk.vendor="Tyk" \
      version="1.0" \
      description="Image for plugin development"

ARG TYK_GW_TAG
ENV TYK_GW_PATH=${GOPATH}/src/github.com/TykTechnologies/tyk

RUN mkdir -p /go/src/plugin-build $TYK_GW_PATH
COPY data/build.sh /build.sh
RUN chmod +x /build.sh

RUN curl -sL "https://api.github.com/repos/TykTechnologies/tyk/tarball/${TYK_GW_TAG}" | \
    tar -C $TYK_GW_PATH --strip-components=1 -xzf -

ENTRYPOINT ["/build.sh"]

