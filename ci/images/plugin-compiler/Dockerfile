ARG BASE_IMAGE=tykio/golang-cross:1.16-bullseye
FROM ${BASE_IMAGE}

LABEL description="Image for plugin development"

ENV TYK_GW_PATH=/go/src/github.com/TykTechnologies/tyk

ENV GO111MODULE=off

# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
ENV PLUGIN_SOURCE_PATH=/plugin-source

RUN mkdir -p $TYK_GW_PATH $PLUGIN_SOURCE_PATH

RUN apt-get remove -y --allow-remove-essential --auto-remove mercurial \
	&& rm /usr/bin/passwd && rm /usr/sbin/adduser

# This is already vendored from release pipeline
WORKDIR $TYK_GW_PATH
ADD . $TYK_GW_PATH

ARG GITHUB_SHA
ARG GITHUB_TAG
ENV GITHUB_SHA ${GITHUB_SHA}
ENV GITHUB_TAG ${GITHUB_TAG}

COPY ci/images/plugin-compiler/data/build.sh /build.sh
RUN chmod +x /build.sh

ENTRYPOINT ["/build.sh"]
