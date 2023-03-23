ARG GOLANG_CROSS=1.16

FROM tykio/golang-cross:${GOLANG_CROSS}
LABEL description="Image for plugin development"

ENV TYK_GW_PATH=/go/src/github.com/TykTechnologies/tyk

ENV GO111MODULE=on

# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
ENV PLUGIN_SOURCE_PATH=/plugin-source

RUN mkdir -p  $TYK_GW_PATH $PLUGIN_SOURCE_PATH

RUN apt-get update \
    && apt-get dist-upgrade -y curl git-core 

COPY ci/images/plugin-compiler/data/build.sh /build.sh
RUN chmod +x /build.sh

# Remove some things to decrease CVE surface
RUN  apt-get remove -y --allow-remove-essential --auto-remove curl libtiff5 ncurses-base \
	&& rm /usr/bin/passwd && rm /usr/sbin/adduser

# Clean up 
RUN rm -rf /root/.cache \
    && apt-get -y autoremove \
    && apt-get clean

COPY . $TYK_GW_PATH
RUN cd $TYK_GW_PATH && go mod vendor

ENTRYPOINT ["/build.sh"]