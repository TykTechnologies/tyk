ARG GOLANG_CROSS=1.16

FROM tykio/golang-cross:${GOLANG_CROSS}
LABEL description="Image for plugin development"

ENV TYK_GW_PATH=/go/src/github.com/TykTechnologies/tyk

ENV GO111MODULE=on

# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
ENV PLUGIN_SOURCE_PATH=/plugin-source

RUN mkdir -p  $TYK_GW_PATH $PLUGIN_SOURCE_PATH

COPY ci/images/plugin-compiler/data/build.sh /build.sh
RUN chmod +x /build.sh
 && dpkg --add-architecture arm64                      \
 && apt-get update                                     \
 && apt-get dist-upgrade -y -q                         \
        autoconf                                       \
        automake                                       \
        autotools-dev                                  \
        bc                                             \
        binfmt-support                                 \
        binutils-multiarch                             \
        binutils-multiarch-dev                         \
        build-essential                                \
        clang                                          \
        git-core                                       \
        crossbuild-essential-arm64                     \
        curl                                           \
        libtool                                        \
        multistrap                                     \
        patch                                          \
        wget                                           \
        xz-utils                                       \
        lsb-release                                    \
        cmake                                          \
        apt-transport-https                            \
        qemu-user-static                               \
        libxml2-dev                                    \
        lzma-dev                                       \
        openssl                                        \
        libssl-dev                                     \
        unzip                                          \
        sudo                                           \
        jq                                             \
        rpm                                            \
        ruby-dev

# Remove some things to decrease CVE surface
RUN  apt-get remove -y --allow-remove-essential --auto-remove curl\
	&& rm /usr/bin/passwd && rm /usr/sbin/adduser

COPY . $TYK_GW_PATH
RUN cd $TYK_GW_PATH && go mod vendor

ENTRYPOINT ["/build.sh"]

