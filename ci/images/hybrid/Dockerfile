FROM debian:bookworm-slim
ARG TARGETARCH

LABEL Description="Tyk Hybrid Gateway image" Vendor="Tyk"

RUN echo http://deb.debian.org/debian/ bookworm main >> /etc/apt/sources.list.d/debian.sources && \
    echo deb http://deb.debian.org/debian/ bookworm-updates main >> /etc/apt/sources.list.d/debian.sources

RUN apt-get update \
 && apt-get dist-upgrade -y --no-install-recommends redis-server nginx \
            python3-setuptools libpython3-dev curl ca-certificates python3-grpcio \
 && apt-get autoremove -y \
 && rm -rf /usr/include/* && rm /usr/lib/*-linux-gnu/*.a && rm /usr/lib/*-linux-gnu/*.o \
 && rm -rf /root/.cache \
 && rm -rf /var/lib/apt/lists/*

COPY *${TARGETARCH}.deb /
RUN dpkg -i /*${TARGETARCH}.deb

COPY ci/images/hybrid/nginx/1_upstream.conf /etc/nginx/conf.d/
COPY ci/images/hybrid/nginx/sample.tconf /etc/nginx/sites-enabled/
COPY ci/images/hybrid/EULA.md /opt/tyk-gateway/EULA.md
COPY ci/images/hybrid/entrypoint.sh /opt/tyk-gateway/entrypoint.sh

VOLUME ["/etc/nginx/sites-enabled/"]

RUN echo "** Use of the Tyk hybrid Container is subject to the End User License Agreement located in /opt/tyk-gateway/EULA.md **"

EXPOSE 8080 80 443

ENV PORT=8080
WORKDIR /opt/tyk-gateway/
ENTRYPOINT ["./entrypoint.sh"]
