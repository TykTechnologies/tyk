FROM debian:buster-slim

LABEL Description="Tyk Gateway docker image" Vendor="Tyk"

RUN apt-get update \
 && apt-get dist-upgrade -y --no-install-recommends redis-server nginx \
            build-essential python3-setuptools libpython3.7 curl ca-certificates  \
 && curl https://bootstrap.pypa.io/get-pip.py | python3 \
 && pip3 install grpcio==1.24.0 \
 && apt-get purge -y build-essential \
 && apt-get autoremove -y \
 && rm -rf /root/.cache \
 && rm -rf /var/lib/apt/lists/*

RUN rm /etc/nginx/sites-enabled/default && rm /etc/nginx/sites-available/default

COPY images/hybrid/nginx/1_upstream.conf /etc/nginx/conf.d/
COPY images/hybrid/nginx/sample.tconf /etc/nginx/sites-enabled/
COPY images/hybrid/EULA.md /opt/tyk-gateway/EULA.md
COPY images/hybrid/entrypoint.sh /opt/tyk-gateway/entrypoint.sh

VOLUME ["/etc/nginx/sites-enabled/"]

RUN echo "** Use of the Tyk hybrid Container is subject to the End User License Agreement located in /opt/tyk-gateway/EULA.md **"

EXPOSE 8080 80 443

WORKDIR /opt/tyk-gateway/
ENTRYPOINT ["./entrypoint.sh"]
