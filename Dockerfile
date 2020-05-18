FROM debian:buster-slim
ENV GRPCVERSION 1.24.0
ENV TYKVERSION 2.9.4.1
ENV TYKLANG ""
LABEL Description="Tyk Gateway docker image" Vendor="Tyk" Version=$TYKVERSION
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
            wget curl ca-certificates apt-transport-https gnupg unzip \
 && curl -L https://packagecloud.io/tyk/tyk-gateway/gpgkey | apt-key add - \
 && apt-get install -y --no-install-recommends \
            build-essential \
            python3-setuptools \
            libpython3.7 \
            python3.7-dev \
            jq \
            git \
            redis-server \
 && rm -rf /usr/include/* && rm /usr/lib/x86_64-linux-gnu/*.a && rm /usr/lib/x86_64-linux-gnu/*.o \
 && rm /usr/lib/python3.7/config-3.7m-x86_64-linux-gnu/*.a \
 && wget https://bootstrap.pypa.io/get-pip.py && python3 get-pip.py && rm get-pip.py \
 && pip3 install protobuf grpcio==$GRPCVERSION \
 && apt-get purge -y build-essential \
 && apt-get autoremove -y \
 && rm -rf /root/.cache

RUN curl -sL https://deb.nodesource.com/setup_14.x | bash -
RUN apt-get install -y nodejs

WORKDIR /opt
RUN git clone https://github.com/trevorblades/countries
RUN npm install --prefix /opt/countries

COPY docker/tyk.conf /opt/tyk-gateway/tyk.conf
COPY docker/countries.json /opt/tyk-gateway/apps/countries.json
COPY docker/composed.json /opt/tyk-gateway/apps/composed.json
COPY tyk /opt/tyk-gateway/tyk
COPY templates/ /opt/tyk-gateway/templates/

COPY docker/entrypoint.sh /opt/tyk-gateway/entrypoint.sh
RUN chmod +x /opt/tyk-gateway/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/opt/tyk-gateway/entrypoint.sh"]