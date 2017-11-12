FROM golang:1.9.2-alpine3.6

RUN apk add --update git vim bash && rm -rf /var/cache/apk/*

RUN echo 'alias ll="ls -la"' >> ~/.bashrc

ARG APP_NAME
ENV APP_NAME ${APP_NAME:-tyk}

ENV PROTOVERSION 3.2.0
ENV TYKVERSION 2.3.10
ENV TYKLANG ""

ENV TYKLISTENPORT 8080
ENV TYKSECRET 352d20ee67be67f6340b4c0605b044b7
ENV TYK_PATH /opt/tyk-gateway/

LABEL Description="Tyk Gateway docker image" Vendor="Tyk" Version=$TYKVERSION

RUN mkdir -p /go/src/github.com/gtforge/${APP_NAME} && mkdir -p /opt/tyk-gateway/
COPY templates /opt/tyk-gateway/templates

ADD . /go/src/github.com/gtforge/${APP_NAME}
RUN cd /go/src/github.com/gtforge/${APP_NAME} && \
  go get && go build -v -i && \
  cp ${APP_NAME} /opt/tyk-gateway/${APP_NAME} && \
  rm -rf /go/src/github.com/gtforge/

VOLUME ["/opt/tyk-gateway/"]

WORKDIR /opt/tyk-gateway/

EXPOSE $TYKLISTENPORT

CMD []
