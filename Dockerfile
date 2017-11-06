FROM golang:1.9.2-alpine3.6

RUN apk add --update git vim bash && rm -rf /var/cache/apk/*

RUN echo 'alias ll="ls -la"' >> ~/.bashrc

ARG BUNDLE_GITHUB__COM
RUN echo -e "machine github.com\n  login ${BUNDLE_GITHUB__COM}" >> ~/.netrc
RUN echo -e '' > ~/.netrc

ARG BUNDLE_GITHUB__COM
ARG APP_NAME
ENV APP_NAME ${APP_NAME:-tyk}

ENV PROTOVERSION 3.2.0
ENV TYKVERSION 2.3.10
ENV TYKLANG ""

ENV TYKLISTENPORT 8080
ENV TYKSECRET 352d20ee67be67f6340b4c0605b044b7
ENV TYK_PATH /opt/tyk-gateway/

LABEL Description="Tyk Gateway docker image" Vendor="Tyk" Version=$TYKVERSION

RUN mkdir -p /go/src/github.com/gtforge/${APP_NAME}
RUN echo -e "machine github.com\n  login ${BUNDLE_GITHUB__COM}" >> ~/.netrc

RUN echo -e '' > ~/.netrc

ADD . /go/src/github.com/gtforge/${APP_NAME}
WORKDIR /go/src/github.com/gtforge/${APP_NAME}
RUN go get && go build -v -i
RUN mkdir -p /opt/tyk-gateway/ && cp ${APP_NAME} /opt/tyk-gateway/${APP_NAME}
COPY templates /opt/tyk-gateway/templates

VOLUME ["/opt/tyk-gateway/"]

WORKDIR /opt/tyk-gateway/

EXPOSE $TYKLISTENPORT

CMD []