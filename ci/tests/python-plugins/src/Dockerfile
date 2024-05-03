ARG BASE_IMAGE
FROM busybox:stable-glibc as BB

FROM ${BASE_IMAGE}

COPY --from=BB /bin/sh /bin/sh
COPY --from=BB /bin/rm /bin/rm
COPY --from=BB /bin/httpd /bin/httpd

WORKDIR /tmp

ADD . .

RUN rm -f bundle.zip && /opt/tyk-gateway/tyk bundle build -y

ENTRYPOINT [ "httpd" ]

CMD [ "-f", "-p", "0.0.0.0:80" ]
