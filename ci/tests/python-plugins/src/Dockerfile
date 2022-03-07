ARG tag
FROM tykio/tyk-gateway:${tag}

RUN apt-get update && apt-get install -y busybox
WORKDIR /tmp
ADD . .
RUN rm -f bundle.zip && /opt/tyk-gateway/tyk bundle build -y
ENTRYPOINT [ "busybox" ]
CMD [ "httpd", "-f", "-p", "0.0.0.0:80" ]
