FROM busybox:ubuntu-14.04
MAINTAINER Jimmi Dyson <jimmidyson@gmail.com>

ADD ./stage/tyk /bin/tyk
ADD tyk.conf.example /etc/tyk/tyk.conf
ADD templates/ /etc/tyk/templates/

EXPOSE 8080

ENTRYPOINT ["/bin/tyk"]
CMD []
