FROM golang:1.7

RUN mkdir -p /go/src/github.com/getsentry/raven-go
WORKDIR /go/src/github.com/getsentry/raven-go
ENV GOPATH /go

RUN go install -race std && go get golang.org/x/tools/cmd/cover

COPY . /go/src/github.com/getsentry/raven-go

RUN go get -v ./...

CMD ["./runtests.sh"]
