#!/bin/bash
set -e

mkdir /go
mv vendor _novendor
ln -s $PWD/_novendor /go/src
ln -s /develop/go/src/github.com/TykTechnologies/tyk /go/src/github.com/TykTechnologies/tyk
OLD_GOPATH=$GOPATH
export GOPATH=/go
go build -tags 'coprocess grpc'
export GOPATH=$OLD_GOPATH
rm -rf /go
mv $PWD/_novendor $PWD/vendor