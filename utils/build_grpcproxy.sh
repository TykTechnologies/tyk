#!/bin/bash

mv vendor/golang.org/x/net/trace vendor/golang.org/x/net/trace-ignore
go build --tags='coprocess grpc'
mv vendor/golang.org/x/net/trace-ignore vendor/golang.org/x/net/trace