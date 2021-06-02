#!/bin/sh

# Dependencies needed:
# * grpc (for protoc)
# * go get -u github.com/golang/protobuf/protoc-gen-go
# * pip3 install grpcio grpcio-tools

echo "Generating bindings for Go."
protoc -I. --go_out=plugins=grpc:../ *.proto

echo "Generating bindings for Python."
mkdir -p ../bindings/python
protoc -I. --python_out=../bindings/python *.proto
python3 codegen.py

echo "Generating bindings for Ruby."
mkdir -p ../bindings/ruby
protoc -I. --ruby_out=plugins=grpc:../bindings/ruby *.proto

cp ../bindings/python/* ../python/proto/

echo
echo "Done"
