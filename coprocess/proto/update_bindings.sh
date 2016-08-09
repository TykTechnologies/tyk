#!/bin/sh
echo "Generating bindings for Go."
protoc -I. --go_out=../ *.proto
cd .. ; ls -l *.pb.go ; cd -

echo "Generating bindings for Python."
mkdir -p ../bindings/python
protoc -I. --python_out=../bindings/python *.proto
cd ../bindings/python ; ls -l *.py ; cd -

echo
echo "Done"
