#!/bin/bash
set -e

# Build gw test binary
go test -o gateway.test -c ./gateway

BENCHMARKS=$(./gateway.test -test.list=Bench.+)

for benchmark in $BENCHMARKS; do
	echo $benchmark
	benchRegex="^${benchmark}$"
	./gateway.test -test.run=^$ -test.bench=$benchRegex -test.count=1 \
			-test.benchtime 30s -test.benchmem \
			-test.cpuprofile=coverage/$benchmark-cpu.out \
			-test.memprofile=coverage/$benchmark-mem.out \
			-test.trace=coverage/$benchmark-trace.out
done
