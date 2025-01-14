#!/bin/bash
set -e

# Build gw test binary
go test -o gateway.test -c ./gateway

BENCHMARKS=$(./gateway.test -test.list=Bench.+)

for benchmark in $BENCHMARKS; do
	echo $benchmark
	benchRegex="^${benchmark}$"
	./gateway.test -test.run=^$ -test.bench=$benchRegex -test.count=1 -test.benchtime 10s -test.benchmem -test.cpuprofile=tyk-cpu.out -test.memprofile=mem.out -test.trace=trace.out
done
