module github.com/TykTechnologies/tyk/smoke-tests/plugin-compiler/foobar-plugin

go 1.15

require (
	github.com/HdrHistogram/hdrhistogram-go v1.1.0 // indirect
	github.com/Masterminds/sprig/v3 v3.2.2
	github.com/TykTechnologies/murmur3 v0.0.0-20190927072507-ba59b2844ad7 // indirect
	github.com/TykTechnologies/tyk v1.9.2-0.20210625184536-6b5eac3429dd
	github.com/kr/pretty v0.2.0
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/uber/jaeger-client-go v2.29.1+incompatible // indirect
	github.com/uber/jaeger-lib v2.4.1+incompatible // indirect
	go.uber.org/atomic v1.8.0 // indirect
)

replace github.com/TykTechnologies/tyk => ../../../
