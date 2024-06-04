module github.com/TykTechnologies/tyk/ci/tests/plugin-compiler/testplugin

go 1.21.0

toolchain go1.21.4

require (
	github.com/Masterminds/sprig/v3 v3.2.3
	github.com/TykTechnologies/tyk v1.9.2-0.20240604111314-25a8a36fe795
	github.com/kr/pretty v0.3.1
)

replace github.com/TykTechnologies/tyk => ../../../../../
