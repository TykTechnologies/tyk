module github.com/TykTechnologies/tyk/ci/tests/plugin-compiler/testplugin

go 1.22

require (
	github.com/Masterminds/sprig/v3 v3.2.2
	github.com/TykTechnologies/tyk v1.9.2-0.20230606201232-e599d84bdfd1
	github.com/kr/pretty v0.2.1
)

replace github.com/jensneuse/graphql-go-tools => github.com/TykTechnologies/graphql-go-tools v1.6.2-0.20210609111804-af8c15678972
