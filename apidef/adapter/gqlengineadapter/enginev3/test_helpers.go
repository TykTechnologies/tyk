package enginev3

import (
	"net/http"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/graphql_datasource"

	"github.com/TykTechnologies/tyk/apidef"
)

// SetSubscriptionClientFactoryForTest plugs a subscription client factory into
// a UniversalDataGraph instance so tests can run the engine config builder
// without dialing real GraphQL upstreams. Exported so callers in
// `ee/middleware/graphql_federation/*_test.go` (or any other in-tree test
// package) can wire a mock factory in. Production code paths set the factory
// via `subscriptionClientFactoryOrDefault`, so this helper is only meaningful
// for tests.
func SetSubscriptionClientFactoryForTest(u *UniversalDataGraph, factory graphqldatasource.GraphQLSubscriptionClientFactory) {
	u.subscriptionClientFactory = factory
}

// NewUDGForTest constructs a UniversalDataGraph wired up like the gateway
// would for an EngineConfigV3 build. Tests under
// `ee/middleware/graphql_federation/` use this to exercise federation
// integration without depending on the gateway package.
func NewUDGForTest(apiDef *apidef.APIDefinition, httpClient *http.Client) *UniversalDataGraph {
	return &UniversalDataGraph{
		ApiDefinition: apiDef,
		HttpClient:    httpClient,
	}
}

// NewUDGForTestWithSubscriptionFactory is a convenience around NewUDGForTest
// for plan-shape tests that need a mock subscription client factory.
func NewUDGForTestWithSubscriptionFactory(apiDef *apidef.APIDefinition, httpClient *http.Client, factory graphqldatasource.GraphQLSubscriptionClientFactory) *UniversalDataGraph {
	udg := NewUDGForTest(apiDef, httpClient)
	udg.subscriptionClientFactory = factory
	return udg
}
