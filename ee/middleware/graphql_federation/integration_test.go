package graphql_federation

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/graphql_datasource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/adapter/gqlengineadapter/enginev3"
)

// init registers the federation provider for tests in this package. The
// gateway's `mw_graphql_federation_ee.go` does the same registration in the
// real binary, but tests in this package run with `go test` directly against
// the adapter and need the provider plugged in.
func init() {
	enginev3.RegisterFederationProvider(NewProvider())
}

// mockSubscriptionClientFactory satisfies
// graphqldatasource.GraphQLSubscriptionClientFactory so the engine config
// builder doesn't try to dial a real upstream during tests.
type mockSubscriptionClientFactory struct{}

func (m *mockSubscriptionClientFactory) NewSubscriptionClient(httpClient, streamingClient *http.Client, engineCtx context.Context, options ...graphqldatasource.Options) graphqldatasource.GraphQLSubscriptionClient {
	return &graphqldatasource.SubscriptionClient{}
}

// TestUniversalDataGraph_FederationSubgraph asserts the plan-shape contract:
// when the customer's SDL declares `@key` types, the engine V3 configuration
// produced by the adapter must register an `_entities` and `_service` data
// source on Query.
func TestUniversalDataGraph_FederationSubgraph(t *testing.T) {
	schema := `
		type Query {
			me: User
		}
		type User @key(fields: "id") {
			id: ID!
			username: String!
		}
	`

	apiDef := &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Schema: schema,
			Engine: apidef.GraphQLEngineConfig{
				FieldConfigs: []apidef.GraphQLFieldConfig{},
				DataSources:  []apidef.GraphQLEngineDataSource{},
			},
		},
	}

	udg := enginev3.NewUDGForTest(apiDef, nil)
	conf, err := udg.EngineConfigV3()
	require.NoError(t, err)
	require.NotNil(t, conf)

	hasEntitiesDS := false
	hasServiceDS := false
	for _, ds := range conf.DataSources() {
		for _, rootNode := range ds.RootNodes {
			if rootNode.TypeName == "Query" {
				for _, fieldName := range rootNode.FieldNames {
					if fieldName == "_entities" {
						hasEntitiesDS = true
					}
					if fieldName == "_service" {
						hasServiceDS = true
					}
				}
			}
		}
	}

	assert.True(t, hasEntitiesDS, "Should have _entities data source")
	assert.True(t, hasServiceDS, "Should have _service data source")
}

// TestUDGFederation_Subscription_PlanShape is a sanity check on the engine
// configuration produced for a UDG API that mixes federation (`@key`) with a
// Subscription type. It verifies three properties of the plan shape:
//
//  1. The user GraphQL data source carries a Subscription RootNode for the
//     subscription field — without this the planner has no source for the
//     operation.
//  2. The federation-internal entities data source (responsible for
//     `_entities`) does NOT have any Subscription-typed RootNode. Apollo
//     Federation never dispatches subscriptions to `_entities`, and the
//     planner must not be allowed to think it can.
//  3. The User entity remains wired as an entity — the federation
//     `_Entity` union and `_entities` Query field appear on the federated
//     schema, proving Subscription-on-an-entity-type didn't break the
//     existing federation path.
func TestUDGFederation_Subscription_PlanShape(t *testing.T) {
	schema := `
		type Query { user(id: ID!): User }
		type User @key(fields: "id") {
			id: ID!
			username: String!
		}
		type Subscription { onUser: User! }
	`

	// buildEntityResolvers probes the configured upstream for `_service
	// { sdl }`. Stand up a minimal mock that answers with a federation-v2
	// SDL so the resolver-builder picks the federation-passthrough
	// strategy and the engine config can be assembled without a real
	// upstream.
	upstreamSDL := `extend schema @link(url: "https://specs.apollo.dev/federation/v2.5", import: ["@key"])
type User @key(fields: "id") {
  id: ID!
  username: String!
}
`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"_service":{"sdl":%q}}}`, upstreamSDL)))
	}))
	defer upstream.Close()

	apiDef := &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Schema: schema,
			Engine: apidef.GraphQLEngineConfig{
				FieldConfigs: []apidef.GraphQLFieldConfig{},
				DataSources: []apidef.GraphQLEngineDataSource{
					{
						Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
						Name: "users_ds",
						RootFields: []apidef.GraphQLTypeFields{
							{Type: "Query", Fields: []string{"user"}},
							{Type: "Subscription", Fields: []string{"onUser"}},
							{Type: "User", Fields: []string{"id", "username"}},
						},
						Config: []byte(fmt.Sprintf(`{"url":%q,"method":"POST"}`, upstream.URL)),
					},
				},
			},
		},
	}

	udg := enginev3.NewUDGForTestWithSubscriptionFactory(apiDef, nil, &mockSubscriptionClientFactory{})
	conf, err := udg.EngineConfigV3()
	require.NoError(t, err)
	require.NotNil(t, conf)

	// Walk the configured data sources to classify them. The user
	// GraphQL data source is identified by its registered Subscription
	// RootNode; the federation-internal entities DS is identified by
	// having `_entities` as a Query RootNode.
	var (
		userDSHasSubscription     bool
		entitiesDSSawSubscription bool
		hasEntitiesDS             bool
		hasUserEntityRoot         bool
	)
	for _, ds := range conf.DataSources() {
		dsHasEntities := false
		for _, rootNode := range ds.RootNodes {
			if rootNode.TypeName == "Query" {
				for _, fieldName := range rootNode.FieldNames {
					if fieldName == "_entities" {
						dsHasEntities = true
						hasEntitiesDS = true
					}
				}
			}
			if rootNode.TypeName == "User" {
				hasUserEntityRoot = true
			}
		}
		// Now check Subscription RootNodes on this DS.
		for _, rootNode := range ds.RootNodes {
			if rootNode.TypeName != "Subscription" {
				continue
			}
			if dsHasEntities {
				entitiesDSSawSubscription = true
			} else {
				for _, fieldName := range rootNode.FieldNames {
					if fieldName == "onUser" {
						userDSHasSubscription = true
					}
				}
			}
		}
	}

	assert.True(t, userDSHasSubscription,
		"user GraphQL data source must register Subscription.onUser as a RootNode")
	assert.False(t, entitiesDSSawSubscription,
		"entities data source must NOT advertise any Subscription RootNode")
	assert.True(t, hasEntitiesDS,
		"federation _entities Query data source must still be present on a federation+subscription API")
	assert.True(t, hasUserEntityRoot,
		"User entity RootNode must remain wired on the user data source")
}

// TestEntitiesDataSourcePlanner_NoSubscriptions pins the documented contract
// in entities_datasource.go: federation `_entities` resolution never carries
// subscription wiring, so `ConfigureSubscription` must return the zero
// SubscriptionConfiguration. Guards against an accidental flip if a future
// refactor moves subscription wiring around.
func TestEntitiesDataSourcePlanner_NoSubscriptions(t *testing.T) {
	planner := &entitiesDataSourcePlanner{}
	subCfg := planner.ConfigureSubscription()
	assert.Empty(t, subCfg.Input,
		"entitiesDataSourcePlanner.ConfigureSubscription must return zero SubscriptionConfiguration")
}
