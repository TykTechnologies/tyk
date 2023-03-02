package adapter

import (
	"encoding/json"
	"net/http"
	"testing"

	graphqlDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestSupergraphGraphQLEngineAdapter_EngineConfig(t *testing.T) {
	t.Run("should create v2 config for supergraph execution mode without error", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2SupergraphConfigJson), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
		}

		httpClient := &http.Client{}
		adapter := supergraphGraphQLEngineAdapter{
			apiDefinition:             apiDef,
			httpClient:                httpClient,
			streamingClient:           nil,
			subscriptionClientFactory: &MockSubscriptionClientFactory{},
		}

		_, err := adapter.EngineConfig()
		assert.NoError(t, err)
	})
	t.Run("should create v2 config for supergraph with batching disabled", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2SupergraphConfigJson), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
		}
		apiDef.GraphQL.Supergraph.DisableQueryBatching = true

		httpClient := &http.Client{}
		streamingClient := &http.Client{}
		adapter := supergraphGraphQLEngineAdapter{
			apiDefinition:             apiDef,
			httpClient:                httpClient,
			streamingClient:           streamingClient,
			subscriptionClientFactory: &MockSubscriptionClientFactory{},
		}

		v2Config, err := adapter.EngineConfig()
		assert.NoError(t, err)
		expectedDataSource := plan.DataSourceConfiguration{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"me"},
				},
				{
					TypeName:   "User",
					FieldNames: []string{"id", "username"},
				},
			},
			ChildNodes: []plan.TypeField{
				{
					TypeName:   "User",
					FieldNames: []string{"id", "username"},
				},
			},
			Factory: &graphqlDataSource.Factory{
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL:    "http://accounts.service",
					Method: http.MethodPost,
					Header: http.Header{
						"Auth":           []string{"appended_header"},
						"Header1":        []string{"override_global"},
						"Header2":        []string{"value2"},
						"X-Tyk-Internal": []string{"true"},
					},
				},
				Subscription: graphqlDataSource.SubscriptionConfiguration{
					URL:    "http://accounts.service",
					UseSSE: true,
				},
				Federation: graphqlDataSource.FederationConfiguration{
					Enabled:    true,
					ServiceSDL: `extend type Query {me: User} type User @key(fields: "id"){ id: ID! username: String!}`,
				},
			}),
		}
		assert.Containsf(t, v2Config.DataSources(), expectedDataSource, "engine configuration does not contain proxy-only data source")

	})
}
