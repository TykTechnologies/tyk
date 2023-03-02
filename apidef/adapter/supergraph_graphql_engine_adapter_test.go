package adapter

import (
	"encoding/json"
	"net/http"
	"strconv"
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

func TestSupergraphGraphQLEngineAdapter_supergraphDataSourceConfigs(t *testing.T) {
	expectedDataSourceConfigs := []graphqlDataSource.Configuration{
		{
			Fetch: graphqlDataSource.FetchConfiguration{
				URL:    "http://accounts.service",
				Method: http.MethodPost,
				Header: http.Header{
					"Header1":        []string{"override_global"},
					"Header2":        []string{"value2"},
					"X-Tyk-Internal": []string{"true"},
					"Auth":           []string{"appended_header"},
				},
			},
			Subscription: graphqlDataSource.SubscriptionConfiguration{
				URL:    "http://accounts.service",
				UseSSE: true,
			},
			Federation: graphqlDataSource.FederationConfiguration{
				Enabled:    true,
				ServiceSDL: federationAccountsServiceSDL,
			},
		},
		{
			Fetch: graphqlDataSource.FetchConfiguration{
				URL:    "http://products.service",
				Method: http.MethodPost,
				Header: http.Header{
					"Header1": []string{"value1"},
					"Header2": []string{"value2"},
				},
			},
			Subscription: graphqlDataSource.SubscriptionConfiguration{
				URL: "http://products.service",
			},
			Federation: graphqlDataSource.FederationConfiguration{
				Enabled:    true,
				ServiceSDL: federationProductsServiceSDL,
			},
		},
		{
			Fetch: graphqlDataSource.FetchConfiguration{
				URL:    "http://reviews.service",
				Method: http.MethodPost,
				Header: http.Header{
					"Header1": []string{"override_global"},
					"Auth":    []string{"appended_header"},
					"Header2": []string{"value2"},
				},
			},
			Subscription: graphqlDataSource.SubscriptionConfiguration{
				URL: "http://reviews.service",
			},
			Federation: graphqlDataSource.FederationConfiguration{
				Enabled:    true,
				ServiceSDL: federationReviewsServiceSDL,
			},
		},
	}

	var gqlConfig apidef.GraphQLConfig
	require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2SupergraphConfigJson), &gqlConfig))

	apiDef := &apidef.APIDefinition{
		GraphQL: gqlConfig,
	}

	adapter := NewGraphQLConfigAdapter(apiDef)
	actualGraphQLConfigs := adapter.subgraphDataSourceConfigs()
	assert.Equal(t, expectedDataSourceConfigs, actualGraphQLConfigs)
}

const federationAccountsServiceSDL = `extend type Query {me: User} type User @key(fields: "id"){ id: ID! username: String!}`
const federationProductsServiceSDL = `extend type Query {topProducts(first: Int = 5): [Product]} type Product @key(fields: "upc") {upc: String! name: String! price: Int!}`
const federationReviewsServiceSDL = `type Review { body: String! author: User! @provides(fields: "username") product: Product! } extend type User @key(fields: "id") { id: ID! @external reviews: [Review] } extend type Product @key(fields: "upc") { upc: String! @external reviews: [Review] }`
const federationMergedSDL = `type Query { me: User topProducts(first: Int = 5): [Product] } type User { id: ID! username: String! reviews: [Review] } type Product { upc: String! name: String! price: Int! reviews: [Review] } type Review { body: String! author: User! product: Product! }`

var graphqlEngineV2SupergraphConfigJson = `{
	"enabled": true,
	"execution_mode": "supergraph",
	"version": "2",
	"schema": "",
	"last_schema_update": "2020-11-11T11:11:11.000+01:00",
	"engine": {
		"field_configs": [],
		"data_sources": []
	},
	"supergraph": {
		"subgraphs": [
			{
				"api_id": "",
				"url": "tyk://accounts.service",
				"sdl": ` + strconv.Quote(federationAccountsServiceSDL) + `,
				"headers": {
					"header1": "override_global",
					"Auth": "appended_header"
				},
				"subscription_type": "sse"
			},
			{
				"api_id": "",
				"url": "http://products.service",
				"sdl": ` + strconv.Quote(federationProductsServiceSDL) + `
			},
			{
				"api_id": "",
				"url": "http://ignored.service",
				"sdl": ""
			},
			{
				"api_id": "",
				"url": "http://reviews.service",
				"sdl": ` + strconv.Quote(federationReviewsServiceSDL) + `,
				"headers": {
					"header1": "override_global",
					"header2": "value2",
					"Auth": "appended_header"
				}
			}
		],
		"global_headers": {
			"header1": "value1",
			"header2": "value2"
		},
		"merged_sdl": "` + federationMergedSDL + `"
	},
	"playground": {}
}`
