package gqlengineadapter

import (
	"encoding/json"
	"net/http"
	"testing"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-073
// SW-REQ-073:nominal:nominal
// SW-REQ-073:boundary:nominal
// SW-REQ-073:error_handling:nominal
// SW-REQ-073:error_handling:negative
// SW-REQ-073:determinism:nominal
func TestProxyOnlyEngineConfigPreservesLocalProxyConfiguration(t *testing.T) {
	apiDef := &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Schema: "type Query { hello(name: String!): String! }",
			Proxy: apidef.GraphQLProxyConfig{
				RequestHeaders:   map[string]string{"x-api-key": "secret"},
				SubscriptionType: apidef.GQLSubscriptionSSE,
				SSEUsePost:       true,
			},
		},
		Proxy: apidef.ProxyConfig{TargetURL: "tyk://internal-api/graphql"},
	}
	httpClient := &http.Client{}
	streamingClient := &http.Client{}

	adapter := &ProxyOnly{
		ApiDefinition:             apiDef,
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		subscriptionClientFactory: reqproofSubscriptionClientFactory{},
	}
	engineConfig, err := adapter.EngineConfig()
	require.NoError(t, err)
	require.NotNil(t, adapter.Schema)
	require.Len(t, engineConfig.DataSources(), 1)

	dataSource := engineConfig.DataSources()[0]
	require.Equal(t, []plan.TypeField{{TypeName: "Query", FieldNames: []string{"hello"}}}, dataSource.RootNodes)
	require.IsType(t, &graphqldatasource.Factory{}, dataSource.Factory)

	factory := dataSource.Factory.(*graphqldatasource.Factory)
	require.Same(t, httpClient, factory.HTTPClient)
	require.Same(t, streamingClient, factory.StreamingClient)
	require.NotNil(t, factory.SubscriptionClient)

	var custom graphqldatasource.Configuration
	require.NoError(t, json.Unmarshal(dataSource.Custom, &custom))
	require.Equal(t, "http://internal-api/graphql", custom.Fetch.URL)
	require.Equal(t, http.Header{
		"X-Api-Key":      {"secret"},
		"X-Tyk-Internal": {"true"},
	}, custom.Fetch.Header)
	require.Equal(t, "http://internal-api/graphql", custom.Subscription.URL)
	require.True(t, custom.Subscription.UseSSE)
	require.True(t, custom.Subscription.SSEMethodPost)
	require.Contains(t, engineConfig.FieldConfigurations(), plan.FieldConfiguration{
		TypeName:  "Query",
		FieldName: "hello",
		Arguments: plan.ArgumentsConfigurations{
			{Name: "name", SourceType: plan.FieldArgumentSource},
		},
	})

	repeatedAdapter := &ProxyOnly{
		ApiDefinition:             apiDef,
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		subscriptionClientFactory: reqproofSubscriptionClientFactory{},
	}
	repeatedConfig, err := repeatedAdapter.EngineConfig()
	require.NoError(t, err)
	require.Equal(t, engineConfig.DataSources(), repeatedConfig.DataSources())
	require.Equal(t, engineConfig.FieldConfigurations(), repeatedConfig.FieldConfigurations())

	providedSchema, err := parseSchema("type Query { provided: String! }")
	require.NoError(t, err)
	providedSchemaAdapter := &ProxyOnly{
		ApiDefinition: &apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{
				Schema: "type Query { broken: }",
				Proxy:  apidef.GraphQLProxyConfig{},
			},
			Proxy: apidef.ProxyConfig{TargetURL: "http://upstream.example.test/graphql"},
		},
		Schema:                    providedSchema,
		subscriptionClientFactory: reqproofSubscriptionClientFactory{},
	}
	_, err = providedSchemaAdapter.EngineConfig()
	require.NoError(t, err)
	require.Same(t, providedSchema, providedSchemaAdapter.Schema)

	badSchemaAdapter := &ProxyOnly{
		ApiDefinition: &apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{Schema: "type Query { broken: }"},
			Proxy:   apidef.ProxyConfig{TargetURL: "http://upstream.example.test/graphql"},
		},
		subscriptionClientFactory: reqproofSubscriptionClientFactory{},
	}
	badConfig, err := badSchemaAdapter.EngineConfig()
	require.Error(t, err)
	require.Nil(t, badConfig)
}
