package gqlengineadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	restdatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/rest_datasource"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestParseSchema(t *testing.T) {
	inputSchema := `
		type Query {
			hello: String!
		}`

	// We are pretty confident that the schema parsing works, as it is tested in the library already.
	// We just want to make sure that there is no weird error happening.
	parsedSchema, err := parseSchema(inputSchema)
	assert.NotNil(t, parsedSchema)
	assert.NoError(t, err)
}

func TestGraphqlDataSourceWebSocketProtocol(t *testing.T) {
	run := func(subscriptionType apidef.SubscriptionType, expectedWebSocketProtocol string) func(t *testing.T) {
		return func(t *testing.T) {
			t.Helper()
			actualProtocol := graphqlDataSourceWebSocketProtocol(subscriptionType)
			assert.Equal(t, expectedWebSocketProtocol, actualProtocol)
		}
	}

	t.Run("should return 'graphql-ws' for undefined subscription type",
		run(apidef.GQLSubscriptionUndefined, graphqldatasource.ProtocolGraphQLWS),
	)

	t.Run("should return 'graphql-ws' for graphql-ws subscription type",
		run(apidef.GQLSubscriptionWS, graphqldatasource.ProtocolGraphQLWS),
	)

	t.Run("should return 'graphql-ws' for sse subscription type as websocket protocol is irrelevant in that case",
		run(apidef.GQLSubscriptionSSE, graphqldatasource.ProtocolGraphQLWS),
	)

	t.Run("should return 'graphql-transport-ws' for graphql-transport-ws subscription type",
		run(apidef.GQLSubscriptionTransportWS, graphqldatasource.ProtocolGraphQLTWS),
	)
}

func TestGraphqlSubscriptionType(t *testing.T) {
	run := func(subscriptionType apidef.SubscriptionType, expectedGraphQLSubscriptionType graphql.SubscriptionType) func(t *testing.T) {
		return func(t *testing.T) {
			t.Helper()
			actualSubscriptionType := graphqlSubscriptionType(subscriptionType)
			assert.Equal(t, expectedGraphQLSubscriptionType, actualSubscriptionType)
		}
	}

	t.Run("should return 'Unknown' for undefined subscription type",
		run(apidef.GQLSubscriptionUndefined, graphql.SubscriptionTypeUnknown),
	)

	t.Run("should return 'SSE' for sse subscription type as websocket protocol is irrelevant in that case",
		run(apidef.GQLSubscriptionSSE, graphql.SubscriptionTypeSSE),
	)

	t.Run("should return 'GraphQLWS' for graphql-ws subscription type",
		run(apidef.GQLSubscriptionWS, graphql.SubscriptionTypeGraphQLWS),
	)

	t.Run("should return 'GraphQLTransportWS' for graphql-transport-ws subscription type",
		run(apidef.GQLSubscriptionTransportWS, graphql.SubscriptionTypeGraphQLTransportWS),
	)
}

func TestConvertApiDefinitionHeadersToHttpHeaders(t *testing.T) {
	t.Run("should return nil for empty input", func(t *testing.T) {
		assert.Nil(t, ConvertApiDefinitionHeadersToHttpHeaders(nil))
	})

	t.Run("should successfully convert API Definition header to Http Headers", func(t *testing.T) {
		apiDefinitionHeaders := map[string]string{
			"Authorization": "token",
			"X-Tyk-Key":     "value",
		}

		expectedHttpHeaders := http.Header{
			"Authorization": {"token"},
			"X-Tyk-Key":     {"value"},
		}

		actualHttpHeaders := ConvertApiDefinitionHeadersToHttpHeaders(apiDefinitionHeaders)
		assert.Equal(t, expectedHttpHeaders, actualHttpHeaders)
	})
}

func TestRemoveDuplicateApiDefinitionHeaders(t *testing.T) {
	apiDefinitionHeadersFirstArgument := map[string]string{
		"duplicate-header": "value",
	}
	apiDefinitionHeadersSecondArgument := map[string]string{
		"Duplicate-Header":     "value",
		"Non-Duplicate-Header": "another_value",
	}

	expectedDeduplicatedHeaders := map[string]string{
		"Duplicate-Header":     "value",
		"Non-Duplicate-Header": "another_value",
	}

	actualDeduplicatedHeaders := RemoveDuplicateApiDefinitionHeaders(apiDefinitionHeadersFirstArgument, apiDefinitionHeadersSecondArgument)
	assert.Equal(t, expectedDeduplicatedHeaders, actualDeduplicatedHeaders)
}

func TestGenerateRestDataSourceFromGraphql(t *testing.T) {
	t.Run("should return error if generation is not possible", func(t *testing.T) {
		gqlConfig := apidef.GraphQLEngineDataSourceConfigGraphQL{
			URL:              "http://local.fake",
			Method:           http.MethodPost,
			Headers:          nil,
			SubscriptionType: "",
			HasOperation:     false,
			Operation:        "{ invalidOperation }",
			Variables:        nil,
		}

		restEngineConfig, err := generateRestDataSourceFromGraphql(gqlConfig)
		assert.Equal(t, err, ErrGraphQLConfigIsMissingOperation)
		assert.Nil(t, restEngineConfig)
	})

	t.Run("should convert GraphQL Data Source config to REST engine config", func(t *testing.T) {
		gqlConfig := apidef.GraphQLEngineDataSourceConfigGraphQL{
			URL:    "http://local.fake",
			Method: http.MethodPost,
			Headers: map[string]string{
				"x-header": "header-value",
			},
			SubscriptionType: "",
			HasOperation:     true,
			Operation:        "mutation MyOp { myOperation }",
			Variables:        json.RawMessage(`{"var":"val"}`),
		}

		expectedRestEngineConfig := restdatasource.ConfigJSON(restdatasource.Configuration{
			Fetch: restdatasource.FetchConfiguration{
				URL:    "http://local.fake",
				Method: http.MethodPost,
				Body:   `{"variables":{"var":"val"},"query":"mutation MyOp { myOperation }"}`,
				Header: http.Header{
					"X-Header": []string{"header-value"},
				},
			},
		})

		actualRestEngineConfig, err := generateRestDataSourceFromGraphql(gqlConfig)
		assert.NoError(t, err)
		assert.Equal(t, expectedRestEngineConfig, actualRestEngineConfig)
	})
}

var mockSubscriptionClient = &graphqldatasource.SubscriptionClient{}

type MockSubscriptionClientFactory struct{}

func (m *MockSubscriptionClientFactory) NewSubscriptionClient(httpClient, streamingClient *http.Client, engineCtx context.Context, options ...graphqldatasource.Options) graphqldatasource.GraphQLSubscriptionClient {
	return mockSubscriptionClient
}
