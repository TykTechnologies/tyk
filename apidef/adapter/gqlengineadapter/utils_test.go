package gqlengineadapter

import (
	"context"
	"net/http"
	"testing"

	graphqlDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/stretchr/testify/assert"

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
			actualProtocol := graphqlDataSourceWebSocketProtocol(subscriptionType)
			assert.Equal(t, expectedWebSocketProtocol, actualProtocol)
		}
	}

	t.Run("should return 'graphql-ws' for undefined subscription type",
		run(apidef.GQLSubscriptionUndefined, graphqlDataSource.ProtocolGraphQLWS),
	)

	t.Run("should return 'graphql-ws' for graphql-ws subscription type",
		run(apidef.GQLSubscriptionWS, graphqlDataSource.ProtocolGraphQLWS),
	)

	t.Run("should return 'graphql-ws' for sse subscription type as websocket protocol is irrelevant in that case",
		run(apidef.GQLSubscriptionSSE, graphqlDataSource.ProtocolGraphQLWS),
	)

	t.Run("should return 'graphql-transport-ws' for graphql-transport-ws subscription type",
		run(apidef.GQLSubscriptionTransportWS, graphqlDataSource.ProtocolGraphQLTWS),
	)
}

func TestGraphqlSubscriptionType(t *testing.T) {
	run := func(subscriptionType apidef.SubscriptionType, expectedGraphQLSubscriptionType graphql.SubscriptionType) func(t *testing.T) {
		return func(t *testing.T) {
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
		assert.Nil(t, convertApiDefinitionHeadersToHttpHeaders(nil))
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

		actualHttpHeaders := convertApiDefinitionHeadersToHttpHeaders(apiDefinitionHeaders)
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

	actualDeduplicatedHeaders := removeDuplicateApiDefinitionHeaders(apiDefinitionHeadersFirstArgument, apiDefinitionHeadersSecondArgument)
	assert.Equal(t, expectedDeduplicatedHeaders, actualDeduplicatedHeaders)
}

var mockSubscriptionClient = &graphqlDataSource.SubscriptionClient{}

type MockSubscriptionClientFactory struct{}

func (m *MockSubscriptionClientFactory) NewSubscriptionClient(httpClient, streamingClient *http.Client, engineCtx context.Context, options ...graphqlDataSource.Options) graphqlDataSource.GraphQLSubscriptionClient {
	return mockSubscriptionClient
}
