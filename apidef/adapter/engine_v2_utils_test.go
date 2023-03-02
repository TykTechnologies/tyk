package adapter

import (
	"net/http"
	neturl "net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	graphqlDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	restDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestGraphqlDataSourceConfiguration(t *testing.T) {
	type testInput struct {
		url              string
		method           string
		headers          map[string]string
		subscriptionType apidef.SubscriptionType
	}

	t.Run("with internal data source url and sse", func(t *testing.T) {
		internalDataSource := testInput{
			url:    "tyk://data-source.fake",
			method: http.MethodGet,
			headers: map[string]string{
				"Authorization": "token",
				"X-Tyk-Key":     "value",
			},
			subscriptionType: apidef.GQLSubscriptionSSE,
		}

		expectedGraphqlDataSourceConfiguration := graphqlDataSource.Configuration{
			Fetch: graphqlDataSource.FetchConfiguration{
				URL:    "http://data-source.fake",
				Method: http.MethodGet,
				Header: http.Header{
					"Authorization": {"token"},
					http.CanonicalHeaderKey(apidef.TykInternalApiHeader): {"true"},
					"X-Tyk-Key": {"value"},
				},
			},
			Subscription: graphqlDataSource.SubscriptionConfiguration{
				URL:           "http://data-source.fake",
				UseSSE:        true,
				SSEMethodPost: false,
			},
		}

		actualGraphqlDataSourceConfiguration := graphqlDataSourceConfiguration(
			internalDataSource.url,
			internalDataSource.method,
			internalDataSource.headers,
			internalDataSource.subscriptionType,
		)

		assert.Equal(t, expectedGraphqlDataSourceConfiguration, actualGraphqlDataSourceConfiguration)
	})

	t.Run("with external data source url and no sse", func(t *testing.T) {
		externalDataSource := testInput{
			url:    "http://data-source.fake",
			method: http.MethodGet,
			headers: map[string]string{
				"Authorization": "token",
				"X-Tyk-Key":     "value",
			},
			subscriptionType: apidef.GQLSubscriptionTransportWS,
		}

		expectedGraphqlDataSourceConfiguration := graphqlDataSource.Configuration{
			Fetch: graphqlDataSource.FetchConfiguration{
				URL:    "http://data-source.fake",
				Method: http.MethodGet,
				Header: http.Header{
					"Authorization": {"token"},
					"X-Tyk-Key":     {"value"},
				},
			},
			Subscription: graphqlDataSource.SubscriptionConfiguration{
				URL:           "http://data-source.fake",
				UseSSE:        false,
				SSEMethodPost: false,
			},
		}

		actualGraphqlDataSourceConfiguration := graphqlDataSourceConfiguration(
			externalDataSource.url,
			externalDataSource.method,
			externalDataSource.headers,
			externalDataSource.subscriptionType,
		)

		assert.Equal(t, expectedGraphqlDataSourceConfiguration, actualGraphqlDataSourceConfiguration)
	})

}

func TestCreateArgumentConfigurationsForArgumentNames(t *testing.T) {
	expectedArgumentConfigurations := plan.ArgumentsConfigurations{
		{
			Name:       "argument1",
			SourceType: plan.FieldArgumentSource,
		},
		{
			Name:       "argument2",
			SourceType: plan.FieldArgumentSource,
		},
	}

	actualArgumentConfigurations := createArgumentConfigurationsForArgumentNames("argument1", "argument2")
	assert.Equal(t, expectedArgumentConfigurations, actualArgumentConfigurations)
}

func TestExtractURLQueryParamsForEngineV2(t *testing.T) {
	type expectedOutput struct {
		urlWithoutParams string
		engineV2Queries  []restDataSource.QueryConfiguration
		err              error
	}

	providedApiDefQueries := []apidef.QueryVariable{
		{
			Name:  "providedQueryName1",
			Value: "providedQueryValue1",
		},
		{
			Name:  "providedQueryName2",
			Value: "providedQueryValue2",
		},
	}

	t.Run("without query params in url", func(t *testing.T) {
		inputUrl := "http://rest-data-source.fake"
		expected := expectedOutput{
			urlWithoutParams: "http://rest-data-source.fake",
			engineV2Queries: []restDataSource.QueryConfiguration{
				{
					Name:  "providedQueryName1",
					Value: "providedQueryValue1",
				},
				{
					Name:  "providedQueryName2",
					Value: "providedQueryValue2",
				},
			},
			err: nil,
		}
		actualUrlWithoutParams, actualEngineV2Queries, actualErr := extractURLQueryParamsForEngineV2(inputUrl, providedApiDefQueries)
		assert.Equal(t, expected.urlWithoutParams, actualUrlWithoutParams)
		assert.Equal(t, expected.engineV2Queries, actualEngineV2Queries)
		assert.Equal(t, expected.err, actualErr)
	})

	t.Run("with query params in url", func(t *testing.T) {
		inputUrl := "http://rest-data-source.fake?urlParam=urlParamValue"
		expected := expectedOutput{
			urlWithoutParams: "http://rest-data-source.fake",
			engineV2Queries: []restDataSource.QueryConfiguration{
				{
					Name:  "urlParam",
					Value: "urlParamValue",
				},
				{
					Name:  "providedQueryName1",
					Value: "providedQueryValue1",
				},
				{
					Name:  "providedQueryName2",
					Value: "providedQueryValue2",
				},
			},
			err: nil,
		}
		actualUrlWithoutParams, actualEngineV2Queries, actualErr := extractURLQueryParamsForEngineV2(inputUrl, providedApiDefQueries)
		assert.Equal(t, expected.urlWithoutParams, actualUrlWithoutParams)
		assert.Equal(t, expected.engineV2Queries, actualEngineV2Queries)
		assert.Equal(t, expected.err, actualErr)
	})
}

func TestAppendURLQueryParamsToEngineV2Queries(t *testing.T) {
	existingEngineV2Queries := &[]restDataSource.QueryConfiguration{
		{
			Name:  "existingName",
			Value: "existingValue",
		},
	}

	queryValues := neturl.Values{
		"newKey1": {"newKey1Value1"},
		"newKey2": {"newKey2Value1", "newKey2Value2"},
	}

	expectedEngineV2Queries := &[]restDataSource.QueryConfiguration{
		{
			Name:  "existingName",
			Value: "existingValue",
		},
		{
			Name:  "newKey1",
			Value: "newKey1Value1",
		},
		{
			Name:  "newKey2",
			Value: "newKey2Value1,newKey2Value2",
		},
	}

	appendURLQueryParamsToEngineV2Queries(existingEngineV2Queries, queryValues)
	assert.Equal(t, expectedEngineV2Queries, existingEngineV2Queries)
}

func TestAppendApiDefQueriesConfigToEngineV2Queries(t *testing.T) {
	existingEngineV2Queries := &[]restDataSource.QueryConfiguration{
		{
			Name:  "existingName",
			Value: "existingValue",
		},
	}

	apiDefQueryVariables := []apidef.QueryVariable{
		{
			Name:  "newName1",
			Value: "newValue2",
		},
		{
			Name:  "newName2",
			Value: "newValue2",
		},
	}

	expectedEngineV2Queries := &[]restDataSource.QueryConfiguration{
		{
			Name:  "existingName",
			Value: "existingValue",
		},
		{
			Name:  "newName1",
			Value: "newValue2",
		},
		{
			Name:  "newName2",
			Value: "newValue2",
		},
	}

	appendApiDefQueriesConfigToEngineV2Queries(existingEngineV2Queries, apiDefQueryVariables)
	assert.Equal(t, expectedEngineV2Queries, existingEngineV2Queries)
}

func TestCreateGraphQLDataSourceFactory(t *testing.T) {
	inputParams := createGraphQLDataSourceFactoryParams{
		graphqlConfig: apidef.GraphQLEngineDataSourceConfigGraphQL{
			SubscriptionType: apidef.GQLSubscriptionSSE,
		},
		subscriptionClientFactory: &MockSubscriptionClientFactory{},
		httpClient: &http.Client{
			Timeout: 0,
		},
		streamingClient: &http.Client{
			Timeout: 1,
		},
	}

	expectedGraphQLDataSourceFactory := &graphqlDataSource.Factory{
		HTTPClient: &http.Client{
			Timeout: 0,
		},
		StreamingClient: &http.Client{
			Timeout: 1,
		},
		SubscriptionClient: mockSubscriptionClient,
	}

	actualGraphQLDataSourceFactory, err := createGraphQLDataSourceFactory(inputParams)
	assert.Nil(t, err)
	assert.Equal(t, expectedGraphQLDataSourceFactory, actualGraphQLDataSourceFactory)
}
