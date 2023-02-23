package adapter

import (
	"net/http"
	"testing"

	graphqlDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/stretchr/testify/assert"

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
