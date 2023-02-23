package adapter

import (
	"strings"

	graphqlDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"

	"github.com/TykTechnologies/tyk/apidef"
)

func graphqlDataSourceConfiguration(url string, method string, headers map[string]string, subscriptionType apidef.SubscriptionType) graphqlDataSource.Configuration {
	dataSourceHeaders := make(map[string]string)
	for name, value := range headers {
		dataSourceHeaders[name] = value
	}

	if strings.HasPrefix(url, "tyk://") {
		url = strings.ReplaceAll(url, "tyk://", "http://")
		dataSourceHeaders[apidef.TykInternalApiHeader] = "true"
	}

	cfg := graphqlDataSource.Configuration{
		Fetch: graphqlDataSource.FetchConfiguration{
			URL:    url,
			Method: method,
			Header: convertApiDefinitionHeadersToHttpHeaders(dataSourceHeaders),
		},
		Subscription: graphqlDataSource.SubscriptionConfiguration{
			URL:    url,
			UseSSE: subscriptionType == apidef.GQLSubscriptionSSE,
		},
	}

	return cfg
}
