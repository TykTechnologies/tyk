package adapter

import (
	"net/http"
	"strings"

	graphqlDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
)

type proxyOnlyGraphQLEngineAdapter struct {
	apiDefinition   *apidef.APIDefinition
	schema          *graphql.Schema
	httpClient      *http.Client
	streamingClient *http.Client

	subscriptionClientFactory graphqlDataSource.GraphQLSubscriptionClientFactory
}

func (p *proxyOnlyGraphQLEngineAdapter) EngineConfig() (*graphql.EngineV2Configuration, error) {
	staticHeaders := make(http.Header)

	url := p.apiDefinition.Proxy.TargetURL
	if strings.HasPrefix(url, "tyk://") {
		url = strings.ReplaceAll(url, "tyk://", "http://")
		staticHeaders.Set(apidef.TykInternalApiHeader, "true")
	}

	upstreamConfig := graphql.ProxyUpstreamConfig{
		URL:              url,
		StaticHeaders:    staticHeaders,
		SubscriptionType: graphqlSubscriptionType(p.apiDefinition.GraphQL.Proxy.SubscriptionType),
	}

	v2Config, err := graphql.NewProxyEngineConfigFactory(
		p.schema,
		upstreamConfig,
		graphqlDataSource.NewBatchFactory(),
		graphql.WithProxyHttpClient(p.httpClient),
		graphql.WithProxyStreamingClient(p.streamingClient),
		graphql.WithProxySubscriptionClientFactory(p.subscriptionClientFactory),
	).EngineV2Configuration()

	v2Config.EnableSingleFlight(true)
	return &v2Config, err
}
