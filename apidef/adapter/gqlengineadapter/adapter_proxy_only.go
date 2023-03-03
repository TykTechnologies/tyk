package gqlengineadapter

import (
	"net/http"
	"strings"

	graphqlDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
)

type ProxyOnly struct {
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client

	schema                    *graphql.Schema
	subscriptionClientFactory graphqlDataSource.GraphQLSubscriptionClientFactory
}

func (p *ProxyOnly) EngineConfig() (*graphql.EngineV2Configuration, error) {
	var err error
	p.schema, err = parseSchema(p.ApiDefinition.GraphQL.Schema)
	if err != nil {
		return nil, err
	}

	staticHeaders := make(http.Header)

	url := p.ApiDefinition.Proxy.TargetURL
	if strings.HasPrefix(url, "tyk://") {
		url = strings.ReplaceAll(url, "tyk://", "http://")
		staticHeaders.Set(apidef.TykInternalApiHeader, "true")
	}

	upstreamConfig := graphql.ProxyUpstreamConfig{
		URL:              url,
		StaticHeaders:    staticHeaders,
		SubscriptionType: graphqlSubscriptionType(p.ApiDefinition.GraphQL.Proxy.SubscriptionType),
	}

	v2Config, err := graphql.NewProxyEngineConfigFactory(
		p.schema,
		upstreamConfig,
		graphqlDataSource.NewBatchFactory(),
		graphql.WithProxyHttpClient(p.HttpClient),
		graphql.WithProxyStreamingClient(p.StreamingClient),
		graphql.WithProxySubscriptionClientFactory(subscriptionClientFactoryOrDefault(p.subscriptionClientFactory)),
	).EngineV2Configuration()

	v2Config.EnableSingleFlight(true)
	return &v2Config, err
}
