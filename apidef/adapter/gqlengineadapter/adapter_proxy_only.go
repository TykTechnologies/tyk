package gqlengineadapter

import (
	"net/http"
	"strings"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
)

type ProxyOnly struct {
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	Schema          *graphql.Schema

	subscriptionClientFactory graphqldatasource.GraphQLSubscriptionClientFactory
}

func (p *ProxyOnly) EngineConfig() (*graphql.EngineV2Configuration, error) {
	var err error
	if p.Schema == nil {
		p.Schema, err = parseSchema(p.ApiDefinition.GraphQL.Schema)
		if err != nil {
			return nil, err
		}
	}

	staticHeaders := make(http.Header)
	for key, value := range p.ApiDefinition.GraphQL.Proxy.RequestHeaders {
		staticHeaders.Set(key, value)
	}

	url := p.ApiDefinition.Proxy.TargetURL
	if strings.HasPrefix(url, "tyk://") {
		url = strings.ReplaceAll(url, "tyk://", "http://")
		staticHeaders.Set(apidef.TykInternalApiHeader, "true")
	}

	upstreamConfig := graphql.ProxyUpstreamConfig{
		URL:              url,
		StaticHeaders:    staticHeaders,
		SubscriptionType: graphqlSubscriptionType(p.ApiDefinition.GraphQL.Proxy.SubscriptionType),
		SSEMethodPost:    p.ApiDefinition.GraphQL.Proxy.SSEUsePost,
	}

	v2Config, err := graphql.NewProxyEngineConfigFactory(
		p.Schema,
		upstreamConfig,
		graphqldatasource.NewBatchFactory(),
		graphql.WithProxyHttpClient(p.HttpClient),
		graphql.WithProxyStreamingClient(p.StreamingClient),
		graphql.WithProxySubscriptionClientFactory(subscriptionClientFactoryOrDefault(p.subscriptionClientFactory)),
	).EngineV2Configuration()

	if err != nil {
		return nil, err
	}

	v2Config.EnableSingleFlight(false)
	return &v2Config, nil
}
