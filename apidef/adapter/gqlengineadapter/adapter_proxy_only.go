package gqlengineadapter

import (
	"github.com/TykTechnologies/graphql-go-tools/pkg/customdirective"
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
	Schema          *graphql.Schema

	subscriptionClientFactory graphqlDataSource.GraphQLSubscriptionClientFactory
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
	}

	customDirectives := make(map[string]customdirective.CustomDirective)

	toUpperDirective := NewToUpperDirective()
	customDirectives[toUpperDirective.Name()] = toUpperDirective

	v2Config, err := graphql.NewProxyEngineConfigFactory(
		p.Schema,
		upstreamConfig,
		graphqlDataSource.NewBatchFactory(),
		graphql.WithProxyHttpClient(p.HttpClient),
		graphql.WithProxyStreamingClient(p.StreamingClient),
		graphql.WithProxySubscriptionClientFactory(subscriptionClientFactoryOrDefault(p.subscriptionClientFactory)),
		graphql.WithProxyCustomDirectives(customDirectives),
	).EngineV2Configuration()

	v2Config.EnableSingleFlight(false)
	return &v2Config, err
}
