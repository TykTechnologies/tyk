package enginev3

import (
	"net/http"
	"strings"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
)

type ProxyOnly struct {
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	Schema          *graphql.Schema

	subscriptionClientFactory graphqldatasource.GraphQLSubscriptionClientFactory
}

func (p *ProxyOnly) EngineConfigV3() (*graphql.EngineV2Configuration, error) {
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

	v2Config, err := graphql.NewProxyEngineConfigFactory(
		p.Schema,
		upstreamConfig,
		graphql.WithProxyHttpClient(p.HttpClient),
		graphql.WithProxyStreamingClient(p.StreamingClient),
		graphql.WithProxySubscriptionClientFactory(subscriptionClientFactoryOrDefault(p.subscriptionClientFactory)),
	).EngineV2Configuration()

	v2Config.EnableSingleFlight(false)
	return &v2Config, err
}

func parseSchema(schemaAsString string) (parsedSchema *graphql.Schema, err error) {
	parsedSchema, err = graphql.NewSchemaFromString(schemaAsString)
	if err != nil {
		return nil, err
	}

	normalizationResult, err := parsedSchema.Normalize()
	if err != nil {
		return nil, err
	}

	if !normalizationResult.Successful && normalizationResult.Errors != nil {
		return nil, normalizationResult.Errors
	}

	return parsedSchema, nil
}

func graphqlSubscriptionType(subscriptionType apidef.SubscriptionType) graphql.SubscriptionType {
	switch subscriptionType {
	case apidef.GQLSubscriptionWS:
		return graphql.SubscriptionTypeGraphQLWS
	case apidef.GQLSubscriptionTransportWS:
		return graphql.SubscriptionTypeGraphQLTransportWS
	case apidef.GQLSubscriptionSSE:
		return graphql.SubscriptionTypeSSE
	default:
		return graphql.SubscriptionTypeUnknown
	}
}

func subscriptionClientFactoryOrDefault(providedSubscriptionClientFactory graphqldatasource.GraphQLSubscriptionClientFactory) graphqldatasource.GraphQLSubscriptionClientFactory {
	if providedSubscriptionClientFactory != nil {
		return providedSubscriptionClientFactory
	}
	return &graphqldatasource.DefaultSubscriptionClientFactory{}
}
