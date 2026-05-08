package enginev3

import (
	"encoding/json"
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

	// When the customer's SDL declares Apollo Federation `@key` types
	// (proxy-mode federation passthrough or subgraph mode), the proxy data
	// source needs `UpstreamSchema` set to the full federation-aware SDL —
	// otherwise the planner's abstract-selection rewriter cannot resolve
	// `_Entity` and `_entities` queries fail at planning time. For plain
	// (non-federation) proxy schemas we leave the data source untouched to
	// preserve existing behaviour.
	if err == nil && p.Schema != nil && proxySchemaIsFederated(p.ApiDefinition.GraphQL.Schema, p.Schema) {
		augmentedSDL := string(p.Schema.Document())
		dataSources := v2Config.DataSources()
		for i, ds := range dataSources {
			var cfg graphqldatasource.Configuration
			if err := json.Unmarshal(ds.Custom, &cfg); err != nil {
				continue
			}
			if cfg.UpstreamSchema != "" {
				continue
			}
			cfg.UpstreamSchema = augmentedSDL
			dataSources[i].Custom = graphqldatasource.ConfigJson(cfg)
		}
		v2Config.SetDataSources(dataSources)
	}

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
		// V3 default flip: when no `subscription_type` is set, default to
		// `graphql-transport-ws` (modern Apollo subprotocol) instead of falling
		// through to the v2 library's legacy `graphql-ws` fallback. V3 is
		// Preview-labeled, so this is not a back-compat concern.
		return graphql.SubscriptionTypeGraphQLTransportWS
	}
}

// proxySchemaIsFederated reports whether the proxy mode is fronting an Apollo
// Federation subgraph. Two signals trigger this:
//  1. The customer's original SDL declares any `@key` directive (federation
//     passthrough — gateway middleware then augments the schema before reaching
//     here).
//  2. The parsed schema already exposes `_entities` on Query (subgraph mode,
//     where customers hand-write the federation schema themselves).
func proxySchemaIsFederated(customerSDL string, parsed *graphql.Schema) bool {
	if customerSDL != "" {
		entityTypes, err := keyedEntityTypes(customerSDL)
		if err == nil && len(entityTypes) > 0 {
			return true
		}
	}
	if parsed != nil {
		printed := string(parsed.Document())
		entityTypes, err := keyedEntityTypes(printed)
		if err == nil && len(entityTypes) > 0 {
			return true
		}
	}
	return false
}

func subscriptionClientFactoryOrDefault(providedSubscriptionClientFactory graphqldatasource.GraphQLSubscriptionClientFactory) graphqldatasource.GraphQLSubscriptionClientFactory {
	if providedSubscriptionClientFactory != nil {
		return providedSubscriptionClientFactory
	}
	return &graphqldatasource.DefaultSubscriptionClientFactory{}
}
