package enginev3

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/astparser"
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
	// `_Entity` and `_entities` queries fail at planning time. The hook lives
	// in CE because subgraph mode (`GraphQLExecutionModeSubgraph`) is a
	// longstanding CE feature — its hand-written federation SDL needs the
	// same upstream-schema wiring. For plain (non-federation) proxy schemas
	// we leave the data source untouched.
	if err == nil && p.Schema != nil && proxySchemaIsFederated(p.ApiDefinition.GraphQL.Schema, p.Schema) {
		augmentedSDL := string(p.Schema.Document())
		dataSources := v2Config.DataSources()
		modified := false
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
			modified = true
		}
		if modified {
			v2Config.SetDataSources(dataSources)
		}
	}

	v2Config.EnableSingleFlight(false)
	return &v2Config, err
}

// proxySchemaIsFederated reports whether the proxy mode is fronting an Apollo
// Federation subgraph. Two signals trigger this:
//  1. The customer's original SDL declares any `@key` directive (federation
//     passthrough — gateway middleware then augments the schema before reaching
//     here).
//  2. The parsed schema already exposes `@key` types after normalization
//     (subgraph mode, where customers hand-write the federation schema
//     themselves).
//
// This helper lives in CE because subgraph mode is a CE feature; the EE-only
// federation v2 work (UDG entity resolvers, schema augmentation, `_service`
// SDL synthesis) lives under `ee/middleware/graphql_federation/`.
func proxySchemaIsFederated(customerSDL string, parsed *graphql.Schema) bool {
	if customerSDL != "" && schemaContainsKeyDirective(customerSDL) {
		return true
	}
	if parsed != nil {
		printed := string(parsed.Document())
		if schemaContainsKeyDirective(printed) {
			return true
		}
	}
	return false
}

// schemaContainsKeyDirective parses the SDL and reports whether any object
// type definition or extension carries the `@key` directive. Mirrors the same
// helper in `ee/middleware/graphql_federation` (kept duplicated to avoid CE
// importing from `ee/`).
func schemaContainsKeyDirective(sdl string) bool {
	doc, report := astparser.ParseGraphqlDocumentString(sdl)
	if report.HasErrors() {
		return false
	}
	for i := range doc.ObjectTypeDefinitions {
		def := doc.ObjectTypeDefinitions[i]
		if !def.HasDirectives {
			continue
		}
		for _, dRef := range def.Directives.Refs {
			if doc.DirectiveNameString(dRef) == "key" {
				return true
			}
		}
	}
	for i := range doc.ObjectTypeExtensions {
		ext := doc.ObjectTypeExtensions[i]
		if !ext.HasDirectives {
			continue
		}
		for _, dRef := range ext.Directives.Refs {
			if doc.DirectiveNameString(dRef) == "key" {
				return true
			}
		}
	}
	return false
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

func subscriptionClientFactoryOrDefault(providedSubscriptionClientFactory graphqldatasource.GraphQLSubscriptionClientFactory) graphqldatasource.GraphQLSubscriptionClientFactory {
	if providedSubscriptionClientFactory != nil {
		return providedSubscriptionClientFactory
	}
	return &graphqldatasource.DefaultSubscriptionClientFactory{}
}
