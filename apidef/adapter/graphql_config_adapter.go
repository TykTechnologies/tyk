package adapter

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/httpclient"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/adapter/gqlengineadapter"
)

var ErrUnsupportedGraphQLConfigVersion = errors.New("provided version of GraphQL config is not supported for this operation")
var ErrUnsupportedGraphQLExecutionMode = errors.New("provided execution mode of GraphQL config is not supported for this operation")

type GraphQLEngineAdapter interface {
	EngineConfig() (*graphql.EngineV2Configuration, error)
}

type GraphQLConfigAdapterOption func(adapter *GraphQLConfigAdapter)

func WithSchema(schema *graphql.Schema) GraphQLConfigAdapterOption {
	return func(adapter *GraphQLConfigAdapter) {
		adapter.schema = schema
	}
}

func WithHttpClient(httpClient *http.Client) GraphQLConfigAdapterOption {
	return func(adapter *GraphQLConfigAdapter) {
		adapter.httpClient = httpClient
	}
}

func WithStreamingClient(streamingClient *http.Client) GraphQLConfigAdapterOption {
	return func(adapter *GraphQLConfigAdapter) {
		adapter.streamingClient = streamingClient
	}
}

type GraphQLConfigAdapter struct {
	apiDefinition   *apidef.APIDefinition
	httpClient      *http.Client
	streamingClient *http.Client
	schema          *graphql.Schema
}

func NewGraphQLConfigAdapter(apiDefinition *apidef.APIDefinition, options ...GraphQLConfigAdapterOption) GraphQLConfigAdapter {
	adapter := GraphQLConfigAdapter{
		apiDefinition: apiDefinition,
	}
	for _, option := range options {
		option(&adapter)
	}

	return adapter
}

func (g *GraphQLConfigAdapter) EngineConfigV2() (*graphql.EngineV2Configuration, error) {
	if g.apiDefinition.GraphQL.Version != apidef.GraphQLConfigVersion2 {
		return nil, ErrUnsupportedGraphQLConfigVersion
	}

	var engineAdapter GraphQLEngineAdapter
	adapterType := graphqlEngineAdapterTypeFromApiDefinition(g.apiDefinition)
	switch adapterType {
	case GraphQLEngineAdapterTypeProxyOnly:
		engineAdapter = &gqlengineadapter.ProxyOnly{
			ApiDefinition:   g.apiDefinition,
			HttpClient:      g.getHttpClient(),
			StreamingClient: g.getStreamingClient(),
			Schema:          g.schema,
		}
	case GraphQLEngineAdapterTypeSupergraph:
		engineAdapter = &gqlengineadapter.Supergraph{
			ApiDefinition:   g.apiDefinition,
			HttpClient:      g.getHttpClient(),
			StreamingClient: g.getStreamingClient(),
		}
	case GraphQLEngineAdapterTypeUniversalDataGraph:
		engineAdapter = &gqlengineadapter.UniversalDataGraph{
			ApiDefinition:   g.apiDefinition,
			HttpClient:      g.getHttpClient(),
			StreamingClient: g.getStreamingClient(),
			Schema:          g.schema,
		}
	default:
		return nil, ErrUnsupportedGraphQLExecutionMode
	}

	return engineAdapter.EngineConfig()
}

func (g *GraphQLConfigAdapter) getHttpClient() *http.Client {
	if g.httpClient == nil {
		g.httpClient = httpclient.DefaultNetHttpClient
	}

	return g.httpClient
}

func (g *GraphQLConfigAdapter) getStreamingClient() *http.Client {
	if g.streamingClient == nil {
		g.streamingClient = httpclient.DefaultNetHttpClient
		g.streamingClient.Timeout = 0
	}

	return g.streamingClient
}
