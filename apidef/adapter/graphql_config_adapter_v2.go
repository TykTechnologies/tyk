package adapter

import (
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/httpclient"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
	v2 "github.com/TykTechnologies/tyk/apidef/adapter/gqlengineadapter/v2"
	"net/http"
)

type GraphQLEngineAdapterV2 interface {
	EngineConfigV2() (*graphql.EngineV2Configuration, error)
}

type GraphQLConfigAdapterV2 struct {
	apiDefinition   *apidef.APIDefinition
	httpClient      *http.Client
	streamingClient *http.Client
	schema          *graphql.Schema
}

func (g *GraphQLConfigAdapterV2) EngineConfigV2() (*graphql.EngineV2Configuration, error) {
	if g.apiDefinition.GraphQL.Version != apidef.GraphQLConfigVersion2 {
		return nil, ErrUnsupportedGraphQLConfigVersion
	}

	var engineAdapter GraphQLEngineAdapterV2
	adapterType := graphqlEngineAdapterTypeFromApiDefinition(g.apiDefinition)
	switch adapterType {
	case GraphQLEngineAdapterTypeProxyOnly:
		engineAdapter = &v2.ProxyOnly{
			ApiDefinition:   g.apiDefinition,
			HttpClient:      g.getHttpClient(),
			StreamingClient: g.getStreamingClient(),
			//Schema:          g.schema,
		}
	case GraphQLEngineAdapterTypeSupergraph:
		engineAdapter = &v2.Supergraph{
			ApiDefinition:   g.apiDefinition,
			HttpClient:      g.getHttpClient(),
			StreamingClient: g.getStreamingClient(),
		}
	//case GraphQLEngineAdapterTypeUniversalDataGraph:
	//	engineAdapter = &gqlengineadapter.UniversalDataGraph{
	//		ApiDefinition:   g.apiDefinition,
	//		HttpClient:      g.getHttpClient(),
	//		StreamingClient: g.getStreamingClient(),
	//		Schema:          g.schema,
	//}
	default:
		return nil, ErrUnsupportedGraphQLExecutionMode
	}

	return engineAdapter.EngineConfigV2()
}

func (g *GraphQLConfigAdapterV2) getHttpClient() *http.Client {
	if g.httpClient == nil {
		g.httpClient = httpclient.DefaultNetHttpClient
	}
	return g.httpClient
}

func (g *GraphQLConfigAdapterV2) getStreamingClient() *http.Client {
	if g.streamingClient == nil {
		g.streamingClient = httpclient.DefaultNetHttpClient
		g.streamingClient.Timeout = 0
	}
	return g.streamingClient
}
