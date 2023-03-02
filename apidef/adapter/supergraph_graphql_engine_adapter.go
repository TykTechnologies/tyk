package adapter

import (
	"net/http"

	graphqlDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
)

type supergraphGraphQLEngineAdapter struct {
	apiDefinition   *apidef.APIDefinition
	httpClient      *http.Client
	streamingClient *http.Client

	subscriptionClientFactory graphqlDataSource.GraphQLSubscriptionClientFactory
}

func (s *supergraphGraphQLEngineAdapter) EngineConfig() (*graphql.EngineV2Configuration, error) {
	dataSourceConfs := s.subgraphDataSourceConfigs()
	var federationConfigV2Factory *graphql.FederationEngineConfigFactory
	if s.apiDefinition.GraphQL.Supergraph.DisableQueryBatching {
		federationConfigV2Factory = graphql.NewFederationEngineConfigFactory(
			dataSourceConfs,
			nil,
			graphql.WithFederationHttpClient(s.httpClient),
			graphql.WithFederationStreamingClient(s.streamingClient),
			graphql.WithFederationSubscriptionClientFactory(s.subscriptionClientFactory),
		)
	} else {
		federationConfigV2Factory = graphql.NewFederationEngineConfigFactory(
			dataSourceConfs,
			graphqlDataSource.NewBatchFactory(),
			graphql.WithFederationHttpClient(s.httpClient),
			graphql.WithFederationStreamingClient(s.streamingClient),
			graphql.WithFederationSubscriptionClientFactory(s.subscriptionClientFactory),
		)
	}

	err := federationConfigV2Factory.SetMergedSchemaFromString(s.apiDefinition.GraphQL.Supergraph.MergedSDL)
	if err != nil {
		return nil, err
	}

	conf, err := federationConfigV2Factory.EngineV2Configuration()
	if err != nil {
		return nil, err
	}

	conf.EnableSingleFlight(true)
	if !s.apiDefinition.GraphQL.Supergraph.DisableQueryBatching {
		conf.EnableDataLoader(true)
	}

	return &conf, nil
}

func (s *supergraphGraphQLEngineAdapter) subgraphDataSourceConfigs() []graphqlDataSource.Configuration {
	confs := make([]graphqlDataSource.Configuration, 0)
	if len(s.apiDefinition.GraphQL.Supergraph.Subgraphs) == 0 {
		return confs
	}

	for _, apiDefSubgraphConf := range s.apiDefinition.GraphQL.Supergraph.Subgraphs {
		if len(apiDefSubgraphConf.SDL) == 0 {
			continue
		}
		hdr := removeDuplicateApiDefinitionHeaders(apiDefSubgraphConf.Headers, s.apiDefinition.GraphQL.Supergraph.GlobalHeaders)
		conf := graphqlDataSourceConfiguration(
			apiDefSubgraphConf.URL,
			http.MethodPost,
			hdr,
			apiDefSubgraphConf.SubscriptionType)
		conf.Federation = graphqlDataSource.FederationConfiguration{
			Enabled:    true,
			ServiceSDL: apiDefSubgraphConf.SDL,
		}

		confs = append(confs, conf)
	}

	return confs
}
