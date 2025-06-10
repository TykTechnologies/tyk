package gqlengineadapter

import (
	"net/http"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
)

type Supergraph struct {
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client

	subscriptionClientFactory graphqldatasource.GraphQLSubscriptionClientFactory
}

func (s *Supergraph) EngineConfig() (*graphql.EngineV2Configuration, error) {
	dataSourceConfs := s.subgraphDataSourceConfigs()
	var federationConfigV2Factory *graphql.FederationEngineConfigFactory
	if s.ApiDefinition.GraphQL.Supergraph.DisableQueryBatching {
		federationConfigV2Factory = graphql.NewFederationEngineConfigFactory(
			dataSourceConfs,
			nil,
			graphql.WithFederationHttpClient(s.HttpClient),
			graphql.WithFederationStreamingClient(s.StreamingClient),
			graphql.WithFederationSubscriptionClientFactory(subscriptionClientFactoryOrDefault(s.subscriptionClientFactory)),
		)
	} else {
		federationConfigV2Factory = graphql.NewFederationEngineConfigFactory(
			dataSourceConfs,
			graphqldatasource.NewBatchFactory(),
			graphql.WithFederationHttpClient(s.HttpClient),
			graphql.WithFederationStreamingClient(s.StreamingClient),
			graphql.WithFederationSubscriptionClientFactory(subscriptionClientFactoryOrDefault(s.subscriptionClientFactory)),
		)
	}

	err := federationConfigV2Factory.SetMergedSchemaFromString(s.ApiDefinition.GraphQL.Supergraph.MergedSDL)
	if err != nil {
		return nil, err
	}

	conf, err := federationConfigV2Factory.EngineV2Configuration()
	if err != nil {
		return nil, err
	}

	conf.EnableSingleFlight(true)
	if !s.ApiDefinition.GraphQL.Supergraph.DisableQueryBatching {
		conf.EnableDataLoader(true)
	}

	return &conf, nil
}

func (s *Supergraph) subgraphDataSourceConfigs() []graphqldatasource.Configuration {
	confs := make([]graphqldatasource.Configuration, 0)
	if len(s.ApiDefinition.GraphQL.Supergraph.Subgraphs) == 0 {
		return confs
	}

	for _, apiDefSubgraphConf := range s.ApiDefinition.GraphQL.Supergraph.Subgraphs {
		if len(apiDefSubgraphConf.SDL) == 0 {
			continue
		}
		hdr := removeDuplicateApiDefinitionHeaders(apiDefSubgraphConf.Headers, s.ApiDefinition.GraphQL.Supergraph.GlobalHeaders)
		conf := graphqlDataSourceConfiguration(
			apiDefSubgraphConf.URL,
			http.MethodPost,
			hdr,
			apiDefSubgraphConf.SubscriptionType,
			apiDefSubgraphConf.SSEUsePost,
		)
		conf.Federation = graphqldatasource.FederationConfiguration{
			Enabled:    true,
			ServiceSDL: apiDefSubgraphConf.SDL,
		}

		confs = append(confs, conf)
	}

	return confs
}
