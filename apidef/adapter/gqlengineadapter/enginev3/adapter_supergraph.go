package enginev3

import (
	"net/http"
	"strings"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/adapter/gqlengineadapter"
)

type Supergraph struct {
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client

	subscriptionClientFactory graphqldatasource.GraphQLSubscriptionClientFactory
}

func (s *Supergraph) EngineConfigV3() (*graphql.EngineV2Configuration, error) {
	dataSourceConfs := s.subgraphDataSourceConfigs()
	var federationConfigV2Factory *graphql.FederationEngineConfigFactory
	federationConfigV2Factory = graphql.NewFederationEngineConfigFactory(
		dataSourceConfs,
		graphql.WithFederationHttpClient(s.HttpClient),
		graphql.WithFederationStreamingClient(s.StreamingClient),
		graphql.WithFederationSubscriptionClientFactory(subscriptionClientFactoryOrDefault(s.subscriptionClientFactory)),
	)

	err := federationConfigV2Factory.SetMergedSchemaFromString(s.ApiDefinition.GraphQL.Supergraph.MergedSDL)
	if err != nil {
		return nil, err
	}

	conf, err := federationConfigV2Factory.EngineV2Configuration()
	if err != nil {
		return nil, err
	}

	conf.EnableSingleFlight(true)

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
		hdr := gqlengineadapter.RemoveDuplicateApiDefinitionHeaders(apiDefSubgraphConf.Headers, s.ApiDefinition.GraphQL.Supergraph.GlobalHeaders)
		conf := graphqlDataSourceConfiguration(
			apiDefSubgraphConf.URL,
			http.MethodPost,
			hdr,
			apiDefSubgraphConf.SubscriptionType)
		conf.Federation = graphqldatasource.FederationConfiguration{
			Enabled:    true,
			ServiceSDL: apiDefSubgraphConf.SDL,
		}

		confs = append(confs, conf)
	}

	return confs
}

func graphqlDataSourceConfiguration(url string, method string, headers map[string]string, subscriptionType apidef.SubscriptionType) graphqldatasource.Configuration {
	dataSourceHeaders := make(map[string]string)
	for name, value := range headers {
		dataSourceHeaders[name] = value
	}

	if strings.HasPrefix(url, "tyk://") {
		url = strings.ReplaceAll(url, "tyk://", "http://")
		dataSourceHeaders[apidef.TykInternalApiHeader] = "true"
	}

	cfg := graphqldatasource.Configuration{
		Fetch: graphqldatasource.FetchConfiguration{
			URL:    url,
			Method: method,
			Header: gqlengineadapter.ConvertApiDefinitionHeadersToHttpHeaders(dataSourceHeaders),
		},
		Subscription: graphqldatasource.SubscriptionConfiguration{
			URL:    url,
			UseSSE: subscriptionType == apidef.GQLSubscriptionSSE,
		},
	}

	return cfg
}
