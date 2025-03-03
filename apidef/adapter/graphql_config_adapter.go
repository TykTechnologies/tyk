package adapter

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	graphqlDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/httpclient"
	kafkaDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/kafka_datasource"
	restDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
)

var ErrUnsupportedGraphQLConfigVersion = errors.New("provided version of GraphQL config is not supported for this operation")

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

func withGraphQLSubscriptionClientFactory(factory graphqlDataSource.GraphQLSubscriptionClientFactory) GraphQLConfigAdapterOption {
	return func(adapter *GraphQLConfigAdapter) {
		adapter.subscriptionClientFactory = factory
	}
}

type GraphQLConfigAdapter struct {
	apiDefinition   *apidef.APIDefinition
	httpClient      *http.Client
	streamingClient *http.Client
	schema          *graphql.Schema

	subscriptionClientFactory graphqlDataSource.GraphQLSubscriptionClientFactory
}

func NewGraphQLConfigAdapter(apiDefinition *apidef.APIDefinition, options ...GraphQLConfigAdapterOption) GraphQLConfigAdapter {
	adapter := GraphQLConfigAdapter{
		apiDefinition:             apiDefinition,
		subscriptionClientFactory: &graphqlDataSource.DefaultSubscriptionClientFactory{},
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

	if isProxyOnlyAPIDefinition(g.apiDefinition) {
		return g.createV2ConfigForProxyOnlyExecutionMode()
	}

	if isSupergraphAPIDefinition(g.apiDefinition) {
		return g.createV2ConfigForSupergraphExecutionMode()
	}

	return g.createV2ConfigForEngineExecutionMode()
}

func (g *GraphQLConfigAdapter) createV2ConfigForProxyOnlyExecutionMode() (*graphql.EngineV2Configuration, error) {
	staticHeaders := make(http.Header)
	for key, value := range g.apiDefinition.GraphQL.Proxy.RequestHeaders {
		staticHeaders.Set(key, value)
	}

	url := g.apiDefinition.Proxy.TargetURL
	if strings.HasPrefix(url, "tyk://") {
		url = strings.ReplaceAll(url, "tyk://", "http://")
		staticHeaders.Set(apidef.TykInternalApiHeader, "true")
	}

	upstreamConfig := graphql.ProxyUpstreamConfig{
		URL:              url,
		StaticHeaders:    staticHeaders,
		SubscriptionType: graphqlSubscriptionType(g.apiDefinition.GraphQL.Proxy.SubscriptionType),
	}

	if g.schema == nil {
		var err error
		g.schema, err = graphql.NewSchemaFromString(g.apiDefinition.GraphQL.Schema)
		if err != nil {
			return nil, err
		}
	}

	v2Config, err := graphql.NewProxyEngineConfigFactory(
		g.schema,
		upstreamConfig,
		graphqlDataSource.NewBatchFactory(),
		graphql.WithProxyHttpClient(g.httpClient),
		graphql.WithProxyStreamingClient(g.streamingClient),
		graphql.WithProxySubscriptionClientFactory(g.subscriptionClientFactory),
	).EngineV2Configuration()

	v2Config.EnableSingleFlight(true)
	return &v2Config, err
}

func (g *GraphQLConfigAdapter) createV2ConfigForSupergraphExecutionMode() (*graphql.EngineV2Configuration, error) {
	dataSourceConfs := g.subgraphDataSourceConfigs()
	var federationConfigV2Factory *graphql.FederationEngineConfigFactory
	if g.apiDefinition.GraphQL.Supergraph.DisableQueryBatching {
		federationConfigV2Factory = graphql.NewFederationEngineConfigFactory(
			dataSourceConfs,
			nil,
			graphql.WithFederationHttpClient(g.getHttpClient()),
			graphql.WithFederationStreamingClient(g.getStreamingClient()),
			graphql.WithFederationSubscriptionClientFactory(g.subscriptionClientFactory),
		)
	} else {
		federationConfigV2Factory = graphql.NewFederationEngineConfigFactory(
			dataSourceConfs,
			graphqlDataSource.NewBatchFactory(),
			graphql.WithFederationHttpClient(g.getHttpClient()),
			graphql.WithFederationStreamingClient(g.getStreamingClient()),
			graphql.WithFederationSubscriptionClientFactory(g.subscriptionClientFactory),
		)
	}

	err := federationConfigV2Factory.SetMergedSchemaFromString(g.apiDefinition.GraphQL.Supergraph.MergedSDL)
	if err != nil {
		return nil, err
	}

	conf, err := federationConfigV2Factory.EngineV2Configuration()
	if err != nil {
		return nil, err
	}

	conf.EnableSingleFlight(true)
	if !g.apiDefinition.GraphQL.Supergraph.DisableQueryBatching {
		conf.EnableDataLoader(true)
	}

	return &conf, nil
}

func (g *GraphQLConfigAdapter) createV2ConfigForEngineExecutionMode() (*graphql.EngineV2Configuration, error) {
	var err error
	g.schema, err = parseSchema(g.apiDefinition.GraphQL.Schema)
	if err != nil {
		return nil, err
	}

	conf := graphql.NewEngineV2Configuration(g.schema)
	conf.EnableSingleFlight(true)

	fieldConfigs := g.engineConfigV2FieldConfigs()
	datsSources, err := g.engineConfigV2DataSources()
	if err != nil {
		return nil, err
	}

	conf.SetFieldConfigurations(fieldConfigs)
	conf.SetDataSources(datsSources)

	return &conf, nil
}

func (g *GraphQLConfigAdapter) engineConfigV2FieldConfigs() (planFieldConfigs plan.FieldConfigurations) {
	for _, fc := range g.apiDefinition.GraphQL.Engine.FieldConfigs {
		planFieldConfig := plan.FieldConfiguration{
			TypeName:              fc.TypeName,
			FieldName:             fc.FieldName,
			DisableDefaultMapping: fc.DisableDefaultMapping,
			Path:                  fc.Path,
		}

		planFieldConfigs = append(planFieldConfigs, planFieldConfig)
	}

	generatedArgs := g.schema.GetAllFieldArguments(graphql.NewSkipReservedNamesFunc())
	generatedArgsAsLookupMap := graphql.CreateTypeFieldArgumentsLookupMap(generatedArgs)
	g.engineConfigV2Arguments(&planFieldConfigs, generatedArgsAsLookupMap)

	return planFieldConfigs
}

func (g *GraphQLConfigAdapter) engineConfigV2DataSources() (planDataSources []plan.DataSourceConfiguration, err error) {
	for _, ds := range g.apiDefinition.GraphQL.Engine.DataSources {
		planDataSource := plan.DataSourceConfiguration{
			RootNodes: []plan.TypeField{},
		}

		for _, typeField := range ds.RootFields {
			planTypeField := plan.TypeField{
				TypeName:   typeField.Type,
				FieldNames: typeField.Fields,
			}

			planDataSource.RootNodes = append(planDataSource.RootNodes, planTypeField)
		}

		switch ds.Kind {
		case apidef.GraphQLEngineDataSourceKindREST:
			var restConfig apidef.GraphQLEngineDataSourceConfigREST
			err = json.Unmarshal(ds.Config, &restConfig)
			if err != nil {
				return nil, err
			}

			planDataSource.Factory = &restDataSource.Factory{
				Client: g.getHttpClient(),
			}

			urlWithoutQueryParams, queryConfigs, err := extractURLQueryParamsForEngineV2(restConfig.URL, restConfig.Query)
			if err != nil {
				return nil, err
			}

			planDataSource.Custom = restDataSource.ConfigJSON(restDataSource.Configuration{
				Fetch: restDataSource.FetchConfiguration{
					URL:    urlWithoutQueryParams,
					Method: restConfig.Method,
					Body:   restConfig.Body,
					Query:  queryConfigs,
					Header: convertApiDefinitionHeadersToHttpHeaders(restConfig.Headers),
				},
			})

		case apidef.GraphQLEngineDataSourceKindGraphQL:
			var graphqlConfig apidef.GraphQLEngineDataSourceConfigGraphQL
			err = json.Unmarshal(ds.Config, &graphqlConfig)
			if err != nil {
				return nil, err
			}

			planDataSource.Factory, err = createGraphQLDataSourceFactory(createGraphQLDataSourceFactoryParams{
				graphqlConfig:             graphqlConfig,
				subscriptionClientFactory: g.subscriptionClientFactory,
				httpClient:                g.getHttpClient(),
				streamingClient:           g.getStreamingClient(),
			})
			if err != nil {
				return nil, err
			}

			planDataSource.Custom = graphqlDataSource.ConfigJson(graphqlDataSourceConfiguration(
				graphqlConfig.URL,
				graphqlConfig.Method,
				graphqlConfig.Headers,
				graphqlConfig.SubscriptionType,
			))

		case apidef.GraphQLEngineDataSourceKindKafka:
			var kafkaConfig apidef.GraphQLEngineDataSourceConfigKafka
			err = json.Unmarshal(ds.Config, &kafkaConfig)
			if err != nil {
				return nil, err
			}

			planDataSource.Factory = &kafkaDataSource.Factory{}
			planDataSource.Custom = kafkaDataSource.ConfigJSON(kafkaDataSource.Configuration{
				Subscription: kafkaDataSource.SubscriptionConfiguration{
					BrokerAddresses:      kafkaConfig.BrokerAddresses,
					Topics:               kafkaConfig.Topics,
					GroupID:              kafkaConfig.GroupID,
					ClientID:             kafkaConfig.ClientID,
					KafkaVersion:         kafkaConfig.KafkaVersion,
					StartConsumingLatest: kafkaConfig.StartConsumingLatest,
					BalanceStrategy:      kafkaConfig.BalanceStrategy,
					IsolationLevel:       kafkaConfig.IsolationLevel,
					SASL:                 kafkaConfig.SASL,
				},
			})
		}

		planDataSources = append(planDataSources, planDataSource)
	}

	err = g.determineChildNodes(planDataSources)
	return planDataSources, err
}

func (g *GraphQLConfigAdapter) subgraphDataSourceConfigs() []graphqlDataSource.Configuration {
	confs := make([]graphqlDataSource.Configuration, 0)
	if len(g.apiDefinition.GraphQL.Supergraph.Subgraphs) == 0 {
		return confs
	}

	for _, apiDefSubgraphConf := range g.apiDefinition.GraphQL.Supergraph.Subgraphs {
		if len(apiDefSubgraphConf.SDL) == 0 {
			continue
		}
		hdr := removeDuplicateApiDefinitionHeaders(apiDefSubgraphConf.Headers, g.apiDefinition.GraphQL.Supergraph.GlobalHeaders)
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

func (g *GraphQLConfigAdapter) engineConfigV2Arguments(fieldConfs *plan.FieldConfigurations, generatedArgs map[graphql.TypeFieldLookupKey]graphql.TypeFieldArguments) {
	for i := range *fieldConfs {
		if len(generatedArgs) == 0 {
			return
		}

		lookupKey := graphql.CreateTypeFieldLookupKey((*fieldConfs)[i].TypeName, (*fieldConfs)[i].FieldName)
		currentArgs, ok := generatedArgs[lookupKey]
		if !ok {
			continue
		}

		(*fieldConfs)[i].Arguments = createArgumentConfigurationsForArgumentNames(currentArgs.ArgumentNames...)
		delete(generatedArgs, lookupKey)
	}

	for _, genArgs := range generatedArgs {
		*fieldConfs = append(*fieldConfs, plan.FieldConfiguration{
			TypeName:  genArgs.TypeName,
			FieldName: genArgs.FieldName,
			Arguments: createArgumentConfigurationsForArgumentNames(genArgs.ArgumentNames...),
		})
	}
}

func (g *GraphQLConfigAdapter) determineChildNodes(planDataSources []plan.DataSourceConfiguration) error {
	for i := range planDataSources {
		if _, ok := planDataSources[i].Factory.(*restDataSource.Factory); ok {
			continue
		}
		for j := range planDataSources[i].RootNodes {
			typeName := planDataSources[i].RootNodes[j].TypeName
			for k := range planDataSources[i].RootNodes[j].FieldNames {
				fieldName := planDataSources[i].RootNodes[j].FieldNames[k]
				typeFields := g.schema.GetAllNestedFieldChildrenFromTypeField(typeName, fieldName, graphql.NewIsDataSourceConfigV2RootFieldSkipFunc(planDataSources))

				children := make([]plan.TypeField, 0)
				for _, tf := range typeFields {
					childNode := plan.TypeField{
						TypeName:   tf.TypeName,
						FieldNames: tf.FieldNames,
					}
					children = append(children, childNode)
				}
				planDataSources[i].ChildNodes = append(planDataSources[i].ChildNodes, children...)
			}
		}
	}
	return nil
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
