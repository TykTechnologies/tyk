package adapter

import (
	"encoding/json"
	"errors"
	"net/http"
	neturl "net/url"
	"sort"
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

	if g.isProxyOnlyAPIDefinition() {
		return g.createV2ConfigForProxyOnlyExecutionMode()
	}

	if g.isSupergraphAPIDefinition() {
		return g.createV2ConfigForSupergraphExecutionMode()
	}

	return g.createV2ConfigForEngineExecutionMode()
}

func (g *GraphQLConfigAdapter) createV2ConfigForProxyOnlyExecutionMode() (*graphql.EngineV2Configuration, error) {
	staticHeaders := make(http.Header)
	for authHeaderKey, authHeaderValue := range g.apiDefinition.GraphQL.Proxy.AuthHeaders {
		staticHeaders.Add(authHeaderKey, authHeaderValue)
	}

	url := g.apiDefinition.Proxy.TargetURL
	if strings.HasPrefix(url, "tyk://") {
		url = strings.ReplaceAll(url, "tyk://", "http://")
		staticHeaders.Set(apidef.TykInternalApiHeader, "true")
	}

	upstreamConfig := graphql.ProxyUpstreamConfig{
		URL:              url,
		StaticHeaders:    staticHeaders,
		SubscriptionType: g.graphqlSubscriptionType(g.apiDefinition.GraphQL.Proxy.SubscriptionType),
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
	if err := g.parseSchema(); err != nil {
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

func (g *GraphQLConfigAdapter) parseSchema() (err error) {
	if g.schema != nil {
		return nil
	}

	g.schema, err = graphql.NewSchemaFromString(g.apiDefinition.GraphQL.Schema)
	if err != nil {
		return err
	}

	normalizationResult, err := g.schema.Normalize()
	if err != nil {
		return err
	}

	if !normalizationResult.Successful && normalizationResult.Errors != nil {
		return normalizationResult.Errors
	}

	return nil
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

			urlWithoutQueryParams, queryConfigs, err := g.extractURLQueryParamsForEngineV2(restConfig.URL, restConfig.Query)
			if err != nil {
				return nil, err
			}

			planDataSource.Custom = restDataSource.ConfigJSON(restDataSource.Configuration{
				Fetch: restDataSource.FetchConfiguration{
					URL:    urlWithoutQueryParams,
					Method: restConfig.Method,
					Body:   restConfig.Body,
					Query:  queryConfigs,
					Header: g.convertHeadersToHttpHeaders(restConfig.Headers),
				},
			})

		case apidef.GraphQLEngineDataSourceKindGraphQL:
			var graphqlConfig apidef.GraphQLEngineDataSourceConfigGraphQL
			err = json.Unmarshal(ds.Config, &graphqlConfig)
			if err != nil {
				return nil, err
			}

			planDataSource.Factory, err = g.createGraphQLDataSourceFactory(graphqlConfig)
			if err != nil {
				return nil, err
			}

			planDataSource.Custom = graphqlDataSource.ConfigJson(g.graphqlDataSourceConfiguration(
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
		hdr := g.removeDuplicateHeaders(apiDefSubgraphConf.Headers, g.apiDefinition.GraphQL.Supergraph.GlobalHeaders)
		conf := g.graphqlDataSourceConfiguration(
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

func (g *GraphQLConfigAdapter) graphqlDataSourceConfiguration(url string, method string, headers map[string]string, subscriptionType apidef.SubscriptionType) graphqlDataSource.Configuration {
	dataSourceHeaders := make(map[string]string)
	for name, value := range headers {
		dataSourceHeaders[name] = value
	}

	if strings.HasPrefix(url, "tyk://") {
		url = strings.ReplaceAll(url, "tyk://", "http://")
		dataSourceHeaders[apidef.TykInternalApiHeader] = "true"
	}

	cfg := graphqlDataSource.Configuration{
		Fetch: graphqlDataSource.FetchConfiguration{
			URL:    url,
			Method: method,
			Header: g.convertHeadersToHttpHeaders(dataSourceHeaders),
		},
		Subscription: graphqlDataSource.SubscriptionConfiguration{
			URL:    url,
			UseSSE: subscriptionType == apidef.GQLSubscriptionSSE,
		},
	}

	return cfg
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

		(*fieldConfs)[i].Arguments = g.createArgumentConfigurationsForArgumentNames(currentArgs.ArgumentNames)
		delete(generatedArgs, lookupKey)
	}

	for _, genArgs := range generatedArgs {
		*fieldConfs = append(*fieldConfs, plan.FieldConfiguration{
			TypeName:  genArgs.TypeName,
			FieldName: genArgs.FieldName,
			Arguments: g.createArgumentConfigurationsForArgumentNames(genArgs.ArgumentNames),
		})
	}
}

func (g *GraphQLConfigAdapter) createArgumentConfigurationsForArgumentNames(argumentNames []string) plan.ArgumentsConfigurations {
	argConfs := plan.ArgumentsConfigurations{}
	for _, argName := range argumentNames {
		argConf := plan.ArgumentConfiguration{
			Name:       argName,
			SourceType: plan.FieldArgumentSource,
		}

		argConfs = append(argConfs, argConf)
	}

	return argConfs
}

func (g *GraphQLConfigAdapter) extractURLQueryParamsForEngineV2(url string, providedApiDefQueries []apidef.QueryVariable) (urlWithoutParams string, engineV2Queries []restDataSource.QueryConfiguration, err error) {
	urlParts := strings.Split(url, "?")
	urlWithoutParams = urlParts[0]

	queryPart := ""
	if len(urlParts) == 2 {
		queryPart = urlParts[1]
	}
	// Parse only query part as URL could contain templating {{.argument.id}} which should not be escaped
	values, err := neturl.ParseQuery(queryPart)
	if err != nil {
		return "", nil, err
	}

	engineV2Queries = make([]restDataSource.QueryConfiguration, 0)
	g.convertURLQueryParamsIntoEngineV2Queries(&engineV2Queries, values)
	g.convertApiDefQueriesConfigIntoEngineV2Queries(&engineV2Queries, providedApiDefQueries)

	if len(engineV2Queries) == 0 {
		return urlWithoutParams, nil, nil
	}

	return urlWithoutParams, engineV2Queries, nil
}

func (g *GraphQLConfigAdapter) convertURLQueryParamsIntoEngineV2Queries(engineV2Queries *[]restDataSource.QueryConfiguration, queryValues neturl.Values) {
	for queryKey, queryValue := range queryValues {
		*engineV2Queries = append(*engineV2Queries, restDataSource.QueryConfiguration{
			Name:  queryKey,
			Value: strings.Join(queryValue, ","),
		})
	}

	sort.Slice(*engineV2Queries, func(i, j int) bool {
		return (*engineV2Queries)[i].Name < (*engineV2Queries)[j].Name
	})
}

func (g *GraphQLConfigAdapter) convertApiDefQueriesConfigIntoEngineV2Queries(engineV2Queries *[]restDataSource.QueryConfiguration, apiDefQueries []apidef.QueryVariable) {
	if len(apiDefQueries) == 0 {
		return
	}

	for _, apiDefQueryVar := range apiDefQueries {
		engineV2Query := restDataSource.QueryConfiguration{
			Name:  apiDefQueryVar.Name,
			Value: apiDefQueryVar.Value,
		}

		*engineV2Queries = append(*engineV2Queries, engineV2Query)
	}
}

func (g *GraphQLConfigAdapter) convertHeadersToHttpHeaders(apiDefHeaders map[string]string) http.Header {
	if len(apiDefHeaders) == 0 {
		return nil
	}

	engineV2Headers := make(http.Header)
	for apiDefHeaderKey, apiDefHeaderValue := range apiDefHeaders {
		engineV2Headers.Add(apiDefHeaderKey, apiDefHeaderValue)
	}

	return engineV2Headers
}

func (g *GraphQLConfigAdapter) removeDuplicateHeaders(headers ...map[string]string) map[string]string {
	hdr := make(map[string]string)
	// headers priority depends on the order of arguments
	for _, header := range headers {
		for k, v := range header {
			keyCanonical := http.CanonicalHeaderKey(k)
			if _, ok := hdr[keyCanonical]; ok {
				// skip because header is present
				continue
			}
			hdr[keyCanonical] = v
		}
	}
	return hdr
}

func (g *GraphQLConfigAdapter) determineChildNodes(planDataSources []plan.DataSourceConfiguration) error {
	for i := range planDataSources {
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

func (g *GraphQLConfigAdapter) isSupergraphAPIDefinition() bool {
	return g.apiDefinition.GraphQL.Enabled && g.apiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeSupergraph
}

func (g *GraphQLConfigAdapter) isProxyOnlyAPIDefinition() bool {
	return g.apiDefinition.GraphQL.Enabled &&
		(g.apiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeProxyOnly || g.apiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeSubgraph)
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

func (g *GraphQLConfigAdapter) createGraphQLDataSourceFactory(graphqlConfig apidef.GraphQLEngineDataSourceConfigGraphQL) (*graphqlDataSource.Factory, error) {
	factory := &graphqlDataSource.Factory{
		HTTPClient:      g.getHttpClient(),
		StreamingClient: g.getStreamingClient(),
	}

	wsProtocol := g.graphqlDataSourceWebSocketProtocol(graphqlConfig.SubscriptionType)
	graphqlSubscriptionClient := g.subscriptionClientFactory.NewSubscriptionClient(
		g.getHttpClient(),
		g.getStreamingClient(),
		nil,
		graphqlDataSource.WithWSSubProtocol(wsProtocol),
	)

	subscriptionClient, ok := graphqlSubscriptionClient.(*graphqlDataSource.SubscriptionClient)
	if !ok {
		return nil, errors.New("incorrect SubscriptionClient has been created")
	}
	factory.SubscriptionClient = subscriptionClient
	return factory, nil
}

func (g *GraphQLConfigAdapter) graphqlDataSourceWebSocketProtocol(subscriptionType apidef.SubscriptionType) string {
	wsProtocol := graphqlDataSource.ProtocolGraphQLWS
	if subscriptionType == apidef.GQLSubscriptionTransportWS {
		wsProtocol = graphqlDataSource.ProtocolGraphQLTWS
	}
	return wsProtocol
}

func (g *GraphQLConfigAdapter) graphqlSubscriptionType(subscriptionType apidef.SubscriptionType) graphql.SubscriptionType {
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
