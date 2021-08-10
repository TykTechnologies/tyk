package adapter

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	graphqlDataSource "github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/httpclient"
	restDataSource "github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
	"github.com/jensneuse/graphql-go-tools/pkg/graphql/federation"

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

type GraphQLConfigAdapter struct {
	config     apidef.GraphQLConfig
	httpClient *http.Client
	schema     *graphql.Schema
}

func NewGraphQLConfigAdapter(config apidef.GraphQLConfig, options ...GraphQLConfigAdapterOption) GraphQLConfigAdapter {
	adapter := GraphQLConfigAdapter{config: config}
	for _, option := range options {
		option(&adapter)
	}

	return adapter
}

func (g *GraphQLConfigAdapter) EngineConfigV2() (*graphql.EngineV2Configuration, error) {
	if g.config.Version != apidef.GraphQLConfigVersion2 {
		return nil, ErrUnsupportedGraphQLConfigVersion
	}

	if g.isSupergraphAPIDefinition() {
		return g.createV2ConfigForSupergraphExecutionMode()
	}

	return g.createV2ConfigForEngineExecutionMode()
}

func (g *GraphQLConfigAdapter) createV2ConfigForSupergraphExecutionMode() (*graphql.EngineV2Configuration, error) {
	dataSourceConfs := g.subgraphDataSourceConfigs()
	federationConfigV2Factory := federation.NewEngineConfigV2Factory(g.getHttpClient(), dataSourceConfs...)
	err := federationConfigV2Factory.SetMergedSchemaFromString(g.config.Supergraph.MergedSDL)
	if err != nil {
		return nil, err
	}

	conf, err := federationConfigV2Factory.EngineV2Configuration()
	if err != nil {
		return nil, err
	}

	return &conf, nil
}

func (g *GraphQLConfigAdapter) createV2ConfigForEngineExecutionMode() (*graphql.EngineV2Configuration, error) {
	if err := g.parseSchema(); err != nil {
		return nil, err
	}

	conf := graphql.NewEngineV2Configuration(g.schema)

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

	g.schema, err = graphql.NewSchemaFromString(g.config.Schema)
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
	for _, fc := range g.config.Engine.FieldConfigs {
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
	for _, ds := range g.config.Engine.DataSources {
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

			planDataSource.Custom = restDataSource.ConfigJSON(restDataSource.Configuration{
				Fetch: restDataSource.FetchConfiguration{
					URL:    restConfig.URL,
					Method: restConfig.Method,
					Body:   restConfig.Body,
					Query:  g.convertURLQueriesToEngineV2Queries(restConfig.Query),
					Header: g.convertHeadersToHttpHeaders(restConfig.Headers),
				},
			})

		case apidef.GraphQLEngineDataSourceKindGraphQL:
			var graphqlConfig apidef.GraphQLEngineDataSourceConfigGraphQL
			err = json.Unmarshal(ds.Config, &graphqlConfig)
			if err != nil {
				return nil, err
			}

			planDataSource.Factory = &graphqlDataSource.Factory{
				Client: g.getHttpClient(),
			}

			planDataSource.Custom = graphqlDataSource.ConfigJson(g.graphqlDataSourceConfiguration(
				graphqlConfig.URL,
				graphqlConfig.Method,
				graphqlConfig.Headers,
			))
		}

		planDataSources = append(planDataSources, planDataSource)
	}

	err = g.determineChildNodes(planDataSources)
	return planDataSources, err
}

func (g *GraphQLConfigAdapter) subgraphDataSourceConfigs() []graphqlDataSource.Configuration {
	confs := make([]graphqlDataSource.Configuration, 0)
	if len(g.config.Supergraph.Subgraphs) == 0 {
		return confs
	}

	for _, apiDefSubgraphConf := range g.config.Supergraph.Subgraphs {
		if len(apiDefSubgraphConf.SDL) == 0 {
			continue
		}

		conf := g.graphqlDataSourceConfiguration(apiDefSubgraphConf.URL, http.MethodPost, g.config.Supergraph.GlobalHeaders)
		conf.Federation = graphqlDataSource.FederationConfiguration{
			Enabled:    true,
			ServiceSDL: apiDefSubgraphConf.SDL,
		}

		confs = append(confs, conf)
	}

	return confs
}

func (g *GraphQLConfigAdapter) graphqlDataSourceConfiguration(url string, method string, headers map[string]string) graphqlDataSource.Configuration {
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
			URL: url,
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

func (g *GraphQLConfigAdapter) convertURLQueriesToEngineV2Queries(apiDefQueries []apidef.QueryVariable) []restDataSource.QueryConfiguration {
	if len(apiDefQueries) == 0 {
		return nil
	}

	var engineV2Queries []restDataSource.QueryConfiguration
	for _, apiDefQueryVar := range apiDefQueries {
		engineV2Query := restDataSource.QueryConfiguration{
			Name:  apiDefQueryVar.Name,
			Value: apiDefQueryVar.Value,
		}

		engineV2Queries = append(engineV2Queries, engineV2Query)
	}

	return engineV2Queries
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
	return g.config.Enabled && g.config.ExecutionMode == apidef.GraphQLExecutionModeSupergraph
}

func (g *GraphQLConfigAdapter) getHttpClient() *http.Client {
	if g.httpClient == nil {
		g.httpClient = httpclient.DefaultNetHttpClient
	}

	return g.httpClient
}
