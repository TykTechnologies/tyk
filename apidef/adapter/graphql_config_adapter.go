package adapter

import (
	"encoding/json"
	"errors"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"

	graphqlDataSource "github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/httpclient"
	restDataSource "github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
)

var ErrUnsupportedGraphQLConfigVersion = errors.New("provided version of GraphQL config is not supported for this operation")

type GraphQLConfigAdapter struct {
	config     apidef.GraphQLConfig
	httpClient *http.Client
	schema     *graphql.Schema
}

func NewGraphQLConfigAdapter(config apidef.GraphQLConfig) GraphQLConfigAdapter {
	return GraphQLConfigAdapter{config: config}
}

func (g *GraphQLConfigAdapter) EngineConfigV2() (*graphql.EngineV2Configuration, error) {
	if g.config.Version != apidef.GraphQLConfigVersion2 {
		return nil, ErrUnsupportedGraphQLConfigVersion
	}

	var err error
	g.schema, err = graphql.NewSchemaFromString(g.config.Schema)
	if err != nil {
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

			factory := &restDataSource.Factory{}
			if g.httpClient != nil {
				factory.Client = httpclient.NewNetHttpClient(g.httpClient)
			}
			planDataSource.Factory = factory

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
					Header: g.convertHttpHeadersToEngineV2Headers(restConfig.Headers),
				},
			})

		case apidef.GraphQLEngineDataSourceKindGraphQL:
			var graphqlConfig apidef.GraphQLEngineDataSourceConfigGraphQL
			err = json.Unmarshal(ds.Config, &graphqlConfig)
			if err != nil {
				return nil, err
			}

			factory := &graphqlDataSource.Factory{}
			if g.httpClient != nil {
				factory.Client = httpclient.NewNetHttpClient(g.httpClient)
			}
			planDataSource.Factory = factory

			planDataSource.Custom = graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL:    graphqlConfig.URL,
					Method: graphqlConfig.Method,
					Header: g.convertHttpHeadersToEngineV2Headers(graphqlConfig.Headers),
				},
			})
		}

		planDataSources = append(planDataSources, planDataSource)
	}

	err = g.determineChildNodes(planDataSources)
	return planDataSources, err
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

func (g *GraphQLConfigAdapter) SetHttpClient(httpClient *http.Client) {
	g.httpClient = httpClient
}

func (g *GraphQLConfigAdapter) extractURLQueryParamsForEngineV2(url string, providedApiDefQueries []apidef.QueryVariable) (urlWithoutParams string, engineV2Queries []restDataSource.QueryConfiguration, err error) {
	parsedURL, err := neturl.Parse(url)
	if err != nil {
		return "", nil, err
	}

	engineV2Queries = make([]restDataSource.QueryConfiguration, 0)
	g.convertURLQueryParamsIntoEngineV2Queries(&engineV2Queries, parsedURL)
	g.convertApiDefQueriesConfigIntoEngineV2Queries(&engineV2Queries, providedApiDefQueries)

	parsedURL.RawQuery = ""
	if len(engineV2Queries) == 0 {
		return parsedURL.String(), nil, nil
	}

	return parsedURL.String(), engineV2Queries, nil
}

func (g *GraphQLConfigAdapter) convertURLQueryParamsIntoEngineV2Queries(engineV2Queries *[]restDataSource.QueryConfiguration, parsedURL *neturl.URL) {
	queryValues := parsedURL.Query()
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

func (g *GraphQLConfigAdapter) convertHttpHeadersToEngineV2Headers(apiDefHeaders map[string]string) http.Header {
	if len(apiDefHeaders) == 0 {
		return nil
	}

	engineV2Headers := make(http.Header)
	for apiDefHeaderKey, apiDefHeaderValue := range apiDefHeaders {
		engineV2Headers[apiDefHeaderKey] = []string{apiDefHeaderValue}
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
