package apidef

import (
	"encoding/json"
	"errors"

	"github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
)

var ErrUnsupportedGraphQLConfigVersion = errors.New("provided version of GraphQL config is not supported for this operation")

type GraphQLConfigAdapter struct {
	config GraphQLConfig
}

func NewGraphQLConfigAdapter(config GraphQLConfig) GraphQLConfigAdapter {
	return GraphQLConfigAdapter{config: config}
}

func (g *GraphQLConfigAdapter) EngineConfigV2() (*graphql.EngineV2Configuration, error) {
	if g.config.Version != GraphQLConfigVersion2 {
		return nil, ErrUnsupportedGraphQLConfigVersion
	}

	schema, err := graphql.NewSchemaFromString(g.config.Schema)
	if err != nil {
		return nil, err
	}

	conf := graphql.NewEngineV2Configuration(schema)

	fieldConfigs, err := g.engineConfigV2FieldConfigs()
	if err != nil {
		return nil, err
	}

	datsSources, err := g.engineConfigV2DataSources()
	if err != nil {
		return nil, err
	}

	conf.SetFieldConfigurations(fieldConfigs)
	conf.SetDataSources(datsSources)

	return &conf, nil
}

func (g *GraphQLConfigAdapter) engineConfigV2FieldConfigs() (planFieldConfigs plan.FieldConfigurations, err error) {
	for _, fc := range g.config.EngineConfig.FieldConfigs {
		planFieldConfig := plan.FieldConfiguration{
			TypeName:              fc.TypeName,
			FieldName:             fc.FieldName,
			DisableDefaultMapping: fc.DisableDefaultMapping,
			Path:                  fc.Path,
		}

		planFieldConfigs = append(planFieldConfigs, planFieldConfig)
	}

	return planFieldConfigs, nil
}

func (g *GraphQLConfigAdapter) engineConfigV2DataSources() (planDataSources []plan.DataSourceConfiguration, err error) {
	for _, ds := range g.config.EngineConfig.DataSources {
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
		case GraphQLEngineDataSourceKindREST:
			planDataSource.Factory = &rest_datasource.Factory{}
			restConfig := GraphQLEngineDataSourceConfigREST{}
			err = json.Unmarshal(ds.Config, &restConfig)
			if err != nil {
				return nil, err
			}

			planDataSource.Custom = rest_datasource.ConfigJSON(rest_datasource.Configuration{
				Fetch: rest_datasource.FetchConfiguration{
					URL:    restConfig.URL,
					Method: restConfig.Method,
				},
			})

		case GraphQLEngineDataSourceKindGraphQL:
			planDataSource.Factory = &graphql_datasource.Factory{}
			graphqlConfig := GraphQLEngineDataSourceConfigGraphQL{}
			err = json.Unmarshal(ds.Config, &graphqlConfig)
			if err != nil {
				return nil, err
			}

			planDataSource.Custom = graphql_datasource.ConfigJson(graphql_datasource.Configuration{
				Fetch: graphql_datasource.FetchConfiguration{
					URL:        graphqlConfig.URL,
					HttpMethod: graphqlConfig.Method,
				},
			})
		}

		planDataSources = append(planDataSources, planDataSource)
	}

	return planDataSources, nil
}
